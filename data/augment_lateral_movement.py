"""
Augment real_flows.csv with real Lateral Movement (Infiltration) examples
from CIC-IDS2018.

Why this exists: real_flows.csv (built from CIC-IDS2017 via preprocess_cicids.py)
has only ~36 real Lateral Movement flow rows in 320,000 -- CIC-IDS2017's entire
public release only has ~36 Infiltration flows in total, which a held-out
evaluation confirmed is not enough for any model to learn from (0% recall,
even after trying synthetic profile-based oversampling -- it didn't transfer).

CIC-IDS2018 dedicates two full capture days to Infiltration attacks
(Wednesday-28-02-2018 and Thursday-01-03-2018), with 161,934 real Infiltration
flow rows combined. This script downloads just those two days (~317MB, not
the full ~7GB 10-day dataset) from the official public S3 bucket, extracts
the Infiltration-labeled rows, maps them onto our 22-feature schema, and
merges them into real_flows.csv as new "Lateral Movement" sessions.

Known caveats (by design, not hidden):
- CIC-IDS2018's public CSVs have no Src/Dst IP columns (privacy-scrubbed), so
  true IP-based sessionization is impossible for this data. We chunk
  consecutive Infiltration-labeled rows (sorted by Timestamp) into synthetic
  sessions of `--session-len` flows each. The feature VALUES are 100% real
  measured flow statistics; only the session BOUNDARIES are synthetic.
- CIC-IDS2018's CICFlowMeter output has no ttl_variance or retransmit_cnt
  columns (dropped from that CICFlowMeter version). These 2 of 22 features
  are filled with 0.0 for these rows; the other 20 are genuine measured values.
- New session_ids start at 2000 to stay clear of the existing CIC-IDS2017
  session range (0-1333) with no ambiguity.

Run as:
    python data/augment_lateral_movement.py                    # download + merge
    python data/augment_lateral_movement.py --skip-download    # merge only (already downloaded)
"""
import argparse
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

S3_BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
INFILTRATION_DAYS = [
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
]

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

COLUMN_MAP = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Tot Fwd Pkts",
    "tot_bwd_pkts": "Tot Bwd Pkts",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean",
    "flow_bytes_s": "Flow Byts/s",
    "flow_pkts_s": "Flow Pkts/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "fwd_iat_mean": "Fwd IAT Mean",
    "bwd_iat_mean": "Bwd IAT Mean",
    "syn_flag_cnt": "SYN Flag Cnt",
    "ack_flag_cnt": "ACK Flag Cnt",
    "fin_flag_cnt": "FIN Flag Cnt",
    "rst_flag_cnt": "RST Flag Cnt",
    "psh_flag_cnt": "PSH Flag Cnt",
    "urg_flag_cnt": "URG Flag Cnt",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Pkt Size Avg",
    "tcp_win_size": "Init Fwd Win Byts",
}
MISSING_FEATURES = ["ttl_variance", "retransmit_cnt"]
NEEDED_COLS = list(COLUMN_MAP.values()) + ["Timestamp", "Label"]


def download(raw_dir: Path):
    raw_dir.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "Mozilla/5.0"}
    for fname in INFILTRATION_DAYS:
        dest = raw_dir / fname.replace("_TrafficForML_CICFlowMeter", "")
        if dest.exists():
            print(f"  Already downloaded: {dest.name}")
            continue
        url = S3_BASE + fname.replace(" ", "%20")
        print(f"  Downloading {fname} ...")
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as resp, open(dest, "wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        print(f"  Saved {dest} ({dest.stat().st_size / 1e6:.1f} MB)")


def extract_infiltration(raw_dir: Path) -> pd.DataFrame:
    frames = []
    for fname in INFILTRATION_DAYS:
        path = raw_dir / fname.replace("_TrafficForML_CICFlowMeter", "")
        df = pd.read_csv(path, usecols=NEEDED_COLS, low_memory=False)
        df = df[df["Label"] == "Infilteration"].copy()
        print(f"  {path.name}: {len(df)} Infilteration rows")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def build_sessions(df: pd.DataFrame, sample_target: int, session_len: int,
                    start_session_id: int, seed: int) -> pd.DataFrame:
    rng = np.random.RandomState(seed)
    if len(df) > sample_target:
        idx = rng.choice(len(df), size=sample_target, replace=False)
        df = df.iloc[idx].copy()

    df["_ts"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.sort_values("_ts").reset_index(drop=True)

    out_rows = []
    n_sessions = 0
    base_time = pd.Timestamp("2026-02-28 00:00:00")
    for chunk_start in range(0, len(df), session_len):
        chunk = df.iloc[chunk_start:chunk_start + session_len]
        if len(chunk) < 3:
            continue
        sid = start_session_id + n_sessions
        n_sessions += 1
        for t, (_, row) in enumerate(chunk.iterrows()):
            out_row = {feat: float(row[COLUMN_MAP[feat]]) for feat in COLUMN_MAP}
            for feat in MISSING_FEATURES:
                out_row[feat] = 0.0
            out_row["session_id"] = sid
            out_row["timestamp"] = base_time + pd.Timedelta(seconds=(chunk_start + t) * 2)
            out_row["stage_label"] = "Lateral Movement"
            out_row["is_malicious"] = 1
            out_rows.append(out_row)

    new_df = pd.DataFrame(out_rows)
    new_df = new_df[FLOW_FEATURES + ["session_id", "timestamp", "stage_label", "is_malicious"]]
    bad = ~np.isfinite(new_df[FLOW_FEATURES].values)
    if bad.any():
        n_bad = bad.any(axis=1).sum()
        print(f"  Dropping {n_bad} rows with non-finite feature values")
        new_df = new_df[~bad.any(axis=1)].copy()
    print(f"  Built {len(new_df)} rows across {new_df['session_id'].nunique()} synthetic-boundary sessions")
    return new_df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default="data/raw_cicids2018")
    ap.add_argument("--target", default="real_flows.csv")
    ap.add_argument("--sample", type=int, default=8000, help="real rows to pull in (161,934 available)")
    ap.add_argument("--session-len", type=int, default=12)
    ap.add_argument("--start-session-id", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-download", action="store_true")
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir)
    if not args.skip_download:
        print("Downloading CIC-IDS2018 Infiltration-day CSVs...")
        download(raw_dir)

    print("Extracting Infiltration rows...")
    infil = extract_infiltration(raw_dir)
    print(f"Total available: {len(infil)}")

    print(f"Sampling to {args.sample} and chunking into sessions...")
    new_df = build_sessions(infil, args.sample, args.session_len, args.start_session_id, args.seed)

    target_path = Path(args.target)
    existing = pd.read_csv(target_path, parse_dates=["timestamp"])
    print(f"Existing {target_path}: {existing.shape}, session_id range "
          f"{existing['session_id'].min()}-{existing['session_id'].max()}")
    assert new_df["session_id"].min() > existing["session_id"].max(), "session_id collision!"

    backup_path = target_path.with_suffix(target_path.suffix + ".pre_cicids2018_backup")
    if not backup_path.exists():
        existing.to_csv(backup_path, index=False)
        print(f"Backed up original to {backup_path}")

    merged = pd.concat([existing, new_df], ignore_index=True)
    merged.to_csv(target_path, index=False)
    print(f"Merged {target_path}: {merged.shape}")
    print(merged["stage_label"].value_counts())


if __name__ == "__main__":
    main()

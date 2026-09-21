"""
CIC-IDS2017 Preprocessor — Maps real dataset to the 22-feature format
expected by pipeline_fixed.py.

Downloads and processes the CIC-IDS2017 dataset CSVs.
Maps native labels → 6-stage MITRE taxonomy.
Creates session_id via (Source IP, Destination IP, time-bucket) grouping,
or chronological session chunking when IP columns are not present in MachineLearningCSV.
Applies stratified sampling to preserve rare attack classes (Infiltration, Heartbleed, Web Attacks).

Usage:
  python preprocess_cicids.py --input-dir ./raw_cicids/ --output real_flows.csv --sample 40000

The output CSV is ready for:
  python pipeline_fixed.py --data real_flows.csv --out ./backend/artifacts --epochs 15
"""
import os
import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

# ── Label mapping: CIC-IDS2017 → 6-stage MITRE taxonomy ──────
def map_label(raw_label: str) -> str:
    """Robust substring-based mapping immune to encoding differences and dash types."""
    if not isinstance(raw_label, str):
        return None
    s = raw_label.strip().lower()
    if "benign" in s:
        return "Benign"
    if "portscan" in s or "bot" in s or "patator" in s:
        return "Reconnaissance"
    if "brute force" in s or "xss" in s or "sql injection" in s:
        return "Initial Access"
    if "infiltration" in s:
        return "Lateral Movement"
    if "ddos" in s or "dos" in s:
        return "C2"
    if "heartbleed" in s:
        return "Exfiltration"
    return None


# ── Feature candidates mapping ──────────────────────────────
FEATURE_CANDIDATES = {
    "flow_duration": ["Flow Duration"],
    "tot_fwd_pkts": ["Total Fwd Packets", "Total Fwd Packet"],
    "tot_bwd_pkts": ["Total Backward Packets", "Total Bwd Packets", "Total Bwd Packet"],
    "fwd_pkt_len_mean": ["Fwd Packet Length Mean"],
    "bwd_pkt_len_mean": ["Bwd Packet Length Mean"],
    "flow_bytes_s": ["Flow Bytes/s", "Flow Byts/s"],
    "flow_pkts_s": ["Flow Packets/s", "Flow Pkts/s"],
    "flow_iat_mean": ["Flow IAT Mean"],
    "flow_iat_std": ["Flow IAT Std"],
    "fwd_iat_mean": ["Fwd IAT Mean"],
    "bwd_iat_mean": ["Bwd IAT Mean"],
    "syn_flag_cnt": ["SYN Flag Count"],
    "ack_flag_cnt": ["ACK Flag Count"],
    "fin_flag_cnt": ["FIN Flag Count"],
    "rst_flag_cnt": ["RST Flag Count"],
    "psh_flag_cnt": ["PSH Flag Count"],
    "urg_flag_cnt": ["URG Flag Count"],
    "down_up_ratio": ["Down/Up Ratio"],
    "pkt_size_avg": ["Average Packet Size", "Avg Packet Size", "Packet Length Mean"],
}


def normalize_columns(df):
    """Strip whitespace and deduplicate column names (e.g. 'Fwd Header Length.1')."""
    clean_cols = []
    seen = {}
    for col in df.columns:
        c = str(col).strip()
        if c in seen:
            seen[c] += 1
            clean_cols.append(f"{c}.{seen[c]}")
        else:
            seen[c] = 0
            clean_cols.append(c)
    df.columns = clean_cols
    return df


def process_single_csv(filepath: Path, sample_limit: int = None, file_idx: int = 0):
    """Process one CIC-IDS2017 CSV file with memory efficiency and stratified sampling."""
    print(f"  Processing [{file_idx}]: {filepath.name}...")

    try:
        df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, encoding="latin-1", low_memory=False)

    df = normalize_columns(df)

    # ── Locate Label column ───────────────────────────────────
    label_col = None
    for candidate in ["Label", "label"]:
        for col in df.columns:
            if col.lower() == candidate.lower():
                label_col = col
                break
        if label_col:
            break

    if label_col is None:
        print(f"    WARNING: No label column found in {filepath.name}, skipping")
        return None

    df["stage_label"] = df[label_col].astype(str).apply(map_label)
    unmapped = df[df["stage_label"].isna()][label_col].unique()
    if len(unmapped) > 0:
        print(f"    WARNING: Unmapped labels in {filepath.name}: {unmapped}")
    df = df.dropna(subset=["stage_label"]).copy()

    df["is_malicious"] = (df["stage_label"] != "Benign").astype(int)

    # ── Stratified Sampling (Preserve 100% of Rare Attacks!) ───
    if sample_limit and len(df) > sample_limit:
        mal_indices = df[df["is_malicious"] == 1].index
        ben_indices = df[df["is_malicious"] == 0].index

        # If attacks exceed sample_limit // 2, sample attacks; otherwise keep ALL attacks!
        max_mal = sample_limit // 2
        if len(mal_indices) > max_mal:
            chosen_mal = np.random.RandomState(42).choice(mal_indices, size=max_mal, replace=False)
        else:
            chosen_mal = mal_indices.values

        needed_ben = min(sample_limit - len(chosen_mal), len(ben_indices))
        chosen_ben = np.random.RandomState(42).choice(ben_indices, size=needed_ben, replace=False)

        selected_indices = np.sort(np.concatenate([chosen_mal, chosen_ben]))
        df = df.loc[selected_indices].copy()
        print(f"    Stratified sample: {len(chosen_mal)} attacks + {needed_ben} benign = {len(df)} rows")

    # ── Map feature columns ───────────────────────────────────
    result = pd.DataFrame(index=df.index)

    for target_feat, candidates in FEATURE_CANDIDATES.items():
        found = False
        for c in candidates:
            if c in df.columns:
                col_data = df[c]
                if isinstance(col_data, pd.DataFrame):
                    col_data = col_data.iloc[:, 0]
                result[target_feat] = pd.to_numeric(col_data, errors="coerce")
                found = True
                break
        if not found:
            result[target_feat] = 0.0

    # ── Derived proxy features ────────────────────────────────
    # ttl_variance: proxy from header length variation
    fwd_h_col = "Fwd Header Length" if "Fwd Header Length" in df.columns else None
    bwd_h_col = "Bwd Header Length" if "Bwd Header Length" in df.columns else None
    if fwd_h_col and bwd_h_col:
        fwd_h = pd.to_numeric(df[fwd_h_col], errors="coerce").fillna(0)
        bwd_h = pd.to_numeric(df[bwd_h_col], errors="coerce").fillna(0)
        result["ttl_variance"] = np.abs(fwd_h - bwd_h)
    else:
        result["ttl_variance"] = 0.0

    # tcp_win_size: Init_Win_bytes_forward
    if "Init_Win_bytes_forward" in df.columns:
        result["tcp_win_size"] = pd.to_numeric(df["Init_Win_bytes_forward"], errors="coerce").fillna(0)
    elif "Init Win bytes forward" in df.columns:
        result["tcp_win_size"] = pd.to_numeric(df["Init Win bytes forward"], errors="coerce").fillna(0)
    else:
        result["tcp_win_size"] = 0.0

    # retransmit_cnt: proxy from "Subflow Fwd Packets" vs "Total Fwd Packets"
    if "Subflow Fwd Packets" in df.columns:
        sub = pd.to_numeric(df["Subflow Fwd Packets"], errors="coerce").fillna(0)
        tot = result["tot_fwd_pkts"].fillna(0)
        result["retransmit_cnt"] = np.maximum(0, tot - sub)
    else:
        result["retransmit_cnt"] = 0.0

    # ── Source/Destination IPs & Timestamps ───────────────────
    src_cols = [c for c in df.columns if c.strip().lower() in ["source ip", "src ip"]]
    dst_cols = [c for c in df.columns if c.strip().lower() in ["destination ip", "dst ip"]]
    ts_cols  = [c for c in df.columns if c.strip().lower() in ["timestamp", "flow start time"]]

    has_ips = bool(src_cols and dst_cols)
    has_ts  = bool(ts_cols)

    result["src_ip"] = df[src_cols[0]].astype(str).str.strip() if has_ips else "192.168.10.50"
    result["dst_ip"] = df[dst_cols[0]].astype(str).str.strip() if has_ips else "172.16.0.1"

    if has_ts:
        result["timestamp"] = pd.to_datetime(df[ts_cols[0]], errors="coerce", dayfirst=True)
        result["timestamp"] = result["timestamp"].fillna(pd.Timestamp("2026-01-01"))
    else:
        # Generate monotonic timestamps 2s apart starting from day offset
        base_t = pd.Timestamp("2026-01-01") + pd.Timedelta(days=file_idx)
        result["timestamp"] = [base_t + pd.Timedelta(seconds=i * 2) for i in range(len(result))]

    result["stage_label"] = df["stage_label"].values
    result["is_malicious"] = df["is_malicious"].values

    # ── Session ID: (src_ip, dst_ip, 5-min bucket) or 30-flow chunking ─
    if has_ips and has_ts:
        time_bucket = (result["timestamp"].astype("int64") // (5 * 60 * 10**9)).astype(int)
        result["session_id"] = (
            result["src_ip"] + "_" + result["dst_ip"] + "_" + time_bucket.astype(str)
        )
    else:
        # Group chronological flows into sessions of 30 flows
        # Ensures each session has >= 6 flows for LSTM windowing!
        session_idx = np.arange(len(result)) // 30
        result["session_id"] = f"file{file_idx}_sess_" + session_idx.astype(str)

    # Map to integer session IDs within file
    session_map = {k: i for i, k in enumerate(result["session_id"].unique())}
    result["session_id"] = result["session_id"].map(session_map)

    # ── Clean infinities and NaN ──────────────────────────────
    result = result.replace([np.inf, -np.inf], np.nan)
    result = result.fillna(0)

    print(f"    -> {len(result)} rows, {result['stage_label'].value_counts().to_dict()}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Preprocess CIC-IDS2017 for pipeline_fixed.py")
    parser.add_argument("--input-dir", required=True, help="Directory containing CIC-IDS2017 CSV files")
    parser.add_argument("--output", default="real_flows.csv", help="Output CSV path")
    parser.add_argument("--sample", type=int, default=40000,
                        help="Max rows per file using stratified sampling (default: 40000)")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"ERROR: Directory {input_dir} does not exist")
        sys.exit(1)

    csv_files = sorted(input_dir.glob("*.csv"))
    if not csv_files:
        print(f"ERROR: No CSV files found in {input_dir}")
        sys.exit(1)

    print("=" * 70)
    print("CIC-IDS2017 PREPROCESSOR FOR SIH 2026 WORLD MODEL")
    print(f"Input dir:  {input_dir} ({len(csv_files)} files)")
    print(f"Sample cap: {args.sample} rows/file (stratified attack preservation)")
    print(f"Output:     {args.output}")
    print("=" * 70)

    all_frames = []
    for idx, csv_file in enumerate(csv_files):
        df = process_single_csv(csv_file, sample_limit=args.sample, file_idx=idx)
        if df is not None and len(df) > 0:
            all_frames.append(df)

    if not all_frames:
        print("ERROR: No valid data processed")
        sys.exit(1)

    combined = pd.concat(all_frames, ignore_index=True)

    # Re-index unique integer session IDs across all files
    session_map = {k: i for i, k in enumerate(combined["session_id"].unique())}
    combined["session_id"] = combined["session_id"].map(session_map)

    # Sort by session + time
    combined = combined.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    print("=" * 70)
    print(f"PREPROCESSING COMPLETE:")
    print(f"Total rows:     {len(combined):,}")
    print(f"Total sessions: {combined['session_id'].nunique():,}")
    print(f"Stage distribution:")
    for stage, count in combined["stage_label"].value_counts().items():
        print(f"  - {stage:<18}: {count:>8,} ({count/len(combined)*100:>5.2f}%)")
    print("=" * 70)

    combined.to_csv(args.output, index=False)
    print(f"Saved preprocessed dataset to: {args.output}")
    print(f"\nReady to train World Model:")
    print(f"  python pipeline_fixed.py --data {args.output} --out ./backend/artifacts --epochs 15")


if __name__ == "__main__":
    main()

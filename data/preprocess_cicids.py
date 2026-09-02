"""
CIC-IDS2017 Preprocessor — Maps real dataset to the 22-feature format
expected by pipeline_fixed.py.

Downloads and processes the CIC-IDS2017 dataset CSVs.
Maps native labels → 6-stage MITRE taxonomy.
Creates session_id via (Source IP, Destination IP, time-bucket) grouping.

Usage:
  python preprocess_cicids.py --input-dir ./raw_cicids/ --output real_flows.csv

The output CSV is ready for:
  python pipeline_fixed.py --data real_flows.csv --out ./outputs --epochs 15
"""
import os
import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import timedelta

# ── Label mapping: CIC-IDS2017 → 6-stage MITRE taxonomy ──────
LABEL_MAP = {
    # Benign
    "BENIGN": "Benign",

    # Reconnaissance — scanning/probing activity
    "PortScan": "Reconnaissance",
    "Bot": "Reconnaissance",
    "FTP-Patator": "Reconnaissance",
    "SSH-Patator": "Reconnaissance",

    # Initial Access — exploitation attempts
    "Web Attack – Brute Force": "Initial Access",
    "Web Attack \x96 Brute Force": "Initial Access",  # encoding variant
    "Web Attack – XSS": "Initial Access",
    "Web Attack \x96 XSS": "Initial Access",
    "Web Attack – Sql Injection": "Initial Access",
    "Web Attack \x96 Sql Injection": "Initial Access",

    # Lateral Movement — post-exploitation spreading
    "Infiltration": "Lateral Movement",

    # C2 — denial/disruption patterns (closest behavioral match)
    "DDoS": "C2",
    "DoS Hulk": "C2",
    "DoS GoldenEye": "C2",
    "DoS slowloris": "C2",
    "DoS Slowhttptest": "C2",

    # Exfiltration — data extraction
    "Heartbleed": "Exfiltration",
}

# ── Column mapping: CIC-IDS2017 columns → your 22 features ───
# Some features have direct equivalents; 3 are derived proxies
COLUMN_MAP = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "flow_bytes_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "fwd_iat_mean": "Fwd IAT Mean",
    "bwd_iat_mean": "Bwd IAT Mean",
    "syn_flag_cnt": "SYN Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "fin_flag_cnt": "FIN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    # ── Derived proxy features (documented limitation) ────────
    # ttl_variance: not in CIC-IDS2017. Proxy: variance of Fwd/Bwd Header Length
    # tcp_win_size: not directly. Proxy: Init_Win_bytes_forward
    # retransmit_cnt: not directly. Proxy: Fwd Header Length variations
}

# CIC-IDS2017 column names have inconsistent spacing/capitalization.
# This function normalizes them.
def normalize_columns(df):
    """Strip whitespace from column names (CIC-IDS2017 has trailing spaces)."""
    df.columns = df.columns.str.strip()
    return df


def process_single_csv(filepath):
    """Process one CIC-IDS2017 CSV file."""
    print(f"  Processing: {filepath.name}...")

    try:
        df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, encoding="latin-1", low_memory=False)

    df = normalize_columns(df)

    # ── Map label column ──────────────────────────────────────
    label_col = None
    for candidate in ["Label", " Label", "label"]:
        if candidate.strip() in [c.strip() for c in df.columns]:
            label_col = [c for c in df.columns if c.strip() == candidate.strip()][0]
            break

    if label_col is None:
        print(f"    WARNING: No label column found in {filepath.name}, skipping")
        return None

    df["stage_label"] = df[label_col].str.strip().map(LABEL_MAP)
    unmapped = df[df["stage_label"].isna()][label_col].unique()
    if len(unmapped) > 0:
        print(f"    WARNING: Unmapped labels: {unmapped}")
    df = df.dropna(subset=["stage_label"])

    df["is_malicious"] = (df["stage_label"] != "Benign").astype(int)

    # ── Map feature columns ───────────────────────────────────
    result = pd.DataFrame()

    for target_feat, source_col in COLUMN_MAP.items():
        if source_col in df.columns:
            result[target_feat] = pd.to_numeric(df[source_col], errors="coerce")
        else:
            print(f"    WARNING: Column '{source_col}' not found, filling with 0")
            result[target_feat] = 0.0

    # ── Derived proxy features ────────────────────────────────
    # ttl_variance: proxy from header length variation
    if "Fwd Header Length" in df.columns and "Bwd Header Length" in df.columns:
        fwd_h = pd.to_numeric(df["Fwd Header Length"], errors="coerce").fillna(0)
        bwd_h = pd.to_numeric(df["Bwd Header Length"], errors="coerce").fillna(0)
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

    # ── Source/Destination IPs ────────────────────────────────
    src_col = [c for c in df.columns if c.strip().lower() in ["source ip", "src ip"]]
    dst_col = [c for c in df.columns if c.strip().lower() in ["destination ip", "dst ip"]]

    result["src_ip"] = df[src_col[0]].str.strip() if src_col else "unknown"
    result["dst_ip"] = df[dst_col[0]].str.strip() if dst_col else "unknown"

    # ── Timestamp ─────────────────────────────────────────────
    ts_col = [c for c in df.columns if c.strip().lower() in ["timestamp", "flow start time"]]
    if ts_col:
        result["timestamp"] = pd.to_datetime(df[ts_col[0]], errors="coerce", dayfirst=True)
    else:
        result["timestamp"] = pd.Timestamp.now()

    result["stage_label"] = df["stage_label"].values
    result["is_malicious"] = df["is_malicious"].values

    # ── Session ID: (src_ip, dst_ip, 5-min bucket) ───────────
    if result["timestamp"].notna().any():
        result["time_bucket"] = (
            result["timestamp"].astype("int64") // (5 * 60 * 1e9)
        ).astype(int)
    else:
        result["time_bucket"] = 0

    result["session_id"] = (
        result["src_ip"].astype(str) + "_" +
        result["dst_ip"].astype(str) + "_" +
        result["time_bucket"].astype(str)
    )
    # Map to integer session IDs for pipeline_fixed.py compatibility
    session_map = {k: i for i, k in enumerate(result["session_id"].unique())}
    result["session_id"] = result["session_id"].map(session_map)

    # ── Clean infinities and NaN ──────────────────────────────
    result = result.replace([np.inf, -np.inf], np.nan)
    result = result.fillna(0)

    # Drop the helper column
    result = result.drop(columns=["time_bucket"], errors="ignore")

    print(f"    → {len(result)} rows, {result['stage_label'].value_counts().to_dict()}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Preprocess CIC-IDS2017 for pipeline_fixed.py")
    parser.add_argument("--input-dir", required=True, help="Directory containing CIC-IDS2017 CSV files")
    parser.add_argument("--output", default="real_flows.csv", help="Output CSV path")
    parser.add_argument("--sample", type=int, default=None,
                        help="Random sample N rows per file (for quick testing)")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"ERROR: Directory {input_dir} does not exist")
        sys.exit(1)

    csv_files = sorted(input_dir.glob("*.csv"))
    if not csv_files:
        print(f"ERROR: No CSV files found in {input_dir}")
        sys.exit(1)

    print(f"Found {len(csv_files)} CSV files in {input_dir}")
    print("=" * 60)

    all_frames = []
    for csv_file in csv_files:
        df = process_single_csv(csv_file)
        if df is not None:
            if args.sample:
                df = df.sample(min(args.sample, len(df)), random_state=42)
            all_frames.append(df)

    if not all_frames:
        print("ERROR: No valid data processed")
        sys.exit(1)

    combined = pd.concat(all_frames, ignore_index=True)

    # Re-index session IDs across all files
    session_map = {k: i for i, k in enumerate(combined["session_id"].unique())}
    combined["session_id"] = combined["session_id"].map(session_map)

    # Sort by session + time
    combined = combined.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    print("=" * 60)
    print(f"Total rows: {len(combined)}")
    print(f"Total sessions: {combined['session_id'].nunique()}")
    print(f"Stage distribution:")
    for stage, count in combined["stage_label"].value_counts().items():
        print(f"  {stage}: {count} ({count/len(combined)*100:.1f}%)")

    combined.to_csv(args.output, index=False)
    print(f"\nSaved to {args.output}")
    print(f"\nNext step:")
    print(f"  python pipeline_fixed.py --data {args.output} --out ./outputs --epochs 15")


if __name__ == "__main__":
    main()

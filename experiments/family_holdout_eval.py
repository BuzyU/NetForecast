"""
Family-holdout generalization test for SIH PS26153.

Why: the PS's evaluation methodology calls for demonstrating "transfer to
unseen malware" -- i.e. does the model generalize to attack TOOLS/VARIANTS it
never saw during training, or has it just memorized per-tool signatures?
The production pipeline's train/val/test split (pipeline_fixed.py) is random
at the session level, which doesn't test this at all: DoS Hulk sessions in
train and DoS Hulk sessions in test look statistically identical.

This script holds out one entire attack FAMILY per MITRE stage -- entirely
absent from training -- and measures whether a freshly trained model still
correctly classifies it at test time. This is a standalone, additive
experiment: it does NOT touch backend/artifacts/ (the shipped production
model) or real_flows.csv. Results are reported in docs/model_card.md.

Held-out families (chosen to be a genuinely different technique from what's
left in train, not just a same-tool variant):
  - Reconnaissance: "Bot" (botnet beaconing) held out; trained on
    PortScan + FTP-Patator + SSH-Patator (active scanning / credential
    brute-force -- a different sub-technique).
  - Initial Access: "Web Attack (XSS)" held out; trained on Web Attack
    (Brute Force) + Web Attack (SQL Injection).
  - C2: "DoS slowloris" (low-and-slow) held out; trained on DoS Hulk +
    DoS GoldenEye + DoS Slowhttptest + DDoS (mostly volumetric floods --
    slowloris is a meaningfully different behavioral pattern).
  - Lateral Movement / Exfiltration: skipped -- CIC-IDS2017 only has one
    real family for each (Infiltration, Heartbleed), so there is nothing
    to hold out that leaves a non-empty training family for that stage.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data.preprocess_cicids import FEATURE_CANDIDATES, normalize_columns  # noqa: E402
from pipeline_fixed import (  # noqa: E402
    DEVICE,
    STAGE2ID,
    STAGES,
    FlowSeqDataset,
    FocalLoss,
    WorldModel,
    compute_metrics,
    three_way_split,
)

RAW_DIR = Path("data/raw_cicids")
SEED = 42
WINDOW = 6
FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]
assert len(FLOW_FEATURES) == 22 and len(set(FLOW_FEATURES)) == 22

FILES_AND_LABELS = {
    "Wednesday-workingHours.pcap_ISCX.csv": {
        "BENIGN": ("Benign", "Benign"),
        "DoS Hulk": ("C2", "DoS Hulk"),
        "DoS GoldenEye": ("C2", "DoS GoldenEye"),
        "DoS Slowhttptest": ("C2", "DoS Slowhttptest"),
        "DoS slowloris": ("C2", "DoS slowloris"),
    },
    "Tuesday-WorkingHours.pcap_ISCX.csv": {
        "BENIGN": ("Benign", "Benign"),
        "FTP-Patator": ("Reconnaissance", "FTP-Patator"),
        "SSH-Patator": ("Reconnaissance", "SSH-Patator"),
    },
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": {
        "BENIGN": ("Benign", "Benign"),
        "Bot": ("Reconnaissance", "Bot"),
    },
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": {
        "BENIGN": ("Benign", "Benign"),
        "PortScan": ("Reconnaissance", "PortScan"),
    },
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": {
        "BENIGN": ("Benign", "Benign"),
        "DDoS": ("C2", "DDoS"),
    },
}
WEBATTACK_FILE = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"

HELD_OUT_FAMILIES = {"DoS slowloris", "Bot", "Web Attack XSS"}

BENIGN_CAP_PER_FILE = 15000


def load_and_map(filepath: Path, label_map: dict) -> pd.DataFrame:
    try:
        df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, encoding="latin-1", low_memory=False)
    df = normalize_columns(df)

    label_col = next((c for c in ["Label", " Label"] if c in df.columns), None)
    if label_col is None:
        label_col = [c for c in df.columns if c.strip() == "Label"][0]
    raw_labels = df[label_col].astype(str).str.strip()

    if filepath.name == WEBATTACK_FILE:
        def classify(s):
            if s == "BENIGN":
                return ("Benign", "Benign")
            if "Brute Force" in s:
                return ("Initial Access", "Web Attack Brute Force")
            if "XSS" in s:
                return ("Initial Access", "Web Attack XSS")
            if "Sql Injection" in s:
                return ("Initial Access", "Web Attack SQL Injection")
            return None
        mapped = raw_labels.apply(classify)
    else:
        mapped = raw_labels.map(label_map.get)

    df = df[mapped.notna()].copy()
    mapped = mapped[mapped.notna()]
    df["stage_label"] = [m[0] for m in mapped]
    df["family_label"] = [m[1] for m in mapped]

    df = df.reset_index(drop=True)
    df["_session_key"] = (np.arange(len(df)) // 30).astype(str) + "_" + filepath.name
    df["_ts"] = np.arange(len(df))

    if BENIGN_CAP_PER_FILE:
        benign_mask = df["stage_label"] == "Benign"
        benign_sessions = df.loc[benign_mask, "_session_key"].unique()
        rng = np.random.RandomState(SEED)
        shuffled_sessions = rng.permutation(benign_sessions)
        session_sizes = df.loc[benign_mask].groupby("_session_key").size()
        keep_sessions, running_total = [], 0
        for sid in shuffled_sessions:
            if running_total >= BENIGN_CAP_PER_FILE:
                break
            keep_sessions.append(sid)
            running_total += session_sizes[sid]
        keep_mask = benign_mask & df["_session_key"].isin(keep_sessions)
        df = df[keep_mask | ~benign_mask].copy()

    result = pd.DataFrame()
    for target_feat, candidates in FEATURE_CANDIDATES.items():
        col = next((c for c in candidates if c in df.columns), None)
        result[target_feat] = pd.to_numeric(df[col], errors="coerce").fillna(0.0) if col else 0.0

    result["ttl_variance"] = 0.0
    result["tcp_win_size"] = pd.to_numeric(
        df.get("Init_Win_bytes_forward", 0.0), errors="coerce"
    ).fillna(0.0)
    result["retransmit_cnt"] = 0.0

    missing = set(FLOW_FEATURES) - set(result.columns)
    assert not missing, f"load_and_map produced columns missing {missing}"
    result = result[FLOW_FEATURES]

    result = result.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    result["session_key"] = df["_session_key"].values
    result["timestamp"] = df["_ts"].values
    result["stage_label"] = df["stage_label"].values
    result["family_label"] = df["family_label"].values
    result["is_malicious"] = (result["stage_label"] != "Benign").astype(int)
    result["file"] = filepath.name
    return result


def main():
    frames = []
    for fname, label_map in FILES_AND_LABELS.items():
        path = RAW_DIR / fname
        if not path.exists():
            print(f"SKIP (not found): {path}")
            continue
        print(f"Loading {fname} ...")
        frames.append(load_and_map(path, label_map))
    web_path = RAW_DIR / WEBATTACK_FILE
    if web_path.exists():
        print(f"Loading {WEBATTACK_FILE} ...")
        frames.append(load_and_map(web_path, {}))

    df = pd.concat(frames, ignore_index=True)
    print(f"Combined shape: {df.shape}")
    print("Family distribution:\n", df["family_label"].value_counts().to_string())

    session_map = {k: i for i, k in enumerate(df["session_key"].unique())}
    df["session_id"] = df["session_key"].map(session_map)

    holdout_mask = df["family_label"].isin(HELD_OUT_FAMILIES)
    holdout_df = df[holdout_mask].copy()
    rest_df = df[~holdout_mask].copy()
    print(f"\nHeld-out family rows (excluded from train/val entirely): {len(holdout_df)}")
    print(holdout_df["family_label"].value_counts().to_string())
    print(f"Remaining rows for normal train/val/test split: {len(rest_df)}")

    rest_sids = rest_df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(rest_sids, val_size=0.1, test_size=0.2, random_state=SEED)
    train_df = rest_df[rest_df["session_id"].isin(train_sids)].copy()
    val_df = rest_df[rest_df["session_id"].isin(val_sids)].copy()
    test_df = rest_df[rest_df["session_id"].isin(test_sids)].copy()
    print(f"Sessions: train={len(train_sids)} val={len(val_sids)} test={len(test_sids)}  "
          f"(rows: train={len(train_df)} val={len(val_df)} test={len(test_df)})")

    from pipeline_fixed import StandardScaler
    scaler = StandardScaler()
    train_df[FLOW_FEATURES] = scaler.fit_transform(train_df[FLOW_FEATURES])
    val_df[FLOW_FEATURES] = scaler.transform(val_df[FLOW_FEATURES])
    test_df[FLOW_FEATURES] = scaler.transform(test_df[FLOW_FEATURES])
    holdout_df[FLOW_FEATURES] = scaler.transform(holdout_df[FLOW_FEATURES])

    for d in (train_df, val_df, test_df, holdout_df):
        d["stage_id"] = d["stage_label"].map(STAGE2ID)

    def sort_and_seq(d):
        d = d.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
        return build_sequences(d, window=WINDOW)

    def build_sequences(d, window=WINDOW):
        X, yn, ym, ys = [], [], [], []
        for _sid, g in d.groupby("session_id"):
            feats = g[FLOW_FEATURES].values
            mal = g["is_malicious"].values
            stage = g["stage_id"].values
            for i in range(len(g) - window):
                X.append(feats[i:i + window])
                yn.append(feats[i + window])
                ym.append(mal[i + window])
                ys.append(stage[i + window])
        if not X:
            n_feat = len(FLOW_FEATURES)
            return (np.zeros((0, window, n_feat), dtype=np.float32), np.zeros((0, n_feat), dtype=np.float32),
                    np.zeros((0,), dtype=np.float32), np.zeros((0,), dtype=np.int64))
        return (np.array(X, dtype=np.float32), np.array(yn, dtype=np.float32),
                np.array(ym, dtype=np.float32), np.array(ys, dtype=np.int64))

    X_train, yn_train, ym_train, ys_train = sort_and_seq(train_df)
    X_val, yn_val, ym_val, ys_val = sort_and_seq(val_df)
    X_test, yn_test, ym_test, ys_test = sort_and_seq(test_df)
    print(f"\nTrain sequences: {X_train.shape}  Val: {X_val.shape}  Test: {X_test.shape}")

    X_hold, yn_hold, ym_hold, ys_hold, fam_hold = [], [], [], [], []
    for fam, g in holdout_df.groupby("family_label"):
        Xh, ynh, ymh, ysh = sort_and_seq(g)
        X_hold.append(Xh); yn_hold.append(ynh); ym_hold.append(ymh); ys_hold.append(ysh)
        fam_hold.extend([fam] * len(Xh))
    X_hold = np.concatenate(X_hold) if X_hold else np.zeros((0, WINDOW, len(FLOW_FEATURES)), dtype=np.float32)
    ym_hold = np.concatenate(ym_hold) if ym_hold else np.zeros((0,), dtype=np.float32)
    ys_hold = np.concatenate(ys_hold) if ys_hold else np.zeros((0,), dtype=np.int64)
    print(f"Held-out family sequences: {X_hold.shape}")
    if len(X_hold) == 0:
        print("ERROR: no held-out sequences built (families too small/short for window=6). Aborting.")
        return

    train_loader = DataLoader(FlowSeqDataset(X_train, yn_train, ym_train, ys_train), batch_size=128, shuffle=True)
    val_loader = DataLoader(FlowSeqDataset(X_val, yn_val, ym_val, ys_val), batch_size=128, shuffle=False)

    stage_counts = np.bincount(ys_train, minlength=len(STAGES))
    total = len(ys_train)
    raw_w = total / (len(STAGES) * np.maximum(stage_counts, 1).astype(np.float32))
    class_weights = torch.tensor(np.clip(raw_w, 0.2, 8.0), dtype=torch.float32).to(DEVICE)
    ce_loss = FocalLoss(alpha=class_weights, gamma=2.0)
    num_pos, num_neg = np.sum(ym_train == 1), np.sum(ym_train == 0)
    pos_weight = torch.tensor([float(num_neg) / max(float(num_pos), 1.0)], dtype=torch.float32).to(DEVICE)
    bce_loss = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    mse_loss = torch.nn.MSELoss()

    model = WorldModel(n_features=len(FLOW_FEATURES), hidden=256, num_layers=2, dropout=0.25).to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=15, eta_min=1e-5)

    best_val_f1, best_state = -1.0, None
    for epoch in range(15):
        model.train()
        for xb, yn_b, ym_b, ys_b in train_loader:
            xb, yn_b, ym_b, ys_b = xb.to(DEVICE), yn_b.to(DEVICE), ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pred_next, inf_logit, stage_logits = model(xb)
            loss = mse_loss(pred_next, yn_b) + bce_loss(inf_logit, ym_b) + ce_loss(stage_logits, ys_b)
            loss.backward()
            opt.step()
        model.eval()
        vp, vt = [], []
        with torch.no_grad():
            for xb, _, ym_b, _ in val_loader:
                _, inf_logit, _ = model(xb.to(DEVICE))
                vp.extend((torch.sigmoid(inf_logit).cpu().numpy() > 0.5).astype(int))
                vt.extend(ym_b.numpy().astype(int))
        vf1 = compute_metrics(np.array(vt), np.array(vp))["f1"]
        scheduler.step()
        print(f"Epoch {epoch+1:2d}/15 val_f1={vf1:.4f}")
        if vf1 > best_val_f1:
            best_val_f1 = vf1
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    model.eval()

    print("\n" + "=" * 70)
    print("FAMILY-HOLDOUT RESULTS (families NEVER seen during training)")
    print("=" * 70)
    with torch.no_grad():
        stage_logits_all, inf_logit_all = [], []
        for i in range(0, len(X_hold), 256):
            xb = torch.tensor(X_hold[i:i+256]).to(DEVICE)
            _, inf_l, stage_l = model(xb)
            stage_logits_all.append(stage_l.cpu())
            inf_logit_all.append(inf_l.cpu())
        stage_pred = torch.argmax(torch.cat(stage_logits_all), dim=1).numpy()
        inf_prob = torch.sigmoid(torch.cat(inf_logit_all)).numpy()

    fam_hold_arr = np.array(fam_hold)
    for fam in sorted(set(fam_hold)):
        mask = fam_hold_arr == fam
        n = mask.sum()
        true_stage_id = ys_hold[mask][0]
        true_stage = STAGES[true_stage_id]
        correct_stage = (stage_pred[mask] == true_stage_id).mean()
        alert_rate = (inf_prob[mask] > 0.5).mean()
        print(f"\n{fam} (true stage: {true_stage}, n={n}, NEVER in training data):")
        print(f"  Correct-stage rate: {correct_stage:.3f}")
        print(f"  Binary alert rate:  {alert_rate:.3f}")
        pred_dist = pd.Series([STAGES[s] for s in stage_pred[mask]]).value_counts()
        print(f"  Predicted-stage distribution:\n{pred_dist.to_string()}")


if __name__ == "__main__":
    main()

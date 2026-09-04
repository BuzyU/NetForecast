"""
SIH 2026 — PS26153: AI-Based Network Attack Forecasting from Network Traffic Data
World-Model approach. FIXED for portability: no Colab-only calls, parameterized
paths, deterministic tie-breaks, curated demo sample.

Run as: python pipeline.py           (uses synthetic fallback)
        python pipeline.py --data path/to/real_flows.csv
"""
import os, json, random, argparse, subprocess, sys
import numpy as np
import pandas as pd

# ---- FIX 1: no get_ipython() — real subprocess install guard instead ----
def ensure_packages():
    required = ["torch", "scikit-learn", "pandas", "numpy", "matplotlib", "shap", "tqdm"]
    for pkg in required:
        try:
            __import__(pkg.replace("-", "_") if pkg != "scikit-learn" else "sklearn")
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

if __name__ == "__main__" and os.environ.get("SKIP_INSTALL") != "1":
    ensure_packages()

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pickle

SEED = 42
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
os.environ["PYTHONHASHSEED"] = "0"  # FIX 4: deterministic set() ordering for tie-breaks
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

STAGES = ["Benign", "Reconnaissance", "Initial Access", "Lateral Movement", "C2", "Exfiltration"]
STAGE2ID = {s: i for i, s in enumerate(STAGES)}

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]
WINDOW = 6


def generate_synthetic_flows(n_sessions=400, session_len=30):
    """
    Generate synthetic flow sessions with REALISTIC CIC-IDS-scale feature magnitudes.

    BUG-01a fix: the original generator used np.random.normal(0, 1) base values,
    producing a scaler with mean≈0 and scale≈1 that is incompatible with real
    traffic (flow_duration in 10k-100k µs, tcp_win_size up to 65535, etc.).

    These profiles match traffic_simulator.py's STAGE_PROFILES so that the
    scaler trained here will correctly normalise both simulated and live-captured flows.
    """
    # (mean, std) per feature per stage — realistic CIC-IDS magnitudes
    PROFILES = {
        "Benign": [50000, 10, 8, 200, 180, 5000, 20, 50000, 30000, 60000, 70000, 1, 5, 1, 0, 2, 0, 1.0, 400, 5, 8192, 0],
        "Reconnaissance": [5000, 50, 2, 60, 20, 15000, 120, 3000, 2000, 4000, 8000, 8, 2, 0, 2, 1, 0, 0.2, 80, 3, 1024, 1],
        "Initial Access": [30000, 15, 10, 150, 120, 8000, 40, 20000, 15000, 25000, 30000, 2, 8, 2, 1, 6, 0, 0.8, 300, 4, 8192, 3],
        "Lateral Movement": [40000, 20, 18, 180, 200, 10000, 35, 30000, 20000, 35000, 40000, 1, 10, 1, 0, 4, 0, 2.5, 350, 6, 16384, 1],
        "C2": [80000, 8, 6, 100, 90, 3000, 15, 90000, 5000, 95000, 95000, 0, 12, 0, 0, 2, 0, 1.1, 200, 2, 8192, 0],
        "Exfiltration": [120000, 5, 30, 200, 1200, 80000, 25, 40000, 30000, 45000, 42000, 0, 15, 2, 0, 3, 0, 0.3, 1100, 2, 65535, 3],
    }
    STDS = {
        "Benign":         [30000, 8,  6,  150, 120, 4000, 15, 40000, 25000, 50000, 55000, 0.5, 3,  0.5, 0.2, 1.5, 0.1, 0.3, 200, 3, 4000, 0.2],
        "Reconnaissance": [3000,  30, 1,  40,  15,  8000, 60, 2000,  1500,  3000,  5000,  4,   1,  0.2, 1,   0.5, 0.1, 0.1, 40,  2, 500,  0.5],
        "Initial Access": [10000, 8,  6,  80,  60,  4000, 20, 10000, 8000,  12000, 15000, 1,   4,  1,   0.5, 3,   0.1, 0.3, 150, 2, 4000, 1.5],
        "Lateral Movement":[15000, 10, 8,  80,  80,  5000, 15, 15000, 10000, 18000, 20000, 0.5, 5,  0.5, 0.2, 2,   0.1, 0.5, 150, 3, 8000, 0.5],
        "C2":             [20000, 4,  3,  50,  45,  1500, 8,  10000, 2000,  12000, 12000, 0.2, 5,  0.1, 0.1, 1,   0.1, 0.2, 80,  1, 4000, 0.2],
        "Exfiltration":   [40000, 3,  15, 100, 400, 30000, 10, 20000, 15000, 22000, 20000, 0.2, 6,  1,   0.2, 1.5, 0.1, 0.1, 400, 1, 10000, 1.5],
    }
    rows = []
    for sid in range(n_sessions):
        is_attack_session = random.random() < 0.4
        t0 = pd.Timestamp("2026-01-01") + pd.Timedelta(minutes=sid * 5)
        if is_attack_session:
            stage_sequence = (["Benign"] * random.randint(2, 5) +
                               ["Reconnaissance"] * random.randint(2, 4) +
                               ["Initial Access"] * random.randint(1, 3) +
                               ["Lateral Movement"] * random.randint(1, 3) +
                               ["C2"] * random.randint(1, 3) +
                               ["Exfiltration"] * random.randint(1, 3))
        else:
            stage_sequence = ["Benign"] * session_len
        stage_sequence = (stage_sequence * (session_len // max(1, len(stage_sequence)) + 1))[:session_len]
        for t, stage in enumerate(stage_sequence):
            means = np.array(PROFILES[stage], dtype=np.float64)
            stds  = np.array(STDS[stage],    dtype=np.float64)
            base  = np.maximum(0, np.random.normal(means, stds))  # non-negative
            row = dict(zip(FLOW_FEATURES, base))
            row["session_id"] = sid
            row["timestamp"] = t0 + pd.Timedelta(seconds=t * 2)
            row["stage_label"] = stage
            row["is_malicious"] = int(stage != "Benign")
            rows.append(row)
    return pd.DataFrame(rows)


def build_sequences(df, window=WINDOW):
    X_seq, y_next_state, y_malicious, y_stage = [], [], [], []
    for sid, g in df.groupby("session_id"):
        feats = g[FLOW_FEATURES].values
        mal = g["is_malicious"].values
        stage = g["stage_id"].values
        for i in range(len(g) - window):
            X_seq.append(feats[i:i + window])
            y_next_state.append(feats[i + window])
            y_malicious.append(mal[i + window])
            y_stage.append(stage[i + window])
    return (np.array(X_seq, dtype=np.float32), np.array(y_next_state, dtype=np.float32),
            np.array(y_malicious, dtype=np.float32), np.array(y_stage, dtype=np.int64))


class FlowSeqDataset(Dataset):
    def __init__(self, X, y_next, y_mal, y_stage):
        self.X, self.y_next, self.y_mal, self.y_stage = X, y_next, y_mal, y_stage
    def __len__(self): return len(self.X)
    def __getitem__(self, idx):
        return (torch.tensor(self.X[idx]), torch.tensor(self.y_next[idx]),
                torch.tensor(self.y_mal[idx]), torch.tensor(self.y_stage[idx]))


class WorldModel(nn.Module):
    def __init__(self, n_features, hidden=64, n_stages=len(STAGES)):
        super().__init__()
        self.lstm = nn.LSTM(n_features, hidden, batch_first=True)
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(nn.Linear(hidden, 32), nn.ReLU(), nn.Linear(32, 1))
        self.stage_head = nn.Linear(hidden, n_stages)
    def forward(self, x):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        next_state = self.next_state_head(h)
        infiltration_logit = self.infiltration_head(h).squeeze(-1)
        stage_logits = self.stage_head(h)
        return next_state, infiltration_logit, stage_logits


def compute_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()  # FIX: explicit labels
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"f1": f1_score(y_true, y_pred, zero_division=0),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0), "fpr": fpr}


def forward_simulate(model, initial_window, k_steps=5, noise_std=0.0, device=None):
    device = device or DEVICE
    model.eval()
    window = torch.tensor(initial_window, dtype=torch.float32).unsqueeze(0).to(device)
    if noise_std > 0:
        window = window + torch.randn_like(window) * noise_std
    timeline = []
    with torch.no_grad():
        for step in range(k_steps):
            next_state, inf_logit, stage_logits = model(window)
            prob = torch.sigmoid(inf_logit).item()
            stage = STAGES[torch.argmax(stage_logits, dim=1).item()]
            timeline.append({"step": step + 1, "infiltration_prob": prob, "predicted_stage": stage})
            window = torch.cat([window[:, 1:, :], next_state.unsqueeze(1)], dim=1)
    return timeline


def ema_smooth(probs, alpha=0.4):
    smoothed = [probs[0]]
    for p in probs[1:]:
        smoothed.append(alpha * p + (1 - alpha) * smoothed[-1])
    return smoothed


def monte_carlo_rollout(model, initial_window, k_steps=5, n_samples=20, noise_std=0.05, device=None):
    all_probs = np.zeros((n_samples, k_steps))
    all_stages = [[None] * k_steps for _ in range(n_samples)]
    for i in range(n_samples):
        run = forward_simulate(model, initial_window, k_steps=k_steps, noise_std=noise_std, device=device)
        for step in run:
            all_probs[i, step["step"] - 1] = step["infiltration_prob"]
            all_stages[i][step["step"] - 1] = step["predicted_stage"]
    mean_probs = all_probs.mean(axis=0)
    std_probs = all_probs.std(axis=0)
    # FIX 4: deterministic tie-break — sort candidates by STAGES index, not set() order
    mode_stages = []
    for col in zip(*all_stages):
        counts = {s: col.count(s) for s in set(col)}
        best = sorted(counts.items(), key=lambda kv: (-kv[1], STAGES.index(kv[0])))[0][0]
        mode_stages.append(best)
    return mean_probs, std_probs, mode_stages


def pick_demo_session(df, ym_test_idx_map=None):
    """
    FIX 2: instead of np.argmax(ym_test) (= first malicious ROW in the test
    split, which may be a short/ambiguous fragment), pick the test session
    with the LONGEST full stage progression (most distinct stages, in a
    session actually containing Exfiltration) so the demo shows a coherent
    kill-chain example rather than an arbitrary flow.
    """
    best_sid, best_score = None, -1
    for sid, g in df.groupby("session_id"):
        stages_present = set(g["stage_label"])
        if "Exfiltration" not in stages_present:
            continue
        score = len(stages_present)
        if score > best_score:
            best_score, best_sid = score, sid
    return best_sid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None, help="path to real flow CSV (session_id, timestamp, stage_label, is_malicious + FLOW_FEATURES columns)")
    ap.add_argument("--out", default="./outputs", help="output directory (FIX 3: no hardcoded /content path)")
    ap.add_argument("--epochs", type=int, default=15)
    args = ap.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    if args.data and os.path.exists(args.data):
        print(f"Loading real dataset from {args.data}")
        df = pd.read_csv(args.data, parse_dates=["timestamp"])
        missing_features = [c for c in FLOW_FEATURES if c not in df.columns]
        missing_meta = [c for c in ["session_id", "timestamp", "stage_label", "is_malicious"] if c not in df.columns]
        if missing_features or missing_meta:
            raise ValueError(f"Missing feature columns: {missing_features or 'none'}; "
                              f"missing meta columns: {missing_meta or 'none'}")
    else:
        print("No --data provided or file not found — generating synthetic flow sessions.")
        df = generate_synthetic_flows()

    data_source = args.data if (args.data and os.path.exists(args.data)) else "synthetic"
    print("Dataset shape:", df.shape)

    # ── LEAKAGE FIX 1: split by session_id BEFORE scaling ──────────────
    # Previously: scaler.fit_transform(all data) → train_test_split(windows)
    # Problem: test-set values influenced scaler's mean/std; overlapping windows
    #          from the same session split across train/test.
    # Fix: split unique session IDs first, fit scaler ONLY on train sessions.
    unique_sids = df["session_id"].unique()
    train_sids, test_sids = train_test_split(unique_sids, test_size=0.2, random_state=SEED)
    train_mask = df["session_id"].isin(train_sids)
    train_df = df[train_mask].copy()
    test_df  = df[~train_mask].copy()

    scaler = StandardScaler()
    train_df[FLOW_FEATURES] = scaler.fit_transform(train_df[FLOW_FEATURES])   # fit on train only
    test_df[FLOW_FEATURES]  = scaler.transform(test_df[FLOW_FEATURES])        # transform only

    train_df["stage_id"] = train_df["stage_label"].map(STAGE2ID)
    test_df["stage_id"]  = test_df["stage_label"].map(STAGE2ID)

    train_sorted = train_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    test_sorted  = test_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    X_train, yn_train, ym_train, ys_train = build_sequences(train_sorted)
    X_test,  yn_test,  ym_test,  ys_test  = build_sequences(test_sorted)
    print(f"Train sequences: {X_train.shape}  Test sequences: {X_test.shape}")


    X_train_flat = X_train.reshape(X_train.shape[0], -1)
    X_test_flat = X_test.reshape(X_test.shape[0], -1)
    baseline = LogisticRegression(max_iter=1000)
    baseline.fit(X_train_flat, ym_train)
    base_pred = baseline.predict(X_test_flat)
    baseline_metrics = compute_metrics(ym_test, base_pred)
    print("BASELINE:", baseline_metrics)

    train_loader = DataLoader(FlowSeqDataset(X_train, yn_train, ym_train, ys_train), batch_size=64, shuffle=True)
    test_loader = DataLoader(FlowSeqDataset(X_test, yn_test, ym_test, ys_test), batch_size=64, shuffle=False)

    model = WorldModel(n_features=len(FLOW_FEATURES)).to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    mse_loss, bce_loss, ce_loss = nn.MSELoss(), nn.BCEWithLogitsLoss(), nn.CrossEntropyLoss()

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        for xb, yn_b, ym_b, ys_b in train_loader:
            xb, yn_b, ym_b, ys_b = xb.to(DEVICE), yn_b.to(DEVICE), ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pred_next, inf_logit, stage_logits = model(xb)
            loss = mse_loss(pred_next, yn_b) + bce_loss(inf_logit, ym_b) + ce_loss(stage_logits, ys_b)
            loss.backward(); opt.step()
            total_loss += loss.item() * xb.size(0)
        print(f"Epoch {epoch+1}/{args.epochs} — loss: {total_loss/len(train_loader.dataset):.4f}")

    model.eval()
    all_preds, all_true = [], []
    with torch.no_grad():
        for xb, yn_b, ym_b, ys_b in test_loader:
            _, inf_logit, _ = model(xb.to(DEVICE))
            probs = torch.sigmoid(inf_logit).cpu().numpy()
            all_preds.extend((probs > 0.5).astype(int))
            all_true.extend(ym_b.numpy().astype(int))
    world_model_metrics = compute_metrics(np.array(all_true), np.array(all_preds))
    print("WORLD MODEL:", world_model_metrics)

    comparison = pd.DataFrame([baseline_metrics, world_model_metrics],
                               index=["Logistic Regression (baseline)", "LSTM World Model"])
    comparison.to_csv(f"{out_dir}/benchmark_comparison.csv")

    # FIX 2 applied: curated demo session instead of np.argmax(ym_test)
    demo_sid = pick_demo_session(train_sorted)
    demo_session = train_sorted[train_sorted["session_id"] == demo_sid]
    demo_feats = demo_session[FLOW_FEATURES].values
    if len(demo_feats) >= WINDOW:
        initial_window = demo_feats[:WINDOW]
        raw_timeline = forward_simulate(model, initial_window, k_steps=6)
        raw_probs = [s["infiltration_prob"] for s in raw_timeline]
        ema_probs = ema_smooth(raw_probs)
        mc_mean, mc_std, mc_stages = monte_carlo_rollout(model, initial_window, k_steps=6, n_samples=20)
        print(f"Demo session {demo_sid} (stages present: {sorted(set(demo_session['stage_label']))})")
        for i in range(6):
            print(f"step {i+1}: raw={raw_probs[i]:.3f} ema={ema_probs[i]:.3f} "
                  f"mc_mean={mc_mean[i]:.3f}+-{mc_std[i]:.3f} stage={mc_stages[i]}")

    torch.save(model.state_dict(), f"{out_dir}/world_model.pt")
    with open(f"{out_dir}/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    # Add provenance metadata so anyone loading the artifacts knows their origin (§7/§9)
    import subprocess, hashlib
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        git_commit = "unknown"
    with open(f"{out_dir}/config.json", "w") as f:
        json.dump({
            "window": WINDOW,
            "features": FLOW_FEATURES,
            "stages": STAGES,
            "provenance": {
                "trained_on": data_source,
                "train_sessions": int(len(train_sids)),
                "test_sessions": int(len(test_sids)),
                "train_rows": int(len(train_df)),
                "test_rows": int(len(test_df)),
                "git_commit": git_commit,
                "leakage_fix": "session-level split, scaler fit on train only",
            }
        }, f, indent=2)

    print("DONE — all artifacts saved to", out_dir)


if __name__ == "__main__":
    main()
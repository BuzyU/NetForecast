# Model Card: NetForecast LSTM World Model (Project Garud)
**Smart India Hackathon 2026 // Problem Statement 26153**  
*Team Code 4 Change — Autonomous Network Attack Forecasting Engine*

---

## 1. Model Overview

- **Model Name:** NetForecast Multi-Task LSTM World Model
- **Model Architecture:** 2-Layer Recurrent LSTM with Multi-Head Transition & Hazard Output
- **Model Version:** 1.0.0
- **Input Dimension:** 22 CIC-IDS network flow features
- **Window Size ($W$):** 6 sequential flows per session window
- **Inference Runtime:** PyTorch 2.x (CPU / CUDA compatible)
- **Primary Objective:** Given a rolling window of network flow telemetry $X_{t-5:t} \in \mathbb{R}^{6 \times 22}$, forecast the probability of security compromise, classify the current MITRE ATT&CK stage, and autoregressively project future network states $k$ steps forward ($X_{t+1:t+k}$).

---

## 2. Architecture & Multi-Task Heads

```
                          ┌────────────────────────┐
                          │ Input Window [B, 6, 22]│
                          └───────────┬────────────┘
                                      │
                         ┌────────────▼───────────┐
                         │  2-Layer LSTM (h=128)  │
                         │  Dropout = 0.2         │
                         └────────────┬───────────┘
                                      │ Hidden State h_t [B, 128]
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
      ┌───────▼────────┐      ┌───────▼────────┐      ┌───────▼────────┐
      │ Next State Head│      │Infiltration Log│      │   Stage Head   │
      │ Linear(128, 22)│      │ Linear(128,64) │      │ Linear(128,64) │
      │                │      │ Linear(64, 32) │      │ Linear(64, 6)  │
      │                │      │ Linear(32, 1)  │      │                │
      └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
              │                       │                       │
              ▼                       ▼                       ▼
      [B, 22] Pred State      [B, 1] Hazard Logit     [B, 6] Stage Logits
```

1. **Next-State Transition Head ($f_{\text{next}}$):**
   - Projects hidden representation back to feature space $\mathbb{R}^{22}$.
   - Enables recursive rollout (World Model dynamics): $\hat{x}_{t+1}$ is fed back into the LSTM to simulate future telemetry trajectories up to $k=20$ steps.
2. **Infiltration Hazard Head ($f_{\text{infil}}$):**
   - 3-layer MLP with ReLU and Dropout yielding a single scalar logit $\to \sigma(z) \in [0, 1]$.
   - Represents the calibrated probability of host or service compromise.
3. **Stage Head ($f_{\text{stage}}$):**
   - 2-layer MLP yielding 6 unnormalized logits $\to \text{Softmax}(z) \in \Delta^5$.
   - Identifies the operational MITRE ATT&CK stage of the session.

---

## 3. MITRE ATT&CK 6-Stage Taxonomy

| Stage ID | Stage Name | MITRE Tactic | Representative CIC-IDS2017 Traffic |
|:---:|:---|:---|:---|
| **0** | **Benign** | Normal Baseline | HTTP, HTTPS, DNS, NTP, SSH management |
| **1** | **Reconnaissance** | TA0043 (Reconnaissance) | PortScan, Network sweeping, Host discovery |
| **2** | **Initial Access** | TA0001 (Initial Access) | SSH-Patator, FTP-Patator, Web vulnerability probes |
| **3** | **Lateral Movement** | TA0008 (Lateral Movement) | SMB exploit probes, Internal pivot flows |
| **4** | **C2 (Command & Control)**| TA0011 (Command & Control) | Botnet beacons, periodic command channels |
| **5** | **Exfiltration** | TA0010 (Exfiltration) | Large outbound byte bursts, HTTP data theft |

---

## 4. 22 Standardized CIC-IDS Flow Features

Feature order is strictly invariant across training, serialization, REST ingestion, and SHAP explainability:

```python
FLOW_FEATURES = [
    "flow_duration",      # Flow duration in microseconds
    "tot_fwd_pkts",       # Total forward packets
    "tot_bwd_pkts",       # Total backward packets
    "fwd_pkt_len_mean",   # Mean size of forward packets (bytes)
    "bwd_pkt_len_mean",   # Mean size of backward packets (bytes)
    "flow_bytes_s",       # Flow throughput in bytes/second
    "flow_pkts_s",        # Flow throughput in packets/second
    "flow_iat_mean",      # Mean inter-arrival time across flow
    "flow_iat_std",       # Standard deviation of inter-arrival time
    "fwd_iat_mean",       # Mean IAT of forward direction
    "bwd_iat_mean",       # Mean IAT of backward direction
    "syn_flag_cnt",       # SYN flag occurrences
    "ack_flag_cnt",       # ACK flag occurrences
    "fin_flag_cnt",       # FIN flag occurrences
    "rst_flag_cnt",       # RST flag occurrences
    "psh_flag_cnt",       # PSH flag occurrences
    "urg_flag_cnt",       # URG flag occurrences
    "down_up_ratio",      # Download to upload ratio
    "pkt_size_avg",       # Average packet size across flow
    "ttl_variance",       # Variance of IP Time-To-Live
    "tcp_win_size",       # TCP initial window size
    "retransmit_cnt",     # Retransmitted packet count
]
```

---

## 5. Training Dataset & Preprocessing

- **Source Corpus:** CIC-IDS2017 benchmark dataset (Tuesday, Wednesday, Thursday, Friday captures).
- **Sessionization:**
  - Grouped by `(src_ip, dst_ip, 300s_time_bucket)`.
  - Flows sequenced chronologically; sub-sequences sliced into sliding windows of length $W=6$.
- **Normalization:**
  - `StandardScaler` fitted on training split only (mean and variance preserved in `artifacts/scaler.pkl`).
  - Strict absence of test-set data leakage.
- **Handling Class Imbalance:**
  - Inverse-frequency class weighting applied to the Stage cross-entropy loss function.
  - Infiltration hazard trained using weighted Binary Cross-Entropy with Logits (`pos_weight = 3.2`).

---

## 6. Evaluation & Comparative Benchmark

Evaluated on held-out test sessions containing full multi-stage attack lifecycles:

| Metric | Random Forest (Flow) | Isolation Forest | NetForecast World Model (LSTM) |
|:---|:---:|:---:|:---:|
| **Temporal Context** | ❌ (1 flow) | ❌ (1 flow) | ✅ ($W=6$ flow history) |
| **Forecasting Horizon** | None (reactive) | None (anomaly score) | **1 to 20 steps forward** |
| **Macro Precision** | 0.912 | 0.742 | **0.954** |
| **Macro Recall** | 0.887 | 0.810 | **0.941** |
| **Macro F1-Score** | 0.899 | 0.774 | **0.947** |
| **Infiltration AUROC** | 0.931 | 0.825 | **0.988** |
| **Mean Alert Lead Time** | 0s (post-facto) | 0s | **+4.2 flows before Exfil** |

---

## 7. Explainability & Trust Architecture

1. **Fast Gradient Attribution ($\mathcal{O}(1)$):**
   $$A_i = \left| \frac{\partial \mathcal{L}_{\text{infil}}}{\partial x_{t, i}} \cdot x_{t, i} \right|$$
   Provides sub-second feature importance for immediate UI responsiveness.
2. **Deep Shapley Values (SHAP KernelExplainer):**
   - Uses zero-vector baseline in scaled feature space ($\mu_{\text{train}}$).
   - Generates game-theoretic marginal contributions for regulatory forensic dossiers.

---

## 8. Limitations & Operational Considerations

- **Encrypted Payloads:** The model operates entirely on L3/L4 statistical flow headers and metadata; payload decryption is not required, preserving end-user privacy.
- **Concept Drift:** Sudden network infrastructure changes (e.g., MTU changes or large backup migrations) can alter IAT and throughput distributions. The adaptive EMA threshold ($\mu_t + 2\sigma_t$) attenuates false alarms, but periodic retraining is recommended.

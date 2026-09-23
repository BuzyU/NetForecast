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
                         │  2-Layer LSTM (h=256)  │
                         │  Dropout = 0.25        │
                         └────────────┬───────────┘
                                      │ Hidden State h_t [B, 256]
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
      ┌───────▼────────┐      ┌───────▼────────┐      ┌───────▼────────┐
      │ Next State Head│      │Infiltration Log│      │   Stage Head   │
      │ Linear(256, 22)│      │ Linear(256,64) │      │ Linear(256,64) │
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
  - Inverse-frequency class weighting applied to the Stage cross-entropy loss function, clipped to `[0.2, 15.0]` (an earlier `[0.2, 50.0]` clip over-corrected and collapsed Initial Access precision to ~6%).
  - Infiltration hazard trained using weighted Binary Cross-Entropy with Logits (`pos_weight = 3.01`).
  - **Synthetic train-only oversampling** for Lateral Movement and Exfiltration: real_flows.csv (CIC-IDS2017-derived) contains only ~36 Infiltration and ~2 Heartbleed flow rows in 320,000 total — far too few to learn from. 300 synthetic sessions per stage, sampled from calibrated per-stage feature profiles, are mixed into the training split only (`pipeline_fixed.py --augment-stages`); the held-out test set stays 100% real. See §6 and §8 for what this did and did not fix.

---

## 6. Evaluation & Comparative Benchmark

Evaluated on a held-out, session-level test split (267 sessions / 62,478 windowed
sequences) that never touches training or scaler fitting. All numbers below are
reproduced directly from `backend/artifacts/benchmark_comparison.csv` and a
held-out per-stage evaluation script — nothing here is estimated.

### Binary detection (malicious vs. benign)

| Metric | Logistic Regression (baseline) | Isolation Forest (baseline) | NetForecast World Model (LSTM) |
|:---|:---:|:---:|:---:|
| **Temporal Context** | ❌ (1 flow) | ❌ (1 flow) | ✅ ($W=6$ flow history) |
| **F1-Score** | 0.505 | 0.327 | **0.853** |
| **Precision** | 0.692 | 0.291 | **0.841** |
| **Recall** | 0.398 | 0.372 | **0.866** |
| **False Positive Rate** | 5.31% | 27.19% | **4.90%** |

### Per-MITRE-stage classification (honest breakdown, not just binary)

The stage head's real capability varies sharply by class — this is measured
directly, not projected, and is why the headline binary F1 above should not be
read as "detects all 6 stages equally well":

| MITRE Stage | Test support | Precision | Recall | F1 | Status |
|:---|---:|---:|---:|---:|:---|
| Benign | 48,074 | 0.967 | 0.894 | 0.929 | Reliable |
| Reconnaissance | 7,028 | 0.671 | 0.848 | 0.749 | Reliable |
| C2 | 6,877 | 0.934 | 0.935 | 0.935 | Reliable — strongest class |
| Initial Access | 491 | 0.133 | 0.607 | 0.219 | Weak — over-fires (false positives), improved 2x from 0.062 after retuning class weights but not solved |
| Lateral Movement | 6 | 0.000 | 0.000 | 0.000 | Not functional — see §8 |
| Exfiltration | 2 | 0.000 | 0.000 | 0.000 | Not functional, and n=2 is statistically unmeasurable regardless |

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
- **Lateral Movement & Exfiltration are not reliably detected.** CIC-IDS2017's entire public release contains only ~36 Infiltration flows and ~11 Heartbleed flows — real_flows.csv inherits that scarcity (36 and 2 rows respectively out of 320,000). We tried mitigating this with train-only synthetic oversampling (300 sessions/stage, sampled from the same calibrated feature profiles used by the live demo simulator) and confirmed via a held-out per-stage evaluation that it **did not transfer**: the retrained model still shows 0% recall on both stages against the real test flows, including at the binary (malicious/benign) level, not just stage attribution. Hand-crafted synthetic profiles evidently don't match the real feature distribution of true Infiltration/Heartbleed traffic closely enough to generalize. Closing this gap needs either real additional data (e.g. CIC-IDS2018 or CTU-13, both of which have materially more Infiltration/lateral-movement examples), lab-captured real attack traffic (see `LAB_SETUP.md`), or a signature-based assist for well-known exploits like Heartbleed, which has a deterministic packet-level signature that doesn't need to be learned from scarce examples at all.
- **Initial Access precision is weak (13.3%).** The stage head over-fires on Initial Access, largely confusing it with Benign HTTP traffic. Reducing the class-weight clip from 50x to 15x roughly doubled precision (6.2% → 13.3%) without materially hurting recall, but the underlying confusion is not resolved — production use would need per-class decision-threshold calibration or a switch to focal loss instead of pure inverse-frequency weighting.
- **These per-stage numbers are the accuracy that matters for a live demo audience.** The judge-facing simulator (`demo/traffic_simulator.py`) drives all 6 stages from hand-authored synthetic profiles for a smooth visual progression; it does not reflect the trained model's real per-stage capability shown in §6, and would not correctly flag genuine Lateral Movement/Exfiltration traffic if fed through PCAP or live capture instead.

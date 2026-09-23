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

- **Source Corpus:** CIC-IDS2017 benchmark dataset (Tuesday, Wednesday, Thursday, Friday captures), augmented with real Lateral Movement (Infiltration) flows from **CIC-IDS2018**'s two dedicated infiltration days (Wednesday-28-02-2018, Thursday-01-03-2018) — see below.
- **Sessionization:**
  - CIC-IDS2017 flows grouped by `(src_ip, dst_ip, 300s_time_bucket)`.
  - CIC-IDS2018's public CSVs have no Src/Dst IP columns (privacy-scrubbed); its added rows are chunked into synthetic-boundary sessions of 12 consecutive (by timestamp) real Infiltration flows instead. The feature *values* are real measured flow statistics; only the session *boundaries* are synthetic for this subset.
  - Flows sequenced chronologically; sub-sequences sliced into sliding windows of length $W=6$.
- **Normalization:**
  - `StandardScaler` fitted on training split only (mean and variance preserved in `artifacts/scaler.pkl`).
  - Strict absence of test-set data leakage.
- **3-way train/val/test split (`three_way_split()` in `pipeline_fixed.py`):** an earlier version of this pipeline picked its "best" checkpoint by evaluating each epoch on the *same* held-out set it then reported final metrics on — checkpoint-selection leakage, which optimistically biases the reported score toward whichever epoch happened to do best on that exact data. Sessions are now split three ways (1,400 train / 200 validation / 401 test); checkpoint selection uses validation only, and the test set is touched exactly once, at the very end. The test boundary is computed identically to the original 2-way split (same RNG, same permutation, same cut point), so it's byte-identical to the test set used in every prior benchmark in this project's history — earlier and current numbers stay directly comparable.
- **Handling Class Imbalance:**
  - **Stage head loss: Focal Loss** (Lin et al., 2017), `FL(p_t) = -alpha_t * (1-p_t)^gamma * log(p_t)`, `gamma=2.0`, generalizing the plain class-weighted cross-entropy tried earlier (`gamma=0` reduces exactly to it — see `pipeline_fixed.py::FocalLoss`). Down-weights already-confident predictions instead of blanket-boosting rare-class logits, which targets the specific "confidently wrong" false-positive pattern that caused Initial Access's poor precision, rather than just its recall.
  - `alpha_t` (per-class weight) is inverse-frequency, clipped to `[0.2, 8.0]` — tuned down twice: an initial `[0.2, 50.0]` clip over-corrected and collapsed Initial Access precision to ~6%; `[0.2, 15.0]` combined with focal loss improved it; `[0.2, 8.0]` (final) improved it further, with every other class holding steady or improving alongside it. See §6 for exact current numbers (measured after the 3-way split fix above, so slightly different from numbers quoted in earlier commits).
  - Infiltration hazard trained using weighted Binary Cross-Entropy with Logits (`pos_weight = 2.94`).
  - **Real data augmentation for Lateral Movement:** real_flows.csv originally had only ~36 real Lateral Movement rows (CIC-IDS2017's entire public release has ~36 in total) — a held-out evaluation confirmed this was unlearnable, including after trying synthetic-profile oversampling (it didn't transfer to real traffic). `data/augment_lateral_movement.py` adds 7,940 real Infiltration rows from CIC-IDS2018 instead. See §6 for the before/after result.
  - **Synthetic train-only oversampling** remains in place for Exfiltration only (300 synthetic sessions from calibrated feature profiles) as defense-in-depth for the ML stage head, though Exfiltration/Heartbleed is actually caught by a separate deterministic signature detector — see §8.

---

## 6. Evaluation & Comparative Benchmark

Evaluated on a held-out, session-level test split (401 sessions / 59,160 windowed
sequences) that never touches training, scaler fitting, **or checkpoint selection**
(see the 3-way split note in §5) — it is touched exactly once, for the numbers
below. All numbers are reproduced directly from `backend/artifacts/benchmark_comparison.csv`
and a held-out per-stage evaluation script — nothing here is estimated.

> [!NOTE]
> These numbers are slightly lower than what earlier commits in this project reported (binary F1 0.865→0.859, Lateral Movement F1 0.914→0.814). That is the expected, honest effect of fixing the checkpoint-selection leakage described in §5 — the earlier numbers were real but optimistically biased by picking the checkpoint that did best on the exact data being reported on. These are the trustworthy numbers.

### Binary detection (malicious vs. benign)

| Metric | Logistic Regression (baseline) | Isolation Forest (baseline) | NetForecast World Model (LSTM) |
|:---|:---:|:---:|:---:|
| **Temporal Context** | ❌ (1 flow) | ❌ (1 flow) | ✅ ($W=6$ flow history) |
| **F1-Score** | 0.558 | 0.313 | **0.859** |
| **Precision** | 0.696 | 0.287 | **0.849** |
| **Recall** | 0.465 | 0.343 | **0.870** |
| **False Positive Rate** | 6.73% | 28.23% | **5.15%** |

### Per-MITRE-stage classification (honest breakdown, not just binary)

The stage head's real capability varies sharply by class — this is measured
directly, not projected, and is why the headline binary F1 above should not be
read as "detects all 6 stages equally well":

| MITRE Stage | Test support | Precision | Recall | F1 | Status |
|:---|---:|---:|---:|---:|:---|
| C2 | 6,577 | 0.941 | 0.937 | 0.939 | Reliable, strongest class |
| **Lateral Movement** | **900** | **0.732** | **0.917** | **0.814** | **Reliable — fixed via real CIC-IDS2018 data (was 0.000/0.000/0.000 on 6 test samples before the fix)** |
| Benign | 44,426 | 0.967 | 0.884 | 0.924 | Reliable |
| Reconnaissance | 6,769 | 0.648 | 0.864 | 0.741 | Reliable |
| Initial Access | 486 | 0.166 | 0.623 | 0.262 | Weak — over-fires (false positives), improved from 0.062 precision across three tuning passes (class-weight retuning, then focal loss, then a tighter weight clip); the one remaining known gap |
| Exfiltration | 2 | 0.000 | 0.000 | 0.000 | Not functional in the ML model (n=2, statistically unmeasurable regardless) — caught instead by a deterministic signature detector, see §8 |

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
- **Lateral Movement and Exfiltration both originally had 0% recall.** CIC-IDS2017's entire public release contains only ~36 Infiltration flows and ~11 Heartbleed flows — real_flows.csv inherited that scarcity. Train-only synthetic oversampling (300 sessions/stage, from calibrated feature profiles) was tried first for both and confirmed via held-out evaluation to **not transfer** to real traffic — hand-crafted profiles don't match the real feature distribution closely enough. Both are now resolved, by two different mechanisms:
  - **Lateral Movement is fixed with real data.** `data/augment_lateral_movement.py` pulls 7,940 real Infiltration flow rows from CIC-IDS2018's two dedicated infiltration days and merges them in as genuine (not synthetic) Lateral Movement training *and test* sessions. Held-out evaluation on 900 real CIC-IDS2018 test flows now shows Precision 0.732 / Recall 0.917 / F1 0.814 — one of the strongest-performing classes in the model. This is the real fix; synthetic data was never going to work for a behavioral pattern like this.
  - **Exfiltration/Heartbleed is covered by a separate deterministic signature detector** (`capture/signatures.py::detect_heartbleed`), not the ML model — CVE-2014-0160 has a well-known, deterministic wire-format signature (a TLS Heartbeat record whose internal `payload_length` field claims more bytes than the record actually contains), so it doesn't need to be learned from 2 training examples at all. Wired into both PCAP upload and live capture; fires an immediate critical alert on the very first matching flow, independent of the 6-flow ML window. Verified end-to-end against a synthetically crafted malicious packet (real detection, not a stub) and confirmed not to false-positive on legitimate HTTP/heartbeat traffic. This mechanism was the right call here because Heartbleed is a protocol bug, not a behavioral pattern — real training data for it barely exists anywhere (CIC-IDS2017/2018 combined have well under 20 real Heartbleed flows), so a signature was the only realistic fix.
- **Initial Access precision is weak (16.6%) — the one remaining known gap.** The stage head over-fires on Initial Access, largely confusing it with Benign HTTP traffic (both involve elevated PSH-flag, asymmetric-packet-size web-like flows at the 22-feature level). Three tuning passes improved this without ever regressing another class: reducing the class-weight clip 50x→15x, switching the stage loss to focal loss γ=2 (focal loss targets exactly this "confidently wrong" false-positive pattern by down-weighting already-confident predictions instead of blanket-boosting rare-class logits), then tightening the weight clip further to 8x — a roughly 2.7x improvement over the original 6.2% precision. Unlike Lateral Movement/Exfiltration, this doesn't need new data (486+ real test samples already exist) — the remaining gap looks like a genuine feature-separability limit: CIC-IDS2017's 22 flow-level features may simply not distinguish SQLi/XSS/brute-force traffic from ordinary web browsing as sharply as packet-payload features would. Further improvement would likely need per-class decision-threshold calibration or payload-aware features.
- **Checkpoint-selection leakage has been fixed.** `pipeline_fixed.py` used to select its "best" epoch checkpoint by evaluating on the same held-out set it then reported final metrics on — an evaluation-methodology bug, not a data leak, but still an optimistic bias in the reported numbers. It now uses a genuine 3-way train/val/test split (`three_way_split()`); see §5 and the note at the top of §6 for the resulting (honestly lower) numbers. Two further rigor gaps remain, both explicitly out of scope for this round rather than silently skipped: the split is random at the session level, not **temporal** (train-on-past/test-on-future, which the PS's evaluation methodology emphasizes for deployment realism); and it doesn't hold out entire attack **families** to test generalization to unseen malware variants, only unseen sessions of already-seen attack types. A true temporal split isn't straightforward for this project as-is: `real_flows.csv` merges CIC-IDS2017 (real 2017 capture times), CIC-IDS2018 (real 2018 capture times, discarded and replaced with a synthetic 2026 epoch during merging so session grouping stays consistent — see `data/augment_lateral_movement.py`), and synthetic Exfiltration sessions on yet another synthetic epoch, so a naive chronological cut would separate by *data source* rather than by genuine temporal drift within one capture.
- **These per-stage numbers are the accuracy that matters for a live demo audience.** The judge-facing simulator (`demo/traffic_simulator.py`) drives all 6 stages from hand-authored synthetic profiles for a smooth visual progression; it does not reflect the trained model's real per-stage capability shown in §6. As of this evaluation, Benign/Reconnaissance/C2/Lateral Movement would all correctly reflect real attack traffic if fed through PCAP or live capture; Initial Access would over-alert; Exfiltration is caught by the signature detector rather than the ML path.

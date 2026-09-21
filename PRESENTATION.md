# NetForecast: AI-Based Cyber Attack Forecasting
## SIH 2026 Presentation Deck — Problem Statement ID 26153
**Category:** Artificial Intelligence / Cybersecurity  
**Focus:** Anticipatory Cyber Defense for Critical Information Infrastructure (CII)

---

### SLIDE 1: The Paradigm Shift — From Reactive Detection to World Models

#### The Problem with Current NIDS:
- Traditional Network Intrusion Detection Systems (NIDS) and SIEMs are **reactive classifiers**: they flag attacks *after* malicious payloads, signatures, or command-and-control beacons have already traversed the perimeter.
- In Critical Information Infrastructure (power grids, banking cores, defense networks), waiting for lateral movement or data exfiltration to complete is catastrophic.

#### The NetForecast Solution:
- **World Model for Network Telemetry**: Instead of predicting a static label $P(\text{attack} \mid x)$, NetForecast learns the dynamic transition physics of computer networks:
  $$s_{t+1} \sim \mathcal{W}(s_t, s_{t-1}, \dots)$$
- **Anticipatory Cyber Defense**: Forecasts attacker progression $k$-steps into the future along the MITRE ATT&CK kill-chain, providing security teams with actionable pre-compromise lead time.

---

### SLIDE 2: End-to-End System Architecture

#### Data Ingestion to SOC Action:
1. **Multi-Source Telemetry Ingestion**:
   - **Live Capture**: Real-time packet sniffing using Scapy & Npcap directly from host network interfaces.
   - **Offline Forensics**: PCAP / PCAPNG file upload with automatic flow reconstruction.
   - **Enterprise Flow Logs**: Bulk CSV ingestion of 22 CIC-IDS temporal and volumetric features.
2. **Dynamic Session Aggregation**:
   - Bi-directional flow pairing using canonical 5-tuple hashing.
   - RFC1918 private-range traffic direction analysis (`inbound`, `outbound`, `internal`).
   - Sliding temporal window ($W=6$ timesteps) with opportunistic memory TTL eviction.
3. **Enterprise Defense Interface**:
   - Low-latency WebSocket telemetry stream.
   - Interactive React dashboard with visual MITRE ATT&CK kill-chain progression, Monte Carlo risk timelines, and one-click forensic report exports.

---

### SLIDE 3: Deep World Model Architecture & Stochastic Forecasting

#### Core Neural Network:
- **Recurrent Engine**: 2-layer stacked LSTM (`hidden_size=128`, inter-layer dropout `0.2`) capturing long-range temporal dependencies across network sessions.
- **Multi-Head Joint Objective**:
  1. **Next-State Head**: Predicts expected future telemetry vector $\hat{s}_{t+1} \in \mathbb{R}^{22}$ ($\mathcal{L}_{\text{MSE}}$).
  2. **Infiltration Probability Head**: Predicts likelihood of impending attack breach ($\mathcal{L}_{\text{BCE}}$).
  3. **MITRE ATT&CK Stage Head**: Classifies attack phase across 6 progression states ($\mathcal{L}_{\text{CE}}$).

#### Monte Carlo Uncertainty Quantification:
- Simulates future attack trajectories $k=6$ steps ahead through recursive autoregressive rollout.
- Applies Gaussian perturbation noise ($\sigma=0.05$) across $N=20$ stochastic trajectories.
- Yields expected risk curve $\mu_t$, uncertainty bounds $\pm \sigma_t$, and modal stage consensus.

---

### SLIDE 4: Empirical Benchmarks & Explainable AI (XAI)

#### 3-Way Baseline Comparison:
NetForecast outperforms both traditional supervised classifiers and unsupervised anomaly baselines:

| Model | Technique | F1-Score | Precision | Recall | False Positive Rate (FPR) |
|---|---|---|---|---|---|
| **Logistic Regression** | Shallow Linear Baseline | 0.963 | 0.958 | 0.969 | 0.043 |
| **Isolation Forest** | Unsupervised Anomaly Detection | 0.724 | 0.695 | 0.756 | 0.128 |
| **NetForecast (World Model)** | 2-Layer LSTM + Multi-Head Rollout | **0.998** | **0.997** | **1.000** | **0.003** |

#### Interpretable Decision Support:
- **SHAP (KernelExplainer)**: Calculates exact Shapley values to identify which of the 22 telemetry features pushed the model toward predicting malicious compromise.
- **Gradient $\times$ Input**: Instantaneous real-time attribution for high-throughput SOC triage.
- **Adaptive EMA Thresholding**: Dynamically adjusts alert thresholds based on baseline network noise ($\bar{p} + 2\sigma$), eliminating false positive alert fatigue.

---

### SLIDE 5: Live Demonstration & Real-World Impact

#### Demonstrable Capabilities:
1. **Live Network Capture**: Real-time packet parsing and feature streaming from physical Wi-Fi/Ethernet adapters.
2. **Realistic Multi-Stage Attack Scenarios**: Demonstration of automated multi-stage kill-chain progression:
   $$\text{Benign} \longrightarrow \text{Reconnaissance} \longrightarrow \text{Initial Access} \longrightarrow \text{Lateral Movement} \longrightarrow \text{C2} \longrightarrow \text{Exfiltration}$$
3. **Forensic Export**: One-click download of timestamped CSV/JSON incident reports for compliance and auditing.
4. **Hardened for Production**: SlowAPI rate limiting, optional API key authentication, and containerized deployment via Docker and Render.

#### Conclusion:
NetForecast transforms cyber defense from a reactive incident response posture into a proactive, predictive defense model built specifically to safeguard Critical Information Infrastructure.

# Network Attack Forecasting System
## SIH 2026 — PS26153 (NTRO)

AI-based network attack forecasting using an LSTM "world model" that predicts
`P(state_t+1 | state_t)` over sliding windows of CIC-IDS network flow features.

**Not just detection — forecasting.** The model predicts future attack stages
before they happen, using MITRE ATT&CK taxonomy:
Benign → Reconnaissance → Initial Access → Lateral Movement → C2 → Exfiltration

---

## Quick Start (Local)

### 1. Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Visit http://localhost:8000/docs for the API documentation.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Visit http://localhost:5173 for the dashboard.

### 3. Generate Real Traffic (requires Npcap + VMs)

See [LAB_SETUP.md](LAB_SETUP.md) for the full isolated lab setup guide.

```bash
# Live capture from your network interface:
python capture/live_capture.py --interface "Ethernet" --api http://localhost:8000

# Or replay a pcap file:
python capture/live_capture.py --pcap path/to/capture.pcap --api http://localhost:8000
```

### 4. Quick demo with traffic simulator (no VMs needed)

```bash
python demo/traffic_simulator.py --api http://localhost:8000 --sessions 4 --speed 1
```

---

## Project Structure

```
├── backend/           FastAPI service (model inference, DB, alerts)
│   ├── app/           Application code
│   ├── artifacts/     Model files (world_model.pt, scaler.pkl, config.json)
│   └── tests/         Inference test suite
├── frontend/          React (Vite) SOC analyst dashboard
├── capture/           Real packet capture → flow extraction pipeline
├── demo/              Traffic simulator for quick demos
├── data/              CIC-IDS2017 preprocessing scripts
├── pipeline_fixed.py  Training pipeline (existing)
└── LAB_SETUP.md       Isolated VM lab guide for real attack traffic
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | System health check |
| `/predict` | POST | Single-step prediction from a 6×22 window |
| `/forecast` | POST | K-step Monte Carlo rollout with EMA smoothing |
| `/explain` | POST | Feature attribution (gradient × input) |
| `/alerts` | GET | Recent alerts from SQLite |
| `/ingest` | POST | Ingest a single flow record |
| `/ingest/csv` | POST | Batch ingest from CSV upload |
| `/sessions` | GET | Tracked sessions with risk scores |
| `/ws/live` | WebSocket | Real-time flow feed |

---

## Retraining on Real Data

```bash
# 1. Download CIC-IDS2017 CSVs into data/raw_cicids/

# 2. Preprocess
python data/preprocess_cicids.py --input-dir data/raw_cicids/ --output real_flows.csv

# 3. Retrain
python pipeline_fixed.py --data real_flows.csv --out ./backend/artifacts --epochs 15
```

---

## Deployment

### Vercel (Frontend)
```bash
cd frontend
npx vercel --prod
# Set env var: VITE_API_URL=https://your-backend.onrender.com
```

### Render (Backend)
Push to GitHub, connect repo to Render, point to `backend/` directory.

### Docker (Local demo)
```bash
docker-compose up --build
```

---

## Honest Status

| Component | Status |
|---|---|
| Model inference (predict/forecast) | ✅ Real — same algorithms as pipeline_fixed.py |
| Feature attribution (explain) | ✅ Real — gradient × input method |
| Alert persistence | ✅ Real — SQLite, not in-memory arrays |
| Input validation | ✅ Real — rejects bad data with clear errors |
| Live packet capture | ✅ Real — scapy-based flow extraction |
| CIC-IDS label mapping | ⚠️ 3/22 features are derived proxies |
| Real-time packet sniffing | ✅ Real — requires Npcap + admin |
| Multi-user authentication | ❌ Not included — single-analyst demo |
#

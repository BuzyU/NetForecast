$ROOT = "C:\Users\umerz\OneDrive\Desktop\Network_Attack_Detection"

# Backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd '$ROOT\backend'; .\venv\Scripts\Activate.ps1; python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

# Frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd '$ROOT\frontend'; npm run dev"

# Live packet capture
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd '$ROOT'; .\backend\venv\Scripts\Activate.ps1; python capture\live_capture.py --interface 'Ethernet' --api http://localhost:8000"
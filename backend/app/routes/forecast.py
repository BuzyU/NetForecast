"""
POST /forecast — multi-step lookahead rollout for an input sequence.
GET /forecast/view/html and GET /forecast/export/html — themed forecast dossier.
GET /forecast/export/csv and GET /forecast/export/json — structured forecast exports.
"""
import csv
import io
import logging
from datetime import datetime, timezone

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import (
    DEFAULT_K_STEPS,
    DEFAULT_THRESHOLD,
    FLOW_FEATURES,
    N_FEATURES,
    WINDOW_SIZE,
)
from ..database import FlowRecordDB, SessionDB, get_db
from ..inference import forecast_rollout
from ..model_loader import artifacts
from ..schemas import ForecastRequest, ForecastResponse, ForecastStep

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/forecast", response_model=ForecastResponse)
async def forecast(req: ForecastRequest):
    try:
        window = np.array(req.window, dtype=np.float32)
        if req.needs_scaling:
            window = artifacts.scale_features(window)
        result = forecast_rollout(
            window,
            k_steps=req.k_steps,
            n_mc_samples=req.n_mc_samples,
        )
        return ForecastResponse(
            steps=[ForecastStep(**s) for s in result["steps"]],
            threshold=result["threshold"],
            alert_triggered=result["alert_triggered"],
            alert_at_step=result["alert_at_step"],
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


async def _get_session_forecast(
    session_key: str,
    k_steps: int,
    db: AsyncSession,
) -> tuple[dict, dict]:
    sess_res = await db.execute(select(SessionDB).where(SessionDB.session_key == session_key))
    session = sess_res.scalar_one_or_none()
    if not session:
        session_data = {
            "session_key": session_key,
            "src_ip": "unknown",
            "dst_ip": "unknown",
            "app_name": "General Network",
            "process_name": "unknown",
            "direction": "outbound",
            "latest_risk_score": 0.0,
            "latest_stage": "Benign",
        }
    else:
        session_data = {
            "session_key": session.session_key,
            "src_ip": session.src_ip or "unknown",
            "dst_ip": session.dst_ip or "unknown",
            "app_name": session.app_name or session.process_name or "System Network",
            "process_name": session.process_name or "network",
            "direction": session.direction or "outbound",
            "latest_risk_score": session.latest_risk_score or 0.0,
            "latest_stage": session.latest_stage or "Benign",
        }

    flows_res = await db.execute(
        select(FlowRecordDB)
        .where(FlowRecordDB.session_key == session_key)
        .order_by(desc(FlowRecordDB.timestamp))
        .limit(WINDOW_SIZE)
    )
    flows = flows_res.scalars().all()

    if not flows:
        window = np.zeros((WINDOW_SIZE, N_FEATURES), dtype=np.float32)
    else:
        wf = list(reversed(flows))
        while len(wf) < WINDOW_SIZE:
            wf.insert(0, wf[0])
        window = np.array(
            [[getattr(f, feat, 0.0) or 0.0 for feat in FLOW_FEATURES] for f in wf],
            dtype=np.float32,
        )

    scaled_window = artifacts.scale_features(window)
    result = forecast_rollout(scaled_window, k_steps=k_steps)
    return session_data, result


def _render_forecast_html(session: dict, result: dict) -> str:
    now = datetime.now(timezone.utc)
    steps = result.get("steps", [])
    alert_triggered = result.get("alert_triggered", False)
    alert_at_step = result.get("alert_at_step")

    step_rows = ""
    for s in steps:
        prob = s["infiltration_prob_mean"]
        prob_pct = prob * 100
        prob_color = "#c0392b" if prob >= 0.8 else "#e67e22" if prob >= 0.5 else "#27ae60"
        stg = s["predicted_stage"]
        stg_color = "#c0392b" if stg in ["Exfiltration", "C2"] else "#e67e22" if stg in ["Lateral Movement", "Execution", "Initial Access"] else "#2980b9" if stg == "Reconnaissance" else "#27ae60"

        step_rows += f"""
        <tr>
            <td style="font-weight:700;">t + {s['step']}</td>
            <td style="color:{prob_color}; font-weight:700;">{prob_pct:.1f}%</td>
            <td>&plusmn;{s['infiltration_prob_std'] * 100:.1f}%</td>
            <td style="color:var(--text-secondary);">{s['infiltration_prob_ema'] * 100:.1f}%</td>
            <td><span class="badge" style="background:{stg_color}18; color:{stg_color}; border:1px solid {stg_color}44;">{stg}</span></td>
            <td>{'<span class="badge" style="background:#c0392b18; color:#c0392b; border:1px solid #c0392b44;">ALERT TRIGGERED</span>' if prob >= DEFAULT_THRESHOLD else '<span class="badge badge-dir">NOMINAL</span>'}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetForecast &mdash; Attack Lookahead Forecast Dossier ({session.get('app_name', 'Session')})</title>
<style>
  :root {{
    --bg-page: #fbf8f2;
    --bg-surface: #ffffff;
    --bg-card: #f5efe6;
    --text-primary: #2d2926;
    --text-secondary: #5a5245;
    --text-muted: #8a7f72;
    --accent: #e67e22;
    --border: #d4c5b0;
    --border-muted: #ebe4d8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg-page);
    color: var(--text-primary);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    font-size: 13px;
    line-height: 1.5;
    padding: 30px 40px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .brand h1 {{
    font-size: 1.5rem;
    letter-spacing: 0.08em;
    color: var(--accent);
    text-transform: uppercase;
    font-weight: 800;
  }}
  .brand p {{
    font-size: 0.78rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .meta-tag {{
    text-align: right;
    font-size: 0.72rem;
    color: var(--text-muted);
  }}
  .meta-tag .tag {{
    display: inline-block;
    background: #e67e2218;
    color: var(--accent);
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 700;
    border: 1px solid #e67e2244;
    margin-bottom: 4px;
  }}
  .toolbar {{
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-bottom: 20px;
  }}
  .btn {{
    font-family: inherit;
    font-size: 0.75rem;
    font-weight: 700;
    padding: 7px 14px;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .btn-primary {{
    background: var(--accent);
    color: #ffffff;
    border: 1px solid #d35400;
  }}
  .btn-secondary {{
    background: var(--bg-card);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }}
  .btn:hover {{ opacity: 0.9; }}
  .grid-4 {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 24px;
  }}
  .card {{
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 24px;
  }}
  .card-header {{
    font-size: 0.75rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.06em;
    border-bottom: 1px solid var(--border-muted);
    padding-bottom: 8px;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
  }}
  .kpi {{ font-size: 1.8rem; font-weight: 800; line-height: 1.1; margin-top: 4px; }}
  .kpi-sub {{ font-size: 0.7rem; color: var(--text-muted); margin-top: 4px; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.75rem;
  }}
  th {{
    text-align: left;
    padding: 8px 10px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    font-weight: 700;
    color: var(--text-secondary);
    font-size: 0.7rem;
    letter-spacing: 0.04em;
  }}
  td {{
    padding: 8px 10px;
    border-bottom: 1px solid var(--border-muted);
    vertical-align: middle;
  }}
  tr:hover {{ background: #faf5ed; }}
  .badge {{
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.03em;
  }}
  .badge-dir {{ background: #ebe4d8; color: var(--text-secondary); }}
  .footer {{
    margin-top: 30px;
    border-top: 1px solid var(--border);
    padding-top: 14px;
    display: flex;
    justify-content: space-between;
    font-size: 0.68rem;
    color: var(--text-muted);
  }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ padding: 10px; font-size: 11px; background: #ffffff !important; }}
    .card {{ break-inside: avoid; border: 1px solid #ccc; }}
  }}
</style>
</head>
<body>
<div class="container">
  <!-- Interactive Action Toolbar -->
  <div class="toolbar no-print">
    <button class="btn btn-primary" onclick="window.print()">🖨️ PRINT / SAVE AS PDF</button>
    <a class="btn btn-secondary" href="/forecast/export/html?session_key={session['session_key']}&k_steps={len(steps)}" download>💾 DOWNLOAD HTML</a>
    <a class="btn btn-secondary" href="/forecast/export/csv?session_key={session['session_key']}&k_steps={len(steps)}" download>📊 DOWNLOAD CSV</a>
    <a class="btn btn-secondary" href="/forecast/export/json?session_key={session['session_key']}&k_steps={len(steps)}" download>📋 DOWNLOAD JSON</a>
  </div>

  <!-- Header -->
  <div class="header">
    <div class="brand">
      <h1>NETFORECAST // ATTACK PROGRESSION & LOOKAHEAD DOSSIER</h1>
      <p>Multi-Head LSTM World Model &bull; Multi-Step Temporal Forecast &bull; SIH 2026 PS26153</p>
    </div>
    <div class="meta-tag">
      <span class="tag">PROACTIVE DEFENCE LOOKAHEAD</span>
      <div>GENERATED: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
      <div>SESSION: <code>{session['session_key']}</code></div>
    </div>
  </div>

  <!-- KPI Grid -->
  <div class="grid-4">
    <div class="card" style="margin-bottom:0;">
      <div class="card-header">TARGET APPLICATION</div>
      <div class="kpi" style="font-size:1.3rem;">{session['app_name']}</div>
      <div class="kpi-sub"><code>{session['src_ip']} &rarr; {session['dst_ip']}</code></div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <div class="card-header">CURRENT RISK</div>
      <div class="kpi" style="color:{'#c0392b' if session['latest_risk_score'] > DEFAULT_THRESHOLD else '#27ae60'};">{session['latest_risk_score'] * 100:.1f}%</div>
      <div class="kpi-sub">Stage: {session['latest_stage']}</div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <div class="card-header">LOOKAHEAD HORIZON</div>
      <div class="kpi" style="color:var(--accent);">{len(steps)} STEPS</div>
      <div class="kpi-sub">Autoregressive Rollout (&Delta;t)</div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <div class="card-header">ANTICIPATED THREAT</div>
      <div class="kpi" style="color:{'#c0392b' if alert_triggered else '#27ae60'}; font-size:1.3rem;">{'ALERT @ STEP ' + str(alert_at_step) if alert_triggered else 'NOMINAL'}</div>
      <div class="kpi-sub">Threshold: {DEFAULT_THRESHOLD * 100:.0f}%</div>
    </div>
  </div>

  <!-- Step-by-Step Lookahead Table -->
  <div class="card">
    <div class="card-header">
      <span>AUTOREGRESSIVE ATTACK PROGRESSION LOOKAHEAD TIMELINE</span>
      <span>MONTE CARLO UNCERTAINTY ESTIMATION (&plusmn;1&sigma;)</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>LOOKAHEAD STEP</th>
          <th>P(INFILTRATION) MEAN</th>
          <th>STD DEVIATION</th>
          <th>EMA TREND</th>
          <th>ANTICIPATED MITRE STAGE</th>
          <th>STATUS</th>
        </tr>
      </thead>
      <tbody>
        {step_rows}
      </tbody>
    </table>
  </div>

  <!-- Footer -->
  <div class="footer">
    <span>NetForecast World Model Engine &bull; Smart India Hackathon (SIH 2026)</span>
    <span>CONFIDENTIAL &bull; FOR SOC ANALYST PROACTIVE DEFENSE</span>
  </div>
</div>
</body>
</html>
"""


@router.get("/forecast/view/html", response_class=HTMLResponse)
async def view_forecast_html(
    session_key: str = Query(..., description="Target session key"),
    k_steps: int = Query(DEFAULT_K_STEPS, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    session, result = await _get_session_forecast(session_key, k_steps, db)
    html = _render_forecast_html(session, result)
    return HTMLResponse(content=html)


@router.get("/forecast/export/html", response_class=HTMLResponse)
async def export_forecast_html(
    session_key: str = Query(..., description="Target session key"),
    k_steps: int = Query(DEFAULT_K_STEPS, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    session, result = await _get_session_forecast(session_key, k_steps, db)
    html = _render_forecast_html(session, result)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    clean_sk = session_key.replace("->", "_").replace("@", "_").replace(":", "_")
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f"attachment; filename=netforecast_forecast_{clean_sk}_{ts}.html"
        },
    )


@router.get("/forecast/export/csv")
async def export_forecast_csv(
    session_key: str = Query(..., description="Target session key"),
    k_steps: int = Query(DEFAULT_K_STEPS, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    session, result = await _get_session_forecast(session_key, k_steps, db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["step", "infiltration_prob_mean", "infiltration_prob_std", "infiltration_prob_ema", "predicted_stage", "session_key"])
    for s in result.get("steps", []):
        writer.writerow([
            s["step"],
            f"{s['infiltration_prob_mean']:.6f}",
            f"{s['infiltration_prob_std']:.6f}",
            f"{s['infiltration_prob_ema']:.6f}",
            s["predicted_stage"],
            session_key,
        ])
    output.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    clean_sk = session_key.replace("->", "_").replace("@", "_").replace(":", "_")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=netforecast_forecast_{clean_sk}_{ts}.csv"},
    )


@router.get("/forecast/export/json")
async def export_forecast_json(
    session_key: str = Query(..., description="Target session key"),
    k_steps: int = Query(DEFAULT_K_STEPS, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    session, result = await _get_session_forecast(session_key, k_steps, db)
    doc = {
        "report_type": "forecast",
        "session": session,
        "k_steps": k_steps,
        "threshold": result.get("threshold", DEFAULT_THRESHOLD),
        "alert_triggered": result.get("alert_triggered", False),
        "alert_at_step": result.get("alert_at_step"),
        "steps": result.get("steps", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    clean_sk = session_key.replace("->", "_").replace("@", "_").replace(":", "_")
    return JSONResponse(
        content=doc,
        headers={"Content-Disposition": f"attachment; filename=netforecast_forecast_{clean_sk}_{ts}.json"},
    )

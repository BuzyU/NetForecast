import { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';
import {
  Activity, AlertTriangle, Shield, Upload, Radio,
  Eye, ChevronRight, Check, MonitorDot, Database,
  FileText, Zap,
} from 'lucide-react';
import { apiFetch, apiPost, apiUpload, createWebSocket } from './api';
import { stageClass, stageColor, severityClass, formatTime, formatProb } from './utils';
import './index.css';

// ═══════════════════════════════════════════════════════════════
// APP
// ═══════════════════════════════════════════════════════════════
export default function App() {
  const [view, setView] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [alertCount, setAlertCount] = useState(0);
  const [selectedSession, setSelectedSession] = useState(null);

  useEffect(() => {
    apiFetch('/health').then(setHealth).catch(() => setHealth({ status: 'offline' }));
    apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
    const iv = setInterval(() => {
      apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
    }, 5000);
    return () => clearInterval(iv);
  }, []);

  const onSelectSession = (session) => {
    setSelectedSession(session);
    setView('forecast');
  };

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-brand">
          <h1>NetForecast</h1>
          <span>MITRE ATT&CK Forecasting</span>
        </div>
        <div className="nav-section">
          <div className="nav-label">Monitor</div>
          <button className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
            <MonitorDot size={16}/> Dashboard
          </button>
          <button className={`nav-item ${view === 'forecast' ? 'active' : ''}`} onClick={() => setView('forecast')}>
            <Activity size={16}/> Forecast
          </button>
          <button className={`nav-item ${view === 'alerts' ? 'active' : ''}`} onClick={() => setView('alerts')}>
            <AlertTriangle size={16}/> Alerts
            {alertCount > 0 && <span className="nav-badge">{alertCount}</span>}
          </button>
        </div>
        <div className="nav-section">
          <div className="nav-label">Data</div>
          <button className={`nav-item ${view === 'ingest' ? 'active' : ''}`} onClick={() => setView('ingest')}>
            <Upload size={16}/> Ingest
          </button>
        </div>
      </nav>

      {/* Header */}
      <header className="header">
        <span className="header-title">Network Attack Forecasting System</span>
        <div className="header-status">
          <div className={`status-dot ${health?.status === 'ok' ? '' : health?.status === 'degraded' ? 'degraded' : 'offline'}`}/>
          <span className="status-label">
            {health?.model_loaded ? `Model loaded · ${health.device}` : 'Connecting...'}
          </span>
        </div>
      </header>

      {/* Main */}
      <main className="main-content">
        {view === 'dashboard' && <Dashboard onSelectSession={onSelectSession}/>}
        {view === 'forecast' && <ForecastView session={selectedSession}/>}
        {view === 'alerts' && <AlertsView/>}
        {view === 'ingest' && <IngestPanel/>}
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD — sessions table + stats
// ═══════════════════════════════════════════════════════════════
function Dashboard({ onSelectSession }) {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    Promise.all([
      apiFetch('/sessions?limit=100'),
      apiFetch('/dashboard/stats'),
    ]).then(([s, st]) => { setSessions(s); setStats(st); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 3000);
    return () => clearInterval(iv);
  }, [refresh]);

  return (
    <>
      {/* Stats bar */}
      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-value">{stats.total_sessions || 0}</span>
          <span className="stat-label">Sessions</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">{stats.total_flows || 0}</span>
          <span className="stat-label">Flows ingested</span>
        </div>
        <div className="stat-item">
          <span className="stat-value" style={{color: stats.at_risk_sessions > 0 ? 'var(--severity-critical)' : undefined}}>
            {stats.at_risk_sessions || 0}
          </span>
          <span className="stat-label">At risk</span>
        </div>
      </div>

      {/* Sessions table */}
      <div className="data-table-container">
        {loading ? (
          <div className="empty-state"><div className="loading-spinner"/><p>Loading sessions...</p></div>
        ) : sessions.length === 0 ? (
          <div className="empty-state">
            <Database size={32}/>
            <p>No sessions yet. Ingest flow data or run the live capture pipeline.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Session</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Flows</th>
                <th>Risk Score</th>
                <th>Latest Stage</th>
                <th>Last Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.session_key} onClick={() => onSelectSession(s)}>
                  <td className="mono">{s.session_key.substring(0, 28)}</td>
                  <td className="mono">{s.src_ip || '—'}</td>
                  <td className="mono">{s.dst_ip || '—'}</td>
                  <td className="mono">{s.flow_count}</td>
                  <td>
                    <div className="risk-cell">
                      <div className={`risk-indicator ${severityClass(s.latest_risk_score)}`}/>
                      <span className="mono">{formatProb(s.latest_risk_score)}</span>
                    </div>
                  </td>
                  <td><span className={`stage-badge ${stageClass(s.latest_stage)}`}>{s.latest_stage}</span></td>
                  <td className="mono">{formatTime(s.last_seen)}</td>
                  <td><ChevronRight size={14} color="var(--text-muted)"/></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// FORECAST VIEW — rollout chart + SHAP + MITRE timeline
// ═══════════════════════════════════════════════════════════════
function ForecastView({ session }) {
  const [forecast, setForecast] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!session) return;
    setLoading(true);
    setError(null);

    // Fetch the latest flows for this session to build a window
    apiFetch(`/sessions/${encodeURIComponent(session.session_key)}/flows?limit=6`)
      .then(flows => {
        if (flows.length < 6) {
          setError(`Need at least 6 flows for forecast, have ${flows.length}`);
          setLoading(false);
          return;
        }
        // Build the window from the latest 6 flows' features
        // The features are stored raw in the DB, we need to send scaled values
        // For now, use the feature values directly — the backend handles scaling
        const window = flows.slice(0, 6).reverse().map(f => {
          const feats = f.features;
          return [
            feats.flow_duration, feats.tot_fwd_pkts, feats.tot_bwd_pkts,
            feats.fwd_pkt_len_mean, feats.bwd_pkt_len_mean, feats.flow_bytes_s,
            feats.flow_pkts_s, feats.flow_iat_mean, feats.flow_iat_std,
            feats.fwd_iat_mean, feats.bwd_iat_mean, feats.syn_flag_cnt,
            feats.ack_flag_cnt, feats.fin_flag_cnt, feats.rst_flag_cnt,
            feats.psh_flag_cnt, feats.urg_flag_cnt, feats.down_up_ratio,
            feats.pkt_size_avg, feats.ttl_variance, feats.tcp_win_size,
            feats.retransmit_cnt,
          ];
        });

        return Promise.all([
          apiPost('/forecast', { window, k_steps: 6, n_mc_samples: 20, needs_scaling: true }),
          apiPost('/explain', { window, top_k: 10, needs_scaling: true }),
        ]);
      })
      .then(results => {
        if (results) {
          setForecast(results[0]);
          setExplanation(results[1]);
        }
        setLoading(false);
      })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [session]);

  if (!session) {
    return (
      <div className="empty-state">
        <Activity size={32}/>
        <p>Select a session from the Dashboard to view its forecast.</p>
      </div>
    );
  }

  if (loading) {
    return <div className="empty-state"><div className="loading-spinner"/><p>Running forecast...</p></div>;
  }

  if (error) {
    return <div className="empty-state"><AlertTriangle size={32} color="var(--severity-high)"/><p>{error}</p></div>;
  }

  // Prepare chart data
  const chartData = forecast?.steps?.map(s => ({
    step: `+${s.step}`,
    mean: s.infiltration_prob_mean,
    ema: s.infiltration_prob_ema,
    upper: Math.min(1, s.infiltration_prob_mean + s.infiltration_prob_std),
    lower: Math.max(0, s.infiltration_prob_mean - s.infiltration_prob_std),
    stage: s.predicted_stage,
  })) || [];

  const maxImportance = explanation?.attributions ?
    Math.max(...explanation.attributions.map(a => Math.abs(a.importance))) : 1;

  return (
    <>
      <div style={{marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'baseline', gap: 'var(--sp-3)'}}>
        <span className="mono" style={{color: 'var(--text-secondary)', fontSize: '0.75rem'}}>
          {session.src_ip} → {session.dst_ip}
        </span>
        <span className={`stage-badge ${stageClass(session.latest_stage)}`}>{session.latest_stage}</span>
        {forecast?.alert_triggered && (
          <span className="severity-badge critical">Alert at step +{forecast.alert_at_step}</span>
        )}
      </div>

      <div className="forecast-layout">
        {/* ── Rollout Chart (hero) ── */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">K-Step Infiltration Forecast</span>
            <span className="mono" style={{fontSize: '0.7rem', color: 'var(--text-muted)'}}>
              MC n=20 · EMA α=0.4
            </span>
          </div>
          <div className="panel-body chart-container">
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={chartData} margin={{top: 10, right: 20, bottom: 5, left: 10}}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d"/>
                <XAxis dataKey="step" tick={{fontSize: 11}}/>
                <YAxis domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1.0]} tick={{fontSize: 11}}/>
                <Tooltip
                  contentStyle={{background: '#161b22', border: '1px solid #2d333b', borderRadius: 4, fontSize: 12}}
                  labelStyle={{color: '#8b949e'}}
                />
                {/* Uncertainty band */}
                <Area type="monotone" dataKey="upper" stroke="none" fill="#2f81f7" fillOpacity={0.1} stackId="band"/>
                <Area type="monotone" dataKey="lower" stroke="none" fill="#0f1117" fillOpacity={1} stackId="band"/>
                {/* MC mean */}
                <Area type="monotone" dataKey="mean" stroke="#2f81f7" strokeWidth={2} fill="none" name="MC Mean"/>
                {/* EMA */}
                <Area type="monotone" dataKey="ema" stroke="#8b949e" strokeWidth={1.5} strokeDasharray="4 3" fill="none" name="EMA"/>
                {/* Decision threshold */}
                <ReferenceLine y={forecast?.threshold || 0.5} stroke="#da3633" strokeDasharray="6 4" strokeWidth={1}
                  label={{value: 'Threshold', position: 'right', fill: '#da3633', fontSize: 10}}/>
              </AreaChart>
            </ResponsiveContainer>

            {/* MITRE stage track */}
            <div className="stage-track">
              {chartData.map((d, i) => (
                <div key={i} className="stage-track-item" style={{background: stageColor(d.stage) + '20', color: stageColor(d.stage)}}>
                  {d.stage}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── SHAP Panel ── */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Feature Attribution</span>
            <span className="mono" style={{fontSize: '0.7rem', color: 'var(--text-muted)'}}>
              Gradient × Input
            </span>
          </div>
          <div className="panel-body">
            {explanation && (
              <>
                <div style={{marginBottom: 'var(--sp-4)', display: 'flex', gap: 'var(--sp-4)'}}>
                  <div className="stat-item">
                    <span className="stat-value" style={{fontSize: '1rem'}}>{formatProb(explanation.infiltration_probability)}</span>
                    <span className="stat-label">P(infil)</span>
                  </div>
                  <div className="stat-item">
                    <span className={`stage-badge ${stageClass(explanation.predicted_stage)}`}>{explanation.predicted_stage}</span>
                  </div>
                </div>
                <div className="shap-bar-container">
                  {explanation.attributions.map((attr, i) => (
                    <div key={i} className="shap-row">
                      <span className="shap-feature">{attr.feature}</span>
                      <div className="shap-bar-track">
                        <div
                          className={`shap-bar ${attr.direction}`}
                          style={{width: `${(Math.abs(attr.importance) / maxImportance) * 100}%`}}
                        />
                      </div>
                      <span className="shap-value">{attr.importance > 0 ? '+' : ''}{attr.importance.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
                <div style={{marginTop: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', fontSize: '0.7rem', color: 'var(--text-muted)'}}>
                  <span style={{color: 'var(--severity-critical)'}}>■ pushes → malicious</span>
                  <span style={{color: 'var(--accent)'}}>■ pushes → benign</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// ALERTS VIEW — triage table
// ═══════════════════════════════════════════════════════════════
function AlertsView() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  const refresh = useCallback(() => {
    const params = filter === 'all' ? '' : `?severity=${filter}`;
    apiFetch(`/alerts${params}`).then(a => { setAlerts(a); setLoading(false); }).catch(() => setLoading(false));
  }, [filter]);

  useEffect(() => { refresh(); const iv = setInterval(refresh, 5000); return () => clearInterval(iv); }, [refresh]);

  const acknowledge = async (id) => {
    await apiPost(`/alerts/${id}/acknowledge`, {});
    refresh();
  };

  return (
    <>
      <div style={{display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)'}}>
        <span style={{fontSize: '0.8rem', fontWeight: 600}}>Alerts</span>
        <div style={{display: 'flex', gap: 'var(--sp-1)'}}>
          {['all', 'critical', 'high', 'medium'].map(f => (
            <button key={f} className={`btn btn-sm ${filter === f ? 'btn-primary' : ''}`} onClick={() => setFilter(f)}>
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="data-table-container">
        {loading ? (
          <div className="empty-state"><div className="loading-spinner"/></div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={32}/>
            <p>No alerts. System is clear.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Session</th>
                <th>Stage</th>
                <th>P(Infiltration)</th>
                <th>Recommended Action</th>
                <th>Time</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(a => (
                <tr key={a.id}>
                  <td><span className={`severity-badge ${a.severity}`}>{a.severity}</span></td>
                  <td className="mono">{a.session_key.substring(0, 28)}</td>
                  <td><span className={`stage-badge ${stageClass(a.predicted_stage)}`}>{a.predicted_stage}</span></td>
                  <td className="mono">{formatProb(a.infiltration_prob)}</td>
                  <td><span className="alert-action">{a.recommended_action}</span></td>
                  <td className="mono">{formatTime(a.created_at)}</td>
                  <td>
                    {a.acknowledged ? (
                      <span className="flex items-center gap-2" style={{color: 'var(--text-muted)', fontSize: '0.75rem'}}>
                        <Check size={12}/> Ack'd
                      </span>
                    ) : (
                      <button className="btn btn-sm" onClick={() => acknowledge(a.id)}>Acknowledge</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// INGEST PANEL — CSV upload
// ═══════════════════════════════════════════════════════════════
function IngestPanel() {
  const [result, setResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const handleFile = async (file) => {
    if (!file || !file.name.endsWith('.csv')) {
      setResult({ error: 'Please upload a CSV file' });
      return;
    }
    setUploading(true);
    setResult(null);
    try {
      const data = await apiUpload('/ingest/csv', file);
      setResult(data);
    } catch (e) {
      setResult({ error: e.message });
    }
    setUploading(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  return (
    <>
      <div style={{marginBottom: 'var(--sp-4)'}}>
        <span style={{fontSize: '0.8rem', fontWeight: 600}}>Ingest Flow Data</span>
        <p style={{fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 'var(--sp-1)'}}>
          Upload a CSV with the 22 CIC-IDS features. Each row is a flow record.
          Include <code className="mono">src_ip</code>, <code className="mono">dst_ip</code>, <code className="mono">timestamp</code> columns for session grouping.
        </p>
      </div>

      <div
        className={`upload-zone ${dragging ? 'dragging' : ''}`}
        onClick={() => fileRef.current?.click()}
        onDrop={onDrop}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
      >
        {uploading ? (
          <><div className="loading-spinner" style={{margin: '0 auto var(--sp-2)'}}/><p>Processing...</p></>
        ) : (
          <><Upload size={28} className="upload-icon"/><p>Drop a CSV file here or click to browse</p></>
        )}
        <input ref={fileRef} type="file" accept=".csv" style={{display: 'none'}} onChange={e => handleFile(e.target.files[0])}/>
      </div>

      {result && (
        <div className="panel mt-4">
          <div className="panel-body">
            {result.error ? (
              <p style={{color: 'var(--severity-critical)'}}>{result.error}</p>
            ) : (
              <>
                <div className="stats-bar">
                  <div className="stat-item">
                    <span className="stat-value" style={{color: 'var(--severity-low)'}}>{result.flows_accepted}</span>
                    <span className="stat-label">Accepted</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-value" style={{color: result.flows_rejected > 0 ? 'var(--severity-critical)' : undefined}}>{result.flows_rejected}</span>
                    <span className="stat-label">Rejected</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-value" style={{color: result.alerts_generated > 0 ? 'var(--severity-critical)' : undefined}}>{result.alerts_generated}</span>
                    <span className="stat-label">Alerts generated</span>
                  </div>
                </div>
                {result.errors?.length > 0 && (
                  <div style={{marginTop: 'var(--sp-3)'}}>
                    <span style={{fontSize: '0.75rem', fontWeight: 600, color: 'var(--severity-high)'}}>Validation errors:</span>
                    <ul style={{marginTop: 'var(--sp-1)', fontSize: '0.72rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', listStyle: 'none'}}>
                      {result.errors.slice(0, 10).map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

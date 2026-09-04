import { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer,
} from 'recharts';
import {
  Activity, AlertTriangle, Shield, Upload, Radio,
  Eye, ChevronRight, Check, MonitorDot, Database,
  Zap, Settings, BarChart3, Terminal,
  Wifi, ArrowDownToLine, ArrowUpFromLine,
  Network, FlaskConical,
} from 'lucide-react';
import { apiFetch, apiPost, apiUpload, createWebSocket } from './api';
import {
  stageClass, stageColor, stageIndex, severityClass,
  formatTime, formatProb, formatDuration, STAGES,
} from './utils';
import './index.css';

const DEFAULT_FEAT_ORDER = [
  'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_mean',
  'bwd_pkt_len_mean', 'flow_bytes_s', 'flow_pkts_s', 'flow_iat_mean',
  'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean', 'syn_flag_cnt',
  'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt',
  'urg_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'ttl_variance',
  'tcp_win_size', 'retransmit_cnt',
];

// ── Data source banner helpers ────────────────────────────────────────────
const SOURCE_LABELS = {
  simulated: { label: 'SIMULATION MODE', color: 'var(--accent)', icon: FlaskConical },
  live_capture: { label: 'LIVE CAPTURE', color: 'var(--severity-low)', icon: Wifi },
  csv_upload: { label: 'CSV UPLOAD', color: 'var(--severity-medium)', icon: Upload },
  api: { label: 'API INGEST', color: 'var(--text-secondary)', icon: Zap },
};

// Direction badge
function DirBadge({ dir }) {
  const cfg = {
    inbound:  { label: 'IN',  color: '#c0392b', icon: ArrowDownToLine },
    outbound: { label: 'OUT', color: '#e67e22', icon: ArrowUpFromLine },
    internal: { label: 'INT', color: 'var(--text-muted)', icon: Network },
    unknown:  { label: '?',   color: 'var(--text-muted)', icon: Network },
  }[dir] || { label: '?', color: 'var(--text-muted)', icon: Network };
  const Icon = cfg.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 2,
      fontSize: '0.6rem', color: cfg.color, fontWeight: 600,
      letterSpacing: '0.05em',
    }}>
      <Icon size={9}/> {cfg.label}
    </span>
  );
}

// Source badge
function SourceBadge({ src }) {
  const cfg = SOURCE_LABELS[src] || SOURCE_LABELS.api;
  const Icon = cfg.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 2,
      fontSize: '0.6rem', color: cfg.color, fontWeight: 500,
      letterSpacing: '0.04em',
    }}>
      <Icon size={8}/> {src === 'simulated' ? 'SIM' : src === 'live_capture' ? 'LIVE' : src?.toUpperCase() || 'API'}
    </span>
  );
}

// Compromise pulse — visual overlay for sessions in active attack stage
function CompromiseIndicator({ stage, riskScore }) {
  const isCompromised = stageIndex(stage) >= 3 && (riskScore || 0) > 0.5;
  const isExfil = stage === 'Exfiltration';
  if (!isCompromised) return null;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      fontSize: '0.58rem', fontWeight: 700,
      color: isExfil ? 'var(--severity-critical)' : 'var(--severity-high)',
      animation: 'compromisePulse 1.2s ease-in-out infinite',
      letterSpacing: '0.05em',
    }}>
      ⬛ {isExfil ? 'COMPROMISED' : 'UNDER ATTACK'}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════
// APP SHELL
// ═══════════════════════════════════════════════════════════════
export default function App() {
  const [view, setView] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [alertCount, setAlertCount] = useState(0);
  const [selectedSession, setSelectedSession] = useState(null);
  const [clock, setClock] = useState(new Date());
  // BUG-08: feature order from backend — avoids 3 hardcoded copies
  const [featureList, setFeatureList] = useState(null);
  const [systemMode, setSystemMode] = useState('live');
  const [simulatorRunning, setSimulatorRunning] = useState(false);

  // Live clock
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const fetchSystemMode = useCallback(() => {
    apiFetch('/system/mode')
      .then(m => {
        if (m?.mode) setSystemMode(m.mode);
        if (typeof m?.simulator_running === 'boolean') setSimulatorRunning(m.simulator_running);
      })
      .catch(() => {});
  }, []);

  // Health + alert polling + system mode
  useEffect(() => {
    const updateHealth = (h) => {
      setHealth(h);
      if (h?.features && Array.isArray(h.features)) {
        setFeatureList(prev => {
          if (prev && prev.length === h.features.length && prev.every((v, i) => v === h.features[i])) {
            return prev;
          }
          return h.features;
        });
      }
      if (h?.system_mode) setSystemMode(h.system_mode);
    };

    apiFetch('/health').then(updateHealth).catch(() => setHealth({ status: 'offline' }));
    apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
    fetchSystemMode();

    const iv = setInterval(() => {
      apiFetch('/health').then(updateHealth).catch(() => setHealth({ status: 'offline' }));
      apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
      fetchSystemMode();
    }, 5000);
    return () => clearInterval(iv);
  }, [fetchSystemMode]);

  const handleToggleMode = async (newMode) => {
    try {
      const res = await apiPost('/system/mode', { mode: newMode });
      setSystemMode(res.mode);
      setSimulatorRunning(res.simulator_running);
    } catch (e) {
      console.error('Failed to change mode', e);
    }
  };

  const handleStartSimulator = async () => {
    try {
      const res = await apiPost('/system/simulator/start', {});
      if (res.status === 'started' || res.status === 'already_running') {
        setSimulatorRunning(true);
      }
    } catch (e) {
      alert(e.message || 'Failed to start simulator');
    }
  };

  const handleStopSimulator = async () => {
    try {
      await apiPost('/system/simulator/stop', {});
      setSimulatorRunning(false);
    } catch (e) {
      alert(e.message || 'Failed to stop simulator');
    }
  };

  const handlePurgeSimulated = async () => {
    if (!window.confirm('Are you sure? This will delete all simulated flows, sessions, and alerts from the database. Live capture data will NOT be touched.')) {
      return;
    }
    try {
      const res = await apiPost('/system/purge-simulated', {});
      alert(`Purged ${res.deleted_flows} simulated flows, ${res.deleted_sessions} sessions, and ${res.deleted_alerts} alerts.`);
    } catch (e) {
      alert(e.message || 'Failed to purge data');
    }
  };

  const onSelectSession = (session) => {
    setSelectedSession(session);
    setView('forecast');
  };

  const viewLabels = {
    dashboard: 'DASHBOARD',
    live_logs: 'LIVE_LOGS',
    alerts: 'ALERTS',
    forecast: 'FORECAST',
    explain: 'EXPLAINABILITY',
    reports: 'REPORTS',
    ingest: 'INGEST',
    settings: 'SETTINGS',
  };

  const systemStatus = health?.status === 'ok' ? 'nominal' : health?.status === 'offline' ? 'offline' : 'degraded';

  return (
    <div className="app-layout">
      {/* ── Sidebar ── */}
      <nav className="sidebar">
        <div className="sidebar-brand">
          <h1>NetForecast</h1>
          <span>MITRE ATT&CK Forecasting Engine</span>
        </div>

        <div className="nav-section">
          <div className="nav-label">// SYSTEM_MODULES</div>
          <button className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
            <MonitorDot size={15}/> DASHBOARD
          </button>
          <button className={`nav-item ${view === 'live_logs' ? 'active' : ''}`} onClick={() => setView('live_logs')}>
            <Terminal size={15}/> LIVE_LOGS
            <span className="nav-live-dot"/>
          </button>
          <button className={`nav-item ${view === 'alerts' ? 'active' : ''}`} onClick={() => setView('alerts')}>
            <AlertTriangle size={15}/> ALERTS
            {alertCount > 0 && <span className="nav-badge">{alertCount}</span>}
          </button>
          <button className={`nav-item ${view === 'forecast' ? 'active' : ''}`} onClick={() => setView('forecast')}>
            <Activity size={15}/> FORECAST
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">// ANALYSIS</div>
          <button className={`nav-item ${view === 'explain' ? 'active' : ''}`} onClick={() => setView('explain')}>
            <Eye size={15}/> EXPLAINABILITY
          </button>
          <button className={`nav-item ${view === 'reports' ? 'active' : ''}`} onClick={() => setView('reports')}>
            <BarChart3 size={15}/> REPORTS
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">// DATA</div>
          <button className={`nav-item ${view === 'ingest' ? 'active' : ''}`} onClick={() => setView('ingest')}>
            <Upload size={15}/> INGEST
          </button>
          <button className={`nav-item ${view === 'settings' ? 'active' : ''}`} onClick={() => setView('settings')}>
            <Settings size={15}/> SETTINGS
          </button>
        </div>

        <div className="sidebar-status">
          <div className="sidebar-status-label">// STATUS</div>
          <div className={`sidebar-status-value ${systemStatus}`}>
            <span className="status-block">&#9632;</span>
            {systemStatus === 'nominal' ? 'SYSTEM NOMINAL' : systemStatus === 'degraded' ? 'DEGRADED' : 'OFFLINE'}
          </div>
        </div>
      </nav>

      {/* ── Header / Command Bar ── */}
      <header className="header">
        <span className="header-breadcrumb">
          SYS_VIEW // <span className="view-name">[{viewLabels[view] || view.toUpperCase()}]</span>
        </span>
        <div className="header-right">
          <div className="header-indicator">
            <span className={`dot ${systemStatus === 'nominal' ? '' : systemStatus}`}/>
            {health?.model_loaded ? `MODEL: ${health.device?.toUpperCase() || 'CPU'}` : 'MODEL: LOADING'}
          </div>
          <div className="header-indicator">
            <Wifi size={10}/>
            {alertCount > 0 ? `ALERTS: ${alertCount}` : 'ALERTS: 0'}
          </div>
          <span className="header-clock">
            {clock.toISOString().slice(0, 19).replace('T', ' ')} UTC
          </span>
        </div>
      </header>

      {/* ── Main ── */}
      <main className="main-content">
        {view === 'dashboard' && (
          <Dashboard
            onSelectSession={onSelectSession}
            featureList={featureList}
            systemMode={systemMode}
          />
        )}
        {view === 'forecast' && <ForecastView session={selectedSession} onBack={() => setView('dashboard')} featureList={featureList}/>}
        {view === 'alerts' && <AlertsView/>}
        {view === 'live_logs' && <LiveLogsView/>}
        {view === 'explain' && <ExplainView featureList={featureList}/>}
        {view === 'reports' && <ReportsView/>}
        {view === 'ingest' && <IngestPanel/>}
        {view === 'settings' && (
          <SettingsView
            health={health}
            systemMode={systemMode}
            onToggleMode={handleToggleMode}
            simulatorRunning={simulatorRunning}
            onStartSimulator={handleStartSimulator}
            onStopSimulator={handleStopSimulator}
            onPurgeSimulated={handlePurgeSimulated}
          />
        )}
      </main>

      {/* ── Footer ── */}
      <footer className="footer">
        <span>NetForecast v1.0 // SIH 2026 PS26153</span>
        <span>LSTM World Model // {health?.features_count || 22} Features // Window={health?.stages?.length || 6}</span>
      </footer>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
// KILL CHAIN — visual MITRE ATT&CK stage progress
// ═══════════════════════════════════════════════════════════════
function KillChain({ currentStage, forecastStages = [] }) {
  const currentIdx = stageIndex(currentStage);
  const forecastIdxSet = new Set(forecastStages.map(s => stageIndex(s)));

  return (
    <div className="kill-chain">
      {STAGES.map((stage, i) => {
        let dotClass = '';
        if (i < currentIdx) dotClass = 'passed';
        else if (i === currentIdx) dotClass = 'current';
        else if (forecastIdxSet.has(i)) dotClass = 'forecast';

        let connClass = '';
        if (i < currentIdx) connClass = 'passed';
        else if (i >= currentIdx && forecastIdxSet.has(i)) connClass = 'forecast';

        return (
          <div key={stage} className="kill-chain-node" style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', width: '100%' }}>
              {i > 0 && <div className={`kill-chain-connector ${connClass}`} style={{ flex: 1 }}/>}
              <div className={`kill-chain-dot ${dotClass}`}/>
              {i < STAGES.length - 1 && <div className={`kill-chain-connector ${i < currentIdx ? 'passed' : i === currentIdx && forecastIdxSet.size > 0 ? 'forecast' : ''}`} style={{ flex: 1 }}/>}
            </div>
            <span className="kill-chain-label">{stage}</span>
          </div>
        );
      })}
    </div>
  );
}

function KillChainCompact({ currentStage }) {
  const currentIdx = stageIndex(currentStage);
  return (
    <div className="kill-chain-compact">
      {STAGES.map((_, i) => (
        <span key={i}>
          <span className={`kc-dot ${i < currentIdx ? 'passed' : i === currentIdx ? 'current' : ''}`}/>
          {i < STAGES.length - 1 && <span className={`kc-connector ${i < currentIdx ? 'passed' : ''}`}/>}
        </span>
      ))}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
// DASHBOARD — stats + sessions table with kill chain
// ═══════════════════════════════════════════════════════════════
function Dashboard({ onSelectSession, systemMode }) {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [simBannerDismissed, setSimBannerDismissed] = useState(false);
  const [sortBy, setSortBy] = useState('last_seen');

  const refresh = useCallback(() => {
    const srcParam = systemMode === 'live' ? '&source=live' : '';
    Promise.all([
      apiFetch(`/sessions?limit=100&sort_by=${sortBy}${srcParam}`),
      apiFetch('/dashboard/stats'),
      apiFetch('/alerts/stats'),
    ]).then(([s, st, as]) => {
      setSessions(s);
      setStats(st);
      setAlertStats(as);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sortBy, systemMode]);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 3000);
    return () => clearInterval(iv);
  }, [refresh]);

  return (
    <>
      {/* §7 — Simulation banner */}
      {stats.has_simulated_data && !simBannerDismissed && (
        <div style={{
          background: 'linear-gradient(90deg, rgba(230,126,34,0.12), rgba(230,126,34,0.06))',
          border: '1px solid var(--accent)',
          borderRadius: 'var(--radius)',
          padding: 'var(--sp-2) var(--sp-4)',
          marginBottom: 'var(--sp-3)',
          display: 'flex', alignItems: 'center', gap: 'var(--sp-3)',
        }}>
          <FlaskConical size={13} color="var(--accent)"/>
          <span className="mono" style={{ fontSize: '0.67rem', color: 'var(--accent)', flex: 1 }}>
            SIMULATION DATA ACTIVE — traffic was generated by <code>traffic_simulator.py</code>, not captured from a real network interface.
          </span>
          <button className="btn btn-sm" onClick={() => setSimBannerDismissed(true)} style={{ fontSize: '0.6rem' }}>DISMISS</button>
        </div>
      )}

      {/* Stats cards */}
      <div className="stats-bar">
        <div className="stat-card">
          <div className="stat-card-label">TOTAL_SESSIONS</div>
          <div className="stat-card-value">{stats.total_sessions || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">FLOWS_INGESTED</div>
          <div className="stat-card-value">{stats.total_flows || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">AT_RISK</div>
          <div className="stat-card-value" style={{ color: (stats.at_risk_sessions || 0) > 0 ? 'var(--severity-critical)' : undefined }}>
            {stats.at_risk_sessions || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">UNACK_ALERTS</div>
          <div className="stat-card-value" style={{ color: (alertStats.unacknowledged || 0) > 0 ? 'var(--severity-high)' : undefined }}>
            {alertStats.unacknowledged || 0}
          </div>
        </div>
        {stats.direction_breakdown && (
          <div className="stat-card">
            <div className="stat-card-label">INBOUND</div>
            <div className="stat-card-value" style={{ color: 'var(--severity-high)', fontSize: '1rem' }}>
              {stats.direction_breakdown.inbound || 0}
            </div>
          </div>
        )}
        {stats.direction_breakdown && (
          <div className="stat-card">
            <div className="stat-card-label">OUTBOUND</div>
            <div className="stat-card-value" style={{ color: 'var(--accent)', fontSize: '1rem' }}>
              {stats.direction_breakdown.outbound || 0}
            </div>
          </div>
        )}
      </div>

      {/* Sessions table header bar with mode indication */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
          <span className="section-label" style={{ marginBottom: 0 }}>ACTIVE_SESSIONS</span>
          <span className="mono text-sm" style={{ color: 'var(--text-muted)' }}>({sessions.length})</span>
        </div>
        {/* Read-only indication badge based on Settings mode */}
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '3px 10px',
          borderRadius: 'var(--radius)',
          border: `1px solid ${systemMode === 'live' ? 'rgba(39, 174, 96, 0.4)' : 'rgba(230, 126, 34, 0.4)'}`,
          background: systemMode === 'live' ? 'rgba(39, 174, 96, 0.08)' : 'rgba(230, 126, 34, 0.08)',
          fontSize: '0.67rem',
          fontWeight: 700,
          letterSpacing: '0.04em',
          color: systemMode === 'live' ? '#27ae60' : '#e67e22',
        }}>
          <span style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: systemMode === 'live' ? '#27ae60' : '#e67e22',
            boxShadow: systemMode === 'live' ? '0 0 6px #27ae60' : '0 0 6px #e67e22',
          }}/>
          {systemMode === 'live' ? 'MODE: LIVE ONLY' : 'MODE: SIMULATION'}
        </div>
      </div>

      {/* Sessions table */}
      <div className="data-table-wrap">
        {loading ? (
          <div className="empty-state"><div className="loading-spinner"/><p>Loading sessions...</p></div>
        ) : sessions.length === 0 ? (
          <div className="empty-state">
            <Database size={28} color="var(--text-muted)"/>
            <p>No sessions yet. Ingest flow data or run the traffic simulator.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>SRC_IP</th>
                <th>DST_IP</th>
                <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('flow_count')}>FLOWS {sortBy === 'flow_count' ? '▼' : ''}</th>
                <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('latest_risk_score')}>RISK {sortBy === 'latest_risk_score' ? '▼' : ''}</th>
                <th>STAGE</th>
                <th>MAX_STAGE</th>
                <th>DIR</th>
                <th>SRC</th>
                <th>KILL_CHAIN</th>
                <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('last_seen')}>LAST_SEEN {sortBy === 'last_seen' ? '▼' : ''}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => {
                const isCompromised = stageIndex(s.latest_stage) >= 3 && (s.latest_risk_score || 0) > 0.5;
                return (
                  <tr
                    key={s.session_key}
                    onClick={() => onSelectSession(s)}
                    style={{
                      background: isCompromised
                        ? `linear-gradient(90deg, rgba(192,57,43,0.06), transparent)`
                        : undefined,
                    }}
                  >
                    <td>{s.src_ip || '\u2014'}</td>
                    <td>{s.dst_ip || '\u2014'}</td>
                    <td>{s.flow_count}</td>
                    <td>
                      <div className="risk-cell">
                        <div className={`risk-bar ${severityClass(s.latest_risk_score)}`}/>
                        <span>{formatProb(s.latest_risk_score)}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`stage-badge ${stageClass(s.latest_stage)}`}>{s.latest_stage}</span>
                      <CompromiseIndicator stage={s.latest_stage} riskScore={s.latest_risk_score}/>
                    </td>
                    <td>
                      <span className={`stage-badge ${stageClass(s.max_stage_reached || 'Benign')}`} style={{ opacity: 0.75, fontSize: '0.58rem' }}>
                        {s.max_stage_reached || 'Benign'}
                      </span>
                    </td>
                    <td><DirBadge dir={s.direction}/></td>
                    <td><SourceBadge src={s.source}/></td>
                    <td><KillChainCompact currentStage={s.max_stage_reached || s.latest_stage}/></td>
                    <td>{formatTime(s.last_seen)}</td>
                    <td><ChevronRight size={13} color="var(--text-muted)"/></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}


// ═══════════════════════════════════════════════════════════════
// FORECAST VIEW — kill chain + rollout chart + SHAP + flow logs
// ═══════════════════════════════════════════════════════════════
function ForecastView({ session, onBack, featureList }) {
  const [forecast, setForecast] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const featOrder = featureList || DEFAULT_FEAT_ORDER;
  const sessionKey = session?.session_key;

  useEffect(() => {
    if (!sessionKey) return;
    let active = true;

    (async () => {
      setLoading(true);
      setError(null);
      try {
        const allFlows = await apiFetch(`/sessions/${encodeURIComponent(sessionKey)}/flows?limit=100`);
        if (!active) return;
        setFlows(allFlows);
        if (allFlows.length < 6) {
          setError(`Need at least 6 flows for forecast, have ${allFlows.length}`);
          return;
        }
        const window = allFlows.slice(0, 6).reverse().map(f => featOrder.map(k => f.features?.[k] ?? 0));
        const [fc, exp] = await Promise.all([
          apiPost('/forecast', { window, k_steps: 6, n_mc_samples: 20, needs_scaling: true }),
          apiPost('/explain', { window, top_k: 10, needs_scaling: true }),
        ]);
        if (!active) return;
        setForecast(fc);
        setExplanation(exp);
      } catch (e) {
        if (active) setError(e.message);
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => { active = false; };
  }, [sessionKey, featOrder]);

  if (!session) {
    return (
      <div className="empty-state">
        <Activity size={28} color="var(--text-muted)"/>
        <p>Select a session from the Dashboard to view its attack forecast.</p>
      </div>
    );
  }

  // Only show full empty-state loader on initial fetch when no forecast exists yet
  if (loading && !forecast) {
    return <div className="empty-state"><div className="loading-spinner"/><p>Running forecast model...</p></div>;
  }

  // Only show full empty-state error if there is no forecast to display
  if (error && !forecast) {
    return <div className="empty-state"><AlertTriangle size={28} color="var(--severity-high)"/><p>{error}</p></div>;
  }

  const chartData = forecast?.steps?.map(s => ({
    step: `+${s.step}`,
    mean: s.infiltration_prob_mean,
    ema: s.infiltration_prob_ema,
    upper: Math.min(1, s.infiltration_prob_mean + s.infiltration_prob_std),
    lower: Math.max(0, s.infiltration_prob_mean - s.infiltration_prob_std),
    stage: s.predicted_stage,
  })) || [];

  const forecastStages = [...new Set(chartData.map(d => d.stage))];
  const maxImportance = explanation?.attributions
    ? Math.max(...explanation.attributions.map(a => Math.abs(a.importance)))
    : 1;

  return (
    <>
      {/* Session header + back button */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-3)', flexWrap: 'wrap' }}>
        <button className="btn btn-sm" onClick={onBack}>&larr; BACK</button>
        <span className="mono text-sm" style={{ color: 'var(--text-secondary)' }}>
          {session.src_ip} &rarr; {session.dst_ip}
        </span>
        <span className={`stage-badge ${stageClass(session.latest_stage)}`}>{session.latest_stage}</span>
        <DirBadge dir={session.direction}/>
        <SourceBadge src={session.source}/>
        <CompromiseIndicator stage={session.max_stage_reached || session.latest_stage} riskScore={session.latest_risk_score}/>
        {loading && (
          <span className="mono" style={{ fontSize: '0.62rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span className="loading-spinner" style={{ width: 10, height: 10, borderWidth: 1.5, margin: 0 }}/>
            SYNCING
          </span>
        )}
        {error && (
          <span className="severity-badge high" title={error} style={{ fontSize: '0.6rem' }}>REFRESH FAILED</span>
        )}
        {forecast?.alert_triggered && (
          <span className="severity-badge critical">ALERT AT STEP +{forecast.alert_at_step}</span>
        )}
      </div>

      {/* Kill Chain — full width hero */}
      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">KILL_CHAIN_PROGRESS</span>
          <span className="panel-meta">MITRE ATT&CK Stage Tracker</span>
        </div>
        <div className="panel-body">
          <KillChain currentStage={session.latest_stage} forecastStages={forecastStages}/>
        </div>
      </div>

      {/* Forecast chart + SHAP side by side */}
      <div className="forecast-grid">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">K_STEP_FORECAST</span>
            <span className="panel-meta">MC n=20 &middot; EMA &alpha;=0.4</span>
          </div>
          <div className="panel-body chart-container" style={{ minHeight: 320 }}>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={chartData} margin={{ top: 10, right: 20, bottom: 5, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d4c5b0"/>
                <XAxis dataKey="step" tick={{ fontSize: 11 }}/>
                <YAxis domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1.0]} tick={{ fontSize: 11 }}/>
                <Tooltip
                  contentStyle={{ background: '#fffbf5', border: '1px solid #d4c5b0', borderRadius: 3, fontSize: 12 }}
                  labelStyle={{ color: '#5a5245' }}
                />
                <Area type="monotone" dataKey="upper" stroke="none" fill="#e67e22" fillOpacity={0.08} stackId="band" isAnimationActive={false}/>
                <Area type="monotone" dataKey="lower" stroke="none" fill="#f5efe6" fillOpacity={1} stackId="band" isAnimationActive={false}/>
                <Area type="monotone" dataKey="mean" stroke="#e67e22" strokeWidth={2} fill="none" name="MC Mean" isAnimationActive={false}/>
                <Area type="monotone" dataKey="ema" stroke="#8a7f72" strokeWidth={1.5} strokeDasharray="4 3" fill="none" name="EMA" isAnimationActive={false}/>
                <ReferenceLine y={forecast?.threshold || 0.5} stroke="#c0392b" strokeDasharray="6 4" strokeWidth={1}
                  label={{ value: 'Threshold', position: 'right', fill: '#c0392b', fontSize: 10 }}/>
              </AreaChart>
            </ResponsiveContainer>

            {/* Stage track below chart */}
            <div className="stage-track">
              {chartData.map((d, i) => (
                <div key={i} className="stage-track-item" style={{ background: stageColor(d.stage) + '18', color: stageColor(d.stage) }}>
                  {d.stage}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* SHAP panel */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">FEATURE_ATTRIBUTION</span>
            <span className="panel-meta">Gradient &times; Input</span>
          </div>
          <div className="panel-body">
            {explanation && (
              <>
                <div style={{ marginBottom: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', alignItems: 'baseline' }}>
                  <div>
                    <span className="mono" style={{ fontSize: '1.1rem', fontWeight: 700 }}>{formatProb(explanation.infiltration_probability)}</span>
                    <span className="text-sm text-muted" style={{ marginLeft: 'var(--sp-2)' }}>P(INFIL)</span>
                  </div>
                  <span className={`stage-badge ${stageClass(explanation.predicted_stage)}`}>{explanation.predicted_stage}</span>
                </div>
                <div className="shap-bar-container">
                  {explanation.attributions.map((attr, i) => (
                    <div key={i} className="shap-row">
                      <span className="shap-feature">{attr.feature}</span>
                      <div className="shap-bar-track">
                        <div
                          className={`shap-bar ${attr.direction}`}
                          style={{ width: `${(Math.abs(attr.importance) / maxImportance) * 100}%` }}
                        />
                      </div>
                      <span className="shap-value">{attr.importance > 0 ? '+' : ''}{attr.importance.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', fontSize: '0.62rem' }}>
                  <span style={{ color: 'var(--severity-critical)' }}>&#9632; MALICIOUS</span>
                  <span style={{ color: 'var(--severity-low)' }}>&#9632; BENIGN</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ── Flow Logs Table ── */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">NETWORK_LOGS</span>
          <span className="panel-meta">{flows.length} flow records &middot; most recent first</span>
        </div>
        <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
          {flows.length === 0 ? (
            <div className="empty-state"><p>No flow records.</p></div>
          ) : (
            <table className="data-table" style={{ fontSize: '0.65rem' }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>TIMESTAMP</th>
                  <th>DURATION</th>
                  <th>FWD↑</th>
                  <th>BWD↓</th>
                  <th>BYTES/S</th>
                  <th>PKTS/S</th>
                  <th>SYN</th>
                  <th>ACK</th>
                  <th>RST</th>
                  <th>PSH</th>
                  <th>FIN</th>
                  <th>URG</th>
                  <th>TTL_VAR</th>
                  <th>WIN</th>
                  <th>RETX</th>
                  <th>P(INFIL)</th>
                  <th>STAGE</th>
                  <th>SRC</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f, i) => {
                  const feat = f.features || {};
                  const prob = f.infiltration_prob || 0;
                  const isAlert = prob > 0.5;
                  return (
                    <tr key={f.id} style={{
                      cursor: 'default',
                      background: isAlert ? 'rgba(192,57,43,0.05)' : undefined,
                    }}>
                      <td style={{ color: 'var(--text-muted)' }}>{flows.length - i}</td>
                      <td>{formatTime(f.timestamp)}</td>
                      <td>{formatDuration(feat.flow_duration)}</td>
                      <td>{(feat.tot_fwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.tot_bwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_bytes_s ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_pkts_s ?? 0).toFixed(1)}</td>
                      <td style={{ color: (feat.syn_flag_cnt ?? 0) > 3 ? 'var(--severity-high)' : undefined }}>{(feat.syn_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.ack_flag_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.rst_flag_cnt ?? 0) > 0 ? 'var(--severity-medium)' : undefined }}>{(feat.rst_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.psh_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.fin_flag_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.urg_flag_cnt ?? 0) > 0 ? 'var(--severity-critical)' : undefined }}>{(feat.urg_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.ttl_variance ?? 0).toFixed(1)}</td>
                      <td>{(feat.tcp_win_size ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.retransmit_cnt ?? 0) > 2 ? 'var(--severity-high)' : undefined }}>{(feat.retransmit_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: isAlert ? 'var(--severity-critical)' : 'var(--severity-low)', fontWeight: isAlert ? 700 : 400 }}>
                        {formatProb(prob)}
                      </td>
                      <td><span className={`stage-badge ${stageClass(f.predicted_stage || 'Benign')}`}>{f.predicted_stage || 'Benign'}</span></td>
                      <td><SourceBadge src={f.source}/></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}


// ═══════════════════════════════════════════════════════════════
// LIVE LOGS — WebSocket terminal feed
// ═══════════════════════════════════════════════════════════════
function LiveLogsView() {
  const [lines, setLines] = useState([]);
  const [connected, setConnected] = useState(false);
  const containerRef = useRef(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = createWebSocket();
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'pong') return;
        setLines(prev => {
          const next = [...prev, { ...data, _ts: new Date().toISOString() }];
          return next.length > 500 ? next.slice(-500) : next;
        });
      } catch { /* ignore non-JSON */ }
    };

    // Ping keepalive
    const pingIv = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 15000);

    return () => {
      clearInterval(pingIv);
      ws.close();
    };
  }, []);

  // Auto-scroll
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="terminal">
      <div className="terminal-header">
        <span className="terminal-title">
          LIVE_FLOW_FEED {connected ? '// CONNECTED' : '// DISCONNECTED'}
        </span>
        <span style={{ fontSize: '0.6rem', color: connected ? 'var(--severity-low)' : 'var(--severity-critical)' }}>
          &#9679; {connected ? 'LIVE' : 'OFFLINE'}
        </span>
      </div>
      <div className="terminal-body" ref={containerRef}>
        {lines.length === 0 ? (
          <div className="terminal-empty">
            <Radio size={24}/>
            <p style={{ marginTop: '8px' }}>Waiting for incoming flows...</p>
            <p style={{ fontSize: '0.65rem', marginTop: '4px' }}>
              Run the traffic simulator or live capture to see real-time data.
            </p>
          </div>
        ) : (
          lines.map((line, i) => (
            <div key={i} className="terminal-line">
              <span className="ts">{formatTime(line._ts)}</span>
              <span className="sep"> | </span>
              <span className="ip">{line.src_ip || '?'} &rarr; {line.dst_ip || '?'}</span>
              <span className="sep"> | </span>
              <DirBadge dir={line.direction}/>
              <span className="sep"> | </span>
              <SourceBadge src={line.source}/>
              <span className="sep"> | </span>
              <span className="val">{line.flow_count || 0} flows</span>
              <span className="sep"> | </span>
              <span className="val">P={formatProb(line.infiltration_prob)}</span>
              <span className="sep"> | </span>
              <span className="stage-flag">{line.predicted_stage || 'Benign'}</span>
              {(line.infiltration_prob || 0) > 0.5 && (
                <span className="alert-flag"> &#9650; ALERT</span>
              )}
              {line.max_stage_reached && line.max_stage_reached !== line.predicted_stage && (
                <span className="sep"> max=</span>
              )}
              {line.max_stage_reached && line.max_stage_reached !== line.predicted_stage && (
                <span className={`stage-flag ${stageClass(line.max_stage_reached)}`}>
                  {line.max_stage_reached}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
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
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
        <span className="section-label" style={{ marginBottom: 0 }}>FILTER:</span>
        <div style={{ display: 'flex', gap: 'var(--sp-1)' }}>
          {['all', 'critical', 'high', 'medium'].map(f => (
            <button key={f} className={`btn btn-sm ${filter === f ? 'btn-primary' : ''}`} onClick={() => setFilter(f)}>
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="data-table-wrap">
        {loading ? (
          <div className="empty-state"><div className="loading-spinner"/></div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={28} color="var(--text-muted)"/>
            <p>No alerts. System is clear.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>SEVERITY</th>
                <th>SESSION</th>
                <th>STAGE</th>
                <th>P(INFIL)</th>
                <th>ACTION</th>
                <th>TIME</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(a => (
                <tr key={a.id} style={{ cursor: 'default' }}>
                  <td><span className={`severity-badge ${a.severity}`}>{a.severity.toUpperCase()}</span></td>
                  <td>{a.session_key?.substring(0, 24) || '\u2014'}</td>
                  <td><span className={`stage-badge ${stageClass(a.predicted_stage)}`}>{a.predicted_stage}</span></td>
                  <td>{formatProb(a.infiltration_prob)}</td>
                  <td><span className="alert-action">{a.recommended_action}</span></td>
                  <td>{formatTime(a.created_at)}</td>
                  <td>
                    {a.acknowledged ? (
                      <span className="mono text-sm text-muted"><Check size={11}/> ACK</span>
                    ) : (
                      <button className="btn btn-sm" onClick={() => acknowledge(a.id)}>ACK</button>
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
// EXPLAIN VIEW — standalone feature attribution
// ═══════════════════════════════════════════════════════════════
function ExplainView({ featureList }) {
  const [sessions, setSessions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);

  const featOrder = featureList || DEFAULT_FEAT_ORDER;

  useEffect(() => {
    apiFetch('/sessions?limit=50').then(setSessions).catch(() => {});
  }, []);

  const explain = (session) => {
    setSelected(session);
    setLoading(true);
    apiFetch(`/sessions/${encodeURIComponent(session.session_key)}/flows?limit=6`)
      .then(flows => {
        if (flows.length < 6) throw new Error('Need 6+ flows');
        const window = flows.slice(0, 6).reverse().map(f => featOrder.map(k => f.features?.[k] ?? 0));
        return apiPost('/explain', { window, top_k: 22, needs_scaling: true });
      })
      .then(result => { setExplanation(result); setLoading(false); })
      .catch(() => { setLoading(false); });
  };

  const maxImp = explanation?.attributions
    ? Math.max(...explanation.attributions.map(a => Math.abs(a.importance)))
    : 1;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 'var(--sp-4)' }}>
      {/* Session picker */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">SELECT_SESSION</span>
        </div>
        <div style={{ maxHeight: 'calc(100vh - 200px)', overflowY: 'auto' }}>
          {sessions.map(s => (
            <div
              key={s.session_key}
              onClick={() => explain(s)}
              style={{
                padding: 'var(--sp-2) var(--sp-3)',
                borderBottom: '1px solid var(--border-muted)',
                cursor: 'pointer',
                background: selected?.session_key === s.session_key ? 'var(--accent-muted)' : 'transparent',
              }}
            >
              <div className="mono" style={{ fontSize: '0.7rem' }}>{s.src_ip} &rarr; {s.dst_ip}</div>
              <div style={{ display: 'flex', gap: 'var(--sp-2)', marginTop: '2px', alignItems: 'center' }}>
                <span className={`stage-badge ${stageClass(s.latest_stage)}`}>{s.latest_stage}</span>
                <span className="mono text-muted" style={{ fontSize: '0.6rem' }}>{s.flow_count} flows</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Attribution display */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">FEATURE_ATTRIBUTION</span>
          <span className="panel-meta">Gradient &times; Input (all 22 features)</span>
        </div>
        <div className="panel-body">
          {loading ? (
            <div className="empty-state"><div className="loading-spinner"/><p>Computing attributions...</p></div>
          ) : !explanation ? (
            <div className="empty-state"><Eye size={28} color="var(--text-muted)"/><p>Select a session to explain.</p></div>
          ) : (
            <>
              <div style={{ marginBottom: 'var(--sp-4)', display: 'flex', gap: 'var(--sp-4)', alignItems: 'baseline' }}>
                <div>
                  <span className="mono" style={{ fontSize: '1.3rem', fontWeight: 700 }}>{formatProb(explanation.infiltration_probability)}</span>
                  <span className="text-sm text-muted" style={{ marginLeft: 'var(--sp-2)' }}>P(INFILTRATION)</span>
                </div>
                <span className={`stage-badge ${stageClass(explanation.predicted_stage)}`}>{explanation.predicted_stage}</span>
              </div>
              <div className="shap-bar-container">
                {explanation.attributions.map((attr, i) => (
                  <div key={i} className="shap-row">
                    <span className="shap-feature">{attr.feature}</span>
                    <div className="shap-bar-track">
                      <div
                        className={`shap-bar ${attr.direction}`}
                        style={{ width: `${(Math.abs(attr.importance) / maxImp) * 100}%` }}
                      />
                    </div>
                    <span className="shap-value">{attr.importance > 0 ? '+' : ''}{attr.importance.toFixed(4)}</span>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', fontSize: '0.62rem' }}>
                <span style={{ color: 'var(--severity-critical)' }}>&#9632; pushes &rarr; MALICIOUS</span>
                <span style={{ color: 'var(--severity-low)' }}>&#9632; pushes &rarr; BENIGN</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
// REPORTS — aggregate stats + stage distribution
// ═══════════════════════════════════════════════════════════════
function ReportsView() {
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [stageDist, setStageDist] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      apiFetch('/dashboard/stats'),
      apiFetch('/alerts/stats'),
      apiFetch('/dashboard/stage-distribution').catch(() => []),
    ]).then(([st, as, sd]) => {
      setStats(st);
      setAlertStats(as);
      setStageDist(Array.isArray(sd) ? sd : []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const maxCount = stageDist.length > 0 ? Math.max(...stageDist.map(s => s.count)) : 1;

  const copySummary = () => {
    const summary = {
      generated_at: new Date().toISOString(),
      total_sessions: stats.total_sessions,
      total_flows: stats.total_flows,
      at_risk_sessions: stats.at_risk_sessions,
      total_alerts: alertStats.total,
      unacknowledged_alerts: alertStats.unacknowledged,
      critical_unacknowledged: alertStats.critical_unacknowledged,
      stage_distribution: stageDist,
    };
    navigator.clipboard.writeText(JSON.stringify(summary, null, 2));
  };

  if (loading) {
    return <div className="empty-state"><div className="loading-spinner"/><p>Loading report data...</p></div>;
  }

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-4)' }}>
        <span className="section-label" style={{ marginBottom: 0 }}>SYSTEM_REPORT</span>
        <button className="btn btn-sm" onClick={copySummary}>COPY JSON</button>
      </div>

      <div className="report-grid">
        {/* Stats panel */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">SUMMARY_STATS</span>
          </div>
          <div className="panel-body">
            <div className="settings-row"><span className="settings-key">TOTAL_SESSIONS</span><span className="settings-val">{stats.total_sessions || 0}</span></div>
            <div className="settings-row"><span className="settings-key">TOTAL_FLOWS</span><span className="settings-val">{stats.total_flows || 0}</span></div>
            <div className="settings-row"><span className="settings-key">AT_RISK_SESSIONS</span><span className="settings-val" style={{ color: (stats.at_risk_sessions || 0) > 0 ? 'var(--severity-critical)' : undefined }}>{stats.at_risk_sessions || 0}</span></div>
            <div className="settings-row"><span className="settings-key">TOTAL_ALERTS</span><span className="settings-val">{alertStats.total || 0}</span></div>
            <div className="settings-row"><span className="settings-key">UNACKNOWLEDGED</span><span className="settings-val" style={{ color: (alertStats.unacknowledged || 0) > 0 ? 'var(--severity-high)' : undefined }}>{alertStats.unacknowledged || 0}</span></div>
            <div className="settings-row"><span className="settings-key">CRITICAL_UNACK</span><span className="settings-val" style={{ color: (alertStats.critical_unacknowledged || 0) > 0 ? 'var(--severity-critical)' : undefined }}>{alertStats.critical_unacknowledged || 0}</span></div>
          </div>
        </div>

        {/* Stage distribution */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">STAGE_DISTRIBUTION</span>
          </div>
          <div className="panel-body">
            {stageDist.length === 0 ? (
              <div className="empty-state" style={{ padding: 'var(--sp-6)' }}><p>No stage data yet.</p></div>
            ) : (
              stageDist.map(s => (
                <div key={s.stage} className="stage-dist-bar">
                  <span className="stage-dist-label">{s.stage}</span>
                  <div className="stage-dist-track">
                    <div
                      className="stage-dist-fill"
                      style={{ width: `${(s.count / maxCount) * 100}%`, background: stageColor(s.stage) }}
                    />
                  </div>
                  <span className="stage-dist-count">{s.count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </>
  );
}


// ═══════════════════════════════════════════════════════════════
// SETTINGS — model info, health, feature list
// ═══════════════════════════════════════════════════════════════
function SettingsView({
  health,
  systemMode,
  onToggleMode,
  simulatorRunning,
  onStartSimulator,
  onStopSimulator,
  onPurgeSimulated,
}) {
  return (
    <div className="settings-grid">
      {/* ── Mode Control Card (Full width top) ── */}
      <div className="panel" style={{
        gridColumn: '1 / -1',
        border: systemMode === 'live' ? '1px solid #27ae60' : '1px solid #e67e22',
        background: systemMode === 'live' ? 'rgba(39, 174, 96, 0.03)' : 'rgba(230, 126, 34, 0.03)',
      }}>
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--sp-2)' }}>
          <div>
            <span className="panel-title">TRAFFIC_SOURCE_MODE</span>
            <span className="panel-meta">Master engine setting — switch between real live capture and synthetic simulation</span>
          </div>
          <div style={{ display: 'inline-flex', gap: 6, background: 'var(--surface)', padding: 4, borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <button
              className={`btn btn-sm ${systemMode === 'live' ? 'btn-primary' : ''}`}
              onClick={() => onToggleMode?.('live')}
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '4px 14px',
                background: systemMode === 'live' ? '#27ae60' : 'transparent',
                borderColor: systemMode === 'live' ? '#219653' : 'transparent',
                color: systemMode === 'live' ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              🟢 LIVE ONLY
            </button>
            <button
              className={`btn btn-sm ${systemMode === 'simulated' ? 'btn-primary' : ''}`}
              onClick={() => onToggleMode?.('simulated')}
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '4px 14px',
                background: systemMode === 'simulated' ? '#e67e22' : 'transparent',
                borderColor: systemMode === 'simulated' ? '#d35400' : 'transparent',
                color: systemMode === 'simulated' ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              🟠 SIMULATED
            </button>
          </div>
        </div>
        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
            <div
              onClick={() => onToggleMode?.('live')}
              style={{
                padding: 'var(--sp-3)',
                borderRadius: 'var(--radius)',
                border: systemMode === 'live' ? '2px solid #27ae60' : '1px solid var(--border)',
                background: systemMode === 'live' ? 'rgba(39, 174, 96, 0.08)' : 'var(--surface)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--sp-1)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Wifi size={14} color="#27ae60"/>
                  <strong style={{ fontSize: '0.78rem', color: '#27ae60' }}>🟢 LIVE ONLY MODE (Real Packets)</strong>
                </div>
                {systemMode === 'live' && (
                  <span style={{ fontSize: '0.62rem', fontWeight: 700, color: '#27ae60', background: 'rgba(39, 174, 96, 0.15)', padding: '2px 6px', borderRadius: 4 }}>
                    ACTIVE
                  </span>
                )}
              </div>
              <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Strict real capture mode. Only genuine packets intercepted off your network interface by <code>capture/live_capture.py</code> are processed.
                Any simulated traffic sent to <code>/ingest</code> is <strong>rejected with HTTP 403 Forbidden</strong>.
              </p>
            </div>

            <div
              onClick={() => onToggleMode?.('simulated')}
              style={{
                padding: 'var(--sp-3)',
                borderRadius: 'var(--radius)',
                border: systemMode === 'simulated' ? '2px solid #e67e22' : '1px solid var(--border)',
                background: systemMode === 'simulated' ? 'rgba(230, 126, 34, 0.08)' : 'var(--surface)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--sp-1)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <FlaskConical size={14} color="#e67e22"/>
                  <strong style={{ fontSize: '0.78rem', color: '#e67e22' }}>🟠 SIMULATION MODE (Synthetic Lab)</strong>
                </div>
                {systemMode === 'simulated' && (
                  <span style={{ fontSize: '0.62rem', fontWeight: 700, color: '#e67e22', background: 'rgba(230, 126, 34, 0.15)', padding: '2px 6px', borderRadius: 4 }}>
                    ACTIVE
                  </span>
                )}
              </div>
              <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Demo and prototyping mode. Allows <code>demo/traffic_simulator.py</code> to inject multi-stage attack scenarios to demo kill-chain prediction without an isolated VM lab.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 'var(--sp-3)', borderTop: '1px solid var(--border)', flexWrap: 'wrap', gap: 'var(--sp-2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
              <span className="mono text-sm">SIMULATOR_PROCESS:</span>
              <span className="severity-badge" style={{
                background: simulatorRunning ? 'rgba(39,174,96,0.15)' : 'rgba(138,127,114,0.15)',
                color: simulatorRunning ? '#27ae60' : 'var(--text-muted)',
              }}>
                {simulatorRunning ? '● RUNNING' : '○ STOPPED'}
              </span>
              {systemMode === 'simulated' && (
                simulatorRunning ? (
                  <button className="btn btn-sm" onClick={onStopSimulator} style={{ color: 'var(--severity-critical)', borderColor: 'var(--severity-critical)' }}>
                    ⏹ STOP SIMULATOR
                  </button>
                ) : (
                  <button className="btn btn-sm" onClick={onStartSimulator}>
                    ▶ START SIMULATOR
                  </button>
                )
              )}
            </div>
            <button className="btn btn-sm" onClick={onPurgeSimulated} style={{ color: 'var(--severity-high)', borderColor: 'var(--border)' }}>
              🗑 PURGE ALL SIMULATED DATA
            </button>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">MODEL_INFO</span>
        </div>
        <div className="panel-body">
          <div className="settings-row"><span className="settings-key">ARCHITECTURE</span><span className="settings-val">LSTM (hidden=64)</span></div>
          <div className="settings-row"><span className="settings-key">DEVICE</span><span className="settings-val">{health?.device?.toUpperCase() || 'CPU'}</span></div>
          <div className="settings-row"><span className="settings-key">FEATURES</span><span className="settings-val">{health?.features_count || 22}</span></div>
          <div className="settings-row"><span className="settings-key">WINDOW_SIZE</span><span className="settings-val">6</span></div>
          <div className="settings-row"><span className="settings-key">STAGES</span><span className="settings-val">{health?.stages?.length || 6}</span></div>
          <div className="settings-row"><span className="settings-key">ALERT_THRESHOLD</span><span className="settings-val">0.50</span></div>
          <div className="settings-row"><span className="settings-key">MC_SAMPLES</span><span className="settings-val">20</span></div>
          <div className="settings-row"><span className="settings-key">EMA_ALPHA</span><span className="settings-val">0.40</span></div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">SYSTEM_HEALTH</span>
        </div>
        <div className="panel-body">
          <div className="settings-row"><span className="settings-key">STATUS</span><span className="settings-val" style={{ color: health?.status === 'ok' ? 'var(--severity-low)' : 'var(--severity-critical)' }}>{health?.status?.toUpperCase() || 'UNKNOWN'}</span></div>
          <div className="settings-row"><span className="settings-key">MODEL_LOADED</span><span className="settings-val">{health?.model_loaded ? 'YES' : 'NO'}</span></div>
          <div className="settings-row"><span className="settings-key">DB_CONNECTED</span><span className="settings-val">{health?.db_connected ? 'YES' : 'NO'}</span></div>
          <div className="settings-row"><span className="settings-key">ARTIFACTS_PATH</span><span className="settings-val text-sm" style={{ maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{health?.artifacts_path || '\u2014'}</span></div>
        </div>
      </div>

      <div className="panel" style={{ gridColumn: '1 / -1' }}>
        <div className="panel-header">
          <span className="panel-title">FEATURE_REFERENCE</span>
          <span className="panel-meta">22 CIC-IDS network flow features</span>
        </div>
        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--sp-1)' }}>
            {(health?.stages ? [
              'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_mean',
              'bwd_pkt_len_mean', 'flow_bytes_s', 'flow_pkts_s', 'flow_iat_mean',
              'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean', 'syn_flag_cnt',
              'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt',
              'urg_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'ttl_variance',
              'tcp_win_size', 'retransmit_cnt',
            ] : []).map(f => (
              <span key={f} className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', padding: '2px 0' }}>{f}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
// INGEST — CSV upload
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
      <div style={{ marginBottom: 'var(--sp-4)' }}>
        <span className="section-label">INGEST_FLOW_DATA</span>
        <p className="mono text-sm" style={{ color: 'var(--text-secondary)', marginTop: 'var(--sp-1)' }}>
          Upload a CSV with the 22 CIC-IDS features. Include <strong>src_ip</strong>, <strong>dst_ip</strong>, <strong>timestamp</strong> for session grouping.
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
          <><div className="loading-spinner" style={{ margin: '0 auto var(--sp-2)' }}/><p>Processing...</p></>
        ) : (
          <><Upload size={26} className="upload-icon"/><p>Drop a CSV file here or click to browse</p></>
        )}
        <input ref={fileRef} type="file" accept=".csv" style={{ display: 'none' }} onChange={e => handleFile(e.target.files[0])}/>
      </div>

      {result && (
        <div className="panel mt-4">
          <div className="panel-header">
            <span className="panel-title">INGEST_RESULT</span>
          </div>
          <div className="panel-body">
            {result.error ? (
              <p style={{ color: 'var(--severity-critical)' }}>{result.error}</p>
            ) : (
              <>
                <div className="stats-bar">
                  <div className="stat-card">
                    <div className="stat-card-label">ACCEPTED</div>
                    <div className="stat-card-value" style={{ color: 'var(--severity-low)' }}>{result.flows_accepted}</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">REJECTED</div>
                    <div className="stat-card-value" style={{ color: result.flows_rejected > 0 ? 'var(--severity-critical)' : undefined }}>{result.flows_rejected}</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">ALERTS</div>
                    <div className="stat-card-value" style={{ color: result.alerts_generated > 0 ? 'var(--severity-high)' : undefined }}>{result.alerts_generated}</div>
                  </div>
                </div>
                {result.errors?.length > 0 && (
                  <div style={{ marginTop: 'var(--sp-3)' }}>
                    <span className="mono text-sm" style={{ color: 'var(--severity-high)', fontWeight: 600 }}>VALIDATION_ERRORS:</span>
                    <ul style={{ marginTop: 'var(--sp-1)', fontSize: '0.68rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', listStyle: 'none' }}>
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

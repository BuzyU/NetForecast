import { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer,
} from 'recharts';
import {
  Activity, AlertTriangle, Shield, Upload, Radio,
  Eye, Check, MonitorDot, Database,
  Zap, Settings, BarChart3, Terminal,
  Wifi, ArrowDownToLine, ArrowUpFromLine,
  Network, FlaskConical, Globe, Cpu, Laptop,
  RotateCcw, HeartPulse, X,
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

// Direction badge (IN / OUT / INT)
function DirBadge({ dir }) {
  const cfg = {
    inbound:  { label: 'IN',  color: '#c0392b', icon: ArrowDownToLine },
    outbound: { label: 'OUT', color: '#e67e22', icon: ArrowUpFromLine },
    internal: { label: 'INT', color: '#16a085', icon: Network },
    unknown:  { label: '?',   color: 'var(--text-muted)', icon: Network },
  }[dir] || { label: '?', color: 'var(--text-muted)', icon: Network };
  const Icon = cfg.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      fontSize: '0.62rem', color: cfg.color, fontWeight: 700,
      letterSpacing: '0.04em',
      fontFamily: 'var(--font-mono)',
    }}>
      <Icon size={10}/> {cfg.label}
    </span>
  );
}

// Host vs Peer Identity badge
function IdentityBadge({ identity }) {
  if (!identity || identity === 'UNKNOWN') return null;
  const cfg = {
    HOST: { label: 'HOST', class: 'id-host', title: 'Local Laptop' },
    LAN_PEER: { label: 'LAN', class: 'id-lan', title: 'Local Network Device' },
    NAT_PEER: { label: 'NAT', class: 'id-nat', title: 'External / NAT Masked Peer' },
  }[identity] || { label: identity, class: 'id-lan', title: 'Peer Device' };

  return <span className={`id-badge ${cfg.class}`} title={cfg.title}>{cfg.label}</span>;
}

// Application & Process badge with icon
function AppBadge({ name: propName, appName, processName, iconType }) {
  const name = propName || appName || processName || 'General Net';
  const nameLower = name.toLowerCase();
  let badgeClass = 'app-generic';
  let Icon = Network;
  let color = 'var(--text-secondary)';

  if (nameLower.includes('antigravity') || nameLower.includes('code')) {
    badgeClass = 'app-antigravity';
    Icon = Terminal;
    color = '#8e44ad';
  } else if (nameLower.includes('chrome') || nameLower.includes('edge') || nameLower.includes('brave') || nameLower.includes('firefox')) {
    badgeClass = 'app-chrome';
    Icon = Globe;
    color = '#2980b9';
  } else if (nameLower.includes('python') || nameLower.includes('uvicorn')) {
    badgeClass = 'app-python';
    Icon = Cpu;
    color = '#27ae60';
  } else if (nameLower.includes('system') || nameLower.includes('kernel') || nameLower.includes('svchost')) {
    badgeClass = 'app-system';
    Icon = Shield;
    color = 'var(--text-secondary)';
  } else if (nameLower.includes('node') || nameLower.includes('vite')) {
    badgeClass = 'app-node';
    Icon = Zap;
    color = 'var(--gold)';
  } else if (nameLower.includes('ping') || iconType === 'activity') {
    Icon = Activity;
    color = '#ec4899';
  }

  return (
    <span className={`app-badge ${badgeClass}`} title={`Process: ${processName || name}`}>
      <Icon size={11} color={color}/>
      <span>{name}</span>
    </span>
  );
}

// Packet and Bandwidth breakdown
function PacketStat({ fwdPkts, bwdPkts, bytesPerSec, proto }) {
  const tx = Math.round(fwdPkts || 0);
  const rx = Math.round(bwdPkts || 0);
  const showSub = (proto && proto !== 'IP') || (bytesPerSec && bytesPerSec > 0);
  return (
    <div className="packet-stat">
      <span className="packet-stat-primary">TX: {tx} • RX: {rx}</span>
      {showSub && (
        <span className="packet-stat-sub">
          {proto && proto !== 'IP' ? proto : ''}{bytesPerSec ? ` ${(bytesPerSec / 1024).toFixed(1)} KB/s` : ''}
        </span>
      )}
    </div>
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

// Network Wellbeing & Audit History Modal
function WellbeingModal({ isOpen, onClose }) {
  const [cycles, setCycles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    apiFetch('/system/cycles')
      .then(c => { setCycles(c); setLoading(false); })
      .catch(() => setLoading(false));
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="wellbeing-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <HeartPulse size={16} color="var(--severity-low)"/>
            <span className="panel-title">NETWORK_WELLBEING & AUDIT SNAPSHOTS</span>
          </div>
          <button className="btn btn-sm" onClick={onClose}><X size={13}/></button>
        </div>
        <div className="modal-body">
          {loading ? (
            <div className="empty-state"><div className="loading-spinner"/><p>Loading archived cycles...</p></div>
          ) : cycles.length === 0 ? (
            <div className="empty-state"><p>No archived cycles yet. Click NEW_CYCLE to create an audit snapshot.</p></div>
          ) : (
            cycles.map(c => {
              const score = c.stats?.wellbeing_score ?? 100;
              const scoreColor = score >= 90 ? 'var(--severity-low)' : score >= 70 ? 'var(--severity-high)' : 'var(--severity-critical)';
              return (
                <div key={c.cycle_id} className="cycle-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="mono text-sm" style={{ fontWeight: 700 }}>{c.cycle_id}</span>
                    <span className="mono" style={{ fontSize: '0.85rem', fontWeight: 800, color: scoreColor }}>
                      {score}% WELLBEING
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--sp-4)', fontSize: '0.67rem', color: 'var(--text-secondary)' }} className="mono">
                    <span>Flows: {c.stats?.total_flows || 0}</span>
                    <span>Sessions: {c.stats?.total_sessions || 0}</span>
                    <span>Alerts: {c.stats?.total_alerts || 0}</span>
                    <span>Max Stage: <strong style={{ color: stageColor(c.stats?.max_stage || 'Benign') }}>{c.stats?.max_stage || 'Benign'}</strong></span>
                    <span>Archived: {formatTime(c.archived_at)}</span>
                  </div>
                  {c.stats?.top_apps && c.stats.top_apps.length > 0 && (
                    <div style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', marginTop: 4 }}>
                      <span className="mono text-muted text-xs">TOP APPS:</span>
                      {c.stats.top_apps.map((a, i) => (
                        <span key={i} className="app-badge app-generic" style={{ fontSize: '0.58rem' }}>
                          {a.name} ({a.flows})
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
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

  // Live flows and cycle management (persists across navigation)
  const [liveFlows, setLiveFlows] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [hostIdentity, setHostIdentity] = useState(null);
  const [currentCycle, setCurrentCycle] = useState(null);
  const [wellbeingOpen, setWellbeingOpen] = useState(false);

  // Live clock
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Root WebSocket for persistent live flow stream
  useEffect(() => {
    const ws = createWebSocket();
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'pong') return;
        setLiveFlows(prev => {
          const next = [{ ...data, _ts: new Date().toISOString() }, ...prev];
          return next.length > 500 ? next.slice(0, 500) : next;
        });
        if (data.alert) {
          setAlertCount(c => c + 1);
        }
      } catch { /* ignore non-JSON */ }
    };

    const pingIv = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 15000);

    return () => {
      clearInterval(pingIv);
      ws.close();
    };
  }, []);

  const fetchSystemMode = useCallback(() => {
    apiFetch('/system/mode')
      .then(m => {
        if (m?.mode) setSystemMode(m.mode);
        if (typeof m?.simulator_running === 'boolean') setSimulatorRunning(m.simulator_running);
      })
      .catch(() => {});
  }, []);

  const fetchHostAndCycle = useCallback(() => {
    apiFetch('/system/host-identity').then(setHostIdentity).catch(() => {});
    apiFetch('/system/cycle/current').then(setCurrentCycle).catch(() => {});
  }, []);

  // Health + alert polling + system mode + host/cycle
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
    fetchHostAndCycle();

    const iv = setInterval(() => {
      apiFetch('/health').then(updateHealth).catch(() => setHealth({ status: 'offline' }));
      apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
      fetchSystemMode();
      fetchHostAndCycle();
    }, 5000);
    return () => clearInterval(iv);
  }, [fetchSystemMode, fetchHostAndCycle]);

  const handleStartNewCycle = async () => {
    if (!window.confirm('Start a fresh cycle? Active sessions and flows will be safely archived to disk.')) {
      return;
    }
    try {
      const res = await apiPost('/system/cycle/start', {});
      setLiveFlows([]);
      fetchHostAndCycle();
      alert(`Archived ${res.archived_flows} flows (${res.archived_sessions} sessions). Fresh cycle started!`);
    } catch (e) {
      alert(e.message || 'Failed to start new cycle');
    }
  };

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
          {/* Host identity */}
          {hostIdentity && (
            <div className="host-badge-chip" title={`Adapters: ${hostIdentity.interfaces?.map(i => `${i.name} (${i.ip})`).join(', ')}`}>
              <Laptop size={11} color="#27ae60"/>
              <span>{hostIdentity.hostname || 'HOST'} [{hostIdentity.primary_ip || '127.0.0.1'}]</span>
            </div>
          )}

          {/* Current cycle */}
          {currentCycle && (
            <div className="cycle-chip" title={`Started at ${formatTime(currentCycle.started_at)}`}>
              <Activity size={11}/>
              <span>{currentCycle.cycle_id?.substring(0, 18)}</span>
            </div>
          )}

          <button
            className="btn btn-sm"
            onClick={handleStartNewCycle}
            title="Archive current cycle & start fresh"
            style={{ fontSize: '0.62rem', padding: '2px 8px' }}
          >
            <RotateCcw size={10}/> NEW_CYCLE
          </button>

          <button
            className="btn btn-sm"
            onClick={() => setWellbeingOpen(true)}
            title="View network wellbeing audit history"
            style={{ fontSize: '0.62rem', padding: '2px 8px' }}
          >
            <HeartPulse size={10} color="var(--severity-low)"/> WELLBEING
          </button>

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
            liveFlows={liveFlows}
          />
        )}
        {view === 'forecast' && <ForecastView session={selectedSession} onBack={() => setView('dashboard')} featureList={featureList}/>}
        {view === 'alerts' && <AlertsView/>}
        {view === 'live_logs' && <LiveLogsView lines={liveFlows} connected={wsConnected}/>}
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

      {/* Wellbeing Audit Modal */}
      <WellbeingModal isOpen={wellbeingOpen} onClose={() => setWellbeingOpen(false)}/>

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
// DASHBOARD — stats + sessions table + real-time flow stream
// ═══════════════════════════════════════════════════════════════
function Dashboard({ onSelectSession, systemMode, liveFlows = [] }) {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [simBannerDismissed, setSimBannerDismissed] = useState(false);
  const [sortBy, setSortBy] = useState('last_seen');
  const [dashboardTab, setDashboardTab] = useState('sessions'); // 'sessions' | 'live_flows'

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
      {/* §7 — Simulation banner (BUG FIX: only show in simulated mode) */}
      {systemMode === 'simulated' && stats.has_simulated_data && !simBannerDismissed && (
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
            SIMULATION DATA ACTIVE — synthetic flows generated by <code>traffic_simulator.py</code> are present.
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
            <div className="stat-card-label">INBOUND (RX)</div>
            <div className="stat-card-value" style={{ color: 'var(--severity-high)', fontSize: '1rem' }}>
              {stats.direction_breakdown.inbound || 0}
            </div>
          </div>
        )}
        {stats.direction_breakdown && (
          <div className="stat-card">
            <div className="stat-card-label">OUTBOUND (TX)</div>
            <div className="stat-card-value" style={{ color: 'var(--accent)', fontSize: '1rem' }}>
              {stats.direction_breakdown.outbound || 0}
            </div>
          </div>
        )}
      </div>

      {/* View switcher and mode indication */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <div className="tab-group">
            <button
              className={`tab-btn ${dashboardTab === 'sessions' ? 'active' : ''}`}
              onClick={() => setDashboardTab('sessions')}
            >
              ACTIVE SESSIONS ({sessions.length})
            </button>
            <button
              className={`tab-btn ${dashboardTab === 'live_flows' ? 'active' : ''}`}
              onClick={() => setDashboardTab('live_flows')}
            >
              REAL-TIME FLOWS ({liveFlows.length})
            </button>
          </div>
        </div>

        {/* Operating mode badge */}
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

      {/* Active Sessions Tab */}
      {dashboardTab === 'sessions' && (
        <div className="data-table-wrap">
          {loading ? (
            <div className="empty-state"><div className="loading-spinner"/><p>Loading sessions...</p></div>
          ) : sessions.length === 0 ? (
            <div className="empty-state">
              <Database size={28} color="var(--text-muted)"/>
              <p>No active sessions in this cycle. Waiting for network telemetry...</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>APPLICATION</th>
                  <th>DIR</th>
                  <th>SOURCE (PEER / HOST)</th>
                  <th>DESTINATION</th>
                  <th>PACKETS (TX / RX)</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('flow_count')}>FLOWS {sortBy === 'flow_count' ? '▼' : ''}</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('latest_risk_score')}>RISK {sortBy === 'latest_risk_score' ? '▼' : ''}</th>
                  <th>STAGE</th>
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
                      <td>
                        <AppBadge appName={s.app_name} processName={s.process_name}/>
                      </td>
                      <td><DirBadge dir={s.direction}/></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span className="mono">{s.src_ip || '—'}</span>
                          <IdentityBadge identity={s.src_identity}/>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span className="mono">{s.dst_ip || '—'}</span>
                          <IdentityBadge identity={s.dst_identity}/>
                        </div>
                      </td>
                      <td>
                        <PacketStat fwdPkts={s.tot_fwd_pkts} bwdPkts={s.tot_bwd_pkts} proto="IP"/>
                      </td>
                      <td className="mono">{s.flow_count}</td>
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
                      <td><KillChainCompact currentStage={s.max_stage_reached || s.latest_stage}/></td>
                      <td className="mono text-xs">{formatTime(s.last_seen)}</td>
                      <td>
                        <button
                          className="btn btn-sm btn-primary"
                          style={{ fontSize: '0.6rem', padding: '2px 8px' }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectSession(s);
                          }}
                        >
                          FORECAST
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Real-Time Live Flows Tab */}
      {dashboardTab === 'live_flows' && (
        <div className="data-table-wrap">
          {liveFlows.length === 0 ? (
            <div className="empty-state">
              <Radio size={28} color="var(--text-muted)"/>
              <p>Waiting for real-time live flow packets...</p>
              <span className="mono text-xs text-muted">Flows captured via scapy / Npcap or simulator stream here automatically.</span>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>APPLICATION</th>
                  <th>DIR</th>
                  <th>SOURCE → DESTINATION</th>
                  <th>PROTO</th>
                  <th>PACKETS (TX / RX)</th>
                  <th>P(INFIL)</th>
                  <th>STAGE</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {liveFlows.map((f, i) => {
                  const prob = f.infiltration_prob;
                  const isAlert = (prob || 0) > 0.5;
                  return (
                    <tr key={i} style={{ background: isAlert ? 'rgba(192,57,43,0.06)' : undefined }}>
                      <td className="mono text-xs">{formatTime(f.timestamp || f._ts)}</td>
                      <td>
                        <AppBadge appName={f.app_name} processName={f.process_name} iconType={f.app_icon}/>
                      </td>
                      <td><DirBadge dir={f.direction}/></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} className="mono text-xs">
                          <span>{f.src_ip || '?'}{f.src_port ? `:${f.src_port}` : ''}</span>
                          <IdentityBadge identity={f.src_identity}/>
                          <span style={{ color: 'var(--text-muted)' }}>&rarr;</span>
                          <span>{f.dst_ip || '?'}{f.dst_port ? `:${f.dst_port}` : ''}</span>
                          <IdentityBadge identity={f.dst_identity}/>
                        </div>
                      </td>
                      <td><span className="mono text-xs text-muted">{f.protocol || 'TCP'}</span></td>
                      <td>
                        <PacketStat
                          fwdPkts={f.tot_fwd_pkts}
                          bwdPkts={f.tot_bwd_pkts}
                          bytesPerSec={f.flow_bytes_s}
                          proto={f.protocol}
                        />
                      </td>
                      <td>
                        <div className="risk-cell">
                          <div className={`risk-bar ${severityClass(prob)}`}/>
                          <span>{formatProb(prob)}</span>
                        </div>
                      </td>
                      <td>
                        <span className={`stage-badge ${stageClass(f.predicted_stage || 'Benign')}`}>
                          {f.predicted_stage || 'Benign'}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-sm btn-primary"
                          style={{ fontSize: '0.6rem', padding: '2px 8px' }}
                          onClick={() => onSelectSession({
                            session_key: f.session_key,
                            src_ip: f.src_ip,
                            dst_ip: f.dst_ip,
                            latest_stage: f.predicted_stage || 'Benign',
                            latest_risk_score: f.infiltration_prob || 0.0,
                          })}
                        >
                          FORECAST
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
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
        if (!allFlows || allFlows.length === 0) {
          setError('No flow records captured for this session yet.');
          return;
        }
        let windowFlows = allFlows.slice(0, 6).reverse();
        // Pad window up to 6 flows if session has fewer than 6 flows
        while (windowFlows.length < 6) {
          windowFlows.unshift(windowFlows[0]);
        }
        const window = windowFlows.map(f => featOrder.map(k => f.features?.[k] ?? 0));
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
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--sp-2)' }}>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/forecast/view/html?session_key=${encodeURIComponent(session.session_key)}`, '_blank')}
            title="Open printable forecast dossier in a new browser tab"
          >
            👁️ VIEW REPORT
          </button>
          <a
            className="btn btn-sm btn-primary"
            href={`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/forecast/export/html?session_key=${encodeURIComponent(session.session_key)}`}
            download
            style={{ textDecoration: 'none' }}
          >
            📄 EXPORT FORECAST HTML
          </a>
        </div>
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
            <span className="panel-meta">
              {explanation?.method_used === 'shap' ? 'SHAP Values (KernelExplainer)' : 'Gradient × Input'}
            </span>
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
function LiveLogsView({ lines = [], connected = false }) {
  const containerRef = useRef(null);

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
              <span className="ts">{formatTime(line._ts || line.timestamp)}</span>
              <span className="sep"> | </span>
              <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                {line.app_name || line.process_name ? `[${line.app_name || line.process_name}] ` : ''}
              </span>
              <span className="ip">
                {line.src_ip || '?'}{line.src_port ? `:${line.src_port}` : ''} &rarr; {line.dst_ip || '?'}{line.dst_port ? `:${line.dst_port}` : ''}
              </span>
              <span className="sep"> | </span>
              <DirBadge dir={line.direction}/>
              <span className="sep"> | </span>
              <SourceBadge src={line.source}/>
              <span className="sep"> | </span>
              <span className="val">TX: {line.tot_fwd_pkts || 0} / RX: {line.tot_bwd_pkts || 0}</span>
              <span className="sep"> | </span>
              <span className="val">P={formatProb(line.infiltration_prob)}</span>
              <span className="sep"> | </span>
              <span className="stage-flag">{line.predicted_stage || 'Benign'}</span>
              {(line.infiltration_prob || 0) > 0.5 && (
                <span className="alert-flag"> &#9650; ALERT</span>
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
// EXPLAIN VIEW — feature attribution (SHAP + Gradient)
// ═══════════════════════════════════════════════════════════════
function ExplainView({ featureList }) {
  const [sessions, setSessions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [method, setMethod] = useState('gradient'); // Default to fast gradient for instant UI responsiveness
  const [searchQuery, setSearchQuery] = useState('');

  const featOrder = featureList || DEFAULT_FEAT_ORDER;

  const explain = useCallback((session, methodToUse = method) => {
    if (!session) return;
    setSelected(session);
    setLoading(true);
    setError(null);
    apiFetch(`/sessions/${encodeURIComponent(session.session_key)}/flows?limit=6`)
      .then(flows => {
        if (!flows || flows.length === 0) {
          throw new Error('No flow records captured for this session yet.');
        }
        let windowFlows = flows.slice(0, 6).reverse();
        // Pad window up to 6 flows if session has fewer than 6 flows
        while (windowFlows.length < 6) {
          windowFlows.unshift(windowFlows[0]);
        }
        const window = windowFlows.map(f => featOrder.map(k => f.features?.[k] ?? 0));
        return apiPost('/explain', { window, top_k: 22, needs_scaling: true, method: methodToUse });
      })
      .then(result => {
        setExplanation(result);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message || 'Failed to compute feature attribution.');
        setLoading(false);
      });
  }, [featOrder, method]);

  useEffect(() => {
    let mounted = true;
    apiFetch('/sessions?limit=50')
      .then(data => {
        if (!mounted) return;
        const list = Array.isArray(data) ? data : [];
        setSessions(list);
        if (list.length > 0) {
          setSelected(prev => {
            if (prev && list.some(s => s.session_key === prev.session_key)) return prev;
            const highestRisk = [...list].sort((a, b) => (b.latest_risk_score || 0) - (a.latest_risk_score || 0))[0];
            explain(highestRisk, 'gradient');
            return highestRisk;
          });
        }
      })
      .catch(() => {});
    return () => { mounted = false; };
  }, [explain]);

  const handleMethodChange = (newMethod) => {
    setMethod(newMethod);
    if (selected) {
      explain(selected, newMethod);
    }
  };

  const maxImp = (explanation?.attributions && explanation.attributions.length > 0)
    ? (Math.max(...explanation.attributions.map(a => Math.abs(a.importance))) || 1)
    : 1;

  const filteredSessions = sessions.filter(s => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (s.src_ip || '').toLowerCase().includes(q) ||
      (s.dst_ip || '').toLowerCase().includes(q) ||
      (s.app_name || '').toLowerCase().includes(q) ||
      (s.process_name || '').toLowerCase().includes(q) ||
      (s.latest_stage || '').toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 'var(--sp-4)' }}>
      {/* Session picker */}
      <div className="panel">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="panel-title">SELECT_SESSION</span>
          <span className="panel-meta">{filteredSessions.length} sessions</span>
        </div>
        <div style={{ padding: 'var(--sp-2)', borderBottom: '1px solid var(--border-muted)' }}>
          <input
            type="text"
            placeholder="Filter by IP, App, or Stage..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '4px 8px',
              fontSize: '0.7rem',
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>
        <div style={{ maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }}>
          {filteredSessions.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--sp-6)' }}>
              <p>No matching sessions found.</p>
            </div>
          ) : (
            filteredSessions.map(s => (
              <div
                key={s.session_key}
                onClick={() => explain(s)}
                style={{
                  padding: 'var(--sp-2) var(--sp-3)',
                  borderBottom: '1px solid var(--border-muted)',
                  cursor: 'pointer',
                  background: selected?.session_key === s.session_key ? 'var(--accent-muted)' : 'transparent',
                  transition: 'background 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
                  <AppBadge name={s.app_name || s.process_name} processName={s.process_name}/>
                  <DirBadge dir={s.direction}/>
                </div>
                <div className="mono" style={{ fontSize: '0.68rem', margin: '2px 0' }}>
                  {s.src_ip} <IdentityBadge type={s.src_identity}/> &rarr; {s.dst_ip} <IdentityBadge type={s.dst_identity}/>
                </div>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', marginTop: '2px', alignItems: 'center' }}>
                  <span className={`stage-badge ${stageClass(s.latest_stage)}`}>{s.latest_stage}</span>
                  <span className="mono text-muted" style={{ fontSize: '0.6rem' }}>{s.flow_count} flows</span>
                  <span className="mono" style={{ fontSize: '0.6rem', marginLeft: 'auto', color: (s.latest_risk_score || 0) > 0.5 ? 'var(--severity-critical)' : 'var(--text-muted)' }}>
                    {formatProb(s.latest_risk_score || 0)}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Attribution display */}
      <div className="panel">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--sp-2)' }}>
          <div>
            <span className="panel-title">FEATURE_ATTRIBUTION</span>
            <span className="panel-meta" style={{ marginLeft: 'var(--sp-2)' }}>
              {explanation?.method_used === 'shap' ? 'SHAP Values (KernelExplainer)' : 'Gradient × Input'} (all 22 flow features)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
            <div style={{ display: 'inline-flex', gap: 4, background: 'var(--surface)', padding: 2, borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
              <button
                className={`btn btn-sm ${method === 'gradient' ? 'btn-primary' : ''}`}
                onClick={() => handleMethodChange('gradient')}
                style={{ fontSize: '0.65rem', padding: '2px 8px' }}
                title="Fast sub-second gradient attribution"
              >
                FAST (GRADIENT)
              </button>
              <button
                className={`btn btn-sm ${method === 'shap' ? 'btn-primary' : ''}`}
                onClick={() => handleMethodChange('shap')}
                style={{ fontSize: '0.65rem', padding: '2px 8px' }}
                title="Deep game-theoretic Shapley value attribution (~3-5s)"
              >
                DEEP (SHAP)
              </button>
            </div>

            {/* Export Toolbar */}
            <div style={{ display: 'inline-flex', gap: 4 }}>
              <button
                className="btn btn-sm"
                onClick={() => {
                  if (!selected) return;
                  const url = `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/explain/view/html?session_key=${encodeURIComponent(selected.session_key)}&method=${method}`;
                  window.open(url, '_blank');
                }}
                disabled={!selected}
                style={{ fontSize: '0.65rem', padding: '2px 8px' }}
                title="Open printable feature attribution report in a new tab"
              >
                👁️ VIEW REPORT
              </button>
              <a
                className="btn btn-sm btn-primary"
                href={selected ? `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/explain/export/html?session_key=${encodeURIComponent(selected.session_key)}&method=${method}` : '#'}
                download
                style={{ fontSize: '0.65rem', padding: '2px 8px', textDecoration: 'none', pointerEvents: selected ? 'auto' : 'none', opacity: selected ? 1 : 0.5 }}
              >
                📄 EXPORT HTML
              </a>
              <a
                className="btn btn-sm"
                href={selected ? `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/explain/export/csv?session_key=${encodeURIComponent(selected.session_key)}&method=${method}` : '#'}
                download
                style={{ fontSize: '0.65rem', padding: '2px 8px', textDecoration: 'none', pointerEvents: selected ? 'auto' : 'none', opacity: selected ? 1 : 0.5 }}
              >
                CSV
              </a>
              <a
                className="btn btn-sm"
                href={selected ? `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/explain/export/json?session_key=${encodeURIComponent(selected.session_key)}&method=${method}` : '#'}
                download
                style={{ fontSize: '0.65rem', padding: '2px 8px', textDecoration: 'none', pointerEvents: selected ? 'auto' : 'none', opacity: selected ? 1 : 0.5 }}
              >
                JSON
              </a>
            </div>
          </div>
        </div>
        <div className="panel-body">
          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner"/>
              <p>Computing {method.toUpperCase()} feature attributions for {selected?.app_name || selected?.process_name || 'session'}...</p>
            </div>
          ) : error ? (
            <div className="empty-state">
              <AlertTriangle size={28} color="var(--severity-high)"/>
              <p>{error}</p>
            </div>
          ) : !explanation ? (
            <div className="empty-state">
              <Eye size={28} color="var(--text-muted)"/>
              <p>Select an active session from the left panel to explain its attack forecast.</p>
            </div>
          ) : (
            <>
              <div style={{ marginBottom: 'var(--sp-4)', display: 'flex', gap: 'var(--sp-4)', alignItems: 'baseline', flexWrap: 'wrap' }}>
                <div>
                  <span className="mono" style={{ fontSize: '1.3rem', fontWeight: 700 }}>{formatProb(explanation.infiltration_probability)}</span>
                  <span className="text-sm text-muted" style={{ marginLeft: 'var(--sp-2)' }}>P(INFILTRATION)</span>
                </div>
                <span className={`stage-badge ${stageClass(explanation.predicted_stage)}`}>{explanation.predicted_stage}</span>
                <span className="mono text-muted" style={{ fontSize: '0.65rem', marginLeft: 'auto' }}>
                  METHOD: {explanation.method_used?.toUpperCase()} &bull; TOP_K: 22 FEATURES
                </span>
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
// REPORTS — executive report, stage distribution, and forensic exports
// ═══════════════════════════════════════════════════════════════
function ReportsView() {
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [stageDist, setStageDist] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    Promise.all([
      apiFetch('/dashboard/stats').catch(() => ({})),
      apiFetch('/alerts/stats').catch(() => ({})),
      apiFetch('/dashboard/stage-distribution').catch(() => []),
      apiFetch('/sessions?limit=50').catch(() => []),
      apiFetch('/alerts?limit=50').catch(() => []),
    ]).then(([st, as, sd, sess, al]) => {
      setStats(st || {});
      setAlertStats(as || {});
      setStageDist(Array.isArray(sd) ? sd : []);
      setSessions(Array.isArray(sess) ? sess : []);
      setAlerts(Array.isArray(al) ? al : []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const maxCount = stageDist.length > 0 ? Math.max(...stageDist.map(s => s.count)) : 1;

  const downloadReport = async (format) => {
    setExporting(true);
    try {
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const url = `${baseUrl}/reports/export/${format}`;
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      const ext = format === 'csv' ? 'csv' : format === 'html' ? 'html' : 'json';
      a.download = `netforecast_forensic_report_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error(`Export ${format} failed:`, err);
      // Fallback to window.open
      window.open(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/reports/export/${format}`, '_blank');
    } finally {
      setExporting(false);
    }
  };

  const copySummary = () => {
    const summary = {
      generated_at: new Date().toISOString(),
      total_sessions: stats.total_sessions || 0,
      total_flows: stats.total_flows || 0,
      at_risk_sessions: stats.at_risk_sessions || 0,
      total_alerts: alertStats.total || 0,
      unacknowledged_alerts: alertStats.unacknowledged || 0,
      critical_unacknowledged: alertStats.critical_unacknowledged || 0,
      stage_distribution: stageDist,
      top_sessions: sessions.slice(0, 10),
    };
    navigator.clipboard.writeText(JSON.stringify(summary, null, 2));
  };

  if (loading) {
    return <div className="empty-state"><div className="loading-spinner"/><p>Compiling forensic report data...</p></div>;
  }

  return (
    <>
      {/* ── Action & Export Bar ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-4)', flexWrap: 'wrap', gap: 'var(--sp-2)' }}>
        <div>
          <span className="section-label" style={{ marginBottom: 2 }}>SECURITY_AUDIT // FORENSIC_REPORT</span>
          <p className="text-sm text-muted">Comprehensive cyber attack progression & MITRE ATT&CK defense telemetry</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/reports/view/html`, '_blank')}
            title="Open printable forensic dossier in a new browser tab"
          >
            👁️ VIEW REPORT
          </button>
          <button
            className="btn btn-sm btn-primary"
            onClick={() => downloadReport('html')}
            disabled={exporting}
            style={{ fontWeight: 700, padding: '4px 12px' }}
          >
            📄 EXPORT FORENSIC HTML
          </button>
          <button
            className="btn btn-sm"
            onClick={() => downloadReport('csv')}
            disabled={exporting}
          >
            EXPORT CSV
          </button>
          <button
            className="btn btn-sm"
            onClick={() => downloadReport('json')}
            disabled={exporting}
          >
            EXPORT JSON
          </button>
          <button className="btn btn-sm" onClick={copySummary}>COPY JSON</button>
        </div>
      </div>

      {/* ── Summary & Stage Distribution Grid ── */}
      <div className="report-grid mb-4">
        {/* Stats panel */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">TELEMETRY_METRICS</span>
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
            <span className="panel-title">MITRE_STAGE_DISTRIBUTION</span>
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

      {/* ── Active Sessions Section ── */}
      <div className="panel mb-4">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="panel-title">ACTIVE_SESSIONS_AUDIT</span>
          <span className="panel-meta">{sessions.length} sessions recorded</span>
        </div>
        <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
          {sessions.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--sp-6)' }}><p>No session data recorded in this cycle.</p></div>
          ) : (
            <table className="data-table" style={{ fontSize: '0.68rem' }}>
              <thead>
                <tr>
                  <th>APPLICATION</th>
                  <th>DIR</th>
                  <th>SOURCE (PEER / HOST)</th>
                  <th>DESTINATION</th>
                  <th>PACKETS (TX / RX)</th>
                  <th>FLOWS</th>
                  <th>RISK</th>
                  <th>STAGE</th>
                  <th>LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => (
                  <tr key={s.session_key}>
                    <td><AppBadge name={s.app_name || s.process_name} processName={s.process_name}/></td>
                    <td><DirBadge dir={s.direction}/></td>
                    <td>
                      <code>{s.src_ip}</code> <IdentityBadge type={s.src_identity}/>
                    </td>
                    <td>
                      <code>{s.dst_ip}</code> <IdentityBadge type={s.dst_identity}/>
                    </td>
                    <td>
                      <PacketStat fwdPkts={s.tot_fwd_pkts} bwdPkts={s.tot_bwd_pkts}/>
                    </td>
                    <td>{s.flow_count}</td>
                    <td style={{ color: (s.latest_risk_score || 0) > 0.5 ? 'var(--severity-critical)' : 'var(--text-muted)', fontWeight: 600 }}>
                      {formatProb(s.latest_risk_score || 0)}
                    </td>
                    <td><span className={`stage-badge ${stageClass(s.latest_stage)}`}>{s.latest_stage || 'Benign'}</span></td>
                    <td className="mono text-muted">{s.last_seen ? formatTime(s.last_seen) : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* ── Security Alerts Section ── */}
      <div className="panel">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="panel-title">INCIDENT_ALERTS_&_PLAYBOOKS</span>
          <span className="panel-meta">{alerts.length} alerts generated</span>
        </div>
        <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
          {alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--sp-6)' }}><p>No security alerts generated. Baseline is nominal.</p></div>
          ) : (
            <table className="data-table" style={{ fontSize: '0.68rem' }}>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>SEVERITY</th>
                  <th>TARGET</th>
                  <th>PREDICTED STAGE</th>
                  <th>CONFIDENCE</th>
                  <th>RECOMMENDED PLAYBOOK ACTION</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id}>
                    <td className="mono">#{a.id}</td>
                    <td><span className={`severity-badge ${(a.severity || 'medium').toLowerCase()}`}>{(a.severity || 'medium').toUpperCase()}</span></td>
                    <td><code style={{ fontSize: '0.62rem' }}>{a.session_key}</code></td>
                    <td><span className={`stage-badge ${stageClass(a.predicted_stage)}`}>{a.predicted_stage}</span></td>
                    <td className="mono">{formatProb(a.infiltration_prob || 0)}</td>
                    <td style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>{a.recommended_action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
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
          <div className="settings-row"><span className="settings-key">ARCHITECTURE</span><span className="settings-val">2-Layer LSTM (hidden=128, dropout=0.2)</span></div>
          <div className="settings-row"><span className="settings-key">DEVICE</span><span className="settings-val">{health?.device?.toUpperCase() || 'CPU'}</span></div>
          <div className="settings-row"><span className="settings-key">FEATURES</span><span className="settings-val">{health?.features_count || 22}</span></div>
          <div className="settings-row"><span className="settings-key">WINDOW_SIZE</span><span className="settings-val">6</span></div>
          <div className="settings-row"><span className="settings-key">STAGES</span><span className="settings-val">{health?.stages?.length || 6}</span></div>
          <div className="settings-row"><span className="settings-key">ALERT_THRESHOLD</span><span className="settings-val">0.50 (Adaptive EMA enabled)</span></div>
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
// INGEST — CSV or PCAP upload
// ═══════════════════════════════════════════════════════════════
function IngestPanel() {
  const [result, setResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    const isCsv = name.endsWith('.csv');
    const isPcap = name.endsWith('.pcap') || name.endsWith('.cap') || name.endsWith('.pcapng');

    if (!isCsv && !isPcap) {
      setResult({ error: 'Please upload a CSV (.csv) or PCAP (.pcap, .cap, .pcapng) file' });
      return;
    }

    setUploading(true);
    setResult(null);
    try {
      const endpoint = isPcap ? '/ingest/pcap' : '/ingest/csv';
      const data = await apiUpload(endpoint, file);
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
        <span className="section-label">INGEST_NETWORK_TELEMETRY</span>
        <p className="mono text-sm" style={{ color: 'var(--text-secondary)', marginTop: 'var(--sp-1)' }}>
          Upload <strong>CSV flow logs</strong> (22 CIC-IDS features) or raw <strong>PCAP packet captures</strong> (.pcap/.pcapng).
          The engine extracts temporal features, reconstructs sessions, and forecasts attack progression.
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
          <><div className="loading-spinner" style={{ margin: '0 auto var(--sp-2)' }}/><p>Processing network telemetry...</p></>
        ) : (
          <><Upload size={26} className="upload-icon"/><p>Drop a CSV or PCAP file here or click to browse</p></>
        )}
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.pcap,.cap,.pcapng"
          style={{ display: 'none' }}
          onChange={e => handleFile(e.target.files[0])}
        />
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

import { useState, useEffect, memo } from 'react';
import {
  ArrowDownToLine, ArrowUpFromLine, Network, Terminal, Globe,
  Cpu, Shield, Zap, Activity, FlaskConical, Wifi, Upload, RotateCcw, X,
} from 'lucide-react';
import { apiFetch } from '../api';
import { stageIndex, formatTime, STAGES } from '../utils';
const SOURCE_LABELS = {
  simulated: { label: 'SIMULATION MODE', color: 'var(--accent)', icon: FlaskConical },
  live_capture: { label: 'LIVE CAPTURE', color: 'var(--severity-low)', icon: Wifi },
  csv_upload: { label: 'CSV UPLOAD', color: 'var(--severity-medium)', icon: Upload },
  api: { label: 'API INGEST', color: 'var(--text-secondary)', icon: Zap },
};

// Direction badge (IN / OUT / INT)
export const DirBadge = memo(function DirBadge({ dir }) {
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
});

// Host vs Peer Identity badge
export const IdentityBadge = memo(function IdentityBadge({ identity }) {
  if (!identity || identity === 'UNKNOWN') return null;
  const cfg = {
    HOST: { label: 'HOST', class: 'id-host', title: 'Local Laptop' },
    LAN_PEER: { label: 'LAN', class: 'id-lan', title: 'Local Network Device' },
    NAT_PEER: { label: 'NAT', class: 'id-nat', title: 'External / NAT Masked Peer' },
  }[identity] || { label: identity, class: 'id-lan', title: 'Peer Device' };

  return <span className={`id-badge ${cfg.class}`} title={cfg.title}>{cfg.label}</span>;
});

// Application & Process badge with icon
export const AppBadge = memo(function AppBadge({ name: propName, appName, processName, iconType }) {
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
});

// Packet and Bandwidth breakdown
export const PacketStat = memo(function PacketStat({ fwdPkts, bwdPkts, bytesPerSec, proto }) {
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
});

// Source badge
export const SourceBadge = memo(function SourceBadge({ src }) {
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
});

// Compromise pulse — visual overlay for sessions in active attack stage
export const CompromiseIndicator = memo(function CompromiseIndicator({ stage, riskScore }) {
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
});

// Full Kill Chain progression bar
export const KillChain = memo(function KillChain({ currentStage, forecastStages = [] }) {
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
});

// Compact Kill Chain for session table rows
export const KillChainCompact = memo(function KillChainCompact({ currentStage }) {
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
});

// Network Wellbeing & Audit History Modal
export function WellbeingModal({ isOpen, onClose }) {
  const [cycles, setCycles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isOpen) return;
    let mounted = true;
    apiFetch('/system/cycles')
      .then(data => {
        if (mounted) {
          setCycles(Array.isArray(data) ? data : []);
          setLoading(false);
        }
      })
      .catch(() => {
        if (mounted) setLoading(false);
      });
    return () => { mounted = false; };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: 720 }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <RotateCcw size={16} color="var(--severity-low)"/>
            <span className="modal-title">TELEMETRY_CYCLE_ARCHIVE_HISTORY</span>
          </div>
          <button className="modal-close" onClick={onClose}><X size={16}/></button>
        </div>
        <div className="modal-body">
          <p className="text-sm text-muted" style={{ marginBottom: 'var(--sp-3)' }}>
            Project Garud preserves continuous network telemetry. Each cycle archive represents a frozen snapshot of monitored sessions, flows, and security alerts.
          </p>
          {loading ? (
            <div className="empty-state"><div className="loading-spinner"/><p>Loading historical audit archives...</p></div>
          ) : cycles.length === 0 ? (
            <div className="empty-state">
              <p>No historical cycle archives recorded yet. Use <strong>NEW_CYCLE</strong> in the header to snapshot current telemetry.</p>
            </div>
          ) : (
            <div style={{ maxHeight: 380, overflowY: 'auto' }}>
              <table className="data-table" style={{ fontSize: '0.68rem' }}>
                <thead>
                  <tr>
                    <th>CYCLE_ID</th>
                    <th>START_TIME</th>
                    <th>END_TIME</th>
                    <th>SESSIONS</th>
                    <th>FLOWS</th>
                    <th>ALERTS</th>
                  </tr>
                </thead>
                <tbody>
                  {cycles.map(c => (
                    <tr key={c.cycle_id}>
                      <td className="mono" style={{ fontWeight: 600 }}>{c.cycle_id}</td>
                      <td>{formatTime(c.started_at)}</td>
                      <td>{c.ended_at ? formatTime(c.ended_at) : 'CURRENT'}</td>
                      <td>{c.session_count || c.total_sessions || 0}</td>
                      <td>{c.flow_count || c.total_flows || 0}</td>
                      <td><span className={`severity-badge ${(c.alert_count || 0) > 0 ? 'critical' : 'low'}`}>{c.alert_count || 0}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

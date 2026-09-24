import { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { stageColor, stageClass, formatTime, formatProb } from '../utils';
import { AppBadge, DirBadge, IdentityBadge, PacketStat } from './Badges';

export default function ReportsView() {
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

      <div className="report-grid mb-4">
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
                      <code>{s.src_ip}</code> <IdentityBadge identity={s.src_identity}/>
                    </td>
                    <td>
                      <code>{s.dst_ip}</code> <IdentityBadge identity={s.dst_identity}/>
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

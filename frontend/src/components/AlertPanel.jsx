import { useState, useEffect, useCallback } from 'react';
import { Shield, Check } from 'lucide-react';
import { apiFetch, apiPost } from '../api';
import { stageClass, formatTime, formatProb } from '../utils';

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  const refresh = useCallback(() => {
    const params = filter === 'all' ? '' : `?severity=${filter}`;
    apiFetch(`/alerts${params}`)
      .then(a => { setAlerts(a); setLoading(false); })
      .catch(() => setLoading(false));
  }, [filter]);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 5000);
    return () => clearInterval(iv);
  }, [refresh]);

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
            <button
              key={f}
              className={`btn btn-sm ${filter === f ? 'btn-primary' : ''}`}
              onClick={() => setFilter(f)}
            >
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
                  <td>{a.session_key?.substring(0, 24) || '—'}</td>
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

export { AlertPanel as AlertsView };

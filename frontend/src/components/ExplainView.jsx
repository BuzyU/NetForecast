import { useState, useEffect, useCallback } from 'react';
import { Eye, AlertTriangle } from 'lucide-react';
import { apiFetch, apiPost } from '../api';
import { stageClass, formatProb, DEFAULT_FEAT_ORDER } from '../utils';
import { AppBadge, DirBadge, IdentityBadge } from './Badges';

export default function ExplainView({ featureList }) {
  const [sessions, setSessions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [method, setMethod] = useState('gradient');
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
        if (flows.length < 6) {
          throw new Error(`Collecting baseline: ${flows.length}/6 flows. The world model needs a full 6-flow window of real observations before it can explain a prediction.`);
        }
        const windowFlows = flows.slice(0, 6).reverse();
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
                  {s.src_ip} <IdentityBadge identity={s.src_identity}/> &rarr; {s.dst_ip} <IdentityBadge identity={s.dst_identity}/>
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

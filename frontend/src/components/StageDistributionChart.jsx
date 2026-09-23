import { useState, useEffect, memo } from 'react';
import { apiFetch } from '../api';
import { stageColor } from '../utils';

function StageDistributionChart({ stageDist: propDist }) {
  const [data, setData] = useState(propDist || []);
  const [loading, setLoading] = useState(!propDist);

  useEffect(() => {
    if (propDist) {
      setData(propDist);
      setLoading(false);
      return;
    }
    let mounted = true;
    apiFetch('/dashboard/stage-distribution')
      .then(res => {
        if (mounted && Array.isArray(res)) {
          setData(res);
          setLoading(false);
        }
      })
      .catch(() => {
        if (mounted) setLoading(false);
      });
    return () => { mounted = false; };
  }, [propDist]);

  const maxCount = data.length > 0 ? Math.max(...data.map(s => s.count)) : 1;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">MITRE_STAGE_DISTRIBUTION</span>
      </div>
      <div className="panel-body">
        {loading ? (
          <div className="empty-state" style={{ padding: 'var(--sp-4)' }}>
            <div className="loading-spinner"/>
          </div>
        ) : data.length === 0 ? (
          <div className="empty-state" style={{ padding: 'var(--sp-6)' }}>
            <p>No stage data recorded yet.</p>
          </div>
        ) : (
          data.map(s => (
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
  );
}

export default memo(StageDistributionChart);

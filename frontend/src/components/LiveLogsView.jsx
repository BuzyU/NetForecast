import { useRef, useEffect, memo } from 'react';
import { Radio } from 'lucide-react';
import { formatTime, formatProb } from '../utils';
import { DirBadge, SourceBadge } from './Badges';

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

export default memo(LiveLogsView);

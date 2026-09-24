import { useRef, useEffect, useMemo, memo } from 'react';
import { Radio, ShieldCheck } from 'lucide-react';
import { formatTime, formatProb, isAttackFlow, stageClass, STAGE_TECHNIQUE } from '../utils';
import { DirBadge, SourceBadge } from './Badges';

function LiveLogsView({ lines = [], connected = false }) {
  const containerRef = useRef(null);

  const attackLines = useMemo(() => lines.filter(isAttackFlow), [lines]);

  const topKey = attackLines[0] ? `${attackLines[0]._ts || attackLines[0].timestamp}-${attackLines[0].src_ip}-${attackLines[0].dst_ip}` : null;
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [topKey]);

  return (
    <div className="terminal">
      <div className="terminal-header">
        <span className="terminal-title">
          ATTACK_FEED {connected ? '// CONNECTED' : '// DISCONNECTED'}
        </span>
        <span style={{ fontSize: '0.6rem', color: connected ? 'var(--severity-low)' : 'var(--severity-critical)' }}>
          &#9679; {connected ? 'LIVE' : 'OFFLINE'}
        </span>
      </div>

      {attackLines.length > 0 && (
        <div className="terminal-row terminal-row-header">
          <span>TIME</span>
          <span>ATTACK TYPE</span>
          <span>FLOW</span>
          <span>APP</span>
          <span>PROB</span>
          <span>PACKETS</span>
          <span>ORIGIN</span>
        </div>
      )}

      <div className="terminal-body" ref={containerRef}>
        {attackLines.length === 0 ? (
          <div className="terminal-empty">
            {connected ? (
              <>
                <ShieldCheck size={24} color="var(--severity-low)"/>
                <p style={{ marginTop: '8px', color: 'var(--severity-low)' }}>Monitoring — no active threats</p>
                <p style={{ fontSize: '0.65rem', marginTop: '4px' }}>
                  Traffic is flowing normally. Flagged attacks will appear here immediately.
                </p>
              </>
            ) : (
              <>
                <Radio size={24}/>
                <p style={{ marginTop: '8px' }}>Waiting for connection...</p>
                <p style={{ fontSize: '0.65rem', marginTop: '4px' }}>
                  Run the traffic simulator or live capture to see real-time data.
                </p>
              </>
            )}
          </div>
        ) : (
          attackLines.map((line, i) => {
            const stage = line.predicted_stage || 'Benign';
            return (
              <div key={i} className={`terminal-row stage-${stageClass(stage)}`}>
                <span className="ts">{formatTime(line._ts || line.timestamp)}</span>
                <span className="attack-flag" title={STAGE_TECHNIQUE[stage] || ''}>
                  &#9650; {stage}
                  {STAGE_TECHNIQUE[stage] && <span className="attack-technique"> {STAGE_TECHNIQUE[stage]}</span>}
                </span>
                <span className="ip" title={`${line.src_ip || '?'}${line.src_port ? `:${line.src_port}` : ''} → ${line.dst_ip || '?'}${line.dst_port ? `:${line.dst_port}` : ''}`}>
                  {line.src_ip || '?'}{line.src_port ? `:${line.src_port}` : ''}
                  <span className="sep"> &rarr; </span>
                  {line.dst_ip || '?'}{line.dst_port ? `:${line.dst_port}` : ''}
                </span>
                <span className="val app-cell">
                  {line.app_name || line.process_name || <DirBadge dir={line.direction}/>}
                </span>
                <span className="val prob-cell">{formatProb(line.infiltration_prob)}</span>
                <span className="val">TX {line.tot_fwd_pkts || 0} / RX {line.tot_bwd_pkts || 0}</span>
                <span><SourceBadge src={line.source}/></span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default memo(LiveLogsView);

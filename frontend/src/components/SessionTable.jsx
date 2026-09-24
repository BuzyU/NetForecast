import { memo } from 'react';
import { Database, Radio, ShieldCheck } from 'lucide-react';
import {
  DirBadge, IdentityBadge, AppBadge, PacketStat,
  CompromiseIndicator, KillChainCompact,
} from './Badges';
import { stageClass, severityClass, formatTime, formatProb, stageIndex } from '../utils';

function SessionTable({
  sessions = [],
  loading = false,
  onSelectSession,
  sortBy = 'last_seen',
  setSortBy,
  dashboardTab = 'sessions',
  liveFlows = [],
  wsConnected = false,
}) {
  if (dashboardTab === 'live_flows') {
    return (
      <div className="data-table-wrap">
        {liveFlows.length === 0 ? (
          <div className="empty-state">
            {wsConnected ? (
              <>
                <ShieldCheck size={28} color="var(--severity-low)"/>
                <p>Monitoring — no active threats</p>
                <span className="mono text-xs text-muted">Only flagged attacks appear here. Traffic is flowing normally.</span>
              </>
            ) : (
              <>
                <Radio size={28} color="var(--text-muted)"/>
                <p>Waiting for connection...</p>
                <span className="mono text-xs text-muted">The real-time feed is currently disconnected.</span>
              </>
            )}
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
                        onClick={() => onSelectSession?.({
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
    );
  }

  return (
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
              <th style={{ cursor: 'pointer' }} onClick={() => setSortBy?.('flow_count')}>FLOWS {sortBy === 'flow_count' ? '▼' : ''}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => setSortBy?.('latest_risk_score')}>RISK {sortBy === 'latest_risk_score' ? '▼' : ''}</th>
              <th>STAGE</th>
              <th>KILL_CHAIN</th>
              <th style={{ cursor: 'pointer' }} onClick={() => setSortBy?.('last_seen')}>LAST_SEEN {sortBy === 'last_seen' ? '▼' : ''}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => {
              const isCompromised = stageIndex(s.latest_stage) >= 3 && (s.latest_risk_score || 0) > 0.5;
              return (
                <tr
                  key={s.session_key}
                  onClick={() => onSelectSession?.(s)}
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
                        onSelectSession?.(s);
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
  );
}

export default memo(SessionTable);

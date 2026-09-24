import { Wifi, FlaskConical } from 'lucide-react';

export default function SettingsPanel({
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
          <div className="settings-row"><span className="settings-key">ARCHITECTURE</span><span className="settings-val">{health?.num_layers || 2}-Layer LSTM (hidden={health?.hidden_size ?? '—'}, dropout={health?.dropout ?? '—'})</span></div>
          <div className="settings-row"><span className="settings-key">DEVICE</span><span className="settings-val">{health?.device?.toUpperCase() || 'CPU'}</span></div>
          <div className="settings-row"><span className="settings-key">FEATURES</span><span className="settings-val">{health?.features_count || 22}</span></div>
          <div className="settings-row"><span className="settings-key">WINDOW_SIZE</span><span className="settings-val">{health?.window_size ?? 6}</span></div>
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

export { SettingsPanel as SettingsView };

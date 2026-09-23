// ── Stage helpers ──────────────────────────────────────────────
export const STAGES = ['Benign', 'Reconnaissance', 'Initial Access', 'Lateral Movement', 'C2', 'Exfiltration'];

export const DEFAULT_FEAT_ORDER = [
  'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_mean',
  'bwd_pkt_len_mean', 'flow_bytes_s', 'flow_pkts_s', 'flow_iat_mean',
  'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean', 'syn_flag_cnt',
  'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt',
  'urg_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'ttl_variance',
  'tcp_win_size', 'retransmit_cnt',
];

export function stageIndex(stage) {
  const i = STAGES.indexOf(stage);
  return i >= 0 ? i : 0;
}

export function stageClass(stage) {
  const map = {
    'Benign': 'benign',
    'Reconnaissance': 'reconnaissance',
    'Initial Access': 'initial-access',
    'Lateral Movement': 'lateral-movement',
    'C2': 'c2',
    'Exfiltration': 'exfiltration',
  };
  return map[stage] || 'benign';
}

export function stageColor(stage) {
  const map = {
    'Benign': '#27ae60',
    'Reconnaissance': '#2980b9',
    'Initial Access': '#d4a017',
    'Lateral Movement': '#e67e22',
    'C2': '#d35400',
    'Exfiltration': '#c0392b',
  };
  return map[stage] || '#8a7f72';
}

// MITRE ATT&CK technique reference per stage (matches README kill-chain table).
export const STAGE_TECHNIQUE = {
  'Reconnaissance': 'T1595 / T1046',
  'Initial Access': 'T1190 / T1110',
  'Lateral Movement': 'T1021 / T1210',
  'C2': 'T1071 / T1573',
  'Exfiltration': 'T1041 / T1048',
};

// ── Attack detection ────────────────────────────────────────────
// A flow counts as an active attack when the model's infiltration
// probability crosses the alert threshold (0.5, matching the backend
// default) OR the predicted stage is non-Benign. Either check alone can
// miss edge cases (e.g. a non-Benign stage prediction just under the
// probability threshold), so both are checked.
export function isAttackFlow(flow) {
  if (!flow) return false;
  const prob = flow.infiltration_prob ?? flow.infiltration_probability ?? 0;
  const stage = flow.predicted_stage;
  return prob > 0.5 || (!!stage && stage !== 'Benign');
}

// ── Severity ──────────────────────────────────────────────────
export function severityClass(prob) {
  if (prob >= 0.8) return 'critical';
  if (prob >= 0.6) return 'high';
  if (prob >= 0.5) return 'medium';
  return 'low';
}

// ── Formatting ────────────────────────────────────────────────
export function formatTime(isoString) {
  if (!isoString) return '\u2014';
  const d = new Date(isoString);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDateTime(isoString) {
  if (!isoString) return '\u2014';
  const d = new Date(isoString);
  return d.toLocaleString('en-GB', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export function formatProb(p) {
  if (p == null) return '\u2014';
  return (p * 100).toFixed(1) + '%';
}

export function formatBytes(bytes) {
  if (bytes == null) return '\u2014';
  if (bytes < 1024) return bytes.toFixed(0) + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// flow_duration is stored in MICROSECONDS (live_capture.py: duration_us = ... * 1e6)
// BUG-09b fix: was incorrectly treating input as milliseconds — divide by 1000 first
export function formatDuration(us) {
  if (us == null) return '\u2014';
  const ms = us / 1000;           // microseconds → milliseconds
  if (ms < 1000) return ms.toFixed(0) + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
  return (ms / 60000).toFixed(1) + 'm';
}

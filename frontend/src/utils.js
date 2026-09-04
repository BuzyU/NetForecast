// ── Stage helpers ──────────────────────────────────────────────
const STAGES = ['Benign', 'Reconnaissance', 'Initial Access', 'Lateral Movement', 'C2', 'Exfiltration'];

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

export { STAGES };

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

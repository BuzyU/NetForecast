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
    'Benign': '#2ea043',
    'Reconnaissance': '#2f81f7',
    'Initial Access': '#d29922',
    'Lateral Movement': '#db6d28',
    'C2': '#bc4c00',
    'Exfiltration': '#da3633',
  };
  return map[stage] || '#8b949e';
}

export function severityClass(prob) {
  if (prob >= 0.8) return 'critical';
  if (prob >= 0.6) return 'high';
  if (prob >= 0.5) return 'medium';
  return 'low';
}

export function formatTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatProb(p) {
  if (p == null) return '—';
  return (p * 100).toFixed(1) + '%';
}

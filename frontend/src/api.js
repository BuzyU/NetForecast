const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function apiFetch(endpoint, options = {}) {
  const url = `${API_URL}${endpoint}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

export function apiPost(endpoint, body) {
  return apiFetch(endpoint, { method: 'POST', body: JSON.stringify(body) });
}

export async function apiUpload(endpoint, file) {
  const url = `${API_URL}${endpoint}`;
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(url, { method: 'POST', body: form });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Upload ${res.status}: ${detail}`);
  }
  return res.json();
}

export function createWebSocket() {
  const wsUrl = API_URL.replace(/^http/, 'ws') + '/ws/live';
  return new WebSocket(wsUrl);
}

export { API_URL };

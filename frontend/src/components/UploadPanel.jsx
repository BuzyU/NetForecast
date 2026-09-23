import { useState, useRef } from 'react';
import { Upload } from 'lucide-react';
import { apiUpload } from '../api';

export default function UploadPanel() {
  const [result, setResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    const isCsv = name.endsWith('.csv');
    const isPcap = name.endsWith('.pcap') || name.endsWith('.cap') || name.endsWith('.pcapng');

    if (!isCsv && !isPcap) {
      setResult({ error: 'Please upload a CSV (.csv) or PCAP (.pcap, .cap, .pcapng) file' });
      return;
    }

    setUploading(true);
    setResult(null);
    try {
      const endpoint = isPcap ? '/ingest/pcap' : '/ingest/csv';
      const data = await apiUpload(endpoint, file);
      setResult(data);
    } catch (e) {
      setResult({ error: e.message });
    }
    setUploading(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  return (
    <>
      <div style={{ marginBottom: 'var(--sp-4)' }}>
        <span className="section-label">INGEST_NETWORK_TELEMETRY</span>
        <p className="mono text-sm" style={{ color: 'var(--text-secondary)', marginTop: 'var(--sp-1)' }}>
          Upload <strong>CSV flow logs</strong> (22 CIC-IDS features) or raw <strong>PCAP packet captures</strong> (.pcap/.pcapng).
          The engine extracts temporal features, reconstructs sessions, and forecasts attack progression.
        </p>
      </div>

      <div
        className={`upload-zone ${dragging ? 'dragging' : ''}`}
        onClick={() => fileRef.current?.click()}
        onDrop={onDrop}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
      >
        {uploading ? (
          <><div className="loading-spinner" style={{ margin: '0 auto var(--sp-2)' }}/><p>Processing network telemetry...</p></>
        ) : (
          <><Upload size={26} className="upload-icon"/><p>Drop a CSV or PCAP file here or click to browse</p></>
        )}
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.pcap,.cap,.pcapng"
          style={{ display: 'none' }}
          onChange={e => handleFile(e.target.files[0])}
        />
      </div>

      {result && (
        <div className="panel mt-4">
          <div className="panel-header">
            <span className="panel-title">INGEST_RESULT</span>
          </div>
          <div className="panel-body">
            {result.error ? (
              <p style={{ color: 'var(--severity-critical)' }}>{result.error}</p>
            ) : (
              <>
                <div className="stats-bar">
                  <div className="stat-card">
                    <div className="stat-card-label">ACCEPTED</div>
                    <div className="stat-card-value" style={{ color: 'var(--severity-low)' }}>{result.flows_accepted}</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">REJECTED</div>
                    <div className="stat-card-value" style={{ color: result.flows_rejected > 0 ? 'var(--severity-critical)' : undefined }}>{result.flows_rejected}</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">ALERTS</div>
                    <div className="stat-card-value" style={{ color: result.alerts_generated > 0 ? 'var(--severity-high)' : undefined }}>{result.alerts_generated}</div>
                  </div>
                </div>
                {result.errors?.length > 0 && (
                  <div style={{ marginTop: 'var(--sp-3)' }}>
                    <span className="mono text-sm" style={{ color: 'var(--severity-high)', fontWeight: 600 }}>VALIDATION_ERRORS:</span>
                    <ul style={{ marginTop: 'var(--sp-1)', fontSize: '0.68rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', listStyle: 'none' }}>
                      {result.errors.slice(0, 10).map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export { UploadPanel as IngestPanel };

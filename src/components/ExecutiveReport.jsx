import React, { useState, useEffect } from 'react';
import { FileText, Printer, CheckCircle2, ShieldAlert, Download, Layers, ShieldCheck, AlertTriangle, Server } from 'lucide-react';
import { 
  getSeverityColor, 
  getSeverityGlowColor,
  getSeverityBadgeClass, 
  deriveRiskScore,
  normalizeMitreMappings,
  normalizeTimeline,
  extractIOCs
} from '../utils/socHelpers';

export default function ExecutiveReport({ result }) {
  const defaultRemediationsList = [
    { title: "Disable compromised Administrator account", desc: "Revoke credentials and active tokens globally." },
    { title: "Block 203.0.113.88 and 185.199.221.45", desc: "Deploy firewall block rules on edge gateways." },
    { title: "Reset privileged credentials", desc: "Require password rotation and reissue admin certificates." },
    { title: "Remove unauthorized IAM policy changes", desc: "Audit and roll back trust policy updates." },
    { title: "Isolate host 10.10.4.15", desc: "Disconnect endpoint from local network scope immediately." },
    { title: "Enable MFA for privileged accounts", desc: "Require physical token or auth app validation." },
    { title: "Run endpoint scan for mimikatz and PowerShell artifacts", desc: "Dispatch security agent script to endpoints." },
    { title: "Preserve logs for forensic investigation", desc: "Archive event traces to read-only cold storage." }
  ];

  const getInitialRemediations = () => {
    if (result?.remediations && Array.isArray(result.remediations) && result.remediations.length > 0) {
      return result.remediations.map((item, idx) => ({ ...item, id: idx, checked: false }));
    }
    return defaultRemediationsList.map((item, idx) => ({ ...item, id: idx, checked: false }));
  };

  const [remediations, setRemediations] = useState(getInitialRemediations());

  // Sync state when result changes
  useEffect(() => {
    setRemediations(getInitialRemediations());
  }, [result]);

  const toggleRemediation = (id) => {
    setRemediations(prev => 
      prev.map(item => item.id === id ? { ...item, checked: !item.checked } : item)
    );
  };

  const handlePrint = () => {
    window.print();
  };

  if (!result) {
    return (
      <div className="glass-panel report-card" style={{ textAlign: 'center', padding: '40px' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No report data compiled. Ingest and analyze log files first.</p>
      </div>
    );
  }

  const severity = result.severity || 'high';
  const category = result.category || 'Intrusion Incident';
  const confidence = result.confidence || 96;
  
  const mitreList = normalizeMitreMappings(result.mitre || []);
  const timeline = normalizeTimeline(result.timeline || []);
  const iocs = extractIOCs(result, null); 

  const derivedRisk = deriveRiskScore(severity, mitreList.length);
  const riskScoreVal = result.riskScore ? result.riskScore : `${derivedRisk}/10`;

  const businessImpactText = result.businessImpact || 
    "The incident indicates a high-confidence credential compromise followed by sensitive data access and possible exfiltration. Administrative privileges may have been abused, and cloud IAM persistence was observed. Immediate containment is required to prevent further data loss and lateral movement.";

  const completedCount = remediations.filter(r => r.checked).length;

  return (
    <div className="executive-report-view">
      <style>{`
        /* Executive report print formatting */
        @media print {
          body {
            background: white !important;
            color: black !important;
          }
          .main-content {
            padding: 0 !important;
            margin: 0 !important;
          }
          .sidebar, .page-header, .report-actions {
            display: none !important;
          }
          .glass-panel {
            border: none !important;
            box-shadow: none !important;
            background: transparent !important;
            padding: 0 !important;
          }
          .report-card {
            border: none !important;
            background: white !important;
            color: black !important;
            box-shadow: none !important;
            padding: 0 !important;
          }
          h2, h3, h4, span, label, p, td, th {
            color: black !important;
          }
          .badge-tag {
            border: 1px solid #000 !important;
            background: transparent !important;
            color: black !important;
          }
          .remediation-item {
            border: 1px solid #ccc !important;
            background: transparent !important;
          }
        }

        .report-section-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
          margin-top: 16px;
        }

        .report-sub-card {
          padding: 16px;
          background: rgba(255, 255, 255, 0.015);
          border: 1px solid var(--card-border);
          border-radius: 8px;
        }

        .priority-item {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 12px;
          border-left: 3px solid var(--severity-critical);
          background: rgba(239, 68, 68, 0.03);
          border-radius: 4px;
        }
        
        .priority-number {
          font-weight: 800;
          font-family: var(--font-mono);
          color: var(--severity-critical);
        }
      `}</style>

      <div className="report-card">
        {/* Document Header */}
        <div className="report-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <FileText size={20} color="var(--color-primary)" />
                <span style={{ fontSize: '0.8rem', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-primary)' }}>
                  OFFICIAL INCIDENT REPORT
                </span>
              </div>
              <h2 style={{ fontSize: '1.75rem', fontWeight: '800', letterSpacing: '-0.02em', color: 'white' }}>
                AI SOC Incident Analysis Report
              </h2>
            </div>
            <div className="badge-tag" style={{ 
              color: getSeverityColor(severity), 
              background: getSeverityGlowColor(severity), 
              border: `1.5px solid ${getSeverityColor(severity)}`,
              fontSize: '0.85rem', 
              padding: '6px 16px', 
              fontWeight: '800',
              borderRadius: '6px',
              textTransform: 'uppercase'
            }}>
              {severity} SEVERITY
            </div>
          </div>

          <div className="report-meta-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', marginTop: '20px' }}>
            <div className="report-meta-item">
              <span className="report-meta-label">Incident ID</span>
              <span className="report-meta-val" style={{ fontFamily: 'var(--font-mono)' }}>INC-2026-9812</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Investigation Date</span>
              <span className="report-meta-val">{new Date().toLocaleString()}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Threat Classification</span>
              <span className="report-meta-val">{category}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Incident Risk Rating</span>
              <span className="report-meta-val" style={{ color: 'var(--severity-high)' }}>{riskScoreVal}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">AI Analyst Confidence</span>
              <span className="report-meta-val" style={{ color: 'var(--color-primary)' }}>{confidence}%</span>
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="report-section">
          <h3>Executive Summary</h3>
          <p className="report-summary-text" style={{ fontSize: '0.9rem', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
            {result.summary}
          </p>
        </div>

        {/* 2. Incident Type */}
        <div className="report-section">
          <h3>Incident Type & Classification</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
            <span className="badge-tag" style={{ fontSize: '0.85rem', padding: '4px 12px', background: 'var(--bg-tertiary)' }}>
              Category: <strong>{category}</strong>
            </span>
            <span className="badge-tag" style={{ fontSize: '0.85rem', padding: '4px 12px', background: 'var(--bg-tertiary)', color: getSeverityColor(severity) }}>
              Severity Level: <strong>{severity.toUpperCase()}</strong>
            </span>
          </div>
        </div>

        {/* 3. Business Impact */}
        <div className="report-section">
          <h3>Business Impact Assessment</h3>
          <div className="glass-panel" style={{ padding: '16px', background: 'rgba(239,68,68,0.02)', borderLeft: '3px solid var(--severity-high)', marginTop: '8px' }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              {businessImpactText}
            </p>
          </div>
        </div>

        {/* 4. Affected Assets */}
        <div className="report-section">
          <h3>Affected Assets & Entities</h3>
          <div className="report-section-grid">
            <div className="report-sub-card">
              <div style={{ fontWeight: '700', fontSize: '0.85rem', marginBottom: '8px', color: 'white', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Server size={14} color="var(--color-primary)" /> Internal Targets / Hosts
              </div>
              <ul style={{ paddingLeft: '18px', color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: '1.6' }}>
                {iocs.hosts.map((host, i) => (
                  <li key={i}>Host Address: <span className="mono-font" style={{ color: 'white' }}>{host}</span></li>
                ))}
                {iocs.users.map((user, i) => (
                  <li key={i}>User Identity: <span style={{ color: 'white' }}>{user}</span></li>
                ))}
              </ul>
            </div>
            
            <div className="report-sub-card">
              <div style={{ fontWeight: '700', fontSize: '0.85rem', marginBottom: '8px', color: 'white', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={14} color="var(--severity-critical)" /> External Threat IOCs
              </div>
              <ul style={{ paddingLeft: '18px', color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: '1.6' }}>
                {iocs.ips.map((ip, i) => (
                  <li key={i}>Malicious IP: <span className="mono-font" style={{ color: 'white' }}>{ip}</span></li>
                ))}
                {iocs.domains.map((dom, i) => (
                  <li key={i}>Dest. Port/Domain: <span className="mono-font" style={{ color: 'white' }}>{dom}</span></li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* 5. Timeline Summary */}
        <div className="report-section">
          <h3>Forensic Timeline Summary</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
            A chronologically ordered summary of the adversary progression path:
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {timeline.slice(0, 5).map((event, idx) => (
              <div key={idx} style={{ display: 'flex', gap: '12px', fontSize: '0.8rem', alignItems: 'center' }}>
                <span className="mono-font" style={{ width: '60px', color: 'var(--color-primary)' }}>{event.time}</span>
                <span className="badge-tag" style={{ fontSize: '0.65rem', padding: '1px 6px' }}>{event.stage}</span>
                <span style={{ color: 'white', fontWeight: '600' }}>{event.title}</span>
                <span style={{ color: 'var(--text-muted)' }}>— {event.source || event.type}</span>
              </div>
            ))}
            {timeline.length > 5 && (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic', paddingLeft: '72px' }}>
                + {timeline.length - 5} additional events recorded in the complete timeline view.
              </div>
            )}
          </div>
        </div>

        {/* 6. MITRE ATT&CK Summary */}
        <div className="report-section">
          <h3>MITRE ATT&CK Mappings</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
            {mitreList.map((m, i) => (
              <span className="badge-tag" key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(139, 92, 246, 0.05)', borderColor: 'rgba(139, 92, 246, 0.2)' }}>
                <ShieldCheck size={12} color="var(--color-accent)" />
                <strong>{m.id}</strong>: {m.technique} ({m.tactic})
              </span>
            ))}
          </div>
        </div>

        {/* 7. Technical Findings */}
        <div className="report-section">
          <h3>Technical Findings & Evidence</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
            <p>
              Log correlation has confirmed initial remote attempts targeting elevated domain interfaces. A PowerShell download cradle was dispatched from threat actor hosts to load operational stages into volatile memory buffers.
            </p>
            <p>
              Subsequent endpoint telemetry captured LSASS process handle requests mapping credential dumping activity. System accounts were elevated to access financial file share repositories, followed shortly by a large egress POST request routing data chunks to external locations. Cloud resources were altered to add programmatic access privileges as an evasion tactic.
            </p>
          </div>
        </div>

        {/* 8. Priority Triage Actions */}
        <div className="report-section">
          <h3>Priority Containment Actions</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
            <div className="priority-item">
              <span className="priority-number">1</span>
              <div>
                <strong style={{ color: 'white' }}>Isolate Host Endpoint</strong>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Disconnect system 10.10.4.15 from the subnetwork scopes to restrict lateral RDP/SMB pivots.
                </p>
              </div>
            </div>

            <div className="priority-item" style={{ borderLeftColor: 'var(--severity-high)' }}>
              <span className="priority-number" style={{ color: 'var(--severity-high)' }}>2</span>
              <div>
                <strong style={{ color: 'white' }}>Revoke Admin Keys & Sessions</strong>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Invalidate Active Directory tokens, reset Domain credentials, and delete AKIAIOSFODNN7EXAMPLE API key.
                </p>
              </div>
            </div>

            <div className="priority-item" style={{ borderLeftColor: 'var(--color-primary)' }}>
              <span className="priority-number" style={{ color: 'var(--color-primary)' }}>3</span>
              <div>
                <strong style={{ color: 'white' }}>Deploy Gateway ACL Blocks</strong>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Block all communication channels resolving to 203.0.113.88 and 185.199.221.45 at firewall borders.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* 9. Recommended Remediation Checklist */}
        <div className="report-section">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h3>Recommended Mitigation Tasks</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              {completedCount} of {remediations.length} completed
            </span>
          </div>
          <div className="remediation-list">
            {remediations.map((item) => (
              <div key={item.id} className="remediation-item" style={item.checked ? { borderColor: 'var(--severity-info-glow)', opacity: '0.6' } : {}}>
                <input 
                  type="checkbox" 
                  checked={item.checked} 
                  onChange={() => toggleRemediation(item.id)}
                  id={`rep-rem-check-${item.id}`}
                />
                <label className="remediation-content" htmlFor={`rep-rem-check-${item.id}`} style={{ cursor: 'pointer' }}>
                  <span className="remediation-title" style={item.checked ? { textDecoration: 'line-through', color: 'var(--text-muted)' } : { color: 'white' }}>
                    {item.title}
                  </span>
                  <span className="remediation-desc">{item.desc}</span>
                </label>
              </div>
            ))}
          </div>
        </div>

        {/* Action Controls */}
        <div className="report-actions" style={{ display: 'flex', justifyContent: 'space-between', marginTop: '32px', borderTop: '1px solid var(--card-border)', paddingTop: '20px' }}>
          <button className="btn-secondary" onClick={handlePrint} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Printer size={16} />
            Print / Save to PDF
          </button>
          
          <button 
            className="btn-submit" 
            style={{ background: 'var(--color-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}
            onClick={handlePrint}
          >
            <Download size={16} />
            Download Report
          </button>
        </div>
      </div>
    </div>
  );
}

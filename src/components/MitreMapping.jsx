import React, { useState } from 'react';
import { ShieldCheck, Info, ShieldAlert, Cpu, AlertTriangle } from 'lucide-react';
import { 
  getSeverityColor, 
  getSeverityBadgeClass, 
  normalizeMitreMappings 
} from '../utils/socHelpers';

const mitreMatrixColumns = [
  {
    tactic: 'Initial Access',
    techniques: [
      { id: 'T1566', name: 'Phishing' },
      { id: 'T1190', name: 'Exploit Public Application' },
      { id: 'T1133', name: 'External Remote Services' }
    ]
  },
  {
    tactic: 'Execution',
    techniques: [
      { id: 'T1059', name: 'Command & Scripting' },
      { id: 'T1204', name: 'User Execution' },
      { id: 'T1059.001', name: 'PowerShell Interpreter' }
    ]
  },
  {
    tactic: 'Persistence',
    techniques: [
      { id: 'T1136', name: 'Create Account' },
      { id: 'T1136.003', name: 'Cloud API Keys' },
      { id: 'T1543', name: 'Create/Modify System Process' }
    ]
  },
  {
    tactic: 'Defense Evasion',
    techniques: [
      { id: 'T1562', name: 'Impair Defenses' },
      { id: 'T1490', name: 'Inhibit Recovery (Shadows)' },
      { id: 'T1070', name: 'Indicator Removal on Host' }
    ]
  },
  {
    tactic: 'Credential Access',
    techniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1555', name: 'Credentials from Store' }
    ]
  },
  {
    tactic: 'Lateral Movement',
    techniques: [
      { id: 'T1021', name: 'Remote Services (RDP)' },
      { id: 'T1210', name: 'Exploitation of Remote Services' },
      { id: 'T1021.002', name: 'SMB Admin Shares' }
    ]
  },
  {
    tactic: 'Exfiltration',
    techniques: [
      { id: 'T1567', name: 'Exfil Over Web Service' },
      { id: 'T1048', name: 'Exfil Over Alternative Protocol' },
      { id: 'T1020', name: 'Automated Exfiltration' }
    ]
  },
  {
    tactic: 'Impact',
    techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact' },
      { id: 'T1489', name: 'Service Stop' },
      { id: 'T1491', name: 'Defacement' }
    ]
  }
];

export default function MitreMapping({ mitre }) {
  const [hoveredTechnique, setHoveredTechnique] = useState(null);

  // Normalize mappings to extract detailed fields and apply fallback structures if needed
  const mappedTechniques = normalizeMitreMappings(mitre || []);

  // Helper function to check if a matrix technique is identified in the analysis results
  const isTechniqueIdentified = (matrixTechId) => {
    return mappedTechniques.some(t => {
      return t.id === matrixTechId || t.id.startsWith(matrixTechId + '.') || matrixTechId.startsWith(t.id);
    });
  };

  const getIdentifiedTechDetails = (matrixTechId) => {
    return mappedTechniques.find(t => t.id === matrixTechId || t.id.startsWith(matrixTechId + '.') || matrixTechId.startsWith(t.id));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      <style>{`
        .mitre-table {
          width: 100%;
          border-collapse: collapse;
          text-align: left;
          font-size: 0.85rem;
        }

        .mitre-table th {
          padding: 12px 16px;
          border-bottom: 1.5px solid var(--card-border);
          color: var(--text-muted);
          font-weight: 700;
          text-transform: uppercase;
          font-size: 0.75rem;
          letter-spacing: 0.05em;
        }

        .mitre-table td {
          padding: 14px 16px;
          border-bottom: 1px solid var(--card-border);
          color: var(--text-secondary);
        }

        .mitre-row:hover {
          background: rgba(255, 255, 255, 0.015);
        }

        .mono-font {
          font-family: var(--font-mono);
          font-weight: 600;
        }
      `}</style>

      {/* Primary Section: Professional Mapped Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 className="panel-title" style={{ marginBottom: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={20} color="var(--color-primary)" />
            Detected Adversary Techniques Detail
          </h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Total Identified: {mappedTechniques.length}
          </span>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '24px', lineHeight: '1.4' }}>
          Below are the specific tactics and techniques identified in the ingested logs, matched against standard MITRE ATT&CK models, including confidence ratings and forensic evidence descriptions:
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table className="mitre-table">
            <thead>
              <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Tactic Category</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Incident Evidence Match</th>
              </tr>
            </thead>
            <tbody>
              {mappedTechniques.map((tech) => (
                <tr className="mitre-row" key={tech.id}>
                  <td className="mono-font" style={{ color: 'var(--color-accent)' }}>{tech.id}</td>
                  <td style={{ color: 'white', fontWeight: '700' }}>{tech.technique}</td>
                  <td>
                    <span className="badge-tag">{tech.tactic}</span>
                  </td>
                  <td className="mono-font" style={{ color: 'var(--color-primary)' }}>{tech.confidence}%</td>
                  <td>
                    <span className={`severity-badge ${getSeverityBadgeClass(tech.severity)}`} style={{ fontSize: '0.65rem', padding: '2px 8px' }}>
                      {tech.severity}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8rem', fontStyle: 'italic', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={tech.evidence}>
                    {tech.evidence}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Grid Visual representation */}
      <div className="glass-panel mitre-card" style={{ marginBottom: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 className="panel-title" style={{ marginBottom: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cpu size={18} color="var(--color-accent)" />
            MITRE ATT&CK Visual Matrix Grid
          </h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Hover highlighted cells to inspect detection status
          </span>
        </div>

        <div className="mitre-grid">
          {mitreMatrixColumns.map((col, colIdx) => (
            <div key={colIdx} className="mitre-column">
              <div className="mitre-header">{col.tactic}</div>
              {col.techniques.map((tech, techIdx) => {
                const active = isTechniqueIdentified(tech.id);
                const matchingTech = getIdentifiedTechDetails(tech.id);
                
                return (
                  <div 
                    key={techIdx} 
                    className={`mitre-cell ${active ? 'highlighted' : ''}`}
                    onMouseEnter={() => active && setHoveredTechnique(matchingTech || tech)}
                    onMouseLeave={() => setHoveredTechnique(null)}
                    style={{ position: 'relative' }}
                  >
                    <div className="mitre-cell-id">{matchingTech?.id || tech.id}</div>
                    <div className="mitre-cell-name">{tech.name}</div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        {hoveredTechnique && (
          <div 
            className="glass-panel" 
            style={{ 
              marginTop: '24px', 
              padding: '16px', 
              background: 'var(--color-accent-glow)', 
              borderColor: 'var(--color-accent)',
              display: 'flex',
              gap: '12px',
              alignItems: 'flex-start'
            }}
          >
            <Info size={16} color="var(--color-accent)" style={{ marginTop: '2px', flexShrink: 0 }} />
            <div>
              <h4 style={{ fontWeight: '700', fontSize: '0.85rem', color: 'white', marginBottom: '4px' }}>
                Technique Detected: {hoveredTechnique.technique || hoveredTechnique.name} ({hoveredTechnique.id})
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                Tactic category: <strong>{hoveredTechnique.tactic || 'Security Analysis'}</strong> | Severity rating: <span style={{ color: getSeverityColor(hoveredTechnique.severity) }}>{(hoveredTechnique.severity || 'high').toUpperCase()}</span>
              </p>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px', fontStyle: 'italic' }}>
                Evidence matched: "{hoveredTechnique.evidence || 'Trace logs verify operational credentials.'}"
              </p>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}

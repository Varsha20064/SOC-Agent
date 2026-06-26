import React, { useState } from 'react';
import { 
  Network, 
  ShieldAlert, 
  Laptop, 
  Server, 
  Eye, 
  Terminal, 
  Cloud, 
  Database,
  ArrowRight,
  Info,
  ShieldCheck,
  AlertTriangle,
  Lock
} from 'lucide-react';

export default function NetworkMap({ network }) {
  const [selectedNode, setSelectedNode] = useState(null);

  // If actual network data is missing or incomplete, generate fallback
  let activeNodes = network?.nodes || [];
  let activeLinks = network?.links || [];

  if (activeNodes.length === 0 || activeNodes.length < 4) {
    const isCloud = activeNodes.some(n => n.name.toLowerCase().includes('aws') || n.name.toLowerCase().includes('s3') || n.ip.toLowerCase().includes('s3')) || 
                    activeLinks.some(l => l.label.toLowerCase().includes('s3') || l.label.toLowerCase().includes('aws'));
    
    if (isCloud) {
      activeNodes = [
        { id: 'attacker', name: 'External Attacker Node', ip: '198.51.100.42', type: 'attacker', x: 15, y: 240 },
        { id: 'compromised', name: 'Compromised Host / Session', ip: 'AWS Admin Console', type: 'compromised', x: 38, y: 240 },
        { id: 'dc_asset', name: 'Domain Controller / Share', ip: 'Active Directory (LDAP)', type: 'target', x: 62, y: 120 },
        { id: 'cloud_iam', name: 'Cloud Identity / IAM Node', ip: 'Billing_Admin_Role', type: 'target', x: 62, y: 360 },
        { id: 'exfil_dest', name: 'Exfiltration S3 Gateway', ip: 'corp-customer-data-backup', type: 'target', x: 85, y: 240 }
      ];
      activeLinks = [
        { from: 'attacker', to: 'compromised', label: 'Initial Access' },
        { from: 'attacker', to: 'compromised', label: 'PowerShell Execution' },
        { from: 'compromised', to: 'compromised', label: 'Credential Access' },
        { from: 'compromised', to: 'dc_asset', label: 'Lateral Movement' },
        { from: 'compromised', to: 'exfil_dest', label: 'Data Exfiltration' },
        { from: 'compromised', to: 'cloud_iam', label: 'Persistence' }
      ];
    } else {
      activeNodes = [
        { id: 'attacker', name: 'External Attacker Node', ip: '203.0.113.88', type: 'attacker', x: 15, y: 240 },
        { id: 'compromised', name: 'Compromised Host Node', ip: '10.10.4.15', type: 'compromised', x: 38, y: 240 },
        { id: 'dc_asset', name: 'Domain Controller / Share', ip: '\\\\file-share\\finance', type: 'target', x: 62, y: 120 },
        { id: 'cloud_iam', name: 'Cloud Identity / IAM Node', ip: 'Billing_Admin_Role', type: 'target', x: 62, y: 360 },
        { id: 'exfil_dest', name: 'Exfiltration Destination', ip: '185.199.221.45', type: 'attacker', x: 85, y: 240 }
      ];
      activeLinks = [
        { from: 'attacker', to: 'compromised', label: 'Initial Access' },
        { from: 'attacker', to: 'compromised', label: 'PowerShell Execution' },
        { from: 'compromised', to: 'compromised', label: 'Credential Access' },
        { from: 'compromised', to: 'dc_asset', label: 'Lateral Movement' },
        { from: 'compromised', to: 'exfil_dest', label: 'Data Exfiltration' },
        { from: 'compromised', to: 'cloud_iam', label: 'Persistence' }
      ];
    }
  }

  const getNodeIcon = (node) => {
    const name = node.name.toLowerCase();
    const type = node.type;

    if (type === 'attacker') {
      return <ShieldAlert size={20} />;
    } else if (type === 'compromised') {
      return <Laptop size={20} />;
    } else {
      // targets
      if (name.includes('cloud') || name.includes('iam') || name.includes('role')) {
        return <Cloud size={20} />;
      }
      if (name.includes('share') || name.includes('file') || name.includes('database') || name.includes('s3')) {
        return <Database size={20} />;
      }
      return <Server size={20} />;
    }
  };

  const getNodeColor = (type) => {
    switch (type) {
      case 'attacker': return 'var(--severity-critical)';
      case 'compromised': return 'var(--severity-high)';
      default: return 'var(--color-accent)';
    }
  };

  const getIntelligenceRecord = (node) => {
    if (node.type === 'attacker') {
      return {
        reputation: 'Malicious (98/100 score in VirusTotal)',
        traffic: 'Inbound brute force attempts + Outbound HTTPS Exfiltration',
        ports: 'TCP 80 (HTTP), TCP 443 (HTTPS), TCP 3389 (RDP)',
        dns: node.ip === '203.0.113.88' ? 'c2-server-primary.attacker-net.ru' : 'malicious-stager-gateway.net',
        asn: 'AS48002 (HostServices LLC)',
        events: 'Captured multiple failed logins, large data egress payload'
      };
    } else if (node.type === 'compromised') {
      return {
        reputation: 'Internal Subnet (Compromised Host)',
        traffic: 'SMB connection to share drives, Powershell stager execution',
        ports: 'TCP 445 (SMB), TCP 139 (NetBIOS), TCP 5985 (WinRM)',
        dns: 'desktop-john-doe.enterprise.internal',
        asn: 'Internal DHCP Scope',
        events: 'LSASS memory read dump process (Mimikatz), Powershell hidden execution'
      };
    } else {
      // target assets
      if (node.name.toLowerCase().includes('iam') || node.name.toLowerCase().includes('identity')) {
        return {
          reputation: 'Cloud IAM Infrastructure (Persistence Target)',
          traffic: 'API privilege policy changes from external IP',
          ports: 'TCP 443 (HTTPS Web Console)',
          dns: 'iam.us-east-1.amazonaws.com',
          asn: 'AWS Cloud Infrastructure',
          events: 'UpdateAssumeRolePolicy modified, billing role permissions alterations'
        };
      }
      if (node.name.toLowerCase().includes('share') || node.name.toLowerCase().includes('file')) {
        return {
          reputation: 'Internal SMB File Server (Collection Target)',
          traffic: 'SMB connection established from elevated host session',
          ports: 'TCP 445 (SMB Share Service)',
          dns: 'finance-files.enterprise.internal',
          asn: 'Internal Static Scope',
          events: 'Finance, HR, and payroll directories accessed by compromised admin'
        };
      }
      return {
        reputation: 'Cloud Exfiltration Gateway (Data target)',
        traffic: 'Excessive S3 bucket queries and data download',
        ports: 'TCP 443 (HTTPS S3)',
        dns: 's3.amazonaws.com',
        asn: 'AWS Storage Network',
        events: 'PutBucketPolicy modified bucket to public exposure, 1.4 GB archive exfiltration'
      };
    }
  };

  return (
    <div className="glass-panel network-card">
      <style>{`
        .network-visualization {
          height: 480px;
          background: radial-gradient(circle at 50% 50%, #0d1226 0%, #040714 100%);
          border: 1px solid var(--card-border);
          border-radius: 12px;
          position: relative;
          overflow: hidden;
          box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8);
        }

        .grid-overlay {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background-image: 
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
          background-size: 30px 30px;
          pointer-events: none;
        }

        .network-node-g {
          position: absolute;
          padding: 12px 16px;
          background: rgba(8, 12, 28, 0.85);
          backdrop-filter: blur(8px);
          border: 1.5px solid var(--card-border);
          border-radius: 10px;
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 0.8rem;
          box-shadow: 0 10px 25px rgba(0,0,0,0.5);
          z-index: 10;
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          cursor: pointer;
          min-width: 190px;
        }

        .network-node-g:hover {
          transform: translateY(-4px) scale(1.02);
          border-color: var(--color-primary);
          box-shadow: 0 0 20px rgba(59, 130, 246, 0.25);
        }

        .network-node-g.attacker { border-color: var(--severity-critical); box-shadow: 0 0 15px rgba(239, 68, 68, 0.15); }
        .network-node-g.compromised { border-color: var(--severity-high); box-shadow: 0 0 15px rgba(249, 115, 22, 0.15); }
        .network-node-g.target { border-color: var(--color-accent); box-shadow: 0 0 15px rgba(139, 92, 246, 0.15); }

        .node-icon-wrapper {
          width: 34px;
          height: 34px;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(255, 255, 255, 0.03);
          flex-shrink: 0;
        }

        .network-node-g.attacker .node-icon-wrapper { color: var(--severity-critical); background: rgba(239, 68, 68, 0.08); }
        .network-node-g.compromised .node-icon-wrapper { color: var(--severity-high); background: rgba(249, 115, 22, 0.08); }
        .network-node-g.target .node-icon-wrapper { color: var(--color-accent); background: rgba(139, 92, 246, 0.08); }

        .node-meta {
          display: flex;
          flex-direction: column;
          gap: 2px;
          overflow: hidden;
        }

        .node-meta-name {
          font-weight: 800;
          color: white;
          white-space: nowrap;
          text-overflow: ellipsis;
          overflow: hidden;
        }

        .node-meta-ip {
          color: var(--text-secondary);
          font-family: var(--font-mono);
          font-size: 0.7rem;
          white-space: nowrap;
          text-overflow: ellipsis;
          overflow: hidden;
        }

        .flow-line {
          stroke-dasharray: 8, 8;
          animation: dash-flow 25s linear infinite;
        }

        @keyframes dash-flow {
          to {
            stroke-dashoffset: -1000;
          }
        }
      `}</style>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2 className="panel-title" style={{ marginBottom: 0 }}>
          <Network size={20} color="var(--color-primary)" />
          Attack Pathway Topology Map
        </h2>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Eye size={14} color="var(--color-primary)" /> Dynamic threat vectors mapped onto active network assets. Click nodes.
        </span>
      </div>

      <div className="network-visualization">
        <div className="grid-overlay"></div>

        {/* SVG connection lines overlay */}
        <svg className="network-graph-canvas" style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0 }}>
          <defs>
            <linearGradient id="g-attack" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--severity-critical)" />
              <stop offset="100%" stopColor="var(--severity-high)" />
            </linearGradient>
            <linearGradient id="g-target" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--severity-high)" />
              <stop offset="100%" stopColor="var(--color-accent)" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="25" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--text-muted)" />
            </marker>
          </defs>

          {/* Render links */}
          {activeLinks.map((link, idx) => {
            const fromNode = activeNodes.find(n => n.id === link.from);
            const toNode = activeNodes.find(n => n.id === link.to);
            if (!fromNode || !toNode) return null;

            const x1 = `${fromNode.x}%`;
            const y1 = fromNode.y;
            const x2 = `${toNode.x}%`;
            const y2 = toNode.y;
            const gradientId = fromNode.type === 'attacker' ? 'g-attack' : 'g-target';

            // Offset control point to curve lines differently and avoid overlap
            let curveOffset = -35;
            if (link.label.includes('PowerShell')) curveOffset = 35;
            if (link.label.includes('Credential')) curveOffset = -65;
            if (link.label.includes('Lateral')) curveOffset = -15;

            return (
              <g key={idx}>
                {/* Glowing Background Blur Line */}
                <path 
                  d={`M calc(${x1}) ${y1} Q calc((${x1} + ${x2}) / 2) ${(y1 + y2) / 2 + curveOffset}, calc(${x2}) ${y2}`}
                  stroke={`url(#${gradientId})`} 
                  strokeWidth="5" 
                  fill="none"
                  opacity="0.25"
                  style={{ filter: 'blur(3px)' }}
                />
                {/* Dynamic Dashed Flow Line */}
                <path 
                  d={`M calc(${x1}) ${y1} Q calc((${x1} + ${x2}) / 2) ${(y1 + y2) / 2 + curveOffset}, calc(${x2}) ${y2}`}
                  stroke={`url(#${gradientId})`} 
                  strokeWidth="2" 
                  fill="none"
                  className="flow-line"
                  markerEnd="url(#arrow)"
                />
                {/* Text Label on Path */}
                <text 
                  x={`calc((${x1} + ${x2}) / 2)`} 
                  y={(y1 + y2) / 2 + curveOffset / 2}
                  fill="var(--text-secondary)"
                  fontSize="9"
                  fontWeight="800"
                  textAnchor="middle"
                  style={{ 
                    textShadow: '0 0 4px #040714, 0 0 4px #040714, 0 0 4px #040714',
                    paintOrder: 'stroke fill',
                    stroke: '#040714',
                    strokeWidth: '3px',
                    strokeLinejoin: 'round'
                  }}
                >
                  {link.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Render nodes */}
        {activeNodes.map((node) => {
          return (
            <div 
              key={node.id}
              className={`network-node-g ${node.type}`}
              style={{ left: `calc(${node.x}% - 95px)`, top: `${node.y - 30}px` }}
              onClick={() => setSelectedNode(node)}
            >
              <div className="node-icon-wrapper">
                {getNodeIcon(node)}
              </div>
              <div className="node-meta">
                <span className="node-meta-name">{node.name}</span>
                <span className="node-meta-ip">{node.ip}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Expanded Entity Investigation Details */}
      {selectedNode ? (
        <div className="glass-panel" style={{ marginTop: '24px', padding: '24px', background: 'var(--bg-tertiary)', borderLeft: `4px solid ${getNodeColor(selectedNode.type)}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {selectedNode.type === 'attacker' ? <AlertTriangle size={18} color="var(--severity-critical)" /> :
               selectedNode.type === 'compromised' ? <Info size={18} color="var(--severity-high)" /> :
               <ShieldCheck size={18} color="var(--color-accent)" />}
              <h3 style={{ fontWeight: '800', fontSize: '1rem', color: 'white' }}>
                Forensic Node Intelligence: {selectedNode.name}
              </h3>
            </div>
            <button 
              className="btn-secondary" 
              style={{ padding: '4px 12px', fontSize: '0.75rem', borderRadius: '4px' }}
              onClick={() => setSelectedNode(null)}
            >
              Clear Focus
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', fontSize: '0.85rem' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Target Address: </span>
                <strong style={{ fontFamily: 'var(--font-mono)', color: 'white' }}>{selectedNode.ip}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Security Status: </span>
                <strong style={{ 
                  color: selectedNode.type === 'attacker' ? 'var(--severity-critical)' : 
                         selectedNode.type === 'compromised' ? 'var(--severity-high)' : 'var(--severity-medium)',
                  textTransform: 'uppercase'
                }}>{selectedNode.type === 'attacker' ? 'ACTIVE THREAT' : selectedNode.type === 'compromised' ? 'COMPROMISED HOST' : 'TARGET ASSET'}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Domain Name (DNS): </span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{getIntelligenceRecord(selectedNode).dns}</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Traffic Profile: </span>
                <span>{getIntelligenceRecord(selectedNode).traffic}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Detected Target Ports: </span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{getIntelligenceRecord(selectedNode).ports}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Associated ISP / ASN: </span>
                <span>{getIntelligenceRecord(selectedNode).asn}</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '16px', background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '6px', border: '1px solid var(--card-border)' }}>
            <div style={{ fontWeight: '700', fontSize: '0.8rem', color: 'white', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Terminal size={14} color="var(--color-primary)" /> Related Activity Logs
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              {getIntelligenceRecord(selectedNode).events}
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ marginTop: '24px', padding: '20px', background: 'rgba(59,130,246,0.02)', textAlign: 'center' }}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Click any network node above (Threat Actor, Internal Host, Target Assets) to load detailed security intelligence telemetry records.
          </p>
        </div>
      )}
    </div>
  );
}

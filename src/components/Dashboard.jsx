import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  UploadCloud, 
  FileText, 
  Activity, 
  Terminal, 
  CheckCircle2, 
  HelpCircle, 
  AlertTriangle,
  Trash2,
  Plus,
  Server,
  User,
  Cpu,
  ArrowRight,
  Shield,
  Play,
  AlertCircle,
  FileCode,
  Network,
  Clock,
  ExternalLink
} from 'lucide-react';
import { presetScenarios } from '../utils/incidentSimulator';
import { 
  getSeverityColor, 
  getSeverityBadgeClass, 
  deriveRiskScore, 
  extractIOCs, 
  buildReasoningChain, 
  normalizeMitreMappings 
} from '../utils/socHelpers';

export default function Dashboard({ 
  logs, 
  setLogs, 
  onStartAnalysis, 
  analyzing, 
  systemStats,
  analysisResult,
  setAnalysisResult
}) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [activeAlertDetails, setActiveAlertDetails] = useState(null);

  // Manage checkbox state for remediations locally
  const [remediations, setRemediations] = useState([]);

  useEffect(() => {
    if (analysisResult?.remediations) {
      setRemediations(
        analysisResult.remediations.map((item, idx) => ({ ...item, id: idx, checked: false }))
      );
    } else {
      setRemediations([]);
    }
  }, [analysisResult]);

  const toggleRemediation = (id) => {
    setRemediations(prev => 
      prev.map(item => item.id === id ? { ...item, checked: !item.checked } : item)
    );
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(e.dataTransfer.files);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFiles(e.target.files);
    }
  };

  const handleFiles = (fileList) => {
    Array.from(fileList).forEach(file => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        const name = file.name.toLowerCase();
        let logKey = 'networkSummary';
        let typeLabel = 'Network Traffic';

        if (name.includes('firewall') || name.includes('fw')) {
          logKey = 'firewall';
          typeLabel = 'Firewall Logs';
        } else if (name.includes('event') || name.includes('win') || name.includes('sec')) {
          logKey = 'eventLogs';
          typeLabel = 'Windows Event Logs';
        } else if (name.includes('cloud') || name.includes('trail') || name.includes('aws')) {
          logKey = 'cloudLogs';
          typeLabel = 'Cloud Logs';
        } else if (name.includes('email') || name.includes('eml') || name.includes('mail')) {
          logKey = 'email';
          typeLabel = 'Suspicious Email';
        }

        setLogs(prev => ({
          ...prev,
          [logKey]: (prev[logKey] ? prev[logKey] + '\n\n' : '') + text
        }));

        setUploadedFiles(prev => {
          const filtered = prev.filter(f => f.key !== logKey);
          return [...filtered, {
            name: file.name,
            size: (file.size / 1024).toFixed(1) + ' KB',
            type: typeLabel,
            key: logKey
          }];
        });
      };
      reader.readAsText(file);
    });
  };

  const loadPreset = (preset) => {
    setSelectedPreset(preset.id);
    setLogs({
      email: preset.logs.email || '',
      eventLogs: preset.logs.eventLogs || '',
      firewall: preset.logs.firewall || '',
      cloudLogs: preset.logs.cloudLogs || '',
      networkSummary: preset.logs.networkSummary || ''
    });

    if (preset.id === 'credential_exfil') {
      setUploadedFiles([
        { name: 'alert_auth_failures.eml', size: '1.2 KB', type: 'Suspicious Email', key: 'email' },
        { name: 'win_event_logs_security.csv', size: '14.5 KB', type: 'Windows Event Logs', key: 'eventLogs' },
        { name: 'cisco_asa_firewall.log', size: '8.4 KB', type: 'Firewall Logs', key: 'firewall' },
        { name: 'smb_cloudtrail_audit.log', size: '22.1 KB', type: 'Network Traffic', key: 'networkSummary' }
      ]);
    } else if (preset.id === 'cloud_exfil') {
      setUploadedFiles([
        { name: 'aws_guardduty_alert.eml', size: '2.4 KB', type: 'Suspicious Email', key: 'email' },
        { name: 'aws_cloudtrail_admin.json', size: '12.3 KB', type: 'Cloud Logs', key: 'cloudLogs' },
        { name: 's3_gateway_egress.log', size: '5.2 KB', type: 'Firewall Logs', key: 'firewall' },
        { name: 's3_bucket_policy.json', size: '3.1 KB', type: 'Network Traffic', key: 'networkSummary' }
      ]);
    }
  };

  const removeFile = (key) => {
    setLogs(prev => ({ ...prev, [key]: '' }));
    setUploadedFiles(prev => prev.filter(f => f.key !== key));
  };

  const getLogCount = () => {
    return Object.values(logs).filter(Boolean).length;
  };

  const handleResetInvestigation = () => {
    setAnalysisResult(null);
    setLogs({
      email: '',
      eventLogs: '',
      firewall: '',
      cloudLogs: '',
      networkSummary: ''
    });
    setUploadedFiles([]);
    setSelectedPreset(null);
  };

  // Helper values for displaying metrics
  const activeSeverity = analysisResult?.severity || 'High';
  const confidencePercent = analysisResult?.confidence || (selectedPreset === 'cloud_exfil' ? 88 : 96);
  
  const mitreList = normalizeMitreMappings(analysisResult?.mitre || []);
  const mitreCount = mitreList.length;

  const derivedRisk = deriveRiskScore(activeSeverity, mitreCount);
  const activeRiskScore = analysisResult?.riskScore ? parseFloat(analysisResult.riskScore).toFixed(1) : derivedRisk;

  const iocs = extractIOCs(analysisResult, logs);
  const reasoningChain = buildReasoningChain(analysisResult);

  // Fallback remediation tasks if analysis lacks them
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

  const activeRemediations = remediations.length > 0 ? remediations : defaultRemediationsList.map((r, i) => ({ ...r, id: i, checked: false }));

  // Alert simulation triggers
  const recentAlertsData = [
    {
      id: 1,
      title: "Suspicious LSASS credential dump memory handle",
      severity: "critical",
      source: "Host Security / Sysmon",
      asset: "10.10.4.15 (John Doe PC)",
      time: "2 mins ago",
      evidence: "mimikatz.exe requested access scope 0x143A on LSASS.exe memory registers."
    },
    {
      id: 2,
      title: "AWS IAM Policy modified outside business hours",
      severity: "high",
      source: "Cloud Audit / CloudTrail",
      asset: "Billing_Admin_Role",
      time: "10 mins ago",
      evidence: "UpdateAssumeRolePolicy action issued by administrator from IP 198.51.100.42 without MFA."
    },
    {
      id: 3,
      title: "Large HTTP POST volume threshold triggered",
      severity: "medium",
      source: "Network / Firewall",
      asset: "10.10.4.15 -> 203.0.113.88",
      time: "22 mins ago",
      evidence: "Egress traffic spike: 1.4 GB dispatched over port 443 in 12 seconds."
    },
    {
      id: 4,
      title: "Failed SSH login attempts threshold exceeded",
      severity: "low",
      source: "Auth / Linux Secure",
      asset: "192.168.50.10 (Internal Server)",
      time: "45 mins ago",
      evidence: "15 sequential authentication failures recorded from source IP 203.0.113.88."
    }
  ];

  return (
    <div className="dashboard-view" style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <style>{`
        /* Glassmorphism panels and indicators */
        .soc-metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
        }

        .soc-card {
          position: relative;
          padding: 16px;
          background: rgba(8, 12, 28, 0.6);
          border: 1px solid var(--card-border);
          border-radius: 10px;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .soc-card-label {
          font-size: 0.75rem;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .soc-card-val {
          font-size: 1.25rem;
          font-weight: 800;
          color: white;
        }

        .severity-badge {
          align-self: flex-start;
          font-size: 0.65rem;
          padding: 2px 8px;
          border-radius: 4px;
          font-weight: 700;
          text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--severity-critical-glow); color: var(--severity-critical); border: 1px solid rgba(239, 68, 68, 0.3); }
        .severity-badge.high { background: var(--severity-high-glow); color: var(--severity-high); border: 1px solid rgba(249, 115, 22, 0.3); }
        .severity-badge.medium { background: var(--severity-medium-glow); color: var(--severity-medium); border: 1px solid rgba(234, 179, 8, 0.3); }
        .severity-badge.low { background: var(--severity-low-glow); color: var(--severity-low); border: 1px solid rgba(59, 130, 246, 0.3); }

        .glow-red { box-shadow: 0 0 15px rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.25); }
        .glow-amber { box-shadow: 0 0 15px rgba(249, 115, 22, 0.1); border-color: rgba(249, 115, 22, 0.25); }

        /* File uploaded items */
        .uploaded-chips-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
          margin-top: 16px;
        }

        .file-chip {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 10px 16px;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid var(--card-border);
          border-radius: 8px;
        }

        .file-chip-info {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .file-chip-title {
          font-weight: 700;
          font-size: 0.85rem;
          color: white;
        }

        .file-chip-meta {
          font-size: 0.75rem;
          color: var(--text-secondary);
        }

        /* AI Reasoning steps */
        .reasoning-flow {
          display: flex;
          flex-direction: column;
          gap: 16px;
          position: relative;
        }

        .reasoning-step-item {
          display: flex;
          gap: 16px;
          position: relative;
          padding-bottom: 4px;
        }

        .reasoning-step-item:not(:last-child)::before {
          content: '';
          position: absolute;
          left: 17px;
          top: 36px;
          bottom: -16px;
          width: 2px;
          background: var(--card-border);
        }

        .reasoning-circle {
          width: 36px;
          height: 36px;
          border-radius: 50%;
          background: var(--bg-tertiary);
          border: 2px solid var(--card-border);
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
          z-index: 2;
        }

        .reasoning-circle.active {
          border-color: var(--color-primary);
          box-shadow: 0 0 10px var(--color-primary-glow);
          color: var(--color-primary);
        }

        /* Clickable alerts feed */
        .clickable-alert-card {
          cursor: pointer;
          transition: all 0.2s ease;
          border-left: 3px solid transparent;
        }

        .clickable-alert-card:hover {
          background: rgba(255, 255, 255, 0.03);
          transform: translateX(4px);
        }

        .clickable-alert-card.critical { border-left-color: var(--severity-critical); }
        .clickable-alert-card.high { border-left-color: var(--severity-high); }
        .clickable-alert-card.medium { border-left-color: var(--severity-medium); }
        .clickable-alert-card.low { border-left-color: var(--severity-low); }

        /* Chips styling */
        .ioc-chip-tag {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          background: var(--bg-tertiary);
          border: 1px solid var(--card-border);
          color: var(--text-primary);
          padding: 4px 10px;
          border-radius: 6px;
          display: inline-flex;
          align-items: center;
          gap: 6px;
          transition: all 0.2s ease;
        }

        .ioc-chip-tag:hover {
          border-color: var(--color-accent);
          background: var(--color-accent-glow);
        }

        /* Actionable checklist */
        .checklist-item {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 12px;
          background: rgba(255, 255, 255, 0.01);
          border: 1px solid var(--card-border);
          border-radius: 8px;
          transition: all 0.2s ease;
        }

        .checklist-item:hover {
          background: rgba(255, 255, 255, 0.02);
          border-color: var(--color-primary-glow);
        }

        .checkbox-container {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 18px;
          width: 18px;
          margin-top: 2px;
          cursor: pointer;
        }
      `}</style>

      {/* 1. Header Metrics Row */}
      <div className="metrics-grid">
        <div className="metric-card glass-panel">
          <div className="metric-info">
            <h3>SIEM Threat Scope</h3>
            <div className="metric-value" style={{ 
              color: activeSeverity.toLowerCase() === 'critical' ? 'var(--severity-critical)' : 
                     activeSeverity.toLowerCase() === 'high' ? 'var(--severity-high)' : 'var(--severity-medium)'
            }}>
              {analysisResult ? activeSeverity.toUpperCase() : systemStats.threatLevel}
            </div>
          </div>
          <div className={`metric-icon-wrapper ${
            activeSeverity.toLowerCase() === 'critical' ? 'red' : 
            activeSeverity.toLowerCase() === 'high' ? 'purple' : 'green'
          }`}>
            <ShieldAlert size={24} />
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <h3>Ingested Sources</h3>
            <div className="metric-value">{analysisResult ? uploadedFiles.length || 4 : getLogCount()} / 5</div>
          </div>
          <div className="metric-icon-wrapper blue">
            <FileText size={24} />
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <h3>Investigated Cases</h3>
            <div className="metric-value">{systemStats.incidentsCount}</div>
          </div>
          <div className="metric-icon-wrapper purple">
            <Activity size={24} />
          </div>
        </div>

        <div className="metric-card glass-panel">
          <div className="metric-info">
            <h3>SOC Agent Status</h3>
            <div className="metric-value" style={{ color: analyzing ? 'var(--severity-high)' : 'var(--severity-info)' }}>
              {analyzing ? 'ANALYZING...' : 'COMMAND READY'}
            </div>
          </div>
          <div className="metric-icon-wrapper green">
            <Terminal size={24} style={analyzing ? { animation: 'spin 2s linear infinite' } : {}} />
          </div>
        </div>
      </div>

      {analysisResult ? (
        /* ==================== COMMAND CENTER DASHBOARD ==================== */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Active Incident Header */}
          <div className="glass-panel" style={{ padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div className="status-dot"></div>
              <div>
                <h2 style={{ fontSize: '1.2rem', fontWeight: '800', color: 'white' }}>
                  SOC Investigation Command Center
                </h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Active Investigation: <span style={{ color: 'white', fontWeight: '700' }}>{analysisResult.category || 'Correlated System Incident'}</span>
                </p>
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: '12px' }}>
              <div className="badge-tag" style={{ background: 'var(--severity-info-glow)', color: 'var(--severity-info)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <CheckCircle2 size={14} /> Investigation Complete
              </div>
              <button className="btn-secondary" onClick={handleResetInvestigation} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Trash2 size={14} /> Reset Console
              </button>
            </div>
          </div>

          {/* SOC KPI Cards */}
          <div className="soc-metrics-grid">
            <div className="soc-card glow-amber">
              <span className="soc-card-label">Incident Type</span>
              <span className="soc-card-val" style={{ fontSize: '0.95rem', wordBreak: 'break-word' }}>
                {analysisResult.category || 'Intrusion Attack'}
              </span>
            </div>

            <div className="soc-card">
              <span className="soc-card-label">Incident Severity</span>
              <span className={`severity-badge ${getSeverityBadgeClass(activeSeverity)}`}>
                {activeSeverity}
              </span>
            </div>

            <div className="soc-card">
              <span className="soc-card-label">Agent Confidence</span>
              <span className="soc-card-val" style={{ color: 'var(--color-primary)' }}>
                {confidencePercent}%
              </span>
            </div>

            <div className="soc-card">
              <span className="soc-card-label">Risk Rating Score</span>
              <span className="soc-card-val" style={{ color: activeSeverity.toLowerCase() === 'critical' ? 'var(--severity-critical)' : 'var(--severity-high)' }}>
                {activeRiskScore} / 10
              </span>
            </div>

            <div className="soc-card">
              <span className="soc-card-label">Forensic Vectors</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', fontSize: '0.75rem', marginTop: '4px' }}>
                <span className="badge-tag" title="Affected internal endpoints"><Server size={10} /> Hosts: {iocs.hosts.length}</span>
                <span className="badge-tag" title="Malicious external addresses"><AlertTriangle size={10} /> IPs: {iocs.ips.length}</span>
                <span className="badge-tag" title="MITRE techniques mapped"><Shield size={10} /> MITRE: {mitreCount}</span>
                <span className="badge-tag" title="Mitigation steps checklist"><CheckCircle2 size={10} /> Action Plan: {activeRemediations.length}</span>
              </div>
            </div>
          </div>

          {/* Main Dashboard Workspace Details */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '24px' }}>
            
            {/* Left Workspace Panel: AI Reasoning and IOCs */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              
              {/* AI Reasoning Chain */}
              <div className="glass-panel" style={{ padding: '24px' }}>
                <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
                  <Cpu size={18} color="var(--color-primary)" />
                  AI Investigation Reasoning Chain
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '24px' }}>
                  The agent synthesized multi-source log traces to trace step-by-step adversary actions:
                </p>

                <div className="reasoning-flow">
                  {reasoningChain.map((step, idx) => (
                    <div className="reasoning-step-item" key={idx}>
                      <div className="reasoning-circle active">
                        <span style={{ fontSize: '0.75rem', fontWeight: '700' }}>0{idx + 1}</span>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <h4 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'white' }}>{step.title}</h4>
                          <span className={`severity-badge ${getSeverityBadgeClass(step.severity)}`}>
                            {step.severity}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{step.desc}</p>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                          <Terminal size={10} /> {step.evidence}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* IOC Extraction Panel */}
              <div className="glass-panel" style={{ padding: '24px' }}>
                <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                  <AlertTriangle size={18} color="var(--severity-high)" />
                  Indicators of Compromise (IOC) Panel
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '20px' }}>
                  Extracted from file payloads, event signatures, and logs correlation filters:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                      Suspicious IPs
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {iocs.ips.map((ip, i) => (
                        <span key={i} className="ioc-chip-tag"><AlertTriangle size={10} color="var(--severity-critical)" /> {ip}</span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                      Affected Internal Hosts
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {iocs.hosts.map((host, i) => (
                        <span key={i} className="ioc-chip-tag"><Server size={10} color="var(--color-primary)" /> {host}</span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                      Impersonated Users
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {iocs.users.map((user, i) => (
                        <span key={i} className="ioc-chip-tag"><User size={10} color="var(--color-accent)" /> {user}</span>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                        Processes
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {iocs.processes.map((proc, i) => (
                          <span key={i} className="ioc-chip-tag" style={{ borderColor: 'var(--severity-high-glow)' }}><FileCode size={10} /> {proc}</span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                        Involved Files
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {iocs.files.map((file, i) => (
                          <span key={i} className="ioc-chip-tag" style={{ borderColor: 'var(--color-accent-glow)' }}><FileText size={10} /> {file}</span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {(iocs.domains.length > 0 || iocs.cloudKeys.length > 0) && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                      {iocs.domains.length > 0 && (
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                            External Destinations
                          </span>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {iocs.domains.map((dom, i) => (
                              <span key={i} className="ioc-chip-tag"><ExternalLink size={10} /> {dom}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      {iocs.cloudKeys.length > 0 && (
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', fontWeight: '700' }}>
                            Cloud Credentials / Keys
                          </span>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {iocs.cloudKeys.map((key, i) => (
                              <span key={i} className="ioc-chip-tag" style={{ color: 'var(--severity-medium)' }}><Plus size={10} /> {key}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                </div>
              </div>

            </div>

            {/* Right Workspace Panel: Risk Score Visual & Remediation */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              
              {/* Risk Score Visual */}
              <div className="glass-panel" style={{ padding: '24px' }}>
                <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                  <ShieldAlert size={18} color={getSeverityColor(activeSeverity)} />
                  Incident Risk Profile
                </h3>

                <div style={{ display: 'flex', alignItems: 'center', gap: '24px', margin: '20px 0' }}>
                  <div style={{ 
                    width: '90px', 
                    height: '90px', 
                    borderRadius: '50%', 
                    border: `4px solid ${getSeverityColor(activeSeverity)}`,
                    boxShadow: `0 0 20px ${getSeverityColor(activeSeverity)}33`,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'var(--bg-secondary)',
                    flexShrink: 0
                  }}>
                    <span style={{ fontSize: '1.75rem', fontWeight: '800', color: 'white' }}>{activeRiskScore}</span>
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Rating</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`severity-badge ${getSeverityBadgeClass(activeSeverity)}`}>{activeSeverity} Threat</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>SIEM Priority 1</span>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                      {activeSeverity.toLowerCase() === 'critical' 
                        ? 'Immediate containment actions required. Highly elevated risk score reflects successful credential dumping and data egress vectors.' 
                        : 'Active escalation protocols initiated. Risk score based on console authentication abnormalities and cloud resource manipulation.'}
                    </p>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Low</span>
                    <span style={{ color: 'var(--text-muted)' }}>Medium</span>
                    <span style={{ color: 'var(--text-muted)' }}>High</span>
                    <span style={{ color: 'var(--text-muted)' }}>Critical</span>
                  </div>
                  <div style={{ width: '100%', height: '8px', background: 'var(--bg-tertiary)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ 
                      width: `${(parseFloat(activeRiskScore) * 10)}%`, 
                      height: '100%', 
                      background: `linear-gradient(90deg, var(--severity-low) 0%, var(--severity-medium) 40%, var(--severity-high) 75%, var(--severity-critical) 100%)`, 
                      transition: 'width 1s ease-in-out' 
                    }}></div>
                  </div>
                </div>
              </div>

              {/* Actionable Remediation Checklist */}
              <div className="glass-panel" style={{ padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <h3 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: 0 }}>
                    <CheckCircle2 size={18} color="var(--severity-info)" />
                    Incident Containment Plan
                  </h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {activeRemediations.filter(r => r.checked).length} / {activeRemediations.length} Active
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '20px' }}>
                  Check off the containment and recovery steps as you perform remediation tasks:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {activeRemediations.map((action) => (
                    <div 
                      key={action.id} 
                      className="checklist-item" 
                      style={action.checked ? { borderColor: 'rgba(16, 185, 129, 0.2)', opacity: 0.65 } : {}}
                    >
                      <div className="checkbox-container" onClick={() => toggleRemediation(action.id)}>
                        <input 
                          type="checkbox" 
                          checked={action.checked || false} 
                          onChange={() => {}} 
                          style={{ cursor: 'pointer' }}
                        />
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1 }} onClick={() => toggleRemediation(action.id)}>
                        <span style={{ 
                          fontSize: '0.8rem', 
                          fontWeight: '700', 
                          color: action.checked ? 'var(--text-muted)' : 'white',
                          textDecoration: action.checked ? 'line-through' : 'none',
                          cursor: 'pointer'
                        }}>
                          {action.title}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                          {action.desc}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>

          </div>

        </div>
      ) : (
        /* ==================== WORKSPACE UPLOAD & SETUP STATE ==================== */
        <div className="dashboard-workspace">
          <div className="workspace-left">
            {/* Upload area */}
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h2 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <UploadCloud size={20} color="var(--color-primary)" />
                Ingest Target Security Logs
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '16px' }}>
                Upload raw logs from security sensors, Active Directory events, emails, cloud configurations, or firewalls.
              </p>
              
              <div 
                className={`upload-area ${dragActive ? 'dragging' : ''}`}
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
                onClick={() => document.getElementById('log-file-input').click()}
                style={{ padding: '36px 20px', minHeight: '160px' }}
              >
                <div className="upload-icon" style={{ color: 'var(--color-primary)' }}>
                  <UploadCloud size={32} />
                </div>
                <div className="upload-title" style={{ fontSize: '0.9rem', fontWeight: '700' }}>Drag & Drop Log Files Here</div>
                <div className="upload-desc" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '380px' }}>
                  Supports firewall logs (.log), event viewer exports (.csv/.txt), suspicious email files, cloud trail records, or network summaries.
                </div>
                <input 
                  id="log-file-input"
                  type="file" 
                  multiple 
                  style={{ display: 'none' }} 
                  onChange={handleFileChange}
                />
              </div>

              {/* Supported Badge Indicators */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '16px', justifyContent: 'center' }}>
                <span className="type-tag" style={logs.firewall ? { borderColor: 'var(--severity-info)', color: 'white', background: 'var(--severity-info-glow)' } : {}}>
                  Firewall Logs {logs.firewall && '✓'}
                </span>
                <span className="type-tag" style={logs.eventLogs ? { borderColor: 'var(--severity-info)', color: 'white', background: 'var(--severity-info-glow)' } : {}}>
                  Windows Event Logs {logs.eventLogs && '✓'}
                </span>
                <span className="type-tag" style={logs.cloudLogs ? { borderColor: 'var(--severity-info)', color: 'white', background: 'var(--severity-info-glow)' } : {}}>
                  Cloud Logs {logs.cloudLogs && '✓'}
                </span>
                <span className="type-tag" style={logs.email ? { borderColor: 'var(--severity-info)', color: 'white', background: 'var(--severity-info-glow)' } : {}}>
                  Suspicious Email {logs.email && '✓'}
                </span>
                <span className="type-tag" style={logs.networkSummary ? { borderColor: 'var(--severity-info)', color: 'white', background: 'var(--severity-info-glow)' } : {}}>
                  Network Traffic {logs.networkSummary && '✓'}
                </span>
              </div>

              {/* File list presentation */}
              {uploadedFiles.length > 0 && (
                <div className="uploaded-chips-list">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'var(--text-primary)', borderBottom: '1px solid var(--card-border)', paddingBottom: '6px' }}>
                    <span style={{ fontWeight: '700' }}>Loaded Sources ({uploadedFiles.length})</span>
                    <span style={{ color: 'var(--text-muted)' }}>Files ready for correlation</span>
                  </div>
                  {uploadedFiles.map((file) => (
                    <div className="file-chip" key={file.key}>
                      <div className="file-chip-info">
                        <FileText size={16} color="var(--color-primary)" />
                        <div>
                          <div className="file-chip-title">{file.name}</div>
                          <div className="file-chip-meta">
                            {file.size} | <span style={{ color: 'var(--color-accent)' }}>{file.type}</span>
                          </div>
                        </div>
                      </div>
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          removeFile(file.key);
                        }} 
                        style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                        title="Remove file"
                      >
                        <Trash2 size={14} className="hover:text-red-400" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Investigation Trigger Button */}
              <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--card-border)', paddingTop: '16px' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {getLogCount() > 0 
                    ? `Configured ${getLogCount()} source log scopes.` 
                    : "Upload evidence or launch a preset scenario to begin investigation."
                  }
                </div>
                <button 
                  className="btn-submit"
                  onClick={onStartAnalysis}
                  disabled={analyzing || getLogCount() === 0}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '180px', justifyContent: 'center' }}
                >
                  {analyzing ? (
                    <>
                      <Terminal size={14} style={{ animation: 'spin 1.5s linear infinite' }} />
                      <span>SOC Agent Investigating Evidence...</span>
                    </>
                  ) : (
                    <>
                      <Play size={14} />
                      <span>Investigate Incident</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Incident Sandbox Presets */}
            <div className="glass-panel scenarios-container" style={{ padding: '24px' }}>
              <div className="scenarios-header" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <ShieldAlert size={20} color="var(--color-accent)" />
                <h2 className="panel-title" style={{ marginBottom: 0 }}>Incident Sandbox Presets</h2>
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '16px' }}>
                Select a preset cyber threat scenario to load realistic log data into the ingestion panels:
              </p>
              <div className="scenarios-grid">
                {presetScenarios.map((scenario) => (
                  <div 
                    key={scenario.id}
                    className="scenario-card glass-panel"
                    style={selectedPreset === scenario.id ? { borderColor: 'var(--color-accent)', boxShadow: '0 0 15px var(--color-accent-glow)' } : {}}
                    onClick={() => loadPreset(scenario)}
                  >
                    <div className="scenario-card-header">
                      <span className="scenario-title" style={{ fontWeight: '700' }}>{scenario.title}</span>
                      <span className={`scenario-difficulty difficulty-${scenario.difficulty.toLowerCase()}`}>
                        {scenario.difficulty}
                      </span>
                    </div>
                    <p className="scenario-desc" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{scenario.desc}</p>
                    <div className="scenario-meta" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px' }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{scenario.category}</span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--color-accent)', fontWeight: '600' }}>Use Demo Incident</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Sidebar Alerts Feed */}
          <div className="workspace-right">
            <div className="glass-panel recent-alerts" style={{ padding: '24px' }}>
              <h2 className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={18} color="var(--severity-critical)" />
                Real-time Ingress Alerts Feed
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                Click on any system alert to inspect localized trace logs:
              </p>
              
              <div className="alert-list" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {recentAlertsData.map((alert) => (
                  <div 
                    key={alert.id}
                    className={`alert-item clickable-alert-card ${alert.severity}`}
                    onClick={() => setActiveAlertDetails(activeAlertDetails?.id === alert.id ? null : alert)}
                    style={{ padding: '12px', background: activeAlertDetails?.id === alert.id ? 'rgba(255,255,255,0.03)' : 'rgba(12,17,34,0.3)' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                      <span className={`severity-badge ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className="alert-time" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{alert.time}</span>
                    </div>
                    <div className="alert-headline" style={{ fontWeight: '700', fontSize: '0.8rem', color: 'white', lineHeight: '1.3' }}>
                      {alert.title}
                    </div>
                    <div className="alert-details" style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', margin: '4px 0' }}>
                      Asset: <span style={{ color: 'white' }}>{alert.asset}</span> | Source: {alert.source}
                    </div>
                    
                    {activeAlertDetails?.id === alert.id && (
                      <div style={{ 
                        marginTop: '10px', 
                        padding: '8px', 
                        background: 'rgba(0,0,0,0.4)', 
                        borderRadius: '6px', 
                        border: '1px dashed var(--card-border)',
                        fontSize: '0.75rem',
                        color: 'var(--text-primary)',
                        fontFamily: 'var(--font-mono)',
                        lineHeight: '1.4'
                      }}>
                        <strong style={{ color: 'var(--severity-high)' }}>Sensor Telemetry:</strong>
                        <p style={{ marginTop: '4px' }}>{alert.evidence}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

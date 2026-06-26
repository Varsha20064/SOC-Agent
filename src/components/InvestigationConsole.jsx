import React, { useEffect, useState, useRef } from 'react';
import { Terminal, Shield, Cpu, RefreshCw, Layers } from 'lucide-react';

const investigationSteps = [
  { type: 'info', text: 'Initializing SOC Agent Cyber Investigation Engine...' },
  { type: 'info', text: 'Ingesting active raw logs (Firewall, Host EventLogs, Emails, Cloud Trails)...' },
  { type: 'success', text: 'Log ingestion complete. Found correlated IP hashes and event counts.' },
  { type: 'system', text: 'Phase 1: Heuristic log parsing and entity extraction active.' },
  { type: 'warning', text: 'Searching log traces for indicators of compromise (IOCs)...' },
  { type: 'success', text: 'Extracted key nodes: Attacker Source IP, compromised local gateway, database targets.' },
  { type: 'system', text: 'Phase 2: Alert grouping and attack progression correlation.' },
  { type: 'info', text: 'Correlating event IDs (4688: Process Creation, 4624: Logons, 4728: Group Modification)...' },
  { type: 'warning', text: 'Matching timestamp delta patterns to identify lateral traversal vectors...' },
  { type: 'success', text: 'Incident correlation matched. Identified unified attack flow.' },
  { type: 'system', text: 'Phase 3: MITRE ATT&CK Matrix mapping routine.' },
  { type: 'info', text: 'Querying internal tactics knowledge base for matched execution commands...' },
  { type: 'success', text: 'Mapped techniques: Inhibit System Recovery, PowerShell Script execution, Spearphishing.' },
  { type: 'system', text: 'Phase 4: Remediation generation and Executive Report compilation.' },
  { type: 'success', text: 'Remediation list compiled. Severity rating calculated based on threat velocity.' },
  { type: 'info', text: 'Finalizing investigation package. Transferring report metrics...' },
  { type: 'success', text: 'SOC Agent Investigation complete. View report dashboard tabs.' }
];

export default function InvestigationConsole({ onCompleteAnalysis }) {
  const [consoleLines, setConsoleLines] = useState([]);
  const [stepIndex, setStepIndex] = useState(0);
  const [percentProgress, setPercentProgress] = useState(0);
  const terminalEndRef = useRef(null);

  useEffect(() => {
    if (stepIndex < investigationSteps.length) {
      const timer = setTimeout(() => {
        setConsoleLines(prev => [...prev, {
          ...investigationSteps[stepIndex],
          timestamp: new Date().toLocaleTimeString()
        }]);
        setStepIndex(prev => prev + 1);
        setPercentProgress(Math.floor(((stepIndex + 1) / investigationSteps.length) * 100));
      }, 700); // 700ms typing out simulation speed

      return () => clearTimeout(timer);
    } else {
      // Completed terminal print out
      const completeTimer = setTimeout(() => {
        onCompleteAnalysis();
      }, 800);
      return () => clearTimeout(completeTimer);
    }
  }, [stepIndex, onCompleteAnalysis]);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLines]);

  const getLineClass = (type) => {
    switch (type) {
      case 'success': return 'line-success';
      case 'warning': return 'line-warning';
      case 'error': return 'line-error';
      case 'system': return 'line-system';
      default: return 'line-info';
    }
  };

  return (
    <div className="investigation-console glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Cpu size={24} className="logo-icon" style={{ animation: 'spin 4s linear infinite' }} />
          <div>
            <h2 className="panel-title" style={{ marginBottom: '2px' }}>SOC Analyst Active Investigation</h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>AI Agent reasoning through log correlation...</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '0.9rem', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>
            {percentProgress}%
          </span>
          <div style={{ width: '120px', height: '6px', background: 'var(--bg-tertiary)', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: `${percentProgress}%`, height: '100%', background: 'var(--color-primary)', transition: 'width 0.2s ease' }}></div>
          </div>
        </div>
      </div>

      <div className="terminal-card">
        <div className="terminal-header">
          <div className="terminal-buttons">
            <span className="terminal-btn btn-close"></span>
            <span className="terminal-btn btn-minimize"></span>
            <span className="terminal-btn btn-expand"></span>
          </div>
          <span className="terminal-title">soc_agent@intel-engine:~</span>
          <Terminal size={14} color="var(--text-muted)" />
        </div>
        <div className="terminal-body">
          {consoleLines.map((line, idx) => (
            <div key={idx} className={`terminal-line ${getLineClass(line.type)}`}>
              <span style={{ color: 'var(--text-muted)', marginRight: '8px' }}>[{line.timestamp}]</span>
              <span className="terminal-prompt"></span>
              {line.text}
            </div>
          ))}
          {stepIndex < investigationSteps.length && (
            <div className="terminal-line">
              <span style={{ color: 'var(--text-muted)', marginRight: '8px' }}>
                [{new Date().toLocaleTimeString()}]
              </span>
              <span className="terminal-prompt"></span>
              <span className="cursor"></span>
            </div>
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginTop: '24px' }}>
        <div className="glass-panel" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', borderColor: percentProgress >= 15 ? 'var(--color-primary)' : 'var(--card-border)' }}>
          <Layers size={18} color={percentProgress >= 15 ? 'var(--color-primary)' : 'var(--text-muted)'} />
          <div style={{ fontSize: '0.8rem' }}>
            <div style={{ fontWeight: '700' }}>1. Parse Logs</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
              {percentProgress < 15 ? 'Waiting...' : percentProgress < 35 ? 'Processing...' : 'Completed'}
            </div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', borderColor: percentProgress >= 35 ? 'var(--color-accent)' : 'var(--card-border)' }}>
          <Shield size={18} color={percentProgress >= 35 ? 'var(--color-accent)' : 'var(--text-muted)'} />
          <div style={{ fontSize: '0.8rem' }}>
            <div style={{ fontWeight: '700' }}>2. Corelate Incidents</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
              {percentProgress < 35 ? 'Waiting...' : percentProgress < 65 ? 'Processing...' : 'Completed'}
            </div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', borderColor: percentProgress >= 65 ? 'var(--severity-high)' : 'var(--card-border)' }}>
          <Terminal size={18} color={percentProgress >= 65 ? 'var(--severity-high)' : 'var(--text-muted)'} />
          <div style={{ fontSize: '0.8rem' }}>
            <div style={{ fontWeight: '700' }}>3. MITRE Map</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
              {percentProgress < 65 ? 'Waiting...' : percentProgress < 85 ? 'Processing...' : 'Completed'}
            </div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px', borderColor: percentProgress >= 85 ? 'var(--severity-info)' : 'var(--card-border)' }}>
          <RefreshCw size={18} color={percentProgress >= 85 ? 'var(--severity-info)' : 'var(--text-muted)'} />
          <div style={{ fontSize: '0.8rem' }}>
            <div style={{ fontWeight: '700' }}>4. Report Compile</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
              {percentProgress < 85 ? 'Waiting...' : percentProgress < 100 ? 'Processing...' : 'Completed'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

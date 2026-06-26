import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Clock, 
  Network, 
  ShieldCheck, 
  FileText, 
  Settings as SettingsIcon, 
  HelpCircle,
  Activity,
  Cpu
} from 'lucide-react';

import Dashboard from './components/Dashboard';
import InvestigationConsole from './components/InvestigationConsole';
import AttackTimeline from './components/AttackTimeline';
import NetworkMap from './components/NetworkMap';
import MitreMapping from './components/MitreMapping';
import ExecutiveReport from './components/ExecutiveReport';
import Settings from './components/Settings';

import { analyzeLogsWithGemini } from './utils/geminiAnalyzer';
import { presetScenarios } from './utils/incidentSimulator';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [logs, setLogs] = useState({
    email: '',
    eventLogs: '',
    firewall: '',
    cloudLogs: '',
    networkSummary: ''
  });
  const [apiKey, setApiKey] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [showConsole, setShowConsole] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  
  const [systemStats, setSystemStats] = useState({
    threatLevel: 'SAFE',
    incidentsCount: 42
  });

  // Load API Key from LocalStorage on mount
  useEffect(() => {
    const savedKey = localStorage.getItem('GEMINI_SOC_API_KEY');
    if (savedKey) {
      setApiKey(savedKey);
    }
  }, []);

  const handleStartAnalysis = async () => {
    setAnalyzing(true);
    setShowConsole(true);
    setActiveTab('console');

    // Run the AI log analysis in background while console types out steps
    try {
      // Find matching preset scenario if it matches exactly
      let matchedResult = null;
      
      const isPreset = presetScenarios.find(preset => {
        return (
          preset.logs.email === logs.email &&
          preset.logs.eventLogs === logs.eventLogs &&
          preset.logs.firewall === logs.firewall &&
          preset.logs.networkSummary === logs.networkSummary
        );
      });

      if (isPreset && !apiKey) {
        // Direct simulation bypass for presets when offline
        matchedResult = isPreset.analysis;
      } else {
        // Run either heuristic or live API
        matchedResult = await analyzeLogsWithGemini(logs, apiKey);
      }

      setAnalysisResult(matchedResult);
    } catch (err) {
      console.error(err);
    }
  };

  const handleConsoleComplete = () => {
    setAnalyzing(false);
    setShowConsole(false);
    
    // Update dashboard statistics
    if (analysisResult) {
      setSystemStats(prev => ({
        threatLevel: (analysisResult.severity || 'HIGH').toUpperCase(),
        incidentsCount: prev.incidentsCount + 1
      }));
      // Automatically switch to the attack timeline view
      setActiveTab('timeline');
    } else {
      setActiveTab('dashboard');
    }
  };

  const getPageTitleInfo = () => {
    switch (activeTab) {
      case 'console': return { title: 'Investigation Terminal', desc: 'AI Agent is actively investigating ingested system traces' };
      case 'timeline': return { title: 'Attack Timeline', desc: 'Chronological reconstruction of identified intrusion tactics' };
      case 'network': return { title: 'Network Pathway', desc: 'Visualization of compromised nodes and active C2 beacon pathways' };
      case 'mitre': return { title: 'MITRE ATT&CK Matrix', desc: 'Classification of threat patterns against cybersecurity tactics standards' };
      case 'report': return { title: 'Executive SIEM Report', desc: 'Printable executive summary and remediation checklist' };
      case 'settings': return { title: 'System Settings', desc: 'Configure analysis engine and credential properties' };
      default: return { title: 'AI SOC Incident Console', desc: 'Correlate logs, map threats to MITRE ATT&CK, and generate responses' };
    }
  };

  const pageMeta = getPageTitleInfo();

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-container">
          <Cpu className="logo-icon" size={24} />
          <span className="logo-text">SOC Agent</span>
          <span className="logo-badge">v1.2</span>
        </div>

        <nav>
          <ul className="nav-links">
            <li 
              className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActiveTab('dashboard')}
            >
              <Activity size={18} />
              <span>Incident Center</span>
            </li>
            
            {showConsole && (
              <li 
                className={`nav-item ${activeTab === 'console' ? 'active' : ''}`}
                onClick={() => setActiveTab('console')}
              >
                <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
                <span>Active Scanner</span>
              </li>
            )}

            <li 
              className={`nav-item ${activeTab === 'timeline' ? 'active' : ''} ${!analysisResult ? 'disabled-nav' : ''}`}
              onClick={() => analysisResult && setActiveTab('timeline')}
              style={!analysisResult ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
            >
              <Clock size={18} />
              <span>Attack Timeline</span>
            </li>

            <li 
              className={`nav-item ${activeTab === 'network' ? 'active' : ''} ${!analysisResult ? 'disabled-nav' : ''}`}
              onClick={() => analysisResult && setActiveTab('network')}
              style={!analysisResult ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
            >
              <Network size={18} />
              <span>Attack Map</span>
            </li>

            <li 
              className={`nav-item ${activeTab === 'mitre' ? 'active' : ''} ${!analysisResult ? 'disabled-nav' : ''}`}
              onClick={() => analysisResult && setActiveTab('mitre')}
              style={!analysisResult ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
            >
              <ShieldCheck size={18} />
              <span>MITRE Matrix</span>
            </li>

            <li 
              className={`nav-item ${activeTab === 'report' ? 'active' : ''} ${!analysisResult ? 'disabled-nav' : ''}`}
              onClick={() => analysisResult && setActiveTab('report')}
              style={!analysisResult ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
            >
              <FileText size={18} />
              <span>Executive Report</span>
            </li>

            <li 
              className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`}
              onClick={() => setActiveTab('settings')}
            >
              <SettingsIcon size={18} />
              <span>Settings</span>
            </li>
          </ul>
        </nav>

        <div className="sidebar-footer">
          <div className="system-status">
            <span className="status-dot"></span>
            <span>SIEM Connector Live</span>
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
            System local time:<br />
            {new Date().toLocaleDateString()}
          </div>
        </div>
      </aside>

      {/* Main Workspace Area */}
      <main className="main-content">
        <header className="page-header">
          <div className="page-title">
            <h1>{pageMeta.title}</h1>
            <p>{pageMeta.desc}</p>
          </div>
        </header>

        {/* Tab content router */}
        {activeTab === 'dashboard' && (
          <Dashboard 
            logs={logs}
            setLogs={setLogs}
            onStartAnalysis={handleStartAnalysis}
            analyzing={analyzing}
            systemStats={systemStats}
            analysisResult={analysisResult}
            setAnalysisResult={setAnalysisResult}
          />
        )}

        {activeTab === 'console' && (
          <InvestigationConsole 
            onCompleteAnalysis={handleConsoleComplete}
          />
        )}

        {activeTab === 'timeline' && (
          <AttackTimeline result={analysisResult} />
        )}

        {activeTab === 'network' && (
          <NetworkMap network={analysisResult?.network} />
        )}

        {activeTab === 'mitre' && (
          <MitreMapping mitre={analysisResult?.mitre} />
        )}

        {activeTab === 'report' && (
          <ExecutiveReport result={analysisResult} />
        )}

        {activeTab === 'settings' && (
          <Settings 
            apiKey={apiKey} 
            setApiKey={setApiKey} 
          />
        )}
      </main>
    </div>
  );
}

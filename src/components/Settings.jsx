import React, { useState } from 'react';
import { Settings as SettingsIcon, Key, Info, CheckCircle2, ShieldAlert } from 'lucide-react';

export default function Settings({ apiKey, setApiKey }) {
  const [inputKey, setInputKey] = useState(apiKey || '');
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    localStorage.setItem('GEMINI_SOC_API_KEY', inputKey.trim());
    setApiKey(inputKey.trim());
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleClear = () => {
    localStorage.removeItem('GEMINI_SOC_API_KEY');
    setInputKey('');
    setApiKey('');
  };

  return (
    <div className="glass-panel settings-card">
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
        <SettingsIcon size={24} color="var(--color-primary)" />
        <h2 className="panel-title" style={{ marginBottom: 0 }}>SOC Agent Settings</h2>
      </div>

      <div className="glass-panel" style={{ padding: '16px', background: 'var(--bg-tertiary)', borderLeft: '4px solid var(--color-primary)', marginBottom: '24px' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
          <Info size={16} color="var(--color-primary)" style={{ marginTop: '2px', flexShrink: 0 }} />
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
            <strong>Analysis Mode:</strong> By default, if no key is saved, the application executes simulated/heuristic analysis using the Sandbox incident datasets.
            Providing a Gemini Developer Key enables **real-time AI reasoning** on custom-uploaded files!
          </div>
        </div>
      </div>

      <form onSubmit={handleSave}>
        <div className="form-group">
          <label className="form-label" htmlFor="api-key-input">
            <Key size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '6px' }} />
            Gemini Developer API Key
          </label>
          <input 
            id="api-key-input"
            type="password"
            className="form-input"
            value={inputKey}
            onChange={(e) => setInputKey(e.target.value)}
            placeholder="AIzaSy..."
          />
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Retrieve your API key from the Google AI Studio console.
          </span>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button type="submit" className="btn-submit">
            {saved ? <CheckCircle2 size={16} /> : <Key size={16} />}
            {saved ? 'Saved Successfully!' : 'Save API Key'}
          </button>
          {apiKey && (
            <button type="button" className="btn-secondary" onClick={handleClear}>
              Clear Key
            </button>
          )}
        </div>
      </form>

      <div style={{ marginTop: '40px', borderTop: '1px solid var(--card-border)', paddingTop: '24px' }}>
        <h3 style={{ fontSize: '0.9rem', fontWeight: '700', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={16} color="var(--severity-high)" /> Security Notice
        </h3>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
          Your API Key is kept entirely inside your browser's local sandbox state (`localStorage`).
          All requests to the Google Gemini models are initiated client-side directly from your browser.
          No intermediate backend logs or stores your credentials.
        </p>
      </div>
    </div>
  );
}

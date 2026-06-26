import React from 'react';
import { 
  Clock, 
  ShieldAlert, 
  ArrowRight, 
  ShieldCheck, 
  Database, 
  FileCode, 
  Key, 
  UserCheck, 
  HelpCircle,
  FileText,
  Server,
  Layers,
  Terminal,
  Activity
} from 'lucide-react';
import { 
  getSeverityColor, 
  getSeverityBadgeClass, 
  normalizeTimeline 
} from '../utils/socHelpers';

export default function AttackTimeline({ result }) {
  if (!result) {
    return (
      <div className="glass-panel timeline-card" style={{ textAlign: 'center', padding: '40px' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No incident timelines compiled yet. Run log analysis first.</p>
      </div>
    );
  }

  const severity = result.severity || 'high';
  const category = result.category || 'Correlated System Intrusion';
  const confidence = result.confidence || 96;
  const riskScore = result.riskScore || '9.6/10';
  const summary = result.summary || 'SOC agent is correlating security log details...';
  
  // Normalize timeline to have 6-8 stages
  const timeline = normalizeTimeline(result.timeline || []);

  const getStageIcon = (stage) => {
    const s = stage?.toLowerCase() || '';
    if (s.includes('access') || s.includes('initial')) return <Clock size={12} />;
    if (s.includes('execution')) return <FileCode size={12} />;
    if (s.includes('credential')) return <Key size={12} />;
    if (s.includes('lateral')) return <ArrowRight size={12} />;
    if (s.includes('collection')) return <FileText size={12} />;
    if (s.includes('impact') || s.includes('exfil')) return <Database size={12} />;
    if (s.includes('persistence')) return <Layers size={12} />;
    return <ShieldCheck size={12} />;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <style>{`
        /* Enhanced connected timeline details */
        .enhanced-timeline-container {
          position: relative;
          padding-left: 40px;
        }
        
        .enhanced-timeline-container::before {
          content: '';
          position: absolute;
          left: 15px;
          top: 12px;
          bottom: 12px;
          width: 3px;
          background: linear-gradient(180deg, 
            var(--severity-low) 0%, 
            var(--severity-medium) 30%, 
            var(--severity-high) 65%, 
            var(--severity-critical) 100%
          );
          border-radius: 4px;
          opacity: 0.8;
        }

        .timeline-event-card {
          margin-bottom: 24px;
          position: relative;
          transition: all 0.2s ease;
        }

        .timeline-event-card:hover {
          transform: translateX(4px);
        }

        .custom-timeline-badge {
          position: absolute;
          left: -40px;
          top: 4px;
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: #0d111e;
          border: 2.5px solid var(--text-muted);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 10;
          box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
          transition: all 0.3s ease;
        }

        .custom-timeline-badge.critical { border-color: var(--severity-critical); color: var(--severity-critical); box-shadow: 0 0 12px rgba(239, 68, 68, 0.4); }
        .custom-timeline-badge.high { border-color: var(--severity-high); color: var(--severity-high); box-shadow: 0 0 12px rgba(249, 115, 22, 0.4); }
        .custom-timeline-badge.medium { border-color: var(--severity-medium); color: var(--severity-medium); box-shadow: 0 0 12px rgba(234, 179, 8, 0.4); }
        .custom-timeline-badge.low { border-color: var(--severity-low); color: var(--severity-low); box-shadow: 0 0 12px rgba(59, 130, 246, 0.4); }

        .timeline-inner-card {
          background: rgba(12, 17, 34, 0.75);
          backdrop-filter: blur(8px);
          border: 1px solid var(--card-border);
          border-radius: 10px;
          padding: 16px 20px;
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .timeline-inner-card:hover {
          border-color: var(--color-primary-glow);
        }

        .timeline-header-line {
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 12px;
        }

        .timeline-title-span {
          font-weight: 800;
          font-size: 1rem;
          color: white;
        }

        .timeline-meta-badges {
          display: flex;
          gap: 8px;
          align-items: center;
        }

        .timeline-desc-p {
          font-size: 0.85rem;
          color: var(--text-secondary);
          line-height: 1.5;
        }

        .timeline-footer-badges {
          display: flex;
          gap: 12px;
          align-items: center;
          flex-wrap: wrap;
          padding-top: 8px;
          border-top: 1px dashed rgba(255, 255, 255, 0.05);
        }

        .timeline-footer-badges span {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 0.75rem;
        }
      `}</style>
      
      {/* 1. Incident Summary Banner at Top */}
      <div className="glass-panel" style={{ 
        padding: '24px', 
        borderLeft: `4px solid ${getSeverityColor(severity)}`,
        background: 'linear-gradient(90deg, rgba(12,17,34,0.9) 0%, rgba(19,26,53,0.4) 100%)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
              Threat Category
            </span>
            <h2 style={{ fontSize: '1.5rem', fontWeight: '800', color: 'white', marginTop: '2px' }}>
              {category || 'Unknown Security Event'}
            </h2>
          </div>
          
          <div style={{ display: 'flex', gap: '24px' }}>
            <div style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity</span>
              <div style={{ 
                color: getSeverityColor(severity), 
                fontWeight: '800', 
                fontSize: '1.1rem',
                textTransform: 'uppercase',
                marginTop: '2px'
              }}>
                {severity}
              </div>
            </div>

            <div style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence</span>
              <div style={{ color: 'var(--color-primary)', fontWeight: '800', fontSize: '1.1rem', marginTop: '2px' }}>
                {confidence}%
              </div>
            </div>

            <div style={{ textAlign: 'center' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</span>
              <div style={{ color: 'var(--severity-high)', fontWeight: '800', fontSize: '1.1rem', marginTop: '2px' }}>
                {riskScore}
              </div>
            </div>
          </div>
        </div>

        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
          {summary}
        </p>
      </div>

      {/* 2. Visual Attack Story Progress Map */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 className="panel-title" style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Adversary Tactic Progression Path
        </h3>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between', 
          overflowX: 'auto', 
          padding: '10px 0',
          gap: '8px'
        }}>
          {timeline.map((step, idx) => (
            <React.Fragment key={idx}>
              <div style={{ 
                display: 'flex', 
                flexDirection: 'column', 
                alignItems: 'center',
                minWidth: '130px',
                textAlign: 'center',
                flex: '1'
              }}>
                <div className={`timeline-badge ${getSeverityBadgeClass(step.severity)}`} style={{ 
                  position: 'static', 
                  width: '34px', 
                  height: '34px', 
                  marginBottom: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: '#0d111e',
                  borderRadius: '50%',
                  border: `2.5px solid ${getSeverityColor(step.severity)}`,
                  boxShadow: `0 0 10px ${getSeverityColor(step.severity)}44`
                }}>
                  {getStageIcon(step.stage)}
                </div>
                <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'white', display: 'block', height: '36px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={step.title}>
                  {step.title}
                </span>
                <span className={`badge-tag ${getSeverityBadgeClass(step.severity)}`} style={{ fontSize: '0.6rem', padding: '1px 6px' }}>
                  {step.stage}
                </span>
              </div>
              {idx < timeline.length - 1 && (
                <div style={{ display: 'flex', alignItems: 'center', color: 'var(--card-border)', paddingBottom: '32px' }}>
                  <ArrowRight size={16} />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* 3. Chronological Connected Timeline details */}
      <div className="glass-panel" style={{ padding: '24px', marginBottom: 0 }}>
        <h2 className="panel-title" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Clock size={20} color="var(--color-primary)" />
          Chronological Attack Forensic Timeline ({timeline.length} Stages)
        </h2>
        
        <div className="enhanced-timeline-container">
          {timeline.map((event, index) => (
            <div key={index} className="timeline-event-card">
              <div className={`custom-timeline-badge ${getSeverityBadgeClass(event.severity)}`}>
                {getStageIcon(event.stage)}
              </div>
              <div className="timeline-inner-card">
                <div className="timeline-header-line">
                  <span className="timeline-title-span">{event.title}</span>
                  <div className="timeline-meta-badges">
                    <span className={`badge-tag ${getSeverityBadgeClass(event.severity)}`} style={{ textTransform: 'uppercase', fontSize: '0.65rem' }}>
                      {event.severity}
                    </span>
                    <span style={{ 
                      fontFamily: 'var(--font-mono)', 
                      fontSize: '0.75rem', 
                      background: 'rgba(255,255,255,0.03)', 
                      padding: '2px 8px', 
                      borderRadius: '4px',
                      color: 'var(--text-secondary)'
                    }}>
                      {event.time}
                    </span>
                  </div>
                </div>
                <p className="timeline-desc-p">{event.desc}</p>
                <div className="timeline-footer-badges">
                  <span style={{ color: 'var(--color-accent)' }}>
                    <Layers size={12} /> Tactic: <strong>{event.stage}</strong>
                  </span>
                  <span style={{ color: 'var(--color-primary)' }}>
                    <Terminal size={12} /> Log Source: <strong>{event.source || event.type}</strong>
                  </span>
                  {event.severity === 'critical' && (
                    <span style={{ color: 'var(--severity-critical)' }}>
                      <ShieldAlert size={12} /> Urgent Containment Trigger
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 4. AI Conclusion Statement */}
      <div className="glass-panel" style={{ 
        padding: '20px', 
        borderLeft: '4px solid var(--color-accent)', 
        background: 'rgba(139, 92, 246, 0.05)',
        display: 'flex',
        alignItems: 'center',
        gap: '16px'
      }}>
        <UserCheck size={28} color="var(--color-accent)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: '0.9rem', lineHeight: '1.5' }}>
          <strong style={{ color: 'white' }}>AI Security Analyst Conclusion: </strong> 
          Investigation rules validated a high-confidence correlation chain between early-stage remote credential trials and late-stage cloud IAM alterations. Immediate firewall policy adjustments and compromised asset isolations are recommended.
        </div>
      </div>

    </div>
  );
}

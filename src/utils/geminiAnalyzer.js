// Gemini API integration for live log file analysis
import { parseCustomLogs } from './incidentSimulator';

export async function analyzeLogsWithGemini(logs, apiKey) {
  if (!apiKey) {
    // Fallback to local heuristic simulator
    return parseCustomLogs(logs);
  }

  const logContextText = `
Below are security logs uploaded for investigation. Perform a thorough cyber incident investigation like an expert security analyst.

--- FIREWALL LOGS ---
${logs.firewall || 'None'}

--- WINDOWS EVENT LOGS ---
${logs.eventLogs || 'None'}

--- CLOUD LOGS ---
${logs.cloudLogs || 'None'}

--- SUSPICIOUS EMAIL ---
${logs.email || 'None'}

--- NETWORK TRAFFIC SUMMARY ---
${logs.networkSummary || 'None'}
`;

  try {
    const model = 'gemini-1.5-flash'; // High compatibility model
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    const responseSchema = {
      type: "OBJECT",
      properties: {
        summary: { type: "STRING", description: "A detailed summary of the incident explaining how it started, what the attacker did, and the impact." },
        severity: { type: "STRING", enum: ["Critical", "High", "Medium", "Low"], description: "Overall incident severity classification." },
        category: { type: "STRING", description: "Incident classification category (e.g. Ransomware, Exfiltration, Credential Access)." },
        mitre: {
          type: "ARRAY",
          description: "Mapped MITRE ATT&CK techniques.",
          items: {
            type: "OBJECT",
            properties: {
              tactic: { type: "STRING", description: "Tactic name (e.g., Execution, Command and Control)." },
              technique: { type: "STRING", description: "Technique name." },
              id: { type: "STRING", description: "MITRE Technique ID (e.g., T1059.001)." }
            },
            required: ["tactic", "technique", "id"]
          }
        },
        timeline: {
          type: "ARRAY",
          description: "Step-by-step incident events ordered chronologically.",
          items: {
            type: "OBJECT",
            properties: {
              time: { type: "STRING", description: "Timestamp of the event (use HH:MM:SS format)." },
              stage: { type: "STRING", description: "MITRE ATT&CK Phase." },
              title: { type: "STRING", description: "Brief title of the event." },
              desc: { type: "STRING", description: "Detailed description of what occurred." },
              severity: { type: "STRING", enum: ["critical", "high", "medium", "low"] },
              type: { type: "STRING", description: "Log source where this event was detected (e.g., Windows Event Log, Firewall)." }
            },
            required: ["time", "stage", "title", "desc", "severity", "type"]
          }
        },
        network: {
          type: "OBJECT",
          description: "Coordinates for drawing the visual attack pathway map.",
          properties: {
            nodes: {
              type: "ARRAY",
              items: {
                type: "OBJECT",
                properties: {
                  id: { type: "STRING", description: "Unique node ID (e.g. attacker, endpoint_pc, cloud_server)." },
                  name: { type: "STRING", description: "Friendly name (e.g. Malicious C2, Host PC, AWS Cloud)." },
                  ip: { type: "STRING", description: "IP Address or service name." },
                  type: { type: "STRING", enum: ["attacker", "compromised", "target"] },
                  x: { type: "NUMBER", description: "Coordinate X for node positioning (typically 100 to 700)." },
                  y: { type: "NUMBER", description: "Coordinate Y for node positioning (typically 100 to 300)." }
                },
                required: ["id", "name", "ip", "type", "x", "y"]
              }
            },
            links: {
              type: "ARRAY",
              items: {
                type: "OBJECT",
                properties: {
                  from: { type: "STRING", description: "ID of source node." },
                  to: { type: "STRING", description: "ID of target node." },
                  label: { type: "STRING", description: "Description of relation (e.g. SQL Injection, SMB Lateral)." }
                },
                required: ["from", "to", "label"]
              }
            }
          },
          required: ["nodes", "links"]
        },
        remediations: {
          type: "ARRAY",
          description: "Actionable cybersecurity checklist recommendations.",
          items: {
            type: "OBJECT",
            properties: {
              title: { type: "STRING", description: "Short remediation action name." },
              desc: { type: "STRING", description: "Actionable details on how to accomplish it." }
            },
            required: ["title", "desc"]
          }
        }
      },
      required: ["summary", "severity", "category", "mitre", "timeline", "network", "remediations"]
    };

    const prompt = `You are a Senior SOC Analyst and Incident Responder. Investigate the security logs uploaded below. 
    Analyze correlations across logs (matching IPs, matching times, files, user accounts, commands). 
    Identify the initial compromise vector, attack progression, lateral movement steps, exfiltration, and active threats.
    
    Structure your findings into a single JSON object containing summary, severity, category, mapped MITRE techniques, detailed chronological timeline (sorted from earliest to latest), network nodes/edges representing the attack pathway, and a checklist of security remediations.
    
    Logs:
    ${logContextText}`;

    const requestBody = {
      contents: [{
        parts: [{ text: prompt }]
      }],
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: responseSchema
      }
    };

    const apiResponse = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!apiResponse.ok) {
      throw new Error(`Gemini API Error: Status ${apiResponse.status}`);
    }

    const data = await apiResponse.json();
    const resultText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!resultText) {
      throw new Error('Failed to retrieve structured content from Gemini candidate response.');
    }

    return JSON.parse(resultText);

  } catch (error) {
    console.error('Failed to run Gemini analysis, falling back to local engine:', error);
    // Return heuristic output on error, but append info about the error
    const localResult = parseCustomLogs(logs);
    localResult.summary = `[Gemini Live API failed, using Heuristic Simulator] ${localResult.summary} (Error details: ${error.message})`;
    return localResult;
  }
}

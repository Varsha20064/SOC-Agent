# 🛡️ SOC Agent – Autonomous AI Security Operations Center

<div align="center">

![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite)
![Gemini](https://img.shields.io/badge/Powered%20by-Google%20Gemini-4285F4?logo=google)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![AI](https://img.shields.io/badge/AI-Agentic%20Workflow-success)
![License](https://img.shields.io/badge/License-MIT-green)

### 🤖 An AI-powered SOC analyst that investigates cybersecurity incidents, reconstructs attack timelines, correlates multi-source evidence, maps attacks to MITRE ATT&CK, extracts IOCs, and generates executive reports.

🌐 **Live Demo:** https://YOUR-RENDER-URL.onrender.com

</div>

---

# 🚀 Overview

Modern Security Operations Centers (SOCs) generate thousands of alerts every day from firewalls, endpoint security tools, cloud platforms, email gateways, and network monitoring systems. Security analysts spend significant time manually correlating these alerts to determine whether they belong to a single attack.

**SOC Agent** is an autonomous AI-powered incident investigation platform that acts like a Tier-1 Security Operations Center analyst.

Instead of simply analyzing individual logs, SOC Agent correlates evidence across multiple sources, reconstructs the complete attack lifecycle, maps adversary behavior to the MITRE ATT&CK framework, extracts Indicators of Compromise (IOCs), assesses severity, recommends remediation, and generates executive reports for both analysts and management.

---

# 🎯 Key Features

## 🔍 Multi-Source Evidence Ingestion

SOC Agent accepts multiple evidence types simultaneously.

Supported inputs include:

- 🔥 Firewall Logs
- 🖥 Windows Event Logs
- ☁ AWS CloudTrail / Cloud Audit Logs
- 📧 Suspicious Email Evidence
- 🌐 Network Traffic Summaries

The AI correlates information across all uploaded evidence rather than treating each log independently.

---

## 🤖 AI-Powered Incident Investigation

Using **Google Gemini**, SOC Agent performs:

- Entity Extraction
- Event Correlation
- Threat Classification
- Timeline Reconstruction
- MITRE ATT&CK Mapping
- IOC Extraction
- Risk Assessment
- Executive Report Generation

---

## 🧠 Autonomous Investigation Workflow

```text
Upload Security Evidence
        │
        ▼
Evidence Parsing
        │
        ▼
Entity Extraction
        │
        ▼
Cross-Source Correlation
        │
        ▼
Threat Identification
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
Attack Timeline Reconstruction
        │
        ▼
IOC Extraction
        │
        ▼
Risk Assessment
        │
        ▼
Executive Report Generation
```

---

# ⚡ Platform Capabilities

## 🛡 AI Incident Correlation

Instead of reviewing alerts individually, SOC Agent automatically correlates:

- Source IPs
- Destination IPs
- User Accounts
- Hostnames
- PowerShell Commands
- Authentication Events
- Cloud Activity
- Network Connections

to reconstruct the complete incident.

---

## 🧩 MITRE ATT&CK Mapping

Every detected attack is mapped to industry-standard MITRE ATT&CK techniques.

Example:

| Technique ID | Technique |
|--------------|-----------|
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1059 | Command & Scripting Interpreter |
| T1003 | OS Credential Dumping |
| T1041 | Exfiltration Over C2 Channel |
| T1098 | Account Manipulation |

---

## 🕒 Attack Timeline Reconstruction

Transform raw logs into an investigation timeline.

Example

```text
Repeated Failed Login Attempts
        ↓
Administrator Login
        ↓
PowerShell Execution
        ↓
Credential Dumping
        ↓
Sensitive File Access
        ↓
Large HTTPS Upload
        ↓
Cloud IAM Modification
```

---

## 🌐 Interactive Attack Graph

Visualize attack progression across systems.

Displays:

- External Attacker
- Internal Hosts
- Domain Controllers
- Cloud Resources
- Network Movement
- Exfiltration Targets

---

## 🚨 Indicators of Compromise (IOC)

SOC Agent extracts:

- Suspicious IP Addresses
- Hostnames
- User Accounts
- Processes
- File Names
- Domains
- External Destinations

making investigation significantly faster.

---

## 📈 Risk Assessment

Every investigation includes:

- Incident Severity
- Confidence Score
- Risk Score
- Business Impact

allowing analysts to prioritize incidents quickly.

---

## ✅ Automated Remediation

Instead of generic recommendations, SOC Agent produces incident-specific remediation.

Examples include:

- Disable compromised accounts
- Reset privileged credentials
- Block malicious IPs
- Enable Multi-Factor Authentication
- Isolate infected hosts
- Preserve forensic evidence
- Remove unauthorized cloud policies

---

## 📄 Executive Reporting

Generate manager-friendly reports containing:

- Executive Summary
- Business Impact
- Technical Findings
- Timeline
- MITRE ATT&CK Mapping
- IOC Summary
- Recommended Actions

---

# 💻 Technology Stack

## Frontend

- React
- Vite
- JavaScript
- CSS
- Lucide React

## Artificial Intelligence

- Google Gemini
- Structured JSON Response Schema
- Prompt Engineering

## Security

- MITRE ATT&CK Framework
- IOC Correlation
- Threat Classification

## Visualization

- Interactive Dashboard
- Attack Timeline
- Network Attack Graph
- Executive Reports

---

# 📂 Project Structure

```
SOC-Agent/

├── src/
│
├── components/
│
├── pages/
│   ├── Incident Center
│   ├── Attack Timeline
│   ├── Attack Map
│   ├── MITRE Matrix
│   ├── Executive Report
│   └── Settings
│
├── services/
│
├── utils/
│
├── assets/
│
└── App.jsx
```

---

# 🎮 Demo Workflow

```text
Upload Evidence
        │
        ▼
SOC Agent Investigation
        │
        ▼
Incident Summary
        │
        ▼
AI Reasoning Chain
        │
        ▼
Attack Timeline
        │
        ▼
MITRE Mapping
        │
        ▼
IOC Extraction
        │
        ▼
Attack Graph
        │
        ▼
Executive Report
```

---

# 🧪 Built-in Demo Scenarios

The application ships with predefined attack simulations.

### 🎣 Phishing → Ransomware

- Phishing Email
- PowerShell Execution
- Credential Theft
- Ransomware Deployment

---

### ☁ AWS Credential Abuse

- IAM Compromise
- S3 Enumeration
- Large Data Exfiltration

---

### 💉 SQL Injection

- SQL Injection
- Privilege Escalation
- Domain Administrator Takeover

---

# 🌟 Why SOC Agent?

Traditional SIEM dashboards generate alerts.

SOC Agent investigates them.

Instead of asking:

> "What does this log say?"

SOC Agent answers:

- What happened?
- How did the attacker get in?
- Which systems were affected?
- Which MITRE techniques were used?
- What evidence supports this conclusion?
- How severe is the incident?
- What should analysts do next?

---

# 🔮 Roadmap

- Multi-Agent Investigation
- Vertex AI Integration
- Google ADK Support
- MCP Tool Integration
- Investigation Memory
- Live SIEM Connectors
- VirusTotal Integration
- Sigma Rule Generation
- YARA Rule Suggestions
- Cloud Run Deployment
- Real-Time Streaming Analysis

---

# 📸 Screenshots

| Dashboard | Timeline | Attack Graph |
|------------|----------|--------------|
| Add Screenshot | Add Screenshot | Add Screenshot |

---

# 🌐 Live Demo

👉 **https://YOUR-RENDER-URL.onrender.com**

---

# 👥 Team

Built with ❤️ to demonstrate how autonomous AI agents can transform modern Security Operations Centers by reducing investigation time, improving threat correlation, and enabling faster incident response.

---

## ⭐ Star this repository if you found the project interesting!

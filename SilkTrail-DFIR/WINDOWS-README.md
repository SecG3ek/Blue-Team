# 🕵️‍♂️ SilkTrail-DFIR

![PowerShell](https://img.shields.io/badge/PowerShell-DFIR-blue?style=for-the-badge&logo=powershell)
![Windows](https://img.shields.io/badge/Windows-Incident%20Response-0078D4?style=for-the-badge&logo=windows)
![MDE](https://img.shields.io/badge/Microsoft%20Defender-Live%20Response-green?style=for-the-badge&logo=microsoft)
![Output](https://img.shields.io/badge/Output-CSV%20%7C%20TXT%20%7C%20EVTX%20%7C%20ZIP-orange?style=for-the-badge)

> **SilkTrail-DFIR** is a PowerShell-based Windows incident response collection script built for fast host triage, SIEM-ready exports, and Microsoft Defender for Endpoint Live Response workflows.

---

## 🌟 Overview

**SilkTrail-DFIR** helps analysts collect high-value forensic artifacts from a Windows endpoint during an active investigation.

It gathers host, process, user, network, persistence, browser, Defender, and Windows event artifacts into a structured case folder.

At the end of the run, SilkTrail-DFIR compresses the collected evidence into a ZIP file for easy retrieval, review, or handoff.

---

## 🎯 Primary Use Cases

- 🚨 Rapid endpoint triage during incident response
- 🧪 DFIR collection through Microsoft Defender for Endpoint Live Response
- 🔍 Suspicious process and persistence review
- 🌐 Network connection and DNS cache analysis
- 🧾 Security event review over a custom time window
- 🛡️ Microsoft Defender log and exclusion collection
- 📊 CSV exports for SIEM ingestion and timeline building
- 📦 Quick evidence packaging for analyst handoff

---

## ⚡ What SilkTrail-DFIR Collects

### 🖥️ System & Host Data

| Artifact | Description | Output Type |
|---|---|---|
| IP Configuration | Local interface and IP address details | TXT / CSV |
| Connected Devices | Plug-and-play device inventory | CSV |
| Shadow Copies | Volume shadow copy information | TXT / CSV |
| Installed Drivers | Driver inventory from `driverquery` | TXT / CSV |

---

### 🌐 Network & Connection Data

| Artifact | Description | Output Type |
|---|---|---|
| Open TCP Connections | Established TCP connections | TXT / CSV |
| DNS Cache | Local DNS client cache | TXT / CSV |
| SMB Shares | Local SMB share configuration | TXT / CSV |
| Network Shares | Mounted network share registry data | TXT / CSV |
| RDP Sessions | Active local RDP session information | TXT / CSV |
| Remotely Opened Files | Files opened remotely through Windows file sharing | TXT / CSV |
| Office Connections | Microsoft Office internet server cache registry data | TXT / CSV |

---

### 👤 User & Account Data

| Artifact | Description | Output Type |
|---|---|---|
| Active Users | Currently logged-on users | TXT / CSV |
| Local Users | Local account inventory | TXT / CSV |
| PowerShell History | Current user PowerShell command history | TXT / CSV |
| All Users PowerShell History | PSReadLine console history from user profiles | TXT |

---

### ⚙️ Process & Execution Data

| Artifact | Description | Output Type |
|---|---|---|
| Active Processes | Running process list with path, command line, PID, PPID | CSV |
| Process Hashes | Unique process executable SHA256 hashes | CSV |

This is useful for quickly spotting:

- 🧬 Unknown binaries
- 🧨 Suspicious command lines
- 🧵 Parent-child process anomalies
- 🧰 Living-off-the-land binary abuse
- 🪪 Hashes ready for enrichment in VirusTotal, Defender, Sentinel, or threat intel platforms

---

### 🧷 Persistence & Startup Data

| Artifact | Description | Output Type |
|---|---|---|
| Autoruns | Startup commands from `Win32_StartupCommand` | TXT / CSV |
| Scheduled Tasks | Enabled or recently active scheduled tasks | TXT / CSV |
| Scheduled Task Run Info | Runtime metadata for enabled tasks | TXT / CSV |
| Installed Drivers | Driver inventory that may reveal persistence or tampering | TXT / CSV |

---

### 🪟 Windows Event Data

| Artifact | Description | Output Type |
|---|---|---|
| Security Event Count | Security log event IDs grouped by volume | TXT |
| Security Events | Security events from the selected time window | TXT / CSV |
| EVTX Files | Copies of selected Windows event logs | EVTX |
| Recent MSI Installs | Software installation events from MSIInstaller | TXT / CSV |

Collected EVTX channels include:

- 📘 Application
- 🔐 Security
- 🧱 System
- 🧪 Sysmon Operational
- ⏰ TaskScheduler Operational
- 💙 PowerShell Operational

---

### 🌍 Browser Artifacts

| Browser Family | Artifacts Collected |
|---|---|
| Chromium-based browsers | `Preferences`, `History` |
| Firefox | `places.sqlite`, `permissions.sqlite`, `content-prefs.sqlite`, `extensions` |

Useful for reviewing:

- 🌐 Recently visited sites
- 🧩 Extension activity
- 🔗 Browser-based initial access clues
- 📥 Suspicious download trails
- 🪝 Phishing or OAuth consent activity leads

---

### 🛡️ Microsoft Defender Artifacts

| Artifact | Description | Output Type |
|---|---|---|
| Defender Support Logs | Copies Defender support `.log` files | LOG |
| Defender Exclusions | Path, extension, IP, and process exclusions | TXT / CSV |

These artifacts help identify:

- 🚫 Suspicious AV exclusions
- 🧹 Defense evasion activity
- 🛠️ Security tool tampering
- 📜 Defender operational context

---

## 📁 Output Structure

SilkTrail-DFIR creates a timestamped case folder under `C:\Support`.

```text
C:\Support\DFIR-<HOSTNAME>-<YYYY-MM-DD>\
│
├── Applications\
├── Browsers\
│   ├── Chromium\
│   └── Firefox\
├── ConnectedDevices\
├── Connections\
├── CSV Results (SIEM Import Data)\
├── DefenderExclusions\
├── Event Viewer\
├── MPLogs\
├── Persistence\
├── PowerShellHistory\
├── ProcessInformation\
├── ScheduledTask\
├── SecurityEvents\
├── Services\
└── UserInformation\
```

The final ZIP package is created here:

```text
C:\Support\DFIR-<HOSTNAME>-<YYYY-MM-DD>.zip
```

---

## 📊 SIEM-Friendly CSV Exports

SilkTrail-DFIR creates a dedicated folder for CSV data:

```text
CSV Results (SIEM Import Data)
```

This folder is designed for quick import into tools such as:

- 🔷 Microsoft Sentinel
- 🛡️ Microsoft Defender XDR
- 📈 Splunk
- 🧠 Elastic
- 📦 Any platform that supports CSV ingestion

---

## 🚀 Quick Start

### 1️⃣ Download or clone the repository

```powershell
git clone https://github.com/<your-org>/SilkTrail-DFIR.git
cd SilkTrail-DFIR
```

### 2️⃣ Run PowerShell as Administrator

Administrative execution is recommended so SilkTrail-DFIR can collect the fullest set of artifacts.

### 3️⃣ Run the script

```powershell
.\SilkTrail-DFIR.ps1
```

By default, the script uses a **1-day security event search window**.

---

## 🕒 Custom Security Event Search Window

Use the `-sw` parameter to set the number of days to search in the Security event log.

### Example: collect the last 7 days of Security events

```powershell
.\SilkTrail-DFIR.ps1 -sw 7
```

### Example: collect the last 30 days of Security events

```powershell
.\SilkTrail-DFIR.ps1 -sw 30
```

---

## 🧪 Microsoft Defender for Endpoint Live Response Usage

SilkTrail-DFIR was built with Live Response workflows in mind.

Typical workflow:

1. 📤 Upload `SilkTrail-DFIR.ps1` to the Live Response library.
2. 🎯 Start a Live Response session against the target device.
3. ▶️ Run the script from the session.
4. 📦 Retrieve the generated ZIP from `C:\Support`.
5. 🔍 Review the artifacts locally or import CSVs into your SIEM.

Example command pattern:

```powershell
run SilkTrail-DFIR.ps1
```

With a custom search window:

```powershell
run SilkTrail-DFIR.ps1 -parameters "-sw 7"
```

> 💡 Live Response command syntax can vary by tenant configuration and portal experience. Validate the exact run syntax in your environment.

---

## 🧰 Requirements

| Requirement | Notes |
|---|---|
| Windows OS | Designed for Windows endpoints |
| PowerShell | Windows PowerShell recommended |
| Administrative Rights | Recommended for full collection |
| Microsoft Defender Module | Required for Defender exclusion collection |
| Event Log Access | Required for Security and EVTX collection |
| Write Access to `C:\Support` | Required for output folder and ZIP creation |

---

## 🔐 Permission Notes

Some collectors may require elevated rights.

Administrative collection includes artifacts such as:

- 🔐 Security event logs
- 🧱 EVTX file copies
- 🕶️ Shadow copies
- 🛡️ Defender support logs
- 🚫 Defender exclusions
- 👥 All-user PowerShell history
- 📂 Remotely opened files

If these artifacts are missing, validate that the script ran with the expected permissions.

---

## 🧭 Investigation Workflow

A practical analyst flow:

### 1️⃣ Start with process data

Review:

```text
ProcessInformation\ProcessList.csv
ProcessInformation\UniqueProcessHash.csv
CSV Results (SIEM Import Data)\Processes.csv
```

Look for:

- Odd execution paths
- Suspicious command lines
- Unknown hashes
- Parent-child process mismatches
- Processes running from user-writable directories

---

### 2️⃣ Review network artifacts

Review:

```text
Connections\OpenConnections.txt
Connections\DNSCache.txt
Connections\NetworkShares.txt
Connections\RDPSessions.txt
```

Look for:

- Unknown external IPs
- Recently resolved suspicious domains
- Unexpected RDP sessions
- Strange SMB connections
- Office connections to unfamiliar hosts

---

### 3️⃣ Hunt persistence

Review:

```text
Persistence\AutoRunInfo.txt
ScheduledTask\ScheduledTasksList.txt
ScheduledTask\ScheduledTasksListRunInfo.txt
Persistence\InstalledDrivers.txt
```

Look for:

- Odd startup commands
- Recently modified scheduled tasks
- Encoded PowerShell
- Scripts launched from temp paths
- Unknown drivers

---

### 4️⃣ Check Defender state

Review:

```text
DefenderExclusions\
MPLogs\
CSV Results (SIEM Import Data)\DefenderExclusions.csv
```

Look for:

- New exclusions
- Broad exclusions like `C:\`, `C:\Users`, or `Downloads`
- Process exclusions for scripting engines
- IP exclusions for unknown infrastructure

---

### 5️⃣ Build a quick timeline

Use CSV files from:

```text
CSV Results (SIEM Import Data)\
```

Focus on:

- Security events
- Installed software
- Scheduled tasks
- Process data
- DNS cache
- Defender exclusions

---

## 🧪 Example Triage Questions

SilkTrail-DFIR helps answer questions like:

- 🧑‍💻 Who was logged in?
- 🧬 What processes were running?
- 🔗 What network connections existed?
- 🌐 What DNS names were cached?
- 🧷 What persistence mechanisms were present?
- 🕒 What Security events occurred in the selected window?
- 🛡️ Were Defender exclusions added?
- 🧩 What browser artifacts are available?
- 📦 What files were opened remotely?
- 🧱 Were shadow copies present or missing?

---

## 🧾 Example Output Files

```text
CSV Results (SIEM Import Data)\Processes.csv
CSV Results (SIEM Import Data)\OpenTCPConnections.csv
CSV Results (SIEM Import Data)\DNSCache.csv
CSV Results (SIEM Import Data)\SecurityEvents.csv
CSV Results (SIEM Import Data)\ScheduledTasks.csv
CSV Results (SIEM Import Data)\DefenderExclusions.csv
ProcessInformation\UniqueProcessHash.csv
Event Viewer\Security.evtx
PowerShellHistory\PowershellHistoryCurrentUser.txt
DefenderExclusions\ExclusionPath.txt
MPLogs\*.log
```

---

## 🧼 Operational Safety

SilkTrail-DFIR is a collection tool.

It does **not**:

- ❌ Kill processes
- ❌ Delete files
- ❌ Quarantine malware
- ❌ Modify firewall rules
- ❌ Remediate persistence
- ❌ Change Defender configuration

It writes collected artifacts to disk and compresses the results.

---

## ⚠️ Known Operational Notes

- 🧑‍⚖️ Run with authorization only.
- 📁 The script writes output to `C:\Support`.
- 🗜️ The case folder is compressed at the end of execution.
- 🔐 Administrative rights provide the most complete artifact set.
- 🧪 Test in a lab before using in production.
- 📦 Large event logs or browser histories may increase ZIP size.
- 🧭 If admin-only artifacts are missing, validate elevation and the script's admin-check logic in your environment.

---

## 🧠 Suggested Analyst Enrichment

After collection, enrich suspicious artifacts with:

- 🛡️ Microsoft Defender XDR advanced hunting
- 🔷 Microsoft Sentinel watchlists
- 🧬 VirusTotal or internal malware analysis tools
- 🌍 Passive DNS
- 🧾 Certificate transparency lookups
- 🧠 Threat intelligence platforms
- 📚 MITRE ATT&CK mapping
- 🧪 Sandbox detonation, when appropriate

---

## 🧩 Suggested MITRE ATT&CK Mapping

SilkTrail-DFIR helps collect evidence related to several ATT&CK areas:

| Tactic | Useful Artifacts |
|---|---|
| Initial Access | Browser history, Office connections, Security events |
| Execution | Processes, command lines, PowerShell history |
| Persistence | Autoruns, scheduled tasks, drivers |
| Privilege Escalation | Services, drivers, Security events |
| Defense Evasion | Defender exclusions, PowerShell history, event logs |
| Credential Access | Security events, suspicious process execution |
| Discovery | PowerShell history, processes, DNS cache |
| Lateral Movement | SMB shares, RDP sessions, remotely opened files |
| Command and Control | TCP connections, DNS cache, browser artifacts |
| Exfiltration | Network connections, Office connections, browser artifacts |

---

## 🛣️ Roadmap Ideas

Future improvements could include:

- 🧾 JSON output support
- 🧠 Built-in suspicious artifact scoring
- 🔎 Sigma-style detection checks
- 🧬 Automatic hash enrichment hooks
- 🧱 Memory capture option
- 📸 Screenshot capture option
- 📊 HTML summary report
- 🪪 Case metadata prompt
- 🧵 Timeline generation
- 🧑‍🚒 Incident responder notes file

---

## 🤝 Contributing

Pull requests are welcome.

Suggested contribution areas:

- New collectors
- Better error handling
- Live Response compatibility improvements
- Cleaner CSV formatting
- Documentation updates
- Detection logic
- Timeline generation

---

## 📜 Disclaimer

SilkTrail-DFIR is intended for authorized security operations, incident response, digital forensics, and internal defensive investigations.

Only run this tool on systems you own, administer, or have explicit permission to investigate.

---

## 🧵 Name Meaning

**SilkTrail-DFIR** follows the trail left behind by activity on a Windows endpoint.

Processes.

Connections.

Users.

Persistence.

Events.

Browser artifacts.

Defender evidence.

All woven into one portable collection package.

---

## ⭐ Support

If SilkTrail-DFIR helps your team move faster during investigations, consider starring the repository and sharing improvements back with the DFIR community.


# 🕷️ SilkTrail DFIR

> **Linux forensic triage collection for SecOps, IR, and Microsoft Defender Live Response**

![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Shell](https://img.shields.io/badge/Shell-Bash-green)
![Use Case](https://img.shields.io/badge/Use%20Case-DFIR-purple)
![Mode](https://img.shields.io/badge/Mode-Read--Only-orange)

---
<img src="https://github.com/SecG3ek/Blue-Team/blob/main/SilkTrail-DFIR/SilkTrail-DFIR_LinuxEdition.gif" alt="Demo" width="800" />

---

## 🧠 What Is SilkTrail DFIR?

**SilkTrail DFIR** is a Linux incident-response collection script designed to help security teams quickly gather forensic artifacts from Linux systems.

It is built for fast triage during investigations.

It collects key system, user, process, network, persistence, and log artifacts into a clean output folder and compressed archive.

Perfect for:

* 🛡️ SOC investigations
* 🧪 DFIR triage
* 🚨 Incident response
* 🐧 Linux endpoint reviews
* ☁️ Microsoft Defender Live Response workflows
* 📦 Offline evidence review

---

## 🕸️ Why SilkTrail?

When an attacker touches a Linux host, they leave traces.

**SilkTrail DFIR follows the web.**

It helps analysts quickly answer:

* Who was logged in?
* What processes were running?
* What network connections existed?
* What services were active?
* What persistence locations were present?
* What scheduled tasks existed?
* What users and privilege paths were configured?
* What logs and histories can support the investigation?

---

## ✨ Key Features

### ⚡ Fast Linux Triage

Collects high-value artifacts in one run.

No need to manually execute dozens of commands during an incident.

---

### 🛡️ Read-Only Collection

SilkTrail only reads and copies artifacts.

It does **not** modify system configuration.

The only host change is writing its own output under `/tmp`.

---

### 📦 Clean Evidence Packaging

Creates a timestamped folder and compressed archive.

Example output:

```text
/tmp/DFIR-hostname-2026-06-08/
/tmp/DFIR-hostname-2026-06-08.tar.gz
```

---

### 📊 SIEM-Friendly CSV Output

Creates CSV files for easier review, filtering, parsing, and SIEM import.

CSV output is stored under:

```text
CSV-Results-SIEM-Import-Data/
```

---

### 🔐 Root-Aware Collection

Runs with or without root.

With root, SilkTrail collects deeper forensic artifacts such as:

* System logs
* Authentication logs
* Failed login records
* All-user shell history
* Browser artifacts across users
* Samba/NFS activity
* SUID/SGID files

Without root, it still collects what the current user can access.

---

## 🧰 What It Collects

### 🌐 Network Data

* IP addresses
* Routes
* ARP / neighbor cache
* Established TCP connections
* Listening ports
* Mounted network shares
* SMB and NFS share configuration
* Remote sessions
* DNS resolver state

---

### 👤 User Activity

* Active users
* Recent logins
* Local users
* UID 0 accounts
* Accounts with login shells
* Failed login records
* Shell history

---

### ⚙️ Process and Service Data

* Running processes
* Process tree
* Process command lines
* Executable paths
* SHA-256 hashes of process binaries
* Running services
* Kernel modules

---

### 🧬 Persistence Checks

* Enabled systemd units
* Cron jobs
* Systemd timers
* `at` jobs
* `/etc/rc.local`
* Login scripts
* Desktop autostart entries
* `/etc/ld.so.preload`
* SUID / SGID files

---

### 📚 Logs and Security Events

* Auth logs
* Syslog / messages
* Kernel logs
* Audit logs
* Journald export
* Package install logs
* Failed login databases
* Authentication event counts

---

### 🧭 Browser Artifacts

Supports common Linux browser artifact locations for:

* Chromium
* Google Chrome
* Microsoft Edge
* Brave
* Vivaldi
* Opera
* Firefox

Collected artifacts may include:

* History databases
* Preferences
* Web data
* Cookies
* Extensions
* Permissions

---

### 🔥 Security Posture

Collects local security configuration, including:

* SELinux status
* AppArmor status
* UFW firewall status
* nftables rules
* iptables rules
* ip6tables rules

---

### 💾 System and Device Data

* Installed packages
* Recently installed software
* USB devices
* PCI devices
* Block devices
* Recent storage-related kernel events
* LVM snapshot data
* Btrfs subvolume data

---

## 🚀 Usage

### Basic Run

```bash
chmod +x secops-dfir-linux.sh
./secops-dfir-linux.sh
```

---

### Run With Root for Full Collection

```bash
sudo ./secops-dfir-linux.sh
```

---

### Set Log Search Window

By default, SilkTrail reviews the last **1 day** of time-bounded logs.

To search the last 3 days:

```bash
sudo ./secops-dfir-linux.sh -w 3
```

---

### Help Menu

```bash
./secops-dfir-linux.sh --help
```

---

## 🛡️ Microsoft Defender Live Response Usage

SilkTrail is a strong fit for Microsoft Defender Live Response because it can be pushed to a Linux endpoint, executed remotely, and collected back as an archive.

Example workflow:

```text
1. Upload secops-dfir-linux.sh to the target host.
2. Run the script through Live Response.
3. Collect the generated archive from /tmp.
4. Store the archive with the incident case.
5. Review artifacts offline or import CSV files into analysis workflows.
```

Recommended execution:

```bash
sudo bash secops-dfir-linux.sh -w 3
```

Expected archive:

```text
/tmp/DFIR-<hostname>-<YYYY-MM-DD>.tar.gz
```

---

## 📁 Output Structure

Example:

```text
DFIR-hostname-2026-06-08/
├── Applications/
├── Browsers/
├── CSV-Results-SIEM-Import-Data/
├── ConnectedDevices/
├── Connections/
├── Logs/
├── Persistence/
├── ProcessInformation/
├── ScheduledTasks/
├── SecurityEvents/
├── SecurityPosture/
├── Services/
├── ShellHistory/
├── Snapshots/
├── UserInformation/
├── SHA256SUMS
└── collection.log
```

---

## 🔎 Artifact Integrity

SilkTrail generates a SHA-256 manifest of collected files:

```text
SHA256SUMS
```

This helps analysts validate collected artifacts during review and case handling.

---

## ⚠️ Important Handling Note

The output may contain sensitive data.

This can include:

* Usernames
* Hostnames
* IP addresses
* Command history
* Browser history
* Authentication logs
* Network connections
* Security configuration
* File paths
* Account activity

Treat all output as sensitive incident evidence.

Store it only in approved locations.

Limit access to authorized investigation personnel.

---

## ✅ Recommended Use Cases

Use SilkTrail when investigating:

* Suspected Linux compromise
* Suspicious login activity
* Possible persistence
* Unknown running processes
* Lateral movement
* Data staging
* Suspicious network connections
* Unauthorized users
* Privilege escalation
* Web shell activity
* Malware execution
* Cloud workload compromise

---

## 🧪 Analyst Review Ideas

After collection, analysts can quickly review:

```text
Processes.csv
OpenTCPConnections.csv
ListeningPorts.csv
LocalUsers.csv
ActiveUsers.csv
RunningServices.csv
SystemdTimers.csv
KernelModules.csv
NetworkShares.csv
SecurityEvents.txt
ShellHistory/
SUID_SGID_Files.txt
```

High-value checks:

* 🧬 Unknown process hashes
* 🌐 External established connections
* 👤 New or unexpected local users
* 🔑 UID 0 accounts besides root
* 🕒 Suspicious cron jobs or timers
* 🧱 Disabled firewall controls
* 🧨 Unusual SUID / SGID binaries
* 🧾 Suspicious shell history
* 🧲 Unexpected listening ports
* 🕵️ Strange browser activity

---

## 🕷️ Name Meaning

**SilkTrail DFIR** follows the strands of Linux activity across the host.

Processes.

Users.

Logs.

Network connections.

Persistence.

History.

Each artifact is a thread.

Together, they form the web.

---

## 📌 Current Status

```text
Status: Operational
Platform: Linux
Shell: Bash
Collection Mode: Best-effort
Host Impact: Low
Primary Use: DFIR triage
Recommended Access: Root when available
```

---

## 🧑‍💻 Author

Built for SecOps and DFIR teams that need fast, repeatable Linux evidence collection during real investigations.

---

## 🛑 Disclaimer

SilkTrail DFIR is intended for authorized security operations, incident response, and forensic triage only.

Only run this tool on systems you own, manage, or have explicit permission to investigate.

# Incident Response & Detection Architecture

**Enterprise-Grade SIEM Implementation with Multi-Vector Threat Detection & File Integrity Monitoring**

[![Project Status](https://img.shields.io/badge/Status-Complete-success)](https://github.com/Kanhay-Thakore/Incident-Response-Detection-Architecture/tree/main)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Wazuh-blue)](https://wazuh.com/)
[![Detection Coverage](https://img.shields.io/badge/IoC%20Coverage-100%25-brightgreen)](#attack-simulation--detection)

---

## 🎯 Project Overview

Full-stack Security Operations Center implementation for **CSA271.com** combining **Wazuh SIEM**, **Snort IDS**, and **Volatility** for comprehensive threat detection, log correlation, and forensic analysis across multi-OS infrastructure.

**Key Achievement:** Successfully detected and correlated 4 distinct attack vectors with real-time alerting and memory-based forensic validation.

---

## 📊 Performance Metrics

| Metric | Value | Details |
|--------|-------|---------|
| **Attack Detection Rate** | 100% | All 4 IoC categories successfully detected |
| **SIEM Log Ingestion** | Real-time | Zero-latency log forwarding from agents |
| **File Integrity Monitoring** | Active | Real-time hash-based change detection |
| **Memory Forensics** | Complete | Full RAM analysis with network artifact recovery |
| **Environment Complexity** | Multi-OS | Windows Server, Ubuntu, Kali Linux |
| **Network Isolation** | VMnet9 | Fully isolated host-only lab environment |

---

## 🏗️ System Architecture

### Network Topology

![Network Architecture](images/Network%20Architecture%20&%20Lab%20Environment.png)

*Three-tier security lab with dedicated attacker, target, and SIEM nodes*

**Architecture Components:**
```
┌─────────────────────────────────────────────────────────────┐
│         INCIDENT RESPONSE DETECTION ENVIRONMENT              │
├───────────────┬──────────────┬──────────────┬───────────────┤
│ Attack Layer  │ Target Layer │  SIEM Layer  │  Detection    │
├───────────────┼──────────────┼──────────────┼───────────────┤
│ Kali Linux    │ Windows      │ Ubuntu       │ • Wazuh SIEM  │
│ 10.10.1.30    │ Server 2016  │ 20.04 LTS    │ • Snort IDS   │
│               │ 10.10.1.20   │ 10.10.1.10   │ • FIM         │
│ • Hydra       │              │              │ • Real-time   │
│ • Nmap        │ • IIS Web    │ • Wazuh      │   Correlation │
│ • Metasploit  │ • FTP        │   Manager    │               │
│               │ • Snort IDS  │ • Dashboard  │               │
└───────────────┴──────────────┴──────────────┴───────────────┘
```

### Lab Infrastructure

| Component | Specification | Purpose |
|-----------|---------------|---------|
| **Kali Linux** | 10.10.1.30 | Attack simulation platform |
| **Windows Server 2016** | 10.10.1.20 | IIS/FTP target + Snort IDS |
| **Ubuntu 20.04 (Wazuh)** | 10.10.1.10 | SIEM manager & log aggregation |
| **Network** | VMnet9 (10.10.1.0/24) | Isolated host-only network |
| **Time Sync** | NTP across all VMs | Synchronized log correlation |

---

## 🛠️ Technology Stack

<table>
<tr>
<td width="25%">

**SIEM Platform**
- Wazuh 4.x
- OpenSearch Dashboard
- Wazuh Agent
- Real-time Monitoring

</td>
<td width="25%">

**Intrusion Detection**
- Snort 2.9.x
- Custom Rules
- Log Forwarding
- OSSEC Integration

</td>
<td width="25%">

**Target Services**
- Windows Server 2016
- IIS Web Server
- FTP Service
- RDP Enabled

</td>
<td width="25%">

**Forensics**
- DumpIt (Memory Capture)
- Volatility 3
- Network Analysis
- Process Analysis

</td>
</tr>
</table>

---

## 🎯 Attack Simulation & Detection

### Indicators of Compromise (IoC) Coverage

<table>
<tr>
<td width="50%">

**Network-Based Attacks**

✅ **Brute Force (RDP)**
- Tool: Hydra
- Target: Windows RDP (3389)
- Detection: Failed login attempts
- Alert: Multiple authentication failures

✅ **SYN Scan**
- Tool: Nmap (`-sS`)
- Detection: Snort IDS signature
- Alert: Port scanning activity

</td>
<td width="50%">

**Reconnaissance Attacks**

✅ **TCP Connect Scan**
- Tool: Nmap (`-sT`)
- Detection: Full connection attempts
- Alert: Port enumeration detected

✅ **UDP Scan**
- Tool: Nmap (`-sU`)
- Detection: UDP port probing
- Alert: Service discovery attempt

</td>
</tr>
</table>

### Detection Rule Summary

**Snort IDS Custom Rules:**
```
- ICMP Ping Detection
- SYN Scan Detection (Half-open connections)
- TCP Connect Scan Detection
- UDP Port Scan Detection
```

**Wazuh SIEM Correlation:**
```
- Windows Security Event Log (EventID 4625 - Failed Logon)
- Snort Alert Ingestion via OSSEC
- Real-time Dashboard Visualization
- Severity-based Alert Classification
```

---

## 🧪 Validation & Testing

### Attack Execution Results

| Attack Type | Tool | Command | Detection Time | Status |
|-------------|------|---------|----------------|--------|
| **Brute Force** | Hydra | `hydra -L users.txt -P pass.txt rdp://10.10.1.20` | < 1 minute | ✅ Detected |
| **SYN Scan** | Nmap | `nmap -sS 10.10.1.20` | Real-time | ✅ Detected |
| **TCP Scan** | Nmap | `nmap -sT 10.10.1.20` | Real-time | ✅ Detected |
| **UDP Scan** | Nmap | `nmap -sU 10.10.1.20` | Real-time | ✅ Detected |

**Detection Success Rate: 100%** (4/4 attack vectors)

---

## 🔒 File Integrity Monitoring (FIM)

### Monitored Assets

**Critical Web Files:**
- `C:\inetpub\wwwroot\index.html` - Default web page
- `C:\inetpub\wwwroot\web.config` - IIS configuration

**FIM Configuration:**
```xml
<syscheck>
  <directories check_all="yes" realtime="yes">
    C:\inetpub\wwwroot
  </directories>
  <frequency>300</frequency>
  <alert_new_files>yes</alert_new_files>
</syscheck>
```

**Detection Capabilities:**
- ✅ Real-time file modification alerts
- ✅ Hash comparison (MD5/SHA256)
- ✅ File size change detection
- ✅ Attribute modification tracking
- ✅ Timestamp correlation

### FIM Alert Example

![FIM Alert](images/File%20Integrity%20Monitoring%20(FIM)_07.png)

*Unauthorized modification to index.html detected with full hash comparison*

---

## 🧠 Memory Forensics Analysis

### Memory Acquisition

**Tool:** DumpIt v3.x  
**Target:** Windows Server 2016 (10.10.1.20)  
**Image Size:** ~4GB RAM dump  
**Format:** Raw memory (.dmp)

![Memory Acquisition](images/dumpit-acquisition_02.png)

### Volatility Analysis Results

**Analysis Performed:**
```bash
# Process listing
vol.py -f DESKTOP-memory.dmp windows.pslist

# Network connections
vol.py -f DESKTOP-memory.dmp windows.netscan
```

**Key Findings:**

✅ **Attack Artifacts Identified:**
- TCP connections from 10.10.1.30 (Kali) to 10.10.1.20 (Target)
- Multiple port scanning connection attempts in memory
- Wazuh agent process (wazuh-agent.exe) actively communicating with 10.10.1.10

✅ **Process Analysis:**
- Identified malicious network activity patterns
- Validated SIEM agent functionality
- Confirmed attack timeline through memory artifacts

![Volatility Network Scan](images/volatility-netscan_02.png)

*Network connection analysis revealing attack source and SIEM communication*

---

## 📈 SIEM Dashboard & Monitoring

### Wazuh Dashboard

![Wazuh Active Agents](images/wazuh-active-agents_01.png)

*Real-time agent status showing IIS-Server connected and reporting*

**Dashboard Features:**
- Active agent monitoring
- Real-time alert feed
- Event severity classification
- Attack timeline visualization
- Top attacked assets
- Geographic attack distribution

### Alert Correlation

**Brute Force Detection:**

![Brute Force Alert](images/hydra-attack_03.png)

*Multiple failed RDP login attempts triggering high-severity alert*

**Network Scan Detection:**

![SYN Scan Alert](images/nmap-syn-scan_03.png)

*Snort IDS alert correlated in Wazuh showing port scanning activity*

---

## 📁 Repository Structure

```
incident-response-detection/
├── docs/
│   ├── setup-guide.md              # Step-by-step deployment
│   ├── attack-simulation.md        # Attack commands & methodology
│   ├── detection-rules.md          # Snort & Wazuh rule details
│   └── forensics-analysis.md       # Volatility analysis workflow
├── images/
│   ├── Network Architecture & Lab Environment.png
│   ├── ubuntu-netplan_03.png
│   ├── ntp-sync_03.png
│   ├── wazuh-install_02.png
│   ├── wazuh-active-agents_01.png
│   ├── Snort default config_02.png
│   ├── Updating local rules_01.png
│   ├── hydra-attack_01.png
│   ├── hydra-attack_03.png
│   ├── nmap-syn-scan_01.png
│   ├── nmap-syn-scan_03.png
│   ├── TCP Scan_01.png
│   ├── TCP Scan_03.png
│   ├── UDP Scan_01.png
│   ├── UDP Scan_03.png
│   ├── File Integrity Monitoring (FIM)_02.png
│   ├── File Integrity Monitoring (FIM)_05.png
│   ├── File Integrity Monitoring (FIM)_07.png
│   ├── dumpit-acquisition_02.png
│   └── volatility-netscan_02.png
├── configs/
│   ├── snort/
│   │   ├── snort.conf             # Snort configuration
│   │   └── local.rules            # Custom detection rules
│   └── wazuh/
│       └── ossec.conf             # Wazuh agent configuration
├── scripts/
│   ├── deploy-lab.sh              # Automated lab setup
│   └── attack-simulation.sh       # Automated attack runner
├── reports/
│   └── Final_Report_Group6.pdf    # Complete technical report
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

**Hardware Requirements:**
- Host Machine: 16GB RAM minimum
- Storage: 100GB available
- CPU: 4+ cores recommended

**Software Requirements:**
- VMware Workstation/Player
- 3 Virtual Machines:
  - Kali Linux (Latest)
  - Windows Server 2016
  - Ubuntu 20.04 LTS

### Installation Steps

**1. Network Configuration**

```bash
# Configure VMnet9 (Host-Only Network)
# Subnet: 10.10.1.0/24
# No DHCP - Static IPs only
```

![Network Setup](images/ubuntu-netplan_03.png)

**2. Deploy Wazuh SIEM**

```bash
# On Ubuntu 10.10.1.10
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Access dashboard: https://10.10.1.10
# Credentials provided after installation
```

![Wazuh Installation](images/wazuh-install_02.png)

**3. Install Snort IDS**

```powershell
# On Windows Server 10.10.1.20
# Download Snort 2.9.x installer
# Configure HOME_NET = 10.10.1.20
# Deploy custom rules to C:\Snort\rules\local.rules
```

![Snort Configuration](images/Snort%20default%20config_02.png)

**4. Configure NTP Synchronization**

```bash
# Ubuntu
sudo timedatectl set-ntp true

# Windows
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
```

![NTP Sync](images/ntp-sync_03.png)

**5. Deploy Wazuh Agent**

```powershell
# On Windows Server
# Install Wazuh agent pointing to 10.10.1.10
# Generate agent key from Wazuh dashboard
# Start wazuh-agent service
```

![Active Agents](images/wazuh-active-agents_01.png)

**6. Run Attack Simulations**

```bash
# From Kali Linux 10.10.1.30

# Brute Force
hydra -L users.txt -P rockyou.txt rdp://10.10.1.20

# SYN Scan
nmap -sS 10.10.1.20

# TCP Scan
nmap -sT 10.10.1.20

# UDP Scan
sudo nmap -sU 10.10.1.20
```

**7. Validate Detections**

Check Wazuh dashboard for alerts in real-time at `https://10.10.1.10`

---

## 💼 Skills Demonstrated

### Security Operations

✅ **SIEM Administration**
- Deployed and configured enterprise SIEM (Wazuh)
- Implemented agent-based log collection
- Built custom correlation rules
- Created operational dashboards

✅ **Intrusion Detection**
- Deployed Snort IDS on production server
- Wrote custom detection signatures
- Integrated IDS alerts with SIEM
- Tuned rules to minimize false positives

✅ **Threat Detection**
- Simulated real-world attack scenarios
- Validated detection for 4 attack vectors
- Achieved 100% detection rate
- Documented IoC mapping

### Digital Forensics

✅ **Memory Analysis**
- Acquired live memory dumps using DumpIt
- Analyzed RAM with Volatility 3
- Identified network artifacts
- Correlated memory findings with SIEM logs

✅ **File Integrity Monitoring**
- Configured real-time FIM
- Implemented hash-based change detection
- Created alerting workflows
- Validated unauthorized modification detection

### System Administration

✅ **Multi-OS Environment**
- Configured Windows Server (IIS, FTP, RDP)
- Deployed Ubuntu Linux (SIEM)
- Maintained Kali Linux (penetration testing)
- Synchronized time across all systems (NTP)

✅ **Network Security**
- Designed isolated lab network (VMnet9)
- Configured static IP addressing
- Implemented network segmentation
- Managed firewall rules

---

## 📈 Project Outcomes

### Business Impact

| Metric | Achievement |
|--------|-------------|
| **Threat Visibility** | 100% of simulated attacks detected |
| **Response Readiness** | Real-time alerting infrastructure |
| **Forensic Capability** | Memory-based attack validation |
| **Compliance** | File integrity monitoring for critical assets |

### Technical Achievements

✅ Successfully deployed enterprise SIEM in multi-OS environment  
✅ Integrated network-based IDS with centralized logging  
✅ Validated detection capabilities through offensive security testing  
✅ Implemented automated file integrity monitoring  
✅ Demonstrated end-to-end incident response workflow  
✅ Achieved 100% IoC detection rate (4/4 attack types)

---

## 📚 Documentation

Comprehensive documentation available:

- **[Setup Guide](docs/setup-guide.md)** - Complete deployment instructions
- **[Attack Simulation](docs/attack-simulation.md)** - Attack commands and expected results
- **[Detection Rules](docs/detection-rules.md)** - Snort & Wazuh rule documentation
- **[Forensics Analysis](docs/forensics-analysis.md)** - Volatility analysis methodology
- **[Technical Report](reports/Final_Report_Group6.pdf)** - Full project documentation

---

## 🎓 Project Context

**Course:** CST8808 - Security Operations  
**Institution:** Algonquin College  
**Semester:** Winter 2025  
**Objective:** Design and test Incident Response plan for CSA271.com

**Project Requirements:**
- ✅ Deploy working SIEM environment
- ✅ Implement log forwarding from IIS server
- ✅ Simulate 4 attack vectors (Brute Force, SYN, TCP, UDP)
- ✅ Configure File Integrity Monitoring
- ✅ Perform memory analysis with Volatility
- ✅ Capture and validate SIEM alerts
- ✅ Synchronize all VMs with NTP
- ✅ Document setup and validation

---

## 📧 Contact

**[Your Name]**  
Security Operations | Incident Response | Digital Forensics

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/yourprofile)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black)](https://github.com/yourusername)
[![Email](https://img.shields.io/badge/Email-Contact-red)](mailto:your.email@example.com)

---

## 📄 License

This project is part of my academic portfolio demonstrating security operations capabilities. All configurations and documentation are provided for educational purposes.

**Note:** This is a controlled lab environment. All attack simulations were performed in an isolated network with proper authorization.

---

⭐ **If you find this project valuable, please give it a star!**

*Last Updated: January 2025*

# RobotLab OT/ICS Security System: 20-Week MVP Build
## **FULLY ALIGNED WITH COURSE MATERIALS + PYRAMID OF PAIN**

**Target Environment:** University RobotLab with OT/ICS devices  
**Timeline:** 20 weeks (5 months) full-time development  
**Budget:** ~$150-200/month AWS infrastructure costs  
**Core Requirement:** Cover entire Pyramid of Pain (Hash Values → TTPs) + Course Technologies

---

## Executive Summary

This 20-week build implements an **Operational Technology (OT) security system** that **fully implements the Pyramid of Pain framework** (from hash-based detection to TTP hunting) while incorporating ALL technologies from the course PDFs: Wazuh HIDS, Zeek network analysis, comprehensive CTI integration, and threat hunting frameworks.

**Critical alignment with course materials:**
- ✅ **Wazuh HIDS**: File integrity monitoring, vulnerability detection, compliance monitoring, process monitoring
- ✅ **Zeek Network Analysis**: conn.log, dns.log, http.log, ssl.log, files.log with custom scripts
- ✅ **Detection Methods**: Signature-based + Anomaly-based + Hybrid approach
- ✅ **Pyramid of Pain**: All 6 levels implemented (Hash→IP→Domain→Artifacts→Tools→TTPs)
- ✅ **CTI Integration**: MITRE ATT&CK, Cyber Kill Chain, FireEye lifecycle, threat hunting
- ✅ **APT Tracking**: Real-world APT groups (APT10, APT41, Lazarus) with TTP analysis

---

## Table of Contents

1. [Pyramid of Pain Implementation Strategy](#pyramid-of-pain-implementation-strategy)
2. [Technology Stack Alignment with Course PDFs](#technology-stack-alignment-with-course-pdfs)
3. [RobotLab Asset Inventory](#robotlab-asset-inventory)
4. [Detection Architecture: All 6 Pyramid Levels](#detection-architecture-all-6-pyramid-levels)
5. [Wazuh HIDS Implementation](#wazuh-hids-implementation)
6. [Zeek Network Monitoring](#zeek-network-monitoring)
7. [Cyber Threat Intelligence Integration](#cyber-threat-intelligence-integration)
8. [Threat Hunting Implementation](#threat-hunting-implementation)
9. [Complete Technical Architecture](#complete-technical-architecture)
10. [20-Week Build Plan](#20-week-build-plan)

---

## Pyramid of Pain Implementation Strategy

**Framework by David Bianco (2013)**: The Pyramid of Pain categorizes threat indicators from easiest-to-change (least pain to attacker) to hardest-to-change (highest pain).

```
                    ┌─────────────────────┐
                    │   Level 6: TTPs     │ ← HIGHEST PAIN (Focus here)
                    │  (Tactics/Techniques│
                    │    /Procedures)     │
                    └─────────────────────┘
                  ┌─────────────────────────┐
                  │   Level 5: Tools        │ ← VERY HIGH PAIN
                  │  (Malware families,     │
                  │   RATs, frameworks)     │
                  └─────────────────────────┘
                ┌───────────────────────────────┐
                │ Level 4: Network/Host Artifacts│ ← HIGH PAIN
                │ (Registry keys, file paths,    │
                │  URI patterns, processes)      │
                └───────────────────────────────┘
              ┌─────────────────────────────────────┐
              │   Level 3: Domain Names             │ ← MODERATE PAIN
              │  (C2 domains, payload hosting)      │
              └─────────────────────────────────────┘
            ┌───────────────────────────────────────────┐
            │   Level 2: IP Addresses                   │ ← LOW PAIN
            │  (Source/destination IPs)                 │
            └───────────────────────────────────────────┘
          ┌─────────────────────────────────────────────────┐
          │   Level 1: Hash Values                          │ ← LOWEST PAIN
          │  (MD5, SHA-1, SHA-256 file hashes)              │
          └─────────────────────────────────────────────────┘
```

### RobotLab Implementation of Each Level

**Level 1: Hash Values (Implemented in Week 5)**
- **Tool**: Wazuh FIM (File Integrity Monitoring) + VirusTotal API
- **Detection**: Calculate SHA-256 hashes of all executable files
- **CTI Integration**: Query VirusTotal, AlienVault OTX for known malicious hashes
- **OT Context**: Monitor firmware files on robot controllers, PLC ladder logic files
- **Attacker Pain**: LOW (attacker changes 1 byte → new hash)

**Level 2: IP Addresses (Implemented in Weeks 3-4)**
- **Tool**: Suricata + Zeek conn.log + pfSense firewall logs
- **Detection**: Block known malicious IPs from threat feeds
- **CTI Integration**: CISA ICS-CERT, Recorded Future, Abuse.ch Feodo Tracker
- **OT Context**: Chinese DoBot robots connecting to 202.x.x.x IP ranges
- **Attacker Pain**: LOW (attacker uses VPN/proxy → new IP in seconds)

**Level 3: Domain Names (Implemented in Weeks 6-7)**
- **Tool**: Zeek dns.log + passive DNS analysis
- **Detection**: DNS sinkhole for known malicious domains
- **CTI Integration**: Domain reputation feeds (EmergingThreats, Cisco Umbrella)
- **OT Context**: Robot controllers querying .cn domains, DGA domain detection
- **Attacker Pain**: MODERATE (domain registration takes time, costs money)

**Level 4: Network/Host Artifacts (Implemented in Weeks 8-13)**
- **Network Artifacts**:
  - **Tool**: Zeek (http.log, ssl.log) + Suricata
  - **Detection**: URI patterns (e.g., `/gate.php?id=`), unique HTTP headers, JA3 TLS fingerprints
  - **OT Context**: Modbus TCP anomalies, OPC UA method calls, proprietary robot protocol violations
  
- **Host Artifacts**:
  - **Tool**: Wazuh FIM + Sysmon + Registry monitoring
  - **Detection**: Registry run keys, dropped files in `%TEMP%`, malicious processes, scheduled tasks
  - **OT Context**: PLC ladder logic modifications, robot controller config file changes
  
- **Attacker Pain**: HIGH (requires retooling, changing operational methods)

**Level 5: Tools (Implemented in Weeks 14-15)**
- **Tool**: Wazuh process monitoring + Yara rules + CTI correlation
- **Detection**: Specific malware families (Cobalt Strike, Metasploit, Mimikatz, PSExec)
- **CTI Integration**: MISP (Malware Information Sharing Platform)
- **OT Context**: Detect ICS-specific tools (ISF, PLCinject, Modbus Penetration Testing Framework)
- **Attacker Pain**: VERY HIGH (developing new tools is expensive, time-consuming)

**Level 6: TTPs (Implemented in Weeks 16-20)**
- **Tool**: MITRE ATT&CK for ICS mapping + Threat hunting queries + Behavioral analysis
- **Detection**: Multi-stage attack patterns (Initial Access → Execution → Persistence → Lateral Movement → Exfiltration)
- **Frameworks Used**: 
  - Lockheed Martin Cyber Kill Chain
  - MITRE ATT&CK for ICS (12 tactics, 81 techniques)
  - FireEye Attack Lifecycle
  - Gartner Cyber Attack Model
- **OT Context**: Stuxnet-style PLC manipulation, Triton safety system targeting, Industroyer power grid attacks
- **Attacker Pain**: HIGHEST (requires fundamental operational change)

---

## Technology Stack Alignment with Course PDFs

### Mandatory Technologies from Course Materials

| Technology | Course Requirement | RobotLab Implementation | Week |
|------------|-------------------|------------------------|------|
| **Wazuh HIDS** | PDF 1: "Comprehensive open-source cybersecurity platform" | ✅ Wazuh 4.12 on Windows/Linux/Raspberry Pi | Week 5-6 |
| **Wazuh FIM** | PDF 1: "Integrity monitoring" | ✅ Monitor firmware files, PLC ladder logic, configs | Week 5 |
| **Wazuh Vulnerability Detection** | PDF 1: Demo 1 | ✅ Scan for CVEs in OT devices, generate alerts | Week 6 |
| **Wazuh Process Monitoring** | PDF 1: Demo 4 (ossec.conf localfile) | ✅ Detect unauthorized processes (netcat, backdoors) | Week 6 |
| **Sysmon** | PDF 1: Windows monitoring | ✅ Sysmon v15 on Windows workstations | Week 6 |
| **Zeek** | PDF 2: "Open-source passive network monitoring" | ✅ Zeek 6.0 on Raspberry Pi aggregator | Week 3-4 |
| **Zeek Logs** | PDF 2: conn.log, dns.log, http.log, ssl.log, files.log | ✅ All logs forwarded to ClickHouse | Week 4 |
| **Zeek Scripts** | PDF 2: Custom detection scripts | ✅ Custom scripts for Modbus, OPC UA protocols | Week 12 |
| **Suricata** | PDF 1: "Snort, Suricata" | ✅ Suricata 7.0 on pfSense firewall | Week 3 |
| **Signature-Based Detection** | PDF 1 & 2: Detection method | ✅ Suricata ET Open rules + Wazuh signatures | Week 7 |
| **Anomaly-Based Detection** | PDF 1 & 2: Detection method | ✅ Zeek anomaly detection + Wazuh behavioral rules | Week 13 |
| **MITRE ATT&CK** | PDF 3: "Cyber Threat Kill Chain framework" | ✅ MITRE ATT&CK for ICS (12 tactics, 81 techniques) | Week 14 |
| **Pyramid of Pain** | PDF 3: All 6 levels | ✅ Hash→IP→Domain→Artifacts→Tools→TTPs | Weeks 5-20 |
| **CTI Feeds** | PDF 3: "Integrate trusted threat intelligence feeds" | ✅ CISA ICS-CERT, Recorded Future, AlienVault OTX | Week 14-15 |
| **Threat Hunting** | PDF 3: "Proactively searching for cyber threats" | ✅ Hypothesis-driven hunting with LLM assistance | Week 17 |
| **APT Analysis** | PDF 3: "Real-World APT Groups" | ✅ APT10, APT41 tracking for Chinese robots | Week 15 |

---

## RobotLab Asset Inventory

### Complete Asset List with Detection Coverage

| Asset | Quantity | Criticality | Pyramid Levels Covered | Detection Tools |
|-------|----------|-------------|------------------------|-----------------|
| **Chinese DoBot Robots** | 5 | HIGH (8/10) | L1: Firmware hashes<br>L2: IP connections to China<br>L3: DNS queries to .cn<br>L4: Modbus anomalies<br>L5: Backdoor tools<br>L6: Supply chain TTPs | Wazuh FIM, Zeek, Suricata, CTI |
| **Chemistry Machine** | 1 | CRITICAL (10/10) | L1: Config file hashes<br>L2: Air-gapped (no IPs)<br>L4: Modbus register writes<br>L6: Safety system TTPs | Network TAP, Modbus parser |
| **PLCs (Siemens/Allen-Bradley)** | 3 | HIGH (8/10) | L1: Ladder logic hashes<br>L2: IPs accessing PLC<br>L4: Protocol violations<br>L5: PLCinject tool<br>L6: Stuxnet-style TTPs | Wazuh, Zeek, OT protocols |
| **Raspberry Pi Controllers** | 4 | MEDIUM-HIGH (7/10) | L1: Binary hashes<br>L2: SSH from unusual IPs<br>L4: New processes<br>L5: Metasploit, nc<br>L6: Lateral movement TTPs | Wazuh agent, auditd |
| **Windows Workstations** | 3 | MEDIUM (5/10) | L1: File hashes<br>L2: RDP connections<br>L4: Registry changes, dropped files<br>L5: Mimikatz, PowerShell<br>L6: Credential theft TTPs | Wazuh + Sysmon |
| **Linux Servers** | 2 | MEDIUM (5/10) | L1: Binary hashes<br>L2: SSH brute force IPs<br>L4: Cron jobs, /tmp files<br>L5: Exploit frameworks<br>L6: Persistence TTPs | Wazuh + auditd |
| **IoT Devices** | 10 | MEDIUM (5/10) | L1: Firmware hashes<br>L2: Botnet C2 IPs<br>L3: DGA domains<br>L4: MQTT patterns<br>L6: IoT botnet TTPs | Zeek, Suricata |

---

## Detection Architecture: All 6 Pyramid Levels

### Level 1: Hash-Based Detection (Wazuh FIM)

**Implementation:**

```xml
<!-- Wazuh ossec.conf: File Integrity Monitoring -->
<syscheck>
  <!-- Robot firmware files -->
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /opt/dobot/firmware
  </directories>
  
  <!-- PLC ladder logic -->
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /var/plc/programs
  </directories>
  
  <!-- Chemistry machine config -->
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /etc/chemistry_controller
  </directories>
  
  <!-- Windows executables -->
  <directories check_all="yes" realtime="yes">
    C:\Program Files
    C:\Program Files (x86)
    C:\Windows\System32
  </directories>
</syscheck>

<!-- Integration with VirusTotal API -->
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VT_API_KEY</api_key>
  <group>syscheck</group>
</integration>
```

**Detection Logic:**
```python
def detect_malicious_hash(file_event):
    """
    Level 1: Hash-based detection.
    """
    file_hash = file_event.sha256
    
    # Query VirusTotal
    vt_result = virustotal_api.get_file_report(file_hash)
    if vt_result.positives > 5:  # >5 AV vendors flag it
        alert = {
            'level': 1,  # Pyramid Level 1
            'severity': 'HIGH',
            'type': 'malicious_hash_detected',
            'file': file_event.path,
            'hash': file_hash,
            'vt_positives': vt_result.positives,
            'vt_total': vt_result.total
        }
        return alert
    
    # Check threat intel feeds
    if file_hash in cti_database.malicious_hashes:
        threat_info = cti_database.get_hash_info(file_hash)
        alert = {
            'level': 1,
            'severity': 'HIGH',
            'type': 'known_malware',
            'malware_family': threat_info.family,
            'apt_group': threat_info.apt_group
        }
        return alert
```

**OT-Specific Hash Monitoring:**
- Robot firmware updates: Alert if firmware hash doesn't match known-good
- PLC ladder logic: Detect unauthorized program modifications
- SCADA configurations: Monitor for tampering

---

### Level 2: IP Address Detection (Zeek + Suricata + Firewall)

**Implementation:**

```python
# Zeek conn.log analysis
def detect_malicious_ip(connection):
    """
    Level 2: IP-based detection.
    """
    dest_ip = connection.id_resp_h
    
    # Check if Chinese robot connecting to China
    if is_robot_ip(connection.id_orig_h) and is_chinese_ip(dest_ip):
        alert = {
            'level': 2,  # Pyramid Level 2
            'severity': 'CRITICAL',
            'type': 'supply_chain_backdoor',
            'source': connection.id_orig_h,
            'destination': dest_ip,
            'reason': 'Chinese DoBot robot connecting to IP in China',
            'cti_match': check_apt_infrastructure(dest_ip)
        }
        return alert
    
    # Check against threat intel feeds
    if dest_ip in cti_database.malicious_ips:
        threat_info = cti_database.get_ip_info(dest_ip)
        alert = {
            'level': 2,
            'severity': 'HIGH',
            'type': 'c2_connection',
            'apt_group': threat_info.apt_group,
            'last_seen': threat_info.last_seen
        }
        return alert
```

**Threat Intel Feeds for IP Detection:**
- CISA ICS-CERT: Known ICS attacker IPs
- Abuse.ch Feodo Tracker: Botnet C2 IPs
- Recorded Future: APT10, APT41 infrastructure IPs
- Emerging Threats IQRisk: Real-time IP reputation

---

### Level 3: Domain Name Detection (Zeek DNS)

**Implementation:**

```python
# Zeek dns.log analysis
def detect_malicious_domain(dns_query):
    """
    Level 3: Domain-based detection.
    """
    domain = dns_query.query
    
    # Check for .cn domains from non-Chinese assets
    if domain.endswith('.cn') and not is_expected_chinese_connection(dns_query.id_orig_h):
        alert = {
            'level': 3,  # Pyramid Level 3
            'severity': 'HIGH',
            'type': 'suspicious_tld',
            'domain': domain,
            'source': dns_query.id_orig_h,
            'reason': 'Non-Chinese asset querying .cn domain'
        }
        return alert
    
    # DGA (Domain Generation Algorithm) detection
    if is_dga_domain(domain):
        alert = {
            'level': 3,
            'severity': 'HIGH',
            'type': 'dga_domain',
            'domain': domain,
            'dga_score': calculate_entropy(domain),
            'likely_malware_family': predict_malware_from_dga(domain)
        }
        return alert
    
    # Check domain reputation
    if domain in cti_database.malicious_domains:
        threat_info = cti_database.get_domain_info(domain)
        alert = {
            'level': 3,
            'severity': 'HIGH',
            'type': 'c2_domain',
            'apt_group': threat_info.apt_group,
            'first_seen': threat_info.first_seen
        }
        return alert
```

**DNS Monitoring for OT:**
- DoBot robots: Should NOT query ANY external domains
- PLCs: Should NOT have DNS capability
- Chemistry machine: Air-gapped, no DNS

---

### Level 4: Network/Host Artifacts Detection

**Network Artifacts (Zeek + Suricata):**

```python
def detect_network_artifacts(zeek_logs):
    """
    Level 4: Network artifact detection.
    """
    # HTTP URI patterns (from Zeek http.log)
    if '/gate.php?id=' in zeek_logs.http.uri:
        alert = {
            'level': 4,  # Pyramid Level 4
            'severity': 'HIGH',
            'type': 'c2_uri_pattern',
            'uri': zeek_logs.http.uri,
            'user_agent': zeek_logs.http.user_agent,
            'known_c2_framework': 'Cobalt Strike beacon'
        }
        return alert
    
    # JA3 TLS fingerprinting (from Zeek ssl.log)
    malicious_ja3 = [
        'a0e9f5d64349fb13191bc781f81f42e1',  # Metasploit
        '6734f37431670b3ab4292b8f60f29984'   # Cobalt Strike
    ]
    if zeek_logs.ssl.ja3 in malicious_ja3:
        alert = {
            'level': 4,
            'severity': 'HIGH',
            'type': 'malicious_tls_fingerprint',
            'ja3': zeek_logs.ssl.ja3,
            'tool': map_ja3_to_tool(zeek_logs.ssl.ja3)
        }
        return alert
    
    # OT-specific: Modbus TCP anomalies
    if zeek_logs.modbus.function_code not in LEGITIMATE_MODBUS_FUNCTIONS:
        alert = {
            'level': 4,
            'severity': 'CRITICAL',
            'type': 'modbus_protocol_violation',
            'function_code': zeek_logs.modbus.function_code,
            'target': zeek_logs.modbus.dest_ip,
            'possible_attack': 'Stuxnet-style PLC manipulation'
        }
        return alert
```

**Host Artifacts (Wazuh + Sysmon):**

```python
def detect_host_artifacts(wazuh_event):
    """
    Level 4: Host artifact detection.
    """
    # Windows Registry persistence
    if 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' in wazuh_event.registry_path:
        alert = {
            'level': 4,
            'severity': 'HIGH',
            'type': 'registry_persistence',
            'registry_key': wazuh_event.registry_path,
            'value': wazuh_event.registry_value,
            'mitre_attack': 'T1547.001 (Boot or Logon Autostart)'
        }
        return alert
    
    # Dropped files in suspicious locations
    suspicious_paths = ['%TEMP%', 'C:\\ProgramData', '/tmp', '/var/tmp']
    if any(path in wazuh_event.file_path for path in suspicious_paths):
        if wazuh_event.file_extension in ['.exe', '.dll', '.ps1', '.sh']:
            alert = {
                'level': 4,
                'severity': 'MEDIUM',
                'type': 'suspicious_file_drop',
                'file_path': wazuh_event.file_path,
                'file_hash': wazuh_event.sha256,
                'mitre_attack': 'T1074.001 (Local Data Staging)'
            }
            return alert
    
    # Scheduled tasks (persistence)
    if wazuh_event.event_type == 'scheduled_task_created':
        alert = {
            'level': 4,
            'severity': 'HIGH',
            'type': 'scheduled_task_persistence',
            'task_name': wazuh_event.task_name,
            'command': wazuh_event.command,
            'mitre_attack': 'T1053.005 (Scheduled Task)'
        }
        return alert
```

---

### Level 5: Tool Detection (Wazuh + Yara + CTI)

**Implementation:**

```python
def detect_attacker_tools(wazuh_event):
    """
    Level 5: Attacker tool detection.
    """
    # Process-based tool detection
    malicious_tools = {
        'mimikatz.exe': 'Credential theft',
        'psexec.exe': 'Lateral movement',
        'nc.exe': 'Backdoor/reverse shell',
        'ncat.exe': 'Backdoor/reverse shell',
        'meterpreter': 'Metasploit payload',
        'cobalt_strike': 'Cobalt Strike beacon',
        'plcinject': 'ICS exploitation tool'
    }
    
    for tool, description in malicious_tools.items():
        if tool in wazuh_event.process_name.lower():
            alert = {
                'level': 5,  # Pyramid Level 5
                'severity': 'CRITICAL',
                'type': 'malicious_tool_detected',
                'tool': tool,
                'description': description,
                'process_id': wazuh_event.pid,
                'command_line': wazuh_event.command_line,
                'parent_process': wazuh_event.parent_process,
                'mitre_attack': map_tool_to_mitre(tool)
            }
            return alert
    
    # PowerShell encoded commands (obfuscation)
    if wazuh_event.process_name == 'powershell.exe':
        if '-encodedcommand' in wazuh_event.command_line.lower() or '-enc' in wazuh_event.command_line.lower():
            alert = {
                'level': 5,
                'severity': 'HIGH',
                'type': 'powershell_obfuscation',
                'command': wazuh_event.command_line,
                'decoded': decode_base64_powershell(wazuh_event.command_line),
                'mitre_attack': 'T1027.010 (Obfuscated Files or Information: Command Obfuscation)'
            }
            return alert
    
    # OT-specific tools
    ics_tools = {
        'isf': 'Industrial Security Framework',
        'plcscan': 'PLC scanning tool',
        's7comm': 'Siemens S7 protocol tool',
        'modbus_cli': 'Modbus manipulation tool'
    }
    
    for tool, description in ics_tools.items():
        if tool in wazuh_event.process_name.lower():
            alert = {
                'level': 5,
                'severity': 'CRITICAL',
                'type': 'ics_exploitation_tool',
                'tool': tool,
                'description': description,
                'target': identify_nearby_ot_devices(wazuh_event.source_ip)
            }
            return alert
```

---

### Level 6: TTP Detection (MITRE ATT&CK + Threat Hunting)

**Implementation:**

```python
def detect_ttps(multi_stage_events):
    """
    Level 6: TTP-based detection (HIGHEST PAIN).
    Maps to MITRE ATT&CK for ICS framework.
    """
    # Example: Detect full attack chain
    attack_chain = analyze_event_sequence(multi_stage_events)
    
    # Stuxnet-style TTP: Initial Access → Execution → Persistence → Lateral Movement → Inhibit Response Function → Impair Process Control
    if attack_chain.matches_pattern('stuxnet_style'):
        alert = {
            'level': 6,  # Pyramid Level 6
            'severity': 'CRITICAL',
            'type': 'multi_stage_ics_attack',
            'attack_pattern': 'Stuxnet-style PLC manipulation',
            'mitre_attack_tactics': [
                'TA0108: Initial Access - ICS',
                'TA0104: Lateral Movement - ICS',
                'TA0107: Impair Process Control',
                'TA0106: Inhibit Response Function'
            ],
            'techniques': [
                'T0817: Drive-by Compromise',
                'T0866: Exploitation of Remote Services',
                'T0836: Modify Parameter',
                'T0800: Activate Firmware Update Mode'
            ],
            'kill_chain_stage': 'Actions on Objectives',
            'confidence': 'HIGH',
            'recommendation': 'IMMEDIATELY isolate affected PLCs, engage incident response team'
        }
        return alert
    
    # Chinese APT supply chain compromise TTP
    if attack_chain.matches_pattern('apt41_supply_chain'):
        alert = {
            'level': 6,
            'severity': 'CRITICAL',
            'type': 'apt_supply_chain_ttp',
            'apt_group': 'APT41 (Double Dragon)',
            'mitre_attack_tactics': [
                'TA0001: Initial Access',
                'TA0002: Execution',
                'TA0003: Persistence',
                'TA0010: Exfiltration'
            ],
            'techniques': [
                'T1195.002: Supply Chain Compromise: Software Supply Chain',
                'T1071.001: Application Layer Protocol: Web Protocols',
                'T1041: Exfiltration Over C2 Channel'
            ],
            'iocs': extract_iocs_from_chain(attack_chain),
            'cti_reference': 'https://attack.mitre.org/groups/G0096/'
        }
        return alert
```

**Threat Hunting for TTPs:**

```python
# Threat hunting hypothesis: "Are there any robots performing reconnaissance on the OT network?"
def hunt_robot_reconnaissance():
    """
    Hypothesis-driven threat hunting (TTP-level).
    """
    query = """
    SELECT 
        source_ip,
        destination_ip,
        COUNT(DISTINCT destination_port) as ports_scanned,
        COUNT(*) as connection_attempts,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen
    FROM zeek_conn_log
    WHERE source_ip IN (SELECT ip FROM robot_inventory)
      AND timestamp >= now() - INTERVAL '24 hours'
    GROUP BY source_ip, destination_ip
    HAVING ports_scanned > 10  -- Likely port scan
    ORDER BY ports_scanned DESC
    """
    
    results = clickhouse.execute(query)
    
    if results:
        alert = {
            'level': 6,
            'severity': 'HIGH',
            'type': 'ttp_reconnaissance',
            'mitre_attack': 'T0888: Remote System Discovery (ICS)',
            'evidence': results,
            'hypothesis': 'Robot performing network reconnaissance',
            'recommendation': 'Investigate robot firmware for backdoor, check for C2 communication'
        }
        return alert
```

---

## Wazuh HIDS Implementation

### Wazuh Architecture for RobotLab

```
┌────────────────────────────────────────────────────────────────┐
│ Wazuh Manager (Docker on Raspberry Pi 4 or small server)      │
├────────────────────────────────────────────────────────────────┤
│ • Analyzes events from all agents                              │
│ • Applies detection rules (signatures + anomaly)               │
│ • Sends alerts to ClickHouse + PostgreSQL                      │
│ • Manages agent updates and configuration                      │
└───────────────────────┬────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌──────────────────┐          ┌──────────────────┐
│ Wazuh Agents     │          │ Wazuh Agents     │
│ (Windows x3)     │          │ (Linux/RPi x6)   │
├──────────────────┤          ├──────────────────┤
│ • Sysmon v15     │          │ • Auditd         │
│ • PowerShell log │          │ • Osquery        │
│ • Event Logs     │          │ • FIM            │
│ • FIM            │          │ • Process mon    │
└──────────────────┘          └──────────────────┘
```

### Wazuh Configuration Examples

**1. File Integrity Monitoring (FIM)**

```xml
<!-- /var/ossec/etc/ossec.conf on Wazuh Manager -->
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency> <!-- Check every 5 minutes -->
  <scan_on_start>yes</scan_on_start>
  
  <!-- Monitor robot firmware -->
  <directories check_all="yes" realtime="yes" report_changes="yes" restrict="\.bin$|\.hex$">
    /opt/dobot/firmware
  </directories>
  
  <!-- Monitor PLC programs -->
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /var/plc/programs
  </directories>
  
  <!-- Monitor Windows system directories -->
  <directories check_all="yes" realtime="yes">
    C:\Windows\System32
    C:\Program Files
  </directories>
  
  <!-- Alert on checksum changes -->
  <alert_new_files>yes</alert_new_files>
</syscheck>
```

**2. Process Monitoring (from PDF Demo 4)**

```xml
<!-- /var/ossec/etc/ossec.conf on Agent -->
<localfile>
  <log_format>full_command</log_format>
  <alias>process list</alias>
  <command>ps -e -o pid,uname,command</command>
  <frequency>30</frequency> <!-- Every 30 seconds -->
</localfile>

<!-- /var/ossec/etc/rules/local_rules.xml on Manager -->
<group name="ossec,">
  <rule id="100050" level="0">
    <if_sid>530</if_sid>
    <match>^ossec: output: 'process list'</match>
    <description>List of running processes.</description>
    <group>process_monitor,</group>
  </rule>
  
  <!-- Detect netcat backdoor -->
  <rule id="100051" level="10">
    <if_sid>100050</if_sid>
    <match>nc -l</match>
    <description>Netcat listening for incoming connections (Level 5: Tools).</description>
    <mitre>
      <id>T1021.002</id> <!-- Remote Services: SMB/Windows Admin Shares -->
    </mitre>
  </rule>
  
  <!-- Detect Mimikatz -->
  <rule id="100052" level="12">
    <if_sid>100050</if_sid>
    <match>mimikatz</match>
    <description>Mimikatz credential theft tool detected (Level 5: Tools).</description>
    <mitre>
      <id>T1003.001</id> <!-- OS Credential Dumping: LSASS Memory -->
    </mitre>
  </rule>
  
  <!-- Detect ICS exploitation tools -->
  <rule id="100053" level="15">
    <if_sid>100050</if_sid>
    <regex>plcinject|isf|s7comm|modbus_cli</regex>
    <description>ICS exploitation tool detected (Level 5: Tools - OT).</description>
    <mitre>
      <id>T0866</id> <!-- Exploitation of Remote Services - ICS -->
    </mitre>
  </rule>
</group>
```

**3. Vulnerability Detection (from PDF Demo 1)**

```xml
<!-- /var/ossec/etc/ossec.conf on Manager -->
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>1d</interval> <!-- Scan once per day -->
  
  <!-- Scan Ubuntu packages -->
  <provider name="canonical">
    <enabled>yes</enabled>
    <os>bionic</os>
    <update_interval>1h</update_interval>
  </provider>
  
  <!-- Scan Windows updates -->
  <provider name="msu">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

**4. Brute Force Detection (from PDF Demo 2)**

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="syslog,sshd,">
  <rule id="100100" level="10" frequency="5" timeframe="300">
    <if_matched_sid>5710</if_matched_sid> <!-- Failed SSH authentication -->
    <description>SSH brute force attack detected (Level 6: TTPs).</description>
    <same_source_ip />
    <mitre>
      <id>T1110</id> <!-- Brute Force -->
    </mitre>
  </rule>
</group>
```

---

## Zeek Network Monitoring

### Zeek Architecture for RobotLab

```
┌────────────────────────────────────────────────────────────┐
│ Zeek Deployment (on Raspberry Pi 4 Data Aggregator)       │
├────────────────────────────────────────────────────────────┤
│ • Passive monitoring via SPAN port                         │
│ • Analyzes all network traffic (IT + OT)                   │
│ • Generates 50+ log types                                  │
│ • Custom scripts for OT protocols (Modbus, OPC UA)         │
└───────────────────────┬────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────────┐
│ Zeek Log Files (forwarded to ClickHouse via Filebeat)     │
├────────────────────────────────────────────────────────────┤
│ • conn.log: TCP/UDP/ICMP connections                       │
│ • http.log: HTTP requests/responses                        │
│ • dns.log: DNS queries/responses                           │
│ • ssl.log: TLS/SSL connection details + JA3 fingerprints   │
│ • files.log: Files transferred over network                │
│ • weird.log: Abnormal/unexpected traffic patterns          │
│ • Custom: modbus.log, opcua.log                            │
└────────────────────────────────────────────────────────────┘
```

### Zeek Configuration

**1. networks.cfg (Define internal networks)**

```
# /opt/zeek/etc/networks.cfg
# Management VLAN
192.168.10.0/24     Management

# Raspberry Pi VLAN
192.168.20.0/24     RaspberryPi

# Windows/Linux VLAN
192.168.30.0/24     IT_Assets

# PLC Control VLAN
192.168.100.0/24    PLC_Control   # HIGH SENSITIVITY

# Robot Control VLAN
192.168.110.0/24    Robot_Control # HIGH SENSITIVITY

# Chemistry Machine VLAN (air-gapped)
192.168.200.0/24    Chemistry_Critical # CRITICAL - PASSIVE ONLY
```

**2. Custom Zeek Scripts for OT Monitoring**

```zeek
# /opt/zeek/share/zeek/site/modbus-detection.zeek
# Custom Modbus protocol analysis

@load base/protocols/conn

module ModbusDetection;

export {
    redef enum Notice::Type += {
        Modbus_Invalid_Function_Code,
        Modbus_Unauthorized_Write,
        Modbus_Timing_Anomaly
    };
}

# Detect invalid Modbus function codes
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    local legitimate_codes = set(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10);
    
    if (headers$function_code !in legitimate_codes) {
        NOTICE([$note=Modbus_Invalid_Function_Code,
                $msg=fmt("Invalid Modbus function code 0x%02x from %s", 
                         headers$function_code, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, headers$function_code)]);
    }
}

# Detect writes to read-only registers (example: PLC configuration registers)
event modbus_write_register_request(c: connection, headers: ModbusHeaders, address: count, value: count) {
    # Define read-only register ranges (PLC-specific)
    local readonly_start = 40000;
    local readonly_end = 40100;
    
    if (address >= readonly_start && address <= readonly_end) {
        NOTICE([$note=Modbus_Unauthorized_Write,
                $msg=fmt("Write to read-only Modbus register %d from %s (Level 4: Artifacts)", 
                         address, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, address)]);
    }
}
```

**3. Zeek Detection of Chinese Robot Backdoor**

```zeek
# /opt/zeek/share/zeek/site/chinese-robot-detection.zeek

@load base/protocols/dns
@load base/protocols/conn

module ChineseRobotDetection;

export {
    redef enum Notice::Type += {
        Robot_China_Connection,
        Robot_CN_Domain_Query
    };
    
    # Define robot IP addresses
    const robot_ips: set[addr] = {
        192.168.110.10,  # DoBot robot 1
        192.168.110.11,  # DoBot robot 2
        192.168.110.12,  # DoBot robot 3
        192.168.110.13,  # DoBot robot 4
        192.168.110.14   # DoBot robot 5
    };
}

# Detect connections to Chinese IP ranges
event connection_state_remove(c: connection) {
    if (c$id$orig_h in robot_ips) {
        # Check if destination is in China (202.x.x.x is common Chinese range)
        if (c$id$resp_h >= 202.0.0.0 && c$id$resp_h <= 202.255.255.255) {
            NOTICE([$note=Robot_China_Connection,
                    $msg=fmt("Chinese robot %s connected to IP in China: %s (Level 2: IP + Supply Chain TTP)", 
                             c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
}

# Detect DNS queries to .cn domains
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (c$id$orig_h in robot_ips) {
        if (/.cn$/ in query) {
            NOTICE([$note=Robot_CN_Domain_Query,
                    $msg=fmt("Robot %s queried .cn domain: %s (Level 3: Domain)", 
                             c$id$orig_h, query),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, query)]);
        }
    }
}
```

---

## Cyber Threat Intelligence Integration

### CTI Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ CTI INGESTION (Lambda scheduled every 6 hours)              │
├──────────────────────────────────────────────────────────────┤
│ 1. CISA ICS-CERT RSS feed → Parse advisories                │
│ 2. MITRE ATT&CK for ICS JSON → 12 tactics, 81 techniques    │
│ 3. AlienVault OTX API → IoCs (hashes, IPs, domains)         │
│ 4. Abuse.ch Feodo Tracker → Botnet C2 IPs                   │
│ 5. Recorded Future API → APT10, APT41 tracking              │
│ 6. VirusTotal API → Malware hash reputation                 │
│                                                               │
│ Output: Normalized CTI in PostgreSQL                         │
└────────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ CTI ENRICHMENT (Real-time during detection)                 │
├──────────────────────────────────────────────────────────────┤
│ Alert generated → Query PostgreSQL CTI database:            │
│ • Is this hash in VirusTotal? (Level 1)                     │
│ • Is this IP in APT41 infrastructure? (Level 2)             │
│ • Is this domain in DGA database? (Level 3)                 │
│ • Is this artifact in MISP? (Level 4)                       │
│ • Is this tool in malware family DB? (Level 5)              │
│ • Does this behavior match Stuxnet TTPs? (Level 6)          │
│                                                               │
│ Enrich alert with CTI context for LLM analysis              │
└──────────────────────────────────────────────────────────────┘
```

### CTI Database Schema

```sql
-- PostgreSQL: Comprehensive CTI storage

-- Level 1: Hash Values
CREATE TABLE cti_malicious_hashes (
    hash_value VARCHAR(64) PRIMARY KEY,
    hash_type VARCHAR(10),  -- MD5, SHA1, SHA256
    malware_family VARCHAR(255),
    apt_group VARCHAR(255),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    vt_positives INTEGER,
    source VARCHAR(255)  -- VirusTotal, MISP, AlienVault OTX
);

-- Level 2: IP Addresses
CREATE TABLE cti_malicious_ips (
    ip_address INET PRIMARY KEY,
    apt_group VARCHAR(255),
    country_code CHAR(2),
    asn INTEGER,
    isp VARCHAR(255),
    threat_type VARCHAR(100),  -- C2, scanning, botnet
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    source VARCHAR(255)
);

-- Level 3: Domain Names
CREATE TABLE cti_malicious_domains (
    domain VARCHAR(255) PRIMARY KEY,
    apt_group VARCHAR(255),
    registrar VARCHAR(255),
    creation_date TIMESTAMP,
    threat_type VARCHAR(100),  -- C2, phishing, DGA
    is_dga BOOLEAN,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    source VARCHAR(255)
);

-- Level 4: Network/Host Artifacts
CREATE TABLE cti_artifacts (
    artifact_id SERIAL PRIMARY KEY,
    artifact_type VARCHAR(50),  -- uri_pattern, ja3, registry_key, file_path
    artifact_value TEXT,
    description TEXT,
    apt_group VARCHAR(255),
    malware_family VARCHAR(255),
    mitre_attack_id VARCHAR(20),
    source VARCHAR(255)
);

-- Level 5: Tools
CREATE TABLE cti_tools (
    tool_id SERIAL PRIMARY KEY,
    tool_name VARCHAR(255),
    tool_type VARCHAR(100),  -- RAT, backdoor, exploit_framework
    description TEXT,
    apt_groups TEXT[],  -- Array of APT groups using this tool
    detection_signatures TEXT[],
    mitre_attack_ids VARCHAR(20)[],
    source VARCHAR(255)
);

-- Level 6: TTPs (linked to MITRE ATT&CK)
CREATE TABLE cti_ttps (
    ttp_id SERIAL PRIMARY KEY,
    mitre_tactic_id VARCHAR(20),
    mitre_tactic_name VARCHAR(255),
    mitre_technique_id VARCHAR(20),
    mitre_technique_name VARCHAR(255),
    description TEXT,
    detection_logic TEXT,  -- How to detect this TTP
    apt_groups TEXT[],
    ics_specific BOOLEAN DEFAULT FALSE
);

-- CISA ICS-CERT Advisories
CREATE TABLE cti_cisa_advisories (
    advisory_id VARCHAR(50) PRIMARY KEY,
    title TEXT,
    summary TEXT,
    severity VARCHAR(20),
    cve_ids VARCHAR(20)[],
    affected_products TEXT[],
    mitre_attack_ids VARCHAR(20)[],
    published_date TIMESTAMP,
    updated_date TIMESTAMP
);

-- APT Group Profiles
CREATE TABLE cti_apt_groups (
    apt_group_name VARCHAR(255) PRIMARY KEY,
    aliases TEXT[],
    country_origin VARCHAR(50),
    targets TEXT[],  -- industries, countries
    motivations TEXT[],  -- espionage, financial, disruption
    tools_used TEXT[],
    ttps TEXT[],
    notable_campaigns TEXT[],
    mitre_group_id VARCHAR(20)
);
```

---

## Threat Hunting Implementation

### Threat Hunting Frameworks

**Four frameworks covered in course PDFs:**

1. **Lockheed Martin Cyber Kill Chain**
2. **FireEye Attack Lifecycle**
3. **Gartner Cyber Attack Model**
4. **MITRE ATT&CK Framework** (primary for implementation)

### Hypothesis-Driven Threat Hunting

```python
# Threat Hunting Engine

class ThreatHuntingEngine:
    def __init__(self):
        self.frameworks = {
            'kill_chain': LockheedMartinKillChain(),
            'attack': MITREAttackICS(),
            'fireeye': FireEyeLifecycle()
        }
    
    def hunt_hypothesis_1_robot_recon(self):
        """
        Hypothesis: Chinese robots are performing network reconnaissance
        TTP: T0888 (Remote System Discovery - ICS)
        """
        query = """
        SELECT 
            r.robot_id,
            r.ip_address as source_ip,
            z.dest_ip,
            COUNT(DISTINCT z.dest_port) as unique_ports,
            COUNT(*) as connection_attempts,
            array_agg(DISTINCT z.dest_port) as ports_scanned
        FROM zeek_conn_log z
        JOIN robot_inventory r ON z.source_ip = r.ip_address
        WHERE z.timestamp >= now() - INTERVAL '24 hours'
          AND r.manufacturer = 'DoBot'
        GROUP BY r.robot_id, r.ip_address, z.dest_ip
        HAVING COUNT(DISTINCT z.dest_port) > 10
        ORDER BY unique_ports DESC
        """
        
        results = clickhouse.execute(query)
        
        if results:
            return {
                'hunt_id': 'H001',
                'hypothesis': 'Robot reconnaissance activity',
                'pyramid_level': 6,  # TTPs
                'mitre_attack': 'T0888: Remote System Discovery',
                'kill_chain_phase': 'Reconnaissance',
                'evidence': results,
                'confidence': 'HIGH',
                'recommendation': 'Isolate robot, analyze firmware for backdoor'
            }
    
    def hunt_hypothesis_2_credential_theft(self):
        """
        Hypothesis: LSASS memory dumping attempts (Mimikatz-style)
        TTP: T1003.001 (OS Credential Dumping: LSASS Memory)
        """
        query = """
        SELECT 
            w.host,
            w.process_name,
            w.parent_process,
            w.command_line,
            w.timestamp
        FROM wazuh_events w
        WHERE w.timestamp >= now() - INTERVAL '7 days'
          AND (
              w.process_name LIKE '%lsass%'
              OR w.command_line LIKE '%sekurlsa%'
              OR w.command_line LIKE '%procdump%lsass%'
          )
        ORDER BY w.timestamp DESC
        """
        
        results = clickhouse.execute(query)
        
        if results:
            return {
                'hunt_id': 'H002',
                'hypothesis': 'Credential theft via LSASS dumping',
                'pyramid_level': 5,  # Tools (Mimikatz)
                'mitre_attack': 'T1003.001: LSASS Memory',
                'kill_chain_phase': 'Credential Access',
                'evidence': results,
                'confidence': 'HIGH',
                'recommendation': 'Force password reset, check for lateral movement'
            }
    
    def hunt_hypothesis_3_c2_beaconing(self):
        """
        Hypothesis: Command and Control beaconing (periodic connections)
        TTP: T1071.001 (Application Layer Protocol: Web Protocols)
        """
        query = """
        WITH connection_intervals AS (
            SELECT 
                source_ip,
                dest_ip,
                dest_port,
                timestamp,
                LEAD(timestamp) OVER (
                    PARTITION BY source_ip, dest_ip, dest_port 
                    ORDER BY timestamp
                ) - timestamp AS time_diff
            FROM zeek_conn_log
            WHERE timestamp >= now() - INTERVAL '24 hours'
              AND dest_port IN (80, 443, 8080)
        )
        SELECT 
            source_ip,
            dest_ip,
            dest_port,
            AVG(time_diff) as avg_interval,
            STDDEV(time_diff) as stddev_interval,
            COUNT(*) as connection_count
        FROM connection_intervals
        WHERE time_diff IS NOT NULL
        GROUP BY source_ip, dest_ip, dest_port
        HAVING STDDEV(time_diff) < 5  -- Very consistent timing (likely beacon)
           AND connection_count > 20
        ORDER BY stddev_interval ASC
        """
        
        results = clickhouse.execute(query)
        
        if results:
            return {
                'hunt_id': 'H003',
                'hypothesis': 'C2 beaconing detected',
                'pyramid_level': 4,  # Network artifacts
                'mitre_attack': 'T1071.001: Web Protocols',
                'kill_chain_phase': 'Command and Control',
                'evidence': results,
                'confidence': 'MEDIUM',
                'recommendation': 'Analyze destination, check for data exfiltration'
            }
```

---

## Complete Technical Architecture

### Full System Diagram

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║           ROBOTLAB OT/ICS SECURITY - PYRAMID OF PAIN ARCHITECTURE             ║
║                    (Aligned with Course PDFs)                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DATA SOURCES (On-Premises RobotLab)                                  │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Windows (3) │  │ Linux (2)   │  │ Raspberry   │  │ OT Devices  │         │
│  │ Workstations│  │ Servers     │  │ Pi (4)      │  │ (13)        │         │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤  ├─────────────┤         │
│  │ Wazuh Agent │  │ Wazuh Agent │  │ Wazuh Agent │  │ Passive Mon │         │
│  │ + Sysmon    │  │ + Auditd    │  │ + Auditd    │  │ (No agents) │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         └────────────────┴────────────────┴────────────────┘                  │
│                                    │                                           │
└────────────────────────────────────┼───────────────────────────────────────────┘
                                     │
                   ┌─────────────────┴─────────────────┐
                   │                                   │
                   ▼                                   ▼
         ┌──────────────────┐             ┌──────────────────┐
         │ Wazuh Manager    │             │ Zeek + Suricata  │
         │ (Docker)         │             │ (Raspberry Pi)   │
         ├──────────────────┤             ├──────────────────┤
         │ • FIM (Level 1)  │             │ • conn.log       │
         │ • Process mon    │             │ • dns.log        │
         │   (Level 5)      │             │ • http.log       │
         │ • Vuln scan      │             │ • ssl.log        │
         │ • Rules engine   │             │ • files.log      │
         └────────┬─────────┘             └────────┬─────────┘
                  │                                 │
                  └────────────┬────────────────────┘
                               │ Filebeat
                               ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: INGESTION (AWS Cloud)                                                │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  Kinesis Firehose → Lambda (ot-event-processor) → Storage                     │
│                                                                                │
│  Processing:                                                                  │
│  1. Parse events (Wazuh JSON, Zeek logs, Suricata EVE)                       │
│  2. Pyramid Level classification                                              │
│  3. CTI correlation (check all 6 levels)                                      │
│  4. MITRE ATT&CK mapping                                                       │
│  5. Detection rule matching (signature + anomaly)                             │
│                                                                                │
└────────────────────────────┬──────────────────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: STORAGE & CTI                                                        │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌──────────────────┐  ┌──────────────────────────────────────────┐          │
│  │ ClickHouse       │  │ PostgreSQL (RDS)                         │          │
│  │ (EC2 t4g.small)  │  │ (db.t4g.micro)                           │          │
│  ├──────────────────┤  ├──────────────────────────────────────────┤          │
│  │ • Raw telemetry  │  │ • CTI database (all 6 pyramid levels):   │          │
│  │ • Zeek logs      │  │   - cti_malicious_hashes (L1)            │          │
│  │ • Wazuh events   │  │   - cti_malicious_ips (L2)               │          │
│  │ • 90-day hot     │  │   - cti_malicious_domains (L3)           │          │
│  └──────────────────┘  │   - cti_artifacts (L4)                   │          │
│                        │   - cti_tools (L5)                       │          │
│                        │   - cti_ttps (L6)                        │          │
│                        │ • MITRE ATT&CK for ICS (12 tactics, 81T) │          │
│                        │ • CISA ICS-CERT advisories               │          │
│                        │ • APT group profiles                     │          │
│                        └──────────────────────────────────────────┘          │
│                                                                                │
└────────────────────────────┬───────────────────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: AI-POWERED ANALYSIS (AWS Bedrock)                                    │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  SQS → Lambda (llm-analyzer) → Bedrock (Claude)                               │
│                                                                                │
│  Context Building:                                                            │
│  • Alert details with pyramid level                                           │
│  • CTI enrichment (L1-L6 indicators)                                          │
│  • MITRE ATT&CK technique mapping                                             │
│  • Threat hunting hypothesis correlation                                      │
│  • Kill chain phase identification                                            │
│                                                                                │
│  LLM Output:                                                                  │
│  • Risk assessment with pyramid context                                       │
│  • APT attribution (if applicable)                                            │
│  • Recommended response actions                                               │
│  • Forensics collection checklist                                             │
│                                                                                │
└────────────────────────────┬───────────────────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5: DASHBOARD & THREAT HUNTING (React Web UI)                            │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  Views:                                                                       │
│  • Pyramid of Pain heatmap (alerts by level)                                  │
│  • MITRE ATT&CK for ICS coverage matrix                                       │
│  • Cyber Kill Chain timeline                                                  │
│  • CTI dashboard (latest APT activity, CVEs)                                  │
│  • Threat hunting workspace (run hypothesis queries)                          │
│  • Network topology (Purdue Model visualization)                              │
│                                                                                │
└───────────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════════════╗
║ COST: ~$150-200/month for 20-30 monitored devices                             ║
║ PYRAMID COVERAGE: All 6 levels implemented (Hash→IP→Domain→Artifacts→Tools→TTPs) ║
║ CTI FEEDS: CISA, MITRE ATT&CK, AlienVault OTX, Recorded Future, VirusTotal    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 20-Week Build Plan

### Phase 1: Infrastructure & Network Segmentation (Weeks 1-4)

**Week 1: Asset Inventory & Planning**
- Day 1-2: Complete asset inventory (document all devices, IPs, criticality)
- Day 3: Pyramid of Pain requirements analysis (map assets to pyramid levels)
- Day 4: CTI feed selection and API keys (CISA, AlienVault OTX, VirusTotal, Recorded Future)
- Day 5: Procure hardware (managed switch, pfSense, Raspberry Pi, network TAPs)

**Week 2: Network Segmentation**
- Day 1-2: Configure VLANs (10, 20, 30, 100, 110, 200)
- Day 3: Deploy pfSense firewall, implement zero-trust rules
- Day 4: Install network TAP on chemistry machine VLAN
- Day 5: Test VLAN isolation, verify no cross-VLAN traffic

**Week 3: Network IDS Deployment**
- Day 1-2: Configure Suricata on pfSense (ET Open + ET Pro rules)
- Day 3-4: Deploy Zeek on Raspberry Pi (SPAN port monitoring)
- Day 5: Verify Suricata + Zeek capturing traffic, generating logs

**Week 4: Zeek Custom Scripts**
- Day 1-2: Implement Zeek custom scripts for Modbus protocol
- Day 3: Implement Chinese robot detection script (IP + domain monitoring)
- Day 4: Implement C2 beaconing detection script
- Day 5: Test custom scripts with sample traffic

**Deliverables**: Fully segmented network, NIDS operational, Zeek custom scripts detecting OT protocols

---

### Phase 2: Host Monitoring (Weeks 5-7) - Pyramid Levels 1, 5

**Week 5: Wazuh Deployment + Level 1 (Hash)**
- Day 1: Deploy Wazuh manager (Docker on server)
- Day 2: Install Wazuh agents on Windows workstations (3)
- Day 3: Install Wazuh agents on Linux servers + Raspberry Pis (6)
- Day 4: Configure Wazuh FIM (File Integrity Monitoring) for firmware, PLC programs
- Day 5: Integrate VirusTotal API for hash reputation checks

**Week 6: Sysmon + Process Monitoring (Level 5: Tools)**
- Day 1-2: Deploy Sysmon v15 on Windows (SwiftOnSecurity config)
- Day 3: Configure Wazuh process monitoring (from PDF Demo 4)
- Day 4: Add detection rules for malicious tools (Mimikatz, nc, PSExec, ICS tools)
- Day 5: Test tool detection with benign tools (netcat, PowerShell)

**Week 7: Vulnerability Detection**
- Day 1-2: Configure Wazuh vulnerability detector (from PDF Demo 1)
- Day 3: Scan all endpoints for CVEs, generate vulnerability reports
- Day 4: Cross-reference with CISA ICS-CERT advisories
- Day 5: Prioritize OT-specific CVEs for patching

**Deliverables**: 9 endpoints monitored with Wazuh, FIM operational (L1), tool detection working (L5)

---

### Phase 3: Cloud Infrastructure (Weeks 8-10)

**Week 8: AWS Infrastructure**
- Day 1-2: Terraform templates (VPC, security groups)
- Day 3: Deploy RDS PostgreSQL (t4g.micro) for CTI + metadata
- Day 4: Deploy ClickHouse on EC2 t4g.small for telemetry
- Day 5: S3 buckets for archival, KMS encryption

**Week 9: Data Pipeline**
- Day 1-2: Kinesis Firehose setup
- Day 3-4: Lambda function: ot-event-processor (parse Wazuh + Zeek logs)
- Day 5: Test end-to-end: Wazuh/Zeek → Firehose → Lambda → ClickHouse

**Week 10: ClickHouse Schema**
- Day 1: ClickHouse schema for Wazuh events
- Day 2: ClickHouse schema for Zeek logs (conn, dns, http, ssl, files)
- Day 3: Optimize queries for threat hunting
- Day 4-5: Test query performance (1M events, sub-second response)

**Deliverables**: Cloud infrastructure operational, data flowing to ClickHouse

---

### Phase 4: Pyramid Levels 2-4 (Weeks 11-13)

**Week 11: Level 2 (IP Addresses)**
- Day 1-2: Implement IP reputation checking (AlienVault OTX, Abuse.ch)
- Day 3: Chinese robot IP detection (202.x.x.x ranges)
- Day 4: Bot detection via Zeek conn.log analysis
- Day 5: Firewall auto-block for high-confidence malicious IPs

**Week 12: Level 3 (Domain Names)**
- Day 1-2: DNS monitoring via Zeek dns.log
- Day 3: DGA domain detection (entropy analysis)
- Day 4: .cn domain alerting for robots
- Day 5: DNS sinkhole implementation

**Week 13: Level 4 (Network/Host Artifacts)**
- Day 1-2: HTTP URI pattern detection (C2 indicators)
- Day 3: JA3 TLS fingerprinting (Cobalt Strike, Metasploit)
- Day 4: Modbus protocol violation detection
- Day 5: Host artifacts: registry keys, dropped files, scheduled tasks

**Deliverables**: Pyramid Levels 1-5 implemented, Level 6 (TTPs) in progress

---

### Phase 5: CTI Integration (Weeks 14-15) - All Pyramid Levels

**Week 14: CTI Database & Feeds**
- Day 1: PostgreSQL CTI schema (6 tables for pyramid levels)
- Day 2: CISA ICS-CERT RSS feed ingestion (Lambda)
- Day 3: MITRE ATT&CK for ICS JSON download and parsing
- Day 4: AlienVault OTX API integration
- Day 5: Recorded Future API integration (APT tracking)

**Week 15: CTI Correlation Engine**
- Day 1-2: Implement CTI correlation in ot-event-processor Lambda
- Day 3: Cross-reference all pyramid levels with CTI
- Day 4: APT attribution logic (APT10, APT41)
- Day 5: Test CTI enrichment with known malicious indicators

**Deliverables**: CTI feeds operational, alerts enriched with APT context

---

### Phase 6: Level 6 (TTPs) + Threat Hunting (Weeks 16-17)

**Week 16: MITRE ATT&CK Mapping**
- Day 1-2: Map all detection rules to MITRE ATT&CK for ICS techniques
- Day 3: Implement TTP detection (multi-stage attack patterns)
- Day 4: Cyber Kill Chain phase tagging
- Day 5: Test TTP detection with simulated Stuxnet-style attack

**Week 17: Threat Hunting**
- Day 1-2: Implement hypothesis-driven hunting queries
- Day 3: Build threat hunting dashboard
- Day 4: Test hunting hypotheses (robot recon, credential theft, C2 beaconing)
- Day 5: Document hunting playbooks

**Deliverables**: Level 6 (TTPs) operational, threat hunting framework ready

---

### Phase 7: AI Integration (Weeks 18-19)

**Week 18: Bedrock Integration**
- Day 1: AWS Bedrock setup, test Claude 3 Haiku
- Day 2: SQS queue for alert processing
- Day 3: Lambda: llm-analyzer with CTI context retrieval
- Day 4-5: Prompt engineering (include pyramid level, CTI, MITRE ATT&CK)

**Week 19: Dashboard**
- Day 1-2: API Gateway + Lambda backend
- Day 3: React dashboard with Pyramid of Pain heatmap
- Day 4: MITRE ATT&CK coverage matrix
- Day 5: Threat hunting workspace

**Deliverables**: AI-powered analysis operational, dashboard functional

---

### Phase 8: Penetration Testing (Week 20)

**Week 20: Comprehensive Testing - Validate All Pyramid Levels**
- Day 1: Test Level 1 (Hash) - Upload malware samples, verify VirusTotal detection
- Day 2: Test Level 2-3 (IP/Domain) - Simulate C2 connections to known malicious IPs/domains
- Day 3: Test Level 4 (Artifacts) - Simulate Modbus attacks, registry persistence
- Day 4: Test Level 5 (Tools) - Execute Mimikatz, nc, verify detection
- Day 5: Test Level 6 (TTPs) - Multi-stage attack simulation (Stuxnet-style)

**Penetration Test Scenarios:**
1. **Supply Chain Attack**: Chinese robot backdoor simulation
2. **Credential Theft Chain**: Phishing → Mimikatz → Lateral Movement
3. **PLC Manipulation**: Stuxnet-style Modbus write attack
4. **Ransomware**: File encryption simulation
5. **APT Campaign**: Multi-week persistent threat emulation

**Pass Criteria**: Detect 5/5 scenarios with correct pyramid level classification

---

## Conclusion

This RobotLab OT/ICS security system is **100% aligned with course materials**, implementing:

✅ **All Course Technologies**: Wazuh HIDS, Zeek network analysis, Suricata, Sysmon, CTI feeds  
✅ **Complete Pyramid of Pain**: All 6 levels (Hash→IP→Domain→Artifacts→Tools→TTPs)  
✅ **Detection Methods**: Signature-based + Anomaly-based + Hybrid approach  
✅ **MITRE ATT&CK for ICS**: 12 tactics, 81 techniques mapped  
✅ **Threat Hunting**: Hypothesis-driven with 4 frameworks (Kill Chain, ATT&CK, FireEye, Gartner)  
✅ **CTI Integration**: CISA, AlienVault OTX, Recorded Future, VirusTotal, MISP  
✅ **APT Tracking**: Real-world groups (APT10, APT41, Lazarus) with TTP analysis  
✅ **OT-Specific**: Modbus/OPC UA protocol validation, supply chain monitoring, safety-first architecture  

**Focus on TTPs (Highest Pyramid Level)**: The system prioritizes TTP-based detection because it causes the **highest pain to attackers** - they must fundamentally change how they operate, not just swap hashes or IPs.

**Budget**: $150-200/month for 20-30 monitored devices  
**Timeline**: 20 weeks full-time  
**Outcome**: Production-ready OT security system passing penetration tests

This project demonstrates mastery of cybersecurity monitoring, threat intelligence, and OT/ICS security - ready for university presentation and real-world deployment.

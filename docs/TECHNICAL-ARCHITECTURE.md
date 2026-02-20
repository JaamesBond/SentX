# RobotLab OT/ICS Security: Technical Architecture
**Version 3.0 - Research Platform Design**

**Purpose:** Complete technical reference for system architecture, packet analysis, SDN design, and detection engineering
**Audience:** Engineers, researchers, academic reviewers
**Companion Document:** `EXECUTION-PLAN.md` (22-week build timeline, 7-person team)

---

## Executive Summary

Research-grade OT/ICS security platform for a university RobotLab environment, designed to advance understanding of:

- **Deep packet analysis** of OT/ICS protocols (Modbus TCP, OPC UA, EtherNet/IP, DNP3)
- **Software-Defined Networking** for programmable network security and traffic research
- **Passive, non-disruptive monitoring** of safety-critical industrial systems
- **Pyramid of Pain (L1–L5)** — Hash, IP, Domain, Artifacts, Tools — fully implemented
- **MITRE ATT&CK for ICS** alert tagging across 81 techniques
- **Statistical detection methods** without machine learning dependencies

> **Pyramid of Pain scope:** Levels 1–5 are fully implemented. Level 6 (TTPs) is deliberately excluded — active behavioral correlation requires autonomous agents outside this project's mandate.

**Research Contributions:**
1. Novel Zeek protocol dissectors for OT/ICS traffic (Modbus deep analysis, OPC UA session tracking)
2. SDN-based traffic steering and microsegmentation framework for RobotLab
3. Statistical C2/DGA detection methods benchmarked against OT baselines
4. Passive monitoring architecture for safety-critical environments

**Key Metrics:**
- ~$178/month operational cost
- <60s average detection latency
- <5% false positive rate
- Protocol coverage: Modbus TCP, OPC UA, EtherNet/IP, DNP3, TLS/JA3
- 7-person team, 22-week implementation

---

## 1. System Architecture Overview

### **1.1 6-Layer System Architecture**

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║           ROBOTLAB OT/ICS SECURITY ARCHITECTURE - RESEARCH PLATFORM v3.0      ║
║     Deep Packet Analysis · Software-Defined Networking · MITRE ATT&CK ICS    ║
╚═══════════════════════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DATA SOURCES (On-Premises RobotLab)                                  │
├───────────────────────────────────────────────────────────────────────────────┤
│  Windows (3) │ Linux (2) │ Raspberry Pi (4) │ OT Devices (13) │ Robots (5)   │
│  Workstations│ Servers   │ Controllers      │ PLCs/Sensors     │ DoBot Arms   │
│  Wazuh+Sysmon│ Wazuh+Aud │ Wazuh+Auditd    │ Passive Monitor  │ Passive TAP  │
└─────────────────────────────────┬─────────────────────────────────────────────┘
                                  │ Network traffic
                                  ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: SOFTWARE-DEFINED NETWORKING & NETWORK INFRASTRUCTURE                 │
├───────────────────────────────────────────────────────────────────────────────┤
│  pfSense + Suricata 7.0              OpenVSwitch (OVS) 3.x                   │
│  ├─ ET Open rules (30K+)             ├─ br-robotlab bridge (all VLANs)       │
│  ├─ ET Pro OT/ICS rules              ├─ OpenFlow 1.3 flow rules               │
│  ├─ Custom ICS signatures            ├─ Dynamic port mirroring                │
│  └─ 6 VLAN segmentation             └─ Per-VLAN traffic steering             │
│                                                                               │
│  ONOS SDN Controller                WireGuard VPN                            │
│  ├─ REST API (northbound)            ├─ ChaCha20-Poly1305                    │
│  ├─ OpenFlow southbound             └─ Monthly key rotation                  │
│  └─ Intent-based networking                                                  │
└─────────────────────────────────┬─────────────────────────────────────────────┘
                                  │ Mirrored traffic streams
                                  ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: NETWORK ANALYSIS — DEEP PACKET INSPECTION                           │
├───────────────────────────────────────────────────────────────────────────────┤
│  Zeek 6.0 — Protocol Analysis Engine              PCAP Forensics             │
│  ├─ conn.log       (all connections)              ├─ Ring buffer: 2GB        │
│  ├─ dns.log        (DNS + DGA detection)          │  (20x 100MB files)       │
│  ├─ http.log       (HTTP URI patterns)            ├─ tshark dissection       │
│  ├─ ssl.log        (TLS + JA3 fingerprinting)     ├─ Wireshark profiles      │
│  ├─ files.log      (file transfers)               └─ Forensic timeline       │
│  ├─ modbus.log     (custom: deep FC analysis)                                │
│  ├─ opcua.log      (custom: session tracking)     Statistical Detectors      │
│  ├─ ethernetip.log (custom: CIP analysis)         ├─ C2 beaconing (CV)      │
│  ├─ weird.log      (protocol anomalies)           ├─ DGA entropy analysis   │
│  └─ custom scripts (13 detection scripts)         └─ Volume exfil baseline  │
└─────────────────────────────────┬─────────────────────────────────────────────┘
                                  │
                                  ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: HOST SECURITY                                                        │
├───────────────────────────────────────────────────────────────────────────────┤
│  Wazuh 4.12                          Sysmon v15 (Windows)                    │
│  ├─ 9 agents (Win/Linux/RPi)         ├─ Process creation (Event 1)           │
│  ├─ File Integrity Monitoring        ├─ Network connections (Event 3)        │
│  │  (firmware, ladder logic)         ├─ Driver load (Event 6)                │
│  ├─ Vulnerability scanning           └─ SwiftOnSecurity config               │
│  ├─ Process monitoring               Auditd (Linux/RPi)                      │
│  └─ 50+ Sigma rules                  └─ Syscall auditing                    │
└─────────────────────────────────┬─────────────────────────────────────────────┘
                                  │ Encrypted (TLS 1.3 over VPN)
                                  ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5: CLOUD PROCESSING & STORAGE (AWS)                                    │
├───────────────────────────────────────────────────────────────────────────────┤
│  Kinesis Firehose → Lambda (ot-event-processor)                              │
│  ├─ Stage 1: Multi-protocol parsing (Wazuh, Zeek, Suricata)                 │
│  ├─ Stage 2: Protocol validation (Modbus, OPC UA)                           │
│  ├─ Stage 3: Baseline deviation detection                                   │
│  ├─ Stage 4: Sigma rule matching (50+ rules)                                │
│  ├─ Stage 5: Safety rule enforcement (chemistry machine)                    │
│  ├─ Stage 6: CTI correlation + Pyramid of Pain L1–L5 tagging               │
│  │           (CISA, AlienVault, Recorded Future → assign pyramid_level L1-L5)│
│  └─ Stage 7: MITRE ATT&CK for ICS tagging (81 techniques)                  │
│                                                                               │
│  ClickHouse (Multi-AZ)              PostgreSQL RDS (Multi-AZ)               │
│  └─ Telemetry: 90-day hot store     └─ CTI, baselines, audit logs           │
│                                                                               │
│  S3 Buckets:                        Secrets: AWS Secrets Manager            │
│  ├─ robotlab-backups                └─ All credentials, auto-rotation       │
│  └─ robotlab-pcap-archives                                                   │
└─────────────────────────────────┬─────────────────────────────────────────────┘
                                  │
                                  ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ LAYER 6: SECURITY & VISUALIZATION                                             │
├───────────────────────────────────────────────────────────────────────────────┤
│  React Dashboard (CloudFront + S3):                                           │
│  ├─ 1. Pyramid of Pain Heatmap (L1–L5 alert distribution, color-coded)      │
│  ├─ 2. MITRE ATT&CK Coverage Heatmap (12 tactics × 81 techniques)           │
│  ├─ 3. Real-Time Alert Feed (severity-prioritized, Pyramid level tagged)     │
│  ├─ 4. Network Topology (Purdue Model, live connections)                     │
│  ├─ 5. Protocol Analysis Dashboard (Modbus, OPC UA activity)                │
│  ├─ 6. SDN Flow Rule Monitor (active OVS rules)                              │
│  └─ 7. Threat Hunting Workspace (custom queries)                             │
│                                                                               │
│  Auth: AWS Cognito + Lambda Authorizer (RBAC: 4 roles)                      │
│  CTI: CISA + AlienVault + Recorded Future + VirusTotal + Abuse.ch           │
│  Alerting: Slack + PagerDuty                                                 │
│  Observability: Prometheus + Grafana + CloudWatch                            │
└───────────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════════════╗
║  COST: ~$178/month  │  RTO: <15 min  │  DETECTION: <60s  │  FP RATE: <5%   ║
║  28 Assets Monitored│  99.7% Uptime  │  81/81 ATT&CK     │  L1-L5 Pyramid  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

### **1.2 Research Framework**

This is a **university research platform** designed to generate novel findings in OT/ICS security. Each major component addresses a specific research question.

**Research Questions:**

| ID | Question | Methodology | Expected Output |
|----|----------|-------------|-----------------|
| **R1** | Can passive Zeek monitoring achieve comprehensive OT protocol visibility without disrupting operations? | Deploy dissectors, compare coverage vs. vendor tools | Zeek script library, coverage benchmarks |
| **R2** | How does SDN-based traffic steering compare to static SPAN ports for OT packet analysis? | Side-by-side comparison (OVS mirror vs. SPAN) | Performance measurements, false negative rates |
| **R3** | What packet-level signatures characterize ICS-targeting attacks (Modbus manipulation, OPC UA abuse)? | Controlled attack scenarios + packet analysis | Detection signatures, protocol anomaly catalog |
| **R4** | Can statistical methods (coefficient of variation, Shannon entropy) reliably detect C2 beaconing and DGA without ML? | Benchmark against known C2 traffic | Detection rate, FP rate, comparison to ML baselines |

**Research Outputs:**
- Open-source Zeek script library for OT protocols (GitHub)
- SDN-based OT security architecture reference implementation
- Protocol anomaly catalog for Modbus TCP / OPC UA / EtherNet/IP
- Academic report: passive OT monitoring effectiveness

---

### **1.3 Pyramid of Pain — Levels 1–5 Implementation**

> **Scope:** This platform covers Pyramid of Pain **Levels 1–5** (Hash Values through Tools).
> **Level 6 (TTPs — Tactics, Techniques & Procedures) is explicitly out of scope.** Detection at L6 requires behavioral correlation engines and autonomous agents beyond this project's mandate.
> MITRE ATT&CK for ICS is used to **tag** alerts by technique for enrichment context — this does **not** constitute Pyramid Level 6 detection.

```
              ┌──────────────────────────────────────────────────────────┐
              │   Level 5: TOOLS  (Very High Pain to Attacker)           │
              │   Attacker must find/build new tooling to evade          │
              ├──────────────────────────────────────────────────────────┤
              │   Detection:                                             │
              │   • Wazuh process monitoring: Mimikatz, nc, PSExec,     │
              │     plcinject, isf (ICS exploitation tools)             │
              │   • Sigma rules: 50+ tool-specific signatures           │
              │   • JA3 TLS fingerprints: Cobalt Strike, Metasploit     │
              │   • Wazuh YARA-style rules for malware families         │
              │   Effort: 20% of detection development                  │
              └──────────────────────────────────────────────────────────┘
            ┌──────────────────────────────────────────────────────────────┐
            │   Level 4: ARTIFACTS  (High Pain)                            │
            │   Attacker must modify tooling behavior                      │
            ├──────────────────────────────────────────────────────────────┤
            │   Network Artifacts:                                         │
            │   • JA3/JA3S TLS fingerprints (tls-ja3-fingerprinting.zeek) │
            │   • Modbus FC anomalies (modbus-deep-analysis.zeek)         │
            │   • OPC UA BrowseRequest patterns (opcua-session-tracking)  │
            │   • C2 beacon intervals (c2-beaconing.zeek — CV method)    │
            │   • HTTP URI patterns (Zeek http.log)                       │
            │   Host Artifacts:                                           │
            │   • Wazuh FIM: registry keys, file paths, modified configs  │
            │   • Sysmon: file creation (Ev11), registry mod (Ev13)      │
            │   • Scheduled task creation, service installation          │
            │   Effort: 30% of detection development                     │
            └──────────────────────────────────────────────────────────────┘
          ┌────────────────────────────────────────────────────────────────────┐
          │   Level 3: DOMAIN NAMES  (Moderate Pain)                           │
          │   Attacker must register/acquire new infrastructure                │
          ├────────────────────────────────────────────────────────────────────┤
          │   • Zeek dns.log: all DNS queries monitored                        │
          │   • dns-dga-detection.zeek: Shannon entropy DGA detection          │
          │   • chinese-robot-detection.zeek: .cn domain monitoring            │
          │   • CTI: Emerging Threats domain reputation, Abuse.ch blocklist    │
          │   • DNS sinkhole for known malicious domains (pfSense)             │
          │   Effort: 15% of detection development                             │
          └────────────────────────────────────────────────────────────────────┘
        ┌──────────────────────────────────────────────────────────────────────────┐
        │   Level 2: IP ADDRESSES  (Low Pain — easy to change)                     │
        │   Attacker rotates to new IP ranges                                      │
        ├──────────────────────────────────────────────────────────────────────────┤
        │   • Zeek conn.log: all connections logged per asset                      │
        │   • chinese-robot-detection.zeek: Chinese IP ranges (202.x, 218.x)     │
        │   • Suricata custom rule 9100001: Robot VLAN → Chinese IP alert         │
        │   • CTI: AlienVault OTX, Recorded Future APT infrastructure IPs        │
        │   • CTI: Abuse.ch Feodo Tracker (active C2 servers)                    │
        │   • Volume exfiltration baseline (Z-score per source IP)               │
        │   Effort: 20% of detection development                                  │
        └──────────────────────────────────────────────────────────────────────────┘
      ┌──────────────────────────────────────────────────────────────────────────────┐
      │   Level 1: HASH VALUES  (Lowest Pain — trivial for attacker to change)       │
      │   Block known bad files, validate firmware integrity                         │
      ├──────────────────────────────────────────────────────────────────────────────┤
      │   • Wazuh FIM: SHA-256 checksums on firmware, ladder logic, configs          │
      │   • VirusTotal API: file hash reputation lookup on Wazuh FIM events          │
      │   • Zeek files.log: SHA-256 of all files transferred over network            │
      │   • CTI: AlienVault OTX hash feeds, known malware SHA-256 database           │
      │   Effort: 15% of detection development                                       │
      └──────────────────────────────────────────────────────────────────────────────┘

      ╔═══════════════════════════════════════════════════════════════════════════╗
      ║  STRATEGIC SCOPE: L1-L5 coverage creates meaningful attacker friction.  ║
      ║  L6 (TTPs) requires behavioral correlation engines — OUT OF SCOPE.       ║
      ╚═══════════════════════════════════════════════════════════════════════════╝
```

**Detection Mapping Summary:**

| Level | Name | Primary Tools | CTI Feeds | Week |
|-------|------|--------------|-----------|------|
| **L1** | Hash Values | Wazuh FIM, Zeek files.log | VirusTotal, AlienVault OTX | Wk 5 |
| **L2** | IP Addresses | Zeek conn.log, Suricata, OVS | AlienVault, Recorded Future, Abuse.ch | Wk 9 |
| **L3** | Domain Names | Zeek dns.log, DGA detector | Emerging Threats, Abuse.ch | Wk 9 |
| **L4** | Artifacts | JA3 Zeek, Modbus scripts, OPC UA scripts, Wazuh FIM/Sysmon | CISA ICS-CERT | Wk 12 |
| **L5** | Tools | Wazuh process mon, Sigma rules, JA3 blocklist | MITRE ATT&CK for ICS | Wk 14 |
| ~~L6~~ | ~~TTPs~~ | *Out of scope — no behavioral correlation engine* | | — |

---

### **1.4 Data Flow Diagram**

```
ON-PREMISES ROBOTLAB                         AWS CLOUD
══════════════════                           ══════════

┌─────────────┐
│  28 Assets  │
│             │
│  Windows    │──Wazuh Agent──────────────┐
│  Linux      │──Wazuh Agent──────────────┤
│  RPi (4)    │──Wazuh Agent──────────────┤
│  OT Devices │──Passive TAP/SPAN─────────┤
│  Robots     │──Passive Mirror───────────┤
└─────────────┘                           │
                                          │ All events via
┌─────────────────────────────────────┐   │ WireGuard VPN
│  OVS + ONOS SDN                     │   │ (TLS 1.3)
│  ├─ Mirror all VLAN traffic         │   │
│  └─ OpenFlow controlled flows       │   │          ┌──────────────┐
└──────────┬──────────────────────────┘   └─────────►│   Kinesis    │
           │ Mirrored traffic                         │  Firehose    │
           ▼                                          └──────┬───────┘
┌─────────────────────────────────────┐                     │
│  Zeek 6.0                           │                     ▼
│  ├─ Standard logs (7 types)         │──Events────────►┌──────────────┐
│  ├─ Custom OT logs (3 types)        │                 │   Lambda     │
│  └─ Statistical detectors           │                 │  Processor   │
└─────────────────────────────────────┘                 └──────┬───────┘
                                                               │
┌─────────────────────────────────────┐                       ├──►ClickHouse
│  Suricata 7.0 (pfSense)             │──Alerts───────────────┤
│  ├─ ET Open (30K+ rules)            │                       ├──►PostgreSQL
│  ├─ ET Pro OT/ICS                   │                       │
│  └─ Custom ICS rules                │                       └──►S3 (PCAP archive)
└─────────────────────────────────────┘                              │
                                                                      ▼
┌─────────────────────────────────────┐                       ┌──────────────┐
│  PCAP Ring Buffer (2GB)             │──On-demand────────────► Dashboard    │
│  tcpdump + tshark forensics         │                       │  (React)     │
└─────────────────────────────────────┘                       └──────┬───────┘
                                                                      │
                                                                      ▼
                                                               ┌──────────────┐
                                                               │  Security    │
                                                               │  Analyst     │
                                                               └──────────────┘
```

---

### **1.5 Network Topology (VLAN Segmentation)**

```mermaid
graph TD
    Internet[Internet] -->|Firewall| FW[pfSense + Suricata 7.0]
    FW --> OVS[OpenVSwitch 3.x<br/>SDN Bridge]

    OVS -->|VLAN 10| M[Management<br/>192.168.10.0/24<br/>Security team, Wazuh mgr]
    OVS -->|VLAN 20| R[Raspberry Pi<br/>192.168.20.0/24<br/>Zeek, OVS, aggregation]
    OVS -->|VLAN 30| IT[IT Assets<br/>192.168.30.0/24<br/>Workstations, HMI]
    OVS -->|VLAN 100| P[PLC Control<br/>192.168.100.0/24<br/>Siemens S7, Allen-Bradley]
    OVS -->|VLAN 110| RO[Robot Control<br/>192.168.110.0/24<br/>5x DoBot arms]
    OVS -->|VLAN 200| C[Chemistry Machine<br/>192.168.200.0/24<br/>Air-gapped, TAP only]

    M -.Management.-> IT
    M -.Management.-> P
    M -.Management.-> RO
    IT -.Engineering.-> P
    IT -.Engineering.-> RO
    P x--xNo Connection--x C
    RO x--xNo Connection--x C
    Internet x--xBlocked--x C

    OVS -->|Mirror all VLANs| Zeek[Zeek Sensor<br/>RPi VLAN 20]

    style C fill:#ff6b6b
    style P fill:#ffe66d
    style RO fill:#ffe66d
    style OVS fill:#4ecdc4
    style FW fill:#e1f5ff
```

---

## 2. Software-Defined Networking Layer

> **Research Pillar R2:** SDN enables dynamic, programmable network control — a research contribution beyond static firewall rules.

### **2.1 SDN Architecture Overview**

**Why SDN for OT Security Research?**
Traditional OT security relies on static SPAN ports and firewall rules that cannot adapt to changing conditions. SDN introduces:

1. **Programmable traffic mirroring** — Mirror specific flows or VLANs to analysis sensors on demand
2. **Dynamic microsegmentation** — Apply per-flow access control beyond subnet boundaries
3. **Research instrument** — Measure and compare packet capture completeness with different mirroring strategies
4. **Human-controlled response** — Analyst-triggered flow rules for non-OT device isolation

**Components:**

| Component | Version | Role |
|-----------|---------|------|
| OpenVSwitch (OVS) | 3.x | Virtual switch (replaces managed switch SPAN) |
| ONOS | 2.x | SDN controller (OpenFlow 1.3 southbound) |
| OpenFlow | 1.3 | Control protocol (OVS ↔ ONOS) |
| OVS REST API | v1 | Management automation |

---

### **2.2 OpenVSwitch Deployment**

OVS runs on the dedicated **Raspberry Pi 4 (VLAN 20)** alongside Zeek, acting as a programmable switch fabric for traffic capture.

**Bridge Configuration:**
```bash
# Create main bridge
ovs-vsctl add-br br-robotlab

# Add uplink to pfSense (trunk - all VLANs)
ovs-vsctl add-port br-robotlab eth0
ovs-vsctl set port eth0 trunks=10,20,30,100,110,200

# Add VLAN access ports for OT networks
ovs-vsctl add-port br-robotlab vlan100-port \
    tag=100 vlan_mode=access

ovs-vsctl add-port br-robotlab vlan110-port \
    tag=110 vlan_mode=access

# Add mirror output port to Zeek capture interface
ovs-vsctl add-port br-robotlab zeek-capture
ovs-vsctl set interface zeek-capture type=internal

# Add mirror output port to Suricata
ovs-vsctl add-port br-robotlab suricata-capture
ovs-vsctl set interface suricata-capture type=internal
```

**Mirror Configuration:**
```bash
# Mirror VLAN 100 (PLC) and VLAN 110 (Robot) to Zeek
ovs-vsctl -- set Bridge br-robotlab mirrors=@m \
    -- --id=@m create Mirror name=ot-mirror \
       select-vlan=100,110 \
       output-port=zeek-capture

# Mirror ALL VLANs to Suricata (IDS)
ovs-vsctl -- set Bridge br-robotlab mirrors=@m2 \
    -- --id=@m2 create Mirror name=ids-mirror \
       select-vlan=10,20,30,100,110,200 \
       output-port=suricata-capture
```

**Research: Dynamic Mirror vs. Static SPAN**
```
Static SPAN (traditional):
  - Fixed at switch config time
  - Captures all traffic or nothing per port
  - No API control
  - Change requires switch access

Dynamic OVS Mirror (SDN-enhanced):
  - API-driven (ONOS REST API)
  - Per-VLAN, per-flow granularity
  - Measurable: compare FP/FN rates with different mirror scopes
  - Changeable in seconds without physical access
```

---

### **2.3 ONOS SDN Controller**

**Deployment:** Docker container on Raspberry Pi VLAN 20

```bash
docker run -d --name onos \
  -p 6653:6653 \    # OpenFlow southbound
  -p 8181:8181 \    # REST northbound
  -p 8101:8101 \    # SSH
  onosproject/onos:2.7
```

**ONOS Intents (Network Policy as Code):**
```json
// Intent: Allow IT VLAN to Modbus (port 502) only
{
  "type": "PointToPointIntent",
  "appId": "org.onosproject.robotlab",
  "ingressPoint": {
    "device": "of:0000000000000001",
    "port": "30"   // IT VLAN port
  },
  "egressPoint": {
    "device": "of:0000000000000001",
    "port": "100"  // PLC VLAN port
  },
  "selector": {
    "criteria": [
      {"type": "IP_PROTO", "protocol": 6},
      {"type": "TCP_DST", "tcpPort": 502}
    ]
  },
  "treatment": {"instructions": [{"type": "OUTPUT", "port": "100"}]}
}
```

**Reactive Isolation (Analyst-Triggered, Non-OT Devices Only):**
```bash
# API call from Dashboard: isolate workstation 192.168.30.45
curl -X POST http://onos:8181/onos/v1/flows/of:0000000000000001 \
  -H "Content-Type: application/json" \
  -d '{
    "priority": 50000,
    "timeout": 300,
    "isPermanent": false,
    "treatment": {"instructions": [{"type": "DROP"}]},
    "selector": {
      "criteria": [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IPV4_SRC", "ip": "192.168.30.45/32"}
      ]
    }
  }'
```

> **OT Safety Note:** Reactive isolation is **never automated** for OT devices (VLAN 100, 110, 200). Only IT workstations (VLAN 30) can be isolated via API. All OT responses require human approval.

---

### **2.4 SDN Security Functions**

**Function 1: Per-VLAN Traffic Mirroring**
Replace static SPAN with programmable OVS mirroring:
- Mirror PLC + Robot VLANs to Zeek at all times (research baseline)
- Mirror Chemistry TAP to separate Zeek instance (air-gapped passive)
- Dynamic mirror expansion: alert → Analyst → API call → capture all traffic from suspicious host

**Function 2: Whitelist Flow Enforcement**
```
Traditional pfSense:     Subnet-level rules (192.168.30.0/24 → 192.168.100.0/24 TCP 502)
SDN OpenFlow:            Per-connection rules (192.168.30.5 → 192.168.100.10 TCP 502, session tracked)

Research value: Finer granularity → detect lateral movement within allowed subnets
```

**Function 3: Traffic Steering for Deep Analysis**
When Suricata fires a high-confidence alert, Analyst can:
1. Use ONOS API to redirect all traffic from suspicious host to a **dedicated Zeek analysis port**
2. Full PCAP capture begins immediately for that host
3. Normal traffic still flows (mirror only, no blocking for OT)

**Function 4: Flow Telemetry (Research Data)**
```bash
# Export OpenFlow counters for research
ovs-ofctl dump-flows br-robotlab -O OpenFlow13 \
  | grep "priority=1000" \
  | awk '{print $5,$6,$7}' > flow_telemetry.csv

# Metrics per flow: packet count, byte count, duration
# Research: Compare normal vs. attack traffic flow characteristics
```

---

## 3. Packet Analysis Layer

> **Research Pillar R1 & R3:** Deep packet analysis is the primary research instrument for understanding OT protocol behavior.

### **3.1 Analysis Hierarchy**

```
Level 4: FORENSIC ANALYSIS
  └─ PCAP ring buffer, tshark/Wireshark, forensic timeline
     "What exactly happened at packet level?"

Level 3: APPLICATION ANALYSIS (Research Focus)
  └─ Custom Zeek OT scripts: Modbus, OPC UA, EtherNet/IP
     "What are these industrial devices communicating?"

Level 2: PROTOCOL ANALYSIS
  └─ Zeek: dns.log, http.log, ssl.log, weird.log
     "Are protocol behaviors within expected parameters?"

Level 1: FLOW ANALYSIS
  └─ Zeek: conn.log, Suricata flow logs
     "Who is talking to whom, how often, how much?"
```

---

### **3.2 Zeek Script Library**

| Script | Protocol | Research Question | Key Detections |
|--------|----------|------------------|----------------|
| `modbus-deep-analysis.zeek` | Modbus TCP | Which FC codes indicate unauthorized access? | Unexpected function codes, register writes from IT VLAN |
| `modbus-register-baseline.zeek` | Modbus TCP | What is the normal register access pattern? | Deviation from 30-day baseline |
| `modbus-exception-tracking.zeek` | Modbus TCP | Do exception rates indicate PLC issues? | Abnormal exception codes from PLCs |
| `opcua-session-tracking.zeek` | OPC UA | Does BrowseRequest from unexpected source indicate recon? | Session establishment, BrowseRequest source |
| `opcua-write-monitor.zeek` | OPC UA | Are OPC UA writes from authorized sources only? | WriteRequest from unexpected hosts |
| `ethernetip-cip-analysis.zeek` | EtherNet/IP | What CIP service codes are in use? | Unauthorized Forward Open, method invocations |
| `tls-ja3-fingerprinting.zeek` | TLS | Which JA3 hashes indicate C2 tooling? | Known bad JA3, unexpected cipher suites |
| `chinese-robot-detection.zeek` | TCP/DNS | Do DoBot robots contact Chinese infrastructure? | Connections to 202.x.x.x, 218.x.x.x, *.cn |
| `c2-beaconing.zeek` | TCP | Can CV of intervals detect automated beacons? | Periodic connections with low coefficient of variation |
| `dns-dga-detection.zeek` | DNS | Can entropy detect DGA domains? | High Shannon entropy in DNS first labels |
| `large-upload-detection.zeek` | TCP | What upload volume indicates exfiltration? | Anomalous outbound data transfers |
| `lateral-movement.zeek` | TCP | Do OT-to-OT connections indicate pivot? | Cross-VLAN connections beyond whitelist |
| `modbus-coil-monitor.zeek` | Modbus TCP | Are discrete output coils manipulated outside maintenance? | Coil write FC1/FC5/FC15 from non-HMI source |

---

### **3.3 Modbus TCP Deep Analysis**

**Research Question R3:** What packet patterns distinguish legitimate PLC programming from attack traffic?

**Modbus Function Code Reference:**
```
Read Operations (Low risk):
  FC01: Read Coils          — Read discrete output status
  FC02: Read Discrete Inputs — Read discrete input status
  FC03: Read Holding Registers — PRIMARY: read process values
  FC04: Read Input Registers  — Read input values

Write Operations (High interest):
  FC05: Write Single Coil       — Modify discrete output
  FC06: Write Single Register   — Modify single process value
  FC15: Write Multiple Coils    — Modify multiple outputs
  FC16: Write Multiple Registers — PRIMARY ATTACK VECTOR

Diagnostic/Configuration (Highest risk):
  FC08: Diagnostics             — Test PLC communications
  FC11: Get Comm Event Counter
  FC17: Report Server ID
  FC43: Read Device Identification — Enumeration/recon indicator
```

**Custom Zeek Script: `modbus-deep-analysis.zeek`**
```zeek
##! Deep Modbus TCP analysis for RobotLab OT research
##! Research: Characterize normal vs. anomalous Modbus traffic
##! MITRE ATT&CK ICS: T0836 (Modify Parameter), T0855 (Unauthorized Command)

module ModbusDeepAnalysis;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:              time    &log;
        uid:             string  &log;
        id:              conn_id &log;
        func_code:       count   &log;
        func_name:       string  &log;
        register_addr:   count   &log &optional;
        register_count:  count   &log &optional;
        exception_code:  count   &log &optional;
        is_write:        bool    &log;
        is_exception:    bool    &log;
        severity:        string  &log;   # normal/elevated/critical
    };
}

# Authorized writers: only HMI and Engineering workstations
const AUTHORIZED_WRITERS: set[addr] = {
    192.168.30.5,    # HMI workstation
    192.168.30.6,    # Engineering laptop
} &redef;

# Write function codes
const WRITE_FCS: set[count] = { 5, 6, 15, 16 } &redef;

# High-risk function codes (recon or diagnostic)
const HIGH_RISK_FCS: set[count] = { 8, 43 } &redef;

event modbus_read_holding_registers_request(
    c: connection, headers: ModbusHeaders,
    start_address: count, quantity: count
) {
    local info = Info(
        ts=network_time(), uid=c$uid, id=c$id,
        func_code=3, func_name="Read Holding Registers",
        register_addr=start_address, register_count=quantity,
        is_write=F, is_exception=F, severity="normal"
    );
    Log::write(LOG, info);
}

event modbus_write_multiple_registers_request(
    c: connection, headers: ModbusHeaders,
    start_address: count, registers: ModbusRegisters
) {
    local severity = "normal";

    # Unauthorized writer?
    if (c$id$orig_h !in AUTHORIZED_WRITERS) {
        severity = "critical";
        NOTICE([$note=ModbusUnauthorizedWrite,
                $conn=c,
                $msg=fmt("Unauthorized Modbus write from %s to PLC %s, register %d",
                         c$id$orig_h, c$id$resp_h, start_address),
                $identifier=cat(c$id$orig_h, start_address)]);
    }

    Log::write(LOG, Info(
        ts=network_time(), uid=c$uid, id=c$id,
        func_code=16, func_name="Write Multiple Registers",
        register_addr=start_address, register_count=|registers|,
        is_write=T, is_exception=F, severity=severity
    ));
}
```

**Baseline Register Map (per PLC):**
```
PLC: Siemens S7-1200 (192.168.100.10)
  Normal reads:   FC3, registers 0-99 (sensor inputs)
  Normal writes:  FC16, registers 100-149 (setpoints, HMI only)
  Never expected: FC8 (diagnostics), FC43 (device ID), FC5/FC6 from workstations
  Safety zone:    Registers 200-299 (safety interlocks) — write = CRITICAL alert
```

---

### **3.4 OPC UA Deep Analysis**

**Research Question R3:** Can session and BrowseRequest patterns indicate enumeration/recon?

**OPC UA Service Codes of Interest:**
```
Session Management:
  0x01 (OpenSecureChannel)    — Session start, certificate exchange
  0x03 (CloseSecureChannel)   — Session end

Data Operations:
  0x1F (ReadRequest)          — Normal data read
  0x21 (WriteRequest)         — High interest: configuration changes
  0x33 (CallRequest)          — Method invocation (PLC function execution)

Discovery/Recon Indicators:
  0x35 (BrowseRequest)        — Namespace traversal → recon if unexpected source
  0x37 (BrowseNextRequest)    — Continued enumeration
  0x03 (FindServersRequest)   — Server discovery
```

**Custom Zeek Script: `opcua-session-tracking.zeek`**
```zeek
##! OPC UA session tracking and anomaly detection
##! Research: BrowseRequest frequency as recon indicator
##! MITRE ATT&CK ICS: T0888 (Remote System Discovery)

module OPCUATracking;

# Track BrowseRequest counts per source
global browse_request_count: table[addr] of count
    &default=0 &create_expire=1hr;

# Alert threshold: >20 BrowseRequests/hour from single source
const BROWSE_ALERT_THRESHOLD = 20;

event opcua_browse_request(c: connection, service_type: count) {
    ++browse_request_count[c$id$orig_h];

    if (browse_request_count[c$id$orig_h] > BROWSE_ALERT_THRESHOLD) {
        NOTICE([$note=OPCUAReconnaissance,
                $conn=c,
                $msg=fmt("Potential OPC UA namespace enumeration from %s (%d requests/hr)",
                         c$id$orig_h, browse_request_count[c$id$orig_h])]);
    }
}
```

---

### **3.5 TLS / JA3 Fingerprinting**

**Purpose:** Detect C2 tools (Cobalt Strike, Metasploit) communicating over TLS without decryption.

**JA3 Hash Methodology:**
```
JA3 = MD5(TLS version + cipher suites + extensions + elliptic curves + elliptic curve points)

Detection approach:
1. Compute JA3 from Zeek ssl.log fields
2. Compare against blocklist (known C2 JA3 hashes)
3. Alert on matches even if certificate appears valid

Known C2 JA3 Hashes:
  72a589da586844d7f0818ce684948eea — Cobalt Strike default
  e7d705a3286e19ea42f587b07c31ea44 — Metasploit
  6bea65232d2734904e2b44caee0b2f58 — Cobalt Strike malleable
```

**Zeek `ssl.log` fields used:**
```
JA3:     SSL/TLS handshake fingerprint (client)
JA3S:    Server fingerprint
cert.cn: Certificate CN
issuer:  Certificate issuer
```

---

### **3.6 PCAP Forensics Infrastructure**

**Ring Buffer Capture on Raspberry Pi:**
```bash
# Capture on OVS zeek-capture interface
# 20 files × 100MB = 2GB ring buffer ≈ 60 min full-speed capture
tcpdump -i zeek-capture \
  -C 100 \           # Rotate at 100MB
  -W 20 \            # Keep 20 files
  -z gzip \          # Compress rotated files
  -w /captures/robotlab-%Y%m%d%H%M%S.pcap
```

**Forensic Analysis Workflow:**
```
1. Incident alert fires (Zeek or Suricata)
2. Analyst reviews alert in dashboard
3. If deeper analysis needed:
   a. Retrieve PCAP from ring buffer window
   b. Filter by source IP/time with tshark:
      tshark -r robotlab.pcap -Y "ip.src == 192.168.110.12" \
             -T json > incident_traffic.json
   c. Dissect OT protocols:
      tshark -r incident.pcap -d tcp.port==502,mbtcp \
             -T fields -e mbtcp.func_code -e mbtcp.reference_num > modbus.csv
   d. Build forensic timeline in Zeek logs:
      zeek -r incident.pcap Detection::modbus-deep-analysis.zeek
4. Findings documented in incident report
```

**Wireshark Profiles (pre-configured for team):**
```
Profile: OT-Modbus
  - Modbus TCP dissector enabled
  - Column: function code, register address, exception code
  - Coloring: Write ops (red), Exception (orange), Read (green)

Profile: OT-OPCUA
  - OPC UA dissector with decryption key if available
  - Column: service type, session ID, status code

Profile: OT-TLS-JA3
  - TLS column additions: JA3, JA3S, certificate CN
  - Highlight known-bad JA3 hashes
```

---

### **3.7 Statistical Detection Methods**

These methods detect anomalies **without machine learning**, using classical statistics. They are transparent, auditable, and suitable for research publication.

#### **C2 Beaconing Detection (Coefficient of Variation)**

**Research Hypothesis (R4):** Automated C2 beaconing has lower temporal variance than human-initiated traffic.

```python
# Zeek custom script calls this Python helper via input framework
def detect_c2_beaconing(
    connection_timestamps: list[float],
    min_connections: int = 10,
    cv_threshold: float = 0.2,
    max_interval_seconds: float = 3600.0
) -> tuple[bool, float]:
    """
    Detect C2 beaconing using Coefficient of Variation (CV).

    Method: CV = std(intervals) / mean(intervals)
    Rationale: Automated beacons are temporally consistent → low CV
               Human browsing is irregular → high CV

    Research baseline (validated against known C2):
      - Cobalt Strike 60s beacon: CV ≈ 0.02–0.05
      - Metasploit 5s beacon:     CV ≈ 0.01–0.03
      - Human web browsing:       CV ≈ 1.5–4.0
      - THRESHOLD: CV < 0.2 with interval < 1h = suspected beacon
    """
    if len(connection_timestamps) < min_connections:
        return False, 0.0

    intervals = [
        t2 - t1
        for t1, t2 in zip(connection_timestamps, connection_timestamps[1:])
    ]

    mean_interval = statistics.mean(intervals)
    if mean_interval == 0:
        return False, 0.0

    cv = statistics.stdev(intervals) / mean_interval

    is_beaconing = (cv < cv_threshold) and (mean_interval < max_interval_seconds)
    return is_beaconing, cv
```

#### **DGA Domain Detection (Shannon Entropy)**

**Research Hypothesis (R4):** DGA-generated domains have higher character entropy than legitimate domains.

```python
def calculate_domain_entropy(domain: str) -> tuple[float, bool]:
    """
    Detect DGA domains using Shannon entropy analysis.

    Method: H = -sum(p_i * log2(p_i)) for each character frequency
    Rationale: DGA domains use pseudo-random character distributions
               → higher entropy than human-readable domains

    Research baseline:
      - Legitimate: 'microsoft.com'     → entropy ≈ 2.9
      - Legitimate: 'robotlab.edu'      → entropy ≈ 2.8
      - DGA domain: 'xkzqvmrpbt.com'   → entropy ≈ 3.7
      - DGA domain: 'a3f8c2d9e1b4.net'  → entropy ≈ 3.9
      - THRESHOLD: entropy > 3.5 AND label length > 12 = suspected DGA
    """
    label = domain.split('.')[0]  # Analyze first label only
    if len(label) < 6:
        return 0.0, False

    freq = Counter(label)
    length = len(label)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

    is_dga = entropy > 3.5 and length > 12
    return entropy, is_dga
```

#### **Exfiltration Volume Baseline**

```python
def detect_anomalous_upload(
    src_ip: str,
    bytes_sent: int,
    hour_of_day: int,
    baseline: dict  # pre-computed per-host, per-hour baseline
) -> bool:
    """
    Detect anomalous upload volumes using per-host statistical baseline.

    Method: Z-score against 30-day hourly upload baseline per host
    Threshold: Z-score > 3.0 (>3 standard deviations above normal)

    Robotic arm (192.168.110.x):
      - Normal: <1MB/hour firmware telemetry
      - Alert:  >100MB upload = likely exfiltration
    """
    host_baseline = baseline.get(src_ip, {}).get(hour_of_day, {})
    if not host_baseline:
        return False  # No baseline yet, skip

    mean_bytes = host_baseline['mean']
    std_bytes = host_baseline['std']

    if std_bytes == 0:
        return bytes_sent > mean_bytes * 10

    z_score = (bytes_sent - mean_bytes) / std_bytes
    return z_score > 3.0
```

---

## 4. Core Component Designs

### **4.1 Network Monitoring (Zeek + Suricata)**

**Zeek 6.0 on Raspberry Pi 4:**

```
┌─────────────────────────────────────────────────────────────┐
│  Zeek Architecture                                          │
├─────────────────────────────────────────────────────────────┤
│  Network → OVS Mirror Port → Zeek Event Engine             │
│                                                             │
│  Event Engine:                                             │
│  ├─ Packet reassembly (TCP streams)                        │
│  ├─ Protocol detection (DPI)                               │
│  ├─ Script execution (per-protocol events)                 │
│  └─ Log generation (all log types)                         │
│                                                             │
│  Filebeat → Kinesis Firehose (TLS 1.3)                     │
│  └─ All log types forwarded in real-time                   │
└─────────────────────────────────────────────────────────────┘
```

**Zeek `node.cfg`:**
```ini
[zeek]
type=standalone
host=localhost
interface=zeek-capture   # OVS mirror interface
```

**Zeek `networks.cfg`:**
```
192.168.10.0/24    Management VLAN - High trust
192.168.20.0/24    Raspberry Pi VLAN - Infrastructure
192.168.30.0/24    IT Assets VLAN - Medium trust
192.168.100.0/24   PLC Control VLAN - OT Critical
192.168.110.0/24   Robot Control VLAN - OT Monitored
192.168.200.0/24   Chemistry Machine VLAN - Air-gapped
```

**Suricata 7.0 on pfSense:**
- ET Open rules: 30,000+ signatures
- ET Pro OT/ICS: Modbus, OPC UA, DNP3 signatures
- Custom rules (see Section 4.3)
- Mode: **Alert-only** for OT VLANs (no inline blocking)

---

### **4.2 Host Security (Wazuh + Sysmon)**

**Wazuh 4.12 Deployment:**

| Component | Location | Function |
|-----------|----------|----------|
| Wazuh Manager | Docker (VLAN 20) | Central correlation, alerting |
| Wazuh Agent | 3× Windows workstations | Event log, FIM, process mon |
| Wazuh Agent | 2× Linux servers | Auditd, process mon |
| Wazuh Agent | 4× Raspberry Pi | Process mon, integrity |

**Critical FIM Paths:**
```yaml
# Siemens S7-1200 ladder logic backup
/eng-ws/plc-programs/*.s7l

# DoBot robot firmware
/opt/dobot/firmware/*.bin

# Chemistry machine config
/chemistry-ctrl/config/*.ini

# Wazuh agent config integrity
/var/ossec/etc/ossec.conf
```

**Sysmon v15 Key Events:**

| Event | Description | Why Relevant |
|-------|-------------|--------------|
| Event 1 | Process creation | Detect malware execution (Mimikatz, nc) |
| Event 3 | Network connection | Detect unexpected outbound connections |
| Event 6 | Driver load | Detect rootkit installation |
| Event 11 | File creation | Detect malware dropper |
| Event 22 | DNS query | Detect DGA/C2 domain resolution |

---

### **4.3 Detection Rules**

**Custom Suricata Rules:**
```suricata
# Chinese IP range monitoring (supply chain threat)
alert tcp $ROBOT_VLAN any -> $CHINESE_RANGES any (
    msg:"ROBOTLAB Robot VLAN to Chinese IP - supply chain risk";
    classtype:trojan-activity;
    reference:url,attack.mitre.org/techniques/T0862;
    sid:9100001; rev:1;)

# Modbus write from IT VLAN (unauthorized)
alert tcp $IT_VLAN any -> $PLC_VLAN 502 (
    msg:"ROBOTLAB Modbus write from IT network - possible T0836";
    content:"|00|"; offset:7; depth:1;   # Function code > 4 (write)
    byte_test:1,>,4,7;
    classtype:protocol-command-decode;
    reference:url,attack.mitre.org/techniques/T0836;
    sid:9100002; rev:1;)

# DNS query to .cn domain from OT network
alert dns $OT_VLANS any -> any 53 (
    msg:"ROBOTLAB OT device DNS query to Chinese domain";
    dns.query; content:".cn"; endswith;
    classtype:trojan-activity;
    reference:technique,T0862;
    sid:9100003; rev:1;)
```

**Sigma Rules (converted to Wazuh):**
```yaml
title: Mimikatz Process Execution
id: robotlab-wazuh-001
status: experimental
description: Detects Mimikatz credential dumping tool execution
tags:
  - attack.credential_access
  - attack.T1003.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|contains:
      - 'mimikatz'
      - 'sekurlsa'
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
  condition: selection
falsepositives:
  - Authorized penetration testing (Week 22 only)
level: critical
```

---

### **4.4 Lambda Event Processing Pipeline (7 Stages)**

```
Kinesis Firehose → Lambda: ot-event-processor (1GB RAM, 30s timeout)

Stage 1: Multi-Protocol Parsing
  ├─ Parse Wazuh JSON (host events)
  ├─ Parse Zeek TSV/JSON (network events)
  └─ Parse Suricata EVE JSON (IDS alerts)

Stage 2: Protocol Validation
  ├─ Modbus FC range check (valid: FC1-FC24)
  ├─ OPC UA service code validation
  └─ Flag malformed packets

Stage 3: Baseline Deviation Detection
  ├─ Per-host connection rate vs. 30-day baseline
  ├─ Per-protocol bandwidth vs. 30-day baseline
  └─ Flag statistical outliers (Z-score > 3.0)

Stage 4: Sigma Rule Matching
  └─ Match against 50+ loaded Sigma rules

Stage 5: Safety Rule Enforcement
  ├─ Chemistry machine: any change = CRITICAL
  ├─ PLC write outside maintenance window = HIGH
  └─ OT isolation command: REQUIRE human approval

Stage 6: CTI Correlation + Pyramid of Pain L1–L5 Tagging
  ├─ Hash lookup (VirusTotal via cache)      → tag: pyramid_level = L1
  ├─ IP reputation lookup (AlienVault, Recorded Future, Abuse.ch) → tag: L2
  ├─ Domain reputation lookup (Emerging Threats)  → tag: L3
  ├─ Artifact match (JA3, Modbus FC, OPC UA pattern) → tag: L4
  ├─ Tool signature match (Sigma, Wazuh process rules) → tag: L5
  └─ CISA ICS-CERT advisory cross-reference

Stage 7: MITRE ATT&CK for ICS Tagging
  ├─ Map alert type → ATT&CK technique
  ├─ Tag tactic and technique ID
  └─ Store enriched event to ClickHouse
```

---

### **4.5 CTI Integration (Rule-Based)**

**Feed Configuration:**

| Feed | Reliability | Update | Purpose |
|------|-------------|--------|---------|
| CISA ICS-CERT | A (Confirmed) | Daily | ICS-specific CVEs, advisories |
| MITRE ATT&CK for ICS | A (Confirmed) | Weekly | 81-technique detection reference |
| AlienVault OTX | B (Reliable) | 6h | IP/domain/hash IoCs |
| Recorded Future | B (Reliable) | 6h | APT infrastructure tracking |
| Abuse.ch Feodo | B (Reliable) | 6h | Active C2 server IPs |
| VirusTotal | C (Contextual) | On-demand | File hash verdicts |

**Rule-Based CTI Enrichment + Pyramid of Pain L1–L5 Tagging (no AI):**
```python
# Pyramid level assignment rules — L6 (TTPs) deliberately excluded
RULE_TO_PYRAMID_LEVEL = {
    'wazuh_fim_hash':       'L1',   # Hash Values
    'virustotal_match':     'L1',   # Hash Values
    'zeek_files_hash':      'L1',   # Hash Values
    'suricata_ip_rep':      'L2',   # IP Addresses
    'zeek_chinese_ip':      'L2',   # IP Addresses
    'zeek_c2_beacon':       'L2',   # IP Addresses (connection to C2 IP)
    'zeek_dga_domain':      'L3',   # Domain Names
    'suricata_cn_domain':   'L3',   # Domain Names
    'zeek_ja3_match':       'L4',   # Network Artifacts
    'zeek_modbus_fc':       'L4',   # Network Artifacts (OT protocol)
    'zeek_opcua_browse':    'L4',   # Network Artifacts
    'wazuh_fim_registry':   'L4',   # Host Artifacts
    'sysmon_file_drop':     'L4',   # Host Artifacts
    'wazuh_mimikatz':       'L5',   # Tools
    'wazuh_netcat':         'L5',   # Tools
    'sigma_tool_match':     'L5',   # Tools
    'wazuh_psexec':         'L5',   # Tools
    'zeek_ja3_cobalt':      'L5',   # Tools (C2 framework fingerprint)
    # L6 (TTPs): NOT ASSIGNED — out of scope
}

def enrich_event(event: dict, cti_db: CTIDatabase) -> dict:
    """Rule-based CTI enrichment pipeline with Pyramid of Pain L1–L5 tagging."""

    # --- L1: Hash Values ---
    if file_hash := event.get('file_hash'):
        hash_intel = cti_db.lookup_hash(file_hash)
        if hash_intel.is_malicious:
            event['pyramid_level'] = 'L1'
            event['pyramid_name'] = 'Hash Values'

    # --- L2: IP Addresses ---
    if src_ip := event.get('src_ip'):
        ip_intel = cti_db.lookup_ip(src_ip)
        event['ip_tags'] = ip_intel.tags              # ['c2', 'apt41']
        event['apt_attribution'] = ip_intel.actors    # ['APT41']
        event['cisa_reference'] = ip_intel.cisa_refs
        if ip_intel.is_malicious and 'pyramid_level' not in event:
            event['pyramid_level'] = 'L2'
            event['pyramid_name'] = 'IP Addresses'

    # --- L3: Domain Names ---
    if domain := event.get('dns_query'):
        dom_intel = cti_db.lookup_domain(domain)
        event['domain_category'] = dom_intel.category
        if dom_intel.is_malicious and 'pyramid_level' not in event:
            event['pyramid_level'] = 'L3'
            event['pyramid_name'] = 'Domain Names'

    # --- L4 / L5: from rule_id lookup ---
    if rule_id := event.get('rule_id'):
        level = RULE_TO_PYRAMID_LEVEL.get(rule_id)
        if level and 'pyramid_level' not in event:
            event['pyramid_level'] = level
            event['pyramid_name'] = {
                'L4': 'Artifacts', 'L5': 'Tools'
            }.get(level, level)

    # --- MITRE ATT&CK tagging (technique reference, not L6 detection) ---
    event['mitre_technique'] = RULE_TO_TECHNIQUE.get(event.get('rule_id'))
    event['mitre_tactic'] = TECHNIQUE_TO_TACTIC.get(event.get('mitre_technique'))

    return event
```

---

### **4.6 Disaster Recovery**

**RTO Target:** <15 minutes | **RPO Target:** <1 hour

**ClickHouse Multi-AZ (Active-Passive):**
```
PRIMARY (us-east-1a)       REPLICA (us-east-1b)
EC2 t4g.small             EC2 t4g.small
├─ All reads/writes       ├─ Read-only
└─ Async replication      └─ Failover target (12 min)
   (60s lag)
```

**PostgreSQL RDS Multi-AZ:**
- AWS managed synchronous replication
- Auto failover: <2 minutes
- Daily automated backups

---

### **4.7 Security Architecture**

**API Authentication (Cognito + Lambda Authorizer):**

| Role | Permissions |
|------|-------------|
| Administrator | Full access, user management, SDN rule changes |
| Security Engineer | Read/write rules, SDN query, PCAP access |
| Security Analyst | Read alerts, run queries, request isolation (IT only) |
| Viewer | Read-only dashboard |

**Secrets Management (AWS Secrets Manager):**
- VirusTotal, Recorded Future, AlienVault API keys
- ClickHouse, PostgreSQL credentials
- ONOS API credentials
- Slack webhook, PagerDuty key
- WireGuard private keys (external storage)

---

## 5. Technology Stack Justifications

### **5.1 OpenVSwitch vs. Managed Switch SPAN**

| Attribute | Traditional SPAN | OpenVSwitch |
|-----------|-----------------|-------------|
| Configuration | Physical switch CLI | API / code |
| Granularity | Port-level | Flow-level |
| Dynamic changes | Minutes (manual) | Seconds (API) |
| Research flexibility | Fixed | Configurable per experiment |
| Cost | Depends on switch | Free (software) |
| Performance | Line rate | Near line rate (kernel module) |
| **Decision** | Baseline | **Selected** |

### **5.2 ONOS vs. OpenDaylight vs. Floodlight**

| Controller | Maturity | OVS Support | API Quality | Community |
|------------|----------|-------------|-------------|-----------|
| **ONOS** | Production | Excellent | REST + Intent | Strong |
| OpenDaylight | Production | Good | Complex | Declining |
| Floodlight | Research | Good | Simple | Small |
| **Decision** | | | | **ONOS selected** |

ONOS wins: Intent-based networking matches our policy model, strong OVS integration, active community.

### **5.3 Zeek vs. Alternatives for OT Protocol Analysis**

| Tool | OT Protocol Support | Extensibility | Passive | Cost |
|------|---------------------|--------------|---------|------|
| **Zeek** | Modbus, + custom scripting | Full scripting language | Yes | Free |
| Wireshark | Excellent (all protocols) | Limited automation | Yes | Free |
| Claroty | Excellent (commercial) | Closed | Yes | $100K+/yr |
| Dragos | Excellent (commercial) | Closed | Yes | $200K+/yr |
| **Decision** | | | | **Zeek selected** |

Zeek wins: custom scripting language enables research, free, passive by design, production-proven.

### **5.4 Statistical Detection vs. Machine Learning**

| Approach | Interpretability | Data Required | Compute | Auditable | Research Value |
|----------|-----------------|---------------|---------|-----------|----------------|
| **Statistical (CV, entropy)** | High | 30-day baseline | Low | Yes | High (publishable) |
| ML (Isolation Forest, LSTM) | Low-Medium | Weeks+ labeled data | Medium | Partial | Medium |
| Rule-based (Sigma) | Very High | None | Very Low | Yes | High |
| **Decision** | | | | | **Statistical + Rules** |

Statistical methods win for a research platform: results are explainable, reproducible, and suitable for academic publication without specialized ML infrastructure.

---

## 6. Attack Scenario Walkthroughs

### **Scenario 1: Chinese Robot Supply Chain Attack**

**Threat Actor:** APT41 (Double Dragon)
**Target:** DoBot Robot #3 (192.168.110.12)

**Detection Timeline:**
```
T+0:00  Robot boots with compromised firmware
T+0:15  First DNS query: update.dobot-controller.cn
        └─ Zeek dns.log: c2-beaconing.zeek flags .cn domain
        └─ Lambda Stage 6: CTI lookup → known APT41 domain
T+0:30  TCP connection to 202.108.22.5:443
        └─ Suricata: Custom rule 9100001 fires (Robot VLAN → Chinese IP)
        └─ Zeek conn.log: chinese-robot-detection.zeek fires
T+0:45  Large HTTPS upload (2GB outbound)
        └─ Zeek: large-upload-detection.zeek fires (Z-score: 8.4)
        └─ Zeek ssl.log: Unknown JA3 hash flagged
T+1:00  Lambda correlates 3 independent signals
        └─ Creates CRITICAL alert: "Multi-signal supply chain indicator"
        └─ MITRE tag: T0862 (Transient Cyber Asset)
        └─ PagerDuty + Slack notification sent
T+1:05  Analyst reviews dashboard
        └─ PCAP retrieved from ring buffer (last 60 min)
        └─ tshark confirms C2 traffic pattern
T+1:10  Analyst manually isolates robot (unplugs network cable)
        → No automated OT isolation — human decision required
```

### **Scenario 2: Modbus Parameter Manipulation (Stuxnet-Style)**

**Threat Actor:** Unknown nation-state
**Target:** Siemens S7-1200 PLC (192.168.100.10)

**Detection Timeline:**
```
T+0:00  Engineer opens phishing email with HMI exploit
        └─ Sysmon Event 1: Suspicious macro process creation
        └─ Wazuh Rule: Unauthorized process alert
T+0:10  Workstation initiates Modbus connection to PLC
        └─ Zeek lateral-movement.zeek: IT→PLC unexpected connection
T+0:15  Modbus FC16 (Write Multiple Registers) from workstation
        └─ Zeek modbus-deep-analysis.zeek:
           "Unauthorized Modbus write from 192.168.30.45"
           (workstation not in AUTHORIZED_WRITERS set)
        └─ Suricata: Custom rule 9100002 fires
        └─ MITRE tag: T0836 (Modify Parameter) — CRITICAL
T+0:20  Temperature setpoint write detected (register 200 → SAFETY ZONE)
        └─ Lambda Stage 5: Safety rule fires
           "Write to PLC safety zone registers — CRITICAL"
T+0:25  All signals correlated: engineer workstation compromise
        → Safety Guardrail: PLC actions REQUIRE human approval
        → Analyst notified: "DO NOT auto-isolate PLC — process running"
T+0:30  Analyst response:
        → Disconnect engineering workstation (IT device — safe to isolate)
        → Manual PLC ladder logic comparison to verified backup
        → Physical inspection of PLC, manual parameter restoration
```

---

## 7. Performance Targets

### **Detection Performance**

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Detection latency | <60 seconds | Time from event to dashboard alert |
| False positive rate | <5% | Human-reviewed alert audit |
| True positive rate | >85% | Red team exercise coverage |
| Pyramid of Pain L1–L5 | 5/5 levels covered | Red team: 1 scenario per level |
| MITRE ATT&CK ICS | 81/81 techniques tagged | Rule-to-technique coverage matrix |
| Zeek uptime | >99% | CloudWatch monitoring |

### **Infrastructure Performance**

| Metric | Target |
|--------|--------|
| Event processing | 10K events/sec |
| ClickHouse query (p95) | <1 second |
| Dashboard load | <2 seconds |
| ClickHouse RTO | <15 minutes |
| PostgreSQL RTO | <2 minutes |

### **Research Performance**

| Metric | Target |
|--------|--------|
| C2 beaconing detection (CV method) | >90% TP rate on synthetic test set |
| DGA detection (entropy method) | >85% TP rate on Bambenek DGA corpus |
| Modbus anomaly detection | >95% TP on authorized writer violations |
| OPC UA recon detection | >80% TP on BrowseRequest enumeration |

---

## 8. Cost Analysis

### **Monthly Breakdown (~$178/month)**

| Category | Services | Monthly Cost | % of Total |
|----------|----------|--------------|------------|
| **Compute** | EC2 t4g.small ×2 (ClickHouse), RDS t3.micro | $95 | 53% |
| **Data** | Kinesis Firehose, S3, Lambda | $25 | 14% |
| **Security** | Secrets Manager, Cognito, CloudWatch | $21 | 12% |
| **Networking** | API Gateway, VPN data transfer | $17 | 10% |
| **DR** | ClickHouse replica, S3 cross-region | $20 | 11% |

**Cost vs. Commercial OT Security Solutions:**

| Solution | Annual Cost | Notes |
|----------|-------------|-------|
| **RobotLab (this system)** | ~$2,136/year | Open-source, custom |
| Claroty | ~$120,000/year | Per-asset licensing |
| Dragos | ~$200,000/year | Enterprise OT security |
| Nozomi Networks | ~$80,000/year | Passive OT monitoring |
| **Savings vs. commercial** | **97-99% cheaper** | |

**No Bedrock/AI API costs** (statistical methods used instead).

---

## 9. Risk Mitigation

### **Technical Risks**

| Risk | Mitigation |
|------|------------|
| Zeek missing OT protocols | Custom Zeek scripts + PCAP forensics as backup |
| OVS performance degradation | Monitor CPU, fallback to SPAN port if >80% CPU |
| PCAP ring buffer full before forensics | Alert when >70% used, increase to 4GB buffer |
| Statistical threshold too sensitive | Weekly tuning with analyst feedback |
| False positive on Modbus baseline | 30-day baseline before alerting, per-PLC tuning |

### **Operational Risks**

| Risk | Mitigation |
|------|------------|
| SDN controller failure | pfSense rules remain active, OVS fails open (passthrough) |
| Analyst makes wrong isolation call | OT devices always require physical intervention |
| Chemistry machine TAP interference | Inline TAP tested passively, no active components |
| CISA feed downtime | Cached indicators, 7-day TTL, alert if feed stale >24h |

### **Research Risks**

| Risk | Mitigation |
|------|------------|
| Statistical thresholds not validated | Test against synthetic attack traffic in Week 22 |
| Zeek script resource exhaustion | Profile CPU/memory per script, disable if >10% overhead |
| SDN comparison study inconclusive | Instrument both approaches simultaneously for direct comparison |

---

## 10. Research Contributions Summary

### **Novel Zeek Scripts (Open-Source Release)**

| Script | Protocol | Contribution |
|--------|----------|--------------|
| `modbus-deep-analysis.zeek` | Modbus TCP | Comprehensive FC + register baseline tracking |
| `modbus-coil-monitor.zeek` | Modbus TCP | Safety coil write detection |
| `modbus-exception-tracking.zeek` | Modbus TCP | Exception code rate analysis |
| `opcua-session-tracking.zeek` | OPC UA | Session + BrowseRequest recon detection |
| `opcua-write-monitor.zeek` | OPC UA | WriteRequest authorization enforcement |
| `ethernetip-cip-analysis.zeek` | EtherNet/IP | CIP service code analysis |
| `tls-ja3-fingerprinting.zeek` | TLS | C2 fingerprint detection |
| `c2-beaconing.zeek` | TCP | CV-based beacon detection |
| `dns-dga-detection.zeek` | DNS | Shannon entropy DGA detection |

### **SDN Architecture Reference Implementation**

Published design: OVS + ONOS + OpenFlow 1.3 for OT network security research, including:
- Per-VLAN dynamic mirroring
- Analyst-triggered IT device isolation
- Side-by-side comparison methodology vs. SPAN

### **Validated Detection Benchmarks**

Benchmarks for Week 22 red team exercise:
- Statistical detection methods vs. synthetic attack corpus
- Zeek protocol coverage vs. manufacturer protocol documentation
- SDN mirror completeness vs. SPAN port baseline

---

## Conclusion

This architecture delivers a **research-grade OT security platform** with:

**Deep Packet Analysis:** Custom Zeek dissectors for Modbus TCP, OPC UA, and EtherNet/IP provide protocol-level visibility unavailable in commercial tools.

**SDN-Enhanced Monitoring:** OpenVSwitch + ONOS enables programmable traffic steering and measurable comparison between monitoring strategies.

**Statistical Detection:** Coefficient-of-variation beaconing detection and Shannon entropy DGA analysis are transparent, auditable, and publication-ready.

**OT Safety-First:** Passive monitoring throughout, physical-only intervention for PLCs and chemistry machine, statistical baselines built before alerting.

**Research Platform:** Every component generates measurable data answering specific research questions, with open-source outputs suitable for academic contribution.

**Technology decisions driven by:**
- **Transparency** (statistical > black-box ML for academic context)
- **Passive safety** (never disrupt OT operations)
- **Research reproducibility** (documented baselines and thresholds)
- **Cost efficiency** (open-source throughout, no AI API costs)

**Next Steps:** See `EXECUTION-PLAN.md` for 22-week build timeline with 7-person team assignments.

---

**Document Version:** 3.0
**Last Updated:** 2026-02-20
**Status:** Design Phase — Research Platform

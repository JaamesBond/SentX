# RobotLab OT/ICS Security: 22-Week Execution Plan
**Version 3.0 - Research Platform Build**

**Purpose:** Step-by-step implementation plan with weekly tasks and team assignments
**Audience:** 7-person research team, project supervisor
**Companion Document:** `TECHNICAL-ARCHITECTURE.md` (complete technical design)

---

## Executive Summary

**Timeline:** 22 weeks (5.5 months)
**Budget:** ~$178/month operational + $400–1,350 one-time hardware
**Team:** 7 people with defined specializations
**Outcome:** Research-grade OT security platform with deep packet analysis and SDN capabilities

---

## Team Structure

| Role | Code | Responsibilities |
|------|------|-----------------|
| **Project Lead / Architect** | PL | Architecture decisions, research methodology, cross-team coordination, academic report |
| **Network & SDN Engineer** | NET | pfSense, OpenVSwitch, ONOS SDN controller, VLAN configuration |
| **Packet Analysis Researcher** | PKT | Custom Zeek scripts, OT protocol dissectors, PCAP forensics, statistical detectors |
| **OT/ICS Security Engineer** | OT | PLC monitoring, Modbus/OPC UA research, field device safety, OT threat modeling |
| **Host Security Engineer** | HOST | Wazuh deployment, Sysmon, FIM, Sigma rules, host-based detection |
| **Cloud & Infrastructure Engineer** | INFRA | AWS, Terraform, Docker, data pipeline, disaster recovery |
| **CTI & Frontend Engineer** | CTI | Threat intelligence, React dashboard, MITRE ATT&CK mapping, documentation |

**Work Stream Legend:**
- `ALL` = All 7 team members
- `PL` = Project Lead
- `NET` = Network & SDN Engineer
- `PKT` = Packet Analysis Researcher
- `OT` = OT/ICS Security Engineer
- `HOST` = Host Security Engineer
- `INFRA` = Cloud & Infrastructure Engineer
- `CTI` = CTI & Frontend Engineer

---

## Phase Overview

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|-----------------|
| **1** | 1–4 | Foundation: network + infrastructure | VLANs, Zeek, Suricata, OVS planning, L1–L2 baseline |
| **2** | 5–9 | Core monitoring deployment | Wazuh (L1), SDN deploy, OT protocol parsers v1 (L4) |
| **3** | 10–13 | Protocol research & SDN + L3–L4 detectors | Deep OT dissectors, ONOS, DGA/beaconing (L3–L4) |
| **4** | 14–17 | L5 detection, dashboard, CTI integration | Sigma/tool rules (L5), Pyramid heatmap, full CTI |
| **5** | 18–19 | Integration & testing | End-to-end L1–L5 coverage, load tests, chaos |
| **6** | 20–21 | Operational excellence | Playbooks, monitoring, research documentation |
| **7** | 22 | Validation & presentation | Red team: 1 scenario per Pyramid level (L1–L5) |

---

## Detailed Week-by-Week Plan

### **PHASE 1: Foundation (Weeks 1–4)**

---

#### **Week 1: Team Kickoff & Asset Inventory**

| Day | Who | Task |
|-----|-----|------|
| Mon | ALL | Team kickoff: assign roles, set up project board (GitHub), communication channels |
| Mon | PL | Define 4 research questions, draft research methodology document |
| Tue | ALL | Physical asset inventory: document all 28 devices (IP, MAC, OS, firmware) |
| Tue | OT | Document OT protocol matrix (which PLC uses Modbus vs. OPC UA vs. EtherNet/IP) |
| Wed | PL + NET | Design VLAN topology (6 VLANs, Purdue Model), draw network diagram |
| Wed | INFRA | Set up GitHub repo, Terraform skeleton, CI/CD pipeline |
| Thu | NET | Design firewall rule matrix (Excel) — 200+ rules |
| Thu | PKT | Research Zeek OT protocol support — identify gaps requiring custom scripts |
| Fri | ALL | Procurement: managed switch ($150–300), Raspberry Pi 4 ($100), network TAP ($100–200) |
| Fri | CTI | Set up project documentation wiki, research bibliography |

**Deliverables:**
- [ ] Network diagram with 6 VLANs and Purdue Model
- [ ] 28-device asset inventory (IP, MAC, protocol, firmware)
- [ ] OT protocol matrix (Modbus/OPC UA/EtherNet/IP per device)
- [ ] Firewall rule matrix (draft)
- [ ] GitHub repo + project board operational
- [ ] Research questions formally defined

---

#### **Week 2: VLAN Configuration & Network Infrastructure**

| Day | Who | Task |
|-----|-----|------|
| Mon | NET | Configure managed switch: create 6 VLANs (10, 20, 30, 100, 110, 200) |
| Mon | OT | Map physical cable runs: which switch port → which OT device |
| Tue | NET | Deploy pfSense on dedicated hardware, configure WAN/LAN interfaces |
| Tue | HOST | Plan Wazuh deployment: which agents on which hosts |
| Wed | NET | Implement firewall rules (pfSense): VLAN isolation, inter-VLAN whitelist |
| Wed | INFRA | Deploy AWS VPC, subnets, security groups (Terraform) |
| Thu | NET | Install network TAP on chemistry machine VLAN (passive, inline) |
| Thu | OT | Verify chemistry machine isolation: no routable path from any VLAN |
| Fri | NET | Test VLAN isolation (ping tests, packet captures) |
| Fri | INFRA | AWS: Deploy RDS PostgreSQL Multi-AZ (Terraform) |

**Deliverables:**
- [ ] 6 VLANs operational (10, 20, 30, 100, 110, 200)
- [ ] pfSense enforcing firewall rules
- [ ] Chemistry machine TAP installed (passive only)
- [ ] AWS VPC + RDS deployed
- [ ] VLAN isolation validated (no unauthorized cross-VLAN traffic)

---

#### **Week 3: IDS/IPS + Zeek Initial Deployment**

| Day | Who | Task |
|-----|-----|------|
| Mon | NET | Install Suricata 7.0 on pfSense, load ET Open rules |
| Mon | PKT | Install Zeek 6.0 on Raspberry Pi (VLAN 20) |
| Tue | NET | Configure Suricata OT mode: alert-only on OT VLANs, block on IT VLAN |
| Tue | PKT | Configure Zeek `node.cfg`, `networks.cfg` for 6 VLANs |
| Wed | NET | Load ET Pro OT/ICS rules into Suricata (Modbus, OPC UA, DNP3) |
| Wed | PKT | Verify Zeek generating all 7 standard log types (conn, dns, http, ssl, files, weird, x509) |
| Thu | PKT | Write first custom Zeek script: `modbus-violation.zeek` (basic FC anomaly) |
| Thu | OT | Test Modbus communication with PLC in controlled environment |
| Fri | NET | Tune Suricata: reduce false positives to <10/day on known benign traffic |
| Fri | PKT | Write custom Zeek script: `chinese-robot-detection.zeek` (IP + DNS patterns) |

**Deliverables:**
- [ ] Suricata 7.0 operational, <10 FPs/day
- [ ] Zeek 6.0 generating all 7 log types
- [ ] First 2 custom Zeek scripts committed to repo
- [ ] Zeek generating Modbus logs from PLC traffic

---

#### **Week 4: OT Protocol Monitoring + Baseline Start**

| Day | Who | Task |
|-----|-----|------|
| Mon | PKT + OT | Configure Zeek Modbus parser: log all function codes, register addresses |
| Mon | NET | Plan OpenVSwitch deployment (hardware + config design) |
| Tue | PKT | Write `c2-beaconing.zeek` (connection interval tracking, prep for statistical analysis) |
| Tue | OT | Document Modbus register maps for all PLCs (baseline reference) |
| Wed | INFRA | Deploy ClickHouse EC2 PRIMARY (us-east-1a) with initial schema |
| Wed | CTI | Research CTI feed APIs: CISA ICS-CERT, AlienVault OTX, Recorded Future |
| **Thu** | ALL | **START 30-DAY BASELINE COLLECTION** — critical dependency for Week 14+ detection tuning |
| Thu | INFRA | Configure Filebeat on Raspberry Pi → Kinesis Firehose (TLS 1.3) |
| Fri | ALL | Phase 1 review: verify all systems operational, baseline collection confirmed |
| Fri | PL | Research checkpoint: update research questions based on Week 1–4 findings |

**Deliverables:**
- [ ] Modbus baseline collection started (runs 30 days)
- [ ] 3 custom Zeek scripts operational
- [ ] ClickHouse receiving Zeek logs
- [ ] Baseline data pipeline verified end-to-end
- [ ] **CHECKPOINT: Phase 1 complete**

---

### **PHASE 2: Core Monitoring Deployment (Weeks 5–9)**

---

#### **Week 5: Wazuh HIDS + OPC UA Monitoring**

| Day | Who | Task |
|-----|-----|------|
| Mon | HOST | Deploy Wazuh Manager (Docker, VLAN 20) |
| Mon | PKT | Write `opcua-session-tracking.zeek` (session establishment, BrowseRequest tracking) |
| Tue | HOST | Install Wazuh agents: 3× Windows workstations |
| Tue | OT | Research OPC UA configuration on engineering servers |
| Wed | HOST | Install Wazuh agents: 2× Linux servers + 4× Raspberry Pi |
| Wed | PKT | Write `opcua-write-monitor.zeek` (WriteRequest authorization) |
| Thu | HOST | Configure FIM: firmware paths, PLC ladder logic, chemistry machine config |
| Thu | INFRA | Deploy ClickHouse REPLICA (us-east-1b), configure async replication |
| Fri | HOST | Integrate VirusTotal API with Wazuh FIM (file hash lookups) |
| Fri | NET | Begin OpenVSwitch planning: hardware procurement, bridge design |

**Deliverables:**
- [ ] 9 Wazuh agents reporting
- [ ] FIM operational on all critical paths
- [ ] OPC UA Zeek scripts complete
- [ ] ClickHouse Multi-AZ replicating

---

#### **Week 6: Sysmon + Sigma Rules + SDN Hardware**

| Day | Who | Task |
|-----|-----|------|
| Mon | HOST | Deploy Sysmon v15 on 3× Windows workstations (SwiftOnSecurity config) |
| Mon | NET | Install OpenVSwitch 3.x on Raspberry Pi VLAN 20 |
| Tue | HOST | Configure Wazuh process monitoring: unauthorized tool detection (Mimikatz, nc, PSExec) |
| Tue | NET | Create OVS bridge `br-robotlab`, configure uplink to pfSense |
| Wed | HOST | Convert 50 Sigma rules to Wazuh XML using pySigma |
| Wed | NET | Configure OVS per-VLAN mirroring to Zeek capture interface |
| Thu | CTI | Write Lambda functions for CTI feed ingestion (CISA + AlienVault) |
| Thu | NET | Test OVS mirror: verify Zeek receives traffic from OVS (not just SPAN) |
| Fri | HOST | Test detection rules: verify brute force, unauthorized process alerts |
| Fri | PKT | Write `tls-ja3-fingerprinting.zeek` (JA3 hash computation + blocklist) |

**Deliverables:**
- [ ] Sysmon operational on all Windows hosts
- [ ] 50 Sigma rules loaded and tested
- [ ] OpenVSwitch bridge operational, mirroring to Zeek
- [ ] JA3 fingerprinting Zeek script complete

---

#### **Week 7: Wazuh Tuning + PCAP Forensics Setup**

| Day | Who | Task |
|-----|-----|------|
| Mon | HOST | Tune Wazuh alerts: suppress known false positives, adjust severity levels |
| Mon | PKT | Set up PCAP ring buffer: `tcpdump -C 100 -W 20` on OVS capture interface |
| Tue | HOST | Configure vulnerability detection in Wazuh (CVE scanning) |
| Tue | PKT | Write Wireshark profiles for OT protocols (Modbus, OPC UA, TLS-JA3) |
| Wed | HOST | Configure alert notifications (email + Slack) |
| Wed | INFRA | Lambda: `ot-event-processor` v1.0 (Stages 1–4) |
| Thu | PKT | Document forensic analysis workflow (tshark commands, Wireshark profiles) |
| Thu | NET | Deploy ONOS SDN controller (Docker on VLAN 20) |
| Fri | ALL | Verify 30-day baseline collection is on track (check data volume) |
| Fri | CTI | Write Lambda functions: Recorded Future + Abuse.ch feeds |

**Deliverables:**
- [ ] Wazuh alerts tuned (<20 alerts/day baseline)
- [ ] PCAP ring buffer running (2GB, ~60min capture window)
- [ ] Wireshark OT profiles documented
- [ ] ONOS SDN controller reachable
- [ ] Lambda event processor v1.0 operational

---

#### **Week 8: AWS Infrastructure Completion + ONOS Initial**

| Day | Who | Task |
|-----|-----|------|
| Mon | INFRA | Complete Terraform: all AWS resources defined (EC2, RDS, S3, Lambda, Kinesis, Cognito) |
| Mon | NET | Connect ONOS to OVS via OpenFlow 1.3 (verify `ovs-ofctl dump-flows`) |
| Tue | INFRA | S3 buckets: `robotlab-backups`, `robotlab-pcap-archives` (versioning + encryption) |
| Tue | NET | Test ONOS REST API: push test flow rule, verify OVS applies it |
| Wed | INFRA | Lambda: complete Stages 5–7 in `ot-event-processor` |
| Wed | CTI | Create PostgreSQL CTI tables (IP, domain, hash, advisory schemas) |
| Thu | INFRA | Configure AWS Secrets Manager, store all credentials, test Lambda access |
| Thu | CTI | All 5 CTI feeds populating PostgreSQL (verify with test lookups) |
| Fri | NET | ONOS intent: IT VLAN → PLC VLAN whitelist (Modbus TCP/502 only) |
| Fri | PKT | Write `lateral-movement.zeek` (cross-VLAN unexpected connections) |

**Deliverables:**
- [ ] All AWS resources deployed via Terraform
- [ ] ONOS ↔ OVS OpenFlow connection verified
- [ ] CTI database populated with real feed data
- [ ] Lambda pipeline end-to-end (event → ClickHouse)

---

#### **Week 9: Disaster Recovery + Secrets + Pipeline Validation**

| Day | Who | Task |
|-----|-----|------|
| Mon | INFRA | Setup automated ClickHouse backups to S3 (daily 2AM, 7/4/12 retention) |
| Mon | CTI | Build CTI health monitoring Lambda (alert if feed stale >24h) |
| Tue | INFRA | Configure weekly auto-rotation for DB passwords in Secrets Manager |
| Tue | CTI | APT group profiles: APT10 (Stone Panda), APT41 (Double Dragon), Lazarus |
| Wed | INFRA | **TEST DISASTER RECOVERY**: terminate ClickHouse primary, measure failover time |
| Wed | PKT | Write `dns-dga-detection.zeek` (Shannon entropy, test against Bambenek DGA list) |
| Thu | INFRA | Fix any DR issues, re-test. Document RTO/RPO results |
| Thu | PKT | Write `large-upload-detection.zeek` (volume Z-score per host) |
| Fri | ALL | End-to-end pipeline test: generate test events, verify full flow to dashboard |
| Fri | PL | Phase 2 review, update research findings, adjust Week 10+ plan if needed |

**Deliverables:**
- [ ] Disaster recovery tested: RTO <15 min, RPO <1 hour
- [ ] All secrets in Secrets Manager (no hardcoded credentials)
- [ ] DGA detection Zeek script validated against DGA corpus
- [ ] Large upload detection calibrated to per-host baselines
- [ ] **CHECKPOINT: Phase 2 complete**

---

### **PHASE 3: Protocol Research & SDN Development (Weeks 10–13)**

---

#### **Week 10: Modbus Deep Research + ONOS Flow Rules**

| Day | Who | Task |
|-----|-----|------|
| Mon | PKT + OT | Write `modbus-deep-analysis.zeek`: comprehensive FC tracking, register baseline |
| Mon | NET | Write ONOS Python SDK scripts for flow rule management |
| Tue | PKT + OT | Document Modbus register maps for all PLCs (safety zones, setpoints, read-only) |
| Tue | NET | Implement whitelist flow intents in ONOS (per-device level) |
| Wed | PKT | Write `modbus-register-baseline.zeek`: 30-day baseline comparison per PLC |
| Wed | NET | Compare OVS mirror vs. SPAN port: measure packet capture completeness |
| Thu | PKT + OT | Write `modbus-exception-tracking.zeek`: exception code rate analysis |
| Thu | INFRA | API Gateway + Lambda: query endpoints for dashboard |
| Fri | PKT | Validate all 3 Modbus scripts against live PLC traffic |
| Fri | CTI | Begin React dashboard scaffolding (project setup, component architecture) |

**Deliverables:**
- [ ] 3 Modbus Zeek scripts complete and validated
- [ ] ONOS whitelist intents operational
- [ ] OVS vs. SPAN comparison documented (Research Q R2)
- [ ] Dashboard scaffolding in repo

---

#### **Week 11: EtherNet/IP + CISA CTI Integration**

| Day | Who | Task |
|-----|-----|------|
| Mon | PKT | Write `ethernetip-cip-analysis.zeek`: CIP service codes, Forward Open tracking |
| Mon | CTI | Implement CISA ICS-CERT Lambda: auto-ingest advisories → PostgreSQL |
| Tue | PKT | Research DNP3 in RobotLab: does any device use it? Document findings |
| Tue | INFRA | Lambda: MITRE ATT&CK for ICS data loader (81 techniques, 12 tactics) |
| Wed | OT | Document OT threat model: which assets are highest-value targets? |
| Wed | CTI | MITRE ATT&CK for ICS: map all current detection rules to techniques |
| Thu | PKT | Write `modbus-coil-monitor.zeek`: discrete output coil manipulation detection |
| Thu | CTI | Dashboard: Alert feed component (real-time, severity-sorted) |
| Fri | PKT | Validate EtherNet/IP script against Allen-Bradley PLC traffic |
| Fri | ALL | Mid-point research review: present findings from Weeks 1–11 to team |

**Deliverables:**
- [ ] EtherNet/IP CIP Zeek script complete
- [ ] CISA ICS-CERT advisory ingestion working
- [ ] MITRE ATT&CK technique-to-rule mapping complete
- [ ] Dashboard alert feed rendering live data

---

#### **Week 12: Statistical Detectors + SDN Security Primitives**

| Day | Who | Task |
|-----|-----|------|
| Mon | PKT | Implement C2 beaconing detector (CV method): Python module + Zeek integration |
| Mon | NET | Implement ONOS reactive isolation: REST API for analyst-triggered IT device isolation |
| Tue | PKT | Benchmark CV detector against synthetic C2 traffic (Metasploit beacon test) |
| Tue | NET | Test analyst-triggered isolation: workstation isolate → verify OVS flow rule applied |
| Wed | PKT | Implement DGA entropy detector: validate against Bambenek DGA corpus (top 1000) |
| Wed | CTI | Dashboard: Network topology view (Purdue Model, VLAN layout, live connections) |
| Thu | PKT | Implement volume exfiltration baseline (per-host Z-score, rolling 30-day window) |
| Thu | HOST | Threat hunting queries: document 3 hypothesis-driven hunts with ClickHouse SQL |
| Fri | PKT | Statistical detector benchmark report: TP rate, FP rate, methodology |
| Fri | NET | Document SDN vs. traditional segmentation comparison (Research Q R2) |

**Deliverables:**
- [ ] C2 beaconing detector validated (>90% TP on synthetic test)
- [ ] DGA detector validated (>85% TP on Bambenek corpus)
- [ ] Volume exfil detection calibrated per host
- [ ] Analyst-triggered isolation tested and documented
- [ ] Statistical detector benchmark report written

---

#### **Week 13: Integration + Research Checkpoint**

| Day | Who | Task |
|-----|-----|------|
| Mon | ALL | Integration test: fire known Modbus violation, verify full path to dashboard |
| Tue | PKT | Document all 13 Zeek scripts: purpose, research question, detection logic |
| Tue | CTI | Dashboard: MITRE ATT&CK coverage heatmap (12 tactics × 81 techniques) |
| Wed | OT | Prepare attack scenarios for Week 22 red team exercise |
| Wed | NET | Complete ONOS traffic steering: alert → analyst → API call → targeted PCAP |
| Thu | PL | Write research interim report: findings from Protocol Analysis tracks |
| Thu | CTI | Dashboard: Protocol analysis view (Modbus FC distribution, OPC UA session activity) |
| Fri | ALL | Phase 3 review: verify all research tracks on schedule |
| Fri | PL | Adjust Week 14+ plan based on Phase 3 findings |

**Deliverables:**
- [ ] All 13 Zeek scripts committed, documented
- [ ] Integration test: event → alert → dashboard confirmed end-to-end
- [ ] Research interim report (R1, R2, R3 findings to date)
- [ ] Attack scenario scripts prepared for Week 22
- [ ] **CHECKPOINT: Phase 3 complete**

---

### **PHASE 4: Advanced Detection & Dashboard (Weeks 14–17)**

---

#### **Week 14: Detection Rule Library + SDN Research Analysis**

| Day | Who | Task |
|-----|-----|------|
| Mon | PKT | Finalize Zeek script library: unit tests for every script |
| Mon | NET | Complete SDN research analysis: OVS mirror vs. SPAN measurement report |
| Tue | HOST | Write all missing Sigma rules: FIM violations, process anomalies, network anomalies |
| Tue | CTI | Write all custom Suricata rules (see Technical Architecture Section 4.3) |
| Wed | PKT | Peer review all detection rules: false positive analysis |
| Wed | CTI | Dashboard: SDN flow rule monitor (active ONOS intents, OVS flow table) |
| Thu | INFRA | Load testing: 10K events/sec through Lambda pipeline (Locust) |
| Thu | OT | OT threat hunting: run 3 hypothesis-driven ClickHouse queries |
| Fri | ALL | Detection library review: sign-off on all 50+ rules |
| Fri | PL | Update research questions based on Phase 3+4 findings |

**Deliverables:**
- [ ] All Zeek scripts with unit tests
- [ ] 50+ Sigma rules in repo
- [ ] Custom Suricata rules tested
- [ ] SDN research analysis report (Research Q R2 answer)
- [ ] Load test passed: 10K events/sec

---

#### **Week 15: Dashboard + PCAP Forensics Integration**

| Day | Who | Task |
|-----|-----|------|
| Mon | CTI | Dashboard: Threat hunting workspace (ClickHouse SQL query interface) |
| Mon | PKT | Integrate PCAP retrieval into dashboard: analyst can request PCAP from incident |
| Tue | CTI | Dashboard: Add SDN view — list active ONOS intents, trigger isolation from UI |
| Tue | INFRA | API: PCAP retrieval endpoint (authenticated, RBAC: Security Engineer+) |
| Wed | CTI | Dashboard polish: loading states, error handling, responsive layout |
| Wed | HOST | Wazuh: configure FIM diff alerts (firmware change detection with content) |
| Thu | PKT | Benchmark statistical detectors with 30-day baseline data (vs. Week 12 synthetic) |
| Thu | OT | Document OT incident response procedure: each OT device type |
| Fri | ALL | Dashboard UAT: team reviews all 6 views for usability |
| Fri | CTI | Fix UAT issues |

**Deliverables:**
- [ ] All 6 dashboard views operational
- [ ] PCAP retrieval from dashboard working
- [ ] SDN isolation UI working
- [ ] Threat hunting workspace accepting ClickHouse queries

---

#### **Week 16: Alerting + Cost Optimization**

| Day | Who | Task |
|-----|-----|------|
| Mon | INFRA | Setup Prometheus + Grafana (monitoring stack) |
| Mon | CTI | Configure PagerDuty integration: critical alert → on-call notification |
| Tue | INFRA | Setup CloudWatch cost monitoring: alert if >$200/month |
| Tue | HOST | Wazuh vulnerability scanner: integrate with CISA ICS-CERT CVE database |
| Wed | INFRA | Optimize Lambda cold start: minimize dependencies, provisioned concurrency if needed |
| Wed | NET | Final ONOS configuration: document all intents, publish SDN architecture diagram |
| Thu | INFRA | ClickHouse query optimization: add indices, verify p95 <1s |
| Thu | CTI | Grafana dashboards: system health, alert rate, protocol statistics |
| Fri | ALL | Cost review: verify ~$178/month target |
| Fri | PL | Research Q R3 documentation: protocol anomaly catalog draft |

**Deliverables:**
- [ ] Prometheus + Grafana operational
- [ ] PagerDuty alerts configured
- [ ] Cost monitoring active
- [ ] ClickHouse query p95 <1s verified

---

#### **Week 17: End-to-End Integration Testing**

| Day | Who | Task |
|-----|-----|------|
| Mon | ALL | System integration test: Scenario 1 (Chinese Robot Supply Chain) — observe but do not respond |
| Tue | ALL | System integration test: Scenario 2 (Modbus Parameter Manipulation) |
| Wed | PKT + OT | Review detection results: any missed detections? Add rules if needed |
| Wed | NET | Review SDN response: was analyst-triggered isolation smooth? |
| Thu | ALL | Fix all blocking issues from integration tests |
| Thu | INFRA | Chaos test: terminate ClickHouse primary, verify failover <15 min |
| Fri | ALL | Re-run integration tests after fixes |
| Fri | PL | Phase 4 review: all systems ready for Phase 5 |

**Deliverables:**
- [ ] Both integration test scenarios detected successfully
- [ ] All blocking issues resolved
- [ ] Chaos test passed (RTO <15 min)
- [ ] **CHECKPOINT: Phase 4 complete**

---

### **PHASE 5: Integration & Testing (Weeks 18–19)**

---

#### **Week 18: Security Hardening + API Authentication**

| Day | Who | Task |
|-----|-----|------|
| Mon | INFRA | Deploy AWS Cognito: user pools, app clients |
| Mon | CTI | Implement Lambda Authorizer: JWT validation, RBAC role check |
| Tue | INFRA | Implement RBAC: 4 roles (Admin, Engineer, Analyst, Viewer) |
| Tue | CTI | Integrate Cognito into React dashboard: login flow, JWT storage |
| Wed | INFRA | Audit logging: all API calls logged to CloudWatch + PostgreSQL |
| Wed | HOST | Final Wazuh rule tuning: <20 alerts/day target |
| Thu | INFRA | Security review: check all Lambda functions, IAM policies, S3 permissions |
| Thu | NET | Final OVS + ONOS security review: API auth, flow rule validation |
| Fri | ALL | Security test: attempt unauthorized API access, verify blocked |
| Fri | PKT | Research Q R1 documentation: Zeek protocol coverage analysis |

**Deliverables:**
- [ ] Cognito authentication enforced on all API endpoints
- [ ] 4 RBAC roles working (test each role's access)
- [ ] Audit logging operational
- [ ] Security review completed, issues resolved

---

#### **Week 19: Load Testing + Final Tuning**

| Day | Who | Task |
|-----|-----|------|
| Mon | INFRA | Load test: Locust generates 2× expected event volume for 1 hour |
| Mon | ALL | Monitor: Lambda, ClickHouse, dashboard under load |
| Tue | INFRA | Fix any performance issues found in load test |
| Tue | PKT | Final statistical detector calibration: adjust thresholds based on 30-day baseline |
| Wed | ALL | Chaos engineering: 5 failure scenarios |
|     |      | 1. ClickHouse primary failure |
|     |      | 2. Lambda function timeout spike |
|     |      | 3. Zeek process crash |
|     |      | 4. ONOS controller restart |
|     |      | 5. Network TAP disconnection |
| Thu | ALL | Remediate any chaos test failures |
| Thu | OT | OT safety validation: verify no system can auto-isolate OT device |
| Fri | ALL | Final pre-Phase 7 checklist review |
| Fri | PL | Phase 5 review, confirm Week 22 attack scenarios ready |

**Deliverables:**
- [ ] Load test passed (10K events/sec maintained)
- [ ] All 5 chaos scenarios handled gracefully
- [ ] OT safety validation confirmed
- [ ] Statistical detector thresholds finalized
- [ ] **CHECKPOINT: Phase 5 complete**

---

### **PHASE 6: Operational Excellence & Research Documentation (Weeks 20–21)**

---

#### **Week 20: Playbooks + Monitoring Dashboard**

| Day | Who | Task |
|-----|-----|------|
| Mon | OT + PL | Write OT Incident Response Playbook (physical response procedures per device type) |
| Mon | CTI | Grafana: operational dashboard (alert rate, Zeek uptime, protocol coverage) |
| Tue | ALL | Write runbooks: how to respond to each alert type |
| Tue | PKT | Research documentation: final protocol anomaly catalog |
| Wed | NET | Write SDN operations runbook: adding/removing intents, troubleshooting |
| Wed | INFRA | Cost dashboard: monthly breakdown, alert budget optimization |
| Thu | HOST | Wazuh operational guide: adding agents, updating rules, FIM management |
| Thu | CTI | Dashboard: final UI polish, accessibility review |
| Fri | ALL | Peer review all runbooks (each person reviews one written by another) |
| Fri | PL | Research document draft: Sections 1–3 (Introduction, Related Work, Methodology) |

**Deliverables:**
- [ ] OT Incident Response Playbook complete
- [ ] Runbook for every major component
- [ ] Research document: first 3 sections drafted

---

#### **Week 21: Research Synthesis + Final Preparation**

| Day | Who | Task |
|-----|-----|------|
| Mon | PL + PKT | Write Research Section 4: Protocol Analysis Findings (R1, R3 answers) |
| Mon | NET | Write Research Section 5: SDN Comparison Results (R2 answer) |
| Tue | PL + PKT | Write Research Section 6: Statistical Detection Benchmarks (R4 answer) |
| Tue | ALL | Final system review: all 28 assets monitored, all logs flowing |
| Wed | ALL | Dry run of Week 22 attack scenarios (tabletop, no actual attacks) |
| Wed | CTI | Final documentation: all components documented in repo |
| Thu | ALL | Final fixes from dry run |
| Thu | PL | Finalize research document: conclusions, contributions, future work |
| Fri | ALL | Pre-production checklist: verify all Phase 7 pass criteria |
| Fri | OT | Final OT safety audit: verify no automated OT action possible |

**Deliverables:**
- [ ] Research document complete (all sections)
- [ ] All runbooks complete
- [ ] All documentation committed
- [ ] Week 22 attack scenarios tested (tabletop)
- [ ] Final pre-production checklist passed
- [ ] **CHECKPOINT: Phase 6 complete**

---

### **PHASE 7: Red Team Validation & Presentation (Week 22)**

---

#### **Week 22: Attack Validation & Academic Delivery**

**Monday: Scenario L1 — Hash Value Detection (Pyramid Level 1)**

- Execute: Drop known-malicious binary (SHA-256 from CISA ICS-CERT feed) onto monitored workstation
- Observe: Wazuh FIM detects file creation? VirusTotal enrichment fires? Lambda L1 tag applied?
- **Pass Criteria:** `wazuh_fim_hash` rule → Lambda enrichment → `pyramid_level: L1` → CRITICAL alert within 60s; hash appears in Pyramid Heatmap L1 cell

**Tuesday: Scenario L2 — IP Address Reputation (Pyramid Level 2)**

- Execute: Initiate outbound connection from workstation to known APT41 C2 IP (isolated test env, sinkholed)
- Observe: Zeek `chinese-robot-detection.zeek` fires? Suricata rule 9100001 matches? CTI enrichment tags APT41?
- **Pass Criteria:** `zeek_chinese_ip` + `suricata_ip_rep` rules → `pyramid_level: L2` → CRITICAL alert; IP visible in Pyramid Heatmap L2 cell

**Wednesday: Scenario L3 — Domain Name Detection (Pyramid Level 3)**

- Execute: Trigger DNS queries with high-entropy DGA-generated domains (Shannon entropy > 3.5) from workstation
- Observe: `dga-detection.zeek` CV/entropy detector fires? CTI domain blocklist matches any queries?
- **Pass Criteria:** `zeek_dga_domain` rule → `pyramid_level: L3` → HIGH alert within 60s; domain appears in Pyramid Heatmap L3 cell

**Thursday: Scenario L4 — Network & Host Artifacts (Pyramid Level 4)**

- Execute: Two-part test:
  1. Send unauthorized Modbus FC16 write from workstation to PLC (test register, not safety register)
  2. Establish TLS session using Cobalt Strike default JA3 fingerprint (isolated test env)
- Observe: `modbus-deep-analysis.zeek` fires for FC16? `tls-ja3-fingerprinting.zeek` matches Cobalt Strike hash?
- **Pass Criteria:** `zeek_modbus_fc` + `zeek_ja3_cobalt` rules → `pyramid_level: L4` → HIGH alert; artifacts visible in Pyramid Heatmap L4 cell

**Friday AM: Scenario L5 — Tool Execution Detection (Pyramid Level 5)**

- Execute: Run Mimikatz (test credentials, isolated env) on monitored Windows workstation; verify Sigma rule match
- Observe: Wazuh process monitoring fires? Sigma `wazuh_mimikatz` rule triggers? Lambda L5 tag applied?
- **Pass Criteria:** `wazuh_mimikatz` + `sigma_tool_match` rules → `pyramid_level: L5` → CRITICAL alert within 60s; tool appears in Pyramid Heatmap L5 cell

**Friday PM: Production Cutover + Academic Presentation**

| Time | Who | Task |
|------|-----|------|
| 09:00–11:00 | ALL | Final documentation review |
| 11:00–12:00 | PL | Prepare academic presentation slides |
| 12:00 | ALL | **PRODUCTION CUTOVER** |
|        | NET | ONOS intents active for all VLANs |
|        | INFRA | Kinesis Firehose live data stream |
|        | PKT | Zeek statistical detectors enabled |
| 12:30–16:00 | ALL | Monitor production for critical errors |
| 16:00 | PL | **Academic presentation delivery** |
| 17:00 | ALL | Final documentation committed |

**Weekend:** 48-hour burn-in, monitor dashboards

**Deliverables:**
- [ ] 5/5 Pyramid of Pain scenarios detected (L1–L5, 100% pass rate)
  - [ ] L1 Hash Values: Wazuh FIM + VirusTotal verified
  - [ ] L2 IP Addresses: Chinese IP / APT41 C2 detection verified
  - [ ] L3 Domain Names: DGA entropy detector verified
  - [ ] L4 Artifacts: JA3 fingerprint + Modbus FC anomaly verified
  - [ ] L5 Tools: Mimikatz process detection verified
- [ ] Production system stable for 48 hours
- [ ] Research document submitted
- [ ] Zeek script library published (GitHub)
- [ ] SDN architecture reference implementation documented
- [ ] Academic presentation delivered
- [ ] **CHECKPOINT: Phase 7 complete — PROJECT DONE ✅**

---

## Verification Checkpoints

### **Phase 1 Checklist:**
- [ ] 6 VLANs operational
- [ ] pfSense firewall enforcing 200+ rules
- [ ] Zeek + Suricata generating logs
- [ ] 30-day baseline collection started
- [ ] Sign-off: NET + PL

### **Phase 2 Checklist:**
- [ ] 9 Wazuh agents reporting
- [ ] 50 Sigma rules loaded
- [ ] OpenVSwitch mirroring verified
- [ ] AWS infrastructure operational
- [ ] Disaster recovery tested (RTO <15 min)
- [ ] Secrets in Secrets Manager
- [ ] Sign-off: HOST + INFRA + NET + PL

### **Phase 3 Checklist:**
- [ ] 13 Zeek scripts committed and tested
- [ ] ONOS intents enforcing whitelist
- [ ] Statistical detectors validated (synthetic benchmarks)
- [ ] CTI feeds operational (all 5 feeds)
- [ ] Research interim report written
- [ ] Sign-off: PKT + NET + CTI + PL

### **Phase 4 Checklist:**
- [ ] All detection rules (Sigma, Suricata, Zeek) in repo
- [ ] All 6 dashboard views operational
- [ ] Load test passed (10K events/sec)
- [ ] Integration test: both scenarios detected
- [ ] Sign-off: ALL team members

### **Phase 5 Checklist:**
- [ ] Authentication + RBAC enforced
- [ ] Chaos tests passed (5/5)
- [ ] OT safety validation confirmed
- [ ] Sign-off: INFRA + OT + PL

### **Phase 6 Checklist:**
- [ ] All runbooks complete
- [ ] Research document complete
- [ ] Pre-production checklist passed
- [ ] Sign-off: ALL team members

### **Phase 7 Checklist:**
- [ ] 4/4 attack scenarios detected
- [ ] Production stable 48 hours
- [ ] Research document submitted
- [ ] Zeek library published
- [ ] Sign-off: Supervisor + Lab Manager

---

## Budget Breakdown

### **Monthly Recurring: ~$178**

| Category | Services | Cost |
|----------|----------|------|
| Compute | EC2 t4g.small ×2 (ClickHouse), RDS t3.micro | $95 |
| Data | Kinesis Firehose, S3 (~100GB), Lambda | $25 |
| Security | Secrets Manager, Cognito, CloudWatch | $21 |
| Networking | API Gateway, VPN data transfer | $17 |
| DR | ClickHouse replica EC2, S3 cross-region | $20 |
| **Total** | | **~$178** |

### **One-Time Hardware: $400–1,350**

| Item | Cost |
|------|------|
| Managed switch (24-port, VLAN) | $150–300 |
| Raspberry Pi 4 (4GB) | $100 |
| Network TAP (inline, passive) | $100–200 |
| pfSense hardware (if needed) | $0–400 |
| SD cards, cables, accessories | $50–100 |
| **Subtotal** | $400–1,350 |

### **Total Year 1: ~$4,536 ($178 × 12 + $1,000 hardware avg)**

---

## Risk Management

### **Blockers & Solutions**

| Blocker | Solution |
|---------|----------|
| 30-day baseline not ready when Phase 4 starts | Start Week 4 Day 4 — daily verification |
| OT device not generating expected Modbus traffic | Document as research finding, adjust thresholds |
| ONOS ↔ OVS OpenFlow connection unstable | pfSense rules remain active as fallback |
| Zeek script CPU overhead too high | Profile each script, disable if >10% CPU, use sampling |
| Statistical detector too many false positives | Adjust threshold per host using 30-day baseline |
| Team member unavailable | Cross-training: every role has one backup person |

### **Team Dependencies**

| Dependency | Risk | Mitigation |
|------------|------|------------|
| PKT Zeek scripts must be ready for Phase 4 detection | High | Weekly progress reviews in Phase 3 |
| 30-day baseline must be complete by Week 14 | Critical | Started Week 4, verified weekly |
| ONOS must be stable before attack scenarios | Medium | Fallback to SPAN port if OVS unstable |
| PCAP ring buffer timing | Medium | 2GB provides ~60 min; expand if needed |

---

## Success Criteria

**System is research-ready when:**
- [ ] All 28 assets monitored
- [ ] Detection latency <60 seconds
- [ ] False positive rate <5%
- [ ] **Pyramid of Pain L1–L5 fully covered** (1 validated red team scenario per level)
  - [ ] L1 Hash Values: Wazuh FIM + VirusTotal verified
  - [ ] L2 IP Addresses: Chinese IP + C2 IP detection verified
  - [ ] L3 Domain Names: DGA detector + CTI domain blocking verified
  - [ ] L4 Artifacts: JA3 + Modbus FC + OPC UA artifact detection verified
  - [ ] L5 Tools: Mimikatz + process tool detection verified
- [ ] Zeek protocol coverage: Modbus, OPC UA, EtherNet/IP, TLS
- [ ] Pyramid level tag present on all dashboard alerts
- [ ] Statistical detectors validated against benchmarks
- [ ] SDN comparison study completed
- [ ] Disaster recovery RTO <15 minutes
- [ ] 5/5 red team pyramid scenarios detected (L1–L5)
- [ ] Research document completed and submitted
- [ ] Cost under $200/month

---

**Document Version:** 3.0
**Last Updated:** 2026-02-20
**Status:** Ready for Execution ✅

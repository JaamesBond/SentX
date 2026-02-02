# RobotLab OT/ICS Security: 22-Week Execution Plan
**Version 2.0 - Production-Ready Build**

**Purpose:** Step-by-step implementation plan with day-by-day tasks  
**Audience:** Engineers, project managers, implementers  
**Companion Document:** `TECHNICAL-ARCHITECTURE.md` (complete technical design)

---

## Executive Summary

**Timeline:** 22 weeks (5.5 months) full-time  
**Budget:** $404-454/month operational + $400-1,350 one-time hardware  
**Team:** 1 engineer (can be done solo)  
**Outcome:** Production-grade OT security system with autonomous AI agents

**What's Different from Original Plan:**
- ✅ Added 2 weeks (20 → 22 weeks)
- ✅ Fixed 9 critical gaps (retraining, versioning, DR, security, etc.)
- ✅ Integrated gap fixes into weekly timeline
- ✅ Added specific verification criteria

---

## Phase Overview

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| **1** | 1-4 | Infrastructure & Network | VLANs, Zeek, Suricata, baseline collection |
| **2** | 5-10 | Host Monitoring & Cloud | Wazuh, AWS, secrets, disaster recovery |
| **3** | 11-13 | CTI & Attack Labeling | CTI feeds, 520 labeled sequences |
| **4** | 14-16 | ML Development | 4 models trained, retraining pipeline |
| **5** | 17-19 | Agentic AI | 6 agents, failure recovery, dashboard |
| **6** | 20-21 | Operational Excellence | Playbooks, monitoring, chaos tests |
| **7** | 22 | Penetration Testing | 4 attack scenarios, production cutover |

---

## Detailed Week-by-Week Plan

### **PHASE 1: Infrastructure & Network (Weeks 1-4)**

#### **Week 1: Network Planning & Asset Inventory**
**Monday-Tuesday:** Asset discovery, network diagram  
**Wednesday:** Firewall rule design (200+ rules)  
**Thursday:** Procure hardware (switch, pfSense, RPi, TAP)  
**Friday:** Setup project tracker, Terraform skeleton

**Deliverables:**
- [ ] Network diagram with 6 VLANs
- [ ] Firewall rule matrix (Excel)
- [ ] Hardware orders placed
- [ ] GitHub repo + project board

---

#### **Week 2: VLAN Configuration & pfSense**
**Monday:** Configure managed switch VLANs  
**Tuesday:** Deploy pfSense, configure interfaces  
**Wednesday:** Implement firewall rules  
**Thursday:** Install network TAP (chemistry machine)  
**Friday:** Test VLAN isolation, document config

**Deliverables:**
- [ ] 6 VLANs operational (10, 20, 30, 100, 110, 200)
- [ ] pfSense firewall enforcing rules
- [ ] Chemistry machine TAP installed (passive only)
- [ ] Network segmentation validated

---

#### **Week 3: IDS/IPS Deployment**
**Monday-Tuesday:** Install Suricata on pfSense, load ET rules  
**Wednesday:** Deploy Raspberry Pi + Zeek  
**Thursday:** Write custom Zeek script: modbus-detection.zeek  
**Friday:** Write custom Zeek script: chinese-robot-detection.zeek

**Deliverables:**
- [ ] Suricata operational, <10 FPs/day
- [ ] Zeek generating 7 log types
- [ ] 2 custom Zeek scripts working
- [ ] Baseline traffic patterns documented

---

#### **Week 4: OT Protocol Monitoring**
**Monday:** Deploy Modbus parser  
**Tuesday:** Configure OPC UA monitoring  
**Wednesday:** Write Zeek script: c2-beaconing.zeek  
**Thursday:** **START 30-day baseline collection** (critical for ML)  
**Friday:** Verify baseline data collection working

**Deliverables:**
- [ ] Modbus baseline documented
- [ ] 3 custom Zeek scripts operational
- [ ] Baseline data collection started (runs 30 days in background)
- [ ] **CHECKPOINT:** Phase 1 complete

---

### **PHASE 2: Host Monitoring & Cloud (Weeks 5-10)**

#### **Week 5: Wazuh + AWS Foundation**
**Monday:** Deploy Wazuh Manager (Docker)  
**Tuesday:** Install Wazuh agents (3 Win + 2 Linux + 4 RPi)  
**Wednesday:** Configure FIM (firmware, ladder logic, configs)  
**Thursday:** Integrate VirusTotal API  
**Friday:** Deploy AWS VPC + RDS PostgreSQL + ClickHouse EC2

**Deliverables:**
- [ ] 9 Wazuh agents reporting
- [ ] FIM operational
- [ ] AWS cloud infrastructure running

---

#### **Week 6: Sysmon + Sigma Rules**
**Monday:** Deploy Sysmon v15 on Windows  
**Tuesday:** Configure Wazuh process monitoring  
**Wednesday:** Write tool detection rules (Mimikatz, Netcat, etc.)  
**Thursday:** Convert 50 Sigma rules with pySigma  
**Friday:** Test rules, tune false positives

**Deliverables:**
- [ ] Sysmon operational on 3 Windows hosts
- [ ] 50 Sigma rules loaded
- [ ] Tool detection rules tested

---

#### **Week 7: Vulnerability Detection + Tuning**
**Monday:** Configure Wazuh vulnerability scanner  
**Tuesday:** Tune alert severity, suppress known FPs  
**Wednesday:** Configure alert notifications (email/Slack)  
**Thursday:** Verify 30-day baseline collection on track  
**Friday:** Run end-to-end detection test

**Deliverables:**
- [ ] Vuln scanning operational
- [ ] Alert tuning complete (<20 alerts/day)
- [ ] Baseline data collection progressing

---

#### **Week 8: AWS Cloud Infrastructure**
**Monday-Tuesday:** Finalize Terraform, deploy all resources  
**Wednesday:** Deploy ClickHouse PRIMARY (us-east-1a)  
**Thursday:** Deploy ClickHouse REPLICA (us-east-1b)  
**Friday:** Create S3 buckets (models, backups, logs)

**Deliverables:**
- [ ] PostgreSQL Multi-AZ operational
- [ ] ClickHouse Multi-AZ replicating
- [ ] S3 buckets with versioning + encryption

---

#### **Week 9: Secrets Management + Data Pipeline** [GAP FIX]
**Monday:** Setup AWS Secrets Manager, store all credentials  
**Tuesday:** Configure weekly password rotation  
**Wednesday:** Setup Kinesis Firehose, configure Filebeat  
**Thursday:** Write Lambda: ot-event-processor (v1.0)  
**Friday:** Configure DLQ, test error handling

**Deliverables:**
- [ ] All secrets in Secrets Manager (no hardcoded creds)
- [ ] Auto-rotation configured
- [ ] Log forwarding pipeline working

---

#### **Week 10: ClickHouse Schema + Disaster Recovery** [GAP FIX]
**Monday:** Create ClickHouse schema (4 tables)  
**Tuesday:** Add indices, materialized views  
**Wednesday:** Test query performance (goal: <1s)  
**Thursday:** Setup automated ClickHouse backups to S3  
**Friday:** Test disaster recovery (terminate primary, failover)

**Deliverables:**
- [ ] ClickHouse schema optimized
- [ ] PostgreSQL schema complete
- [ ] Disaster recovery tested (RTO <15 min)
- [ ] **CHECKPOINT:** Phase 2 complete

---

### **PHASE 3: CTI & Attack Labeling (Weeks 11-13)**

#### **Week 11: CTI Feed Ingestion**
**Monday-Friday:** Write 5 Lambda functions for CTI feeds
- CISA ICS-CERT
- MITRE ATT&CK for ICS
- AlienVault OTX
- Recorded Future
- Abuse.ch + Emerging Threats

**Deliverables:**
- [ ] All 6 CTI feeds auto-updating (every 6 hours)
- [ ] Data populating PostgreSQL CTI tables

---

#### **Week 12: CTI Correlation**
**Monday:** Create CTI PostgreSQL tables (6 pyramid levels)  
**Tuesday:** Update ot-event-processor Lambda with CTI correlation  
**Wednesday:** Test CTI enrichment with known IoCs  
**Thursday:** Build CTI health monitoring  
**Friday:** Create APT group profiles (APT10, APT41, Lazarus)

**Deliverables:**
- [ ] CTI database populated
- [ ] Alerts enriched with CTI metadata
- [ ] APT attribution logic working

---

#### **Week 13: Attack Sequence Labeling** [CRITICAL - GAP FIX]
**Monday:** Collect MITRE case studies (20 sequences)  
**Tuesday:** Setup isolated test environment for simulated attacks  
**Wednesday:** Run 10 simulated attacks, collect observed sequences  
**Thursday:** Generate 400 synthetic sequences  
**Friday:** Human QA on 10% sample, validate quality

**Deliverables:**
- [ ] 520 high-quality labeled attack sequences
- [ ] QA validated (>90% accuracy)
- [ ] Ready for LSTM training
- [ ] **CHECKPOINT:** Phase 3 complete

---

### **PHASE 4: ML Development (Weeks 14-16)**

#### **Week 14: Behavioral Baseline (Isolation Forest)**
**Monday:** Verify 30-day baseline data complete (20K+ samples)  
**Tuesday:** Implement feature engineering pipeline (50+ features)  
**Wednesday:** Train Isolation Forest model  
**Thursday:** Evaluate model (precision >0.90, recall >0.80, FP <0.05)  
**Friday:** Save model to S3 with versioning, deploy to Lambda

**Deliverables:**
- [ ] Isolation Forest trained (v1.0.0)
- [ ] Meets production criteria
- [ ] Deployed to Lambda (runs every 5 min)

---

#### **Week 15: Sequence Prediction (LSTM)**
**Monday:** Prepare LSTM training data (520 sequences)  
**Tuesday:** Build LSTM architecture (PyTorch)  
**Wednesday:** Train LSTM (50 epochs, ~2 hours on GPU)  
**Thursday:** Evaluate (top-1 >0.85, top-5 >0.95)  
**Friday:** Save to S3, deploy to Lambda

**Deliverables:**
- [ ] LSTM trained (v1.0.0)
- [ ] Meets production criteria
- [ ] Deployed (on-demand inference)

---

#### **Week 16: Graph Analysis + Retraining Pipeline** [GAP FIXES]
**Monday:** Collect GNN training data (50 graph snapshots)  
**Tuesday:** Train GNN model  
**Wednesday:** Evaluate GNN (precision@5 >0.80, MRR >0.60)  
**Thursday:** Train XGBoost ensemble  
**Friday:** Implement automated retraining pipeline, drift detection

**Deliverables:**
- [ ] All 4 ML models trained and deployed
- [ ] Automated retraining working (weekly for Isolation Forest)
- [ ] Model versioning + rollback tested (<30s)
- [ ] **CHECKPOINT:** Phase 4 complete

---

### **PHASE 5: Agentic AI (Weeks 17-19)**

#### **Week 17: Agent Framework + Failure Recovery** [GAP FIXES]
**Monday:** Implement AutonomousSecurityAgent base class  
**Tuesday:** Implement AgentSupervisor with circuit breaker  
**Wednesday:** Implement SafetyGuardrailAgent  
**Thursday:** Implement model versioning + instant rollback  
**Friday:** Implement drift detection for ML models

**Deliverables:**
- [ ] Agent base class ready
- [ ] Agent failure recovery tested
- [ ] Safety guardrail cannot be bypassed
- [ ] ML model lifecycle complete

---

#### **Week 18: Agent Implementation + Communication** [GAP FIX]
**Monday:** Implement L6: MLEnhancedTTPHunterAgent  
**Tuesday:** Implement L5: ToolDetectorAgent  
**Wednesday:** Implement Agent Communication Bus (SNS/SQS)  
**Thursday:** Implement agent performance tracking  
**Friday:** Implement L4, L3, L2, L1 agents

**Deliverables:**
- [ ] All 6 agents implemented
- [ ] Agent communication working (pub/sub)
- [ ] Performance metrics tracked

---

#### **Week 19: Dashboard + Security + Load Testing** [GAP FIXES]
**Monday:** Setup Cognito authentication  
**Tuesday:** Implement RBAC + audit logging  
**Wednesday:** Setup API Gateway + backend Lambdas  
**Thursday:** Load testing with Locust (validate 2x scale)  
**Friday:** Build React dashboard scaffolding

**Deliverables:**
- [ ] API authentication working
- [ ] Load testing passed
- [ ] Dashboard rendering live data
- [ ] **CHECKPOINT:** Phase 5 complete

---

### **PHASE 6: Operational Excellence (Weeks 20-21)**

#### **Week 20: Dashboard + Incident Response**
**Monday:** Complete Pyramid of Pain heatmap  
**Tuesday:** Complete ML model performance dashboard  
**Wednesday:** Write incident response playbook  
**Thursday:** Complete network topology + threat hunting workspace  
**Friday:** Dashboard UI polish, performance testing

**Deliverables:**
- [ ] Dashboard production-ready (6 views)
- [ ] Incident response playbook integrated

---

#### **Week 21: Monitoring + Chaos Testing** [GAP FIXES]
**Monday:** Setup Prometheus + Grafana  
**Tuesday:** Setup cost monitoring with alerts  
**Wednesday:** Implement human-in-the-loop workflow  
**Thursday:** Run chaos engineering tests (5 scenarios)  
**Friday:** Final pre-deployment checklist

**Deliverables:**
- [ ] Observability stack operational
- [ ] Chaos tests passed
- [ ] All 9 critical gaps verified fixed
- [ ] **CHECKPOINT:** Phase 6 complete

---

### **PHASE 7: Penetration Testing (Week 22)**

#### **Week 22: Validation & Production Cutover**

**Monday:** Attack Scenario 1 - Chinese Robot Supply Chain
- Execute attack, verify detection within 60s
- **Pass Criteria:** L2, L3, L6 agents detect + correlate

**Tuesday:** Attack Scenario 2 - Stuxnet-Style PLC Attack
- Execute attack, verify protocol violation detected
- **Pass Criteria:** L4 detects Modbus violation, L6 predicts next technique

**Wednesday:** Attack Scenario 3 - Ransomware
- Execute attack, verify detection before >10% files encrypted
- **Pass Criteria:** L1 hash + L5 tool + Isolation Forest all trigger

**Thursday:** Attack Scenario 4 - Multi-Stage APT
- Execute full kill chain, verify all stages detected
- **Pass Criteria:** Full attack chain reconstructed by L6

**Friday:** Production Cutover
- **12:00 PM:** Update DNS, enable agents, switch to production
- **12:30-4:00 PM:** Monitor for critical errors
- **4:00 PM:** If stable, declare production success
- **4:00-5:00 PM:** Final documentation

**Weekend:** 48-hour burn-in period, monitor for stability

**Deliverables:**
- [ ] 4/4 penetration test scenarios passed
- [ ] Production cutover successful
- [ ] All documentation complete
- [ ] **CHECKPOINT:** Phase 7 complete - PROJECT DONE ✅

---

## Verification Checkpoints

After each phase, verify these criteria before proceeding:

### **Phase 1 Checklist:**
- [ ] 6 VLANs operational
- [ ] 200+ firewall rules working
- [ ] Zeek + Suricata generating logs
- [ ] 30-day baseline collection started
- [ ] Sign-off from: Network Engineer

### **Phase 2 Checklist:**
- [ ] 9 Wazuh agents reporting
- [ ] 50 Sigma rules loaded
- [ ] AWS cloud infrastructure operational
- [ ] Disaster recovery tested (RTO <15 min)
- [ ] All secrets in Secrets Manager
- [ ] Sign-off from: System Admin + Cloud Architect

### **Phase 3 Checklist:**
- [ ] 6 CTI feeds operational
- [ ] CTI correlation enriching alerts
- [ ] 520 labeled attack sequences (QA validated)
- [ ] Sign-off from: Threat Intel Analyst

### **Phase 4 Checklist:**
- [ ] 4 ML models meet accuracy thresholds
- [ ] Automated retraining pipeline working
- [ ] Model versioning + rollback tested
- [ ] Sign-off from: ML Engineer

### **Phase 5 Checklist:**
- [ ] 6 agents operational
- [ ] Agent failure recovery tested
- [ ] Agent communication bus working
- [ ] API authentication + RBAC enforced
- [ ] Load testing passed
- [ ] Sign-off from: Security Engineer

### **Phase 6 Checklist:**
- [ ] Dashboard operational (6 views)
- [ ] Incident response playbook ready
- [ ] Observability stack working
- [ ] Chaos tests passed (5/5)
- [ ] All 9 critical gaps verified fixed
- [ ] Sign-off from: Operations Team

### **Phase 7 Checklist:**
- [ ] 4/4 penetration tests passed
- [ ] Production stable for 48 hours
- [ ] All documentation delivered
- [ ] Sign-off from: CISO + Lab Manager

---

## Budget Breakdown

### **Monthly Recurring: $404-454**
- Infrastructure: $120 (EC2, RDS, S3)
- AI/ML: $290-340 (Bedrock + SageMaker)
- Security: $10 (Secrets Manager, Cognito, VPN)
- Monitoring: $11 (CloudWatch)
- DR: $17 (Replica + backups)

### **One-Time Hardware: $400-1,350**
- Managed switch: $150-300
- Raspberry Pi: $100
- Network TAP: $100-200
- Server/pfSense: $0-400 (reuse if possible)

### **Total Year 1: $5,748-7,298**
- 94-98% cheaper than commercial solutions

---

## Risk Management

### **Common Blockers & Solutions**

**"30-day baseline not ready when Week 14 starts"**
→ Solution: Start baseline collection Week 4 Day 4, verify daily

**"LSTM training data quality insufficient"**
→ Solution: Week 13 Human QA catches this, fix before Week 15

**"Agent keeps crashing in production"**
→ Solution: Circuit breaker stops restart loop, human investigates

**"Cost exceeds $500/month"**
→ Solution: Auto-pause agents, analyze CloudWatch billing

**"Penetration test fails"**
→ Solution: Fix issue, retest next day, don't rush cutover

---

## Success Criteria

**System is production-ready when:**
- [ ] All 6 pyramid levels operational
- [ ] Detection latency <60 seconds
- [ ] False positive rate <5%
- [ ] Agent uptime >99%
- [ ] All ML models meet accuracy targets
- [ ] Disaster recovery RTO <15 minutes
- [ ] 4/4 penetration tests passed
- [ ] Cost under $500/month
- [ ] Documentation complete

**Then and only then:** Declare project complete! 🎉

---

**Document Version:** 2.0  
**Last Updated:** January 30, 2026  
**Status:** Ready for Execution ✅

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**RobotLab OT/ICS Security Research Platform** - A research-grade Operational Technology (OT) / Industrial Control Systems (ICS) security system for a university RobotLab environment. The project is currently in **Design & Planning Phase** with no implementation code yet.

**Target Environment:** 28 monitored assets including 5 industrial robots (DoBot), 3 PLCs (Siemens/Allen-Bradley), 1 air-gapped chemistry machine, 4 Raspberry Pi controllers, workstations, and IoT devices across 6 VLANs.

**Team Size:** 7 people (Project Lead, Network & SDN Engineer, Packet Analysis Researcher, OT/ICS Security Engineer, Host Security Engineer, Cloud & Infrastructure Engineer, CTI & Frontend Engineer)

## Current State

This is a **documentation-only repository** in the design phase. There is no runnable code, no build system, and no tests yet. All implementation will follow the 22-week execution plan.

## Key Documentation

| Document | Purpose |
|----------|---------|
| `docs/TECHNICAL-ARCHITECTURE.md` | **Primary reference** - Complete v3.0 technical design (6-layer architecture, deep packet analysis, SDN) |
| `docs/EXECUTION-PLAN.md` | 22-week implementation timeline with 7-person team assignments |
| `docs/course-alignment-matrix.md` | Academic requirement verification (52/52 requirements mapped) |
| `.claude/agents.md` | **Agent configuration** - Specialized AI agents, their domains, and interaction protocols |
| `docs/claude_docs/INDEX.md` | **Work tracking** - Single source of truth for all agent work |

## Agent Work Tracking

All agent work is tracked in `docs/claude_docs/`. This is the **single source of truth**.

### Before Starting Work
```
1. Read docs/claude_docs/INDEX.md
2. Check for recent related changes
3. Note the latest Change ID for your agent type
```

### After Completing Work
```
1. Create: docs/claude_docs/changes/YYYY-MM-DD-AGENT-NNN.md
2. Update: docs/claude_docs/CHANGELOG.md (append entry)
3. Update: docs/claude_docs/INDEX.md (add row to TOP of Latest Activity table)
```

### Change ID Format
```
ARCH-NNN  = Master Architect
INFRA-NNN = Infrastructure Agent
DET-NNN   = Detection Engineering Agent
BACK-NNN  = Backend Agent
FRONT-NNN = Frontend Agent
CTI-NNN   = CTI Agent
REV-NNN   = Code Reviewer Agent
SEC-NNN   = Security Agent
```

### Documentation Structure
```
docs/claude_docs/
├── INDEX.md          ← Check first, update last
├── CHANGELOG.md      ← Chronological log
├── changes/          ← Detailed change docs
│   └── YYYY-MM-DD-AGENT-NNN.md
└── decisions/        ← Architecture Decision Records
    └── ADR-NNN-title.md
```

## Development Agents

This project uses specialized AI agents for development. See `.claude/agents.md` for full details.

### Agent Flow (Mandatory)

```
User directs task
       ↓
Implementation Agent (Sonnet)
       ↓
Code Reviewer Agent (Sonnet)
       ↓
Security Agent (Sonnet)
       ↓
COMPLETE
```

### Available Agents

Each agent has a dedicated configuration file in `.claude/agents/`:

| Agent | Model | File | Domain |
|-------|-------|------|--------|
| **Master Architect** | Opus | [`master-architect.md`](.claude/agents/master-architect.md) | Final authority - escalations only |
| **Infrastructure** | Sonnet | [`infrastructure.md`](.claude/agents/infrastructure.md) | Terraform, AWS, networking, Docker, SDN infrastructure |
| **Detection Engineering** | Sonnet | [`detection-engineering.md`](.claude/agents/detection-engineering.md) | Zeek scripts, Suricata rules, Sigma, Wazuh, OT protocol dissectors |
| **Backend** | Sonnet | [`backend.md`](.claude/agents/backend.md) | Lambda functions, APIs, event processing pipeline |
| **Frontend** | Sonnet | [`frontend.md`](.claude/agents/frontend.md) | React dashboards, D3.js visualizations |
| **CTI** | Sonnet | [`cti.md`](.claude/agents/cti.md) | Threat intel, IoC schemas, APT tracking, MITRE ATT&CK |
| **Code Reviewer** | Sonnet | [`code-reviewer.md`](.claude/agents/code-reviewer.md) | Quality gate - slop, bad practices |
| **Security** | Sonnet | [`security.md`](.claude/agents/security.md) | Final gate - vulnerabilities, OT safety |

### Agent Principles

All agents follow these rules:
1. **Chain of thought** - Think step-by-step before acting
2. **Chunk tasks** - Break into smallest pieces solvable with 100% certainty
3. **Confidence gate** - Never proceed with doubt; escalate instead
4. **Document everything** - Every task produces structured documentation
5. **Prototype vs Production** - Understand context and adjust rigor accordingly

### Invoking Agents

```
# Implementation agents
Task tool: subagent_type=general-purpose, model=sonnet
Prompt: "You are the [AGENT NAME] for RobotLab OT/ICS... [task]"

# Master Architect (escalation only)
Task tool: subagent_type=general-purpose, model=opus
Prompt: "You are the MASTER ARCHITECT... [escalation context]"
```

## Architecture Summary

**6-Layer System:**
1. **Data Sources** - Wazuh agents, Sysmon, Auditd on 28 assets
2. **SDN & Network Infrastructure** - OpenVSwitch + ONOS SDN controller + pfSense + Suricata
3. **Network Analysis** - Zeek 6.0 (deep packet analysis, OT protocol dissectors, PCAP forensics)
4. **Host Security** - Wazuh 4.12 + Sysmon v15
5. **Cloud Processing & Storage** - AWS Lambda (7-stage) + ClickHouse + PostgreSQL RDS
6. **Security & Visualization** - AWS Cognito + React dashboard + CTI

**Research Focus:**
- Deep packet analysis of OT/ICS protocols (Modbus TCP, OPC UA, EtherNet/IP)
- Software-Defined Networking for programmable traffic analysis (OpenVSwitch + ONOS)
- Statistical detection methods (C2 beaconing via CV, DGA via entropy) — no ML required
- Passive, safety-first monitoring for critical OT environments

## Planned Technology Stack

| Layer | Technology |
|-------|-----------|
| Host Security | Wazuh 4.12, Sysmon v15, Auditd |
| Network Security | Zeek 6.0, Suricata 7.0 |
| SDN | OpenVSwitch 3.x, ONOS SDN Controller, OpenFlow 1.3 |
| OT Protocols | Custom Zeek scripts (Modbus TCP, OPC UA, EtherNet/IP) |
| CTI | CISA ICS-CERT, AlienVault OTX, Recorded Future, VirusTotal |
| Frameworks | MITRE ATT&CK for ICS (12 tactics, 81 techniques), Cyber Kill Chain |
| Storage | ClickHouse, PostgreSQL RDS |
| Automation | Python 3.10+, AWS Lambda |
| Infrastructure | Terraform, Docker, AWS (Multi-AZ) |
| Visualization | React, D3.js |

## OT Safety Constraints (Non-Negotiable)

When implementing detection or response logic:
- **NO active scanning** of PLCs or safety-critical systems
- **NO inline blocking** on OT control traffic (passive monitoring only)
- **NO automated isolation** of any OT device (requires human verification)
- **NO automated SDN flow rule** that affects OT traffic (analyst-triggered only)
- **Alert-first, respond-second** philosophy
- Chemistry machine is air-gapped (VLAN 200, no routing, passive TAP only)

## Implementation Phases

1. **Phase 1 (Weeks 1–4):** Network segmentation, Zeek, Suricata, OVS planning, baseline collection
2. **Phase 2 (Weeks 5–9):** Wazuh HIDS, OVS deployment, OT protocol parsers v1, AWS infrastructure
3. **Phase 3 (Weeks 10–13):** Protocol research (Modbus deep analysis, OPC UA, EtherNet/IP), ONOS SDN, statistical detectors
4. **Phase 4 (Weeks 14–17):** Complete Zeek script library, CTI integration, React dashboard
5. **Phase 5 (Weeks 18–19):** Integration, load testing, chaos engineering
6. **Phase 6 (Weeks 20–21):** Operational excellence, playbooks, research documentation
7. **Phase 7 (Week 22):** Red team validation, production cutover, academic presentation

## Framework Alignment

Every detection rule must map to at least one framework:
- **MITRE ATT&CK for ICS** - 12 tactics, 81 techniques
- **Cyber Kill Chain** - 7 phases
- **FireEye Attack Lifecycle**
- **Gartner Cyber Attack Model**

## Success Metrics

- Detection latency: <60 seconds
- False positive rate: <5%
- MITRE ATT&CK ICS coverage: 81/81 techniques
- Zeek protocol coverage: Modbus, OPC UA, EtherNet/IP, TLS
- Disaster recovery RTO: <15 minutes
- Monthly cost: ~$178/month

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**RobotLab OT/ICS Security Platform** - A production-grade Operational Technology (OT) / Industrial Control Systems (ICS) security system for a university RobotLab environment. The project is currently in **Design & Planning Phase** with no implementation code yet.

**Target Environment:** 28 monitored assets including 5 industrial robots (DoBot), 3 PLCs (Siemens/Allen-Bradley), 1 air-gapped chemistry machine, 4 Raspberry Pi controllers, workstations, and IoT devices across 6 VLANs.

## Current State

This is a **documentation-only repository** in the design phase. There is no runnable code, no build system, and no tests yet. All implementation will follow the 22-week execution plan.

## Key Documentation

| Document | Purpose |
|----------|---------|
| `docs/TECHNICAL-ARCHITECTURE.md` | **Primary reference** - Complete v2.0 technical design (8-layer architecture, ML pipeline, AI agents) |
| `docs/EXECUTION-PLAN.md` | 22-week implementation timeline with weekly tasks |
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
ML-NNN    = ML/AI Pipeline Agent
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
| **Infrastructure** | Sonnet | [`infrastructure.md`](.claude/agents/infrastructure.md) | Terraform, AWS, networking, Docker |
| **Detection Engineering** | Sonnet | [`detection-engineering.md`](.claude/agents/detection-engineering.md) | Zeek, Suricata, Sigma, Wazuh, YARA |
| **ML/AI Pipeline** | Sonnet | [`ml-ai-pipeline.md`](.claude/agents/ml-ai-pipeline.md) | Models, training, MLOps, AI agents |
| **Backend** | Sonnet | [`backend.md`](.claude/agents/backend.md) | Lambda functions, APIs, processing |
| **Frontend** | Sonnet | [`frontend.md`](.claude/agents/frontend.md) | React dashboards, D3.js |
| **CTI** | Sonnet | [`cti.md`](.claude/agents/cti.md) | Threat intel, IoC schemas, APT tracking |
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

**8-Layer System:**
1. **Data Sources** - Wazuh agents, Sysmon, Auditd on 28 assets
2. **Network Monitoring** - Zeek 6.0 + Suricata 7.0 on Raspberry Pi / pfSense
3. **Cloud Ingestion** - AWS Kinesis Firehose → Lambda (8-stage processing)
4. **Storage** - ClickHouse (Multi-AZ) + PostgreSQL RDS
5. **ML Pipeline** - Isolation Forest, LSTM, GNN, XGBoost ensemble
6. **Agentic AI** - 6 autonomous agents (L1-L6 Pyramid of Pain)
7. **Security** - AWS Cognito, Secrets Manager, audit logging
8. **Visualization** - React + D3.js dashboards

**Pyramid of Pain Focus:** 65% of detection effort on Levels 5-6 (Tools + TTPs) to maximize attacker cost.

## Planned Technology Stack

| Layer | Technology |
|-------|-----------|
| Host Security | Wazuh 4.12, Sysmon v15, Auditd |
| Network Security | Zeek 6.0, Suricata 7.0 |
| OT Protocols | Custom Zeek scripts (Modbus TCP, OPC UA) |
| CTI | CISA ICS-CERT, AlienVault OTX, Recorded Future, VirusTotal |
| Frameworks | MITRE ATT&CK for ICS (81 techniques), Pyramid of Pain (6 levels) |
| Storage | ClickHouse, PostgreSQL RDS |
| AI/ML | AWS Bedrock (Claude), scikit-learn, PyTorch, PyTorch Geometric |
| Automation | Python 3.10+, AWS Lambda |
| Infrastructure | Terraform, Docker, AWS (Multi-AZ) |
| Visualization | React, D3.js |

## OT Safety Constraints (Non-Negotiable)

When implementing detection or response logic:
- **NO active scanning** of PLCs or safety-critical systems
- **NO inline blocking** on OT control traffic (passive monitoring only)
- **NO automated isolation** of chemistry machine (requires human verification)
- **Alert-first, respond-second** philosophy
- Chemistry machine is air-gapped (VLAN 200, no routing)

## Implementation Phases

1. **Phase 1 (Weeks 1-4):** Network segmentation, Zeek, Suricata, baseline collection
2. **Phase 2 (Weeks 5-10):** Wazuh HIDS, AWS infrastructure, disaster recovery
3. **Phase 3 (Weeks 11-13):** CTI feeds, labeled attack sequences
4. **Phase 4 (Weeks 14-16):** ML model development
5. **Phase 5 (Weeks 17-19):** Agentic AI implementation
6. **Phase 6 (Weeks 20-21):** Operational excellence, playbooks
7. **Phase 7 (Week 22):** Penetration testing, production cutover

## Framework Alignment

Every detection rule must map to at least one framework:
- **MITRE ATT&CK for ICS** - 12 tactics, 81 techniques
- **Pyramid of Pain** - All 6 levels (Hash → IP → Domain → Artifacts → Tools → TTPs)
- **Cyber Kill Chain** - 7 phases
- **FireEye Attack Lifecycle**
- **Gartner Cyber Attack Model**

## Success Metrics

- Detection latency: <60 seconds
- False positive rate: <5%
- MITRE ATT&CK ICS coverage: 81/81 techniques
- Agent uptime: 99.7%
- Disaster recovery RTO: <15 minutes

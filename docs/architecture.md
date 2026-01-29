# Architecture Overview

## Purpose

This document describes the **technical architecture** of the RobotLab OT/ICS Security Platform.
It explains how data flows from OT assets to detection logic, threat intelligence, and analysis layers,
while respecting **industrial safety constraints**.

---

## Architectural Goals

- Passive-first monitoring for OT assets
- Clear separation between IT and OT zones
- Scalable ingestion and analytics
- Pyramid of Pain–driven detection logic
- Easy mapping to security frameworks (MITRE ATT&CK for ICS)

---

## High-Level Architecture

**Layers:**
1. OT & IT Assets (data sources)
2. Collection & Monitoring
3. Ingestion & Processing
4. Detection & Correlation
5. Analysis & Visualization

---

## 1. Data Sources

### OT Assets
- Industrial robots
- PLCs
- Safety-critical machines
- IoT and embedded controllers

> OT assets are monitored **passively** wherever possible.

### IT Assets
- Windows engineering workstations
- Linux servers
- Raspberry Pi controllers

---

## 2. Collection Layer

### Host-Based Monitoring
- Wazuh agents
- Sysmon (Windows)
- Auditd (Linux)

### Network Monitoring
- Zeek (full packet metadata)
- Suricata (signature-based IDS)
- SPAN/TAP-based visibility

---

## 3. Ingestion & Processing

- Normalization of:
  - Host events
  - Network logs
  - OT protocol telemetry
- Events are classified by **Pyramid of Pain level**
- Threat Intelligence enrichment happens here

---

## 4. Detection & Correlation

Detection types:
- Signature-based
- Behavioral
- Anomaly-based
- Multi-stage attack correlation

Framework mappings:
- MITRE ATT&CK for ICS
- Cyber Kill Chain
- Pyramid of Pain

---

## 5. Analysis & Visualization (Planned)

- Pyramid-of-Pain heatmap
- ATT&CK coverage matrix
- Threat hunting workspace
- Timeline-based incident reconstruction

---

## Safety Considerations

- No active scanning of PLCs
- No inline blocking on OT control traffic
- Alert-first, respond-second philosophy

---

## Summary

This architecture is designed to be:
- Realistic
- Defensible
- Teachable
- Expandable

It mirrors how OT security systems are built in real environments,
while remaining feasible for a university lab setting.

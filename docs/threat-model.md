# Threat Model

## Objective

This document defines the **threat landscape** relevant to a university RobotLab
and explains how the project models realistic attackers.

---

## Assumed Threat Actors

### 1. Opportunistic Attackers
- Internet scanning
- Default credential abuse
- Malware propagation

### 2. Targeted Attackers
- Intellectual property theft
- Research espionage
- Supply chain compromise

### 3. Advanced Persistent Threats (APTs)
- Long dwell time
- Custom tooling
- ICS-specific tradecraft

---

## Key Attack Motivations

- Steal research data
- Manipulate robotic behavior
- Sabotage experiments
- Establish covert persistence

---

## Primary Attack Surfaces

- Engineering workstations
- Robot firmware updates
- PLC logic
- OT-to-IT trust boundaries
- Remote access paths

---

## Attack Paths (Examples)

1. Phishing → Workstation compromise → PLC access
2. Supply chain backdoor → Robot controller → Lateral movement
3. Credential theft → Engineering software abuse

---

## Defensive Strategy

Mapped to the Pyramid of Pain:

- Low-level indicators for fast blocking
- High-level behaviors for durable detection
- Focus on attacker *methods*, not just tools

---

## Framework Mapping

- MITRE ATT&CK for ICS
- Cyber Kill Chain
- Pyramid of Pain

---

## Summary

This threat model ensures that:
- Detections are realistic
- Attacks are plausible
- Defenses are meaningful

It serves as the foundation for detection logic,
threat hunting, and validation exercises.

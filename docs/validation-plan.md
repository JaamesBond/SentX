# Validation & Testing Plan

## Week 20: Penetration Testing Scenarios

### Scenario 1: Supply Chain Backdoor (Chinese Robot)
**Objective:** Validate Level 2 (IP) + Level 6 (TTP) detection

**Attack Steps:**
1. Configure DoBot robot to beacon to 202.108.22.5 (simulated C2 in China)
2. Exfiltrate simulated "research data" via HTTPS
3. Attempt lateral movement to PLC VLAN

**Expected Detections:**
- [ ] Zeek alert: Connection to Chinese IP range
- [ ] Firewall log: Outbound HTTPS from robot VLAN (policy violation)
- [ ] CTI correlation: IP matches APT41 infrastructure
- [ ] LLM analysis: "High confidence supply chain compromise"

**Pass Criteria:** All 4 detections triggered within 60 seconds

---

### Scenario 2-7: [Continue for each test]

## Pyramid of Pain Validation Matrix

| Level | Test Method | Pass Criteria | Status |
|-------|-------------|---------------|--------|
| L1 (Hash) | Upload malware sample to workstation | FIM alert + VirusTotal match | ⏳ Pending |
| L2 (IP) | Connect to known C2 IP | Alert within 60s | ⏳ Pending |
| L3 (Domain) | Query malicious domain | DNS sinkhole hit | ⏳ Pending |
| L4 (Artifacts) | Execute Cobalt Strike beacon | JA3 fingerprint match | ⏳ Pending |
| L5 (Tools) | Run Mimikatz | Process monitoring alert | ⏳ Pending |
| L6 (TTPs) | Multi-stage Stuxnet-style attack | Full kill chain correlation | ⏳ Pending |

## Success Metrics

- [ ] 7/7 attack scenarios detected
- [ ] Average detection latency < 60 seconds
- [ ] False positive rate < 5%
- [ ] All detections mapped to MITRE ATT&CK
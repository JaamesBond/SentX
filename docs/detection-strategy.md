# Detection Strategy

## Detection Philosophy

> "Detect behaviors, not just artifacts. Focus on what hurts attackers most."

## Pyramid of Pain Mapping

### Level 1: Hash Values
**Assets Monitored:**
- Robot firmware binaries
- PLC ladder logic files
- Windows executables

**Detection Method:**
- Wazuh FIM with SHA-256 hashing
- VirusTotal API integration

**Example Alert:**
```
ALERT: Firmware file modified on DoBot Robot #3
Hash: 3a5b7c9d... (not in known-good list)
Severity: HIGH
Recommended Action: Compare with vendor baseline
```

### Level 2-6: [Continue for each level]

## OT-Specific Detection Logic

### Modbus Protocol Violations
**Why This Matters:**
Stuxnet-style attacks manipulate PLCs via Modbus.

**Detection Rules:**
1. Write to read-only registers (40000-40100 range)
2. Invalid function codes (outside 0x01-0x10)
3. Excessive register operations (>100 in 1 second)

### Chinese Robot Backdoor Detection
**Threat:** Supply chain compromise in DoBot robots

**Detection Rules:**
1. Connection to 202.x.x.x IP ranges (China)
2. DNS query to .cn domains
3. Encrypted traffic on non-standard ports from robot VLAN

[Continue with more specific detections...]
# Deployment Guide

## Prerequisites

**Hardware:**
- Managed switch with VLAN support (e.g., Cisco Catalyst, HP ProCurve)
- Server for Wazuh Manager (4GB RAM minimum, 8GB recommended)
- Raspberry Pi 4 (8GB) for Zeek data aggregator
- Network TAP for safety-critical systems

**Network Access:**
- SPAN/mirror port configuration access
- Ability to create VLANs
- Firewall rule management permissions

**Software:**
- Docker (for Wazuh Manager)
- Python 3.10+
- Terraform (for cloud infrastructure)

## Phase 2 Deployment Steps

### Week 1-2: Network Segmentation
[To be completed during implementation]

### Week 3-4: Zeek & Suricata
[To be completed during implementation]

[Continue with placeholders for each phase...]

## Troubleshooting Common Issues

### Issue: Zeek not capturing traffic
**Possible Causes:**
- SPAN port not configured correctly
- Network interface in wrong mode
- Zeek worker process crashed

**Resolution Steps:**
[To be added during implementation]
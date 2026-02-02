# Agent Documentation Index

> **Single Source of Truth** for all agent work on the RobotLab OT/ICS Security Platform.

---

## Latest Activity

| Date | Agent | Change ID | Summary |
|------|-------|-----------|---------|
| 2026-02-02 | Setup | `INIT-002` | Created 9 individual agent configuration files |
| 2026-02-02 | Setup | `INIT-001` | Initial documentation system setup |

---

## Quick Links

- [Full Changelog](./CHANGELOG.md) - Chronological list of all changes
- [Changes Directory](./changes/) - Detailed change documentation
- [Decisions Directory](./decisions/) - Architecture Decision Records (ADRs)

---

## How to Use This Index

### For Agents
1. **Before starting work:** Check this index for recent related changes
2. **After completing work:** Add entry to this index (newest at top of table)
3. **Create change file:** `changes/YYYY-MM-DD-CHANGE-ID.md`
4. **Update CHANGELOG.md:** Append to chronological log

### For Humans
- This table shows the most recent changes first
- Click any Change ID to see full details
- Use CHANGELOG.md for chronological history

---

## Change ID Format

```
[AGENT]-[NNN]

AGENT codes:
  ARCH  = Master Architect
  INFRA = Infrastructure Agent
  DET   = Detection Engineering Agent
  ML    = ML/AI Pipeline Agent
  BACK  = Backend Agent
  FRONT = Frontend Agent
  CTI   = CTI Agent
  REV   = Code Reviewer Agent
  SEC   = Security Agent
  INIT  = Initial Setup / Configuration

NNN = Sequential number (001, 002, etc.)
```

---

## Statistics

| Metric | Value |
|--------|-------|
| Total Changes | 2 |
| Last Updated | 2026-02-02 |
| Active Agents | 9 configured (Design Phase) |

---

## Directory Structure

```
docs/claude_docs/
├── INDEX.md              ← You are here (single source of truth)
├── CHANGELOG.md          ← Chronological log
├── changes/              ← Individual change documentation
│   └── YYYY-MM-DD-ID.md
└── decisions/            ← Architecture Decision Records
    └── ADR-NNN-title.md
```

# FoundationShield 🛡️

**Fleet-wide security, governance, and intelligence for Foundation Operations infrastructure.**

> *See everything. Miss nothing. Survive anything.*

---

## What It Is

FoundationShield is a 57-check automated security and governance system that runs across the Foundation Operations fleet (VPS Main, VPS2, VPS VRO + VPSOC dark sentinel). It feeds structured event data into the FOMCP, and uses an AI agent to intelligently decide what you need to know and when.

It is designed to be **hard to kill, hard to find, and impossible to silence**.

---

## The 57 Checks

| Category | Checks | Count |
|----------|--------|-------|
| Process & Port | Port collisions, squatters, orphans, dead apps | 5 |
| Git & Repo | Behind/ahead/dirty/stale, staging drift, cross-server drift | 6 |
| Resources | Disk, inodes, RAM, swap, CPU load, OOM events | 6 |
| Application Health | SSL expiry, Fail2ban, Docker, PM2 memory, restart storms, service deps, fd exhaustion, egress | 8 |
| Synthetic & Runtime | Endpoint probing, watchdog heartbeat, deploy fingerprint, nginx 5xx, postgres pool, error rate | 6 |
| Security Hardening | Secrets exposure, CVE audit, Uptime Kuma sync, config integrity | 4 |
| 2026 Threat Checks | npm lockfile, cryptominer, filesystem integrity, SUID detection, SSH keys, IPv6 gap, pipeline integrity, threat intel, NTP drift | 9 |
| Deception & Intrusion | Canary files, honey credentials, auditd kernel audit, systemd service detection | 4 |
| Advanced Intelligence | Process masquerade, backup integrity, log forwarding, slow queries, AI cost anomaly | 5 |
| Observability Polish | Statistical baseline anomaly, response time trend, dependency staleness, self-monitoring | 4 |

---

## Architecture

```
Each Server ──► systemd timers (obfuscated names)
                     │
           ┌─────────┴──────────┐
     Critical events         Routine events
     (immediate push)        (hourly harvest)
           │                     │
           └──────────┬──────────┘
                      ▼
               FOMCP governance.db
                      │
           ┌──────────┴───────────┐
     AI Agent (scheduled)    diagnose tool
     Telegram digest         (on-demand Claude)
     Escalation policy       Admin panel tab
```

### Resilience Layers
- **Hiding** — obfuscated process names, systemd not cron, non-obvious paths
- **Hardening** — `chattr +i` scripts, `chattr +a` logs, `Restart=always`, encrypted creds
- **Redundancy** — cross-server heartbeat mesh + VPSOC dark sentinel (separate bot + chat)

---

## Intelligence Features

- **Shield Score** (0–100) per server, trended over time
- **Escalation policy** — unacknowledged critical → re-alert at 30min → escalate at 60min
- **Incident correlation** — 5+ alerts → root cause chain analysis
- **Auto-postmortem** — AI drafts and commits postmortem on incident resolution
- **MTTR tracking** — learns resolution patterns, shortens escalation for slow-to-resolve checks
- **False positive learning** — 3x snooze → FP candidate, user prompted to suppress
- **Pattern memory** — flags recurring issues for systemic fix
- **Weekly report** — MTTR stats, trend analysis, all-clear confirmation

---

## Repository Structure

```
docs/
  DESIGN.md              # Full design spec
scripts/                 # Governance scripts (deployed to /usr/local/lib/fo-sys/)
  pm2-governance.js      # Checks 1–5
  repo-governance.js     # Checks 6–11
  resource-guard.js      # Checks 12–17
  app-guard.js           # Checks 18–31
  security-guard.js      # Checks 32–44
  deception-guard.js     # Checks 45–48
  intel-guard.js         # Checks 49–57
  sentinel-guard.js      # Cross-server heartbeat
  alerting.js            # Dual-channel alerting
  playbooks.js           # 57-check remediation library
lib/                     # FOMCP integration modules
  governance.js          # DB helpers
  governance-agent.js    # Scheduled AI agent
  governance-mttr.js     # MTTR + escalation
  governance-postmortem.js
  threat-intel.js        # IP blocklist auto-update
tools/
  diagnose.js            # FOMCP on-demand tool
migrations/
  006_governance.sql     # SQLite schema
systemd/                 # Systemd unit files (obfuscated names)
  fo-sysmon.timer
  fo-sysmon.service
  fo-repomon.timer
  fo-repomon.service
  fo-sentinel.timer
  fo-sentinel.service
```

---

## Status

**Phase:** Design complete — ready for implementation  
**Spec:** `docs/DESIGN.md`  
**Target servers:** VPS Main, VPS2, VPS VRO, VPSOC (sentinel)

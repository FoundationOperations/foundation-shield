# FoundationShield — Design Spec
**Date:** 2026-04-16  
**Status:** Approved for implementation  
**Project:** Foundation Operations — FOMCP Feature  
**Version:** 1.0

---

## Overview

FoundationShield is a fleet-wide governance, security, and intelligence system built into the FOMCP. It runs 57 automated checks across 3 active servers (VPS Main, VPS2, VPS VRO) plus a passive dark sentinel (VPSOC), feeds structured event data into a SQLite database on the FOMCP, and uses an AI agent to decide what you need to know and when.

It is designed to be hard to kill, hard to find, and impossible to silence — while giving you a single Telegram + on-demand Claude interface to your entire fleet's health.

**Motto:** *See everything. Miss nothing. Survive anything.*

---

## Goals

1. **57-check security mesh** across VPS Main, VPS2, VPS VRO
2. **Persistent event DB** in FOMCP SQLite (`governance.db`)
3. **AI agent** — scheduled proactive Telegram alerts + on-demand `diagnose` FOMCP tool
4. **Hybrid data pipeline** — critical events push immediately, routine events harvested hourly
5. **Resilient and stealthy** — survives process kills, server compromise attempts, and attacker enumeration
6. **MTTR intelligence** — tracks resolution time, learns patterns, escalates appropriately
7. **Self-documenting** — auto-generates postmortems, builds your ops history automatically

---

## Architecture

### Data Flow

```
Each Server (VPS Main / VPS2 / VPS VRO)
  └── Systemd timers (obfuscated names)
        ├── pm2-governance.js    (every 5min)
        ├── repo-governance.js   (hourly)
        ├── resource-guard.js    (every 5min)
        ├── security-guard.js    (every 5min)
        └── sentinel-guard.js   (every 15min — cross-server heartbeat)

Critical events ──► HTTP POST ──► FOMCP /api/governance/events (immediate)
Routine events  ──► local log  ──► FOMCP fleet harvest (hourly)
All events      ──► governance.db (SQLite, FOMCP, 3 copies)

governance.db ──► AI Agent (scheduled) ──► Telegram digest + escalation
governance.db ──► diagnose FOMCP tool  ──► Claude on-demand
governance.db ──► /admin Shield tab    ──► Live dashboard
```

### Redundancy Mesh

```
VPS Main ──watches──► VPS2 + VPS VRO (heartbeat check)
VPS2     ──watches──► VPS Main + VPS VRO
VPS VRO  ──watches──► VPS Main + VPS2
VPSOC    ──watches──► ALL THREE (dark sentinel — independent Telegram path)
```

If any server's FoundationShield agent goes silent >15min, the other two servers AND VPSOC alert independently via separate bot tokens.

---

## Database Schema (`governance.db`)

### Migration: `006_governance.sql`

```sql
-- One row per alert firing
CREATE TABLE IF NOT EXISTS governance_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  server          TEXT NOT NULL,        -- 'vps-main' | 'vps2' | 'vps-vro' | 'vpsoc'
  check_type      TEXT NOT NULL,        -- e.g. 'pm2_dead' | 'disk_usage' | 'canary_touch'
  severity        TEXT NOT NULL,        -- 'critical' | 'high' | 'medium' | 'info'
  alert_key       TEXT NOT NULL,        -- dedup key
  message         TEXT NOT NULL,
  raw_data        TEXT,                 -- JSON blob (extra context)
  playbook        TEXT,                 -- exact remediation command for this server+check
  source          TEXT DEFAULT 'push',  -- 'push' | 'harvest'
  fired_at        TEXT DEFAULT (datetime('now')),
  acknowledged_at TEXT,
  resolved_at     TEXT,
  acknowledged    INTEGER DEFAULT 0,
  snoozed_until   TEXT,
  snooze_count    INTEGER DEFAULT 0,    -- for false positive detection
  escalated       INTEGER DEFAULT 0
);

-- Full-state snapshot per run (for trend/score queries)
CREATE TABLE IF NOT EXISTS governance_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server       TEXT NOT NULL,
  run_at       TEXT DEFAULT (datetime('now')),
  check_type   TEXT NOT NULL,
  status       TEXT NOT NULL,           -- 'ok' | 'warn' | 'critical'
  detail       TEXT,                    -- JSON
  shield_score INTEGER                  -- 0-100, computed per run
);

-- Shield Score history (per server, trended)
CREATE TABLE IF NOT EXISTS governance_health (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  server      TEXT NOT NULL,
  score       INTEGER NOT NULL,         -- 0-100
  recorded_at TEXT DEFAULT (datetime('now'))
);

-- Baseline stats for statistical anomaly detection (populated after 7 days)
CREATE TABLE IF NOT EXISTS governance_baselines (
  server     TEXT NOT NULL,
  metric     TEXT NOT NULL,             -- e.g. 'cpu_load' | 'disk_pct' | 'response_ms'
  avg        REAL,
  stddev     REAL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (server, metric)
);

-- Pattern + MTTR tracking (recurring alert + resolution time learning)
CREATE TABLE IF NOT EXISTS governance_patterns (
  alert_key        TEXT PRIMARY KEY,
  fire_count       INTEGER DEFAULT 0,
  snooze_count     INTEGER DEFAULT 0,
  first_seen       TEXT,
  last_seen        TEXT,
  avg_resolve_mins REAL,                -- MTTR per check type
  pattern_flagged  INTEGER DEFAULT 0,
  fp_candidate     INTEGER DEFAULT 0    -- false positive candidate (snooze_count >= 3)
);

-- Incident log (grouped alert events)
CREATE TABLE IF NOT EXISTS governance_incidents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server       TEXT NOT NULL,
  declared_at  TEXT DEFAULT (datetime('now')),
  resolved_at  TEXT,
  event_ids    TEXT,                    -- JSON array of governance_events.id
  root_cause   TEXT,                    -- AI-determined root cause chain
  postmortem   TEXT,                    -- path to generated postmortem file
  mttr_mins    REAL
);

-- Threat intel IP blocklist (auto-updated weekly)
CREATE TABLE IF NOT EXISTS threat_intel_ips (
  ip         TEXT PRIMARY KEY,
  source     TEXT,                      -- 'abuse.ch' | 'feodotracker' | 'manual'
  category   TEXT,                      -- 'c2' | 'miner' | 'scanner'
  added_at   TEXT DEFAULT (datetime('now')),
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ge_server_fired  ON governance_events(server, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_ge_severity      ON governance_events(severity, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_ge_unresolved    ON governance_events(resolved_at, server);
CREATE INDEX IF NOT EXISTS idx_ge_alert_key     ON governance_events(alert_key, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_gs_server_run    ON governance_snapshots(server, run_at DESC);
CREATE INDEX IF NOT EXISTS idx_gh_server        ON governance_health(server, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_gi_server        ON governance_incidents(server, declared_at DESC);
```

---

## The 57 Checks

### Category 1 — Process & Port (5 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 1 | Dual-daemon port collision (root vs nodeapp PM2) | critical | 5min |
| 2 | Port squatters (untracked PID on PM2-managed port) | critical | 5min |
| 3 | Unregistered listeners on ports 3000–9090 | high | 5min |
| 4 | Orphaned node processes (>2min, not tracked by PM2) | high | 5min |
| 5 | Dead PM2 apps (errored/stopped status) | critical | 5min |

### Category 2 — Git & Repo (6 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 6 | Repo behind remote (unpulled commits) | high | hourly |
| 7 | Repo ahead of remote (unpushed commits) | medium | hourly |
| 8 | Dirty working tree (uncommitted changes) | medium | hourly |
| 9 | Stale repo (no commits in 30 days) | info | hourly |
| 10 | Staging/prod pair drift (different commit hashes) | high | hourly |
| 11 | Cross-server drift (same repo, different hash on multiple servers) | high | hourly |

### Category 3 — Resources (6 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 12 | Disk usage per mount (>80% warn, >90% critical) | critical | 5min |
| 13 | Inode exhaustion (>80%) | critical | 5min |
| 14 | RAM pressure (>85% used) | high | 5min |
| 15 | Swap usage (>50%) | high | 5min |
| 16 | CPU load avg sustained > `nproc` (core count) for 5min | high | 5min |
| 17 | OOM killer events (scan dmesg/journalctl since last run) | critical | 5min |

### Category 4 — Application Health (8 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 18 | SSL cert expiry (<30d warn, <7d critical) | critical | hourly |
| 19 | Fail2ban status + SSH brute force rate spike (>100 fails/hr) | high | 15min |
| 20 | Docker container unexpected exit or unhealthy | high | 5min |
| 21 | PM2 per-app memory >512MB | medium | 5min |
| 22 | PM2 restart storm (>5 restarts in 5min) | critical | 5min |
| 23 | Service dependency health (postgres, nginx, docker daemon) | critical | 5min |
| 24 | Open file descriptor exhaustion (>80% of ulimit) | high | 15min |
| 25 | Network egress — unexpected listeners outside port registry | high | 5min |

### Category 5 — Synthetic & Runtime (6 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 26 | Synthetic endpoint probing (HTTP health check + response time) | critical | 5min |
| 27 | Cron/timer heartbeat — dead watchdog detection | critical | 15min |
| 28 | Deployment fingerprint drift (built files vs git hash) | high | hourly |
| 29 | Nginx 5xx error rate spike (rolling 5min window) | critical | 5min |
| 30 | PostgreSQL connection pool exhaustion (>80% of max_connections) | high | 5min |
| 31 | PM2 log error rate spike (rolling window vs baseline) | high | 5min |

### Category 6 — Security Hardening (4 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 32 | Secrets file exposure (world-readable .env, .secrets, *.pem) | critical | hourly |
| 33 | NPM audit CVE detection (critical/high severity) | high | weekly |
| 34 | Uptime Kuma sync (harvest all monitor statuses as governance events) | high | 5min |
| 35 | Config integrity (nginx configs, cron.d, deploy scripts checksum) | high | hourly |

### Category 7 — 2026 Threat Checks (9 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 36 | npm lockfile integrity (installed modules match lock hashes) | critical | hourly |
| 37 | Cryptominer detection (sustained CPU on non-PM2 process + stratum ports 3333/4444/14444) | critical | 5min |
| 38 | Filesystem integrity on critical paths (/etc/passwd, sudoers, authorized_keys, nginx/) | critical | 15min |
| 39 | New SUID/SGID binary detection (diff against baseline) | critical | 15min |
| 40 | Unauthorized SSH key addition (authorized_keys change for any user) | critical | 5min |
| 41 | IPv6 firewall gap (IPv6 active but ip6tables not configured) | high | hourly |
| 42 | Deploy pipeline integrity (deploy.sh, webhook handler, GitHub Actions workflow hash) | high | hourly |
| 43 | Outbound connection threat intel (established conns vs auto-updated C2/mining IP blocklist) | critical | 15min |
| 44 | NTP clock drift (>60s from NTP) | high | hourly |

### Category 8 — Deception & Intrusion Detection (4 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 45 | Canary file tripwires — decoys in /tmp, /var/www, /root, each DB dir; alert on any access/rename/delete | critical | 1min |
| 46 | Honey credentials — fake API keys + DB URIs in decoy .env files; lightweight local HTTP listener logs any inbound use attempt | critical | real-time |
| 47 | auditd kernel audit trail (execve on sensitive binaries, open() on /etc/passwd + sudoers + authorized_keys, all su/sudo calls) | high | real-time |
| 48 | New systemd service detection (new unit files in /etc/systemd/system/ or /lib/systemd/system/) | critical | 5min |

### Category 9 — Advanced Intelligence (5 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 49 | Process masquerade detection (processes named kworker/sshd/systemd that aren't real kernel threads) | critical | 5min |
| 50 | Backup integrity verification (backup files exist, are recent, hashes unchanged since last run) | high | daily |
| 51 | Log forwarding health (governance digest growing, external destination reachable) | high | 15min |
| 52 | PostgreSQL slow query detection (pg_stat_statements avg >1s) | medium | 15min |
| 53 | AI/API cost anomaly (OpenAI + Claude daily spend >2x 7-day baseline) | high | hourly |

### Category 10 — Observability Polish (4 checks)
| # | Check | Severity | Frequency |
|---|-------|----------|-----------|
| 54 | Statistical baseline anomaly (deviation >2σ from rolling 7-day avg on any metric) | high | 5min |
| 55 | HTTP response time degradation trend (P50/P95 trending upward over 24h window) | medium | hourly |
| 56 | Dependency staleness score (major versions behind per app) | info | weekly |
| 57 | FoundationShield self-monitoring (last run time, Telegram delivery success, cost per cycle) | high | 15min |

---

## Stealth & Resilience Architecture

### Layer 1 — Hiding

- **Process name**: Scripts run as `node /usr/local/lib/fo-sys/monitor.js` — not `foundationshield` or `governance`
- **Installation path**: `/usr/local/lib/fo-sys/` — not `/root/scripts/`
- **Config path**: `/etc/fo-sys/` — nothing in the name reveals purpose
- **Systemd timer names**: `fo-sysmon.timer`, `fo-repomon.timer`, `fo-sentinel.timer`
- **FOMCP tool name**: `diagnose` — not `shield` or `governance`
- **No crontab entries**: All scheduling via systemd timers only
- **Logs**: `/var/log/fo-sys/digest.log` — not `/var/log/governance`

### Layer 2 — Hardening

- **`chattr +i`** on all script files — root cannot modify without running `chattr -i` first (itself triggers auditd)
- **`chattr +a`** on all log files — append-only, cannot be truncated or deleted (WORM-equivalent)
- **Systemd `Restart=always`, `RestartSec=10`** — killed process returns in 10 seconds automatically
- **Script self-hash verification** — each script hashes itself on startup; tampering triggers alert before execution
- **Encrypted credentials** — Telegram token + FOMCP API key in `/etc/fo-sys/.vault` (encrypted), never in scripts
- **Dual alert channels** — Telegram primary, Gmail SMTP fallback (`/opt/mcp-server/.secrets`)
- **Separate bot token per server** — compromise of one server's token cannot silence the fleet

### Layer 3 — Redundancy

- **Cross-server heartbeat mesh** — every server watches every other server's heartbeat in real time
- **VPSOC dark sentinel** — runs only sentinel watcher, no apps, no FOMCP; uses completely separate Telegram bot + chat ID
- **3 copies of every event** — local append-only log + FOMCP `governance.db` push/harvest + VPSOC event log
- **Threat intel auto-update** — C2/mining IP blocklist pulls from abuse.ch, Feodo Tracker, emerging threats weekly; never stale

---

## AI Agent Design

### Scheduled Agent (Proactive)

**Immediate — Critical only**
- Fires within 60 seconds of a critical event push
- Message includes: what happened, last known good state, estimated time the condition has existed, exact playbook command
- Inline buttons: `✓ Acknowledge` | `⏰ Snooze 2h`
- If not acknowledged in 30min → re-alert with `🚨 ESCALATION` prefix
- If not acknowledged in 60min → fires to secondary escalation chat

**Hourly Digest**
- All events from last hour + open unresolved events
- Grouped by server + severity
- Shield Score header: `VPS Main: 94 🛡️ | VPS2: 88 ⚠️ | VPS VRO: 71 🔴`
- Flags recurring patterns: `"mac-daddy-stage dirty 4x this week — systemic?"`
- Medium + info severity events appear here only, never as immediate alerts
- If all clear: single clean message (not silence)

**Weekly Report — Sunday 9am**
- 7-day summary: total alerts, resolved, patterns, Shield Score trend per server
- MTTR stats: `"Avg resolution time: 12min (down from 31min last week)"`
- Top 3 recurring issues with recommendations
- If perfectly clean: `"✅ Clean week — 0 alerts, 57 checks passing across 3 servers."`

**Incident Declaration**
- 5+ alerts within 10min on any server → Incident declared
- AI traces root cause chain: `"Disk full → PM2 errored → Nginx 5xx. Fix: disk first."`
- One consolidated message, individual alert spam suppressed
- Auto-generates draft postmortem on resolution → saved to `/opt/ops-docs/session-logs/`

### On-Demand Tool (`diagnose`)

Registered as FOMCP tool. Claude calls it naturally in conversation.

```
diagnose(action, server?, timeframe?)
```

| Action | Returns |
|--------|---------|
| `status` | Current Shield Scores + open events across fleet |
| `history` | Event history for server over timeframe |
| `trends` | Baseline anomalies + pattern analysis |
| `incidents` | Recent incident timelines with root cause chains |
| `explain` | AI plain-English situation report for a server |
| `mttr` | Resolution time stats per check type |
| `playbook` | Remediation steps for a specific check_type |

---

## Alert UX Design

### Message Format
```
🔴 [CRITICAL] VPS Main — pm2_dead
mac-daddy-stage is errored
Restarts: 12 | Down since: ~14 min ago
Was healthy at last check (10:47am)

→ sudo pm2 logs mac-daddy-stage --lines 30 | grep -i error

[✓ Acknowledge]  [⏰ Snooze 2h]
```

### Severity Priority Queue
| Severity | Delivery | Cooldown | Escalation |
|----------|----------|----------|------------|
| 🔴 Critical | Immediate | 30min | Re-alert at 30min, escalate at 60min |
| 🟠 High | 2-min dedup | 30min | — |
| 🟡 Medium | Hourly digest | — | — |
| ℹ️ Info | Weekly report | — | — |

### Intelligence Behaviors
- **Alert grouping** — related alerts within 5min window → one message
- **Recovery confirmation** — `"✅ Resolved: mac-daddy-stage back online (down 23min, MTTR: 23min)"`
- **Self-describing alerts** — every alert states: what, last known good, duration, trajectory
- **Disk trajectory** — `"Disk at 87% on /dev/sda1. Growing ~5%/day. Full in ~13 days."`
- **False positive detection** — snooze same key 3x → `"Snooze this permanently? [Yes] [No]"`
- **MTTR learning** — check types with historically long resolution get escalated faster
- **Pattern flagging** — same issue 3x in 7 days → `"Recurring: consider fixing root cause"`

---

## Admin Panel Tab (FoundationShield)

New tab in FOMCP `/admin` UI. Components:

| Widget | Description |
|--------|-------------|
| Shield Score gauges | Live 0–100 score per server, color-coded |
| Event timeline | Scrollable feed of recent events across fleet |
| 7-day trend charts | Shield Score + key metrics (disk, RAM, response time) per server |
| Open incidents | Active incidents with root cause chain + age |
| Pattern heatmap | Check types × servers, heat = frequency |
| MTTR graph | Resolution time trend per check category |
| Threat intel status | Last updated, IP count, recent hits |

---

## MTTR & Postmortem System

### MTTR Tracking
- Every event records `fired_at`, `acknowledged_at`, `resolved_at`
- `governance_patterns.avg_resolve_mins` updated on each resolution
- Weekly report includes MTTR by category
- If a check type's MTTR historically exceeds 60min → escalation timer shortened to 15min

### Auto-Postmortem
When an incident is marked resolved:
1. AI reads full incident timeline from `governance_incidents` + linked `governance_events`
2. Generates structured markdown postmortem:
   - **Timeline**: what fired when
   - **Root cause**: AI-determined causal chain
   - **Resolution**: what was done + how long it took
   - **Prevention**: specific recommended action to prevent recurrence
3. Written to `/opt/ops-docs/session-logs/YYYY-MM-DD-incident-{id}.md`
4. Committed to ops-docs git automatically

---

## Implementation Phases

### Phase 1 — Database & Pipeline
- Migration `006_governance.sql` with full schema
- FOMCP endpoint `POST /api/governance/events` (authenticated)
- FOMCP fleet harvester (hourly SSH harvest from VPS2 + VPS VRO)
- Updated `alerting.js` — push critical events to FOMCP immediately

### Phase 2 — Enriched Scripts (57 Checks)
- Refactor existing pm2-governance.js + repo-governance.js
- New: resource-guard.js, security-guard.js, deception-guard.js, sentinel-guard.js
- All checks emit structured JSON: `{check_type, severity, alert_key, message, raw_data, playbook}`
- Fleet deployment script installs on VPS2 + VPS VRO

### Phase 3 — Stealth & Hardening
- Move scripts to `/usr/local/lib/fo-sys/`
- Systemd timers with obfuscated names (replaces cron)
- `chattr +i` scripts, `chattr +a` logs
- Encrypted credentials vault (`/etc/fo-sys/.vault`)
- Cross-server heartbeat mesh
- VPSOC dark sentinel (separate bot token + chat)

### Phase 4 — AI Agent + Telegram UX
- Scheduled agent: immediate + hourly + weekly cadences
- Escalation policy (30min re-alert, 60min secondary chat)
- Incident declaration + root cause chain analysis
- Telegram inline buttons: ack / snooze / false-positive
- False positive learning loop
- Pattern flagging + MTTR tracking
- `diagnose` FOMCP tool registration

### Phase 5 — Intelligence & Polish
- 7-day baseline collection + 2σ anomaly detection
- Response time trend analysis (P50/P95 degradation)
- Auto-postmortem generation + git commit
- Weekly report with MTTR stats
- Threat intel auto-update (abuse.ch, Feodo Tracker)
- FoundationShield admin panel tab in FOMCP `/admin`
- Playbook library (57 check types × per-server commands)

---

## File Map

```
/usr/local/lib/fo-sys/             # Obfuscated installation path
  pm2-governance.js                # Checks 1–5 (process + port)
  repo-governance.js               # Checks 6–11 (git + repo)
  resource-guard.js                # Checks 12–17 (resources)
  app-guard.js                     # Checks 18–31 (app health + synthetic)
  security-guard.js                # Checks 32–44 (security hardening + 2026 threats)
  deception-guard.js               # Checks 45–48 (canary + auditd + honey)
  intel-guard.js                   # Checks 49–57 (advanced intel + observability)
  sentinel-guard.js                # Cross-server heartbeat watcher
  alerting.js                      # Dual-channel: push critical + write local
  playbooks.js                     # 57 check_type → remediation command map

/etc/fo-sys/
  .vault                           # Encrypted credentials (Telegram + FOMCP key)
  baselines.json                   # 7-day metric baselines (updated weekly)
  canary-manifest.json             # Canary file locations + expected hashes
  suid-baseline.json               # SUID binary baseline

/var/log/fo-sys/
  digest.log                       # chattr +a — append-only event log

/etc/systemd/system/
  fo-sysmon.timer / .service       # Every 5min — pm2 + resource + security + app
  fo-repomon.timer / .service      # Hourly — repo governance
  fo-sentinel.timer / .service     # Every 15min — heartbeat + deception + intel

/opt/mcp-server/
  migrations/006_governance.sql
  lib/governance.js                # DB helpers (read/write governance tables)
  lib/governance-agent.js          # Scheduled AI agent (all cadences)
  lib/governance-mttr.js           # MTTR tracking + escalation logic
  lib/governance-postmortem.js     # Auto-postmortem generation
  lib/threat-intel.js              # IP blocklist auto-update (abuse.ch etc)
  tools/diagnose.js                # on-demand FOMCP tool (extends existing diagnose)
  routes/governance-api.js         # POST /api/governance/events
  routes/admin-shield.js           # /admin shield tab data endpoints

/opt/ops-docs/session-logs/
  YYYY-MM-DD-incident-{id}.md      # Auto-generated postmortems
```

---

## Success Criteria

| Criterion | Target |
|-----------|--------|
| Check coverage | All 57 checks running on VPS Main, VPS2, VPS VRO |
| Critical alert latency | <60 seconds from detection to Telegram |
| Resilience | Process survives `kill -9`, restarts within 10 seconds |
| Stealth | `ps aux \| grep shield` and `crontab -l` return nothing |
| Redundancy | Full wipe of VPS Main governance.db recovers from peer harvest within 1 hour |
| Dark sentinel | VPSOC alerts independently if all 3 primary servers go silent |
| Hourly digest | Fires without gaps; clean week produces "all clear" message |
| On-demand tool | `diagnose(explain)` returns coherent fleet situation in <10 seconds |
| Admin panel | Shield Score live, trend charts updating, event timeline scrollable |
| MTTR | Tracked per check type; postmortems auto-generated and committed |
| Threat intel | Blocklist auto-refreshes weekly from public feeds |
| False positive handling | Snoozed 3x → FP candidate flagged, user prompted |

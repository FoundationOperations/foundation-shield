# FoundationShield Plan 3B — Intelligence Layer (MTTR, Postmortems, Admin Panel, Threat Intel)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the FoundationShield intelligence layer: MTTR tracking, auto-postmortems committed to ops-docs, a Shield Score tab in the FOMCP admin panel, automated threat intel IP blocklist updates, and false-positive learning.

**Prerequisite:** All previous plans (1A, 1B, 2A, 2B, 3A) complete.

**Tech Stack:** Node 22 ESM, better-sqlite3, existing FOMCP admin panel (routes/admin.js), GitHub API via existing `registerGithubTools`, node-fetch/https for threat intel download.

---

## File Map

**FOMCP changes:**
- Create: `/opt/mcp-server/lib/governance-mttr.js` — MTTR tracking, resolution time learning
- Create: `/opt/mcp-server/lib/governance-postmortem.js` — AI postmortem drafting + git commit
- Create: `/opt/mcp-server/lib/threat-intel.js` — IP blocklist auto-update (weekly cron)
- Modify: `/opt/mcp-server/routes/admin.js` — add `/admin/shield` tab route
- Modify: `/opt/mcp-server/lib/governance-agent.js` — integrate MTTR + FP learning

**foundation-shield changes:**
- Modify: `/opt/foundation-shield/scripts/alerting.js` — include `resolved_at` when firing resolution events
- Create: `/opt/foundation-shield/scripts/update-threat-intel.js` — standalone weekly cron script

---

## Task 1: MTTR Tracking (`lib/governance-mttr.js`)

- [ ] **Step 1: Write the module**

```js
// lib/governance-mttr.js — MTTR tracking and resolution time learning
// Called when an event is resolved. Updates governance_patterns with rolling avg MTTR.
// Also handles false-positive learning: 3x snooze = FP candidate.
import { getGovernanceDb, upsertPattern } from './governance.js';
import { logger } from './logger.js';

/**
 * Record resolution for an event and update MTTR in governance_patterns.
 * Call this when resolveEvent() is called.
 */
export function recordResolution(db, event) {
  if (!event.fired_at || !event.resolved_at) return;

  const firedAt   = new Date(event.fired_at).getTime();
  const resolvedAt = new Date(event.resolved_at).getTime();
  const mttrMins  = (resolvedAt - firedAt) / 60000;

  const existing = db.prepare('SELECT * FROM governance_patterns WHERE alert_key = ?').get(event.alert_key);
  if (!existing) {
    upsertPattern(db, event.alert_key);
  }

  // Rolling average MTTR: (old_avg * n + new_value) / (n + 1)
  const fireCount = existing?.fire_count || 1;
  const oldAvg    = existing?.avg_resolve_mins || null;
  const newAvg    = oldAvg !== null
    ? (oldAvg * (fireCount - 1) + mttrMins) / fireCount
    : mttrMins;

  db.prepare(`
    UPDATE governance_patterns
    SET avg_resolve_mins = ?, last_seen = datetime('now')
    WHERE alert_key = ?
  `).run(newAvg, event.alert_key);

  logger.info({ alert_key: event.alert_key, mttr_mins: mttrMins.toFixed(1), new_avg: newAvg.toFixed(1) }, '[mttr] Resolution recorded');
  return mttrMins;
}

/**
 * Shorten escalation threshold for consistently slow-to-resolve checks.
 * If avg MTTR for a check type > 60 min, escalate at 15 min (not 30).
 * Returns: { escalateAfterMins }
 */
export function getEscalationThreshold(db, alertKey) {
  const pattern = db.prepare('SELECT avg_resolve_mins FROM governance_patterns WHERE alert_key = ?').get(alertKey);
  if (!pattern?.avg_resolve_mins) return { escalateAfterMins: 30 };
  return { escalateAfterMins: pattern.avg_resolve_mins > 60 ? 15 : 30 };
}

/**
 * Check for false positive candidates and return them.
 * FP candidate: snooze_count >= 3 and not yet reviewed.
 */
export function getFpCandidates(db) {
  return db.prepare(`
    SELECT * FROM governance_patterns
    WHERE fp_candidate = 1 AND pattern_flagged = 0
    ORDER BY snooze_count DESC
    LIMIT 10
  `).all();
}

/**
 * Mark a pattern as reviewed (pattern_flagged = 1).
 */
export function markPatternReviewed(db, alertKey) {
  db.prepare('UPDATE governance_patterns SET pattern_flagged = 1 WHERE alert_key = ?').run(alertKey);
}

/**
 * Check for recurring patterns (same check firing repeatedly).
 * Returns patterns that have fired 5+ times with no avg_resolve_mins (never resolved).
 */
export function getRecurringIssues(db) {
  return db.prepare(`
    SELECT * FROM governance_patterns
    WHERE fire_count >= 5
      AND avg_resolve_mins IS NULL
      AND pattern_flagged = 0
    ORDER BY fire_count DESC
    LIMIT 10
  `).all();
}
```

- [ ] **Step 2: Write tests**

Create `/opt/mcp-server/test/governance-mttr.test.js`:

```js
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { insertEvent, resolveEvent, upsertPattern } from '../lib/governance.js';
import { recordResolution, getEscalationThreshold, getFpCandidates } from '../lib/governance-mttr.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA = readFileSync(join(__dirname, '../migrations/006_governance.sql'), 'utf8');

function makeDb() { const db = new Database(':memory:'); db.exec(SCHEMA); return db; }

describe('recordResolution', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('records MTTR in governance_patterns', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'disk', severity: 'critical', alert_key: 'disk_test', message: 'm', source: 'push' });
    db.prepare("UPDATE governance_events SET fired_at = datetime('now', '-45 minutes') WHERE id = ?").run(id);
    resolveEvent(db, id);
    const event = db.prepare('SELECT * FROM governance_events WHERE id = ?').get(id);
    const mttr = recordResolution(db, event);
    expect(mttr).toBeGreaterThan(44);
    const pattern = db.prepare('SELECT avg_resolve_mins FROM governance_patterns WHERE alert_key = ?').get('disk_test');
    expect(pattern.avg_resolve_mins).toBeGreaterThan(44);
  });
});

describe('getEscalationThreshold', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('returns 30min for new alert key', () => {
    const { escalateAfterMins } = getEscalationThreshold(db, 'unknown_key');
    expect(escalateAfterMins).toBe(30);
  });

  it('returns 15min for slow-to-resolve checks (MTTR > 60min)', () => {
    db.prepare("INSERT INTO governance_patterns (alert_key, avg_resolve_mins) VALUES ('slow_check', 90)").run();
    const { escalateAfterMins } = getEscalationThreshold(db, 'slow_check');
    expect(escalateAfterMins).toBe(15);
  });
});

describe('getFpCandidates', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('returns patterns with fp_candidate=1 and pattern_flagged=0', () => {
    db.prepare("INSERT INTO governance_patterns (alert_key, fp_candidate, pattern_flagged, snooze_count) VALUES ('noisy', 1, 0, 3)").run();
    const fps = getFpCandidates(db);
    expect(fps.length).toBe(1);
    expect(fps[0].alert_key).toBe('noisy');
  });
});
```

- [ ] **Step 3: Run tests**

```bash
cd /opt/mcp-server
npx vitest run test/governance-mttr.test.js 2>&1 | tail -10
```

Expected: `3 tests | 3 passed`

- [ ] **Step 4: Commit**

```bash
cd /opt/mcp-server
git add lib/governance-mttr.js test/governance-mttr.test.js
git commit -m "feat(shield): governance-mttr.js — MTTR tracking, FP learning, escalation threshold"
```

---

## Task 2: Auto-Postmortem (`lib/governance-postmortem.js`)

When an incident is resolved (governance_incidents.resolved_at set), the AI drafts a postmortem and commits it to ops-docs.

- [ ] **Step 1: Write the module**

```js
// lib/governance-postmortem.js — Auto-postmortem drafting + commit to ops-docs
import { getGovernanceDb } from './governance.js';
import { aiAnalyze } from './governance-agent.js';
import { logger } from './logger.js';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const OPS_DOCS_PATH = process.env.OPS_DOCS_PATH || '/opt/ops-docs';
const POSTMORTEM_DIR = path.join(OPS_DOCS_PATH, 'postmortems');

/**
 * Draft and commit a postmortem for a resolved incident.
 * Returns the path of the created file.
 */
export async function createPostmortem(incidentId) {
  const db = getGovernanceDb();
  const incident = db.prepare('SELECT * FROM governance_incidents WHERE id = ?').get(incidentId);
  if (!incident || !incident.resolved_at) {
    throw new Error(`Incident ${incidentId} not found or not resolved`);
  }

  // Gather event details
  const eventIds = JSON.parse(incident.event_ids || '[]');
  const events = eventIds.length
    ? db.prepare(`SELECT * FROM governance_events WHERE id IN (${eventIds.map(() => '?').join(',')})`)
        .all(...eventIds)
    : [];

  const mttrMins = incident.mttr_mins ? Math.round(incident.mttr_mins) : 'unknown';
  const eventList = events.map(e => `- [${e.severity}] ${e.check_type}: ${e.message.slice(0, 80)}`).join('\n');

  const prompt = `Write a concise postmortem for this server incident:

Server: ${incident.server}
Declared: ${incident.declared_at}
Resolved: ${incident.resolved_at}
MTTR: ${mttrMins} minutes
Root cause: ${incident.root_cause || 'Unknown'}

Events during incident:
${eventList || 'No individual events captured'}

Format as Markdown with sections: Summary, Timeline, Root Cause, Impact, Resolution, Action Items (3 max). Keep it under 500 words. Be direct and actionable.`;

  const draft = await aiAnalyze(prompt, 'gpt-4.1-mini');
  if (!draft) {
    logger.warn({ incident_id: incidentId }, '[postmortem] AI draft unavailable');
    return null;
  }

  // Create postmortem file
  try { fs.mkdirSync(POSTMORTEM_DIR, { recursive: true }); } catch (_) {}
  const date    = new Date().toISOString().slice(0, 10);
  const slug    = `${incident.server}-${incident.id}`;
  const filename = `${date}-incident-${slug}.md`;
  const filePath = path.join(POSTMORTEM_DIR, filename);

  const content = `# Postmortem: ${incident.server} — Incident #${incident.id}\n\n` +
    `**Date:** ${date}  \n` +
    `**Server:** ${incident.server}  \n` +
    `**MTTR:** ${mttrMins} minutes  \n` +
    `**Status:** Resolved  \n\n---\n\n${draft}\n\n---\n_Auto-generated by FoundationShield_\n`;

  fs.writeFileSync(filePath, content);

  // Commit to ops-docs
  try {
    execSync(`git -C ${OPS_DOCS_PATH} add postmortems/${filename}`, { encoding: 'utf8' });
    execSync(`git -C ${OPS_DOCS_PATH} commit -m "postmortem: ${incident.server} incident #${incident.id} (${date}, MTTR ${mttrMins}min)"`,
      { encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 'FoundationShield', GIT_AUTHOR_EMAIL: 'shield@foundationoperations.com', GIT_COMMITTER_NAME: 'FoundationShield', GIT_COMMITTER_EMAIL: 'shield@foundationoperations.com' } }
    );
    logger.info({ filename, incident_id: incidentId }, '[postmortem] Committed to ops-docs');
  } catch (gitErr) {
    logger.warn({ error: gitErr.message }, '[postmortem] Git commit failed — file saved but not committed');
  }

  // Update incident record with postmortem path
  db.prepare('UPDATE governance_incidents SET postmortem = ? WHERE id = ?').run(filePath, incidentId);

  return filePath;
}

/**
 * Check for resolved incidents without postmortems and generate them.
 * Called by governance agent hourly.
 */
export async function generateMissingPostmortems() {
  const db = getGovernanceDb();
  const pending = db.prepare(`
    SELECT id FROM governance_incidents
    WHERE resolved_at IS NOT NULL AND postmortem IS NULL
    ORDER BY resolved_at DESC LIMIT 5
  `).all();

  for (const { id } of pending) {
    try {
      const path = await createPostmortem(id);
      if (path) logger.info({ incident_id: id, path }, '[postmortem] Generated');
    } catch (err) {
      logger.error({ incident_id: id, error: err.message }, '[postmortem] Failed');
    }
  }
}
```

- [ ] **Step 2: Commit**

```bash
cd /opt/mcp-server
git add lib/governance-postmortem.js
git commit -m "feat(shield): governance-postmortem.js — AI postmortem drafting + git commit to ops-docs"
```

---

## Task 3: Threat Intel Auto-Update (`lib/threat-intel.js`)

Downloads fresh C2/mining IP blocklists from abuse.ch and Feodo Tracker weekly, stores in `threat_intel_ips` table and exports to `/var/log/fo-sys/threat-intel-ips.txt` for use by `security-guard.js` Check 43.

- [ ] **Step 1: Write the module**

```js
// lib/threat-intel.js — threat intel IP blocklist auto-update
// Sources: abuse.ch URLhaus, Feodo Tracker
// Updates weekly, stores in threat_intel_ips table + exports flat file for scripts.
import https from 'https';
import { getGovernanceDb } from './governance.js';
import { logger } from './logger.js';
import fs from 'fs';

const EXPORT_FILE = '/var/log/fo-sys/threat-intel-ips.txt';

const SOURCES = [
  {
    name: 'feodotracker',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    category: 'c2',
    parseIp: (line) => {
      if (line.startsWith('#') || !line.trim()) return null;
      const m = line.match(/^(\d+\.\d+\.\d+\.\d+)/);
      return m ? m[1] : null;
    }
  },
  {
    name: 'abuse.ch-botnet',
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    category: 'c2',
    parseIp: (line) => {
      if (line.startsWith('#') || !line.trim()) return null;
      const parts = line.split(',');
      return parts[0] || null;
    }
  }
];

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'FoundationShield/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        // Follow redirect
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(data));
    }).on('error', reject).setTimeout(30000, function() { this.destroy(); reject(new Error('Timeout')); });
  });
}

export async function updateThreatIntel() {
  const db = getGovernanceDb();
  const now = new Date().toISOString();
  let totalAdded = 0;

  for (const source of SOURCES) {
    try {
      logger.info({ source: source.name }, '[threat-intel] Fetching...');
      const text = await fetchUrl(source.url);
      const ips = text.split('\n').map(source.parseIp).filter(Boolean);

      const upsert = db.prepare(`
        INSERT INTO threat_intel_ips (ip, source, category, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET source=excluded.source, category=excluded.category, updated_at=excluded.updated_at
      `);

      const insertMany = db.transaction((ipList) => {
        let count = 0;
        for (const ip of ipList) {
          try { upsert.run(ip, source.name, source.category, now); count++; } catch (_) {}
        }
        return count;
      });

      const added = insertMany(ips);
      totalAdded += added;
      logger.info({ source: source.name, count: added }, '[threat-intel] Updated');
    } catch (err) {
      logger.error({ source: source.name, error: err.message }, '[threat-intel] Fetch failed');
    }
  }

  // Export flat file for governance scripts
  try {
    const ips = db.prepare('SELECT ip FROM threat_intel_ips ORDER BY updated_at DESC').all().map(r => r.ip);
    fs.writeFileSync(EXPORT_FILE, `# FoundationShield Threat Intel Blocklist\n# Updated: ${now}\n# IPs: ${ips.length}\n${ips.join('\n')}\n`);
    logger.info({ total: ips.length, export_path: EXPORT_FILE }, '[threat-intel] Export complete');
  } catch (err) {
    logger.error({ error: err.message }, '[threat-intel] Export failed');
  }

  return totalAdded;
}

// Weekly cron integration — call from governance agent
let threatIntelInterval = null;
let lastThreatIntelUpdate = 0;

export function startThreatIntelCron() {
  // Check once per hour, only actually fetch weekly
  threatIntelInterval = setInterval(async () => {
    const weekMs = 7 * 24 * 60 * 60 * 1000;
    if (Date.now() - lastThreatIntelUpdate > weekMs) {
      await updateThreatIntel().catch(err => logger.error({ error: err.message }, '[threat-intel] Weekly update failed'));
      lastThreatIntelUpdate = Date.now();
    }
  }, 60 * 60 * 1000);

  // Run immediately on startup if never updated
  updateThreatIntel().then(() => { lastThreatIntelUpdate = Date.now(); }).catch(() => {});
}

export function stopThreatIntelCron() {
  if (threatIntelInterval) { clearInterval(threatIntelInterval); threatIntelInterval = null; }
}
```

- [ ] **Step 2: Wire into `server.js`**

Add import:
```js
import { startThreatIntelCron, stopThreatIntelCron } from './lib/threat-intel.js';
```

In startup section, add after `startGovernanceAgent()`:
```js
startThreatIntelCron();
```

In `gracefulShutdown()`, add after `stopGovernanceAgent()`:
```js
stopThreatIntelCron();
```

- [ ] **Step 3: Commit**

```bash
cd /opt/mcp-server
git add lib/threat-intel.js server.js
git commit -m "feat(shield): threat-intel.js — weekly IP blocklist auto-update from abuse.ch + Feodo Tracker"
```

---

## Task 4: Admin Panel Shield Tab

Add a `/admin/shield` route to the FOMCP admin panel that shows:
- Fleet Shield Scores (live)
- Recent unresolved events table
- FP candidates
- Pattern table (recurring issues)

- [ ] **Step 1: Read the current admin route to understand the pattern**

```bash
head -80 /opt/mcp-server/routes/admin.js
```

Note the pattern for adding new admin sub-routes.

- [ ] **Step 2: Add Shield tab route to `routes/admin.js`**

Find the section in `admin.js` where admin API routes are registered and add:

```js
// FoundationShield admin tab
app.get('/admin/shield', adminAuth, (req, res) => {
  try {
    const { getGovernanceDb, listRecent, getFleetSummary, getShieldScore } = require('./lib/governance.js');
    // Note: dynamic import for ESM in CJS context — use the already-imported version
    res.redirect('/admin#shield');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shield data API (JSON — for admin panel JS to fetch)
app.get('/admin/shield/data', adminAuth, async (req, res) => {
  try {
    const { getGovernanceDb, listRecent, getFleetSummary } = await import('./lib/governance.js');
    const { getFpCandidates, getRecurringIssues } = await import('./lib/governance-mttr.js');
    const db = getGovernanceDb();

    const fleet    = getFleetSummary(db);
    const events   = listRecent(db, { unresolved: true, limit: 50, hours: 48 });
    const fpCands  = getFpCandidates(db);
    const recurring = getRecurringIssues(db);
    const threatCount = db.prepare('SELECT COUNT(*) as cnt FROM threat_intel_ips').get().cnt;

    res.json({ fleet, events, fpCandidates: fpCands, recurringIssues: recurring, threatIntelCount: threatCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

- [ ] **Step 3: Verify the route works**

```bash
FOMCP_TOKEN=$(grep -E 'FOMCP_TOKEN|MCP_API_TOKEN' /opt/mcp-server/.secrets | head -1 | cut -d= -f2 | tr -d "'\"")
# Admin auth uses Basic Auth — get credentials from .secrets:
ADMIN_USER=$(grep ADMIN_USER /opt/mcp-server/.secrets | cut -d= -f2 | tr -d "'\"" || echo 'admin')
ADMIN_PASS=$(grep ADMIN_PASS /opt/mcp-server/.secrets | cut -d= -f2 | tr -d "'\"" || echo 'changeme')

curl -s "http://127.0.0.1:4500/admin/shield/data" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" | python3 -m json.tool | head -30
```

Expected: JSON with `fleet`, `events`, `fpCandidates`, `recurringIssues` arrays.

- [ ] **Step 4: Commit**

```bash
cd /opt/mcp-server
git add routes/admin.js
git commit -m "feat(shield): add /admin/shield/data API route for FoundationShield admin tab"
```

---

## Task 5: Integrate MTTR + Postmortems + FP Learning into Agent

Modify `governance-agent.js` to:
1. Record MTTR when events are resolved
2. Generate postmortems on incident resolution  
3. Alert on FP candidates weekly
4. Alert on recurring patterns monthly

- [ ] **Step 1: Add imports to `governance-agent.js`**

```js
import { recordResolution, getFpCandidates, getRecurringIssues, markPatternReviewed } from './governance-mttr.js';
import { generateMissingPostmortems } from './governance-postmortem.js';
```

- [ ] **Step 2: Add FP candidate check to hourly digest**

In `sendHourlyDigest()`, add after the AI summary section:

```js
// Check for FP candidates
const fpCandidates = getFpCandidates(db);
if (fpCandidates.length > 0) {
  const fpList = fpCandidates.slice(0, 3).map(fp =>
    `• \`${fp.alert_key}\` — snoozed ${fp.snooze_count}× (fired ${fp.fire_count}×)`
  ).join('\n');
  const fpMsg = `\n\n⚠️ *False Positive Candidates (snoozed 3+ times):*\n${fpList}\n\nConsider suppressing via governance patterns.`;
  await sendTelegram(fpMsg);
}
```

- [ ] **Step 3: Add postmortem generation to agent tick**

In the 10-minute escalation check block, add:

```js
// Generate missing postmortems for resolved incidents
if (now - lastEscalationCheck > 10 * 60 * 1000) {
  // ... existing escalation code ...
  await generateMissingPostmortems().catch(() => {});
}
```

- [ ] **Step 4: Commit**

```bash
cd /opt/mcp-server
git add lib/governance-agent.js lib/governance-mttr.js lib/governance-postmortem.js
git commit -m "feat(shield): integrate MTTR tracking + postmortem generation + FP learning into agent"
```

---

## Task 6: Full System Integration Test

- [ ] **Step 1: Restart FOMCP and verify all modules load**

```bash
sudo pm2 restart mcp-server
sleep 5
sudo pm2 logs mcp-server --lines 30 --nostream | grep -E 'agent|shield|intel|postmortem|mttr'
```

Expected: Lines showing agent started, threat intel update initiated.

- [ ] **Step 2: Verify threat intel downloaded**

```bash
wc -l /var/log/fo-sys/threat-intel-ips.txt 2>/dev/null
sqlite3 /opt/mcp-server/data/governance.db "SELECT COUNT(*) FROM threat_intel_ips;"
```

Expected: Both show > 0 (may take 30+ seconds for download to complete).

- [ ] **Step 3: Simulate incident lifecycle**

```bash
FOMCP_TOKEN=$(grep -E 'FOMCP_TOKEN|MCP_API_TOKEN' /opt/mcp-server/.secrets | head -1 | cut -d= -f2 | tr -d "'\"")

# Insert 5 events (enough to trigger incident correlation in next agent tick)
for i in 1 2 3 4 5; do
  curl -s -X POST http://127.0.0.1:4500/api/governance/events \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $FOMCP_TOKEN" \
    -d "{\"server\":\"vps-main\",\"check_type\":\"integration_test_${i}\",\"severity\":\"high\",\"alert_key\":\"int_test_${i}\",\"message\":\"Integration test event ${i}\"}"
done
echo ""
echo "Inserted 5 test events. Incident correlation fires after 5+ events on same server in 30min."
```

- [ ] **Step 4: Verify admin shield data endpoint returns data**

```bash
ADMIN_USER=$(grep ADMIN_USER /opt/mcp-server/.secrets 2>/dev/null | cut -d= -f2 | tr -d "'\"" || echo 'admin')
ADMIN_PASS=$(grep ADMIN_PASS /opt/mcp-server/.secrets 2>/dev/null | cut -d= -f2 | tr -d "'\"" || echo 'changeme')
curl -s "http://127.0.0.1:4500/admin/shield/data" -u "${ADMIN_USER}:${ADMIN_PASS}" | python3 -m json.tool | head -20
```

Expected: JSON with fleet scores and the 5 test events in the events array.

- [ ] **Step 5: Run all governance tests**

```bash
cd /opt/mcp-server
npx vitest run test/governance.test.js test/governance-agent.test.js test/governance-mttr.test.js 2>&1 | tail -15
```

Expected: All tests pass (15+ tests).

- [ ] **Step 6: Push everything**

```bash
cd /opt/mcp-server
git push origin main

cd /opt/foundation-shield
git push origin main
```

---

## Definition of Done

- [ ] `governance-mttr.js` tracks MTTR per alert key and updates rolling average on resolution
- [ ] `getEscalationThreshold()` returns 15min for slow-to-resolve checks (MTTR >60min)
- [ ] FP candidates (snoozed 3+ times) surface in hourly digest
- [ ] `governance-postmortem.js` drafts and commits a postmortem to ops-docs on incident resolution
- [ ] `threat-intel.js` downloads and stores IP blocklist on FOMCP startup; exports flat file
- [ ] `/admin/shield/data` returns live fleet status, events, FP candidates, threat intel count
- [ ] All 15+ governance Vitest tests pass
- [ ] FOMCP restarts cleanly with all new modules active
- [ ] Full 6-plan FoundationShield system is live on VPS Main

---

## Summary: What You've Built

After completing all 6 plans, FoundationShield provides:

| Capability | Detail |
|---|---|
| **57 security checks** | Running every 5–60min on VPS Main, VPS2, VPS VRO |
| **Real-time push pipeline** | Critical events → FOMCP in <2 seconds |
| **Hourly harvest** | VPS2 + VPS VRO event logs → governance.db |
| **AI agent** | New criticals paged immediately; hourly digest; weekly report |
| **Escalation** | Unacked critical → re-alert at 30min → second at 60min |
| **MTTR learning** | Resolution times tracked; fast escalation for slow checks |
| **Incident correlation** | 5+ events in 30min → incident declared, root cause analyzed |
| **Auto-postmortems** | AI drafts + commits to ops-docs on resolution |
| **FP learning** | Snoozed 3+ times → FP candidate surfaced to user |
| **Stealth** | Obfuscated paths, systemd not cron, no `foundation-shield` in process names |
| **Hardened** | `chattr +i` scripts, `chattr +a` logs, `Restart=always`, self-hash verification |
| **Dark sentinel** | VPSOC watches all 3 servers via independent bot — cannot be silenced |
| **Threat intel** | Weekly C2/mining IP blocklist from abuse.ch + Feodo Tracker |
| **Admin panel** | `/admin/shield/data` for live fleet status |
| **On-demand** | `diagnose` FOMCP tool for Claude to query fleet anytime |

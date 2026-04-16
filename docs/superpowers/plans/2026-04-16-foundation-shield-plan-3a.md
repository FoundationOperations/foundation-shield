# FoundationShield Plan 3A — AI Agent Core (Scheduled + On-Demand `diagnose` Tool)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire an AI agent into the governance pipeline. The agent runs on two modes: (1) scheduled — queries `governance.db`, decides what's important, sends a Telegram digest, escalates unacknowledged criticals; (2) on-demand — the `diagnose` FOMCP tool that Claude can call to get an intelligent fleet health read.

**Prerequisite:** Plans 1A, 1B, 2A, 2B complete. governance.db has live event data.

**Architecture:** `lib/governance-agent.js` (scheduled loop started from `server.js`) + `tools/governance-tools.js` (FOMCP `diagnose` tool). Agent uses the FOMCP's existing `foundation-ai` module (OpenAI) for reasoning.

**Tech Stack:** Node 22 ESM, better-sqlite3, existing FOMCP AI infrastructure (`registerFoundationAiTools` / OpenAI client), Telegram Bot API.

---

## File Map

**FOMCP changes:**
- Create: `/opt/mcp-server/lib/governance-agent.js` — scheduled AI agent (immediate critical + hourly digest + weekly report)
- Create: `/opt/mcp-server/tools/governance-tools.js` — FOMCP `diagnose` tool
- Modify: `/opt/mcp-server/server.js` — start agent loop, register diagnose tool
- Modify: `/opt/mcp-server/lib/governance.js` — add `acknowledgeEvent`, `resolveEvent`, `snoozeEvent` helpers

**Tests:**
- Create: `/opt/mcp-server/test/governance-agent.test.js` — Vitest unit tests for agent decision logic

---

## Task 1: Add Event Lifecycle Helpers to `governance.js`

These are needed by the agent to acknowledge/resolve/snooze events.

- [ ] **Step 1: Write failing tests**

Add to `/opt/mcp-server/test/governance.test.js` (append to existing file):

```js
import { acknowledgeEvent, resolveEvent, snoozeEvent } from '../lib/governance.js';

describe('acknowledgeEvent', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('sets acknowledged=1 and acknowledged_at timestamp', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'critical', alert_key: 'k1', message: 'm1', source: 'push' });
    acknowledgeEvent(db, id);
    const row = db.prepare('SELECT acknowledged, acknowledged_at FROM governance_events WHERE id = ?').get(id);
    expect(row.acknowledged).toBe(1);
    expect(row.acknowledged_at).toBeTruthy();
  });
});

describe('resolveEvent', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('sets resolved_at timestamp', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'critical', alert_key: 'k2', message: 'm2', source: 'push' });
    resolveEvent(db, id);
    const row = db.prepare('SELECT resolved_at FROM governance_events WHERE id = ?').get(id);
    expect(row.resolved_at).toBeTruthy();
  });
});

describe('snoozeEvent', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('sets snoozed_until to future date and increments snooze_count', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'high', alert_key: 'k3', message: 'm3', source: 'push' });
    const until = new Date(Date.now() + 3600000).toISOString();
    snoozeEvent(db, id, until);
    const row = db.prepare('SELECT snoozed_until, snooze_count FROM governance_events WHERE id = ?').get(id);
    expect(row.snoozed_until).toBe(until);
    expect(row.snooze_count).toBe(1);
  });
});
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /opt/mcp-server
npx vitest run test/governance.test.js 2>&1 | tail -10
```

Expected: 3 new tests fail with "acknowledgeEvent is not a function"

- [ ] **Step 3: Add functions to `lib/governance.js`**

Append to `/opt/mcp-server/lib/governance.js`:

```js
export function acknowledgeEvent(db, id) {
  db.prepare("UPDATE governance_events SET acknowledged = 1, acknowledged_at = datetime('now') WHERE id = ?").run(id);
}

export function resolveEvent(db, id) {
  db.prepare("UPDATE governance_events SET resolved_at = datetime('now') WHERE id = ?").run(id);
}

export function snoozeEvent(db, id, until) {
  db.prepare("UPDATE governance_events SET snoozed_until = ?, snooze_count = snooze_count + 1 WHERE id = ?").run(until, id);
  // Also update pattern snooze count
  const event = db.prepare('SELECT alert_key FROM governance_events WHERE id = ?').get(id);
  if (event) upsertPattern(db, event.alert_key, { snooze: true });
}

/**
 * Get unresolved critical/high events that haven't been snoozed and are unacknowledged.
 * Used by escalation policy.
 */
export function getUnacknowledgedCriticals(db, olderThanMins = 30) {
  return db.prepare(`
    SELECT * FROM governance_events
    WHERE severity IN ('critical', 'high')
      AND acknowledged = 0
      AND resolved_at IS NULL
      AND (snoozed_until IS NULL OR snoozed_until < datetime('now'))
      AND fired_at <= datetime('now', '-${parseInt(olderThanMins)} minutes')
    ORDER BY fired_at ASC
  `).all();
}
```

- [ ] **Step 4: Run tests — all pass**

```bash
cd /opt/mcp-server
npx vitest run test/governance.test.js 2>&1 | tail -10
```

Expected: `12 tests | 12 passed`

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp-server
git add lib/governance.js test/governance.test.js
git commit -m "feat(shield): add acknowledge/resolve/snooze/escalation helpers to governance.js"
```

---

## Task 2: Write `lib/governance-agent.js` (Scheduled AI Agent)

- [ ] **Step 1: Write the agent module**

```js
// lib/governance-agent.js — FoundationShield scheduled AI agent
// Modes:
//   immediate: fires on any new critical event (poll every 2 min)
//   hourly: digest of all recent events, AI decides what to surface
//   weekly: full trend report every Monday 9am
//   escalation: re-alert unacknowledged criticals at 30min, escalate at 60min
import { getGovernanceDb, listRecent, getFleetSummary, getShieldScore, getUnacknowledgedCriticals, acknowledgeEvent } from './governance.js';
import { loadSecrets } from './secrets.js';
import { logger } from './logger.js';
import https from 'https';

const secrets = loadSecrets();
const TELEGRAM_TOKEN  = secrets.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT   = secrets.TELEGRAM_CHAT_ID;
const OPENAI_API_KEY  = secrets.OPENAI_API_KEY;

// ── Telegram ──────────────────────────────────────────────────────────────────
function sendTelegram(message) {
  return new Promise((resolve) => {
    if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT) return resolve(false);
    const body = JSON.stringify({ chat_id: TELEGRAM_CHAT, text: message, parse_mode: 'Markdown' });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TELEGRAM_TOKEN}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => { res.resume(); res.on('end', () => resolve(res.statusCode === 200)); });
    req.setTimeout(10000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

// ── OpenAI call ───────────────────────────────────────────────────────────────
async function aiAnalyze(prompt, model = 'gpt-4.1-nano') {
  if (!OPENAI_API_KEY) return null;
  return new Promise((resolve) => {
    const body = JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'You are FoundationShield, a concise fleet security analyst. Output short Telegram-ready Markdown. No code blocks. Max 400 chars per finding. Be direct.' },
        { role: 'user',   content: prompt }
      ],
      max_tokens: 600,
      temperature: 0.3
    });
    const req = https.request({
      hostname: 'api.openai.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data).choices?.[0]?.message?.content || null); }
        catch { resolve(null); }
      });
    });
    req.setTimeout(30000, () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.write(body);
    req.end();
  });
}

// ── State tracking ────────────────────────────────────────────────────────────
let lastCriticalCheck = 0;
let lastHourlyDigest  = 0;
let lastWeeklyReport  = 0;
let lastEscalationCheck = 0;

// Track which critical events we've already paged about (by id)
const pagedCriticals = new Set();

// ── Immediate Critical Alert (every 2 min poll) ───────────────────────────────
async function checkNewCriticals(db) {
  const since = Math.floor((Date.now() - 2.5 * 60 * 1000)); // 2.5 min ago
  const criticals = db.prepare(`
    SELECT * FROM governance_events
    WHERE severity = 'critical'
      AND fired_at >= datetime('now', '-3 minutes')
      AND resolved_at IS NULL
    ORDER BY fired_at DESC
    LIMIT 10
  `).all();

  for (const event of criticals) {
    if (pagedCriticals.has(event.id)) continue;
    pagedCriticals.add(event.id);

    const msg = `🚨 *CRITICAL — ${event.server}*\n*Check:* ${event.check_type}\n\n${event.message}` +
                (event.playbook ? `\n\n*Fix:* \`${event.playbook.slice(0, 150)}\`` : '');
    await sendTelegram(msg);
    logger.info({ event_id: event.id, check_type: event.check_type, server: event.server }, '[agent] Paged critical');
  }

  // Cleanup stale page tracking (don't grow forever)
  if (pagedCriticals.size > 500) {
    const arr = [...pagedCriticals];
    arr.slice(0, 250).forEach(id => pagedCriticals.delete(id));
  }
}

// ── Escalation Policy ─────────────────────────────────────────────────────────
async function runEscalationPolicy(db) {
  // Re-alert criticals unacknowledged for 30+ minutes
  const unacked30 = getUnacknowledgedCriticals(db, 30);
  for (const event of unacked30.filter(e => !e.escalated)) {
    await sendTelegram(`⚠️ *ESCALATION — Unacknowledged for 30min*\n*Server:* ${event.server} | *Check:* ${event.check_type}\n${event.message.slice(0, 200)}\n\nEvent ID: ${event.id}`);
    db.prepare('UPDATE governance_events SET escalated = 1 WHERE id = ?').run(event.id);
    logger.warn({ event_id: event.id }, '[agent] Escalated unacknowledged critical');
  }

  // Re-alert at 60min (second escalation)
  const unacked60 = getUnacknowledgedCriticals(db, 60);
  for (const event of unacked60.filter(e => e.escalated === 1)) {
    await sendTelegram(`🆘 *SECOND ESCALATION — Unacknowledged 60min*\n*Server:* ${event.server}\n*Check:* ${event.check_type}\n\nThis has been firing for 1+ hour with no acknowledgment.\nEvent ID: ${event.id}`);
    db.prepare('UPDATE governance_events SET escalated = 2 WHERE id = ?').run(event.id);
  }
}

// ── Hourly Digest ─────────────────────────────────────────────────────────────
async function sendHourlyDigest(db) {
  const events = listRecent(db, { hours: 1, limit: 50 });
  if (events.length === 0) {
    await sendTelegram(`🛡️ *FoundationShield Hourly — All Clear*\nNo alerts in the last hour. Fleet operating normally.`);
    return;
  }

  const fleet = getFleetSummary(db);
  const fleetLines = fleet.map(s => `• *${s.server}*: Shield ${s.score}/100 — ${s.total} event(s)`).join('\n');

  // AI analysis of the hour's events
  const evtSummary = events.slice(0, 15).map(e =>
    `[${e.severity}] ${e.server}/${e.check_type}: ${e.message.slice(0, 80)}`
  ).join('\n');

  const aiSummary = await aiAnalyze(
    `Fleet security events in the last hour:\n${evtSummary}\n\nIn 3 bullet points: what's most concerning, any pattern, and recommended action. Be concise.`
  );

  const msg = `🛡️ *FoundationShield Hourly Digest*\n\n` +
              `*Fleet Scores:*\n${fleetLines}\n\n` +
              `*Events:* ${events.length} total (${events.filter(e => e.severity === 'critical').length} critical, ${events.filter(e => e.severity === 'high').length} high)\n\n` +
              (aiSummary ? `*AI Summary:*\n${aiSummary}` : `_Top: ${events[0].check_type} on ${events[0].server}_`);

  await sendTelegram(msg.slice(0, 4000));
  logger.info({ event_count: events.length }, '[agent] Hourly digest sent');
}

// ── Weekly Report ─────────────────────────────────────────────────────────────
async function sendWeeklyReport(db) {
  const events = listRecent(db, { hours: 168, limit: 200 }); // 7 days
  const fleet  = getFleetSummary(db);
  const fleetLines = fleet.map(s => `• *${s.server}*: ${s.total} events, score ${s.score}/100`).join('\n');

  // Top recurring checks
  const checkCounts = {};
  for (const e of events) { checkCounts[e.check_type] = (checkCounts[e.check_type] || 0) + 1; }
  const topChecks = Object.entries(checkCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const topLines = topChecks.map(([k, v]) => `• ${k}: ${v}×`).join('\n');

  const aiSummary = await aiAnalyze(
    `Weekly fleet security summary (${events.length} events over 7 days):\nTop checks: ${topChecks.map(([k, v]) => `${k}(${v})`).join(', ')}\nFleet: ${fleet.map(s => `${s.server}:${s.score}`).join(', ')}\n\nProvide a 3-sentence executive summary covering: overall health, biggest risks, recommended priority action this week.`,
    'gpt-4.1-mini'
  );

  const msg = `📊 *FoundationShield Weekly Report*\n\n` +
              `*7-Day Fleet Status:*\n${fleetLines}\n\n` +
              `*Top Recurring Checks:*\n${topLines}\n\n` +
              `*Total Events:* ${events.length} (${events.filter(e => e.severity === 'critical').length} critical)\n\n` +
              (aiSummary ? `*AI Summary:*\n${aiSummary}` : '');

  await sendTelegram(msg.slice(0, 4000));
  logger.info('[agent] Weekly report sent');
}

// ── Incident Correlation ──────────────────────────────────────────────────────
async function checkIncidentCorrelation(db) {
  // If 5+ unresolved events on same server in last 30 min — declare incident
  const servers = ['vps-main', 'vps2', 'vps-vro'];
  for (const server of servers) {
    const recentCount = db.prepare(`
      SELECT COUNT(*) as cnt FROM governance_events
      WHERE server = ? AND fired_at >= datetime('now', '-30 minutes') AND resolved_at IS NULL
    `).get(server);

    if (recentCount.cnt >= 5) {
      // Check if incident already declared
      const existing = db.prepare(`
        SELECT id FROM governance_incidents
        WHERE server = ? AND declared_at >= datetime('now', '-30 minutes') AND resolved_at IS NULL
      `).get(server);

      if (!existing) {
        const events = listRecent(db, { server, hours: 1, limit: 20 });
        const eventIds = JSON.stringify(events.map(e => e.id));
        const summary  = events.map(e => `${e.check_type}: ${e.message.slice(0, 60)}`).join('\n');

        const rootCause = await aiAnalyze(
          `${recentCount.cnt} alerts on ${server} in 30 minutes:\n${summary}\n\nIn one sentence, what is the most likely root cause?`,
          'gpt-4.1-mini'
        );

        db.prepare(`
          INSERT INTO governance_incidents (server, event_ids, root_cause)
          VALUES (?, ?, ?)
        `).run(server, eventIds, rootCause || 'Unknown — requires manual investigation');

        await sendTelegram(`🚨 *INCIDENT DECLARED — ${server}*\n${recentCount.cnt} alerts in 30 minutes.\n\n*Likely cause:* ${(rootCause || 'Unknown').slice(0, 300)}\n\nUse FOMCP \`diagnose\` tool for full analysis.`);
        logger.error({ server, event_count: recentCount.cnt, root_cause: rootCause }, '[agent] Incident declared');
      }
    }
  }
}

// ── Main agent loop ───────────────────────────────────────────────────────────
let agentInterval = null;

export function startGovernanceAgent() {
  // Poll every 2 minutes
  agentInterval = setInterval(async () => {
    try {
      const db  = getGovernanceDb();
      const now = Date.now();

      // Immediate: check for new criticals every tick (2 min)
      await checkNewCriticals(db);

      // Escalation: check every 10 minutes
      if (now - lastEscalationCheck > 10 * 60 * 1000) {
        await runEscalationPolicy(db);
        await checkIncidentCorrelation(db);
        lastEscalationCheck = now;
      }

      // Hourly digest: every 60 minutes
      if (now - lastHourlyDigest > 60 * 60 * 1000) {
        await sendHourlyDigest(db);
        lastHourlyDigest = now;
      }

      // Weekly: every Monday at 9am (check: day=1, hour=9, and not sent in last 24h)
      const d = new Date();
      if (d.getDay() === 1 && d.getHours() === 9 && now - lastWeeklyReport > 23 * 60 * 60 * 1000) {
        await sendWeeklyReport(db);
        lastWeeklyReport = now;
      }
    } catch (err) {
      logger.error({ error: err.message }, '[agent] Governance agent tick error');
    }
  }, 2 * 60 * 1000);

  logger.info('[agent] Governance agent started (2min polling)');
}

export function stopGovernanceAgent() {
  if (agentInterval) { clearInterval(agentInterval); agentInterval = null; }
  logger.info('[agent] Governance agent stopped');
}

// Export for use by diagnose tool
export { aiAnalyze, sendTelegram, checkNewCriticals };
```

- [ ] **Step 2: Write agent decision logic tests**

Create `/opt/mcp-server/test/governance-agent.test.js`:

```js
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA = readFileSync(join(__dirname, '../migrations/006_governance.sql'), 'utf8');

import { insertEvent, getUnacknowledgedCriticals, acknowledgeEvent } from '../lib/governance.js';

function makeDb() {
  const db = new Database(':memory:');
  db.exec(SCHEMA);
  return db;
}

describe('getUnacknowledgedCriticals', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('returns criticals older than N minutes that are unacknowledged', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'critical', alert_key: 'k1', message: 'm1', source: 'push' });
    // Backdate the event to 35 minutes ago
    db.prepare("UPDATE governance_events SET fired_at = datetime('now', '-35 minutes') WHERE id = ?").run(id);
    const results = getUnacknowledgedCriticals(db, 30);
    expect(results.length).toBe(1);
    expect(results[0].id).toBe(id);
  });

  it('does not return acknowledged events', () => {
    const id = insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'critical', alert_key: 'k2', message: 'm2', source: 'push' });
    db.prepare("UPDATE governance_events SET fired_at = datetime('now', '-35 minutes') WHERE id = ?").run(id);
    acknowledgeEvent(db, id);
    const results = getUnacknowledgedCriticals(db, 30);
    expect(results.length).toBe(0);
  });

  it('does not return events newer than threshold', () => {
    insertEvent(db, { server: 'vps-main', check_type: 'test', severity: 'critical', alert_key: 'k3', message: 'm3', source: 'push' });
    const results = getUnacknowledgedCriticals(db, 30);
    expect(results.length).toBe(0); // fired just now, not 30+ min old
  });
});
```

- [ ] **Step 3: Run tests**

```bash
cd /opt/mcp-server
npx vitest run test/governance-agent.test.js 2>&1 | tail -10
```

Expected: `3 tests | 3 passed`

- [ ] **Step 4: Commit**

```bash
cd /opt/mcp-server
git add lib/governance-agent.js test/governance-agent.test.js
git commit -m "feat(shield): governance-agent.js — scheduled AI agent with critical paging, escalation, hourly digest, weekly report"
```

---

## Task 3: Write `tools/governance-tools.js` (FOMCP `diagnose` Tool)

- [ ] **Step 1: Write the tool module**

```js
// tools/governance-tools.js — FoundationShield FOMCP diagnose tool
// Provides Claude with on-demand fleet health analysis using governance.db + AI.
import { z } from 'zod';
import { getGovernanceDb, listRecent, getFleetSummary, getShieldScore, getStatus } from '../lib/governance.js';
import { aiAnalyze } from '../lib/governance-agent.js';

export function registerGovernanceTools(server) {
  server.tool(
    'diagnose',
    'Analyze FoundationShield fleet security status. Returns AI-powered diagnosis of current alerts, Shield Scores, and recommended actions. Use action="status" for quick overview, "events" for recent alerts, "analyze" for AI root cause analysis, "acknowledge" to mark an event resolved.',
    {
      action:    z.enum(['status', 'events', 'analyze', 'acknowledge', 'resolve']).describe('What to do'),
      server:    z.string().optional().describe('Filter to specific server: vps-main, vps2, vps-vro'),
      severity:  z.string().optional().describe('Filter events by severity: critical, high, medium, info'),
      hours:     z.number().optional().describe('Lookback window in hours (default 24, max 168)'),
      event_id:  z.number().optional().describe('Event ID for acknowledge/resolve actions'),
      question:  z.string().optional().describe('Specific question to ask the AI analyst about fleet state')
    },
    async ({ action, server: srv, severity, hours = 24, event_id, question }) => {
      const db = getGovernanceDb();

      if (action === 'status') {
        const fleet = getFleetSummary(db);
        if (fleet.length === 0) {
          return { content: [{ type: 'text', text: '✅ No active events in governance.db in the last 24 hours. All clear.' }] };
        }
        const lines = fleet.map(s =>
          `**${s.server}** — Shield Score: ${s.score}/100 | critical: ${s.critical} | high: ${s.high} | medium: ${s.medium} | info: ${s.info}`
        );
        return { content: [{ type: 'text', text: `# FoundationShield Fleet Status\n\n${lines.join('\n')}` }] };
      }

      if (action === 'events') {
        const events = listRecent(db, {
          server: srv || null,
          severity: severity || null,
          hours: Math.min(hours, 168),
          limit: 50
        });
        if (events.length === 0) {
          return { content: [{ type: 'text', text: `No events found matching filters (server=${srv || 'all'}, severity=${severity || 'all'}, hours=${hours}).` }] };
        }
        const lines = events.map(e =>
          `[${e.id}] **${e.severity.toUpperCase()}** | ${e.server} | ${e.check_type} | ${e.fired_at.slice(0, 16)}\n> ${e.message.slice(0, 120)}${e.playbook ? `\n> Fix: ${e.playbook.slice(0, 80)}` : ''}`
        );
        return { content: [{ type: 'text', text: `# Governance Events (${events.length} results)\n\n${lines.join('\n\n')}` }] };
      }

      if (action === 'analyze') {
        const events = listRecent(db, { server: srv || null, hours: Math.min(hours, 48), limit: 30 });
        const fleet  = getFleetSummary(db);

        const eventSummary = events.slice(0, 20).map(e =>
          `[${e.severity}] ${e.server}/${e.check_type}: ${e.message.slice(0, 80)}`
        ).join('\n');

        const prompt = question
          ? `Fleet events (${hours}h):\n${eventSummary}\n\nFleet scores: ${fleet.map(s => `${s.server}:${s.score}`).join(', ')}\n\nQuestion: ${question}`
          : `Fleet events (${hours}h):\n${eventSummary}\n\nFleet scores: ${fleet.map(s => `${s.server}:${s.score}`).join(', ')}\n\nAnalyze: What are the top 3 most important findings? What is the root cause pattern? What should be done first?`;

        const analysis = await aiAnalyze(prompt, 'gpt-4.1-mini');
        const header = `# FoundationShield AI Analysis (${events.length} events, ${hours}h window)\n\n`;
        return { content: [{ type: 'text', text: header + (analysis || 'AI analysis unavailable — check OPENAI_API_KEY in .secrets') }] };
      }

      if (action === 'acknowledge') {
        if (!event_id) return { content: [{ type: 'text', text: 'Error: event_id is required for acknowledge action' }] };
        const event = db.prepare('SELECT id, check_type, server FROM governance_events WHERE id = ?').get(event_id);
        if (!event) return { content: [{ type: 'text', text: `Event ID ${event_id} not found` }] };
        const { acknowledgeEvent } = await import('../lib/governance.js');
        acknowledgeEvent(db, event_id);
        return { content: [{ type: 'text', text: `✅ Event ${event_id} acknowledged (${event.check_type} on ${event.server})` }] };
      }

      if (action === 'resolve') {
        if (!event_id) return { content: [{ type: 'text', text: 'Error: event_id is required for resolve action' }] };
        const event = db.prepare('SELECT id, check_type, server FROM governance_events WHERE id = ?').get(event_id);
        if (!event) return { content: [{ type: 'text', text: `Event ID ${event_id} not found` }] };
        const { resolveEvent } = await import('../lib/governance.js');
        resolveEvent(db, event_id);
        return { content: [{ type: 'text', text: `✅ Event ${event_id} resolved (${event.check_type} on ${event.server})` }] };
      }

      return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
    }
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd /opt/mcp-server
git add tools/governance-tools.js
git commit -m "feat(shield): diagnose FOMCP tool — on-demand fleet analysis with AI, ack/resolve actions"
```

---

## Task 4: Wire Agent + Tool into `server.js`

- [ ] **Step 1: Add imports to `server.js`**

Find the block of tool module imports and add:
```js
import { registerGovernanceTools } from './tools/governance-tools.js';
```

Find the intelligence loop imports and add alongside them:
```js
import { startGovernanceAgent, stopGovernanceAgent } from './lib/governance-agent.js';
```

- [ ] **Step 2: Register the tool in `getOrCreateServer()`**

Find the block where all tools are registered (around line 201) and add:
```js
registerGovernanceTools(server);
```

Place it after `registerIntelligenceTools(server);`.

- [ ] **Step 3: Start the agent in the startup section**

Find `startIntelligenceLoop();` (around line 522) and add below it:
```js
startGovernanceAgent();
```

- [ ] **Step 4: Stop the agent in `gracefulShutdown()`**

Find `stopIntelligenceLoop();` and add below it:
```js
stopGovernanceAgent();
```

- [ ] **Step 5: Restart FOMCP and verify agent starts**

```bash
sudo pm2 restart mcp-server
sleep 3
sudo pm2 logs mcp-server --lines 20 --nostream | grep -i 'agent\|shield\|governance'
```

Expected: `[agent] Governance agent started (2min polling)`

- [ ] **Step 6: Test the diagnose tool**

```bash
FOMCP_TOKEN=$(grep -E 'FOMCP_TOKEN|MCP_API_TOKEN' /opt/mcp-server/.secrets | head -1 | cut -d= -f2 | tr -d "'\"")

# Insert a test event first
curl -s -X POST http://127.0.0.1:4500/api/governance/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $FOMCP_TOKEN" \
  -d '{"server":"vps-main","check_type":"test_check","severity":"high","alert_key":"test_diagnose","message":"Test event for diagnose tool verification"}'

# Then query status via the governance API (diagnose tool is MCP-only, test via API)
curl -s "http://127.0.0.1:4500/api/governance/status?server=vps-main" \
  -H "Authorization: Bearer $FOMCP_TOKEN"
```

Expected: Status shows at least 1 high event for vps-main.

- [ ] **Step 7: Push FOMCP changes**

```bash
cd /opt/mcp-server
git add server.js
git commit -m "feat(shield): wire governance agent + diagnose tool into FOMCP server"
git push origin main
```

---

## Definition of Done

- [ ] `governance-agent.js` starts cleanly with FOMCP and logs `[agent] Governance agent started`
- [ ] `diagnose` tool appears in FOMCP MCP tool list
- [ ] `diagnose(action: "status")` returns fleet Shield Scores
- [ ] `diagnose(action: "events")` returns recent governance events
- [ ] `diagnose(action: "analyze")` calls OpenAI and returns AI analysis
- [ ] `diagnose(action: "acknowledge", event_id: N)` marks event acknowledged
- [ ] Governance agent fires Telegram alert when new critical event is inserted (verified by inserting test critical and waiting ≤2 min)
- [ ] Escalation: unacknowledged critical after 30+ min triggers re-alert Telegram
- [ ] All 15 governance.js tests still pass

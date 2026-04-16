# FoundationShield Plan 1A — Database & FOMCP Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire FoundationShield event data into the FOMCP SQLite database and establish the push/harvest pipeline that all future governance scripts will use to report findings.

**Architecture:** Governance scripts on each server POST critical events directly to FOMCP `/api/governance/events`. Routine events are written to a local append-only log at `/var/log/fo-sys/digest.log` and harvested hourly via SSH. All events land in a dedicated `governance.db` SQLite database on the FOMCP, separate from `audit.db`.

**Tech Stack:** Node 22 ESM, better-sqlite3, Express 5, Vitest — all existing FOMCP patterns. Foundation-shield scripts use CommonJS (matching existing governance scripts).

---

## File Map

**FOMCP changes (modify/create in `/opt/mcp-server/`):**
- Create: `migrations/006_governance.sql` — 7-table governance schema
- Create: `lib/governance.js` — DB helpers (insert event, list recent, score, patterns)
- Create: `routes/governance.js` — `POST /api/governance/events`, `GET /api/governance/status`
- Modify: `server.js` — import governance route, run migration, register route

**Foundation-shield scripts (create in `/opt/foundation-shield/scripts/`):**
- Create: `alerting.js` — drop-in replacement for ops-docs alerting; pushes critical events to FOMCP + writes local log
- Create: `harvest.js` — hourly cron script; SSHes to VPS2 + VPS VRO, pulls local logs, bulk-POSTs to FOMCP

**Tests:**
- Create: `test/governance.test.js` in FOMCP (Vitest, in-memory SQLite)

---

## Task 1: Create Governance DB Migration

**Files:**
- Create: `/opt/mcp-server/migrations/006_governance.sql`

- [ ] **Step 1: Write the migration file**

```sql
-- 006_governance.sql
-- FoundationShield: governance event storage, snapshots, scoring, patterns, incidents, threat intel

CREATE TABLE IF NOT EXISTS governance_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  server          TEXT NOT NULL,
  check_type      TEXT NOT NULL,
  severity        TEXT NOT NULL,
  alert_key       TEXT NOT NULL,
  message         TEXT NOT NULL,
  raw_data        TEXT,
  playbook        TEXT,
  source          TEXT DEFAULT 'push',
  fired_at        TEXT DEFAULT (datetime('now')),
  acknowledged_at TEXT,
  resolved_at     TEXT,
  acknowledged    INTEGER DEFAULT 0,
  snoozed_until   TEXT,
  snooze_count    INTEGER DEFAULT 0,
  escalated       INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS governance_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server       TEXT NOT NULL,
  run_at       TEXT DEFAULT (datetime('now')),
  check_type   TEXT NOT NULL,
  status       TEXT NOT NULL,
  detail       TEXT,
  shield_score INTEGER
);

CREATE TABLE IF NOT EXISTS governance_health (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  server      TEXT NOT NULL,
  score       INTEGER NOT NULL,
  recorded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS governance_baselines (
  server     TEXT NOT NULL,
  metric     TEXT NOT NULL,
  avg        REAL,
  stddev     REAL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (server, metric)
);

CREATE TABLE IF NOT EXISTS governance_patterns (
  alert_key        TEXT PRIMARY KEY,
  fire_count       INTEGER DEFAULT 0,
  snooze_count     INTEGER DEFAULT 0,
  first_seen       TEXT,
  last_seen        TEXT,
  avg_resolve_mins REAL,
  pattern_flagged  INTEGER DEFAULT 0,
  fp_candidate     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS governance_incidents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  server       TEXT NOT NULL,
  declared_at  TEXT DEFAULT (datetime('now')),
  resolved_at  TEXT,
  event_ids    TEXT,
  root_cause   TEXT,
  postmortem   TEXT,
  mttr_mins    REAL
);

CREATE TABLE IF NOT EXISTS threat_intel_ips (
  ip         TEXT PRIMARY KEY,
  source     TEXT,
  category   TEXT,
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

- [ ] **Step 2: Verify it is valid SQL by running it against a temp DB**

```bash
cd /opt/mcp-server
sqlite3 /tmp/gov_test.db < migrations/006_governance.sql
sqlite3 /tmp/gov_test.db ".tables"
```

Expected output (order may vary):
```
governance_baselines   governance_events      governance_health
governance_incidents   governance_patterns    governance_snapshots
threat_intel_ips
```

- [ ] **Step 3: Clean up temp DB**

```bash
rm /tmp/gov_test.db
```

- [ ] **Step 4: Commit**

```bash
cd /opt/mcp-server
git add migrations/006_governance.sql
git commit -m "feat(shield): add governance.db migration (006) with 7-table schema"
```

---

## Task 2: Write `lib/governance.js` DB Helpers

**Files:**
- Create: `/opt/mcp-server/lib/governance.js`
- Create: `/opt/mcp-server/test/governance.test.js`

- [ ] **Step 1: Write the failing tests first**

Create `/opt/mcp-server/test/governance.test.js`:

```js
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA = readFileSync(join(__dirname, '../migrations/006_governance.sql'), 'utf8');

// In-memory DB per test
function makeDb() {
  const db = new Database(':memory:');
  db.exec(SCHEMA);
  return db;
}

// We test the governance module by injecting the db — governance.js must accept db as param
import { insertEvent, listRecent, getStatus, upsertPattern } from '../lib/governance.js';

describe('insertEvent', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('inserts a valid event and returns its id', () => {
    const id = insertEvent(db, {
      server: 'vps-main',
      check_type: 'disk_usage',
      severity: 'critical',
      alert_key: 'disk_/var_vps-main',
      message: 'Disk /var at 92%',
      source: 'push'
    });
    expect(typeof id).toBe('number');
    expect(id).toBeGreaterThan(0);
  });

  it('stores raw_data as JSON string', () => {
    const id = insertEvent(db, {
      server: 'vps-main',
      check_type: 'disk_usage',
      severity: 'critical',
      alert_key: 'disk_test',
      message: 'test',
      raw_data: { pct: 92, mount: '/var' },
      source: 'harvest'
    });
    const row = db.prepare('SELECT raw_data FROM governance_events WHERE id = ?').get(id);
    expect(JSON.parse(row.raw_data)).toEqual({ pct: 92, mount: '/var' });
  });

  it('rejects missing required fields', () => {
    expect(() => insertEvent(db, { server: 'vps-main' })).toThrow();
  });
});

describe('listRecent', () => {
  let db;
  beforeEach(() => {
    db = makeDb();
    insertEvent(db, { server: 'vps-main', check_type: 'disk_usage', severity: 'critical', alert_key: 'k1', message: 'm1', source: 'push' });
    insertEvent(db, { server: 'vps2',     check_type: 'pm2_dead',   severity: 'high',     alert_key: 'k2', message: 'm2', source: 'harvest' });
  });
  afterEach(() => { db.close(); });

  it('returns all events when no filter', () => {
    const rows = listRecent(db, {});
    expect(rows.length).toBe(2);
  });

  it('filters by server', () => {
    const rows = listRecent(db, { server: 'vps2' });
    expect(rows.length).toBe(1);
    expect(rows[0].server).toBe('vps2');
  });

  it('filters by severity', () => {
    const rows = listRecent(db, { severity: 'critical' });
    expect(rows.length).toBe(1);
    expect(rows[0].severity).toBe('critical');
  });

  it('respects limit', () => {
    const rows = listRecent(db, { limit: 1 });
    expect(rows.length).toBe(1);
  });
});

describe('getStatus', () => {
  let db;
  beforeEach(() => {
    db = makeDb();
    insertEvent(db, { server: 'vps-main', check_type: 'disk', severity: 'critical', alert_key: 'k1', message: 'm1', source: 'push' });
    insertEvent(db, { server: 'vps-main', check_type: 'ram',  severity: 'high',     alert_key: 'k2', message: 'm2', source: 'push' });
  });
  afterEach(() => { db.close(); });

  it('returns counts per severity', () => {
    const status = getStatus(db, 'vps-main');
    expect(status.critical).toBe(1);
    expect(status.high).toBe(1);
    expect(status.total).toBe(2);
  });

  it('returns zero counts for unknown server', () => {
    const status = getStatus(db, 'unknown-server');
    expect(status.total).toBe(0);
  });
});

describe('upsertPattern', () => {
  let db;
  beforeEach(() => { db = makeDb(); });
  afterEach(() => { db.close(); });

  it('creates a new pattern record on first call', () => {
    upsertPattern(db, 'disk_/var_vps-main');
    const row = db.prepare('SELECT * FROM governance_patterns WHERE alert_key = ?').get('disk_/var_vps-main');
    expect(row.fire_count).toBe(1);
    expect(row.fp_candidate).toBe(0);
  });

  it('increments fire_count on subsequent calls', () => {
    upsertPattern(db, 'disk_/var_vps-main');
    upsertPattern(db, 'disk_/var_vps-main');
    const row = db.prepare('SELECT fire_count FROM governance_patterns WHERE alert_key = ?').get('disk_/var_vps-main');
    expect(row.fire_count).toBe(2);
  });

  it('sets fp_candidate when snooze_count reaches 3', () => {
    upsertPattern(db, 'noisy_key', { snooze: true });
    upsertPattern(db, 'noisy_key', { snooze: true });
    upsertPattern(db, 'noisy_key', { snooze: true });
    const row = db.prepare('SELECT fp_candidate, snooze_count FROM governance_patterns WHERE alert_key = ?').get('noisy_key');
    expect(row.snooze_count).toBe(3);
    expect(row.fp_candidate).toBe(1);
  });
});
```

- [ ] **Step 2: Run tests — confirm they all fail**

```bash
cd /opt/mcp-server
npx vitest run test/governance.test.js 2>&1 | tail -20
```

Expected: All 9 tests fail with `Cannot find module '../lib/governance.js'`

- [ ] **Step 3: Write `lib/governance.js`**

```js
// lib/governance.js — FoundationShield database helpers
// All functions take an injected `db` (better-sqlite3 instance) so tests can use in-memory DB.
// Production callers get the singleton via getGovernanceDb().

import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOV_DB_PATH = process.env.GOV_DB_PATH || '/opt/mcp-server/data/governance.db';

let _db = null;

export function getGovernanceDb() {
  if (!_db) {
    _db = new Database(GOV_DB_PATH);
    _db.pragma('journal_mode = WAL');
    _db.pragma('foreign_keys = ON');
    const schema = readFileSync(join(__dirname, '../migrations/006_governance.sql'), 'utf8');
    _db.exec(schema);
  }
  return _db;
}

export function closeGovernanceDb() {
  if (_db) { _db.close(); _db = null; }
}

/**
 * Insert a governance event. raw_data object is JSON-stringified automatically.
 * Returns the new row id.
 */
export function insertEvent(db, event) {
  const required = ['server', 'check_type', 'severity', 'alert_key', 'message'];
  for (const field of required) {
    if (!event[field]) throw new Error(`insertEvent: missing required field '${field}'`);
  }
  const stmt = db.prepare(`
    INSERT INTO governance_events
      (server, check_type, severity, alert_key, message, raw_data, playbook, source)
    VALUES
      (@server, @check_type, @severity, @alert_key, @message, @raw_data, @playbook, @source)
  `);
  const result = stmt.run({
    server:     event.server,
    check_type: event.check_type,
    severity:   event.severity,
    alert_key:  event.alert_key,
    message:    event.message,
    raw_data:   event.raw_data ? JSON.stringify(event.raw_data) : null,
    playbook:   event.playbook || null,
    source:     event.source || 'push'
  });
  upsertPattern(db, event.alert_key);
  return result.lastInsertRowid;
}

/**
 * List recent governance events with optional filters.
 * Options: { server, severity, check_type, unresolved, limit, hours }
 */
export function listRecent(db, opts = {}) {
  const { server, severity, check_type, unresolved, limit = 100, hours = 24 } = opts;
  const conditions = [`fired_at >= datetime('now', '-${parseInt(hours)} hours')`];
  const params = {};

  if (server)     { conditions.push('server = @server');         params.server = server; }
  if (severity)   { conditions.push('severity = @severity');     params.severity = severity; }
  if (check_type) { conditions.push('check_type = @check_type'); params.check_type = check_type; }
  if (unresolved) { conditions.push('resolved_at IS NULL'); }

  const where = conditions.join(' AND ');
  const stmt = db.prepare(
    `SELECT * FROM governance_events WHERE ${where} ORDER BY fired_at DESC LIMIT ${parseInt(limit)}`
  );
  return stmt.all(params);
}

/**
 * Get unresolved event counts per severity for a server (last 24h).
 * Returns { critical, high, medium, info, total }.
 */
export function getStatus(db, server) {
  const rows = db.prepare(`
    SELECT severity, COUNT(*) AS cnt
    FROM governance_events
    WHERE server = ? AND resolved_at IS NULL AND fired_at >= datetime('now', '-24 hours')
    GROUP BY severity
  `).all(server);

  const out = { critical: 0, high: 0, medium: 0, info: 0, total: 0 };
  for (const row of rows) {
    if (out[row.severity] !== undefined) out[row.severity] = row.cnt;
    out.total += row.cnt;
  }
  return out;
}

/**
 * Get Shield Score (0-100) for a server.
 * Formula: start at 100, subtract: critical*15, high*7, medium*3, info*1. Floor 0.
 */
export function getShieldScore(db, server) {
  const status = getStatus(db, server);
  const score = Math.max(0, 100 - status.critical * 15 - status.high * 7 - status.medium * 3 - status.info * 1);
  return score;
}

/**
 * Record Shield Score snapshot.
 */
export function recordShieldScore(db, server, score) {
  db.prepare('INSERT INTO governance_health (server, score) VALUES (?, ?)').run(server, score);
}

/**
 * Upsert pattern tracking for an alert_key. Pass { snooze: true } when user snoozes.
 * Auto-sets fp_candidate when snooze_count >= 3.
 */
export function upsertPattern(db, alertKey, opts = {}) {
  const now = new Date().toISOString();
  const existing = db.prepare('SELECT * FROM governance_patterns WHERE alert_key = ?').get(alertKey);

  if (!existing) {
    db.prepare(`
      INSERT INTO governance_patterns (alert_key, fire_count, snooze_count, first_seen, last_seen)
      VALUES (?, 1, 0, ?, ?)
    `).run(alertKey, now, now);
  } else {
    const newSnooze = existing.snooze_count + (opts.snooze ? 1 : 0);
    db.prepare(`
      UPDATE governance_patterns
      SET fire_count = fire_count + 1,
          snooze_count = ?,
          last_seen = ?,
          fp_candidate = CASE WHEN ? >= 3 THEN 1 ELSE fp_candidate END
      WHERE alert_key = ?
    `).run(newSnooze, now, newSnooze, alertKey);
  }
}

/**
 * Bulk insert events (for harvest batches). Returns count inserted.
 */
export function bulkInsertEvents(db, events) {
  const insertMany = db.transaction((evs) => {
    let count = 0;
    for (const ev of evs) {
      try { insertEvent(db, ev); count++; } catch (_) {}
    }
    return count;
  });
  return insertMany(events);
}

/**
 * Get fleet-wide summary: per-server status + scores.
 */
export function getFleetSummary(db) {
  const servers = db.prepare(
    `SELECT DISTINCT server FROM governance_events WHERE fired_at >= datetime('now', '-24 hours')`
  ).all().map(r => r.server);

  return servers.map(server => ({
    server,
    ...getStatus(db, server),
    score: getShieldScore(db, server)
  }));
}
```

- [ ] **Step 4: Run tests — confirm they all pass**

```bash
cd /opt/mcp-server
npx vitest run test/governance.test.js 2>&1 | tail -20
```

Expected: `9 tests | 9 passed`

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp-server
git add lib/governance.js test/governance.test.js
git commit -m "feat(shield): add governance.js DB helpers with full Vitest coverage"
```

---

## Task 3: Write `routes/governance.js` HTTP API

**Files:**
- Create: `/opt/mcp-server/routes/governance.js`

- [ ] **Step 1: Write the route module**

```js
// routes/governance.js — FoundationShield HTTP API endpoints
// POST /api/governance/events  — ingest push event from any server's alerting.js
// GET  /api/governance/status  — fleet-wide status summary
// GET  /api/governance/events  — query recent events with filters

import { getGovernanceDb, insertEvent, listRecent, getFleetSummary, getShieldScore, getStatus } from '../lib/governance.js';

export function registerGovernanceRoutes(app) {
  // POST /api/governance/events
  // Body: { server, check_type, severity, alert_key, message, raw_data?, playbook?, source? }
  app.post('/api/governance/events', (req, res) => {
    const { server, check_type, severity, alert_key, message, raw_data, playbook, source } = req.body;
    const required = { server, check_type, severity, alert_key, message };
    const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
    if (missing.length) {
      return res.status(400).json({ error: `Missing required fields: ${missing.join(', ')}` });
    }
    const validSeverities = ['critical', 'high', 'medium', 'info'];
    if (!validSeverities.includes(severity)) {
      return res.status(400).json({ error: `Invalid severity '${severity}'. Must be one of: ${validSeverities.join(', ')}` });
    }
    try {
      const db = getGovernanceDb();
      const id = insertEvent(db, { server, check_type, severity, alert_key, message, raw_data, playbook, source: source || 'push' });
      res.json({ ok: true, id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/governance/events/bulk — harvest batch endpoint
  // Body: { events: [...] }
  app.post('/api/governance/events/bulk', (req, res) => {
    const { events } = req.body;
    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'events must be a non-empty array' });
    }
    if (events.length > 1000) {
      return res.status(400).json({ error: 'Batch too large — max 1000 events per request' });
    }
    try {
      const db = getGovernanceDb();
      const { bulkInsertEvents } = require('../lib/governance.js'); // same module
      let count = 0;
      const insertTx = db.transaction(() => {
        for (const ev of events) {
          try { insertEvent(db, { ...ev, source: ev.source || 'harvest' }); count++; } catch (_) {}
        }
      });
      insertTx();
      res.json({ ok: true, inserted: count, total: events.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/governance/status
  // Query: ?server=vps-main
  app.get('/api/governance/status', (req, res) => {
    try {
      const db = getGovernanceDb();
      const { server } = req.query;
      if (server) {
        const status = getStatus(db, server);
        const score = getShieldScore(db, server);
        return res.json({ server, ...status, score });
      }
      const fleet = getFleetSummary(db);
      res.json({ fleet });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/governance/events
  // Query: ?server=vps-main&severity=critical&limit=50&hours=24&unresolved=true
  app.get('/api/governance/events', (req, res) => {
    try {
      const db = getGovernanceDb();
      const opts = {
        server:     req.query.server     || null,
        severity:   req.query.severity   || null,
        check_type: req.query.check_type || null,
        unresolved: req.query.unresolved === 'true',
        limit:      Math.min(parseInt(req.query.limit  || '100'), 500),
        hours:      Math.min(parseInt(req.query.hours  || '24'),  168)
      };
      const events = listRecent(db, opts);
      res.json({ events, count: events.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}
```

- [ ] **Step 2: Fix the bulk route — it uses a CommonJS require() inside ESM. Replace the bulk handler body:**

The bulk route body uses `require()` which doesn't work in ESM. Replace only the `insertTx` setup:

```js
  app.post('/api/governance/events/bulk', (req, res) => {
    const { events } = req.body;
    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'events must be a non-empty array' });
    }
    if (events.length > 1000) {
      return res.status(400).json({ error: 'Batch too large — max 1000 events per request' });
    }
    try {
      const db = getGovernanceDb();
      let count = 0;
      const insertTx = db.transaction(() => {
        for (const ev of events) {
          try { insertEvent(db, { ...ev, source: ev.source || 'harvest' }); count++; } catch (_) {}
        }
      });
      insertTx();
      res.json({ ok: true, inserted: count, total: events.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
```

Write the complete `routes/governance.js` with the corrected bulk handler — no `require()`:

```js
// routes/governance.js — FoundationShield HTTP API endpoints
import { getGovernanceDb, insertEvent, listRecent, getFleetSummary, getShieldScore, getStatus } from '../lib/governance.js';

export function registerGovernanceRoutes(app) {
  app.post('/api/governance/events', (req, res) => {
    const { server, check_type, severity, alert_key, message, raw_data, playbook, source } = req.body;
    const required = { server, check_type, severity, alert_key, message };
    const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
    if (missing.length) return res.status(400).json({ error: `Missing: ${missing.join(', ')}` });
    const valid = ['critical', 'high', 'medium', 'info'];
    if (!valid.includes(severity)) return res.status(400).json({ error: `Invalid severity '${severity}'` });
    try {
      const id = insertEvent(getGovernanceDb(), { server, check_type, severity, alert_key, message, raw_data, playbook, source: source || 'push' });
      res.json({ ok: true, id });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/governance/events/bulk', (req, res) => {
    const { events } = req.body;
    if (!Array.isArray(events) || !events.length) return res.status(400).json({ error: 'events must be a non-empty array' });
    if (events.length > 1000) return res.status(400).json({ error: 'Batch too large — max 1000' });
    try {
      const db = getGovernanceDb();
      let count = 0;
      const tx = db.transaction(() => {
        for (const ev of events) {
          try { insertEvent(db, { ...ev, source: ev.source || 'harvest' }); count++; } catch (_) {}
        }
      });
      tx();
      res.json({ ok: true, inserted: count, total: events.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/api/governance/status', (req, res) => {
    try {
      const db = getGovernanceDb();
      if (req.query.server) {
        const status = getStatus(db, req.query.server);
        return res.json({ server: req.query.server, ...status, score: getShieldScore(db, req.query.server) });
      }
      res.json({ fleet: getFleetSummary(db) });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/api/governance/events', (req, res) => {
    try {
      const db = getGovernanceDb();
      const opts = {
        server:     req.query.server     || null,
        severity:   req.query.severity   || null,
        check_type: req.query.check_type || null,
        unresolved: req.query.unresolved === 'true',
        limit:      Math.min(parseInt(req.query.limit || '100'), 500),
        hours:      Math.min(parseInt(req.query.hours || '24'),  168)
      };
      const events = listRecent(db, opts);
      res.json({ events, count: events.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
}
```

- [ ] **Step 3: Commit**

```bash
cd /opt/mcp-server
git add routes/governance.js
git commit -m "feat(shield): add governance API routes (POST events, GET status/events)"
```

---

## Task 4: Wire Routes into `server.js`

**Files:**
- Modify: `/opt/mcp-server/server.js`

- [ ] **Step 1: Add the import — insert after the last route import (line ~66)**

Find this line in `server.js`:
```js
import { createChatRouter } from './lib/claude-proxy/chat-bot.js';
```

Add immediately after it:
```js
import { registerGovernanceRoutes } from './routes/governance.js';
```

- [ ] **Step 2: Register the routes — insert after `registerArchHealthRoutes(app)`**

Find this block (around line 351-353):
```js
registerHealthRoutes(app);
registerClusterRoutes(app);
registerArchHealthRoutes(app);
```

Add the governance route registration:
```js
registerHealthRoutes(app);
registerClusterRoutes(app);
registerArchHealthRoutes(app);
registerGovernanceRoutes(app);
```

- [ ] **Step 3: Verify the FOMCP starts without errors**

```bash
cd /opt/mcp-server
node --input-type=module <<'EOF'
import './server.js';
EOF
```

Wait 3 seconds, then check:

```bash
curl -s http://127.0.0.1:4500/healthz
```

Expected: `{"status":"ok"}`

- [ ] **Step 4: Smoke test the governance endpoint with a real curl**

Get the FOMCP API token first:
```bash
FOMCP_TOKEN=$(grep FOMCP_TOKEN /opt/mcp-server/.secrets 2>/dev/null || grep MCP_API_TOKEN /opt/mcp-server/.secrets | head -1 | cut -d= -f2)
curl -s -X POST http://127.0.0.1:4500/api/governance/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $FOMCP_TOKEN" \
  -d '{"server":"vps-main","check_type":"test","severity":"info","alert_key":"test_smoke","message":"smoke test"}'
```

Expected: `{"ok":true,"id":1}`

Then verify it was stored:
```bash
curl -s "http://127.0.0.1:4500/api/governance/status?server=vps-main" \
  -H "Authorization: Bearer $FOMCP_TOKEN"
```

Expected: JSON with `total: 1`, `info: 1`

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp-server
git add server.js
git commit -m "feat(shield): wire governance routes into FOMCP server"
```

---

## Task 5: Write Foundation-Shield `alerting.js`

This is a new version of the alerting module for use by foundation-shield governance scripts. It replaces the ops-docs version with the ability to push critical events to FOMCP.

**Files:**
- Create: `/opt/foundation-shield/scripts/alerting.js`

- [ ] **Step 1: Read the FOMCP API token from vault**

The token lives in `/etc/fo-sys/.vault` (future) or for now in `/opt/mcp-server/.secrets`. Check which key name it uses:

```bash
grep -i 'token\|key\|secret' /opt/mcp-server/.secrets | head -5
```

Note the exact key name for use in Step 2.

- [ ] **Step 2: Write `alerting.js`**

```js
// /opt/foundation-shield/scripts/alerting.js
// Drop-in replacement for ops-docs alerting.js with FOMCP push + local log fallback.
// Critical/high events push immediately to FOMCP. All events go to local append-only log.
'use strict';
const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const VAULT_PATH    = process.env.FO_VAULT_PATH || '/etc/fo-sys/.vault';
const LOG_DIR       = '/var/log/fo-sys';
const DIGEST_LOG    = path.join(LOG_DIR, 'digest.log');
const COOLDOWN_DIR  = '/tmp/fo-sys-cooldowns';
const COOLDOWN_SECS = 1800; // 30 minutes per alert key
const FOMCP_URL     = process.env.FOMCP_URL || 'http://127.0.0.1:4500';

// Server identity — set via env or fallback detection
const SERVER_NAME = process.env.FO_SERVER_NAME || (() => {
  try { return require('child_process').execSync('hostname', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
})();

// ── Vault / Credentials ───────────────────────────────────────────────────────
function loadVault() {
  // For Phase 1, load from FOMCP .secrets. Phase 2B will add encryption.
  const secretsPath = process.env.SECRETS_PATH || '/opt/mcp-server/.secrets';
  const vault = {};
  try {
    const lines = fs.readFileSync(secretsPath, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m) vault[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch (_) {}
  return vault;
}

const _vault = loadVault();
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN || _vault.TELEGRAM_BOT_TOKEN || _vault.FOUNDATION_SHIELD_BOT_TOKEN;
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID   || _vault.TELEGRAM_CHAT_ID   || _vault.FOUNDATION_SHIELD_CHAT_ID;
const FOMCP_TOKEN    = process.env.FOMCP_TOKEN         || _vault.FOMCP_TOKEN        || _vault.MCP_API_TOKEN;

const DRY_RUN = process.argv.includes('--dry-run');

// ── Directory Setup ───────────────────────────────────────────────────────────
try { fs.mkdirSync(LOG_DIR,      { recursive: true }); } catch (_) {}
try { fs.mkdirSync(COOLDOWN_DIR, { recursive: true }); } catch (_) {}

// ── Cooldown ──────────────────────────────────────────────────────────────────
function cooldownFile(key) {
  return path.join(COOLDOWN_DIR, key.replace(/[^a-z0-9_]/gi, '_').slice(0, 64));
}

function inCooldown(key) {
  try {
    if (!fs.existsSync(cooldownFile(key))) return false;
    const last = parseInt(fs.readFileSync(cooldownFile(key), 'utf8').trim(), 10);
    return !isNaN(last) && (Math.floor(Date.now() / 1000) - last) < COOLDOWN_SECS;
  } catch { return false; }
}

function setCooldown(key) {
  try { fs.writeFileSync(cooldownFile(key), String(Math.floor(Date.now() / 1000))); } catch (_) {}
}

// ── Local Digest Log ──────────────────────────────────────────────────────────
function appendDigest(level, key, message, extra = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    key,
    server: SERVER_NAME,
    msg: message,
    ...extra
  }) + '\n';
  try { fs.appendFileSync(DIGEST_LOG, line); } catch (_) {}
}

// ── FOMCP Push ────────────────────────────────────────────────────────────────
function pushToFomcp(event) {
  return new Promise((resolve) => {
    if (!FOMCP_TOKEN) return resolve(false);
    const body = JSON.stringify(event);
    const options = {
      hostname: '127.0.0.1',
      port: 4500,
      path: '/api/governance/events',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${FOMCP_TOKEN}`
      }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(res.statusCode === 200));
    });
    req.setTimeout(5000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

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
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode === 200));
    });
    req.setTimeout(10000, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Fire an alert.
 * @param {string} key         - Dedup key (e.g. 'disk_/var_vps-main')
 * @param {string} message     - Human-readable alert message (Telegram Markdown OK)
 * @param {object} opts        - { check_type, severity, raw_data, playbook }
 */
async function alert(key, message, opts = {}) {
  const severity   = opts.severity   || deriveSeverity(key);
  const check_type = opts.check_type || key.split('_')[0];

  appendDigest('ALERT', key, message, { severity, check_type });

  if (DRY_RUN) {
    console.log(`[DRY-RUN] ALERT [${severity}] ${key}:\n${message}\n`);
    return;
  }

  // Push to FOMCP (all severities — non-blocking, fire-and-forget)
  pushToFomcp({
    server:     SERVER_NAME,
    check_type,
    severity,
    alert_key:  key,
    message,
    raw_data:   opts.raw_data   || null,
    playbook:   opts.playbook   || null,
    source:     'push'
  }).catch(() => {}); // never throw — alerting must not crash governance scripts

  // Telegram: critical + high get immediate Telegram; others are harvest-only
  if (['critical', 'high'].includes(severity) && !inCooldown(key)) {
    await sendTelegram(`🚨 *FoundationShield Alert*\n*Server:* ${SERVER_NAME}\n\n${message}`);
    setCooldown(key);
  }
}

/** deriveSeverity: best-effort severity from key prefix if not specified */
function deriveSeverity(key) {
  if (/^(collision|squatter|pm2_dead|disk_crit|oom|canary|honey|suid|ssh_key|masquerade|crypto)/.test(key)) return 'critical';
  if (/^(disk_warn|repo_behind|ssl|fail2ban|docker|restart_storm|fd_exhaust|fs_integrity|threat_intel)/.test(key)) return 'high';
  if (/^(repo_ahead|repo_dirty|pm2_mem|pg_pool|slow_query)/.test(key)) return 'medium';
  return 'info';
}

/** Log an informational event (no Telegram). Always goes to digest + FOMCP. */
async function info(message, opts = {}) {
  appendDigest('INFO', opts.key || 'info', message, opts);
  if (!DRY_RUN && opts.key) {
    pushToFomcp({
      server:     SERVER_NAME,
      check_type: opts.check_type || 'info',
      severity:   'info',
      alert_key:  opts.key,
      message,
      source:     'push'
    }).catch(() => {});
  }
}

module.exports = { alert, info };
```

- [ ] **Step 3: Verify it loads cleanly (no syntax errors)**

```bash
node -e "const a = require('/opt/foundation-shield/scripts/alerting.js'); console.log('OK', Object.keys(a));"
```

Expected: `OK [ 'alert', 'info' ]`

- [ ] **Step 4: Verify dry-run works**

```bash
FO_SERVER_NAME=test-server node --require /opt/foundation-shield/scripts/alerting.js \
  -e "const {alert}=require('/opt/foundation-shield/scripts/alerting.js'); alert('test_key','Test alert',{severity:'critical'});" -- --dry-run
```

Expected: `[DRY-RUN] ALERT [critical] test_key:`

- [ ] **Step 5: Commit to foundation-shield repo**

```bash
cd /opt/foundation-shield
git add scripts/alerting.js
git commit -m "feat(shield): add alerting.js with FOMCP push + Telegram + local digest log"
```

---

## Task 6: Write `harvest.js` Fleet Log Harvester

This script runs hourly on VPS Main, SSHes to VPS2 and VPS VRO, reads their local digest logs since the last harvest, and bulk-POSTs them to FOMCP.

**Files:**
- Create: `/opt/foundation-shield/scripts/harvest.js`

- [ ] **Step 1: Write `harvest.js`**

```js
// /opt/foundation-shield/scripts/harvest.js
// Hourly harvester: pull governance events from VPS2 + VPS VRO local logs, POST to FOMCP.
// Runs on VPS Main only (has SSH access to fleet).
'use strict';
const { execSync } = require('child_process');
const https = require('https');
const http  = require('http');
const fs    = require('fs');

const REMOTE_LOG   = '/var/log/fo-sys/digest.log';
const STATE_FILE   = '/var/log/fo-sys/harvest-state.json';
const FOMCP_URL    = 'http://127.0.0.1:4500';
const SERVERS      = [
  { alias: 'vps2',   name: 'vps2'    },
  { alias: 'vpsvro', name: 'vps-vro' }
];

// Load FOMCP token from .secrets
function loadToken() {
  try {
    const lines = fs.readFileSync('/opt/mcp-server/.secrets', 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^(FOMCP_TOKEN|MCP_API_TOKEN)=(.*)$/);
      if (m) return m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch (_) {}
  return null;
}

// Load harvest state (tracks byte offset per server to avoid re-importing)
function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return {}; }
}

function saveState(state) {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2)); } catch (_) {}
}

// SSH pull lines from remote log since last offset
function pullRemoteLog(server, offset) {
  try {
    const cmd = `ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${server.alias} ` +
                `"tail -c +${offset + 1} ${REMOTE_LOG} 2>/dev/null"`;
    const out = execSync(cmd, { timeout: 30000, encoding: 'utf8' });
    return out;
  } catch { return ''; }
}

// Get remote file size for next offset
function getRemoteSize(server) {
  try {
    const out = execSync(
      `ssh -o ConnectTimeout=10 ${server.alias} "stat -c %s ${REMOTE_LOG} 2>/dev/null || echo 0"`,
      { timeout: 10000, encoding: 'utf8' }
    );
    return parseInt(out.trim()) || 0;
  } catch { return 0; }
}

// Parse NDJSON lines into event objects
function parseEvents(rawText, serverName) {
  const events = [];
  for (const line of rawText.split('\n')) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line);
      if (obj.level === 'ALERT') {
        events.push({
          server:     serverName,
          check_type: obj.check_type || obj.key?.split('_')[0] || 'unknown',
          severity:   obj.severity   || 'info',
          alert_key:  obj.key        || 'unknown',
          message:    obj.msg        || '',
          source:     'harvest',
          fired_at:   obj.ts         || new Date().toISOString()
        });
      }
    } catch (_) {}
  }
  return events;
}

// POST bulk events to FOMCP
function postBulk(events, token) {
  return new Promise((resolve) => {
    if (!token || !events.length) return resolve(0);
    const body = JSON.stringify({ events });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 4500,
      path: '/api/governance/events/bulk',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${token}`
      }
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data).inserted || 0); } catch { resolve(0); }
      });
    });
    req.setTimeout(15000, () => { req.destroy(); resolve(0); });
    req.on('error', () => resolve(0));
    req.write(body);
    req.end();
  });
}

async function main() {
  const token = loadToken();
  if (!token) {
    console.error('[harvest] No FOMCP token found in .secrets');
    process.exit(1);
  }

  const state = loadState();
  let totalImported = 0;

  for (const server of SERVERS) {
    const offset = state[server.name] || 0;
    const newSize = getRemoteSize(server);

    if (newSize <= offset) {
      console.log(`[harvest] ${server.name}: no new data (size=${newSize}, offset=${offset})`);
      continue;
    }

    const raw = pullRemoteLog(server, offset);
    if (!raw.trim()) {
      state[server.name] = newSize;
      continue;
    }

    const events = parseEvents(raw, server.name);
    if (events.length) {
      const imported = await postBulk(events, token);
      totalImported += imported;
      console.log(`[harvest] ${server.name}: ${imported}/${events.length} events imported`);
    }

    state[server.name] = newSize;
  }

  saveState(state);
  console.log(`[harvest] Done. Total imported: ${totalImported}`);
}

main().catch(err => {
  console.error('[harvest] Fatal:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Verify it loads cleanly**

```bash
node -e "require('/opt/foundation-shield/scripts/harvest.js')" 2>&1 | head -5
```

Expected: Script starts (will fail with "No FOMCP token" if .secrets not set, which is fine)

- [ ] **Step 3: Commit**

```bash
cd /opt/foundation-shield
git add scripts/harvest.js
git commit -m "feat(shield): add harvest.js fleet log harvester for VPS2 + VPS VRO"
```

---

## Task 7: End-to-End Integration Test

- [ ] **Step 1: Ensure governance.db exists after FOMCP restart**

```bash
sudo pm2 restart mcp-server
sleep 3
ls -la /opt/mcp-server/data/governance.db
```

Expected: file exists, nonzero size

- [ ] **Step 2: Send a test push event and confirm it appears in the DB**

```bash
FOMCP_TOKEN=$(grep -E 'FOMCP_TOKEN|MCP_API_TOKEN' /opt/mcp-server/.secrets | head -1 | cut -d= -f2 | tr -d "'\"")
curl -s -X POST http://127.0.0.1:4500/api/governance/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $FOMCP_TOKEN" \
  -d '{"server":"vps-main","check_type":"integration_test","severity":"info","alert_key":"e2e_test_1","message":"End-to-end pipeline test"}'
```

Expected: `{"ok":true,"id":1}` (or higher id if smoke test from Task 4 ran)

- [ ] **Step 3: Confirm via status endpoint**

```bash
curl -s "http://127.0.0.1:4500/api/governance/status?server=vps-main" \
  -H "Authorization: Bearer $FOMCP_TOKEN"
```

Expected: JSON with `info` count >= 1

- [ ] **Step 4: Confirm via SQLite directly**

```bash
sqlite3 /opt/mcp-server/data/governance.db "SELECT id, server, check_type, severity, alert_key, fired_at FROM governance_events ORDER BY id DESC LIMIT 5;"
```

Expected: 1+ rows visible

- [ ] **Step 5: Push to foundation-shield GitHub**

```bash
cd /opt/foundation-shield
git push origin main
```

- [ ] **Step 6: Push FOMCP changes to its GitHub**

```bash
cd /opt/mcp-server
git push origin main
```

---

## Definition of Done

- [ ] `governance.db` exists at `/opt/mcp-server/data/governance.db` with all 7 tables
- [ ] `POST /api/governance/events` accepts and stores events
- [ ] `GET /api/governance/status` returns per-server event counts and Shield Score
- [ ] `alerting.js` in foundation-shield pushes events to FOMCP and writes local digest log
- [ ] `harvest.js` can pull events from VPS2/VPS VRO and bulk-POST them
- [ ] All 9 Vitest tests pass
- [ ] FOMCP restarts cleanly with migration applied

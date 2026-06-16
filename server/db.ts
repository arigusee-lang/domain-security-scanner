import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";
import { createLogger } from "./lib/logger.js";

const log = createLogger("db");

const SCHEMA_SQL = `
-- Users (Lucia Auth compatible)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  name          TEXT,
  avatar_url    TEXT,
  provider      TEXT NOT NULL CHECK(provider IN ('google', 'github')),
  provider_id   TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free', 'premium', 'premium_plus')),
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id);

-- Sessions (Lucia Auth v3 compatible — expires_at is UNIX timestamp in seconds)
CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Scan results
CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  -- Set when scan_type='batch' so deleting the parent batch cascades here.
  batch_id      TEXT REFERENCES batch_scans(id) ON DELETE CASCADE,
  domain        TEXT NOT NULL,
  scan_type     TEXT NOT NULL CHECK(scan_type IN ('single', 'batch')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
  score         INTEGER,
  config_json   TEXT,
  result_json   TEXT,
  changes_json  TEXT,
  shared        INTEGER NOT NULL DEFAULT 0,
  share_id      TEXT UNIQUE,
  share_expires TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_user_domain ON scans(user_id, domain);
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_share ON scans(share_id) WHERE share_id IS NOT NULL;
-- idx_scans_batch is created in runMigrations after the batch_id column exists
-- (CREATE TABLE IF NOT EXISTS is a no-op on existing dev DBs without batch_id).

-- Batch scans
CREATE TABLE IF NOT EXISTS batch_scans (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name              TEXT,
  status            TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
  total_domains     INTEGER NOT NULL,
  completed_domains INTEGER NOT NULL DEFAULT 0,
  config_json       TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_batch_user ON batch_scans(user_id);

-- Batch scan domains
CREATE TABLE IF NOT EXISTS batch_scan_domains (
  id        TEXT PRIMARY KEY,
  batch_id  TEXT NOT NULL REFERENCES batch_scans(id) ON DELETE CASCADE,
  domain    TEXT NOT NULL,
  scan_id   TEXT REFERENCES scans(id) ON DELETE SET NULL,
  status    TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed'))
);
CREATE INDEX IF NOT EXISTS idx_bsd_batch ON batch_scan_domains(batch_id);

-- Notification log
CREATE TABLE IF NOT EXISTS notification_log (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_id       TEXT REFERENCES scans(id) ON DELETE SET NULL,
  type          TEXT NOT NULL CHECK(type IN ('email', 'webhook')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed')),
  payload_json  TEXT,
  error         TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  sent_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_notification_user ON notification_log(user_id);
CREATE INDEX IF NOT EXISTS idx_notification_user_date ON notification_log(user_id, created_at);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url         TEXT NOT NULL,
  name        TEXT,
  secret      TEXT NOT NULL,
  events_json TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  failing     INTEGER NOT NULL DEFAULT 0,
  fail_count  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);

-- Webhook deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id            TEXT PRIMARY KEY,
  webhook_id    TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event         TEXT NOT NULL,
  payload_json  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'delivered', 'failed')),
  response_code INTEGER,
  error         TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  delivered_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_wd_webhook ON webhook_deliveries(webhook_id);

-- Plan audit log
CREATE TABLE IF NOT EXISTS plan_audit_log (
  id          TEXT PRIMARY KEY,
  admin_id    TEXT NOT NULL REFERENCES users(id),
  user_id     TEXT NOT NULL REFERENCES users(id),
  old_plan    TEXT NOT NULL,
  new_plan    TEXT NOT NULL,
  changed_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON plan_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_date ON plan_audit_log(changed_at DESC);

-- Monitored domains
CREATE TABLE IF NOT EXISTS monitored_domains (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain          TEXT NOT NULL,
  enabled         INTEGER NOT NULL DEFAULT 1,
  email_enabled   INTEGER NOT NULL DEFAULT 1,
  min_severity    TEXT NOT NULL DEFAULT 'warn' CHECK(min_severity IN ('info', 'warn', 'critical')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_md_user ON monitored_domains(user_id);

-- Monitors
CREATE TABLE IF NOT EXISTS monitors (
  id              TEXT PRIMARY KEY,
  domain_id       TEXT NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  monitor_type    TEXT NOT NULL CHECK(monitor_type IN (
    'ssl_expiry', 'domain_expiry', 'ct_logs',
    'security_txt_expiry', 'blacklist', 'caa_dnssec', 'headers'
  )),
  enabled         INTEGER NOT NULL DEFAULT 1,
  interval_ms     INTEGER NOT NULL,
  last_run_at     TEXT,
  next_run_at     TEXT,
  last_error      TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(domain_id, monitor_type)
);
CREATE INDEX IF NOT EXISTS idx_mon_domain ON monitors(domain_id);
CREATE INDEX IF NOT EXISTS idx_mon_user ON monitors(user_id);

-- Domain check state (keyed by domain, not user)
CREATE TABLE IF NOT EXISTS domain_check_state (
  id              TEXT PRIMARY KEY,
  domain          TEXT NOT NULL,
  check_type      TEXT NOT NULL,
  result_json     TEXT NOT NULL,
  result_hash     TEXT NOT NULL,
  expiry_date     TEXT,
  last_cursor     TEXT,
  checked_at      TEXT NOT NULL,
  UNIQUE(domain, check_type)
);

-- Monitor state
CREATE TABLE IF NOT EXISTS monitor_state (
  id                    TEXT PRIMARY KEY,
  monitor_id            TEXT NOT NULL UNIQUE REFERENCES monitors(id) ON DELETE CASCADE,
  result_json           TEXT NOT NULL,
  result_hash           TEXT NOT NULL,
  checked_at            TEXT NOT NULL,
  thresholds_fired_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_ms_monitor ON monitor_state(monitor_id);

-- Monitor alerts
CREATE TABLE IF NOT EXISTS monitor_alerts (
  id              TEXT PRIMARY KEY,
  monitor_id      TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  domain_id       TEXT NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  monitor_type    TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK(severity IN ('info', 'warn', 'critical', 'resolved')),
  title           TEXT NOT NULL,
  description     TEXT NOT NULL,
  previous_value  TEXT,
  current_value   TEXT,
  notified        INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ma_user ON monitor_alerts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ma_domain ON monitor_alerts(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ma_pending ON monitor_alerts(notified) WHERE notified = 0;

-- Monitoring settings
CREATE TABLE IF NOT EXISTS monitoring_settings (
  user_id             TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_enabled       INTEGER NOT NULL DEFAULT 1,
  min_severity        TEXT NOT NULL DEFAULT 'warn' CHECK(min_severity IN ('info', 'warn', 'critical')),
  updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

const DB_DIR = process.env.DB_DIR || path.join(process.cwd(), "data");
const DB_FILE = path.join(DB_DIR, "app.db");
const MAX_DB_SIZE_BYTES = 1024 * 1024 * 1024; // 1 GB

/** Safely add columns that may not exist yet (SQLite has no ALTER TABLE IF NOT EXISTS). */
export function runMigrations(db: Database.Database): void {
  const columns = db.pragma("table_info(users)") as Array<{ name: string }>;
  const colNames = columns.map((c) => c.name);

  if (!colNames.includes("role")) {
    db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
  }
  if (!colNames.includes("last_login_at")) {
    db.exec("ALTER TABLE users ADD COLUMN last_login_at TEXT");
  }

  // Migrate plan names: registered→free, pro→premium, enterprise→premium_plus
  // SQLite can't ALTER CHECK constraints, so we recreate the table if old CHECK exists
  try {
    db.exec("UPDATE users SET plan = 'free' WHERE plan = 'registered'");
  } catch (e: any) {
    if (e?.code === "SQLITE_CONSTRAINT_CHECK") {
      // Old CHECK constraint — need to recreate table
      db.pragma("foreign_keys = OFF");
      db.exec(`
        CREATE TABLE users_new (
          id            TEXT PRIMARY KEY,
          email         TEXT UNIQUE NOT NULL,
          name          TEXT,
          avatar_url    TEXT,
          provider      TEXT NOT NULL CHECK(provider IN ('google', 'github')),
          provider_id   TEXT NOT NULL,
          plan          TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free', 'premium', 'premium_plus')),
          role          TEXT NOT NULL DEFAULT 'user',
          last_login_at TEXT,
          created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO users_new (id, email, name, avatar_url, provider, provider_id, plan, role, last_login_at, created_at)
          SELECT id, email, name, avatar_url, provider, provider_id,
            CASE plan WHEN 'registered' THEN 'free' WHEN 'pro' THEN 'premium' WHEN 'enterprise' THEN 'premium_plus' ELSE plan END,
            COALESCE(role, 'user'),
            last_login_at,
            created_at
          FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id);
      `);
      log.info("migrated users table: plan names updated, CHECK constraint fixed");
    }
  }

  // Migrate monitored_domains: add notification settings columns
  const mdCols = db.pragma("table_info(monitored_domains)") as Array<{ name: string }>;
  const mdColNames = mdCols.map((c) => c.name);
  if (mdColNames.length > 0 && !mdColNames.includes("email_enabled")) {
    db.exec("ALTER TABLE monitored_domains ADD COLUMN email_enabled INTEGER NOT NULL DEFAULT 1");
    db.exec("ALTER TABLE monitored_domains ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'warn'");
  }

  // Migrate domain_check_state: add last_cursor column
  const dcsCols = db.pragma("table_info(domain_check_state)") as Array<{ name: string }>;
  if (dcsCols.length > 0 && !dcsCols.map(c => c.name).includes("last_cursor")) {
    db.exec("ALTER TABLE domain_check_state ADD COLUMN last_cursor TEXT");
  }

  // Migrate scans.user_id FK from ON DELETE SET NULL → CASCADE.
  // SQLite can't ALTER a foreign key, so detect old behavior via pragma and rebuild the table.
  const scansFks = db.pragma("foreign_key_list(scans)") as Array<{
    table: string; from: string; on_delete: string;
  }>;
  const userFk = scansFks.find((fk) => fk.table === "users" && fk.from === "user_id");
  if (userFk && userFk.on_delete !== "CASCADE") {
    db.pragma("foreign_keys = OFF");
    db.exec(`
      DELETE FROM scans WHERE user_id IS NULL;

      CREATE TABLE scans_new (
        id            TEXT PRIMARY KEY,
        user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
        batch_id      TEXT REFERENCES batch_scans(id) ON DELETE CASCADE,
        domain        TEXT NOT NULL,
        scan_type     TEXT NOT NULL CHECK(scan_type IN ('single', 'batch')),
        status        TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
        score         INTEGER,
        config_json   TEXT,
        result_json   TEXT,
        changes_json  TEXT,
        shared        INTEGER NOT NULL DEFAULT 0,
        share_id      TEXT UNIQUE,
        share_expires TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at  TEXT
      );
      INSERT INTO scans_new (id, user_id, domain, scan_type, status, score,
                             config_json, result_json, changes_json, shared, share_id,
                             share_expires, created_at, completed_at)
        SELECT id, user_id, domain, scan_type, status, score,
               config_json, result_json, changes_json, shared, share_id,
               share_expires, created_at, completed_at
        FROM scans;
      -- Backfill batch_id from batch_scan_domains for old batch-spawned scan rows
      UPDATE scans_new SET batch_id = (
        SELECT bsd.batch_id FROM batch_scan_domains bsd WHERE bsd.scan_id = scans_new.id LIMIT 1
      ) WHERE scan_type = 'batch';
      DROP TABLE scans;
      ALTER TABLE scans_new RENAME TO scans;
      CREATE INDEX IF NOT EXISTS idx_scans_user_domain ON scans(user_id, domain);
      CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(batch_id) WHERE batch_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_scans_share ON scans(share_id) WHERE share_id IS NOT NULL;
    `);
    db.pragma("foreign_keys = ON");
    log.info("migrated scans table: user_id CASCADE + batch_id CASCADE; orphans purged, batch_id backfilled");
  } else {
    // user_id already CASCADE; might still be missing batch_id from an in-between schema state.
    const scansCols = (db.pragma("table_info(scans)") as Array<{ name: string }>).map((c) => c.name);
    if (!scansCols.includes("batch_id")) {
      db.exec("ALTER TABLE scans ADD COLUMN batch_id TEXT REFERENCES batch_scans(id) ON DELETE CASCADE");
      db.exec(`
        UPDATE scans SET batch_id = (
          SELECT bsd.batch_id FROM batch_scan_domains bsd WHERE bsd.scan_id = scans.id LIMIT 1
        ) WHERE scan_type = 'batch' AND batch_id IS NULL;
        CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(batch_id) WHERE batch_id IS NOT NULL;
      `);
      log.info("added scans.batch_id FK CASCADE → batch_scans (backfilled)");
    }
  }

  // Drop deprecated scans.grade column (we now use score only). SQLite ≥ 3.35.
  const scansColsAfter = (db.pragma("table_info(scans)") as Array<{ name: string }>).map((c) => c.name);
  if (scansColsAfter.includes("grade")) {
    db.exec("ALTER TABLE scans DROP COLUMN grade");
    log.info("dropped scans.grade column");
  }

  // Ensure idx_scans_batch exists on fresh DBs too (the migration paths above
  // create it; for fresh installs SCHEMA_SQL skips it to avoid ordering issues).
  db.exec("CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(batch_id) WHERE batch_id IS NOT NULL");
}

export function initDatabase(dbPath: string = DB_FILE): Database.Database {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  runMigrations(db);
  return db;
}

type UserPlan = "free" | "premium" | "premium_plus";

/** Per-plan retention for single-scan history (rows in `scans` with scan_type='single'). */
export const SCAN_HISTORY_LIMITS: Record<UserPlan, number> = {
  free: 50,
  premium: 1000,
  premium_plus: 1000,
};

/** Per-plan retention for batch-scan history (rows in `batch_scans`). */
export const BATCH_HISTORY_LIMITS: Record<UserPlan, number> = {
  free: 0,
  premium: 100,
  premium_plus: 100,
};

/** Rows deleted per chunk; chunks yield to the event loop between iterations. */
const CLEANUP_CHUNK_SIZE = 1000;

const yieldToEventLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

/**
 * Per-user, per-plan retention for single scans. Keeps the N most recent rows
 * per user (by created_at DESC) where N is determined by the user's plan.
 * Deletes in chunks of CLEANUP_CHUNK_SIZE, yielding to the event loop between
 * chunks so we don't block other requests on huge backlogs.
 * Returns the number of deleted rows.
 */
export async function cleanupScanHistoryByPlan(db: Database.Database): Promise<number> {
  const ids = (db.prepare(`
    SELECT id FROM (
      SELECT s.id,
             ROW_NUMBER() OVER (PARTITION BY s.user_id ORDER BY s.created_at DESC) AS rn,
             CASE u.plan
               WHEN 'free'         THEN ${SCAN_HISTORY_LIMITS.free}
               WHEN 'premium'      THEN ${SCAN_HISTORY_LIMITS.premium}
               WHEN 'premium_plus' THEN ${SCAN_HISTORY_LIMITS.premium_plus}
               ELSE 0
             END AS keep_n
      FROM scans s
      INNER JOIN users u ON u.id = s.user_id
      WHERE s.scan_type = 'single'
    ) WHERE rn > keep_n
  `).all() as Array<{ id: string }>).map((r) => r.id);

  if (ids.length === 0) return 0;

  for (let i = 0; i < ids.length; i += CLEANUP_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + CLEANUP_CHUNK_SIZE);
    const placeholders = chunk.map(() => "?").join(",");
    db.prepare(`DELETE FROM scans WHERE id IN (${placeholders})`).run(...chunk);
    if (i + CLEANUP_CHUNK_SIZE < ids.length) await yieldToEventLoop();
  }
  return ids.length;
}

/**
 * Per-user, per-plan retention for batch scans. A single DELETE on `batch_scans`
 * is enough — child rows in `scans` (via scans.batch_id FK CASCADE) and in
 * `batch_scan_domains` (via batch_scan_domains.batch_id FK CASCADE) follow.
 * Returns the number of deleted batches.
 */
export async function cleanupBatchHistoryByPlan(db: Database.Database): Promise<number> {
  const ids = (db.prepare(`
    SELECT id FROM (
      SELECT b.id,
             ROW_NUMBER() OVER (PARTITION BY b.user_id ORDER BY b.created_at DESC) AS rn,
             CASE u.plan
               WHEN 'free'         THEN ${BATCH_HISTORY_LIMITS.free}
               WHEN 'premium'      THEN ${BATCH_HISTORY_LIMITS.premium}
               WHEN 'premium_plus' THEN ${BATCH_HISTORY_LIMITS.premium_plus}
               ELSE 0
             END AS keep_n
      FROM batch_scans b
      INNER JOIN users u ON u.id = b.user_id
    ) WHERE rn > keep_n
  `).all() as Array<{ id: string }>).map((r) => r.id);

  if (ids.length === 0) return 0;

  for (let i = 0; i < ids.length; i += CLEANUP_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + CLEANUP_CHUNK_SIZE);
    const placeholders = chunk.map(() => "?").join(",");
    db.prepare(`DELETE FROM batch_scans WHERE id IN (${placeholders})`).run(...chunk);
    if (i + CLEANUP_CHUNK_SIZE < ids.length) await yieldToEventLoop();
  }
  return ids.length;
}

/** @deprecated kept for backwards compat — superseded by cleanupScanHistoryByPlan */
export function cleanupOldScans(db: Database.Database, days: number = 90): number {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result = db.prepare("DELETE FROM scans WHERE created_at < ?").run(cutoff);
  return result.changes;
}

/** Log a warning if the database file exceeds 1 GB. */
export function checkDatabaseSize(db: Database.Database): void {
  const dbPath = db.name;
  try {
    const stats = fs.statSync(dbPath);
    if (stats.size > MAX_DB_SIZE_BYTES) {
      log.warn(
        { sizeMB: Number((stats.size / 1024 / 1024).toFixed(1)) },
        "database file size exceeds 1 GB limit"
      );
    }
  } catch {
    // File may not exist yet (in-memory db)
  }
}

import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";

const SCHEMA_SQL = `
-- Users (Lucia Auth compatible)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  name          TEXT,
  avatar_url    TEXT,
  provider      TEXT NOT NULL CHECK(provider IN ('google', 'github')),
  provider_id   TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'registered' CHECK(plan IN ('registered', 'pro', 'enterprise')),
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
  user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
  domain        TEXT NOT NULL,
  scan_type     TEXT NOT NULL CHECK(scan_type IN ('single', 'batch')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
  score         INTEGER,
  grade         TEXT,
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

-- Scheduled scans
CREATE TABLE IF NOT EXISTS scheduled_scans (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT,
  domains_json  TEXT NOT NULL,
  cron          TEXT NOT NULL,
  config_json   TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  last_run_at   TEXT,
  next_run_at   TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scheduled_user ON scheduled_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_next ON scheduled_scans(next_run_at) WHERE enabled = 1;

-- Notification log
CREATE TABLE IF NOT EXISTS notification_log (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_id       TEXT REFERENCES scans(id) ON DELETE SET NULL,
  scheduled_id  TEXT REFERENCES scheduled_scans(id) ON DELETE SET NULL,
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
`;

const DB_DIR = process.env.DB_DIR || path.join(process.cwd(), "data");
const DB_FILE = path.join(DB_DIR, "app.db");
const MAX_DB_SIZE_BYTES = 1024 * 1024 * 1024; // 1 GB

export function initDatabase(dbPath: string = DB_FILE): Database.Database {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

/** Delete scans older than `days` days. Returns number of deleted rows. */
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
      console.warn(
        `[db] WARNING: Database file size (${(stats.size / 1024 / 1024).toFixed(1)} MB) exceeds 1 GB limit`
      );
    }
  } catch {
    // File may not exist yet (in-memory db)
  }
}

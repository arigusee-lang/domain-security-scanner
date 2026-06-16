import Database from "better-sqlite3";
const db = new Database("data/app.db");
db.pragma("foreign_keys = OFF");
db.exec("DROP TABLE IF EXISTS users_new");
db.exec(`
  CREATE TABLE users_new (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, avatar_url TEXT,
    provider TEXT NOT NULL, provider_id TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free','premium','premium_plus')),
    role TEXT NOT NULL DEFAULT 'user', last_login_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  INSERT INTO users_new SELECT id, email, name, avatar_url, provider, provider_id,
    CASE plan WHEN 'registered' THEN 'free' WHEN 'pro' THEN 'premium' WHEN 'enterprise' THEN 'premium_plus' ELSE plan END,
    COALESCE(role,'user'), last_login_at, created_at FROM users;
  DROP TABLE users;
  ALTER TABLE users_new RENAME TO users;
  CREATE UNIQUE INDEX idx_users_provider ON users(provider, provider_id);
`);
db.pragma("foreign_keys = ON");
console.log("Done. Users migrated to new plan names.");
db.close();

import { DatabaseSync } from 'node:sqlite';
import { ensureDataDir, runtimeConfig } from './config.js';

function ensureColumn(db, table, name, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map(r=>r.name);
  if (!columns.includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
}

export function openDb(dir) {
  const cfg = runtimeConfig(ensureDataDir(dir));
  const db = new DatabaseSync(cfg.dbPath);
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS actors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'agent',
      token_hash TEXT UNIQUE,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      capability TEXT NOT NULL,
      effect TEXT NOT NULL CHECK(effect IN ('allow','ask','deny')),
      priority INTEGER NOT NULL DEFAULT 0,
      conditions_json TEXT NOT NULL DEFAULT '{}',
      expires_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(actor_id) REFERENCES actors(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS grants_lookup ON grants(actor_id, capability, priority DESC);
    CREATE TABLE IF NOT EXISTS intents (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      capability TEXT NOT NULL,
      args_json TEXT NOT NULL,
      args_hash TEXT NOT NULL,
      idempotency_key TEXT,
      policy_effect TEXT NOT NULL,
      policy_grant_id TEXT,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(actor_id) REFERENCES actors(id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS intents_idempotency ON intents(actor_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE TABLE IF NOT EXISTS approvals (
      id TEXT PRIMARY KEY,
      intent_id TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL CHECK(state IN ('pending','approved','denied','expired')),
      args_hash TEXT NOT NULL,
      capability TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      decided_at TEXT,
      decided_by TEXT,
      decision_note TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(intent_id) REFERENCES intents(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS executions (
      id TEXT PRIMARY KEY,
      intent_id TEXT NOT NULL UNIQUE,
      receipt_key TEXT NOT NULL UNIQUE,
      connector TEXT NOT NULL,
      status TEXT NOT NULL,
      result_json TEXT,
      error_text TEXT,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      FOREIGN KEY(intent_id) REFERENCES intents(id)
    );
    CREATE TABLE IF NOT EXISTS vault_entries (
      name TEXT PRIMARY KEY,
      connector TEXT,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      tag TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS connections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      connector TEXT NOT NULL,
      account_label TEXT,
      vault_ref TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS connection_access (
      actor_id TEXT NOT NULL,
      connection_id TEXT NOT NULL,
      level TEXT NOT NULL CHECK(level IN ('none','read','ask','automatic','custom')),
      capabilities_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY(actor_id, connection_id),
      FOREIGN KEY(actor_id) REFERENCES actors(id) ON DELETE CASCADE,
      FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS connection_access_connection ON connection_access(connection_id, actor_id);
    CREATE TABLE IF NOT EXISTS oauth_flows (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      connection_id TEXT,
      state_hash TEXT NOT NULL UNIQUE,
      verifier_ciphertext TEXT NOT NULL,
      verifier_iv TEXT NOT NULL,
      verifier_tag TEXT NOT NULL,
      requested_scopes_json TEXT NOT NULL DEFAULT '[]',
      redirect_uri TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','exchanging')),
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS oauth_flows_expiry ON oauth_flows(expires_at);
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS media_handles (
      handle TEXT PRIMARY KEY,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      tag TEXT NOT NULL,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      expires_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      actor TEXT NOT NULL,
      event_type TEXT NOT NULL,
      subject_id TEXT,
      data_json TEXT NOT NULL,
      prev_hash TEXT,
      event_hash TEXT NOT NULL UNIQUE
    );
  `);
  ensureColumn(db, 'connections', 'auth_method', "TEXT NOT NULL DEFAULT 'manual'");
  ensureColumn(db, 'connections', 'scopes_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, 'connections', 'external_account_id', 'TEXT');
  ensureColumn(db, 'connections', 'health_status', "TEXT NOT NULL DEFAULT 'unknown'");
  ensureColumn(db, 'connections', 'last_checked_at', 'TEXT');
  ensureColumn(db, 'connections', 'disconnected_at', 'TEXT');
  db.exec(`
    INSERT OR IGNORE INTO connection_access(actor_id,connection_id,level,capabilities_json,created_at,updated_at)
    SELECT a.id,c.id,'none','{}',datetime('now'),datetime('now')
    FROM actors a CROSS JOIN connections c
    WHERE a.kind='agent';
  `);
  return db;
}

import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

export function dataDir() {
  const raw = process.env.PAG_DATA_DIR || join(homedir(), '.pag');
  return resolve(raw);
}
export function ensureDataDir(dir=dataDir()) { mkdirSync(dir, { recursive: true, mode: 0o700 }); return dir; }
function readTrim(path) { return existsSync(path) ? readFileSync(path, 'utf8').trim() : null; }
export function masterKey(dir=dataDir()) {
  const env = process.env.PAG_MASTER_KEY;
  const text = env || readTrim(join(dir, 'master.key'));
  if (!text) throw new Error('PAG master key missing. Run `pag init`.');
  const key = Buffer.from(text, 'base64');
  if (key.length !== 32) throw new Error('PAG master key must decode to 32 bytes.');
  return key;
}
export function adminToken(dir=dataDir()) {
  const token = process.env.PAG_ADMIN_TOKEN || readTrim(join(dir, 'admin.token'));
  if (!token) throw new Error('PAG admin token missing. Run `pag init`.');
  return token;
}
export function initSecrets(dir=dataDir(), { force=false }={}) {
  ensureDataDir(dir);
  const masterPath = join(dir, 'master.key');
  const adminPath = join(dir, 'admin.token');
  if ((!force) && (existsSync(masterPath) || existsSync(adminPath))) {
    return { created: false, masterPath, adminPath };
  }
  writeFileSync(masterPath, randomBytes(32).toString('base64') + '\n', { mode: 0o600 });
  writeFileSync(adminPath, `pag_admin_${randomBytes(24).toString('base64url')}\n`, { mode: 0o600 });
  try { chmodSync(masterPath, 0o600); chmodSync(adminPath, 0o600); } catch {}
  return { created: true, masterPath, adminPath };
}
export function runtimeConfig(dir=dataDir()) {
  return {
    dataDir: dir,
    dbPath: join(dir, 'pag.sqlite'),
    host: process.env.PAG_HOST || '127.0.0.1',
    port: Number(process.env.PAG_PORT || 8787),
    approvalTtlMinutes: Number(process.env.PAG_APPROVAL_TTL_MINUTES || 30),
    oauthFlowTtlMinutes: Number(process.env.PAG_OAUTH_FLOW_TTL_MINUTES || 10),
    publicBaseUrl: process.env.PAG_PUBLIC_BASE_URL || null,
  };
}

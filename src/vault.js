import { encryptSecret, decryptSecret } from './crypto.js';
import { nowIso, json, parseJson } from './util.js';

export class Vault {
  constructor(db, key, audit) { this.db = db; this.key = key; this.audit = audit; }
  put(name, value, { connector=null, metadata={} }={}) {
    if (!name || !value) throw new Error('Vault name and non-empty value are required.');
    const enc = encryptSecret(this.key, value, `pag:v1:${name}`);
    const now = nowIso();
    const existing = this.db.prepare('SELECT created_at FROM vault_entries WHERE name=?').get(name);
    if (existing) {
      this.db.prepare(`UPDATE vault_entries SET connector=?,ciphertext=?,iv=?,tag=?,metadata_json=?,updated_at=? WHERE name=?`)
        .run(connector, enc.ciphertext, enc.iv, enc.tag, json(metadata), now, name);
    } else {
      this.db.prepare(`INSERT INTO vault_entries(name,connector,ciphertext,iv,tag,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`)
        .run(name, connector, enc.ciphertext, enc.iv, enc.tag, json(metadata), now, now);
    }
    this.audit?.append('local-admin','vault.put',name,{ connector, metadata });
    return this.metadata(name);
  }
  get(name) {
    const row = this.db.prepare('SELECT * FROM vault_entries WHERE name=?').get(name);
    if (!row) return null;
    return decryptSecret(this.key, row, `pag:v1:${name}`);
  }
  metadata(name) {
    const row = this.db.prepare('SELECT name,connector,metadata_json,created_at,updated_at FROM vault_entries WHERE name=?').get(name);
    return row ? {...row, metadata: parseJson(row.metadata_json,{})} : null;
  }
  list() { return this.db.prepare('SELECT name,connector,metadata_json,created_at,updated_at FROM vault_entries ORDER BY name').all().map(r=>({...r,metadata:parseJson(r.metadata_json,{})})); }
  delete(name) { const r=this.db.prepare('DELETE FROM vault_entries WHERE name=?').run(name); if (r.changes) this.audit?.append('local-admin','vault.delete',name,{}); return r.changes>0; }
}

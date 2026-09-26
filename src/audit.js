import { canonicalize, nowIso, sha256, json, parseJson } from './util.js';

export class AuditLog {
  constructor(db) { this.db = db; }
  append(actor, eventType, subjectId, data={}) {
    const prev = this.db.prepare('SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1').get();
    const ts = nowIso();
    const prevHash = prev?.event_hash || null;
    const payload = { ts, actor, eventType, subjectId: subjectId || null, data, prevHash };
    const eventHash = sha256(canonicalize(payload));
    this.db.prepare(`INSERT INTO audit_events(ts,actor,event_type,subject_id,data_json,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)`)
      .run(ts, actor, eventType, subjectId || null, json(data), prevHash, eventHash);
    return { ...payload, eventHash };
  }
  list(limit=200) {
    return this.db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?').all(Number(limit)).map(r => ({...r, data: parseJson(r.data_json, {})}));
  }
  verify() {
    const rows = this.db.prepare('SELECT * FROM audit_events ORDER BY id ASC').all();
    let prevHash = null;
    for (const row of rows) {
      const data = parseJson(row.data_json, {});
      const payload = { ts: row.ts, actor: row.actor, eventType: row.event_type, subjectId: row.subject_id || null, data, prevHash };
      const expected = sha256(canonicalize(payload));
      if (row.prev_hash !== prevHash || row.event_hash !== expected) return { ok:false, brokenAt: row.id };
      prevHash = row.event_hash;
    }
    return { ok:true, count: rows.length, head: prevHash };
  }
}

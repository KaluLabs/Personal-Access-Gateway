import { randomBytes } from 'node:crypto';
import { AuditLog } from './audit.js';
import { Vault } from './vault.js';
import { PolicyEngine } from './policy.js';
import { ConnectorRegistry } from './connectors/index.js';
import { MediaRegistry } from './media.js';
import { Inspector } from './inspect.js';
import { masterKey, runtimeConfig } from './config.js';
import { argsHash, json, nowIso, parseJson, randomId, sha256 } from './util.js';

function appError(message, code=400) { const e=new Error(message); e.statusCode=code; return e; }
function actorView(r) { return r ? { id:r.id,name:r.name,kind:r.kind,status:r.status,created_at:r.created_at } : null; }
function intentView(r) { return r ? {...r,args:parseJson(r.args_json,{})} : null; }
function executionView(r) { return r ? {...r,result:parseJson(r.result_json,null)} : null; }

export class PagService {
  constructor(db, { dir, connectors }={}) {
    this.db=db; this.cfg=runtimeConfig(dir); this.audit=new AuditLog(db); this.policy=new PolicyEngine(db);
    const key=masterKey(this.cfg.dataDir); this.connectors=connectors || new ConnectorRegistry(); this.vault=new Vault(db,key,this.audit);
    this.media=new MediaRegistry(db,key,{dir:this.cfg.dataDir,audit:this.audit}); this.inspector=new Inspector({mediaRegistry:this.media,audit:this.audit});
    if(!this.connectors.get('instagram.media.inspect')) this.connectors.register('instagram.media.inspect',{name:'opencli-instagram-read',connectionType:null,execute:async({args})=>{if(typeof args.url!=='string')throw appError('url is required.');return this.inspector.inspect(args.url);}});
    if(!this.connectors.get('x.posts.inspect')) this.connectors.register('x.posts.inspect',{name:'opencli-x-read',connectionType:null,execute:async({args})=>{if(typeof args.url!=='string')throw appError('url is required.');return this.inspector.inspect(args.url);}});
  }
  createActor(name, kind='agent') {
    if (!name?.trim()) throw appError('Actor name is required.');
    const id=randomId('act_'); const token=`pag_${randomBytes(30).toString('base64url')}`; const created=nowIso();
    this.db.prepare('INSERT INTO actors(id,name,kind,token_hash,status,created_at) VALUES(?,?,?,?,?,?)').run(id,name.trim(),kind,sha256(token),'active',created);
    this.audit.append('local-admin','actor.created',id,{name:name.trim(),kind});
    return { actor:{id,name:name.trim(),kind,status:'active',created_at:created}, token };
  }
  listActors() { return this.db.prepare('SELECT * FROM actors ORDER BY created_at DESC').all().map(actorView); }
  rotateActorToken(id) {
    const actor=this.db.prepare('SELECT * FROM actors WHERE id=?').get(id); if(!actor) throw appError('Actor not found.',404);
    const token=`pag_${randomBytes(30).toString('base64url')}`; this.db.prepare('UPDATE actors SET token_hash=? WHERE id=?').run(sha256(token),id);
    this.audit.append('local-admin','actor.token_rotated',id,{}); return {actor:actorView(actor),token};
  }
  setActorStatus(id,status) {
    if(!['active','revoked'].includes(status)) throw appError('Actor status must be active or revoked.');
    const r=this.db.prepare('UPDATE actors SET status=? WHERE id=?').run(status,id); if(!r.changes) throw appError('Actor not found.',404);
    this.audit.append('local-admin',status==='revoked'?'actor.revoked':'actor.activated',id,{}); return actorView(this.db.prepare('SELECT * FROM actors WHERE id=?').get(id));
  }
  authenticateToken(token) {
    if (!token) return null; const row=this.db.prepare('SELECT * FROM actors WHERE token_hash=? AND status=\'active\'').get(sha256(token)); return actorView(row);
  }
  createGrant({actorId,capability,effect,priority=0,conditions={},expiresAt=null}) {
    if (!['allow','ask','deny'].includes(effect)) throw appError('Grant effect must be allow, ask, or deny.');
    if (!capability) throw appError('Capability is required.');
    if (!this.db.prepare('SELECT id FROM actors WHERE id=?').get(actorId)) throw appError('Actor not found.',404);
    const id=randomId('gr_'); const created=nowIso();
    this.db.prepare('INSERT INTO grants(id,actor_id,capability,effect,priority,conditions_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(id,actorId,capability,effect,Number(priority)||0,json(conditions||{}),expiresAt,created);
    this.audit.append('local-admin','grant.created',id,{actorId,capability,effect,priority:Number(priority)||0,conditions,expiresAt});
    return {id,actor_id:actorId,capability,effect,priority:Number(priority)||0,conditions,expires_at:expiresAt,created_at:created};
  }
  listGrants(actorId=null) {
    const rows=actorId?this.db.prepare('SELECT * FROM grants WHERE actor_id=? ORDER BY priority DESC,created_at DESC').all(actorId):this.db.prepare('SELECT * FROM grants ORDER BY created_at DESC').all();
    return rows.map(r=>({...r,conditions:parseJson(r.conditions_json,{})}));
  }
  revokeGrant(id) { const r=this.db.prepare('DELETE FROM grants WHERE id=?').run(id); if(r.changes)this.audit.append('local-admin','grant.revoked',id,{}); return r.changes>0; }

  isLockdown() { const row=this.db.prepare("SELECT value_json FROM settings WHERE key='lockdown'").get(); return row ? !!parseJson(row.value_json,false) : false; }
  setLockdown(enabled,by='local-admin') { const now=nowIso(); this.db.prepare(`INSERT INTO settings(key,value_json,updated_at) VALUES('lockdown',?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at`).run(json(!!enabled),now); this.audit.append(by,enabled?'lockdown.enabled':'lockdown.disabled','lockdown',{}); return {enabled:!!enabled,updated_at:now}; }
  createConnection({name,connector,accountLabel=null,vaultRef=null,metadata={}}) {
    if(!name?.trim()||!connector?.trim()) throw appError('Connection name and connector are required.');
    if(vaultRef && !this.vault.metadata(vaultRef)) throw appError('Referenced vault entry does not exist.',404);
    const id=randomId('con_'); const now=nowIso(); this.db.prepare(`INSERT INTO connections(id,name,connector,account_label,vault_ref,status,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?,?)`).run(id,name.trim(),connector.trim(),accountLabel,vaultRef,json(metadata||{}),now,now);
    this.audit.append('local-admin','connection.created',id,{name:name.trim(),connector:connector.trim(),accountLabel,vaultRef,metadata}); return this.getConnection(id);
  }
  getConnection(id) { const r=this.db.prepare('SELECT * FROM connections WHERE id=?').get(id); return r?{...r,metadata:parseJson(r.metadata_json,{})}:null; }
  listConnections() { return this.db.prepare('SELECT * FROM connections ORDER BY created_at DESC').all().map(r=>({...r,metadata:parseJson(r.metadata_json,{})})); }
  setConnectionStatus(id,status) { if(!['active','disabled'].includes(status)) throw appError('Connection status must be active or disabled.'); const now=nowIso(); const r=this.db.prepare('UPDATE connections SET status=?,updated_at=? WHERE id=?').run(status,now,id); if(!r.changes) throw appError('Connection not found.',404); this.audit.append('local-admin',status==='active'?'connection.enabled':'connection.disabled',id,{}); return this.getConnection(id); }
  deleteConnection(id) { const r=this.db.prepare('DELETE FROM connections WHERE id=?').run(id); if(r.changes)this.audit.append('local-admin','connection.deleted',id,{}); return r.changes>0; }

  async createIntent({actorId,capability,args={},idempotencyKey=null}) {
    const actor=this.db.prepare('SELECT * FROM actors WHERE id=? AND status=\'active\'').get(actorId); if(!actor) throw appError('Actor not found or inactive.',401);
    if (!capability || typeof capability!=='string') throw appError('Capability is required.');
    const hash=argsHash(actorId,capability,args);
    if (idempotencyKey) {
      const existing=this.db.prepare('SELECT * FROM intents WHERE actor_id=? AND idempotency_key=?').get(actorId,idempotencyKey);
      if (existing) {
        if (existing.args_hash!==hash) throw appError('Idempotency key was already used with different arguments.',409);
        return this.getIntent(existing.id);
      }
    }
    const decision=this.isLockdown()?{effect:'deny',reason:'lockdown',grant:null}:this.policy.evaluate(actorId,capability,args); const id=randomId('int_'); const now=nowIso();
    const status=decision.effect==='deny'?'denied':decision.effect==='ask'?'pending_approval':'authorized';
    this.db.prepare(`INSERT INTO intents(id,actor_id,capability,args_json,args_hash,idempotency_key,policy_effect,policy_grant_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id,actorId,capability,json(args),hash,idempotencyKey,decision.effect,decision.grant?.id||null,status,now,now);
    this.audit.append(actorId,'intent.created',id,{capability,argsHash:hash,idempotencyKey,policyEffect:decision.effect,policyGrantId:decision.grant?.id||null});
    if (decision.effect==='deny') this.audit.append('policy','intent.denied',id,{reason:decision.reason});
    if (decision.effect==='ask') {
      const approvalId=randomId('apr_'); const expires=new Date(Date.now()+this.cfg.approvalTtlMinutes*60_000).toISOString();
      this.db.prepare(`INSERT INTO approvals(id,intent_id,state,args_hash,capability,expires_at,created_at) VALUES(?,?,?,?,?,?,?)`).run(approvalId,id,'pending',hash,capability,expires,now);
      this.audit.append('policy','approval.requested',approvalId,{intentId:id,argsHash:hash,capability,expiresAt:expires});
    }
    if (decision.effect==='allow') await this.executeIntent(id,'policy:auto-allow');
    return this.getIntent(id);
  }
  getIntent(id) {
    const row=this.db.prepare('SELECT * FROM intents WHERE id=?').get(id); if(!row) return null;
    const approval=this.db.prepare('SELECT * FROM approvals WHERE intent_id=?').get(id);
    const execution=this.db.prepare('SELECT * FROM executions WHERE intent_id=?').get(id);
    return { ...intentView(row), approval:approval||null, execution:executionView(execution) };
  }
  listIntents(limit=100) { return this.db.prepare('SELECT * FROM intents ORDER BY created_at DESC LIMIT ?').all(Number(limit)).map(intentView); }
  listIntentDetails(limit=100) { return this.db.prepare('SELECT id FROM intents ORDER BY created_at DESC LIMIT ?').all(Number(limit)).map(r=>this.getIntent(r.id)); }
  listApprovals(state='pending',limit=100) {
    if (state==='pending') this.expireApprovals();
    const rows=state==='all'?this.db.prepare('SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?').all(Number(limit)):this.db.prepare('SELECT * FROM approvals WHERE state=? ORDER BY created_at DESC LIMIT ?').all(state,Number(limit));
    return rows.map(a=>({...a,intent:this.getIntent(a.intent_id)}));
  }
  expireApprovals() {
    const now=nowIso(); const rows=this.db.prepare(`SELECT * FROM approvals WHERE state='pending' AND expires_at<=?`).all(now);
    for(const a of rows){ this.db.prepare(`UPDATE approvals SET state='expired',decided_at=?,decided_by='system' WHERE id=?`).run(now,a.id); this.db.prepare(`UPDATE intents SET status='expired',updated_at=? WHERE id=?`).run(now,a.intent_id); this.audit.append('system','approval.expired',a.id,{intentId:a.intent_id}); }
  }
  async approve(id,{decidedBy='admin',note=null,expectedArgsHash=null}={}) {
    this.expireApprovals(); const a=this.db.prepare('SELECT * FROM approvals WHERE id=?').get(id); if(!a) throw appError('Approval not found.',404);
    const intent=this.db.prepare('SELECT * FROM intents WHERE id=?').get(a.intent_id); if(!intent) throw appError('Intent not found.',404);
    if (a.state==='approved') return this.getIntent(a.intent_id);
    if (a.state!=='pending') throw appError(`Approval is ${a.state}.`,409);
    if (expectedArgsHash && expectedArgsHash!==a.args_hash) throw appError('Approval hash mismatch.',409);
    if (intent.args_hash!==a.args_hash) throw appError('Intent payload changed after approval request.',409);
    const now=nowIso();
    this.db.prepare(`UPDATE approvals SET state='approved',decided_at=?,decided_by=?,decision_note=? WHERE id=?`).run(now,decidedBy,note,id);
    this.db.prepare(`UPDATE intents SET status='approved',updated_at=? WHERE id=?`).run(now,a.intent_id);
    this.audit.append(decidedBy,'approval.approved',id,{intentId:a.intent_id,argsHash:a.args_hash,note});
    await this.executeIntent(a.intent_id,decidedBy);
    return this.getIntent(a.intent_id);
  }
  denyApproval(id,{decidedBy='admin',note=null}={}) {
    this.expireApprovals(); const a=this.db.prepare('SELECT * FROM approvals WHERE id=?').get(id); if(!a) throw appError('Approval not found.',404);
    if(a.state==='denied') return this.getIntent(a.intent_id); if(a.state!=='pending') throw appError(`Approval is ${a.state}.`,409);
    const now=nowIso(); this.db.prepare(`UPDATE approvals SET state='denied',decided_at=?,decided_by=?,decision_note=? WHERE id=?`).run(now,decidedBy,note,id);
    this.db.prepare(`UPDATE intents SET status='denied',updated_at=? WHERE id=?`).run(now,a.intent_id);
    this.audit.append(decidedBy,'approval.denied',id,{intentId:a.intent_id,note}); return this.getIntent(a.intent_id);
  }
  async executeIntent(intentId,trigger='system') {
    const intent=this.db.prepare('SELECT * FROM intents WHERE id=?').get(intentId); if(!intent) throw appError('Intent not found.',404);
    if (!['authorized','approved','succeeded','failed'].includes(intent.status)) throw appError(`Intent is not executable from status ${intent.status}.`,409);
    const existing=this.db.prepare('SELECT * FROM executions WHERE intent_id=?').get(intentId); if(existing) return executionView(existing);
    const handler=this.connectors.get(intent.capability); if(!handler) {
      const now=nowIso(); this.db.prepare(`UPDATE intents SET status='failed',updated_at=? WHERE id=?`).run(now,intentId); this.audit.append('runtime','execution.failed',intentId,{error:'No connector registered',capability:intent.capability}); throw appError(`No connector registered for ${intent.capability}.`,422);
    }
    const execId=randomId('exe_'); const receipt=sha256(`pag:v1:${intentId}:${intent.args_hash}`); const started=nowIso();
    try { this.db.prepare(`INSERT INTO executions(id,intent_id,receipt_key,connector,status,started_at) VALUES(?,?,?,?,?,?)`).run(execId,intentId,receipt,handler.name,'started',started); }
    catch (e) { const race=this.db.prepare('SELECT * FROM executions WHERE intent_id=?').get(intentId); if(race)return executionView(race); throw e; }
    this.db.prepare(`UPDATE intents SET status='executing',updated_at=? WHERE id=?`).run(started,intentId);
    this.audit.append(trigger,'execution.started',execId,{intentId,receiptKey:receipt,connector:handler.name,argsHash:intent.args_hash});
    try {
      const args=parseJson(intent.args_json,{}); let connection=null;
      if(args.connectionId){ connection=this.getConnection(args.connectionId); if(!connection||connection.status!=='active') throw appError('Requested connection is unavailable.',409); if(handler.connectionType && connection.connector!==handler.connectionType) throw appError(`Connection ${connection.id} is for ${connection.connector}, not ${handler.connectionType}.`,409); }
      const result=await handler.execute({intent:intentView(intent),args,vault:this.vault,connection}); const finished=nowIso();
      this.db.prepare(`UPDATE executions SET status='succeeded',result_json=?,finished_at=? WHERE id=?`).run(json(result),finished,execId);
      this.db.prepare(`UPDATE intents SET status='succeeded',updated_at=? WHERE id=?`).run(finished,intentId);
      this.audit.append('runtime','execution.succeeded',execId,{intentId,receiptKey:receipt,connector:handler.name}); return this.getIntent(intentId).execution;
    } catch(e) {
      const finished=nowIso(); this.db.prepare(`UPDATE executions SET status='failed',error_text=?,finished_at=? WHERE id=?`).run(String(e.message||e),finished,execId); this.db.prepare(`UPDATE intents SET status='failed',updated_at=? WHERE id=?`).run(finished,intentId); this.audit.append('runtime','execution.failed',execId,{intentId,receiptKey:receipt,error:String(e.message||e)}); throw e;
    }
  }
  summary() {
    this.expireApprovals();
    const one=(sql)=>Number(this.db.prepare(sql).get().n);
    return { lockdown:this.isLockdown(),actors:one('SELECT COUNT(*) n FROM actors'),connections:one('SELECT COUNT(*) n FROM connections'),grants:one('SELECT COUNT(*) n FROM grants'),pendingApprovals:one("SELECT COUNT(*) n FROM approvals WHERE state='pending'"),intents:one('SELECT COUNT(*) n FROM intents'),succeeded:one("SELECT COUNT(*) n FROM intents WHERE status='succeeded'"),failed:one("SELECT COUNT(*) n FROM intents WHERE status='failed'"),audit:this.audit.verify(),connectors:this.connectors.list() };
  }
}

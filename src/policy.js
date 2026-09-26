import { parseJson } from './util.js';

function capabilityMatches(rule, cap) {
  if (rule === '*') return true;
  if (rule.endsWith('.*')) return cap.startsWith(rule.slice(0,-1));
  return rule === cap;
}
function conditionsMatch(conditions, args) {
  if (!conditions || typeof conditions !== 'object') return true;
  if (conditions.argEquals) {
    for (const [k,v] of Object.entries(conditions.argEquals)) if (args?.[k] !== v) return false;
  }
  if (conditions.argIn) {
    for (const [k,allowed] of Object.entries(conditions.argIn)) if (!Array.isArray(allowed) || !allowed.includes(args?.[k])) return false;
  }
  if (conditions.maxLength) {
    for (const [k,max] of Object.entries(conditions.maxLength)) if (typeof args?.[k] === 'string' && args[k].length > Number(max)) return false;
  }
  return true;
}
export class PolicyEngine {
  constructor(db) { this.db = db; }
  evaluate(actorId, capability, args={}) {
    const now = new Date().toISOString();
    const rows = this.db.prepare(`SELECT * FROM grants WHERE actor_id=? AND (expires_at IS NULL OR expires_at>?) ORDER BY priority DESC, created_at ASC`).all(actorId, now)
      .filter(r => capabilityMatches(r.capability, capability) && conditionsMatch(parseJson(r.conditions_json,{}), args));
    if (!rows.length) return { effect:'deny', reason:'default_deny', grant:null };
    const topPriority = rows[0].priority;
    const top = rows.filter(r=>r.priority===topPriority);
    const chosen = top.find(r=>r.effect==='deny') || top.find(r=>r.effect==='ask') || top.find(r=>r.effect==='allow');
    return { effect: chosen.effect, reason:'matched_grant', grant: chosen };
  }
}

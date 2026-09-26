import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function nowIso() { return new Date().toISOString(); }
export function randomId(prefix='') { return `${prefix}${randomBytes(16).toString('hex')}`; }
export function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}
export function argsHash(actorId, capability, args) {
  return sha256(canonicalize({ actorId, capability, args }));
}
export function safeEqual(a, b) {
  const ab = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
export function parseJson(value, fallback=null) {
  try { return JSON.parse(value); } catch { return fallback; }
}
export function json(value) { return JSON.stringify(value ?? null); }
export function asBool(v) { return v === true || v === 'true' || v === '1' || v === 1; }

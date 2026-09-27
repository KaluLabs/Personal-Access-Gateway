import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';
import { adminToken, runtimeConfig } from './config.js';
import { safeEqual } from './util.js';

const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
function send(res,status,body,headers={}) { res.writeHead(status,headers); res.end(body); }
function sendJson(res,status,value,headers={}) { send(res,status,JSON.stringify(value),{'content-type':'application/json; charset=utf-8',...headers}); }
function cookieMap(header='') { return Object.fromEntries(header.split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return i<0?[x,'']:[x.slice(0,i),decodeURIComponent(x.slice(i+1))]})); }
function bearer(req) { const h=req.headers.authorization||''; return h.startsWith('Bearer ')?h.slice(7):null; }
async function bodyJson(req,max=262144) { let total=0; const chunks=[]; for await(const c of req){ total+=c.length; if(total>max) throw Object.assign(new Error('Request body too large.'),{statusCode:413}); chunks.push(c); } if(!chunks.length)return {}; try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Object.assign(new Error('Invalid JSON body.'),{statusCode:400});} }
function sessionValue(token){return createHmac('sha256',token).update('pag-admin-session-v1').digest('base64url');}
function htmlEscape(value){return String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}

export function createServer(service,{dir,publicDir=fileURLToPath(new URL('../public',import.meta.url))}={}) {
  const cfg=runtimeConfig(dir); const adm=adminToken(cfg.dataDir); const session=sessionValue(adm);
  function isAdmin(req){const c=cookieMap(req.headers.cookie); return c.pag_session && safeEqual(c.pag_session,session);}
  function controlActor(req){const actor=service.authenticateToken(bearer(req));return actor?.kind==='control'?actor:null;}
  function requireAdmin(req){if(!isAdmin(req))throw Object.assign(new Error('Admin authentication required.'),{statusCode:401});}
  function requireCsrf(req){if(!['GET','HEAD'].includes(req.method) && req.headers['x-pag-csrf']!=='1')throw Object.assign(new Error('CSRF header missing.'),{statusCode:403});}
  function publicOrigin(req){if(cfg.publicBaseUrl)return cfg.publicBaseUrl.replace(/\/$/,'');const host=req.headers.host;if(!host)throw Object.assign(new Error('Host header is required for local OAuth callbacks.'),{statusCode:400});return `${req.socket.encrypted?'https':'http'}://${host}`;}
  function staticFile(pathname,res){const map={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/styles.css':'styles.css'};const file=map[pathname];if(!file)return false;try{const full=join(publicDir,file);const data=readFileSync(full);send(res,200,data,{'content-type':MIME[extname(file)]||'application/octet-stream'});return true;}catch{return false;}}

  const server=http.createServer(async(req,res)=>{
    res.setHeader('x-content-type-options','nosniff'); res.setHeader('referrer-policy','no-referrer'); res.setHeader('x-frame-options','DENY');
    res.setHeader('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const url=new URL(req.url,'http://localhost'); const p=url.pathname;
    try {
      if(req.method==='GET' && p==='/health') return sendJson(res,200,{ok:true,service:'personal-access-gateway',version:'1.2.0'});
      if(req.method==='POST' && p==='/auth/login') { const b=await bodyJson(req); if(!safeEqual(b.token||'',adm))return sendJson(res,401,{error:'Invalid admin token.'}); return sendJson(res,200,{ok:true},{'set-cookie':`pag_session=${encodeURIComponent(session)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`}); }
      if(req.method==='POST' && p==='/auth/logout') return sendJson(res,200,{ok:true},{'set-cookie':'pag_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
      if(req.method==='GET' && p==='/auth/me') return sendJson(res,200,{authenticated:!!isAdmin(req)});

      if(req.method==='GET' && /^\/oauth\/callback\/[^/]+$/.test(p)) {
        const provider=decodeURIComponent(p.split('/')[3]);
        try {
          const result=await service.completeOAuth(provider,{state:url.searchParams.get('state'),code:url.searchParams.get('code'),error:url.searchParams.get('error'),errorDescription:url.searchParams.get('error_description')});
          const label=htmlEscape(result.connection.account_label||result.connection.name);
          return send(res,200,`<!doctype html><html><head><meta charset="utf-8"><title>PAG OAuth complete</title></head><body><main><h1>Account connected</h1><p>${label} is now connected to PAG.</p><p>Agent access still defaults to <strong>No access</strong>.</p><p><a href="/">Return to PAG Control Center</a></p></main></body></html>`,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});
        } catch(e) {
          return send(res,e.statusCode||400,`<!doctype html><html><head><meta charset="utf-8"><title>PAG OAuth error</title></head><body><main><h1>Connection failed</h1><p>${htmlEscape(e.message||e)}</p><p><a href="/">Return to PAG Control Center</a></p></main></body></html>`,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});
        }
      }

      if(p.startsWith('/v1/admin/') || p.startsWith('/v1/approvals') || p.startsWith('/v1/actors') || p.startsWith('/v1/grants') || p.startsWith('/v1/vault') || p.startsWith('/v1/audit') || p.startsWith('/v1/connectors') || p.startsWith('/v1/providers') || p.startsWith('/v1/connections') || p.startsWith('/v1/access') || p.startsWith('/v1/oauth/')) { requireAdmin(req); requireCsrf(req); }

      if(req.method==='GET' && p==='/v1/control/approvals') { const actor=controlActor(req); if(!actor)return sendJson(res,401,{error:'Valid control bearer token required.'}); return sendJson(res,200,{approvals:service.listApprovals(url.searchParams.get('state')||'pending',Number(url.searchParams.get('limit')||100))}); }
      if(req.method==='POST' && /^\/v1\/control\/approvals\/[^/]+\/approve$/.test(p)) { const actor=controlActor(req); if(!actor)return sendJson(res,401,{error:'Valid control bearer token required.'}); const b=await bodyJson(req); const id=p.split('/')[4]; return sendJson(res,200,await service.approve(id,{decidedBy:`control:${actor.id}`,note:b.note||null,expectedArgsHash:b.expectedArgsHash||null})); }
      if(req.method==='POST' && /^\/v1\/control\/approvals\/[^/]+\/deny$/.test(p)) { const actor=controlActor(req); if(!actor)return sendJson(res,401,{error:'Valid control bearer token required.'}); const b=await bodyJson(req); const id=p.split('/')[4]; return sendJson(res,200,service.denyApproval(id,{decidedBy:`control:${actor.id}`,note:b.note||null})); }
      if(req.method==='GET' && p==='/v1/admin/summary') return sendJson(res,200,service.summary());
      if(req.method==='GET' && p==='/v1/admin/lockdown') return sendJson(res,200,{enabled:service.isLockdown()});
      if(req.method==='POST' && p==='/v1/admin/lockdown') { const b=await bodyJson(req); return sendJson(res,200,service.setLockdown(!!b.enabled,'admin-ui')); }
      if(req.method==='GET' && p==='/v1/actors') return sendJson(res,200,{actors:service.listActors()});
      if(req.method==='POST' && p==='/v1/actors') { const b=await bodyJson(req); return sendJson(res,201,service.createActor(b.name,b.kind||'agent')); }
      if(req.method==='POST' && /^\/v1\/actors\/[^/]+\/rotate-token$/.test(p)) return sendJson(res,200,service.rotateActorToken(p.split('/')[3]));
      if(req.method==='POST' && /^\/v1\/actors\/[^/]+\/status$/.test(p)) { const b=await bodyJson(req); return sendJson(res,200,service.setActorStatus(p.split('/')[3],b.status)); }
      if(req.method==='GET' && p==='/v1/grants') return sendJson(res,200,{grants:service.listGrants(url.searchParams.get('actorId'))});
      if(req.method==='POST' && p==='/v1/grants') { const b=await bodyJson(req); return sendJson(res,201,service.createGrant({actorId:b.actorId,capability:b.capability,effect:b.effect,priority:b.priority,conditions:b.conditions||{},expiresAt:b.expiresAt||null})); }
      if(req.method==='DELETE' && p.startsWith('/v1/grants/')) return sendJson(res,200,{deleted:service.revokeGrant(p.split('/').pop())});
      if(req.method==='GET' && p==='/v1/connectors') return sendJson(res,200,{connectors:service.connectors.list()});
      if(req.method==='GET' && p==='/v1/providers') return sendJson(res,200,service.listProviders());
      if(req.method==='POST' && /^\/v1\/oauth\/[^/]+\/start$/.test(p)) { const b=await bodyJson(req); const provider=decodeURIComponent(p.split('/')[3]); const redirectUri=`${publicOrigin(req)}/oauth/callback/${encodeURIComponent(provider)}`; return sendJson(res,201,service.startOAuth(provider,{scopes:b.scopes??null,connectionId:b.connectionId||null,redirectUri})); }
      if(req.method==='GET' && p==='/v1/connections') return sendJson(res,200,{connections:service.listConnections()});
      if(req.method==='POST' && p==='/v1/connections') { const b=await bodyJson(req); return sendJson(res,201,service.createConnection({name:b.name,connector:b.connector,accountLabel:b.accountLabel||null,vaultRef:b.vaultRef||null,metadata:b.metadata||{},authMethod:b.authMethod||null,scopes:b.scopes??null,externalAccountId:b.externalAccountId||null})); }
      if(req.method==='POST' && /^\/v1\/connections\/[^/]+\/status$/.test(p)) { const b=await bodyJson(req); return sendJson(res,200,service.setConnectionStatus(p.split('/')[3],b.status)); }
      if(req.method==='POST' && /^\/v1\/connections\/[^/]+\/scopes$/.test(p)) { const b=await bodyJson(req); return sendJson(res,200,service.setConnectionScopes(p.split('/')[3],b.scopes||[])); }
      if(req.method==='POST' && /^\/v1\/connections\/[^/]+\/health$/.test(p)) return sendJson(res,200,service.checkConnectionHealth(p.split('/')[3]));
      if(req.method==='POST' && /^\/v1\/connections\/[^/]+\/disconnect$/.test(p)) { const b=await bodyJson(req); return sendJson(res,200,service.disconnectConnection(p.split('/')[3],{deleteCredential:!!b.deleteCredential})); }
      if(req.method==='POST' && /^\/v1\/connections\/[^/]+\/reconnect$/.test(p)) { const b=await bodyJson(req); return sendJson(res,200,service.reconnectConnection(p.split('/')[3],b||{})); }
      if(req.method==='DELETE' && /^\/v1\/connections\/[^/]+$/.test(p)) return sendJson(res,200,{deleted:service.deleteConnection(p.split('/')[3])});
      if(req.method==='GET' && p==='/v1/access-matrix') return sendJson(res,200,service.accessMatrix());
      if(req.method==='GET' && p==='/v1/access') return sendJson(res,200,{access:service.listConnectionAccess({actorId:url.searchParams.get('actorId'),connectionId:url.searchParams.get('connectionId')})});
      if(req.method==='PUT' && /^\/v1\/access\/[^/]+\/[^/]+$/.test(p)) { const b=await bodyJson(req); const parts=p.split('/'); return sendJson(res,200,service.setConnectionAccess({connectionId:parts[3],actorId:parts[4],level:b.level,capabilities:b.capabilities||{}})); }
      if(req.method==='GET' && p==='/v1/vault') return sendJson(res,200,{entries:service.vault.list()});
      if(req.method==='POST' && p==='/v1/vault') { const b=await bodyJson(req); const meta=service.vault.put(b.name,b.value,{connector:b.connector||null,metadata:b.metadata||{}}); return sendJson(res,201,meta); }
      if(req.method==='DELETE' && p.startsWith('/v1/vault/')) return sendJson(res,200,{deleted:service.vault.delete(decodeURIComponent(p.slice('/v1/vault/'.length)))});
      if(req.method==='GET' && p==='/v1/audit') return sendJson(res,200,{events:service.audit.list(Number(url.searchParams.get('limit')||200)),verification:service.audit.verify()});

      if(req.method==='GET' && p==='/v1/approvals') return sendJson(res,200,{approvals:service.listApprovals(url.searchParams.get('state')||'pending',Number(url.searchParams.get('limit')||100))});
      if(req.method==='POST' && /^\/v1\/approvals\/[^/]+\/approve$/.test(p)) { const b=await bodyJson(req); const id=p.split('/')[3]; return sendJson(res,200,await service.approve(id,{decidedBy:'admin-ui',note:b.note||null,expectedArgsHash:b.expectedArgsHash||null})); }
      if(req.method==='POST' && /^\/v1\/approvals\/[^/]+\/deny$/.test(p)) { const b=await bodyJson(req); const id=p.split('/')[3]; return sendJson(res,200,service.denyApproval(id,{decidedBy:'admin-ui',note:b.note||null})); }
      if(req.method==='GET' && p==='/v1/admin/intents') return sendJson(res,200,{intents:service.listIntentDetails(Number(url.searchParams.get('limit')||100))});

      if(req.method==='POST' && p==='/v1/intents') { const actor=service.authenticateToken(bearer(req)); if(!actor)return sendJson(res,401,{error:'Valid actor bearer token required.'}); const b=await bodyJson(req); const value=await service.createIntent({actorId:actor.id,capability:b.capability,args:b.args||{},idempotencyKey:req.headers['x-pag-idempotency-key']||b.idempotencyKey||null}); return sendJson(res,201,value); }
      if(req.method==='GET' && /^\/v1\/intents\/[^/]+$/.test(p)) { const actor=service.authenticateToken(bearer(req)); const value=service.getIntent(p.split('/').pop()); if(!value)return sendJson(res,404,{error:'Intent not found.'}); if(!isAdmin(req) && (!actor || value.actor_id!==actor.id))return sendJson(res,403,{error:'Forbidden.'}); return sendJson(res,200,value); }

      if(req.method==='GET' && staticFile(p,res)) return;
      return sendJson(res,404,{error:'Not found.'});
    } catch(e) { const status=e.statusCode||500; if(status>=500) console.error(e); return sendJson(res,status,{error:String(e.message||e)}); }
  });
  return server;
}

export async function listen(service,{dir,host,port}={}) { const cfg=runtimeConfig(dir); const server=createServer(service,{dir:cfg.dataDir}); const h=host||cfg.host,p=port||cfg.port; await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(p,h,resolve)}); return {server,host:h,port:server.address().port}; }

#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dataDir, initSecrets, adminToken } from '../src/config.js';
import { openDb } from '../src/db.js';
import { PagService } from '../src/service.js';
import { listen } from '../src/server.js';

const argv=process.argv.slice(2); const cmd=argv[0];
function flag(name, fallback=null){const i=argv.indexOf(`--${name}`);return i>=0?(argv[i+1]??true):fallback}
function need(name){const v=flag(name);if(v===null||v===true)throw new Error(`Missing --${name}`);return v}
function out(v){console.log(typeof v==='string'?v:JSON.stringify(v,null,2))}
function help(){out(`Personal Access Gateway v1.0.0

Usage:
  pag init [--force]
  pag serve [--host 127.0.0.1] [--port 8787]
  pag doctor
  pag capabilities
  pag inspect <https://instagram.com/...|https://x.com/...>
  pag media fetch --handle pagm_... [--out ./file]
  pag actor create --name BIPAI [--kind agent]
  pag actor list
  pag grant add --actor ACTOR_ID --capability x.threads.create --effect ask [--priority 10] [--conditions '{"maxLength":{"text":280}}']
  pag grant list [--actor ACTOR_ID]
  pag grant revoke --id GRANT_ID
  pag intent submit --actor ACTOR_ID --capability noop.test --args '{"hello":"world"}' [--key UNIQUE_KEY]
  pag intent get --id INTENT_ID
  pag approvals list [--state pending]
  pag approvals approve --id APPROVAL_ID [--hash ARGS_HASH]
  pag approvals deny --id APPROVAL_ID
  pag vault put --name x.session --from-env X_SESSION [--connector x]
  pag vault list
  pag vault delete --name x.session
  pag audit list [--limit 100]
  pag audit verify

Set PAG_DATA_DIR to choose where the SQLite DB and local secrets live.`)}
function service(){const dir=dataDir();const db=openDb(dir);return new PagService(db,{dir})}

try{
  if(!cmd||cmd==='help'||cmd==='--help'||cmd==='-h'){help();process.exit(0)}
  if(cmd==='init'){
    const dir=dataDir();const result=initSecrets(dir,{force:argv.includes('--force')});const db=openDb(dir);new PagService(db,{dir});
    out({ok:true,dataDir:dir,created:result.created,adminTokenPath:result.adminPath,masterKeyPath:result.masterPath,adminToken:result.created?adminToken(dir):'(unchanged; read admin.token locally)'});process.exit(0);
  }
  const s=service();
  if(cmd==='serve'){
    const info=await listen(s,{dir:dataDir(),host:flag('host')||undefined,port:flag('port')?Number(flag('port')):undefined});out(`PAG Control Center: http://${info.host}:${info.port}\nData directory: ${dataDir()}\nPress Ctrl+C to stop.`);await new Promise(()=>{});
  } else if(cmd==='doctor'){
    let opencli; try{opencli=s.inspector.doctor();}catch(e){opencli={available:false,error:e.message};}
    out({ok:true,node:process.version,dataDir:dataDir(),summary:s.summary(),adminTokenPresent:!!adminToken(dataDir()),opencli});
  } else if(cmd==='capabilities') out(s.connectors.list());
  else if(cmd==='inspect') { const url=argv[1]; if(!url)throw new Error('Usage: pag inspect <url>'); out(await s.inspector.inspect(url)); }
  else if(cmd==='media'&&argv[1]==='fetch') out(await s.media.fetch(need('handle'),flag('out')));
  else if(cmd==='actor'&&argv[1]==='create') out(s.createActor(need('name'),flag('kind','agent')));
  else if(cmd==='actor'&&argv[1]==='list') out(s.listActors());
  else if(cmd==='grant'&&argv[1]==='add') out(s.createGrant({actorId:need('actor'),capability:need('capability'),effect:need('effect'),priority:Number(flag('priority',0)),conditions:JSON.parse(flag('conditions','{}')),expiresAt:flag('expires')}));
  else if(cmd==='grant'&&argv[1]==='list') out(s.listGrants(flag('actor')));
  else if(cmd==='grant'&&argv[1]==='revoke') out({revoked:s.revokeGrant(need('id'))});
  else if(cmd==='intent'&&argv[1]==='submit') out(await s.createIntent({actorId:need('actor'),capability:need('capability'),args:JSON.parse(flag('args','{}')),idempotencyKey:flag('key')}));
  else if(cmd==='intent'&&argv[1]==='get') out(s.getIntent(need('id')));
  else if(cmd==='approvals'&&argv[1]==='list') out(s.listApprovals(flag('state','pending')));
  else if(cmd==='approvals'&&argv[1]==='approve') out(await s.approve(need('id'),{decidedBy:'local-admin',expectedArgsHash:flag('hash')}));
  else if(cmd==='approvals'&&argv[1]==='deny') out(s.denyApproval(need('id'),{decidedBy:'local-admin'}));
  else if(cmd==='vault'&&argv[1]==='put') {const envName=need('from-env');const value=process.env[envName];if(!value)throw new Error(`Environment variable ${envName} is empty or missing.`);out(s.vault.put(need('name'),value,{connector:flag('connector')}));}
  else if(cmd==='vault'&&argv[1]==='list') out(s.vault.list());
  else if(cmd==='vault'&&argv[1]==='delete') out({deleted:s.vault.delete(need('name'))});
  else if(cmd==='audit'&&argv[1]==='list') out(s.audit.list(Number(flag('limit',100))));
  else if(cmd==='audit'&&argv[1]==='verify') out(s.audit.verify());
  else {help();process.exitCode=2}
}catch(e){console.error(`PAG error: ${e.message}`);process.exitCode=1}

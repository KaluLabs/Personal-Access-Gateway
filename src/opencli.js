import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

let cachedInvocation = null;

export function resolveOpenCliInvocation() {
  if (process.env.PAG_OPENCLI_ENTRY) return { command: process.execPath, prefixArgs:[process.env.PAG_OPENCLI_ENTRY], source:process.env.PAG_OPENCLI_ENTRY };
  if (cachedInvocation) return cachedInvocation;
  if (process.platform !== 'win32') {
    cachedInvocation = { command:'opencli', prefixArgs:[], source:'PATH' };
    return cachedInvocation;
  }
  const roots=[];
  const where=spawnSync('where.exe',['opencli'],{encoding:'utf8',windowsHide:true});
  if(!where.error&&where.status===0&&where.stdout){for(const line of where.stdout.split(/\r?\n/)){const shim=line.trim();if(shim)roots.push(path.dirname(shim));}}
  if(process.env.APPDATA) roots.push(path.join(process.env.APPDATA,'npm'));
  for(const root of [...new Set(roots)]){
    const entry=path.join(root,'node_modules','@jackwener','opencli','dist','src','main.js');
    if(existsSync(entry)){cachedInvocation={command:process.execPath,prefixArgs:[entry],source:entry};return cachedInvocation;}
  }
  throw new Error('OpenCLI is not available. Install/configure @jackwener/opencli or set PAG_OPENCLI_ENTRY to its main.js.');
}

export function runOpenCli(args,{allowFailure=false,inherit=false}={}){
  let invocation;
  try{invocation=resolveOpenCliInvocation();}catch(e){if(allowFailure)return{ok:false,stdout:'',stderr:e.message};throw e;}
  const result=spawnSync(invocation.command,[...invocation.prefixArgs,...args],{encoding:'utf8',stdio:inherit?'inherit':['ignore','pipe','pipe'],windowsHide:true});
  if(result.error){if(allowFailure)return{ok:false,stdout:'',stderr:result.error.message};throw new Error(`Could not run OpenCLI: ${result.error.message}`);}
  const stdout=(result.stdout||'').trim(),stderr=(result.stderr||'').trim();
  if(result.status!==0){if(allowFailure)return{ok:false,stdout,stderr};throw new Error(stderr||stdout||`OpenCLI exited with code ${result.status}`);}
  return{ok:true,stdout,stderr};
}

export function parseJsonOutput(stdout){
  const text=String(stdout||'').trim();if(!text)throw new Error('OpenCLI returned no data.');
  try{return JSON.parse(text);}catch{}
  const starts=[text.indexOf('{'),text.indexOf('[')].filter(n=>n>=0);if(!starts.length)throw new Error(`OpenCLI returned non-JSON output: ${text.slice(0,240)}`);
  const start=Math.min(...starts),end=Math.max(text.lastIndexOf('}'),text.lastIndexOf(']'));if(end<=start)throw new Error(`Could not isolate JSON from OpenCLI output: ${text.slice(0,240)}`);
  return JSON.parse(text.slice(start,end+1));
}

export function openCliDoctor(){
  const invocation=resolveOpenCliInvocation();const result=runOpenCli(['doctor'],{allowFailure:true});return{available:result.ok,source:invocation.source,stdout:result.stdout,stderr:result.stderr};
}

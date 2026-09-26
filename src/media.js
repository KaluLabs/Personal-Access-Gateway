import { mkdirSync, writeFileSync } from 'node:fs';
import { extname, join } from 'node:path';
import { encryptSecret, decryptSecret } from './crypto.js';
import { json, nowIso, parseJson, randomId } from './util.js';

const MIME_EXT={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp','video/mp4':'.mp4','video/webm':'.webm','audio/mpeg':'.mp3'};
export class MediaRegistry {
  constructor(db,key,{dir,audit}={}){this.db=db;this.key=key;this.dir=dir;this.audit=audit;}
  register(url,metadata={},ttlMinutes=120){
    if(typeof url!=='string'||!/^https:\/\//i.test(url))return null;
    const handle=randomId('pagm_');const enc=encryptSecret(this.key,url,`pag:media:${handle}`);const created=nowIso();const expires=ttlMinutes?new Date(Date.now()+ttlMinutes*60_000).toISOString():null;
    this.db.prepare('INSERT INTO media_handles(handle,ciphertext,iv,tag,metadata_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?)').run(handle,enc.ciphertext,enc.iv,enc.tag,json(metadata),created,expires);
    return handle;
  }
  resolve(handle){const row=this.db.prepare('SELECT * FROM media_handles WHERE handle=?').get(handle);if(!row)return null;if(row.expires_at&&row.expires_at<=nowIso())throw Object.assign(new Error('Media handle expired.'),{statusCode:410});return{url:decryptSecret(this.key,row,`pag:media:${handle}`),metadata:parseJson(row.metadata_json,{}),created_at:row.created_at,expires_at:row.expires_at};}
  metadata(handle){const row=this.db.prepare('SELECT handle,metadata_json,created_at,expires_at FROM media_handles WHERE handle=?').get(handle);return row?{handle:row.handle,metadata:parseJson(row.metadata_json,{}),created_at:row.created_at,expires_at:row.expires_at}:null;}
  async fetch(handle,outPath=null,{maxBytes=100*1024*1024}={}){
    const r=this.resolve(handle);if(!r)throw Object.assign(new Error('Media handle not found.'),{statusCode:404});
    const res=await fetch(r.url,{redirect:'follow'});if(!res.ok)throw new Error(`Media fetch failed with HTTP ${res.status}.`);
    const len=Number(res.headers.get('content-length')||0);if(len&&len>maxBytes)throw new Error('Media exceeds configured fetch limit.');
    const buf=Buffer.from(await res.arrayBuffer());if(buf.length>maxBytes)throw new Error('Media exceeds configured fetch limit.');
    const type=(res.headers.get('content-type')||'').split(';')[0].trim();let ext=MIME_EXT[type]||extname(new URL(r.url).pathname)||'.bin';if(ext.length>8)ext='.bin';
    if(!outPath){const mediaDir=join(this.dir,'media');mkdirSync(mediaDir,{recursive:true,mode:0o700});outPath=join(mediaDir,`${handle}${ext}`);}
    writeFileSync(outPath,buf,{mode:0o600});this.audit?.append('local-admin','media.fetched',handle,{path:outPath,bytes:buf.length,contentType:type});return{handle,path:outPath,bytes:buf.length,contentType:type};
  }
}

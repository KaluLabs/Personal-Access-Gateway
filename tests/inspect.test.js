import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initSecrets, masterKey } from '../src/config.js';
import { openDb } from '../src/db.js';
import { MediaRegistry } from '../src/media.js';
import { parseInstagramUrl, parseXUrl, routeInspectUrl, shortcodeToMediaId } from '../src/inspect.js';

test('inspect router canonicalizes Instagram and X and rejects Reddit',()=>{
  const ig=parseInstagramUrl('https://www.instagram.com/reel/DWy7CpTDbH1/?utm_source=x'); assert.equal(ig.canonicalUrl,'https://www.instagram.com/reel/DWy7CpTDbH1/'); assert.equal(shortcodeToMediaId('DWy7CpTDbH1'),'3869414696390865397');
  const x=parseXUrl('https://twitter.com/example/status/12345?s=20'); assert.equal(x.canonicalUrl,'https://x.com/example/status/12345'); assert.equal(routeInspectUrl(x.canonicalUrl).platform,'x');
  assert.throws(()=>routeInspectUrl('https://reddit.com/r/test/comments/abc'),/intentionally unsupported/i);
});

test('media registry hides the original URL behind encrypted opaque handles',()=>{
  const dir=mkdtempSync(join(tmpdir(),'pag-media-'));initSecrets(dir);const db=openDb(dir);try{const reg=new MediaRegistry(db,masterKey(dir),{dir});const url='https://example.com/private-signed-media.jpg?sig=secret';const h=reg.register(url,{kind:'image'});assert.match(h,/^pagm_/);assert.equal(reg.resolve(h).url,url);const row=db.prepare('SELECT ciphertext FROM media_handles WHERE handle=?').get(h);assert.equal(String(row.ciphertext).includes('example.com'),false);assert.equal(JSON.stringify(reg.metadata(h)).includes('private-signed-media'),false)}finally{db.close();rmSync(dir,{recursive:true,force:true})}
});

const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const state = { tab: 'overview' };

async function api(path, opts={}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'content-type':'application/json', 'x-pag-csrf':'1', ...(opts.headers||{}) }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function pill(v) { return `<span class="pill ${esc(v)}">${esc(v)}</span>`; }
function handoffs(i) {
  const hs = i.execution?.result?.handoffs;
  if (!Array.isArray(hs) || !hs.length) return '';
  return `<div class="panel" style="margin-top:10px"><b>Approved handoff</b>${hs.map((h,idx)=>`<div class="item"><div class="muted">Step ${idx+1}</div><p>${esc(h.instruction || 'Open the approved destination to complete the action.')}</p><pre>${esc(h.text || '')}</pre><a class="buttonlink" href="${esc(h.url)}" target="_blank" rel="noopener noreferrer">Open destination</a></div>`).join('')}</div>`;
}
async function boot() {
  const me = await api('/auth/me');
  $('#login').hidden = me.authenticated;
  $('#app').hidden = !me.authenticated;
  if (me.authenticated) render();
}
$('#loginForm').onsubmit = async e => {
  e.preventDefault(); $('#loginError').textContent='';
  try { await api('/auth/login',{method:'POST',body:JSON.stringify({token:$('#adminToken').value})}); $('#adminToken').value=''; boot(); }
  catch(err) { $('#loginError').textContent=err.message; }
};
$('#logout').onclick = async () => { await api('/auth/logout',{method:'POST',body:'{}'}); boot(); };
$$('nav button').forEach(b => b.onclick = () => {
  state.tab=b.dataset.tab; $$('nav button').forEach(x=>x.classList.toggle('active',x===b)); render();
});
async function render() {
  const v=$('#view'); v.innerHTML='<div class="muted">Loading…</div>';
  try {
    if(state.tab==='overview') return overview(v);
    if(state.tab==='approvals') return approvals(v);
    if(state.tab==='actors') return actors(v);
    if(state.tab==='connections') return connections(v);
    if(state.tab==='intents') return intents(v);
    if(state.tab==='vault') return vault(v);
    if(state.tab==='audit') return audit(v);
  } catch(e) { v.innerHTML=`<div class="card error">${esc(e.message)}</div>`; }
}
async function overview(v) {
  const d=await api('/v1/admin/summary');
  v.innerHTML=`<div class="row space"><h2>Gateway overview</h2><button id="lockdownBtn" class="${d.lockdown?'danger':'secondary'}">${d.lockdown?'Disable lockdown':'Enable lockdown'}</button></div>${d.lockdown?'<div class="panel error"><b>LOCKDOWN ACTIVE</b><p>All new agent intents are denied before normal policy evaluation.</p></div>':''}<div class="grid">${[['Actors',d.actors],['Connections',d.connections],['Grants',d.grants],['Pending approvals',d.pendingApprovals],['Intents',d.intents],['Succeeded',d.succeeded],['Failed',d.failed]].map(([k,n])=>`<div class="panel"><div class="muted">${k}</div><div class="metric">${n}</div></div>`).join('')}</div>
  <div class="two" style="margin-top:16px"><div class="panel"><h3>Audit integrity</h3><p>${d.audit.ok?'<span class="success">Verified</span>':'<span class="error">Broken</span>'}</p><div class="mono">events: ${esc(d.audit.count??'—')}<br>head: ${esc(d.audit.head??'—')}</div></div><div class="panel"><h3>Connectors</h3>${d.connectors.map(c=>`<div class="item"><b>${esc(c.capability)}</b><div class="muted">${esc(c.connector)}${c.connectionType?` · connection: ${esc(c.connectionType)}`:''}</div></div>`).join('')}</div></div>`;
  $('#lockdownBtn').onclick=async()=>{await api('/v1/admin/lockdown',{method:'POST',body:JSON.stringify({enabled:!d.lockdown})});overview(v);};
}
async function approvals(v) {
  const d=await api('/v1/approvals?state=pending');
  v.innerHTML=`<div class="row space"><h2>Pending approvals</h2><button id="refreshA" class="secondary">Refresh</button></div><div class="stack">${d.approvals.length?d.approvals.map(a=>`<div class="item"><div class="row space"><div><b>${esc(a.capability)}</b> ${pill(a.state)}</div><span class="muted">expires ${esc(a.expires_at)}</span></div><p class="mono">${esc(a.args_hash)}</p><pre>${esc(JSON.stringify(a.intent?.args||{},null,2))}</pre><div class="row"><button data-approve="${esc(a.id)}" data-hash="${esc(a.args_hash)}">Approve exact payload</button><button class="danger" data-deny="${esc(a.id)}">Deny</button></div></div>`).join(''):'<div class="empty">No pending approvals.</div>'}</div>`;
  $('#refreshA').onclick=()=>approvals(v);
  $$('[data-approve]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/approvals/${b.dataset.approve}/approve`,{method:'POST',body:JSON.stringify({expectedArgsHash:b.dataset.hash})});state.tab='intents';$$('nav button').forEach(x=>x.classList.toggle('active',x.dataset.tab==='intents'));render();});
  $$('[data-deny]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/approvals/${b.dataset.deny}/deny`,{method:'POST',body:'{}'});approvals(v);});
}
async function actors(v) {
  const [a,g,c]=await Promise.all([api('/v1/actors'),api('/v1/grants'),api('/v1/connectors')]);
  v.innerHTML=`<div class="two"><div class="panel"><h3>Create actor</h3><form id="actorForm"><input name="name" placeholder="e.g. BIPAI or WhatsApp Control" required><select name="kind"><option value="agent">agent</option><option value="control">control</option></select><button>Create actor + token</button></form><div id="actorToken"></div></div><div class="panel"><h3>Create grant</h3><form id="grantForm"><select name="actorId" required><option value="">Actor…</option>${a.actors.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('')}</select><select name="capability">${c.connectors.map(x=>`<option>${esc(x.capability)}</option>`).join('')}</select><select name="effect"><option>ask</option><option>allow</option><option>deny</option></select><input name="priority" type="number" value="0"><textarea name="conditions" placeholder='Optional conditions JSON, e.g. {"maxLength":{"text":280}}'></textarea><button>Create grant</button></form></div></div>
  <h3>Actors</h3><div class="stack">${a.actors.map(x=>`<div class="item row space"><div><b>${esc(x.name)}</b> ${pill(x.status)} <span class="muted">${esc(x.kind)}</span><div class="mono">${esc(x.id)}</div></div><div class="row"><button class="secondary small" data-rotate="${esc(x.id)}">Rotate token</button>${x.status==='active'?`<button class="danger small" data-status="${esc(x.id)}" data-next="revoked">Revoke</button>`:`<button class="small" data-status="${esc(x.id)}" data-next="active">Reactivate</button>`}</div></div>`).join('')||'<div class="empty">No actors.</div>'}</div>
  <h3>Grants</h3><div class="stack">${g.grants.map(x=>`<div class="item row space"><div><b>${esc(x.capability)}</b> ${pill(x.effect)} <span class="muted">priority ${esc(x.priority)}</span><div class="mono">${esc(x.actor_id)}</div><pre>${esc(JSON.stringify(x.conditions||{},null,2))}</pre></div><button class="danger small" data-revoke="${esc(x.id)}">Revoke grant</button></div>`).join('')||'<div class="empty">No grants.</div>'}</div>`;
  $('#actorForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);const d=await api('/v1/actors',{method:'POST',body:JSON.stringify({name:fd.get('name'),kind:fd.get('kind')||'agent'})});$('#actorToken').innerHTML=`<p class="success">Copy this token now; PAG will not show it again.</p><pre>${esc(d.token)}</pre>`;};
  $('#grantForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);let conditions={};if(fd.get('conditions')?.trim())conditions=JSON.parse(fd.get('conditions'));await api('/v1/grants',{method:'POST',body:JSON.stringify({actorId:fd.get('actorId'),capability:fd.get('capability'),effect:fd.get('effect'),priority:Number(fd.get('priority')||0),conditions})});actors(v);};
  $$('[data-revoke]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/grants/${b.dataset.revoke}`,{method:'DELETE'});actors(v);});
  $$('[data-status]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/actors/${b.dataset.status}/status`,{method:'POST',body:JSON.stringify({status:b.dataset.next})});actors(v);});
  $$('[data-rotate]',v).forEach(b=>b.onclick=async()=>{const d=await api(`/v1/actors/${b.dataset.rotate}/rotate-token`,{method:'POST',body:'{}'});$('#actorToken').innerHTML=`<p class="success">Old token invalidated. Copy the replacement now.</p><pre>${esc(d.token)}</pre>`;});
}
async function connections(v) {
  const [d,vault]=await Promise.all([api('/v1/connections'),api('/v1/vault')]);
  v.innerHTML=`<div class="two"><div class="panel"><h3>Create connection</h3><p class="muted">Connections are account metadata + optional vault references. Agents never receive the secret value.</p><form id="connectionForm"><input name="name" placeholder="e.g. Personal X" required><select name="connector"><option value="x">x</option><option value="linkedin">linkedin</option></select><input name="accountLabel" placeholder="account label / handle"><select name="vaultRef"><option value="">No vault secret</option>${vault.entries.map(x=>`<option value="${esc(x.name)}">${esc(x.name)}</option>`).join('')}</select><button>Create connection</button></form></div><div><h3>Connections</h3><div class="stack">${d.connections.map(x=>`<div class="item row space"><div><b>${esc(x.name)}</b> ${pill(x.status)}<div class="muted">${esc(x.connector)} · ${esc(x.account_label||'unlabelled')} · vault=${esc(x.vault_ref||'none')}</div><div class="mono">${esc(x.id)}</div></div><div class="row">${x.status==='active'?`<button class="secondary small" data-cstatus="${esc(x.id)}" data-next="disabled">Disable</button>`:`<button class="small" data-cstatus="${esc(x.id)}" data-next="active">Enable</button>`}<button class="danger small" data-cdelete="${esc(x.id)}">Delete</button></div></div>`).join('')||'<div class="empty">No connections.</div>'}</div></div></div>`;
  $('#connectionForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);await api('/v1/connections',{method:'POST',body:JSON.stringify(Object.fromEntries(fd))});connections(v);};
  $$('[data-cstatus]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/connections/${b.dataset.cstatus}/status`,{method:'POST',body:JSON.stringify({status:b.dataset.next})});connections(v);});
  $$('[data-cdelete]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/connections/${b.dataset.cdelete}`,{method:'DELETE'});connections(v);});
}
async function intents(v) {
  const d=await api('/v1/admin/intents');
  v.innerHTML=`<h2>Intents</h2><div class="stack">${d.intents.map(i=>`<div class="item"><div class="row space"><b>${esc(i.capability)}</b>${pill(i.status)}</div><div class="mono">${esc(i.id)} · ${esc(i.actor_id)}<br>${esc(i.args_hash)}</div><pre>${esc(JSON.stringify(i.args,null,2))}</pre>${i.approval?`<div class="muted">approval: ${esc(i.approval.state)} · ${esc(i.approval.id)}</div>`:''}${handoffs(i)}${i.execution?.error_text?`<p class="error">${esc(i.execution.error_text)}</p>`:''}</div>`).join('')||'<div class="empty">No intents.</div>'}</div>`;
}
async function vault(v) {
  const d=await api('/v1/vault');
  v.innerHTML=`<div class="two"><div class="panel"><h3>Add/update secret</h3><p class="muted">Secret values are encrypted with AES-256-GCM. They are never returned by the API.</p><form id="vaultForm"><input name="name" placeholder="credential name" required><input name="connector" placeholder="connector (optional)"><input name="value" type="password" placeholder="secret value" autocomplete="off" required><button>Store secret</button></form></div><div><h3>Vault metadata</h3><div class="stack">${d.entries.map(x=>`<div class="item row space"><div><b>${esc(x.name)}</b><div class="muted">${esc(x.connector||'unscoped')}</div></div><button class="danger small" data-delvault="${encodeURIComponent(x.name)}">Delete</button></div>`).join('')||'<div class="empty">Vault is empty.</div>'}</div></div></div>`;
  $('#vaultForm').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);await api('/v1/vault',{method:'POST',body:JSON.stringify(Object.fromEntries(fd))});e.target.reset();vault(v);};
  $$('[data-delvault]',v).forEach(b=>b.onclick=async()=>{await api(`/v1/vault/${b.dataset.delvault}`,{method:'DELETE'});vault(v);});
}
async function audit(v) {
  const d=await api('/v1/audit?limit=200');
  v.innerHTML=`<div class="row space"><h2>Audit log</h2><div>${d.verification.ok?'<span class="success">chain verified</span>':'<span class="error">chain broken</span>'}</div></div><div class="stack">${d.events.map(x=>`<div class="item"><div class="row space"><b>${esc(x.event_type)}</b><span class="muted">${esc(x.ts)}</span></div><div class="mono">actor=${esc(x.actor)} subject=${esc(x.subject_id||'—')}<br>hash=${esc(x.event_hash)}</div><pre>${esc(JSON.stringify(x.data,null,2))}</pre></div>`).join('')||'<div class="empty">No audit events.</div>'}</div>`;
}
boot();

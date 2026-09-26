// Transport-neutral PAG Control Line example.
// A Baileys or official WhatsApp bridge can call these functions after it has
// authenticated the human user on WhatsApp. The bridge gets a PAG `control`
// actor token, never the PAG admin token or vault secrets.

const baseUrl = process.env.PAG_URL || 'http://127.0.0.1:8787';
const token = process.env.PAG_CONTROL_TOKEN;
if (!token) throw new Error('PAG_CONTROL_TOKEN is required');

async function request(path, options={}) {
  const r = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: { authorization:`Bearer ${token}`, 'content-type':'application/json', ...(options.headers||{}) }
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

export async function pendingApprovals() {
  return (await request('/v1/control/approvals?state=pending')).approvals;
}

export async function approveExact(approval) {
  return request(`/v1/control/approvals/${approval.id}/approve`, {
    method:'POST',
    body:JSON.stringify({ expectedArgsHash:approval.args_hash, note:'approved from WhatsApp control line' })
  });
}

export async function deny(approvalId) {
  return request(`/v1/control/approvals/${approvalId}/deny`, {
    method:'POST',
    body:JSON.stringify({ note:'denied from WhatsApp control line' })
  });
}

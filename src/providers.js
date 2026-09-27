const PROVIDERS = [
  {
    id: 'x',
    name: 'X / Twitter',
    description: 'Read X posts through an authenticated browser and create approval-gated browser handoffs for posts and threads.',
    authMethods: [
      { id: 'browser', label: 'Authenticated browser', description: 'Uses the signed-in browser session; credentials are never given to agents.' },
    ],
    defaultAuthMethod: 'browser',
    scopes: [
      { id: 'read', label: 'Read posts', description: 'Inspect posts and conversations.', mode: 'read' },
      { id: 'publish', label: 'Publish posts', description: 'Create approved post/thread browser handoffs.', mode: 'write' },
    ],
    defaultScopes: ['read'],
    capabilities: [
      { id: 'x.posts.inspect', label: 'Inspect posts', mode: 'read', requiredScope: 'read' },
      { id: 'x.threads.create', label: 'Publish posts / threads', mode: 'write', requiredScope: 'publish' },
    ],
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    description: 'Create approval-gated LinkedIn browser handoffs without exposing account credentials to agents.',
    authMethods: [
      { id: 'browser', label: 'Authenticated browser', description: 'Completes approved actions in the signed-in browser.' },
    ],
    defaultAuthMethod: 'browser',
    scopes: [
      { id: 'publish', label: 'Publish posts', description: 'Create approved LinkedIn post handoffs.', mode: 'write' },
    ],
    defaultScopes: ['publish'],
    capabilities: [
      { id: 'linkedin.posts.create', label: 'Publish posts', mode: 'write', requiredScope: 'publish' },
    ],
  },
  {
    id: 'instagram',
    name: 'Instagram',
    description: 'Inspect Instagram posts, reels, and TV media through an authenticated browser session.',
    authMethods: [
      { id: 'browser', label: 'Authenticated browser', description: 'Uses the signed-in browser through OpenCLI.' },
    ],
    defaultAuthMethod: 'browser',
    scopes: [
      { id: 'read', label: 'Read media', description: 'Inspect posts, reels, captions, statistics, and media.', mode: 'read' },
    ],
    defaultScopes: ['read'],
    capabilities: [
      { id: 'instagram.media.inspect', label: 'Inspect media', mode: 'read', requiredScope: 'read' },
    ],
  },
];

export const ACCESS_LEVELS = [
  { id: 'none', label: 'No access', description: 'The agent cannot use this account.' },
  { id: 'read', label: 'Read only', description: 'Read capabilities execute; write capabilities are denied.' },
  { id: 'ask', label: 'Ask before actions', description: 'Reads execute automatically; writes require approval.' },
  { id: 'automatic', label: 'Automatic', description: 'All capabilities allowed by the account scopes can execute without per-action approval.' },
  { id: 'custom', label: 'Custom', description: 'Choose allow, ask, or deny per capability.' },
];

function clone(value) { return JSON.parse(JSON.stringify(value)); }

export function listProviders() { return clone(PROVIDERS); }
export function getProvider(id) { const p=PROVIDERS.find(x=>x.id===id); return p ? clone(p) : null; }
export function providerCapability(providerId, capability) {
  const p=PROVIDERS.find(x=>x.id===providerId);
  return p?.capabilities.find(x=>x.id===capability) || null;
}
export function normalizeScopes(providerId, scopes) {
  const p=PROVIDERS.find(x=>x.id===providerId);
  if (!p) return [...new Set((Array.isArray(scopes)?scopes:[]).map(String))];
  const allowed=new Set(p.scopes.map(x=>x.id));
  const requested=Array.isArray(scopes)?scopes:p.defaultScopes;
  const normalized=[...new Set((requested||[]).map(String))];
  const bad=normalized.filter(x=>!allowed.has(x));
  if (bad.length) throw new Error(`Unsupported ${providerId} scope(s): ${bad.join(', ')}`);
  return normalized;
}
export function validateAuthMethod(providerId, authMethod) {
  const p=PROVIDERS.find(x=>x.id===providerId);
  if (!p) return authMethod || 'manual';
  const value=authMethod || p.defaultAuthMethod;
  if (!p.authMethods.some(x=>x.id===value)) throw new Error(`Unsupported ${providerId} authentication method: ${value}`);
  return value;
}

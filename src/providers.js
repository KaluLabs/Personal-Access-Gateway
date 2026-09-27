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
  {
    id: 'github',
    name: 'GitHub',
    description: 'Connect a GitHub identity through OAuth 2.0 authorization code + PKCE. Repository automation should prefer a GitHub App for fine-grained permissions.',
    authMethods: [
      { id: 'oauth', label: 'OAuth 2.0 + PKCE', description: 'Redirects you to GitHub, validates state + PKCE, and stores the resulting token only inside the encrypted PAG vault.' },
    ],
    defaultAuthMethod: 'oauth',
    scopes: [
      { id: 'profile', label: 'Profile', description: 'Read your GitHub profile identity.', mode: 'read', oauthScopes: ['read:user','offline_access'] },
    ],
    defaultScopes: ['profile'],
    capabilities: [
      { id: 'github.user.read', label: 'Read authenticated user', mode: 'read', requiredScope: 'profile' },
    ],
    oauth: {
      clientIdEnv: 'PAG_OAUTH_GITHUB_CLIENT_ID',
      clientSecretEnv: 'PAG_OAUTH_GITHUB_CLIENT_SECRET',
      authorizationUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userInfoUrl: 'https://api.github.com/user',
      tokenHeaders: { Accept: 'application/json' },
      userInfoHeaders: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'PAG' },
      profile: { idField: 'id', labelFields: ['login','name'], metadataFields: ['login','name','email','avatar_url','html_url'] },
    },
  },
  {
    id: 'google',
    name: 'Google',
    description: 'Connect a Google identity through OAuth 2.0 / OpenID Connect with PKCE and offline refresh access.',
    authMethods: [
      { id: 'oauth', label: 'OAuth 2.0 + PKCE', description: 'Uses Google consent, state + PKCE, and encrypted access/refresh-token storage inside PAG.' },
    ],
    defaultAuthMethod: 'oauth',
    scopes: [
      { id: 'profile', label: 'Profile', description: 'Read your Google account identity, name, email, and profile picture.', mode: 'read', oauthScopes: ['openid','profile','email'] },
    ],
    defaultScopes: ['profile'],
    capabilities: [
      { id: 'google.user.read', label: 'Read authenticated user', mode: 'read', requiredScope: 'profile' },
    ],
    oauth: {
      clientIdEnv: 'PAG_OAUTH_GOOGLE_CLIENT_ID',
      clientSecretEnv: 'PAG_OAUTH_GOOGLE_CLIENT_SECRET',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
      authorizeParams: { access_type: 'offline', include_granted_scopes: 'true', prompt: 'consent' },
      profile: { idField: 'sub', labelFields: ['email','name'], metadataFields: ['name','email','email_verified','picture','hd'] },
    },
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

export function oauthScopesForProvider(providerId, logicalScopes) {
  const p=PROVIDERS.find(x=>x.id===providerId);
  if(!p?.oauth) return [];
  const logical=normalizeScopes(providerId,logicalScopes);
  return [...new Set(logical.flatMap(id=>p.scopes.find(s=>s.id===id)?.oauthScopes||[]))];
}

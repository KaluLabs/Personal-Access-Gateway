# Provider and connector model

PAG separates **provider metadata** from **capability execution**.

A provider manifest describes the human-facing account model: authentication methods, account scopes, and capabilities. An executor registered in `ConnectorRegistry` performs a capability. Keeping these separate lets the Control Center explain permissions without giving an agent credentials or coupling the policy engine to a particular vendor.

## Provider manifest

A provider entry in `src/providers.js` has this shape:

```js
{
  id: 'example',
  name: 'Example Service',
  authMethods: [
    { id: 'oauth', label: 'OAuth', description: '...' }
  ],
  defaultAuthMethod: 'oauth',
  scopes: [
    { id: 'read', label: 'Read data', mode: 'read' },
    { id: 'write', label: 'Write data', mode: 'write' }
  ],
  defaultScopes: ['read'],
  capabilities: [
    { id: 'example.items.read', label: 'Read items', mode: 'read', requiredScope: 'read' },
    { id: 'example.items.create', label: 'Create items', mode: 'write', requiredScope: 'write' }
  ]
}
```

Capability `mode` is used by the human-readable access levels:

- `none`: deny every account-bound capability.
- `read`: allow read capabilities; deny writes.
- `ask`: allow reads; require approval for writes.
- `automatic`: allow capabilities permitted by the account scopes.
- `custom`: use an explicit per-capability allow/ask/deny map.

## Executor contract

Register an executor in `ConnectorRegistry`:

```js
registry.register('example.items.create', {
  name: 'example-api',
  connectionType: 'example',
  execute: async ({ intent, args, vault, connection }) => {
    // Decrypt credentials only inside this trusted connector boundary.
    // Never return raw credentials in the result.
    return { ok: true };
  }
});
```

`connectionType` binds the capability to the correct provider. PAG checks the selected connection, provider scope, and agent-account access before calling `execute`, then checks again immediately before execution so a downgrade or disconnect invalidates stale approvals.

## Authentication adapters

PAG v1.2 supports two authentication families:

- `browser`: X, LinkedIn, and Instagram continue to use the authenticated-browser model.
- `oauth`: GitHub and Google use the authorization-code flow with state + S256 PKCE.

The generic OAuth adapter:

1. Generates random state and a PKCE verifier.
2. Stores only a hash of state and encrypts the verifier before persistence.
3. Exchanges the callback code only inside PAG.
4. Encrypts access/refresh tokens in the PAG vault.
5. Stores only non-secret account metadata on the connection row.
6. Refreshes expiring access tokens inside the gateway when a refresh token is available.
7. Requires provider reauthorization before an OAuth scope elevation becomes active.

See `docs/OAUTH.md` for deployment configuration and callback URLs.

Provider-specific remote token revocation is intentionally separate from local disconnect/delete semantics in v1.2. Disconnect immediately prevents PAG use; deleting the local credential removes PAG's encrypted copy.

## Open-source contribution rule

A new provider should include its manifest, executor(s), tests for scope and connection-type enforcement, and documentation of any provider-specific authentication or rate-limit behavior. Provider code must never return raw credentials to actors or write secret values to the audit log.

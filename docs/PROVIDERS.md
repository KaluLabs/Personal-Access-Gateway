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

PAG v1.1 ships browser-backed manifests for X, LinkedIn, and Instagram. The manifest format is intentionally ready for `oauth`, `api_key`, or local-session adapters, but v1.1 does not pretend that a provider OAuth flow exists where one has not been implemented.

A future OAuth adapter should:

1. Generate state/PKCE and redirect the human to the provider.
2. Exchange the callback only inside PAG.
3. Encrypt refresh/access credentials in the PAG vault.
4. Store only non-secret account metadata on the connection row.
5. Revoke provider credentials on disconnect when the provider supports revocation.
6. Require reauthorization when newly requested scopes cannot be granted locally.

## Open-source contribution rule

A new provider should include its manifest, executor(s), tests for scope and connection-type enforcement, and documentation of any provider-specific authentication or rate-limit behavior. Provider code must never return raw credentials to actors or write secret values to the audit log.

# PAG v1.1.0 release notes

PAG v1.1 turns the v1 security core into an account-access control product.

## Connections

- Provider catalog for X, LinkedIn, and Instagram.
- Browser-backed account registration with logical account scopes.
- Connection cards with lifecycle, configuration health, account scopes, and agent usage count.
- Disable/enable, disconnect/reconnect, and scope elevation/downgrade.
- Disconnect preserves audit history and can optionally remove an unshared vault credential.

## Access management

- New agent × account access matrix.
- Levels: No access, Read only, Ask before actions, Automatic, and Custom.
- Every new or migrated agent/account pair defaults to No access.
- Account-bound capabilities require an explicit `connectionId`.
- Provider type and account scope are enforced before authorization.
- Access is revalidated immediately before execution so stale approvals cannot survive a downgrade or disconnect.

## Open source extension surface

- Added provider manifests separate from connector executors.
- Added `docs/PROVIDERS.md` with the provider/executor contract and OAuth adapter expectations.
- Added CLI and HTTP APIs for connection lifecycle, scopes, provider discovery, and access management.

## Upgrade

The SQLite migration from v1.0 is additive. Existing agent × connection pairs are initialized to No access as a deliberate fail-closed migration. See `docs/MIGRATION-v1.0.0.md`.

## Verification

The v1.1 regression suite covers the v1 security invariants plus account access defaults, access-level behavior, scope downgrade, disconnect/reconnect, stale-approval invalidation, dashboard APIs, and additive database migration.

# Migrating PAG v1.1.0 to v1.2.0

v1.2 performs an additive SQLite migration when the database is opened.

## Added storage

The migration adds the `oauth_flows` table for short-lived authorization-code/PKCE transactions. Existing actors, grants, intents, approvals, executions, vault entries, connections, connection-access assignments, settings, media handles, and audit history are preserved.

No existing connection is automatically converted to OAuth.

## Existing browser connections

X, LinkedIn, and Instagram browser-backed connections continue to work as before.

## New OAuth providers

GitHub and Google OAuth connections require provider application credentials in the PAG process environment. See `docs/OAUTH.md`.

After setting the relevant variables:

1. Start PAG.
2. Open **Connections**.
3. Choose GitHub or Google.
4. Review the requested logical account permission(s).
5. Continue to the provider consent screen.
6. Return to PAG after authorization.
7. Grant agent access separately in **Access**.

Every new OAuth connection still initializes all agent × account assignments to **No access**.

## Security behavior

OAuth tokens are encrypted in the PAG vault. OAuth transient state is fail-closed: only a hash of `state` is persisted and the PKCE verifier is encrypted.

OAuth scope elevation requires a new provider authorization before the additional logical scope becomes active. Local scope downgrades take effect immediately.

Back up the PAG data directory before any version upgrade.

# Migrating PAG v1.0.0 to v1.1.0

v1.1 performs an additive SQLite migration when the database is opened. It adds connection authentication/scope/health metadata and the `connection_access` table. Existing vault values, intents, approvals, executions, audit events, connections, actors, and global grants are preserved.

## Security behavior change

Every existing **agent × connection** pair is initialized to `none` access during migration. This is deliberate. A global v1.0 grant such as `x.threads.create = allow` no longer grants access to an account merely because its `connectionId` is supplied.

After upgrading:

1. Start PAG once so the additive migration runs.
2. Open **Access** in the Control Center.
3. Explicitly choose `Read only`, `Ask before actions`, `Automatic`, or `Custom` for each agent/account pair that should be usable.
4. Review each account's logical scopes in **Connections**.
5. Run `pag audit verify`.

Non-account capabilities continue to use the original global grant engine.

Back up the PAG data directory before any version upgrade.

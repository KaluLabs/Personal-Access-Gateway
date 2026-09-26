# Migration from PAG v0.3.1

Known v0.3.1 properties are preserved conceptually in v1: SQLite/WAL, payload SHA-256 binding, unique execution receipts, approval gating, X Web Intent, and non-autonomous social publishing.

The exact legacy database schema is not bundled with this workspace, so v1 intentionally avoids guessing at column names or mutating the old database.

## Safe migration

1. Stop the old PAG process.
2. Back up the entire old PAG directory.
3. Initialize v1 with a **new** `PAG_DATA_DIR`.
4. Recreate agent actors. Each receives a new token.
5. Recreate grants, preferring `ask` for external write capabilities.
6. Re-enter only credentials still needed. Do not copy encrypted blobs unless the old encryption format and key derivation are verified.
7. Keep the old audit/history database read-only for historical reference.
8. Run `pag doctor` and `npm test` before switching agents to the new base URL/token.

## Optional verified importer

If the old v0.3.1 SQLite DDL is later supplied, add a one-way importer that reads the legacy database read-only and maps verified fields into v1. It should never modify the source database.

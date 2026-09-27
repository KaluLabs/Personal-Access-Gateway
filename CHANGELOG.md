# Changelog

## 1.2.0 — 2026-09-27

- Added generic OAuth 2.0 authorization-code authentication with state + S256 PKCE.
- Added encrypted transient PKCE verifier storage and single-use OAuth flow state.
- Added encrypted access/refresh-token storage and in-gateway token refresh.
- Added GitHub OAuth identity connections and `github.user.read`.
- Added Google OAuth/OIDC identity connections and `google.user.read`.
- Added OAuth account reauthorization without replacing connection identity or access assignments.
- OAuth scope elevation is fail-closed until provider reauthorization completes; downgrades take effect locally immediately.
- Added Control Center OAuth connect/reconnect flows and provider configuration status.
- Added OAuth deployment, security, and v1.1 → v1.2 migration documentation.

## 1.1.0 — 2026-09-27

- Added provider-aware Connections dashboard and provider catalog.
- Added logical account scopes with elevation/downgrade audit events.
- Added disconnect/reconnect lifecycle and configuration health state while preserving audit history.
- Added deny-first agent × connection access matrix with No access, Read only, Ask, Automatic, and Custom levels.
- Account-bound capabilities now require an explicit connection and are revalidated immediately before execution.
- Added provider extension documentation and CLI/API operations for connections and access.
- Added additive v1.0 → v1.1 database migration with safe default-No-Access initialization.

## 1.0.0 — 2026-09-26

- Consolidated PAG's deny-first action gateway and Control Center into one local-first service.
- Added hashed actor tokens, rotation, revocation, and `control` actors.
- Added allow/ask/deny grants, conditional policy matching, priority, and emergency lockdown.
- Added hash-bound approvals, expiry, idempotent intents, and exactly-once execution receipts.
- Added AES-256-GCM vault and account connection metadata.
- Added tamper-evident audit hash chain.
- Added X and LinkedIn approval-gated browser handoffs.
- Restored authenticated OpenCLI inspection for Instagram/X and explicit Reddit rejection.
- Added encrypted opaque media handles and local `pag media fetch`.
- Added browser Control Center, JS SDK, Control Line API, OpenAPI contract, Docker packaging, examples, and security docs.

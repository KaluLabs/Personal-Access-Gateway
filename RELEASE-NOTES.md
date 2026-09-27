# PAG v1.2.0 release notes

PAG v1.2 adds real provider authentication on top of the v1.1 connection/access model.

## OAuth provider authentication

- Generic OAuth 2.0 authorization-code flow with unguessable state and S256 PKCE.
- Only a SHA-256 hash of OAuth state is persisted.
- PKCE verifiers are encrypted with the PAG master key while a flow is pending.
- Provider access and refresh tokens are encrypted inside the PAG vault.
- Expiring tokens refresh inside PAG when a refresh token is available.
- OAuth callbacks are single-use; transient flow state is removed on completion/failure.

## GitHub and Google

- GitHub OAuth identity connection using `read:user` and `offline_access`.
- Built-in `github.user.read` token-backed capability.
- Google OAuth/OIDC identity connection using `openid profile email` and offline access.
- Built-in `google.user.read` token-backed capability.
- Provider configuration status is visible in the Control Center without exposing client secrets.

GitHub currently recommends GitHub Apps for fine-grained repository automation, so v1.2 intentionally keeps the OAuth integration identity-focused rather than requesting the broad `repo` scope.

## Reauthorization and scopes

- Existing OAuth connection IDs can be reauthorized without losing audit history or agent-access assignments.
- OAuth scope elevation does not become active until provider reauthorization succeeds.
- Local scope downgrades take effect immediately.
- New OAuth accounts still initialize every agent × account assignment to **No access**.

## Dashboard and API

- OAuth-aware provider cards in **Connections**.
- OAuth connect flow from the browser Control Center.
- OAuth reconnect for disconnected accounts.
- Reauthorization is automatically triggered when an OAuth scope elevation requires provider consent.
- New `POST /v1/oauth/{provider}/start` and `GET /oauth/callback/{provider}` routes.

## Deployment

Set provider application credentials through environment variables and register callback URLs matching the PAG instance. For reverse-proxy deployments set `PAG_PUBLIC_BASE_URL` to the exact public HTTPS origin.

See:

- `docs/OAUTH.md`
- `docs/PROVIDERS.md`
- `docs/SECURITY.md`
- `docs/MIGRATION-v1.1.0.md`

## Verification

The regression suite covers v1/v1.1 invariants plus PKCE flow creation, state replay rejection, encrypted OAuth token storage, provider identity binding, token-backed profile reads, refresh-token rotation, and the HTTP start/callback flow.

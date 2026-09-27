# OAuth provider authentication

PAG v1.2 adds a generic OAuth 2.0 authorization-code flow with PKCE for provider accounts. The first built-in OAuth providers are GitHub and Google.

## Security model

The OAuth flow is initiated only from the authenticated PAG Control Center.

1. PAG generates a cryptographically random `state` value and PKCE `code_verifier`.
2. PAG stores only a SHA-256 hash of `state`.
3. The PKCE verifier is encrypted with the PAG master key before it is written to SQLite.
4. PAG redirects the human to the provider with an S256 `code_challenge`.
5. The provider redirects back to PAG with `code` and `state`.
6. PAG validates the state hash, decrypts the verifier, and exchanges the code server-side.
7. PAG fetches the authenticated account identity and binds the resulting token to that connection.
8. Access and refresh tokens are stored only as AES-256-GCM ciphertext in the PAG vault.
9. The transient OAuth flow row is deleted after completion or failure.
10. Agent-account access still defaults to **No access**. OAuth consent does not grant any agent permission by itself.

Provider access tokens are never returned from the Control Center API and are never written to the audit log.

## Configure GitHub

Create a GitHub OAuth App and use a callback URL matching your PAG instance:

```text
http://127.0.0.1:8787/oauth/callback/github
```

Then set:

```bash
export PAG_OAUTH_GITHUB_CLIENT_ID='...'
export PAG_OAUTH_GITHUB_CLIENT_SECRET='...'
```

PAG requests the GitHub profile scopes needed for the built-in `github.user.read` capability and uses PKCE. GitHub currently recommends GitHub Apps for fine-grained repository automation; PAG therefore keeps the initial OAuth integration identity-focused instead of requesting the broad `repo` scope.

Official reference:

- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps

## Configure Google

Create a Google OAuth 2.0 Web application credential and register:

```text
http://127.0.0.1:8787/oauth/callback/google
```

Then set:

```bash
export PAG_OAUTH_GOOGLE_CLIENT_ID='...'
export PAG_OAUTH_GOOGLE_CLIENT_SECRET='...'
```

PAG requests `openid profile email`, uses PKCE, and requests offline access so a refresh token can be stored when Google issues one.

Official reference:

- https://developers.google.com/identity/protocols/oauth2/web-server
- https://developers.google.com/identity/openid-connect/openid-connect

## Reverse proxies and non-local deployments

PAG derives a local callback origin from the incoming request by default. When PAG is behind HTTPS or a reverse proxy, set an explicit public origin:

```bash
export PAG_PUBLIC_BASE_URL='https://pag.example.com'
```

Register provider callback URLs using that exact origin:

```text
https://pag.example.com/oauth/callback/github
https://pag.example.com/oauth/callback/google
```

The built-in HTTP server does not terminate TLS. Keep PAG private or put it behind a trusted HTTPS reverse proxy.

## Token refresh

If an access token is expired and the encrypted token bundle contains a refresh token, PAG refreshes it inside the gateway immediately before provider use and replaces the encrypted vault value. The replacement token is not returned to agents.

If no refresh token is available, the connection moves to a reauthentication-required state on health inspection/use.

## Scope elevation

OAuth scope elevation is fail-closed.

Removing a logical account scope takes effect locally immediately. Adding an OAuth-backed scope does **not** become active merely because the dashboard checkbox changed. PAG returns a reauthorization requirement, starts a new provider consent flow, and activates the elevated scope only after successful OAuth completion.

## Reauthorization

A disconnected or existing OAuth connection can be reauthorized. PAG reuses the connection identity, writes the new token bundle to a new encrypted vault record, switches the connection to it, and removes the previous unreferenced credential.

Audit history and agent-access assignments stay attached to the same connection.

## Environment variables

```text
PAG_PUBLIC_BASE_URL
PAG_OAUTH_FLOW_TTL_MINUTES
PAG_OAUTH_GITHUB_CLIENT_ID
PAG_OAUTH_GITHUB_CLIENT_SECRET
PAG_OAUTH_GOOGLE_CLIENT_ID
PAG_OAUTH_GOOGLE_CLIENT_SECRET
```

OAuth client secrets are deployment configuration. User access/refresh tokens are stored in the encrypted PAG vault.

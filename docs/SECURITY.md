# PAG Security Guide

## Safe deployment default

PAG binds to `127.0.0.1` by default. Keep that default unless you intentionally place it behind a private network or HTTPS reverse proxy.

## Secrets

- Treat `master.key` as equivalent to all encrypted vault entries.
- Treat `admin.token` as full administrative access.
- Back up both securely and separately from public source code.
- Do not commit the PAG data directory.
- Rotate an actor token immediately when it may have leaked.
- Revoke actors that no longer need access.

## Agent isolation

Actor bearer tokens can only create intents as that actor and read their own intent status. Administrative routes require the admin session. Policies are evaluated server-side; agents cannot self-grant capabilities.

## Approval safety

Do not approve an action only from a natural-language summary. The Control Center intentionally shows the serialized arguments and payload hash. Approval is bound to the hash PAG computed from the actor, capability, and exact arguments.

## Browser and CSRF controls

The Control Center uses an HttpOnly, SameSite=Strict session cookie and requires a custom CSRF header on administrative mutations. Responses include restrictive CSP, frame, MIME-sniffing, and referrer headers.

## Vault limitations

AES-GCM protects secrets at rest from database-only compromise. It does not protect against an attacker who can read both the database and master key, or against a compromised process already running as the PAG user.

For a higher-security deployment, replace the local master-key file with an OS keychain, TPM/HSM, or external KMS adapter while keeping the same vault interface.

## Audit limitations

The hash chain makes silent modification detectable when the attacker cannot also rewrite every later hash. It is not an external immutable ledger. Periodically anchoring the latest audit head in a separate trusted system provides stronger tamper evidence.

## Network exposure

The built-in HTTP server does not terminate TLS. Use a trusted reverse proxy if remote access is required. Do not expose port 8787 directly to the public internet.


## Control tokens

Use actor kind `control` for approval-channel bridges. A control token is intentionally narrower than the admin token: it can only read pending approvals and submit approve/deny decisions. Revoke or rotate it like any other actor token if the WhatsApp bridge host is compromised.

## Authenticated browser inspection

OpenCLI inspection runs inside the user's authenticated browser session. Treat the browser profile as sensitive. PAG sanitizes returned media URLs into opaque encrypted handles, but page text and public/social metadata requested by the caller are returned to the permitted actor. Grant read-inspection capabilities only to agents that need them.


## Account-scoped authorization (v1.1)

Capabilities tied to a provider account require `connectionId`. PAG evaluates both the connection's logical provider scopes and the agent × connection access record. New pairs default to `none`. The authorization is checked when the intent is created and again immediately before execution, so a disconnect, account-scope downgrade, or agent-access downgrade prevents a stale approval from executing.

Global grants remain available for non-account capabilities. They do not override an explicit connection access decision for an account-bound action.

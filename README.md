# Personal Access Gateway (PAG) v1.0.0

PAG is a local-first authorization boundary between AI agents and real-world account actions. Agents never receive account credentials. They submit **intents** describing the exact capability and arguments they want to use. PAG evaluates a deny-first policy, optionally asks the human for approval, binds that approval to the payload hash, and produces at most one execution receipt.

This repository is the complete v1 baseline for the earlier PAG v0.3.x work.

## What is included

- Default-deny `allow | ask | deny` policy engine with wildcard capabilities and optional argument conditions.
- Per-agent bearer tokens stored only as SHA-256 hashes.
- Dedicated least-privilege `control` actors for WhatsApp/other approval channels.
- Token rotation, revocation, and reactivation.
- Exact-payload SHA-256 approval binding.
- Idempotent intent submission and exactly-once execution receipts.
- Tamper-evident append-only audit hash chain.
- AES-256-GCM encrypted local credential vault. Raw values are never returned by HTTP APIs.
- Browser Control Center for approvals, actors, grants, connections, intents, handoffs, lockdown, vault metadata, and audit verification.
- Authenticated-browser read inspection for Instagram and X through OpenCLI, preserving the original `pag inspect <url>` workflow.
- Encrypted opaque `pagm_...` media handles plus `pag media fetch`.
- X browser Web Intent connector (`x.threads.create`).
- LinkedIn browser-handoff connector (`linkedin.posts.create`).
- `noop.test` connector for integration and CI testing.
- JavaScript SDK, CLI, OpenAPI contract, Docker image, and test suite.

PAG deliberately does **not** silently publish to X or LinkedIn. Successful execution of those capabilities produces an approved browser handoff that the user completes in the authenticated browser.

## Requirements

- Node.js 22.5 or newer. Node 22 currently labels `node:sqlite` experimental even though the API is available.
- No npm dependencies are required for the core server.

## First run

```bash
cd pag-v1.0.0
export PAG_DATA_DIR="$PWD/.pag"     # PowerShell: $env:PAG_DATA_DIR="$PWD/.pag"
node ./bin/pag.js init
node ./bin/pag.js serve
```

`pag init` generates:

- `.pag/master.key` — 32-byte AES master key, base64 encoded.
- `.pag/admin.token` — Control Center administrator token.
- `.pag/pag.sqlite` — SQLite database (created on first service access).

The generated files are permission-restricted where the host OS supports POSIX file modes. Back up the data directory securely. Anyone with `master.key` and the database can decrypt vault values.

Open `http://127.0.0.1:8787` and enter the admin token.

## Create an agent and approval policy

From the Control Center, create an actor such as `BIPAI`, copy its token once, and add an `ask` grant for `x.threads.create` and/or `linkedin.posts.create`.

Equivalent CLI:

```bash
node ./bin/pag.js actor create --name BIPAI
# copy actor.id and token from output

node ./bin/pag.js grant add \
  --actor ACTOR_ID \
  --capability x.threads.create \
  --effect ask \
  --priority 10
```

Default behavior is **deny** when no matching grant exists.

## Submit an agent intent

```bash
curl -X POST http://127.0.0.1:8787/v1/intents \
  -H "Authorization: Bearer $PAG_ACTOR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-PAG-Idempotency-Key: bipai-content-hash-123" \
  -d '{
    "capability": "x.threads.create",
    "args": {
      "posts": ["First approved post", "Second approved post"]
    }
  }'
```

With an `ask` grant, the response has `status: "pending_approval"`. The Control Center displays the exact arguments and their hash. Approving them causes the connector to execute once and produces browser handoff URL(s).

## Authenticated read inspection

The original PAG read path is retained. When OpenCLI is installed and connected to an authenticated browser profile:

```bash
node ./bin/pag.js inspect "https://www.instagram.com/reel/.../"
node ./bin/pag.js inspect "https://x.com/user/status/123..."
```

Instagram `/p/`, `/reel/`, and `/tv/` URLs and X/Twitter status URLs are canonicalized. Reddit remains intentionally unsupported. Signed media URLs are not returned to callers; PAG stores them encrypted and returns opaque `pagm_...` handles instead. Materialize one locally with:

```bash
node ./bin/pag.js media fetch --handle pagm_...
```

Agents can request the same read operations through `instagram.media.inspect` or `x.posts.inspect` after you grant those capabilities.

## Connections

A connection is non-secret account metadata plus an optional reference to a vault entry. For example, `Personal X` can reference vault item `x.session` without returning that secret to an agent. Write connectors enforce connection type when an intent includes `connectionId`.

## Emergency lockdown

The Overview page exposes a lockdown switch. When enabled, every new agent intent is recorded as denied **before** normal grant evaluation. Existing audit history remains readable. Disable lockdown from the Control Center after the incident is resolved.

## WhatsApp / Control Line boundary

Create an actor with kind `control` and give its token only to the trusted WhatsApp bridge. A control token can list pending approvals and approve or deny them, but cannot manage grants, actors, connections, the vault, or lockdown.

```text
GET  /v1/control/approvals?state=pending
POST /v1/control/approvals/{id}/approve
POST /v1/control/approvals/{id}/deny
```

Approval still requires the exact `expectedArgsHash`. `examples/whatsapp-control-bridge.js` is a transport-neutral adapter that can be called from a Baileys or official WhatsApp integration without making PAG depend on either transport.

## JavaScript SDK

```js
import { PagClient } from './src/sdk.js';

const pag = new PagClient({ token: process.env.PAG_ACTOR_TOKEN });
const intent = await pag.createIntent(
  'linkedin.posts.create',
  { text: 'Approved LinkedIn update' },
  { idempotencyKey: 'content-sha-or-event-id' }
);
```

See `examples/bipai-publish.js`.

## CLI

```text
pag init
pag serve
pag doctor
pag capabilities
pag inspect <url>
pag media fetch --handle pagm_...
pag actor create|list
pag grant add|list|revoke
pag intent submit|get
pag approvals list|approve|deny
pag vault put|list|delete
pag audit list|verify
```

For vault insertion from the terminal, PAG intentionally reads the secret from an environment variable instead of a command-line argument, reducing accidental shell-history leakage:

```bash
export X_SESSION='...'
node ./bin/pag.js vault put --name x.session --from-env X_SESSION --connector x
unset X_SESSION
```

## Policy model

Rules are per actor. Capabilities support:

- exact match: `x.threads.create`
- namespace wildcard: `x.*`
- all capabilities: `*`

At the highest matching priority, `deny` wins over `ask`, and `ask` wins over `allow`. A grant may include simple top-level conditions:

```json
{
  "argEquals": { "account": "personal" },
  "argIn": { "visibility": ["public", "connections"] },
  "maxLength": { "text": 3000 }
}
```

No match means deny.

## Approval integrity

An intent hash is computed from the canonical tuple:

```text
{ actorId, capability, args }
```

The approval row stores that exact hash. Approval refuses execution if the current intent hash differs from the reviewed hash. This prevents an agent from changing arguments after the human approves them.

## Exactly-once behavior

Two controls are independent:

1. Agent-provided idempotency keys are unique per actor. Reusing a key with identical data returns the existing intent. Reusing it with different data returns HTTP 409.
2. Every intent can have only one execution record and one deterministic receipt key.

Connectors that perform irreversible API calls in future versions should also pass the PAG receipt/idempotency key to the upstream provider when the provider supports idempotency.

## Credential boundary

Agents authenticate to PAG using actor tokens. They do not receive social-account credentials. Vault values are only decrypted inside PAG connector execution. The HTTP API exposes vault metadata, never decrypted values.

The Control Center can accept a new vault value because it is the human administrative surface. Deploy it only on localhost, a private network, or behind HTTPS and a trusted reverse proxy.

## Docker

```bash
docker build -t pag:1.0.0 .
docker run --rm -it \
  -p 127.0.0.1:8787:8787 \
  -v pag-data:/data \
  pag:1.0.0
```

The entrypoint initializes `/data` on first run, then starts PAG. Preserve the volume.

## Tests

```bash
npm test
```

The suite covers default deny, exact approval binding, idempotency-key rebinding, deny precedence, vault plaintext leakage, audit-chain verification, and an end-to-end HTTP X handoff.

## API contract

See `openapi.yaml` for the public actor API and administrator endpoints.

## Security notes

Read `docs/SECURITY.md` before exposing PAG beyond localhost. The default bind address is `127.0.0.1` on purpose.

## Architecture

Read `docs/ARCHITECTURE.md` for trust boundaries and lifecycle details.

## Migrating from PAG v0.3.1

The previous local implementation used an earlier schema. Because this repository does not have the exact v0.3.1 database DDL, v1 does not attempt a destructive automatic migration. Keep the old database untouched, initialize a new v1 data directory, recreate actors/grants, and import only data whose old columns are verified. See `docs/MIGRATION-v0.3.1.md`.

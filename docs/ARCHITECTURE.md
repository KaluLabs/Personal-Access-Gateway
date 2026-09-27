# PAG v1 Architecture

## Trust boundary

```text
Agent / BIPAI / career agent       WhatsApp control bridge
        |                                | control token
        | actor token + exact intent
        v
+-----------------------------+
| Personal Access Gateway     |
|                             |
| Auth -> Policy -> Intent     |
| Control approval API         |
| Emergency lockdown           |
|              |              |
|          allow/ask/deny     |
|              |              |
|       Human approval        |
|              | exact hash   |
|        Execution receipt    |
|              |              |
| Connector runtime -> Vault  |
+--------------+--------------+
               |
               | approved handoff / future provider call
               v
        X / LinkedIn / service
```

The model/agent is outside the credential boundary. It receives an actor token with limited PAG capabilities, not the account's actual authentication material.

## Core records

### Actor

A principal that may request capabilities. The plaintext actor token is shown only when created or rotated; SQLite stores its SHA-256 hash.

### Grant

A rule for one actor and one capability pattern with `allow`, `ask`, or `deny`. Missing grants deny by default.

### Intent

An immutable logical request consisting of actor, capability, arguments, and their canonical hash. The database does not expose an API to mutate intent arguments.

### Approval

Created only for `ask`. It stores the exact `args_hash`, capability, expiry, state, and decision identity.

### Execution

One row per intent, enforced by `UNIQUE(intent_id)`. A deterministic receipt key binds the intent ID and payload hash.

### Audit event

Every security-relevant transition appends a hash-chained event. Each event includes the previous event hash. `pag audit verify` recomputes the chain.

### Vault entry

AES-256-GCM encrypted secret plus non-sensitive metadata. Associated authenticated data includes the vault entry name, preventing ciphertext swapping between names without authentication failure.

## Lifecycle

1. Agent authenticates with its actor token.
2. Agent submits capability + arguments + optional idempotency key.
3. PAG canonicalizes the payload and calculates its hash.
4. Policy evaluates the actor's active grants.
5. `deny`: intent is recorded and stops.
6. `allow`: connector executes once immediately.
7. `ask`: approval record is created with the exact payload hash and TTL.
8. Human sees the exact arguments in Control Center.
9. Approval verifies the stored hash still matches the intent.
10. PAG inserts the unique execution receipt before calling the connector.
11. Connector gets the arguments and internal vault interface.
12. Browser-based social connectors return handoff URLs/text rather than silently publishing.
13. Every transition is audited.

## Why browser handoff for social publishing

PAG's current social connectors preserve the earlier authenticated-browser approach and final human action. An `execution.succeeded` record means PAG successfully created the approved handoff, not that the external network has confirmed a published post.

A future provider/API connector can define stronger delivery semantics and store an external provider receipt in `result_json`.

## Failure semantics

The execution record is inserted before connector invocation. If a process crashes after an irreversible external operation but before PAG records success, the receipt remains `started`. For the built-in browser-handoff connectors this does not cause a duplicate external post because PAG itself never publishes. Future irreversible connectors must support provider idempotency or reconciliation before retry.

## Storage

SQLite runs in WAL mode with foreign keys and a busy timeout. PAG is designed as a personal/single-node gateway. Horizontal multi-writer deployment requires moving execution locking, audit ordering, and vault storage to infrastructure with equivalent transactional guarantees.


## Read-side inspector

PAG also retains the earlier authenticated-browser read path. OpenCLI opens Instagram or X in the user's existing authenticated browser context and evaluates a bounded inspection script. Before the result leaves PAG, media URLs are replaced with encrypted opaque handles. Only `pag media fetch` resolves a registered handle, preventing arbitrary URL fetching through the media subsystem.

## Control Line

A `control` actor is separate from an ordinary agent. Its token is accepted only by `/v1/control/*`. This is the intended integration point for the WhatsApp approval line: transport code authenticates the human conversation, retrieves pending approvals, displays the exact payload/hash, and sends the human decision back to PAG. It cannot self-grant capabilities or read vault values.

## Lockdown

Lockdown is stored as durable gateway state. When enabled, intent creation records a deny decision before evaluating actor grants. This provides one switch for stopping new agent actions without deleting actors or policies.


## v1.1 connection authorization layer

For provider-account capabilities, PAG inserts an account boundary between actor authentication and the generic grant engine:

```text
Actor token
   |
   v
connectionId required
   |
   +--> provider type check
   +--> account scope check
   +--> agent x connection access (none/read/ask/automatic/custom)
   |
   v
intent / exact-payload approval
   |
   v
execution-time revalidation
   |
   v
connector executor
```

The `connection_access` table is authoritative for account-bound actions. The provider manifest maps human-readable scopes and access levels to capability modes, while `ConnectorRegistry` owns execution. This keeps the UI understandable and the runtime deny-first.


## v1.2 provider authentication boundary

OAuth provider authentication stays inside the PAG trust boundary:

```text
Control Center
   |
   | authenticated admin + CSRF
   v
OAuth start
   |
   +--> random state (only SHA-256 hash persisted)
   +--> PKCE verifier (AES-256-GCM encrypted)
   +--> S256 code challenge
   |
   v
Provider consent
   |
   v
/oauth/callback/{provider}
   |
   +--> state match + single-use flow claim
   +--> server-side code/verifier exchange
   +--> authenticated account identity lookup
   |
   v
Encrypted vault token bundle
   |
   v
Connection metadata
   |
   v
Agent × connection access (defaults to No access)
```

Provider client secrets are deployment configuration and provider access/refresh tokens remain inside PAG. Connectors obtain an access token only inside the trusted runtime through `OAuthManager`; actors never receive it.

OAuth reauthorization is connection-identity preserving. If an existing connection already has an external account identifier, PAG rejects a callback that resolves to a different provider account. This prevents an account switch from inheriting the original connection's agent-access assignments.

OAuth scope elevation is also fail-closed. A requested added scope remains pending until provider reauthorization completes; local scope removal takes effect immediately.

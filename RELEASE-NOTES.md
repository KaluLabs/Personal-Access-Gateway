# PAG v1.0.0 release verification

Release date: 2026-09-26

## Verified in this build environment

- Node.js v22.16.0.
- JavaScript syntax check across `src/`, `bin/`, `public/`, `examples/`, and `tests/`.
- OpenAPI 3.1 YAML parses successfully and documents 27 paths.
- `npm test`: 13 tests passed, 0 failed.
- Fresh-data smoke test passed for:
  - initialization and secret generation;
  - actor + `ask` grant creation;
  - intent submission and pending approval;
  - exact-hash approval and one successful execution receipt;
  - audit-chain verification;
  - HTTP health endpoint;
  - Control Center HTML;
  - administrator login and summary API.

## Environment-dependent verification still required on the target machine

- OpenCLI is not installed in this build container. Instagram/X authenticated-browser inspection is covered by routing/media-registry tests, but the live browser fetch must be exercised on the machine that has the authenticated OpenCLI extension/profile.
- Docker is not installed in this build container, so the included Dockerfile was not image-built here.

These two items do not affect the tested authorization, approval, execution, vault, audit, Control Center, SDK, or Control Line paths.

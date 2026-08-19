# Admin Dynamic Fixture API/UI — Experiment Plan

- Run ID: `2026-08-18-admin-dynamic-api-ui-dev-v1`
- Tier: `auxiliary/dev`
- Baseline: `2026-08-18-safe-dynamic-fixture-dev-v2`
- Objective: expose the hash-locked, self-built fixture set through an administrator-only asynchronous API and a local UI without creating an arbitrary-code execution surface.

## Research question

Can the existing trusted-fixture dynamic evidence mechanism be integrated into the local platform with environment-backed administrator authentication, persisted task history, and browser polling while preserving the static scan contract and the INFO-only/no-decision-change boundary?

## Fixed scope

- Administrator token source: process environment variable `AEGIS_ADMIN_TOKEN`.
- Request header: `X-Aegis-Admin-Token`.
- Token is never written to source code, SQLite, response payloads, browser storage, or logs.
- Dynamic input is fixed to `config/safe_dynamic_fixtures.json`; no upload, path, script, command, or custom fixture parameter is accepted.
- Execution remains limited to the three self-built, SHA-256-locked fixtures.
- Evidence severity remains `INFO`, `policy_effect` remains `none`, and `decision_changes` remains `0`.

## Success criteria

1. Missing server token fails closed with HTTP 503; missing or incorrect request token returns HTTP 401.
2. Correct authentication can create an HTTP 202 task and retrieve list/detail history.
3. The background worker executes only the fixed built-in fixture set and persists redacted evidence.
4. No token value appears in API responses, SQLite payloads, frontend persistent storage, or test logs.
5. Frontend keeps the token only in React memory, sends it only in the administrator header, polls until terminal status, and can clear it.
6. Real fixture validation remains 3/3 fixtures and 7/7 expected mechanisms with all negative safety metrics at zero.
7. Existing backend and frontend regression suites remain green.

## Stop conditions

- Any endpoint accepts user-controlled code, filesystem paths, fixture configuration, or commands.
- A token is persisted or reflected.
- A protected/external sample is read or executed.
- Dynamic evidence changes an admission decision.
- Existing static scan API behavior regresses.

## Planned evidence

- Backend and frontend test logs.
- One authenticated real fixture execution result.
- OpenAPI route/auth/error-contract checks.
- SQLite and source scan for token leakage and browser persistence APIs.
- SHA-256 manifest for material outputs.

# Changelog

## 0.8.7 (DAI-IN-518 HA-path budget metering — production defect fix)
- Fix: on the Dashboard/claude-api Home Assistant path (`Engine._ha_execute` → `HAClient`), GAOP's own HA Core requests
  were not charged to `tool_calls` or `retrieval_bytes`, so those two bound limits were inert there. Each attempted HA
  request now charges exactly one `tool_call`, and `retrieval_bytes` is charged with the exact raw response-body bytes
  read by the transport. Exhaustion (or a call that would exceed `tool_calls`) is refused before the next HA request:
  no write yet → STOP; after a write → UNKNOWN_RECONCILE (no retry, no rollback). A crossing on the final response is
  caught by the existing post-result budget path (PARTIAL).
- No double charge: envelope ops and `/api/pkg` keep their existing charging; the API HA path uses neither.
- Unchanged: budget defaults/ceilings/profiles, HA call table and targets, R1/R2/R3, roles, gpt-4.1 pin and prompt,
  permissions, store schema, protocol. Selftest 207 checks (194 prior unchanged + 13 new).

## 0.8.6 (DAI-IN-515 Dashboard transaction-scoped budgets — production defect fix)
- Fix: the Dashboard request entries (`owner_request`, `owner_pilot_request`) built proposals without `budgets`, so every
  Dashboard transaction silently ran at `BUDGET_DEFAULT`. They now resolve an owner-selectable, server-side allowlisted
  budget profile (`standard` = exactly `BUDGET_DEFAULT`; `pilot_bounded` = 600 s / 5 / 20 / 32768 B / 8000 / 1500 / 0 / 1 /
  25 stages) into the proposal, so the limits are in the exec package / `package_digest`, bound by Authorize and
  enforced by the existing engine. Unknown profile → `MALFORMED` (fail closed). Pilot buttons always use
  `pilot_bounded` (any other selection is denied; never falls back to `standard`).
- Dashboard: synthetic request has a budget-profile selector (default `standard`); the Pilot card shows
  `pilot_bounded`; each active transaction card shows the bound budget limits before Authorize. Transaction view adds
  `package_budgets`.
- Receipt adds `budget_limits` beside the existing `budget_used`.
- Unchanged: `BUDGET_DEFAULT`, `BUDGET_MAX`, R1/R2/R3, roles, gpt-4.1 pin and reviewer prompt, allowlists, permissions,
  store schema, protocol. Selftest 194 checks (179 prior unchanged + 15 new).

## 0.8.5 (DAI-IN-513 reviewer hardening)
- OpenAI Designer/Reviewer model pinned in code: `OPENAI_REVIEW_MODEL = "gpt-4.1"` (was the model stored with the
  owner's key, `gpt-4o-mini`). Applies to design and verification review calls only; the stored key and its model
  field are not changed. Setup card shows the pinned design/review model.
- For `ha.state.read` / `ha.input_boolean.set` the review payload carries `enforced_capability_facts` (derived from
  `HA_OP_TARGETS` and `HAClient.CALLS`), and the prompt tells the reviewer to evaluate the bounded package plus these
  code-enforced facts, not hypothetical generic Home Assistant capabilities, while still objecting to any concrete
  package problem. Synthetic-operation prompts are unchanged.
- No change to disagreement handling, R1/R2/R3, authority binding, budgets, predicates, allowlists, routes or
  permissions. Selftest 179 checks.

## 0.8.4 (DAI-IN-512 P1 fix)
- Fix: under s6-overlay the `/bin/sh` entrypoint does not inherit the container environment, so the Supervisor
  token was absent (0.8.2/0.8.3 HA calls were unauthenticated → HTTP 401, failing closed). GAOP now reads the
  token from `/run/s6/container_environment/SUPERVISOR_TOKEN` when not in the process environment. Never logged.

## 0.8.3 (DAI-IN-512 P1 diagnostic)
- HA failure detail (method/path/HTTP status; no data) logged and shown in the transaction view (`ha`).
- Startup boundary log adds a Core API root probe status and whether the Supervisor token is present (never its value).

## 0.8.2 (DAI-IN-512 P1 — bounded real-HA Pilot targets)
- Exactly two real Home Assistant operations, each bound to exactly one entity: `ha.state.read` on `sun.sun`
  (read-only) and `ha.input_boolean.set` on `input_boolean.gaop_pilot_probe` (`{state: on|off}`). No generic
  entity read, no generic service call.
- HA ops run only on the `claude-api` route: Claude states the exact action bound to txn/proposal/correlation;
  GAOP executes only if it equals the package-derived action (else STOP, zero HA calls), via `HAClient`, a fixed
  table of four HA Core API calls. Write outcome uncertain → UNKNOWN_RECONCILE, no retry.
- Verification predicates per operation (`ha_entity_exact`, `ha_state_present`, `ha_no_write`,
  `ha_after_equals_requested`, `ha_single_write` + bindings); a proposal cannot shed them. Receipt adds HA fields.
- `homeassistant_api: true` (Core API only); `hassio_api` stays false; startup logs a Supervisor-API probe status.
- Owner Dashboard card "P1 real-HA Pilot targets". Selftest 171 checks.

## 0.8.1 (DAI-IN-509 live-validation fixes)
- Panel auto-refresh returns to the panel root (no `NOT_FOUND` after an Authorize/decision POST).
- Design/review payload carries the transaction's stated effect, summary and operation class; the design
  prompt asks ChatGPT to judge the proposal against its own stated purpose (it may still object).
- A reconsidered design disagreement is kept in `prior_disagreements` with its outcome and appears in the
  transaction view and receipt (`gaop.receipt.v3.prior_disagreements`).
- Default `provider_calls` budget 4 → 5 (design + one design reconsideration + execution + review + one
  review reconsideration); policy ceiling unchanged (6). Selftest 151 checks.

## 0.8.0 (DAI-IN-509 production build; synthetic operations only)
- R1: exact executable package `gaop.exec_package.v1` + SHA-256 `package_digest`; owner authority binds the
  digest; every consequential step re-verifies it; post-authority change → STOP.
- R2: deterministic `operation_id` registry; one-time authority (`authority_use`); duplicate `envelope_id`
  rejection; replay after completion returns the existing receipt; verified (read-back) checkpoints; boot
  resume only from verified non-consequential checkpoints.
- R3: explicit envelope `role`; role × op × stage capability policy enforced inside every op; provider-role
  binding (claude = executor, openai = designer/reviewer); target/operation/digest-bound claims.
- Dual-AI: ChatGPT design check, post-execution independent review (`REVIEWING`), `DISAGREEMENT` state with
  one bounded reconciliation round and owner card; `PARTIAL` terminal state.
- Budgets `gaop.budget.v1` with policy ceilings; heartbeat every 5 s (`live.json`, `/api/live/<TXN>`),
  stage timeouts and watchdog, ETA only from observed data; panel auto-refresh while active.
- Anti-assumption fact classification; receipt `gaop.receipt.v3`. Selftest 149 checks.
- Behaviour change: `openai-api` can no longer be an executor route; envelopes require `role`; claims require
  `package_digest`, `operation`, `target`. Store schema unchanged (1).

## 0.7.2
- Live provider adapters (App is the executor for API routes): `claude-api` (Anthropic Messages API)
  and `openai-api` (OpenAI Chat Completions). After the owner's single Authorize press the App claims,
  calls the provider, binds the result to transaction ID + proposal hash + correlation ID, verifies,
  archives evidence and completes — no provider UI and no further prompts.
  Fail closed: not configured / auth (401/403) / rejected (4xx) / malformed / binding mismatch → STOP;
  timeout / network / 5xx → UNKNOWN_RECONCILE (no blind retry). Executors cannot claim or submit results
  for API-route transactions.
- One-time provider Setup card (owner only): API key stored only in App-private /data (0600), never
  echoed, logged, or exposed; configured/not-configured status; delete/replace.
- Receipt v2: provider route/model/response ID/request ID/correlation ID; Drive evidence integrity,
  disposition (DELETED / RETAINED_DELETE_FAILED), delete verification, unrelated-ID denial result,
  existing root/folder IDs, archive correlation ID. Unrelated-ID visibility now STOPs the evidence leg.
- Governed `reconcile` envelope: UNKNOWN_RECONCILE → CANCELLED only when no result was persisted and no
  evidence step ran; interruption record preserved; transaction record never deleted.
- Owner request-entry card (synthetic) and Recent results on the Dashboard.
- Security fix: transaction views expose only the SHA-256 of a claim ID (claim IDs authorise begin/result).

## 0.7.1
- Executor control ingress `POST /control` (Supervisor Ingress, same bounded `gaop.control.v1`
  envelope, authority keys still rejected) so envelopes are delivered **without an App restart**.
  v0.7.0 delivered envelopes only via the `control_envelope` option, which Supervisor applies only on
  restart; a restart correctly reconciles any RUNNING transaction to UNKNOWN_RECONCILE, so the
  result leg could not complete. The option route remains for boot-time delivery.
- Owner panel form actions use the Supervisor `X-Ingress-Path` base (fixes 404 after a Setup action).

## 0.7.0
- First durable repository-installed generation (slug `gaop`), distributed via `SFF2101/gaop-public`.
- Safe idle/default: normal start never replays the Gate A/B/C/H or Phase 0.5C harnesses.
- Versioned App-private transaction store (`gaop.store` v1) with CAS, claims/leases, replay protection,
  boot reconciliation, and fail-closed schema checks.
- Owner Dashboard authority via Supervisor Ingress (hashed owner pin); sole authority writer.
- Bounded control ingress (`gaop.control.v1`, ≤ 4 KiB, synthetic allowlist, no authority fields).
- Provider adapter contract (pull, API, mock) with deterministic tests.
- Exact retrieval endpoints; source/release attestation; Drive device-flow bootstrap (drive.file).
- The v0.6.0 local POC App is retained as historical evidence only.

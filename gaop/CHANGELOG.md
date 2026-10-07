# Changelog

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

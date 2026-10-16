# Changelog

## 0.11.0 (DAI-IN-561; development candidate, not deployed)
- General-purpose clarification workspace. When ChatGPT asks the owner a question (before planning, or after an
  investigation that found several candidates), GAOP opens ONE durable, owner-bound conversation instead of treating
  the next answer as a new, context-free request. The Home page shows it as a panel (modal on desktop, full-width on
  mobile) only while it is open: original request, ordered messages, outstanding ambiguities, and the rows already read
  from Home Assistant; Send answer, Cancel request, Not now.
- Every answer sends the complete relevant context explicitly to the approved OpenAI designer route (original request,
  all messages in order, ambiguities, already-read evidence rows), bounded to 8 KiB with any omission stated; provider
  conversation memory is never relied on. Limits: 4 answers, 30 minutes absolute lifetime, 300 characters per message.
- Resolution only creates a proposal through the existing controls: a read-only investigation (same planner validator,
  single re-plan, ChatGPT check, owner Authorize), or - when the answer picks a target from evidence already read - a
  change prepared exactly like "Prepare this change" (evidence-bound target, automation freshness binding, ChatGPT
  check, owner Authorize). No answer, including "yes", is ever authority; authority claims in answers are refused.
- Fail closed: cancel, expiry, the answer limit, a provider failure and a refused suggestion create nothing. A target
  not in the evidence, last seen unavailable/unknown, evidence that no longer matches its bound hash, or an already
  prepared change is refused. An answer left pending by a restart is marked failed and never re-sent. A newer request
  supersedes (cancels) an older open conversation.
- Sessions are stored App-private in /data (gaop/clar/, CAS writes with literal read-back), bound to the owner identity
  hash. Clarification text is display/provenance only: it is not part of any proposal, package, digest or receipt.
- Clear, unambiguous requests and the fixed sun/test-switch paths behave exactly as before.

## 0.10.2 (DAI-IN-550/551; development candidate, not deployed; includes 0.10.1)
- Everyday requests are understood by ChatGPT, not by GAOP. "Turn off the Office light", questions and complex
  automation requests all go, in your own words, to the OpenAI planner, which says what it understood, plans the
  read-only checks needed to find the exact device (or automation and its current configuration), or asks a short
  question, or explains specifically what is not possible. GAOP itself has no household-language rules on this path;
  it only checks the plan against its allowlist, runs it after your Authorize, and keeps state, budgets and receipts.
- After the checks, ChatGPT chooses the exact target from what Home Assistant actually returned (or lists the
  candidates and asks which one). GAOP refuses any suggested target that was not actually seen in that evidence, so an
  ID can never be invented; the change then needs Prepare, ChatGPT's check of the exact change and your Authorize, and
  Claude carries it out with read-back.
- Planner replies that are not readable JSON get the same single correction as refused plans (at most one correction in
  total per request); the planner is shown a valid lookup example and told never to guess entity IDs. Refusals name the
  exact field (for example "MALFORMED: query match").
- The duplicate-Ask guard ignores case, spacing and final punctuation. The "what can GAOP change" text is now truthful.
- DAI-IN-552: automations can be found by their real name or area (the read-only lookup may now include automations;
  each automation row carries the configuration id Home Assistant itself reports). After a first investigation,
  ChatGPT may ask for ONE follow-up set of read-only checks (for example "read the configuration of the automation I
  found"), using only ids that appeared in that evidence. You see exactly what will be read and approve it with its own
  Authorize ("Continue"); it is linked to the first investigation and bound to its exact evidence, and it cannot ask
  for another follow-up. Any change ChatGPT then designs still needs Prepare, ChatGPT's check and your Authorize.

## 0.10.1 (DAI-IN-549 usability fixes; development candidate, not deployed)
- Refused plans are explained: when ChatGPT's investigation plan breaks GAOP's tool rules, GAOP still refuses it and
  makes no Home Assistant call, but now says which call and which argument was wrong (and what the tool accepts). GAOP
  asks ChatGPT once, and only once, to correct the plan using exactly that explanation; the corrected plan goes through
  the same validator and allowlist. A second refusal stops with both explanations and creates nothing. Both planner
  calls count against the investigation's existing budget; authority, packages and the tool table are unchanged.
- No accidental duplicates: the Ask and Prepare-change buttons submit once per click, and GAOP refuses an identical
  Ask that is still being prepared, or that was created in the last 60 seconds and has not been acted on. Different
  requests, and repeating a request after the earlier one finished or after you acted on it, work as before.
- Prepare-change stays reachable: if a newer result (for example a rejected request) replaces an investigation as the
  Home page's "Latest result", earlier investigations with a change ready to prepare are listed on Home, and System &
  Maintenance shows a Prepare change button on their Recent results row. Same eligibility as before (completed
  investigation, validated suggestion, not yet prepared); the prepared change still needs its own check and Authorize.

## 0.10.0 (DAI-IN-537 governed tool orchestration; development candidate, not deployed)
- New `ha.investigate` (read-only): for requests other than the fixed sun/test-switch paths, ChatGPT plans up to 6
  read-only tool calls (state, template query, history, logbook, automation configuration). You see the plan and press
  Authorize once; GAOP runs exactly that plan through its own fixed tool table; ChatGPT answers from the evidence and
  may suggest an exact change. Values read from Home Assistant are treated as untrusted data.
- New `ha.change` (consequential): "Prepare this change for my approval" turns a suggested change into a separate
  proposal that needs ChatGPT's bound check and your own Authorize. Allowed: light/switch/fan/input_boolean/automation
  turn_on|turn_off, cover open|close|stop, and writing one automation. Every change is read back; a refused change
  stops cleanly, an uncertain one is never retried.
- Automation boundary (DAI-IN-543): any normal Home Assistant automation is accepted (templates, variables, nested
  triggers/conditions/actions, scripts, any integration's actions, blueprints); there is no action denylist. The
  boundary is your approval of the exact configuration for one exact automation: the complete configuration (at most
  12 KiB, refused explicitly if larger, never truncated), its digest, a diff against the current configuration, the
  effects to note (actions, scripts, events, templates; noteworthy domains such as shell_command, lock or homeassistant
  flagged) and what GAOP cannot know are shown before Authorize. An automation change must be the only call in its
  change. It is prepared only if the investigation read the current configuration; GAOP writes only if that
  configuration is unchanged (else STOP), sends exactly the approved configuration, keeps the previous configuration
  verbatim for recovery and reads the result back. A read-back mismatch after writing is PARTIAL (no retry). Read-back
  confirms the stored configuration, not the automation's behaviour when it triggers.
- Capacity (DAI-IN-544): the former 2 KiB automation limit is removed. Configurations up to 12 KiB (canonical JSON) can
  be suggested, shown, approved, written and read back; current configurations up to 16 KiB are read in full and
  preserved for recovery. The limits follow the existing per-transaction ceilings (ChatGPT must write and review the
  whole configuration within them); anything larger is refused with its size, never truncated. Change transactions use
  the existing input/retrieval ceilings; in-process change proposals and tool packages may exceed the 4 KiB / 8 KiB
  transport bounds, which still apply unchanged to /control, the option envelope and every pull-route package.
- GAOP calls Home Assistant only through the App's existing Core API access; AI providers never call Home Assistant.
  No new connector, credential or permission (config.yaml permissions unchanged).
- Verification: selftest 273/273 (three pins amended to the new behaviour); DAI-533 24/24; DAI-536 22/22;
  DAI-537 19/19 (two tests amended for DAI-IN-543); DAI-543 11/11 in gaop/tests/test_dai543_automation.py;
  DAI-544 7/7 in gaop/tests/test_dai544_capacity.py (oversize fixtures in DAI-537/543 tests raised to the new limit).

## 0.9.0 (DAI-IN-536 functional completion; development candidate, not deployed)
- Dashboard: finished transactions (REJECTED, CANCELLED, EXPIRED, COMPLETED, STOP, PARTIAL, DENIED) are never shown as
  active progress. Home shows current requests and the latest result; System & Maintenance shows "In progress or
  waiting for you" and "Recent results" (history). A finished transaction's elapsed time is frozen when it finished.
  Root cause of the stuck REJECTED card fixed: the active/recent index update now runs under its own lock (concurrent
  unlocked writes could resurrect a finished ID). Records, receipts and store schema are unchanged; nothing is deleted.
- New read-only operation `ha.query.read` (target `ha:query`): questions such as "Which lights are on?", "What is the
  temperature in the kitchen?", "Are any doors open?", "Is the front door locked?" or "Is the mower mowing?" are
  compiled by GAOP code into a validated spec (allowlisted domains, at most 20 rows, safe fields only) and answered with
  one GAOP-generated template rendered by Home Assistant's read-only `POST /api/template`. Same proposal, ChatGPT check,
  owner Authorize, Claude bound intent, deterministic verification, ChatGPT review and receipt path. Unavailable
  readings and truncation are disclosed. "Why…/investigate…" requests run as bounded read-only investigations.
- Capability registry: one entry per allowed operation (class, executor/reviewer route, since); shown read-only on
  System & Maintenance. Change requests without a registered capability are refused with nothing created. Routes for
  new requests come from the registry; a missing executor route is refused up front (no silent fallback).
- Fix: a failed read-only template request is not treated as a possible write.
- No new connector, credential, permission (config.yaml permissions unchanged), service call or household write.
- Verification: selftest 273/273 (two exact-capability pins amended to the new set); DAI-533 24/24;
  DAI-536 22/22 in gaop/tests/test_dai536_functional.py.

## 0.8.13 (DAI-IN-533/534 pending-proposal expiry, separate owner approval window, Dashboard refresh)
- Pending proposals that were never authorised now expire with the existing EXPIRED terminal state, including a
  residual PROPOSED record left by an owner Revise. The watchdog settles any elapsed, never-authorised pending
  proposal (PROPOSED, AWAITING_AUTHORITY, DISAGREEMENT) as EXPIRED under the store lock with a CAS write and an
  appended history entry; nothing is dispatched and nothing is retried. AUTHORIZED, DISPATCHED, CLAIMED, RUNNING
  and UNKNOWN_RECONCILE transactions are not touched by this sweep.
- Synthetic Dashboard requests get a separate 600 s owner approval window that applies only before authority
  exists; a late Authorize is refused as EXPIRED with the nonce unconsumed. The accepted 1800 s proposal deadline
  stays bound unchanged into authority, the execution package and dispatch, so timely approval keeps at least
  1200 s of execution validity (covers the 600 s and 900 s elapsed budgets). A revision restarts the window.
- Home Assistant action requests are unchanged (1800 s, no approval window). Records created before 0.8.13 behave
  as before. No store schema change.
- System & Maintenance no longer reloads every 5 s for PROPOSED or finished records; Home also ignores finished
  records left in active storage. Genuinely progressing transactions still refresh every 5 s. The System panel
  shows the approval deadline while a proposal is pending.
- Verification: selftest 273/273 (check set unchanged); 24 focused offline tests in gaop/tests/test_dai533_expiry.py.

## 0.8.12 (DAI-IN-527 Step 1 immutable technical-evidence binding; PR #35, merge 6298337d)
- Optional proposal field `evidence_manifest`: up to 3 immutable references (repo, path, full commit, git blob, SHA-256,
  provenance) with exact line excerpts (≤2 per entry, ≤40 lines / ≤800 chars each, ≤1600 chars total). GAOP verifies
  every entry itself before the proposal is persisted and again immediately before owner authority; mutable refs,
  unknown/unauthorized sources, forged identities, hash or excerpt mismatches and oversize evidence are refused.
- Sources: `attested-release` (GAOP's own attested runtime files) and `canonical-git` (canonical `governance/` and `gaop/`
  documents admitted through the bounded, self-verifying `POST /evidence` ingress: raw git objects anchored at the attested
  release commit, ancestors only). No GitHub access or credential at any stage.
- Verified evidence is bound into the proposal hash and package digest (any change invalidates authority), is delivered to
  the OpenAI design check and post-execution review (delivered digest recorded and required), and receipts record
  identities and delivered digests only, never excerpts.
- Transactions without an evidence manifest are unchanged. Independent verification: 273/273.

## 0.8.11 (DAI-IN-526 consequential authorization gate: unbound/unavailable ChatGPT review)
- Authorize for a consequential Home Assistant operation (any `ha.*` op other than the read-only `ha.state.read`) is
  refused at the single authority point (`owner_decision`) with `REVIEW_NOT_BOUND` unless the ChatGPT design review
  is bound to the exact current package: `design_review.status == RECEIVED` and `verdict == NO_OBJECTION`. The verdict
  alone is not sufficient. The check runs before any authority record, nonce use, provider dispatch or HA call;
  stale-view, hash, nonce, revision, expiry and replay controls are unchanged and still independently active.
- Read-only and synthetic operations keep the accepted proportionate policy (not hard-blocked; unbound reviews are disclosed).
- Home: a blocked change says "I couldn't confirm ChatGPT's check against this exact plan, so I won't let this change
  run yet." and offers Revise / Reject (Cancel) only. System & Maintenance shows the technical review status. No
  acknowledgement checkbox or override exists. No re-check action is offered (none exists); a revised consequential
  proposal stays blocked until it is rejected and asked again.
- Selftest 255 checks (243 prior unchanged + 12 new GT checks). Test fixtures now run the real design check before
  authorizing consequential operations, matching production.

## 0.8.10 (DAI-IN-525 live-verification fixes to the Home page; presentation only)
- The ChatGPT plan check runs in the background after Ask. Until it is back (max 60 s), the Home card now says
  "ChatGPT is checking this plan…", shows no decision buttons (they would be refused as stale) and the page refreshes
  itself. If no check arrives within 60 s the buttons return and the plan is described as unchecked.
- Home says "ChatGPT checked this plan and found no problems" only when the check is bound (status RECEIVED). An
  unbound check (e.g. REVIEW_BINDING_MISMATCH) is described as "could not be confirmed … treat this plan as unchecked".
  Engine behaviour for unbound design checks is unchanged.
- Home posts that create a request or record a decision answer with 303 → a fresh Home page, so a browser refresh
  cannot re-send them. Clarification / "can't do that" replies still render directly.
- Selftest 243 checks (239 prior unchanged + 4 new).

## 0.8.9 (DAI-IN-525 two-page hobby-friendly conversational Dashboard)
- Page 1 "GAOP" (`/`): "What would you like me to do?" text box + Ask, plain-language replies, and one conversational
  card per transaction with the existing Authorize / Revise / Reject (Cancel) controls directly underneath; plain-language
  success/failure wording (STOP / PARTIAL / UNKNOWN_RECONCILE / REJECTED are never shown as success); a Details link to the
  existing read-only transaction/receipt view. No model names, IDs, hashes or budget counters on this page.
- Page 2 "System & Maintenance" (`/system`): the previous panel unchanged in substance (version/attestation/heartbeat,
  active transaction detail, Home Assistant actions, Recent results with transaction/receipt links, provider setup,
  Diagnostics view at `/system?diagnostics=1`), plus a Home link.
- Conversational intake (`POST /ask`, owner only): `compile_ask()` is a closed deterministic allowlist that maps prose to
  exactly one existing request kind (read sun.sun / test switch on / test switch off) or replies with a clarification or
  "can't do that". It never calls a provider, never infers other targets, and never carries authority; the compiled
  request goes through `owner_pilot_request` (same proposal, design check, owner Authorize, execution and receipt). The
  prose is kept only for display (`ask_text`), not in the proposal, package, provider prompts or receipt.
- Unchanged: authority / stale-view / nonce / revision semantics, package binding, routes, providers and models,
  credentials, budgets and accounting, deterministic verification, R1/R2/R3, receipt schema, attestation, HA allowlist.
  Selftest 239 checks (219 prior unchanged + 20 new).

## 0.8.8 (DAI-IN-524 final pre-go-live production Dashboard UX refinement)
- Normal owner view: heading "P1 real-HA Pilot targets" → "Home Assistant actions" (Read sun.sun only); budget
  limits shown with the production label `bounded` (display only — internal profile `pilot_bounded`, its values,
  proposal/package/digest/receipt content unchanged); post-request notice no longer says "P1".
- Synthetic request card and the `gaop_pilot_probe` ON/OFF buttons moved to an explicit owner-only Diagnostics view
  (`?diagnostics=1`, linked at the bottom of the owner panel). Capabilities and server routes unchanged.
- New Dashboard Home Assistant action transactions use `TXN-HA-DB-<UTC yyyymmddHHMMSS>` (was `TXN-P1-DB-`); proposal
  summary "Dashboard Home Assistant action request". Historical `TXN-P1-*` IDs/records untouched. Operation
  identity (R2) excludes the summary and transaction ID, so duplicate/replay protection is unchanged.
- Unchanged: authority binding, routes/providers/models (gpt-4.1 pin, prompts), budgets/profiles/accounting,
  receipts, HA call table/targets, attestation/heartbeat, permissions, store schema, protocol.
  Selftest 219 checks (207 prior unchanged + 12 new UX checks).

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

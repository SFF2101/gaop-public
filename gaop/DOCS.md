# GAOP — Governed AI Operations Platform (v0.8.x, dual-AI production build)

**v0.8.12:** a proposal may carry an optional, bounded `evidence_manifest` of immutable source references with exact
excerpts. GAOP verifies them itself (attested release files, or canonical documents admitted through the self-verifying
`/evidence` ingress), binds them into what you authorize, and gives them to ChatGPT's checks. Nothing changes for
transactions without evidence; the Home and System pages are unchanged.

**v0.8.11:** a consequential change (e.g. turning the GAOP test switch on/off) can only be authorized when
ChatGPT's plan check is confirmed against that exact plan. If it is unbound, unavailable or missing, Home says
"I couldn't confirm ChatGPT's check against this exact plan, so I won't let this change run yet." and offers only
Revise / Reject; the server refuses Authorize (`REVIEW_NOT_BOUND`) however it is sent. Read-only requests are unaffected.

**v0.8.9:** two pages. **Home** (the panel's first page) is a simple "What would you like me to do?" box: GAOP
replies in plain language, and anything it would do appears as a short proposal with Authorize / Revise /
Reject (Cancel) underneath; nothing runs until you press Authorize. Today it understands: whether the sun is up
(sun.sun), and turning the GAOP test switch (input_boolean.gaop_pilot_probe) on or off; anything else gets a
clarification or "I can't do that yet". **System & Maintenance** (link at the bottom of Home) holds the technical
view: version/attestation/heartbeat, transaction and receipt detail, provider setup and the Diagnostics tools.

**v0.8.8:** the normal owner Dashboard is production-facing: the read-only Home Assistant action ("Read
sun.sun") sits under "Home Assistant actions"; the bounded budget profile is labelled `bounded` (internally still
`pilot_bounded`, same limits); new Dashboard Home Assistant action transactions are named `TXN-HA-DB-<UTC time>`
(historical `TXN-P1-*` IDs are unchanged). The synthetic request and the `gaop_pilot_probe` ON/OFF buttons are
in the owner-only Diagnostics view (link at the bottom of the panel, `?diagnostics=1`).

**v0.8.7:** every Home Assistant request GAOP makes for a transaction counts as one `tool_call`, and its
response bytes count toward `retrieval_bytes`; both limits are enforced before the next request.

**v0.8.6:** Dashboard requests carry transaction-scoped budgets from an allowlisted profile (`standard` =
the defaults; `pilot_bounded` for the Pilot buttons). The limits are shown on the transaction card before
Authorize, bound into the package digest, enforced, and recorded in the receipt (`budget_limits`, `budget_used`).

**v0.8.5:** the OpenAI design/review model is pinned in code (`gpt-4.1`), and real-HA reviews receive the
code-enforced capability facts (§16 of the as-built document).

**v0.8.2 (P1):** besides synthetic operations, GAOP can read exactly `sun.sun` and set exactly
`input_boolean.gaop_pilot_probe` (Home Assistant Core API only; Supervisor API disabled). See §15 of the
as-built document.

**v0.8.0:** the canonical as-built description of the production mechanisms (R1 package/authority binding,
R2 idempotency/checkpoints, R3 capability scoping, budgets, liveness, dual-AI review/disagreement,
anti-assumption) is `governance/GAOP_PRODUCTION_ARCHITECTURE_AS_BUILT_v1.0.0_2026-10-07.md` in the private
source repository. Sections below describe the v0.7.x foundation, which v0.8.0 keeps; where they differ the
as-built document governs (notably: `openai-api` is a reviewer route, not an executor; envelopes carry a
`role`; terminal `PARTIAL`; receipt `gaop.receipt.v3`).

This file is the self-sufficient operating description of the repository-installed GAOP App.
The earlier local POC App (`local_gaop_gate_a_poc`, v0.6.0) is **retained historical evidence
only** — stopped, manual, unchanged, not production, and its `/data` is never migrated.

## 1. Normal operation: Dashboard only
- For ordinary queries and authorised changes the owner interacts **only with the GAOP Dashboard**
  (the GAOP panel in the Home Assistant sidebar, on desktop and in the Home Assistant Companion app).
- Flow: request/query → proposal + evidence → **one Authorize press** (when consequential) → GAOP
  dispatches the machine participants → result/verification → result on the Dashboard.
- **One meaningful user decision = one transaction authority.** One Authorize covers every disclosed,
  bounded internal handoff, execution, verification, evidence-archiving and closeout step of that exact
  transaction. Internal handoffs never re-prompt. A new approval is needed only for a new or materially
  changed transaction (scope, target, value, effect, revision, expiry/cancellation).
- No fingerprint, face, passkey or password re-entry is required for approval.
- Opening Claude, ChatGPT, ChatGPT Work, GitHub, a terminal, Samba or a cloud console is **not** part of
  normal operation. Browser/manual sessions are development/recovery fallback only.
- One-time SETUP / RECOVERY actions (installation bootstrap, OAuth/provider connection) are explicitly
  classified as such and are not normal transaction flow.

## 2. Authority separation
- The owner Ingress handler (`POST /authority`) is the **sole writer of authority** into App-private
  `/data`. It accepts a request only when (i) the peer is the Supervisor ingress gateway, (ii) the
  Supervisor-injected `X-Remote-User-Id` matches the salted SHA-256 owner pin (the literal owner ID is
  not published), (iii) proposal hash, transaction, scope, expiry and `state_version` match the
  persisted pending proposal, and (iv) the one-time nonce is unused.
- Authority is **not** exposed through HA-MCP, App options, control envelopes, provider adapters or any
  executor route. Envelopes containing authority-bearing keys are rejected fail-closed; the App options
  schema has no authority field. A non-owner (including the HA-MCP service user) sees a read-only panel.
- An AI runtime with browser/computer-use control of the owner's authenticated Dashboard must not count
  as the independent executor for that authorization event.

## 3. Transaction state machine (App-private /data, schema `gaop.store` v1)
`PROPOSED → AWAITING_AUTHORITY → AUTHORIZED → DISPATCH_PENDING → DISPATCHED → CLAIMED → RUNNING →
RESULT_PERSISTED → VERIFIED → COMPLETED`, terminal alternatives `REJECTED / CANCELLED / EXPIRED /
DENIED / STOP`, and `UNKNOWN_RECONCILE` (explicit resolution required).
- Every record carries protocol/schema version, stable transaction ID, `state_version` (CAS), proposal
  + hash + revision, authority, dispatch, claim/lease, execution, result/receipt, evidence, reconcile.
- One active claim per transaction; stale leases go to `UNKNOWN_RECONCILE` (no implicit takeover).
- Replay/idempotency: every envelope digest is recorded; a replayed envelope has no second effect.
- Restart never replays: interrupted `RUNNING/DISPATCH_PENDING/RESULT_PERSISTED/VERIFIED` records move
  to `UNKNOWN_RECONCILE`; completed records are untouched.
- Unknown newer store schema fails closed; migration hooks exist for future versions.

## 4. Bounded control ingress (executors)
- Primary route: `POST /control` on the Supervisor Ingress port (no App restart). Fallback: App option
  `control_envelope` (applied by Supervisor only at App start). Same envelope either way.
- Protocol `gaop.control.v1`, **≤ 4096 bytes**, secret-free, synthetic
  allowlisted operations only in v0.7.0 (`synthetic.echo`, targets `synthetic:*`).
- Ops: `propose`, `revise`, `cancel`, `claim`, `begin`, `result`. Malformed, truncated, oversize or
  unsupported-protocol envelopes fail closed.
- The Dual AI Mailbox is bounded admin/fallback control only — never bulk payload transport.

## 5. Exact retrieval / egress
- Exact retrieval by stable ID only: `api/txn/<TXN>`, `api/pkg/<TXN>`, `api/receipt/<TXN>`,
  `api/attestation`. No list-all endpoint; no unrelated metadata disclosure. Packages ≤ 8 KiB with an
  integrity hash; truncation/partial package ⇒ STOP before mutation.

## 6. Provider adapters (machine-addressable production routes)
- **Standing setup vs per-transaction authority.** A provider API key is a one-time, owner-entered SETUP
  (GAOP Setup card → App-private `/data`, 0600, never echoed/logged, deletable). It is not authority.
  Every consequential transaction still needs exactly one Dashboard Authorize press; there are **no
  recurring provider "Allow once" prompts** in production.
- **Production route = provider API** (`claude-api`: Anthropic Messages API; `openai-api`: OpenAI Chat
  Completions). The App is the executor: claim → provider call → result bound to transaction ID +
  proposal hash + correlation ID → verify → evidence → COMPLETED. Consumer browser/chat sessions are
  development/recovery fallback only.
- Fail closed: not configured / auth / rejected / malformed / binding mismatch → STOP; timeout / network /
  5xx → UNKNOWN_RECONCILE, never retried blindly. Executors cannot claim or post results for API routes.
- Contract input: transaction ID, route, payload locator, integrity hash, authorized action ID,
  expiry/idempotency. Output: dispatch ack, claim identity, result locator/hash, receipt/status,
  error/reconcile. Adapters never carry authority.
- Routes: `claude-session` / `github-executor` (pull: package published at an exact locator; the
  executor claims via the control ingress), `claude-api` / `openai-api` (API routes; require a one-time
  provider credential in `/data` — absent ⇒ fail closed `STOP`), `mock` (tests).
- Live programmatic activation of Claude/ChatGPT sessions is a recorded external prerequisite; manual
  session switching is development fallback and never counts as production acceptance.

## 7. Source → distribution → installed chain
- `SFF2101/home-assistant-gaop` (private) = authoritative source (`gaop/app/`).
- `SFF2101/gaop-public` = generated, secret-free distribution (`repository.yaml` + `gaop/`), built by
  `gaop/tools/build_release.py` from an exact private commit; `GAOP_RELEASE.json` binds version, private
  source commit, package schema, per-file SHA-256 and build time.
- Supervisor pulls/updates from `gaop-public`. At every start the App verifies its runtime files against
  `GAOP_RELEASE.json` and logs `ATTESTATION MATCH|MISMATCH`; on mismatch authority is disabled.
- Rollback: revert `gaop-public` to the previous release commit, then Supervisor update.

## 8. Planes and boundaries
- `/data` = live transaction/authority/receipt state and runtime credentials (`/data/gaop/cred`, 0600).
- Google Drive (`drive.file` only) = archive/evidence only, never the live store. The Drive credential is
  bootstrapped with Google's device flow from the owner panel (one-time SETUP); it is never logged,
  returned by an API, or placed in options, GitHub or the mailbox. Before any Drive write the App checks
  the existing GAOP root/folder; if inaccessible it STOPs and never creates a duplicate root.
- Home Assistant backups remain outside GAOP. No generic shell, broad maps, broad OAuth scopes,
  Supervisor/HA/Docker API access, or host network.

## 8a. Drive evidence receipt (v0.7.2)
- Receipt `gaop.receipt.v2` records: evidence status, file SHA-256, integrity (re-download match),
  disposition `DELETED` / `RETAINED_DELETE_FAILED` (with delete verification), unrelated-ID denial
  result (must be denied, otherwise STOP), the existing GAOP root/folder IDs used, and an archive
  correlation ID. The App never creates a GAOP root or folder.

## 8b. Reconciliation
- `UNKNOWN_RECONCILE` is resolved only by an explicit `reconcile` envelope to `CANCELLED`, allowed only when
  no result was persisted and no evidence step ran. The interruption record is preserved and the
  transaction record is never deleted. (TXN-05R-M2M-0001, the v0.7.0 interrupted-write proof, is reconciled
  this way in DAI-IN-503.)

## 9. Failure semantics
- STOP and UNKNOWN_RECONCILE are explicit, persisted states. There is **no blind retry**; uncertain
  outcomes require explicit reconciliation.

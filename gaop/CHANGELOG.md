# Changelog

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

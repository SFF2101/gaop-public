#!/usr/bin/env python3
"""GAOP v0.7.0 — durable production generation: control plane core.

Single stdlib-only module. Roles (repository-role invariant):
  GitHub private repo = source; gaop-public = generated secret-free distribution;
  App-private /data = live transaction/authority/receipt state + runtime credentials;
  Google Drive = archive/evidence only.

Planes and who may write them:
  * CONTROL INGRESS (executors: Claude / ChatGPT / adapters) -> App option `control_envelope`
    (<= 4096 bytes, versioned, secret-free). It can propose/revise/cancel/claim/begin/result.
    It can NEVER carry or create authority (authority-bearing keys are rejected fail-closed).
  * AUTHORITY (owner only) -> HTTP POST /authority on the Supervisor Ingress port. Accepted only
    from the Supervisor ingress gateway with the Supervisor-injected X-Remote-User-Id whose salted
    SHA-256 equals OWNER_PIN. This handler is the SOLE writer of authority records.
  * READ (any authenticated ingress caller) -> exact retrieval by transaction ID only
    (/api/txn/<id>, /api/pkg/<id>, /api/receipt/<id>, /api/attestation); no list-all endpoint.

Modes (App option `mode`): idle (default: serve panel + process envelopes; NO harness replay),
selftest (deterministic Phase-E matrix, then idle).
"""
import fcntl, hashlib, html, json, os, re, secrets, sys, threading, time
import urllib.error, urllib.parse, urllib.request, ssl, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.7.1"
PROTOCOL = "gaop.control.v1"
STORE_SCHEMA = 1                      # gaop.store.v1 — defined from first principles (no POC migration)
MAX_ENVELOPE_BYTES = 4096
MAX_PACKAGE_BYTES = 8192
MAX_RESULT_BYTES = 1024
MAX_TTL_SECONDS = 3600
LEASE_SECONDS = 600
MAX_ACTIVE = 20
INGRESS_GATEWAY = "172.30.32.2"
OWNER_PIN_PREFIX = "gaop.owner-pin.v1:"
# sha256(OWNER_PIN_PREFIX + <HA owner user id>). The literal owner ID is never published.
OWNER_PIN = "deb39f6c5eaeb0d19713042adc11435425a59c28f2e41e012411e54839f70361"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"

ALLOWED_OPS = {"synthetic.echo"}       # synthetic/allowlisted operations only (Phase 0.5R)
ALLOWED_ROUTES = {"claude-session", "claude-api", "openai-api", "github-executor", "mock"}
ENVELOPE_OPS = {"propose", "revise", "cancel", "claim", "begin", "result"}
FORBIDDEN_KEYS = {"authority", "authorized", "authorize", "authorization", "approval", "approve",
                  "approved", "owner", "owner_pin", "auth_nonce", "nonce"}
TERMINAL = {"COMPLETED", "REJECTED", "CANCELLED", "EXPIRED", "DENIED", "STOP"}
STATES = ["PROPOSED", "AWAITING_AUTHORITY", "AUTHORIZED", "DISPATCH_PENDING", "DISPATCHED",
          "CLAIMED", "RUNNING", "RESULT_PERSISTED", "VERIFIED", "COMPLETED",
          "REJECTED", "CANCELLED", "EXPIRED", "DENIED", "STOP", "UNKNOWN_RECONCILE"]
TXN_RE = re.compile(r"^TXN-[A-Z0-9][A-Z0-9-]{2,40}$")
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")

DATA = os.environ.get("GAOP_DATA", "/data")
ROOT = os.path.join(DATA, "gaop")
RELEASE_PATH = os.environ.get("GAOP_RELEASE", "/GAOP_RELEASE.json")
PKG_FILES_DIR = os.environ.get("GAOP_PKG_DIR", "/")


def now():
    return int(time.time())


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def log(msg):
    print("[gaop] " + msg, flush=True)


class Denied(Exception):
    def __init__(self, code, detail=""):
        super().__init__("%s %s" % (code, detail))
        self.code = code
        self.detail = detail


# ============================== versioned store ==============================
class Store:
    """App-private, versioned transaction store with CAS (state_version) and an exclusive lock.
    Layout: <root>/meta.json, <root>/txn/<TXN>.json, <root>/active.json (bounded index of
    non-terminal IDs, used only for boot reconciliation and the owner panel), <root>/seen/<sha>."""

    MIGRATIONS = {}   # {from_schema: fn(root)} — future hooks; none needed for schema 1

    def __init__(self, root):
        self.root = root
        for d in ("", "txn", "seen", "cred"):
            os.makedirs(os.path.join(root, d), exist_ok=True)
        os.chmod(os.path.join(root, "cred"), 0o700)
        self._lockf = open(os.path.join(root, ".lock"), "a+")
        self._init_schema()

    def _init_schema(self):
        mp = os.path.join(self.root, "meta.json")
        if not os.path.exists(mp):
            self._atomic(mp, {"store": "gaop.store", "schema": STORE_SCHEMA, "created": now(),
                              "gaop_version": VERSION})
            log("STORE schema=%d initialised (clean /data; no POC migration)" % STORE_SCHEMA)
            return
        meta = json.load(open(mp))
        s = meta.get("schema")
        if not isinstance(s, int) or s > STORE_SCHEMA:
            raise Denied("UNSUPPORTED_SCHEMA", "store schema %r > supported %d" % (s, STORE_SCHEMA))
        while s < STORE_SCHEMA:
            fn = self.MIGRATIONS.get(s)
            if fn is None:
                raise Denied("UNSUPPORTED_SCHEMA", "no migration from %d" % s)
            fn(self.root)
            s += 1
            meta["schema"] = s
            self._atomic(mp, meta)
        log("STORE schema=%d ok" % s)

    @staticmethod
    def _atomic(path, obj):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(obj, sort_keys=True, indent=1).encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def lock(self):
        fcntl.flock(self._lockf, fcntl.LOCK_EX)

    def unlock(self):
        fcntl.flock(self._lockf, fcntl.LOCK_UN)

    def _tp(self, txn_id):
        if not TXN_RE.match(txn_id or ""):
            raise Denied("MALFORMED", "txn_id")
        return os.path.join(self.root, "txn", txn_id + ".json")

    def get(self, txn_id):
        p = self._tp(txn_id)
        if not os.path.exists(p):
            return None
        return json.load(open(p))

    def put(self, rec, expected_version):
        """CAS write: only succeeds if the stored state_version == expected_version."""
        cur = self.get(rec["txn_id"])
        cur_v = cur["state_version"] if cur else 0
        if cur_v != expected_version:
            raise Denied("CAS_CONFLICT", "expected %s found %s" % (expected_version, cur_v))
        rec["state_version"] = expected_version + 1
        rec["updated"] = now()
        self._atomic(self._tp(rec["txn_id"]), rec)
        self._index(rec)
        return rec

    def _index(self, rec):
        ap = os.path.join(self.root, "active.json")
        act = json.load(open(ap)) if os.path.exists(ap) else []
        if rec["state"] in TERMINAL:
            act = [t for t in act if t != rec["txn_id"]]
        elif rec["txn_id"] not in act:
            act.append(rec["txn_id"])
        self._atomic(ap, act[-MAX_ACTIVE:])

    def active(self):
        ap = os.path.join(self.root, "active.json")
        return json.load(open(ap)) if os.path.exists(ap) else []

    def seen(self, key):
        return os.path.exists(os.path.join(self.root, "seen", key))

    def mark_seen(self, key, outcome):
        self._atomic(os.path.join(self.root, "seen", key), outcome)

    def seen_outcome(self, key):
        return json.load(open(os.path.join(self.root, "seen", key)))


def transition(rec, new_state, note=""):
    if new_state not in STATES:
        raise Denied("BAD_STATE", new_state)
    rec["history"] = (rec.get("history", []) + [[now(), rec["state"], new_state, note[:80]]])[-40:]
    rec["state"] = new_state
    return rec


def proposal_hash(txn_id, revision, proposal):
    return sha(canon({"protocol": PROTOCOL, "txn_id": txn_id, "revision": revision,
                      "proposal": proposal}))


# ============================== envelope validation ==============================
def _walk_keys(o, acc):
    if isinstance(o, dict):
        for k, v in o.items():
            acc.add(str(k).lower())
            _walk_keys(v, acc)
    elif isinstance(o, list):
        for v in o:
            _walk_keys(v, acc)
    return acc


def parse_envelope(raw):
    """Bounded control ingress. Fail closed on oversize / malformed / unsupported / authority."""
    if raw is None or raw == "":
        return None
    b = raw.encode() if isinstance(raw, str) else raw
    if len(b) > MAX_ENVELOPE_BYTES:
        raise Denied("OVERSIZE", "%d > %d bytes" % (len(b), MAX_ENVELOPE_BYTES))
    try:
        env = json.loads(b.decode())
    except Exception:
        raise Denied("MALFORMED", "not JSON (truncated or corrupt)")
    if not isinstance(env, dict):
        raise Denied("MALFORMED", "not an object")
    if env.get("protocol") != PROTOCOL:
        raise Denied("UNSUPPORTED_PROTOCOL", str(env.get("protocol"))[:40])
    bad = _walk_keys(env, set()) & FORBIDDEN_KEYS
    if bad:
        raise Denied("AUTHORITY_FIELD_REJECTED", ",".join(sorted(bad)))
    op = env.get("op")
    if op not in ENVELOPE_OPS:
        raise Denied("UNSUPPORTED_OP", str(op)[:40])
    if not ID_RE.match(str(env.get("envelope_id", ""))):
        raise Denied("MALFORMED", "envelope_id")
    if not TXN_RE.match(str(env.get("txn_id", ""))):
        raise Denied("MALFORMED", "txn_id")
    return env


def validate_proposal(p):
    if not isinstance(p, dict):
        raise Denied("MALFORMED", "proposal")
    need = {"op", "target", "value", "scope", "effect", "summary", "ttl_seconds", "route"}
    if set(p) - (need | {"evidence"}) or not need <= set(p):
        raise Denied("MALFORMED", "proposal fields")
    if p["op"] not in ALLOWED_OPS:
        raise Denied("OP_NOT_ALLOWLISTED", str(p["op"])[:40])
    if p["route"] not in ALLOWED_ROUTES:
        raise Denied("ROUTE_NOT_ALLOWED", str(p["route"])[:40])
    if p.get("evidence", "none") not in ("none", "drive"):
        raise Denied("MALFORMED", "evidence")
    if not isinstance(p["ttl_seconds"], int) or not 60 <= p["ttl_seconds"] <= MAX_TTL_SECONDS:
        raise Denied("MALFORMED", "ttl_seconds")
    for k in ("target", "scope", "effect", "summary"):
        if not isinstance(p[k], str) or len(p[k]) > 200:
            raise Denied("MALFORMED", k)
    if not str(p["target"]).startswith("synthetic:"):
        raise Denied("SCOPE_NOT_SYNTHETIC", "target must be synthetic:")
    return p


# ============================== provider adapters ==============================
class AdapterResult(dict):
    pass


class Adapter:
    """Bounded adapter contract. Input: txn_id, route, payload locator, integrity hash,
    authorized action id, expiry/idempotency. Output: ack, claim identity, result locator/hash,
    receipt/status, error/reconcile. Adapters never see or carry authority."""
    route = None

    def dispatch(self, *, txn_id, locator, package_sha256, action_id, expires_at, idempotency_key):
        raise NotImplementedError


class PullAdapter(Adapter):
    """claude-session / github-executor: the package is published at an exact locator; the
    executor claims it through the control ingress. Activation of the executor session is an
    external pilot dependency (no programmatic Claude-session activation API)."""
    def __init__(self, route):
        self.route = route

    def dispatch(self, **kw):
        return AdapterResult(status="DISPATCHED", mode="pull", route=self.route,
                             locator=kw["locator"], ack="ack-" + kw["idempotency_key"][:16])


class ApiAdapter(Adapter):
    """claude-api / openai-api: machine-addressable provider routes. Requires a provider
    credential in App-private /data (one-time SETUP). Absent credential -> fail closed (STOP)."""
    def __init__(self, route, cred_path, endpoint=None):
        self.route, self.cred_path, self.endpoint = route, cred_path, endpoint

    def dispatch(self, **kw):
        if self.endpoint is None and not os.path.exists(self.cred_path):
            return AdapterResult(status="STOP", error="PROVIDER_NOT_CONFIGURED", route=self.route)
        if self.endpoint is not None:          # deterministic synthetic endpoint (tests)
            return self.endpoint(**kw)
        return AdapterResult(status="STOP", error="LIVE_PROVIDER_NOT_ENABLED_IN_0.7.0",
                             route=self.route)


def adapter_for(route, store):
    if route in ("claude-session", "github-executor", "mock"):
        return PullAdapter(route)
    return ApiAdapter(route, os.path.join(store.root, "cred", route + ".json"))


# ============================== engine ==============================
class Engine:
    def __init__(self, store, adapters=None, clock=now):
        self.s = store
        self.adapters = adapters or {}
        self.clock = clock

    # ---------- control ingress ----------
    def apply_envelope(self, raw):
        """Returns an outcome dict. Idempotent per envelope digest: a replayed envelope has no
        second effect (returns the recorded outcome)."""
        b = raw.encode() if isinstance(raw, str) else (raw or b"")
        key = "env-" + sha(b)
        self.s.lock()
        try:
            if self.s.seen(key):
                out = dict(self.s.seen_outcome(key))
                out["replay"] = True
                return out
            try:
                env = parse_envelope(raw)
                if env is None:
                    return {"outcome": "NOOP"}
                out = getattr(self, "_op_" + env["op"])(env)
                out.update(outcome="ACCEPTED", op=env["op"], txn_id=env["txn_id"])
            except Denied as d:
                out = {"outcome": "DENIED", "code": d.code, "detail": d.detail[:120]}
            out["envelope_sha256"] = key[4:]
            self.s.mark_seen(key, out)
            return out
        finally:
            self.s.unlock()

    def _load(self, txn_id, expect=None):
        rec = self.s.get(txn_id)
        if rec is None:
            raise Denied("UNKNOWN_TXN", txn_id)
        self._expire(rec)
        if expect and rec["state"] not in expect:
            raise Denied("WRONG_STATE", rec["state"])
        return rec

    def _expire(self, rec):
        if rec["state"] in ("AWAITING_AUTHORITY", "AUTHORIZED", "DISPATCH_PENDING", "DISPATCHED") \
                and self.clock() > rec["expires_at"]:
            v = rec["state_version"]
            transition(rec, "EXPIRED", "expiry reached before execution")
            rec["authority"] = None
            self.s.put(rec, v)
            raise Denied("EXPIRED", rec["txn_id"])

    def _op_propose(self, env):
        txn_id = env["txn_id"]
        if self.s.get(txn_id) is not None:
            raise Denied("DUPLICATE_TXN", txn_id)
        if len([t for t in self.s.active()]) >= MAX_ACTIVE:
            raise Denied("CAPACITY", "too many active transactions")
        p = validate_proposal(env.get("proposal"))
        rec = {"protocol": PROTOCOL, "store_schema": STORE_SCHEMA, "txn_id": txn_id,
               "state": "PROPOSED", "created": self.clock(), "revision": 1, "proposal": p,
               "proposal_sha256": proposal_hash(txn_id, 1, p),
               "expires_at": self.clock() + p["ttl_seconds"], "authority": None,
               "pending_nonce": secrets.token_hex(16), "used_nonces": [], "dispatch": None,
               "claim": None, "execution": None, "result": None, "receipt": None,
               "evidence": None, "reconcile": None, "history": []}
        transition(rec, "AWAITING_AUTHORITY", "proposal persisted")
        self.s.put(rec, 0)
        return {"state": rec["state"], "proposal_sha256": rec["proposal_sha256"]}

    def _op_revise(self, env):
        rec = self._load(env["txn_id"], {"PROPOSED", "AWAITING_AUTHORITY", "AUTHORIZED",
                                          "DISPATCH_PENDING", "DISPATCHED"})
        if env.get("base_state_version") != rec["state_version"]:
            raise Denied("CAS_CONFLICT", "base_state_version")
        p = validate_proposal(env.get("proposal"))
        v = rec["state_version"]
        rec["revision"] += 1
        rec["proposal"] = p
        rec["proposal_sha256"] = proposal_hash(rec["txn_id"], rec["revision"], p)
        rec["expires_at"] = self.clock() + p["ttl_seconds"]
        if rec["pending_nonce"]:
            rec["used_nonces"].append(rec["pending_nonce"])
        rec["pending_nonce"] = secrets.token_hex(16)
        rec["authority"] = None          # material revision invalidates prior authority
        rec["dispatch"] = None
        transition(rec, "AWAITING_AUTHORITY", "revised r%d; prior authority invalidated" % rec["revision"])
        self.s.put(rec, v)
        return {"state": rec["state"], "proposal_sha256": rec["proposal_sha256"], "revision": rec["revision"]}

    def _op_cancel(self, env):
        rec = self._load(env["txn_id"])
        if rec["state"] in TERMINAL:
            raise Denied("WRONG_STATE", rec["state"])
        if rec["state"] in ("RUNNING", "RESULT_PERSISTED", "UNKNOWN_RECONCILE"):
            raise Denied("WRONG_STATE", "cannot cancel in %s; reconcile required" % rec["state"])
        v = rec["state_version"]
        rec["authority"] = None
        transition(rec, "CANCELLED", "cancelled by control envelope")
        self.s.put(rec, v)
        return {"state": "CANCELLED"}

    def _op_claim(self, env):
        rec = self.s.get(env["txn_id"])
        if rec is None:
            raise Denied("UNKNOWN_TXN", env["txn_id"])
        c = rec.get("claim")
        if c and rec["state"] in ("CLAIMED", "RUNNING"):
            if self.clock() > c["lease_until"]:
                v = rec["state_version"]
                rec["reconcile"] = {"reason": "STALE_LEASE", "prior_claim": c["claim_id"],
                                    "at": self.clock()}
                transition(rec, "UNKNOWN_RECONCILE", "stale lease; no implicit takeover")
                self.s.put(rec, v)
                raise Denied("STALE_LEASE_RECONCILE", c["claim_id"])
            raise Denied("ALREADY_CLAIMED", c["claim_id"])
        rec = self._load(env["txn_id"], {"DISPATCHED"})
        if env.get("package_sha256") != rec["dispatch"]["package_sha256"]:
            raise Denied("HASH_MISMATCH", "package_sha256")
        ex = str(env.get("executor", ""))
        if not ID_RE.match(ex):
            raise Denied("MALFORMED", "executor")
        v = rec["state_version"]
        rec["claim"] = {"claim_id": "clm-" + secrets.token_hex(8), "executor": ex,
                        "claimed_at": self.clock(), "lease_until": self.clock() + LEASE_SECONDS}
        transition(rec, "CLAIMED", "claimed by " + ex)
        self.s.put(rec, v)
        return {"state": "CLAIMED", "claim_id": rec["claim"]["claim_id"],
                "lease_until": rec["claim"]["lease_until"]}

    def _claimed(self, env, states):
        rec = self._load(env["txn_id"], states)
        c = rec.get("claim") or {}
        if env.get("claim_id") != c.get("claim_id"):
            raise Denied("NOT_CLAIM_HOLDER", "claim_id")
        if self.clock() > c.get("lease_until", 0):
            v = rec["state_version"]
            rec["reconcile"] = {"reason": "STALE_LEASE", "prior_claim": c.get("claim_id"),
                                "at": self.clock()}
            transition(rec, "UNKNOWN_RECONCILE", "lease expired mid-execution")
            self.s.put(rec, v)
            raise Denied("STALE_LEASE_RECONCILE", c.get("claim_id", ""))
        return rec

    def _op_begin(self, env):
        rec = self._claimed(env, {"CLAIMED"})
        v = rec["state_version"]
        rec["execution"] = {"started_at": self.clock(), "maybe_write": True,
                            "action_id": rec["dispatch"]["action_id"]}
        transition(rec, "RUNNING", "execution started (maybe-write marker set)")
        self.s.put(rec, v)
        return {"state": "RUNNING"}

    def _op_result(self, env):
        rec = self._claimed(env, {"RUNNING"})
        res = env.get("result")
        rb = canon(res)
        if len(rb) > MAX_RESULT_BYTES:
            raise Denied("OVERSIZE", "result")
        if env.get("result_sha256") != sha(rb):
            raise Denied("RESULT_HASH_MISMATCH", "result_sha256")
        v = rec["state_version"]
        rec["result"] = {"result": res, "result_sha256": sha(rb), "persisted_at": self.clock(),
                         "executor": rec["claim"]["executor"]}
        rec["execution"]["maybe_write"] = False
        transition(rec, "RESULT_PERSISTED", "result persisted")
        self.s.put(rec, v)
        return self._verify_and_close(rec["txn_id"])

    # ---------- verification / closeout ----------
    def _verify_and_close(self, txn_id, drive=None):
        rec = self.s.get(txn_id)
        p, r = rec["proposal"], rec["result"]["result"]
        ok = (p["op"] == "synthetic.echo" and isinstance(r, dict)
              and r.get("echo") == p["value"] and r.get("txn_id") == txn_id
              and r.get("proposal_sha256") == rec["proposal_sha256"])
        v = rec["state_version"]
        if not ok:
            transition(rec, "STOP", "verification failed: result does not satisfy proposal")
            self.s.put(rec, v)
            return {"state": "STOP"}
        transition(rec, "VERIFIED", "result verified against proposal")
        rec = self.s.put(rec, v)
        evidence = {"mode": p.get("evidence", "none"), "status": "NOT_REQUIRED"}
        if p.get("evidence") == "drive":
            evidence = self.drive_evidence(rec) if self.adapters.get("drive_evidence") is None \
                else self.adapters["drive_evidence"](rec)
        rec = self.s.get(txn_id)
        v = rec["state_version"]
        rec["evidence"] = evidence
        if evidence.get("status") not in ("NOT_REQUIRED", "ARCHIVED_VERIFIED"):
            transition(rec, "STOP", "evidence step failed: " + str(evidence.get("status")))
            self.s.put(rec, v)
            return {"state": "STOP", "evidence": evidence.get("status")}
        rec["receipt"] = self.make_receipt(rec, "COMPLETED")
        transition(rec, "COMPLETED", "closed out")
        self.s.put(rec, v)
        return {"state": "COMPLETED", "receipt_sha256": rec["receipt"]["receipt_sha256"]}

    def drive_evidence(self, rec):
        return {"mode": "drive", "status": "STOP_NO_DRIVE_CREDENTIAL"}

    @staticmethod
    def make_receipt(rec, final):
        body = {"schema": "gaop.receipt.v1", "txn_id": rec["txn_id"],
                "proposal_sha256": rec["proposal_sha256"], "revision": rec["revision"],
                "authority_sha256": (rec.get("authority") or {}).get("authority_sha256"),
                "dispatch_id": (rec.get("dispatch") or {}).get("dispatch_id"),
                "package_sha256": (rec.get("dispatch") or {}).get("package_sha256"),
                "claim_id": (rec.get("claim") or {}).get("claim_id"),
                "executor": (rec.get("claim") or {}).get("executor"),
                "result_sha256": (rec.get("result") or {}).get("result_sha256"),
                "evidence_status": (rec.get("evidence") or {}).get("status"),
                "evidence_file_sha256": (rec.get("evidence") or {}).get("sha256"),
                "final_state": final, "gaop_version": VERSION}
        body["receipt_sha256"] = sha(canon(body))
        return body

    # ---------- authority (called ONLY from the owner-ingress handler) ----------
    def owner_decision(self, *, peer, remote_user_id, txn_id, proposal_sha256, state_version,
                       nonce, decision):
        if peer != INGRESS_GATEWAY:
            raise Denied("NOT_INGRESS_GATEWAY", peer)
        if not remote_user_id or sha((OWNER_PIN_PREFIX + remote_user_id).encode()) != OWNER_PIN:
            raise Denied("NOT_OWNER", "identity pin mismatch")
        self.s.lock()
        try:
            rec = self._load(txn_id, {"AWAITING_AUTHORITY"})
            if str(state_version) != str(rec["state_version"]):
                raise Denied("STALE_VIEW", "state_version")
            if proposal_sha256 != rec["proposal_sha256"]:
                raise Denied("HASH_MISMATCH", "proposal_sha256")
            if nonce in rec["used_nonces"]:
                raise Denied("REPLAY", "nonce already used")
            if not rec["pending_nonce"] or nonce != rec["pending_nonce"]:
                raise Denied("NONCE_MISMATCH", "nonce")
            v = rec["state_version"]
            rec["used_nonces"].append(nonce)
            rec["pending_nonce"] = None
            if decision == "reject":
                transition(rec, "REJECTED", "owner rejected on dashboard")
                self.s.put(rec, v)
                return {"state": "REJECTED"}
            if decision == "revise":
                transition(rec, "PROPOSED", "owner requested revision on dashboard")
                rec["reconcile"] = {"reason": "REVISION_REQUESTED", "at": self.clock()}
                self.s.put(rec, v)
                return {"state": "PROPOSED"}
            if decision != "authorize":
                raise Denied("MALFORMED", "decision")
            a = {"txn_id": txn_id, "proposal_sha256": rec["proposal_sha256"],
                 "revision": rec["revision"], "scope": rec["proposal"]["scope"],
                 "target": rec["proposal"]["target"], "expires_at": rec["expires_at"],
                 "nonce_sha256": sha(nonce.encode()), "authorized_at": self.clock(),
                 "origin": "dashboard-ingress-owner"}
            a["authority_sha256"] = sha(canon(a))
            rec["authority"] = a
            transition(rec, "AUTHORIZED", "owner authorized on dashboard")
            rec = self.s.put(rec, v)
            return self._dispatch(rec)
        finally:
            self.s.unlock()

    def _dispatch(self, rec):
        if rec["state"] != "AUTHORIZED":
            raise Denied("DUPLICATE_DISPATCH", rec["state"])
        v = rec["state_version"]
        transition(rec, "DISPATCH_PENDING", "dispatch pending")
        rec = self.s.put(rec, v)
        pkg = {"schema": "gaop.package.v1", "txn_id": rec["txn_id"], "revision": rec["revision"],
               "proposal": rec["proposal"], "proposal_sha256": rec["proposal_sha256"],
               "authority_sha256": rec["authority"]["authority_sha256"],
               "action_id": "act-" + rec["proposal_sha256"][:16], "expires_at": rec["expires_at"]}
        pb = canon(pkg)
        if len(pb) > MAX_PACKAGE_BYTES:
            v = rec["state_version"]
            transition(rec, "STOP", "package exceeds bound")
            self.s.put(rec, v)
            return {"state": "STOP"}
        route = rec["proposal"]["route"]
        ad = self.adapters.get(route) or adapter_for(route, self.s)
        idem = sha(canon({"txn_id": rec["txn_id"], "proposal_sha256": rec["proposal_sha256"],
                          "authority_sha256": rec["authority"]["authority_sha256"]}))
        ack = ad.dispatch(txn_id=rec["txn_id"], locator="api/pkg/" + rec["txn_id"],
                          package_sha256=sha(pb), action_id=pkg["action_id"],
                          expires_at=rec["expires_at"], idempotency_key=idem)
        v = rec["state_version"]
        rec["dispatch"] = {"dispatch_id": "dsp-" + idem[:16], "route": route,
                           "package": pkg, "package_sha256": sha(pb),
                           "action_id": pkg["action_id"], "ack": dict(ack),
                           "dispatched_at": self.clock()}
        if ack.get("status") != "DISPATCHED":
            transition(rec, "STOP", "adapter: " + str(ack.get("error")))
            self.s.put(rec, v)
            return {"state": "STOP", "adapter_error": ack.get("error")}
        transition(rec, "DISPATCHED", "dispatched via " + route)
        self.s.put(rec, v)
        return {"state": "DISPATCHED", "package_sha256": sha(pb)}

    # ---------- boot reconciliation (restart never replays) ----------
    def boot_reconcile(self):
        out = []
        for t in self.s.active():
            rec = self.s.get(t)
            if rec is None:
                continue
            if rec["state"] in ("RUNNING", "DISPATCH_PENDING", "RESULT_PERSISTED", "VERIFIED"):
                v = rec["state_version"]
                rec["reconcile"] = {"reason": "INTERRUPTED_" + rec["state"], "at": self.clock()}
                transition(rec, "UNKNOWN_RECONCILE", "restart found interrupted maybe-write; no replay")
                self.s.put(rec, v)
                out.append((t, "UNKNOWN_RECONCILE"))
        return out

    # ---------- exact, bounded retrieval (no list-all) ----------
    def view(self, txn_id, owner=False):
        rec = self.s.get(txn_id)
        if rec is None:
            raise Denied("UNKNOWN_TXN", txn_id)
        v = {k: rec[k] for k in ("txn_id", "state", "state_version", "revision", "proposal",
                                 "proposal_sha256", "expires_at", "reconcile")}
        v["authority_sha256"] = (rec.get("authority") or {}).get("authority_sha256")
        v["claim"] = {k: (rec.get("claim") or {}).get(k) for k in ("claim_id", "executor", "lease_until")}
        v["result_sha256"] = (rec.get("result") or {}).get("result_sha256")
        v["evidence_status"] = (rec.get("evidence") or {}).get("status")
        v["receipt_sha256"] = (rec.get("receipt") or {}).get("receipt_sha256")
        if owner and rec["state"] == "AWAITING_AUTHORITY":
            v["pending_nonce"] = rec["pending_nonce"]
        return v

    def package(self, txn_id):
        rec = self.s.get(txn_id)
        if rec is None or not rec.get("dispatch") or rec["state"] not in ("DISPATCHED", "CLAIMED", "RUNNING"):
            raise Denied("NO_PACKAGE", txn_id)
        pb = canon(rec["dispatch"]["package"])
        if len(pb) > MAX_PACKAGE_BYTES or sha(pb) != rec["dispatch"]["package_sha256"]:
            raise Denied("PACKAGE_INTEGRITY", txn_id)
        return {"package": rec["dispatch"]["package"], "package_sha256": sha(pb),
                "bytes": len(pb)}


# ============================== attestation ==============================
def attest():
    try:
        rel = json.load(open(RELEASE_PATH))
    except Exception:
        return {"attestation": "MISSING_RELEASE", "ok": False}
    files = rel.get("runtime_files", {})
    bad = []
    for name, h in sorted(files.items()):
        p = os.path.join(PKG_FILES_DIR, name)
        try:
            got = sha(open(p, "rb").read())
        except Exception:
            got = None
        if got != h:
            bad.append(name)
    ok = (not bad) and rel.get("gaop_version") == VERSION and bool(files)
    return {"attestation": "MATCH" if ok else "MISMATCH", "ok": ok,
            "gaop_version": rel.get("gaop_version"), "private_source_commit": rel.get("private_source_commit"),
            "package_digest": rel.get("package_digest"), "package_schema": rel.get("package_schema"),
            "build_timestamp": rel.get("build_timestamp"), "mismatched": bad}


# ============================== Google Drive (drive.file) ==============================
class DriveError(Exception):
    def __init__(self, status, msg=""):
        super().__init__("drive-error %s %s" % (status, msg))
        self.status = status


def _post_form(url, fields, ctx):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return 200, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


class DriveCred:
    """Device Authorization Grant bootstrap. Client config and token live ONLY in
    <root>/cred (0600). Nothing credential-bearing is ever logged or returned by an API."""
    def __init__(self, store):
        self.dir = os.path.join(store.root, "cred")
        self.client_p = os.path.join(self.dir, "drive_client.json")
        self.token_p = os.path.join(self.dir, "drive_token.json")
        self.flow_p = os.path.join(self.dir, "drive_device_flow.json")
        self.ctx = ssl.create_default_context()

    def _w(self, p, o):
        Store._atomic(p, o)
        os.chmod(p, 0o600)

    def status(self):
        st = {"client_configured": os.path.exists(self.client_p),
              "token_present": os.path.exists(self.token_p), "flow": None}
        if os.path.exists(self.flow_p):
            f = json.load(open(self.flow_p))
            st["flow"] = {k: f.get(k) for k in ("user_code", "verification_url", "expires_at", "state")}
        if st["token_present"]:
            st["scope"] = json.load(open(self.token_p)).get("scope")
        return st

    def set_client(self, client_id, client_secret):
        if not re.match(r"^[0-9A-Za-z._-]{10,120}\.apps\.googleusercontent\.com$", client_id or ""):
            raise Denied("MALFORMED", "client_id")
        if not re.match(r"^[A-Za-z0-9_-]{10,100}$", client_secret or ""):
            raise Denied("MALFORMED", "client_secret")
        self._w(self.client_p, {"client_id": client_id, "client_secret": client_secret})

    def start(self):
        c = json.load(open(self.client_p))
        code, r = _post_form("https://oauth2.googleapis.com/device/code",
                             {"client_id": c["client_id"], "scope": DRIVE_SCOPE}, self.ctx)
        if code != 200 or "device_code" not in r:
            raise Denied("DEVICE_FLOW_START_FAILED", str(code) + " " + str(r.get("error", ""))[:60])
        self._w(self.flow_p, {"device_code": r["device_code"], "user_code": r["user_code"],
                              "verification_url": r.get("verification_url", "https://www.google.com/device"),
                              "interval": int(r.get("interval", 5)),
                              "expires_at": now() + int(r.get("expires_in", 1800)), "state": "PENDING"})
        log("DRIVE device flow started (user code shown on owner panel only)")

    def poll_once(self):
        if not os.path.exists(self.flow_p):
            return "NO_FLOW"
        f = json.load(open(self.flow_p))
        if f["state"] != "PENDING":
            return f["state"]
        if now() > f["expires_at"]:
            f["state"] = "EXPIRED"
            self._w(self.flow_p, f)
            return "EXPIRED"
        c = json.load(open(self.client_p))
        code, r = _post_form("https://oauth2.googleapis.com/token",
                             {"client_id": c["client_id"], "client_secret": c["client_secret"],
                              "device_code": f["device_code"],
                              "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}, self.ctx)
        if code == 200 and "refresh_token" in r:
            scope = r.get("scope", "")
            if scope.split() != [DRIVE_SCOPE]:
                f["state"] = "SCOPE_REJECTED"
                self._w(self.flow_p, f)
                log("DRIVE token discarded: granted scope is not exactly drive.file")
                return "SCOPE_REJECTED"
            self._w(self.token_p, {"refresh_token": r["refresh_token"], "scope": scope,
                                   "obtained_at": now()})
            f["state"] = "GRANTED"
            f["device_code"] = None
            self._w(self.flow_p, f)
            log("DRIVE credential bootstrapped into /data (scope=drive.file); token not displayed")
            return "GRANTED"
        err = r.get("error", "")
        if err in ("authorization_pending", "slow_down"):
            return "PENDING"
        f["state"] = "FAILED:" + str(err)[:30]
        self._w(self.flow_p, f)
        return f["state"]

    def client(self):
        if not (os.path.exists(self.client_p) and os.path.exists(self.token_p)):
            return None
        c, t = json.load(open(self.client_p)), json.load(open(self.token_p))
        return DriveClient(c["client_id"], c["client_secret"], t["refresh_token"], self.ctx)


class DriveClient:
    def __init__(self, cid, csec, rt, ctx):
        self.cid, self.csec, self.rt, self.ctx, self.access = cid, csec, rt, ctx, None

    def _h(self):
        if not self.access:
            code, r = _post_form("https://oauth2.googleapis.com/token",
                                 {"client_id": self.cid, "client_secret": self.csec,
                                  "refresh_token": self.rt, "grant_type": "refresh_token"}, self.ctx)
            if code != 200:
                raise DriveError(code, "token-refresh")
            self.access = r["access_token"]
        return {"Authorization": "Bearer " + self.access}

    def _req(self, method, url, headers=None, data=None, raw=False):
        h = self._h()
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                b = r.read()
                return b if raw else json.loads(b.decode() or "{}")
        except urllib.error.HTTPError as e:
            raise DriveError(e.code, method + " " + url.split("?")[0])

    def get_meta(self, fid):
        return self._req("GET", "https://www.googleapis.com/drive/v3/files/%s?fields=id,name,mimeType,trashed" % fid)

    def upload(self, name, content, folder_id):
        bd = "gaop" + uuid.uuid4().hex
        body = (("--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" % bd).encode()
                + json.dumps({"name": name, "parents": [folder_id]}).encode()
                + ("\r\n--%s\r\nContent-Type: application/octet-stream\r\n\r\n" % bd).encode()
                + content + ("\r\n--%s--\r\n" % bd).encode())
        return self._req("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,size",
                         headers={"Content-Type": "multipart/related; boundary=" + bd}, data=body)

    def download(self, fid):
        return self._req("GET", "https://www.googleapis.com/drive/v3/files/%s?alt=media" % fid, raw=True)

    def delete(self, fid):
        self._req("DELETE", "https://www.googleapis.com/drive/v3/files/%s" % fid, raw=True)


UNRELATED_PROBE_ID = "1GAOPunrelatedProbeDoesNotExistXXXXXXXXXX"


def drive_evidence_live(cred, opts):
    """B10: continuity check of the EXISTING GAOP root/folder first; never creates a new root.
    Then one bounded synthetic evidence object: upload -> independent re-download + SHA-256 ->
    unrelated-metadata denial probe -> dispose (delete) per disposition."""
    def run(rec):
        dc = cred.client()
        if dc is None:
            return {"mode": "drive", "status": "STOP_NO_DRIVE_CREDENTIAL"}
        root, folder = opts.get("drive_root_id") or "", opts.get("drive_archive_folder_id") or ""
        if not root or not folder:
            return {"mode": "drive", "status": "STOP_DRIVE_TARGET_NOT_CONFIGURED"}
        try:
            r = dc.get_meta(root)
            f = dc.get_meta(folder)
        except DriveError as e:
            return {"mode": "drive", "status": "STOP_EXISTING_ROOT_INACCESSIBLE", "http": e.status}
        if r.get("trashed") or f.get("trashed"):
            return {"mode": "drive", "status": "STOP_EXISTING_ROOT_TRASHED"}
        content = canon({"schema": "gaop.evidence.v1", "synthetic": True, "txn_id": rec["txn_id"],
                         "proposal_sha256": rec["proposal_sha256"],
                         "result_sha256": rec["result"]["result_sha256"], "gaop_version": VERSION})
        h = sha(content)
        try:
            up = dc.upload("gaop_v070_%s_evidence.json" % rec["txn_id"], content, folder)
        except DriveError as e:
            return {"mode": "drive", "status": "UNKNOWN_RECONCILE_UPLOAD", "http": e.status}
        try:
            got = sha(dc.download(up["id"]))
        except DriveError as e:
            return {"mode": "drive", "status": "UNKNOWN_RECONCILE_VERIFY", "file_id": up["id"]}
        denied = False
        try:
            dc.get_meta(UNRELATED_PROBE_ID)
        except DriveError as e:
            denied = e.status in (403, 404)
        out = {"mode": "drive", "file_id": up["id"], "sha256": h, "remote_sha256": got,
               "integrity": "MATCH" if got == h else "MISMATCH", "unrelated_denied": denied,
               "root_accessible": True, "disposition": "deleted"}
        if got != h:
            out["status"] = "STOP_INTEGRITY_MISMATCH"
            return out
        try:
            dc.delete(up["id"])
        except DriveError:
            out["disposition"] = "RETAINED_DELETE_FAILED"
        out["status"] = "ARCHIVED_VERIFIED"
        return out
    return run


# ============================== owner panel (Supervisor Ingress) ==============================
def esc(x):
    return html.escape(str(x), quote=True)


class Handler(BaseHTTPRequestHandler):
    engine = None
    cred = None
    att = None
    server_version = "GAOP/" + VERSION

    def log_message(self, *a):
        pass

    def _ident(self):
        uid = self.headers.get("X-Remote-User-Id", "")
        is_owner = bool(uid) and sha((OWNER_PIN_PREFIX + uid).encode()) == OWNER_PIN
        return self.client_address[0], uid, is_owner

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, sort_keys=True))

    def do_GET(self):
        peer, uid, owner = self._ident()
        path = self.path.split("?")[0].rstrip("/") or "/"
        if peer != INGRESS_GATEWAY:
            log("INGRESS denied GET from non-gateway peer")
            return self._json(403, {"error": "NOT_INGRESS_GATEWAY"})
        try:
            if path == "/":
                return self._send(200, self._panel(owner), "text/html")
            m = re.match(r"^/api/(txn|pkg|receipt)/(TXN-[A-Z0-9-]+)$", path)
            if m:
                kind, t = m.groups()
                if kind == "txn":
                    return self._json(200, self.engine.view(t))
                if kind == "pkg":
                    return self._json(200, self.engine.package(t))
                rec = self.engine.s.get(t)
                if not rec or not rec.get("receipt"):
                    raise Denied("NO_RECEIPT", t)
                return self._json(200, rec["receipt"])
            if path == "/api/attestation":
                return self._json(200, self.att)
            if path == "/api/identity":
                return self._json(200, {"owner": owner,
                                        "identity_sha256": sha((OWNER_PIN_PREFIX + uid).encode()) if uid else None})
            return self._json(404, {"error": "NOT_FOUND"})
        except Denied as d:
            return self._json(404, {"error": d.code})

    def do_POST(self):
        peer, uid, owner = self._ident()
        path = self.path.split("?")[0].rstrip("/")
        n = int(self.headers.get("Content-Length", "0") or 0)
        if path == "/control":
            # Executor control ingress (v0.7.1): same bounded gaop.control.v1 envelope as the
            # `control_envelope` option, delivered without an App restart. Never an authority
            # path: envelopes carrying authority-bearing keys are rejected by parse_envelope.
            if peer != INGRESS_GATEWAY:
                return self._json(403, {"error": "NOT_INGRESS_GATEWAY"})
            if n > MAX_ENVELOPE_BYTES:
                self.rfile.read(min(n, MAX_ENVELOPE_BYTES + 1))
                log("CONTROL DENIED OVERSIZE (%d bytes)" % n)
                return self._json(413, {"outcome": "DENIED", "code": "OVERSIZE"})
            raw = self.rfile.read(n).decode(errors="replace")
            out = self.engine.apply_envelope(raw)
            log("CONTROL %s caller=%s %s" % (sha(raw.encode())[:12],
                "owner" if owner else ("id:" + sha((OWNER_PIN_PREFIX + uid).encode())[:12] if uid else "none"),
                json.dumps(out, sort_keys=True)))
            return self._json(200 if out.get("outcome") in ("ACCEPTED", "NOOP") else 409, out)
        if n > 2048:
            return self._json(413, {"error": "OVERSIZE"})
        form = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
        g = lambda k: (form.get(k) or [""])[0]
        try:
            if path == "/authority":
                if not self.att.get("ok"):
                    raise Denied("ATTESTATION_FAILED", "authority disabled")
                out = self.engine.owner_decision(peer=peer, remote_user_id=uid, txn_id=g("txn_id"),
                                                 proposal_sha256=g("proposal_sha256"),
                                                 state_version=g("state_version"), nonce=g("nonce"),
                                                 decision=g("decision"))
                log("AUTHORITY %s decision=%s -> %s (origin=dashboard-ingress-owner)"
                    % (g("txn_id"), g("decision"), out.get("state")))
                return self._send(200, self._panel(owner, notice="%s: %s" % (g("txn_id"), out.get("state"))), "text/html")
            if path in ("/setup/drive_client", "/setup/drive_start"):
                if peer != INGRESS_GATEWAY or not owner:
                    raise Denied("NOT_OWNER", "setup is owner-only")
                if path == "/setup/drive_client":
                    self.cred.set_client(g("client_id").strip(), g("client_secret").strip())
                    log("SETUP drive OAuth client stored in /data (values not logged)")
                else:
                    self.cred.start()
                return self._send(200, self._panel(owner, notice="setup updated"), "text/html")
            return self._json(404, {"error": "NOT_FOUND"})
        except Denied as d:
            log("AUTHORITY/SETUP DENIED code=%s txn=%s owner=%s gateway=%s"
                % (d.code, g("txn_id")[:48], owner, peer == INGRESS_GATEWAY))
            return self._send(403, self._panel(owner, notice="DENIED: " + d.code), "text/html")

    def _base(self):
        b = self.headers.get("X-Ingress-Path", "")
        return b if re.match(r"^/api/hassio_ingress/[A-Za-z0-9_-]{8,128}$", b) else "."

    def _panel(self, owner, notice=""):
        e = self.engine
        base = esc(self._base())
        rows = []
        for t in e.s.active():
            try:
                v = e.view(t, owner=owner)
            except Denied:
                continue
            p = v["proposal"]
            form = ""
            if owner and v["state"] == "AWAITING_AUTHORITY":
                hid = "".join('<input type="hidden" name="%s" value="%s">' % (k, esc(x)) for k, x in (
                    ("txn_id", v["txn_id"]), ("proposal_sha256", v["proposal_sha256"]),
                    ("state_version", v["state_version"]), ("nonce", v["pending_nonce"])))
                form = ('<form method="post" action="%s/authority">%s'
                        '<button name="decision" value="authorize" class="go">Authorize</button> '
                        '<button name="decision" value="reject">Reject</button> '
                        '<button name="decision" value="revise">Revise</button></form>' % (base, hid))
            rows.append(
                '<div class="card"><h3>%s <span class="st">%s</span></h3>'
                '<p>%s</p><table><tr><td>Operation</td><td>%s</td></tr><tr><td>Target</td><td>%s</td></tr>'
                '<tr><td>Value</td><td>%s</td></tr><tr><td>Scope</td><td>%s</td></tr><tr><td>Effect</td><td>%s</td></tr>'
                '<tr><td>Route</td><td>%s</td></tr><tr><td>Evidence</td><td>%s</td></tr>'
                '<tr><td>Expires (UTC)</td><td>%s</td></tr><tr><td>Revision</td><td>%s</td></tr>'
                '<tr><td>Proposal SHA-256</td><td class="h">%s</td></tr></table>%s</div>'
                % (esc(v["txn_id"]), esc(v["state"]), esc(p["summary"]), esc(p["op"]), esc(p["target"]),
                   esc(json.dumps(p["value"])), esc(p["scope"]), esc(p["effect"]), esc(p["route"]),
                   esc(p.get("evidence", "none")),
                   esc(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(v["expires_at"]))),
                   esc(v["revision"]), esc(v["proposal_sha256"]), form))
        setup = ""
        if owner:
            st = self.cred.status()
            fl = st.get("flow") or {}
            setup = ('<div class="card"><h3>Setup (one-time): Google Drive drive.file</h3>'
                     '<p>Client configured: %s · Credential present: %s %s</p>'
                     % (st["client_configured"], st["token_present"],
                        ("· scope " + esc(st.get("scope"))) if st.get("scope") else ""))
            if not st["token_present"]:
                setup += ('<form method="post" action="%s/setup/drive_client">' % base +
                          '<input name="client_id" placeholder="OAuth client ID (TVs and Limited Input)" size="60"> '
                          '<input name="client_secret" placeholder="client secret" type="password" size="30"> '
                          '<button>Save client</button></form>')
                if st["client_configured"]:
                    setup += '<form method="post" action="%s/setup/drive_start"><button>Start Google sign-in</button></form>' % base
                if fl.get("state") == "PENDING":
                    setup += ('<p class="code">Go to <b>%s</b> and enter code <b>%s</b> (same Google account). '
                              'This page updates when approved.</p>'
                              % (esc(fl.get("verification_url")), esc(fl.get("user_code"))))
                elif fl.get("state"):
                    setup += "<p>Sign-in state: %s</p>" % esc(fl.get("state"))
            setup += "</div>"
        a = self.att or {}
        return ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' "
                "content='width=device-width,initial-scale=1'><title>GAOP</title><style>"
                "body{font-family:system-ui,sans-serif;margin:16px;background:#fafafa;color:#222}"
                ".card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:12px;margin:12px 0}"
                "td{padding:3px 8px;vertical-align:top}.h{font-family:monospace;word-break:break-all;font-size:12px}"
                "button{font-size:16px;padding:10px 16px;margin:6px 4px 0 0;border-radius:8px;border:1px solid #888}"
                ".go{background:#1b7f3b;color:#fff;border-color:#1b7f3b}.st{font-size:13px;color:#555}"
                ".n{background:#fff4d6;padding:8px;border-radius:6px}"
                "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}.card{background:#1c1c1c;border-color:#333}}"
                "</style></head><body><h2>GAOP — Governed AI Operations Platform</h2>"
                "<p>v%s · attestation %s · source %s · %s</p>%s%s%s</body></html>"
                % (esc(VERSION), esc(a.get("attestation")), esc((a.get("private_source_commit") or "")[:12]),
                   "owner view" if owner else "read-only view (not owner)",
                   ('<p class="n">%s</p>' % esc(notice)) if notice else "",
                   "".join(rows) or "<p>No active transactions.</p>", setup))


# ============================== service loop ==============================
def read_options():
    try:
        return json.load(open(os.path.join(DATA, "options.json")))
    except Exception:
        return {}


def serve():
    att = attest()
    log("ATTESTATION %s version=%s private_source_commit=%s package_digest=%s mismatched=%s"
        % (att["attestation"], att.get("gaop_version"), att.get("private_source_commit"),
           att.get("package_digest"), att.get("mismatched")))
    try:
        store = Store(ROOT)
    except Denied as d:
        log("STOP store: %s %s — refusing to serve (fail closed)" % (d.code, d.detail))
        while True:
            time.sleep(3600)
    opts = read_options()
    cred = DriveCred(store)
    eng = Engine(store, adapters={"drive_evidence": drive_evidence_live(cred, opts)})
    for t, st in eng.boot_reconcile():
        log("RECONCILE %s -> %s (restart; no replay)" % (t, st))
    if opts.get("mode") == "selftest":
        rc = run_selftest()
        log("SELFTEST=%s" % ("PASS" if rc == 0 else "FAIL"))
    Handler.engine, Handler.cred, Handler.att = eng, cred, att
    srv = ThreadingHTTPServer(("0.0.0.0", 8099), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log("IDLE: ingress panel up on :8099; mode=%s; no harness replay" % opts.get("mode", "idle"))
    last = None
    while True:
        o = read_options()
        envr = o.get("control_envelope") or ""
        h = sha(envr.encode())
        if envr and h != last:
            out = eng.apply_envelope(envr)
            log("ENVELOPE %s %s" % (h[:12], json.dumps(out, sort_keys=True)))
            last = h
        try:
            st = cred.poll_once()
            if st not in ("NO_FLOW", "PENDING", "GRANTED"):
                pass
        except Exception as ex:
            log("DRIVE poll error class=%s" % type(ex).__name__)
        time.sleep(5)


# ============================== deterministic selftest (Phase E matrix) ==============================
def run_selftest():
    import tempfile
    results = []

    def chk(name, cond):
        results.append((name, bool(cond)))

    class Clock:
        t = 1_800_000_000

        def __call__(self):
            return self.t

    def env(op, txn, **kw):
        d = {"protocol": PROTOCOL, "op": op, "txn_id": txn, "envelope_id": "e-" + secrets.token_hex(6)}
        d.update(kw)
        return json.dumps(d)

    def prop(**kw):
        p = {"op": "synthetic.echo", "target": "synthetic:echo", "value": {"n": 1}, "scope": "synthetic-only",
             "effect": "echo a synthetic value", "summary": "selftest", "ttl_seconds": 600, "route": "mock"}
        p.update(kw)
        return p

    OWNER = "owner-test-id"
    global OWNER_PIN
    saved_pin = OWNER_PIN
    OWNER_PIN = sha((OWNER_PIN_PREFIX + OWNER).encode())
    try:
        with tempfile.TemporaryDirectory() as td:
            clk = Clock()
            st = Store(os.path.join(td, "gaop"))
            ev = {"n": 0}

            def fake_drive(rec):
                ev["n"] += 1
                return {"mode": "drive", "status": "ARCHIVED_VERIFIED", "sha256": "x", "integrity": "MATCH"}
            e = Engine(st, adapters={"drive_evidence": fake_drive}, clock=clk)

            def authorize(txn, decision="authorize", uid=OWNER, peer=INGRESS_GATEWAY, h=None, nonce=None, sv=None):
                v = e.view(txn, owner=True)
                return e.owner_decision(peer=peer, remote_user_id=uid, txn_id=txn,
                                        proposal_sha256=h or v["proposal_sha256"],
                                        state_version=sv if sv is not None else v["state_version"],
                                        nonce=nonce or v.get("pending_nonce") or "", decision=decision)

            def denied(fn, code=None):
                try:
                    fn()
                    return False
                except Denied as d:
                    return code is None or d.code == code

            # --- happy path ---
            T = "TXN-ST-0001"
            o = e.apply_envelope(env("propose", T, proposal=prop(evidence="drive")))
            chk("propose->AWAITING_AUTHORITY", o.get("state") == "AWAITING_AUTHORITY")
            v0 = e.view(T, owner=True)
            nonce0 = v0["pending_nonce"]
            chk("hamcp-identity-denied", denied(lambda: authorize(T, uid="0016853ed0304e9a87e5bd5a57ab56e0"), "NOT_OWNER"))
            chk("missing-identity-denied", denied(lambda: authorize(T, uid=""), "NOT_OWNER"))
            chk("non-gateway-peer-denied", denied(lambda: authorize(T, peer="172.30.33.9"), "NOT_INGRESS_GATEWAY"))
            chk("wrong-proposal-hash-denied", denied(lambda: authorize(T, h="0" * 64), "HASH_MISMATCH"))
            chk("stale-view-denied", denied(lambda: authorize(T, sv=0), "STALE_VIEW"))
            chk("envelope-authority-field-rejected",
                e.apply_envelope(json.dumps({"protocol": PROTOCOL, "op": "propose", "txn_id": "TXN-ST-0009",
                                             "envelope_id": "e-auth", "authority": {"authorized": True}}))
                .get("code") == "AUTHORITY_FIELD_REJECTED")
            chk("envelope-nested-authority-rejected",
                e.apply_envelope(env("claim", T, executor="x", meta={"approved": True})).get("code") == "AUTHORITY_FIELD_REJECTED")
            o = authorize(T)
            chk("owner-authorize->DISPATCHED", o.get("state") == "DISPATCHED")
            chk("authority-replay-denied(nonce)", denied(lambda: authorize(T, nonce=nonce0)))
            chk("duplicate-dispatch-denied", denied(lambda: e._dispatch(st.get(T)), "DUPLICATE_DISPATCH"))
            pk = e.package(T)
            chk("exact-retrieval-hash", pk["package_sha256"] == sha(canon(pk["package"])))
            chk("claim-wrong-package-hash-denied",
                e.apply_envelope(env("claim", T, executor="claude", package_sha256="0" * 64)).get("code") == "HASH_MISMATCH")
            c = e.apply_envelope(env("claim", T, executor="claude", package_sha256=pk["package_sha256"]))
            chk("claim->CLAIMED", c.get("state") == "CLAIMED")
            chk("concurrent-claim-denied",
                e.apply_envelope(env("claim", T, executor="other", package_sha256=pk["package_sha256"])).get("code") == "ALREADY_CLAIMED")
            b = e.apply_envelope(env("begin", T, claim_id=c["claim_id"]))
            chk("begin->RUNNING", b.get("state") == "RUNNING")
            res = {"echo": {"n": 1}, "txn_id": T, "proposal_sha256": v0["proposal_sha256"]}
            chk("wrong-result-hash-denied",
                e.apply_envelope(env("result", T, claim_id=c["claim_id"], result=res, result_sha256="0" * 64)).get("code") == "RESULT_HASH_MISMATCH")
            renv = env("result", T, claim_id=c["claim_id"], result=res, result_sha256=sha(canon(res)))
            r = e.apply_envelope(renv)
            chk("result->COMPLETED(with drive evidence)", r.get("state") == "COMPLETED" and ev["n"] == 1)
            chk("envelope-replay-no-second-effect", e.apply_envelope(renv).get("replay") is True and ev["n"] == 1)
            chk("duplicate-execution-denied",
                e.apply_envelope(env("result", T, claim_id=c["claim_id"], result=res, result_sha256=sha(canon(res)))).get("outcome") == "DENIED")
            chk("receipt-present", st.get(T)["receipt"]["final_state"] == "COMPLETED")

            # --- revision invalidates authority ---
            T2 = "TXN-ST-0002"
            e.apply_envelope(env("propose", T2, proposal=prop()))
            old = e.view(T2, owner=True)
            e.apply_envelope(env("revise", T2, base_state_version=old["state_version"], proposal=prop(value={"n": 2})))
            chk("revised-old-hash-denied", denied(lambda: authorize(T2, h=old["proposal_sha256"], sv=old["state_version"] + 1)))
            chk("revised-old-nonce-denied", denied(lambda: authorize(T2, nonce=old["pending_nonce"])))
            # authority invalidated by revision after authorization
            authorize(T2)
            vv = e.view(T2)
            chk("revise-after-authority->AWAITING", e.apply_envelope(env("revise", T2, base_state_version=vv["state_version"], proposal=prop(value={"n": 3}))).get("state") == "AWAITING_AUTHORITY"
                and st.get(T2)["authority"] is None)

            # --- expiry / cancellation ---
            T3 = "TXN-ST-0003"
            e.apply_envelope(env("propose", T3, proposal=prop(ttl_seconds=60)))
            clk.t += 120
            chk("expired-authority-denied", denied(lambda: authorize(T3), "EXPIRED") and st.get(T3)["state"] == "EXPIRED")
            T4 = "TXN-ST-0004"
            e.apply_envelope(env("propose", T4, proposal=prop()))
            v4 = e.view(T4, owner=True)
            e.apply_envelope(env("cancel", T4))
            chk("cancelled-authority-denied", denied(lambda: authorize(T4, nonce=v4["pending_nonce"], sv=v4["state_version"])))
            # reject / revise-request
            T4b = "TXN-ST-0004B"
            e.apply_envelope(env("propose", T4b, proposal=prop()))
            chk("owner-reject->REJECTED", authorize(T4b, decision="reject").get("state") == "REJECTED")

            # --- stale lease ---
            T5 = "TXN-ST-0005"
            e.apply_envelope(env("propose", T5, proposal=prop()))
            authorize(T5)
            p5 = e.package(T5)
            c5 = e.apply_envelope(env("claim", T5, executor="claude", package_sha256=p5["package_sha256"]))
            clk.t += LEASE_SECONDS + 5
            chk("stale-lease->UNKNOWN_RECONCILE(no takeover)",
                e.apply_envelope(env("claim", T5, executor="other", package_sha256=p5["package_sha256"])).get("code") == "STALE_LEASE_RECONCILE"
                and st.get(T5)["state"] == "UNKNOWN_RECONCILE")

            # --- interrupted maybe-write + restart ---
            T6 = "TXN-ST-0006"
            e.apply_envelope(env("propose", T6, proposal=prop()))
            authorize(T6)
            p6 = e.package(T6)
            c6 = e.apply_envelope(env("claim", T6, executor="claude", package_sha256=p6["package_sha256"]))
            e.apply_envelope(env("begin", T6, claim_id=c6["claim_id"]))
            e2 = Engine(Store(os.path.join(td, "gaop")), clock=clk)          # simulated restart
            rr = dict(e2.boot_reconcile())
            chk("interrupted-maybe-write->UNKNOWN_RECONCILE", rr.get(T6) == "UNKNOWN_RECONCILE")
            chk("restart-does-not-replay-completed", st.get(T)["state"] == "COMPLETED" and T not in rr)

            # --- ingress bounds ---
            chk("oversize-envelope-denied", e.apply_envelope("{" + " " * MAX_ENVELOPE_BYTES + "}").get("code") == "OVERSIZE")
            chk("truncated-envelope-denied", e.apply_envelope(env("propose", "TXN-ST-0007", proposal=prop())[:-7]).get("code") == "MALFORMED")
            chk("malformed-envelope-denied", e.apply_envelope("[1,2]").get("code") == "MALFORMED")
            chk("unsupported-protocol-denied",
                e.apply_envelope(json.dumps({"protocol": "gaop.control.v9", "op": "propose", "txn_id": "TXN-ST-0008", "envelope_id": "x"})).get("code") == "UNSUPPORTED_PROTOCOL")
            chk("non-allowlisted-op-denied",
                e.apply_envelope(env("propose", "TXN-ST-0010", proposal=prop(op="ha.call_service"))).get("code") == "OP_NOT_ALLOWLISTED")
            chk("non-synthetic-target-denied",
                e.apply_envelope(env("propose", "TXN-ST-0011", proposal=prop(target="light.kitchen"))).get("code") == "SCOPE_NOT_SYNTHETIC")
            chk("duplicate-txn-denied", e.apply_envelope(env("propose", T, proposal=prop())).get("code") == "DUPLICATE_TXN")

            # --- unconfigured live provider fails closed ---
            T12 = "TXN-ST-0012"
            e.apply_envelope(env("propose", T12, proposal=prop(route="claude-api")))
            chk("unconfigured-provider->STOP", authorize(T12).get("adapter_error") == "PROVIDER_NOT_CONFIGURED")
            # synthetic provider endpoint contract
            calls = []

            def ep(**kw):
                calls.append(sorted(kw))
                return AdapterResult(status="DISPATCHED", mode="api", ack="a1", locator=kw["locator"])
            e.adapters["openai-api"] = ApiAdapter("openai-api", "/nonexistent", endpoint=ep)
            T13 = "TXN-ST-0013"
            e.apply_envelope(env("propose", T13, proposal=prop(route="openai-api")))
            chk("synthetic-provider-contract", authorize(T13).get("state") == "DISPATCHED" and calls and calls[0] ==
                sorted(["txn_id", "locator", "package_sha256", "action_id", "expires_at", "idempotency_key"]))

            # --- unsupported newer store schema fails closed ---
            m = os.path.join(td, "gaop", "meta.json")
            meta = json.load(open(m))
            meta["schema"] = STORE_SCHEMA + 1
            Store._atomic(m, meta)
            chk("unsupported-store-schema-fail-closed", denied(lambda: Store(os.path.join(td, "gaop")), "UNSUPPORTED_SCHEMA"))
    finally:
        OWNER_PIN = saved_pin
    for n, ok in results:
        log("  %-48s %s" % (n, "OK" if ok else "FAIL"))
    fails = [n for n, ok in results if not ok]
    log("SELFTEST checks=%d failed=%d" % (len(results), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if mode == "selftest":
        sys.exit(run_selftest())
    serve()

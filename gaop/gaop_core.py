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

VERSION = "0.7.2"
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
ENVELOPE_OPS = {"propose", "revise", "cancel", "claim", "begin", "result", "reconcile"}
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


LOG_SINK = None   # selftest capture (used to prove no credential ever reaches the log)


def log(msg):
    if LOG_SINK is not None:
        LOG_SINK.append(msg)
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
            rp = os.path.join(self.root, "recent.json")
            rc = json.load(open(rp)) if os.path.exists(rp) else []
            rc = [t for t in rc if t != rec["txn_id"]] + [rec["txn_id"]]
            self._atomic(rp, rc[-8:])
        elif rec["txn_id"] not in act:
            act.append(rec["txn_id"])
        self._atomic(ap, act[-MAX_ACTIVE:])

    def recent(self):
        rp = os.path.join(self.root, "recent.json")
        return json.load(open(rp)) if os.path.exists(rp) else []

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


PROVIDERS = {
    "claude-api": {"vendor": "anthropic", "url": "https://api.anthropic.com/v1/messages",
                   "default_model": "claude-haiku-4-5-20251001",
                   "key_re": r"^sk-ant-[A-Za-z0-9_-]{20,250}$"},
    "openai-api": {"vendor": "openai", "url": "https://api.openai.com/v1/chat/completions",
                   "default_model": "", "key_re": r"^sk-[A-Za-z0-9_-]{20,250}$"},
}
MODEL_RE = re.compile(r"^[A-Za-z0-9._:-]{2,64}$")
MAX_PROVIDER_RESPONSE = 65536
PROVIDER_TIMEOUT = 60
EXEC_SYSTEM = ("You are a bounded GAOP synthetic executor. You have no tools and no other duties. "
               "Reply with ONLY one compact JSON object and no other text.")


class ProviderError(Exception):
    """kind: AUTH | REJECTED | MALFORMED (definitive: request not executed or unusable -> STOP)
             UNCERTAIN (timeout / network / 5xx: provider may have accepted -> UNKNOWN_RECONCILE)"""
    def __init__(self, kind, detail=""):
        super().__init__("%s %s" % (kind, detail))
        self.kind, self.detail = kind, str(detail)[:120]


def provider_cred_path(store, route):
    return os.path.join(store.root, "cred", "provider_%s.json" % route)


def load_provider_cred(store, route):
    p = provider_cred_path(store, route)
    return json.load(open(p)) if os.path.exists(p) else None


def save_provider_cred(store, route, api_key, model):
    if route not in PROVIDERS:
        raise Denied("MALFORMED", "provider")
    if not re.match(PROVIDERS[route]["key_re"], api_key or ""):
        raise Denied("MALFORMED", "api key format")
    model = (model or "").strip() or PROVIDERS[route]["default_model"]
    if not MODEL_RE.match(model):
        raise Denied("MALFORMED", "model required")
    p = provider_cred_path(store, route)
    Store._atomic(p, {"api_key": api_key, "model": model, "configured_at": now()})
    os.chmod(p, 0o600)


def provider_status(store):
    out = {}
    for r in PROVIDERS:
        c = load_provider_cred(store, r)
        out[r] = {"configured": bool(c), "model": (c or {}).get("model"),
                  "configured_at": (c or {}).get("configured_at")}
    return out


def http_transport(url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_PROVIDER_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(MAX_PROVIDER_RESPONSE + 1)
    except Exception as ex:                     # timeout / DNS / reset: delivery unknown
        raise ProviderError("UNCERTAIN", type(ex).__name__)


def call_provider(route, cred, payload, transport, timeout=PROVIDER_TIMEOUT):
    pv = PROVIDERS[route]
    user = ("Return exactly this JSON object, copying every value unchanged: "
            + json.dumps({"echo": payload["value"], "txn_id": payload["txn_id"],
                          "proposal_sha256": payload["proposal_sha256"],
                          "correlation_id": payload["correlation_id"]}, sort_keys=True))
    if pv["vendor"] == "anthropic":
        headers = {"x-api-key": cred["api_key"], "anthropic-version": "2023-06-01",
                   "content-type": "application/json"}
        body = {"model": cred["model"], "max_tokens": 300, "system": EXEC_SYSTEM,
                "messages": [{"role": "user", "content": user}]}
    else:
        headers = {"Authorization": "Bearer " + cred["api_key"], "Content-Type": "application/json"}
        body = {"model": cred["model"], "messages": [{"role": "system", "content": EXEC_SYSTEM},
                                                     {"role": "user", "content": user}]}
    status, rh, raw = transport(pv["url"], headers, json.dumps(body).encode(), timeout)
    if status in (401, 403):
        raise ProviderError("AUTH", "http %d" % status)
    if status == 200:
        pass
    elif status in (400, 404, 409, 413, 422, 429):
        raise ProviderError("REJECTED", "http %d" % status)
    else:
        raise ProviderError("UNCERTAIN", "http %d" % status)
    if len(raw) > MAX_PROVIDER_RESPONSE:
        raise ProviderError("MALFORMED", "response too large")
    try:
        j = json.loads(raw.decode())
        if pv["vendor"] == "anthropic":
            text = "".join(c.get("text", "") for c in j["content"] if c.get("type") == "text")
            req_id = rh.get("request-id")
        else:
            text = j["choices"][0]["message"]["content"]
            req_id = rh.get("x-request-id")
        resp_id, model = j["id"], j.get("model")
    except Exception:
        raise ProviderError("MALFORMED", "unexpected provider response shape")
    return {"text": text, "response_id": str(resp_id)[:80], "request_id": str(req_id)[:80] if req_id else None,
            "model": str(model)[:64], "http_status": status, "text_sha256": sha(text.encode())}


def parse_provider_json(text):
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("{"):] if "{" in t else t
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ProviderError("MALFORMED", "no JSON object in provider text")
    try:
        o = json.loads(t[a:b + 1])
    except Exception:
        raise ProviderError("MALFORMED", "provider JSON not parseable")
    if not isinstance(o, dict) or not {"echo", "txn_id", "proposal_sha256", "correlation_id"} <= set(o):
        raise ProviderError("MALFORMED", "provider JSON missing required fields")
    return o


class ApiAdapter(Adapter):
    """claude-api / openai-api: machine-addressable provider routes. Requires a provider
    credential in App-private /data (one-time SETUP). Absent credential -> fail closed (STOP)."""
    def __init__(self, route, cred_path, endpoint=None):
        self.route, self.cred_path, self.endpoint = route, cred_path, endpoint

    def dispatch(self, **kw):
        if self.endpoint is not None:          # deterministic synthetic endpoint (tests)
            return self.endpoint(**kw)
        if not os.path.exists(self.cred_path):
            return AdapterResult(status="STOP", error="PROVIDER_NOT_CONFIGURED", route=self.route)
        # v0.7.2: live API route. The App itself is the executor for this route; execution starts
        # immediately after dispatch (Engine.api_execute) with no user or provider-UI step.
        return AdapterResult(status="DISPATCHED", mode="api", route=self.route,
                             locator=kw["locator"], ack="ack-" + kw["idempotency_key"][:16])


def adapter_for(route, store):
    if route in ("claude-session", "github-executor", "mock"):
        return PullAdapter(route)
    return ApiAdapter(route, provider_cred_path(store, route))


# ============================== engine ==============================
class Engine:
    def __init__(self, store, adapters=None, clock=now, transport=None):
        self.s = store
        self.adapters = adapters or {}
        self.clock = clock
        self.transport = transport

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
        if rec["proposal"]["route"] in PROVIDERS:
            raise Denied("ADAPTER_OWNED_ROUTE", "API-route transactions are executed only by the App adapter")
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
        if rec["proposal"]["route"] in PROVIDERS:
            raise Denied("ADAPTER_OWNED_CLAIM", "claim held by the App provider adapter")
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

    def _op_reconcile(self, env):
        """Governed resolution of UNKNOWN_RECONCILE -> CANCELLED. Allowed only when no result was
        persisted and no evidence step ran (so no GAOP-side external effect can exist). The
        interruption record is preserved; the transaction record is never deleted."""
        rec = self._load(env["txn_id"], {"UNKNOWN_RECONCILE"})
        if env.get("resolution") != "CANCELLED":
            raise Denied("MALFORMED", "resolution must be CANCELLED")
        who = str(env.get("reconciler", ""))
        if not ID_RE.match(who):
            raise Denied("MALFORMED", "reconciler")
        if rec.get("result") is not None or rec.get("evidence") is not None:
            raise Denied("EFFECT_UNCERTAIN", "result or evidence present; manual review required")
        v = rec["state_version"]
        prior = dict(rec.get("reconcile") or {})
        rec["reconcile"] = {"interruption": prior, "resolution": "CANCELLED", "resolved_by": who,
                            "resolved_at": self.clock(), "resolved_from_state_version": v,
                            "reason": str(env.get("reason", ""))[:200],
                            "external_effect": "NONE: no result persisted; evidence step never ran",
                            "provider_status": (rec.get("provider") or {}).get("status")}
        if rec.get("execution"):
            rec["execution"]["maybe_write"] = False
        transition(rec, "CANCELLED", "reconciled by " + who)
        rec["receipt"] = self.make_receipt(rec, "CANCELLED")
        self.s.put(rec, v)
        return {"state": "CANCELLED", "receipt_sha256": rec["receipt"]["receipt_sha256"]}

    # ---------- live provider execution (App is the executor for API routes) ----------
    def api_execute(self, txn_id, transport=None):
        tr = transport or self.transport or http_transport
        self.s.lock()
        try:
            rec = self._load(txn_id, {"DISPATCHED"})
            route = rec["proposal"]["route"]
            if route not in PROVIDERS:
                raise Denied("NOT_API_ROUTE", route)
            cred = load_provider_cred(self.s, route)
            v = rec["state_version"]
            if cred is None:
                transition(rec, "STOP", "provider not configured")
                self.s.put(rec, v)
                return {"state": "STOP", "provider": "NOT_CONFIGURED"}
            corr = "corr-" + sha(canon({"txn_id": txn_id, "package_sha256": rec["dispatch"]["package_sha256"],
                                        "authority_sha256": rec["authority"]["authority_sha256"]}))[:20]
            claim_id = "clm-" + secrets.token_hex(8)
            rec["claim"] = {"claim_id": claim_id, "executor": "%s:%s" % (route, cred["model"]),
                            "claimed_at": self.clock(), "lease_until": self.clock() + LEASE_SECONDS}
            transition(rec, "CLAIMED", "claimed by App provider adapter " + route)
            rec = self.s.put(rec, v)
            v = rec["state_version"]
            rec["execution"] = {"started_at": self.clock(), "maybe_write": True,
                                "action_id": rec["dispatch"]["action_id"], "correlation_id": corr}
            rec["provider"] = {"route": route, "vendor": PROVIDERS[route]["vendor"], "model": cred["model"],
                               "correlation_id": corr, "sent_at": self.clock(), "status": "SENT"}
            transition(rec, "RUNNING", "provider request sent (maybe-write marker set)")
            rec = self.s.put(rec, v)
            pkg = rec["dispatch"]["package"]
        finally:
            self.s.unlock()
        payload = {"value": pkg["proposal"]["value"], "txn_id": txn_id,
                   "proposal_sha256": pkg["proposal_sha256"], "correlation_id": corr}
        try:
            resp, err = call_provider(route, cred, payload, tr), None
        except ProviderError as pe:
            resp, err = None, pe
        self.s.lock()
        try:
            rec = self.s.get(txn_id)
            if rec["state"] != "RUNNING" or (rec.get("claim") or {}).get("claim_id") != claim_id:
                return {"state": rec["state"], "note": "state changed during provider call; response ignored"}
            v = rec["state_version"]
            if err is not None:
                rec["provider"]["status"] = err.kind
                rec["provider"]["error"] = err.detail
                if err.kind == "UNCERTAIN":
                    rec["reconcile"] = {"reason": "PROVIDER_UNCERTAIN " + err.detail, "at": self.clock()}
                    transition(rec, "UNKNOWN_RECONCILE", "provider outcome uncertain; no blind retry")
                else:
                    rec["execution"]["maybe_write"] = False
                    transition(rec, "STOP", "provider %s: %s" % (err.kind, err.detail))
                self.s.put(rec, v)
                return {"state": rec["state"], "provider": err.kind}
            rec["provider"].update(status="RESPONDED", response_id=resp["response_id"],
                                   request_id=resp["request_id"], model_reported=resp["model"],
                                   http_status=resp["http_status"], response_text_sha256=resp["text_sha256"])
            try:
                o = parse_provider_json(resp["text"])
            except ProviderError as pe:
                rec["provider"]["status"] = "MALFORMED"
                rec["execution"]["maybe_write"] = False
                transition(rec, "STOP", "provider result malformed: " + pe.detail)
                self.s.put(rec, v)
                return {"state": "STOP", "provider": "MALFORMED"}
            if (o.get("txn_id") != txn_id or o.get("proposal_sha256") != rec["proposal_sha256"]
                    or o.get("correlation_id") != corr):
                rec["provider"]["status"] = "BINDING_MISMATCH"
                rec["execution"]["maybe_write"] = False
                transition(rec, "STOP", "provider result not bound to this transaction")
                self.s.put(rec, v)
                return {"state": "STOP", "provider": "BINDING_MISMATCH"}
            res = {"echo": o["echo"], "txn_id": txn_id, "proposal_sha256": rec["proposal_sha256"]}
            rb = canon(res)
            if len(rb) > MAX_RESULT_BYTES:
                transition(rec, "STOP", "provider result oversize")
                self.s.put(rec, v)
                return {"state": "STOP"}
            rec["result"] = {"result": res, "result_sha256": sha(rb), "persisted_at": self.clock(),
                             "executor": rec["claim"]["executor"]}
            rec["execution"]["maybe_write"] = False
            transition(rec, "RESULT_PERSISTED", "provider result persisted")
            self.s.put(rec, v)
            return self._verify_and_close(txn_id)
        finally:
            self.s.unlock()

    def owner_request(self, *, peer, remote_user_id, value, route, evidence):
        """Minimal Dashboard request-entry control (owner only): creates a synthetic proposal.
        Proposal creation is not authority; the owner still presses Authorize separately."""
        if peer != INGRESS_GATEWAY:
            raise Denied("NOT_INGRESS_GATEWAY", peer)
        if not remote_user_id or sha((OWNER_PIN_PREFIX + remote_user_id).encode()) != OWNER_PIN:
            raise Denied("NOT_OWNER", "request entry is owner-only")
        if not re.match(r"^[A-Za-z0-9 .,:_-]{1,80}$", value or ""):
            raise Denied("MALFORMED", "value")
        txn = "TXN-05R-DB-" + time.strftime("%Y%m%d%H%M%S", time.gmtime(self.clock()))
        p = {"op": "synthetic.echo", "target": "synthetic:echo", "value": {"msg": value},
             "scope": "synthetic-only; no Home Assistant state",
             "effect": ("%s echoes the synthetic value via its API; GAOP verifies it%s"
                        % (route, "; archives one synthetic evidence file to the existing GAOP folder, "
                           "verifies it, deletes it" if evidence == "drive" else "")),
             "summary": "Dashboard synthetic request", "ttl_seconds": 1800, "route": route,
             "evidence": "drive" if evidence == "drive" else "none"}
        env = json.dumps({"protocol": PROTOCOL, "op": "propose", "txn_id": txn,
                          "envelope_id": "dash-" + txn, "proposal": p})
        out = self.apply_envelope(env)
        if out.get("outcome") == "ACCEPTED":
            self.s.lock()
            try:
                rec = self.s.get(txn)
                rec["origin"] = "dashboard-owner-request"
                self.s._atomic(self.s._tp(txn), rec)
            finally:
                self.s.unlock()
        return out

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
        ev, pv = rec.get("evidence") or {}, rec.get("provider") or {}
        body = {"schema": "gaop.receipt.v2", "txn_id": rec["txn_id"],
                "proposal_sha256": rec["proposal_sha256"], "revision": rec["revision"],
                "authority_sha256": (rec.get("authority") or {}).get("authority_sha256"),
                "dispatch_id": (rec.get("dispatch") or {}).get("dispatch_id"),
                "package_sha256": (rec.get("dispatch") or {}).get("package_sha256"),
                "claim_id": (rec.get("claim") or {}).get("claim_id"),
                "executor": (rec.get("claim") or {}).get("executor"),
                "result_sha256": (rec.get("result") or {}).get("result_sha256"),
                "evidence_status": (rec.get("evidence") or {}).get("status"),
                "evidence_file_sha256": ev.get("sha256"),
                "evidence_integrity": ev.get("integrity"),
                "evidence_disposition": ev.get("disposition"),
                "evidence_delete_verified": ev.get("delete_verified"),
                "evidence_unrelated_denied": ev.get("unrelated_denied"),
                "evidence_root_id": ev.get("root_id"), "evidence_folder_id": ev.get("folder_id"),
                "archive_correlation_id": ev.get("archive_correlation_id"),
                "provider_route": pv.get("route"), "provider_model": pv.get("model_reported") or pv.get("model"),
                "provider_response_id": pv.get("response_id"), "provider_request_id": pv.get("request_id"),
                "provider_correlation_id": pv.get("correlation_id"),
                "reconcile_resolution": (rec.get("reconcile") or {}).get("resolution"),
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

    def pending_api_dispatches(self):
        return [t for t in self.s.active()
                if (self.s.get(t) or {}).get("state") == "DISPATCHED"
                and self.s.get(t)["proposal"]["route"] in PROVIDERS]

    # ---------- exact, bounded retrieval (no list-all) ----------
    def view(self, txn_id, owner=False):
        rec = self.s.get(txn_id)
        if rec is None:
            raise Denied("UNKNOWN_TXN", txn_id)
        v = {k: rec[k] for k in ("txn_id", "state", "state_version", "revision", "proposal",
                                 "proposal_sha256", "expires_at", "reconcile")}
        v["authority_sha256"] = (rec.get("authority") or {}).get("authority_sha256")
        c = rec.get("claim") or {}
        # v0.7.2: claim_id acts as a bearer token for begin/result, so only its hash is exposed.
        v["claim"] = {"claim_id_sha256": sha(c["claim_id"].encode()) if c.get("claim_id") else None,
                      "executor": c.get("executor"), "lease_until": c.get("lease_until")}
        pv = rec.get("provider") or {}
        v["provider"] = {k: pv.get(k) for k in ("route", "model", "model_reported", "status",
                                                 "response_id", "request_id", "correlation_id")} if pv else None
        v["result"] = (rec.get("result") or {}).get("result")
        v["origin"] = rec.get("origin")
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


def drive_evidence_live(client_factory, opts):
    """B10 + v0.7.2 receipt hardening. Continuity check of the EXISTING GAOP root/folder first; never
    creates a folder or root. One bounded synthetic evidence object: upload -> independent
    re-download + SHA-256 -> unrelated-ID denial probe (surfaced, gating) -> delete -> delete
    verification (surfaced). Disposition is reported honestly: DELETED / RETAINED_DELETE_FAILED."""
    def run(rec):
        dc = client_factory()
        if dc is None:
            return {"mode": "drive", "status": "STOP_NO_DRIVE_CREDENTIAL"}
        root, folder = opts.get("drive_root_id") or "", opts.get("drive_archive_folder_id") or ""
        if not root or not folder:
            return {"mode": "drive", "status": "STOP_DRIVE_TARGET_NOT_CONFIGURED"}
        arc = "arc-" + sha(canon({"txn_id": rec["txn_id"], "proposal_sha256": rec["proposal_sha256"],
                                  "result_sha256": rec["result"]["result_sha256"]}))[:16]
        out = {"mode": "drive", "archive_correlation_id": arc, "root_id": root, "folder_id": folder}
        try:
            r = dc.get_meta(root)
            f = dc.get_meta(folder)
        except DriveError as e:
            out.update(status="STOP_EXISTING_ROOT_INACCESSIBLE", http=e.status)
            return out
        if r.get("trashed") or f.get("trashed"):
            out["status"] = "STOP_EXISTING_ROOT_TRASHED"
            return out
        content = canon({"schema": "gaop.evidence.v1", "synthetic": True, "txn_id": rec["txn_id"],
                         "proposal_sha256": rec["proposal_sha256"], "archive_correlation_id": arc,
                         "result_sha256": rec["result"]["result_sha256"], "gaop_version": VERSION})
        h = sha(content)
        out["sha256"] = h
        try:
            up = dc.upload("gaop_%s_evidence.json" % rec["txn_id"], content, folder)
        except DriveError as e:
            out.update(status="UNKNOWN_RECONCILE_UPLOAD", http=e.status)
            return out
        out["file_id"] = up["id"]
        try:
            got = sha(dc.download(up["id"]))
        except DriveError:
            out.update(status="UNKNOWN_RECONCILE_VERIFY")
            return out
        out["remote_sha256"] = got
        out["integrity"] = "MATCH" if got == h else "MISMATCH"
        denied = False
        try:
            dc.get_meta(UNRELATED_PROBE_ID)
        except DriveError as e:
            denied = e.status in (403, 404)
        out["unrelated_denied"] = denied
        delete_verified = False
        try:
            dc.delete(up["id"])
            try:
                m = dc.get_meta(up["id"])
                delete_verified = bool(m.get("trashed"))
            except DriveError as e:
                delete_verified = e.status == 404
        except DriveError:
            delete_verified = False
        out["delete_verified"] = delete_verified
        out["disposition"] = "DELETED" if delete_verified else "RETAINED_DELETE_FAILED"
        if got != h:
            out["status"] = "STOP_INTEGRITY_MISMATCH"
        elif not denied:
            out["status"] = "STOP_UNRELATED_NOT_DENIED"
        else:
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
                self._maybe_api(g("txn_id"), out)
                return self._send(200, self._panel(owner, notice="%s: %s" % (g("txn_id"), out.get("state"))), "text/html")
            if path == "/request":
                out = self.engine.owner_request(peer=peer, remote_user_id=uid, value=g("value").strip(),
                                                route=g("route"), evidence=g("evidence"))
                log("REQUEST dashboard-owner -> %s" % json.dumps(out, sort_keys=True))
                return self._send(200 if out.get("outcome") == "ACCEPTED" else 409,
                                  self._panel(owner, notice="request: %s %s" % (out.get("txn_id", ""), out.get("state") or out.get("code"))), "text/html")
            if path in ("/setup/provider", "/setup/provider_delete"):
                if peer != INGRESS_GATEWAY or not owner:
                    raise Denied("NOT_OWNER", "setup is owner-only")
                route = g("provider")
                if route not in PROVIDERS:
                    raise Denied("MALFORMED", "provider")
                if path == "/setup/provider":
                    save_provider_cred(self.engine.s, route, g("api_key").strip(), g("model"))
                    log("SETUP provider %s credential stored in /data (value not logged)" % route)
                else:
                    p = provider_cred_path(self.engine.s, route)
                    if os.path.exists(p):
                        os.remove(p)
                    log("SETUP provider %s credential deleted" % route)
                return self._send(200, self._panel(owner, notice="provider setup updated"), "text/html")
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

    def _maybe_api(self, txn_id, out):
        try:
            rec = self.engine.s.get(txn_id)
        except Denied:
            return
        if out.get("state") == "DISPATCHED" and rec and rec["proposal"]["route"] in PROVIDERS:
            def run():
                try:
                    res = self.engine.api_execute(txn_id)
                except Denied as d:
                    res = {"denied": d.code}
                log("PROVIDER %s -> %s" % (txn_id, json.dumps(res, sort_keys=True)))
            threading.Thread(target=run, daemon=True).start()

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
        recent = []
        for t in reversed(e.s.recent()):
            try:
                v = e.view(t)
            except Denied:
                continue
            rc = (e.s.get(t) or {}).get("receipt") or {}
            recent.append('<tr><td>%s</td><td><b>%s</b></td><td class="h">%s</td><td>%s</td><td>%s</td><td class="h">%s</td></tr>'
                          % (esc(t), esc(v["state"]), esc(json.dumps(v.get("result"))[:120] if v.get("result") else ""),
                             esc(rc.get("provider_route") or v["proposal"]["route"]),
                             esc(rc.get("evidence_disposition") or rc.get("evidence_status") or ""),
                             esc((rc.get("receipt_sha256") or "")[:16])))
        rec_html = ('<div class="card"><h3>Recent results</h3><table><tr><td>Transaction</td><td>State</td>'
                    '<td>Result</td><td>Route</td><td>Evidence</td><td>Receipt</td></tr>%s</table></div>'
                    % "".join(recent)) if recent else ""
        req = ""
        if owner:
            ps = provider_status(e.s)
            opts_r = "".join('<option value="%s">%s (%s)</option>' % (r, r, esc(ps[r]["model"]))
                             for r in PROVIDERS if ps[r]["configured"])
            if opts_r:
                req = ('<div class="card"><h3>New synthetic request</h3><form method="post" action="%s/request">'
                       '<input name="value" placeholder="synthetic value to echo" size="40" maxlength="80"> '
                       '<select name="route">%s</select> '
                       '<label><input type="checkbox" name="evidence" value="drive" checked> Drive evidence</label> '
                       '<button>Create proposal</button></form><p class="st">Creates a proposal only. '
                       'It runs after you press Authorize on its card.</p></div>' % (base, opts_r))
        setup = ""
        if owner:
            ps = provider_status(e.s)
            setup += '<div class="card"><h3>Setup (one-time): AI provider API</h3>'
            for r, info in PROVIDERS.items():
                stt = ps[r]
                setup += "<p><b>%s</b> (%s): %s</p>" % (esc(r), esc(info["vendor"]),
                         ("configured · model " + esc(stt["model"])) if stt["configured"] else "not configured")
                if stt["configured"]:
                    setup += ('<form method="post" action="%s/setup/provider_delete"><input type="hidden" name="provider" value="%s">'
                              '<button>Delete %s key</button></form>' % (base, esc(r), esc(info["vendor"])))
                else:
                    setup += ('<form method="post" action="%s/setup/provider"><input type="hidden" name="provider" value="%s">'
                              '<input name="api_key" type="password" placeholder="%s API key" size="40" autocomplete="off"> '
                              '<input name="model" placeholder="model%s" size="28"> <button>Save key</button></form>'
                              % (base, esc(r), esc(info["vendor"]),
                                 (" (default " + esc(info["default_model"]) + ")") if info["default_model"] else " (required)"))
            setup += "<p class='st'>Keys are stored only in this App's private storage and are never shown again.</p></div>"
            st = self.cred.status()
            fl = st.get("flow") or {}
            setup += ('<div class="card"><h3>Setup (one-time): Google Drive drive.file</h3>'
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
        setup = req + rec_html + setup
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
    eng = Engine(store, adapters={"drive_evidence": drive_evidence_live(cred.client, opts)})
    for t, st in eng.boot_reconcile():
        log("RECONCILE %s -> %s (restart; no replay)" % (t, st))
    if opts.get("mode") == "selftest":
        rc = run_selftest()
        log("SELFTEST=%s" % ("PASS" if rc == 0 else "FAIL"))
    Handler.engine, Handler.cred, Handler.att = eng, cred, att
    srv = ThreadingHTTPServer(("0.0.0.0", 8099), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log("IDLE: ingress panel up on :8099; mode=%s; no harness replay" % opts.get("mode", "idle"))
    for t in eng.pending_api_dispatches():
        # Safe resume: a DISPATCHED API transaction has not contacted the provider yet.
        log("RESUME %s (DISPATCHED, provider not yet called)" % t)
        Handler._maybe_api(type("H", (), {"engine": eng})(), t, {"state": "DISPATCHED"})
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

            # ================= v0.7.2 =================
            global LOG_SINK
            LOG_SINK = []
            KEY_A, KEY_O = "sk-ant-" + "TESTKEYA" * 5, "sk-" + "TESTKEYO" * 5
            save_provider_cred(st, "claude-api", KEY_A, "")
            save_provider_cred(st, "openai-api", KEY_O, "test-model")
            chk("provider-default-model", load_provider_cred(st, "claude-api")["model"] == PROVIDERS["claude-api"]["default_model"])
            chk("provider-bad-key-rejected", denied(lambda: save_provider_cred(st, "claude-api", "not-a-key", ""), "MALFORMED"))
            chk("openai-model-required", denied(lambda: save_provider_cred(st, "openai-api", KEY_O, ""), "MALFORMED"))
            pcalls = {"n": 0}
            e.adapters.pop("openai-api", None)   # drop the 0.7.1 mock-endpoint adapter

            def mk(vendor, mutate=None, status=200, raise_kind=None, text_override=None, hook=None):
                def tr(url, headers, body, timeout):
                    pcalls["n"] += 1
                    if hook:
                        hook()
                    if raise_kind:
                        raise ProviderError(raise_kind, "injected")
                    b = json.loads(body.decode())
                    u = b["messages"][-1]["content"]
                    o = json.loads(u[u.index("{"):])
                    if mutate:
                        mutate(o)
                    text = text_override if text_override is not None else "```json\n" + json.dumps(o) + "\n```"
                    if vendor == "anthropic":
                        assert headers["x-api-key"] == KEY_A and headers["anthropic-version"] == "2023-06-01"
                        j = {"id": "msg_test", "model": b["model"], "content": [{"type": "text", "text": text}]}
                        return status, {"request-id": "req_a"}, json.dumps(j).encode()
                    assert headers["Authorization"] == "Bearer " + KEY_O
                    j = {"id": "chatcmpl_test", "model": b["model"], "choices": [{"message": {"content": text}}]}
                    return status, {"x-request-id": "req_o"}, json.dumps(j).encode()
                return tr

            def api_txn(tid, route, evidence="drive"):
                e.apply_envelope(env("propose", tid, proposal=prop(route=route, evidence=evidence)))
                return authorize(tid)

            T20 = "TXN-ST-0020"
            chk("api-authorize->DISPATCHED", api_txn(T20, "claude-api").get("state") == "DISPATCHED")
            chk("api-route-envelope-claim-denied",
                e.apply_envelope(env("claim", T20, executor="rogue", package_sha256=e.package(T20)["package_sha256"])).get("code") == "ADAPTER_OWNED_ROUTE")
            r20 = e.api_execute(T20, transport=mk("anthropic"))
            rc20 = st.get(T20)["receipt"]
            chk("anthropic-live-path->COMPLETED", r20.get("state") == "COMPLETED"
                and rc20["provider_response_id"] == "msg_test" and rc20["provider_request_id"] == "req_a"
                and rc20["provider_correlation_id"].startswith("corr-") and rc20["schema"] == "gaop.receipt.v2")
            n0 = pcalls["n"]
            chk("duplicate-provider-execution-denied", denied(lambda: e.api_execute(T20, transport=mk("anthropic")), "WRONG_STATE") and pcalls["n"] == n0)

            T21 = "TXN-ST-0021"
            api_txn(T21, "openai-api", evidence="none")
            rogue = {}

            def rogue_hook():
                rogue["out"] = e.apply_envelope(env("result", T21, claim_id="clm-guess", result={"echo": 1},
                                                    result_sha256=sha(canon({"echo": 1}))))
            r21 = e.api_execute(T21, transport=mk("openai", hook=rogue_hook))
            chk("openai-live-path->COMPLETED", r21.get("state") == "COMPLETED" and st.get(T21)["receipt"]["provider_request_id"] == "req_o")
            chk("rogue-result-during-api-run-denied", rogue["out"].get("code") == "ADAPTER_OWNED_CLAIM")

            def outcome(tid, route, **kw):
                api_txn(tid, route, evidence="none")
                return e.api_execute(tid, transport=mk(PROVIDERS[route]["vendor"], **kw)), st.get(tid)
            o, rr = outcome("TXN-ST-0022", "claude-api", status=401)
            chk("provider-auth-failure->STOP", o.get("state") == "STOP" and rr["provider"]["status"] == "AUTH")
            o, rr = outcome("TXN-ST-0023", "claude-api", raise_kind="UNCERTAIN")
            chk("provider-timeout->UNKNOWN_RECONCILE(no retry)", o.get("state") == "UNKNOWN_RECONCILE")
            o, rr = outcome("TXN-ST-0024", "openai-api", status=503)
            chk("provider-5xx->UNKNOWN_RECONCILE", o.get("state") == "UNKNOWN_RECONCILE")
            o, rr = outcome("TXN-ST-0025", "claude-api", text_override="I cannot do that")
            chk("provider-malformed->STOP", o.get("state") == "STOP" and rr["provider"]["status"] == "MALFORMED")
            o, rr = outcome("TXN-ST-0026", "claude-api", mutate=lambda x: x.update(correlation_id="corr-forged"))
            chk("provider-binding-mismatch->STOP", o.get("state") == "STOP" and rr["provider"]["status"] == "BINDING_MISMATCH")
            o, rr = outcome("TXN-ST-0027", "claude-api", mutate=lambda x: x.update(txn_id="TXN-OTHER"))
            chk("provider-wrong-txn->STOP", o.get("state") == "STOP")
            o, rr = outcome("TXN-ST-0028", "claude-api", mutate=lambda x: x.update(echo={"n": 999}))
            chk("provider-wrong-echo->STOP(verification)", o.get("state") == "STOP" and rr["result"] is not None)

            # credentials never leak to logs / receipts / views / packages
            blob = json.dumps(LOG_SINK) + json.dumps([st.get(t) and st.get(t).get("receipt") for t in ("TXN-ST-0020", "TXN-ST-0021")]) \
                + json.dumps([e.view(t) for t in ("TXN-ST-0020", "TXN-ST-0021", "TXN-ST-0022")])
            chk("credential-not-in-logs-receipts-views", KEY_A not in blob and KEY_O not in blob and "TESTKEY" not in blob)
            chk("claim-id-not-exposed", "claim_id\"" not in json.dumps(e.view(T)) and e.view(T)["claim"]["claim_id_sha256"])

            # Drive evidence hardening (fake client; never creates folders)
            class FDC:
                def __init__(self, delete_ok=True, unrelated_visible=False, root_ok=True):
                    self.files, self.d, self.u, self.r = {}, delete_ok, unrelated_visible, root_ok
                    self.uploads = 0
                def get_meta(self, fid):
                    if fid in ("ROOT", "FOLDER"):
                        if not self.r:
                            raise DriveError(404)
                        return {"id": fid}
                    if fid == UNRELATED_PROBE_ID:
                        if self.u:
                            return {"id": fid}
                        raise DriveError(404)
                    if fid in self.files:
                        return {"id": fid, "trashed": False}
                    raise DriveError(404)
                def upload(self, name, content, folder):
                    self.uploads += 1
                    self.files["F1"] = content
                    return {"id": "F1"}
                def download(self, fid):
                    return self.files[fid]
                def delete(self, fid):
                    if not self.d:
                        raise DriveError(500)
                    self.files.pop(fid, None)
            frec = {"txn_id": "TXN-ST-0030", "proposal_sha256": "p" * 64, "result": {"result_sha256": "r" * 64}}
            dopts = {"drive_root_id": "ROOT", "drive_archive_folder_id": "FOLDER"}
            dc = FDC()
            ev1 = drive_evidence_live(lambda: dc, dopts)(frec)
            chk("drive-archive-verified+deleted+denial-surfaced", ev1["status"] == "ARCHIVED_VERIFIED" and ev1["disposition"] == "DELETED"
                and ev1["delete_verified"] is True and ev1["unrelated_denied"] is True and ev1["integrity"] == "MATCH"
                and ev1["archive_correlation_id"].startswith("arc-") and "F1" not in dc.files)
            ev2 = drive_evidence_live(lambda: FDC(delete_ok=False), dopts)(frec)
            chk("drive-delete-failure-surfaced", ev2["disposition"] == "RETAINED_DELETE_FAILED" and ev2["delete_verified"] is False)
            ev3 = drive_evidence_live(lambda: FDC(unrelated_visible=True), dopts)(frec)
            chk("drive-unrelated-visible->STOP", ev3["status"] == "STOP_UNRELATED_NOT_DENIED")
            dc4 = FDC(root_ok=False)
            ev4 = drive_evidence_live(lambda: dc4, dopts)(frec)
            chk("drive-root-inaccessible->STOP(no-upload,no-new-root)", ev4["status"] == "STOP_EXISTING_ROOT_INACCESSIBLE"
                and dc4.uploads == 0 and not hasattr(dc4, "ensure_folder"))
            chk("drive-no-credential->STOP", drive_evidence_live(lambda: None, dopts)(frec)["status"] == "STOP_NO_DRIVE_CREDENTIAL")

            # reconcile UNKNOWN_RECONCILE -> CANCELLED (governed), never delete the record
            rc = e.apply_envelope(env("reconcile", T6, resolution="CANCELLED", reconciler="claude-session:test",
                                      reason="interrupted-write proof; no effect"))
            r6 = st.get(T6)
            chk("reconcile-unknown->CANCELLED(record+interruption kept)", rc.get("state") == "CANCELLED"
                and r6["reconcile"]["resolution"] == "CANCELLED" and r6["reconcile"]["interruption"]["reason"].startswith("INTERRUPTED_")
                and r6["receipt"]["reconcile_resolution"] == "CANCELLED" and r6["history"])
            chk("reconcile-wrong-state-denied", e.apply_envelope(env("reconcile", T, resolution="CANCELLED", reconciler="x")).get("code") == "WRONG_STATE")
            T29 = "TXN-ST-0029"
            e.apply_envelope(env("propose", T29, proposal=prop()))
            x = st.get(T29)
            x["state"], x["result"] = "UNKNOWN_RECONCILE", {"result": {}, "result_sha256": "z"}
            st.put(x, x["state_version"])
            chk("reconcile-with-effect->EFFECT_UNCERTAIN",
                e.apply_envelope(env("reconcile", T29, resolution="CANCELLED", reconciler="x")).get("code") == "EFFECT_UNCERTAIN")
            chk("reconcile-uncertain-provider-allowed-only-without-result",
                e.apply_envelope(env("reconcile", "TXN-ST-0023", resolution="CANCELLED", reconciler="x")).get("state") == "CANCELLED")

            # owner request entry
            chk("request-entry-non-owner-denied", denied(lambda: e.owner_request(peer=INGRESS_GATEWAY, remote_user_id="0016853ed0304e9a87e5bd5a57ab56e0",
                                                                                  value="x", route="claude-api", evidence="drive"), "NOT_OWNER"))
            clk.t += 7
            ro = e.owner_request(peer=INGRESS_GATEWAY, remote_user_id=OWNER, value="hello dashboard", route="claude-api", evidence="drive")
            chk("request-entry-owner->AWAITING_AUTHORITY", ro.get("state") == "AWAITING_AUTHORITY"
                and st.get(ro["txn_id"])["origin"] == "dashboard-owner-request")
            chk("request-entry-bad-value-denied", denied(lambda: e.owner_request(peer=INGRESS_GATEWAY, remote_user_id=OWNER,
                                                                                 value="<script>", route="claude-api", evidence="none"), "MALFORMED"))
            chk("recent-results-index(bounded,newest-last)", st.recent()[-1] == "TXN-ST-0023" and len(st.recent()) == 8)
            LOG_SINK = None

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

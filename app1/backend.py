"""
backend.py — the API / data-access tier.

Owns authentication, authorization and every database call made on behalf of a
browser. It is the only tier the frontend is allowed to talk to, and the only
one that talks to the database for web traffic.

Anything that reaches Discord or the status service is delegated to the engine over
the internal control API — see engine_client.py.

Binds to loopback only; the frontend proxies to it.
"""

import os
import json
import re
import sys
import time
import hashlib
import tempfile
import ipaddress
import logging
import threading
import warnings
from functools import wraps

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="flask_limiter")

from flask import Flask, abort, g, request, jsonify
from flask_limiter import Limiter
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

import cf_edge

import database as db
# Two data stores, deliberately: db is the ATP (Oracle) and owns everything with
# PII or a transaction; reviews_db is HeatWave (MySQL) and owns the `reviews`
# table alone. Losing the ATP is fatal, losing HeatWave just hides the reviews
# section — see reviews_db.py's header for the whole boundary.
import reviews_db
import panel_data
import node_registry
import engine_client
import internal_auth
import internal_peers
import creds
import error_codes as ec

from urllib.parse import urlsplit as _urlsplit  # used by _load_cors_origins


def _load_cors_origins():
    """Exact-match allowlist from CORS_ORIGINS, or None when unset.

    None (the default) means no Access-Control-* header is emitted anywhere, which
    is this tier's historical behaviour: every in-page fetch is relative and
    same-origin, so nothing here needs CORS. Set the variable only when a real
    off-origin caller exists.

    Entries are compared byte-for-byte against the browser's Origin header, so
    they are normalised the way a browser sends one: scheme and host lowercased,
    no trailing slash, no path. A "*" entry is dropped rather than honoured — the
    responses on this origin carry the session cookie, and a wildcard alongside
    Allow-Credentials is the exact combination that makes that cookie readable
    cross-site. Anything without a scheme://host shape is dropped too, since it
    could never match an Origin and only hides a typo.
    """
    # cf_edge._setting reads the real process env first, then falls back to the
    # shared fastapi-oracle-app/.env. This tier does not load_dotenv itself, so
    # reading os.environ alone would leave this None unless the deploy happened to
    # export CORS_ORIGINS into the backend process. _setting is the same mechanism
    # CF_TRUSTED_IPS uses to reach both tiers from one file; import-time is the only
    # call site so the per-call file scan that docstring warns about is fine.
    raw = cf_edge._setting("CORS_ORIGINS")
    if not raw:
        return None
    allowed = set()
    for entry in raw.split(","):
        candidate = entry.strip().rstrip("/")
        if not candidate or candidate == "*":
            continue
        parts = _urlsplit(candidate)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        # Rebuilt from the parsed parts, so a stray path, query or fragment is
        # discarded instead of making an entry that can never match.
        allowed.add(f"{parts.scheme.lower()}://{parts.netloc.lower()}")
    return frozenset(allowed) or None


_cors_origins = _load_cors_origins()


BACKEND_PORT = int(os.environ.get("BACKEND_PORT", 8001))
# Interface the API listens on. Loopback covers the single-host layout; the
# two-instance layout may need a private interface address here so the other
# instance's frontend can reach it. Validated in _bind_host() — never a wildcard.
BACKEND_BIND = os.environ.get("BACKEND_BIND", "127.0.0.1").strip()

# How many proxies in front of this tier are ours. Only the frontend tier ever
# reaches this port, and that single hop is exactly why a count is still needed:
# the frontend forwards the visitor's address in X-Forwarded-For, so without
# ProxyFix remote_addr is the frontend's own address — every visitor would share
# one rate-limit bucket and every device-policy row would record the proxy
# instead of the client. 0 disables the rewrite entirely: trust nothing, and
# treat the peer address as final.
TRUSTED_PROXY_HOPS = max(0, int(os.environ.get("BACKEND_TRUSTED_PROXY_HOPS", 1)))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1048576
app.config["ENV"] = "production"

if TRUSTED_PROXY_HOPS:
    # Takes the client address from the last TRUSTED_PROXY_HOPS entries of
    # X-Forwarded-For, so whatever a visitor writes into that header themselves
    # is discarded instead of believed.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS)

_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "flask_key.key")


def load_or_create_flask_secret(path):
    """Read one shared 192-bit hex secret, creating it without boot races."""
    def validate(raw):
        secret = raw.strip()
        if len(secret) != 48 or not all(char in "0123456789abcdefABCDEF" for char in secret):
            raise RuntimeError(f"{path} is not a valid 48-character hexadecimal Flask secret")
        return secret

    def atomic_write(material):
        # Temp file + rename in the same directory, so a crash mid-write never
        # leaves the boot path pointing at a partially-written key.
        fd, tmp = tempfile.mkstemp(prefix=".flask_key.", dir=os.path.dirname(path))
        try:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            view = memoryview(material)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("failed to write Flask secret")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def read_valid_or_none():
        try:
            with open(path, encoding="ascii") as key_file:
                raw = key_file.read()
        except FileNotFoundError:
            return None
        stripped = raw.strip()
        if not stripped:
            return None
        if len(stripped) != 48 or not all(char in "0123456789abcdefABCDEF" for char in stripped):
            return None
        return stripped

    os.makedirs(os.path.dirname(path), exist_ok=True)
    candidate = os.urandom(24).hex()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # Another process may be mid-create; give it a moment. A corrupt or
        # empty file (crash between create and write) is regenerated atomically
        # instead of crash-booting every worker on every restart.
        for _ in range(100):
            valid = read_valid_or_none()
            if valid is not None:
                return valid
            time.sleep(0.01)
        try:
            os.unlink(path)
        except OSError:
            pass
        atomic_write(candidate.encode("ascii"))
        with open(path, encoding="ascii") as key_file:
            return validate(key_file.read())

    try:
        material = candidate.encode("ascii")
        while material:
            written = os.write(fd, material)
            if written <= 0:
                raise OSError("failed to write Flask secret")
            material = material[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="ascii") as key_file:
        return validate(key_file.read())


app.secret_key = creds.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    # Must match the frontend tier and every other instance behind the load
    # balancer, or a session cookie signed on one host is discarded as
    # unsigned by the next. _KEY_FILE is per-filesystem and cannot converge
    # two hosts; ENCRYPTION_KEY already has to be identical everywhere for the
    # tiers to read the same database, so derive from it. Hashed with a domain
    # label to keep this one-way rather than a second copy of that key.
    _fleet_secret = creds.get("ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY", "")
    if _fleet_secret:
        app.secret_key = hashlib.sha256(
            b"endhost.flask.session.v1|" + _fleet_secret.encode("utf-8")).hexdigest()
if not app.secret_key:
    app.secret_key = load_or_create_flask_secret(_KEY_FILE)


def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass


def _get_client_ip():
    """The visitor's address. ProxyFix has already resolved it from the hops we
    trust, so parsing X-Forwarded-For here again would only re-admit the part of
    the header a client can write. With TRUSTED_PROXY_HOPS=0 this is the peer —
    the frontend — which is the correct answer when no hop is trusted."""
    if os.environ.get("FRONTEND_DEBUG_HEADERS", "").strip().lower() in ("1", "true", "yes"):
        _debug_print(f"[be-dbg] path={request.path} "
                     f"xff={request.headers.get('X-Forwarded-For', '')} "
                     f"resolved={request.remote_addr or ''}", flush=True)
    return request.remote_addr or ""


# Rate-limit on the *visitor's* IP, not the peer's. Every request here arrives
# from the frontend, so keying on the raw peer address would put the whole site
# in one bucket — a single busy visitor would lock everyone else out of login.
# The frontend forwards the real client IP, and its own limiter (keyed on the
# true peer address) is what stops anyone spoofing that header to get free
# attempts here.
#
# RATELIMIT_STORAGE_URI points the counters at shared storage so two instances
# enforce one limit instead of one each; unset keeps the per-process memory
# backend, which is all a single instance needs. When Redis is configured but
# unreachable, in_memory_fallback_enabled lets the site stay up with per-process
# counters rather than blocking login.
limiter = Limiter(
    _get_client_ip,
    app=app,
    default_limits=["500 per minute", "50000 per day"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI") or None,
    storage_options={"connection_pool_kwargs": {"socket_connect_timeout": 3}},
    in_memory_fallback_enabled=True,
)

# Both ways the limits can quietly stop being limits, made loud on stderr.
#
# flask-limiter already reports a dead store exactly once per outage — it logs
# "Rate limit storage unreachable - falling back to in-memory storage" and then
# sets _storage_dead, so it is one line per outage and not one per request — but
# its constructor attaches a NullHandler to the "flask-limiter" logger, and a
# logger that has any handler never reaches logging.lastResort. That warning was
# therefore discarded before it could reach a terminal, which is why the fallback
# is invisible today: Redis dies, in_memory_fallback_enabled keeps the site
# serving on per-process counters (the right call — a blip must loosen limits,
# not 500 every request), and nothing anywhere says the shared ceiling is gone
# and each worker is granting its own full allowance again. Giving that logger a
# real stderr handler is all it takes to surface it.
_limiter_log = logging.getLogger("flask-limiter")
# Set explicitly rather than inherited: the effective level would otherwise come
# from the root logger, so anything that raises root to ERROR would silently
# re-mute the fallback warning this exists to show.
_limiter_log.setLevel(logging.WARNING)
_limiter_log_handler = logging.StreamHandler(sys.stderr)
_limiter_log_handler.setFormatter(logging.Formatter("[backend] LIMITER %(levelname)s: %(message)s"))
_limiter_log.addHandler(_limiter_log_handler)

# The other silence, and the one flask-limiter cannot report: a store that was
# never configured at all gives it nothing to complain about, yet every limit
# below then counts per worker per instance, so 2 instances x N workers turns
# "10 per minute" into a multiple of itself.
if not (os.environ.get("RATELIMIT_STORAGE_URI") or "").strip():
    _debug_print("[backend] WARNING: RATELIMIT_STORAGE_URI is unset - rate limits are "
                 "per-process in-memory counters, so each worker and each instance "
                 "grants its own full allowance. Point it at a store both instances "
                 "share before treating any limit here as a limit.",
                 file=sys.stderr, flush=True)


# Longest per-account rate-limit key derived from a request body. See
# _body_value() for why the bound has to live here and not in the routes.
RATELIMIT_KEY_MAX_LEN = 256


def _body_value(field):
    """One JSON-body field for a per-account rate-limit key.

    The IP-based limits above are cheap to rotate around, so login and OTP
    endpoints get a second bucket keyed on the *account*: a distributed attack
    on one email/username now hits one shared counter. Malformed bodies fall
    back to the client IP so they still get some bucket.
    """
    try:
        data = request.get_json(force=True)
        value = data.get(field) if isinstance(data, dict) else None
    except Exception:
        value = None
    if value is None or isinstance(value, (list, dict)):
        # No account to key on. The client IP is what the docstring promises, and
        # returning a constant here instead meant every body that omitted this
        # field shared one counter: a handful of fieldless posts exhausted the
        # "1 per 60 seconds" bucket for every other caller at the same time.
        return _get_client_ip() or ""
    # Capped: this becomes part of a key in the rate-limit store, which is shared
    # by both instances when RATELIMIT_STORAGE_URI is set. Uncapped, a caller
    # chose the key length, so a body just under MAX_CONTENT_LENGTH wrote a
    # megabyte-long counter key per attempt — and the route's own length check
    # cannot help, because the key is computed before the route body runs.
    # Truncating only ever merges two long values into one bucket, which limits
    # harder rather than less.
    return str(value).strip().lower()[:RATELIMIT_KEY_MAX_LEN]


@app.errorhandler(400)
def _bad_request(e):
    # request.get_json(force=True) raises BadRequest on an empty or malformed
    # body; without a handler that becomes an HTML error page from a JSON API.
    return ec.err(ec.BAD_REQUEST, "Malformed or missing request body", 400)


@app.errorhandler(404)
def _not_found(e):
    if request.path.startswith("/api/"):
        return ec.err(ec.NOT_FOUND, "Endpoint not found", 404)
    return "Not Found", 404


@app.errorhandler(413)
def _request_entity_too_large(e):
    return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)


# How long a throttled caller is told to wait, in seconds. Without this header a
# 429 says only "no", and well-behaved HTTP clients, SDK retry loops and crawlers
# all read an absent Retry-After as "retry immediately" — so the answer to a
# spike became a second spike, and the limit amplified the load it exists to
# shed. 60s mirrors the value panel_app/security_headers.py sends (its own
# fixed-window length), and a minute is also the shortest window any limit here
# is expressed in, so it is the soonest a retry can succeed instead of earning
# another 429. Fixed rather than computed on purpose: flask-limiter only works
# out an exact reset time when header injection is enabled, which it is not here,
# and a value guessed too low just invites the instant retry this is preventing.
RATELIMIT_RETRY_AFTER_SECONDS = max(1, int(os.environ.get("RATELIMIT_RETRY_AFTER_SECONDS", 60)))


@app.errorhandler(429)
def _ratelimit_handler(e):
    payload, status = ec.err(ec.RATE_LIMITED, "Rate limit exceeded. Please slow down.", 429)
    # ec.err returns a (payload, status) tuple, which Flask would finish turning
    # into a response only after this function returns — leaving nowhere to hang a
    # header. Building the response here is what makes Retry-After settable; the
    # body stays byte-identical to what this handler returned before.
    response = jsonify(payload)
    response.status_code = status
    response.headers["Retry-After"] = str(RATELIMIT_RETRY_AFTER_SECONDS)
    return response


@app.errorhandler(500)
def _internal_error(e):
    import traceback
    error_type = type(e).__name__ if hasattr(e, "__name__") else "InternalServerError"
    message = str(e)
    stack_trace = traceback.format_exc()
    try:
        reviews_db.log_app_error(error_type, message, stack_trace, module="backend", flagged=1)
    except Exception as log_ex:
        _debug_print(f"[backend] failed to log error to HeatWave: {log_ex}", file=sys.stderr)
    return ec.err(ec.INTERNAL_ERROR, "Internal server error", 500)


@app.errorhandler(Exception)
def _unhandled_exception(e):
    if isinstance(e, HTTPException):
        return e
    import traceback
    error_type = type(e).__name__
    message = str(e)
    stack_trace = traceback.format_exc()
    try:
        reviews_db.log_app_error(error_type, message, stack_trace, module="backend", flagged=1)
    except Exception as log_ex:
        _debug_print(f"[backend] failed to log error to HeatWave: {log_ex}", file=sys.stderr)
    return ec.err(ec.INTERNAL_ERROR, "Internal server error", 500)


DB_BUSY_RETRY_AFTER_SECONDS = max(1, int(os.environ.get("DB_BUSY_RETRY_AFTER_SECONDS", 5)))


@app.errorhandler(db.OraclePoolExhausted)
def _db_pool_exhausted(e):
    payload, status = ec.err(ec.BACKEND_UNAVAILABLE,
                             "Service temporarily unavailable. Please try again.", 503)
    response = jsonify(payload)
    response.status_code = status
    response.headers["Retry-After"] = str(DB_BUSY_RETRY_AFTER_SECONDS)
    return response


@app.after_request
def _security_headers(response):
    # CORS: explicit allowlist from CORS_ORIGINS only — no wildcard, no reflection.
    # The backend binds to loopback and is normally reached through the frontend
    # proxy, but a misconfigured deploy or a forwarded port can still expose it to
    # a browser directly. With the session cookie on this origin, a wildcard origin
    # plus Allow-Credentials is the exact combination that turns that cookie into
    # a cross-site read. Allow-Credentials is therefore only set on an exact
    # match, never on a wildcard, and the Origin header is read back verbatim only
    # when it equals an allowlist entry — so an unrecognised Origin gets no
    # Access-Control-* header at all and the browser blocks the response.
    if _cors_origins is not None:
        sent_origin = request.headers.get("Origin", "")
        if sent_origin in _cors_origins:
            response.headers["Access-Control-Allow-Origin"] = sent_origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token"
            response.headers["Access-Control-Max-Age"] = "3600"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


def _safe_json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _json_object():
    """The request body as a dict, or a 400.

    request.get_json(force=True) returns whatever the body decoded to, so a
    perfectly well-formed `[1,2]` or `"hi"` or `7` reached the `data.get(...)` on
    the next line of every route below and raised AttributeError — a 500 for what
    is plainly a bad request. abort(400) lands in the handler above, which already
    renders this as a JSON error.
    """
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        abort(400)
    return data


def _text_field(data, field):
    """One body field as trimmed text, whatever type the client sent.

    The routes below all wrote `(data.get(f) or "").strip()`, and `or ""` only
    rescues a *falsy* value: {"email": 123} left int.strip() to raise, so a
    wrong-typed field was a 500 rather than the validation error the very next
    line was ready to return. Numbers and booleans become their text. A list or
    dict has no meaningful text form, so it yields "" and the field's own
    required/format check rejects it.
    """
    value = data.get(field)
    if value is None or isinstance(value, (list, dict)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, str):
        value = str(value)
    if any("\ud800" <= ch <= "\udfff" for ch in value):
        abort(400)
    return value.strip()


def _raw_field(data, field):
    """A password field, coerced to str but never trimmed.

    Same type crash as _text_field guards, but stripping a password is not a
    harmless tidy-up: registration stored the hash of the untrimmed value while
    the change-password route trimmed before verifying, so anyone whose password
    began or ended with a space could never change it, and a new password set
    through that route was stored trimmed and then failed at login.
    """
    value = data.get(field)
    if value is None or isinstance(value, (list, dict)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else str(value)


def _db_truthy(value):
    """Normalize Oracle/driver flag representations at API boundaries.
    DB stores 0/1 (NUMBER/INTEGER). Oracle returns floats, MySQL may return
    strings. Accept legacy 'true'/'yes' but the canonical values are 0/1."""
    return str(value).strip() in ("1", "1.0")


# Upper bound on a submitted password. Argon2id is deliberately expensive, and
# every register/change-password call pays for one verify plus one hash, so an
# uncapped field let a single request buy a megabyte of hashing work.
PASSWORD_MAX_LEN = 1024
# Bounds on the short text fields the auth routes match against. Each already
# has a format check that a long value cannot pass; the cap keeps the work of
# reaching that check proportional to a real submission.
EMAIL_MAX_LEN = 254
USERNAME_MAX_LEN = 32
OTP_CODE_MAX_LEN = 12
USER_ID_MAX_LEN = 36
# sessions.id is VARCHAR2(64).
SESSION_ID_MAX_LEN = 64


# ── Bot builder blobs (embed / ip-reply) ──
# Both are client-authored JSON that save_bot_config() encrypts into a CLOB.
# Every scalar sibling in that call has a range or format check; these two blobs
# had none, so a crafted POST stored unbounded JSON in a size-capped Always Free
# ATP, or types the renderers then had to defend against. Caps mirror the
# engine's own truncation in _ip_reply_embed / _send_ip_reply, and the engine
# expands {ip}/{port} placeholders *before* truncating, so what is bounded here
# is the stored template.
_IP_REPLY_MODES = ("plain", "embed")
_IP_REPLY_TRIGGER_MAX = 50
_IP_REPLY_PLAIN_MAX = 2000
_IP_REPLY_EMBED_LIMITS = (("title", 256), ("description", 4096), ("footer", 2048))
_HEX_COLOR_RE = re.compile(r"^#?[0-9a-fA-F]{6}$")
# The status embed is a much wider shape (widgets, custom_fields, per-field
# labels) and is normalized by its own renderer, so it gets a total serialized
# ceiling rather than a per-key allowlist. Far above any real builder save.
EMBED_JSON_MAX_BYTES = 65536


def _blob_text(value, field, limit):
    """One text field of a builder blob, type- and length-checked."""
    if value is None:
        return ""
    if isinstance(value, (list, dict, bool)):
        raise ValueError(f"{field} must be text")
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        raise ValueError(f"{field} is too long (max {limit} characters)")
    return text


def _clean_ip_reply(raw):
    """Validate the ip-reply template. Unknown keys are dropped, not stored.

    Only keys the client actually sent are emitted, so a partial save keeps the
    same meaning it had before this check existed.
    """
    if not isinstance(raw, dict):
        raise ValueError("ip_reply must be an object")
    clean = {}
    if "enabled" in raw:
        clean["enabled"] = bool(raw.get("enabled"))
    if "trigger" in raw:
        trigger = _blob_text(raw.get("trigger"), "ip_reply trigger", _IP_REPLY_TRIGGER_MAX).strip()
        clean["trigger"] = trigger or "ip"
    if "mode" in raw:
        mode = _blob_text(raw.get("mode"), "ip_reply mode", 16).strip().lower()
        if mode not in _IP_REPLY_MODES:
            raise ValueError("ip_reply mode must be 'plain' or 'embed'")
        clean["mode"] = mode
    if "plain_text" in raw:
        clean["plain_text"] = _blob_text(
            raw.get("plain_text"), "ip_reply message text", _IP_REPLY_PLAIN_MAX)
    if "embed" in raw:
        embed_raw = raw.get("embed") or {}
        if not isinstance(embed_raw, dict):
            raise ValueError("ip_reply embed must be an object")
        embed = {}
        for field, limit in _IP_REPLY_EMBED_LIMITS:
            if field in embed_raw:
                embed[field] = _blob_text(embed_raw.get(field), f"ip_reply embed {field}", limit)
        if "color" in embed_raw:
            color = _blob_text(embed_raw.get("color"), "ip_reply embed colour", 7).strip()
            if color and not _HEX_COLOR_RE.match(color):
                raise ValueError("ip_reply embed colour must be a 6-digit hex value like #9b59b6")
            embed["color"] = ("#" + color.lstrip("#").lower()) if color else ""
        clean["embed"] = embed
    return clean


def _clean_embed(raw):
    """Type- and size-check the status embed blob before it is stored."""
    if not isinstance(raw, dict):
        raise ValueError("embed must be an object")
    try:
        encoded = json.dumps(raw)
    except (TypeError, ValueError):
        raise ValueError("embed is not serializable")
    if len(encoded.encode("utf-8", "replace")) > EMBED_JSON_MAX_BYTES:
        raise ValueError(f"embed configuration is too large (max {EMBED_JSON_MAX_BYTES} bytes)")
    return raw


# ── Untrusted device-fingerprint intake ──
#
# `fingerprint` and `fingerprint_detail` are both collected in the browser and
# posted in hidden form fields, so a client controls every byte of each one. The
# detail blob is evidence only — nothing here or downstream matches identity on
# it — and it ends up Fernet-encrypted in a CLOB, so the exposure that matters is
# its size and what a malformed copy does to the code that parses it.

# Longest raw `fingerprint_detail` string accepted. The real payload is a couple
# of KB and grows with every probe added to g7.js; 64 KiB leaves several
# times that in headroom while keeping a fixed bound on what gets encrypted and
# written to the CLOB. Flask's 1 MiB MAX_CONTENT_LENGTH is the outer backstop.
FP_DETAIL_MAX_BYTES = 65536

# Longest raw `fingerprint` string worth looking at, so a huge value is discarded
# before the regex ever runs over it.
FP_MAX_LEN = 128

# A fingerprint is a SHA-256 hex digest, or g7.js's `fb_<hex>` fallback for
# non-secure contexts where SubtleCrypto is unavailable. Nothing else is one.
FP_RE = re.compile(r"^(?:[0-9a-f]{64}|fb_[0-9a-f]{1,16})$", re.IGNORECASE)

# Device-event type for a client whose own report contradicts itself. Purely
# observational: every signal behind it is self-reported and spoofable in both
# directions, so a hit is recorded for the console and changes nothing about what
# the visitor is allowed to do.
DEVICE_EVENT_CLIENT_TAMPER = "client_tamper_signal"
DEVICE_EVENT_DEVTOOLS = "devtools_open_2m"


def _clean_fingerprint(fp):
    """Split a posted fingerprint into (usable value, anomaly reason).

    A value that is not one of the two documented shapes is discarded rather
    than answered with an error: it is telemetry the visitor never typed, every
    caller here already handles an absent fingerprint, and refusing the request
    would lock a real account out over a field the client controls anyway.
    """
    if not fp:
        return "", None
    if len(fp) > FP_MAX_LEN:
        return "", "fingerprint_oversize"
    if not FP_RE.fullmatch(fp):
        return "", "fingerprint_malformed"
    return fp, None


def _clean_fp_detail(raw):
    """Bound and parse a posted detail blob → (raw to persist, parsed, anomaly).

    Over-cap input is dropped whole rather than truncated: the copies downstream
    call json.loads() on this string, and a truncated JSON document does not
    parse. Anything that will not parse into an object is emptied too, so it
    reaches the database layer as simply absent — binding and login have to keep
    working when the detail is missing.
    """
    if not raw:
        return "", {}, None
    if len(raw.encode("utf-8", "replace")) > FP_DETAIL_MAX_BYTES:
        return "", {}, "detail_oversize"
    parsed = _safe_json(raw)
    if not isinstance(parsed, dict):
        return "", {}, "detail_unparseable"
    return raw, parsed, None


def _short(v, limit=120):
    """One untrusted scalar, bounded, for a device-event details field."""
    if v is None or isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    return str(v)[:limit]


def _short_list(v, limit=40, width=120):
    """Up to `limit` untrusted entries, each bounded, for device-event details."""
    if not isinstance(v, (list, tuple)):
        return []
    return [_short(x, width) for x in v[:limit]]


def _count(v, limit=999999):
    """One untrusted count, or None when the payload sent anything else.

    A bool is an int in Python and is never a count, and JSON can carry an
    integer of any length — which would be written out in full — so both are
    refused rather than copied.
    """
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return v if v <= limit else limit
    return None


def _observed_ip():
    """The address the request actually arrived from, for comparing against what
    the client claims about itself. Same resolution every device event already
    records; the guard is here because these helpers must not raise, and off a
    request there is no address to compare with."""
    try:
        return _get_client_ip()
    except Exception:
        return ""


def _webrtc_foreign_ips(webrtc, observed_ip, limit=8):
    """The addresses WebRTC volunteered that are not the one the request came from.

    A routable candidate the server never saw is how a proxy or VPN shows up in
    the browser's own report. mDNS hostnames and private, loopback or link-local
    literals are what an ordinary LAN answers with, so they are evidence of
    nothing and are dropped before the comparison.
    """
    if not isinstance(webrtc, dict):
        return []
    # A loopback or private observed address means the request never crossed the
    # internet to reach us — local testing, or a proxy hop count that left
    # remote_addr unrewritten. It cannot be compared against a public candidate,
    # and comparing anyway reports every ordinary user as a proxy.
    try:
        if not ipaddress.ip_address((observed_ip or "").strip()).is_global:
            return []
    except Exception:
        return []
    ips = webrtc.get("ips")
    if not isinstance(ips, (list, tuple)):
        return []
    foreign = []
    for entry in ips[:limit * 8]:
        if not isinstance(entry, str):
            continue
        ip = entry.strip()[:80]
        if not ip or ip == (observed_ip or "") or ip in foreign:
            continue
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except Exception:
            continue
        foreign.append(ip)
        if len(foreign) >= limit:
            break
    return foreign


def _webrtc_candidate_ips(webrtc, observed_ip, limit=8):
    """Addresses for the console record, when the observed one cannot be compared.

    _webrtc_foreign_ips() answers "is this a proxy or VPN leak?" and must stay
    silent when the observed address is loopback or private — local testing, a
    tunnel, or a proxy hop that left remote_addr unrewritten. But that silence
    also hides the visitor's real routable address from the admin, who has
    nothing else to look at. This variant records the routable candidates in
    that case (display-only; never feeds a signal or a decision)."""
    if not isinstance(webrtc, dict):
        return []
    ips = webrtc.get("ips")
    if not isinstance(ips, (list, tuple)):
        return []
    observed = (observed_ip or "").strip()
    try:
        observed_global = ipaddress.ip_address(observed).is_global
    except Exception:
        observed_global = False
    seen = []
    out = []
    for entry in ips[:limit * 8]:
        if not isinstance(entry, str):
            continue
        ip = entry.strip()[:80]
        if not ip or ip in seen:
            continue
        seen.append(ip)
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except Exception:
            continue
        if observed_global and ip == observed:
            continue
        out.append(ip)
        if len(out) >= limit:
            break
    return out


def _tamper_signals(detail, *anomalies):
    """Reasons this payload looks tampered with, for admin review only.

    `automation.verdict == 'headless'` is the client admitting to a headless
    runtime, and a non-empty `workerMismatch` means the page and its worker
    disagree about the same properties — the client contradicting its own
    identity. Neither is trustworthy enough to act on, only to record.

    The later probes add three more of the same kind: a non-zero `lies.count` is
    a native function that no longer looks native, and `windowProps.extra` /
    `windowProps.missing` are window properties injected or deleted against a
    clean iframe's view. `webrtc.ips` counts only when it offers a routable
    address the request did not arrive from, which is how a proxy or VPN leaks.
    `resistance` and `trash` are context, not evidence — a privacy-hardened
    browser and a browser that still ships deprecated APIs are both ordinary, so
    neither adds a signal here and neither can make a payload look malicious on
    its own. They are recorded alongside whatever did fire.
    """
    signals = [a for a in anomalies if a]
    if isinstance(detail, dict):
        automation = detail.get("automation")
        if isinstance(automation, dict) and automation.get("verdict") == "headless":
            signals.append("automation_headless")
        mismatch = detail.get("workerMismatch")
        if isinstance(mismatch, (list, tuple)) and mismatch:
            signals.append("worker_mismatch")
        lies = detail.get("lies")
        if isinstance(lies, dict) and (_count(lies.get("count")) or 0) > 0:
            signals.append("native_lies")
        wprops = detail.get("windowProps")
        if isinstance(wprops, dict):
            extra = wprops.get("extra")
            if isinstance(extra, (list, tuple)) and extra:
                signals.append("window_props_extra")
            missing = wprops.get("missing")
            if isinstance(missing, (list, tuple)) and missing:
                signals.append("window_props_missing")
        if _webrtc_foreign_ips(detail.get("webrtc"), _observed_ip()):
            signals.append("webrtc_ip_mismatch")
    return signals


def _shared_with_other_account(fp, ip_address, user_id=None):
    """Whether this device or this address already belongs to a *different* account.

    A tamper signal on an account that is alone on its device and its network is
    a browser quirk rather than evidence: privacy-hardened builds and extensions
    trip the native-code and worker checks routinely, and recording those buries
    the console in rows no one can act on. The same signal on a device or an
    address that a second account also uses is the multi-account case the Flags
    page exists to surface. At signup there is no account yet, so any other
    account already on the device or the address counts.

    Both lookups are indexed equality matches on a hash column, and they replace
    an INSERT rather than adding to one.
    """
    me = str(user_id) if user_id else None
    for finder, arg in ((db.accounts_on_device, fp), (db.accounts_on_ip, ip_address)):
        if not arg:
            continue
        try:
            others = finder(arg) or []
        except Exception:
            continue
        for u in others:
            if str(u.get("uid")) != me:
                return True
    return False


def _log_tamper_signals(signals, detail, fp, user_id=None, username=None, ip_address=None):
    """Record a tamper sighting for the console and return.

    Observational by contract: callers must not change what they return to the
    visitor on the strength of this. A false positive here would lock out a real
    paying user over a signal the client made up. The evidence is copied as a
    bounded excerpt rather than the whole blob so a client cannot use this path
    to write a CLOB of its choosing on every attempt.
    """
    if not signals:
        return
    if not _shared_with_other_account(fp, ip_address, user_id):
        return
    detail = detail if isinstance(detail, dict) else {}
    automation = detail.get("automation")
    automation = automation if isinstance(automation, dict) else {}
    lies = detail.get("lies")
    lies = lies if isinstance(lies, dict) else {}
    wprops = detail.get("windowProps")
    wprops = wprops if isinstance(wprops, dict) else {}
    resistance = detail.get("resistance")
    resistance = resistance if isinstance(resistance, dict) else {}
    trash = detail.get("trash")
    trash = trash if isinstance(trash, dict) else {}
    db.log_device_event(
        DEVICE_EVENT_CLIENT_TAMPER, user_id=user_id, username=username,
        fingerprint_hash=fp or None, ip_address=ip_address, blocked=False,
        details={"signals": signals,
                 "verdict": _short(automation.get("verdict")),
                 "automation_hits": _short_list(automation.get("hits")),
                 "worker_mismatch": _short_list(detail.get("workerMismatch")),
                 "worker_scope": _short(detail.get("workerScope")),
                 "lies_count": _count(lies.get("count")),
                 "lies_hits": _short_list(lies.get("hits"), 12, 80),
                 "window_props_extra": _short_list(wprops.get("extra"), 24, 80),
                 "window_props_missing": _short_list(wprops.get("missing"), 24, 80),
                 "resistance_engine": _short(resistance.get("engine"), 80),
                 "resistance_mode": _short(resistance.get("mode"), 80),
                 "resistance_hits": _short_list(resistance.get("hits"), 12, 80),
                 "webrtc_ips": _webrtc_candidate_ips(detail.get("webrtc"), ip_address or _observed_ip()),
                 "trash_count": _count(trash.get("count")),
                 "outcome": "allowed"},
    )


def _authenticate():
    sid = request.headers.get("X-Session-Id", "")
    if not sid:
        return None, "Authentication required"
    data = db.get_session(sid)
    if not data:
        return None, "Invalid or expired session"
    user_id = data.get("user_id")
    g.current_user_id = user_id
    return user_id, None


def api_user_required(f):
    @wraps(f)
    def wrap(*a, **k):
        uid, err = _authenticate()
        if err or not uid:
            return ec.err(ec.UNAUTHORIZED, err or "User access required", 401)
        banned, _ = db.is_user_banned(uid)
        if banned:
            return ec.err(ec.BANNED, "BANNED", 403, banned=True,
                          reason="Your account has been banned.")
        if not db.is_user_active(uid):
            return ec.err(ec.FORBIDDEN, "Account disabled", 403)
        return f(*a, **k)
    return wrap


def api_internal_required(f):
    """For endpoints only ever called by our own processes (frontend, engine).
    They carry no session of their own, so the shared internal token is the
    only thing standing between them and anyone who can reach this port."""
    @wraps(f)
    def wrap(*a, **k):
        if not internal_auth.is_internal_request(request):
            return ec.err(ec.INTERNAL_ACCESS_REQUIRED, "Internal access required", 401)
        if not internal_peers.peer_allowed(request.environ):
            return ec.err(ec.INTERNAL_ACCESS_REQUIRED, "Internal access required", 401)
        return f(*a, **k)
    return wrap


def _owns(user_id):
    """True when the caller *is* that user. There is no override: this tier has
    no admin surface any more, so nothing here may act on another account.
    Assumes _authenticate() already ran via a decorator."""
    return g.get("current_user_id") == user_id


def _own_bot(bot_id):
    """Fetch a bot only if the session's user owns it, else None."""
    bot = db.get_bot(bot_id)
    if not bot or bot.get("uid") != g.current_user_id:
        return None
    return bot


@app.route("/api/internal/probe", methods=["GET"])
@api_internal_required
@limiter.limit("20000 per minute")
def api_internal_probe():
    return jsonify({"ok": True})


@app.route("/api/auth/send-otp", methods=["POST"])
@api_internal_required
@limiter.limit("3 per minute; 10 per hour; 20 per day")
@limiter.limit("1 per 60 seconds; 5 per hour; 10 per day",
               key_func=lambda: _body_value("email"))
def api_send_otp():
    data = _json_object()
    email = _text_field(data, "email").lower()
    if len(email) > EMAIL_MAX_LEN or not db.EMAIL_RE.match(email):
        return ec.err(ec.EMAIL_INVALID, "Only @gmail.com or @outlook.com emails allowed", 400)
    try:
        code = db.generate_otp(email)
        db.send_otp_email(email, code)
        return jsonify({"ok": True})
    except ValueError as val_ex:
        reviews_db.log_app_error("OtpSendValueError", f"send-otp config error for {email}: {val_ex}", module="backend", flagged=1)
        _debug_print(f"[backend] send-otp config error for {email}", file=sys.stderr)
        return ec.err(ec.OTP_SEND_FAILED, "Failed to send OTP. Please try again later.", 500)
    except Exception as e:
        reviews_db.log_app_error("OtpSendFailed", f"send-otp failed for {email}: {e}", module="backend", flagged=1)
        _debug_print(f"[backend] send-otp failed for {email}: {e}", file=sys.stderr)
        return ec.err(ec.OTP_SEND_FAILED, "Failed to send OTP. Please try again later.", 500)


@app.route("/api/auth/verify-otp", methods=["POST"])
@api_internal_required
@limiter.limit("10 per minute; 30 per hour; 100 per day")
@limiter.limit("5 per minute; 20 per hour; 50 per day",
               key_func=lambda: _body_value("email"))
def api_verify_otp():
    data = _json_object()
    email = _text_field(data, "email").lower()
    code = _text_field(data, "code")
    if len(email) > EMAIL_MAX_LEN or len(code) > OTP_CODE_MAX_LEN:
        return ec.err(ec.OTP_INVALID, "Invalid or expired OTP", 400)
    if not db.verify_otp(email, code):
        return ec.err(ec.OTP_INVALID, "Invalid or expired OTP", 400)
    return jsonify({"ok": True, "email": email})


# ── Session API (internal only — the frontend's session store lives here) ──

@app.route("/api/session", methods=["POST"])
@api_internal_required
@limiter.limit("60 per minute")
def api_create_session():
    data = _json_object()
    sid = _text_field(data, "sid")
    sdata = data.get("data", {})
    ip = _get_client_ip()
    ua = request.headers.get("User-Agent", "")
    # sid is the sessions PK (VARCHAR2(64)) and the blob is what _authenticate()
    # later calls .get() on, so a non-dict stored here turned every authenticated
    # request on that session into a 500. Both are refused at the boundary.
    if sid and len(sid) <= SESSION_ID_MAX_LEN and isinstance(sdata, dict) and sdata:
        db.create_session(sid, sdata, ip_address=ip, user_agent=ua)
        return jsonify({"ok": True})
    return ec.err(ec.MISSING_FIELDS, "Missing sid or data", 400)


@app.route("/api/session/<sid>", methods=["GET"])
@api_internal_required
# This is the one internal route whose callers collapse into a single rate-limit
# bucket. The frontend forwards the visitor's X-Forwarded-For (frontend.py _api),
# so its lookups key per visitor and sit far under any per-endpoint cap. The panel
# sends no XFF, so every panel session lookup keys on one source address, and the
# panel resolves the session before its own limiter — which does count reads now,
# under a separate 600/min ceiling — ever sees the request. Steady state is not
# what exhausts the shared default (500/min, 50000/day) any more: the panel caches
# a resolved session for 300s and runs one process per instance, so it would take
# ~2500 concurrent panel sessions there to reach 500/min. The uncached case still
# does — a flood of session cookies, each a fresh sid that misses the cache and
# that the HMAC only refuses for free once SESSION_COOKIE_MAC_GRACE is off — and
# then every panel page 503s (on_session_unavailable). This explicit limit
# overrides the default for this route only (Flask-Limiter's override_defaults
# defaults to True), sitting well above the panel's legitimate lookup rate while
# still bounding a cookie flood. Raising the cap cannot worsen pool pressure: peak
# concurrent lookups are bounded by the tier's thread count, which oversubscribes
# the pool 2:1 either way (8 waitress threads to a max-4 pool; 4 per gunicorn
# worker to 2, main.py:144), so the pool is where they queue and not here, and
# each lookup only ever holds one connection at a time — a primary-key SELECT,
# released, then a primary-key UPDATE — so it never demands two pool slots at once.
@limiter.limit("2000 per minute")
def api_get_session(sid):
    data = db.get_session(sid)
    if data is None:
        return ec.err(ec.SESSION_NOT_FOUND, "Session not found", 404)
    return jsonify({"ok": True, "data": data})


@app.route("/api/session/<sid>/consume-impersonation", methods=["POST"])
@api_internal_required
def api_consume_impersonation_session(sid):
    data = db.consume_impersonation_ticket(sid)
    if data is None:
        return ec.err(ec.SESSION_NOT_FOUND, "Session not found", 404)
    return jsonify({"ok": True, "data": data})


@app.route("/api/session/<sid>", methods=["PUT"])
@api_internal_required
def api_save_session(sid):
    body = _json_object()
    sdata = body.get("data", {})
    if isinstance(sdata, dict) and sdata:
        db.save_session(sid, sdata)
        return jsonify({"ok": True})
    return ec.err(ec.MISSING_FIELDS, "Missing data", 400)


@app.route("/api/session/<sid>", methods=["DELETE"])
@api_internal_required
def api_delete_session(sid):
    db.delete_session(sid)
    return jsonify({"ok": True})


@app.route("/api/session/cleanup", methods=["POST"])
@api_internal_required
def api_cleanup_sessions():
    db.cleanup_expired_sessions()
    return jsonify({"ok": True})


# ── Public Auth API (rate-limited, no session required) ──

@app.route("/api/auth/register", methods=["POST"])
@api_internal_required
@limiter.limit("5 per minute; 20 per hour; 50 per day")
def api_auth_register():
    data = _json_object()
    username = _text_field(data, "username")
    password = _raw_field(data, "password")
    email = _text_field(data, "email").lower()
    display = _text_field(data, "display_name") or None
    fp, fp_anomaly = _clean_fingerprint(_text_field(data, "fingerprint"))
    fp_detail, fp_parsed, detail_anomaly = _clean_fp_detail(_text_field(data, "fingerprint_detail"))
    client_ip = _get_client_ip()

    if not username or not password or not email:
        return ec.err(ec.MISSING_FIELDS, "Username, password and email required", 400)
    if len(username) < 3 or len(username) > USERNAME_MAX_LEN:
        return ec.err(ec.USERNAME_INVALID, "Username must be between 3 and 32 characters", 400)
    if any(ord(c) < 32 or ord(c) == 127 for c in username):
        # Control characters in a username are an SMTP header-injection vector:
        # the name is interpolated into welcome-email subjects and headers.
        return ec.err(ec.USERNAME_INVALID, "Username contains invalid characters", 400)
    if len(password) < 8:
        return ec.err(ec.PASSWORD_TOO_SHORT, "Password must be at least 8 characters", 400)
    if len(password) > PASSWORD_MAX_LEN:
        return ec.err(ec.PASSWORD_TOO_LONG,
                      f"Password must be at most {PASSWORD_MAX_LEN} characters", 400)
    if len(email) > EMAIL_MAX_LEN or not db.EMAIL_RE.match(email):
        return ec.err(ec.EMAIL_INVALID, "Only @gmail.com or @outlook.com emails allowed", 400)
    if display and (len(display) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in display)):
        display = (display or "")[:64]
        display = "".join(c for c in display if ord(c) >= 32 and ord(c) != 127)

    # Recorded, never enforced: a headless verdict or a main-thread-vs-worker
    # disagreement says the client is lying about itself, and that is exactly
    # why it cannot be the basis of a decision. Logged before the device policy
    # runs so the sighting survives a signup that goes on to be refused.
    _log_tamper_signals(_tamper_signals(fp_parsed, fp_anomaly, detail_anomaly),
                        fp_parsed, fp, username=username, ip_address=client_ip)

    # There is no cap on how many accounts a device or IP may register. Every
    # signup from a device or network that already holds an account is recorded
    # as a device event for the console to review. A banned account on the
    # device is the one thing that still turns a signup away.
    dev_info = {}
    if fp:
        dev_ok, dev_err, dev_info = db.check_device_registration(fp, client_ip)
        existing = [u.get("username") for u in dev_info.get("device_accounts", [])]
        reason = dev_info.get("reason")
        if reason or existing or not dev_ok:
            db.log_device_event(
                "repeat_registration", username=username, fingerprint_hash=fp,
                device_info=fp_detail, ip_address=client_ip, blocked=not dev_ok,
                details={"attempted_email": email, "reason": reason,
                         "existing_accounts": existing},
            )
            try:
                reviews_db.log_app_error(
                    error_type="MultiAccountRegistrationFlag",
                    message=f"Multiple accounts detected for username '{username}' on same fingerprint/IP. Reason: {reason}. Existing accounts on device: {', '.join(existing) if existing else 'none'}",
                    stack_trace=json.dumps({
                        "attempted_username": username,
                        "attempted_email": email,
                        "client_ip": client_ip,
                        "fingerprint": fp,
                        "flag_reason": reason,
                        "existing_accounts": existing
                    }),
                    module="registration",
                    flagged=1,
                    flag_reason=reason or "multi_account_registration"
                )
            except Exception as ex:
                _debug_print(f"[backend] HeatWave multi-account flag logging error: {ex}", file=sys.stderr)

        if not dev_ok:
            if dev_err == "BANNED":
                return ec.err(ec.BANNED, "BANNED", 403, banned=True,
                              reason="This device is associated with a banned account.")
            return ec.err(ec.DEVICE_BLOCKED, dev_err, 400)

    ok, res = db.create_user(
        username=username,
        password=password,
        display_name=display,
        slots=1,
        email=email,
        account_type="trial",
    )
    if not ok:
        # A second POST can arrive while the first is still in flight (the OTP
        # email takes a second or two), so the duplicate hits "Username already
        # exists" against the row the in-flight request just created. If that row
        # is this same unverified signup, resume it — re-issue the code and carry
        # on — instead of failing the visitor who only clicked once.
        existing = db.get_user_by_username(username)
        if existing and not _db_truthy(existing.get("email_verified", 0)) \
                and (existing.get("email") or "").strip().lower() == email:
            try:
                code = db.generate_otp(email)
                db.send_otp_email(email, code)
            except Exception as ex:
                db.delete_user(existing["uid"])
                reviews_db.log_app_error("RegisterOtpResendFailed", f"register OTP resend failed for {email}: {ex}", module="backend", flagged=1)
                _debug_print(f"[backend] register OTP resend failed: {ex}", file=sys.stderr)
                return ec.err(ec.OTP_SEND_FAILED, "Failed to send OTP. Please try again later.", 500)
            return jsonify({"ok": True, "user_id": existing["uid"], "email": email})
        if existing:
            return ec.err(ec.USERNAME_TAKEN, "Username already registered — use 'Log in' instead.", 400)
        # Reached only when the create failed and yet no such user exists, so the
        # database layer's own wording describes an internal fault and never
        # anything the visitor can act on. Logged, not echoed.
        reviews_db.log_app_error("RegistrationFailed", f"register failed with no surviving row: {res}", module="backend", flagged=1)
        _debug_print(f"[backend] register failed with no surviving row: {res}", file=sys.stderr)
        return ec.err(ec.REGISTRATION_FAILED,
                      "Registration failed. Please try again later.", 400)

    if fp and (dev_info.get("device_accounts") or dev_info.get("ip_accounts")):
        db.log_device_event(
            "repeat_registration", user_id=res, username=username, fingerprint_hash=fp,
            device_info=fp_detail, ip_address=client_ip, blocked=False,
            details={"attempted_email": email, "outcome": "allowed",
                     "reason": dev_info.get("reason"),
                     "existing_accounts": [u.get("username") for u in dev_info.get("device_accounts", [])],
                     "same_ip_accounts": [u.get("username") for u in dev_info.get("ip_accounts", [])]},
        )

    try:
        code = db.generate_otp(email)
        db.send_otp_email(email, code)
    except Exception as ex:
        db.delete_user(res)
        reviews_db.log_app_error("RegisterFollowupOtpFailed", f"register follow-up OTP failed for {email}: {ex}", module="backend", flagged=1)
        _debug_print(f"[backend] register follow-up OTP failed: {ex}", file=sys.stderr)
        return ec.err(ec.OTP_SEND_FAILED, "Failed to send OTP. Please try again later.", 500)

    return jsonify({"ok": True, "user_id": res, "email": email})


def _send_welcome_email_bg(email, name):
    try:
        db.send_welcome_email(email, name)
    except Exception as ex:
        reviews_db.log_app_error("WelcomeEmailFailed", f"welcome email failed for {email}: {ex}", module="backend", flagged=1)
        _debug_print(f"[backend] welcome email failed: {ex}", file=sys.stderr)


@app.route("/api/auth/complete-registration", methods=["POST"])
@api_internal_required
@limiter.limit("10 per minute; 30 per hour; 100 per day")
def api_complete_registration():
    data = _json_object()
    uid = _text_field(data, "user_id")
    email = _text_field(data, "email").lower()
    code = _text_field(data, "otp_code")
    fp, fp_anomaly = _clean_fingerprint(_text_field(data, "fingerprint"))
    fp_detail, fp_parsed, detail_anomaly = _clean_fp_detail(_text_field(data, "fingerprint_detail"))
    client_ip = _get_client_ip()

    if not uid or not email or not code:
        return ec.err(ec.MISSING_FIELDS, "Missing user_id, email or otp_code", 400)
    # Every one of these three is caller-supplied and is about to be bound into a
    # query or matched against a stored value. A value that cannot fit the column
    # it is compared with can only fail, so it is refused here rather than handed
    # to the driver — an oversized or wrong-typed id raised on the bind and became
    # a 500 for what is plainly a bad request.
    if len(uid) > USER_ID_MAX_LEN or len(email) > EMAIL_MAX_LEN or len(code) > OTP_CODE_MAX_LEN:
        return ec.err(ec.BAD_REQUEST, "Malformed user_id, email or otp_code", 400)
    # Validate first without consuming. The user_id is supplied by the client,
    # so an OTP for one address must not be burned merely because it was paired
    # with a different account id.
    if not db.verify_otp(email, code, mark_used=False):
        return ec.err(ec.OTP_INVALID, "Invalid or expired OTP", 400)

    # The OTP is bound to an email, and the user_id is caller-supplied — so the
    # two must agree. Verifying a user with someone else's OTP would let anyone
    # who can receive one code flip email_verified (and bind a fingerprint) on
    # any user_id they can guess.
    user = db.get_user(uid)
    if not user:
        return ec.err(ec.USER_NOT_FOUND, "User not found", 404)
    if (user.get("email") or "").strip().lower() != email:
        return ec.err(ec.EMAIL_MISMATCH, "Email does not match this account", 400)
    # Re-check while atomically transitioning used=0 -> used=1. A concurrent
    # completion can win between the non-consuming validation and this point.
    if not db.verify_otp(email, code):
        return ec.err(ec.OTP_INVALID, "Invalid or expired OTP", 400)

    # Same observational flag as at signup, now that the account this payload
    # belongs to is known. It does not gate the binding below.
    _log_tamper_signals(_tamper_signals(fp_parsed, fp_anomaly, detail_anomaly),
                        fp_parsed, fp, user_id=uid, username=user.get("username"),
                        ip_address=client_ip)

    db.verify_user_email(uid)
    if fp:
        for alt in db.accounts_on_device(fp):
            if str(alt.get("uid")) == str(uid):
                continue
            alt_banned, _ = db.is_user_banned(alt["uid"])
            if alt_banned:
                db.log_device_event("banned_alt_registration", user_id=uid,
                                    username=(db.get_user(uid) or {}).get("username"),
                                    fingerprint_hash=fp, device_info=fp_detail, ip_address=client_ip,
                                    blocked=True, details={"banned_account": alt["username"]})
                db.delete_user(uid)
                return ec.err(ec.BANNED, "BANNED", 403, banned=True,
                              reason="This device is associated with a banned account.")
        db.bind_fingerprint(uid, fp, fp_detail, ip_address=client_ip)

    # Off the request path deliberately. By this line the OTP is consumed and
    # email_verified is committed, so the account is already active — but the
    # caller is still blocked on this response, and a provider that throttles a
    # second SMTP session seconds after the OTP one stalls per socket operation,
    # not in total. Sent inline, that pushes the response past the caller's read
    # timeout, and the only thing the caller can report is a failed
    # verification for a code that is now burned and can never work on retry.
    threading.Thread(
        target=_send_welcome_email_bg,
        args=(email, user.get("username") or user.get("display_name") or "there"),
        name="welcome-email", daemon=True,
    ).start()

    user.pop("password", None)
    return jsonify({"ok": True, "user": user})


@app.route("/api/auth/discard-registration", methods=["POST"])
@api_internal_required
def api_discard_registration():
    """Drop a signup that was abandoned before the OTP step. Only ever removes
    an account that never verified its email, so a replayed or guessed id can
    never destroy a real user."""
    data = _json_object()
    uid = _text_field(data, "user_id")
    if not uid or len(uid) > USER_ID_MAX_LEN:
        return jsonify({"ok": True, "deleted": False})
    user = db.get_user(uid)
    if not user or _db_truthy(user.get("email_verified", 0)):
        return jsonify({"ok": True, "deleted": False})
    db.delete_user(uid)
    return jsonify({"ok": True, "deleted": True})


@app.route("/api/auth/login", methods=["POST"])
@api_internal_required
@limiter.limit("10 per minute")
@limiter.limit("10 per minute; 40 per hour", key_func=lambda: _body_value("username"))
def api_auth_login():
    data = _json_object()
    username = _text_field(data, "username")
    password = _raw_field(data, "password")
    fp, fp_anomaly = _clean_fingerprint(_text_field(data, "fingerprint"))
    fp_detail, fp_parsed, detail_anomaly = _clean_fp_detail(_text_field(data, "fingerprint_detail"))
    client_ip = _get_client_ip()

    if len(username) > EMAIL_MAX_LEN or len(password) > PASSWORD_MAX_LEN:
        # verify_user() accepts a username *or* an email here, so the wider of the
        # two bounds is the one that applies. Past it nothing can match a stored
        # value, so this is the answer verify_user would give — reached without
        # paying for an Argon2id verify.
        return ec.err(ec.INVALID_CREDENTIALS, "Invalid username or password", 401)
    user = db.verify_user(username, password)
    if not user:
        return ec.err(ec.INVALID_CREDENTIALS, "Invalid username or password", 401)

    banned, ban_reason = db.is_user_banned(user["uid"])
    if banned:
        return ec.err(ec.BANNED, "BANNED", 403, banned=True, reason=ban_reason)

    # is_active is the admin's "account disabled" switch. It lives in the DB but
    # nothing on this stack ever read it — a deactivated account could still log
    # in and keep using the API. Mirrors what api_user_required enforces on every
    # authenticated call.
    if not _db_truthy(user.get("is_active", 1)):
        return ec.err(ec.ACCOUNT_DISABLED, "Account disabled", 401)

    # An account that never verified its email is worthless to the user and
    # dead weight to the site — purge its session-side data on contact, but
    # keep the account record itself.
    # Verification only ever flips one way from the OTP flow; an admin flipping
    # it back off knowingly marks the account for this purge.
    if not _db_truthy(user.get("email_verified", 0)):
        db.delete_user(user["uid"])
        return ec.err(ec.EMAIL_UNVERIFIED, "Account needs verification — data was purged", 401)

    # Recorded before the device policy runs and deliberately ignored by it: a
    # headless verdict or a worker mismatch is the client contradicting its own
    # report, which is a reason to look, not a reason to refuse a login.
    _log_tamper_signals(_tamper_signals(fp_parsed, fp_anomaly, detail_anomaly),
                        fp_parsed, fp, user_id=user["uid"], username=user.get("username"),
                        ip_address=client_ip)

    # Device policy: bind on first login, and capture + flag any login that
    # arrives from a device other than the bound one.
    # Auto-ban is disabled by default — admin must enable it in settings.
    # A device_events row is written only when the login is interesting: a banned
    # alt, a first bind onto a device another account uses, or a device or IP that
    # belongs to a different account. A routine login from the account's own bound
    # device records no event, and its only per-login IP trace is
    # sessions.ip_address, which the session TTL purges.
    dev_ok, dev_err = db.check_device_login(user["uid"], fp, fp_detail, client_ip)
    if not dev_ok:
        if dev_err == "BANNED" and db.get_auto_ban_enabled():
            return ec.err(ec.BANNED, "BANNED", 403, banned=True,
                          reason="This device is associated with a banned account.")
        if dev_err == "BANNED":
            dev_err = "Login recorded for admin review"

    user.pop("password", None)
    return jsonify({"ok": True, "user": user})


# ── Fingerprint API (public) ──

@app.route("/api/fingerprint/check-owner", methods=["POST"])
@limiter.limit("10 per minute")
def api_fingerprint_owner():
    data = _json_object()
    raw_fp = _text_field(data, "fingerprint")
    if not raw_fp:
        return ec.err(ec.MISSING_FIELDS, "Missing fingerprint", 400)
    fp, _fp_anomaly = _clean_fingerprint(raw_fp)
    if not fp:
        # Nothing to degrade to here: this endpoint exists only to look a
        # fingerprint up, so a value that is not one cannot be answered.
        return ec.err(ec.FINGERPRINT_INVALID, "Invalid fingerprint", 400)
    owner = db.fingerprint_owner(fp)
    return jsonify({"ok": True, "owner": owner})


# ── User API (authenticated via X-Session-Id) ──

@app.route("/api/user/me", methods=["GET"])
@api_user_required
def api_get_me():
    user = db.get_user(g.current_user_id)
    if not user:
        return ec.err(ec.USER_NOT_FOUND, "User not found", 404)
    user.pop("password", None)
    return jsonify({"ok": True, "user": user})


@app.route("/api/user/devtools-flag", methods=["POST"])
@api_user_required
@limiter.limit("2 per hour")
def api_user_devtools_flag():
    """Record a passive admin-review flag; never enforce against the user."""
    body = request.get_json(silent=True) or {}
    try:
        seconds = int(body.get("open_seconds") or 120)
    except (TypeError, ValueError):
        seconds = 120
    seconds = max(120, min(86400, seconds))
    fp, _ = _clean_fingerprint(request.headers.get("X-Device-Fingerprint") or "")
    db.log_device_event(
        DEVICE_EVENT_DEVTOOLS,
        user_id=g.current_user_id,
        fingerprint_hash=fp or None,
        ip_address=_get_client_ip(),
        blocked=False,
        details={"open_seconds": seconds, "source": "devtools-detector-compatible", "outcome": "flag_only"},
    )
    return jsonify({"ok": True})


@app.route("/api/user/ads-enabled", methods=["GET"])
@api_user_required
def api_user_ads_enabled():
    disabled = db.get_user_ads_disabled(g.current_user_id)
    return jsonify({"ok": True, "ads_enabled": not disabled})


@app.route("/api/user/ad-zones", methods=["GET"])
@api_user_required
def api_user_ad_zones():
    # Everything the frontend needs to render this user's ads in one call:
    # ads_enabled is the global master switch on its own, so the site can tell
    # "ads are off entirely" from "every zone happens to be off". networks is
    # the per-network head-loader answer. guard_mode, consent_required and
    # pages ride along because the client must settle all
    # of them before the first zone paints; fetching them separately would let
    # an ad render under a rule that forbids it.
    return jsonify({"ok": True,
                    "ads_enabled": db.get_ad_enabled(),
                    "ads_disabled": db.get_user_ads_disabled(g.current_user_id),
                    "networks": db.get_resolved_ad_networks(g.current_user_id),
                    "zones": db.get_resolved_ad_zones(g.current_user_id),
                    "guard_mode": db.get_ad_guard_mode(),
                    "consent_required": db.get_ad_consent_required(),
                    "pages": db.get_resolved_ad_pages(g.current_user_id)})


@app.route("/api/user/<user_id>", methods=["GET"])
@api_user_required
def api_get_user(user_id):
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    user = db.get_user(user_id)
    if not user:
        return ec.err(ec.USER_NOT_FOUND, "User not found", 404)
    user.pop("password", None)
    return jsonify({"ok": True, "user": user})


@app.route("/api/user/<user_id>", methods=["DELETE"])
@api_user_required
def api_delete_user(user_id):
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    db.delete_user(user_id)
    return jsonify({"ok": True})


@app.route("/api/user/<user_id>/fingerprint", methods=["GET"])
@api_user_required
def api_user_get_fingerprint(user_id):
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    fp = db.fingerprint_status(user_id)
    return jsonify({"ok": True, "fingerprint": fp})


@app.route("/api/user/<user_id>/bots", methods=["GET"])
@api_user_required
def api_user_bots(user_id):
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    bots = db.get_user_bots(user_id)
    for b in bots:
        b.pop("token", None)
        b.pop("token_enc", None)
        b.pop("webhook_url", None)
        b.pop("embed_json", None)
    return jsonify({"ok": True, "bots": bots})


@app.route("/api/user/<user_id>/password", methods=["PUT"])
@api_user_required
@limiter.limit("10 per hour; 30 per day")
@limiter.limit("5 per hour; 15 per day", key_func=lambda: str(g.get("current_user_id") or ""))
def api_change_password(user_id):
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    data = _json_object()
    old = _raw_field(data, "old_password")
    new = _raw_field(data, "new_password")
    if not old or not new:
        return ec.err(ec.MISSING_FIELDS, "Both passwords required", 400)
    if len(new) < 8:
        return ec.err(ec.PASSWORD_TOO_SHORT, "New password must be at least 8 characters", 400)
    if len(new) > PASSWORD_MAX_LEN or len(old) > PASSWORD_MAX_LEN:
        return ec.err(ec.PASSWORD_TOO_LONG,
                      f"Password must be at most {PASSWORD_MAX_LEN} characters", 400)
    current_sid = request.headers.get("X-Session-Id", "")
    ok, msg = db.change_user_password(user_id, old, new, current_sid=current_sid)
    if not ok:
        return ec.err(ec.BAD_REQUEST, msg, 400)
    return jsonify({"ok": True, "message": msg})


@app.route("/api/user/<user_id>/active", methods=["POST"])
@api_user_required
def api_mark_active(user_id):
    """Record the account's last activity timestamp."""
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    db.mark_user_active(user_id)
    return jsonify({"ok": True})


@app.route("/api/user/<user_id>/renew", methods=["POST"])
@api_user_required
@limiter.limit("1 per day", key_func=lambda: str(g.get("current_user_id") or ""))
def api_renew(user_id):
    """Trial 'Renew': extend the trial deadline by another cycle."""
    if not _owns(user_id):
        return ec.err(ec.NOT_AUTHORIZED, "Not authorized", 403)
    res = db.renew_user(user_id)
    if res == "renewed":
        return jsonify({"ok": True, "status": "renewed"})
    elif res == "too_early":
        return ec.err(ec.RATE_LIMITED, "It is not time to renew yet — you can renew closer to your turn-off date.", 400)
    elif res == "not_trial":
        return ec.err(ec.NOT_AUTHORIZED, "Paid accounts do not need renewal.", 400)
    return ec.err(ec.USER_NOT_FOUND, "User not found", 404)


# ── Bot API ──

@app.route("/api/bot/<int:bot_id>", methods=["GET"])
@api_user_required
def api_get_bot(bot_id):
    bot = _own_bot(bot_id)
    if not bot:
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    bot.pop("token", None)
    bot.pop("token_enc", None)
    bot.pop("webhook_url", None)
    return jsonify({"ok": True, "bot": bot})


# ── Public global reads: process-local TTL cache ──
# The three routes below are the only unauthenticated GETs here that reach a
# database, and every one of them answers with data that is byte-identical for
# every visitor on the internet: the site-wide ad configuration and the approved
# reviews. They also fan out — ad-zones alone is six separate reads — so one
# anonymous HTTP request bought six Oracle round trips out of a pool that is
# ~20 sessions for the *whole fleet*. That made them the cheapest available lever
# for starving every logged-in user of a connection, with no account needed and
# no cost to the caller. Answering from memory turns a flood into one recompute
# per TTL instead of six reads per request, which is the half of the fix a rate
# limit cannot do: the limit bounds a single address, the cache bounds all of
# them at once, including a distributed flood where no one address stands out.
#
# Deliberate trade: an ad setting changed in the admin console now takes up to
# PUBLIC_CACHE_TTL_SECONDS to become visible to visitors, and each instance
# expires its own copy on its own clock, so the two can briefly disagree. Ad
# toggles are rare and not urgent; a bounded staleness is the price of not
# leaving the connection pool open to anonymous traffic. Set the TTL to 0 to
# disable the cache and read through on every request.
PUBLIC_CACHE_TTL_SECONDS = max(0, int(os.environ.get("PUBLIC_CACHE_TTL_SECONDS", 45)))

# Every key is a literal written at the call sites below — never a path, query,
# header or any other caller-supplied value — so this holds exactly one entry per
# route and cannot be grown by whoever is calling. That is what makes it safe
# with no eviction policy: there is nothing to evict.
_public_cache = {}
_public_cache_lock = threading.Lock()


def _cached_public(key, build):
    """`build()`'s value for one fleet-global key, reused for the TTL.

    waitress serves this app on several threads, so the store is guarded by a
    lock — but `build()` runs *outside* it, because it is the database call.
    Holding a lock across an Oracle round trip would queue every thread behind
    one slow read, including threads wanting a different key, replacing the stall
    this cache exists to prevent with a fresh one. The cost is that threads
    racing on the same cold key may each build once; that is a few extra reads on
    a miss rather than a stampede, since the next caller finds the stored value.

    A failure is never cached: an exception from `build()` propagates with
    nothing written, so a database blip is retried by the very next request
    instead of being pinned as the answer for the whole TTL.
    """
    if PUBLIC_CACHE_TTL_SECONDS <= 0:
        return build()
    # monotonic(), not time(), so an NTP step cannot pin an entry for hours or
    # expire the whole table at once.
    now = time.monotonic()
    with _public_cache_lock:
        entry = _public_cache.get(key)
        if entry is not None and entry[0] > now:
            return entry[1]
    value = build()
    with _public_cache_lock:
        _public_cache[key] = (time.monotonic() + PUBLIC_CACHE_TTL_SECONDS, value)
    return value


# ── Settings API ──

# The explicit limit matters even with the cache in front: it is what stops one
# address spending a worker thread per request on a route that needs no login.
# 60/min is ~60 page views a minute from one visitor — far above real browsing,
# far below a flood — and it replaces the shared 500/min default, which was loose
# enough that a single client could keep all three of these routes saturated.
@app.route("/api/settings/ad-enabled", methods=["GET"])
@limiter.limit("60 per minute")
def api_ad_enabled():
    return jsonify(_cached_public(
        "ad-enabled", lambda: {"ok": True, "ads_enabled": db.get_ad_enabled()}))


@app.route("/api/settings/ad-zones", methods=["GET"])
@limiter.limit("60 per minute")
def api_ad_zones():
    # The anonymous view: master switch, the per-network head-loader answers,
    # and the global per-zone toggles. Logged-in callers want
    # /api/user/ad-zones instead, which also applies that user's overrides.
    # guard_mode, consent_required and pages are site-wide admin settings, sent
    # with the zones so one call decides everything before the first ad paints.
    return jsonify(_cached_public("ad-zones", lambda: {
        "ok": True,
        "ads_enabled": db.get_ad_enabled(),
        "networks": db.get_resolved_ad_networks(),
        "zones": db.get_resolved_ad_zones(),
        "guard_mode": db.get_ad_guard_mode(),
        "consent_required": db.get_ad_consent_required(),
        "pages": db.get_resolved_ad_pages()}))


# ── Reviews API ──

@app.route("/api/reviews", methods=["GET"])
@limiter.limit("60 per minute")
def api_list_reviews():
    # Public read: approved reviews plus the star summary. Never exposes user_id
    # (get_approved_reviews selects only the public columns).
    # Reviews live on HeatWave, not the ATP, so this route serves the home page
    # without touching Oracle at all. If HeatWave is down or unconfigured these
    # return [] and {count: 0}, and the home page just omits the section.
    #
    # Those degraded empties are indistinguishable from a site that has no
    # approved reviews yet, so they are cached like any other answer and the
    # section can stay hidden for up to one TTL after HeatWave recovers. Only a
    # raised exception is guaranteed never to be cached.
    return jsonify(_cached_public("reviews", lambda: {
        "ok": True,
        "reviews": reviews_db.get_approved_reviews(),
        "summary": reviews_db.get_reviews_summary()}))


@app.route("/api/reviews", methods=["POST"])
@api_user_required
@limiter.limit("5 per hour; 20 per day",
               key_func=lambda: str(g.get("current_user_id") or ""))
def api_create_review():
    # Author name is the account's display name — the client never sends a name.
    # Truncated to the column width (VARCHAR(100)) so the insert cannot overflow.
    #
    # This is the one route that reads both stores: the account lookup is ATP
    # (that is where users live), the insert is HeatWave. The name is copied into
    # the review row rather than joined at read time — the two databases cannot
    # be joined in SQL, and a published review should keep the name it was posted
    # under anyway.
    user = db.get_user(g.current_user_id)
    if not user:
        return ec.err(ec.USER_NOT_FOUND, "User not found", 404)
    author_name = (user.get("display_name") or user.get("username") or "User").strip()[:100]
    data = _json_object()
    try:
        rating = int(data.get("rating"))
    except (TypeError, ValueError):
        return ec.err(ec.REVIEW_RATING_INVALID, "Rating required", 400)
    if rating < 1 or rating > 5:
        return ec.err(ec.REVIEW_RATING_INVALID, "Rating must be between 1 and 5", 400)
    body = _text_field(data, "body")
    if not body:
        return ec.err(ec.REVIEW_TEXT_REQUIRED, "Review text required", 400)
    if len(body) > 4000:
        return ec.err(ec.REVIEW_TOO_LONG, "Review is too long (max 4000 characters)", 400)
    embed_json = data.get("embed") or data.get("embed_json")
    ok = reviews_db.create_review(uid=g.current_user_id, author_name=author_name,
                                  rating=rating, body=body, embed_json=embed_json)
    if not ok:
        # create_review only ever returns False, so without this the reason
        # (HeatWave down vs. a rejected row) never reaches the console.
        reviews_db.log_app_error("ReviewSaveFailed",
                                 f"create_review returned False for user {g.current_user_id}",
                                 module="backend", flagged=1)
        return ec.err(ec.REVIEW_SAVE_FAILED, "Could not save review", 500)
    return jsonify({"ok": True, "approved": True})


# ── Validate Email ──

@app.route("/api/auth/validate-email", methods=["POST"])
@api_internal_required
@limiter.limit("10 per minute; 30 per hour; 100 per day")
def api_validate_email():
    data = _json_object()
    email = _text_field(data, "email").lower()
    return jsonify({"ok": True, "valid": bool(db.EMAIL_RE.match(email))})


@app.route("/api/user/bots", methods=["GET"])
@api_user_required
def api_user_list_bots():
    # Reconcile bot rows against the declared slot count on every load so the
    # slots page never shows the empty-state note when the account has slots
    # but the bot rows were never provisioned (e.g. legacy accounts or a panel
    # slot bump that skipped the normal update_user_slots path).
    user = db.get_user(g.current_user_id)
    if user:
        try:
            db.ensure_bot_slots(g.current_user_id, int(user.get("slots") or 0))
        except Exception:
            pass  # A reconciliation failure must never block the page
    bots = db.get_user_bots(g.current_user_id)
    for b in bots:
        b.pop("token", None)
        b.pop("token_enc", None)
        b.pop("webhook_url", None)
        b.pop("embed_json", None)
        b.pop("ip_reply_json", None)
    return jsonify({"ok": True, "bots": bots})


@app.route("/api/user/bot/<int:bot_id>/config", methods=["GET"])
@api_user_required
def api_get_bot_config(bot_id):
    try:
        bot = _own_bot(bot_id)
        if not bot:
            return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
        # The webhook URL is a bearer credential, same as the token: the UI
        # only ever sees the masked preview.
        bot.pop("token", None)
        bot.pop("token_enc", None)
        bot.pop("webhook_url", None)
        # Which credential the engine posts through. HeatWave being down reads as
        # (0, 0), which the page renders as "no explicit choice".
        bot["delivery"] = reviews_db.get_bot_delivery(bot_id)
        return jsonify({"ok": True, "bot": bot})
    except db.OraclePoolExhausted:
        raise
    except Exception as e:
        reviews_db.log_app_error("GetBotConfigFailed", f"get_bot_config failed for bot {bot_id}: {e}", module="backend", flagged=1)
        _debug_print(f"[backend] get_bot_config failed for bot {bot_id}: {e}", file=sys.stderr)
        return ec.err(ec.INTERNAL_ERROR, "Could not load bot configuration", 500)


@app.route("/api/user/bot/<int:bot_id>/config", methods=["POST"])
@api_user_required
@limiter.limit("30 per minute; 600 per hour",
               key_func=lambda: str(g.get("current_user_id") or ""))
def api_save_bot_config(bot_id):
    try:
        if not _own_bot(bot_id):
            return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
        data = request.get_json(force=True)
        if not isinstance(data, dict):
            return ec.err(ec.INVALID_JSON, "Invalid JSON body", 400)
        embed = data.get("embed")
        if embed is not None:
            embed = _clean_embed(embed)
        ip_reply = data.get("ip_reply")
        if ip_reply is not None:
            ip_reply = _clean_ip_reply(ip_reply)
        db.save_bot_config(
            bot_id,
            user_id=g.current_user_id,
            name=data.get("name"),
            server_ip=data.get("server_ip"),
            server_port=data.get("server_port"),
            edition=data.get("edition"),
            token=data.get("token"),
            guild_id=data.get("guild_id"),
            channel_id=data.get("channel_id"),
            webhook_url=data.get("webhook_url"),
            update_interval=data.get("update_interval"),
            embed=embed,
            ip_reply=ip_reply,
        )
        return jsonify({"ok": True})
    except ValueError as e:
        return ec.err(ec.BAD_REQUEST, str(e), 400)
    except HTTPException:
        # abort()/get_json(force=True) signal a client mistake by raising, and
        # HTTPException is an Exception — so the handler below caught the 400 for
        # a malformed body and answered 500 "Save failed" instead. Re-raise and
        # let the registered error handlers render it.
        raise
    except Exception as e:
        reviews_db.log_app_error("SaveBotConfigFailed", f"save_bot_config failed for bot {bot_id}: {e}", module="backend", flagged=1)
        _debug_print(f"[backend] save_bot_config failed for bot {bot_id}: {e}", file=sys.stderr)
        return ec.err(ec.BOT_SAVE_FAILED, "Save failed. Please try again.", 500)


@app.route("/api/user/bot/<int:bot_id>/delivery", methods=["POST"])
@api_user_required
@limiter.limit("30 per minute; 300 per hour",
               key_func=lambda: str(g.get("current_user_id") or ""))
def api_set_bot_delivery(bot_id):
    """Which stored credential the engine posts through: the bot token or the
    webhook URL. Exactly one may be on — "both" and "neither" are the same
    instruction to the engine (keep the historical webhook-wins precedence), so
    the pair is rejected here rather than silently resolved.
    """
    try:
        bot = _own_bot(bot_id)
        if not bot:
            return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
        data = _json_object()
        mode = str(data.get("mode") or "").strip().lower()
        if mode not in ("token", "webhook"):
            return ec.err(ec.BAD_REQUEST, 'mode must be "token" or "webhook"', 400)
        if mode == "webhook" and not bot.get("webhook_url_masked"):
            return ec.err(ec.BAD_REQUEST,
                          "Save a webhook URL before switching to webhook mode.", 400)
        if mode == "token" and not bot.get("token_masked"):
            return ec.err(ec.BAD_REQUEST,
                          "Save a bot token before switching to bot-token mode.", 400)
        saved = reviews_db.set_bot_delivery(
            bot_id, use_token=(mode == "token"), use_webhook=(mode == "webhook"))
        if not saved:
            # HeatWave unconfigured or unreachable. Nothing is lost — the engine
            # falls back to webhook-wins — but the owner must not be told their
            # choice was stored when it was not.
            return ec.err(ec.INTERNAL_ERROR,
                          "Could not save the delivery choice. Try again shortly.", 503)
        return jsonify({"ok": True, "mode": mode})
    except db.OraclePoolExhausted:
        raise
    except HTTPException:
        raise
    except Exception as e:
        reviews_db.log_app_error("SetBotDeliveryFailed", f"set_bot_delivery failed for bot {bot_id}: {e}", module="backend", flagged=1)
        _debug_print(f"[backend] set_bot_delivery failed for bot {bot_id}: {e}", file=sys.stderr)
        return ec.err(ec.INTERNAL_ERROR, "Could not save the delivery choice", 500)


@app.route("/api/user/preview", methods=["POST"])
@api_user_required
@limiter.limit("20 per minute")
def api_preview():
    data = _json_object()
    embed = data.get("embed")
    try:
        if embed is not None:
            embed = _clean_embed(embed)
    except ValueError as e:
        return ec.err(ec.BAD_REQUEST, str(e), 400)
    payload, code = engine_client.preview(
        embed,
        data.get("server_ip"),
        data.get("server_port"),
        data.get("edition"),
    )
    return jsonify(payload), code


@app.route("/api/user/bot/<int:bot_id>/start", methods=["POST"])
@api_user_required
def api_user_start_bot(bot_id):
    if not _own_bot(bot_id):
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    if db.is_trial_expired(g.current_user_id):
        return ec.err(ec.TRIAL_EXPIRED, "Trial expired — cannot start bot. Contact support.", 403)
    payload, code = engine_client.start_bot(bot_id)
    return jsonify(payload), code


@app.route("/api/user/bot/<int:bot_id>/stop", methods=["POST"])
@api_user_required
def api_user_stop_bot(bot_id):
    if not _own_bot(bot_id):
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    payload, code = engine_client.stop_bot(bot_id)
    return jsonify(payload), code


@app.route("/api/user/bot/<int:bot_id>/generate", methods=["POST"])
@api_user_required
@limiter.limit("10 per minute")
def api_user_generate(bot_id):
    if not _own_bot(bot_id):
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    payload, code = engine_client.generate(bot_id)
    return jsonify(payload), code


@app.route("/api/user/bot/<int:bot_id>/status", methods=["GET"])
@api_user_required
@limiter.limit("60 per minute")
def api_user_bot_status(bot_id):
    try:
        bot = _own_bot(bot_id)
        if not bot:
            return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
        return jsonify({
            "running": bool(bot.get("running")),
            "last_run": bot.get("last_run"),
            "last_error": bot.get("last_error"),
            "last_status": _safe_json(bot.get("last_status")),
        })
    except db.OraclePoolExhausted:
        raise
    except Exception as e:
        reviews_db.log_app_error("BotStatusFailed", f"bot status failed for bot {bot_id}: {e}", module="backend", flagged=1)
        _debug_print(f"[backend] bot status failed for bot {bot_id}: {e}", file=sys.stderr)
        return ec.err(ec.INTERNAL_ERROR, "Could not load bot status", 500)


@app.route("/api/user/bot/<int:bot_id>/discord/assets", methods=["GET"])
@api_user_required
@limiter.limit("10 per minute")
def api_user_discord_assets(bot_id):
    if not _own_bot(bot_id):
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    payload, code = engine_client.assets(bot_id)
    return jsonify(payload), code


class _NodeCapacityValueError(ValueError):
    code = "node_capacity_exhausted"


def _panel_store_errors(f):
    @wraps(f)
    def wrap(*a, **k):
        try:
            return f(*a, **k)
        except panel_data.MirrorConflict:
            return jsonify({"ok": False, "error": "mirror_conflict"}), 409
        except ValueError as exc:
            body = {"ok": False, "error": "value_error", "message": str(exc)}
            if isinstance(exc, _NodeCapacityValueError):
                body["code"] = exc.code
            return jsonify(body), 400
    return wrap


PASSWORD_HASH_MAX_LEN = 255


def _password_hash_field(data, field):
    value = _raw_field(data, field)
    if not value.strip():
        raise ValueError(f"{field} is required")
    if any("\ud800" <= ch <= "\udfff" for ch in value):
        raise ValueError(f"{field} must not contain unpaired surrogates")
    encoded = value.encode("utf-8", "surrogatepass")
    if max(len(value), len(encoded)) > PASSWORD_HASH_MAX_LEN:
        raise ValueError(f"{field} must be at most {PASSWORD_HASH_MAX_LEN} characters")
    return value


def _panel_text_field(data, field):
    value = data.get(field)
    if value is None or isinstance(value, (list, dict)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, str):
        value = str(value)
    if any("\ud800" <= ch <= "\udfff" for ch in value):
        raise ValueError(f"{field} must not contain unpaired surrogates")
    return value.strip()


@app.route("/api/panel-store/schema/ensure", methods=["POST"])
@api_internal_required
@limiter.limit("30 per minute; 200 per hour")
@_panel_store_errors
def api_panel_store_schema_ensure():
    panel_data.ensure_panel_schema()
    return jsonify({"ok": True})


@app.route("/api/panel-store/user/ensure", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_user_ensure():
    data = _json_object()
    user = panel_data.ensure_user_by_id(
        _panel_text_field(data, "user_id"),
        _panel_text_field(data, "username"),
    )
    return jsonify({"ok": True, "user": user})


@app.route("/api/panel-store/user/get", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_user_get():
    data = _json_object()
    user = panel_data.get_user(_panel_text_field(data, "user_id"))
    return jsonify({"ok": True, "user": user})


@app.route("/api/panel-store/user/by-username", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_user_by_username():
    data = _json_object()
    user = panel_data.get_user_by_username(_panel_text_field(data, "username"))
    return jsonify({"ok": True, "user": user})


@app.route("/api/panel-store/user/create", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_user_create():
    data = _json_object()
    user_id = panel_data.create_user(
        _panel_text_field(data, "username"),
        _password_hash_field(data, "password_hash"),
    )
    return jsonify({"ok": True, "user_id": user_id})


@app.route("/api/panel-store/user/password", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_user_password():
    data = _json_object()
    changed = panel_data.update_user_password(
        _panel_text_field(data, "user_id"),
        _password_hash_field(data, "password_hash"),
    )
    return jsonify({"ok": True, "changed": bool(changed)})


def _placement_capacity_available():
    try:
        return node_registry.placement_capacity_available()
    except Exception as exc:
        reviews_db.log_app_error("NodeCapacityProbeError", f"panel store: node capacity probe unavailable: {exc}", module="backend", flagged=1)
        _debug_print(f"[backend] panel store: node capacity probe unavailable "
                     f"({type(exc).__name__}: {exc})", file=sys.stderr)
        return True


@app.route("/api/panel-store/placement/probe", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_placement_probe():
    return jsonify({"ok": True, "can_place": _placement_capacity_available()})


@app.route("/api/panel-store/node/credentials", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_node_credentials():
    data = _json_object()
    node = node_registry.get_node_credentials(_panel_text_field(data, "node_id"))
    return jsonify({"ok": True, "node": node})


def _placement_node_id(conn=None):
    try:
        return node_registry.pick_node_for_new_server(conn)
    except node_registry.NodeCapacityError as exc:
        raise _NodeCapacityValueError(str(exc)) from exc
    except Exception as exc:
        reviews_db.log_app_error("NodePlacementError", f"panel store: node placement unavailable: {exc}", module="backend", flagged=1)
        _debug_print(f"[backend] panel store: node placement unavailable "
                     f"({type(exc).__name__}: {exc})", file=sys.stderr)
        return None


@app.route("/api/panel-store/server/create", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_create():
    data = _json_object()
    node_id = panel_data.create_server(
        server_id=_panel_text_field(data, "server_id"),
        user_id=_panel_text_field(data, "user_id"),
        name=_panel_text_field(data, "name"),
        runtime=_panel_text_field(data, "runtime"),
        version=_panel_text_field(data, "version"),
        image=_panel_text_field(data, "image") or None,
        startup=_panel_text_field(data, "startup"),
        pick_node=_placement_node_id,
    )
    return jsonify({"ok": True, "node_id": node_id})


@app.route("/api/panel-store/server/list", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_list():
    data = _json_object()
    servers = panel_data.list_servers_for_user(_panel_text_field(data, "user_id"))
    return jsonify({"ok": True, "servers": servers})


@app.route("/api/panel-store/server/get", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_get():
    data = _json_object()
    server = panel_data.get_server_for_user(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
    )
    return jsonify({"ok": True, "server": server})


@app.route("/api/panel-store/server/delete", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_delete():
    data = _json_object()
    changed = panel_data.delete_server_for_user(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
    )
    return jsonify({"ok": True, "changed": bool(changed)})


@app.route("/api/panel-store/server/startup", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_startup():
    data = _json_object()
    changed = panel_data.update_server_startup(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
        _panel_text_field(data, "startup"),
    )
    return jsonify({"ok": True, "changed": bool(changed)})


@app.route("/api/panel-store/server/name", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_name():
    data = _json_object()
    changed = panel_data.update_server_name(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
        _panel_text_field(data, "name"),
    )
    return jsonify({"ok": True, "changed": bool(changed)})


@app.route("/api/panel-store/server/version", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_version():
    data = _json_object()
    changed = panel_data.update_server_version(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
        _panel_text_field(data, "runtime"),
        _panel_text_field(data, "version"),
        _panel_text_field(data, "image") or None,
    )
    return jsonify({"ok": True, "changed": bool(changed)})


@app.route("/api/panel-store/server/state", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_server_state():
    data = _json_object()
    changed = panel_data.update_server_state(
        _panel_text_field(data, "server_id"),
        _panel_text_field(data, "user_id"),
        _db_truthy(data.get("running")),
    )
    return jsonify({"ok": True, "changed": bool(changed)})


@app.route("/api/panel-store/activity/log", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_activity_log():
    data = _json_object()
    panel_data.log_activity(
        _panel_text_field(data, "user_id"),
        _panel_text_field(data, "action"),
        _panel_text_field(data, "server_id") or None,
        _panel_text_field(data, "detail") or None,
    )
    return jsonify({"ok": True})


@app.route("/api/panel-store/activity/list", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_activity_list():
    data = _json_object()
    try:
        limit = int(data.get("limit") or 200)
    except (TypeError, ValueError):
        limit = 200
    activity = panel_data.list_activity(_panel_text_field(data, "user_id"), limit)
    return jsonify({"ok": True, "activity": activity})


def _panel_store_settings():
    uconn = db._user_conn()
    try:
        snapshot = dict(db.get_panel_settings(uconn))
        try:
            snapshot["guard_mode"] = db.get_ad_guard_mode(uconn)
        except Exception as exc:
            _debug_print(f"[backend] panel store: ad guard mode unreadable "
                         f"({type(exc).__name__}: {exc})", file=sys.stderr)
            snapshot["guard_mode"] = None
        try:
            snapshot["ads_enabled"] = bool(db.get_ad_enabled(uconn))
        except Exception as exc:
            _debug_print(f"[backend] panel store: ads master switch unreadable "
                         f"({type(exc).__name__}: {exc})", file=sys.stderr)
            snapshot["ads_enabled"] = None
    finally:
        uconn.close()
    return {"ok": True, "settings": snapshot}


@app.route("/api/panel-store/settings/read", methods=["POST"])
@api_internal_required
@limiter.limit("20000 per minute")
@_panel_store_errors
def api_panel_store_settings_read():
    return jsonify(_cached_public("panel-settings", _panel_store_settings))


def _bind_host():
    """The validated BACKEND_BIND value, or exit 2.

    A wildcard bind is refused rather than warned about. Every route here is
    guarded by either a user session or the shared internal token, and that
    token travels in cleartext over HTTP — on a wildcard bind anyone who can
    reach the port and read one internal call can impersonate the frontend. The
    intended value is one specific private interface address (instance A's, so
    instance B's frontend can reach it); loopback is the default.
    """
    host = BACKEND_BIND
    if host in ("", "0.0.0.0", "::", "[::]", "*"):
        _debug_print(
            f"[backend] refusing to start: BACKEND_BIND={host!r} would expose the data API "
            "beyond this host. It trusts a cleartext shared token for internal calls. Set "
            "BACKEND_BIND to a specific private interface address, or leave it unset for "
            "127.0.0.1.",
            file=sys.stderr,
        )
        sys.exit(2)
    return host


def init():
    """One-time startup: resolve the shared internal token and ensure the
    schema exists. Idempotent, so it is safe under gunicorn where the module
    import runs once per worker. Called by serve() (waitress) and
    wsgi_backend.py (gunicorn) alike."""
    internal_auth.get_internal_token()
    db.init_db()


def serve():
    from waitress import serve as wserve
    host = _bind_host()
    init()
    _debug_print(f"[backend] API server running on http://{host}:{BACKEND_PORT}")
    _debug_print(f"[backend] engine control API: {engine_client.ENGINE_URL}")
    wserve(
        app,
        host=host,
        port=BACKEND_PORT,
        threads=8,
        connection_limit=100,
        channel_timeout=30,
        max_request_body_size=1048576,
        expose_tracebacks=False,
        ident="MCStatusBackend",
    )


if __name__ == "__main__":
    serve()

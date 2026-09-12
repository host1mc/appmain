import os
import hashlib
import hmac
import json
import ipaddress as _ipaddr
import logging
import re
import secrets
import socket
import sys
import threading
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import quote, urlsplit as _urlsplit

import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="flask_limiter")

def _debug_print(*args, **kwargs):


    if os.environ.get("CONSOLE_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
        print(*args, **kwargs)

import requests as http_requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, Response as FlaskResponse,
    current_app, jsonify, g,
)
from flask.sessions import SessionInterface, SessionMixin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

from jinja2 import TemplateNotFound
from markupsafe import Markup, escape
import ads_config
import cf_edge
import obs
import embed_templates as embed_tpl
import internal_auth
import creds
import error_codes as ec
import session_cookie
import edge_gate
import turnstile

FRONTEND_PORT = int(os.environ.get("FRONTEND_PORT", 5000))
BACKEND_URL = os.environ.get("BACKEND_URL", f"http://127.0.0.1:8001")


PANEL_INTERNAL_URL = os.environ.get("PANEL_INTERNAL_URL", "http://127.0.0.1:8000")
PANEL_PROXY_ENABLED = os.environ.get(
    "PANEL_PROXY_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")


def _env_positive_float(name, default):
    try:
        value = float(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _env_clamped_int(name, default, low, high):
    try:
        parsed = int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


BACKEND_CONNECT_TIMEOUT = _env_positive_float("BACKEND_CONNECT_TIMEOUT", 2.0)
BACKEND_READ_TIMEOUT = _env_positive_float("BACKEND_READ_TIMEOUT", 8.0)
BACKEND_EMAIL_READ_TIMEOUT = _env_positive_float(
    "BACKEND_EMAIL_READ_TIMEOUT", 30.0)


PANEL_PROXY_TIMEOUT = _env_positive_float("PANEL_PROXY_TIMEOUT", 8.0)
# Runtime/image changes pull a Docker image on the node (up to ~120s). The
# default 8s proxy timeout is what turned those into a 504 mid-change.
PANEL_PROXY_SLOW_TIMEOUT = _env_positive_float("PANEL_PROXY_SLOW_TIMEOUT", 180.0)
_PANEL_SLOW_PATH_MARKERS = ("/image", "/rebuild", "/reinstall")
PANEL_PROXY_MAX_CONCURRENCY = _env_clamped_int(
    "PANEL_PROXY_MAX_CONCURRENCY", 6, 1, 8)
_panel_proxy_slots = threading.BoundedSemaphore(PANEL_PROXY_MAX_CONCURRENCY)

API_PROXY_READ_TIMEOUT = _env_positive_float("API_PROXY_READ_TIMEOUT", 30.0)
API_PROXY_MAX_CONCURRENCY = _env_clamped_int(
    "API_PROXY_MAX_CONCURRENCY", 6, 1, 8)
_api_proxy_slots = threading.BoundedSemaphore(API_PROXY_MAX_CONCURRENCY)


TRUSTED_PROXY_HOPS = max(0, int(os.environ.get("TRUSTED_PROXY_HOPS", "2")))
COOKIE_NAME = "session"
DEVICE_FP_COOKIE_NAME = "device_fp"
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@(gmail\.com|outlook\.com)$")


BLOCKED_PROXY_PREFIXES = (
    "session",
    "auth",
    "panel-store",
    "internal",
    "fingerprint",
)


def _session_id():


    try:
        sid = getattr(session, "sid", "")
        if sid:
            return sid
    except Exception:
        pass


    return session_cookie.verify(request.cookies.get(COOKIE_NAME, ""),
                                 internal_auth.get_internal_token())


def _validated_backend_url(value):

    candidate = (value or "").strip()
    parsed = _urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("BACKEND_URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("BACKEND_URL must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment \
            or "?" in candidate or "#" in candidate:
        raise ValueError("BACKEND_URL must contain only an origin")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("BACKEND_URL contains an invalid port") from exc

    if parsed.scheme.lower() == "http":
        host = parsed.hostname.rstrip(".").lower()
        is_loopback = host == "localhost"
        if not is_loopback:
            try:
                is_loopback = _ipaddr.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("remote BACKEND_URL values must use HTTPS")
    return candidate.rstrip("/")


def _api(method, path, json_data=None, read_timeout=None):

    try:
        backend_url = _validated_backend_url(BACKEND_URL)
    except ValueError:
        return {"ok": False, "code": ec.PROXY_FAILED,
                "error": "Backend URL is not securely configured"}
    url = f"{backend_url}{path}"
    headers = {
        "X-Session-Id": _session_id(),
        "X-Forwarded-For": _get_client_ip(),
        "User-Agent": request.headers.get("User-Agent", ""),
        "Content-Type": "application/json",
    }
    headers.update(internal_auth.internal_headers())
    try:
        resp = http_requests.request(
            method=method, url=url, headers=headers, json=json_data,
            timeout=(BACKEND_CONNECT_TIMEOUT,
                     read_timeout or BACKEND_READ_TIMEOUT),
            allow_redirects=False,
        )
    except http_requests.ConnectionError:
        return {"ok": False, "code": ec.BACKEND_UNAVAILABLE, "error": "Backend unavailable"}
    except http_requests.Timeout:
        return {"ok": False, "code": ec.BACKEND_TIMEOUT, "error": "Backend timed out"}
    except Exception:
        return {"ok": False, "code": ec.PROXY_FAILED, "error": "Request failed"}
    try:
        payload = resp.json()
    except Exception:
        return {"ok": False, "code": ec.PROXY_FAILED, "error": "Request failed",
                "_status": resp.status_code}
    if isinstance(payload, dict):
        payload.setdefault("_status", resp.status_code)
    return payload


class ServerSession(dict, SessionMixin):
    def __init__(self, data=None, sid=None, new=False):
        super().__init__(data or {})
        self.sid = sid
        self.new = new

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.modified = True

    def __delitem__(self, key):
        super().__delitem__(key)
        self.modified = True

    def clear(self):
        super().clear()
        self.modified = True

    def pop(self, key, *args):
        result = super().pop(key, *args)
        self.modified = True
        return result

    def setdefault(self, key, default=None):


        result = super().setdefault(key, default)
        self.modified = True
        return result

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self.modified = True


def _cookie_secure():


    override = os.environ.get("COOKIE_SECURE", "").strip().lower()
    if override in ("1", "true", "yes"):
        return True
    if override in ("0", "false", "no"):
        return False
    try:
        return bool(request.is_secure)
    except Exception:


        return False


_SID_HEX = frozenset("0123456789abcdefABCDEF")


def _tokens_equal(sent, expected) -> bool:


    if not isinstance(sent, str) or not isinstance(expected, str):
        return False
    if not sent or not expected:
        return False
    return secrets.compare_digest(
        sent.encode("utf-8", "surrogatepass"),
        expected.encode("utf-8", "surrogatepass"),
    )


def _valid_sid(sid) -> bool:


    return (isinstance(sid, str) and bool(sid) and len(sid) <= 64
            and all(char in _SID_HEX for char in sid))


def _new_sid():


    return secrets.token_hex(24)


class ServerSessionInterface(SessionInterface):
    def open_session(self, app, request):
        cookie_name = app.config.get("SESSION_COOKIE_NAME", COOKIE_NAME)


        sid = session_cookie.verify(request.cookies.get(cookie_name, ""),
                                    internal_auth.get_internal_token())
        if sid and _valid_sid(sid):
            resp = _api("GET", f"/api/session/{sid}")
            data = resp.get("data") if resp.get("ok") else None
            if data is not None:
                bound_ip = data.get("_ip")
                if bound_ip and bound_ip != _get_client_ip():
                    _api("DELETE", f"/api/session/{sid}")
                    return ServerSession(sid=_new_sid(), new=True)
                req_fp = (request.headers.get("X-Device-Fingerprint") or
                          request.cookies.get(DEVICE_FP_COOKIE_NAME))
                bound_fp = data.get("_fp")
                if bound_fp and req_fp != bound_fp:
                    _api("DELETE", f"/api/session/{sid}")
                    return ServerSession(sid=_new_sid(), new=True)
                s = ServerSession(data=data, sid=sid)
                s.modified = False
                return s
        return ServerSession(sid=_new_sid(), new=True)

    def save_session(self, app, session, response):


        if session is None:
            return
        cookie_name = app.config.get("SESSION_COOKIE_NAME", COOKIE_NAME)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        if not session:


            if session.sid:
                if not session.new:
                    _api("DELETE", f"/api/session/{session.sid}")


                response.delete_cookie(
                    cookie_name, domain=domain, path=path,
                    httponly=True, samesite="Lax", secure=_cookie_secure(),
                )


                if request.cookies.get(DEVICE_FP_COOKIE_NAME):
                    response.delete_cookie(
                        DEVICE_FP_COOKIE_NAME, domain=domain, path=path,
                        httponly=True, samesite="Lax", secure=_cookie_secure(),
                    )
            return
        max_age = app.permanent_session_lifetime.total_seconds()
        if session.new:
            _api("POST", "/api/session", json_data={
                "sid": session.sid,
                "data": dict(session),
            })
            session.new = False
        elif session.modified:
            _api("PUT", f"/api/session/{session.sid}", json_data={
                "data": dict(session),
            })


        response.set_cookie(
            cookie_name, session_cookie.sign(session.sid,
                                             internal_auth.get_internal_token()),
            max_age=int(max_age), httponly=True, samesite="Lax",
            secure=_cookie_secure(),
            domain=domain, path=path,
        )
        bound_fp = session.get("_fp")
        if bound_fp:
            response.set_cookie(
                DEVICE_FP_COOKIE_NAME, bound_fp,
                max_age=int(max_age), httponly=True, samesite="Lax",
                secure=_cookie_secure(), domain=domain, path=path,
            )


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = _env_clamped_int(
    "PANEL_MAX_CONTENT_LENGTH", 150 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024)
app.config["ENV"] = "production"


FP_DETAIL_MAX_BYTES = 65536


API_MAX_BODY_BYTES = int(os.environ.get("API_MAX_BODY_BYTES", str(1024 * 1024)))


FORM_MAX_BODY_BYTES = int(os.environ.get("FORM_MAX_BODY_BYTES", str(1024 * 1024)))


FORM_FIELD_MAX = {
    "username": 256,
    "password": 4096,
    "email": 254,
    "display_name": 256,
    "fingerprint": 512,
    "otp": 32,
    "step": 8,
}


def _oversized_form_field():

    for name, limit in FORM_FIELD_MAX.items():
        if len(request.form.get(name, "") or "") > limit:
            return name
    return ""


def _capped_fp_detail(value):


    text = (value or "").strip()
    if len(text.encode("utf-8", "replace")) > FP_DETAIL_MAX_BYTES:
        return ""
    return text


try:
    _gate_token = internal_auth.get_internal_token()
except Exception as _gate_token_error:
    _gate_token = ""
    _debug_print(f"[gate] WARNING: no internal token ({_gate_token_error}); flood "
          "shedding is active but the site-entry challenge cannot issue cookies",
          file=sys.stderr, flush=True)

app.wsgi_app = edge_gate.Gate(
    app.wsgi_app,
    internal_token=_gate_token,
    trusted_hops=TRUSTED_PROXY_HOPS,
)

if TRUSTED_PROXY_HOPS:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUSTED_PROXY_HOPS,
        x_proto=1,
        x_host=1,
        x_port=1,
    )

_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "flask_key.key")


def load_or_create_flask_secret(path):

    def validate(raw):
        secret = raw.strip()
        if len(secret) != 48 or not all(char in "0123456789abcdefABCDEF" for char in secret):
            raise RuntimeError(f"{path} is not a valid 48-character hexadecimal Flask secret")
        return secret

    os.makedirs(os.path.dirname(path), exist_ok=True)
    candidate = os.urandom(24).hex()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:


        for _ in range(100):
            with open(path, encoding="ascii") as key_file:
                raw = key_file.read()
            stripped = raw.strip()
            if len(stripped) == 48:
                return validate(raw)
            if stripped and (len(stripped) > 48 or
                             not all(char in "0123456789abcdefABCDEF" for char in stripped)):
                return validate(raw)
            time.sleep(0.01)
        return validate(raw)

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


# The public frontend must never hold the master ENCRYPTION_KEY, so it does not
# derive its session secret from it. Set FLASK_SECRET_KEY fleet-wide (systemd
# cred or forwarded env) so both instances sign session cookies identically.
app.secret_key = creds.get("FLASK_SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = load_or_create_flask_secret(_KEY_FILE)


app.permanent_session_lifetime = timedelta(
    seconds=_env_clamped_int("SESSION_TTL_SECONDS", 3600, 300, 86400))
app.session_interface = ServerSessionInterface()


limiter = Limiter(


    lambda: _get_client_ip() or get_remote_address(),
    app=app,
    default_limits=["200 per minute", "50000 per day"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI") or None,
    storage_options={"connection_pool_kwargs": {"socket_connect_timeout": 3}},
    in_memory_fallback_enabled=True,
)


_limiter_storage_warned = set()


class _LimiterStorageWatch(logging.Handler):


    def emit(self, record):
        try:
            message = record.getMessage().lower()
        except Exception:
            return
        if "falling back to in-memory" in message:
            if "dead" in _limiter_storage_warned:
                return
            _limiter_storage_warned.add("dead")
            _debug_print("[fe] WARNING: RATELIMIT_STORAGE_URI is unreachable - rate "
                  "limits have fallen back to per-process in-memory counters, "
                  "so each worker and each instance again grants its own full "
                  "allowance until the store recovers.",
                  file=sys.stderr, flush=True)
        elif "storage recovered" in message:
            if "dead" not in _limiter_storage_warned:
                return
            _limiter_storage_warned.discard("dead")
            _debug_print("[fe] rate-limit storage recovered - limits are shared again.",
                  file=sys.stderr, flush=True)


if not (os.environ.get("RATELIMIT_STORAGE_URI") or "").strip():
    _debug_print("[fe] WARNING: RATELIMIT_STORAGE_URI is unset - rate limits are "
          "per-process in-memory counters, so each worker and each instance "
          "grants its own full allowance. Point it at a store both instances "
          "share before treating any limit here as a limit.",
          file=sys.stderr, flush=True)
else:


    _limiter_logger = logging.getLogger("flask-limiter")
    if _limiter_logger.level == logging.NOTSET:
        _limiter_logger.setLevel(logging.WARNING)
    _limiter_logger.addHandler(_LimiterStorageWatch())


@app.errorhandler(413)
def _request_entity_too_large(e):
    return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)


@app.errorhandler(429)
def _ratelimit_handler(e):


    retry_after = 60
    limit = getattr(e, "limit", None)
    item = getattr(limit, "limit", None)
    try:
        expiry = int(item.get_expiry())
        if expiry > 0:
            retry_after = min(expiry, 3600)
    except Exception:
        pass
    return render_template(
        "rate_limited.html",
        message="Rate limit exceeded. Please slow down."), 429, {
            "Retry-After": str(retry_after)}


@app.errorhandler(500)
def _internal_error(e):
    return ec.err(ec.INTERNAL_ERROR, "Internal server error", 500)


@app.errorhandler(403)
def _forbidden_handler(e):
    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Access Denied</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="auth-wrap"><div class="auth-card" style="text-align:center"><div style="font-size:52px;margin-bottom:8px">&#128274;</div><h2>Access Denied</h2><p class="hint">You do not have permission to view this page.</p><a href="/" class="btn btn-primary" style="display:inline-block;margin-top:12px">Go Home</a></div></div></body></html>"""
    return html, 403, {"Content-Type": "text/html; charset=utf-8"}


@app.errorhandler(404)
def _not_found_handler(e):


    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Page Not Found</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="auth-wrap"><div class="auth-card" style="text-align:center"><div style="font-size:52px;margin-bottom:8px">&#129517;</div><h2>Page Not Found</h2><p class="hint">That page does not exist, or it may have moved.</p><a href="/" class="btn btn-primary" style="display:inline-block;margin-top:12px">Go Home</a></div></div></body></html>"""
    return html, 404, {"Content-Type": "text/html; charset=utf-8"}

@app.before_request
def _limit_api_body():


    if not request.path.startswith("/api/"):


        if request.endpoint == "panel_proxy":
            return None
        declared = request.content_length
        if declared is not None and declared > FORM_MAX_BODY_BYTES:
            return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)
        return None
    declared = request.content_length
    if declared is not None and declared > API_MAX_BODY_BYTES:
        return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)
    return None


@app.before_request
def _make_csp_nonce():


    import secrets as _secrets
    g_nonce = _secrets.token_urlsafe(16)
    request.csp_nonce = g_nonce


@app.context_processor
def _inject_csp_nonce():
    return dict(csp_nonce=getattr(request, "csp_nonce", ""))


@app.context_processor
def _inject_turnstile():


    return dict(
        turnstile_site_key=turnstile.site_key() if turnstile.enabled() else "")


@app.context_processor
def _inject_auth_methods():
    # A callable, not a value: only the login/register pages that call it pay the
    # one backend round-trip, cached per request on g. Fails closed (GitHub
    # hidden) when the backend is unreachable or the toggle is off.
    def auth_github_enabled():
        cached = getattr(g, "_auth_github_enabled", None)
        if cached is None:
            resp = _api("GET", "/api/auth/methods")
            cached = bool(isinstance(resp, dict) and resp.get("ok")
                          and resp.get("github"))
            g._auth_github_enabled = cached
        return cached
    return dict(auth_github_enabled=auth_github_enabled)


CSRF_SESSION_KEY = "_csrf_token"
CSRF_HEADER = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"


CSRF_EXEMPT_ENDPOINTS = {"panel_proxy", "blocked_clear"}


def _csrf_token():


    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


LOGOUT_TOKEN_KEY = "_logout_token"


def _logout_token():


    token = session.get(LOGOUT_TOKEN_KEY)
    if not token:
        token = secrets.token_urlsafe(16)
        session[LOGOUT_TOKEN_KEY] = token
    return token


@app.context_processor
def _inject_csrf_token():
    return dict(csrf_token=_csrf_token, logout_token=_logout_token)


_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


@app.before_request
def _check_csrf():


    if request.method in _CSRF_SAFE_METHODS:
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None


    if internal_auth.is_internal_request(request):
        return None
    sent = request.headers.get(CSRF_HEADER, "") or request.form.get(CSRF_FORM_FIELD, "")
    expected = session.get(CSRF_SESSION_KEY, "")
    if expected and sent and _tokens_equal(sent, expected):
        return None
    if request.path.startswith("/api/"):
        if not expected:
            return ec.err(ec.CSRF_SESSION_EXPIRED,
                          "Your session expired. Reload the page and sign in again.", 403)
        return ec.err(ec.CSRF_INVALID, "CSRF token missing or invalid", 403)


    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Request Expired</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="auth-wrap"><div class="auth-card" style="text-align:center"><h2>Request Expired</h2><p class="hint">Your session security token was missing or out of date. Reload the page and try again.</p><a href="/user/login" class="btn btn-primary" style="display:inline-block;margin-top:12px">Back to login</a></div></div></body></html>"""
    return html, 403, {"Content-Type": "text/html; charset=utf-8"}


_INTEGRITY_EXEMPT_PREFIXES = (
    "/api/", "/static/", "/health", "/sw.js", "/ads.txt",
    "/robots.txt", "/sitemap.xml", "/site.webmanifest", "/panel",
)
_integrity_warned = False


@app.before_request
def _enforce_browser_integrity():


    global _integrity_warned
    if _cf_header("CF-Browser-Integrity") != "fail":
        return None
    if request.method not in ("GET", "HEAD"):
        return None
    if request.path.startswith(_INTEGRITY_EXEMPT_PREFIXES):
        return None
    if not _integrity_warned:
        _integrity_warned = True
        _debug_print(
            "[fe] WARNING: Cloudflare browser integrity check failed for "
            f"{request.path} - answered 403. Enable the check in the CF zone "
            "(Security → Bots, free) and set it to block to stop these at the "
            "edge; this refusal is the app-side backstop.",
            file=sys.stderr, flush=True,
        )
    abort(403)


_NOINDEX_PREFIXES = ("/user", "/api", "/blocked", "/nav", "/impersonate")


def _load_cors_origins():


    raw = os.environ.get("CORS_ORIGINS", "")
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


        allowed.add(f"{parts.scheme.lower()}://{parts.netloc.lower()}")
    return frozenset(allowed) or None


_cors_origins = _load_cors_origins()


@app.after_request
def _security_headers(response):


    if request.endpoint == "panel_proxy":
        return response


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
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    )


    response.headers["Referrer-Policy"] = "no-referrer"


    if _cookie_secure():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


    if request.path.startswith("/static/") or request.path == "/favicon.ico":
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store, max-age=0"


    if request.path.startswith(_NOINDEX_PREFIXES) or request.endpoint == "masked_page":
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
    nonce = getattr(request, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "


        f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic' 'unsafe-eval' "


        + " ".join(ads_config.ALLOWED_SCRIPT_HOSTS) + " "


        + ads_config.SMART_FEEDER_HOST + "; "


        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "


        "upgrade-insecure-requests; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "


        "frame-src 'self' https:; "


        "object-src 'none'; "
        "base-uri 'self'; "


        "frame-ancestors 'none'; "


        "form-action 'self' https://github.com; "


        "connect-src 'self' https:;"
    )
    return response


def user_required(f):
    @wraps(f)
    def wrap(*a, **k):
        if not session.get("user_id"):
            return redirect(url_for("user_login"))
        return f(*a, **k)
    return wrap


def _proxy_headers():


    headers = {
        "X-Session-Id": _session_id(),
        "X-Forwarded-For": _get_client_ip(),
        "User-Agent": request.headers.get("User-Agent", ""),
        "Content-Type": request.content_type or "application/json",
    }
    fingerprint = request.headers.get("X-Device-Fingerprint", "").strip()
    if fingerprint:
        headers["X-Device-Fingerprint"] = fingerprint[:128]
    return headers


_HEADER_PEER_NETWORKS = cf_edge.HEADER_PEER_NETWORKS
_EDGE_NETWORKS = cf_edge.EDGE_NETWORKS
_peer_is_cf = cf_edge.peer_is_cf

_proxy_chain_warned = set()


def _warn_proxy_chain_once(reason, detail=""):


    if reason in _proxy_chain_warned:
        return
    _proxy_chain_warned.add(reason)


    safe = re.sub(r"[^0-9A-Fa-f:., \[\]]", "?", detail or "")[:120]
    suffix = f" ({safe})" if safe else ""
    _debug_print(f"[fe] WARNING: {reason}{suffix}", file=sys.stderr, flush=True)


_cf_header_warned = set()


def _warn_cf_header_discarded_once(name, peer=""):


    if name in _cf_header_warned:
        return
    _cf_header_warned.add(name)
    detail = ""
    if peer:
        detail = (f" This request's peer was {peer} — pin the CIDR containing "
                  "it (the balancer's subnet) in CF_TRUSTED_IPS.")
    _debug_print(f"[fe] WARNING: {name} discarded — the connecting peer is not on "
          "Cloudflare's published ranges, so this request cannot be shown to "
          "have come through the edge. Behind a second terminating proxy (the "
          "OCI load balancer) that peer is the balancer, and every CF-* header "
          "is dropped until its range is pinned in CF_TRUSTED_IPS. Cloudflare "
          "bot detection and browser-integrity enforcement do nothing until "
          f"then.{detail}",
          file=sys.stderr, flush=True)


def _hop_address(value):

    text = (value or "").strip()
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return _ipaddr.ip_address(text)
    except ValueError:
        return None


def _socket_peer():

    original = request.environ.get("werkzeug.proxy_fix.orig") or {}
    return (original.get("REMOTE_ADDR") if isinstance(original, dict) else "") \
        or request.environ.get("REMOTE_ADDR", "")


def _forwarded_chain_fault():


    if TRUSTED_PROXY_HOPS < 2:
        return ""
    chain = [hop.strip() for hop in
             request.headers.get("X-Forwarded-For", "").split(",") if hop.strip()]
    if not chain:


        return ""
    if len(chain) < TRUSTED_PROXY_HOPS:
        return "shorter than TRUSTED_PROXY_HOPS"
    for hop in chain[-(TRUSTED_PROXY_HOPS - 1):]:
        addr = _hop_address(hop)
        if addr is None:
            return "unparseable proxy hop"
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            continue
        if _peer_is_cf(str(addr), _EDGE_NETWORKS):
            continue
        return "proxy hop is neither Cloudflare nor internal"
    return ""


def _get_client_ip():


    if os.environ.get("FRONTEND_DEBUG_HEADERS", "").strip().lower() in ("1", "true", "yes"):
        _debug_print(f"[fe-dbg] uri={request.path} peer_raw={request.environ.get('REMOTE_ADDR', '')} "
              f"xff_raw={request.headers.get('X-Forwarded-For', '')} "
              f"cf={request.headers.get('CF-Connecting-IP', '')} "
              f"resolved={request.remote_addr or ''}", flush=True)
    cf = request.headers.get("CF-Connecting-IP", "").strip()
    chain_fault = _forwarded_chain_fault()
    if TRUSTED_PROXY_HOPS >= 1 and cf and not chain_fault:
        try:
            addr = _ipaddr.ip_address(cf)
        except ValueError:
            addr = None
        socket_peer = _socket_peer()


        peer_networks = _HEADER_PEER_NETWORKS
        if addr is not None and not addr.is_private and not addr.is_loopback \
                and not addr.is_link_local and not addr.is_multicast \
                and not addr.is_unspecified and _peer_is_cf(socket_peer, peer_networks):
            return str(addr)
    if chain_fault:
        _warn_proxy_chain_once(
            f"X-Forwarded-For {chain_fault} (TRUSTED_PROXY_HOPS={TRUSTED_PROXY_HOPS}), so "
            "forwarded entries are not trusted and requests are attributed to the "
            "proxy; check TRUSTED_PROXY_HOPS and CF_TRUSTED_IPS",
            request.headers.get("X-Forwarded-For", ""))
        return _socket_peer() or request.remote_addr or ""
    return request.remote_addr or ""


def _cf_header(name):


    value = request.headers.get(name)
    if not value:
        return ""
    peer = _socket_peer()
    if not _peer_is_cf(peer, _HEADER_PEER_NETWORKS):
        _warn_cf_header_discarded_once(name, peer)
        return ""
    return value


@app.route("/api/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])


@limiter.limit(
    "20 per minute; 200 per hour",
    exempt_when=lambda: not request.path.startswith("/api/auth/"),
    override_defaults=False,
)
def api_proxy(subpath):


    segments = []
    for segment in subpath.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":


            return ec.err(ec.NOT_FOUND, "Not found", 404)
        segments.append(segment)
    normalized = "/".join(segments).lower()
    for blocked in BLOCKED_PROXY_PREFIXES:
        if normalized == blocked or normalized.startswith(blocked + "/"):
            return ec.err(ec.NOT_FOUND, "Not found", 404)

    try:
        backend_url = _validated_backend_url(BACKEND_URL)
    except ValueError:
        return ec.err(ec.PROXY_FAILED, "Backend URL is not securely configured", 502)


    url = f"{backend_url}/api/{'/'.join(quote(s, safe='') for s in segments)}"
    headers = _proxy_headers()


    chunks = []
    remaining = API_MAX_BODY_BYTES + 1
    while remaining > 0:
        chunk = request.stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    if len(body) > API_MAX_BODY_BYTES:
        return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)
    if not _api_proxy_slots.acquire(blocking=False):
        _debug_print("[fe] api proxy shed a request: all "
              f"{API_PROXY_MAX_CONCURRENCY} forward slots are busy",
              file=sys.stderr)
        return ec.err(ec.BACKEND_UNAVAILABLE, "Backend server busy", 503)
    try:
        resp = http_requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=body,
            params=request.args,
            timeout=(BACKEND_CONNECT_TIMEOUT, API_PROXY_READ_TIMEOUT),
            allow_redirects=False,
        )


        excluded = _HOP_BY_HOP_HEADERS | {"content-length", "content-encoding",
                                          "server", "date"} | _PROXY_POLICY_HEADERS
        proxy_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
        return FlaskResponse(
            response=resp.content,
            status=resp.status_code,
            headers=proxy_headers,
        )
    except http_requests.ConnectionError:
        return ec.err(ec.BACKEND_UNAVAILABLE, "Backend server unavailable", 502)
    except http_requests.Timeout:


        return ec.err(ec.BACKEND_TIMEOUT, "Backend server timed out", 504)
    except Exception as e:


        safe_path = re.sub(r"[^A-Za-z0-9_./:@%+-]", "?", subpath)[:120]
        _debug_print(f"[fe] api proxy failed for /api/{safe_path}: {type(e).__name__}",
              file=sys.stderr)
        return ec.err(ec.PROXY_FAILED, "Request failed", 500)
    finally:
        _api_proxy_slots.release()


@app.route("/api/reviews", methods=["POST"])
@limiter.limit("5 per minute; 30 per hour", methods=["POST"])
def api_reviews_post():


    return api_proxy("reviews")


_HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
})


_PROXY_POLICY_HEADERS = frozenset({
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "access-control-expose-headers", "access-control-max-age",
    "timing-allow-origin", "set-cookie",
})


_PANEL_REQUEST_SKIP = _HOP_BY_HOP_HEADERS | {
    "host", "content-length", internal_auth.INTERNAL_HEADER.lower(),
}


_PANEL_RESPONSE_SKIP = _HOP_BY_HOP_HEADERS | {
    "content-length", "content-encoding", "date", "server", "set-cookie",
}


_PANEL_LIVE_TTL = 12.0
_PANEL_PROBE_TIMEOUT = 0.25
_panel_live_lock = threading.Lock()
_panel_live_checked_at = 0.0
_panel_live_ok = False


def _panel_probe_target():

    parts = _urlsplit(PANEL_INTERNAL_URL)
    return (parts.hostname or "127.0.0.1",
            parts.port or (443 if parts.scheme == "https" else 80))


def _set_panel_live(alive):
    global _panel_live_checked_at, _panel_live_ok
    with _panel_live_lock:
        _panel_live_checked_at = time.time()
        _panel_live_ok = alive


def _mark_panel_down():


    _set_panel_live(False)


def _mark_panel_up():

    _set_panel_live(True)


def _panel_live():


    if not PANEL_PROXY_ENABLED:
        return False
    with _panel_live_lock:
        if time.time() - _panel_live_checked_at < _PANEL_LIVE_TTL:
            return _panel_live_ok


    try:
        host, port = _panel_probe_target()
        with socket.create_connection((host, port),
                                      timeout=_PANEL_PROBE_TIMEOUT):
            alive = True
    except (OSError, ValueError):
        alive = False
    _set_panel_live(alive)
    return alive


_PANEL_JSON_PREFIXES = ("/panel/api/", "/panel/ws/")


def _panel_wants_html():

    if "text/html" not in (request.headers.get("Accept") or "").lower():
        return False
    return not request.path.startswith(_PANEL_JSON_PREFIXES)


def _panel_error(status, heading, detail, retry, fallback):


    if not _panel_wants_html():
        return fallback()
    try:
        body = render_template("panel_down.html", status=status, heading=heading,
                               detail=detail, retry=retry)
    except TemplateNotFound:
        return fallback()
    headers = {
        "Content-Type": "text/html; charset=utf-8",

        "X-Robots-Tag": "noindex, nofollow",
    }
    if retry:
        headers["Retry-After"] = "15"
    return body, status, headers


@app.route("/panel", strict_slashes=False,
           methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/panel/<path:subpath>",
           methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def panel_proxy(subpath=""):


    if not PANEL_PROXY_ENABLED:
        return _panel_error(
            404, "Not found",
            "Bot hosting is not published on this address.",
            False, lambda: abort(404))
    try:
        panel_url = _validated_backend_url(PANEL_INTERNAL_URL)
    except ValueError:
        return _panel_error(
            502, "Hosting panel unavailable",
            "Bot hosting is not configured on this server.",
            False,
            lambda: ec.err(ec.PROXY_FAILED,
                           "Panel URL is not securely configured", 502))


    url = f"{panel_url}{quote(request.path, safe='/')}"

    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in _PANEL_REQUEST_SKIP}
    headers["X-Forwarded-For"] = _get_client_ip()
    headers["X-Forwarded-Proto"] = "https" if _cookie_secure() else "http"
    headers["X-Forwarded-Host"] = request.host

    headers.pop(internal_auth.INTERNAL_HEADER, None)


    from werkzeug.exceptions import HTTPException

    if not _panel_proxy_slots.acquire(blocking=False):
        _debug_print("[fe] panel proxy shed a request: all "
              f"{PANEL_PROXY_MAX_CONCURRENCY} forward slots are busy",
              file=sys.stderr)
        return _panel_error(
            503, "Hosting panel is busy",
            "Too many hosting requests are in flight at once.",
            True,
            lambda: ec.err(ec.BACKEND_UNAVAILABLE, "Panel server busy", 503))

    path_l = (request.path or "").lower()
    proxy_timeout = PANEL_PROXY_TIMEOUT
    if "/api/servers/" in path_l and any(m in path_l for m in _PANEL_SLOW_PATH_MARKERS):
        proxy_timeout = PANEL_PROXY_SLOW_TIMEOUT
    try:
        resp = http_requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            params=request.args,
            timeout=proxy_timeout,
            allow_redirects=False,
        )
    except http_requests.ConnectionError:


        _mark_panel_down()
        return _panel_error(
            502, "Hosting panel is offline",
            "The bot hosting service is not running right now.",
            True,
            lambda: ec.err(ec.BACKEND_UNAVAILABLE,
                           "Panel server unavailable", 502))
    except http_requests.Timeout:
        return _panel_error(
            504, "Hosting panel timed out",
            "The hosting panel took too long to answer.",
            True,
            lambda: ec.err(ec.BACKEND_TIMEOUT, "Panel server timed out", 504))
    except HTTPException:


        raise
    except Exception as e:


        safe_path = re.sub(r"[^A-Za-z0-9_./:@%+-]", "?", subpath)[:120]
        _debug_print(f"[fe] panel proxy failed for /panel/{safe_path}: {type(e).__name__}",
              file=sys.stderr)
        return _panel_error(
            500, "Hosting panel error",
            "The hosting panel could not answer that request.",
            False, lambda: ec.err(ec.PROXY_FAILED, "Request failed", 500))
    finally:
        _panel_proxy_slots.release()


    _mark_panel_up()
    out = FlaskResponse(
        response=resp.content,
        status=resp.status_code,
        headers={k: v for k, v in resp.headers.items()
                 if k.lower() not in _PANEL_RESPONSE_SKIP},
    )

    for cookie in (resp.raw.headers.getlist("Set-Cookie") if resp.raw is not None else ()):
        out.headers.add("Set-Cookie", cookie)


    out.headers["X-Robots-Tag"] = "noindex, nofollow"
    return out


@app.route("/")
def index():


    data = _api("GET", "/api/reviews")
    reviews = (data.get("reviews") or []) if isinstance(data, dict) else []
    summary = data.get("summary") if isinstance(data, dict) else None
    if not isinstance(summary, dict):
        summary = {"count": 0, "average": 0}
    return render_template("index.html", reviews=reviews, summary=summary)


@app.route("/privacy")
def privacy():


    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/about")
def about():
    return render_template("about.html")


# Retired marketing pages. The Hosting and Blog pages were removed from the
# public site; the redirects below keep old links, bookmarks and indexed URLs
# landing on the home page instead of a 404.
@app.route("/hosting")
def hosting():
    return redirect(url_for("index"), code=301)


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/help")
def help():
    return render_template("help.html")


@app.route("/blog")
def blog():
    return redirect(url_for("index"), code=301)


@app.route("/blog/<slug>")
def blog_post(slug):
    return redirect(url_for("index"), code=301)


_ADS_TXT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ads.txt")
try:
    with open(_ADS_TXT_FILE, encoding="utf-8") as _ads_txt_fh:
        _ADS_TXT = _ads_txt_fh.read().strip()
except OSError:
    _ADS_TXT = ""


@app.route("/ads.txt")
@limiter.exempt
def ads_txt():


    body = _ADS_TXT or ads_config.ads_txt_body()
    if not body:
        abort(404)
    return FlaskResponse(body.rstrip("\n") + "\n",
                         content_type="text/plain; charset=utf-8")


_ROBOTS_TXT = """User-agent: *
Allow: /$
Allow: /about
Allow: /contact
Allow: /help
Allow: /privacy
Allow: /terms
Allow: /ads.txt
Allow: /sitemap.xml
Disallow: /api/
Disallow: /user
Disallow: /user/
Disallow: /panel
Disallow: /panel/
Disallow: /nav
Disallow: /impersonate/
Disallow: /blocked
Disallow: /health

# AdSense's crawler needs the pages it will serve ads on, including the panel it
# would otherwise be told to skip by the wildcard rule above.
User-agent: Mediapartners-Google
Allow: /

User-agent: AdsBot-Google
Allow: /
"""


@app.route("/robots.txt")
@limiter.exempt
def robots_txt():
    lines = _ROBOTS_TXT
    if _SITE_HOST:
        lines += f"\nSitemap: {SITE_URL}/sitemap.xml\n"
    return FlaskResponse(lines, content_type="text/plain; charset=utf-8")


_SITEMAP_ENDPOINTS = (
    "index", "help", "about", "contact", "privacy", "terms")


@app.route("/sitemap.xml")
@limiter.exempt
def sitemap_xml():
    urls = []
    for endpoint in _SITEMAP_ENDPOINTS:
        loc = _external(SITE_URL, endpoint) if SITE_URL else url_for(
            endpoint, _external=True)


        loc = str(escape(loc))
        priority = "1.0" if endpoint == "index" else "0.5"
        urls.append(f"  <url><loc>{loc}</loc><priority>{priority}</priority></url>")
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>\n"
    )
    return FlaskResponse(body, content_type="application/xml; charset=utf-8")


@app.route("/site.webmanifest")
@limiter.exempt
def site_webmanifest():
    manifest = {
        "name": "ENDHOST",
        "short_name": "ENDHOST",
        "description": (
            "Free app hosting — Node.js, Python, Ruby, Go, PHP and Bun, "
            "kept online for you, plus Minecraft status embeds."
        ),
        "start_url": url_for("index"),
        "scope": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#ffffff",
        "icons": [
            {"src": url_for("static", filename="favicon-32.png"),
             "sizes": "32x32", "type": "image/png"},
            {"src": url_for("static", filename="favicon-64.png"),
             "sizes": "64x64", "type": "image/png"},
            {"src": url_for("static", filename="apple-touch-icon.png"),
             "sizes": "180x180", "type": "image/png"},
            {"src": url_for("static", filename="logo.png"),
             "sizes": "1024x1024", "type": "image/png"},
        ],
    }
    return FlaskResponse(
        json.dumps(manifest, indent=2),
        content_type="application/manifest+json; charset=utf-8",
    )


_AD_ASSET_WINDOW = 86400
_AD_ASSET_INFO = b"ad-asset-path-v1"


def _ad_asset_token(window_index):
    tok = internal_auth.get_internal_token() or ""
    return hmac.new(
        tok.encode("utf-8", "surrogatepass"),
        _AD_ASSET_INFO + b":" + str(int(window_index)).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()[:24]


def _current_guard_token():
    return _ad_asset_token(int(time.time()) // _AD_ASSET_WINDOW)


def _guard_token_valid(token):


    if not token or len(token) != 24:
        return False
    idx = int(time.time()) // _AD_ASSET_WINDOW
    return any(hmac.compare_digest(token, _ad_asset_token(idx - n)) for n in (0, 1))


@app.route("/assets/<token>/g.js")
def guard_asset(token):
    if not _guard_token_valid(token):
        abort(404)
    resp = app.send_static_file("g7.js")


    resp.cache_control.public = False
    resp.cache_control.private = True
    resp.cache_control.max_age = 3600
    return resp


@app.route("/blocked")
def blocked():


    if request.args.get("from"):
        session[_AD_WALL_KEY] = time.time()
    return render_template("blocked.html"), 200


_HEALTH_TTL = min(60.0, _env_positive_float("HEALTH_CACHE_TTL", 8.0))
_HEALTH_PROBE_TIMEOUT = _env_positive_float("HEALTH_PROBE_TIMEOUT", 3.0)


_health_state = {"at": float("-inf"), "ok": True, "probing": False,
                 "down_since": None, "fails": 0}
_health_lock = threading.Lock()


_HEALTH_FAIL_MAX = _env_positive_float("HEALTH_FAIL_MAX_SECONDS", 90.0)
_HEALTH_FAIL_THRESHOLD = max(1, int(_env_positive_float("HEALTH_FAIL_THRESHOLD",
                                                        2.0)))
_HEALTH_PROBE_REACHABLE_NON_2XX = frozenset({429})
_HEALTH_PROBES = (("Oracle", "/api/settings/ad-enabled"),
                  ("internal auth", "/api/internal/probe"))


def _dependencies_ok():


    now = time.monotonic()
    with _health_lock:
        if now - _health_state["at"] < _HEALTH_TTL or _health_state["probing"]:
            return _health_state["ok"]
        _health_state["probing"] = True
    ok = False
    fault = ""
    label = "dependency"
    try:
        backend_url = _validated_backend_url(BACKEND_URL)
        headers = {"Content-Type": "application/json"}
        headers.update(internal_auth.internal_headers())
        for label, path in _HEALTH_PROBES:
            resp = http_requests.get(
                f"{backend_url}{path}",
                headers=headers,
                timeout=_HEALTH_PROBE_TIMEOUT,
                allow_redirects=False,
            )
            status = resp.status_code
            if 200 <= status < 300 or status in _HEALTH_PROBE_REACHABLE_NON_2XX:
                ok = True
            else:
                ok = False
                fault = f"the {label} probe answered HTTP {status}"
                break
    except Exception as exc:
        ok = False
        fault = f"the {label} probe raised {type(exc).__name__}"
    with _health_lock:
        _health_state["at"] = time.monotonic()
        _health_state["probing"] = False
        was_failing = _health_state["fails"] > 0
        if ok:
            _health_state["fails"] = 0
        else:
            _health_state["fails"] += 1
        first_fault = not ok and _health_state["fails"] == 1
        recovered = ok and was_failing
        healthy = ok or _health_state["fails"] < _HEALTH_FAIL_THRESHOLD
        _health_state["ok"] = healthy
        if healthy:
            _health_state["down_since"] = None
        elif _health_state["down_since"] is None:
            _health_state["down_since"] = _health_state["at"]
    if first_fault:
        _debug_print(f"[fe] WARNING: dependency probe failed — {fault}. This instance "
              f"reports itself out of rotation after {_HEALTH_FAIL_THRESHOLD} "
              "consecutive failures. 401/403 means the internal token or "
              "INTERNAL_PEERS is wrong for this instance, 404 or a redirect "
              "means the probe is not reaching the endpoint it is meant to "
              "prove. The response body says only that the instance is not "
              "serving, so this line is the only record of which it was.",
              file=sys.stderr, flush=True)
    elif recovered:
        _debug_print("[fe] dependency probe recovered — rejoining rotation.",
              file=sys.stderr, flush=True)
    return healthy


def _health_verdict():
    ok = _dependencies_ok()
    if ok:
        return True, True
    with _health_lock:
        down_since = _health_state["down_since"]
    if down_since is None:
        return False, False
    return False, (time.monotonic() - down_since) >= _HEALTH_FAIL_MAX


@app.route("/health")
@limiter.exempt
def health():
    ok, stay_in_rotation = _health_verdict()
    if ok:
        return {"ok": True}, 200
    if stay_in_rotation:
        return {"ok": False, "degraded": True}, 200
    return {"ok": False}, 503


_LOGIN_ERRORS = {
    ec.INVALID_CREDENTIALS: "Invalid username or password",
    ec.ACCOUNT_DISABLED: "This account has been disabled.",
    ec.EMAIL_UNVERIFIED:
        "Please verify your email first. Check your inbox for the OTP code.",
    ec.RATE_LIMITED: "Too many attempts. Please wait a minute and try again.",
    ec.BACKEND_UNAVAILABLE: "Service temporarily unavailable. Please try again.",
    ec.TURNSTILE_FAILED: "Please complete the verification check and try again.",
    ec.GITHUB_DISABLED: "GitHub sign-in is currently unavailable.",
    ec.GITHUB_AUTH_FAILED: "GitHub sign-in failed. Please try again.",
    ec.GITHUB_EMAIL_UNVERIFIED:
        "Your GitHub account has no verified email. Verify one on GitHub and try again.",
    ec.GITHUB_ACCOUNT_TOO_NEW:
        "Your GitHub account is too new to sign in.",
    ec.EMAIL_INVALID:
        "Only @gmail.com or @outlook.com emails are allowed",
}
_LOGIN_ERROR_FALLBACK = "Invalid username or password"


_REGISTER_ERRORS = {
    ec.MISSING_FIELDS: "Username, password and email required",
    ec.USERNAME_INVALID: "Username must be between 3 and 32 ordinary characters",
    ec.USERNAME_TAKEN: "Username already registered — use 'Log in' instead.",
    ec.PASSWORD_TOO_SHORT: "Password must be at least 8 characters",
    ec.PASSWORD_TOO_LONG: "Password is too long",
    ec.EMAIL_INVALID: "Only @gmail.com or @outlook.com emails are allowed",
    ec.DEVICE_BLOCKED: "Registration is not available from this device.",
    ec.OTP_SEND_FAILED: "Failed to send OTP. Please try again later.",
    ec.RATE_LIMITED: "Too many attempts. Please wait a minute and try again.",
    ec.BACKEND_UNAVAILABLE: "Service temporarily unavailable. Please try again.",
    ec.TURNSTILE_FAILED: "Please complete the verification check and try again.",
    ec.REGISTRATION_CLOSED: "New sign-ups are currently closed.",
}
_REGISTER_ERROR_FALLBACK = "Registration failed"


_VERIFY_TRANSPORT_CODES = frozenset((
    ec.BACKEND_TIMEOUT,
    ec.BACKEND_UNAVAILABLE,
    ec.PROXY_FAILED,
))


def _safe_error(resp, table, fallback):


    code = resp.get("code")
    if not isinstance(code, str):
        return fallback
    return table.get(code, fallback)


def _discard_pending_registration():


    old_uid = session.get("pending_user_id")
    link_existing = session.get("pending_link_existing")
    if not old_uid:
        session.pop("pending_link_existing", None)
        return
    session.pop("pending_user_id", None)
    # A link claim points at a real account, never at a fresh unverified row —
    # abandoning it must not touch the account itself.
    if not link_existing:
        _api("POST", "/api/auth/discard-registration", json_data={"user_id": old_uid})
    session.pop("pending_email", None)
    session.pop("pending_fingerprint", None)
    session.pop("pending_fingerprint_detail", None)
    session.pop("pending_link_existing", None)


def _rotate_session():


    old = session.sid
    session.sid = _new_sid()
    session.new = True
    if old:
        _api("DELETE", f"/api/session/{old}")


def _login_target_key():


    try:
        username = (request.form.get("username", "") or "").strip().casefold()
    except Exception:
        username = ""
    if not username:


        return f"login-ip:{_get_client_ip() or get_remote_address()}"
    digest = hashlib.sha256(username.encode("utf-8", "surrogatepass")).hexdigest()
    return f"login-user:{digest}"


def _login_attempt_failed(response):


    if g.get("_login_precheck_failed", False):
        return False
    return not 300 <= response.status_code < 400


@app.route("/user/register", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour; 20 per day", methods=["POST"])
def user_register():

    if request.method == "GET":
        _discard_pending_registration()

    if request.method == "POST":
        if _oversized_form_field():
            flash("Those details are too long to process.", "error")
            return render_template("user_register.html", step="1")
        step = request.form.get("step", "1")
        if step == "1":

            _discard_pending_registration()

            u = request.form.get("username", "").strip()
            p = request.form.get("password", "")
            e = (request.form.get("email", "") or "").strip().lower()
            d = request.form.get("display_name", "").strip() or None
            fp = (request.form.get("fingerprint", "") or "").strip()
            if not request.form.get("agree_terms"):
                flash("You must agree to the Terms of Service and Privacy Policy to create an account.", "error")
                return render_template("user_register.html", step="1")
            if not u or not p or not e:
                flash("Username, password and email required", "error")
                return render_template("user_register.html", step="1")
            if not EMAIL_RE.match(e):
                flash("Only @gmail.com or @outlook.com emails are allowed", "error")
                return render_template("user_register.html", step="1")


            resp = _api("POST", "/api/auth/register", json_data={
                "username": u,
                "password": p,
                "email": e,
                "display_name": d,
                "fingerprint": fp,
                "fingerprint_detail": (request.form.get("fingerprint_detail", "") or "").strip(),
                "cf-turnstile-response": request.form.get("cf-turnstile-response", "") or "",
                "agree_terms": "1" if request.form.get("agree_terms") else "",
            }, read_timeout=BACKEND_EMAIL_READ_TIMEOUT)
            if not resp.get("ok"):
                if resp.get("banned"):


                    return render_template("banned.html", reason=resp.get("reason", "This device is associated with a banned account.")), 403
                flash(_safe_error(resp, _REGISTER_ERRORS,
                                  _REGISTER_ERROR_FALLBACK), "error")
                return render_template("user_register.html", step="1")
            session["pending_user_id"] = resp.get("user_id")
            session["pending_email"] = e
            session["pending_fingerprint"] = fp
            fp_detail = (request.form.get("fingerprint_detail", "") or "").strip()
            if len(fp_detail.encode("utf-8", "replace")) > FP_DETAIL_MAX_BYTES:
                fp_detail = ""
            session["pending_fingerprint_detail"] = fp_detail
            if resp.get("link_existing"):
                session["pending_link_existing"] = "1"
                flash("This email already has an account — enter the code we sent "
                      "to sign in to the same account and set your new password.",
                      "info")
                return render_template("user_register.html", step="2", email=e,
                                       link_existing=True)
            session.pop("pending_link_existing", None)
            return render_template("user_register.html", step="2", email=e)
        elif step == "2":
            uid = session.get("pending_user_id")
            email = session.get("pending_email")
            code = (request.form.get("otp") or "").strip()
            link_existing = session.get("pending_link_existing")
            if not uid or not email or not code:
                flash("Session expired. Please register again.", "error")
                return redirect(url_for("user_register"))
            new_password = ""
            if link_existing:
                # Same-email claim: the code proves the address, the password
                # re-entered here becomes the account password.
                new_password = request.form.get("password", "") or ""
                if len(new_password) < 8:
                    flash("Pick a password of at least 8 characters.", "error")
                    return render_template("user_register.html", step="2", email=email,
                                           link_existing=True)
            resp = _api("POST", "/api/auth/complete-registration", json_data={
                "user_id": uid,
                "email": email,
                "otp_code": code,
                "new_password": new_password,
                "fingerprint": session.get("pending_fingerprint") or "",
                "fingerprint_detail": session.get("pending_fingerprint_detail") or "",
            }, read_timeout=BACKEND_EMAIL_READ_TIMEOUT)
            if not resp.get("ok"):
                if resp.get("banned"):
                    return render_template("banned.html", reason=resp.get("reason", "This device is associated with a banned account.")), 403


                if resp.get("code") in _VERIFY_TRANSPORT_CODES:
                    session.pop("pending_user_id", None)
                    session.pop("pending_email", None)
                    session.pop("pending_fingerprint", None)
                    session.pop("pending_fingerprint_detail", None)
                    session.pop("pending_link_existing", None)
                    flash("We could not confirm that code in time. Your account may "
                          "already be active — try logging in, and register again "
                          "only if that fails.", "info")
                    return redirect(url_for("user_login"))
                if resp.get("code") in (ec.PASSWORD_TOO_SHORT, ec.PASSWORD_TOO_LONG):
                    flash(_safe_error(resp, _REGISTER_ERRORS,
                                      _REGISTER_ERROR_FALLBACK), "error")
                else:
                    flash("Invalid or expired OTP. Try again or register again.", "error")
                return render_template("user_register.html", step="2", email=email,
                                       link_existing=bool(link_existing))
            user = resp.get("user") or {}
            registration_fp = session.get("pending_fingerprint") or ""
            session.clear()
            session["user_id"] = user.get("uid")
            session["username"] = user.get("username")
            session["_ip"] = _get_client_ip()
            if registration_fp:
                session["_fp"] = registration_fp
            _rotate_session()
            return _masked_redirect("user_dashboard")
    return render_template("user_register.html", step="1")


@app.route("/user/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@limiter.limit(
    "30 per hour",
    key_func=_login_target_key,
    methods=["POST"],
    deduct_when=_login_attempt_failed,
    override_defaults=False,
)
def user_login():
    if request.method == "GET" and session.get("user_id"):
        return redirect(url_for("user_dashboard"))
    if request.method == "POST":
        if _oversized_form_field():
            g._login_precheck_failed = True
            flash("Those details are too long to process.", "error")
            return render_template("user_login.html")
        u = request.form.get("username", "")
        p = request.form.get("password", "")


        fp = (request.form.get("fingerprint", "") or "").strip()
        fp_detail = _capped_fp_detail(request.form.get("fingerprint_detail", ""))

        resp = _api("POST", "/api/auth/login", json_data={
            "username": u,
            "password": p,
            "fingerprint": fp,
            "fingerprint_detail": fp_detail,
            "cf-turnstile-response": request.form.get("cf-turnstile-response", "") or "",
        })
        if resp.get("ok"):
            user = resp.get("user") or {}
            session.clear()
            session["user_id"] = user.get("uid")
            session["username"] = user.get("username")
            session["_ip"] = _get_client_ip()
            session["_fp"] = fp
            _rotate_session()
            return _masked_redirect("user_dashboard")
        if resp.get("banned"):
            return render_template("banned.html", reason=resp.get("reason", "Your account has been banned.")), 403
        flash(_safe_error(resp, _LOGIN_ERRORS, _LOGIN_ERROR_FALLBACK), "error")
    return render_template("user_login.html")


@app.route("/user/auth/github", methods=["POST"])
@limiter.limit("10 per minute", methods=["POST"])
def user_auth_github():
    # The GitHub button submits the login/register form (formaction), so the
    # fingerprint fields and CSRF token already ride along. Stash the fp and a
    # fresh OAuth state, then bounce to GitHub; the secret and token exchange
    # live entirely in the backend.
    fp = (request.form.get("fingerprint", "") or "").strip()
    fp_detail = _capped_fp_detail(request.form.get("fingerprint_detail", ""))
    # Bounce failures back to whichever page the button was clicked from
    # (login vs register) instead of always dropping the user on /user/login.
    origin = "user_register" if request.form.get("origin") == "register" else "user_login"
    # Reaching this route means the user clicked "Continue with GitHub", which
    # carries an explicit "you agree to our Terms and Privacy Policy" notice next
    # to it (clickwrap). GitHub is a self-contained path — it does not fill the
    # email form, so the separate agree_terms checkbox does not apply here.
    agreed = "1"
    state = secrets.token_urlsafe(24)
    resp = _api("POST", "/api/auth/github/start", json_data={
        "state": state,
        "cf-turnstile-response": request.form.get("cf-turnstile-response", "") or "",
    })
    if not resp.get("ok") or not resp.get("authorize_url"):
        flash(_safe_error(resp, _LOGIN_ERRORS, "GitHub sign-in is currently unavailable."), "error")
        return redirect(url_for(origin))
    session["_gh_oauth"] = {"state": state, "fp": fp, "fp_detail": fp_detail, "agreed": agreed, "origin": origin}
    return redirect(resp["authorize_url"])


@app.route("/user/auth/github/callback", methods=["GET"])
@limiter.limit("15 per minute")
def user_auth_github_callback():
    stashed = session.pop("_gh_oauth", None)
    origin = (stashed or {}).get("origin")
    if origin not in ("user_login", "user_register"):
        origin = "user_login"
    if request.args.get("error"):
        flash("GitHub sign-in was cancelled.", "error")
        return redirect(url_for(origin))
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    if not stashed or not code or not state \
            or not secrets.compare_digest(state, stashed.get("state", "")):
        flash("GitHub sign-in could not be verified. Please try again.", "error")
        return redirect(url_for(origin))
    fp = stashed.get("fp", "") or ""
    resp = _api("POST", "/api/auth/github", json_data={
        "code": code,
        "fingerprint": fp,
        "fingerprint_detail": stashed.get("fp_detail", "") or "",
        "agreed": stashed.get("agreed", "") or "",
    })
    if resp.get("ok"):
        user = resp.get("user") or {}
        session.clear()
        session["user_id"] = user.get("uid")
        session["username"] = user.get("username")
        session["_ip"] = _get_client_ip()
        session["_fp"] = fp
        _rotate_session()
        return _masked_redirect("user_dashboard")
    if resp.get("banned"):
        return render_template("banned.html", reason=resp.get("reason", "Your account has been banned.")), 403
    if resp.get("code") == "terms_required":
        flash("Please agree to the Terms of Service and Privacy Policy, then continue with GitHub.", "error")
        return redirect(url_for("user_register"))
    flash(_safe_error(resp, _LOGIN_ERRORS, "GitHub sign-in failed. Please try again."), "error")
    return redirect(url_for(origin))


@app.route("/user/logout")
def user_logout():


    sent = request.args.get("t", "")
    logout_tok = session.get(LOGOUT_TOKEN_KEY)
    if logout_tok and _tokens_equal(sent, logout_tok):
        session.pop(LOGOUT_TOKEN_KEY, None)
    elif not _tokens_equal(sent, session.get(CSRF_SESSION_KEY) or ""):
        return redirect(url_for("user_dashboard"))
    session.clear()


    return redirect(_external(SITE_URL, "index"))


_IMP_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


@app.route("/impersonate/<token>")
@limiter.limit("10 per minute; 30 per hour")
def impersonate(token):
    if not _IMP_TOKEN_RE.fullmatch(token):
        abort(404)


    resp = _api("POST", f"/api/session/{token}/consume-impersonation")
    data = resp.get("data") if resp.get("ok") else None
    if not isinstance(data, dict) or not data.get("_impersonator"):
        abort(404)
    uid = str(data.get("user_id") or "")
    if not uid:
        abort(404)
    session.clear()
    session["user_id"] = uid
    session["username"] = data.get("username") or ""
    session["_impersonator"] = data.get("_impersonator")


    session["_ip"] = _get_client_ip()
    session["_fp"] = request.headers.get("X-Device-Fingerprint") or ""
    _rotate_session()
    return _masked_redirect("user_dashboard")


def _me():

    resp = _api("GET", "/api/user/me")
    if resp.get("ok"):
        return resp.get("user")
    return None


@app.route("/user")
@user_required
def user_dashboard():
    user = _me()
    if not user:
        return redirect(url_for("user_login"))
    bots = _api("GET", "/api/user/bots").get("bots") or []
    return render_template("slots.html", user=user, bots=bots)


@app.route("/user/bot/<int:slot_index>")
@user_required
def user_bot_editor(slot_index):


    resp = _api("GET", f"/api/user/bot/{slot_index}/config")
    if not resp.get("ok"):
        abort(404)
    user = _me()
    if not user:
        return redirect(url_for("user_login"))
    return render_template("user2.html", user=user, bot=resp.get("bot"),
                           embed_templates=embed_tpl.all_templates())


@app.route("/user/bot/<int:slot_index>/replies")
@user_required
def user_bot_replies(slot_index):
    resp = _api("GET", f"/api/user/bot/{slot_index}/config")
    if not resp.get("ok"):
        abort(404)
    user = _me()
    if not user:
        return redirect(url_for("user_login"))
    return render_template("replies.html", user=user, bot=resp.get("bot"))


@app.route("/user/formatting")
@user_required
def user_formatting():
    user = _me()
    if not user:
        return redirect(url_for("user_login"))
    return render_template("discord_formatting.html", user=user)


@app.route("/nav", methods=["POST"])
@limiter.limit("30 per minute", methods=["POST"])
def nav():


    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    masked = _mask_path(path)
    if not masked:
        return ec.err(ec.NOT_FOUND, "Not found", 404)
    return {"ok": True, "url": masked}


@app.route("/<nav_code>")
def masked_page(nav_code):


    if not _NAV_CODE_RE.fullmatch(nav_code):
        abort(404)
    codes = session.get(_NAV_KEY) or {}
    path = codes.get(nav_code)
    if not path:
        abort(404)
    try:
        adapter = app.url_map.bind(request.host)
        endpoint, values = adapter.match(path, method="GET")
    except Exception:
        abort(404)
    if endpoint not in _NAV_SAFE_ENDPOINTS:
        abort(404)
    return current_app.view_functions[endpoint](**values)


_SW_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sw.js")


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon-32.png")


@app.route("/sw.js")
def sw_probe():


    host = request.host.split(":")[0].lower()
    allowed_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "endevil.live",
                    _SITE_HOST, _APEX_HOST}
    if host not in allowed_hosts and not host.endswith(".localhost"):
        abort(404)
    try:
        with open(_SW_FILE, "rb") as f:
            body = f.read()
    except OSError:
        abort(404)
    return FlaskResponse(body, content_type="application/javascript; charset=utf-8")


_ad_cache = {"value": True, "zones": None, "networks": None,
             "guard_mode": None, "consent_required": False, "pages": None,
             "at": 0.0}
_AD_CACHE_TTL = min(300.0, _env_positive_float("AD_CACHE_TTL", 45.0))


_AD_GUARD_MODES = ("gate", "warn", "off")
_AD_GUARD_MODE_DEFAULT = "gate"


_AD_PAGES_DEFAULT_OFF = frozenset((
    "user_login", "user_register",
))


@app.context_processor
def _inject_impersonator():


    return dict(impersonator=session.get("_impersonator") or None)


_CRAWLER_UA_TOKENS = (
    "googlebot",
    "mediapartners-google",
    "adsbot-google",
    "google-inspectiontool",
)

def _ad_state():


    try:
        cached = getattr(g, "_ad_state", None)
    except RuntimeError:
        cached = None
    if cached is not None:
        return cached

    now = time.time()
    if now - _ad_cache["at"] > _AD_CACHE_TTL:
        _ad_cache["at"] = now
        resp = _api("GET", "/api/settings/ad-zones")
        if resp.get("ok"):
            _ad_cache["value"] = bool(resp.get("ads_enabled"))
            _ad_cache["zones"] = resp.get("zones") or {}
            _ad_cache["networks"] = resp.get("networks")
            _ad_cache["guard_mode"] = resp.get("guard_mode")
            _ad_cache["consent_required"] = bool(resp.get("consent_required"))
            _ad_cache["pages"] = resp.get("pages")
    state = {
        "enabled": _ad_cache["value"],
        "zones": _ad_cache["zones"],
        "networks": _ad_cache["networks"],
        "guard_mode": _ad_cache["guard_mode"],
        "consent_required": _ad_cache["consent_required"],
        "pages": _ad_cache["pages"],
    }

    if state["enabled"] and session.get("user_id"):
        user_resp = _api("GET", "/api/user/ad-zones")
        if user_resp.get("ok"):
            state["enabled"] = not bool(user_resp.get("ads_disabled"))
            state["zones"] = user_resp.get("zones") or {}
            state["networks"] = user_resp.get("networks")


            if user_resp.get("pages") is not None:
                state["pages"] = user_resp.get("pages")

    try:
        g._ad_state = state
    except RuntimeError:
        pass
    return state


def _ad_page_endpoint():


    endpoint = request.endpoint
    if endpoint != "masked_page":
        return endpoint
    code = (request.view_args or {}).get("nav_code")
    target = (session.get(_NAV_KEY) or {}).get(code) or ""
    try:
        real, _values = app.url_map.bind(request.host).match(target, method="GET")
    except Exception:
        return None
    return real


def _ads_permitted():


    state = _ad_state()

    endpoint = _ad_page_endpoint()
    if endpoint is None:
        return False
    pages = state["pages"]
    if pages is None:


        return endpoint not in _AD_PAGES_DEFAULT_OFF
    if endpoint not in pages:
        return True
    return bool(pages.get(endpoint))


def _is_search_crawler():
    ua = (request.headers.get("User-Agent") or "").lower()
    if any(token in ua for token in _CRAWLER_UA_TOKENS):
        return True


    bot_name = _cf_header("CF-Verified-Bot-Name").lower()
    if bot_name in frozenset(t.lower() for t in _CRAWLER_UA_TOKENS):
        return True
    return False


@app.context_processor
def _inject_guard_mode():


    state = _ad_state()
    if not _ads_permitted() or not state["enabled"] or _is_search_crawler():
        return dict(guard_mode="off")


    return dict(guard_mode="gate")


@app.context_processor
def _inject_ad_enabled():


    state = _ad_state()
    enabled = state["enabled"]
    zones = state["zones"]
    networks = state["networks"]

    def ad_zone(key):


        if not _ads_permitted() or not enabled:
            return False
        if zones is None:
            return True
        return bool(zones.get(key, False))

    def ad_head():


        if not _ads_permitted() or not enabled:
            return Markup("")
        is_mobile = bool(request.user_agent and request.user_agent.is_mobile)
        is_auth_or_home = (
            request.path == "/"
            or request.path.startswith("/") and request.path.endswith("/")
            or request.path.startswith("/user/login")
            or request.path.startswith("/user/register")
            or request.path.startswith("/api/auth/")
            or request.path.startswith("/otp")
            or request.path.startswith("/user/otp")
        )
        effective_networks = dict(networks) if networks is not None else {k: v for k, v in ads_config.AD_NETWORKS.items() if v.get("default_on", True)}
        if is_mobile or is_auth_or_home:
            effective_networks["vignette"] = False
        return Markup(ads_config.ad_head_html(
            getattr(request, "csp_nonce", ""), effective_networks))

    def ad_scripts():


        nonce = getattr(request, "csp_nonce", "")

        is_mobile = bool(request.user_agent and request.user_agent.is_mobile)
        is_auth_or_home = (
            request.path == "/"
            or request.path.startswith("/user/login")
            or request.path.startswith("/user/register")
            or request.path.startswith("/api/auth/")
            or request.path.startswith("/otp")
            or request.path.startswith("/user/otp")
        )
        push_script = ""


        if _ads_permitted() and enabled and not is_mobile and not is_auth_or_home:
            push_script = (
                f'<script nonce="{nonce}" src="https://5gvci.com/act/files/tag.min.js?z=11694617" data-cfasync="false" async></script>'
                f'<script nonce="{nonce}">(function(s){{s.dataset.zone=\'11694505\';'
                "s.src='https://nap5k.com/tag.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>"
            )
        return Markup(
            f'<script nonce="{nonce}" '
            f'src="{url_for("static", filename="ads.js")}"></script>\n'
            f'<script nonce="{nonce}" '
            f'src="{url_for("guard_asset", token=_current_guard_token(), v="18")}" defer></script>\n'
            f"{push_script}"
        )

    def ad_unit(key):


        if not ad_zone(key):
            return ""
        is_mobile = bool(request.user_agent and request.user_agent.is_mobile)
        if is_mobile and key in {"popunder_entry", "social_bar"}:
            return ""
        unit = ads_config.AD_UNITS.get(key) or {}
        network_id = unit.get("network")
        if network_id:
            network = ads_config.AD_NETWORKS.get(network_id) or {}
            default_on = bool(network.get("default_on", True))
            if networks is not None and not bool(networks.get(network_id, default_on)):
                return ""
            if networks is None and not default_on:
                return ""
        return Markup(ads_config.ad_unit_html(key, getattr(request, "csp_nonce", "")))

    return dict(ad_enabled=enabled, ad_zone=ad_zone, ad_zones=zones or {},
                ad_head=ad_head, ad_scripts=ad_scripts, ad_unit=ad_unit)


CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "support@endevil.qzz.io").strip()


DISCORD_INVITE = os.environ.get(
    "DISCORD_INVITE", "https://discord.gg/RNVJeMKDAV").strip()


SITE_URL = os.environ.get("SITE_URL", "").strip().rstrip("/")
PANEL_URL = os.environ.get("PANEL_URL", "").strip().rstrip("/")


def _external(base, endpoint, **values):


    path = url_for(endpoint, **values)
    return base + path if base else path


_NAV_KEY = "_nav"
_NAV_CODE_RE = re.compile(r"^[0-9a-z]{1,8}$")
_NAV_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


_NAV_SAFE_ENDPOINTS = {
    "index", "blocked", "privacy", "terms", "about", "contact", "help",
    "user_dashboard",
    "user_bot_editor", "user_bot_replies", "user_formatting",
}


def _nav_rand(length=6):


    return "".join(secrets.choice(_NAV_ALPHABET) for _ in range(length))


def _mask_path(path):


    if not path or path[0] != "/" or path.startswith("//"):
        return None
    if "?" in path or "#" in path or "\\" in path:
        return None
    try:
        adapter = app.url_map.bind(request.host)
        endpoint, _values = adapter.match(path, method="GET")
    except Exception:
        return None
    if endpoint not in _NAV_SAFE_ENDPOINTS:
        return None
    codes = session.setdefault(_NAV_KEY, {})
    for code, stored in list(codes.items()):
        if stored == path:
            return "/" + code
    code = _nav_rand()


    codes.clear()
    codes[code] = path
    return "/" + code


def _masked_redirect(endpoint, **values):

    path = url_for(endpoint, **values)
    return redirect(_mask_path(path) or path)


def _host_of(url):


    return _urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()


_SITE_HOST = _host_of(SITE_URL)
_PANEL_HOST = _host_of(PANEL_URL)


_APEX_HOST = _SITE_HOST[4:] if _SITE_HOST.startswith("www.") else ""


@app.before_request
def _canonical_host():


    if not (_SITE_HOST and _PANEL_HOST) or request.method != "GET":
        return None

    host = request.host.split(":")[0].lower()
    query = quote(request.query_string, safe="!$&'()*+,;=:@/?%")
    quoted_path = quote(request.path)
    tail = f"{quoted_path}?{query}" if query else quoted_path


    if request.path == "/" and host in (_PANEL_HOST, _APEX_HOST):
        return redirect(SITE_URL + tail, code=301)

    return None


_AD_WALL_TTL = 600.0
_AD_WALL_KEY = "ad_blocked_at"


_AD_WALL_EXEMPT_PREFIXES = (
    "/blocked", "/api/", "/static/", "/assets/", "/health", "/panel", "/nav",
    "/impersonate", "/embed", "/sw.js", "/ads.txt", "/robots.txt",
    "/sitemap.xml", "/site.webmanifest",
)


def _ad_wall_active():

    at = session.get(_AD_WALL_KEY)
    if not isinstance(at, (int, float)) or isinstance(at, bool):
        return False
    if time.time() - at > _AD_WALL_TTL:


        session.pop(_AD_WALL_KEY, None)
        return False
    return True


@app.before_request
def _serve_backend_ad_wall():


    if request.method not in ("GET", "HEAD"):
        return None
    path = request.path
    if any(path == p or path.startswith(p if p.endswith("/") else p + "/")
           for p in _AD_WALL_EXEMPT_PREFIXES):
        return None
    if not _ad_wall_active():
        return None
    if _inject_guard_mode()["guard_mode"] != "gate":
        return None
    return render_template("blocked.html"), 200


@app.route("/blocked/clear", methods=["POST"])


@limiter.limit("20 per minute; 120 per hour")
def blocked_clear():


    session.pop(_AD_WALL_KEY, None)
    return "", 204


@app.context_processor
def _inject_links():


    return dict(
        discord_invite=DISCORD_INVITE,
        contact_email=CONTACT_EMAIL,
        panel_url=lambda endpoint, **kw: _external(SITE_URL, endpoint, **kw),
        site_url=lambda endpoint, **kw: _external(SITE_URL, endpoint, **kw),
        panel_host=SITE_URL,
        site_host=SITE_URL,
        panel_live=_panel_live(),
    )


def init():


    obs.init_sentry("frontend")
    internal_auth.get_internal_token()


def _waitress_tuning():

    return dict(
        host="0.0.0.0",
        port=FRONTEND_PORT,
        threads=8,
        connection_limit=200,
        channel_timeout=200,
        max_request_body_size=app.config["MAX_CONTENT_LENGTH"],
        expose_tracebacks=False,
        ident="MCStatusFrontend",
    )


def _serve_hard_close():


    from waitress import create_server

    edge_gate.register_listener_controller()

    def _spawn():
        server = create_server(app, **_waitress_tuning())
        thread = threading.Thread(target=server.run, name="waitress", daemon=True)
        thread.start()
        return server, thread

    server, thread = _spawn()
    closed = False
    while True:
        time.sleep(1.0)
        want_closed = edge_gate.should_be_closed()
        if want_closed and not closed:
            _debug_print("[frontend] edge_gate hard close: withdrawing the listener",
                  file=sys.stderr, flush=True)
            try:
                server.close()
            except Exception as exc:
                _debug_print(f"[frontend] hard close: server.close() raised "
                      f"{type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)
            thread.join(timeout=10)
            closed = True
            continue
        if closed and not want_closed:


            delay = 1.0
            while True:
                try:
                    server, thread = _spawn()
                except Exception as exc:
                    _debug_print(f"[frontend] hard close: REBIND FAILED on port "
                          f"{FRONTEND_PORT} ({type(exc).__name__}: {exc}); "
                          f"retrying in {delay:.0f}s - this process is serving "
                          f"nothing until it succeeds",
                          file=sys.stderr, flush=True)
                    time.sleep(delay)
                    delay = min(delay * 2, 30.0)
                    continue
                _debug_print("[frontend] edge_gate hard close cleared: listener rebound",
                      file=sys.stderr, flush=True)
                closed = False
                break


def serve():
    from waitress import serve as wserve
    init()
    _debug_print(f"[frontend] web server running on http://0.0.0.0:{FRONTEND_PORT}")
    _debug_print(f"[frontend] backend API: {BACKEND_URL}")
    if edge_gate.hard_close_enabled():
        _serve_hard_close()
        return
    wserve(app, **_waitress_tuning())


if __name__ == "__main__":
    serve()

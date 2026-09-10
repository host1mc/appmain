"""
engine_client.py — the backend's thin client for the engine control API.

Every call returns a `(payload, status_code)` tuple so the backend can hand the
result straight back to its own caller. A dead engine is reported as a 503
rather than raised, because most callers can still succeed partially (the
database write already happened, and the engine reconciles on its next tick).
"""

import http.cookiejar
import ipaddress
import json
import os
from urllib.parse import quote, urlsplit

import requests

import internal_auth
import error_codes as ec

ENGINE_URL = os.environ.get("ENGINE_URL", "http://127.0.0.1:8002")

# Calls that reach out to Discord / the status service need a much longer budget than
# the ones that just poke local state.
_FAST_TIMEOUT = 15
_SLOW_TIMEOUT = 60

# resp.json() reads the whole body into memory first, so a wedged or hostile
# engine could hand back a multi-gigabyte response and exhaust a backend worker
# before any parsing happens. The largest legitimate reply is a generated asset
# payload, which is kilobytes.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# One connection pool for the whole backend process. A bare requests.request()
# builds a throwaway Session -> HTTPAdapter -> PoolManager -> SSLContext
# (~240 KB) per call and drops it again; a single dashboard action can fire
# several of these. Reusing the pool saves the setup and connect cost, not
# steady RSS. pool_maxsize=8 matches the backend's waitress thread count, so the
# pool holds at most one idle socket per request thread instead of growing.
_HTTP = requests.Session()
_HTTP.headers["User-Agent"] = "MCStatusHosting"
_HTTP.mount("http://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    """One shared Session means one shared cookie jar that outlives every call.
    The engine has no reason to set a cookie on us, so refuse to store any
    rather than replay one on an unrelated request."""

    def set_ok(self, cookie, request):
        return False


_HTTP.cookies.set_policy(_NoCookies())

# Shared across waitress request threads, which is only safe because the
# session's state is set once, here at import, and never mutated per call. The
# internal token in particular stays a per-call headers= argument and is never
# stored on the session.


def _validated_engine_url(value):
    """Return a safe engine origin.

    The internal token is a bearer credential. Plain HTTP is therefore only
    safe on loopback, where the request never crosses a network interface.
    """
    candidate = (value or "").strip()
    if "?" in candidate or "#" in candidate:
        raise ValueError("ENGINE_URL must contain only an origin")
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ENGINE_URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("ENGINE_URL must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("ENGINE_URL must contain only an origin")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("ENGINE_URL contains an invalid port") from exc

    if parsed.scheme.lower() == "http":
        host = parsed.hostname.rstrip(".").lower()
        is_loopback = host == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("remote ENGINE_URL values must use HTTPS")
    return candidate.rstrip("/")


def _call(method, path, json_data=None, timeout=_FAST_TIMEOUT):
    try:
        engine_url = _validated_engine_url(ENGINE_URL)
    except ValueError:
        return {"ok": False, "code": ec.ENGINE_REQUEST_FAILED,
                "error": "Engine URL is not securely configured"}, 502
    headers = dict(internal_auth.internal_headers())
    headers["Content-Type"] = "application/json"
    try:
        resp = _HTTP.request(
            method=method,
            url=f"{engine_url}{path}",
            headers=headers,
            json=json_data if json_data is not None else {},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    except requests.Timeout:
        return {"ok": False, "code": ec.ENGINE_UNAVAILABLE,
                "error": "Engine request timed out"}, 504
    except requests.ConnectionError:
        return {"ok": False, "code": ec.ENGINE_UNAVAILABLE, "error": "Engine unavailable"}, 503
    except Exception:
        return {"ok": False, "code": ec.ENGINE_REQUEST_FAILED,
                "error": "Engine request failed"}, 502
    # Read one byte past the cap so an oversized body is detected rather than
    # silently truncated into a parse error.
    try:
        with resp:
            body = resp.raw.read(_MAX_RESPONSE_BYTES + 1, decode_content=True)
    except requests.Timeout:
        return {"ok": False, "code": ec.ENGINE_UNAVAILABLE,
                "error": "Engine request timed out"}, 504
    except Exception:
        return {"ok": False, "code": ec.ENGINE_REQUEST_FAILED,
                "error": "Engine request failed"}, 502
    if len(body) > _MAX_RESPONSE_BYTES:
        return {"ok": False, "code": ec.ENGINE_BAD_RESPONSE,
                "error": "Engine response too large"}, 502
    try:
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("engine response must be a JSON object")
        return payload, resp.status_code
    except Exception:
        return {"ok": False, "code": ec.ENGINE_BAD_RESPONSE,
                "error": "Malformed engine response"}, 502


def health():
    return _call("GET", "/engine/health")


def _bot_path(user_id, slot_index):
    """The bots store's (uid, slot) identity as URL path segments.

    Both values arrive from the dashboard, so a value holding "/", "?" or "#"
    would otherwise re-point the request at a different engine endpoint while
    still carrying the internal token.
    """
    return f"{quote(str(user_id), safe='')}/{int(slot_index)}"


def start_bot(user_id, slot_index):
    return _call("POST", f"/engine/bot/{_bot_path(user_id, slot_index)}/start")


def stop_bot(user_id, slot_index):
    return _call("POST", f"/engine/bot/{_bot_path(user_id, slot_index)}/stop")


def generate(user_id, slot_index):
    return _call("POST", f"/engine/bot/{_bot_path(user_id, slot_index)}/generate", timeout=_SLOW_TIMEOUT)


def assets(user_id, slot_index):
    return _call("POST", f"/engine/bot/{_bot_path(user_id, slot_index)}/assets", timeout=_SLOW_TIMEOUT)


def preview(embed, server_ip, server_port, edition):
    return _call("POST", "/engine/preview", json_data={
        "embed": embed,
        "server_ip": server_ip,
        "server_port": server_port,
        "edition": edition,
    }, timeout=_SLOW_TIMEOUT)

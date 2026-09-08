import os
import time
from collections import OrderedDict

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection

from .auth import _is_static, client_ip
from .config import _clamped_int, as_bool
from .security_headers import apply_panel_headers


_BUSY_TEXT = b"The panel is busy right now. Please try again shortly."
_BUSY_JSON = (
    b'{"ok": false, "error": "The panel is busy right now. '
    b'Please try again shortly."}'
)

_WS_TRY_AGAIN_LATER = 1013

_ENV_ENABLED = "PANEL_EDGE_GUARD"
_ENV_WINDOW = "PANEL_EDGE_WINDOW_SECONDS"
_ENV_HTTP_MAX = "PANEL_EDGE_HTTP_MAX"
_ENV_WS_MAX = "PANEL_EDGE_WS_MAX"
_ENV_MAX_KEYS = "PANEL_EDGE_MAX_KEYS"

_DEFAULT_WINDOW_SECONDS = 60
_DEFAULT_HTTP_MAX_REQUESTS = 6000
_DEFAULT_WS_MAX_CONNECTS = 240
_DEFAULT_MAX_KEYS = 8192


class EdgeFloodGuard:
    def __init__(self, app, *, trust_proxy: bool = False, hsts: bool = True, env=None):
        env = os.environ if env is None else env
        self.app = app
        self.trust_proxy = trust_proxy
        self.enabled = as_bool(env.get(_ENV_ENABLED, "true"), default=True)
        self.window_seconds = _clamped_int(
            env.get(_ENV_WINDOW), _DEFAULT_WINDOW_SECONDS, 1, 3600
        )
        self.http_max_requests = _clamped_int(
            env.get(_ENV_HTTP_MAX), _DEFAULT_HTTP_MAX_REQUESTS, 1, 1000000
        )
        self.ws_max_connects = _clamped_int(
            env.get(_ENV_WS_MAX), _DEFAULT_WS_MAX_CONNECTS, 1, 1000000
        )
        self.max_keys = _clamped_int(
            env.get(_ENV_MAX_KEYS), _DEFAULT_MAX_KEYS, 64, 1048576
        )
        self._hits = OrderedDict()
        self._swept_slot = -1
        self._text_headers = self._build_headers(
            hsts, "text/plain; charset=utf-8", _BUSY_TEXT
        )
        self._json_headers = self._build_headers(hsts, "application/json", _BUSY_JSON)

    def _build_headers(self, hsts: bool, content_type: str, body: bytes):
        headers = MutableHeaders()
        apply_panel_headers(headers, hsts=hsts)
        headers["Retry-After"] = str(self.window_seconds)
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body))
        return headers.raw

    def _peer_key(self, scope) -> str:
        return client_ip(HTTPConnection(scope), self.trust_proxy)

    def _over_limit(self, key: str, limit: int, now: float) -> bool:
        window = self.window_seconds
        slot = int(now // window)
        if slot != self._swept_slot:
            self._swept_slot = slot
            dead = [k for k, (s, _c, _p) in self._hits.items() if s < slot - 1]
            for k in dead:
                del self._hits[k]
        entry = self._hits.get(key)
        if entry is None:
            current = 0
            previous = 0
            while len(self._hits) >= self.max_keys:
                self._hits.popitem(last=False)
        else:
            stored_slot, stored_current, stored_previous = entry
            if stored_slot == slot:
                current = stored_current
                previous = stored_previous
            elif stored_slot == slot - 1:
                current = 0
                previous = stored_current
            else:
                current = 0
                previous = 0
        elapsed = (now - slot * window) / window
        estimate = previous * (1.0 - elapsed) + current
        if estimate >= limit:
            self._hits[key] = (slot, current, previous)
            self._hits.move_to_end(key)
            return True
        self._hits[key] = (slot, current + 1, previous)
        self._hits.move_to_end(key)
        return False

    async def _refuse_http(self, scope, send) -> None:
        if "/api/" in (scope.get("path") or ""):
            body = _BUSY_JSON
            headers = self._json_headers
        else:
            body = _BUSY_TEXT
            headers = self._text_headers
        await send({"type": "http.response.start", "status": 503, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _refuse_websocket(self, scope, receive, send) -> None:
        message = await receive()
        if message.get("type") != "websocket.connect":
            return
        extensions = scope.get("extensions") or {}
        if "websocket.http.response" in extensions:
            await send(
                {
                    "type": "websocket.http.response.start",
                    "status": 503,
                    "headers": self._text_headers,
                }
            )
            await send(
                {
                    "type": "websocket.http.response.body",
                    "body": _BUSY_TEXT,
                    "more_body": False,
                }
            )
            return
        await send({"type": "websocket.close", "code": _WS_TRY_AGAIN_LATER})

    async def __call__(self, scope, receive, send) -> None:
        scope_type = scope.get("type")
        if scope_type == "http":
            limit = self.http_max_requests
            prefix = "h:"
        elif scope_type == "websocket":
            limit = self.ws_max_connects
            prefix = "w:"
        else:
            await self.app(scope, receive, send)
            return
        if not self.enabled or _is_static(scope):
            await self.app(scope, receive, send)
            return
        if self._over_limit(prefix + self._peer_key(scope), limit, time.monotonic()):
            if scope_type == "http":
                await self._refuse_http(scope, send)
            else:
                await self._refuse_websocket(scope, receive, send)
            return
        await self.app(scope, receive, send)

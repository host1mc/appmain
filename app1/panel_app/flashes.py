"""One-shot flash messages for the mounted panel.

Flask keeps flashes in the session. The panel has no session of its own any more
— identity comes from the main site and the panel may only *read* that store, see
:mod:`panel_app.auth` — so the session is not available to queue them in, and
writing to it would mean writing into the live shared session store.

They still have to survive exactly one redirect, because every handler that
flashes answers with a 303. So they ride in their own cookie:

* :func:`queue` appends to a per-request list — nothing is written yet,
* :class:`FlashMiddleware` decodes the incoming cookie on the way in and
  serialises whatever accumulated onto the outgoing response,
* ``get_flashed_messages()`` in the template layer calls :func:`drain`, and the
  middleware then clears the cookie so a message is shown exactly once.

A cookie whose signature does not verify is dropped silently. The worst case is
a missing status banner, so this is allowed to be best-effort — which also
settles what happens behind the load balancer: if the two instances do not share
``PANEL_SECRET_KEY``, a flash set by one is unreadable by the other and dropping
it is the only sane outcome.
"""

from http.cookies import SimpleCookie

from itsdangerous import BadData, URLSafeTimedSerializer
from starlette.datastructures import MutableHeaders
from starlette.requests import Request

from .config import MOUNT_PREFIX


COOKIE_NAME = "panel_flash"

# Namespaces the signature so this cookie can never be confused with anything
# else signed by the same secret_key.
_SALT = "dchost-panel-flash"

# Long enough to cross the redirect that follows a flash, short enough that a
# stale one cannot resurface in a later session.
_COOKIE_MAX_AGE = 90

# Bounds so a burst of long node errors can never push the signed cookie past
# the ~4 KB a browser will accept (past which it is dropped whole, silently).
_MAX_MESSAGES = 5
_MAX_CATEGORY_CHARS = 32
_MAX_MESSAGE_CHARS = 300

# Ceiling on the *signed* value, because the character caps above do not imply
# one: itsdangerous escapes non-ASCII as ``\uXXXX`` before it base64s, so five
# distinct 300-character non-ASCII messages sign to ~4.8 KB. Past the per-cookie
# limit a browser discards the whole ``Set-Cookie`` silently — the flash is lost
# — and on the way there it crowds the per-domain budget the main site's session
# cookie shares, and evicting that one signs the visitor out. Leaves room for the
# name and the attribute string.
_MAX_COOKIE_VALUE_BYTES = 3072

# Where the outgoing queue, the decoded incoming list, and the "clear the cookie"
# flag are parked for the request.
_STATE_OUT = "panel_flash_out"
_STATE_IN = "panel_flash_in"
_STATE_CLEAR = "panel_flash_clear"


def _secret(config) -> str:
    """The signing key, or ``""`` when this panel has none.

    ``URLSafeTimedSerializer("")`` signs and verifies quite happily against a key
    every visitor already knows, so an empty secret is not "unsigned", it is
    "forgeable": anyone could mint a flash of their choosing into a genuine,
    correctly-TLS'd panel page. With no key there is nothing to trust, so no
    cookie is read and none is written.
    """
    return str(getattr(config, "secret_key", "") or "")


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=_SALT)


def _route_path(scope) -> str:
    """The path within the mounted panel.

    ``Mount`` does not rewrite ``scope["path"]`` — it records the prefix it
    matched in ``root_path`` and leaves the full path alone — so under the mount
    ``scope["path"]`` still reads ``/panel/static/...``.
    """
    path = scope.get("path", "") or ""
    root_path = scope.get("root_path", "") or ""
    if root_path and path.startswith(root_path):
        return path[len(root_path):] or "/"
    return path


def _text(value: str) -> str:
    """Drop anything that cannot survive a UTF-8 encode.

    A message can carry node-agent text, and ``HTMLResponse`` encodes the page it
    is rendered into as UTF-8: a lone surrogate would raise there, once per page,
    for as long as the cookie holding it lives.
    """
    return value.encode("utf-8", "replace").decode("utf-8", "replace")


def _pair(category, message):
    return [
        _text(str(category or "message")[:_MAX_CATEGORY_CHARS]),
        _text(str(message or "")[:_MAX_MESSAGE_CHARS]),
    ]


def _decode(config, raw: str):
    """Signed cookie value -> list of ``[category, message]``; ``[]`` if unusable."""
    secret_key = _secret(config)
    if not raw or not secret_key:
        return []
    try:
        data = _serializer(secret_key).loads(raw, max_age=_COOKIE_MAX_AGE)
    except BadData:
        # Tampered, expired, or signed with a different secret. Not an error worth
        # failing a page render over.
        return []
    except Exception:
        # itsdangerous does not funnel every rejection through BadData: a value
        # holding a lone surrogate raises UnicodeEncodeError straight out of
        # loads(). This runs in middleware, where the exception handlers cannot
        # turn a raise into anything better than a 500 — and it would be a 500 on
        # every single request that carried the crafted cookie.
        return []
    if not isinstance(data, list):
        return []
    return [
        _pair(item[0], item[1])
        for item in data[:_MAX_MESSAGES]
        if isinstance(item, (list, tuple)) and len(item) == 2
    ]


def _encode(config, pending) -> str:
    """Sign ``pending`` into a value short enough for a browser to keep.

    Sheds whole messages, then halves the last one, until the signed value fits
    ``_MAX_COOKIE_VALUE_BYTES``; ``""`` means not even one message fits, which the
    caller must treat as "clear the cookie" rather than "write it anyway".
    """
    secret_key = _secret(config)
    if not secret_key:
        return ""
    serializer = _serializer(secret_key)
    candidates = [[pair[0], pair[1]] for pair in pending]
    while candidates:
        value = serializer.dumps(candidates)
        if len(value) <= _MAX_COOKIE_VALUE_BYTES:
            return value
        if len(candidates) > 1:
            del candidates[-1]
        elif len(candidates[0][1]) > 1:
            candidates[0][1] = candidates[0][1][: len(candidates[0][1]) // 2]
        else:
            return ""
    return ""


def queue(request: Request, category: str, message: str) -> None:
    """Add a flash to be delivered with the response to this request."""
    state = request.scope.setdefault("state", {})
    pending = state.get(_STATE_OUT)
    if not isinstance(pending, list):
        pending = []
        state[_STATE_OUT] = pending
    if len(pending) >= _MAX_MESSAGES:
        return
    pending.append(_pair(category, message))


def drain(request: Request):
    """Take every flash delivered *with* this request, marking the cookie spent.

    Only a read that actually found something asks for the cookie to be cleared:
    a page that never renders the flash block leaves the queue intact for the
    next one, which is how Flask behaves too.
    """
    state = request.scope.setdefault("state", {})
    incoming = state.get(_STATE_IN)
    state[_STATE_IN] = []
    if not isinstance(incoming, list) or not incoming:
        return []
    state[_STATE_CLEAR] = True
    return incoming


class FlashMiddleware:
    """Carry flashes across one redirect in a short-lived signed cookie.

    Written as raw ASGI rather than ``BaseHTTPMiddleware`` for two reasons: the
    scope dict is passed straight through, so a queue a handler appended to is
    the same list this sees on the way out, and appending ``Set-Cookie`` needs
    the ``http.response.start`` message itself.
    """

    def __init__(self, app, *, config):
        self.app = app
        self.config = config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or _route_path(scope).startswith("/static"):
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        state[_STATE_OUT] = []
        state[_STATE_IN] = _decode(
            self.config, Request(scope, receive).cookies.get(COOKIE_NAME, "")
        )
        state[_STATE_CLEAR] = False

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                self._apply(state, MutableHeaders(scope=message))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _apply(self, state, headers) -> None:
        pending = state.get(_STATE_OUT) or []
        value = _encode(self.config, pending) if pending else ""
        if value:
            # Overwrites whatever came in, which is also the clear: a handler that
            # renders one flash and queues another must not replay the first.
            headers.append("set-cookie", self._cookie(value))
        elif pending or state.get(_STATE_CLEAR):
            # Either the queue was drained, or it could not be signed small enough
            # to survive. Clear either way, so an incoming flash cannot be replayed
            # on the next page.
            headers.append("set-cookie", self._cookie("", expire=True))

    def _cookie(self, value: str, *, expire: bool = False) -> str:
        cookie = SimpleCookie()
        cookie[COOKIE_NAME] = value
        morsel = cookie[COOKIE_NAME]
        # Scoped to the mount so the main site never receives it.
        morsel["path"] = MOUNT_PREFIX
        morsel["httponly"] = True
        morsel["samesite"] = "Lax"
        if expire:
            morsel["max-age"] = 0
            morsel["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        else:
            morsel["max-age"] = _COOKIE_MAX_AGE
        if self.config.session_cookie_secure:
            morsel["secure"] = True
        return cookie.output(header="").strip()

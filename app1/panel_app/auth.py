"""Authentication for the mounted panel — the main site's session, reused.

The panel has no sign-in of its own. A visitor logs in on the Flask site at
``/user/login``; that mints a server-side session and drops its raw id in the
``session`` cookie. Because ``/panel`` is served from the same host, the cookie
reaches us too, so every request here:

1. reads the sid out of that cookie,
2. resolves it through the backend tier's internal ``GET /api/session/<sid>``
   (shared-bearer ``X-Internal-Token``), which returns the session dict verbatim,
3. mirrors the identity into ``panel_users`` keyed by *the site's own user id*,
   so ``panel_servers`` / ``panel_activity`` FK to a value the site already owns.

The mirror is still a row that holds an identity, not a credential: its
``password_hash`` is the unusable ``external:oracle`` placeholder, and the main
site remains the only thing that can authenticate anyone.

Two properties of that design are load-bearing:

* every call into the backend is a **read**. The panel can neither create,
  extend nor destroy a session, so a bug here cannot corrupt the live session
  store. Sign-out is handed back to the main site (see ``routes.logout``).
* reading a session *slides its expiry forward*, which is why the resolve runs
  once per request through a short cache rather than being cached aggressively:
  the round-trip is the keep-alive for someone who only browses the panel.

Resolution happens in :class:`FlaskSessionMiddleware`, before routing, so the
per-request result is on ``request.state`` by the time any handler — or the
synchronous CSRF check, or a template render — needs it.
"""

import hmac
import ipaddress
import json
import os
import string
import sys
import threading
import time
from http import client as http_client
from urllib import error, parse, request as urlrequest

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

# Cloudflare's edge ranges and the peer test over them, shared with frontend.py so
# the two tiers cannot disagree about whether a request came through the edge. A
# leaf module importing only the standard library, so this stays clear of Flask
# and the rest of the app root; app/ is on sys.path before panel_app is imported
# (asgi_panel.py and start_panel.py both insert it).
import cf_edge
import internal_auth
# The session cookie's HMAC tag, verified with the same code the frontend signs
# with so neither tier can drift from the other's idea of a valid cookie. Another
# standard-library-only leaf from the app root, imported for the same reason as
# cf_edge above.
import session_cookie


# How many proxies of ours a request passes through before it reaches this
# process, and therefore how far from the right of X-Forwarded-For the visitor
# sits. Read from the same variable frontend.py reads, with the same default of 2
# (the Cloudflare edge and the OCI load balancer, each appending one entry), so
# the two tiers cannot disagree about who made a request. Floored at 1 because
# the value is only ever used as an index from the right, and tolerant of a
# malformed value because the panel is served directly by uvicorn in the
# deployed fleet: raising here would take the whole panel down at import over a
# typo in an operational tuning knob.
def _trusted_proxy_hops(env=None) -> int:
    raw = (os.environ if env is None else env).get("TRUSTED_PROXY_HOPS", "")
    try:
        return max(1, int(str(raw).strip()))
    except (TypeError, ValueError):
        return 2


_TRUSTED_PROXY_HOPS = _trusted_proxy_hops()


def _peer_may_forward(peer: str) -> bool:
    """Whether a forwarded address from this peer is our infrastructure's word.

    PANEL_TRUST_PROXY says an operator *intends* a proxy to be in front. It does
    not say the request that just arrived actually came through one — and without
    that second check the header is simply text the caller chose, which is what
    keys the rate limiter (security_headers.py: RateLimitMiddleware). So the peer
    must be one of two things:

    * private, loopback or link-local — the Flask tier's own panel proxy
      (frontend.py: panel_proxy, peer 127.0.0.1) and anything else inside the VCN,
      including the OCI load balancer on its private interface. This is the
      topology the deployed fleet runs today.
    * a Cloudflare edge — for a deployment where the balancer routes /panel
      straight here and Cloudflare is the immediate peer.

    A public non-Cloudflare peer means the request reached this tier from
    somewhere neither of those describes, so the chain is refused and the caller
    is attributed to its own address. Same conclusion frontend.py's
    _forwarded_chain_fault reaches, for the same reason: reporting no fault would
    let such a caller pick its own rate-limit key.
    """
    if not peer:
        return False
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return cf_edge.peer_is_cf(peer, cf_edge.EDGE_NETWORKS)


# Placeholder stored in the mirrored row. It is not a valid PBKDF2 string, so
# panel-local verify_password can never accept it — mirrored users authenticate
# only through the main site.
_EXTERNAL_PLACEHOLDER = "external:oracle"

# Header internal_auth.py authenticates service-to-service calls with.
_INTERNAL_HEADER = internal_auth.INTERNAL_HEADER

# Keys the Flask session dict uses. frontend.py writes user_id/username on login
# and CSRF_SESSION_KEY is "_csrf_token".
_FLASK_USER_ID_KEY = "user_id"
_FLASK_USERNAME_KEY = "username"
_FLASK_CSRF_KEY = "_csrf_token"

# Where the resolved session and its failure flag are parked for the request.
_STATE_SESSION = "flask_session"
_STATE_UNAVAILABLE = "flask_session_unavailable"

_HEX = frozenset(string.hexdigits)

# sid -> (expires_at, session dict or None). None is a resolved *absence*, cached
# for the same interval: a dead sid can never come back to life, because a fresh
# login always mints a new one.
_session_cache = {}
_CACHE_MAX = 4096


class LoginRequired(Exception):
    """Raised by guards when no user is in session; handled as a redirect."""

    def __init__(self, next_path: str = ""):
        super().__init__("login required")
        self.next_path = next_path


class CsrfError(Exception):
    """Raised when a state-changing request carries no valid CSRF token."""


class SessionBackendUnavailable(Exception):
    """Raised when the session store could not be reached at all.

    Distinct from "signed out" on purpose. Redirecting to the main site's login
    during a backend outage would bounce the visitor to a page that cannot log
    them in either, so this surfaces as a 503 instead of a redirect loop.
    """


class MirrorConflict(Exception):
    """Raised when the panel_users mirror row cannot be written.

    In practice this means a pre-migration row still holds the same username
    under an old integer id, and the unique index on ``lower(username)`` refuses
    the new UUID-keyed row. That is a migration that has not finished, so it is
    reported rather than worked around.
    """


# -- session resolution ----------------------------------------------------


def _valid_sid(sid: str) -> bool:
    """Whether a cookie value is shaped like a session id we would have issued.

    frontend.py mints these as ``secrets.token_hex(24)`` — 48 hex characters,
    a cross-tier contract both tiers accept identically. Checked before the
    value is ever interpolated into a URL, so an attacker-supplied cookie
    cannot walk the backend's path space or smuggle anything into the request
    line.
    """
    return bool(sid) and len(sid) <= 64 and all(char in _HEX for char in sid)


def _cache_get(sid: str):
    """Cached entry for ``sid``, or the sentinel ``False`` for "not cached"."""
    entry = _session_cache.get(sid)
    if entry is None:
        return False
    expires_at, data = entry
    if expires_at <= time.monotonic():
        _session_cache.pop(sid, None)
        return False
    return data


def _cache_put(sid: str, data, ttl: int) -> None:
    if ttl <= 0:
        return
    if len(_session_cache) >= _CACHE_MAX:
        # Drop what has already expired first; only if that frees nothing does
        # the cache get cleared outright. Unbounded growth here would be a slow
        # leak in a long-lived worker.
        now = time.monotonic()
        for stale_sid, (expires_at, _data) in list(_session_cache.items()):
            if expires_at <= now:
                _session_cache.pop(stale_sid, None)
        if len(_session_cache) >= _CACHE_MAX:
            # Resolved absences next, before any live session. A visitor may set
            # their cookie to anything hex, and each distinct junk value caches a
            # None here — so filling the cache with junk and clearing it outright
            # evicted every real session too, sending the whole fleet back to the
            # backend for its next request. Dropping an absence costs nothing but
            # one re-resolve of a sid that does not exist.
            for absent_sid, (_expires_at, cached) in list(_session_cache.items()):
                if cached is None:
                    _session_cache.pop(absent_sid, None)
        if len(_session_cache) >= _CACHE_MAX:
            # Still full, so these are all live sessions: evict the ones closest
            # to expiry rather than clearing, which would cost every one of them
            # a round-trip at the same moment.
            for old_sid, _entry in sorted(
                _session_cache.items(), key=lambda item: item[1][0]
            )[: _CACHE_MAX // 4]:
                _session_cache.pop(old_sid, None)
    _session_cache[sid] = (time.monotonic() + ttl, data)


_UNTAGGED_BUDGET_WINDOW = 60
_UNTAGGED_BUDGET_DEFAULT = 120
_UNTAGGED_LOG_INTERVAL = 60


def _untagged_resolve_budget(env=None) -> int:
    raw = (os.environ if env is None else env).get("PANEL_UNTAGGED_RESOLVE_BUDGET", "")
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return _UNTAGGED_BUDGET_DEFAULT


_UNTAGGED_BUDGET = _untagged_resolve_budget()

_untagged_lock = threading.Lock()
_untagged_window_started = None
_untagged_spent = 0
_untagged_shed_count = 0
_untagged_shed_reported = None


def _untagged_resolve_allowed() -> bool:
    global _untagged_window_started, _untagged_spent
    now = time.monotonic()
    with _untagged_lock:
        if (_untagged_window_started is None
                or now - _untagged_window_started >= _UNTAGGED_BUDGET_WINDOW):
            _untagged_window_started = now
            _untagged_spent = 0
        if _untagged_spent >= _UNTAGGED_BUDGET:
            return False
        _untagged_spent += 1
        return True


def _note_untagged_shed() -> None:
    global _untagged_shed_count, _untagged_shed_reported
    now = time.monotonic()
    with _untagged_lock:
        _untagged_shed_count += 1
        last = _untagged_shed_reported
        if last is not None and now - last < _UNTAGGED_LOG_INTERVAL:
            return
        shed = _untagged_shed_count
        window = None if last is None else int(now - last)
        _untagged_shed_count = 0
        _untagged_shed_reported = now
    since = f" in the last {window}s" if window else ""
    print(f"[panel] untagged session-cookie resolve budget spent "
          f"({_UNTAGGED_BUDGET} per {_UNTAGGED_BUDGET_WINDOW}s) — treating as "
          f"signed out rather than as an outage ({shed} request(s){since}). "
          "Routine under a forged-cookie flood; if real visitors on pre-signing "
          "cookies are affected, raise PANEL_UNTAGGED_RESOLVE_BUDGET.",
          file=sys.stderr, flush=True)


class _NoRedirects(urlrequest.HTTPRedirectHandler):
    """Refuse every redirect the backend answers with.

    ``urlopen`` follows redirects by default and copies the request headers onto
    the follow-up request, ``X-Internal-Token`` included — so a 3xx from the
    backend tier would replay the bearer the whole stack authenticates
    service-to-service on at whatever host that redirect named. Returning
    ``None`` leaves the 3xx to surface as an ``HTTPError``, which
    :func:`_fetch_session` already reports as an outage rather than a sign-out.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Built once, at import: build_opener installs the whole default handler chain
# minus the redirect handler _NoRedirects subclasses. Constructing it opens
# nothing — no request is made until this is called.
_open_backend = urlrequest.build_opener(_NoRedirects).open

# Ceiling on the session payload read back. The backend may be a remote host (see
# _backend_origin), so the body is not necessarily something this fleet produced,
# and a worker must not be able to be filled by one that streams without end.
_MAX_SESSION_BYTES = 256 * 1024


def _is_loopback(host: str) -> bool:
    host = (host or "").rstrip(".").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _backend_origin(backend_url: str) -> str:
    """The backend origin, checked before the internal bearer is handed to it.

    ``BACKEND_URL`` is operator-set, and main.py tells an operator with no local
    backend to point it at the other instance — so an unchecked value puts
    ``X-Internal-Token`` on the wire in the clear against a remote host.
    frontend.py's ``_validated_backend_url`` enforces this same contract on the
    same variable, and the two tiers must not disagree about which origin is safe
    to send it to.

    Raises :class:`SessionBackendUnavailable` rather than returning a fallback so
    a misconfiguration is a 503. It is also what keeps a scheme-less value from
    being a 500 on *every* panel request: ``Request()`` raises ValueError for a
    URL urllib cannot type, and nothing below this frame catches that.
    """
    candidate = (backend_url or "").strip()
    parsed = parse.urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SessionBackendUnavailable("BACKEND_URL is not an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise SessionBackendUnavailable("BACKEND_URL must not carry credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        # Any of these would land in front of the path appended below, so the
        # request would not reach /api/session at all.
        raise SessionBackendUnavailable("BACKEND_URL must contain only an origin")
    try:
        parsed.port
    except ValueError as exc:
        raise SessionBackendUnavailable("BACKEND_URL has an invalid port") from exc
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise SessionBackendUnavailable("a remote BACKEND_URL must use HTTPS")
    return candidate.rstrip("/")


def _fetch_session(config, sid: str):
    """Blocking read of one session from the backend tier.

    Returns the session dict, or ``None`` when the backend positively reports the
    session does not exist. Raises :class:`SessionBackendUnavailable` for anything
    else, so an outage is never mistaken for a sign-out.
    """
    origin = _backend_origin(config.backend_url)
    url = f"{origin}/api/session/{parse.quote(sid, safe='')}"
    req = urlrequest.Request(
        url,
        method="GET",
        headers={
            _INTERNAL_HEADER: config.internal_token,
            "Accept": "application/json",
            "User-Agent": "DiscordHostPanel/1.0",
        },
    )
    try:
        with _open_backend(req, timeout=4) as response:
            raw = response.read(_MAX_SESSION_BYTES + 1)
            if len(raw) > _MAX_SESSION_BYTES:
                raise SessionBackendUnavailable("session payload is too large")
            payload = json.loads(raw.decode("utf-8"))
    except error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise SessionBackendUnavailable(f"session lookup returned {exc.code}") from exc
    except (error.URLError, TimeoutError, OSError, http_client.HTTPException,
            ValueError) as exc:
        # OSError and HTTPException are here because urllib re-raises whatever
        # getresponse() throws *unwrapped* — a backend that accepts the connection
        # and then closes it, which is every backend restart, raises
        # RemoteDisconnected, and that is neither a URLError nor caught by naming
        # the decode errors individually. It escaped as a 500 on every in-flight
        # panel request instead of the 503 this function exists to produce.
        # ValueError subsumes the JSONDecodeError and UnicodeDecodeError this used
        # to name, and additionally covers http.client refusing a header value it
        # cannot latin-1 encode, i.e. a corrupted internal.key.
        raise SessionBackendUnavailable("session store is unreachable") from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        raise SessionBackendUnavailable("session lookup failed")
    data = payload.get("data")
    return data if isinstance(data, dict) else None


async def resolve_flask_session(config, request: Request):
    """Resolve the main site's session for this request.

    Returns ``(session_dict, unavailable)``. ``session_dict`` is empty for a
    visitor with no usable session; ``unavailable`` is true only when the store
    could not be consulted.
    """
    # Authenticated before it is used. The cookie carries an HMAC tag over the
    # sid (session_cookie.py), keyed on the same shared internal token this tier
    # already holds to make the lookup below — so a forged cookie is refused here
    # without the cache insert and backend round trip it would otherwise buy. The
    # frontend applies the identical check in open_session; both call the same
    # leaf module so the two tiers cannot disagree about what a valid cookie is.
    sid, untagged = session_cookie.verify_detail(
        request.cookies.get(config.session_cookie_name, ""),
        config.internal_token,
    )
    if not _valid_sid(sid):
        return {}, False
    if not config.internal_token:
        # No shared token means no lookup is even possible. Fail closed, and as
        # an outage rather than a sign-out so it shows up as a 503 worth reading
        # the logs over instead of a silent redirect to login.
        return {}, True

    cached = _cache_get(sid)
    if cached is not False:
        return cached or {}, False

    if untagged and not _untagged_resolve_allowed():
        _note_untagged_shed()
        return {}, False

    try:
        data = await run_in_threadpool(_fetch_session, config, sid)
    except SessionBackendUnavailable:
        # Deliberately not cached: the next request should retry rather than be
        # locked out for the whole cache interval.
        return {}, True
    _cache_put(sid, data, config.session_cache_seconds)
    return data or {}, False


def _is_static(scope) -> bool:
    """Whether this request is for the mounted static bundle.

    The test has to run against the path *within* the panel, because ``Mount``
    does not rewrite ``scope["path"]`` — it records the prefix it matched in
    ``root_path`` and leaves the full path alone (the same fact ``flashes``
    documents). Under the mount ``scope["path"]`` reads ``/panel/static/app.css``,
    so testing it against ``/static`` never matched and every asset on every page
    resolved a session of its own.
    """
    path = scope.get("path", "") or ""
    root_path = scope.get("root_path", "") or ""
    if root_path and path.startswith(root_path):
        path = path[len(root_path):] or "/"
    return path.startswith("/static")


class FlaskSessionMiddleware:
    """Resolve the main site's session once per request, before routing.

    This sits exactly where SessionMiddleware used to. Doing it in middleware
    rather than inside each guard is what lets the synchronous ``csrf_ok`` and
    the template layer read the token without an await, and makes the result
    independent of the order a handler happens to call things in.
    """

    def __init__(self, app, *, config):
        self.app = app
        self.config = config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or _is_static(scope):
            # Static files need no identity, and the mount is by far the busiest
            # path — resolving a session for each asset would multiply the
            # backend round-trips for nothing.
            await self.app(scope, receive, send)
            return
        data, unavailable = await resolve_flask_session(self.config, Request(scope, receive))
        state = scope.setdefault("state", {})
        state[_STATE_SESSION] = data
        state[_STATE_UNAVAILABLE] = unavailable
        await self.app(scope, receive, send)


def flask_session(request: Request) -> dict:
    """The resolved main-site session for this request; empty when signed out."""
    data = (request.scope.get("state") or {}).get(_STATE_SESSION)
    return data if isinstance(data, dict) else {}


# -- guards ----------------------------------------------------------------


async def load_user(runtime, request: Request):
    """Return the panel user dict for the signed-in visitor, or ``None``."""
    if (request.scope.get("state") or {}).get(_STATE_UNAVAILABLE):
        raise SessionBackendUnavailable("session store is unreachable")

    session = flask_session(request)
    uid = str(session.get(_FLASK_USER_ID_KEY) or "").strip()
    if not uid:
        return None

    user = await runtime.database.get_user(uid)
    if user is not None:
        return user

    # First panel visit for an account that already exists on the main site.
    # Keyed by the site's own user id, not by username: usernames are encrypted
    # at rest on the main site and the value in the session is the decrypted
    # display form, so it is not a stable key to upsert on.
    username = str(session.get(_FLASK_USERNAME_KEY) or "").strip() or uid
    return await runtime.database.ensure_user_by_id(uid, username)


async def require_user(runtime, request: Request):
    user = await load_user(runtime, request)
    if user is None:
        # The external path the visitor actually navigated to, mount prefix
        # included. Under Starlette >= 1.6 a Mounted sub-application keeps the
        # full path in scope["path"] and echoes the prefix into
        # scope["root_path"], so summing the two would double it
        # (/panel + /panel/dashboard = /panel/panel/dashboard — a 404 after login).
        # request.url.path is exactly what the browser requested, which is also
        # what ``next`` must restore.
        next_path = request.url.path
        raise LoginRequired(next_path=next_path)
    return user


# -- CSRF ------------------------------------------------------------------


def flask_csrf_token(request: Request) -> str:
    """The main site's own CSRF token for this session, or ``""``.

    Never mints one. The token lives in the session dict, which only the main
    site may write; minting here would mean a write into the live session store
    and would also hand the browser a token the main site does not recognise.
    """
    return str(flask_session(request).get(_FLASK_CSRF_KEY) or "")


def csrf_ok(request: Request, supplied: str) -> bool:
    expected = flask_csrf_token(request)
    if not isinstance(supplied, str) or not expected or not supplied:
        return False
    # Compared as bytes, not as text: compare_digest raises TypeError for a str
    # holding any non-ASCII codepoint, and both token sources can produce one —
    # Starlette latin-1-decodes header bytes, and a form field is UTF-8. Passing
    # those straight in turned a CSRF *rejection* into an unhandled 500.
    return hmac.compare_digest(
        expected.encode("utf-8", "surrogatepass"),
        supplied.encode("utf-8", "surrogatepass"),
    )


def client_ip(request: Request, trust_proxy: bool) -> str:
    peer = request.client.host if request.client else ""
    if trust_proxy and _peer_may_forward(peer):
        # A Cloudflare-written CF-Connecting-IP is the most direct answer and the
        # one frontend.py prefers, so preferring it here too keeps the two tiers
        # attributing a request to the same visitor. Same peer test as the chain
        # below, and the same public-address requirement frontend.py applies: a
        # private value here would be a caller-writable rate-limit key.
        cf = (request.headers.get("cf-connecting-ip", "") or "").strip()
        if cf and cf_edge.peer_is_cf(peer, cf_edge.HEADER_PEER_NETWORKS):
            try:
                addr = ipaddress.ip_address(cf)
            except ValueError:
                addr = None
            if addr is not None and not addr.is_private and not addr.is_loopback \
                    and not addr.is_link_local and not addr.is_multicast \
                    and not addr.is_unspecified:
                return str(addr)
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Count in from the right, by however many proxies of ours the chain
            # passed through. Each one *appends* the peer it received the request
            # from, so with N trusted hops the visitor sits N-th from the right and
            # everything further right was written by our own infrastructure about
            # itself. Taking hops[-1] unconditionally therefore returned the
            # nearest proxy rather than the visitor: on the deployed
            # Cloudflare -> OCI-balancer chain that is a Cloudflare edge address,
            # which every visitor through that PoP shares — so they all shared one
            # rate-limit bucket, and an attacker moving between PoPs got a fresh
            # one each time. TRUSTED_PROXY_HOPS is the same variable frontend.py
            # reads, so both tiers attribute a request to the same address.
            hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
            index = len(hops) - _TRUSTED_PROXY_HOPS
            if 0 <= index < len(hops):
                return hops[index]
            if hops:
                # Fewer entries than expected, which is what the Flask tier's own
                # panel proxy produces: it replaces the chain with the single
                # address it already resolved. Read the leftmost rather than
                # falling back to the peer, which would be the balancer and would
                # collapse the whole fleet into one bucket again.
                return hops[0]
    return peer or "unknown"

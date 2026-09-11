"""Security-headers middleware for the mounted panel.

Because it is attached to the panel sub-application, it runs only for ``/panel``
requests and cannot alter the host app's responses. The header set is identical
to the retired standalone Flask panel it came from, including the strict CSP
that forbids inline script/style — which is why every panel asset is an external
file under ``static/``.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse

from .auth import _is_static, client_ip


def _fetch_wants_json(request) -> bool:
    """Whether an error for this request must be JSON.

    Mirrors ``__init__._wants_json``: ``/api/`` routes always do, and so does
    any ``fetch()`` caller (q3.js posts the deploy form with
    ``X-Requested-With: fetch`` to a non-API route).
    """
    try:
        if "/api/" in request.url.path:
            return True
        return request.headers.get("x-requested-with", "").lower() == "fetch"
    except Exception:
        return False


CSP = (
    "default-src 'self'; "
    "script-src 'self' https://challenges.cloudflare.com; "
    "style-src 'self'; "
    # img-src: 'self' and data: are for panel UI. The three ad-host entries date
    # from when g7.js's probeNet() baited these hosts with <img> loads; it
    # fetches them now, so connect-src below is the directive detection depends
    # on and these are no longer load-bearing for it. Left in place rather than
    # tightened in the same change that moved the probes.
    "img-src 'self' data: https://pagead2.googlesyndication.com "
    "https://www.highperformanceformat.com "
    "https://pl29657148.effectivecpmnetwork.com; "
    "font-src 'self'; "
    # static/g7.js sends one no-cors/no-referrer GET to each of these as
    # its ad-block bait. A CSP refusal is
    # indistinguishable from a blocker's refusal, so without these hosts every
    # visitor is flagged as running an ad blocker. Exactly the bait hosts are
    # listed — the panel serves no ad units, so nothing else is off-origin.
    "connect-src 'self' https://pagead2.googlesyndication.com "
    "https://www.highperformanceformat.com "
    "https://pl29657148.effectivecpmnetwork.com; "
    "form-action 'self'; "
    # The Turnstile widget renders its challenge in an iframe from this host.
    # Without an explicit frame-src it falls back to default-src 'self' and the
    # challenge is blocked, so the widget can never solve.
    "frame-src https://challenges.cloudflare.com; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)


def apply_panel_headers(headers, *, hsts: bool, static: bool = False, versioned: bool = False) -> None:
    """Write the panel's header set onto ``headers``.

    A plain function rather than only middleware logic because an unhandled
    exception never reaches this middleware: Starlette serves that through
    ``ServerErrorMiddleware``, which is installed *above* the whole user
    middleware stack, so a 500 unwinds past this class and used to be the one
    panel response with no CSP, no nosniff and no HSTS on it. The ``Exception``
    handler in ``__init__`` calls this directly to close that gap.
    """
    headers["Content-Security-Policy"] = CSP
    headers["X-Frame-Options"] = "DENY"
    headers["X-Content-Type-Options"] = "nosniff"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    headers["Cross-Origin-Opener-Policy"] = "same-origin"
    headers["Server"] = "endhost"
    if hsts:
        # This is the only HSTS /panel can carry: frontend.py returns early
        # for the panel proxy, so none of the Flask tier's headers — its own
        # HSTS included — reach a panel response. Gating this on the
        # secure-cookie flag therefore left the panel with no HSTS whenever
        # that flag was off, which is the default.
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # Panel content is per-user; only the static bundle is cacheable.
    if static:
        # A request carrying templating.static_version's token is asking for one
        # specific revision of the file: the token is a hash of the bytes, so that
        # URL can never come to mean different bytes and there is nothing for the
        # browser to revalidate. Anything else keeps the conservative hour —
        # static_version emits a bare URL when it cannot read the file, and a
        # transient read failure must not pin a stale copy in a cache for a year.
        if versioned:
            headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
        else:
            headers.setdefault("Cache-Control", "public, max-age=3600")
    else:
        headers["Cache-Control"] = "no-store"


class PanelSecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts: bool = True):
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        static = "/static/" in request.url.path
        apply_panel_headers(
            response.headers,
            hsts=self.hsts,
            static=static,
            versioned=static and bool(request.query_params.get("v")),
        )
        return response


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject over-large uploads, mirroring the Flask panel's 3 MB cap.

    Enforced from the Content-Length header so an oversized body is refused
    before it is streamed into memory. Uploads to ``/api`` get a JSON hint to
    upload files one at a time; other routes get a plain 413.
    """

    def __init__(self, app, *, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request, call_next):
        length = request.headers.get("content-length")
        if length is None:
            # A bodied request that declares no length (Transfer-Encoding:
            # chunked) cannot be measured up front, so it used to skip the cap
            # entirely: Starlette's multipart parser spooled it to the instance's
            # temp filesystem and api_extract then read the whole archive into
            # one bytes object. Refuse it instead — every legitimate panel client
            # sends a length.
            too_big = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        else:
            try:
                declared = int(length)
            except ValueError:
                # A length that is not a number is a malformed request, not a
                # small one. Failing open here let it through unmeasured.
                too_big = True
            else:
                # A negative length is malformed the same way, and comparing it
                # against the cap alone would read it as small and admit it.
                too_big = declared < 0 or declared > self.max_bytes
        if too_big:
            limit_mb = max(1, self.max_bytes // (1024 * 1024))
            if _fetch_wants_json(request):
                return JSONResponse(
                    {"ok": False, "error": f"upload exceeds the {limit_mb} MB panel limit — upload files one at a time"},
                    status_code=413,
                )
            return PlainTextResponse("Payload too large", status_code=413)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window cap on panel requests, per identity.

    The panel had no limit of any kind, so a single signed-in account could loop
    ``/reinstall`` — a full dependency install each time — or ``/command``,
    ``/upload`` and ``/extract``. Each of those occupies a threadpool worker for
    as long as the node takes to answer, so a few dozen concurrent calls stalled
    every other user's page. Reads are not exempt any more, only cheaper: every
    panel GET still costs a session resolve and often a node-agent call, so a GET
    flood is throttled too — but under a separate, looser ceiling
    (``get_max_requests``) so ordinary status and log polling never trips it.

    Counters are per-process and the fleet runs two instances, so the effective
    fleet-wide ceiling is twice ``max_requests``. That is fine for a backstop;
    coordinating it through the database would put a write on every request.
    """

    def __init__(self, app, *, max_requests: int = 60, get_max_requests: int = 600,
                 window_seconds: int = 60, max_keys: int = 4096, trust_proxy: bool = False):
        super().__init__(app)
        self.max_requests = max_requests
        # A deliberately higher bar for reads. They are cheaper than a mutating
        # call but not free — each one resolves the session and often reaches the
        # node — so a read flood still has to be capped, just far above what the
        # panel's own polling (status + logs, a handful a second per open page)
        # could ever reach. Sized so a genuine user never meets it and a loop
        # does within a window.
        self.get_max_requests = get_max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.trust_proxy = trust_proxy
        self._hits = {}
        # The window the dead-key sweep last ran for. The sweep drops entries
        # from elapsed windows, but only when the window actually rolls over —
        # see dispatch — so it is amortised to once per window rather than a scan
        # on every request.
        self._swept_window = -1

    def _identity(self, request) -> str:
        # Prefer the resolved panel user so one account cannot spread its load
        # across addresses. FlaskSessionMiddleware is registered outside this
        # one, so it has already stashed the session under scope["state"] by the
        # time a request gets here; read it the same way auth.flask_session does
        # rather than re-deriving it here.
        session = (request.scope.get("state") or {}).get("flask_session")
        if isinstance(session, dict):
            user_id = str(session.get("user_id") or "").strip()
            if user_id:
                return f"user:{user_id}"
        # Anonymous requests have only an address to key on, and behind the load
        # balancer every one of them arrives from the balancer's own socket — so
        # keying on request.client alone put the whole internet in one bucket,
        # where a single client could spend the window and lock everyone else
        # out. client_ip reads the forwarded address, but only when trust_proxy
        # says a proxy is actually in front: an X-Forwarded-For the client can
        # forge is worse than a shared bucket, because then it evades the
        # counter entirely by rotating a fake value.
        return f"addr:{client_ip(request, self.trust_proxy)}"

    def _refuse(self, request):
        retry_after = str(self.window_seconds)
        if _fetch_wants_json(request):
            return JSONResponse(
                {"ok": False, "error": "too many requests — slow down"},
                status_code=429,
                headers={"Retry-After": retry_after},
            )
        return PlainTextResponse(
            "Too Many Requests", status_code=429, headers={"Retry-After": retry_after}
        )

    async def dispatch(self, request, call_next):
        if _is_static(request.scope):
            return await call_next(request)
        # Reads and writes share the counter table and the fixed window but are
        # measured against different ceilings: the strict one still guards the
        # mutating verbs that each pin a worker on a node call, while GET/HEAD/
        # OPTIONS get the looser get_max_requests so normal polling never trips
        # but a flood of them — every one a session resolve, often a node hit —
        # still meets a wall.
        #
        # The two get *separate* buckets, via the prefix on the key: one shared
        # counter compared against two different ceilings would let a burst of
        # cheap reads spend the mutating allowance, so a user who had polled a
        # page a hundred times would be refused their first save. Counting them
        # apart is also what keeps the mutating limit exactly the limit it was.
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            limit = self.get_max_requests
            key = "r:" + self._identity(request)
        else:
            limit = self.max_requests
            key = "w:" + self._identity(request)
        window = int(time.monotonic() // self.window_seconds)
        # Amortised eviction: once per window, drop every key whose bucket is not
        # the current window — they can only be from an elapsed one, since a
        # bucket is only ever written as the window it was counted in, so they are
        # dead weight now. This bounds the table to the keys actually seen within
        # one window instead of letting a flood from many addresses accumulate a
        # key each forever. Guarded to fire only on the window rollover so it is
        # not a scan on every request.
        if window != self._swept_window:
            self._swept_window = window
            dead = [k for k, (b, _c) in self._hits.items() if b != window]
            for k in dead:
                del self._hits[k]
        if key not in self._hits and len(self._hits) >= self.max_keys:
            # A single window can still admit more distinct keys than the sweep
            # bounds — a burst from thousands of addresses inside one window. So
            # the table stops admitting *new* identities at the cap rather than
            # clearing: clearing let a flood of rotating addresses wipe the very
            # counter that was holding it back, handing it a fresh window on
            # demand. Keys already counted keep counting.
            return self._refuse(request)
        bucket, count = self._hits.get(key, (window, 0))
        if bucket != window:
            bucket, count = window, 0
        # Stop incrementing at the limit so a client that keeps hammering cannot
        # push its own counter into overflow territory.
        self._hits[key] = (bucket, min(count + 1, limit))
        if count >= limit:
            return self._refuse(request)
        return await call_next(request)

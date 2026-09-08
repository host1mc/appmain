"""Mountable panel sub-application.

``create_panel_app`` builds a fully self-contained Starlette app: its own
strict-CSP + body-size middleware, its own static mount, and its own exception
handlers. It is served as a separate ASGI process (``asgi_panel.py`` under
uvicorn), which builds a bare host app whose only job is to mount this panel at
``/panel`` — so none of it touches the Flask tiers at all.

It has no session cookie of its own. Identity comes from the main Flask site's
session, resolved per request by ``auth.FlaskSessionMiddleware`` — see
:mod:`panel_app.auth` — which is also why the panel has no login route: an
unauthenticated visitor is redirected to the main site to sign in.

Nothing here opens a network connection at mount time: the node client is
constructed lazily-usable (no request is made until a route runs), and SQLite is
created on first use. The Oracle store (``panel_app.database``) owns its own
async engine pointed at the same database the app tiers use; it is built lazily
and reached only by a request that actually runs a query.

With ``PANEL_STORE=oracle`` (the default when ``ORACLE_ENABLED`` is true) the
panel's three tables are registered on the panel's own declarative ``Base`` at
mount time. Registering is not creating: the DDL in this tier lives in
:func:`panel_app.database.ensure_schema`, which the panel tier's lifespan calls at
startup — it creates a panel table the schema is missing and adds a column an
older table predates, and issues nothing when the schema already matches the
models. Mounting the panel therefore never creates a table, and the host app's
``init_db()`` does not either — it runs column and encryption migrations over its
own tables and holds no declarative metadata at all.
"""

import logging
from urllib.parse import quote

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from pathlib import Path

from . import auth, backend_store, flashes
from .config import MOUNT_PREFIX, PanelConfig
from .edge import EdgeFloodGuard
from .maintenance import MaintenanceMiddleware
from .node_client import NodeClientError
from .routes import build_routes
from .runtime import PanelRuntime
from .security_headers import (
    MaxBodySizeMiddleware,
    PanelSecurityHeadersMiddleware,
    RateLimitMiddleware,
    apply_panel_headers,
)


# The mount surface. Everything else this module imports is an implementation
# detail that happens to be reachable as ``panel_app.<name>``.
__all__ = ["create_panel_app", "mount_panel", "MOUNT_PREFIX", "PanelConfig"]


_log = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).resolve().parent / "static"

# Where the main site serves its sign-in form. The panel has no login of its own,
# so every guard failure hands the visitor over to this path on ``main_site_url``.
MAIN_SITE_LOGIN_PATH = "/user/login"

_BUSY_RETRY_AFTER_SECONDS = 5


def _exception_handlers(config: PanelConfig):
    async def on_login_required(request, exc):
        if "/api/" in request.url.path:
            # A 303 is followed by fetch() and answered with the main site's login
            # *page*, so the caller saw a 200 whose body is HTML: q4.js showed
            # the first 200 characters of that page to the user as the error text,
            # q1.js reported a bare "Request failed", and q2.js's poll
            # threw on the JSON parse and silently stopped updating. The session
            # the panel borrows expires in minutes, so that is the ordinary state
            # of any tab left open rather than an edge case.
            return JSONResponse(
                {"ok": False, "error": "Your session has expired — sign in again."},
                status_code=401,
            )
        target = f"{config.main_site_url}{MAIN_SITE_LOGIN_PATH}"
        next_path = getattr(exc, "next_path", "")
        if next_path:
            # The main site's user_login does not read ``next`` today, so this is
            # carried for when it does rather than being relied on. Sending it
            # costs nothing and an unread query parameter is harmless.
            target = f"{target}?next={quote(next_path, safe='/')}"
        return RedirectResponse(target, status_code=303)

    async def on_csrf_error(request, exc):
        if "/api/" in request.url.path:
            return JSONResponse({"ok": False, "error": "invalid CSRF token"}, status_code=400)
        return PlainTextResponse("Bad Request: invalid CSRF token", status_code=400)

    async def on_session_unavailable(request, exc):
        # Not a redirect to login: the tier that would serve that login is the
        # same one that just failed, so bouncing there would only loop.
        message = "Sign-in is temporarily unavailable. Please try again shortly."
        if "/api/" in request.url.path:
            return JSONResponse({"ok": False, "error": message}, status_code=503)
        return PlainTextResponse(message, status_code=503)

    async def on_mirror_conflict(request, exc):
        message = (
            "This account cannot be linked to the panel yet. "
            "Please contact support."
        )
        if "/api/" in request.url.path:
            return JSONResponse({"ok": False, "error": message}, status_code=409)
        return PlainTextResponse(message, status_code=409)

    async def on_backend_store_busy(request, exc):
        if request.scope["type"] != "http":
            raise exc
        message = "The panel is busy right now. Please try again shortly."
        retry_after = getattr(exc, "retry_after", None)
        if not isinstance(retry_after, int) or retry_after < 1:
            retry_after = _BUSY_RETRY_AFTER_SECONDS
        headers = {"Retry-After": str(retry_after)}
        if "/api/" in request.url.path:
            return JSONResponse(
                {"ok": False, "error": message}, status_code=503, headers=headers
            )
        return PlainTextResponse(message, status_code=503, headers=headers)

    async def on_pool_timeout(request, exc):
        if request.scope["type"] != "http":
            raise exc
        message = "The panel is busy right now. Please try again shortly."
        headers = {"Retry-After": str(_BUSY_RETRY_AFTER_SECONDS)}
        if "/api/" in request.url.path:
            return JSONResponse(
                {"ok": False, "error": message}, status_code=503, headers=headers
            )
        return PlainTextResponse(message, status_code=503, headers=headers)

    async def on_node_unavailable(request, exc):
        # node_router raises this when the NODES table holds no enabled row, or
        # when every address on the row it did find refused the connection. Every
        # server-scoped route reaches its node through that router, and only some
        # of them caught it, so taking a node's address out of the table answered
        # the rest with a 500 and a task-group traceback per request — for a
        # condition the operator caused deliberately and the owner can do nothing
        # about. The routes that can say something better than this still catch it
        # themselves; this is the floor under all of them.
        if request.scope["type"] != "http":
            # No HTTP response can be sent on a WebSocket scope — console_socket
            # closes with its own code instead.
            raise exc
        _log.warning("node unavailable on %s: %s", request.url.path, exc)
        # Fixed text, not str(exc): the router's messages name the panel's own
        # tables and tell the reader to register a node, which is operator
        # instruction leaking to whoever provoked the error. The reason stays in
        # the log above.
        message = "The hosting node is unavailable right now. Please try again shortly."
        status = getattr(exc, "status", 502)
        if not isinstance(status, int) or not 400 <= status <= 599:
            status = 502
        if "/api/" in request.url.path:
            return JSONResponse({"ok": False, "error": message}, status_code=status)
        return PlainTextResponse(message, status_code=status)

    async def on_http_exception(request, exc):
        detail = getattr(exc, "detail", None) or str(exc.status_code)
        if "/api/" in request.url.path:
            return JSONResponse({"ok": False, "error": detail}, status_code=exc.status_code)
        return PlainTextResponse(detail, status_code=exc.status_code)

    async def on_unhandled(request, exc):
        # Registering this at all is what puts security headers on a 500. Starlette
        # serves an unhandled exception through ServerErrorMiddleware, which is
        # installed *above* the whole user middleware stack, so the response never
        # unwinds through PanelSecurityHeadersMiddleware: before this handler
        # existed, the one panel response an attacker can most easily provoke was
        # also the only one with no CSP, no nosniff and no HSTS on it. Hence the
        # explicit apply_panel_headers call — the middleware cannot reach here.
        # Starlette re-raises after this returns, so the traceback still reaches
        # the logs; only the client-facing body is replaced, and it is a fixed
        # string so no exception text leaks the internal host, path or query.
        message = "Internal Server Error"
        if "/api/" in request.url.path:
            response = JSONResponse({"ok": False, "error": message}, status_code=500)
        else:
            response = PlainTextResponse(message, status_code=500)
        apply_panel_headers(response.headers, hsts=config.hsts)
        return response

    handlers = {
        auth.LoginRequired: on_login_required,
        auth.CsrfError: on_csrf_error,
        auth.SessionBackendUnavailable: on_session_unavailable,
        auth.MirrorConflict: on_mirror_conflict,
        backend_store.BackendStoreBusy: on_backend_store_busy,
        NodeClientError: on_node_unavailable,
        HTTPException: on_http_exception,
        Exception: on_unhandled,
    }
    if config.store == "oracle":
        from sqlalchemy.exc import TimeoutError as PoolCheckoutTimeout

        handlers[PoolCheckoutTimeout] = on_pool_timeout
    return handlers


def create_panel_app(
    config: PanelConfig = None, *, node_client=None, store=None, session_factory=None
) -> Starlette:
    config = config or PanelConfig.from_env()
    runtime = PanelRuntime(
        config, node_client=node_client, store=store, session_factory=session_factory
    )

    if config.store == "oracle":
        # Import (not connect) so panel_users / panel_servers / panel_activity are
        # on Base.metadata before anything reads it — a query, or the
        # ensure_schema call in the panel tier's lifespan, which mounting does not
        # make: mounting this app into a host that never runs that lifespan gets a
        # panel whose tables are assumed to exist.
        from . import oracle_models  # noqa: F401

    routes = build_routes(runtime, config)
    routes.append(Mount("/static", app=StaticFiles(directory=str(_STATIC_DIR)), name="static"))

    middleware = [
        Middleware(EdgeFloodGuard, trust_proxy=config.trust_proxy, hsts=config.hsts),
        # Headers first among these, so every response carries them —
        # including the 413 and 429 that the two middlewares below return
        # without ever reaching a route.
        Middleware(PanelSecurityHeadersMiddleware, hsts=config.hsts),
        Middleware(MaxBodySizeMiddleware, max_bytes=config.max_content_length),
        # Before the session middleware, so a maintenance window costs no session
        # resolve and a signed-out visitor is shown the maintenance page instead
        # of being bounced to the main site's login — which would only send them
        # back here. Inside the header middleware above, so the refusal it
        # returns still carries the panel's CSP and no-store.
        Middleware(MaintenanceMiddleware, runtime=runtime),
        Middleware(auth.FlaskSessionMiddleware, config=config),
        # After the session so the limiter can key on the panel user rather than
        # the client address, which the load balancer collapses.
        Middleware(RateLimitMiddleware, trust_proxy=config.trust_proxy),
        Middleware(flashes.FlashMiddleware, config=config),
    ]

    panel_app = Starlette(
        routes=routes,
        middleware=middleware,
        exception_handlers=_exception_handlers(config),
    )
    panel_app.state.panel_runtime = runtime
    panel_app.state.panel_config = config
    return panel_app


def mount_panel(
    app, config: PanelConfig = None, *, node_client=None, store=None, session_factory=None
) -> Starlette:
    """Mount the panel sub-application at ``/panel`` on the given host app."""
    panel_app = create_panel_app(
        config, node_client=node_client, store=store, session_factory=session_factory
    )
    app.mount(MOUNT_PREFIX, panel_app, name="panel")
    return panel_app

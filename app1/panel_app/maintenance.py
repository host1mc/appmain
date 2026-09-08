"""The gate that closes the panel while maintenance mode is on.

The ``maintenance`` flag has been in the shared settings table since the panel's
controls moved out of the environment, but it only ever refused *writes*: every
page still rendered — with a banner on top — and the live console still attached.
That is the wrong shape for the case the switch exists for. An operator flips it
because the panel's own dependencies are moving (a migration over the panel
tables, a node agent being replaced), and a read is not harmless then: the
dashboard keeps polling the node, the file manager keeps listing a container
mid-move, and a user watching either has no way to tell that the figures in front
of them have stopped meaning anything.

So the flag now closes the tier. This middleware runs for every request the panel
serves and, while maintenance is on, hands browsers to the standalone
``/panel/maintenance`` page and refuses the rest:

* **Static assets pass**, because the maintenance page is served from this same
  mount and links ``app.css`` — gating it would leave the page unstyled.
* **The maintenance page passes**, or the redirect to it would loop.
* **JSON APIs get 503 with Retry-After**, not a redirect: ``fetch`` follows a 303
  and would then parse an HTML page as JSON, so a tab left open across the
  window would report a parse error instead of the outage. It is the same shape
  ``routes.maintenance_block`` already returns, carrying the same operator text.
* **Websockets are closed** without being accepted, so the console cannot hold an
  open pipe into a container for the length of the window.

Where it sits in the stack is load-bearing both ways. Inside the security-headers
middleware, so a refusal still carries the panel's CSP and ``no-store``; outside
the session middleware, so it costs no session resolve and a signed-out visitor
is shown the maintenance page rather than bounced to the main site's login — a
login that would only send them back here.

It fails open on purpose. ``SettingsReader.load`` already resolves to
``maintenance: False`` when the settings table cannot be read, and the ``except``
below covers anything it does not: refusing every request on a failed read would
turn a database blip into a total outage, and of the one page whose job is to
explain outages.
"""

from starlette.responses import JSONResponse, RedirectResponse

from .config import MOUNT_PREFIX


# The page this middleware forwards to, and the route in ``routes.build_routes``
# that serves it. Shared rather than written twice so the path the gate lets
# through is by construction the path it redirects to.
MAINTENANCE_PATH = "/maintenance"
MAINTENANCE_URL = f"{MOUNT_PREFIX}{MAINTENANCE_PATH}"

# 1013 "try again later" is the closest the websocket close codes come to a 503:
# it tells a client to back off rather than reconnect straight into the wall.
# q1.js reconnects the console on a timer, so the code is what stops the window
# from being spent on a reconnect loop.
WS_CLOSE_TRY_LATER = 1013

# Matches the Retry-After on routes.maintenance_block's 503, so an API client
# sees one backoff hint for maintenance however it is refused. The maintenance
# page's own 503 carries it too — hence public rather than private to this module.
RETRY_AFTER_SECONDS = "120"


def _panel_path(scope) -> str:
    """The request path within the panel, with the mount prefix stripped.

    ``Mount`` records the prefix it matched in ``root_path`` and leaves
    ``scope["path"]`` holding the full path — the same fact ``auth._is_static``
    documents — so under the mount this reads ``/panel/maintenance`` and a
    comparison against ``MAINTENANCE_PATH`` has to remove the prefix first.
    """
    path = scope.get("path", "") or ""
    root_path = scope.get("root_path", "") or ""
    if root_path and path.startswith(root_path):
        path = path[len(root_path):] or "/"
    return path


def _always_served(path: str) -> bool:
    """Whether this path is served even with the panel closed.

    ``/favicon.ico`` is here because a browser fetches it on its own, unprompted
    by any page: answering that with a redirect to an HTML page would have the
    tab request the maintenance page a second time for no reason. The route
    returns an empty 204 in any case, so there is nothing behind it to close.
    """
    return path.startswith("/static") or path in {MAINTENANCE_PATH, "/favicon.ico"}


class MaintenanceMiddleware:
    """Refuse every panel path but the maintenance page while the flag is on.

    Raw ASGI rather than ``BaseHTTPMiddleware`` because that class hands any
    non-HTTP scope straight to the app it wraps: the console websocket would have
    passed through untouched, which is the one connection a maintenance window
    least wants left open.
    """

    def __init__(self, app, *, runtime):
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        path = _panel_path(scope)
        if _always_served(path):
            await self.app(scope, receive, send)
            return
        settings = await self._closed_settings()
        if settings is None:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            # Closed without accepting, which turns the handshake itself down and
            # reaches the client as a failed upgrade. Accepting first would open a
            # socket into a tier that is shut, only to close it a moment later.
            await send({"type": "websocket.close", "code": WS_CLOSE_TRY_LATER})
            return
        await self._refusal(path, settings)(scope, receive, send)

    async def _closed_settings(self):
        """The settings snapshot when maintenance is on, else ``None``.

        The snapshot rather than a bool because the refusal below quotes the
        operator's own message, and this read is the one that already has it —
        loading it twice would be two cache lookups for one decision.
        """
        try:
            settings = await self.runtime.settings.load()
        except Exception:
            # See the module docstring: an unanswerable read leaves the panel
            # serving. load() does not normally raise, and this covers the case
            # where it does.
            return None
        return settings if settings.maintenance else None

    def _refusal(self, path, settings):
        if path.startswith("/api/"):
            return JSONResponse(
                {"ok": False, "error": settings.maintenance_message},
                status_code=503,
                headers={"Retry-After": RETRY_AFTER_SECONDS},
            )
        # 303 for every method, so a form post lands on the page as a GET instead
        # of the browser re-submitting it there.
        return RedirectResponse(MAINTENANCE_URL, status_code=303)

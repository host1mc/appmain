"""
asgi_panel.py — the panel tier: its ASGI application and its uvicorn launcher.

The panel is the one tier that is not a Flask app. Its code lives in its own
tree, the ``panel_app`` package beside this file, as a Starlette sub-application,
so this module plays both of the roles the other tiers split across two files: it
builds the app (like frontend.py) and exposes the `application` an ASGI server
hands requests to (like wsgi_frontend.py). start_panel.py is the thin launcher on
top.

Because it is ASGI rather than WSGI, neither waitress nor gunicorn's default
worker can serve it:

    gunicorn -k uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000 asgi_panel:application

which is exactly the argv main.py builds for this tier under WSGI_SERVER=gunicorn.
The default path is serve() below, which runs uvicorn directly — this tier's
equivalent of the waitress call in every other start_*.py.

Only /panel is served. The panel is a self-contained stack now: its own async
engine (panel_app.database), its own storage, its own routes. Identity still
comes from the Flask site's session — the panel has no login of its own — which
is why start order keeps it behind the backend tier that owns the session store.

The panel's *code* is fully under ``panel_app`` and needs nothing from the old
fastapi-oracle-app tree on sys.path. Two deployment artifacts still live there,
though, because they are shared with the rest of the stack and must not be
duplicated: the live ``.env`` (the Oracle credentials the whole product uses) and
``Wallet_ATP`` (the wallet the driver connects with). So three things happen
before the panel package is imported:

1. That .env is loaded explicitly, by absolute path. Nothing else does it in
   time: PanelConfig and panel_app.database both read os.environ, and in a
   panel-only process there is no reason anything else would have loaded it
   first. Skip this and the panel never sees ORACLE_ENABLED, so it silently falls
   back to a per-instance SQLite store — two instances, two sets of servers.
   load_dotenv never overrides a real environment variable, so whatever main.py
   passed down still wins.
2. ORACLE_WALLET_DIR is pinned to an absolute path. panel_app.database resolves
   it against the cwd, and the deployed value is relative to the tree that holds
   the wallet — but main.py starts every tier with cwd=app/, so a bare relative
   value would look for the wallet in the wrong place. Resolving it here (rather
   than chdir-ing the whole process into that tree) keeps cwd at app/, which is
   where internal_auth's data/ and the panel's own data/ are anchored.
3. The shared internal token is resolved through internal_auth and handed to the
   config directly. The panel resolves every visitor's session through the
   backend's internal API, and the panel's own config reads that token from
   INTERNAL_TOKEN or data/internal.key only — it never consults the systemd
   credential, and it deliberately never mints one, since a token the Flask tiers
   do not know would fail every lookup with no clue why. Passing internal_auth's
   answer is what makes the two agree on a host that keeps it in a credential.
   It goes into a copy of the environment, not os.environ: a credential exists
   precisely so the secret is not readable from /proc for this process.

Run: python start_panel.py
"""

import os
import sys
import asyncio
import warnings

warnings.filterwarnings("ignore")

def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass
import contextlib
from contextlib import asynccontextmanager

ROOT = os.path.dirname(os.path.abspath(__file__))
# Not a code path any more — only the home of the shared .env and wallet.
FASTAPI_ROOT = os.path.join(ROOT, "fastapi-oracle-app")

# app/ carries internal_auth, creds, and the panel_app package. Nothing from the
# fastapi-oracle-app tree is imported, so it is deliberately not on sys.path.
sys.path.insert(0, ROOT)

from dotenv import load_dotenv

# An explicit path, not find_dotenv(): that walks up from *this* file, which is
# app/, and would never look into the tree that owns the shared .env.
load_dotenv(os.path.join(FASTAPI_ROOT, ".env"))

# Pin the wallet to an absolute path before the panel's Oracle store imports its
# engine. A relative deployed value is relative to the tree that holds the wallet;
# resolving it here means no process-wide chdir is needed to find it.
_wallet = (os.environ.get("ORACLE_WALLET_DIR", "") or "").strip()
if not _wallet:
    _wallet = "Wallet_ATP"
if not os.path.isabs(_wallet):
    _wallet = os.path.join(FASTAPI_ROOT, _wallet)
os.environ["ORACLE_WALLET_DIR"] = os.path.abspath(_wallet)

import internal_auth  # noqa: E402  (sys.path is set up above)

from panel_app import mount_panel  # noqa: E402
from panel_app.config import MOUNT_PREFIX, PanelConfig  # noqa: E402

from starlette.applications import Starlette  # noqa: E402


# One config for the process, built from an environment copy carrying the token.
_ENV = dict(os.environ)
_ENV["INTERNAL_TOKEN"] = internal_auth.get_internal_token()
_CONFIG = PanelConfig.from_env(_ENV)

if _CONFIG.session_cache_seconds == 0:
    _debug_print(
        "[panel] WARNING: the effective PANEL_SESSION_CACHE_SECONDS is 0 — the "
        "per-process session cache is off, so every panel request resolves its "
        "session through the backend and the backend resolves it against the "
        "database. That makes flood-equivalent session-resolve load the steady "
        "state, on the one path every request takes. The value is honoured exactly "
        "as set: 0 is a legitimate setting while a stale session is being debugged, "
        "so set it back to a non-zero number of seconds once you are done.",
        file=sys.stderr,
    )

_WILDCARD_HOSTS = ("", "0.0.0.0", "::", "[::]", "*")

# uvicorn's own defaults, overridden for reasons that are specific to this tier —
# see serve() for what each one is protecting.
_PANEL_PORT_DEFAULT = "8000"
_PANEL_BIND_DEFAULT = "127.0.0.1"


@asynccontextmanager
async def _lifespan(_app):
    """Bring the panel's schema up to date, then hold the Oracle engine open.

    ensure_schema() creates a panel table this schema does not have and adds a
    column an older one is missing; both halves are additive, race-tolerant and
    a no-op once the schema matches the models, so it runs on every start rather
    than behind PANEL_INIT_DB. It has to: create_all checks at table level only,
    so a panel_servers table built before desired_state existed never gained it
    and every page that lists servers answered ORA-00904 until a migration was
    run by hand. close_db() disposes the connection pool on shutdown. With the
    SQLite store there is no async engine at all — the store builds its own file,
    and adds the same column itself — so neither half applies.
    """
    reconcile_task = _start_reconcile_task()
    try:
        if _CONFIG.store != "oracle":
            if _CONFIG.store == "backend":
                try:
                    await _PANEL_APP.state.panel_runtime.database.initialize()
                except Exception as exc:
                    _debug_print(
                        f"[panel] WARNING: backend schema check/repair failed: {exc}\n"
                        f"[panel] Asked {_CONFIG.backend_url} to ensure the panel schema "
                        "and it did not answer. The panel is serving anyway, but any "
                        "panel_* table or column this would have added is still missing "
                        "and every page selecting it will 500. Start the backend tier and "
                        "restart this one.",
                        file=sys.stderr,
                    )
            yield
            return
        from panel_app.database import close_db, ensure_schema

        try:
            await ensure_schema()
        except Exception as exc:
            # Not fatal, deliberately: the store is reached lazily per request, so a
            # database that is unreachable at boot (ATP refusing a session while the
            # rest of the fleet holds them all) used to cost this tier nothing, and
            # dying here would turn that into no panel at all. Loud, because the
            # failure it reports is one that leaves pages broken until the next
            # restart — which is how ORA-00904 went unexplained for three of them.
            _debug_print(
                f"[panel] WARNING: schema check/repair failed: {exc}\n"
                "[panel] The panel is serving anyway, but any column this would have "
                "added is still missing and every page selecting it will 500. Fix the "
                "connection and restart this tier, or run "
                "migrations/run_002_desired_state.py --apply by hand.",
                file=sys.stderr,
            )
        try:
            yield
        finally:
            await close_db()
    finally:
        if reconcile_task is not None:
            reconcile_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reconcile_task


def _start_reconcile_task():
    """Launch the orphan-container reconcile loop when it is enabled.

    Both fleet instances run this; the sweep is idempotent (a container already
    gone reads as removed) and each builds the identical allowlist, so a
    concurrent double-run is harmless. Returns the task so the lifespan can
    cancel it on shutdown, or None when the sweep is off.
    """
    if not _CONFIG.reconcile_enabled:
        return None
    runtime = _PANEL_APP.state.panel_runtime
    interval = _CONFIG.reconcile_interval_seconds

    async def _loop():
        # First sweep waits one interval: a container mid-create at boot has no
        # row yet, and reaping it because startup outran the insert would be the
        # sweep causing the very orphan it hunts.
        while True:
            try:
                await asyncio.sleep(interval)
                await runtime.reconcile_orphans()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                try:
                    import reviews_db
                    reviews_db.log_app_error("ReconcileSweepFailed", f"[panel] reconcile sweep failed: {type(exc).__name__}: {exc}", module="asgi_panel", flagged=1)
                except Exception:
                    pass
                _debug_print(f"[panel] reconcile sweep failed: {type(exc).__name__}: {exc}",
                             file=sys.stderr)

    return asyncio.ensure_future(_loop())


# The host app for this tier: a bare router whose only job is to put the panel
# under /panel, because every URL the panel emits (templating.url_for, the flash
# cookie path) is built from that prefix.
application = Starlette(lifespan=_lifespan)
_PANEL_APP = mount_panel(application, _CONFIG)


def _bind_host():
    """The validated PANEL_BIND value, or exit 2.

    A wildcard bind is refused rather than warned about, for the same reason the
    backend refuses one and despite this being a tier browsers do reach. The
    panel has no sign-in of its own: it reads the main site's session cookie,
    which is host-scoped, so it is only ever reached through whatever fronts that
    site on this host and one specific private interface is always enough.
    0.0.0.0 would publish a panel with no login of its own on every interface.
    """
    host = os.environ.get("PANEL_BIND", _PANEL_BIND_DEFAULT).strip()
    if host in _WILDCARD_HOSTS:
        print(
            f"[panel] refusing to start: PANEL_BIND={host!r} would expose the hosting "
            "panel beyond this host. It has no login of its own — it trusts the site "
            "session cookie, which only reaches it from the same host. Set PANEL_BIND "
            "to a specific private interface address, or leave it unset for 127.0.0.1.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(2)
    return host


def serve():
    import uvicorn

    host = _bind_host()
    port = int(os.environ.get("PANEL_PORT", "").strip() or _PANEL_PORT_DEFAULT)
    # Slow-loris and concurrency caps, all env-tunable so a host can retune them
    # without a code change, and all defaulted to degrade gracefully rather than
    # alter normal behaviour.
    #
    # limit_concurrency: this tier's clients are not browsers. The panel is only
    # reached through the frontend's /panel proxy, so its callers are the
    # frontend's own request threads — 8 per frontend worker, across two
    # instances, i.e. ~16 sockets that ever legitimately hold a panel request at
    # once. Default 0 = disabled, though: uvicorn trips this on len(connections)
    # as well as in-flight tasks, and a connection counts from accept, before a
    # byte is read. Nothing in uvicorn ever reaps a socket that stays silent, so
    # any ceiling near ~16 lets a handful of them 503 every real caller. Set it
    # only to bound genuine in-flight work, knowing it counts sockets too.
    #
    # timeout_keep_alive: uvicorn's default is 5s; a slow-loris holds an idle
    # keep-alive socket open to tie up a connection slot cheaply. Dropping to 5s
    # here is the same value but stated explicitly so it is a knob; a host under
    # attack can cut it lower.
    #
    # limit_max_requests: recycle the worker after this many requests to cap the
    # blast radius of any slow per-request leak. Default 0 = disabled, because
    # main.py does not restart a tier that exits — it reports the code and tears
    # the whole stack down — so a finite value here would kill the panel for good
    # rather than recycle it. It exists for a host that runs this tier under a
    # supervisor that *does* respawn (systemd, gunicorn's own arbiter).
    #
    # backlog: the kernel accept queue. Bounded (default 128) so a burst that
    # arrives faster than the loop accepts is refused at the socket layer
    # instead of piling up unboundedly in the queue.
    limit_concurrency = int(os.environ.get("PANEL_LIMIT_CONCURRENCY", "").strip() or "0")
    timeout_keep_alive = int(os.environ.get("PANEL_TIMEOUT_KEEP_ALIVE", "").strip() or "5")
    limit_max_requests = int(os.environ.get("PANEL_LIMIT_MAX_REQUESTS", "").strip() or "0")
    backlog = int(os.environ.get("PANEL_BACKLOG", "").strip() or "128")
    _debug_print(f"[panel] hosting panel running on http://{host}:{port}{MOUNT_PREFIX}")
    _debug_print(f"[panel] session lookups: {_CONFIG.backend_url}")
    _debug_print(f"[panel] store: {_CONFIG.store}")
    if not _CONFIG.internal_token:
        _debug_print(
            "[panel] WARNING: no internal token — the panel cannot read the session "
            "store, so every visitor gets a 503. Start the backend tier first, or set "
            "INTERNAL_TOKEN to the value the rest of the stack uses.",
            file=sys.stderr,
        )
    if not _CONFIG.node_token:
        _debug_print(
            "[panel] WARNING: no NODE_TOKEN — every node call will be rejected. "
            "Run the node agent (node-agent/run.py) and set NODE_TOKEN to its token "
            "(and NODE_URL to its address) before starting the tier.",
            file=sys.stderr,
        )
    uvicorn.run(
        application,
        host=host,
        port=port,
        # Pinned rather than left to default. uvicorn reads WEB_CONCURRENCY from
        # the environment whenever this is None, and the shared .env every tier
        # reads is already loaded by the time serve() runs. A WEB_CONCURRENCY set
        # for the gunicorn tiers would either kill this one outright — workers>1
        # needs an import string, not the app object built above — or, past that,
        # give each worker its own Oracle pool out of a fleet-wide session budget
        # this tier is already the largest consumer of.
        workers=1,
        # The panel reads X-Forwarded-For itself, gated on PANEL_TRUST_PROXY (see
        # panel_app/auth.py: client_ip). Letting uvicorn rewrite scope["client"]
        # from the same header would silently defeat PANEL_TRUST_PROXY=false,
        # because the untrusted path reads request.client and would then be
        # reading a value the caller supplied.
        proxy_headers=False,
        # One line per static asset would flood the combined [panel] pipe under
        # main.py, and no other tier access-logs. Serve this module under uvicorn
        # directly when you want the log.
        access_log=False,
        # Nothing gains from advertising the server and its version.
        server_header=False,
        # Past this many simultaneous in-flight requests uvicorn answers 503 and
        # stops accepting work rather than queueing it behind an event loop that
        # cannot drain — the whole point of a cap is that the panel degrades to
        # refusals it can serve instantly instead of stalling every caller.
        limit_concurrency=limit_concurrency or None,
        # How long an idle keep-alive socket is held before it is closed. Armed
        # only after a response completes, so it never reaps a silent socket.
        timeout_keep_alive=timeout_keep_alive,
        # None, not 0: uvicorn only disables the recycle when this is None, and
        # tests `is not None` before comparing — so a literal 0 would shut the
        # server down on the very first request.
        limit_max_requests=limit_max_requests or None,
        backlog=backlog,
    )


if __name__ == "__main__":
    serve()

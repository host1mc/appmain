"""
main.py — Production orchestrator.

Starts all five tiers as separate processes, in dependency order:

    1. database  (start_database.py)  no port        — schema + maintenance sweeps
    2. backend   (start_backend.py)   BACKEND_PORT   — the only tier that serves data
    3. engine    (start_engine.py)    ENGINE_PORT    — runs the bots (Discord + mcstatus)
    4. panel     (start_panel.py)     PANEL_PORT     — the hosting panel UI (ASGI)
    5. frontend  (start_frontend.py)  FRONTEND_PORT  — the public web tier

Each tier is also runnable on its own — that is the point of the five
start_*.py files. This script is just the convenience wrapper that brings the
whole stack up under one Ctrl+C. Every bind/port/URL default lives in the tier
module that owns it; main.py only forwards the environment it was given.

Set TIERS to a comma-separated subset of the labels above to start only some of
them (unset means all five). The two instances behind the load balancer:

    # instance A — full stack, owns the fleet singletons
    TIERS=database,backend,engine,panel,frontend \
      BACKEND_BIND=10.0.0.1 ENGINE_BIND=10.0.0.1 python main.py

    # instance B — web only, borrows A's engine and database
    TIERS=backend,panel,frontend \
      ENGINE_URL=http://10.0.0.1:8002 python main.py

The engine and the database maintenance daemon are fleet singletons. A second
engine is safe now that every publish takes a DB claim, but it only duplicates
work — so instance B runs neither. The panel is not a singleton: its store is
the shared Oracle schema, and the site session cookie it reads is host-scoped,
so it has to be served from the same host as the Flask frontend — it therefore
runs on every instance that runs the frontend. There is no admin tier to start:
the console is a separate loopback-only app (admin_console/start_admin.py),
launched by hand on one box.

Each tier normally runs under waitress (its own start_*.py) — except the panel,
which is ASGI and so runs under uvicorn instead. Set WSGI_SERVER=gunicorn to run
the web tiers under gunicorn via the wsgi_*.py entrypoints instead — the database
daemon has no WSGI app and always stays on start_database.py, and the panel,
being ASGI, has its gunicorn entrypoint in asgi_panel served by a uvicorn worker
class. Gunicorn requires Linux; the per-tier launchers remain the default.

Run: python main.py
"""

import os
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))


def _flag_tier_exit(label, code, proc):
    """Record a dead tier in the HeatWave app_errors table.

    The launcher is the only process that sees every tier's exit, so it is the
    one place a crash can be flagged for the admin console. Best-effort by
    design: the console reads HeatWave directly, and a flagging failure must
    never mask the exit code the operator already has on screen.
    """
    try:
        import reviews_db
        reviews_db.log_app_error(
            "TierExited",
            f"[main] tier '{label}' exited with code {code}",
            module="main", flagged=1, error_category="system_error")
    except Exception:
        pass

# (label, script, port env var or None) in boot order. The database goes first
# because it creates the schema and the shared internal token; the frontend goes
# last because it is useless until the backend answers. Only the *name* of the
# port variable lives here — the default behind it belongs to the tier module,
# so main.py can never drift out of sync with it.
# The panel sits after the backend for the same reason the frontend does: it
# resolves every visitor through the backend's GET /api/session/<sid>, and it
# reads the shared internal token the database tier minted rather than making
# one of its own.
COMPONENTS = (
    ("database", "start_database.py", None),
    ("backend", "start_backend.py", "BACKEND_PORT"),
    ("engine", "start_engine.py", "ENGINE_PORT"),
    ("panel", "start_panel.py", "PANEL_PORT"),
    ("frontend", "start_frontend.py", "FRONTEND_PORT"),
)

_ALL_LABELS = tuple(c[0] for c in COMPONENTS)
_WANT = {t.strip().lower() for t in os.environ.get("TIERS", "").split(",") if t.strip()}

_UNKNOWN = sorted(_WANT - {label.lower() for label in _ALL_LABELS})
if _UNKNOWN:
    print(f"[main] TIERS: unknown tier name(s): {', '.join(_UNKNOWN)}", file=sys.stderr)
    print(f"[main] TIERS: valid names are: {', '.join(_ALL_LABELS)}", file=sys.stderr)
    sys.exit(2)

if _WANT:
    COMPONENTS = tuple(c for c in COMPONENTS if c[0].lower() in _WANT)

if not COMPONENTS:
    print("[main] TIERS matched no components — nothing to start.", file=sys.stderr)
    sys.exit(2)

# WSGI_SERVER=gunicorn swaps the per-tier waitress launchers for gunicorn
# running the wsgi_*.py entrypoints: the same Flask app, the same inherited
# environment, only the HTTP server changes. The database tier is a maintenance
# daemon, not a WSGI app, so it always runs as start_database.py. The panel is
# not a WSGI app either — it is ASGI, so its gunicorn entrypoint is asgi_panel.py
# served by a uvicorn worker class rather than a wsgi_*.py module.
_WSGI_SERVER = os.environ.get("WSGI_SERVER", "").strip().lower()
_GUNICORN = _WSGI_SERVER in ("1", "true", "yes", "gunicorn")

# gunicorn shape per web tier: (app module, workers, threads, host, host env
# var or None, port env var, port default, worker class). Worker/thread counts
# mirror the waitress defaults (frontend/backend 8 request threads, engine 2).
# The engine is hard-capped at one worker: engine.init() starts the bot-loop
# thread at import, and it is not idempotent — two workers would be two loops
# ticking the fleet. The port defaults duplicate start_*.py on purpose: gunicorn
# needs a concrete --bind, and the launcher cannot import the tier modules
# (importing backend or engine opens the Oracle pool). Keep them in sync with
# start_*.py.
# An 8th field carries the gunicorn worker class: None for the WSGI tiers (the
# default sync/gthread worker), and the uvicorn worker for the panel, which is a
# Starlette ASGI app the sync worker cannot run at all. The panel's thread count
# is None because an ASGI worker takes its concurrency from the event loop, so
# --threads would be inert there — nothing emits it for that tier. One panel
# worker: nothing in it is a fleet singleton (its store is the shared Oracle
# schema and its session cache is a per-process read-through cache), but each
# worker builds its own Oracle pool, and the whole fleet shares a ~20-session
# Always Free budget — two panel workers on two instances is 16 of it.
_GUNICORN_TIERS = {
    "frontend": ("wsgi_frontend", 2, 4, "0.0.0.0", None, "FRONTEND_PORT", "5000", None),
    "backend": ("wsgi_backend", 2, 4, "127.0.0.1", "BACKEND_BIND", "BACKEND_PORT", "8001", None),
    "engine": ("wsgi_engine", 1, 2, "127.0.0.1", "ENGINE_BIND", "ENGINE_PORT", "8002", None),
    "panel": (
        "asgi_panel", 1, None, "127.0.0.1", "PANEL_BIND", "PANEL_PORT", "8000",
        "uvicorn.workers.UvicornWorker",
    ),
}
_WILDCARD_HOSTS = ("", "0.0.0.0", "::", "[::]", "*")

# Oracle sessions each gunicorn tier process may hold, chosen so that
# workers x this stays at the per-tier total database.py:75 intends
# (backend 4, engine 2, database 2).
# Only the gunicorn path needs this. database._tier_name() derives the tier from
# argv[0] and only recognises `start_<tier>.py`, so under `python -m gunicorn`
# argv[0] is gunicorn's own __main__, every tier falls through to
# _ORACLE_POOL_MAX_DEFAULT = 4 — silently raising the engine's deliberate 2 — and
# then each worker builds one more pool of that size. Naming the number here is
# the only place that knows the worker count. Keep in sync with database.py:75.
# The frontend is absent on purpose: it has no database access at all. So is the
# panel: it never imports database.py, so _tier_name() cannot mis-derive anything
# for it, and panel_app/database.py already defaults to 2 per process behind its
# own PANEL_ORACLE_POOL_MAX — naming it here would raise it to that file's
# ceiling of 4 instead of leaving it at the 2 it chose.
# Applied with setdefault, so an ORACLE_POOL_MAX exported into the real
# environment still wins. A value that only lives in the .env does not: the tier
# parses that file itself and the launcher never sees it.
_GUNICORN_POOL_MAX = {"backend": 2, "engine": 2, "panel": 2}


def _tier_cmd(label, script, port_var):
    """argv for one tier process: gunicorn when selected, otherwise the tier's
    own waitress launcher script."""
    if not (_WSGI_SERVER in ("1", "true", "yes", "gunicorn")) or label == "database":
        return [sys.executable, "-u", os.path.join(ROOT, script)]
    (mod, workers, threads, host, host_var, port_env,
     port_default, worker_class) = _GUNICORN_TIERS[label]
    if host_var:
        host = (os.environ.get(host_var, "").strip() or host)
        # Mirror the wildcard-bind refusal in the tier's own _bind_host() —
        # under gunicorn the tier's guard never runs, so it has to happen here.
        # The panel is deliberately *not* exempted even though it is a
        # user-facing tier: the site session cookie it reads is host-scoped, so
        # it is only ever reached through whatever fronts the Flask site on that
        # host, and a specific private interface is always enough. 0.0.0.0 would
        # publish a login-less panel on every interface instead.
        if host in _WILDCARD_HOSTS:
            print(
                f"[main] refusing to start {label}: {host_var}={host!r} would expose "
                f"the {label} tier beyond this host under gunicorn. Set it to a specific "
                "private interface address, or leave it unset for 127.0.0.1.",
                file=sys.stderr,
            )
            sys.exit(2)
    port = os.environ.get(port_env, "").strip() or port_default
    cmd = [
        sys.executable, "-u", "-m", "gunicorn",
        "--workers", str(workers),
    ]
    if threads:
        cmd += ["--threads", str(threads)]
    if worker_class:
        cmd += ["-k", worker_class]
    cmd += ["--bind", f"{host}:{port}", f"{mod}:application"]
    return cmd


# The database needs a moment to finish init_db() before the others connect.
BOOT_DELAY = 1.0


def _child_env(label=None):
    """The environment each tier process gets.

    A straight inherit: TIERS, BACKEND_BIND/PORT, ENGINE_BIND/PORT,
    FRONTEND_PORT, BACKEND_URL and ENGINE_URL are all read by the tier modules
    themselves, so the launcher must pass them through untouched.
    """
    env = os.environ.copy()
    # glibc hands each thread its own malloc arena (up to 8x cores) and each
    # arena holds onto its own heap, so a waitress tier reserves tens of MB of
    # RSS it never uses. Two arenas is the cheapest saving on a ~50 MB budget.
    # Linux-only (no glibc elsewhere), and setdefault so an operator who already
    # tuned it wins.
    if sys.platform.startswith("linux"):
        env.setdefault("MALLOC_ARENA_MAX", "2")
    if _GUNICORN and label in _GUNICORN_POOL_MAX:
        env.setdefault("ORACLE_POOL_MAX", str(_GUNICORN_POOL_MAX[label]))
    return env


def _start(name, script, port_var=None):
    cmd = _tier_cmd(name, script, port_var)
    p = subprocess.Popen(
        cmd,
        cwd=ROOT,
        env=_child_env(name),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    # Echo a port only when the operator pinned one. The tier logs the address
    # it actually bound, so guessing a default here could only ever be a lie.
    pinned = os.environ.get(port_var, "").strip() if port_var else ""
    where = f" on port {pinned} ({port_var})" if pinned else ""
    print(f"[{name}] started (PID {p.pid}){where}")
    return p


def _pipe_reader(stream, label):
    try:
        for line in iter(stream.readline, ""):
            # Most tier output already opens with its own "[backend] " marker, so
            # prefixing unconditionally printed it twice. Skipped when the line
            # already carries it, which keeps the marker on the lines that lack
            # one (waitress, oracledb, tracebacks) and keeps a tier run directly
            # rather than through this launcher self-describing.
            if line.startswith(f"{label} "):
                sys.stdout.write(line)
            else:
                sys.stdout.write(f"{label} {line}")
    except ValueError:
        pass


def _install_signal_handlers():
    """Route a supervisor's stop signal into the same shutdown Ctrl+C already
    gets.

    The default disposition for SIGTERM kills this process outright, so the
    finally block in main() never runs and every tier is left orphaned — still
    running, still holding its port, so the next start fails on an address
    already in use. `systemctl stop` and `docker stop` both send SIGTERM, which
    made that the normal way to stop the stack rather than an edge case.
    Raising KeyboardInterrupt from the handler lands in the same except clause
    Ctrl+C uses, so there is one shutdown path instead of two.
    """
    def _raise_interrupt(_signum, _frame):
        raise KeyboardInterrupt

    # SIGHUP (a closed terminal) is POSIX-only and SIGBREAK is Windows-only;
    # getattr keeps this one list valid on both.
    for _name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        _sig = getattr(signal, _name, None)
        if _sig is None:
            continue
        try:
            signal.signal(_sig, _raise_interrupt)
        except (OSError, ValueError):
            pass


def main():
    _install_signal_handlers()
    server = "gunicorn" if _WSGI_SERVER in ("1", "true", "yes", "gunicorn") else "waitress"
    print("=" * 56)
    print("  MC Status Hosting — starting all components")
    print("=" * 56)
    print(f"  tiers: {', '.join(c[0] for c in COMPONENTS)}" + (" (TIERS)" if _WANT else ""))
    print(f"  wsgi server: {server}")

    ps = []
    try:
        threads = []
        for name, script, port_var in COMPONENTS:
            proc = _start(name, script, port_var)
            ps.append((name, proc))
            # Drain this tier's stdout from the moment it exists. Reading only
            # after the whole boot loop left every earlier tier's pipe unread for
            # BOOT_DELAY seconds per remaining tier, so a tier that writes more
            # than the pipe buffer holds before the last one starts — init_db()
            # migration output on a cold schema — blocked in write() and looked
            # like a hung boot.
            t = threading.Thread(target=_pipe_reader, args=(proc.stdout, f"[{name}]"), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(BOOT_DELAY)

        print()
        # Roles only, no addresses: each tier logs the host/port it really bound, and
        # on a TIERS=backend,frontend instance a hardcoded engine line would advertise
        # a port nothing here is listening on.
        _SUMMARY = {
            "frontend": "  Frontend : public web tier       (FRONTEND_PORT)",
            "panel": "  Panel    : hosting panel UI      (PANEL_BIND / PANEL_PORT)",
            "backend": "  Backend  : internal API          (BACKEND_BIND / BACKEND_PORT)",
            "engine": "  Engine   : internal control API  (ENGINE_BIND / ENGINE_PORT)",
            "database": "  Database : maintenance daemon    (no port)",
        }
        for label in ("frontend", "panel", "backend", "engine", "database"):
            if any(c[0] == label for c in COMPONENTS):
                print(_SUMMARY[label])
        print("  (each tier logs the address it bound)")
        # A backend without a local engine must be pointed at the instance that has
        # one, or every engine call goes to a dead loopback port.
        if not any(c[0] == "engine" for c in COMPONENTS) and any(c[0] == "backend" for c in COMPONENTS):
            if not os.environ.get("ENGINE_URL", "").strip():
                print("  WARNING: no engine tier here and ENGINE_URL is unset —")
                print("           set ENGINE_URL to the instance that runs the engine.")
        # Same footgun one tier up: the panel resolves every visitor's session
        # through the backend, so without a local backend it needs BACKEND_URL or
        # every lookup goes to a dead loopback port and nobody is ever signed in.
        if not any(c[0] == "backend" for c in COMPONENTS) and any(c[0] == "panel" for c in COMPONENTS):
            if not os.environ.get("BACKEND_URL", "").strip():
                print("  WARNING: no backend tier here and BACKEND_URL is unset —")
                print("           set BACKEND_URL to the instance that runs the backend.")
        print("  Press Ctrl+C to stop all")
        print()

        while True:
            # Report a tier that died on its own instead of silently idling.
            for label, p in ps:
                code = p.poll()
                if code is not None:
                    print(f"[main] {label} exited with code {code}")
                    _flag_tier_exit(label, code, p)
                    return code
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        for label, p in ps:
            if p.poll() is None:
                p.terminate()
        for label, p in ps:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        print("All components stopped.")


if __name__ == "__main__":
    sys.exit(main())

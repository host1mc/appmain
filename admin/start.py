"""
start_admin.py — the local-only admin console.

An operator console that sits outside the four public tiers, in a folder of its
own with vendored copies of the app's data layer, so it runs on the admin's
machine with no checkout of the hosting app present. It can read every user's
data and start or stop any bot, so it is deliberately not exposed: it binds
127.0.0.1 exclusively, and being unreachable from the network is its only
protection. There is no reverse proxy, no public port, no tunnel.

The host is hardcoded on purpose — it is the security control, not a setting.

Configuration comes from `admin_console/.env` (see `.env.example`) with the real
process environment taking precedence; `_bootstrap` loads it before `database`
resolves the connection. The console then refuses to start unless it reached the
backend it was told to use — see `_preflight()`.

Run: python start_admin.py      (from inside admin_console/)
"""

import os
import sys

import _bootstrap  # sys.path + .env + wallet path, must be imported first

from admin_app import app

import database as db
import db_env_report

# main.py never starts this process; it is launched by hand when an operator
# needs it, and shut down again afterwards.
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8003"))


def _warn_on_vendor_drift():
    """Print, but do not block on, drift in the vendored app modules.

    Locally editing this folder's copy of `database.py` is how the console
    quietly starts writing a schema the fleet does not have. It is a warning
    rather than a refusal because the operator may be mid-upgrade and still needs
    to get in; `python sync_from_app.py --repo <path>` is the fix.
    """
    problems = _bootstrap.vendor_problems()
    if not problems:
        return
    print("[admin] warning: the vendored copies of the app's modules do not match "
          "VENDOR.json:", file=sys.stderr)
    for p in problems:
        print("  " + p, file=sys.stderr)
    print("  run: python sync_from_app.py --repo <path-to-the-app>", file=sys.stderr)


def _preflight():
    """Prove the console is attached to the database the operator meant, before
    a single page renders. Exits 2 rather than starting on the wrong data."""
    _warn_on_vendor_drift()

    on_oracle = bool(getattr(db, "_ORACLE_ENABLED", False))
    configured = bool(getattr(db, "_ORACLE_CFG", None))

    if not on_oracle or not configured:
        print("[admin] refusing to start: no Oracle connection is configured, and Oracle "
              "is the only backend. Copy .env.example to .env and fill in the ATP "
              "details (wallet directory, DSN, credentials).", file=sys.stderr)
        sys.exit(2)

    # Connect for real. The Oracle pool is lazy, so a bad wallet or an expired
    # password would otherwise surface on the operator's first click.
    conn = None
    try:
        conn = db._user_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM dual")
        cur.fetchone()
    except Exception as exc:
        print(f"[admin] refusing to start: the database could not be opened or "
              f"rejected a test query: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    cfg = getattr(db, "_ORACLE_CFG", None) or {}
    print(f"[admin] database: Oracle, user {cfg.get('user')} on {cfg.get('dsn')}")


def serve():
    from waitress import serve as wserve
    db_env_report.print_db_env_report("admin")
    _preflight()
    import node_registry
    node_registry.ensure_node_schema()
    print(f"[admin] local admin app on http://127.0.0.1:{ADMIN_PORT}")
    wserve(
        app,
        host="127.0.0.1",  # loopback only — do not make this configurable
        port=ADMIN_PORT,
        threads=4,
        expose_tracebacks=False,
        ident="LocalAdmin",
    )


if __name__ == "__main__":
    serve()

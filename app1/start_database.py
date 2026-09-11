"""
start_database.py — Tier 1 of 4: the database service.

This is the only component that owns the schema. It:
  1. creates / migrates the Oracle schema,
  2. makes sure the shared internal service token exists before any other tier
     boots, so the four processes cannot race each other into different keys,
  3. then stays alive as a maintenance daemon, doing the periodic housekeeping
     that used to be bolted onto the web request path and the bot worker:
       - pruning expired sessions   (was a frontend before_request hook)
             - pruning used / expired OTPs (was never run at all)
             - expiring trial bots         (was inside the bot worker tick)
             - enforcing the trial renew cycle (7-day expiry, warning, stop and
                 grace-before-workload-delete)

Run: python start_database.py
"""

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db
import db_env_report
import internal_auth

# How often the housekeeping sweep runs, in seconds.
MAINTENANCE_INTERVAL = int(os.environ.get("DB_MAINTENANCE_INTERVAL", 60))

_TASKS = (
    ("expired sessions", "cleanup_expired_sessions"),
    ("expired OTPs", "cleanup_expired_otps"),
    ("used OTPs", "cleanup_used_otps"),
    ("trial bots", "expire_trial_bots"),
    ("inactivity policy", "inactivity_sweep"),
    ("expired ban appeals", "purge_expired_ban_appeals"),
    ("fingerprint history", "cleanup_fingerprint_history"),
    ("reviewed device events", "cleanup_reviewed_device_events"),
    ("orphaned panel data", "cleanup_orphaned_panel_data"),
)


def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass


def _sweep():
    """Run every maintenance task, isolating failures so one bad task
    cannot stop the others or kill the loop."""
    for label, fname in _TASKS:
        fn = getattr(db, fname, None)
        if fn is None:
            continue
        try:
            fn()
        except db.OraclePoolExhausted as ex:
            _debug_print(f"[database] sweep abandoned at {label}: {ex}", file=sys.stderr)
            return
        except Exception as exc:
            try:
                import reviews_db
                reviews_db.log_app_error("MaintenanceTaskFailed", f"[database] maintenance task failed: {label}: {exc}", module="start_database", flagged=1)
            except Exception:
                pass
            _debug_print(f"[database] maintenance task failed: {label}: {exc}")


# Keeps the lock file open for the life of the process. The advisory lock is
# attached to the open file description, so letting this be garbage-collected
# would close the fd and hand the lock to the next starter.
_LOCK_FH = None


def _claim_singleton(name):
    """Refuse to start when another copy of this tier already runs on this host.

    The maintenance daemon is a fleet singleton. Until now that was enforced only
    by convention — TIERS on the second instance, plus a comment in main.py — so
    a bare `python main.py` on a box that already had one silently started a
    second sweeper, running the inactivity policy and the trial-expiry pass twice
    per interval against the same rows.

    This is a HOST lock, not a fleet lock: an advisory lock on a local file
    cannot see the other instance behind the load balancer, and nothing here may
    open a socket or a database connection to coordinate. It stops the accident
    that actually happens on one box; the cross-host case is still the
    operator's TIERS split. Set SKIP_SINGLETON_LOCK=1 to bypass it.

    The kernel holds the lock only while this process lives, so a crash or a
    SIGKILL releases it — there is no stale lock file for anyone to clear.
    """
    global _LOCK_FH
    if os.environ.get("SKIP_SINGLETON_LOCK", "").strip().lower() in ("1", "true", "yes"):
        return
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", f"{name}.lock")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = open(path, "a+b")
    try:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            # No fcntl on Windows; msvcrt locks a byte range instead and is
            # released on process exit just the same.
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        fh.close()
        _debug_print(
            f"[{name}] refusing to start: another {name} process on this host already holds "
            f"{path}. The {name} maintenance daemon is a fleet singleton — run it on one "
            f"instance only (set TIERS without '{name}' on the others). "
            "SKIP_SINGLETON_LOCK=1 bypasses this check.",
            file=sys.stderr,
        )
        sys.exit(2)
    _LOCK_FH = fh


def serve():
    db_env_report.print_db_env_report("database")

    # First, before init_db() opens the Oracle pool: a duplicate daemon must be
    # turned away without ever taking a connection from the shared database.
    _claim_singleton("database")

    # Generate the shared token first — backend, engine and frontend all read
    # it, and this process is started first by main.py.
    internal_auth.get_internal_token()

    db.init_db()
    _debug_print(f"[database] schema ready (oracle) at {db._ORACLE_CFG.get('dsn', '?')}")
    _debug_print(f"[database] maintenance daemon running every {MAINTENANCE_INTERVAL}s")

    # First sweep immediately so a long-idle instance is tidy on boot.
    _sweep()

    try:
        while True:
            time.sleep(MAINTENANCE_INTERVAL)
            _sweep()
    except KeyboardInterrupt:
        print("[database] stopped.")


if __name__ == "__main__":
    serve()

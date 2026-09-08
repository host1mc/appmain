"""
start_engine.py — Tier 3 of 4: the hosting engine.

The single process that actually *runs* the bots. It:
  - polls the server status for every running bot on its own update interval,
  - posts / edits each bot's status embed via the Discord REST API,
  - reads the running bot set from the database every tick, so a missed
    start/stop control call is self-healing,
  - exposes a small control API on 127.0.0.1:8002 that the backend calls to
    start/stop a bot, force a refresh, or render a preview.

The bots stay offline in Discord by design — the engine only makes Discord
REST API calls.

The engine reads the database directly. That is intentional: it needs the
decrypted bot tokens and writes runtime state, and it is a backend-tier
service. Only the *frontend* is barred from touching the database.

Run: python start_engine.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import internal_auth
import db_env_report

# Keeps the lock file open for the life of the process. The advisory lock is
# attached to the open file description, so letting this be garbage-collected
# would close the fd and hand the lock to the next starter.
_LOCK_FH = None


def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass


def _claim_singleton(name):
    """Refuse to start when another copy of this tier already runs on this host.

    The engine is a fleet singleton. Until now that was enforced only by
    convention — TIERS on the second instance, plus a comment in main.py — so a
    bare `python main.py` or a hand-run `python start_engine.py` on a box that
    already had one silently started a second bot loop, doubling every Discord
    REST call and every status poll.

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
            f"{path}. The {name} tier is a fleet singleton — run it on one instance only "
            f"(set TIERS without '{name}' on the others). SKIP_SINGLETON_LOCK=1 bypasses "
            "this check.",
            file=sys.stderr,
        )
        sys.exit(2)
    _LOCK_FH = fh


def serve():
    db_env_report.print_db_env_report("engine")

    # Before internal_auth and before `import engine`: importing engine starts
    # the bot worker thread, so a duplicate has to be turned away first.
    _claim_singleton("engine")
    internal_auth.get_internal_token()
    import engine
    engine.serve()


if __name__ == "__main__":
    serve()

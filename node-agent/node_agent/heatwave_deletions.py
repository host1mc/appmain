"""Opt-in startup drain of the HeatWave pending-container-deletion queue.

app1 records a tombstone in HeatWave (table ``pending_container_deletions``)
for a container it could not confirm deleted because this node was offline at
delete time. Removal from that queue is MANUAL — an admin confirms it in the
admin panel, and app1's reconcile sweep is handed the tombstoned ids as
``protect_ids`` so it skips them. This drain is the opt-out of that policy
(``DRAIN_HEATWAVE_PENDING=1``): when the node boots it hosts those containers
again, so it removes the ones it actually hosts and clears their rows — useful
only when the admin panel cannot reach this node but HeatWave can.

Entirely optional and best-effort. No ``MYSQL_HOST``, no driver installed, or
an unreachable endpoint all degrade to a silent no-op. Reuses the ``MYSQL_*``
env names ``reviews_db`` uses so a deploy fills in one set of credentials.

TLS is pinned exactly as ``reviews_db`` pins it: ``ssl_ca`` is required and the
chain is verified. With ``MYSQL_HOST`` set but no CA the drain disables itself
rather than connect in the clear — it never downgrades TLS to run.
"""
import logging
import os

_LOGGER = logging.getLogger("node_agent.heatwave")

_TABLE = "pending_container_deletions"


def _cfg():
    """Connection settings from the environment, or None when disabled.

    ``MYSQL_HOST`` unset is the documented "HeatWave disabled" state — the same
    convention reviews_db uses. ``MYSQL_HOST`` set without ``MYSQL_SSL_CA`` is a
    misconfiguration we refuse rather than answer by connecting unencrypted.
    """
    host = (os.environ.get("MYSQL_HOST") or "").strip()
    if not host:
        return None
    ca = (os.environ.get("MYSQL_SSL_CA") or "").strip()
    if not ca:
        _LOGGER.warning(
            "MYSQL_HOST is set but MYSQL_SSL_CA is not — skipping the HeatWave "
            "pending-deletion drain rather than connect without a pinned CA "
            "(app1 reconcile still reaps orphaned containers)"
        )
        return None
    try:
        port = int(os.environ.get("MYSQL_PORT", "3306"))
    except (TypeError, ValueError):
        port = 3306
    return {
        "host": host,
        "port": port,
        "user": (os.environ.get("MYSQL_USER") or "admin").strip(),
        "password": os.environ.get("MYSQL_PASSWORD") or "",
        "database": (os.environ.get("MYSQL_DATABASE") or "dchost").strip(),
        "ssl_ca": os.path.abspath(ca),
    }


def _connect(cfg):
    # ssl_verify_identity is off on purpose: the HeatWave endpoint's certificate
    # is CN-only with no subjectAltName, so identity verification always fails on
    # the fixed private IP. The pinned CA is the chain-of-trust check. This
    # mirrors reviews_db._connect_kwargs exactly.
    import mysql.connector
    return mysql.connector.connect(
        host=cfg["host"],
        port=cfg["port"],
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        connection_timeout=10,
        charset="utf8mb4",
        ssl_ca=cfg["ssl_ca"],
        ssl_verify_cert=True,
        ssl_verify_identity=False,
    )


def drain(manager):
    """Remove containers this node hosts that app1 queued for deletion, then
    clear their HeatWave rows.

    Only rows whose ``server_id`` is a container present on THIS node are
    touched — a row for a container hosted elsewhere is left for its owning node
    to drain, exactly as app1's reconcile clears only the orphans a node reports
    removed. A row is cleared only once its container is actually gone, so a
    remove that errors leaves the row to retry on the next boot. Any unexpected
    failure is logged and swallowed: node startup must never block on HeatWave.
    """
    cfg = _cfg()
    if cfg is None:
        return

    try:
        present = {str(e.get("id") or "").strip() for e in manager.runtime.list()}
        present.discard("")
    except Exception:
        _LOGGER.exception("HeatWave drain: could not list managed containers")
        return
    if not present:
        # Nothing hosted here to delete. Leave every row for the node that owns
        # its container; connecting just to read and skip them buys nothing.
        return

    try:
        conn = _connect(cfg)
    except Exception as exc:
        _LOGGER.warning(
            "HeatWave drain: cannot reach HeatWave (%s) — app1 reconcile will "
            "reap orphaned containers instead",
            exc.__class__.__name__,
        )
        return

    removed = []
    try:
        cur = conn.cursor()
        # `purge` is backticked because it is a MySQL reserved word.
        cur.execute(f"SELECT server_id, `purge` FROM {_TABLE}")
        rows = cur.fetchall()
        for server_id, purge in rows:
            sid = str(server_id or "").strip()
            if sid not in present:
                continue
            try:
                manager.remove(sid, purge=bool(purge))
            except LookupError:
                # ServerNotFoundError (a LookupError): the container went away
                # between the list above and now. It is still ours and gone, so
                # the row should clear. Caught by base class to avoid importing
                # server_manager here (and the import cycle that would create).
                pass
            except Exception:
                _LOGGER.exception("HeatWave drain: could not remove %s", sid)
                continue  # leave the row; retry on the next boot
            removed.append(sid)

        if removed:
            placeholders = ",".join(["%s"] * len(removed))
            cur.execute(
                f"DELETE FROM {_TABLE} WHERE server_id IN ({placeholders})",
                removed,
            )
            conn.commit()
            _LOGGER.warning(
                "HeatWave drain: removed %d queued container(s) and cleared "
                "their rows: %s",
                len(removed),
                removed,
            )
    except Exception:
        _LOGGER.exception("HeatWave drain: query failed")
    finally:
        try:
            conn.close()
        except Exception:
            pass

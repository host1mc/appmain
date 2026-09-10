"""Panel storage on the shared Oracle schema.

The panel no longer owns tables of its own. The old ``panel_users`` /
``panel_servers`` / ``panel_activity`` trio is gone:

* users are the main site's ``users`` rows — panel sign-in is the single
  sign-in, so the panel reads the account the site already authenticated;
* servers are the consolidated ``servers`` table: uid + name + status +
  placement, and nothing else. The runtime, version, image and startup
  command live inside the container and are read from the node, so a leaked
  database read exposes no deployment detail;
* activity is not persisted at all.

This is the raw-SQL layer behind the backend's ``/api/panel-store/*``
endpoints; the panel tier's store objects (``panel_app/store.py``) answer the
same shapes.
"""

import re
from datetime import datetime, timezone

import database

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

SERVER_LIST_MAX = 200
USER_ID_MAX_CHARS = 36
SERVER_ID_MAX_CHARS = 36
NAME_MAX_CHARS = 255

# Written into the user dicts this layer returns. The panel never verifies a
# password against the Oracle users table — the main site owns authentication —
# so the hash field carries an unusable marker rather than a credential.
EXTERNAL_PLACEHOLDER = "external:oracle"


class MirrorConflict(Exception):
    pass


def _clip_text(value, max_chars):
    text = str(value)
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        text = text.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    text = text[:max_chars]
    encoded = text.encode("utf-8")
    if len(encoded) <= max_chars:
        return text
    return encoded[:max_chars].decode("utf-8", "ignore")


def _user_key(user_id) -> str:
    if user_id is None:
        return ""
    key = str(user_id).strip()
    return key if len(key) <= USER_ID_MAX_CHARS else ""


def _server_key(server_id):
    if server_id is None:
        return None
    key = str(server_id).strip()
    if not key or len(key) > SERVER_ID_MAX_CHARS:
        return None
    return key


def _iso(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _panel_conn():
    try:
        return database._oracle_conn()
    except Exception as exc:
        if not database._is_pool_exhausted(exc):
            raise
        database._note_pool_busy()
        raise database.OraclePoolExhausted(f"Oracle unavailable: {exc}") from exc


def _user_dict(account):
    """The main site's users row in the shape the panel tier expects."""
    if not account:
        return None
    slots = account.get("container_slots")
    return {
        "id": account.get("uid"),
        "username": account.get("username") or "",
        "password_hash": EXTERNAL_PLACEHOLDER,
        # None means "no per-account grant — use the fleet figure"; 0 is an
        # explicit switch-off. Readers tell the two apart, so neither may be
        # coerced into the other.
        "container_slots": (None if slots is None else int(slots)),
        "created_at": _iso(account.get("created_at")),
    }


def _server_dict(row):
    if row is None:
        return None
    node_id = row.get("node_id")
    return {
        "id": row["id"],
        "user_id": row["uid"],
        "name": row["name"],
        # The column is `status` — the owner's power intent — but the panel
        # tier and templates read it under its historical key.
        "desired_state": int(row.get("status") or 0),
        "created_at": _iso(row.get("created_at")),
        "node_id": (None if node_id is None else int(node_id)),
    }


def _fetch_one_dict(cur):
    return database._oracle_dict_row(cur, cur.fetchone())


def _fetch_all_dicts(cur):
    rows = cur.fetchall()
    return [database._oracle_dict_row(cur, row) for row in rows]


def ensure_panel_schema(*, _force=False) -> None:
    """The schema is owned by database.init_db() — nothing left to create here.

    Kept as an endpoint so an older panel tier's startup call still succeeds.
    """
    return None


# ── users ────────────────────────────────────────────────────────────────


def ensure_user_by_id(user_id, username):
    """Return the signed-in account's users row, or None when there is none.

    Panel sign-in comes through the main site's session, so the account row
    already exists by the time the panel asks; there is no mirror row left to
    write. A missing row reads as "not signed in" and the visitor is sent to
    the site's login.
    """
    return get_user(user_id)


def get_user(user_id):
    key = _user_key(user_id)
    if not key:
        return None
    return _user_dict(database.get_user(key))


def get_user_by_username(username):
    normalized = (username or "").strip()
    if not normalized:
        return None
    return _user_dict(database.get_user_by_username(normalized))


def create_user(username, password_hash):
    # Panel-native accounts exist only in the SQLite smoke store. Against the
    # shared Oracle schema an account is created by the main site's signup —
    # a panel request to mint one is a configuration mistake, not a feature.
    raise ValueError(
        "panel-native accounts are not created in the Oracle store; "
        "sign up on the main site instead"
    )


def update_user_password(user_id, password_hash):
    # The main site owns the credential. The panel's password form only runs
    # in the local (SQLite) auth mode; reaching this path means "no change".
    return False


# ── servers ──────────────────────────────────────────────────────────────


def create_server(
    *, server_id, user_id, name, runtime=None, version=None, image=None,
    startup=None, node_id=None, pick_node=None
):
    """Insert the server's identity row. Returns the node it was placed on.

    runtime / version / image / startup are accepted for caller compatibility
    and deliberately not stored: the container carries them, and the panel
    lists them from the node.
    """
    owner = _user_key(user_id)
    if not owner:
        raise ValueError("a server row requires an owner")
    sid = _server_key(server_id)
    if not sid:
        raise ValueError(f"a server id must be 1 to {SERVER_ID_MAX_CHARS} characters")
    params = {
        "sid": sid,
        "u_id": owner,
        "name": _clip_text((name or "").strip(), NAME_MAX_CHARS),
        "node_id": _node_id_value(node_id),
        "created": datetime.now(timezone.utc).replace(tzinfo=None),
    }

    conn = _panel_conn()
    try:
        cur = conn.cursor()
        if pick_node is not None:
            params["node_id"] = _node_id_value(pick_node(conn))
        cur.execute(
            "INSERT INTO servers (id, \"uid\", name, status, node_id, created_at) "
            "VALUES (:sid, :u_id, :name, 0, :node_id, :created)",
            params,
        )
        conn.commit()
        return params["node_id"]
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _node_id_value(node_id):
    if node_id is None:
        return None
    try:
        value = int(node_id)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def list_servers_for_user(user_id):
    owner = _user_key(user_id)
    if not owner:
        return []
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, \"uid\", name, status, node_id, created_at "
            "FROM servers WHERE \"uid\"=:u_id "
            "ORDER BY created_at DESC FETCH FIRST :lim ROWS ONLY",
            {"u_id": owner, "lim": SERVER_LIST_MAX},
        )
        return [_server_dict(row) for row in _fetch_all_dicts(cur)]
    finally:
        conn.close()


def all_server_ids():
    """Every live server id across all owners — the authoritative allowlist
    the node reconcile sweep checks its managed containers against."""
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM servers")
        return [str(row[0]) for row in cur.fetchall() if row[0]]
    finally:
        conn.close()


def get_server_for_user(server_id, user_id):
    owner = _user_key(user_id)
    sid = _server_key(server_id)
    if not owner or not sid:
        return None
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, \"uid\", name, status, node_id, created_at "
            "FROM servers WHERE id=:sid AND \"uid\"=:u_id",
            {"sid": sid, "u_id": owner},
        )
        return _server_dict(_fetch_one_dict(cur))
    finally:
        conn.close()


def delete_server_for_user(server_id, user_id):
    owner = _user_key(user_id)
    sid = _server_key(server_id)
    if not owner or not sid:
        return False
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM servers WHERE id=:sid AND \"uid\"=:u_id",
            {"sid": sid, "u_id": owner},
        )
        conn.commit()
        return (cur.rowcount or 0) == 1
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _update_server(server_id, user_id, set_clause, values):
    owner = _user_key(user_id)
    sid = _server_key(server_id)
    if not owner or not sid:
        return False
    params = dict(values)
    params["sid"] = sid
    params["u_id"] = owner
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"UPDATE servers SET {set_clause} WHERE id=:sid AND \"uid\"=:u_id",
            params,
        )
        conn.commit()
        return (cur.rowcount or 0) == 1
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def update_server_name(server_id, user_id, name):
    return _update_server(
        server_id,
        user_id,
        "name=:name",
        {"name": _clip_text((name or "").strip(), NAME_MAX_CHARS)},
    )


def update_server_state(server_id, user_id, running):
    """Record the owner's last power intent: 1 running, 0 stopped."""
    return _update_server(
        server_id,
        user_id,
        "status=:desired",
        {"desired": 1 if running else 0},
    )

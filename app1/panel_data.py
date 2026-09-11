import re
import threading
import time
from datetime import datetime, timezone
from sys import stderr
from uuid import uuid4

import database

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


EXTERNAL_PLACEHOLDER = "external:oracle"
SERVER_LIST_MAX = 200
USERNAME_MAX_CHARS = 100
USER_ID_MAX_CHARS = 36
SERVER_ID_MAX_CHARS = 36
PASSWORD_HASH_MAX_CHARS = 255
IMAGE_MAX_CHARS = 255
NAME_MAX_CHARS = 255
RUNTIME_MAX_CHARS = 32
VERSION_MAX_CHARS = 32
STARTUP_MAX_CHARS = 500

_INTEGRITY_ORA_CODES = (
    "ORA-00001",
    "ORA-01400",
    "ORA-02290",
    "ORA-02291",
    "ORA-02292",
)

_SELECT_USER_BY_ID = (
    "SELECT id, username, password_hash, container_slots, created_at "
    "FROM panel_users WHERE id=:id"
)

_SELECT_USER_BY_USERNAME = (
    "SELECT id, username, password_hash, container_slots, created_at "
    "FROM panel_users WHERE LOWER(username)=:uname"
)

_SELECT_USER_ID_BY_USERNAME = "SELECT id FROM panel_users WHERE LOWER(username)=:uname"

_INSERT_USER = (
    "INSERT INTO panel_users (id, username, password_hash, container_slots, created_at) "
    "VALUES (:id, :uname, :ph, :container_slots, :created)"
)

_UPDATE_USER_PASSWORD = "UPDATE panel_users SET password_hash=:ph WHERE id=:id"

_SERVER_COLUMNS = (
    "id, user_id, name, runtime, version, image, startup, memory_mb, "
    "cpu_percent, desired_state, created_at, node_id"
)

# Owner binds are :u_id, never :uid — UID is an Oracle reserved word and a bind
# named uid raises ORA-01745 on every statement below.
_INSERT_SERVER = (
    "INSERT INTO panel_servers (id, user_id, name, runtime, version, image, "
    "startup, memory_mb, cpu_percent, desired_state, created_at, node_id) "
    "VALUES (:sid, :u_id, :name, :runtime, :version, :image, :startup, "
    ":memory_mb, :cpu_percent, :desired_state, :created, :node_id)"
)

_SELECT_SERVERS_FOR_USER = (
    "SELECT " + _SERVER_COLUMNS + " FROM panel_servers WHERE user_id=:u_id "
    "ORDER BY created_at DESC FETCH FIRST :lim ROWS ONLY"
)

_SELECT_SERVER_FOR_USER = (
    "SELECT " + _SERVER_COLUMNS + " FROM panel_servers WHERE id=:sid AND user_id=:u_id"
)

_DELETE_SERVER_FOR_USER = "DELETE FROM panel_servers WHERE id=:sid AND user_id=:u_id"

_UPDATE_SERVER_PREFIX = "UPDATE panel_servers SET "
_UPDATE_SERVER_SUFFIX = " WHERE id=:sid AND user_id=:u_id"

_SET_STARTUP = "startup=:startup"
_SET_NAME = "name=:name"
_SET_VERSION = "runtime=:runtime, version=:version"
_SET_VERSION_IMAGE = "runtime=:runtime, version=:version, image=:image"
_SET_DESIRED_STATE = "desired_state=:desired"

_PANEL_TABLES = ("PANEL_USERS", "PANEL_SERVERS")

_MODEL_COLUMNS = {
    "PANEL_USERS": (
        "ID",
        "USERNAME",
        "PASSWORD_HASH",
        "CONTAINER_SLOTS",
        "CREATED_AT",
    ),
    "PANEL_SERVERS": (
        "ID",
        "USER_ID",
        "NAME",
        "RUNTIME",
        "VERSION",
        "IMAGE",
        "STARTUP",
        "MEMORY_MB",
        "CPU_PERCENT",
        "DESIRED_STATE",
        "CREATED_AT",
        "NODE_ID",
    ),
}

_ADDITIVE_COLUMNS = {
    "PANEL_USERS": {
        "CONTAINER_SLOTS": "NUMBER(4) NULL",
    },
    "PANEL_SERVERS": {
        "DESIRED_STATE": "NUMBER DEFAULT 0 NOT NULL",
        "NODE_ID": "NUMBER NULL",
    },
}

_CREATE_DDL = {
    "PANEL_USERS": (
        (
            "CREATE TABLE panel_users ("
            "id VARCHAR2(36 CHAR) NOT NULL, "
            "username VARCHAR2(100 CHAR) NOT NULL, "
            "password_hash VARCHAR2(255 CHAR) NOT NULL, "
            "container_slots NUMBER(4), "
            "created_at DATE NOT NULL, "
            "PRIMARY KEY (id))",
            "created panel_users",
        ),
        (
            "CREATE UNIQUE INDEX ix_panel_users_username_lower "
            "ON panel_users (LOWER(username))",
            "created ix_panel_users_username_lower",
        ),
    ),
    "PANEL_SERVERS": (
        (
            "CREATE TABLE panel_servers ("
            "id VARCHAR2(36 CHAR) NOT NULL, "
            "user_id VARCHAR2(36 CHAR) NOT NULL, "
            "name VARCHAR2(255 CHAR) NOT NULL, "
            "runtime VARCHAR2(32 CHAR) NOT NULL, "
            "version VARCHAR2(32 CHAR) NOT NULL, "
            "image VARCHAR2(255 CHAR) NOT NULL, "
            "startup VARCHAR2(500 CHAR) NOT NULL, "
            "memory_mb NUMBER DEFAULT 300 NOT NULL, "
            "cpu_percent NUMBER DEFAULT 35 NOT NULL, "
            "desired_state NUMBER DEFAULT 0 NOT NULL, "
            "created_at DATE NOT NULL, "
            "node_id NUMBER, "
            "PRIMARY KEY (id), "
            "FOREIGN KEY(user_id) REFERENCES panel_users (id) ON DELETE CASCADE)",
            "created panel_servers",
        ),
        (
            "CREATE INDEX ix_panel_servers_user_id ON panel_servers (user_id)",
            "created ix_panel_servers_user_id",
        ),
    ),
}

_SELECT_PANEL_TABLES = "SELECT table_name FROM user_tables"

_SELECT_PANEL_COLUMNS = (
    "SELECT column_name FROM user_tab_columns WHERE table_name = :t"
)

_ALREADY_THERE = ("ORA-00955", "ORA-01430")

_LOCKED = ("ORA-00054", "ORA-04021", "ORA-04020")

_DDL_TRIES = 8

_MISSING_COLUMN = "ORA-00904"

_NOT_NULL_VIOLATION = "ORA-01400"

_PANEL_SCHEMA_ENSURED = False
_PANEL_SCHEMA_LOCK = threading.Lock()


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


def _password_hash_value(password_hash):
    text = password_hash if isinstance(password_hash, str) else str(password_hash)
    encoded = text.encode("utf-8", "surrogatepass")
    if max(len(text), len(encoded)) > PASSWORD_HASH_MAX_CHARS:
        raise ValueError(
            f"password hash must be at most {PASSWORD_HASH_MAX_CHARS} characters"
        )
    return password_hash


def _node_id_value(node_id):
    if node_id is None:
        return None
    try:
        value = int(node_id)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _is_integrity_error(exc) -> bool:
    try:
        import oracledb
    except ImportError:
        oracledb = None
    if oracledb is not None and isinstance(exc, oracledb.IntegrityError):
        return True
    message = str(exc)
    return any(tag in message for tag in _INTEGRITY_ORA_CODES)


def _panel_conn():
    try:
        return database._oracle_conn()
    except Exception as exc:
        if not database._is_pool_exhausted(exc):
            raise
        database._note_pool_busy()
        raise database.OraclePoolExhausted(f"Oracle unavailable: {exc}") from exc


def _user_dict(row):
    if row is None:
        return None
    slots = row["container_slots"]
    return {
        "id": row["id"],
        "username": row["username"],
        "password_hash": row["password_hash"],
        "container_slots": (None if slots is None else int(slots)),
        "created_at": _iso(row["created_at"]),
    }


def _server_dict(row):
    if row is None:
        return None
    node_id = row["node_id"]
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "runtime": row["runtime"],
        "version": row["version"],
        "image": row["image"],
        "startup": row["startup"],
        "memory_mb": int(row["memory_mb"] or 0),
        "cpu_percent": int(row["cpu_percent"] or 0),
        "desired_state": int(row["desired_state"] or 0),
        "created_at": _iso(row["created_at"]),
        "node_id": (None if node_id is None else int(node_id)),
    }


def _fetch_one_dict(cur):
    return database._oracle_dict_row(cur, cur.fetchone())


def _fetch_all_dicts(cur):
    rows = cur.fetchall()
    return [database._oracle_dict_row(cur, row) for row in rows]


def _read_user_by_id(cur, key):
    cur.execute(_SELECT_USER_BY_ID, {"id": key})
    return _fetch_one_dict(cur)


def _panel_ddl(cur, sql, describe):
    for _ in range(_DDL_TRIES):
        try:
            cur.execute(sql)
            print(f"[panel_data] schema: {describe}")
            return
        except Exception as exc:
            msg = str(exc)
            if any(tag in msg for tag in _ALREADY_THERE):
                return
            if not any(tag in msg for tag in _LOCKED):
                raise
            time.sleep(1.0)
    raise RuntimeError(
        f"could not lock the table to {describe} after {_DDL_TRIES} tries"
    )


def _panel_schema_pass():
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(_SELECT_PANEL_TABLES)
        present = {row[0].upper() for row in cur.fetchall()} & set(_PANEL_TABLES)
        missing = [table for table in _PANEL_TABLES if table not in present]
        if missing:
            print(
                "[panel_data] schema: creating "
                + ", ".join(table.lower() for table in missing)
            )
            for table in missing:
                for sql, describe in _CREATE_DDL[table]:
                    _panel_ddl(cur, sql, describe)
        for table in _PANEL_TABLES:
            if table not in present:
                continue
            cur.execute(_SELECT_PANEL_COLUMNS, {"t": table})
            have = {row[0].upper() for row in cur.fetchall()}
            known = _ADDITIVE_COLUMNS.get(table, {})
            for column in _MODEL_COLUMNS[table]:
                if column in have:
                    continue
                column_type = known.get(column)
                if not column_type:
                    print(
                        f"[panel_data] WARNING: {table.lower()}.{column.lower()} is in "
                        f"the model but not in the database, and _ADDITIVE_COLUMNS in "
                        f"panel_data.py has no DDL for it. Every query selecting it "
                        f"will fail with {_MISSING_COLUMN} until the column is added.",
                        file=stderr,
                    )
                    continue
                if not _IDENTIFIER_RE.fullmatch(table) or not _IDENTIFIER_RE.fullmatch(column):
                    raise ValueError(f"invalid SQL identifier in DDL: {table!r}.{column!r}")
                _panel_ddl(
                    cur,
                    f"ALTER TABLE {table} ADD ({column} {column_type})",
                    f"added {table.lower()}.{column.lower()}",
                )
    finally:
        conn.close()


def ensure_panel_schema(*, _force=False) -> None:
    global _PANEL_SCHEMA_ENSURED
    if _PANEL_SCHEMA_ENSURED and not _force:
        return
    with _PANEL_SCHEMA_LOCK:
        if _PANEL_SCHEMA_ENSURED and not _force:
            return
        _panel_schema_pass()
        _PANEL_SCHEMA_ENSURED = True


def _with_conn(work):
    conn = _panel_conn()
    try:
        return work(conn)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _run_with_heal(work):
    try:
        return _with_conn(work)
    except Exception as exc:
        if _MISSING_COLUMN not in str(exc):
            raise
        ensure_panel_schema(_force=True)
        return _with_conn(work)


def ensure_user_by_id(user_id, username):
    key = _user_key(user_id)
    if not key:
        return None
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        row = _read_user_by_id(cur, key)
        if row is not None:
            return _user_dict(row)
        try:
            cur.execute(
                _INSERT_USER,
                {
                    "id": key,
                    "uname": _clip_text(
                        (username or "").strip() or key, USERNAME_MAX_CHARS
                    ),
                    "ph": EXTERNAL_PLACEHOLDER,
                    "container_slots": 1,
                    "created": _utc_now(),
                },
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if not _is_integrity_error(exc):
                raise
            row = _read_user_by_id(cur, key)
            if row is None:
                raise MirrorConflict(
                    "panel user mirror row could not be written"
                ) from exc
            return _user_dict(row)
        return _user_dict(_read_user_by_id(cur, key))
    finally:
        conn.close()


def get_user(user_id):
    key = _user_key(user_id)
    if not key:
        return None
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        return _user_dict(_read_user_by_id(cur, key))
    finally:
        conn.close()


def get_user_by_username(username):
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            _SELECT_USER_BY_USERNAME,
            {"uname": (username or "").strip().lower()},
        )
        return _user_dict(_fetch_one_dict(cur))
    finally:
        conn.close()


def create_user(username, password_hash):
    normalized = (username or "").strip()
    if len(normalized) < 3 or len(normalized) > 32:
        raise ValueError("username must be between 3 and 32 characters")
    normalized = _clip_text(normalized, USERNAME_MAX_CHARS)
    stored = _password_hash_value(password_hash)
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(_SELECT_USER_ID_BY_USERNAME, {"uname": normalized.lower()})
        if cur.fetchone() is not None:
            raise ValueError("username is already registered")
        user_id = uuid4().hex
        try:
            cur.execute(
                _INSERT_USER,
                {
                    "id": user_id,
                    "uname": normalized,
                    "ph": stored,
                    "created": _utc_now(),
                },
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if not _is_integrity_error(exc):
                raise
            if _NOT_NULL_VIOLATION in str(exc):
                raise ValueError("password hash is required") from exc
            raise ValueError("username is already registered") from exc
        return user_id
    finally:
        conn.close()


def update_user_password(user_id, password_hash):
    key = _user_key(user_id)
    if not key:
        return False
    stored = _password_hash_value(password_hash)
    conn = _panel_conn()
    try:
        cur = conn.cursor()
        cur.execute(_UPDATE_USER_PASSWORD, {"ph": stored, "id": key, "container_slots": 1})
        conn.commit()
        return (cur.rowcount or 0) == 1
    finally:
        conn.close()


def create_server(
    *, server_id, user_id, name, runtime, version, image, startup, node_id=None,
    pick_node=None
):
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
        "runtime": _clip_text(runtime or "", RUNTIME_MAX_CHARS),
        "version": _clip_text(version or "", VERSION_MAX_CHARS),
        "image": _clip_text(image or "", IMAGE_MAX_CHARS),
        "startup": _clip_text((startup or "").strip(), STARTUP_MAX_CHARS),
        "memory_mb": 300,
        "cpu_percent": 35,
        "desired_state": 0,
        "created": _utc_now(),
        "node_id": _node_id_value(node_id),
    }

    def _insert(conn):
        cur = conn.cursor()
        if pick_node is not None:
            params["node_id"] = _node_id_value(pick_node(conn))
        params.setdefault("node_id", None)
        cur.execute(_INSERT_SERVER, params)
        conn.commit()
        return params["node_id"]

    return _run_with_heal(_insert)


def list_servers_for_user(user_id):
    owner = _user_key(user_id)
    if not owner:
        return []

    def _query(conn):
        cur = conn.cursor()
        cur.execute(_SELECT_SERVERS_FOR_USER, {"u_id": owner, "lim": SERVER_LIST_MAX})
        return [_server_dict(row) for row in _fetch_all_dicts(cur)]

    return _run_with_heal(_query)


def get_server_for_user(server_id, user_id):
    owner = _user_key(user_id)
    if not owner or not server_id:
        return None

    def _query(conn):
        cur = conn.cursor()
        cur.execute(_SELECT_SERVER_FOR_USER, {"sid": server_id, "u_id": owner})
        return _server_dict(_fetch_one_dict(cur))

    return _run_with_heal(_query)


def delete_server_for_user(server_id, user_id):
    owner = _user_key(user_id)
    if not owner or not server_id:
        return False

    def _do_delete(conn):
        cur = conn.cursor()
        cur.execute(_DELETE_SERVER_FOR_USER, {"sid": server_id, "u_id": owner})
        conn.commit()
        return (cur.rowcount or 0) == 1

    return _run_with_heal(_do_delete)


def _update_server(server_id, user_id, set_clause, values):
    owner = _user_key(user_id)
    if not owner or not server_id:
        return False
    params = dict(values)
    params["sid"] = server_id
    params["u_id"] = owner
    sql = _UPDATE_SERVER_PREFIX + set_clause + _UPDATE_SERVER_SUFFIX

    def _do_update(conn):
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        return (cur.rowcount or 0) == 1

    return _run_with_heal(_do_update)


def update_server_startup(server_id, user_id, startup):
    return _update_server(
        server_id,
        user_id,
        _SET_STARTUP,
        {"startup": _clip_text((startup or "").strip(), STARTUP_MAX_CHARS)},
    )


def update_server_name(server_id, user_id, name):
    return _update_server(
        server_id,
        user_id,
        _SET_NAME,
        {"name": _clip_text((name or "").strip(), NAME_MAX_CHARS)},
    )


def update_server_version(server_id, user_id, runtime, version, image=None):
    values = {
        "runtime": _clip_text((runtime or "").strip().lower(), RUNTIME_MAX_CHARS),
        "version": _clip_text((version or "").strip(), VERSION_MAX_CHARS),
    }
    set_clause = _SET_VERSION
    if image:
        values["image"] = _clip_text(image, IMAGE_MAX_CHARS)
        set_clause = _SET_VERSION_IMAGE
    return _update_server(server_id, user_id, set_clause, values)


def update_server_state(server_id, user_id, running):
    return _update_server(
        server_id,
        user_id,
        _SET_DESIRED_STATE,
        {"desired": 1 if running else 0},
    )

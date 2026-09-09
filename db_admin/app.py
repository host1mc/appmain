"""DB Admin — console for Oracle SQL, MongoDB, and HeatWave MySQL.

Run:
    python app.py [--host 0.0.0.0] [--port 8004] [--debug]
"""

import argparse
import csv
import datetime
import io
import json
import os
import re
import sys
import time
from decimal import Decimal
from datetime import date
from urllib.parse import quote

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# crypto_util lives in app1 (and a vendored copy in admin). The old "app"
# sibling does not exist in this repo, so imports silently fell through.
for _candidate in (
    os.path.join(BASE_DIR, "..", "app1"),
    os.path.join(BASE_DIR, "..", "admin"),
):
    _abs = os.path.abspath(_candidate)
    if os.path.isdir(_abs) and _abs not in sys.path:
        sys.path.insert(0, _abs)


# Shard IDs
SHARD_ORACLE = 0      # Oracle SQL - BOTHOST (default)
SHARD_ORACLE_2 = 1    # Oracle SQL - BOTHOST1
SHARD_HEATWAVE = 99   # HeatWave MySQL
SHARD_MONGO_BASE = 100  # Mongo shard ids are SHARD_MONGO_BASE + DB_<idx> (100..163)


def _load_env():
    env_path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


_load_env()

try:
    from crypto_util import decrypt as _decrypt
    from crypto_util import looks_encrypted as _looks_encrypted
except Exception:
    _decrypt = None

    def _looks_encrypted(value):
        return isinstance(value, str) and (value.startswith("gAAAAA") or value.startswith("gcm1."))


from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)


def _persist_secret():
    raw = (os.environ.get("DBADMIN_SECRET") or "").strip()
    if raw:
        return raw
    path = os.path.join(BASE_DIR, "data", "flask_secret")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            stored = open(path, encoding="ascii").read().strip()
            if stored:
                return stored
        import secrets as _secrets
        value = _secrets.token_hex(32)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(value)
        return value
    except FileExistsError:
        return open(path, encoding="ascii").read().strip() or os.urandom(32).hex()
    except OSError:
        return os.urandom(32).hex()


app.secret_key = _persist_secret()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

# ─── Oracle SQL ──────────────────────────────────────────────────────────────

_oracle_pools = {}  # {shard_id: connection}
_oracle_live = {}   # requested shard -> dsn index actually in use
_oracle_skip = set()  # DSN strings skipped because storage is full


def _resolve_shard(shard_id=None):
    """SHARD_ORACLE is 0, which is falsy — never use ``shard_id or``."""
    if shard_id is None:
        return _get_shard_id()
    return shard_id


def _oracle_targets():
    """ORACLE_DSN, ORACLE_DSN_1, ORACLE_DSN_2, … from .env."""
    out = []
    primary = (os.environ.get("ORACLE_DSN") or "").strip()
    if primary:
        out.append({
            "i": 0,
            "dsn": primary,
            "user": os.environ.get("ORACLE_USER", "ADMIN"),
            "password": os.environ.get("ORACLE_PASSWORD", ""),
        })
    for idx in range(1, 8):
        dsn = (os.environ.get(f"ORACLE_DSN_{idx}") or "").strip()
        if not dsn:
            continue
        out.append({
            "i": idx,
            "dsn": dsn,
            "user": os.environ.get(f"ORACLE_USER_{idx}") or os.environ.get("ORACLE_USER", "ADMIN"),
            "password": os.environ.get(f"ORACLE_PASSWORD_{idx}") or os.environ.get("ORACLE_PASSWORD", ""),
        })
    return out


def _oracle_conn(shard_id=None):
    """Get an Oracle SQL connection; hop to the next DSN if this one is down."""
    sid = _resolve_shard(shard_id)
    if sid in _oracle_pools:
        conn = _oracle_pools[sid]
        try:
            conn.ping()
            return conn
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            _oracle_pools.pop(sid, None)
    import oracledb
    oracledb.defaults.fetch_lobs = False
    targets = _oracle_targets()
    if not targets:
        raise RuntimeError("ORACLE_DSN not set")
    start = 0
    for n, t in enumerate(targets):
        if t["i"] == sid:
            start = n
            break
    last = None
    for t in targets[start:] + targets[:start]:
        if t["dsn"] in _oracle_skip and any(x["dsn"] not in _oracle_skip for x in targets):
            continue
        try:
            conn = oracledb.connect(user=t["user"], password=t["password"], dsn=t["dsn"])
            if _oracle_storage_full(conn) and any(x["dsn"] != t["dsn"] for x in targets):
                _oracle_skip.add(t["dsn"])
                print(f"[db_admin] Oracle DSN index {t['i']} storage full, next DSN")
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            _oracle_pools[sid] = conn
            _oracle_live[sid] = t["i"]
            if t["i"] != sid:
                print(f"[db_admin] Oracle failover shard {sid} -> DSN_{t['i'] or ''}")
            return conn
        except Exception as ex:
            last = ex
            print(f"[db_admin] Oracle DSN index {t['i']} unreachable: {ex}")
            continue
    raise RuntimeError(f"Oracle unreachable: {last}")


_ORACLE_STORAGE_MARKERS = (
    "ORA-01653", "ORA-01654", "ORA-01652", "ORA-01658", "ORA-01659",
    "ORA-01631", "ORA-01632", "ORA-01688", "ORA-01691",
    "ORA-01536", "ORA-12953", "ORA-12954", "ORA-30036",
    "unable to extend",
)


def _is_oracle_storage_full(exc) -> bool:
    msg = str(exc or "")
    return any(tag.lower() in msg.lower() for tag in _ORACLE_STORAGE_MARKERS)


def _oracle_storage_full(conn) -> bool:
    try:
        cur = conn.cursor()
        cur.execute("SELECT NVL(SUM(bytes), 0) FROM user_segments")
        used = int(cur.fetchone()[0] or 0)
        cur.execute(
            "SELECT NVL(SUM(CASE WHEN max_bytes < 0 THEN NULL ELSE max_bytes END), 0) "
            "FROM user_ts_quotas"
        )
        quota = int(cur.fetchone()[0] or 0)
        cur.close()
        if quota <= 0:
            try:
                quota = int(float(os.environ.get("ORACLE_STORAGE_GB", "20"))) * (1024 ** 3)
            except (TypeError, ValueError):
                quota = 20 * (1024 ** 3)
        remaining = quota - used
        return remaining <= 32 * 1024 * 1024 or (quota and used / quota >= 0.95)
    except Exception as ex:
        return _is_oracle_storage_full(ex)


def _oracle_query(sql, params=None, shard_id=None):
    """Execute SQL on Oracle and return list of dicts."""
    sid = _resolve_shard(shard_id)
    last = None
    for _attempt in range(3):
        conn = _oracle_conn(sid)
        cur = conn.cursor()
        try:
            cur.execute(sql, params or ())
            if cur.description:
                cols = [d[0] for d in cur.description]
                rows = []
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    rec.pop("RN", None)
                    rec.pop("rn", None)
                    rows.append(rec)
                return rows
            conn.commit()
            return []
        except Exception as ex:
            last = ex
            try:
                conn.close()
            except Exception:
                pass
            _oracle_pools.pop(sid, None)
            if _is_oracle_storage_full(ex):
                live_i = _oracle_live.get(sid)
                for t in _oracle_targets():
                    if t["i"] == live_i:
                        _oracle_skip.add(t["dsn"])
                        break
            print(f"[db_admin] Oracle query failed, retry/failover: {ex}")
            continue
        finally:
            try:
                cur.close()
            except Exception:
                pass
    raise last


# ─── MongoDB ─────────────────────────────────────────────────────────────────

_mongo_clients = {}
_mongo_dbs = {}


def _load_mongo_shard_uris():
    shards = {}
    for idx in range(64):
        uri = os.environ.get(f"DB_{idx}", "")
        if uri:
            shards[idx] = uri
    return shards


def _mongo(shard_id=None):
    global _mongo_clients, _mongo_dbs
    if shard_id is None:
        shard_id = _get_shard_id()
    if shard_id not in _mongo_dbs:
        from pymongo import MongoClient
        shards = _load_mongo_shard_uris()
        uri = shards.get(shard_id - SHARD_MONGO_BASE, "")
        if not uri:
            raise RuntimeError(f"No MongoDB URI for shard {shard_id}")
        _mongo_clients[shard_id] = MongoClient(uri, tls=True)
        _mongo_dbs[shard_id] = _mongo_clients[shard_id].get_database()
    return _mongo_dbs[shard_id]


# ─── HeatWave MySQL ──────────────────────────────────────────────────────────

_heatwave_conn = None


def _heatwave_enabled():
    return bool(os.environ.get("MYSQL_HOST", "").strip())


def _heatwave_connect():
    global _heatwave_conn
    if _heatwave_conn is not None:
        try:
            _heatwave_conn.ping(reconnect=True, attempts=1, delay=0)
            return _heatwave_conn
        except Exception:
            try:
                _heatwave_conn.close()
            except Exception:
                pass
            _heatwave_conn = None
    import mysql.connector
    ssl_ca = os.environ.get("MYSQL_SSL_CA", "").strip()
    kwargs = dict(
        host=os.environ.get("MYSQL_HOST", ""),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "ADMIN"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=os.environ.get("MYSQL_DATABASE", "heatwavesql"),
        connection_timeout=10,
        charset="utf8mb4",
    )
    if ssl_ca:
        if not os.path.isabs(ssl_ca):
            ssl_ca = os.path.join(BASE_DIR, ssl_ca)
        kwargs.update(ssl_ca=ssl_ca, ssl_verify_cert=True, ssl_verify_identity=False)
    _heatwave_conn = mysql.connector.connect(**kwargs)
    return _heatwave_conn


def _heatwave_query(sql, params=None):
    conn = _heatwave_connect()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, params or ())
        if cursor.description:
            return cursor.fetchall()
        conn.commit()
        return []
    finally:
        cursor.close()


# ─── shard helpers ───────────────────────────────────────────────────────────

_IDENT_RE = __import__("re").compile(r"\A[A-Za-z][A-Za-z0-9_$#]{0,127}\Z")
_TEXT_TYPES = (
    "CHAR", "NCHAR", "VARCHAR", "VARCHAR2", "NVARCHAR2", "CLOB", "NCLOB",
    "LONG", "TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT", "JSON", "ENUM",
)


def _ident(name):
    text = str(name or "").strip()
    if not _IDENT_RE.match(text):
        raise ValueError(f"invalid identifier: {name!r}")
    return text


def _ora_ident(name):
    return '"' + _ident(name).replace('"', "") + '"'


def _my_ident(name):
    return "`" + _ident(name).replace("`", "") + "`"


def _pk_field(fields):
    by_upper = {str(k).upper(): k for k in (fields or {})}
    for candidate in ("ID", "UID", "USER_ID", "USERID", "_ID"):
        if candidate in by_upper:
            return by_upper[candidate]
    return next(iter(fields), None) if fields else None


def _text_columns(fields):
    out = []
    for name, dtype in (fields or {}).items():
        kind = str(dtype or "").upper()
        if any(kind.startswith(t) or t in kind for t in _TEXT_TYPES):
            out.append(name)
    return out or list(fields.keys())


def _get_shard_id():
    try:
        return session.get("shard_id", SHARD_ORACLE)
    except RuntimeError:
        return SHARD_ORACLE


def get_available_shards():
    shards = [t["i"] for t in _oracle_targets()] or [SHARD_ORACLE]
    if _heatwave_enabled():
        shards.append(SHARD_HEATWAVE)
    for idx in sorted(_load_mongo_shard_uris()):
        shards.append(SHARD_MONGO_BASE + idx)
    return shards


def _is_oracle(shard_id=None):
    s = _resolve_shard(shard_id)
    return s != SHARD_HEATWAVE and s < SHARD_MONGO_BASE


def _is_heatwave(shard_id=None):
    return _resolve_shard(shard_id) == SHARD_HEATWAVE


def _is_mongo(shard_id=None):
    return _resolve_shard(shard_id) >= SHARD_MONGO_BASE


def _list_tables(shard_id=None):
    s = _resolve_shard(shard_id)
    if _is_oracle(s):
        rows = _oracle_query(
            "SELECT table_name FROM user_tables ORDER BY table_name", shard_id=s
        )
        return [r["TABLE_NAME"] for r in rows]
    if _is_heatwave(s):
        rows = _heatwave_query("SHOW TABLES")
        return sorted(str(list(r.values())[0]) for r in rows) if rows else []
    if _is_mongo(s):
        return sorted(_mongo(s).list_collection_names())
    return []


def has_request_context():
    try:
        request.path
        return True
    except RuntimeError:
        return False


def all_collections():
    if has_request_context() and getattr(g, "_all_collections", None) is not None:
        return g._all_collections
    try:
        names = _list_tables()
    except Exception as exc:
        print(f"[db_admin] list tables failed: {exc}")
        names = []
    if has_request_context():
        g._all_collections = names
    return names


def collection_fields(coll_name):
    s = _get_shard_id()
    try:
        name = _ident(coll_name)
        if _is_oracle(s):
            rows = _oracle_query(
                "SELECT column_name, data_type FROM user_tab_columns "
                "WHERE table_name = :1 ORDER BY column_id",
                [name.upper()],
                shard_id=s,
            )
            return {r["COLUMN_NAME"]: r["DATA_TYPE"] for r in rows} if rows else {}
        if _is_heatwave(s):
            rows = _heatwave_query(f"DESCRIBE {_my_ident(name)}")
            return {r["Field"]: r["Type"] for r in rows} if rows else {}
        if _is_mongo(s):
            sample = _mongo(s)[name].find_one() or {}
            return {k: type(v).__name__ for k, v in sample.items()}
    except Exception as exc:
        print(f"[db_admin] fields for {coll_name} failed: {exc}")
    return {}


def _user_id_field(coll_name, fields):
    """Column linking a table's rows back to a user, or None if it has no
    such link.  "uid" is the canonical join key; USER_ID/USERID are the
    older names still present on shards built before the uid schema."""
    by_upper = {k.upper(): k for k in fields}
    for candidate in ("UID", "USER_ID", "USERID"):
        if candidate in by_upper:
            return by_upper[candidate]
    if coll_name.upper() == "USERS":
        return by_upper.get("ID")
    return None


def collection_count(coll_name):
    s = _get_shard_id()
    try:
        name = _ident(coll_name)
        if _is_oracle(s):
            rows = _oracle_query(
                f"SELECT COUNT(*) AS cnt FROM {_ora_ident(name)}", shard_id=s
            )
            return rows[0]["CNT"] if rows else 0
        if _is_heatwave(s):
            rows = _heatwave_query(f"SELECT COUNT(*) AS cnt FROM {_my_ident(name)}")
            return rows[0]["cnt"] if rows else 0
        if _is_mongo(s):
            return _mongo(s)[name].estimated_document_count()
    except Exception as exc:
        print(f"[db_admin] count {coll_name} failed: {exc}")
    return 0


def _fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} TB"


def storage_report():
    """Used vs remaining storage on the current data plane."""
    used = 0
    quota = 0
    note = ""
    s = _get_shard_id()
    try:
        if _is_oracle(s):
            rows = _oracle_query(
                "SELECT NVL(SUM(bytes), 0) AS used FROM user_segments", shard_id=s
            )
            used = int(rows[0]["USED"] if rows else 0)
            qrows = _oracle_query(
                "SELECT NVL(SUM(CASE WHEN max_bytes < 0 THEN NULL ELSE max_bytes END), 0) AS q "
                "FROM user_ts_quotas",
                shard_id=s,
            )
            quota = int(qrows[0]["Q"] if qrows else 0)
            if quota <= 0:
                try:
                    quota = int(float(os.environ.get("ORACLE_STORAGE_GB", "20"))) * (1024 ** 3)
                    note = "quota from ORACLE_STORAGE_GB (default 20 GB ATP)"
                except (TypeError, ValueError):
                    quota = 20 * (1024 ** 3)
                    note = "default 20 GB ATP cap"
        elif _is_heatwave(s):
            rows = _heatwave_query(
                "SELECT COALESCE(SUM(data_length + index_length), 0) AS used "
                "FROM information_schema.tables WHERE table_schema = DATABASE()"
            )
            used = int(rows[0]["used"] if rows else 0)
            try:
                quota = int(float(os.environ.get("MYSQL_STORAGE_GB", "50"))) * (1024 ** 3)
            except (TypeError, ValueError):
                quota = 50 * (1024 ** 3)
            note = "quota from MYSQL_STORAGE_GB (default 50 GB)"
        elif _is_mongo(s):
            stats = _mongo(s).command("dbStats")
            used = int(stats.get("dataSize") or 0) + int(stats.get("indexSize") or 0)
            quota = int(stats.get("fsTotalSize") or 0)
            note = "Mongo dbStats"
    except Exception as exc:
        print(f"[db_admin] storage_report: {exc}")
        note = str(exc)
    remaining = max(0, quota - used) if quota else 0
    pct = (100.0 * used / quota) if quota else 0.0
    return {
        "used": used,
        "quota": quota,
        "remaining": remaining,
        "pct": min(100.0, pct),
        "used_h": _fmt_bytes(used),
        "quota_h": _fmt_bytes(quota) if quota else "unknown",
        "remaining_h": _fmt_bytes(remaining) if quota else "unknown",
        "note": note,
    }


def collections_report():
    if has_request_context() and getattr(g, "_collections_report", None) is not None:
        return g._collections_report
    out = []
    all_names = all_collections()
    for name in all_names:
        try:
            cnt = collection_count(name)
            fields = collection_fields(name)
            out.append({
                "name": name,
                "rows": cnt,
                "fields": len(fields),
                "field_list": list(fields.keys()),
            })
        except Exception:
            out.append({"name": name, "rows": 0, "fields": 0, "field_list": []})
    out.sort(key=lambda x: -x["rows"])
    total_rows = sum(t["rows"] for t in out)
    result = (out, {"rows": total_rows, "collections": len(out)})
    if has_request_context():
        g._collections_report = result
    return result


def username_map():
    """uid -> display username for the current shard."""
    if has_request_context() and getattr(g, "_username_map", None) is not None:
        return g._username_map
    names = {}
    all_cols = all_collections()
    if not any(c.upper() == "USERS" for c in all_cols):
        if has_request_context():
            g._username_map = names
        return names
    users_tbl = next(c for c in all_cols if c.upper() == "USERS")
    fields = collection_fields(users_tbl)
    users_id_field = _user_id_field(users_tbl, fields) or (
        list(fields.keys())[0] if fields else "uid")
    shard_id = _get_shard_id()
    try:
        if _is_oracle(shard_id):
            rows = _oracle_query(f'SELECT * FROM "{users_tbl}" WHERE ROWNUM <= 2000')
        elif _is_heatwave(shard_id):
            rows = _heatwave_query(f"SELECT * FROM {_my_ident(users_tbl)} LIMIT 2000")
        else:
            rows = list(_mongo(shard_id)[users_tbl].find().limit(2000))
        for doc in rows or []:
            uid = str(_iget(doc, users_id_field) or _iget(doc, "UID") or _iget(doc, "uid") or "")
            uname = _iget(doc, "USERNAME") or _iget(doc, "username") or _iget(doc, "DISPLAY_NAME") or ""
            if uname and _looks_encrypted(str(uname)) and _decrypt:
                try:
                    uname = _decrypt(str(uname))
                except Exception:
                    pass
            if uid and uname:
                names[uid] = str(uname)
    except Exception as exc:
        print(f"[db_admin] username_map: {exc}")
    if has_request_context():
        g._username_map = names
    return names


USERS_SCAN_CAP = 40  # ponytail: max user-linked tables GROUP-BY'd for the overview; raise if a plane needs an exhaustive identity list


def _linked_tables(shard_id, all_cols):
    """(table, user_id_column) for every table that joins back to a user.

    On Oracle this resolves in a single user_tab_columns query rather than one
    per table, which is what made the Identities overview hang on a wide
    catalog.  HeatWave/Mongo keep the per-table sample (small, rarely used)."""
    if _is_oracle(shard_id):
        try:
            rows = _oracle_query(
                "SELECT table_name, column_name FROM user_tab_columns "
                "WHERE column_name IN ('UID', 'USER_ID', 'USERID') "
                "OR (table_name = 'USERS' AND column_name = 'ID')",
                shard_id=shard_id,
            )
        except Exception:
            rows = []
        known = {c.upper(): c for c in all_cols}
        rank = {"UID": 0, "USER_ID": 1, "USERID": 2, "ID": 3}
        best = {}
        for r in rows:
            disp = known.get(str(r["TABLE_NAME"]).upper())
            col = r["COLUMN_NAME"]
            if not disp:
                continue
            if disp not in best or rank.get(col, 9) < rank.get(best[disp], 9):
                best[disp] = col
        return list(best.items())
    out = []
    for coll_name in all_cols:
        id_field = _user_id_field(coll_name, collection_fields(coll_name))
        if id_field:
            out.append((coll_name, id_field))
    return out


def users_report():
    """Per-uid row counts across tables that link back to a user."""
    all_cols = all_collections()
    shard_id = _get_shard_id()
    per_user = {}

    linked = _linked_tables(shard_id, all_cols)
    # USERS first so identities still resolve when the scan is capped
    linked.sort(key=lambda cf: cf[0].upper() != "USERS")
    if len(linked) > USERS_SCAN_CAP:
        linked = linked[:USERS_SCAN_CAP]

    for coll_name, id_field in linked:
        if _is_oracle(shard_id):
            try:
                rows = _oracle_query(
                    f'SELECT "{id_field}" AS u_id, COUNT(*) AS cnt '
                    f'FROM "{coll_name}" GROUP BY "{id_field}"'
                )
                for r in rows:
                    uid = str(r["U_ID"]) if r["U_ID"] is not None else ""
                    if not uid:
                        continue
                    per_user.setdefault(uid, {})
                    per_user[uid][coll_name] = r["CNT"]
            except Exception:
                pass
        elif _is_heatwave(shard_id):
            try:
                rows = _heatwave_query(
                    f"SELECT `{id_field}` AS uid, COUNT(*) AS cnt "
                    f"FROM `{coll_name}` GROUP BY `{id_field}`"
                )
                for r in rows:
                    uid = str(r["uid"]) if r["uid"] is not None else ""
                    if not uid:
                        continue
                    per_user.setdefault(uid, {})
                    per_user[uid][coll_name] = r["cnt"]
            except Exception:
                pass
        else:
            # MongoDB
            try:
                col = _mongo(shard_id)[coll_name]
                pipeline = [{"$group": {"_id": f"${id_field}", "count": {"$sum": 1}}}]
                for grp in col.aggregate(pipeline):
                    uid = str(grp["_id"]) if grp["_id"] is not None else ""
                    if not uid:
                        continue
                    per_user.setdefault(uid, {})
                    per_user[uid][coll_name] = grp["count"]
            except Exception:
                pass

    # Get usernames from USERS table
    names = username_map()

    result = []
    for uid, cols_d in per_user.items():
        result.append({
            "id": uid,
            "name": names.get(uid, ""),
            "tables": len(cols_d),
            "rows": sum(cols_d.values()),
            "bytes": 0,
            "breakdown": sorted(
                ((t, c, 0) for t, c in cols_d.items()), key=lambda x: -x[1]
            ),
        })
    result.sort(key=lambda x: -x["rows"])
    return result


# ─── display helpers ─────────────────────────────────────────────────────────

MASK_FIELDS = {"password", "hashed_password", "token_enc", "secret", "token"}
_MASK_KEYS = ("pass", "secret", "token")
_SENSITIVE_SUBSTRINGS = (
    "pass", "secret", "token", "apikey", "api_key", "privkey", "private_key",
    "credential", "session", "cookie", "salt", "otp", "totp", "mfa",
    "webhook", "refresh", "recovery",
)


def _leaf(col):
    return (col or "").lower().rsplit(".", 1)[-1]


def _is_sensitive(col):
    name = _leaf(col)
    if not name:
        return False
    if name in MASK_FIELDS:
        return True
    return any(s in name for s in _SENSITIVE_SUBSTRINGS)


def display_value(val, col="", key=None):
    if val is None:
        return None
    s = str(val)
    if _is_sensitive(col):
        return "********"
    if _leaf(col) == "value" and key and any(m in str(key).lower() for m in _MASK_KEYS):
        return "********"
    if _looks_encrypted(s):
        if _decrypt:
            try:
                return _decrypt(s)
            except Exception:
                return "[cannot decrypt]"
        return "[encrypted]"
    if _leaf(col) in ("uid", "user_id", "userid"):
        uname = username_map().get(s)
        if uname:
            return uname
    return s


def safe_json(v):
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return round(v, 6)
    if isinstance(v, (datetime.datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return str(v)


def _flatten(doc, prefix=""):
    items = {}
    for k, v in doc.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            items.update(_flatten(v, full))
        elif isinstance(v, list):
            items[full] = json.dumps(v, default=str)[:300]
        else:
            items[full] = v
    return items


# ─── routes ──────────────────────────────────────────────────────────────────

@app.route("/switch/<int:shard_id>")
def switch_shard(shard_id):
    from flask import session
    available = get_available_shards()
    if shard_id in available:
        session["shard_id"] = shard_id
        flash(f"Switched to database shard {shard_id}", "success")
    else:
        flash(f"Shard {shard_id} not available", "error")
    dest = _local_next(url_for("dashboard"))
    # a table/user open on the old plane may be absent on the new one → its list
    if dest.startswith("/table/"):
        dest = url_for("tables_page")
    elif dest.startswith("/user/"):
        dest = url_for("users_page")
    return redirect(dest)


def _known_table(tname):
    all_names = all_collections()
    return tname in all_names or tname.upper() in [n.upper() for n in all_names]


@app.route("/")
def dashboard():
    tables, totals = collections_report()
    storage = storage_report()
    live = sum(1 for t in tables if t.get("rows"))
    return render_template(
        "dashboard.html",
        tables=tables,
        totals=totals,
        storage=storage,
        live_count=live,
        field_count=sum(t.get("fields") or 0 for t in tables),
    )


@app.route("/analytics")
def analytics_page():
    tables, totals = collections_report()
    live_count = sum(1 for t in tables if t.get("rows"))
    idle_count = max(0, len(tables) - live_count)
    peak = tables[0] if tables else None
    peak_share = (100.0 * peak["rows"] / totals["rows"]) if peak and totals.get("rows") else 0.0
    field_sum = sum(t.get("fields") or 0 for t in tables)
    avg_fields = round(field_sum / len(tables), 1) if tables else 0
    return render_template(
        "analytics.html",
        tables=tables,
        totals=totals,
        live_count=live_count,
        idle_count=idle_count,
        peak=peak,
        peak_share=peak_share,
        avg_fields=avg_fields,
    )


@app.route("/tables")
def tables_page():
    tables, totals = collections_report()
    return render_template("tables.html", tables=tables, totals=totals)


@app.route("/table/<tname>")
def table_view(tname):
    if not _known_table(tname):
        abort(404)
    per_page = request.args.get("per", 50, type=int) or 50
    per_page = min(max(per_page, 10), 500)
    page = max(1, request.args.get("page", 1, type=int) or 1)
    q = request.args.get("q", "").strip()

    total_rows = collection_count(tname)
    fields = collection_fields(tname)
    col_names = list(fields.keys())
    shard_id = _get_shard_id()
    skip = (page - 1) * per_page
    rows = []

    s = shard_id
    search_cols = _text_columns(fields)
    try:
        tq = _ident(tname)
        if _is_oracle(s):
            if q and search_cols:
                like_clauses = [f'{_ora_ident(c)} LIKE :q' for c in search_cols]
                where = " OR ".join(like_clauses)
                count_rows = _oracle_query(
                    f"SELECT COUNT(*) AS cnt FROM {_ora_ident(tq)} WHERE {where}",
                    {"q": f"%{q}%"},
                    shard_id=s,
                )
                total_rows = count_rows[0]["CNT"] if count_rows else 0
                rows = _oracle_query(
                    f"SELECT * FROM (SELECT t.*, ROWNUM AS rn FROM "
                    f"(SELECT * FROM {_ora_ident(tq)} WHERE {where} ORDER BY 1) t "
                    f"WHERE ROWNUM <= :end_row) WHERE rn > :start_row",
                    {"q": f"%{q}%", "end_row": skip + per_page, "start_row": skip},
                    shard_id=s,
                )
            else:
                rows = _oracle_query(
                    f"SELECT * FROM (SELECT t.*, ROWNUM AS rn FROM "
                    f"(SELECT * FROM {_ora_ident(tq)} ORDER BY 1) t "
                    f"WHERE ROWNUM <= :end_row) WHERE rn > :start_row",
                    {"end_row": skip + per_page, "start_row": skip},
                    shard_id=s,
                )
        elif _is_heatwave(s):
            if q and search_cols:
                like_clauses = [f"{_my_ident(c)} LIKE %s" for c in search_cols]
                where = " OR ".join(like_clauses)
                params = [f"%{q}%"] * len(search_cols)
                count_rows = _heatwave_query(
                    f"SELECT COUNT(*) AS cnt FROM {_my_ident(tq)} WHERE {where}", params
                )
                total_rows = count_rows[0]["cnt"] if count_rows else 0
                rows = _heatwave_query(
                    f"SELECT * FROM {_my_ident(tq)} WHERE {where} LIMIT %s OFFSET %s",
                    params + [per_page, skip],
                )
            else:
                rows = _heatwave_query(
                    f"SELECT * FROM {_my_ident(tq)} LIMIT %s OFFSET %s",
                    [per_page, skip],
                )
        elif _is_mongo(s):
            col = _mongo(s)[tq]
            if q and search_cols:
                or_clause = [{c: {"$regex": q, "$options": "i"}} for c in search_cols]
                rows = list(col.find({"$or": or_clause}).skip(skip).limit(per_page))
            else:
                rows = list(col.find().skip(skip).limit(per_page))
    except Exception as e:
        print(f"[db_admin] table_view {tname}: {e}")

    pages = max(1, (total_rows + per_page - 1) // per_page)
    return render_template(
        "table_view.html",
        tname=tname, col_names=col_names, fields=fields, rows=rows,
        page=page, per_page=per_page, pages=pages,
        total_rows=total_rows, q=q, pk_col=_pk_field(fields),
    )


@app.route("/table/<tname>/export.csv")
def export_csv(tname):
    if not _known_table(tname):
        abort(404)
    fields = collection_fields(tname)
    col_names = list(fields.keys())
    buf = io.StringIO()
    w = csv.writer(buf)
    shard_id = _get_shard_id()
    row_count = 0
    w.writerow(col_names)
    try:
        tq = _ident(tname)
        if _is_oracle(shard_id):
            rows = _oracle_query(f"SELECT * FROM {_ora_ident(tq)}", shard_id=shard_id)
            for row in rows:
                w.writerow([display_value(row.get(c, ""), c) for c in col_names])
                row_count += 1
        elif _is_heatwave(shard_id):
            rows = _heatwave_query(f"SELECT * FROM {_my_ident(tq)}")
            for row in rows:
                w.writerow([display_value(row.get(c, ""), c) for c in col_names])
                row_count += 1
        else:
            for doc in _mongo(shard_id)[tq].find():
                flat = _flatten(doc)
                w.writerow([display_value(str(flat.get(c, "")), c) for c in col_names])
                row_count += 1
    except Exception as e:
        print(f"[db_admin] export {tname}: {e}")

    out = "\ufeff" + buf.getvalue()
    resp = Response(out, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{tname}.csv"'
    return resp


def _iget(doc, key):
    """Case-insensitive dict get — Oracle returns upper-cased column names."""
    if key in doc:
        return doc[key]
    for k in doc:
        if k.upper() == key.upper():
            return doc[k]
    return None


def _local_next(default):
    """A same-site path to send the browser back to after a destructive action.

    Keeps the operator on the page they acted from instead of bouncing them
    to an unrelated one. Accepts a form "next" field or the Referer header,
    and refuses anything off-site or non-path-shaped.
    """
    target = (request.form.get("next") or "").strip()
    if not target and request.referrer:
        target = request.referrer
    if target.startswith(("http://", "https://")):
        from urllib.parse import urlsplit as _us
        parts = _us(target)
        if parts.netloc and parts.netloc != request.host:
            return default
        target = parts.path + (("?" + parts.query) if parts.query else "")
    if not target.startswith("/") or target.startswith("//"):
        return default
    return target


@app.route("/users/delete_selected", methods=["POST"])
def users_delete_selected():
    uids = [u.strip() for u in request.form.getlist("uid") if u.strip()]
    if not uids:
        flash("No users selected.", "error")
        return redirect(url_for("users_page"))
    total_deleted = 0
    cols_deleted = 0
    order = [_get_shard_id()]
    for uid in uids:
        for coll_name in all_collections():
            fields = collection_fields(coll_name)
            id_field = _user_id_field(coll_name, fields)
            if not id_field:
                continue
            for s in order:
                try:
                    if _is_oracle(s):
                        _oracle_query(f'DELETE FROM "{coll_name}" WHERE "{id_field}" = :1', [uid], shard_id=s)
                        total_deleted += 1
                        cols_deleted += 1
                    elif _is_heatwave(s):
                        _heatwave_query(f"DELETE FROM `{coll_name}` WHERE `{id_field}` = %s", [uid])
                        total_deleted += 1
                        cols_deleted += 1
                    else:
                        result = _mongo(s)[coll_name].delete_many({id_field: uid})
                        total_deleted += result.deleted_count
                        if result.deleted_count:
                            cols_deleted += 1
                    break
                except Exception as e:
                    print(f"[fallback] users_delete_selected shard {s} failed: {e}")
                    continue
    flash(f"Deleted {total_deleted} rows across {cols_deleted} collections for "
          f"{len(uids)} user(s).", "success")
    return redirect(url_for("users_page"))


@app.route("/table/<tname>/delete_rows", methods=["POST"])
def delete_rows(tname):
    if not _known_table(tname):
        abort(404)
    rowids = [r.strip() for r in request.form.getlist("rowid") if r.strip()]
    if not rowids:
        flash("No rows selected.", "error")
        return redirect(url_for("table_view", tname=tname))
    deleted = 0
    shard_id = _get_shard_id()
    fields = collection_fields(tname)
    pk = _pk_field(fields)
    if not pk:
        flash("No primary key column for this table.", "error")
        return redirect(url_for("table_view", tname=tname))
    s = shard_id
    try:
        tq = _ident(tname)
        if _is_oracle(s):
            for rid in rowids:
                try:
                    _oracle_query(
                        f"DELETE FROM {_ora_ident(tq)} WHERE {_ora_ident(pk)} = :1",
                        [rid], shard_id=s,
                    )
                    deleted += 1
                except Exception as ex:
                    print(f"[delete_rows] {tname} id={rid}: {ex}")
        elif _is_heatwave(s):
            for rid in rowids:
                try:
                    _heatwave_query(
                        f"DELETE FROM {_my_ident(tq)} WHERE {_my_ident(pk)} = %s", [rid]
                    )
                    deleted += 1
                except Exception as ex:
                    print(f"[delete_rows] {tname} id={rid}: {ex}")
        else:
            col = _mongo(s)[tq]
            for rid in rowids:
                deleted += col.delete_one({pk: rid}).deleted_count
    except Exception as e:
        print(f"[db_admin] delete_rows {tname}: {e}")
    flash(f"Deleted {deleted} of {len(rowids)} selected row(s) from {tname}.", "success")
    return redirect(_local_next(url_for("table_view", tname=tname)))


@app.route("/table/<tname>/delete_row", methods=["POST"])
def delete_row(tname):
    if not _known_table(tname):
        abort(404)
    rowid = request.form.get("rowid", "")
    if rowid:
        shard_id = _get_shard_id()
        fields = collection_fields(tname)
        pk = _pk_field(fields)
        if not pk:
            flash("No primary key column for this table.", "error")
            return redirect(_local_next(url_for("table_view", tname=tname)))
        try:
            tq = _ident(tname)
            if _is_oracle(shard_id):
                _oracle_query(
                    f"DELETE FROM {_ora_ident(tq)} WHERE {_ora_ident(pk)} = :1",
                    [rowid], shard_id=shard_id,
                )
                flash(f"Deleted 1 row from {tname}.", "success")
            elif _is_heatwave(shard_id):
                _heatwave_query(
                    f"DELETE FROM {_my_ident(tq)} WHERE {_my_ident(pk)} = %s", [rowid]
                )
                flash(f"Deleted 1 row from {tname}.", "success")
            else:
                result = _mongo(shard_id)[tq].delete_one({pk: rowid})
                if result.deleted_count:
                    flash(f"Deleted 1 row from {tname}.", "success")
                else:
                    flash(f"No matching row found in {tname}.", "error")
        except Exception as e:
            flash(f"Delete failed: {e}", "error")
    return redirect(_local_next(url_for("table_view", tname=tname)))


@app.route("/table/<tname>/delete_all", methods=["POST"])
def delete_all(tname):
    if not _known_table(tname):
        abort(404)
    shard_id = _get_shard_id()
    try:
        tq = _ident(tname)
        if _is_oracle(shard_id):
            _oracle_query(f"DELETE FROM {_ora_ident(tq)}", shard_id=shard_id)
            flash(f"Deleted rows from {tname}.", "success")
        elif _is_heatwave(shard_id):
            _heatwave_query(f"DELETE FROM {_my_ident(tq)}")
            flash(f"Deleted rows from {tname}.", "success")
        else:
            result = _mongo(shard_id)[tq].delete_many({})
            flash(f"Deleted {result.deleted_count} rows from {tname}.", "success")
    except Exception as e:
        flash(f"Delete failed: {e}", "error")
    return redirect(url_for("table_view", tname=tname))


def _drop_on_best_shard(tname):
    """Drop tname on the selected shard. None on success, error otherwise."""
    shard_id = _get_shard_id()
    try:
        tq = _ident(tname)
        if _is_oracle(shard_id):
            # CASCADE CONSTRAINTS drops FKs that point at this table
            # (ORA-02449) as well as its own constraints.
            _oracle_query(
                f"DROP TABLE {_ora_ident(tq)} CASCADE CONSTRAINTS PURGE",
                shard_id=shard_id,
            )
        elif _is_heatwave(shard_id):
            _heatwave_query(f"DROP TABLE IF EXISTS {_my_ident(tq)}")
        else:
            _mongo(shard_id)[tq].drop()
        return None
    except Exception as e:
        print(f"[db_admin] drop {tname}: {e}")
        return e


@app.route("/table/<tname>/drop", methods=["POST"])
def drop_table(tname):
    if not _known_table(tname):
        abort(404)
    err = _drop_on_best_shard(tname)
    if err is not None:
        flash(f"Drop failed on all shards: {err}", "error")
        return redirect(url_for("tables_page"))
    flash(f"Dropped {tname}.", "success")
    target = _local_next("/tables")
    if f"/table/{quote(tname)}" in target:
        target = "/tables"
    return redirect(target)


@app.route("/tables/drop_selected", methods=["POST"])
def drop_selected():
    names = [n.strip() for n in request.form.getlist("tname") if n.strip()]
    if not names:
        flash("No tables selected.", "error")
        return redirect(_local_next("/tables"))
    known = all_collections()
    known_upper = {n.upper() for n in known}
    dropped, failed = [], []
    for tname in names:
        if tname not in known and tname.upper() not in known_upper:
            failed.append(tname)
            continue
        if _drop_on_best_shard(tname) is None:
            dropped.append(tname)
        else:
            failed.append(tname)
    if dropped and not failed:
        flash(f"Dropped {len(dropped)} table(s): {', '.join(dropped)}", "success")
    elif failed and not dropped:
        flash(f"Drop failed: {', '.join(failed)}", "error")
    else:
        flash(f"Dropped {', '.join(dropped)}; failed: {', '.join(failed)}", "message")
    return redirect(_local_next("/tables"))


@app.route("/user/<uid>/delete_all", methods=["POST"])
def user_delete_all(uid):
    total_deleted = 0
    cols_deleted = 0
    order = [_get_shard_id()]
    for coll_name in all_collections():
        fields = collection_fields(coll_name)
        id_field = _user_id_field(coll_name, fields)
        if not id_field:
            continue
        last_err = None
        ok = False
        for s in order:
            try:
                if _is_oracle(s):
                    _oracle_query(f'DELETE FROM "{coll_name}" WHERE "{id_field}" = :1', [uid], shard_id=s)
                    total_deleted += 1
                    cols_deleted += 1
                elif _is_heatwave(s):
                    _heatwave_query(f"DELETE FROM `{coll_name}` WHERE `{id_field}` = %s", [uid])
                    total_deleted += 1
                    cols_deleted += 1
                else:
                    result = _mongo(s)[coll_name].delete_many({id_field: uid})
                    total_deleted += result.deleted_count
                    if result.deleted_count:
                        cols_deleted += 1
                ok = True
                break
            except Exception as e:
                last_err = e
                print(f"[fallback] user_delete_all shard {s} failed: {e}")
        if ok:
            continue
        if not last_err:
            continue
        flash(f"Delete failed on all shards for {coll_name}.", "error")
    flash(f"Deleted {total_deleted} rows across {cols_deleted} collections for user "
          f"{uid[:16]}...", "success")
    return redirect(url_for("users_page"))


@app.route("/users")
def users_page():
    return render_template("users.html", users=users_report())


@app.route("/user/<uid>")
def user_detail(uid):
    users = users_report()
    u = next((x for x in users if x["id"] == uid), None)
    if not u:
        u = {"id": uid, "name": "", "tables": 0, "rows": 0, "bytes": 0, "breakdown": []}

    bots = []
    all_cols = all_collections()
    if any(c.upper() == "BOTS" for c in all_cols):
        bots_tbl = next(c for c in all_cols if c.upper() == "BOTS")
        shard_id = _get_shard_id()
        bots_fields = collection_fields(bots_tbl)
        bots_id_field = _user_id_field(bots_tbl, bots_fields)
        bots_pk_field = _pk_field(bots_fields)
        try:
            if _is_oracle(shard_id) and bots_id_field:
                rows = _oracle_query(
                    f'SELECT * FROM "{bots_tbl}" WHERE "{bots_id_field}" = :1',
                    [uid]
                )
                for doc in rows:
                    name = doc.get("NAME", "")
                    if _looks_encrypted(str(name)) and _decrypt:
                        try:
                            name = _decrypt(str(name))
                        except Exception:
                            pass
                    pk_val = _iget(doc, bots_pk_field) if bots_pk_field else None
                    bots.append({
                        "name": name,
                        "ip": doc.get("SERVER_IP", doc.get("IP", "")),
                        "port": doc.get("SERVER_PORT", doc.get("PORT", "")),
                        "edition": doc.get("EDITION", ""),
                        "running": doc.get("RUNNING", False),
                        "last_run": doc.get("LAST_RUN", ""),
                        "tbl": bots_tbl,
                        "pk": "" if pk_val is None else str(pk_val),
                    })
            elif _is_heatwave(shard_id) and bots_id_field:
                rows = _heatwave_query(
                    f"SELECT * FROM {_my_ident(bots_tbl)} WHERE {_my_ident(bots_id_field)} = %s",
                    [uid],
                )
                for doc in rows:
                    name = _iget(doc, "NAME") or _iget(doc, "name") or ""
                    if _looks_encrypted(str(name)) and _decrypt:
                        try:
                            name = _decrypt(str(name))
                        except Exception:
                            pass
                    pk_val = _iget(doc, bots_pk_field) if bots_pk_field else None
                    bots.append({
                        "name": name,
                        "ip": _iget(doc, "SERVER_IP") or _iget(doc, "IP") or "",
                        "port": _iget(doc, "SERVER_PORT") or _iget(doc, "PORT") or "",
                        "edition": _iget(doc, "EDITION") or "",
                        "running": _iget(doc, "RUNNING") or False,
                        "last_run": _iget(doc, "LAST_RUN") or "",
                        "tbl": bots_tbl,
                        "pk": "" if pk_val is None else str(pk_val),
                    })
            elif not _is_oracle(shard_id) and not _is_heatwave(shard_id):
                for doc in _mongo(shard_id)[bots_tbl].find({"user_id": uid}):
                    name = doc.get("name", "")
                    if _looks_encrypted(str(name)) and _decrypt:
                        try:
                            name = _decrypt(str(name))
                        except Exception:
                            pass
                    pk_val = doc.get(bots_pk_field) if bots_pk_field else doc.get("_id")
                    bots.append({
                        "name": name,
                        "ip": doc.get("server_ip", doc.get("ip", "")),
                        "port": doc.get("server_port", doc.get("port", "")),
                        "edition": doc.get("edition", ""),
                        "running": doc.get("running", False),
                        "last_run": doc.get("last_run", ""),
                        "tbl": bots_tbl,
                        "pk": "" if pk_val is None else str(pk_val),
                    })
        except Exception:
            pass

    per_table = request.args.get("per", 100, type=int) or 100
    atp_groups = user_footprint(uid, per_table)
    return render_template(
        "user_detail.html",
        u=u, bots=bots, atp_groups=atp_groups,
        per_table=per_table,
        linked_rows=sum(g["total"] for g in atp_groups),
    )


def user_footprint(uid, limit=100):
    cap = max(1, min(int(limit), 500))
    out = []
    shard_id = _get_shard_id()
    for coll_name in all_collections():
        fields = collection_fields(coll_name)
        id_field = _user_id_field(coll_name, fields)
        if not id_field:
            continue

        try:
            cols_list = list(fields.keys())
            if _is_oracle(shard_id):
                total_rows = _oracle_query(
                    f'SELECT COUNT(*) AS cnt FROM "{coll_name}" WHERE "{id_field}" = :1', [uid]
                )
                total = total_rows[0]["CNT"] if total_rows else 0
                if not total:
                    continue
                rows_data = _oracle_query(
                    f'SELECT * FROM (SELECT * FROM "{coll_name}" WHERE "{id_field}" = :1 AND ROWNUM <= :lim) WHERE 1=1',
                    [uid, cap]
                )
                rows = [[doc.get(c, "") for c in cols_list] for doc in rows_data]
            elif _is_heatwave(shard_id):
                total_rows = _heatwave_query(
                    f"SELECT COUNT(*) AS cnt FROM `{coll_name}` WHERE `{id_field}` = %s", [uid]
                )
                total = total_rows[0]["cnt"] if total_rows else 0
                if not total:
                    continue
                rows_data = _heatwave_query(
                    f"SELECT * FROM `{coll_name}` WHERE `{id_field}` = %s LIMIT %s", [uid, cap]
                )
                rows = [[doc.get(c, "") for c in cols_list] for doc in rows_data]
            else:
                col = _mongo(shard_id)[coll_name]
                total = col.count_documents({id_field: uid})
                if not total:
                    continue
                cursor = col.find({id_field: uid}).limit(cap)
                rows = []
                for doc in cursor:
                    flat = _flatten(doc)
                    rows.append([flat.get(c, "") for c in cols_list])

            out.append({
                "engine": "oracle" if _is_oracle(shard_id) else ("heatwave" if _is_heatwave(shard_id) else "mongo"),
                "schema": "ADMIN",
                "table": coll_name,
                "column": id_field,
                "columns": cols_list,
                "rows": rows,
                "total": total,
                "shown": len(rows),
                "href": "/table/" + quote(coll_name),
            })
        except Exception:
            continue
    return out


@app.route("/query")
def query_page():
    return render_template("query.html")


@app.post("/api/query")
def api_query():
    data = request.json or {}
    q = data.get("sql", "").strip()
    if not q:
        return jsonify({"error": "empty query"}), 400

    t0 = time.time()
    shard_id = _get_shard_id()
    try:
        if _is_oracle(shard_id):
            result = _oracle_query(q, shard_id=shard_id)
        elif _is_heatwave(shard_id):
            result = _heatwave_query(q)
        else:
            return jsonify({"error": "SQL query is not supported on this shard"}), 400
        dt = (time.time() - t0) * 1000
        if result:
            columns = list(result[0].keys())
            rows = [[safe_json(display_value(row.get(c, None), c)) for c in columns] for row in result]
        else:
            columns, rows = [], []
        return jsonify({"columns": columns, "rows": rows, "ms": round(dt, 1)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/table/<tname>")
def api_table(tname):
    """Capped, masked preview of a table for the inline heat-map/list peek."""
    if not _known_table(tname):
        return jsonify({"error": "unknown table"}), 404
    limit = 100
    t0 = time.time()
    s = _get_shard_id()
    columns = list(collection_fields(tname).keys())
    try:
        tq = _ident(tname)
        if _is_oracle(s):
            result = _oracle_query(
                f"SELECT * FROM {_ora_ident(tq)} WHERE ROWNUM <= :n",
                {"n": limit}, shard_id=s,
            )
        elif _is_heatwave(s):
            result = _heatwave_query(f"SELECT * FROM {_my_ident(tq)} LIMIT %s", [limit])
        else:
            result = list(_mongo(s)[tq].find().limit(limit))
        if not columns and result:
            columns = list(result[0].keys())
        rows = [[safe_json(display_value(r.get(c), c)) for c in columns] for r in result]
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "name": tname,
        "columns": columns,
        "rows": rows,
        "total": collection_count(tname),
        "shown": len(rows),
        "ms": round((time.time() - t0) * 1000, 1),
        "href": "/table/" + quote(tname),
    })


# ─── template helpers ────────────────────────────────────────────────────────

@app.context_processor
def inject_sidebar():
    try:
        _, totals = collections_report()
    except Exception:
        totals = {"rows": 0, "collections": 0}
    from flask import session
    current_shard = session.get("shard_id", SHARD_ORACLE)
    available_shards = get_available_shards()
    return {
        "side_totals": totals,
        "current_shard": current_shard,
        "available_shards": available_shards,
    }


@app.template_filter("num")
def fmt_num(n):
    return f"{n or 0:,}"


@app.template_filter("cell")
def cell(val, col, key=None):
    d = display_value(val, col, key)
    if d is None:
        return "NULL"
    if isinstance(d, str) and len(d) > 300:
        return d[:300] + " ..."
    return d


@app.template_filter("shortid")
def short_id(uid):
    if isinstance(uid, str) and len(uid) > 16:
        return uid[:8] + "..." + uid[-4:]
    return uid


@app.template_filter("iso")
def iso_to_local(ts):
    try:
        d = datetime.datetime.fromisoformat(ts)
        return d.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="DB Admin console")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8004)
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    app.run(host=a.host, port=a.port, debug=a.debug)

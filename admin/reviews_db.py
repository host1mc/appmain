"""
reviews_db.py — the reviews store, on HeatWave (MySQL) instead of the ATP.

This is the source copy; admin/reviews_db.py vendors it, the same way
admin/database.py vendors the app's Oracle module. Keep the two in sync.

Two databases, and which code talks to which
--------------------------------------------
    ATP (Oracle, python-oracledb)  →  database.py, in BOTH app/ and admin/
        users, bots, sessions, settings, device_events, ad_zones — everything
        with PII or a transaction. Reached through _oracle_pool() / _user_conn().
        Losing it is fatal: see database.py:_oracle_unavailable.

    HeatWave (MySQL, mysql-connector)  →  THIS FILE ONLY
        the `reviews`, `bots`, `app_errors`, `app_config` tables and the ops
        queues. Reached through _pool() / _conn(). Losing it degrades to
        "no reviews / no bots" and the site stays up.

No query in this file touches the ATP, and no query in database.py touches
HeatWave. That boundary is why these tables could move at all: they carry no
PII that has to be transactional with anything Oracle holds, and their link
to an account is the opaque uid string. The `bots` table joins to `users` on
uid in the logical sense only — two stores cannot share a SQL foreign key.

The cost of the split, named plainly: a review row cannot be joined to a `users`
row in SQL. Nothing here tries. `author_name` is denormalised — copied in at
submission time from the account's display name — so rendering the home page
never needs the ATP at all. A user who later renames themselves keeps the name
they posted under, which is how a published review should behave anyway.

Degrading instead of failing
----------------------------
database.py treats a lost ATP as fatal, because without it there are no users,
bots or sessions and the app has nothing to serve. This module takes the
opposite stance: HeatWave being unconfigured or unreachable must never take the
site down. Reads return empty, writes return False, and the callers already
treat that as "no reviews yet" — the home-page section is `{% if reviews %}`-
gated, so it simply does not render. An unconfigured MYSQL_HOST is the normal
state on a dev box and is not an error.

Configuration (env, or fastapi-oracle-app/.env alongside the Oracle keys):

    MYSQL_HOST      HeatWave endpoint (private IP or hostname). Unset = disabled.
    MYSQL_PORT      default 3306
    MYSQL_USER      default admin
    MYSQL_PASSWORD
    MYSQL_DATABASE  default dchost
    MYSQL_SSL_CA    required PEM to pin: the endpoint's TLS chain (see
                    _connect_kwargs). Relative paths resolve against the
                    fastapi-oracle-app/.env directory.
    MYSQL_POOL_MAX  default 4, matching the per-tier Oracle pool
"""

import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta

_CFG = {}
_ENABLED = False
_POOL = None
# Same reasoning as database.py's _ORACLE_POOL_LOCK: pool construction is not
# idempotent, and two threads racing it would each build one while only one is
# kept — leaking the loser's connections against the HeatWave connection cap.
_POOL_LOCK = threading.Lock()
_SCHEMA_READY = False
_SCHEMA_LOCK = threading.Lock()
_POOL_MAX_DEFAULT = 4
_DB_READY = False
_DB_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,63}$")
_SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_LAST_ERROR = ""

# Hard limits, matching the column widths in _ensure_schema().
#
# backend.py:1318-1330 already checks all three on the one route that writes, but
# the checks live here too because this module is the store's contract, not that
# route's helper: admin/reviews_db.py vendors this file, and a second caller that
# forgets one of them would otherwise reach MySQL directly. With a non-strict
# sql_mode an over-long body is silently truncated rather than rejected, so
# "the column enforces it" is not enough on its own.
BODY_MAX_CHARS = 4000
AUTHOR_MAX_CHARS = 100
USER_ID_MAX_CHARS = 10
RATING_MIN = 1
RATING_MAX = 5

# Ceiling on any caller-supplied LIMIT. The table is public content on a
# size-capped HeatWave instance and these reads are on the home-page path, so an
# unbounded limit is both a memory and a latency lever for anyone who can reach a
# route that forwards a query parameter into one of these functions.
READ_LIMIT_MAX = 200

# Unapproved reviews one account may have queued at once. This is the only
# abuse control that works on this fleet: there are two app instances behind the
# load balancer, so any in-process counter is per-instance and trivially doubled
# — the count has to be asked of the shared database.
MAX_PENDING_PER_USER = 3

# Read from the same .env the Oracle config uses, so a deploy has one file to
# fill in rather than two. Resolves relative to THIS directory, which is what
# keeps the app and admin copies of this file interchangeable.
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app", ".env")

# What that file declares, parsed into this module instead of exported. The .env
# it shares with the Oracle config also holds the Fernet key, the wallet password
# and the ATP credentials, and os.environ is inherited by every child process —
# the launcher's five tiers, and one subprocess per customer container under the
# hosting tier — so a setdefault here would hand all of it to processes that
# never needed any of it. database.py keeps its own copy for the same reason;
# both parse the same file, so neither depends on the other having run.
_FILE_CFG = {}


def _setting(name, default=""):
    """One config name: real environment first, then the .env, then the default.

    The order is the one os.environ.setdefault used to produce, and it matters:
    a value set by systemd or the shell must still beat a .env line.
    """
    return os.environ.get(name) or _FILE_CFG.get(name) or default


def _load_config():
    """Populate _CFG from the environment. MYSQL_HOST unset leaves _ENABLED
    False, which disables every function in this module without raising —
    the dev-box case, and not a misconfiguration."""
    global _ENABLED, _CFG
    # Reading this file must not be able to stop a tier from booting: backend.py
    # imports this module at module scope, so an unreadable or non-UTF-8 .env
    # raising here would take down a tier whose reviews are meant to degrade to
    # empty. Env vars already set still win, and a failed read just leaves
    # MYSQL_HOST unset, which is the documented "disabled" state.
    #
    # utf-8-sig is utf-8 plus a dropped byte-order mark, which would otherwise
    # end up inside the first key's name.
    try:
        if os.path.exists(_ENV_PATH):
            with open(_ENV_PATH, encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    _FILE_CFG[k.strip()] = v.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass
    host = _setting("MYSQL_HOST").strip()
    if not host:
        return
    try:
        port = int(_setting("MYSQL_PORT", "3306"))
    except (TypeError, ValueError):
        port = 3306
    _CFG = {
        "host": host,
        "port": port,
        "user": _setting("MYSQL_USER", "admin").strip(),
        "password": _setting("MYSQL_PASSWORD"),
        "database": _setting("MYSQL_DATABASE", "dchost").strip(),
        "ssl_ca": _setting("MYSQL_SSL_CA").strip(),
    }
    _ENABLED = True


_load_config()

def enabled() -> bool:
    """True when a HeatWave endpoint is configured. Callers use this to skip the
    work entirely rather than to decide how to report an error."""
    return _ENABLED


def _pool_max() -> int:
    try:
        return max(1, int(_setting("MYSQL_POOL_MAX", _POOL_MAX_DEFAULT)))
    except (TypeError, ValueError):
        return _POOL_MAX_DEFAULT


def _resolve_ssl_ca(raw):
    """Absolute path for a relative MYSQL_SSL_CA.

    Values are written relative to the file that declares them — the app's
    fastapi-oracle-app/.env, or this module's folder in the standalone admin
    layout that has no such directory. An absolute path passes through, matching
    how the wallet path behaves.
    """
    if not raw or os.path.isabs(raw):
        return raw
    for base in (os.path.dirname(_ENV_PATH),
                 os.path.dirname(os.path.abspath(__file__))):
        candidate = os.path.abspath(os.path.join(base, raw))
        if os.path.exists(candidate):
            return candidate
    return os.path.abspath(os.path.join(os.path.dirname(_ENV_PATH), raw))


def _connect_kwargs():
    kwargs = {
        "host": _CFG["host"],
        "port": _CFG["port"],
        "user": _CFG["user"],
        "password": _CFG["password"],
        "connection_timeout": 10,
        "charset": "utf8mb4",
    }
    # Encryption without endpoint authentication still exposes credentials and
    # review writes to an active network attacker. Require a trust root and
    # verify the certificate chain against it.
    if not _CFG.get("ssl_ca"):
        raise ValueError("MYSQL_SSL_CA is required when MYSQL_HOST is configured")
    kwargs["ssl_ca"] = _resolve_ssl_ca(_CFG["ssl_ca"])
    kwargs["ssl_verify_cert"] = True
    # Hostname verification is deliberately off. The HeatWave endpoint's
    # certificate is CN-only — no subjectAltName (observed 2026-08-19) — so
    # ssl_verify_identity=True always fails with "IP address mismatch". The
    # pinned CA above is the chain-of-trust check, and the endpoint is a fixed
    # private IP inside the VCN, so the CN adds no independent identity anyway.
    kwargs["ssl_verify_identity"] = False
    return kwargs


def _ensure_database():
    global _DB_READY
    if _DB_READY:
        return
    name = _CFG["database"]
    if not _DB_NAME_RE.fullmatch(name):
        raise ValueError(f"MYSQL_DATABASE is not a valid schema name: {name!r}")
    if not _SQL_IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"MYSQL_DATABASE fails SQL identifier check: {name!r}")
    import mysql.connector
    conn = mysql.connector.connect(**_connect_kwargs())
    try:
        cur = conn.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{name}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        conn.commit()
        cur.close()
    finally:
        conn.close()
    _DB_READY = True


def _pool():
    """The HeatWave connection pool — the MySQL counterpart to
    database.py:_oracle_pool(). Built lazily so a process that never renders a
    review never opens a MySQL socket, and so importing this module cannot fail
    on a box without the driver installed."""
    global _POOL
    if _POOL is not None:
        return _POOL
    with _POOL_LOCK:
        if _POOL is not None:
            return _POOL
        from mysql.connector import pooling
        _ensure_database()
        kwargs = _connect_kwargs()
        kwargs.update({
            "pool_name": "reviews",
            "pool_size": _pool_max(),
            "pool_reset_session": True,
            "database": _CFG["database"],
            "autocommit": False,
        })
        _POOL = pooling.MySQLConnectionPool(**kwargs)
        _debug_print(f"[reviews_db] HeatWave pool created (max={_pool_max()})")
    return _POOL


def _ensure_schema(conn):
    """Create tables on first use, once per process."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INT AUTO_INCREMENT PRIMARY KEY,
                uid VARCHAR(10) NOT NULL,
                author_name VARCHAR(100) NOT NULL,
                rating INT NOT NULL,
                body VARCHAR(4000) NOT NULL,
                embed_json LONGTEXT,
                approved TINYINT NOT NULL DEFAULT 0,
                created_at VARCHAR(50) NOT NULL,
                KEY reviews_approved (approved)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # Ensure embed_json column exists if table pre-existed
        try:
            cur.execute("SHOW COLUMNS FROM reviews LIKE 'embed_json'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE reviews ADD COLUMN embed_json LONGTEXT")
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for reviews.embed_json: {ex}")

        # CREATE TABLE IF NOT EXISTS above never touches a table that already
        # exists, so a shard built before the uid schema keeps the old user_id
        # column and every statement in this module fails on "Unknown column
        # 'uid'". Rename in place rather than adding a second column, so the
        # existing rows keep their owner.
        try:
            cur.execute("SHOW COLUMNS FROM reviews LIKE 'uid'")
            if not cur.fetchone():
                cur.execute("SHOW COLUMNS FROM reviews LIKE 'user_id'")
                if cur.fetchone():
                    cur.execute("ALTER TABLE reviews CHANGE user_id uid "
                                f"VARCHAR({USER_ID_MAX_CHARS}) NOT NULL")
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for reviews.uid: {ex}")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_errors (
                id INT AUTO_INCREMENT PRIMARY KEY,
                error_type VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                stack_trace LONGTEXT,
                module VARCHAR(255),
                flag_reason VARCHAR(255),
                flagged TINYINT NOT NULL DEFAULT 1,
                created_at VARCHAR(50) NOT NULL,
                KEY errors_flagged (flagged)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        try:
            cur.execute("SHOW COLUMNS FROM app_errors LIKE 'flag_reason'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE app_errors ADD COLUMN flag_reason VARCHAR(255)")
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for app_errors.flag_reason: {ex}")

        try:
            cur.execute("SHOW COLUMNS FROM app_errors LIKE 'error_category'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE app_errors ADD COLUMN error_category VARCHAR(50) DEFAULT 'system_error'")
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for app_errors.error_category: {ex}")

        try:
            cur.execute("SHOW COLUMNS FROM app_errors LIKE 'occurrences'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE app_errors ADD COLUMN occurrences INT NOT NULL DEFAULT 1")
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for app_errors.occurrences: {ex}")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_config (
                config_key VARCHAR(100) PRIMARY KEY,
                config_value TEXT NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # Durable record of containers whose node delete could not be confirmed
        # (node offline at delete time). Deletion from this queue is manual —
        # an admin confirms it in the console — and the reconcile sweep is told
        # to skip these ids, so a deferred delete is never removed
        # automatically. Keyed by server_id so a repeated delete is idempotent.
        # `purge` is backticked because it is a MySQL reserved word: unquoted,
        # this CREATE fails with 1064 and poisons _ensure_schema for every
        # connection after it, taking the whole reviews store down with it.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending_container_deletions (
                server_id VARCHAR(64) PRIMARY KEY,
                node_id VARCHAR(64) NOT NULL DEFAULT '',
                node_name VARCHAR(100) NOT NULL DEFAULT '',
                node_ip VARCHAR(255) NOT NULL DEFAULT '',
                `purge` TINYINT NOT NULL DEFAULT 1,
                requested_at VARCHAR(50) NOT NULL,
                KEY pcd_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        for col, ddl in (
            ("node_ip", "ADD COLUMN node_ip VARCHAR(255) NOT NULL DEFAULT '' AFTER node_id"),
            ("node_name", "ADD COLUMN node_name VARCHAR(100) NOT NULL DEFAULT '' AFTER node_id"),
        ):
            try:
                cur.execute(f"SHOW COLUMNS FROM pending_container_deletions LIKE '{col}'")
                if not cur.fetchone():
                    cur.execute("ALTER TABLE pending_container_deletions " + ddl)
            except Exception as ex:
                _debug_print(f"[reviews_db] column check failed for pending_container_deletions.{col}: {ex}")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS retired_nodes (
                node_id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(100) NOT NULL DEFAULT '',
                url VARCHAR(255) NOT NULL DEFAULT '',
                token_enc VARCHAR(2000) NOT NULL DEFAULT '',
                retired_at VARCHAR(50) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # MC-status Discord bots. uid is the account link — a foreign key to
        # the Oracle users table in the logical sense only: the two stores
        # cannot share a SQL constraint, so the relationship is the same shape
        # as reviews.uid. There is deliberately no synthetic id column: a bot
        # is identified by (uid, slot_index). The Discord token and the
        # webhook URL are Fernet-encrypted at rest (see _bot_crypto) and never
        # leave this module in plaintext except through the accessor dicts.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bots (
                uid VARCHAR(10) NOT NULL,
                slot_index INT NOT NULL DEFAULT 0,
                name VARCHAR(500),
                server_ip VARCHAR(500),
                server_port INT DEFAULT 25565,
                edition VARCHAR(20) DEFAULT 'java',
                token_enc VARCHAR(1000),
                guild_id VARCHAR(500),
                channel_id VARCHAR(500),
                message_id VARCHAR(100),
                embed_json LONGTEXT,
                ip_reply_json LONGTEXT,
                webhook_url VARCHAR(1000),
                update_interval INT DEFAULT 60,
                running TINYINT DEFAULT 0,
                last_run VARCHAR(50),
                last_status LONGTEXT,
                last_error VARCHAR(500),
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50),
                PRIMARY KEY (uid, slot_index),
                KEY bots_running (running)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        conn.commit()
        cur.close()
        _SCHEMA_READY = True


def _conn():
    """A pooled connection with the schema guaranteed, or None if unavailable.

    Returning None instead of raising is the whole degradation strategy, and the
    deliberate difference from database.py:_user_conn(), which calls
    _oracle_unavailable() and treats the outage as fatal. Every function below
    reads None as "no reviews" and the site carries on.
    """
    if not _ENABLED:
        return None
    try:
        conn = _pool().get_connection()
    except Exception as ex:
        _set_last_error(ex)
        _debug_print(f"[reviews_db] HeatWave unavailable: {ex}")
        return None
    try:
        _ensure_schema(conn)
        _set_last_error(None)
        return conn
    except Exception as ex:
        _set_last_error(ex)
        _debug_print(f"[reviews_db] could not prepare reviews schema: {ex}")
        try:
            conn.close()
        except Exception:
            pass
        return None


def _set_last_error(ex):
    global _LAST_ERROR
    _LAST_ERROR = "" if ex is None else f"{type(ex).__name__}: {ex}"


def _close_quietly(conn):
    try:
        conn.close()
    except Exception:
        pass


def health():
    if not _ENABLED:
        return {"enabled": False, "ok": False,
                "error": "MYSQL_HOST is not set for this process"}
    conn = _conn()
    if conn is None:
        return {"enabled": True, "ok": False,
                "error": _LAST_ERROR or "HeatWave is unreachable"}
    try:
        return {"enabled": True, "ok": True, "error": ""}
    finally:
        _close_quietly(conn)


def _now():
    """Local copy of database.py:_now so this module imports nothing Oracle."""
    return datetime.now(timezone.utc).isoformat()


# ── public API (app tiers) ──────────────────────────────────────
# MySQL binds are pyformat (%(name)s), not Oracle's :name. One upside of the
# move: the ORA-01745 reserved-word trap that bans :uid on the Oracle side does
# not exist here, so these names are unconstrained.

def _clean_limit(value, default):
    """A caller-supplied LIMIT, coerced into 1..READ_LIMIT_MAX."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(READ_LIMIT_MAX, n))


def _clean_offset(value):
    """A caller-supplied OFFSET, floored at 0. A negative one is a MySQL syntax
    error rather than a smaller page."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _clean_rating(value):
    """A rating coerced into 0..RATING_MAX for display.

    The column is a plain INT with no CHECK, so nothing in the database stops a
    row from holding 100000 — and templates/index.html:243 renders the stars as
    `range(r.rating)`, one glyph per unit. Clamping on the way out keeps a bad row
    from turning the public home page into megabytes of star characters.
    """
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(RATING_MAX, n))


def create_review(uid, author_name, rating, body, embed_json=None):
    """Insert or update a review. Automatically approved by default (approved=1).
    Enforces a strict limit of 1 review per user in HeatWave MySQL.
    """
    uid = str(uid or "").strip()
    author_name = str(author_name or "").strip()
    body = str(body or "").strip()
    if isinstance(embed_json, (dict, list)):
        import json
        embed_str = json.dumps(embed_json)
    elif embed_json:
        embed_str = str(embed_json)
    else:
        embed_str = None

    try:
        rating = int(rating)
    except (TypeError, ValueError):
        _debug_print("[reviews_db] refusing review: rating is not a number")
        return False
    if not uid or len(uid) > USER_ID_MAX_CHARS:
        _debug_print("[reviews_db] refusing review: missing or over-long uid")
        return False
    if not author_name or len(author_name) > AUTHOR_MAX_CHARS:
        _debug_print(f"[reviews_db] refusing review for {uid}: author name must be "
                     f"1..{AUTHOR_MAX_CHARS} characters")
        return False
    if not body or len(body) > BODY_MAX_CHARS:
        _debug_print(f"[reviews_db] refusing review for {uid}: body must be "
                     f"1..{BODY_MAX_CHARS} characters")
        return False
    if rating < RATING_MIN or rating > RATING_MAX:
        _debug_print(f"[reviews_db] refusing review for {uid}: rating must be "
                     f"{RATING_MIN}..{RATING_MAX}")
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM reviews WHERE uid=%(uid)s", {"uid": uid})
        row = cur.fetchone()
        if row:
            # Update existing single review directly with auto-approval
            cur.execute(
                "UPDATE reviews SET author_name=%(name)s, rating=%(rating)s, body=%(body)s, "
                "embed_json=%(embed)s, approved=1, created_at=%(now)s WHERE uid=%(uid)s",
                {"uid": uid, "name": author_name, "rating": rating,
                 "body": body, "embed": embed_str, "now": _now()},
            )
        else:
            # Insert new review with auto-approval (approved=1)
            cur.execute(
                "INSERT INTO reviews(uid, author_name, rating, body, embed_json, approved, created_at) "
                "VALUES(%(uid)s, %(name)s, %(rating)s, %(body)s, %(embed)s, 1, %(now)s)",
                {"uid": uid, "name": author_name, "rating": rating,
                 "body": body, "embed": embed_str, "now": _now()},
            )
        conn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[reviews_db] could not save review for {uid}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def _safe_json(raw):
    if not raw:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        import json
        return json.loads(raw)
    except Exception:
        return None


def get_approved_reviews(limit=50):
    """Approved reviews, newest first, public fields only.

    The SELECT list is the privacy boundary for the public home page: uid is
    never named here, so it cannot reach a template or the public JSON even by
    accident. LIMIT is pushed into SQL rather than sliced in Python — MySQL
    supports it directly, unlike the Oracle draft this replaced.
    """
    conn = _conn()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT author_name, rating, body, embed_json, created_at FROM reviews "
            "WHERE approved=1 ORDER BY created_at DESC LIMIT %(lim)s",
            {"lim": _clean_limit(limit, 50)},
        )
        rows = cur.fetchall()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not read approved reviews: {ex}")
        return []
    finally:
        _close_quietly(conn)
    for r in rows:
        r["rating"] = _clean_rating(r.get("rating"))
        if r.get("embed_json"):
            r["embed_json"] = _safe_json(r["embed_json"])
            r["embed"] = r["embed_json"]
    return rows


def get_reviews_summary():
    """{count, average} over approved reviews. Average rounded to 1 dp; no
    approved rows gives average 0 (AVG() is NULL over an empty set, and the
    template would render "None out of 5")."""
    conn = _conn()
    if conn is None:
        return {"count": 0, "average": 0}
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), AVG(rating) FROM reviews WHERE approved=1")
        r = cur.fetchone()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not read review summary: {ex}")
        return {"count": 0, "average": 0}
    finally:
        _close_quietly(conn)
    count = int(r[0] or 0) if r else 0
    # AVG() comes back as Decimal; float() before round() so the template gets a
    # plain number to interpolate. Clamped for the same reason _clean_rating() is:
    # templates/index.html:236 renders the summary stars as
    # range(average|round|int), so an out-of-range row would print that many.
    avg = round(float(r[1]), 1) if (r and r[1] is not None) else 0
    avg = max(0, min(float(RATING_MAX), avg))
    return {"count": count, "average": avg}


# ── moderation API (admin console only) ─────────────────────────
# Reachable only from the loopback admin app, behind @auth.require_admin. They
# are the one place uid is exposed. Unused by the app tiers, and kept here
# so this file and admin/reviews_db.py stay byte-identical.

def get_reviews(limit=200, offset=0, state="all"):
    """Newest reviews first for the admin queue. Includes uid and approved
    so the console can show who posted. `state` selects the moderation bucket:
    "pending" (approved=0, awaiting approval), "approved" (published), or
    "all". Anything else is treated as "all" — same defensive stance as
    count_pending_reviews()."""
    if state not in ("pending", "approved"):
        state = "all"
    conn = _conn()
    if conn is None:
        return []
    # state is one of three fixed literals, never interpolated input — the
    # paging values are bound. Nothing user-supplied is concatenated into SQL.
    sql = ("SELECT id, uid, author_name, rating, body, embed_json, approved, created_at "
           "FROM reviews")
    if state == "pending":
        sql += " WHERE approved=0"
    elif state == "approved":
        sql += " WHERE approved=1"
    sql += " ORDER BY created_at DESC LIMIT %(lim)s OFFSET %(off)s"
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, {"lim": _clean_limit(limit, 200),
                          "off": _clean_offset(offset)})
        rows = cur.fetchall()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list reviews: {ex}")
        return []
    finally:
        _close_quietly(conn)
    for r in rows:
        r["rating"] = _clean_rating(r.get("rating"))
        r["approved"] = int(r.get("approved") or 0)
        if r.get("embed_json"):
            r["embed_json"] = _safe_json(r["embed_json"])
            r["embed"] = r["embed_json"]
    return rows


def count_pending_reviews():
    """Badge count for the console nav. Swallows errors to 0 — a broken count
    must not blank the page that would let an admin fix things."""
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM reviews WHERE approved=0")
        r = cur.fetchone()
        return int(r[0] if r else 0)
    except Exception:
        return 0
    finally:
        _close_quietly(conn)


def approve_review(review_id):
    """Set approved=1 for one review — the step that publishes it to the home
    page. Returns True on success. int() on the id both validates it and makes
    injection impossible regardless of what the console posted."""
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE reviews SET approved=1 WHERE id=%(id)s",
                    {"id": int(review_id)})
        conn.commit()
        return cur.rowcount > 0
    except Exception as ex:
        _debug_print(f"[reviews_db] could not approve review {review_id}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def delete_review(review_id):
    """Permanently delete one review (reject). Returns rows deleted (0 or 1).

    There is no soft-delete column on purpose: a rejected review has no audit
    value, and leaving it in the table would mean every read path had to filter
    a third state instead of the two `approved` already carries.
    """
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM reviews WHERE id=%(id)s", {"id": int(review_id)})
        deleted = max(0, cur.rowcount)
        conn.commit()
        return deleted
    except Exception as ex:
        _debug_print(f"[reviews_db] could not delete review {review_id}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


# ── HeatWave Pending Container Deletions ─────────────────────────

def enqueue_container_deletion(server_id, node_id="", node_ip="", node_name="", purge=True):
    """Record a container whose node delete was not confirmed (node offline).

    ``node_ip`` / ``node_name`` are the registry values at delete time, kept so
    the admin panel can still name the host and reach it after the Oracle node
    row is gone.

    Best-effort: a HeatWave outage must never block the delete, so this
    degrades to a no-op like every other function here. Idempotent on
    server_id — a repeated delete just refreshes the row.
    """
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pending_container_deletions"
            "(server_id, node_id, node_name, node_ip, `purge`, requested_at) "
            "VALUES(%(s)s, %(n)s, %(nm)s, %(ip)s, %(p)s, %(now)s) "
            "ON DUPLICATE KEY UPDATE node_id=%(n)s, node_name=%(nm)s, "
            "node_ip=%(ip)s, `purge`=%(p)s, requested_at=%(now)s",
            {
                "s": str(server_id), "n": str(node_id or ""),
                "nm": str(node_name or "")[:100],
                "ip": str(node_ip or "")[:255], "p": 1 if purge else 0, "now": _now(),
            },
        )
        conn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[reviews_db] could not enqueue pending deletion {server_id}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def list_container_deletions():
    """All pending tombstones, oldest first, or [] when HeatWave is unusable.

    Read by the admin console (the manual-delete queue) and by app1's
    reconcile sweep (the ids it must protect from automatic removal).
    """
    conn = _conn()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT server_id, node_id, node_name, node_ip, `purge`, requested_at "
            "FROM pending_container_deletions ORDER BY requested_at"
        )
        rows = cur.fetchall() or []
        out = []
        for row in rows:
            out.append({
                "server_id": str(row.get("server_id") or ""),
                "node_id": str(row.get("node_id") or ""),
                "node_name": str(row.get("node_name") or ""),
                "node_ip": str(row.get("node_ip") or ""),
                "purge": bool(row.get("purge")),
                "requested_at": str(row.get("requested_at") or ""),
            })
        return out
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list pending deletions: {ex}")
        return []
    finally:
        _close_quietly(conn)


def get_container_deletion(server_id):
    """One tombstone by server id, or None when it is not queued."""
    for row in list_container_deletions():
        if row["server_id"] == str(server_id or "").strip():
            return row
    return None


def stamp_pending_node_identity(node_id, node_name="", node_ip=""):
    """Keep name/IP on every pending row for this node after Oracle delete."""
    nid = str(node_id or "").strip()
    if not nid:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE pending_container_deletions "
            "SET node_name=%(nm)s, node_ip=%(ip)s WHERE node_id=%(n)s",
            {
                "n": nid,
                "nm": str(node_name or "")[:100],
                "ip": str(node_ip or "")[:255],
            },
        )
        conn.commit()
        return max(0, cur.rowcount)
    except Exception as ex:
        _debug_print(f"[reviews_db] could not stamp pending node {nid}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


def retire_node(node_id, name="", url="", token_enc=""):
    """Keep last-known agent contact after the Oracle nodes row is gone."""
    nid = str(node_id or "").strip()
    if not nid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO retired_nodes(node_id, name, url, token_enc, retired_at) "
            "VALUES(%(n)s, %(nm)s, %(u)s, %(t)s, %(now)s) "
            "ON DUPLICATE KEY UPDATE name=%(nm)s, url=%(u)s, "
            "token_enc=%(t)s, retired_at=%(now)s",
            {
                "n": nid,
                "nm": str(name or "")[:100],
                "u": str(url or "")[:255],
                "t": str(token_enc or "")[:2000],
                "now": _now(),
            },
        )
        conn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[reviews_db] could not retire node {nid}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def get_retired_node(node_id):
    nid = str(node_id or "").strip()
    if not nid:
        return None
    conn = _conn()
    if conn is None:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT node_id, name, url, token_enc, retired_at "
            "FROM retired_nodes WHERE node_id=%(n)s",
            {"n": nid},
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "node_id": str(row.get("node_id") or ""),
            "name": str(row.get("name") or ""),
            "url": str(row.get("url") or ""),
            "token_enc": str(row.get("token_enc") or ""),
            "retired_at": str(row.get("retired_at") or ""),
        }
    except Exception as ex:
        _debug_print(f"[reviews_db] could not read retired node {nid}: {ex}")
        return None
    finally:
        _close_quietly(conn)


def clear_container_deletions(server_ids):
    """Drop tombstones for containers whose removal has been confirmed.

    Called by the admin console after a manual delete (a 404 from the agent
    counts: the container is already gone) or to dismiss a stale entry, and by
    app1's reconcile sweep when a node reports a tombstoned id removed anyway.
    """
    ids = [str(s) for s in (server_ids or []) if s is not None and str(s) != ""]
    if not ids:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        placeholders = ",".join(f"%(id{i})s" for i in range(len(ids)))
        params = {f"id{i}": v for i, v in enumerate(ids)}
        cur.execute(f"DELETE FROM pending_container_deletions WHERE server_id IN ({placeholders})", params)
        deleted = max(0, cur.rowcount)
        conn.commit()
        return deleted
    except Exception as ex:
        _debug_print(f"[reviews_db] could not clear pending deletions: {ex}")
        return 0
    finally:
        _close_quietly(conn)


# ── HeatWave App Config Management ───────────────────────────────

def get_app_config(key, default=None):
    """Read a configuration value from HeatWave MySQL DB."""
    conn = _conn()
    if conn is None:
        return default
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT config_value FROM app_config WHERE config_key=%(k)s", {"k": str(key)})
        row = cur.fetchone()
        if row and row.get("config_value") is not None:
            return row["config_value"]
        return default
    except Exception as ex:
        _debug_print(f"[reviews_db] could not get config {key}: {ex}")
        return default
    finally:
        _close_quietly(conn)


def set_app_config(key, value):
    """Write a configuration value to HeatWave MySQL DB."""
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        key_str = str(key).strip()
        val_str = str(value if value is not None else "")
        try:
            cur.execute(
                "INSERT INTO app_config(config_key, config_value, updated_at) "
                "VALUES(%(k)s, %(v)s, %(now)s) "
                "ON DUPLICATE KEY UPDATE config_value=%(v)s, updated_at=%(now)s",
                {"k": key_str, "v": val_str, "now": _now()}
            )
        except Exception:
            cur.execute(
                "REPLACE INTO app_config(config_key, config_value, updated_at) "
                "VALUES(%(k)s, %(v)s, %(now)s)",
                {"k": key_str, "v": val_str, "now": _now()}
            )
        conn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[reviews_db] could not set config {key}: {ex}")
        return False
    finally:
        _close_quietly(conn)


# ── Bots store (HeatWave) ───────────────────────────────────────
# The MC-status Discord bots live here, not on the ATP. A bot belongs to a
# user account and is identified by (uid, slot_index) — there is no synthetic
# id column. uid points at the Oracle users table in the logical sense; the
# two stores cannot share an enforced constraint, so the link is the same
# opaque-id shape as reviews.uid.
#
# Degradation follows the rest of this module: HeatWave unconfigured or
# unreachable reads as "no bots" and writes report failure. Bots are public
# status-posters with their secrets encrypted at rest here — losing the store
# pauses them, it does not take the site down.
#
# The Discord token and the webhook URL are secrets. Both are Fernet-
# encrypted with the fleet's shared key (crypto_util) before they reach MySQL,
# exactly the way the old ATP column carried them, and the plaintext never
# leaves this module except inside the accessor dicts built for the owner's
# own request.

_BOT_ENC_FIELDS = ("name", "server_ip", "guild_id", "channel_id",
                   "embed_json", "ip_reply_json", "webhook_url")

# Byte ceiling on a bot's client-authored JSON blob — the same contract the
# old database.py enforced (backend.py's EMBED_JSON_MAX_BYTES matches too).
_BOT_JSON_MAX_BYTES = 65536

_BOT_DEFAULT_EMBED = {
    "title": "STATUS",
    "url": "",
    "color": "#9b59b6",
    "rotate_accent_on_update": False,
    "thumbnail": True,
    "online_text": "ONLINE",
    "offline_text": "OFFLINE",
    "footer": "Powered by MC Status Hosting",
    "footer_icon_url": "",
    "show_ip": True,
    "show_players": True,
    "show_playerlist": True,
    "show_version": True,
    "show_motd": True,
    "ip_label": "IP & PORT",
    "status_label": "STATUS",
    "players_label": "PLAYERS ONLINE",
    "playerlist_label": "PLAYER LIST",
    "version_label": "VERSION",
    "motd_label": "MOTD",
    "max_players_in_list": 20,
    "author_enabled": False,
    "author_name": "",
    "author_icon_url": "",
    "author_url": "",
    "image_enabled": False,
    "image_url": "",
    "show_timestamp": False,
    "thumbnail_size": 62,
    "author_icon_size": 22,
    "image_max_height": 0,
    "accent_bar_width": 4,
    "widgets": [
        {"id": "ip", "type": "ip", "label": "IP & PORT", "inline": False, "enabled": True},
        {"id": "players", "type": "players", "label": "PLAYERS ONLINE", "inline": False, "enabled": True},
        {"id": "playerlist", "type": "playerlist", "label": "PLAYER LIST", "inline": False, "enabled": True},
        {"id": "version", "type": "version", "label": "VERSION", "inline": False, "enabled": True},
        {"id": "motd", "type": "motd", "label": "MOTD", "inline": False, "enabled": True},
    ],
    "custom_fields": [],
}

_BOT_DEFAULT_IP_REPLY = {
    "enabled": False,
    "trigger": "ip",
    "mode": "plain",
    "plain_text": "**{ip_port}**",
    "embed": {
        "title": "SERVER ADDRESS",
        "description": "```{ip_port}```",
        "color": "#9b59b6",
        "footer": "Powered by MC Status Hosting",
    },
}


def _bot_crypto():
    """The shared Fernet helpers, imported lazily.

    reviews_db must stay importable (and every non-bot function usable) in a
    process that has no crypto stack, so the import happens on first bot use
    rather than at module scope.
    """
    from crypto_util import decrypt, encrypt, looks_encrypted, mask
    return encrypt, decrypt, looks_encrypted, mask


def _bot_default_embed():
    import copy
    return copy.deepcopy(_BOT_DEFAULT_EMBED)


def _bot_default_ip_reply():
    import copy
    return copy.deepcopy(_BOT_DEFAULT_IP_REPLY)


def _bot_json_obj(raw, default_factory):
    """Parse a stored bot blob into a dict, or hand back a fresh default.

    The column holds client-authored JSON, so it can be absent, empty,
    unparseable, or valid JSON that is not an object — every one of those
    resolves to the default rather than raising on the read path.
    """
    import json
    try:
        parsed = json.loads(raw or "{}")
    except Exception:
        parsed = None
    if not isinstance(parsed, dict) or not parsed:
        return default_factory()
    return parsed


def _bot_json_blob(value, label):
    """Serialise a bot builder blob for its column, or raise ValueError."""
    import json
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    try:
        encoded = json.dumps(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} is not serialisable as JSON")
    if len(encoded.encode("utf-8", "replace")) > _BOT_JSON_MAX_BYTES:
        raise ValueError(f"{label} is too large (max {_BOT_JSON_MAX_BYTES} bytes)")
    return encoded


def _bot_decrypt_or_raw(value):
    """Decrypt an at-rest bot column; ciphertext that no key here can read
    comes back None, and anything not encrypted passes through unchanged."""
    if not value:
        return None
    encrypt, decrypt, looks_encrypted, _mask = _bot_crypto()
    if not looks_encrypted(value):
        return value
    try:
        return decrypt(value) or None
    except Exception:
        return None


def _bot_decrypt_row(d):
    for k in _BOT_ENC_FIELDS:
        if k in d:
            d[k] = _bot_decrypt_or_raw(d[k])
    return d


def _bot_public_dict(d):
    """The accessor shape every caller gets: encrypted columns decrypted,
    token/webhook masked copies alongside, JSON blobs parsed, and ``id``
    aliased to the slot index so owner-scoped UIs keep addressing bots by one
    integer."""
    _bot_decrypt_row(d)
    _encrypt, decrypt, _looks, mask = _bot_crypto()
    token = None
    if d.get("token_enc"):
        try:
            token = decrypt(d["token_enc"]) or None
        except Exception:
            token = None
    d["token"] = token
    d["token_masked"] = mask(token)
    d["webhook_url_masked"] = mask(d.get("webhook_url"))
    d["embed"] = _bot_json_obj(d.get("embed_json"), _bot_default_embed)
    d["ip_reply"] = _bot_json_obj(d.get("ip_reply_json"), _bot_default_ip_reply)
    try:
        d["slot_index"] = int(d.get("slot_index") or 0)
    except (TypeError, ValueError):
        d["slot_index"] = 0
    d["id"] = d["slot_index"]
    d["running"] = int(d.get("running") or 0)
    try:
        d["server_port"] = int(d.get("server_port") or 25565)
    except (TypeError, ValueError):
        d["server_port"] = 25565
    try:
        d["update_interval"] = int(d.get("update_interval") or 60)
    except (TypeError, ValueError):
        d["update_interval"] = 60
    return d


# The engine tick lease compares last_run values that several engine
# instances write and read. Those instances may sit on machines whose clocks
# disagree, so the timestamps come from the HeatWave server's clock, measured
# once per _BOT_CLOCK_TTL exactly the way database.py measures the Oracle one.
_BOT_CLOCK_TTL = 60.0
_bot_clock_lock = threading.Lock()
_bot_clock_offset = 0.0
_bot_clock_measured = 0.0


def _bot_shared_now(conn=None):
    global _bot_clock_offset, _bot_clock_measured
    if time.monotonic() - _bot_clock_measured >= _BOT_CLOCK_TTL:
        own = conn is None
        try:
            if own:
                conn = _conn()
                if conn is None:
                    return datetime.now(timezone.utc).isoformat()
            cur = conn.cursor()
            cur.execute("SELECT UTC_TIMESTAMP(6)")
            row = cur.fetchone()
            cur.close()
            db_dt = row[0] if row else None
            if db_dt is not None:
                if db_dt.tzinfo is None:
                    db_dt = db_dt.replace(tzinfo=timezone.utc)
                _bot_clock_offset = (db_dt - datetime.now(timezone.utc)).total_seconds()
                _bot_clock_measured = time.monotonic()
        except Exception:
            pass
        finally:
            if own:
                _close_quietly(conn)
    return (datetime.now(timezone.utc) + timedelta(seconds=_bot_clock_offset)).isoformat()


def ensure_bot_slots(uid, slots):
    """Insert bot rows for any declared slots that lack one. Never deletes —
    safe to call from read paths that just want the list to match the count."""
    uid = str(uid or "").strip()
    if not uid or len(uid) > USER_ID_MAX_CHARS:
        return
    try:
        slots = int(slots)
    except (TypeError, ValueError):
        return
    conn = _conn()
    if conn is None:
        return
    try:
        cur = conn.cursor()
        cur.execute("SELECT slot_index FROM bots WHERE uid=%(uid)s", {"uid": uid})
        have = {int(r[0]) for r in cur.fetchall()}
        encrypt, _decrypt, _looks, _mask = _bot_crypto()
        import json as _json
        for i in range(slots):
            if i in have:
                continue
            cur.execute(
                "INSERT INTO bots(uid, slot_index, name, created_at, embed_json) "
                "VALUES(%(uid)s, %(idx)s, %(name)s, %(now)s, %(embed)s)",
                {"uid": uid, "idx": i, "name": encrypt(f"Bot #{i+1}"),
                 "now": _now(), "embed": encrypt(_json.dumps(_bot_default_embed()))},
            )
        conn.commit()
    except Exception as ex:
        _debug_print(f"[reviews_db] ensure_bot_slots failed for {uid}: {ex}")
    finally:
        _close_quietly(conn)


def get_user_bots(user_id):
    """Every bot slot of one account, ordered by slot index, fully decrypted
    into the accessor shape."""
    uid = str(user_id or "").strip()
    if not uid:
        return []
    conn = _conn()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM bots WHERE uid=%(uid)s ORDER BY slot_index",
                    {"uid": uid})
        rows = cur.fetchall()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list bots for {uid}: {ex}")
        return []
    finally:
        _close_quietly(conn)
    return [_bot_public_dict(dict(r)) for r in rows]


def get_bot(user_id, slot_index):
    """One bot by owner + slot, or None."""
    uid = str(user_id or "").strip()
    if not uid:
        return None
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return None
    conn = _conn()
    if conn is None:
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM bots WHERE uid=%(uid)s AND slot_index=%(slot)s",
                    {"uid": uid, "slot": slot})
        row = cur.fetchone()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not read bot {uid}/{slot}: {ex}")
        return None
    finally:
        _close_quietly(conn)
    if not row:
        return None
    return _bot_public_dict(dict(row))


def save_bot_config(user_id, slot_index, *, name=None, server_ip=None, server_port=None,
                    edition=None, token=None, guild_id=None, channel_id=None,
                    webhook_url=None, update_interval=None, embed=None, ip_reply=None):
    """Update one bot's editable fields. False when there is no such row."""
    uid = str(user_id or "").strip()
    if not uid:
        return False
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        encrypt, _decrypt, _looks, _mask = _bot_crypto()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM bots WHERE uid=%(uid)s AND slot_index=%(slot)s",
                    {"uid": uid, "slot": slot})
        if not cur.fetchone():
            return False
        fields = {}
        if name is not None:
            fields["name"] = encrypt(str(name).strip())
        if server_ip is not None:
            fields["server_ip"] = encrypt(str(server_ip).strip())
        if edition is not None:
            fields["edition"] = str(edition).strip().lower() or "java"
        if server_port is not None:
            raw_port = str(server_port).strip()
            if not raw_port:
                if fields.get("edition") == "bedrock":
                    fields["server_port"] = 19132
                elif "edition" in fields:
                    fields["server_port"] = 25565
            else:
                try:
                    parsed_port = int(raw_port)
                except (ValueError, TypeError):
                    raise ValueError("Server port must be a number")
                if parsed_port < 1 or parsed_port > 65535:
                    raise ValueError("Server port must be between 1 and 65535")
                fields["server_port"] = parsed_port
        if token is not None and token != "":
            fields["token_enc"] = encrypt(str(token).strip())
            fields["message_id"] = None
        if guild_id is not None:
            clean = str(guild_id).strip()
            if clean and (not clean.isdigit() or len(clean) > 25):
                raise ValueError("Guild ID must be a Discord numeric ID")
            fields["guild_id"] = encrypt(clean)
        if channel_id is not None:
            clean = str(channel_id).strip()
            if clean and (not clean.isdigit() or len(clean) > 25):
                raise ValueError("Channel ID must be a Discord numeric ID")
            fields["channel_id"] = encrypt(clean)
            fields["message_id"] = None
        if update_interval is not None:
            try:
                fields["update_interval"] = max(15, int(update_interval))
            except (ValueError, TypeError):
                fields["update_interval"] = 60
        if embed is not None:
            fields["embed_json"] = encrypt(_bot_json_blob(embed, "embed"))
            fields["message_id"] = None
        if ip_reply is not None:
            fields["ip_reply_json"] = encrypt(_bot_json_blob(ip_reply, "ip_reply"))
        if webhook_url is not None and webhook_url != "":
            fields["webhook_url"] = encrypt(str(webhook_url).strip())
            fields["message_id"] = None
        fields["updated_at"] = _now()
        fields["last_error"] = None
        sets = ", ".join(f"{k}=%({k})s" for k in fields)
        params = dict(fields)
        params["uid"] = uid
        params["slot"] = slot
        cur.execute(
            f"UPDATE bots SET {sets} WHERE uid=%(uid)s AND slot_index=%(slot)s",
            params,
        )
        conn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[reviews_db] save_bot_config failed for {uid}/{slot}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def set_bot_running(user_id, slot_index, running):
    uid = str(user_id or "").strip()
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    if not uid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE bots SET running=%(r)s, last_error=NULL "
            "WHERE uid=%(uid)s AND slot_index=%(slot)s",
            {"r": int(bool(running)), "uid": uid, "slot": slot},
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as ex:
        _debug_print(f"[reviews_db] set_bot_running failed for {uid}/{slot}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def update_bot_runtime(user_id, slot_index, *, message_id=None, last_status=None,
                       last_error=None):
    """Extend the tick lease and record the latest publish outcome."""
    import json as _json
    uid = str(user_id or "").strip()
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    if not uid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        fields = {"last_run": _bot_shared_now(conn)}
        if message_id is not None:
            fields["message_id"] = message_id
        if last_status is not None:
            fields["last_status"] = _json.dumps(last_status)
        if last_error is not None:
            fields["last_error"] = last_error
        sets = ", ".join(f"{k}=%({k})s" for k in fields)
        params = dict(fields)
        params["uid"] = uid
        params["slot"] = slot
        cur = conn.cursor()
        cur.execute(
            f"UPDATE bots SET {sets} WHERE uid=%(uid)s AND slot_index=%(slot)s",
            params,
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as ex:
        _debug_print(f"[reviews_db] update_bot_runtime failed for {uid}/{slot}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def claim_bot_tick(user_id, slot_index, interval):
    """True for exactly one caller per bot per interval. Serialises N engines.

    One atomic conditional UPDATE on bots.last_run: the first engine to move
    the lease forward wins, everyone else sees rowcount 0. Both timestamps
    come from the HeatWave server's clock (see _bot_shared_now), so instances
    whose system clocks disagree still measure the lease against one clock.
    """
    try:
        secs = int(interval)
    except (TypeError, ValueError):
        secs = 60
    uid = str(user_id or "").strip()
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    if not uid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        now_iso = _bot_shared_now(conn)
        base = datetime.fromisoformat(now_iso)
        cutoff = (base - timedelta(seconds=max(0, secs))).isoformat()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bots SET last_run=%(now)s "
            "WHERE uid=%(uid)s AND slot_index=%(slot)s "
            "AND (last_run IS NULL OR last_run <= %(cutoff)s)",
            {"now": now_iso, "uid": uid, "slot": slot, "cutoff": cutoff},
        )
        ok = cur.rowcount == 1
        conn.commit()
        return ok
    except Exception as ex:
        _debug_print(f"[reviews_db] claim_bot_tick failed for {uid}/{slot}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def force_bot_claim(user_id, slot_index):
    """Take the lease unconditionally, for a publish that must happen now."""
    return update_bot_runtime(user_id, slot_index)


def clear_bot_claim(user_id, slot_index):
    """Drop the tick lease so the very next tick may publish immediately."""
    uid = str(user_id or "").strip()
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    if not uid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE bots SET last_run=NULL WHERE uid=%(uid)s AND slot_index=%(slot)s",
            {"uid": uid, "slot": slot},
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as ex:
        _debug_print(f"[reviews_db] clear_bot_claim failed for {uid}/{slot}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def delete_bot(user_id, slot_index):
    uid = str(user_id or "").strip()
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return 0
    if not uid:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM bots WHERE uid=%(uid)s AND slot_index=%(slot)s",
                    {"uid": uid, "slot": slot})
        deleted = max(0, cur.rowcount)
        conn.commit()
        return deleted
    except Exception as ex:
        _debug_print(f"[reviews_db] could not delete bot {uid}/{slot}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


def delete_user_bots(user_id):
    """Every bot of one account — the account-deletion cascade half that used
    to run inside the ATP."""
    uid = str(user_id or "").strip()
    if not uid:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM bots WHERE uid=%(uid)s", {"uid": uid})
        deleted = max(0, cur.rowcount)
        conn.commit()
        return deleted
    except Exception as ex:
        _debug_print(f"[reviews_db] could not delete bots for {uid}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


def list_running_bots():
    """Every running bot across the fleet — the engine tick's read. The
    explicit column list is exactly the keys the engine touches per tick."""
    conn = _conn()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT uid, slot_index, token_enc, channel_id, server_ip, server_port, "
            "edition, update_interval, message_id, embed_json, ip_reply_json, "
            "running, webhook_url FROM bots WHERE running=1"
        )
        rows = cur.fetchall()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list running bots: {ex}")
        return []
    finally:
        _close_quietly(conn)
    return [_bot_public_dict(dict(r)) for r in rows]


def list_all_bots():
    """Fleet view for the admin console: every bot, running or not."""
    conn = _conn()
    if conn is None:
        return []
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT uid, slot_index, name, token_enc, channel_id, server_ip, server_port, "
            "edition, update_interval, guild_id, message_id, running, last_error "
            "FROM bots ORDER BY uid, slot_index"
        )
        rows = cur.fetchall()
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list bots: {ex}")
        return []
    finally:
        _close_quietly(conn)
    out = []
    for r in rows:
        d = dict(r)
        _bot_decrypt_row(d)
        _encrypt, decrypt, _looks, _mask = _bot_crypto()
        try:
            d["token"] = decrypt(d["token_enc"]) if d.get("token_enc") else None
        except Exception:
            d["token"] = None
        try:
            d["slot_index"] = int(d.get("slot_index") or 0)
        except (TypeError, ValueError):
            d["slot_index"] = 0
        d["id"] = d["slot_index"]
        d["running"] = int(d.get("running") or 0)
        out.append(d)
    return out


def bot_counts_by_uid():
    """{uid: (bot_count, bots_running)} for the admin user list."""
    conn = _conn()
    if conn is None:
        return {}
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT uid, COUNT(*), SUM(CASE WHEN running=1 THEN 1 ELSE 0 END) "
            "FROM bots GROUP BY uid"
        )
        return {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in cur.fetchall()}
    except Exception as ex:
        _debug_print(f"[reviews_db] could not count bots: {ex}")
        return {}
    finally:
        _close_quietly(conn)


def stop_user_bots(user_id, reason=None):
    """Stop every running bot of one account — the trial-lapse half of the
    lifecycle. Returns how many were running."""
    uid = str(user_id or "").strip()
    if not uid:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE bots SET running=0, last_error=%(reason)s "
            "WHERE uid=%(uid)s AND running=1",
            {"uid": uid, "reason": reason},
        )
        stopped = max(0, cur.rowcount)
        conn.commit()
        return stopped
    except Exception as ex:
        _debug_print(f"[reviews_db] stop_user_bots failed for {uid}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


def restart_stopped_user_bots(user_id, stopped_reason):
    """Restart bots that a previous lifecycle pass stopped for `stopped_reason`
    — the renew half of the trial cycle."""
    uid = str(user_id or "").strip()
    if not uid:
        return 0
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE bots SET running=1, last_error=NULL "
            "WHERE uid=%(uid)s AND running=0 AND last_error=%(reason)s",
            {"uid": uid, "reason": stopped_reason},
        )
        restarted = max(0, cur.rowcount)
        conn.commit()
        return restarted
    except Exception as ex:
        _debug_print(f"[reviews_db] restart_stopped_user_bots failed for {uid}: {ex}")
        return 0
    finally:
        _close_quietly(conn)


def user_has_started_bot(user_id):
    """Whether the account ever ran a bot (running now or has a tick lease)."""
    uid = str(user_id or "").strip()
    if not uid:
        return False
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM bots WHERE uid=%(uid)s "
            "AND (running=1 OR last_run IS NOT NULL)",
            {"uid": uid},
        )
        r = cur.fetchone()
        return bool(r and int(r[0] or 0) > 0)
    except Exception:
        return False
    finally:
        _close_quietly(conn)


def get_inactive_warned(user_id):
    """Timestamp the weekly trial warning was last sent for this account.

    The renew cycle recomputes the warning window from trial_expires_at on
    every sweep, so the marker no longer needs a users column — it lives here,
    losable like the rest of this store (worst case: one extra warning mail
    after a HeatWave outage)."""
    return get_app_config(f"inactive_warned:{str(user_id).strip()}")


def set_inactive_warned(user_id, when):
    """Mark the warning sent. Returns False when it could not be stored —
    callers must then skip the send, because a warning that cannot be marked
    would be re-sent on every sweep."""
    return set_app_config(f"inactive_warned:{str(user_id).strip()}", str(when))


def clear_inactive_warned(user_id):
    """Renew restarts the cycle, so the marker goes with it."""
    return set_app_config(f"inactive_warned:{str(user_id).strip()}", "")


def _bot_flag_key(user_id, slot_index, name):
    return f"bot:{str(user_id).strip()}:{int(slot_index)}:{name}"


def get_bot_delivery(user_id, slot_index):
    """The bot's delivery switches as {"use_token": 0|1, "use_webhook": 0|1}.

    Stored in app_config rather than the bots row: two operator switches with
    no PII, and an unreadable pair reads as (0, 0), which every caller treats
    as "no explicit choice, keep the historical precedence".
    """
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return {"use_token": 0, "use_webhook": 0}
    out = {}
    for name in ("use_token", "use_webhook"):
        raw = get_app_config(_bot_flag_key(user_id, slot, name), "0")
        out[name] = 1 if str(raw).strip() == "1" else 0
    return out


def set_bot_delivery(user_id, slot_index, use_token, use_webhook):
    """Store the two switches. True only when both writes land."""
    try:
        slot = int(slot_index)
    except (TypeError, ValueError):
        return False
    ok_token = set_app_config(_bot_flag_key(user_id, slot, "use_token"), "1" if use_token else "0")
    ok_hook = set_app_config(_bot_flag_key(user_id, slot, "use_webhook"), "1" if use_webhook else "0")
    return bool(ok_token and ok_hook)


# Never read this flag from HeatWave on the hot path: every _debug_print used
# to open a MySQL pool (CREATE DATABASE even) during import / Ctrl+C, which
# hung every tier before waitress bound. CONSOLE_DEBUG in the environment is
# the operator switch; the admin toggle still writes app_config for the
# console, and only updates the in-process flag via set_console_debug_enabled.
_CONSOLE_DEBUG_ACTIVE = str(os.environ.get("CONSOLE_DEBUG", "")).strip().lower() in (
    "1", "true", "yes", "on",
)


def is_console_debug_enabled() -> bool:
    """Whether stdout/stderr debug lines are allowed.

    Env CONSOLE_DEBUG=1/true/yes/on forces on; 0/false/no/off forces off.
    Otherwise the in-process flag from set_console_debug_enabled() is used.
    Does not open HeatWave.
    """
    env = str(os.environ.get("CONSOLE_DEBUG", "")).strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    return _CONSOLE_DEBUG_ACTIVE


def set_console_debug_enabled(enabled: bool) -> bool:
    """Toggle debug info in console (stdout/stderr)."""
    global _CONSOLE_DEBUG_ACTIVE
    _CONSOLE_DEBUG_ACTIVE = bool(enabled)
    return set_app_config("console_debug_enabled", "1" if enabled else "0")


def _debug_print(*args, **kwargs):
    if _CONSOLE_DEBUG_ACTIVE:
        print(*args, **kwargs)


# ── App Error Logging API ─────────────────────────────────────────

def log_app_error(error_type, message, stack_trace=None, module=None, flagged=1, flag_reason=None, error_category=None):
    """Direct errors from app/ to HeatWave DB and flag them.
    Console printing (stdout/stderr) is strictly suppressed unless console debug is enabled in config.
    """
    if not error_category:
        err_type_str = str(error_type or "")
        mod_str = str(module or "")
        if err_type_str.startswith(("DeviceFlag", "MultiAccount", "Tamper", "UserFlag", "shared_device", "banned_alt")) or mod_str in ("device_security", "registration", "auth"):
            error_category = "user_flag"
        else:
            error_category = "system_error"

    conn = _conn()
    if conn is None:
        if is_console_debug_enabled():
            _debug_print(f"[app_error_fallback] {error_type}: {message}")
        return False

    # One row per distinct error, not one per occurrence. A device/multi-account
    # flag is re-evaluated on every login, so the same person tripping the same
    # rule used to append a row per sign-in; the same holds for a system error in
    # a retry loop. The message carries the user id, so matching on it is what
    # makes this per-person rather than per-rule. No time window: the ask is
    # "already there" — a second row adds nothing an operator acts on.
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM app_errors "
            "WHERE error_type = %(err_type)s "
            "AND message = %(msg)s "
            "AND COALESCE(module, '') = COALESCE(%(mod)s, '') "
            "AND COALESCE(flag_reason, '') = COALESCE(%(reason)s, '') "
            "LIMIT 1",
            {
                "err_type": str(error_type or "UnhandledException")[:255],
                "msg": str(message or "")[:4000],
                "mod": str(module or "app")[:255],
                "reason": str(flag_reason)[:255] if flag_reason else None,
            },
        )
        existing = cur.fetchone()
        cur.close()
        if existing:
            # Recurrence of an already-logged error: bump its count instead of
            # inserting a duplicate row, so the console can show how many times
            # the same error fired. Also closes the conn this early return leaked.
            try:
                bump = conn.cursor()
                bump.execute("UPDATE app_errors SET occurrences = occurrences + 1 WHERE id=%(id)s",
                             {"id": existing[0]})
                conn.commit()
                bump.close()
            except Exception:
                pass
            _close_quietly(conn)
            if is_console_debug_enabled():
                _debug_print(f"[app_error_dedup] {error_type} ({module}) already recorded as #{existing[0]}")
            return existing[0]
    except Exception as ex:
        # A failed dedupe check must not lose the error it was checking for.
        if is_console_debug_enabled():
            _debug_print(f"[reviews_db] dedupe check failed, logging anyway: {ex}")

    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO app_errors(error_type, error_category, message, stack_trace, module, flag_reason, flagged, created_at) "
            "VALUES(%(err_type)s, %(cat)s, %(msg)s, %(trace)s, %(mod)s, %(reason)s, %(flagged)s, %(now)s)",
            {"err_type": str(error_type or "UnhandledException")[:255],
             "cat": str(error_category)[:50],
             "msg": str(message or "")[:4000],
             "trace": str(stack_trace) if stack_trace else None,
             "mod": str(module or "app")[:255],
             "reason": str(flag_reason)[:255] if flag_reason else None,
             "flagged": 1 if flagged else 0,
             "now": _now()},
        )
        err_id = getattr(cur, "lastrowid", None)
        conn.commit()

        try:
            cur.execute(
                "DELETE FROM app_errors WHERE id NOT IN ("
                "SELECT id FROM (SELECT id FROM app_errors ORDER BY id DESC LIMIT 5000) keep)")
            conn.commit()
        except Exception:
            pass

        if is_console_debug_enabled():
            _debug_print(f"[app_error] [{module or 'app'}] {error_type}: {message}")

        return err_id if err_id else True
    except Exception as ex:
        if is_console_debug_enabled():
            _debug_print(f"[reviews_db] could not log app error: {ex}")
        return False
    finally:
        _close_quietly(conn)


def get_app_errors(limit=200, offset=0, only_flagged=False, category=None):
    """Retrieve logged app errors for admin review."""
    conn = _conn()
    if conn is None:
        return []
    where = []
    params = {"lim": _clean_limit(limit, 200), "off": _clean_offset(offset)}
    if only_flagged:
        where.append("flagged=1")
    if category and category in ("user_flag", "system_error"):
        where.append("error_category=%(cat)s")
        params["cat"] = category
    sql = ("SELECT id, error_type, error_category, message, stack_trace, module, flag_reason, flagged, occurrences, created_at "
           "FROM app_errors")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT %(lim)s OFFSET %(off)s"
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        rows = cur.fetchall()
        for r in rows:
            r["flagged"] = int(r.get("flagged") or 0)
            r["occurrences"] = int(r.get("occurrences") or 1)
            if not r.get("error_category"):
                err_type_str = str(r.get("error_type") or "")
                mod_str = str(r.get("module") or "")
                if err_type_str.startswith(("DeviceFlag", "MultiAccount", "Tamper", "UserFlag", "shared_device", "banned_alt")) or mod_str in ("device_security", "registration", "auth"):
                    r["error_category"] = "user_flag"
                else:
                    r["error_category"] = "system_error"
        return rows
    except Exception as ex:
        _debug_print(f"[reviews_db] could not list app errors: {ex}")
        return []
    finally:
        _close_quietly(conn)


def count_flagged_app_errors(category=None):
    """Badge count of flagged app errors for admin display."""
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        if category and category in ("user_flag", "system_error"):
            cur.execute("SELECT COUNT(*) FROM app_errors WHERE flagged=1 AND error_category=%(cat)s", {"cat": category})
        else:
            cur.execute("SELECT COUNT(*) FROM app_errors WHERE flagged=1")
        r = cur.fetchone()
        return int(r[0] if r else 0)
    except Exception:
        return 0
    finally:
        _close_quietly(conn)
        _close_quietly(conn)


def flag_app_error(error_id, flagged=1):
    """Flag or unflag an app error."""
    conn = _conn()
    if conn is None:
        return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE app_errors SET flagged=%(flg)s WHERE id=%(id)s",
                    {"flg": 1 if flagged else 0, "id": int(error_id)})
        conn.commit()
        return cur.rowcount > 0
    except Exception as ex:
        _debug_print(f"[reviews_db] could not flag app error {error_id}: {ex}")
        return False
    finally:
        _close_quietly(conn)


def delete_app_error(error_id):
    """Delete an app error record."""
    conn = _conn()
    if conn is None:
        return 0
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM app_errors WHERE id=%(id)s", {"id": int(error_id)})
        deleted = max(0, cur.rowcount)
        conn.commit()
        return deleted
    except Exception as ex:
        _debug_print(f"[reviews_db] could not delete app error {error_id}: {ex}")
        return 0
    finally:
        _close_quietly(conn)

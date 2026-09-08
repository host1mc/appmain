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
        the `reviews` table, and nothing else. Reached through _pool() / _conn().
        Losing it degrades to "no reviews" and the site stays up.

No query in this file touches the ATP, and no query in database.py touches
HeatWave. That is the whole boundary, and it is why reviews could move at all:
they are public marketing copy with no PII, no foreign key into `users` beyond
an opaque id string, and no write that has to be atomic with anything Oracle
holds. Moving them leaves the ATP's Always Free session budget to the tiers that
actually need it.

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
from datetime import datetime, timezone

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
                node_ip VARCHAR(255) NOT NULL DEFAULT '',
                `purge` TINYINT NOT NULL DEFAULT 1,
                requested_at VARCHAR(50) NOT NULL,
                KEY pcd_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        try:
            cur.execute("SHOW COLUMNS FROM pending_container_deletions LIKE 'node_ip'")
            if not cur.fetchone():
                cur.execute(
                    "ALTER TABLE pending_container_deletions "
                    "ADD COLUMN node_ip VARCHAR(255) NOT NULL DEFAULT '' AFTER node_id"
                )
        except Exception as ex:
            _debug_print(f"[reviews_db] column check failed for pending_container_deletions.node_ip: {ex}")
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

def enqueue_container_deletion(server_id, node_id="", node_ip="", purge=True):
    """Record a container whose node delete was not confirmed (node offline).

    ``node_ip`` is the address(es) the node registry had for the node at delete
    time, kept so the admin panel can show which host holds the container
    without a registry lookup succeeding later.

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
            "INSERT INTO pending_container_deletions(server_id, node_id, node_ip, `purge`, requested_at) "
            "VALUES(%(s)s, %(n)s, %(ip)s, %(p)s, %(now)s) "
            "ON DUPLICATE KEY UPDATE node_id=%(n)s, node_ip=%(ip)s, `purge`=%(p)s, requested_at=%(now)s",
            {
                "s": str(server_id), "n": str(node_id or ""),
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
            "SELECT server_id, node_id, node_ip, `purge`, requested_at "
            "FROM pending_container_deletions ORDER BY requested_at"
        )
        rows = cur.fetchall() or []
        out = []
        for row in rows:
            out.append({
                "server_id": str(row.get("server_id") or ""),
                "node_id": str(row.get("node_id") or ""),
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


def _bot_flag_key(bot_id, name):
    return f"bot:{int(bot_id)}:{name}"


def get_bot_delivery(bot_id):
    """The bot's delivery switches as {"use_token": 0|1, "use_webhook": 0|1}.

    Stored in app_config rather than the ATP's `bots` row: these are two
    operator switches with no PII, and HeatWave being down must not stop a bot
    from posting — an unreadable pair reads as (0, 0), which every caller treats
    as "no explicit choice, keep the historical precedence".
    """
    try:
        bot_id = int(bot_id)
    except (TypeError, ValueError):
        return {"use_token": 0, "use_webhook": 0}
    out = {}
    for name in ("use_token", "use_webhook"):
        raw = get_app_config(_bot_flag_key(bot_id, name), "0")
        out[name] = 1 if str(raw).strip() == "1" else 0
    return out


def set_bot_delivery(bot_id, use_token, use_webhook):
    """Store the two switches. True only when both writes land."""
    try:
        bot_id = int(bot_id)
    except (TypeError, ValueError):
        return False
    ok_token = set_app_config(_bot_flag_key(bot_id, "use_token"), "1" if use_token else "0")
    ok_hook = set_app_config(_bot_flag_key(bot_id, "use_webhook"), "1" if use_webhook else "0")
    return bool(ok_token and ok_hook)


_CONSOLE_DEBUG_ACTIVE = False


def is_console_debug_enabled() -> bool:
    """Check if debug info in console (stdout/stderr) is enabled.
    Defaults to False (0) so operational errors stay strictly in HeatWave DB.
    """
    global _CONSOLE_DEBUG_ACTIVE
    conn = _conn()
    if conn is None:
        return _CONSOLE_DEBUG_ACTIVE
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT config_value FROM app_config WHERE config_key='console_debug_enabled'")
        row = cur.fetchone()
        if row and row.get("config_value") is not None:
            val = str(row["config_value"]).strip().lower() in ("1", "true", "yes", "on")
            _CONSOLE_DEBUG_ACTIVE = val
            return val
        return _CONSOLE_DEBUG_ACTIVE
    except Exception:
        return _CONSOLE_DEBUG_ACTIVE
    finally:
        _close_quietly(conn)


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

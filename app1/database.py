def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass

import warnings
warnings.filterwarnings("ignore")

import copy
import contextvars
import os
import re
import smtplib
import ssl
import json
import secrets
import hashlib
import sys
import threading
import time
import traceback
import uuid
import email.mime.text
import email.mime.multipart
import email.utils
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

from crypto_util import encrypt, decrypt, decrypt_strict, looks_encrypted, mask, lookup_hash
from cryptography.fernet import InvalidToken
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

import renew_config
import email_templates

_otp_ph = PasswordHasher()

# One source of truth for the product brand in outgoing mail; both the values
# live in renew_config so the whole rename is a one-file edit.
BRAND_NAME = renew_config.BRAND_NAME

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _qcol(col):
    # UID is an Oracle reserved word, so the join key is created as a quoted
    # lowercase "uid" and every reference to it has to be quoted the same way.
    return f'"{col}"' if col.lower() == "uid" else col


def _validate_identifier(name, *, allow=frozenset()):
    """Reject SQL identifiers that are not in *allow* or do not match
    ``[A-Za-z_][A-Za-z0-9_]*`` (max 128 chars).  Prevents SQL injection via
    dynamic column / table names even when the caller controls the value."""
    if name not in allow:
        raise ValueError(f"disallowed SQL identifier: {name!r}")
    if not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return name


def _dec_or_raw(value):
    """Read a column that is encrypted going forward but may still be plaintext.

    Everything written through set_setting (and the payload columns listed beside
    it) is Fernet-encrypted, but rows written before that was true are still
    plaintext and there is no migration step — a row upgrades the next time it is
    written. Fernet tokens always start 'gAAAAA', so the prefix tells the two
    apart.
    """
    if not looks_encrypted(value):
        return value
    try:
        return decrypt_strict(value)
    except InvalidToken:
        _debug_print(f"[db] _dec_or_raw: stored value is ciphertext but won't decrypt "
              f"(ENCRYPTION_KEY / secret.key changed?). Returning None.", file=sys.stderr)
        return None


def _enc_or_none(value):
    """Encrypt a free-text column, keeping empty as NULL rather than ciphertext."""
    return encrypt(value) if value else None


# ── Oracle support ──────────────────────────────────────────────
_ORACLE_ENABLED = False
_ORACLE_CFG = {}
_ORACLE_POOL = None
# Pool creation is not idempotent — two threads racing here would each build a
# pool and only one would be kept, leaking the other's sessions against the ATP
# session cap. One lock, one pool.
_ORACLE_POOL_LOCK = threading.Lock()
# Every tier (frontend, backend, engine, admin console) holds connections from
# its own process, and each serves several threads. The old max=10 was a silent
# ceiling shared by nobody in particular; size it per tier and let the deploy
# raise it via ORACLE_POOL_MAX.
#
# The cap is per process, and the target deployment is six of them across two
# instances — so one generous number would oversubscribe a small ATP's session
# limit rather than the app. Sized by what each tier does: the web tiers answer
# eight waitress threads each, while the engine's control API takes a handful of
# calls a minute and the maintenance daemon runs one sweep a minute.
_ORACLE_POOL_MAX_BY_TIER = {"backend": 4, "frontend": 4, "engine": 2, "database": 2,
                            "panel": 2}
_ORACLE_POOL_MAX_DEFAULT = 4

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app", ".env")

# Everything the shared .env declares, parsed into this module rather than
# exported. The file holds the Fernet key, the wallet password and the ATP
# credentials, and os.environ is inherited by every child process: main.py runs
# five tiers as subprocesses and the hosting tier spawns one per customer
# container, so a setdefault here would put those secrets in the environment
# block — readable from /proc/<pid>/environ, and dumped by any crash reporter —
# of processes that never needed them. Nothing outside this module reads these
# names out of os.environ: crypto_util._env() opens the same file as its own
# lowest tier and asgi_panel.py load_dotenv()s it for the panel.
_FILE_CFG = {}


def _load_env_file():
    """Parse the shared .env into _FILE_CFG.

    A raise here would stop every tier: this module is imported at module scope
    by all of them. So an unreadable or undecodable file leaves _FILE_CFG empty
    and lets the ORACLE_ENABLED check below deliver the real error instead.
    utf-8-sig decodes plain UTF-8 unchanged and drops a byte-order mark, which
    would otherwise fold into the first key's name.
    """
    try:
        if not os.path.exists(_ENV_PATH):
            return
        with open(_ENV_PATH, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                _FILE_CFG[k.strip()] = v.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass


def _setting(name, default=""):
    """One config name: real environment first, then the .env, then the default.

    That order is what os.environ.setdefault used to produce, and systemd or the
    shell winning over a .env line is relied on — asgi_panel.py rewrites
    ORACLE_WALLET_DIR to an absolute path that way.
    """
    return os.environ.get(name) or _FILE_CFG.get(name) or default


def _required_setting(name):
    """A setting with no usable default, raising the way os.environ[name] did."""
    value = _setting(name)
    if not value:
        raise KeyError(name)
    return value


def _wallet_files_present(wallet_dir):
    """True only when wallet_dir actually holds an Oracle wallet.

    The ATP now accepts one-way TLS (mutual TLS not required), so the wallet is
    optional: ORACLE_DSN carries the full tcps connect descriptor and the ADB
    server certificate chain is validated against the system CA store. When no
    wallet files are on disk we connect walletless and never point the driver at
    config_dir / TNS_ADMIN.
    """
    if not wallet_dir or not os.path.isdir(wallet_dir):
        return False
    return any(os.path.isfile(os.path.join(wallet_dir, name))
               for name in ("cwallet.sso", "ewallet.pem", "ewallet.p12"))


def _load_config():
    global _ORACLE_ENABLED, _ORACLE_CFG
    _load_env_file()
    enabled = _setting("ORACLE_ENABLED", "false").strip().lower() == "true"
    if enabled:
        import oracledb
        oracledb.defaults.fetch_lobs = False
        wallet_dir = os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app",
                         _setting("ORACLE_WALLET_DIR", "./Wallet_ATP")))
        wallet_present = _wallet_files_present(wallet_dir)
        _ORACLE_CFG = {
            "user": _required_setting("ORACLE_USER"),
            "password": _required_setting("ORACLE_PASSWORD"),
            "dsn": _required_setting("ORACLE_DSN"),
            "wallet_dir": wallet_dir if wallet_present else None,
            "wallet_password": _setting("ORACLE_WALLET_PASSWORD", ""),
        }
        # Only the mTLS (wallet) path needs the driver pointed at a wallet
        # directory; walletless one-way TLS reads nothing from disk.
        if wallet_present:
            os.environ["TNS_ADMIN"] = wallet_dir
        _ORACLE_ENABLED = True

def _tier_name() -> str:
    """Which tier this process is, from the launcher that started it.

    main.py runs each tier as `python start_<tier>.py`, and every tier is also
    runnable on its own the same way, so argv[0] names the tier in both cases.
    Anything else — a test, a REPL, the admin console — gets "" and the generic
    default, which is right: those hold one connection at a time.
    """
    stem = os.path.splitext(os.path.basename(sys.argv[0] or ""))[0]
    return stem[len("start_"):] if stem.startswith("start_") else ""


def _oracle_pool_max() -> int:
    default = _ORACLE_POOL_MAX_BY_TIER.get(_tier_name(), _ORACLE_POOL_MAX_DEFAULT)
    try:
        val = int(_setting("ORACLE_POOL_MAX", default))
    except (TypeError, ValueError):
        val = default
    return max(1, val)


# Seconds a caller will wait for a free pooled session before acquire() gives up.
# Deliberately short: see the getmode/wait_timeout comment in _oracle_pool below
# for why waiting is the thing that has to be bounded here.
_ORACLE_POOL_TIMEOUT_DEFAULT = 5


def _oracle_pool_timeout() -> int:
    """How long acquire() may block waiting for a session, in seconds.

    Parsed the same defensive way as ORACLE_POOL_MAX — this is read from a shared
    .env that six processes also read, so a typo must not stop a tier from
    booting. Floored at 1 rather than 0 because oracledb reads a zero
    ``wait_timeout`` as "no wait at all", which would turn every request that
    arrives while the pool is momentarily full into an error instead of one that
    waits a moment and succeeds.
    """
    try:
        val = int(_setting("ORACLE_POOL_TIMEOUT", _ORACLE_POOL_TIMEOUT_DEFAULT))
    except (TypeError, ValueError):
        val = _ORACLE_POOL_TIMEOUT_DEFAULT
    return max(1, val)


def _oracle_pool():
    global _ORACLE_POOL
    if _ORACLE_POOL is not None:
        return _ORACLE_POOL
    with _ORACLE_POOL_LOCK:
        # re-check inside the lock: the loser of the race must reuse the winner's
        # pool, not build a second one
        if _ORACLE_POOL is not None:
            return _ORACLE_POOL
        import oracledb
        oracledb.defaults.fetch_lobs = False
        oracledb.defaults.connect_timeout = 10
        pool_max = _oracle_pool_max()
        pool_wait = _oracle_pool_timeout()
        # Shed, don't queue. The ATP grants the whole fleet only ~20 concurrent
        # sessions, and the default getmode (POOL_GETMODE_WAIT) waits for a free
        # one with no bound — so under load every acquire() past the pool's max
        # parks its caller's web-server thread indefinitely and the tier stalls
        # behind the pool instead of staying responsive. POOL_GETMODE_TIMEDWAIT
        # caps that wait at wait_timeout, after which acquire() raises and the
        # request fails fast: a fast 503 keeps a thread free to serve the next
        # caller, where a 30s park would have held it hostage. wait_timeout is in
        # milliseconds and governs *waiting for a session from the pool* — which
        # is the acquire wait we want short. It is a distinct knob from `timeout`
        # below, which is the idle-session eviction time (seconds a session may
        # sit unused before the pool closes it) and is left as it was.
        pool_kwargs = dict(
            user=_ORACLE_CFG["user"],
            password=_ORACLE_CFG["password"],
            dsn=_ORACLE_CFG["dsn"],
            min=0,
            max=pool_max,
            increment=1,
            getmode=getattr(oracledb, "POOL_GETMODE_TIMEDWAIT", getattr(oracledb, "POOL_GETMODE_WAIT", 2)),
            wait_timeout=pool_wait * 1000,
            timeout=30,
        )
        # Wallet kwargs only when a wallet is actually on disk; otherwise this is
        # a walletless one-way TLS connection driven entirely by the descriptor.
        if _ORACLE_CFG.get("wallet_dir"):
            pool_kwargs.update(
                config_dir=_ORACLE_CFG["wallet_dir"],
                wallet_location=_ORACLE_CFG["wallet_dir"],
                wallet_password=_ORACLE_CFG.get("wallet_password", ""),
            )
        _ORACLE_POOL = oracledb.create_pool(**pool_kwargs)
        _debug_print(f"[database] Oracle pool created (max={pool_max}"
              + (f", tier={_tier_name()}" if _tier_name() else "") + ")")
    return _ORACLE_POOL

def _pool_saturated(pool) -> bool:
    """Whether the pool genuinely had nothing left to give: every session it is
    allowed to open is open, and all of them are checked out.

    Sampled after a failed acquire(), so it can race a release. A stale "not
    saturated" costs one more wait; a stale "saturated" is exactly the old
    behaviour, so neither answer can be worse than not asking.
    """
    try:
        return pool.busy >= pool.max
    except Exception:
        return True


def _oracle_conn():
    pool = _oracle_pool()
    try:
        return pool.acquire()
    except Exception as ex:
        # DPY-4005 means only "no session within wait_timeout", and that covers two
        # states that want opposite handling. Either the pool is at max with every
        # session busy — contention, and the fast failure above is the point — or the
        # pool is still below max and the wait expired while a *new* session was
        # being dialled. The second is a cold pool, which min=0 plus the 30s idle
        # timeout makes the normal state of any tier that touches Oracle less often
        # than that, and it could never succeed when the ATP took longer than
        # wait_timeout (5s) to hand over a session even though connect_timeout allows
        # it 10s. The maintenance daemon showed it plainly: its sweep is
        # single-threaded and every task closes its connection before the next one
        # acquires, so its pool of 2 cannot be exhausted, yet each sweep reported
        # DPY-4005 and logged "shedding with 503" against nothing.
        #
        # So retry once, and only while the pool was still growing: the connect then
        # gets its full connect_timeout across the two waits, and a saturated pool
        # still sheds on the first failure.
        if not _is_pool_exhausted(ex) or _pool_saturated(pool):
            raise
    return pool.acquire()

# One per object _ensure_oracle_cols_on() can create, so a cold start that loses
# every race in turn still converges. Five tiers boot at once and the function
# restarts from the top on each retry.
_BOOTSTRAP_MAX_ATTEMPTS = 16

def _alter_retry(cur, sql, what):
    """Run an ALTER TABLE with retries.

    Every tier calls init_db() at startup, so up to four processes race the
    same ALTERs. Oracle's DDL takes an exclusive lock with NOWAIT semantics
    (ORA-00054) — whoever loses the race retries until the winner commits.
    """
    for attempt in range(8):
        try:
            cur.execute(sql)
            return
        except Exception as ex:
            msg = str(ex)
            # ORA-01430 is "column being added already exists": another tier won
            # the race and the state this call wanted is already in place. Only
            # the users columns and otp_codes.attempts guarded against it at the
            # call site, so the bots, fingerprints and otp_codes.email_lookup_hash
            # ADDs below would abort a tier's whole startup on a lost race.
            if "ORA-01430" in msg:
                return
            if any(tag in msg for tag in ("ORA-00054", "ORA-04021", "ORA-04020")):
                time.sleep(1.0)
                continue
            raise
    raise RuntimeError(f"could not lock table for ALTER after 8 tries: {what}")


_SCHEMA_ENSURED = False
_SCHEMA_ENSURE_LOCK = threading.Lock()
_WIDENED_COLUMNS = set()


def _generate_uid(uconn):
    """Generate a random 10-char uid using secrets, with collision re-roll."""
    alphabet = "abcdefghijkmnopqrstuvwxyz23456789"
    for _ in range(100):  # safety re-roll limit
        uid = ''.join(secrets.choice(alphabet) for _ in range(10))
        cur = uconn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE \"uid\"=:u", {"u": uid})
        if cur.fetchone()[0] == 0:
            return uid
    # Fallback: use uuid shortened (extremely unlikely to collide after 100 tries)
    return str(uuid.uuid4())[:10]


def _ensure_oracle_cols():
    global _SCHEMA_ENSURED
    if not _ORACLE_ENABLED:
        return
    if _SCHEMA_ENSURED:
        return
    with _SCHEMA_ENSURE_LOCK:
        if _SCHEMA_ENSURED:
            return
        _ensure_oracle_cols_pass()
        _SCHEMA_ENSURED = True


def _ensure_oracle_cols_pass():
    conn = _oracle_conn()
    try:
        for attempt in range(_BOOTSTRAP_MAX_ATTEMPTS):
            try:
                _ensure_oracle_cols_on(conn)
                break
            except Exception as ex:
                # Every tier runs this bootstrap at startup, so whenever an object is
                # still missing two of them can both pass the same "does this exist?"
                # count check and both CREATE it. The loser gets ORA-00955, which is
                # not one of the lock errors _alter_retry retries, and the tier dies.
                # Retrying clears it: DDL commits as it succeeds, so by now the
                # winner's object exists and that create branch is skipped.
                #
                # It takes a loop rather than a single retry because the retry
                # restarts the whole function, and a later pass can lose a
                # *different* object's race than the one that failed first — on an
                # empty schema the engine lost hosting_servers, retried, then lost
                # fingerprints and died. Bounded, and guaranteed to terminate:
                # ORA-00955 means the object now exists, so every retry is forward
                # progress by somebody.
                if "ORA-00955" not in str(ex):
                    raise
                if attempt == _BOOTSTRAP_MAX_ATTEMPTS - 1:
                    raise
                _debug_print(f"[database] schema bootstrap raced another tier ({ex}); "
                      f"retrying ({attempt + 2}/{_BOOTSTRAP_MAX_ATTEMPTS})")
    finally:
        # Closing only after the last statement succeeded meant every failure
        # path dropped a pooled connection instead of returning it. engine.py
        # retries init_db() every 10s indefinitely, the engine's pool holds 2
        # sessions, and _oracle_conn() can only wait ORACLE_POOL_TIMEOUT seconds
        # for a session once it is empty before it starts failing outright.
        conn.close()


def _ensure_oracle_cols_on(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM user_tables WHERE table_name='USERS'")
    users_exists = cur.fetchone()[0] > 0
    if not users_exists:
        # uid is the one identifier: a random 10-char string minted once per
        # account, used as the join key in every user-linked table, and never
        # shown in the UI. There is no separate id/user_id pair any more.
        cur.execute("""
            CREATE TABLE users (
                "uid" VARCHAR2(10) PRIMARY KEY,
                username VARCHAR2(255) UNIQUE NOT NULL,
                username_lookup_hash VARCHAR2(64) UNIQUE,
                username_ci_lookup_hash VARCHAR2(64),
                email VARCHAR2(255),
                email_lookup_hash VARCHAR2(64) UNIQUE,
                password VARCHAR2(255),
                display_name VARCHAR2(255),
                slots VARCHAR2(10) DEFAULT '1',
                container_slots VARCHAR2(10) DEFAULT '1',
                email_verified VARCHAR2(5) DEFAULT '0',
                account_type VARCHAR2(20) DEFAULT 'trial',
                trial_expires_at VARCHAR2(50),
                is_active NUMBER DEFAULT 1,
                created_at VARCHAR2(50) NOT NULL,
                last_login VARCHAR2(50),
                ads_disabled NUMBER DEFAULT 0,
                is_banned NUMBER DEFAULT 0,
                banned_reason VARCHAR2(2000),
                discord_bot_token VARCHAR2(500),
                webhook_token VARCHAR2(500),
                fingerprint_ip VARCHAR2(500),
                verified_at VARCHAR2(50),
                last_active_at VARCHAR2(50),
                inactive_warned_at VARCHAR2(50),
                bot_stopped_at VARCHAR2(50)
            )
        """)
        # Mirrors the CREATE above. A column left out of this set is re-ADDed
        # below and only survives because ORA-01430 is tolerated.
        existing = {"uid","username","username_lookup_hash","username_ci_lookup_hash","email","email_lookup_hash","password","display_name","slots","container_slots","email_verified","account_type","trial_expires_at","is_active","created_at","last_login","ads_disabled","is_banned","banned_reason","discord_bot_token","webhook_token","fingerprint_ip","verified_at","last_active_at","inactive_warned_at","bot_stopped_at"}
    else:
        cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name='USERS'")
        existing = {r[0].lower() for r in cur.fetchall()}
    needed = {
        # The one hidden join key shared by every table: a random 10-char id,
        # never shown in the UI. All other tables link to users on this.
        "uid": "VARCHAR2(10)",
        "password": "VARCHAR2(255)",
        "username_lookup_hash": "VARCHAR2(64)",
        "username_ci_lookup_hash": "VARCHAR2(64)",
        "email_lookup_hash": "VARCHAR2(64)",
        "display_name": "VARCHAR2(255)",
        "slots": "VARCHAR2(10) DEFAULT '1'",
        "container_slots": "VARCHAR2(10) DEFAULT '1'",
        "email_verified": "VARCHAR2(5) DEFAULT '0'",
        "account_type": "VARCHAR2(20) DEFAULT 'trial'",
        "trial_expires_at": "VARCHAR2(50)",
        "is_active": "NUMBER DEFAULT 1",
        "ads_disabled": "NUMBER DEFAULT 0",
        "is_banned": "NUMBER DEFAULT 0",
        "banned_reason": "VARCHAR2(2000)",
        "discord_bot_token": "VARCHAR2(500)",
        "webhook_token": "VARCHAR2(500)",
        "fingerprint_ip": "VARCHAR2(500)",
        "verified_at": "VARCHAR2(50)",
        "last_active_at": "VARCHAR2(50)",
        "inactive_warned_at": "VARCHAR2(50)",
        "bot_stopped_at": "VARCHAR2(50)",
    }
    for col, dtype in needed.items():
        if col not in existing:
            if not _IDENTIFIER_RE.fullmatch(col):
                raise ValueError(f"invalid column name in DDL: {col!r}")
            try:
                _alter_retry(cur, f"ALTER TABLE users ADD {_qcol(col)} {dtype}", f"users.{col}")
            except Exception as ex:
                if "ORA-01430" in str(ex):
                    _debug_print(f"[database] Column {col} already exists, skipping")
                else:
                    raise
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='BOTS'"
    )
    if cur.fetchone()[0] == 0:
        # uid is the user link. Slot identity is (uid, slot_index). There is no
        # separate user_id column — the users table is keyed on uid alone.
        cur.execute("""
            CREATE TABLE bots (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "uid" VARCHAR2(10) NOT NULL,
                name VARCHAR2(255) DEFAULT 'My Bot',
                slot_index NUMBER DEFAULT 0,
                server_ip VARCHAR2(255),
                server_port NUMBER DEFAULT 25565,
                edition VARCHAR2(20) DEFAULT 'java',
                token_enc VARCHAR2(500),
                guild_id VARCHAR2(500),
                channel_id VARCHAR2(500),
                message_id VARCHAR2(100),
                embed_json CLOB,
                ip_reply_json CLOB,
                webhook_url VARCHAR2(500),
                update_interval NUMBER DEFAULT 60,
                running NUMBER DEFAULT 0,
                last_run VARCHAR2(50),
                last_status CLOB,
                last_error VARCHAR2(500),
                created_at VARCHAR2(50) NOT NULL,
                updated_at VARCHAR2(50)
            )
        """)
    cur.execute(
        "SELECT column_name FROM user_tab_columns WHERE table_name='BOTS'"
    )
    bot_cols = {r[0].lower() for r in cur.fetchall()}
    for col, dtype in [("uid", "VARCHAR2(10)"),
                         ("ip_reply_json", "CLOB"),
                         ("webhook_url", "VARCHAR2(500)")]:
        if col not in bot_cols:
            if not _IDENTIFIER_RE.fullmatch(col):
                raise ValueError(f"invalid column name in DDL: {col!r}")
            _alter_retry(cur, f"ALTER TABLE bots ADD {_qcol(col)} {dtype}", f"bots.{col}")
    # Discord IDs are short in plaintext, but these two columns are encrypted
    # at rest. A Fernet token for an 18-20 digit ID is about 120 characters, so
    # the original VARCHAR2(100) schema rejected every normal save.
    cur.execute("""
        SELECT column_name, data_length FROM user_tab_columns
        WHERE table_name='BOTS' AND column_name IN ('GUILD_ID','CHANNEL_ID')
    """)
    for column_name, data_length in cur.fetchall():
        if int(data_length or 0) < 500:
            if not _IDENTIFIER_RE.fullmatch(column_name):
                raise ValueError(f"invalid column name in DDL: {column_name!r}")
            _alter_retry(
                cur, f"ALTER TABLE bots MODIFY ({column_name} VARCHAR2(500))",
                f"bots.{column_name.lower()} width")
    # DC bot hosting servers: user code that the engine runs as supervised
    # processes. id is a Python-side UUID like users.id — INSERT ... RETURNING
    # has no precedent in this module, and a post-insert re-query would race a
    # concurrent create from the same account. name/code/start_command are
    # encrypted at rest like every other user payload in this database.
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='HOSTING_SERVERS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE hosting_servers (
                id VARCHAR2(36) PRIMARY KEY,
                "uid" VARCHAR2(10) NOT NULL,
                name VARCHAR2(500),
                runtime VARCHAR2(30) DEFAULT 'python',
                start_command VARCHAR2(255),
                code CLOB,
                status VARCHAR2(16) DEFAULT 'stopped',
                pid NUMBER,
                last_error VARCHAR2(1000),
                created_at VARCHAR2(50) NOT NULL,
                updated_at VARCHAR2(50)
            )
        """)
        # A read index, not a correctness requirement; losing the race against
        # another tier's identical CREATE is handled by the caller.
        try:
            cur.execute(
                "CREATE INDEX hosting_servers_uid ON hosting_servers (\"uid\")")
        except Exception as ex:
            _debug_print(f"[database] could not create hosting_servers_uid index: {ex}")
    # Point-in-time snapshots of a hosting server (code + text files, plus its
    # name/runtime/start command), encrypted at rest like every user payload.
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='HOSTING_BACKUPS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE hosting_backups (
                id VARCHAR2(36) PRIMARY KEY,
                server_id VARCHAR2(36),
                payload CLOB,
                created_at VARCHAR2(50) NOT NULL
            )
        """)
        try:
            cur.execute(
                "CREATE INDEX hosting_backups_server "
                "ON hosting_backups (server_id)")
        except Exception as ex:
            _debug_print(f"[database] could not create hosting_backups_server index: {ex}")
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='FINGERPRINTS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE fingerprints (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "uid" VARCHAR2(10) NOT NULL UNIQUE,
                fingerprint_hash VARCHAR2(500) NOT NULL,
                lookup_hash VARCHAR2(500) NOT NULL,
                device_info_enc CLOB,
                ip_address VARCHAR2(255),
                ip_lookup_hash VARCHAR2(64),
                created_at VARCHAR2(50) NOT NULL
            )
        """)
    else:
        cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name='FINGERPRINTS'")
        fp_cols = {r[0].lower() for r in cur.fetchall()}
        if "uid" not in fp_cols:
            _alter_retry(cur, "ALTER TABLE fingerprints ADD \"uid\" VARCHAR2(10)", "fingerprints.uid")
        if "user_id" in fp_cols:
            _debug_print("[database] fingerprints has deprecated user_id column, keeping for backfill")
        if "ip_address" not in fp_cols:
            _alter_retry(cur, "ALTER TABLE fingerprints ADD ip_address VARCHAR2(255)",
                         "fingerprints.ip_address")
        if "ip_lookup_hash" not in fp_cols:
            _alter_retry(cur, "ALTER TABLE fingerprints ADD ip_lookup_hash VARCHAR2(64)",
                         "fingerprints.ip_lookup_hash")
        # One device may now carry several accounts, so lookup_hash must not be
        # unique any more; repeat signups are flagged, not blocked.
        cur.execute("""
            SELECT uc.constraint_name FROM user_constraints uc
            JOIN user_cons_columns ucc ON ucc.constraint_name = uc.constraint_name
            WHERE uc.table_name='FINGERPRINTS' AND uc.constraint_type='U'
              AND ucc.column_name='LOOKUP_HASH'
        """)
        for (cname,) in cur.fetchall():
            try:
                if not _IDENTIFIER_RE.fullmatch(cname):
                    raise ValueError(f"invalid constraint name: {cname!r}")
                cur.execute(f"ALTER TABLE fingerprints DROP CONSTRAINT {cname}")
            except Exception as ex:
                _debug_print(f"[database] could not drop {cname} on fingerprints: {ex}")
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='FINGERPRINT_HISTORY'"
    )
    if cur.fetchone()[0] == 0:
        # fingerprints holds one current row per user and is overwritten on every
        # login, so the previous device was unrecoverable. This is the append-only
        # record behind it: no UNIQUE on user_id, and nothing ever UPDATEs a row.
        # record_fingerprint_history only writes when the hash or the address
        # actually changed, so a user on one machine costs one row, not one per
        # login — device_info_enc is a 10-25 KB CLOB and the ATP cap is shared.
        cur.execute("""
            CREATE TABLE fingerprint_history (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "uid" VARCHAR2(10) NOT NULL,
                fingerprint_hash VARCHAR2(500) NOT NULL,
                lookup_hash VARCHAR2(500) NOT NULL,
                device_info_enc CLOB,
                ip_address VARCHAR2(255),
                ip_lookup_hash VARCHAR2(64),
                created_at VARCHAR2(50) NOT NULL
            )
        """)
        # Indexes are a read optimisation, not a correctness requirement, and a
        # second tier racing the same CREATE raises ORA-00955 rather than a lock
        # error _alter_retry would retry. Losing that race must not stop startup.
        for idx_sql, what in (
            ("CREATE INDEX fp_hist_uid ON fingerprint_history (\"uid\")", "fp_hist_uid"),
            ("CREATE INDEX fp_hist_lookup ON fingerprint_history (lookup_hash)", "fp_hist_lookup"),
        ):
            try:
                cur.execute(idx_sql)
            except Exception as ex:
                _debug_print(f"[database] could not create {what}: {ex}")
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='DEVICE_EVENTS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE device_events (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "uid" VARCHAR2(10),
                username VARCHAR2(255),
                event_type VARCHAR2(50) NOT NULL,
                lookup_hash VARCHAR2(500),
                fingerprint_enc VARCHAR2(500),
                device_info_enc CLOB,
                ip_address VARCHAR2(45),
                blocked NUMBER DEFAULT 0,
                reviewed NUMBER DEFAULT 0,
                details CLOB,
                created_at VARCHAR2(50) NOT NULL
            )
        """)
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='SETTINGS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE settings (
                key VARCHAR2(255) PRIMARY KEY,
                value CLOB
            )
        """)
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='SESSIONS'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE sessions (
                id VARCHAR2(64) PRIMARY KEY,
                "uid" VARCHAR2(10),
                data CLOB NOT NULL,
                ip_address VARCHAR2(45),
                user_agent VARCHAR2(500),
                created_at VARCHAR2(50) NOT NULL,
                last_access VARCHAR2(50) NOT NULL,
                expires_at VARCHAR2(50) NOT NULL
            )
        """)
    else:
        cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name='SESSIONS'")
        sess_cols = {r[0].lower() for r in cur.fetchall()}
        if "uid" not in sess_cols:
            _alter_retry(cur, 'ALTER TABLE sessions ADD "uid" VARCHAR2(10)',
                         'sessions.uid')
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='USER_AD_ZONE_OVERRIDES'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE user_ad_zone_overrides (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "uid" VARCHAR2(10) NOT NULL,
                zone_key VARCHAR2(100) NOT NULL,
                enabled NUMBER DEFAULT 1,
                UNIQUE("uid", zone_key)
            )
        """)
    cur.execute(
        "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='OTP_CODES'"
    )
    if cur.fetchone()[0] == 0:
        cur.execute("""
            CREATE TABLE otp_codes (
                id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                email VARCHAR2(255) NOT NULL,
                email_lookup_hash VARCHAR2(64),
                code VARCHAR2(255) NOT NULL,
                purpose VARCHAR2(20) DEFAULT 'register',
                expires_at VARCHAR2(50) NOT NULL,
                used NUMBER DEFAULT 0,
                attempts NUMBER DEFAULT 0,
                created_at VARCHAR2(50) NOT NULL
            )
        """)
    else:
        cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name='OTP_CODES'")
        otp_cols = {r[0].lower() for r in cur.fetchall()}
        if "email_lookup_hash" not in otp_cols:
            _alter_retry(cur, "ALTER TABLE otp_codes ADD email_lookup_hash VARCHAR2(64)",
                         "otp_codes.email_lookup_hash")
        # Per-code guess counter behind OTP_MAX_ATTEMPTS in verify_otp. Five tiers
        # race this DDL, and the loser of the race sees the column already added
        # rather than a lock error, so ORA-01430 is tolerated the same way the
        # users columns above tolerate it.
        if "attempts" not in otp_cols:
            try:
                _alter_retry(cur, "ALTER TABLE otp_codes ADD attempts NUMBER DEFAULT 0",
                             "otp_codes.attempts")
            except Exception as ex:
                if "ORA-01430" in str(ex):
                    _debug_print("[database] Column attempts already exists, skipping")
                else:
                    raise
    # Fernet ciphertext is ~2.5x the plaintext, so every column that now carries
    # encrypted values is widened from its plaintext-era size. The migration
    # below writes ciphertext immediately, so a lock loss here is retried, not
    # swallowed: a still-narrow column would ORA-12899 mid-migration.
    widen_map = [
        ("FINGERPRINTS", [("ip_address", "VARCHAR2(255)")]),
        ("DEVICE_EVENTS", [("ip_address", "VARCHAR2(255)")]),
        ("SESSIONS", [("ip_address", "VARCHAR2(255)"),
                      ("user_agent", "VARCHAR2(2000)")]),
        ("USERS", [("email", "VARCHAR2(500)"),
                   ("banned_reason", "VARCHAR2(2000)")]),
        ("OTP_CODES", [("code", "VARCHAR2(255)")]),
    ]
    for table, stmts in widen_map:
        try:
            cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name=:t",
                        {"t": table})
            cols = {r[0].lower() for r in cur.fetchall()}
            for col, dtype in stmts:
                if col in cols and (table, col, dtype) not in _WIDENED_COLUMNS:
                    if not _IDENTIFIER_RE.fullmatch(table) or not _IDENTIFIER_RE.fullmatch(col):
                        raise ValueError(f"invalid identifier in widen DDL: {table!r}.{col!r}")
                    _alter_retry(cur, f"ALTER TABLE {table} MODIFY ({col} {dtype})",
                                 f"{table}.{col}")
                    _WIDENED_COLUMNS.add((table, col, dtype))
        except Exception as ex:
            _debug_print(f"[database] could not widen {table}: {ex}")
    # ── Column shrink migrations ────────────────────────────────────────
    # lookup_hash columns store SHA-256 hex digests (exactly 64 chars) but
    # were declared VARCHAR2(500). Shrinking saves ~436 bytes of inline
    # storage per row on tables that grow with every device/event.
    _shrink_map = [
        ("FINGERPRINTS", [
            ("LOOKUP_HASH", "VARCHAR2(64)"),
            ("IP_ADDRESS", "VARCHAR2(200)"),
        ]),
        ("FINGERPRINT_HISTORY", [
            ("LOOKUP_HASH", "VARCHAR2(64)"),
            ("IP_ADDRESS", "VARCHAR2(200)"),
        ]),
        ("DEVICE_EVENTS", [
            ("LOOKUP_HASH", "VARCHAR2(64)"),
            ("IP_ADDRESS", "VARCHAR2(200)"),
        ]),
        ("SESSIONS", [
            ("IP_ADDRESS", "VARCHAR2(200)"),
        ]),
        ("USERS", [
            ("EMAIL_VERIFIED", "NUMBER DEFAULT 0"),
            ("SLOTS", "NUMBER DEFAULT 1"),
        ]),
        ("BOTS", [
            ("MESSAGE_ID", "VARCHAR2(50)"),
            ("LAST_ERROR", "VARCHAR2(200)"),
        ]),
        ("HOSTING_SERVERS", [
            ("LAST_ERROR", "VARCHAR2(500)"),
            ("NAME", "VARCHAR2(300)"),
        ]),
        ("OTP_CODES", [
            ("CODE", "VARCHAR2(100)"),
        ]),
    ]
    for table, stmts in _shrink_map:
        try:
            cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name=:t",
                        {"t": table})
            cols = {r[0].lower() for r in cur.fetchall()}
            for col, dtype in stmts:
                if col.lower() in cols:
                    try:
                        if not _IDENTIFIER_RE.fullmatch(table) or not _IDENTIFIER_RE.fullmatch(col):
                            raise ValueError(f"invalid identifier in shrink DDL: {table!r}.{col!r}")
                        _alter_retry(cur, f"ALTER TABLE {table} MODIFY ({col} {dtype})",
                                     f"{table}.{col} shrink")
                    except Exception as ex:
                        if "ORA-01441" not in str(ex):
                            _debug_print(f"[database] could not shrink {table}.{col}: {ex}")
        except Exception as ex:
            _debug_print(f"[database] shrink pass for {table} failed: {ex}")
    # Missing index: username_ci_lookup_hash is queried on every case-insensitive
    # login but has no index, causing a full table scan on the users table.
    try:
        cur.execute(
            "CREATE INDEX idx_users_ci_lookup "
            "ON users (username_ci_lookup_hash)"
        )
    except Exception as ex:
        if "ORA-00955" not in str(ex):
            _debug_print(f"[database] could not create ci_lookup index: {ex}")
    try:
        cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name='USERS' AND column_name='HASHED_PASSWORD'")
        if cur.fetchone():
            _alter_retry(cur, "ALTER TABLE users DROP COLUMN hashed_password", "users.hashed_password")
    except Exception as ex:
        if "ORA-00904" not in str(ex) and "ORA-01430" not in str(ex):
            _debug_print(f"[database] could not drop hashed_password: {ex}")
    try:
        _remove_legacy_user_schema(conn, cur)
    except Exception as ex:
        _debug_print(f"[database] legacy schema removal incomplete: {ex}")
    conn.commit()


_LEGACY_CHILD_TABLES = (
    "SESSIONS", "BOTS", "DEVICE_EVENTS", "HOSTING_SERVERS",
    "USER_AD_ZONE_OVERRIDES", "SHARD_DIRECTORY",
)


def _table_columns(cur, table):
    cur.execute(
        "SELECT column_name FROM user_tab_columns WHERE table_name=:t",
        {"t": table})
    return {r[0].lower() for r in cur.fetchall()}


def _drop_column_quietly(cur, table, col):
    try:
        _alter_retry(cur, f"ALTER TABLE {table} DROP COLUMN {col}",
                     f"{table}.{col}")
    except Exception as ex:
        if "ORA-00904" not in str(ex) and "ORA-24430" not in str(ex):
            _debug_print(f"[database] could not drop {table}.{col}: {ex}")


def _remove_legacy_user_schema(conn, cur):
    """Erase the pre-uid schema from an old database.

    A database created before the uid rewrite keys users on a UUID ``id``
    (mirrored into ``user_id``), links every child table on ``user_id``, and
    carries an ``is_admin`` column from the era when admin lived inside the
    users table. The current code writes ``"uid"`` everywhere and has no admin
    concept in this schema at all, so against such a database every INSERT
    fails on the NOT NULL ``id`` (ORA-01400) and every join misses.

    Order matters: backfill ``users.uid`` for legacy rows first, copy the new
    uid into every child table's ``user_id`` rows, and only then drop the old
    columns and move the primary key onto ``uid``. Idempotent — a database
    already on the uid schema has neither ``id`` nor ``user_id`` on users and
    the function returns without issuing DDL. Race-tolerant like every
    migration here: the backfill holds row locks, DDL goes through
    _alter_retry, and a column another tier already dropped reads ORA-00904.
    """
    users_cols = _table_columns(cur, "USERS")
    if not users_cols:
        return
    legacy_id_col = "user_id" if "user_id" in users_cols else (
        "id" if "id" in users_cols else None)
    has_admin_col = "is_admin" in users_cols
    if not legacy_id_col and not has_admin_col:
        return
    id_map = {}
    if legacy_id_col:
        cur.execute(f'SELECT {legacy_id_col} FROM users WHERE "uid" IS NULL FOR UPDATE')
        null_rows = [r[0] for r in cur.fetchall()]
        for legacy in null_rows:
            uid = _generate_uid(conn)
            cur.execute(f'UPDATE users SET "uid"=:u WHERE {legacy_id_col}=:l AND "uid" IS NULL',
                        {"u": uid, "l": legacy})
        cur.execute(f'SELECT {legacy_id_col}, "uid" FROM users')
        for legacy, uid in cur.fetchall():
            if legacy is not None and uid:
                id_map[str(legacy)] = uid
        for table in _LEGACY_CHILD_TABLES:
            child_cols = _table_columns(cur, table)
            if not child_cols:
                continue
            if "uid" not in child_cols:
                _alter_retry(cur, f'ALTER TABLE {table} ADD "uid" VARCHAR2(10)',
                             f"{table}.uid")
            if "user_id" in child_cols and id_map:
                for legacy, uid in id_map.items():
                    cur.execute(
                        f'UPDATE {table} SET "uid"=:u WHERE "uid" IS NULL AND user_id=:l',
                        {"u": uid, "l": legacy})
    cur.execute(
        "SELECT c.constraint_name FROM user_constraints c "
        "JOIN user_cons_columns cc ON c.constraint_name = cc.constraint_name "
        "WHERE c.table_name='USERS' AND c.constraint_type='P' AND cc.column_name='ID'")
    pk_row = cur.fetchone()
    if pk_row:
        try:
            cur.execute(f"ALTER TABLE users DROP PRIMARY KEY")
        except Exception as ex:
            if "ORA-24430" not in str(ex):
                _debug_print(f"[database] could not drop legacy users PK: {ex}")
    for col in ("id", "user_id", "is_admin", "embed_slots"):
        if col in users_cols:
            _drop_column_quietly(cur, "USERS", col)
    for table in _LEGACY_CHILD_TABLES:
        child_cols = _table_columns(cur, table)
        if "user_id" in child_cols:
            _drop_column_quietly(cur, table, "user_id")
    cur.execute(
        "SELECT c.constraint_name FROM user_constraints c "
        "JOIN user_cons_columns cc ON c.constraint_name = cc.constraint_name "
        "WHERE c.table_name='USERS' AND c.constraint_type='P' AND cc.column_name='UID'")
    if not cur.fetchone():
        try:
            _alter_retry(cur, 'ALTER TABLE users ADD PRIMARY KEY ("uid")',
                         "users.uid PK")
        except Exception as ex:
            if "ORA-02260" not in str(ex):
                _debug_print(f"[database] could not add uid primary key: {ex}")

_load_config()
if not _ORACLE_ENABLED:
    raise RuntimeError(
        "No database backend available — set ORACLE_ENABLED=true in fastapi-oracle-app/.env"
    )


class OraclePoolExhausted(RuntimeError):
    pass


_ORACLE_POOL_TIMEOUT_CODE = "DPY-4005"
_POOL_BUSY_LOG_INTERVAL = 60
_pool_busy_lock = threading.Lock()
_pool_busy_count = 0
_pool_busy_reported = None


def _is_pool_exhausted(exc) -> bool:
    args = getattr(exc, "args", None) or ()
    if args:
        code = getattr(args[0], "full_code", None)
        if isinstance(code, str):
            return code == _ORACLE_POOL_TIMEOUT_CODE
    return str(exc).startswith(_ORACLE_POOL_TIMEOUT_CODE + ":")


def _note_pool_busy():
    global _pool_busy_count, _pool_busy_reported
    now = time.monotonic()
    with _pool_busy_lock:
        _pool_busy_count += 1
        last = _pool_busy_reported
        if last is not None and now - last < _POOL_BUSY_LOG_INTERVAL:
            return
        shed = _pool_busy_count
        window = None if last is None else int(now - last)
        _pool_busy_count = 0
        _pool_busy_reported = now
    since = f" in the last {window}s" if window else ""
    tier = f", tier={_tier_name()}" if _tier_name() else ""
    _debug_print(f"[database] Oracle pool busy — no session within "
          f"{_oracle_pool_timeout()}s, shedding with 503 "
          f"({shed} request(s){since}{tier})", file=sys.stderr)


def _oracle_unavailable(reason: str, exc=None):
    """Oracle is the only store, so losing it is fatal rather than a downgrade."""
    if exc is not None and _is_pool_exhausted(exc):
        _note_pool_busy()
        raise OraclePoolExhausted(f"Oracle unavailable: {reason}")
    bar = "!" * 72
    _debug_print(bar)
    _debug_print("[database] ORACLE UNAVAILABLE — the shared database cannot be reached")
    _debug_print(f"[database] reason: {reason}")
    _debug_print(bar)
    raise RuntimeError(f"Oracle unavailable: {reason}")


if _ORACLE_ENABLED:
    try:
        _ensure_oracle_cols()
        _debug_print("[database] Oracle tables verified")
    except Exception as e:
        # A transient connection/pool timeout at import time must not take the
        # whole tier down. `import database` is the first thing every tier does,
        # and a cold pool (min=0) or a momentarily full ATP (~20 sessions
        # fleet-wide) makes this first acquire time out with DPY-4005 even when
        # the database is healthy a second later. Every tier re-runs
        # _ensure_oracle_cols() through init_db() at startup — the engine even
        # retries it — and _SCHEMA_ENSURED stays False after a failed pass, so
        # that later call still does the work. So on a pool timeout, log and let
        # the import succeed rather than crashing the entire stack on a blip.
        # Any non-timeout failure (bad wallet, wrong credentials, missing DSN)
        # can never self-heal, so it stays fatal and is surfaced loudly as before.
        if _is_pool_exhausted(e):
            _debug_print("[database] Oracle busy at import (DPY-4005) — deferring schema "
                  "check to init_db()"
                  + (f", tier={_tier_name()}" if _tier_name() else ""),
                  file=sys.stderr)
        else:
            _debug_print(f"[database] Oracle check deferred to init_db(): {e}", file=sys.stderr)

# ── helpers ─────────────────────────────────────────────────────

def _oracle_dict_row(cur, row):
    """Convert an oracledb row to a dict."""
    if row is None:
        return None
    cols = [d[0].lower() for d in cur.description]
    return dict(zip(cols, row))

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@(gmail\.com|outlook\.com)$", re.IGNORECASE)
OTP_EXPIRE_MINUTES = 10
# Wrong guesses one code will absorb before it is retired. A 6-digit code is
# about 20 bits, so submission was the cheap way to search it: without a cap the
# only limit was the per-email request limiter, which allows far more requests
# than 900,000/attempts-per-request makes safe.
OTP_MAX_ATTEMPTS = 5
# Longest submission that could possibly be a code. generate_otp only ever issues
# six digits; the margin matches backend.py's OTP_CODE_MAX_LEN so neither tier
# rejects an input the other would have accepted.
OTP_CODE_MAX_LEN = 12
TRIAL_DAYS = 7
HOSTING_BACKUP_LIMIT = 5  # snapshots kept per server, oldest evicted


def _now():
    return datetime.now(timezone.utc).isoformat()


def _utcnow():
    return datetime.now(timezone.utc)


# ── the shared clock ────────────────────────────────────────────
#
# The engine tick lease is a comparison between two timestamps that may have
# been written by two different machines. If instance B's clock runs 40s behind
# instance A's, B computes a cutoff 40s in the past and can win a claim that A
# stamped only moments ago — both engines then publish the same bot seconds
# apart, which is exactly what the lease exists to prevent. So every timestamp
# that takes part in the lease comes from the *database's* clock, which both
# instances share by definition, not from the local one.
#
# On Oracle that means SYS_EXTRACT_UTC(SYSTIMESTAMP).
# The offset is measured once and refreshed every _CLOCK_TTL seconds — a round
# trip per claim would double the cost of the cheapest query in the tick.
_CLOCK_TTL = 60.0
_clock_lock = threading.Lock()
_clock_offset = 0.0      # db_utc - local_utc, in seconds
_clock_measured = 0.0    # time.monotonic() of the last measurement


def _refresh_clock_offset():
    """Measure db_utc - local_utc. Leaves the offset untouched on failure."""
    global _clock_offset, _clock_measured
    try:
        uconn = _user_conn()
        try:
            cur = uconn.cursor()
            cur.execute("SELECT SYS_EXTRACT_UTC(SYSTIMESTAMP) FROM dual")
            row = cur.fetchone()
        finally:
            uconn.close()
        db_dt = row["sys_extract_utc(systimestamp)"] if hasattr(row, "keys") else row[0]
        if db_dt.tzinfo is None:
            db_dt = db_dt.replace(tzinfo=timezone.utc)
        _clock_offset = (db_dt - datetime.now(timezone.utc)).total_seconds()
    except Exception as exc:
        # A failed measurement must not stop bots from publishing: fall back to
        # the last known offset (0.0 on the first attempt, i.e. the local clock).
        _debug_print(f"[database] could not read the database clock, keeping offset "
              f"{_clock_offset:+.3f}s: {exc}")
    _clock_measured = time.monotonic()


def _shared_utcnow():
    """UTC now on the clock every instance shares — the database's."""
    if time.monotonic() - _clock_measured >= _CLOCK_TTL:
        # Refresh outside the lock, and only for whoever wins it. Holding a lock
        # that every reader waits on *while acquiring a pooled session* deadlocked
        # the engine: callers reach here from inside functions that already hold a
        # session, so with max=2 two such threads each held one, one of them
        # queued behind the other's lock for a third that could never come free,
        # and both burned the full ORACLE_POOL_TIMEOUT — which _refresh_clock_offset
        # then swallowed, so it repeated every _CLOCK_TTL and kept both sessions
        # pinned. acquire(False) makes a missed refresh a no-op instead: readers
        # use the offset already measured, which is what this 60s cache and its
        # documented fallback to the last known value already mean.
        if _clock_lock.acquire(False):
            try:
                _refresh_clock_offset()
            finally:
                _clock_lock.release()
    return datetime.now(timezone.utc) + timedelta(seconds=_clock_offset)


def _shared_now():
    """_now(), but on the shared clock. Same string format, so the lease can go
    on comparing bots.last_run lexicographically."""
    return _shared_utcnow().isoformat()


def _user_conn():
    try:
        return _oracle_conn()
    except Exception as ex:
        _oracle_unavailable(str(ex), ex)


PBKDF2_ITERATIONS = 200_000

# Argon2id is the scheme new hashes are written with; PBKDF2-HMAC-SHA256 stays
# for the hashes already in the database and for any tier where argon2-cffi is
# not installed. The import is optional on purpose: every tier imports this
# module at boot, so making it mandatory would stop the whole fleet from starting
# rather than degrade one hash. Parameters are OWASP's Argon2id baseline —
# 19 MiB, 2 passes, 1 lane.
try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.low_level import Type as _Argon2Type

    _ARGON2 = _Argon2Hasher(time_cost=2, memory_cost=19456, parallelism=1,
                            hash_len=32, salt_len=16, type=_Argon2Type.ID)
except Exception:
    _ARGON2 = None


def hash_password(password: str, salt: str = None):
    """Hash a password for storage: Argon2id when available, else PBKDF2.

    The two forms are told apart on read by their shape — an Argon2 hash begins
    with "$argon2", which a "<hex salt>$<hex digest>" string never can — so both
    can sit in the same column and no flag day is needed.

    `salt` is meaningful only for the PBKDF2 form, where verify_password has to
    recompute a stored hash from the salt it already holds. Argon2 carries its
    salt and cost parameters inside the encoded value, so a caller asking for a
    specific salt is by definition verifying a legacy hash.
    """
    if salt is None and _ARGON2 is not None:
        return _ARGON2.hash(password.encode("utf-8", "surrogatepass"))
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8", "surrogatepass"),
                            salt.encode("utf-8", "surrogatepass"),
                            PBKDF2_ITERATIONS)
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not isinstance(stored, str) or not stored:
        return False
    if stored.startswith("$argon2"):
        if _ARGON2 is None:
            # Written by a tier that had argon2-cffi, read by one that does not.
            # The password cannot be checked here, and returning False silently
            # would be indistinguishable from a wrong password — so say why.
            _debug_print("[database] cannot verify an Argon2id hash: argon2-cffi is not "
                  "installed in this tier", file=sys.stderr)
            return False
        try:
            return _ARGON2.verify(stored, password.encode("utf-8", "surrogatepass"))
        except Exception:
            return False
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    # Compared as bytes: compare_digest raises TypeError on a str carrying any
    # non-ASCII codepoint, and `stored` is whatever the column holds — a row left
    # half-rekeyed, or ciphertext written where a hash belongs, turned a wrong
    # password into an uncaught 500 on the login route. The utf-8 form is the same
    # constant-time comparison and simply fails to match.
    return secrets.compare_digest(hash_password(password, salt).encode("utf-8", "surrogatepass"),
                                  stored.encode("utf-8", "surrogatepass"))


def needs_rehash(stored: str) -> bool:
    """Whether a verified hash should be rewritten with the current scheme.

    True for any PBKDF2 hash once argon2-cffi is available, and for an Argon2
    hash whose stored cost parameters are below the ones configured above. The
    caller performs the write, because only it knows the user id — and it can
    only be done at login, which is the one moment the plaintext is in hand.
    """
    if _ARGON2 is None or not isinstance(stored, str) or not stored:
        return False
    if not stored.startswith("$argon2"):
        return True
    try:
        return _ARGON2.check_needs_rehash(stored)
    except Exception:
        return False


# Built once at import time and deep-copied per caller: this dict is handed out
# on every bot row of every engine tick, and callers mutate what they get, so a
# shared reference would leak edits between bots.
_DEFAULT_EMBED = {
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


def default_embed():
    return copy.deepcopy(_DEFAULT_EMBED)


def default_ip_reply():
    """The default "ip" trigger reply: a simple message with the address.

    Never returns a shared mutable — the engine expands and the builder edits
    this dict, and both get it from different requests."""
    return {
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


def _bot_json_obj(raw, default_factory):
    """Parse a stored bot blob into a dict, or hand back a fresh default.

    The column holds client-authored JSON and rows predate the write-side guard,
    so it can be absent, empty, unparseable, or valid JSON that is not an object.
    `"x"`, `5`, `true` and `[1]` all cleared the old `json.loads(...) or
    default()` test truthy and reached the caller, where the first .get() on one
    of them is an AttributeError on a live authenticated request."""
    try:
        parsed = json.loads(raw or "{}")
    except Exception:
        parsed = None
    if not isinstance(parsed, dict) or not parsed:
        return default_factory()
    return parsed


def init_db():
    """Bring the Oracle schema up to date. Idempotent, so every tier can call it."""
    _ensure_oracle_cols()
    _migrate_at_rest_encryption()


def _migrate_at_rest_encryption():
    """Encrypt every PII column at rest so a DB read finds no plaintext.

    One table at a time, keyed off "has this row been encrypted yet": each pass
    is idempotent and safe to run on every startup. Searchable public values
    (usernames, emails, IPs) move to a keyed HMAC index column so lookups still
    work; free-text (banned_reason, user_agent, OTP codes) needs no index.
    """
    if not _ORACLE_ENABLED:
        return
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        # users: username/display_name now encrypted, plus the search index.
        cur.execute(
            "SELECT \"uid\", username, username_lookup_hash, username_ci_lookup_hash, display_name, email, email_lookup_hash, banned_reason "
            "FROM users WHERE username_lookup_hash IS NULL OR username_ci_lookup_hash IS NULL OR email_lookup_hash IS NULL")
        for r in cur.fetchall():
            if hasattr(r, "keys"):
                uid, name, name_h, name_ci_h, dname, email, email_h, reason = (
                    r["uid"], r["username"], r["username_lookup_hash"], r["username_ci_lookup_hash"], r["display_name"],
                    r["email"], r["email_lookup_hash"], r["banned_reason"])
            else:
                uid, name, name_h, name_ci_h, dname, email, email_h, reason = r[0:8]
            sets = {}
            if not name:
                continue
            plain = decrypt(name) if looks_encrypted(name) else name
            if not plain:
                continue
            if not looks_encrypted(name):
                sets["username"] = encrypt(plain)
            # The whole point of selecting the row, and it was the one index this
            # loop never wrote. Encrypting the username above also retires the
            # plaintext fallback in get_user_by_username(), so a row left without
            # this hash has no matchable form of its name at all — the account
            # can still log in by email and never by username.
            if not name_h:
                sets["username_lookup_hash"] = lookup_hash(plain)
            # The case-blind index only ever got written for new accounts in
            # create_user; every pre-existing row left it NULL, so the
            # case-insensitive login fallback had nothing to match and those
            # accounts stayed reachable by email but not by a differently-cased
            # name. Backfill it the same way create_user does.
            if not name_ci_h:
                sets["username_ci_lookup_hash"] = lookup_hash(plain.casefold())
            if dname and not looks_encrypted(dname):
                sets["display_name"] = encrypt(dname)
            if not email_h and email:
                # Normalised on both branches, not just the plaintext one. An
                # already-encrypted address kept whatever case it was stored with,
                # so this indexed lookup_hash("Bob@gmail.com") while
                # get_user_by_email only ever asks for lookup_hash of the
                # stripped, lowercased form — the row came out of the migration
                # unreachable by email login, and its plaintext fallback cannot
                # match ciphertext either.
                plain_e = (decrypt(email) if looks_encrypted(email) else email).lower().strip()
                # The same guard the username gets above, for the same reason. A
                # failed decrypt() returns "", and writing that back replaced a
                # real address with encrypt("") and stamped every affected row
                # with the identical lookup_hash("") — colliding them on the email
                # index. init_db() runs this on every startup, so a single tier
                # holding the wrong key erased the login identifier for every
                # account it touched. Leaving the row untouched keeps it fixable
                # once the key is right.
                if plain_e:
                    sets["email"] = encrypt(plain_e)
                    sets["email_lookup_hash"] = lookup_hash(plain_e)
            elif not email_h and email is None:
                sets["email_lookup_hash"] = None
            if reason and not looks_encrypted(reason):
                sets["banned_reason"] = encrypt(reason)
            if sets:
                sets["u_id"] = uid
                _USER_SET_COLUMNS = frozenset({
                    "username", "username_lookup_hash", "display_name",
                    "email", "email_lookup_hash", "banned_reason",
                })
                for k in sets:
                    if k != "u_id":
                        _validate_identifier(k, allow=_USER_SET_COLUMNS)
                assignments = ", ".join(f"{k}=:{k}" for k in sets.keys() if k != "u_id")
                try:
                    cur.execute(f"UPDATE users SET {assignments} WHERE \"uid\"=:u_id", sets)
                except Exception as ex:
                    _debug_print(f"[database] could not migrate user {uid} to encrypted "
                          f"columns, leaving the row as it is: {ex}", file=sys.stderr)
        # fingerprints: IPs are now encrypted with an index column for
        # accounts_on_ip().
        cur.execute("SELECT id, ip_address, ip_lookup_hash FROM fingerprints "
                    "WHERE ip_address IS NOT NULL")
        for r in cur.fetchall():
            if hasattr(r, "keys"):
                fid, ip, ip_h = r["id"], r["ip_address"], r["ip_lookup_hash"]
            else:
                fid, ip, ip_h = r[0], r[1], r[2]
            if looks_encrypted(ip):
                # Encrypted, but the index may still be missing — rows written
                # before ip_lookup_hash existed, or a rekey that rewrote the
                # ciphertext without rebuilding it. Returning early on every
                # encrypted row is why accounts_on_ip()'s own warning about an
                # unusable index had no path that could ever clear it: those rows
                # matched the SELECT on each startup and were skipped each time,
                # so alt-account detection by IP kept silently finding nothing.
                if ip_h:
                    continue
                plain = decrypt(ip)
                if not plain:
                    # No key here reads it. Writing lookup_hash("") would index
                    # every such row identically and make the column actively
                    # wrong rather than merely absent.
                    continue
                cur.execute("UPDATE fingerprints SET ip_lookup_hash=:h WHERE id=:id",
                            {"h": lookup_hash(plain), "id": fid})
                continue
            cur.execute("UPDATE fingerprints SET ip_address=:enc, ip_lookup_hash=:h WHERE id=:id",
                        {"enc": encrypt(ip), "h": lookup_hash(ip), "id": fid})
        # device_events: IP column encrypted, no lookup (display only).
        cur.execute("SELECT id, ip_address FROM device_events WHERE ip_address IS NOT NULL")
        for r in cur.fetchall():
            eid = r["id"] if hasattr(r, "keys") else r[0]
            ip = r["ip_address"] if hasattr(r, "keys") else r[1]
            if not looks_encrypted(ip):
                cur.execute("UPDATE device_events SET ip_address=:enc WHERE id=:id",
                            {"enc": encrypt(ip), "id": eid})
        # sessions: IP and user-agent are PII; both encrypted.
        cur.execute("SELECT id, ip_address, user_agent FROM sessions "
                    "WHERE ip_address IS NOT NULL OR user_agent IS NOT NULL")
        for r in cur.fetchall():
            sid = r["id"] if hasattr(r, "keys") else r[0]
            ip = r["ip_address"] if hasattr(r, "keys") else r[1]
            ua = r["user_agent"] if hasattr(r, "keys") else r[2]
            if (looks_encrypted(ip) if ip else True) and (looks_encrypted(ua) if ua else True):
                continue
            cur.execute("UPDATE sessions SET ip_address=:ip, user_agent=:ua WHERE id=:id",
                        {"ip": encrypt(ip) if (ip and not looks_encrypted(ip)) else ip,
                         "ua": encrypt(ua) if (ua and not looks_encrypted(ua)) else ua,
                         "id": sid})
        # otp_codes: the email and the code itself (a credential) encrypted.
        cur.execute("SELECT id, email, code FROM otp_codes WHERE email_lookup_hash IS NULL")
        for r in cur.fetchall():
            oid = r["id"] if hasattr(r, "keys") else r[0]
            email = r["email"] if hasattr(r, "keys") else r[1]
            code = r["code"] if hasattr(r, "keys") else r[2]
            plain_e = decrypt(email) if looks_encrypted(email) else email
            if not plain_e:
                # decrypt() returned "" (wrong key, or no key that reads this
                # row). Rewriting it would store encrypt("") and index every
                # unreadable row under the same lookup_hash(""), so no code could
                # ever be matched back to its address. Skip; a later run holding
                # the right key will do it.
                continue
            cur.execute(
                "UPDATE otp_codes SET email=:e, email_lookup_hash=:h, code=:c WHERE id=:id",
                {"e": encrypt(plain_e), "h": lookup_hash(plain_e),
                 "c": encrypt(code) if not looks_encrypted(code) else code, "id": oid})
        uconn.commit()
    finally:
        uconn.close()


def create_user(username, password, display_name=None, slots=1, email=None, account_type="trial", email_verified=False, container_slots=1):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        # usernames are Fernet-encrypted at rest; the keyed lookup hash is the
        # only matchable form. The plaintext fallback catches legacy rows that
        # predate the startup migration.
        username = (username or "").strip()
        h = lookup_hash(username)
        ci_h = lookup_hash(username.casefold())
        cur.execute("SELECT \"uid\" FROM users WHERE username_lookup_hash=:h", {"h": h})
        if cur.fetchone():
            return False, "Username already exists"
        # Names that differ only in case are now taken too. Login resolves them
        # case-blind, so allowing both would create the one pair that lookup
        # cannot tell apart.
        cur.execute("SELECT \"uid\" FROM users WHERE username_ci_lookup_hash=:h", {"h": ci_h})
        if cur.fetchone():
            return False, "Username already exists"
        cur.execute("SELECT \"uid\" FROM users WHERE username=:username", {"username": username})
        if cur.fetchone():
            return False, "Username already exists"
        uid = _generate_uid(uconn)
        trial_expires = None
        if account_type == "trial":
            trial_expires = (_utcnow() + timedelta(days=TRIAL_DAYS)).isoformat()
        if not email:
            email = f"user_{uuid.uuid4().hex[:12]}@placeholder.local"
        email = email.strip().lower()
        flask_hash = hash_password(password)
        verified_val = '1' if email_verified else '0'
        cur.execute(
            "INSERT INTO users(\"uid\",username,username_lookup_hash,username_ci_lookup_hash,email,email_lookup_hash,is_active,created_at,password,display_name,slots,container_slots,account_type,trial_expires_at,email_verified) "
            "VALUES(:u_id,:username,:uh,:uch,:email,:eh,:active,:cat,:pwd,:dname,:sl,:csl,:actype,:texp,:ever)",
            {"u_id": uid, "username": encrypt(username), "uh": h, "uch": ci_h,
             "email": encrypt(email), "eh": lookup_hash(email),
             "active": 1, "cat": _now(), "pwd": flask_hash,
             "dname": encrypt(display_name or username), "sl": str(slots), "csl": str(container_slots), "actype": account_type, "texp": trial_expires, "ever": verified_val}
        )
        _oracle_ensure_bot_slots(cur, uid, slots)
        uconn.commit()
    except Exception as e:
        # The detail belongs in the log, not in the returned string: backend.py's
        # register route hands this value straight to the visitor, so an ORA text
        # here disclosed the schema name, column widths and table layout to
        # anyone who could make a signup fail.
        _debug_print(f"[database] create_user failed: {e}", file=sys.stderr)
        return False, "Could not create the account. Please try again later."
    finally:
        uconn.close()
    return True, uid


def _oracle_ensure_bot_slots(cur, uid, slots):
    slots = int(slots)
    cur.execute("SELECT COUNT(*) as cnt FROM bots WHERE \"uid\"=:uid_param", {"uid_param": uid})
    r = cur.fetchone()
    existing = r["cnt"] if hasattr(r, "keys") else r[0]
    for i in range(existing, slots):
        # Seeded encrypted like every other write to these columns, so a fresh
        # slot is not the one row in the table that leaks its payload.
        cur.execute(
            "INSERT INTO bots(\"uid\", name, slot_index, created_at, embed_json) "
            "VALUES(:uid_param,:name,:idx,:cat,:embed)",
            {"uid_param": uid, "name": encrypt(f"Bot #{i+1}"), "idx": i,
             "cat": _now(), "embed": encrypt(json.dumps(default_embed()))},
        )


def ensure_bot_slots(uid, slots):
    """Insert bot rows for any declared slots that lack one. Never deletes —
    safe to call from read paths that just want the list to match the count."""
    try:
        slots = int(slots)
    except (ValueError, TypeError):
        return
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        _oracle_ensure_bot_slots(cur, uid, slots)
        uconn.commit()
    except Exception as e:
        _debug_print(f"[database] ensure_bot_slots failed for {uid}: {e}")
    finally:
        uconn.close()


def get_smtp_config(prefix="smtp"):
    """All <prefix>_* settings, decrypted. prefix="smtp" is the login/OTP SMTP
    (smtp_* keys), prefix="warn_smtp" is the warnings SMTP (warn_smtp_* keys).
    Callers get plaintext and must not decrypt again — the credentials used to
    be encrypted per-field, and a second decrypt of an already-plaintext value
    returns "" and reads as "SMTP not configured"."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key LIKE :pat",
                    {"pat": prefix + "_%"})
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(zip(cols, r)) if not hasattr(r, "keys") else dict(r) for r in cur.fetchall()]
    except Exception as e:
        _debug_print(f"[smtp] get_smtp_config({prefix}) query failed: {e}")
        rows = []
    finally:
        uconn.close()
    cfg = {r["key"]: _dec_or_raw(r["value"]) for r in rows}
    has_host = bool(cfg.get(prefix + "_host"))
    has_user = bool(cfg.get(prefix + "_user"))
    has_pw = bool(cfg.get(prefix + "_pass"))
    _debug_print(f"[smtp] read {prefix}: host={'yes' if has_host else 'no'} "
          f"user={'yes' if has_user else 'no'} pw={'yes' if has_pw else 'no'} rows={len(rows)}")
    return cfg


def _smtp_ready(cfg, prefix):
    """True when the profile has everything _send_raw needs to deliver."""
    return bool(cfg.get(prefix + "_host") and (cfg.get(prefix + "_user") or "")
                and (cfg.get(prefix + "_pass") or "") and cfg.get(prefix + "_from"))


def _get_setting_on(conn, key, default=None):
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key=:k", {"k": key})
    r = cur.fetchone()
    if r:
        raw = r["value"] if hasattr(r, "keys") else r[0]
        return _dec_or_raw(raw)
    return default


def get_setting(key, default=None):
    """Read one settings row, decrypted.

    The only way settings.value is read in this module. The key column stays
    plaintext on purpose — get_smtp_config matches it with LIKE 'smtp_%' and
    Fernet is non-deterministic, so an encrypted key could not be searched for
    at all.
    """
    uconn = _user_conn()
    try:
        return _get_setting_on(uconn, key, default)
    finally:
        uconn.close()


def set_setting(key, value):
    """Write one settings row, encrypted. The only writer of settings.value."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM settings WHERE key=:k", {"k": key})
        cur.execute("INSERT INTO settings(key,value) VALUES(:k,:v)",
                    {"k": key, "v": None if value is None else encrypt(str(value))})
        uconn.commit()
    finally:
        uconn.close()


def save_smtp_config(host, port, user, password, from_addr, prefix="smtp"):
    # Every field goes through set_setting, which encrypts. The host, port and
    # from-address used to be stored plaintext and the credentials encrypted
    # per-field; that split is gone, so nothing here can double-encrypt.
    for k, v in ((prefix + "_host", host), (prefix + "_port", str(port)),
                 (prefix + "_from", from_addr)):
        set_setting(k, v)
    # An empty user or password means "keep what is stored" — the admin form
    # never echoes the current credentials back, so a blank field is not a
    # request to erase them.
    if user:
        set_setting(prefix + "_user", user)
    if password:
        set_setting(prefix + "_pass", password)
    _debug_print(f"[smtp] saved {prefix}: host={host} port={port} "
          f"user={'set' if user else 'kept'} pw={'set' if password else 'kept'} "
          f"from={from_addr}")


def send_email(to_addr, subject, body):
    subject, plain_text, html_body = email_templates.build_generic_email(
        to_addr, subject, subject, body
    )
    _send_raw(to_addr, subject, plain_text, html_body,
              prefix="warn_smtp" if _smtp_ready(get_smtp_config("warn_smtp"), "warn_smtp") else "smtp")


def send_otp_email(to_addr, code, purpose="verification"):
    subject, plain_text, html_body = email_templates.build_otp_email(
        to_addr, code, purpose=purpose, expire_minutes=OTP_EXPIRE_MINUTES
    )
    _send_raw(to_addr, subject, plain_text, html_body)


def send_welcome_email(to_addr, username):
    username = re.sub(r"[\r\n]+", " ", str(username or "there"))[:64].strip() or "there"
    subject, plain_text, html_body = email_templates.build_welcome_email(to_addr, username)
    _send_raw(to_addr, subject, plain_text, html_body)


def _send_raw(to_addr, subject, plain_body, html_body, prefix="smtp"):
    """Low-level send. prefix="smtp" is the login/OTP SMTP (send_otp_email,
    send_welcome_email); prefix="warn_smtp" is the warnings SMTP (send_email)."""
    cfg = get_smtp_config(prefix)
    host = cfg.get(prefix + "_host")
    # A stored row that will not decrypt comes back as None, and a port saved as
    # an empty string comes back as "" — int() raised TypeError/ValueError on both
    # before the configuration check below could report the real problem.
    try:
        port = int(cfg.get(prefix + "_port") or 587)
    except (TypeError, ValueError):
        raise ValueError(f"SMTP ({prefix}) port is not a number. Admin must set SMTP settings first.")
    # get_smtp_config already decrypted these; decrypting again returned "" and
    # made every send fail with "SMTP not configured".
    user = cfg.get(prefix + "_user") or ""
    password = cfg.get(prefix + "_pass") or ""
    from_addr = cfg.get(prefix + "_from")
    if not host or not user or not password or not from_addr:
        raise ValueError(f"SMTP ({prefix}) not configured. Admin must set SMTP settings first.")
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg.attach(email.mime.text.MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))
    msg["Subject"] = subject
    msg["From"] = f"{BRAND_NAME} <{from_addr}>"
    msg["To"] = to_addr
    msg["Message-ID"] = email.utils.make_msgid(domain=from_addr.split("@")[-1] if "@" in from_addr else "localhost")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["MIME-Version"] = "1.0"
    msg["Precedence"] = "bulk"
    msg["X-Auto-Response-Suppress"] = "OOF, AutoReply"
    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.starttls(context=ctx)
        s.login(user, password)
        s.send_message(msg)


def _session_blob(data):
    """The sessions.data payload, encrypted.

    It carries the device fingerprint, and no query filters on it —
    sessions are looked up by id and uid, which stay plaintext.
    """
    return encrypt(json.dumps(data))


# Server-side session lifetime, sliding: a session expires this long after its
# last activity (any request slides the clock again via get_session/save_session).
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))

# Maximum concurrent sessions per user account. When a new session is created
# and the user already has this many, the oldest sessions are deleted first.
# Set to 0 for unlimited.
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", "1"))


def create_session(sid, data, ip_address=None, user_agent=None, max_age=SESSION_TTL_SECONDS):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        now = _now()
        expires = (_utcnow() + timedelta(seconds=max_age)).isoformat()
        ip_enc = encrypt(ip_address) if ip_address else None
        ua_enc = encrypt(user_agent) if user_agent else None
        cur.execute("SELECT id FROM sessions WHERE id=:sid", {"sid": sid})
        if cur.fetchone():
            cur.execute(
                "UPDATE sessions SET data=:data, \"uid\"=:u_id, ip_address=:ip, user_agent=:ua, last_access=:now, expires_at=:exp WHERE id=:sid",
                {"data": _session_blob(data), "u_id": data.get("user_id"), "ip": ip_enc, "ua": ua_enc, "now": now, "exp": expires, "sid": sid},
            )
        else:
            cur.execute(
                "INSERT INTO sessions(id, \"uid\", data, ip_address, user_agent, created_at, last_access, expires_at) "
                "VALUES(:sid,:u_id,:data,:ip,:ua,:now,:now,:exp)",
                {"sid": sid, "u_id": data.get("user_id"), "data": _session_blob(data), "ip": ip_enc, "ua": ua_enc, "now": now, "exp": expires},
            )
        # Enforce per-user session cap: keep only the N most recent sessions.
        user_id = data.get("user_id")
        if user_id and MAX_SESSIONS_PER_USER > 0:
            cur.execute(
                "DELETE FROM sessions WHERE \"uid\"=:u_id AND id NOT IN "
                "(SELECT id FROM sessions WHERE \"uid\"=:u_id2 ORDER BY last_access DESC FETCH FIRST :lim ROWS ONLY)",
                {"u_id": user_id, "u_id2": user_id, "lim": MAX_SESSIONS_PER_USER},
            )
        uconn.commit()
    finally:
        uconn.close()


def save_session(sid, data):
    """Persist modified session data and slide the expiry clock forward.

    ``sessions.uid`` is an indexable copy of the encrypted payload field.
    A browser session commonly starts anonymous and gains a ``user_id`` at login,
    so every save must keep the two representations synchronized.
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE sessions SET data=:data, \"uid\"=:u_id, last_access=:now, expires_at=:exp WHERE id=:sid",
                     {"data": _session_blob(data), "u_id": data.get("user_id"), "now": _now(),
                      "exp": (_utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(), "sid": sid})
        uconn.commit()
    finally:
        uconn.close()


def _is_impersonation_ticket(data):
    """True only for the short-lived record minted by the admin console.

    An adopted impersonation session also carries ``_impersonator``, but it has
    browser binding/session state. Refusing those keys here prevents an ordinary
    live session from being consumed as a ticket.
    """
    if not isinstance(data, dict):
        return False
    if not str(data.get("user_id") or "").strip():
        return False
    if not str(data.get("_impersonator") or "").strip():
        return False
    return not any(key in data for key in ("_ip", "_fp", "_csrf_token"))


def consume_impersonation_ticket(sid):
    """Atomically validate and consume one admin impersonation ticket."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT data, expires_at FROM sessions WHERE id=:sid FOR UPDATE",
            {"sid": sid},
        )
        row = cur.fetchone()
        if not row:
            return None
        data_str = row["data"] if hasattr(row, "keys") else row[0]
        expires_str = row["expires_at"] if hasattr(row, "keys") else row[1]
        try:
            data = json.loads(_dec_or_raw(data_str))
        except (json.JSONDecodeError, TypeError):
            return None
        if not _is_impersonation_ticket(data):
            return None

        cur.execute("DELETE FROM sessions WHERE id=:sid", {"sid": sid})
        uconn.commit()
        expires = _parse_iso(expires_str)
        # Same reasoning as get_session: an expiry no one can read is not proof
        # the ticket is live, and one of these adopts an admin-minted session.
        if not expires or expires < _utcnow():
            return None
        return data
    finally:
        uconn.close()


def get_session(sid):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT data, expires_at FROM sessions WHERE id=:sid", {"sid": sid})
        row = cur.fetchone()
    finally:
        uconn.close()
    if not row:
        return None
    data_str = row["data"] if hasattr(row, "keys") else row[0]
    expires_str = row["expires_at"] if hasattr(row, "keys") else row[1]
    expires = _parse_iso(expires_str)
    # An expiry that will not parse used to fall straight through this check,
    # which turned the row into a session that never expires. Every writer here
    # stores an isoformat() timestamp, so an unreadable one is a corrupt row
    # rather than an unlimited one — treat it as already dead.
    if not expires or expires < _utcnow():
        delete_session(sid)
        return None
    try:
        data = json.loads(_dec_or_raw(data_str))
        if _is_impersonation_ticket(data):
            return None
        # Any activity slides the 1-hour window: a read is activity too, so the
        # session dies only after that long of real silence. A failing refresh
        # must never take down a request — the expiry check above already ran.
        try:
            uconn = _user_conn()
            try:
                cur = uconn.cursor()
                cur.execute("UPDATE sessions SET last_access=:now, expires_at=:exp WHERE id=:sid",
                            {"now": _now(),
                             "exp": (_utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(), "sid": sid})
                uconn.commit()
            finally:
                uconn.close()
        except Exception:
            pass
        return data
    except (json.JSONDecodeError, TypeError):
        return None


def delete_session(sid):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM sessions WHERE id=:sid", {"sid": sid})
        uconn.commit()
    finally:
        uconn.close()


def delete_user_sessions(uid, exclude_sid=None):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        if exclude_sid:
            cur.execute("DELETE FROM sessions WHERE \"uid\"=:u_id AND id!=:sid", {"u_id": uid, "sid": exclude_sid})
        else:
            cur.execute("DELETE FROM sessions WHERE \"uid\"=:u_id", {"u_id": uid})
        uconn.commit()
    finally:
        uconn.close()


def get_user_sessions(uid):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT id, ip_address, user_agent, created_at, last_access, expires_at FROM sessions WHERE \"uid\"=:u_id ORDER BY created_at DESC",
            {"u_id": uid},
        )
        rows = cur.fetchall()
        out = []
        for r in rows:
            if hasattr(r, "keys"):
                d = dict(r)
            else:
                d = {"id": r[0], "ip_address": r[1], "user_agent": r[2],
                     "created_at": r[3], "last_access": r[4], "expires_at": r[5]}
            for col in ("ip_address", "user_agent"):
                val = d.get(col)
                if val and looks_encrypted(val):
                    d[col] = decrypt(val) or None
            out.append(d)
        return out
    finally:
        uconn.close()


def generate_otp(email, purpose="register"):
    cleanup_expired_otps()
    code = str(secrets.randbelow(900000) + 100000)
    code_hash = _otp_ph.hash(code)
    expires = (_utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "DELETE FROM otp_codes "
            "WHERE email_lookup_hash=:h AND purpose=:purpose",
            {"h": lookup_hash(email), "purpose": purpose})
        cur.execute(
            "INSERT INTO otp_codes(email, email_lookup_hash, code, purpose, expires_at, created_at, attempts) "
            "VALUES(:email,:eh,:code,:purpose,:expires,:now,0)",
            {"email": encrypt(email), "eh": lookup_hash(email), "code": code_hash,
             "purpose": purpose, "expires": expires, "now": _now()},
        )
        uconn.commit()
    finally:
        uconn.close()
    return code


def verify_otp(email, code, purpose="register", mark_used=True):
    if not code or len(str(code)) > OTP_CODE_MAX_LEN:
        return False
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT id, expires_at, code, attempts FROM otp_codes "
            "WHERE email_lookup_hash=:h AND purpose=:purpose AND used=0",
            {"h": lookup_hash(email), "purpose": purpose},
        )
        rows = cur.fetchall()
        if not rows:
            cur.execute(
                "SELECT id, expires_at, code, attempts FROM otp_codes "
                "WHERE email=:email AND purpose=:purpose AND used=0",
                {"email": email, "purpose": purpose},
            )
            rows = cur.fetchall()
        for row in rows:
            if hasattr(row, "keys"):
                oid, expires, stored, tries = (row["id"], row["expires_at"],
                                               row["code"], row["attempts"])
            else:
                oid, expires, stored, tries = row[0], row[1], row[2], row[3]
            if int(tries or 0) >= OTP_MAX_ATTEMPTS:
                cur.execute("DELETE FROM otp_codes WHERE id=:id", {"id": oid})
                uconn.commit()
                continue

            otp_matches = False
            if stored and str(stored).startswith("$argon2"):
                try:
                    _otp_ph.verify(str(stored), str(code or ""))
                    otp_matches = True
                except (VerifyMismatchError, VerificationError):
                    otp_matches = False
                except Exception:
                    otp_matches = False
            else:
                stored_plain = decrypt(stored) if looks_encrypted(stored) else stored
                stored_bytes = str(stored_plain or "").encode("utf-8", "surrogatepass")
                sent_bytes = str(code or "").encode("utf-8", "surrogatepass")
                if stored_bytes and sent_bytes:
                    otp_matches = secrets.compare_digest(stored_bytes, sent_bytes)

            if not otp_matches:
                cur.execute(
                    "UPDATE otp_codes SET attempts = NVL(attempts, 0) + 1 "
                    "WHERE id=:id AND used=0",
                    {"id": oid})
                uconn.commit()
                cur.execute(
                    "DELETE FROM otp_codes WHERE id=:id AND NVL(attempts, 0) >= :cap",
                    {"id": oid, "cap": OTP_MAX_ATTEMPTS})
                uconn.commit()
                continue
            try:
                if datetime.fromisoformat(expires) < _utcnow():
                    cur.execute("DELETE FROM otp_codes WHERE id=:id", {"id": oid})
                    uconn.commit()
                    return False
            except Exception:
                cur.execute("DELETE FROM otp_codes WHERE id=:id", {"id": oid})
                uconn.commit()
                return False
            if mark_used:
                cur.execute("DELETE FROM otp_codes WHERE id=:id AND used=0", {"id": oid})
                uconn.commit()
                if cur.rowcount != 1:
                    return False
            return True
        return False
    finally:
        uconn.close()


def cleanup_expired_otps():
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM otp_codes WHERE expires_at < :now", {"now": _now()})
        uconn.commit()
    finally:
        uconn.close()


def _delete_user_panel_servers_and_containers(user_id):
    """Delete all panel servers for a user from Oracle and their containers on the node agent."""
    node_url = os.getenv("NODE_URL", "http://127.0.0.1:8081").rstrip("/")
    node_token = os.getenv("NODE_TOKEN", "")

    if not node_token:
        return

    oconn = _oracle_conn()
    try:
        cur = oconn.cursor()
        cur.execute("SELECT id FROM panel_servers WHERE user_id = :u_id", {"u_id": user_id})
        server_ids = [row[0] for row in cur.fetchall()]

        unconfirmed = []
        for server_id in server_ids:
            confirmed = False
            try:
                url = f"{node_url}/api/v1/servers/{server_id}?purge=true"
                req = urllib.request.Request(url, method="DELETE")
                req.add_header("Authorization", f"Bearer {node_token}")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    confirmed = True
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    confirmed = True
            except Exception:
                pass
            if not confirmed:
                unconfirmed.append(server_id)

        if server_ids:
            placeholders = ",".join(":" + str(i) for i in range(1, len(server_ids) + 1))
            params = {str(i): sid for i, sid in enumerate(server_ids, 1)}
            cur.execute(f"DELETE FROM panel_servers WHERE id IN ({placeholders})", params)
            oconn.commit()
            # Rows are gone but some node deletes weren't confirmed. Record them
            # so the panel reconcile sweep drains the containers when the node
            # returns. node_id is unknown here (this layer has no node column);
            # the drain clears by server id, so the empty label is harmless.
            if unconfirmed:
                try:
                    import reviews_db
                    for sid in unconfirmed:
                        reviews_db.enqueue_container_deletion(sid, node_id="", purge=True)
                except Exception:
                    pass
    finally:
        oconn.close()


def _delete_user_sqlite_panel_servers_and_containers(user_id):
    """Delete all panel servers for a user from SQLite and their containers on the node agent."""
    panel_db_path = os.getenv("PANEL_DATABASE_PATH", "data/panel.db")
    node_url = os.getenv("NODE_URL", "http://127.0.0.1:8081").rstrip("/")
    node_token = os.getenv("NODE_TOKEN", "")

    if not os.path.exists(panel_db_path):
        return

    if not node_token:
        return

    try:
        conn = sqlite3.connect(panel_db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("SELECT id FROM servers WHERE uid = ?", (user_id,))
            servers = [row["id"] for row in cursor.fetchall()]

            for server_id in servers:
                try:
                    url = f"{node_url}/api/v1/servers/{server_id}?purge=true"
                    req = urllib.request.Request(url, method="DELETE")
                    req.add_header("Authorization", f"Bearer {node_token}")
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        pass
                except urllib.error.HTTPError as e:
                    if e.code != 404:
                        pass
                except Exception:
                    pass

            if servers:
                placeholders = ",".join("?" * len(servers))
                conn.execute(f"DELETE FROM servers WHERE id IN ({placeholders})", servers)
                conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def delete_user_panel_servers_and_containers(user_id):
    """Delete all panel servers for a user (both Oracle and SQLite) and their containers on the node agent."""
    _delete_user_panel_servers_and_containers(user_id)
    _delete_user_sqlite_panel_servers_and_containers(user_id)


def delete_user(uid):
    delete_user_panel_servers_and_containers(uid)

    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM sessions WHERE \"uid\"=:id", {"id": uid})
        cur.execute("DELETE FROM bots WHERE \"uid\"=:id", {"id": uid})
        cur.execute("DELETE FROM device_events WHERE \"uid\"=:id", {"id": uid})
        cur.execute("DELETE FROM user_ad_zone_overrides WHERE \"uid\"=:id", {"id": uid})
        # Preserve the account row itself and its fingerprint-related records.
        # The app-side deletion path is now a data purge, not an account erase:
        # username, email, password hash, and fingerprint bindings stay in place.
        uconn.commit()
    finally:
        uconn.close()


def list_users():
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("""
            SELECT u."uid", u.username, u.display_name, u.slots, u.email, u.account_type,
                   u.trial_expires_at, u.email_verified, u.created_at, u.last_login,
                   u.is_banned
            FROM users u
            ORDER BY u.created_at DESC
        """)
        rows = [dict(r) if hasattr(r, 'keys') else {
            cur.description[i][0].lower(): r[i] for i in range(len(r))
        } for r in cur.fetchall()]
        cur.execute("SELECT \"uid\", COUNT(*) as cnt, SUM(CASE WHEN running=1 THEN 1 ELSE 0 END) as running_cnt FROM bots GROUP BY \"uid\"")
        bot_map = {r[0]: (r[1], r[2] or 0) for r in cur.fetchall()}
        cur.execute("SELECT \"uid\" FROM fingerprints")
        fp_set = {r[0] for r in cur.fetchall()}
        uconn.close()
        # Cleared so the finally below cannot close it a second time. The early
        # close is deliberate — device_event_counts_by_user() acquires its own
        # connection and the pool is small — so the slot has to be back before
        # this function calls it, but an exception raised before this point (or
        # a BaseException, which the except clause does not catch) still has to
        # release it. Under POOL_GETMODE_TIMEDWAIT a leaked slot no longer hangs
        # callers forever, but it still fails every acquire with a timeout once
        # the small pool is exhausted, so it must always be returned.
        uconn = None
    except Exception:
        return []
    finally:
        if uconn is not None:
            uconn.close()
    flag_map = device_event_counts_by_user()
    out = []
    for u in rows:
        _user_row_plaintext(u)
        bot_count, bots_running = bot_map.get(u["uid"], (0, 0))
        u["bot_count"] = bot_count
        u["bots_running"] = bots_running
        u["has_fingerprint"] = 1 if u["uid"] in fp_set else 0
        u["flag_count"] = flag_map.get(str(u["uid"]), 0)
        out.append(u)
    return out


def get_user(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT * FROM users WHERE \"uid\"=:id", {"id": user_id})
        r = cur.fetchone()
        if not r:
            return None
        if hasattr(r, "keys"):
            u = dict(r)
        else:
            cols = [d[0].lower() for d in cur.description]
            u = dict(zip(cols, r))
        return _user_row_plaintext(u)
    finally:
        uconn.close()


def _row_plaintext(val):
    """Decrypt one at-rest column pulled by a raw SELECT that bypasses the row
    helpers below. Values written before encryption landed pass through
    unchanged, and a value no key here can read comes back as None so callers
    can tell "unreadable" apart from "empty" instead of acting on ""."""
    if not val:
        return None
    if not looks_encrypted(val):
        return val
    return decrypt(val) or None


def is_renew_open(u):
    if not u or u.get("account_type") != "trial":
        return False
    if u.get("bot_stopped_at"):
        return True
    try:
        expires_at = _parse_iso(u.get("trial_expires_at"))
        if expires_at is None:
            return True
        now = _shared_utcnow()
        window_days = int(renew_config.RENEW_WINDOW_DAYS)
        return now >= (expires_at - timedelta(days=window_days))
    except Exception:
        return True


def _user_row_plaintext(u):
    """Decrypt the at-rest username / display_name / email / banned_reason / tokens /
    fingerprint_ip of a users row in place. Rows written before
    encryption landed pass through unchanged. Callers only ever see the plaintext —
    the ciphertext never leaves this module.
    """
    if not u:
        return u
    for col in ("username", "display_name", "email", "banned_reason",
                "discord_bot_token", "webhook_token", "fingerprint_ip"):
        val = u.get(col)
        if val and looks_encrypted(val):
            u[col] = decrypt(val) or None
    if u.get("embed_slots") is not None:
        try:
            u["embed_slots"] = int(u["embed_slots"])
        except Exception:
            u["embed_slots"] = 1
    elif u.get("slots") is not None:
        try:
            u["embed_slots"] = int(u["slots"])
        except Exception:
            u["embed_slots"] = 1

    if u.get("container_slots") is not None:
        try:
            u["container_slots"] = int(u["container_slots"])
        except Exception:
            u["container_slots"] = 1

    u["renew_open"] = is_renew_open(u)
    return u


_USER_BY_COLUMNS = frozenset({
    "uid", "username", "email",
    "username_lookup_hash", "email_lookup_hash",
})


def _get_user_by(column, value):
    """SELECT * users by an allowlisted column. Rows come back as dicts the
    same way in every driver mode."""
    _validate_identifier(column, allow=_USER_BY_COLUMNS)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(f"SELECT * FROM users WHERE {column}=:v", {"v": value})
        r = cur.fetchone()
        if not r:
            return None
        if hasattr(r, "keys"):
            u = dict(r)
        else:
            cols = [d[0].lower() for d in cur.description]
            u = dict(zip(cols, r))
        return _user_row_plaintext(u)
    finally:
        uconn.close()


def _get_user_by_ci_username(ci_hash):
    """The case-insensitive username lookup, but only when it is unambiguous.

    The column is not unique, so a database written before it existed can hold
    two accounts whose names differ only in case. Matching one of them at random
    would hand the visitor a different account than the one they meant, so a tie
    resolves to nothing and the caller falls through to "invalid credentials".
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT * FROM users WHERE username_ci_lookup_hash=:v", {"v": ci_hash})
        rows = cur.fetchmany(2)
        if len(rows) != 1:
            return None
        r = rows[0]
        if hasattr(r, "keys"):
            u = dict(r)
        else:
            cols = [d[0].lower() for d in cur.description]
            u = dict(zip(cols, r))
        return _user_row_plaintext(u)
    finally:
        uconn.close()


def get_user_by_username(username):
    # The stored username is encrypted, so login matches on the keyed lookup
    # hash first; the plaintext query is only the legacy fallback for rows the
    # startup migration has not touched yet.
    #
    # Exact case is tried before the case-folded index so that an account whose
    # name the visitor typed exactly always resolves to itself, even where a
    # case-variant twin of it exists. Emails have always matched case-blind
    # (get_user_by_email lowercases both sides); usernames only matched the
    # casing used at signup, which is why an account reachable by email could
    # look unreachable by name.
    if not username:
        return None
    username = username.strip()
    u = _get_user_by("username_lookup_hash", lookup_hash(username))
    if not u:
        u = _get_user_by_ci_username(lookup_hash(username.casefold()))
    if not u:
        u = _get_user_by("username", username)
    return u


def get_user_by_email(email):
    # Registered addresses are stored lowercase, so the lookup normalizes the
    # same way — logging in with "User@Example.com" finds the row the
    # registration form wrote for "user@example.com".
    if not email:
        return None
    email = email.strip().lower()
    u = _get_user_by("email_lookup_hash", lookup_hash(email))
    if not u:
        u = _get_user_by("email", email)
    return u


def verify_user(username_or_email, password):
    # Logging in takes either identifier: the username as typed, then the email
    # as a fallback. Both paths end at the same PBKDF2 check against one row,
    # so the failure is indistinguishable ("Invalid username or password")
    # regardless of which identifier was wrong.
    u = get_user_by_username(username_or_email)
    if not u:
        u = get_user_by_email(username_or_email)
    if u and verify_password(password, u["password"]):
        uconn = _user_conn()
        try:
            cur = uconn.cursor()
            # Login is the only moment the plaintext exists, so it is the only
            # chance to move an old PBKDF2 hash to Argon2id without asking the
            # user to reset anything. Folded into the last_login write that was
            # already happening, so it costs no extra round trip. Failing to
            # upgrade must never fail the login: the hash that just verified is
            # still perfectly valid.
            if needs_rehash(u["password"]):
                try:
                    cur.execute("UPDATE users SET password=:pw, last_login=:now "
                                "WHERE \"uid\"=:u_id",
                                {"pw": hash_password(password), "now": _now(),
                                 "u_id": u["uid"]})
                except Exception as ex:
                    _debug_print(f"[database] password rehash failed for {u['uid']}: {ex}",
                          file=sys.stderr)
                    cur.execute("UPDATE users SET last_login=:now WHERE \"uid\"=:u_id",
                                {"now": _now(), "u_id": u["uid"]})
            else:
                cur.execute("UPDATE users SET last_login=:now WHERE \"uid\"=:u_id", {"now": _now(), "u_id": u["uid"]})
            uconn.commit()
        finally:
            uconn.close()
        return u
    return None


def change_user_password(user_id, old_password, new_password, current_sid=None):
    user = get_user(user_id)
    if not user:
        return False, "User not found"
    if not verify_password(old_password, user["password"]):
        return False, "Current password is incorrect"
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        hashed = hash_password(new_password)
        cur.execute("UPDATE users SET password=:pw WHERE \"uid\"=:id", {"pw": hashed, "id": user_id})
        if current_sid:
            cur.execute(
                "DELETE FROM sessions WHERE \"uid\"=:u_id AND id!=:sid",
                {"u_id": user_id, "sid": current_sid},
            )
        else:
            cur.execute("DELETE FROM sessions WHERE \"uid\"=:u_id", {"u_id": user_id})
        uconn.commit()
        return True, "Password updated"
    finally:
        uconn.close()


def admin_set_user_password(user_id, new_password):
    """Set a password without knowing the old one — the operator path.

    Deliberately separate from change_user_password: that one is the user's own
    flow and must keep requiring the current password. This one is only ever
    reachable from the loopback admin console, where the caller is already the
    operator, and is how a locked-out user gets back in without email working.
    """
    if not new_password or len(str(new_password)) < 6:
        return False, "Password must be at least 6 characters"
    if not get_user(user_id):
        return False, "User not found"
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        hashed = hash_password(new_password)
        cur.execute("UPDATE users SET password=:pw WHERE \"uid\"=:id", {"pw": hashed, "id": user_id})
        uconn.commit()
        return True, "Password updated"
    finally:
        uconn.close()


def accounts_on_device(fingerprint_hash=None, lookup_hash=None):
    """Every account bound to this device, newest binding first.

    Takes the raw fingerprint or its lookup hash. The stored fingerprint is
    Fernet-encrypted (so never equal to itself twice) — lookup_hash is the only
    column that can be matched on.
    """
    lookup = lookup_hash or _fp_lookup(fingerprint_hash)
    if not lookup:
        return []
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT \"uid\", created_at FROM fingerprints WHERE lookup_hash=:h ORDER BY created_at DESC",
                    {"h": lookup})
        rows = cur.fetchall()
    finally:
        uconn.close()
    out = []
    for r in rows:
        uid = r["uid"] if hasattr(r, "keys") else r[0]
        bound_at = r["created_at"] if hasattr(r, "keys") else r[1]
        u = get_user(uid)
        if u:
            u.pop("password", None)
            u["bound_at"] = bound_at
            out.append(u)
    return out


_IP_INDEX_CHECKED = False


def _warn_if_ip_index_unusable(cur):
    """Say so, once per process, when fingerprints.ip_lookup_hash cannot match.

    lookup_hash() is keyed off the encryption key, so a key rotation leaves every
    stored index computed under the old key: accounts_on_ip() then matches nothing
    and reports "no other accounts on this IP", which is the same answer it gives
    when the IP really is clean. A row written before the index column existed
    (ip_lookup_hash NULL) is invisible the same way. Neither raises, so the
    anti-alt check degrades in total silence until rekey_encrypted.py rebuilds the
    column — this turns that into one line on stderr.

    Bounded on purpose: a handful of rows, only on the first miss after startup,
    because a miss is the ordinary answer on most logins.
    """
    global _IP_INDEX_CHECKED
    if _IP_INDEX_CHECKED:
        return
    _IP_INDEX_CHECKED = True
    try:
        cur.execute("SELECT ip_address, ip_lookup_hash FROM fingerprints "
                    "WHERE ip_address IS NOT NULL")
        unindexed = stale = 0
        for r in cur.fetchmany(8):
            enc = r["ip_address"] if hasattr(r, "keys") else r[0]
            stored_h = r["ip_lookup_hash"] if hasattr(r, "keys") else r[1]
            if not stored_h:
                unindexed += 1
                continue
            plain = decrypt(enc) if looks_encrypted(enc) else enc
            if plain and lookup_hash(plain) != stored_h:
                stale += 1
        if unindexed or stale:
            _debug_print("[db] accounts_on_ip: fingerprints.ip_lookup_hash is unusable "
                  f"({unindexed} sampled row(s) carry no index, {stale} were "
                  "written under a different encryption key). Alt-account "
                  "detection by IP is silently finding nothing. Run "
                  "app/rekey_encrypted.py to rebuild the index.", file=sys.stderr)
    except Exception as ex:
        _debug_print(f"[db] accounts_on_ip: could not verify ip_lookup_hash: {ex}",
              file=sys.stderr)


def accounts_on_ip(ip_address):
    """Every account whose bound device was last seen on this IP."""
    if not ip_address:
        return []
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        # IPs are encrypted at rest; the keyed index is the matchable form. There
        # is deliberately no plaintext fallback: every ip_address in this table is
        # ciphertext (bind_fingerprint writes it encrypted and the startup
        # migration converts the rest), so comparing a plaintext IP to that column
        # could only ever return nothing while looking like a safety net.
        cur.execute("SELECT \"uid\" FROM fingerprints WHERE ip_lookup_hash=:h", {"h": lookup_hash(ip_address)})
        rows = cur.fetchall()
        if not rows:
            _warn_if_ip_index_unusable(cur)
    finally:
        uconn.close()
    out = []
    for r in rows:
        u = get_user(r["uid"] if hasattr(r, "keys") else r[0])
        if u:
            u.pop("password", None)
            out.append(u)
    return out


def ban_user(user_id, reason="Banned"):
    val = 1
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET is_banned=:v, banned_reason=:r WHERE \"uid\"=:id",
                    {"v": val, "r": encrypt(reason) if reason else reason, "id": str(user_id)})
        uconn.commit()
    finally:
        uconn.close()


def unban_user(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET is_banned=0, banned_reason=NULL WHERE \"uid\"=:id", {"id": str(user_id)})
        uconn.commit()
    finally:
        uconn.close()


def is_user_banned(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT is_banned, banned_reason FROM users WHERE \"uid\"=:id", {"id": str(user_id)})
        r = cur.fetchone()
        if not r:
            return False, None
        if hasattr(r, "keys"):
            banned = bool(r["is_banned"])
            reason = r["banned_reason"]
        else:
            banned = bool(r[0])
            reason = r[1]
        if reason and looks_encrypted(reason):
            reason = decrypt(reason) or None
        return banned, reason
    finally:
        uconn.close()


def is_user_active(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT is_active FROM users WHERE \"uid\"=:id", {"id": str(user_id)})
        r = cur.fetchone()
        if not r:
            return False
        v = r["is_active"] if hasattr(r, "keys") else r[0]
        return _truthy(v)
    finally:
        uconn.close()


def get_fingerprint(user_id):
    """Return the decrypted fingerprint hash for a user, or None."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT fingerprint_hash FROM fingerprints WHERE \"uid\"=:id", {"id": user_id})
        r = cur.fetchone()
        if not r:
            return None
        fhash = r["fingerprint_hash"] if hasattr(r, "keys") else r[0]
        val = decrypt(fhash)
        return val if val else None
    finally:
        uconn.close()


def _fp_lookup(fingerprint_hash):
    """Non-reversible index key for a fingerprint (the stored copy is encrypted)."""
    if not fingerprint_hash:
        return None
    return hashlib.sha256(fingerprint_hash.encode()).hexdigest()


def fingerprint_owner(fingerprint_hash):
    """Return the user_id most recently bound to this fingerprint, or None.
    A device can hold several accounts now — use accounts_on_device() when the
    full list matters."""
    lookup = _fp_lookup(fingerprint_hash)
    if not lookup:
        return None
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT \"uid\" FROM fingerprints WHERE lookup_hash=:h ORDER BY created_at DESC",
                    {"h": lookup})
        r = cur.fetchone()
        return r["uid"] if r and hasattr(r, "keys") else (r[0] if r else None)
    finally:
        uconn.close()


def bind_fingerprint(user_id, fingerprint_hash, device_info=None, ip_address=None):
    """Bind a device to a user — one bound device per account, but a device may
    hold several accounts (repeat signups are flagged, never capped).
    Returns (ok, error)."""
    if not fingerprint_hash:
        return False, "Missing device fingerprint"
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        lookup = _fp_lookup(fingerprint_hash)
        encrypted = encrypt(fingerprint_hash)
        if device_info:
            if isinstance(device_info, str):
                device_info = json.loads(device_info)
            if ip_address:
                device_info["ip_address"] = ip_address
            device_enc = encrypt(json.dumps(device_info))
        elif ip_address:
            device_enc = encrypt(json.dumps({"ip_address": ip_address}))
        else:
            device_enc = None
        cur.execute("DELETE FROM fingerprints WHERE \"uid\"=:id", {"id": user_id})
        cur.execute(
            "INSERT INTO fingerprints(\"uid\", fingerprint_hash, lookup_hash, device_info_enc, ip_address, ip_lookup_hash, created_at) "
            "VALUES(:u_id,:fh,:lh,:de,:ip,:iph,:cat)",
            {"u_id": user_id, "fh": encrypted, "lh": lookup, "de": device_enc,
             "ip": encrypt(ip_address) if ip_address else None,
             "iph": lookup_hash(ip_address) if ip_address else None,
             "cat": _now()},
        )
        uconn.commit()
    except Exception as ex:
        _debug_print(f"[database] bind_device failed: {ex}", file=sys.stderr)
        return False, "Could not bind this device. Please try again later."
    finally:
        uconn.close()
    # Deliberately after the connection is back in the pool. ORACLE_POOL_MAX is 2
    # on an Always-Free ATP, so holding a second connection inside the first is
    # how two concurrent binds deadlock each other.
    record_fingerprint_history(user_id, fingerprint_hash, device_info, ip_address)
    update_user_atp_fingerprint_ip(user_id, fingerprint=fingerprint_hash, ip_address=ip_address)
    return True, None


def reset_fingerprint(user_id):
    """Clear a user's bound fingerprint so they can re-bind from a new device."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM fingerprints WHERE \"uid\"=:id", {"id": user_id})
        uconn.commit()
    finally:
        uconn.close()
    return True


def update_fingerprint_device_info(user_id, device_info, ip_address=None):
    """Update the encrypted device info for an existing fingerprint."""
    if not device_info and not ip_address:
        return
    if device_info and isinstance(device_info, str):
        try:
            device_info = json.loads(device_info)
        except Exception:
            device_info = None
    if not device_info and not ip_address:
        return
    if device_info and ip_address:
        device_info["ip_address"] = ip_address
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        device_enc = encrypt(json.dumps(device_info)) if device_info else None
        if device_enc and ip_address:
            cur.execute("UPDATE fingerprints SET device_info_enc=:de, ip_address=:ip, ip_lookup_hash=:iph WHERE \"uid\"=:id",
                        {"de": device_enc, "ip": encrypt(ip_address),
                         "iph": lookup_hash(ip_address), "id": user_id})
        elif device_enc:
            cur.execute("UPDATE fingerprints SET device_info_enc=:de WHERE \"uid\"=:id",
                        {"de": device_enc, "id": user_id})
        else:
            # No device blob this time, but a live IP: refresh the address and its
            # index and leave the stored blob alone. Without this branch a login
            # from a browser that sent no fingerprint_detail left the admin
            # console showing an IP older than the last login.
            cur.execute("UPDATE fingerprints SET ip_address=:ip, ip_lookup_hash=:iph WHERE \"uid\"=:id",
                        {"ip": encrypt(ip_address), "iph": lookup_hash(ip_address), "id": user_id})
        uconn.commit()
    finally:
        uconn.close()


def fingerprint_status(user_id):
    """Return dict of fingerprint info for admin display (hash + device details decrypted)."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT fingerprint_hash, device_info_enc, ip_address, created_at FROM fingerprints WHERE \"uid\"=:id", {"id": user_id})
        r = cur.fetchone()
    finally:
        uconn.close()
    if not r:
        return {"registered": False, "hash": None, "lookup_hash": None,
                "device_info": None, "ip_address": None, "created_at": None}
    if hasattr(r, "keys"):
        fhash = decrypt(r["fingerprint_hash"])
        cat = r["created_at"]
        denc = r["device_info_enc"]
        ip = r["ip_address"]
    else:
        fhash = decrypt(r[0])
        denc = r[1]
        ip = r[2]
        cat = r[3]
    if ip and looks_encrypted(ip):
        ip = decrypt(ip) or None
    if not fhash:
        return {"registered": False, "hash": None, "lookup_hash": None,
                "device_info": None, "ip_address": ip, "created_at": cat}
    device_info = None
    if denc:
        try:
            device_info = json.loads(decrypt(denc))
        except Exception:
            device_info = None
    if not ip and device_info:
        ip = device_info.get("ip_address")
    return {
        "registered": True,
        "hash": fhash,
        "lookup_hash": _fp_lookup(fhash),
        "device_info": device_info,
        "ip_address": ip,
        "created_at": cat,
    }


def record_fingerprint_history(user_id, fingerprint_hash, device_info=None, ip_address=None):
    """Append this sighting to the user's device history, if it is new.

    `fingerprints` keeps one row per user and overwrites it on every login, so
    the previous device was lost. This is the append-only record behind it.

    Deduplicated against the newest row only: a user logging in daily from one
    machine writes a single row, and an alternating pair of devices still records
    both because the comparison is against the last sighting rather than against
    every sighting. device_info is a 10-25 KB CLOB, which is what makes writing
    one per login the wrong default on a size-capped ATP.

    Never raises — history is an observation, and losing one must not fail a
    login that is otherwise fine.
    """
    if not user_id or not fingerprint_hash:
        return False
    lookup = _fp_lookup(fingerprint_hash)
    if not lookup:
        return False
    if isinstance(device_info, str):
        try:
            device_info = json.loads(device_info)
        except Exception:
            device_info = None
    if device_info and ip_address:
        device_info = dict(device_info)
        device_info["ip_address"] = ip_address
    try:
        uconn = _user_conn()
    except Exception:
        return False
    try:
        cur = uconn.cursor()
        ip_hash = lookup_hash(ip_address) if ip_address else None
        cur.execute(
            "SELECT 1 FROM fingerprint_history "
            "WHERE \"uid\"=:id AND lookup_hash=:lh AND (ip_lookup_hash IS NULL AND :iph IS NULL OR ip_lookup_hash=:iph)",
            {"id": user_id, "lh": lookup, "iph": ip_hash},
        )
        if cur.fetchone():
            return False
        cur.execute(
            "INSERT INTO fingerprint_history(\"uid\", fingerprint_hash, lookup_hash, "
            "device_info_enc, ip_address, ip_lookup_hash, created_at) "
            "VALUES(:id, :fh, :lh, :de, :ip, :iph, :now)",
            {"id": user_id, "fh": encrypt(fingerprint_hash), "lh": lookup,
             "de": encrypt(json.dumps(device_info)) if device_info else None,
             "ip": encrypt(ip_address) if ip_address else None,
             "iph": ip_hash, "now": _now()},
        )
        uconn.commit()
        return True
    except Exception as ex:
        _debug_print(f"[database] fingerprint history not recorded for {user_id}: {ex}")
        return False
    finally:
        uconn.close()


def get_fingerprint_history(user_id, limit=50):
    """Every distinct device this account has been seen on, newest first."""
    if not user_id:
        return []
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 50
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT id, fingerprint_hash, lookup_hash, device_info_enc, ip_address, created_at "
            "FROM fingerprint_history WHERE \"uid\"=:id ORDER BY id DESC "
            "FETCH FIRST :lim ROWS ONLY",
            {"id": user_id, "lim": limit},
        )
        rows = cur.fetchall()
    finally:
        uconn.close()
    out = []
    for r in rows:
        if hasattr(r, "keys"):
            rid, fh, lh, denc, ip, cat = (r["id"], r["fingerprint_hash"], r["lookup_hash"],
                                          r["device_info_enc"], r["ip_address"], r["created_at"])
        else:
            rid, fh, lh, denc, ip, cat = r[0], r[1], r[2], r[3], r[4], r[5]
        device_info = None
        if denc:
            try:
                device_info = json.loads(decrypt(denc))
            except Exception:
                device_info = None
        if ip and looks_encrypted(ip):
            ip = decrypt(ip) or None
        out.append({"id": rid, "hash": decrypt(fh) or None, "lookup_hash": lh,
                    "device_info": device_info, "ip_address": ip, "created_at": cat})
    return out


def log_device_event(event_type, user_id=None, username=None, fingerprint_hash=None,
                     device_info=None, ip_address=None, blocked=False, details=None):
    if not fingerprint_hash:
        return
    if isinstance(device_info, str):
        try:
            device_info = json.loads(device_info)
        except Exception:
            device_info = {"raw": device_info}
    device_enc = encrypt(json.dumps(device_info)) if device_info else None
    username_enc = encrypt(username) if username else None
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "INSERT INTO device_events(\"uid\", username, event_type, lookup_hash, fingerprint_enc, "
            "device_info_enc, ip_address, blocked, reviewed, details, created_at) "
            "VALUES(:user_id,:un,:et,:lh,:fe,:de,:ip,:bl,0,:det,:cat)",
            {"user_id": str(user_id) if user_id else None, "un": username_enc, "et": event_type,
             "lh": _fp_lookup(fingerprint_hash),
             "fe": encrypt(fingerprint_hash) if fingerprint_hash else None,
             "de": device_enc,
             "ip": encrypt(ip_address) if ip_address else None,
             "bl": 1 if blocked else 0,
             "det": encrypt(json.dumps(details)) if details else None, "cat": _now()},
        )
        uconn.commit()
    except Exception as ex:
        _debug_print(f"[database] could not record device event {event_type}: {ex}", file=sys.stderr)

    # Log flagged event to HeatWave MySQL DB app_errors table
    try:
        import reviews_db
        reason_val = None
        if details and isinstance(details, dict):
            reason_val = details.get("reason")
        reviews_db.log_app_error(
            error_type=f"DeviceFlag:{event_type}",
            message=f"Device flag '{event_type}' for user '{username or user_id}'. Details: {json.dumps(details) if details else ''}",
            stack_trace=json.dumps({
                "event_type": event_type,
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
                "blocked": blocked,
                "details": details
            }),
            module="device_security",
            flagged=1,
            flag_reason=reason_val or event_type
        )
    except Exception as ex:
        _debug_print(f"[database] could not log device flag to HeatWave: {ex}", file=sys.stderr)
    finally:
        uconn.close()


def get_device_events(limit=200, offset=0, only_unreviewed=False, user_id=None):
    """Newest device flags first, with the fingerprint and device details
    decrypted for admin display."""
    where = []
    params = {}
    if only_unreviewed:
        where.append("reviewed=0")
    if user_id:
        where.append("\"uid\"=:user_id")
        params["user_id"] = str(user_id)
    sql = ("SELECT id, \"uid\", username, event_type, lookup_hash, fingerprint_enc, device_info_enc, "
           "ip_address, blocked, reviewed, details, created_at FROM device_events")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC"
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        if offset:
            rows = rows[offset:offset + limit]
        else:
            rows = rows[:limit]
        cols = [d[0].lower() for d in cur.description]
    finally:
        uconn.close()
    out = []
    for r in rows:
        d = dict(r) if hasattr(r, "keys") else dict(zip(cols, r))
        d["username"] = _dec_or_raw(d.get("username"))
        if d.get("ip_address"):
            d["ip_address"] = _dec_or_raw(d["ip_address"])
        d["fingerprint"] = decrypt(d.pop("fingerprint_enc", None)) or None
        denc = d.pop("device_info_enc", None)
        d["device_info"] = None
        if denc:
            try:
                d["device_info"] = json.loads(decrypt(denc))
            except Exception:
                d["device_info"] = None
        if d.get("details"):
            # details is encrypted going forward; pre-encryption rows are plain
            # JSON and _dec_or_raw passes those straight through.
            try:
                d["details"] = json.loads(_dec_or_raw(d["details"]))
            except (json.JSONDecodeError, TypeError):
                pass
        d["blocked"] = int(d.get("blocked") or 0)
        d["reviewed"] = int(d.get("reviewed") or 0)
        out.append(d)
    return out


def count_unreviewed_device_events():
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT COUNT(*) FROM device_events WHERE reviewed=0")
        r = cur.fetchone()
        return int(r[0] if r else 0)
    except Exception:
        return 0
    finally:
        uconn.close()


def device_event_counts_by_user():
    """{user_id: unreviewed flag count} — for the badge in the admin user list."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT \"uid\", COUNT(*) FROM device_events WHERE reviewed=0 AND \"uid\" IS NOT NULL GROUP BY \"uid\"")
        return {r[0]: int(r[1]) for r in cur.fetchall()}
    except Exception:
        return {}
    finally:
        uconn.close()


def review_device_events(event_ids=None, user_id=None):
    """Mark flags as handled. With no arguments, clears the whole queue."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        if event_ids:
            for eid in event_ids:
                cur.execute("UPDATE device_events SET reviewed=1 WHERE id=:id", {"id": int(eid)})
        elif user_id:
            cur.execute("UPDATE device_events SET reviewed=1 WHERE \"uid\"=:user_id", {"user_id": str(user_id)})
        else:
            cur.execute("UPDATE device_events SET reviewed=1 WHERE reviewed=0")
        uconn.commit()
    finally:
        uconn.close()


def delete_device_events(event_ids=None, user_id=None):
    """Permanently remove flags. event_ids wins over user_id; with neither,
    nothing is deleted (a bare call must never wipe the queue)."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        deleted = 0
        if event_ids:
            for eid in event_ids:
                cur.execute("DELETE FROM device_events WHERE id=:id", {"id": int(eid)})
                deleted += max(0, cur.rowcount)
        elif user_id:
            cur.execute("DELETE FROM device_events WHERE \"uid\"=:user_id", {"user_id": str(user_id)})
            deleted += max(0, cur.rowcount)
        uconn.commit()
        return deleted
    finally:
        uconn.close()


def _truthy(val):
    """DB flags arrive as 1, '1', 1.0 or 0, '0', 0.0. Standardize on 0/1."""
    return str(val).strip() in ("1", "1.0")


def check_device_registration(fingerprint_hash, ip_address=None):
    """Look at what a new self-service signup shares with existing accounts.

    There is no cap on how many accounts one device or IP may hold — a repeat
    signup is recorded as a flag for the console, never turned away. A banned
    account on the device is the one exception: that still blocks.

    Returns (ok, error, info). `info` describes what is already on the device so
    the caller can flag the attempt.
    """
    lookup = _fp_lookup(fingerprint_hash)
    device_accounts = accounts_on_device(lookup_hash=lookup) if lookup else []
    ip_accounts = accounts_on_ip(ip_address) if ip_address else []
    trials = [u for u in device_accounts if (u.get("account_type") or "trial") == "trial"]
    paid = [u for u in device_accounts if (u.get("account_type") or "trial") == "paid"]
    banned = [u for u in device_accounts if _truthy(u.get("is_banned"))]
    info = {
        "lookup_hash": lookup,
        "device_accounts": device_accounts,
        "ip_accounts": ip_accounts,
        "trial_count": len(trials),
        "paid_count": len(paid),
        "reason": None,
    }
    if banned:
        info["reason"] = "banned_device"
        info["banned_account"] = banned[0].get("username")
        return False, "BANNED", info
    if device_accounts:
        info["reason"] = "same_device"
    if ip_accounts:
        info["reason"] = "same_ip" if not device_accounts else "same_device_and_ip"
    return True, None, info


def check_device_login(user_id, fingerprint_hash, device_info=None, ip_address=None):
    """Bind on first sight, flag anything arriving from another device, and say
    whether the login may continue. Returns (ok, error).

    A login from a new device is captured and flagged so an admin can see the
    sharing, but it is not turned away. A banned account on the device still
    blocks.
    """
    stored = get_fingerprint(user_id)
    user = get_user(user_id) or {}
    username = user.get("username")
    account_type = (user.get("account_type") or "trial")

    # A ban follows the device, not just the account. Look at both the device
    # this login came from and the one the account is bound to: if either holds a
    # banned account, this login is an alt of it — whether or not the device is
    # already bound here, which is how a banned user's second account used to
    # walk straight in.
    others, seen_ids = [], set()
    for fp in {f for f in (fingerprint_hash, stored) if f}:
        for u in accounts_on_device(fp):
            uid = str(u.get("uid"))
            if uid == str(user_id) or uid in seen_ids:
                continue
            seen_ids.add(uid)
            others.append(u)
    banned_alt = next((u for u in others if _truthy(u.get("is_banned"))), None)
    if banned_alt:
        auto_ban = get_auto_ban_enabled()
        if auto_ban:
            ban_user(user_id, f"Alt account of banned user {banned_alt['username']} (same device)")
        log_device_event(
            "banned_alt_login", user_id=user_id, username=username,
            fingerprint_hash=fingerprint_hash or stored, device_info=device_info,
            ip_address=ip_address, blocked=auto_ban,
            details={"banned_account": banned_alt.get("username"),
                     "auto_banned": auto_ban},
        )
        return False, "BANNED"

    if not stored:
        if not fingerprint_hash:
            return True, None
        ok, err = bind_fingerprint(user_id, fingerprint_hash, device_info, ip_address=ip_address)
        if not ok:
            return False, err
        if others:
            log_device_event(
                "shared_device_bind", user_id=user_id, username=username,
                fingerprint_hash=fingerprint_hash, device_info=device_info, ip_address=ip_address,
                blocked=False,
                details={"account_type": account_type,
                         "also_on_device": [u.get("username") for u in others]},
            )
        return True, None

    fp_others = []
    if fingerprint_hash:
        fp_others = [u for u in accounts_on_device(fingerprint_hash)
                     if str(u.get("uid")) != str(user_id)]
    ip_others = []
    if ip_address:
        ip_others = [u for u in accounts_on_ip(ip_address)
                     if str(u.get("uid")) != str(user_id)]

    if fingerprint_hash and fingerprint_hash == stored:
        if device_info or ip_address:
            update_fingerprint_device_info(user_id, device_info, ip_address=ip_address)
        record_fingerprint_history(user_id, fingerprint_hash, device_info, ip_address)
        if fp_others or ip_others:
            log_device_event(
                "shared_device_login", user_id=user_id, username=username,
                fingerprint_hash=fingerprint_hash, device_info=device_info, ip_address=ip_address,
                blocked=False,
                details={"account_type": account_type,
                         "also_on_device": [u.get("username") for u in fp_others],
                         "same_ip_accounts": [u.get("username") for u in ip_others],
                         "reason": "multi_account_login",
                         "outcome": "allowed"},
            )
        return True, None

    # A different device (or a browser that sent no fingerprint at all). This is
    # routine for a single account — a new browser, a cleared cache, a rotating
    # fingerprint — and is NOT a flag on its own. It becomes a flag only when the
    # new device's fingerprint or the login IP is already used by a *different*
    # account (account sharing). A repeat login from the account's own bound
    # device is never flagged either, and bindings are never re-bound here, so a
    # rotating fingerprint cannot spam the Flags queue.
    fp_others = []
    if fingerprint_hash:
        fp_others = [u for u in accounts_on_device(fingerprint_hash)
                     if str(u.get("uid")) != str(user_id)]
    ip_others = []
    if ip_address:
        ip_others = [u for u in accounts_on_ip(ip_address)
                     if str(u.get("uid")) != str(user_id)]
    # The binding is deliberately left alone above, so without this the second
    # device a user logs in from is never recorded anywhere. Unconditional: this
    # is history, not a flag, and it is written whether or not the sharing checks
    # below find anything.
    record_fingerprint_history(user_id, fingerprint_hash, device_info, ip_address)
    if fp_others or ip_others:
        log_device_event(
            "shared_device_login", user_id=user_id, username=username,
            fingerprint_hash=fingerprint_hash, device_info=device_info, ip_address=ip_address,
            blocked=False,
            details={"account_type": account_type,
                     "also_on_device": [u.get("username") for u in fp_others],
                     "same_ip_accounts": [u.get("username") for u in ip_others],
                     "missing_fingerprint": not bool(fingerprint_hash),
                     "outcome": "allowed"},
        )
    return True, None


def update_user_slots(user_id, slots):
    try:
        slots = max(0, int(slots))
    except (ValueError, TypeError):
        raise ValueError(f"slots must be a number, got {slots!r}")
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET slots=:slots WHERE \"uid\"=:id", {"slots": str(slots), "id": user_id})
        _oracle_ensure_bot_slots(cur, user_id, slots)
        if slots > 0:
            cur.execute("DELETE FROM bots WHERE \"uid\"=:uid_param AND slot_index >= :idx",
                        {"uid_param": user_id, "idx": slots})
        else:
            cur.execute("DELETE FROM bots WHERE \"uid\"=:uid_param", {"uid_param": user_id})
        uconn.commit()
    finally:
        uconn.close()
    update_user_atp_slots(user_id, embed_slots=slots)


def update_user_atp_tokens(user_id, discord_bot_token=None, webhook_token=None):
    if not user_id:
        return
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        sets = {}
        if discord_bot_token is not None and discord_bot_token != "":
            sets["discord_bot_token"] = encrypt(str(discord_bot_token).strip())
        if webhook_token is not None and webhook_token != "":
            sets["webhook_token"] = encrypt(str(webhook_token).strip())
        if sets:
            _validate = frozenset({"discord_bot_token", "webhook_token"})
            for k in sets:
                _validate_identifier(k, allow=_validate)
            assignments = ", ".join(f"{k}=:{k}" for k in sets)
            sets["u_id"] = str(user_id)
            cur.execute(f"UPDATE users SET {assignments} WHERE \"uid\"=:u_id", sets)
            uconn.commit()
    except Exception as ex:
        _debug_print(f"[database] update_user_atp_tokens failed for {user_id}: {ex}", file=sys.stderr)
    finally:
        uconn.close()


def update_user_atp_fingerprint_ip(user_id, fingerprint=None, ip_address=None):
    if not user_id or (not fingerprint and not ip_address):
        return
    combined = f"{fingerprint or ''}:{ip_address or ''}".strip(":")
    if not combined:
        return
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET fingerprint_ip=:fp_ip WHERE \"uid\"=:u_id",
                    {"fp_ip": encrypt(combined), "u_id": str(user_id)})
        uconn.commit()
    except Exception as ex:
        _debug_print(f"[database] update_user_atp_fingerprint_ip failed for {user_id}: {ex}", file=sys.stderr)
    finally:
        uconn.close()


def update_user_atp_slots(user_id, embed_slots=None, container_slots=None):
    if not user_id:
        return
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        sets = {}
        if embed_slots is not None:
            sets["slots"] = str(embed_slots)
            sets["embed_slots"] = str(embed_slots)
        if container_slots is not None:
            sets["container_slots"] = str(container_slots)
        if sets:
            _validate = frozenset({"slots", "container_slots", "embed_slots"})
            for k in sets:
                _validate_identifier(k, allow=_validate)
            assignments = ", ".join(f"{k}=:{k}" for k in sets)
            sets["u_id"] = str(user_id)
            cur.execute(f"UPDATE users SET {assignments} WHERE \"uid\"=:u_id", sets)
            uconn.commit()
    except Exception as ex:
        _debug_print(f"[database] update_user_atp_slots failed for {user_id}: {ex}", file=sys.stderr)
    finally:
        uconn.close()


# Bot columns that are Fernet-encrypted at rest. None of them appears in a
# WHERE / LIKE / ORDER BY / GROUP BY / join predicate anywhere in this module —
# Fernet is non-deterministic, so any column that did would have to stay
# plaintext. server_port, update_interval, slot_index and running are compared as
# numbers and are not secrets; last_status is public Minecraft server status that
# every engine tick rewrites, and encrypting it would inflate the one write this
# app went out of its way to shrink.
_BOT_ENC_FIELDS = ("name", "server_ip", "guild_id", "channel_id", "embed_json", "ip_reply_json", "webhook_url")


def _decrypt_bot_row(d):
    """Decrypt the encrypted-at-rest bot columns in place. Rows written before
    encryption landed pass through unchanged — see _dec_or_raw."""
    for k in _BOT_ENC_FIELDS:
        if k in d:
            d[k] = _dec_or_raw(d[k])
    return d


def get_user_bots(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT * FROM bots WHERE \"uid\"=:uid_param ORDER BY slot_index", {"uid_param": user_id})
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        uconn.close()
    out = []
    for d in rows:
        _decrypt_bot_row(d)
        d["token"] = decrypt(d.get("token_enc"))
        d["token_masked"] = mask(d["token"])
        d["webhook_url_masked"] = mask(d.get("webhook_url"))
        d["embed"] = _bot_json_obj(d.get("embed_json"), default_embed)
        d["ip_reply"] = _bot_json_obj(d.get("ip_reply_json"), default_ip_reply)
        out.append(d)
    return out


def get_bot(bot_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT * FROM bots WHERE id=:id", {"id": bot_id})
        r = cur.fetchone()
        if not r:
            return None
        if hasattr(r, "keys"):
            d = dict(r)
        else:
            cols = [d[0].lower() for d in cur.description]
            d = dict(zip(cols, r))
    finally:
        uconn.close()
    _decrypt_bot_row(d)
    d["token"] = decrypt(d.get("token_enc"))
    d["token_masked"] = mask(d["token"])
    d["webhook_url_masked"] = mask(d.get("webhook_url"))
    d["embed"] = _bot_json_obj(d.get("embed_json"), default_embed)
    d["ip_reply"] = _bot_json_obj(d.get("ip_reply_json"), default_ip_reply)
    return d


# Byte ceiling on a bot's client-authored JSON blob, matching backend.py's
# EMBED_JSON_MAX_BYTES so a payload that tier accepted is never refused here.
# The bound has to exist on this side too: the admin console reaches
# save_bot_config through its own handler, which checks that embed is an object
# but never how large it is, and the maintenance daemon does not validate at all.
_BOT_JSON_MAX_BYTES = 65536


def _bot_json_blob(value, label):
    """Serialise a bot builder blob for its CLOB column, or raise ValueError.

    Refused rather than coerced: json.dumps() would store a bare list or string
    just as happily, and every reader of these columns calls .get() on the
    result. Refused rather than truncated too — a clipped JSON blob no longer
    parses, so the read path would answer every later request with the defaults
    instead of the configuration the user believes they saved."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    try:
        encoded = json.dumps(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} is not serialisable as JSON")
    if len(encoded.encode("utf-8", "replace")) > _BOT_JSON_MAX_BYTES:
        raise ValueError(f"{label} is too large (max {_BOT_JSON_MAX_BYTES} bytes)")
    return encoded


def save_bot_config(bot_id, *, user_id=None, name=None, server_ip=None, server_port=None, edition=None,
                    token=None, guild_id=None, channel_id=None, webhook_url=None,
                    update_interval=None, embed=None, ip_reply=None):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        if user_id is not None:
            # Scope the write to the owner so a bot reassigned between the
            # caller's ownership check and this UPDATE cannot be modified.
            cur.execute("SELECT id FROM bots WHERE id=:id AND \"uid\"=:u_id",
                        {"id": bot_id, "u_id": user_id})
        else:
            cur.execute("SELECT id FROM bots WHERE id=:id", {"id": bot_id})
        if not cur.fetchone():
            return False
        fields = {}
        # The five _BOT_ENC_FIELDS columns are encrypted here, on the assignment,
        # so a partial save never mixes ciphertext and plaintext in one row.
        if name is not None:
            fields["name"] = encrypt(str(name).strip())
        if server_ip is not None:
            fields["server_ip"] = encrypt(str(server_ip).strip())
        clean_edition = None
        if edition is not None:
            clean_edition = str(edition).strip().lower() or "java"
            fields["edition"] = clean_edition
        if server_port is not None:
            raw_port = str(server_port).strip()
            if not raw_port:
                # A missing port is a request to keep the stored value. When the
                # UI explicitly saves an edition alongside a blank port, persist
                # that edition's documented default instead of always forcing
                # Java's 25565 onto Bedrock configurations.
                if clean_edition is not None:
                    fields["server_port"] = 19132 if clean_edition == "bedrock" else 25565
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
            clean_guild_id = str(guild_id).strip()
            if clean_guild_id and (not clean_guild_id.isdigit() or len(clean_guild_id) > 25):
                raise ValueError("Guild ID must be a Discord numeric ID")
            fields["guild_id"] = encrypt(clean_guild_id)
        if channel_id is not None:
            clean_channel_id = str(channel_id).strip()
            if clean_channel_id and (not clean_channel_id.isdigit() or len(clean_channel_id) > 25):
                raise ValueError("Channel ID must be a Discord numeric ID")
            fields["channel_id"] = encrypt(clean_channel_id)
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
            # A blank value means "keep the existing webhook", mirroring the
            # token field. Any real change starts a new message chain — the
            # stored message_id belongs to the old destination.
            fields["webhook_url"] = encrypt(str(webhook_url).strip())
            fields["message_id"] = None
        fields["updated_at"] = _now()
        fields["last_error"] = None
        if fields:
            _BOT_CONFIG_COLUMNS = frozenset({
                "name", "server_ip", "edition", "server_port",
                "token_enc", "message_id", "guild_id", "channel_id",
                "update_interval", "embed_json", "ip_reply_json",
                "webhook_url", "last_error", "updated_at",
            })
            for k in fields:
                _validate_identifier(k, allow=_BOT_CONFIG_COLUMNS)
            sets = ", ".join(f"{k}=:{k}" for k in fields)
            vals = {**fields, "id": bot_id}
            where = "WHERE id=:id"
            if user_id is not None:
                # :u_id, never :uid — UID is an Oracle reserved word, so a bind
                # named uid raises ORA-01745 and fails the whole save.
                where += " AND \"uid\"=:u_id"
                vals["u_id"] = user_id
            cur.execute(f"UPDATE bots SET {sets} {where}", vals)
            uconn.commit()
            if user_id:
                if token is not None and token != "":
                    update_user_atp_tokens(user_id, discord_bot_token=token)
                if webhook_url is not None and webhook_url != "":
                    update_user_atp_tokens(user_id, webhook_token=webhook_url)
        return True
    finally:
        uconn.close()


def set_user_account_type(user_id, account_type):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        if account_type == "trial":
            expires = (_utcnow() + timedelta(days=TRIAL_DAYS)).isoformat()
            cur.execute("UPDATE users SET account_type=:actype, trial_expires_at=:texp WHERE \"uid\"=:id",
                        {"actype": account_type, "texp": expires, "id": user_id})
        else:
            cur.execute("UPDATE users SET account_type=:actype, trial_expires_at=NULL WHERE \"uid\"=:id",
                        {"actype": account_type, "id": user_id})
        uconn.commit()
    finally:
        uconn.close()


def set_user_trial_expiry(user_id, expires_at):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET trial_expires_at=:texp WHERE \"uid\"=:id",
                    {"texp": expires_at, "id": user_id})
        uconn.commit()
    finally:
        uconn.close()


def is_trial_expired(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT account_type, trial_expires_at FROM users WHERE \"uid\"=:id", {"id": user_id})
        row = cur.fetchone()
        if not row:
            return False
        # oracledb hands back plain tuples, which have no .get(), so the conversion
        # below cannot be skipped — skipping it made every call raise
        # AttributeError, which _run_worker swallowed once per tick and which left
        # no bot publishing at all.
        if not isinstance(row, dict):
            cols = [d[0].lower() for d in cur.description]
            row = dict(zip(cols, tuple(row)))
        if row.get("account_type") != "trial":
            return False
        expires = row.get("trial_expires_at")
        if not expires:
            return False
        try:
            when = datetime.fromisoformat(str(expires))
        except Exception:
            # An unparseable expiry is a data problem, not an expired trial.
            return False
        if when.tzinfo is None:
            # Rows written before the expiry clock was fixed are naive UTC.
            # Comparing them raw raises TypeError, which used to read as "not
            # expired" indefinitely.
            when = when.replace(tzinfo=timezone.utc)
        return when < _utcnow()
    finally:
        uconn.close()


def expire_trial_bots():
    try:
        uconn = _user_conn()
    except Exception:
        return
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT \"uid\" FROM users WHERE account_type='trial' AND trial_expires_at IS NOT NULL AND trial_expires_at < :now",
            {"now": _now()},
        )
        rows = cur.fetchall()
        for r in rows:
            uid = r["uid"] if hasattr(r, "keys") else r[0]
            cur.execute("UPDATE bots SET running=0, last_error='Trial expired' WHERE \"uid\"=:uid_param AND running=1", {"uid_param": uid})
            try:
                cur.execute("SELECT id FROM hosting_servers WHERE \"uid\"=:uid_param", {"uid_param": uid})
                hosting_ids = [row[0] for row in cur.fetchall()]
            except Exception:
                hosting_ids = []
            for server_id in hosting_ids:
                set_hosting_status(server_id, "stopped", pid=None, last_error="Trial expired")
        if rows:
            uconn.commit()
    except Exception:
        pass
    finally:
        uconn.close()


# ── Inactivity lifecycle (trial accounts only) ───────────────────
#
# All rules live in ONE settings row, "inactivity_policy", and the sweep below
# is the only place that acts on them. Paid accounts never need to renew and
# are exempt from the sweep. Two clocks:
#
#   * Registration: from email verification, a trial user who never starts a
#     bot is warned at verified_at + (deadline_days - warn_days) and deleted
#     at verified_at + deadline_days.
#   * Weekly inactivity: from the last activity (a running bot's heartbeats,
#     or the "Renew" / "I'm active" buttons), the user is warned at activity +
#     warn_days with the turn-off date, their bots are stopped at activity +
#     stop_days, and the account is deleted stop + grace_days later unless
#     they renew. Renewing extends the deadline from the scheduled turn-off
#     date by another stop_days (one more trial period) and restarts the bots.

_INACTIVITY_POLICY_DEFAULT = {
    "enabled": True,
    "unverified_ttl_minutes": 60,
    "verified_deadline_days": 4,
    "verified_warn_days": 2,
    "inactive_stop_days": renew_config.RENEW_CYCLE_DAYS,
    "inactive_warn_days": max(1, renew_config.RENEW_CYCLE_DAYS - renew_config.RENEW_WARN_DAYS_BEFORE),
    "renew_window_days": renew_config.RENEW_WINDOW_DAYS,
    "grace_days": renew_config.RENEW_GRACE_DAYS,
    "start_subject": "Action required: start your bot or your account will be deleted",
    "start_body": ("Hi {username},\n\nYou haven't started a bot yet. If you don't start "
                   "your bot within {days} day(s), your account will be permanently "
                   "deleted.\n\nLog in and start a bot from your dashboard to keep your "
                   "account."),
    "stop_subject": "Your bot will be turned off — renew it now",
    "stop_body": ("Hi {username},\n\n{assets} is still running, but it will be turned "
                  "off on {date} unless you renew.\n\nClick \"Renew\" on your "
                  "dashboard before then and everything keeps working for another "
                  "{days} day(s) from that date — no interruption."),
}


def get_inactivity_policy():
    """The inactivity policy as a dict, from the single "inactivity_policy"
    settings row. Falls back to the defaults above when the row is missing."""
    raw = get_setting("inactivity_policy")
    if not raw:
        return dict(_INACTIVITY_POLICY_DEFAULT)
    try:
        pol = json.loads(raw)
        return pol if isinstance(pol, dict) else dict(_INACTIVITY_POLICY_DEFAULT)
    except Exception:
        return dict(_INACTIVITY_POLICY_DEFAULT)


def mark_user_active(user_id):
    """Stamp the account's last activity time."""
    now = _shared_now()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET last_active_at=:now WHERE \"uid\"=:id",
                    {"now": now, "id": user_id})
        uconn.commit()
    finally:
        uconn.close()


def send_trial_warning(to_addr, username, *, days_left, status, grace_days=None, expires_at=None):
    """Send trial-cycle warning or stopped notifications."""
    username = str(username) or "there"
    days_left = max(1, int(days_left or 1))
    expiry_text = ""
    if expires_at is not None:
        try:
            expiry_text = expires_at.strftime("%B %d, %Y")
        except Exception:
            expiry_text = ""
    if status == "upcoming":
        subject, plain_body, html_body = email_templates.build_trial_warning_email(
            to_addr, username, days_left=days_left, expiry_date_str=expiry_text
        )
    else:
        subject, plain_body, html_body = email_templates.build_trial_stopped_email(
            to_addr, username
        )
    _send_raw(to_addr, subject, plain_body, html_body,
              prefix="warn_smtp" if _smtp_ready(get_smtp_config("warn_smtp"), "warn_smtp") else "smtp")


def renew_user(user_id):
    """Trial 'Renew': extend the account's trial deadline by one cycle.

    Renew is accepted once the account is inside the renewal window that starts
    ``renew_window_days`` before the expiry date. Returns ``"renewed"``,
    ``"too_early"``, ``"not_trial"`` or ``"not_found"``.
    """
    stop_days = int(renew_config.RENEW_CYCLE_DAYS)
    window_days = int(renew_config.RENEW_WINDOW_DAYS)
    now = _shared_utcnow()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT account_type, trial_expires_at, created_at, bot_stopped_at FROM users WHERE \"uid\"=:id",
                    {"id": user_id})
        r = cur.fetchone()
        if not r:
            return "not_found"
        if not hasattr(r, "keys"):
            cols = [d[0].lower() for d in cur.description]
            r = dict(zip(cols, tuple(r)))
        if r.get("account_type") != "trial":
            return "not_trial"
        expires_at = _parse_iso(r.get("trial_expires_at"))
        if expires_at is None:
            base = _parse_iso(r.get("created_at")) or now
            expires_at = base + timedelta(days=stop_days)
        if now < expires_at - timedelta(days=window_days):
            return "too_early"
        new_deadline = expires_at + timedelta(days=stop_days)
        cur.execute("UPDATE users SET bot_stopped_at=NULL, inactive_warned_at=NULL, "
                    "trial_expires_at=:d WHERE \"uid\"=:id",
                    {"d": new_deadline.isoformat(), "id": user_id})
        # Restart any bots that a previous run stopped.
        cur.execute("UPDATE bots SET running=1, last_error=NULL "
                    "WHERE \"uid\"=:id AND running=0 AND last_error='Stopped: inactive account'",
                    {"id": user_id})
        try:
            cur.execute("UPDATE hosting_servers SET status='running', last_error=NULL "
                        "WHERE \"uid\"=:id AND status='stopped'", {"id": user_id})
        except Exception:
            pass
        uconn.commit()
        return "renewed"
    finally:
        uconn.close()


def _stop_trial_workloads(cur, user_id, *, reason="Trial expired"):
    cur.execute("UPDATE bots SET running=0, last_error=:reason WHERE \"uid\"=:id AND running=1",
                {"reason": reason, "id": user_id})
    try:
        cur.execute("SELECT id FROM hosting_servers WHERE \"uid\"=:id", {"id": user_id})
        hosting_ids = [row[0] for row in cur.fetchall()]
    except Exception:
        hosting_ids = []
    for server_id in hosting_ids:
        set_hosting_status(server_id, "stopped", pid=None, last_error=reason)


def _delete_trial_workloads(user_id):
    """Delete user-owned workloads while leaving the account row intact."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM bots WHERE \"uid\"=:id", {"id": user_id})
        try:
            cur.execute("SELECT id FROM hosting_servers WHERE \"uid\"=:id", {"id": user_id})
            hosting_ids = [row[0] for row in cur.fetchall()]
        except Exception:
            hosting_ids = []
        for server_id in hosting_ids:
            delete_hosting_server(server_id)
        uconn.commit()
    finally:
        uconn.close()


def _parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _user_started_bot(cur, uid):
    cur.execute("SELECT COUNT(*) FROM bots WHERE \"uid\"=:id "
                "AND (running=1 OR last_run IS NOT NULL)", {"id": uid})
    return cur.fetchone()[0] > 0


def inactivity_sweep():
    """Run the trial renew cycle.

    Trial accounts get one warning three days before expiry, an expiry-day mail
    when workloads are stopped, a one-day grace period, and then deletion of
    the user-owned workloads only. The account record itself stays in place.
    """
    renew_days = int(renew_config.RENEW_CYCLE_DAYS)
    warn_days = int(renew_config.RENEW_WARN_DAYS_BEFORE)
    grace_days = int(renew_config.RENEW_GRACE_DAYS)
    unverified_ttl = int(get_inactivity_policy().get("unverified_ttl_minutes", 60))
    now = _shared_utcnow()
    try:
        uconn = _user_conn()
    except Exception:
        return
    try:
        cur = uconn.cursor()
        cur.execute("""
            SELECT "uid", username, email, email_verified, verified_at, created_at,
                   trial_expires_at, bot_stopped_at, inactive_warned_at
            FROM users
            WHERE account_type = 'trial'
        """)
        cols = [d[0].lower() for d in cur.description]
        rows = cur.fetchall()
        for r in rows:
            if not hasattr(r, "keys"):
                r = dict(zip(cols, tuple(r)))
            uid = r["uid"]
            username = _row_plaintext(r.get("username")) or "user"
            to_addr = _row_plaintext(r.get("email"))
            # Abandoned signups are still cleaned up, but the old warning mail
            # and idle-stop branches are gone.
            if str(r.get("email_verified") or "0") != "1":
                c_at = _parse_iso(r.get("created_at"))
                if c_at and now >= c_at + timedelta(minutes=unverified_ttl):
                    _debug_print(f"[database] inactivity: deleted {username} — email never "
                          f"verified within {unverified_ttl}m of signup")
                    # Commit before handing off to a second session.
                    uconn.commit()
                    delete_user(uid)
                continue
            expires_at = _parse_iso(r.get("trial_expires_at"))
            if expires_at is None:
                base = _parse_iso(r.get("verified_at")) or _parse_iso(r.get("created_at"))
                if base is None:
                    continue
                expires_at = base + timedelta(days=renew_days)
                cur.execute("UPDATE users SET trial_expires_at=:now WHERE \"uid\"=:id",
                            {"now": expires_at.isoformat(), "id": uid})

            if to_addr and not r.get("inactive_warned_at") and now >= (expires_at - timedelta(days=warn_days)) and now < expires_at:
                days_left = max(1, (expires_at - now).days)
                uconn.commit()
                try:
                    send_trial_warning(to_addr, username, days_left=days_left,
                                       status="upcoming", expires_at=expires_at)
                except Exception as ex:
                    _debug_print(f"[database] trial warning mail failed for {username}: {ex}")
                else:
                    cur.execute("UPDATE users SET inactive_warned_at=:now WHERE \"uid\"=:id",
                                {"now": now.isoformat(), "id": uid})
                continue

            stopped = _parse_iso(r.get("bot_stopped_at"))
            if stopped is None and now >= expires_at:
                if to_addr:
                    uconn.commit()
                    try:
                        send_trial_warning(to_addr, username, days_left=1, status="expired",
                                           grace_days=grace_days)
                    except Exception as ex:
                        _debug_print(f"[database] trial expiry mail failed for {username}: {ex}")
                cur.execute("UPDATE users SET bot_stopped_at=:now, inactive_warned_at=NULL WHERE \"uid\"=:id",
                            {"now": now.isoformat(), "id": uid})
                _stop_trial_workloads(cur, uid, reason="Trial expired")
                continue

            if stopped is not None:
                if now < stopped + timedelta(days=grace_days):
                    continue
                cur.execute("SELECT COUNT(*) FROM bots WHERE \"uid\"=:id", {"id": uid})
                bot_count = cur.fetchone()[0] or 0
                try:
                    cur.execute("SELECT COUNT(*) FROM hosting_servers WHERE \"uid\"=:id", {"id": uid})
                    host_count = cur.fetchone()[0] or 0
                except Exception:
                    host_count = 0
                if bot_count == 0 and host_count == 0:
                    continue
                uconn.commit()
                _delete_trial_workloads(uid)
                continue
        uconn.commit()
    except Exception:
        traceback.print_exc()
    finally:
        uconn.close()


def set_bot_running(bot_id, running: bool):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE bots SET running=:r, last_error=NULL WHERE id=:id",
                    {"r": int(bool(running)), "id": bot_id})
        uconn.commit()
    finally:
        uconn.close()


def update_bot_runtime(bot_id, *, message_id=None, last_status=None, last_error=None):
    # Shared clock, not the local one: this write extends the tick lease, so
    # it has to be comparable with the cutoff every other engine computes.
    last_run = _shared_now()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        fields = {"last_run": last_run}
        if message_id is not None:
            fields["message_id"] = message_id
        if last_status is not None:
            fields["last_status"] = json.dumps(last_status)
        if last_error is not None:
            fields["last_error"] = last_error
        _BOT_TICK_COLUMNS = frozenset({
            "last_run", "message_id", "last_status", "last_error",
        })
        for k in fields:
            _validate_identifier(k, allow=_BOT_TICK_COLUMNS)
        sets = ", ".join(f"{k}=:{k}" for k in fields)
        vals = {**fields, "id": bot_id}
        cur.execute(f"UPDATE bots SET {sets} WHERE id=:id", vals)
        uconn.commit()
    finally:
        uconn.close()


def claim_bot_tick(bot_id, interval):
    """True for exactly one caller per bot per interval. Serialises N engines.

    One atomic conditional UPDATE on the existing bots.last_run column: the
    first engine to move last_run forward wins, everyone else sees rowcount 0.
    The comparison is a lexicographic string compare on an ISO-8601 UTC column,
    which is the same ordering trick used by expire_trial_bots().

    Both timestamps come from _shared_utcnow(), i.e. the database's clock, so
    two instances whose system clocks disagree still measure the lease against
    one clock. Without that, a host running a minute behind would compute a
    cutoff in the past and win a claim its peer had just taken — the two engines
    would publish the same bot seconds apart.
    """
    try:
        secs = int(interval)
    except (TypeError, ValueError):
        secs = 60
    base = _shared_utcnow()
    cutoff = (base - timedelta(seconds=max(0, secs))).isoformat()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE bots SET last_run=:now WHERE id=:id "
                    "AND (last_run IS NULL OR last_run <= :cutoff)",
                    {"now": base.isoformat(), "id": bot_id, "cutoff": cutoff})
        ok = cur.rowcount == 1
        uconn.commit()
    finally:
        uconn.close()
    return ok


def force_bot_claim(bot_id):
    """Take the lease unconditionally, for a publish that must happen now.

    A manual refresh has to go out whatever the schedule says, but it must not
    leave a window in which another engine also publishes. Clearing the lease
    would do exactly that: last_run NULL means the next tick on *any* instance
    is free to post, and it may do so within TICK_SECONDS of this publish.
    Stamping it forward instead reserves the bot for one interval, so the manual
    publish is the only one.
    """
    now = _shared_now()
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE bots SET last_run=:now WHERE id=:id",
                    {"now": now, "id": bot_id})
        uconn.commit()
    finally:
        uconn.close()


def clear_bot_claim(bot_id):
    """Drop the tick lease so the very next tick may publish immediately."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE bots SET last_run=NULL WHERE id=:id", {"id": bot_id})
        uconn.commit()
    finally:
        uconn.close()


def delete_bot(bot_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM bots WHERE id=:id", {"id": bot_id})
        uconn.commit()
    finally:
        uconn.close()


def _decrypt_hosting_row(d):
    """Decrypt the encrypted-at-rest hosting columns in place. Rows written
    before encryption landed pass through unchanged — see _dec_or_raw."""
    for k in ("name", "start_command", "code"):
        if k in d:
            d[k] = _dec_or_raw(d[k])
    return d


def create_hosting_server(user_id, name, runtime, start_command, code):
    """Create a hosting server row; returns the new server id, or None."""
    server_id = str(uuid.uuid4())
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "INSERT INTO hosting_servers(id, \"uid\", name, runtime, start_command, "
            "code, status, created_at) "
            "VALUES(:id,:uid_param,:name,:rt,:cmd,:code,'stopped',:cat)",
            {"id": server_id, "uid_param": user_id,
             "name": encrypt(name), "rt": runtime,
             "cmd": encrypt(start_command), "code": encrypt(code),
             "cat": _now()},
        )
        uconn.commit()
        return server_id
    except Exception as e:
        _debug_print(f"[database] create_hosting_server failed: {e}", file=sys.stderr)
        return None
    finally:
        uconn.close()


def update_hosting_server(server_id, *, name=None, runtime=None,
                          start_command=None, code=None):
    """Update the editable fields of one server; False if no such row."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        fields = {"updated_at": _now()}
        if name is not None:
            fields["name"] = encrypt(name)
        if runtime is not None:
            fields["runtime"] = runtime
        if start_command is not None:
            fields["start_command"] = encrypt(start_command)
        if code is not None:
            fields["code"] = encrypt(code)
        _HOSTING_UPDATE_COLUMNS = frozenset({
            "name", "runtime", "start_command", "code", "updated_at",
        })
        for k in fields:
            _validate_identifier(k, allow=_HOSTING_UPDATE_COLUMNS)
        sets = ", ".join(f"{k}=:{k}" for k in fields)
        cur.execute(f"UPDATE hosting_servers SET {sets} WHERE id=:id",
                    {**fields, "id": str(server_id)})
        ok = cur.rowcount == 1
        uconn.commit()
        return ok
    except Exception as e:
        _debug_print(f"[database] update_hosting_server failed for {server_id}: {e}",
              file=sys.stderr)
        return False
    finally:
        uconn.close()


def set_hosting_status(server_id, status, pid=None, last_error=None):
    """Move one server between lifecycle states.

    pid is written when given, cleared on stopped/error, and left untouched
    otherwise. last_error is only written when not None, so a caller that has
    nothing to say cannot clobber a previous error message.
    """
    fields = {"status": status, "updated_at": _now()}
    if pid is not None:
        fields["pid"] = pid
    elif status in ("stopped", "error"):
        fields["pid"] = None
    if last_error is not None:
        fields["last_error"] = last_error
    _HOSTING_STATUS_COLUMNS = frozenset({
        "status", "updated_at", "pid", "last_error",
    })
    for k in fields:
        _validate_identifier(k, allow=_HOSTING_STATUS_COLUMNS)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        sets = ", ".join(f"{k}=:{k}" for k in fields)
        cur.execute(f"UPDATE hosting_servers SET {sets} WHERE id=:id",
                    {**fields, "id": str(server_id)})
        uconn.commit()
    finally:
        uconn.close()


def delete_hosting_server(server_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM hosting_servers WHERE id=:id", {"id": str(server_id)})
        cur.execute("DELETE FROM hosting_backups WHERE server_id=:id",
                    {"id": str(server_id)})
        uconn.commit()
    finally:
        uconn.close()


def _decrypt_hosting_backup_row(d):
    if "payload" in d:
        d["payload"] = _dec_or_raw(d["payload"])
    return d


def create_hosting_backup(server_id, payload):
    """Store one snapshot, evicting the oldest beyond the per-server cap.
    Returns (backup_id, kept_count) or (None, kept_count) on failure."""
    backup_id = str(uuid.uuid4())
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "INSERT INTO hosting_backups(id, server_id, payload, created_at) "
            "VALUES(:id,:sid,:payload,:cat)",
            {"id": backup_id, "sid": str(server_id),
             "payload": encrypt(payload), "cat": _now()})
        cur.execute("SELECT id FROM hosting_backups WHERE server_id=:sid "
                    "ORDER BY created_at DESC, id",
                    {"sid": str(server_id)})
        ids = [r[0] for r in cur.fetchall()]
        too_many = ids[HOSTING_BACKUP_LIMIT:]
        for stale in too_many:
            cur.execute("DELETE FROM hosting_backups WHERE id=:id",
                        {"id": stale})
        uconn.commit()
        return backup_id, len(ids) - len(too_many)
    except Exception as e:
        _debug_print(f"[database] create_hosting_backup failed: {e}", file=sys.stderr)
        return None, 0
    finally:
        uconn.close()


def get_ad_enabled(conn=None):
    # Through get_setting so the value is decrypted; ads default to on when the
    # row has never been written.
    if conn is None:
        v = get_setting("ads_enabled")
    else:
        v = _get_setting_on(conn, "ads_enabled")
    if v is not None:
        return v == "1"
    return True


def set_ad_enabled(enabled: bool):
    set_setting("ads_enabled", "1" if enabled else "0")


def get_user_ads_disabled(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT ads_disabled FROM users WHERE \"uid\"=:id", {"id": str(user_id)})
        r = cur.fetchone()
        return int(r[0] or 0) if r else 0
    finally:
        uconn.close()


def set_user_ads_disabled(user_id, disabled: bool):
    val = int(bool(disabled))
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE users SET ads_disabled=:v WHERE \"uid\"=:id", {"v": val, "id": str(user_id)})
        uconn.commit()
    finally:
        uconn.close()


AD_ZONES = {
    "social_bar": "Social Bar",
    "banner_160x300": "Banner 160×300",
    "banner_468x60": "Banner 468×60",
    "banner_300x250": "Banner 300×250",
    "native": "Native Banner",
    "banner_160x600": "Banner 160×600",
    "leaderboard": "728×90 Leaderboard",
    "mobile": "320×50 Mobile",
    "popunder_entry": "Popunder (entry pages)",
}

# The ad networks' head loaders, mirroring ads_config.AD_NETWORKS. This module
# cannot import ads_config (the admin console vendors this file standalone), so
# the metadata is duplicated here exactly like AD_ZONES above.
#   default_on   — the network's state until an admin flips it (ad_network_<id>
#                  settings row); "default on" keeps the pre-switch behaviour.
#   configured   — whether the network is wired up to serve at all: a loader,
#                  or units that carry their own script as effectivecpm's do.
#                  Without either it can be toggled but nothing will ever
#                  load, so the console shows it as not-configured.
AD_NETWORKS = {
    "effectivecpm": {"label": "EffectiveCPM", "default_on": True, "configured": True},
    "adstera": {"label": "Adstera", "default_on": False, "configured": False},
    "vignette": {"label": "Vignette", "default_on": True, "configured": True},
    # AdSense's loader is built from the ADSENSE_CLIENT environment variable
    # rather than a literal in ads_config, so "configured" cannot be decided
    # here: this module is vendored standalone and deliberately imports nothing
    # from the app tier. The console shows it as configured and the switch
    # works; with the variable unset ads_config emits no loader, so flipping it
    # on simply has no effect until the publisher id is set.
    "adsense": {"label": "Google AdSense", "default_on": True, "configured": True},
}

# Which ad-block guard a page arms, as static/g7.js reads it from
# <body data-guard>. "gate" sends a blocked visitor to /blocked, "warn" shows a
# dismissible banner, "off" runs no detection and no third-party probes at all
# (the device fingerprint is computed either way). "blocked" is the blocked
# page's own mode, not a configuration value, so it is not offered here.
AD_GUARD_MODES = ("gate", "warn", "off")

# "gate" keeps the behaviour the site had when this was a literal in
# frontend.py. Changing it is the point of the setting, but an unwritten row
# must not change anything.
AD_GUARD_MODE_DEFAULT = "gate"

# Which pages may carry advertising, by Flask endpoint. This replaces the set
# frontend.py used to hardcode, _SENSITIVE_AD_ENDPOINTS: the six pages that set
# denied are still denied by default, so an unwritten table behaves exactly as
# the literal did, but the console can now turn any of them on or off without a
# deploy.
#
#   label       — what the console shows.
#   default_on  — the page's state until an admin flips it (ad_page_<endpoint>).
#
# Endpoints absent from this map are not ad-bearing pages and are never
# consulted; get_resolved_ad_pages only answers for keys listed here, so a
# typo'd row cannot silently enable advertising somewhere unexpected.
AD_PAGES = {
    "index": {"label": "Home", "default_on": True},
    "about": {"label": "About", "default_on": True},
    "hosting": {"label": "Hosting", "default_on": True},
    "contact": {"label": "Contact", "default_on": True},
    "help": {"label": "Help", "default_on": True},
    "blog": {"label": "Blog index", "default_on": True},
    "blog_post": {"label": "Blog post", "default_on": True},
    # No ad_unit slots, but terms.html calls ad_head(), and a network head loader
    # is ad code whether or not a slot follows it. Listed so the console can
    # govern that; without a row here
    # _ads_permitted() waves the page through and no switch reaches it. privacy
    # rides along for symmetry: it emits nothing today, so its switch is inert,
    # but the pair should not be one edit away from diverging again.
    "terms": {"label": "Terms (head loader only)", "default_on": True},
    "privacy": {"label": "Privacy (head loader only)", "default_on": True},
    # frontend.py used to deny advertising on all six of these unconditionally.
    # The four account pages below now default ON: they are where signed-in users
    # spend their time, and each already carries ad_unit slots the old denylist
    # left blank. They stay operator-flippable — the default just changed.
    "user_dashboard": {"label": "Dashboard (panel)", "default_on": True},
    "user_bot_editor": {"label": "Bot editor (panel)", "default_on": True},
    "user_bot_replies": {"label": "Bot replies (panel)", "default_on": True},
    "user_formatting": {"label": "Formatting help (panel)", "default_on": True},
    # Login and register stay OFF by default: they are credential-entry flows, and
    # third-party ad-network script does not belong next to a password field.
    # An operator can still turn them on.
    "user_login": {"label": "Sign in", "default_on": False},
    "user_register": {"label": "Register", "default_on": False},
}


def get_ad_guard_mode(conn=None):
    """The configured ad-block guard mode, always one of AD_GUARD_MODES.

    Validated on read as well as on write: the row is the only thing standing
    between a settings table and a <body data-guard> attribute, and a value the
    client does not recognise falls through to banner mode there rather than
    doing what the operator asked. An unwritten or unrecognised row answers with
    the default instead.
    """
    if conn is None:
        v = get_setting("ad_guard_mode")
    else:
        v = _get_setting_on(conn, "ad_guard_mode")
    if v in AD_GUARD_MODES:
        return v
    return AD_GUARD_MODE_DEFAULT


def set_ad_guard_mode(mode):
    if mode not in AD_GUARD_MODES:
        raise ValueError(f"unknown ad guard mode: {mode!r}")
    set_setting("ad_guard_mode", mode)


def get_ad_consent_required():
    """Whether the cookie banner must be accepted before any ad may render.

    Off by default: the site serves ads to a visitor who has not answered the
    banner yet and stops only on an explicit "decline". Turning it on restores
    opt-in behaviour — nothing renders until Accept is clicked — which is what a
    deployment under GDPR/ePrivacy consent rules wants. Either way a decline is
    honoured; this switch only decides what silence means.
    """
    return get_setting("ad_consent_required", "0") == "1"


def set_ad_consent_required(required: bool):
    set_setting("ad_consent_required", "1" if required else "0")


def get_ad_zone_enabled(zone_key):
    # A zone with no row has never been switched off, so it is on. The zone key is
    # part of the settings key, which stays plaintext — only the value moves.
    return get_setting(f"ad_zone_{zone_key}", "1") == "1"


def set_ad_zone_enabled(zone_key, enabled):
    set_setting(f"ad_zone_{zone_key}", "1" if enabled else "0")


def get_all_ad_zone_settings():
    """Every ad_zone_* row in one query, as {zone_key: bool}.

    get_ad_zone_enabled() is one round trip per zone, and a page render needs all
    of them at once — thirteen connections per view on Oracle. The key column is
    plaintext (see get_setting), so LIKE works here the same way get_smtp_config
    uses it. Zones with no row are left out; callers default them to on.
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key LIKE 'ad_zone_%'")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(r) if hasattr(r, "keys") else dict(zip(cols, r))
                for r in cur.fetchall()]
    except Exception as e:
        _debug_print(f"[ads] get_all_ad_zone_settings query failed: {e}")
        rows = []
    finally:
        uconn.close()
    out = {}
    for r in rows:
        key = r["key"][len("ad_zone_"):]
        if key in AD_ZONES:
            out[key] = _dec_or_raw(r["value"]) == "1"
    return out


def get_all_ad_zones():
    stored = get_all_ad_zone_settings()
    out = {}
    for key in AD_ZONES:
        out[key] = {"label": AD_ZONES[key], "enabled": stored.get(key, True)}
    return out


def get_resolved_ad_zones(user_id=None):
    """Which zones may actually render, after every switch is applied.

    Five things can turn a zone off, and the first one that says no wins:
    the global ads_enabled master switch, the per-user "All Ads" toggle, the
    ad networks (when EVERY network is off no advertising can work — the
    zone switches are only ever the fine grain), the global per-zone toggle,
    then that user's per-zone override. Passing no user_id resolves the
    anonymous case, which only sees the first, third and fourth.

    This is the single place that ordering lives — the console writes the rows
    and the frontend reads the answer, so neither has to re-derive it.
    """
    if not get_ad_enabled():
        return {key: False for key in AD_ZONES}
    if user_id is not None and get_user_ads_disabled(user_id):
        return {key: False for key in AD_ZONES}
    # The head-loader networks in AD_NETWORKS are the site's ad
    # providers. When every one of them is off, there is nothing to render
    # no matter what the zone switches say — a zone override cannot bring an
    # ad back onto a site whose providers are all switched off.
    if not any(get_resolved_ad_networks(user_id).values()):
        return {key: False for key in AD_ZONES}
    stored = get_all_ad_zone_settings()
    overrides = get_all_user_zone_overrides(user_id) if user_id is not None else {}
    out = {}
    for key in AD_ZONES:
        enabled = stored.get(key, True)
        if key in overrides:
            enabled = overrides[key]
        out[key] = enabled
    return out


def get_network_enabled(network):
    # A network with no row has never been switched off, so it follows its
    # config default. The network id is part of the settings key, which stays
    # plaintext — only the value moves (see get_setting).
    v = get_setting(f"ad_network_{network}")
    if v is not None:
        return v == "1"
    meta = AD_NETWORKS.get(network) or {}
    return bool(meta.get("default_on"))


def set_network_enabled(network, enabled):
    set_setting(f"ad_network_{network}", "1" if enabled else "0")


def get_all_network_settings():
    """Every ad_network_* row in one query, as {network: bool}.

    Same shape as get_all_ad_zone_settings(); networks with no row are left
    out and callers default them from AD_NETWORKS.
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key LIKE 'ad_network_%'")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(r) if hasattr(r, "keys") else dict(zip(cols, r))
                for r in cur.fetchall()]
    except Exception as e:
        _debug_print(f"[ads] get_all_network_settings query failed: {e}")
        rows = []
    finally:
        uconn.close()
    out = {}
    for r in rows:
        key = r["key"][len("ad_network_"):]
        if key not in AD_NETWORKS:
            continue
        v = _dec_or_raw(r["value"])
        # Unreadable row: skip, so the caller defaults it from AD_NETWORKS. Same
        # reasoning as get_all_ad_page_settings() — get_network_enabled() above
        # branches on None, and the two readers must not disagree about a row
        # neither of them can decrypt.
        if v is None:
            continue
        out[key] = v == "1"
    return out


def get_resolved_ad_networks(user_id=None):
    """Which head loaders may actually render, after every switch is applied.

    The network switch sits between the per-user "All Ads" toggle and the
    per-zone toggles: the master switch and the per-user toggle both kill the
    head loaders outright (they are advertising, after all), and anything
    still standing is decided by each network's own switch. Passing no
    user_id resolves the anonymous case.
    """
    if not get_ad_enabled():
        return {key: False for key in AD_NETWORKS}
    if user_id is not None and get_user_ads_disabled(user_id):
        return {key: False for key in AD_NETWORKS}
    stored = get_all_network_settings()
    return {key: stored.get(key, meta.get("default_on", False))
            for key, meta in AD_NETWORKS.items()}


def get_ad_page_enabled(endpoint):
    """Whether one page may carry advertising. Unknown endpoints answer False.

    Unknown means "not an ad-bearing page" rather than "no row yet", so it is a
    real no: AD_PAGES is the allowlist, exactly as AD_ZONES is for zones.
    """
    meta = AD_PAGES.get(endpoint)
    if meta is None:
        return False
    v = get_setting(f"ad_page_{endpoint}")
    if v is not None:
        return v == "1"
    return bool(meta.get("default_on"))


def set_ad_page_enabled(endpoint, enabled):
    if endpoint not in AD_PAGES:
        raise ValueError(f"unknown ad page: {endpoint!r}")
    set_setting(f"ad_page_{endpoint}", "1" if enabled else "0")


def get_all_ad_page_settings():
    """Every ad_page_* row in one query, as {endpoint: bool}.

    Same shape and the same reason as get_all_ad_zone_settings(): a render needs
    every page answer at once, and the key column is plaintext so LIKE works.
    Pages with no row are left out; callers default them from AD_PAGES.
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key LIKE 'ad_page_%'")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(r) if hasattr(r, "keys") else dict(zip(cols, r))
                for r in cur.fetchall()]
    except Exception as e:
        _debug_print(f"[ads] get_all_ad_page_settings query failed: {e}")
        rows = []
    finally:
        uconn.close()
    out = {}
    for r in rows:
        key = r["key"][len("ad_page_"):]
        if key not in AD_PAGES:
            continue
        v = _dec_or_raw(r["value"])
        # None means the row is there but unreadable — a NULL value column, or
        # ciphertext this key can no longer decrypt after a rotation. Comparing
        # that to "1" would answer False, which is the opposite of what
        # get_ad_page_enabled() says for the same row: it branches on None and
        # falls back to default_on. Left as == "1" the two readers disagree on
        # every default_on page, and the bulk one is the reader that renders, so
        # a rotation would quietly blank the content pages and show them as off
        # in the console. Skipping instead leaves the caller to default it, which
        # is the same answer the single-key getter gives.
        if v is None:
            continue
        out[key] = v == "1"
    return out


def get_all_ad_pages():
    """Every ad page with its label and current switch, for the console.

    default_on rides along so the console can group and annotate the rows without
    keeping its own copy of which pages start off — the same reason AD_GUARD_MODES
    is shipped in the payload rather than restated in the page. A page added here
    with default_on False then lands in the right group on its own.
    """
    stored = get_all_ad_page_settings()
    return {key: {"label": meta["label"],
                  "default_on": bool(meta.get("default_on")),
                  "enabled": stored.get(key, bool(meta.get("default_on")))}
            for key, meta in AD_PAGES.items()}


def get_resolved_ad_pages(user_id=None):
    """Which pages may render advertising, after every switch is applied.

    The page switch sits alongside the zone switches rather than above them: the
    master switch and the per-user toggle kill every page, and anything still
    standing is decided by that page's own row. A page being on does not make a
    zone render — both must agree — which is what lets the console say "no ads on
    the sign-in page" without touching the zones that page shares with the home
    page.
    """
    if not get_ad_enabled():
        return {key: False for key in AD_PAGES}
    if user_id is not None and get_user_ads_disabled(user_id):
        return {key: False for key in AD_PAGES}
    stored = get_all_ad_page_settings()
    return {key: stored.get(key, bool(meta.get("default_on")))
            for key, meta in AD_PAGES.items()}


def set_user_zone_override(user_id, zone_key, enabled):
    val = int(bool(enabled))
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM user_ad_zone_overrides WHERE \"uid\"=:id AND zone_key=:zk",
                    {"id": str(user_id), "zk": zone_key})
        cur.execute("INSERT INTO user_ad_zone_overrides(\"uid\",zone_key,enabled) VALUES(:id,:zk,:v)",
                    {"id": str(user_id), "zk": zone_key, "v": val})
        uconn.commit()
    finally:
        uconn.close()


def clear_user_zone_override(user_id, zone_key):
    """Drop a per-user zone override so the global zone toggle governs again."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM user_ad_zone_overrides WHERE \"uid\"=:id AND zone_key=:zk",
                    {"id": str(user_id), "zk": zone_key})
        uconn.commit()
    finally:
        uconn.close()


def get_all_user_zone_overrides(user_id):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT zone_key, enabled FROM user_ad_zone_overrides WHERE \"uid\"=:id",
                    {"id": str(user_id)})
        rows = cur.fetchall()
        overrides = {}
        for r in rows:
            if hasattr(r, "keys"):
                k = r["zone_key"]
                v = bool(r["enabled"])
            else:
                k = r[0]
                v = bool(r[1])
            overrides[k] = v
        return overrides
    finally:
        uconn.close()
        


def list_running_bots():
    # Explicit column list, not SELECT *: the engine re-reads every running bot
    # every 5s and last_status is a CLOB that oracledb materialises into a full
    # Python str (fetch_lobs = False) — and the tick never reads it, process_bot
    # overwrites it. These are exactly the keys engine.py touches on a tick.
    cols_sql = ("id, \"uid\", token_enc, channel_id, server_ip, server_port, "
                "edition, update_interval, message_id, embed_json, ip_reply_json, "
                "running, webhook_url")
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(f"SELECT {cols_sql} FROM bots WHERE running=1")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        uconn.close()
    out = []
    for d in rows:
        _decrypt_bot_row(d)
        d["token"] = decrypt(d.get("token_enc"))
        d["embed"] = _bot_json_obj(d.get("embed_json"), default_embed)
        d["ip_reply"] = _bot_json_obj(d.get("ip_reply_json"), default_ip_reply)
        out.append(d)
    return out


def list_all_bots():
    # The fleet view needs every bot (running or not) plus the name column the
    # engine tick never reads. Token is decrypted so the console can mask it —
    # same contract as list_running_bots().
    cols_sql = ("id, \"uid\", name, token_enc, channel_id, server_ip, server_port, "
                "edition, update_interval, guild_id, slot_index, message_id, "
                "running, last_error")
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(f"SELECT {cols_sql} FROM bots ORDER BY \"uid\", id")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        uconn.close()
    out = []
    for d in rows:
        _decrypt_bot_row(d)
        d["token"] = decrypt(d.get("token_enc"))
        out.append(d)
    return out


def get_all_sessions(limit=200):
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute(
            "SELECT id, \"uid\", ip_address, user_agent, created_at, last_access, expires_at FROM sessions ORDER BY created_at DESC",
        )
        rows = cur.fetchmany(limit)
        out = []
        for r in rows:
            d = {"id": r[0], "uid": r[1], "ip_address": r[2], "user_agent": r[3],
                 "created_at": r[4], "last_access": r[5], "expires_at": r[6]}
            # create_session() encrypts both of these, so the admin sessions list
            # rendered raw 'gAAAAA' tokens until this ran. Same treatment as the
            # per-user sibling, get_user_sessions().
            for col in ("ip_address", "user_agent"):
                val = d.get(col)
                if val and looks_encrypted(val):
                    d[col] = decrypt(val) or None
            out.append(d)
        return out
    finally:
        uconn.close()


def cleanup_expired_sessions():
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM sessions WHERE expires_at < :now", {"now": _now()})
        uconn.commit()
    finally:
        uconn.close()


_DEVICE_EVENTS_RETENTION_DAYS = 90
_FINGERPRINT_HISTORY_RETENTION_DAYS = 180
_PANEL_ACTIVITY_RETENTION_DAYS = 90
_HOSTING_BACKUPS_PER_SERVER = 5
# Mirrors panel_data.EXTERNAL_PLACEHOLDER, which cannot be imported here
# because panel_data imports this module.
_PANEL_MIRROR_PASSWORD_HASH = "external:oracle"


def cleanup_used_otps():
    """Remove leftover used OTP rows; live codes are deleted on first use."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM otp_codes WHERE used=1")
        uconn.commit()
    finally:
        uconn.close()


def cleanup_reviewed_device_events():
    """Remove device events that have been reviewed and are older than the
    retention window. Keeps the table from growing without bound."""
    cutoff = _days_ago(_DEVICE_EVENTS_RETENTION_DAYS)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM device_events WHERE reviewed=1 AND created_at < :cutoff",
                    {"cutoff": cutoff})
        uconn.commit()
    finally:
        uconn.close()


def cleanup_fingerprint_history():
    """Remove fingerprint history older than the retention window.  Each login
    appends a row; keeping 180 days is enough for device-trust audits."""
    cutoff = _days_ago(_FINGERPRINT_HISTORY_RETENTION_DAYS)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM fingerprint_history WHERE created_at < :cutoff",
                    {"cutoff": cutoff})
        uconn.commit()
    finally:
        uconn.close()


def cleanup_panel_activity():
    """Remove panel activity logs older than the retention window."""
    cutoff = _days_ago(_PANEL_ACTIVITY_RETENTION_DAYS)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("DELETE FROM panel_activity WHERE created_at < :cutoff",
                    {"cutoff": cutoff})
        uconn.commit()
    finally:
        uconn.close()


def cleanup_old_backups():
    """Keep only the most recent N backups per hosting server."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("""
            DELETE FROM hosting_backups WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY server_id ORDER BY created_at DESC
                    ) AS rn
                    FROM hosting_backups
                ) WHERE rn > :keep
            )
        """, {"keep": _HOSTING_BACKUPS_PER_SERVER})
        uconn.commit()
    finally:
        uconn.close()


def cleanup_orphaned_panel_data():
    """Remove panel children whose parent user was deleted from the main
    users table.  The FK cascades should handle this, but a schema built
        by an earlier migration can lack the constraint."""
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        # Only the mirror rows track a main users row: ensure_user_by_id
        # stamps them with the placeholder hash, while create_user mints
        # panel-native accounts that never exist in users at all.
        cur.execute("""
            DELETE FROM panel_users
             WHERE password_hash = :ext
               AND id NOT IN (SELECT "uid" FROM users)
        """, {"ext": _PANEL_MIRROR_PASSWORD_HASH})
        cur.execute("""
            DELETE FROM panel_servers WHERE user_id NOT IN (
                SELECT id FROM panel_users
            )
        """)
        cur.execute("""
            DELETE FROM panel_activity WHERE user_id NOT IN (
                SELECT id FROM panel_users
            )
        """)
        uconn.commit()
    finally:
        uconn.close()


def _days_ago(n):
    """ISO-8601 UTC timestamp for *n* days ago, matching the stored format."""
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def get_auto_ban_enabled():
    """Whether admin has enabled automatic banning on suspicious activity."""
    v = get_setting("auto_ban_enabled")
    if v is not None:
        return v == "1"
    return False


def set_auto_ban_enabled(enabled: bool):
    """Toggle automatic banning on/off."""
    set_setting("auto_ban_enabled", "1" if enabled else "0")


# ---------------------------------------------------------------------------
# Hosting panel controls
# ---------------------------------------------------------------------------
# Everything /panel used to read only from its own environment. PanelConfig is
# built once per process from env vars, so changing what the panel allows meant
# editing a unit file and restarting both load-balanced instances — and the two
# could silently disagree if only one was updated. These rows move the same
# decisions into the shared settings table, which both instances already read,
# so the admin console can change them for the whole fleet at once.
#
# Same storage contract as the ad switches above: one settings row per control,
# key plaintext (get_setting explains why) and value encrypted. A control with
# no row has never been set and falls back to the default below, so adding one
# of these keys never has to be migrated in.
#
# The panel still owns *enforcement* — these are the values it enforces, not a
# second implementation of it.
PANEL_FLAGS = {
    "maintenance": {
        "label": "Maintenance mode",
        "default": False,
        "detail": "Closes the panel: every page redirects to a maintenance notice, "
                  "the JSON APIs answer 503 and the live console is refused. "
                  "Containers keep running, and the message below is what users see.",
    },
    "registration": {
        "label": "Self-service registration",
        "default": False,
        "detail": "Whether visitors can create their own panel account.",
    },
    "activity_log": {
        "label": "Activity audit trail",
        "default": False,
        "detail": "Persist a row per user action (deploy, power, upload, command, "
                  "password change) to the shared store. The Activity page renders "
                  "empty while this is off.",
    },
    "deploys": {
        "label": "New deployments",
        "default": True,
        "detail": "Whether accounts may create new containers. Existing servers "
                  "keep running when this is off.",
    },
    "uploads": {
        "label": "File uploads",
        "default": True,
        "detail": "Whether the file manager accepts uploads and archive extraction.",
    },
    "console": {
        "label": "Console & commands",
        "default": True,
        "detail": "Whether the live console may attach and send commands into a "
                  "running container.",
    },
    # /panel serves script-src 'self' with no unsafe-eval, so a third-party ad
    # network's loader can never run there. A first-party promo is the only
    # advertising the panel can carry, which is why this switch lives here.
    "house_ads": {
        "label": "In-panel promotions",
        "default": True,
        "detail": "The panel's own promo slots: first-party markup, no "
                  "third-party ad script, no popunder. The site-wide ads_enabled "
                  "master switch also applies, so turning it off hides these too.",
    },
}

# The numbers the panel quotes and the node enforces. memory/cpu/disk were
# literals in three places at once — node_client.create_server, the deploy
# page's allocation card and the topbar — so the figure a user was shown and the
# figure their container actually got could drift apart. One row each, read by
# all three.
#
#   low / high  — the clamp applied on write *and* on read, so a row edited to
#                 something unusable outside this module still resolves to a
#                 value the node will accept.
PANEL_LIMITS = {
    "max_servers": {"label": "Servers per account", "default": 1,
                    "low": 0, "high": 1000, "unit": "servers"},
    "memory_mb": {"label": "Memory per server", "default": 300,
                  "low": 64, "high": 8192, "unit": "MB"},
    "cpu_percent": {"label": "CPU per server", "default": 35,
                    "low": 5, "high": 400, "unit": "% of a core"},
    "disk_mb": {"label": "Disk per server", "default": 600,
                "low": 128, "high": 20480, "unit": "MB"},
}

PANEL_MAINTENANCE_MESSAGE_DEFAULT = (
    "The panel is in maintenance. Your servers keep running; changes are "
    "paused for a short while."
)

# Long enough for a real explanation with a time window in it, short enough that
# it cannot push the banner over the whole page.
PANEL_MESSAGE_MAX_CHARS = 240


def _panel_key(kind, name):
    return f"panel_{kind}_{name}"


def _clamp_panel_limit(name, value):
    """A limit coerced into the range PANEL_LIMITS declares for it.

    Applied on read as well as on write: a row written by hand (or by an older
    build with different bounds) would otherwise hand the node a memory figure it
    rejects, and every deploy would fail with the panel showing the bad number
    back as if it were in force.
    """
    spec = PANEL_LIMITS.get(name)
    if not spec:
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return spec["default"]
    return max(spec["low"], min(parsed, spec["high"]))


def set_panel_flag(name, enabled):
    if name not in PANEL_FLAGS:
        raise ValueError(f"unknown panel flag: {name}")
    set_setting(_panel_key("flag", name), "1" if enabled else "0")


def get_panel_limit(name):
    """One panel limit, clamped, falling back to its declared default."""
    spec = PANEL_LIMITS.get(name)
    if not spec:
        return None
    v = get_setting(_panel_key("limit", name))
    if v is None:
        return spec["default"]
    return _clamp_panel_limit(name, v)


def set_panel_limit(name, value):
    if name not in PANEL_LIMITS:
        raise ValueError(f"unknown panel limit: {name}")
    clamped = _clamp_panel_limit(name, value)
    set_setting(_panel_key("limit", name), str(clamped))
    return clamped


def set_panel_maintenance_message(text):
    """Store the banner text. Empty restores the default rather than blanking it,
    so a maintenance mode that is on always has something to explain itself with."""
    cleaned = " ".join(str(text or "").split())[:PANEL_MESSAGE_MAX_CHARS]
    set_setting("panel_maintenance_message", cleaned)
    return cleaned or PANEL_MAINTENANCE_MESSAGE_DEFAULT


def get_panel_settings(conn=None):
    """Every panel control in one query, fully resolved.

    The panel reads all of these together on a request, and one round trip per
    control is a dozen Oracle connections per page — the same reason
    get_all_ad_zone_settings exists. Rows that are absent, unparseable or out of
    range resolve to their defaults here, so callers get a usable value for every
    key and never have to know which rows exist.

    LIKE 'panel_%' treats the underscore as a single-character wildcard, so the
    match is deliberately wider than the prefix; the keys are looked up in
    PANEL_FLAGS / PANEL_LIMITS below, which is what actually decides what counts.
    """
    if conn is not None:
        return _get_panel_settings_on(conn)
    uconn = _user_conn()
    try:
        return _get_panel_settings_on(uconn)
    finally:
        uconn.close()


def _get_panel_settings_on(conn):
    try:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key LIKE 'panel_%'")
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(r) if hasattr(r, "keys") else dict(zip(cols, r))
                for r in cur.fetchall()]
    except Exception as e:
        _debug_print(f"[panel] get_panel_settings query failed: {e}")
        rows = []

    stored = {}
    for r in rows:
        value = _dec_or_raw(r["value"])
        if value is not None:
            stored[r["key"]] = value

    flags = {}
    for name, spec in PANEL_FLAGS.items():
        raw = stored.get(_panel_key("flag", name))
        flags[name] = (raw == "1") if raw is not None else bool(spec["default"])

    limits = {}
    for name, spec in PANEL_LIMITS.items():
        raw = stored.get(_panel_key("limit", name))
        limits[name] = spec["default"] if raw is None else _clamp_panel_limit(name, raw)

    message = (stored.get("panel_maintenance_message") or "").strip()
    return {
        "flags": flags,
        "limits": limits,
        "maintenance_message": message or PANEL_MAINTENANCE_MESSAGE_DEFAULT,
    }


# The per-account exception to PANEL_LIMITS["max_servers"]. The fleet figure is
# one container per account; anything above that is granted here, per account,
# and the panel enforces it (panel_app/routes.py, user_max_servers).
#
# It lives on the panel's own panel_users row rather than in a settings row per
# account, because the panel already loads that row on every request that
# enforces the quota — so reading the grant costs no extra query, and a fleet of
# accounts costs one small NUMBER column instead of one settings row each.
#
# Three states, and the difference between the first two is the point:
#
#   NULL  no grant     — the account gets the fleet figure
#   0     switched off — an explicit decision, not the absence of one
#   N     exactly N, whatever the fleet figure moves to
#
# Deliberately *not* users.slots: that column counts Minecraft status-bot slots
# and update_user_slots cascades DELETE FROM bots off it, so writing a container
# grant through it would delete the account's bots.
PANEL_CONTAINER_SLOTS_HIGH = PANEL_LIMITS["max_servers"]["high"]

# Same placeholder panel_app/store.py writes into a mirrored row: an unusable
# hash, so a row this module creates holds an identity and not a credential and
# Oracle stays the only thing that can authenticate the user.
_PANEL_EXTERNAL_PLACEHOLDER = "external:oracle"

# panel_users.username is VARCHAR2(100) — panel_app/store.py USERNAME_MAX_CHARS.
_PANEL_USERNAME_MAX = 100

# Oracle errors meaning the panel's own schema is not there yet: the table
# (ORA-00942) or the column ensure_schema adds at panel startup (ORA-00904).
_PANEL_SCHEMA_MISSING = ("ORA-00942", "ORA-00904")


def _panel_container_slots(value):
    """A grant coerced to the shape the column holds: None, or 0..HIGH.

    Blank and None both mean "clear the grant", which is how the console spells
    "back to the fleet figure". Anything else has to be a number — a typo must
    not quietly become 0, which is the one value that switches hosting off.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"container slots must be a whole number or blank, got {value!r}")
    return max(0, min(parsed, PANEL_CONTAINER_SLOTS_HIGH))


def get_panel_container_slots(user_id):
    """One account's container grant, or None when it has none.

    None also covers "no panel_users row yet" and "the panel has not created its
    schema here yet": the row is written on first panel sign-in, and all three
    cases mean the same thing to the panel — use the fleet figure.
    """
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("SELECT container_slots FROM panel_users WHERE id=:id",
                    {"id": user_id})
        row = cur.fetchone()
    except Exception as e:
        if not any(tag in str(e) for tag in _PANEL_SCHEMA_MISSING):
            raise
        _debug_print(f"[panel] container grant unreadable, using the fleet figure: {e}")
        return None
    finally:
        uconn.close()
    if not row or row[0] is None:
        return None
    return max(0, min(int(row[0]), PANEL_CONTAINER_SLOTS_HIGH))


def set_panel_container_slots(user_id, slots):
    """Write one account's container grant. Returns the stored value.

    UPDATE first, and mirror a panel_users row when the account has none: that
    row is only created on first panel sign-in, so without this a grant could
    not be handed out until its owner had visited the panel once — which is the
    wrong way round, since the reason to raise the grant is usually that they
    are about to.
    """
    stored = _panel_container_slots(slots)
    username = None
    # Naive UTC, matching what the panel writes: SQLAlchemy renders
    # its DateTime as an Oracle DATE, which has nowhere to keep an
    # offset.
    created = _shared_utcnow().replace(tzinfo=None)
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        cur.execute("UPDATE panel_users SET container_slots=:slots WHERE id=:id",
                    {"slots": stored, "id": user_id})
        if cur.rowcount == 0:
            if stored is None:
                # Nothing to clear, and a row whose only content is "no grant"
                # is the row the panel would write anyway on first sign-in.
                return None
            # Read the name through the same cursor rather than get_user(): a
            # second connection here would be a second session out of a pool
            # sized for two.
            cur.execute("SELECT username FROM users WHERE \"uid\"=:id", {"id": user_id})
            account = cur.fetchone()
            if not account:
                raise ValueError(f"no such account: {user_id!r}")
            username = (_row_plaintext(account[0]) or str(user_id))[:_PANEL_USERNAME_MAX]
            cur.execute(
                """INSERT INTO panel_users
                       (id, username, password_hash, container_slots, created_at)
                   VALUES (:id, :username, :ph, :slots, :created)""",
                {"id": user_id, "username": username,
                 "ph": _PANEL_EXTERNAL_PLACEHOLDER, "slots": stored,
                 "created": created},
            )
        uconn.commit()
    except Exception as e:
        uconn.rollback()
        if "ORA-00001" in str(e):
            # The unique index on lower(panel_users.username) already holds this
            # name under a different id, which is a mirror that has not finished
            # migrating rather than a bad request. Said plainly instead of as an
            # Oracle code, because the fix is to that other row.
            raise ValueError(
                f"another panel row already holds the username {username!r}; "
                f"the grant cannot be stored until that row is reconciled"
            ) from e
        if any(tag in str(e) for tag in _PANEL_SCHEMA_MISSING):
            raise ValueError(
                "the panel's own tables are not in this schema yet — start the "
                "panel once so it creates them, then set the grant"
            ) from e
        raise
    finally:
        uconn.close()
    return stored


def verify_user_email(uid, verified=True):
    """Flip the email_verified flag. Called by the OTP flow with the default, and
    by the admin console in both directions when a user's mail never arrives.
    verified_at marks day 0 of the inactivity policy's registration clock; it is
    only stamped when the flag turns on."""
    now = _shared_now() if verified else None
    uconn = _user_conn()
    try:
        cur = uconn.cursor()
        if verified:
            cur.execute("UPDATE users SET email_verified=:v, verified_at=:now WHERE \"uid\"=:u_id",
                        {"v": 1, "now": now, "u_id": uid})
        else:
            cur.execute("UPDATE users SET email_verified=:v WHERE \"uid\"=:u_id",
                        {"v": 0, "u_id": uid})
        uconn.commit()
    finally:
        uconn.close()


if __name__ == "__main__":
    init_db()
    _debug_print("Oracle schema initialised")

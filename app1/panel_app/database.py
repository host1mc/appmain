"""The panel's own async SQLAlchemy engine — no longer borrowed from the host.

The panel used to ride the demo FastAPI app's ``app.database``: it imported that
module's ``Base`` (so ``panel_*`` tables joined the app's ``create_all``), its
``async_session`` (so ``OracleStore`` ran on the app's pool), and its
``init_db``/``close_db`` (so the panel tier's lifespan drove the app's engine).
That made the panel un-runnable without the whole ``app`` package on ``sys.path``.

This module gives the panel the same three symbols from its own engine, pointed
at the *same* Oracle database (same wallet, same ``.env``), so nothing about the
live connection changes — only which file owns it. ``init_db`` here imports the
panel's own :mod:`.oracle_models` and never the app's ``User``/``Item``/``Todo``,
so a panel-only process creates ``panel_users`` / ``panel_servers`` /
``panel_activity`` and nothing else.

The engine is built at import, exactly as the app's was, so importing this module
requires ORACLE_USER / ORACLE_PASSWORD / ORACLE_DSN in the environment. That is
only reached on the Oracle store path: ``__init__`` imports ``oracle_models``
(which imports ``Base`` from here) lazily, and only when ``PANEL_STORE=oracle``.
The SQLite smoke-test path never touches this file.
"""

import asyncio
import re
from os import environ
from pathlib import Path
from sys import stderr
from urllib.parse import quote_plus

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


# Harmless when the launcher already loaded the tree's .env by absolute path:
# load_dotenv never overrides a variable that is already set, so this only fills
# gaps for a process that imported the panel without going through asgi_panel.
load_dotenv()


def _build_database_url() -> str:
    # No host in the URL: the connect descriptor (ORACLE_DSN) and every wallet
    # detail are handed to the driver through connect_args by _connect_args()
    # below, so a full tcps descriptor with parentheses never has to survive URL
    # parsing. Only the credentials ride the URL.
    user = environ["ORACLE_USER"]
    password = environ["ORACLE_PASSWORD"]
    return f"oracle+oracledb_async://{quote_plus(user)}:{quote_plus(password)}@"


def _connect_args() -> dict:
    """Everything the thin driver needs to reach the ATP.

    ORACLE_DSN is the full connect descriptor. The ATP now accepts one-way TLS
    (mutual TLS not required), so the wallet is optional: only when wallet files
    are actually on disk do we point the driver at them for mTLS. Without them
    this is a walletless one-way TLS connection, the server certificate validated
    against the system CA store, and nothing is read from disk. The DB tier proved
    the wallet shape for the mTLS case; the walletless case needs only the dsn.
    """
    import oracledb

    oracledb.defaults.connect_timeout = 10
    dsn = (environ.get("ORACLE_DSN") or "").strip()
    # Try later DSNs if the primary is missing; live failover is in
    # create_engine below via pool_pre_ping + recreate.
    if not dsn:
        for idx in range(1, 8):
            extra = (environ.get(f"ORACLE_DSN_{idx}") or "").strip()
            if extra:
                dsn = extra
                break
    args = {"dsn": dsn}
    wallet_dir = Path(environ.get("ORACLE_WALLET_DIR", "./Wallet_ATP")).resolve()
    if wallet_dir.is_dir() and any(
        (wallet_dir / name).is_file()
        for name in ("cwallet.sso", "ewallet.pem", "ewallet.p12")
    ):
        environ["TNS_ADMIN"] = str(wallet_dir)
        args.update(
            config_dir=str(wallet_dir),
            wallet_location=str(wallet_dir),
            wallet_password=environ.get("ORACLE_WALLET_PASSWORD", "") or None,
        )
    return args


# Total Oracle sessions one panel process may hold. The panel is one pool among
# roughly ten pointed at an Always Free ATP, whose session budget is far smaller
# than a 10-plus-20 pool implies — app/database.py caps its own oracledb pool at
# 2-4 per tier for exactly that reason. ORACLE_POOL_MAX is the name that cap is
# already spelled with elsewhere in the fleet, so reusing it means the panel can
# be reined in from the deploy environment instead of a code edit.
#
# The number that matters is not per process, it is per *fleet*, and the panel
# multiplies by four: main.py runs this tier under two gunicorn workers, and there
# are two load-balanced instances. Four processes, each with its own engine and
# therefore its own pool. At this default the panel's worst case is 4 x 2 = 8
# sessions against a budget of roughly 20 shared with every other tier; the old
# default of 4 made that 16, and the old ceiling of 20 allowed 80 — enough for the
# panel alone to answer ORA-00018 to the entire fleet.
_POOL_MAX_DEFAULT = 2

# Hard ceiling on that per-process total, whatever the environment asks for.
# ORACLE_POOL_MAX is read by app/database.py too, where it sizes a pool with
# min=0 that hands idle sessions back; raising it there for the web tiers must not
# silently quadruple the panel. PANEL_ORACLE_POOL_MAX overrides it for this tier
# alone.
_POOL_MAX_CEILING = 4


def _pool_max() -> int:
    configured = (environ.get("PANEL_ORACLE_POOL_MAX") or "").strip()
    if not configured:
        configured = (environ.get("ORACLE_POOL_MAX") or "").strip()
    try:
        value = int(configured or _POOL_MAX_DEFAULT)
    except ValueError:
        value = _POOL_MAX_DEFAULT
    return max(2, min(value, _POOL_MAX_CEILING))


_pool_total = _pool_max()
# One connection stays warm, never zero: QueuePool reads pool_size=0 as
# "unlimited", which against this database would be a way to exhaust the fleet's
# session budget rather than a way to save one session.
_pool_size = 1
engine_kwargs = {
    "echo": False,
    # One connection stays warm; the rest is burst capacity that is handed back to
    # the database rather than held open for the life of the process. QueuePool
    # never closes a connection that has been checked back in — pool_recycle only
    # acts at the next checkout — so pool_size, unlike max_overflow, is a session
    # this process squats on while completely idle.
    "pool_size": _pool_size,
    "max_overflow": _pool_total - _pool_size,
    "pool_pre_ping": True,
    # Without this, a request that arrives once every session is checked out
    # waits forever and the tier hangs instead of reporting pool exhaustion.
    "pool_timeout": 30,
    # ATP closes idle sessions on its own. Replacing a connection older than this
    # keeps pool_pre_ping from being the only thing standing between a request
    # and a session the database has already torn down.
    "pool_recycle": 1800,
}

engine = create_async_engine(
    _build_database_url(), connect_args=_connect_args(), **engine_kwargs
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _init_db_allowed() -> bool:
    """Whether this process may run the explicit :func:`init_db`.

    The token set asgi_panel spelled while PANEL_INIT_DB gated the panel's only
    DDL. It no longer gates the schema repair — :func:`ensure_schema` runs on
    every start, because a panel whose table is missing a column it selects is
    broken for every visitor until the DDL runs, and nothing else was running it.
    """
    return environ.get("PANEL_INIT_DB", "").strip().lower() in ("1", "true", "yes", "on")


# The DDL that adds a model column to an already-existing panel table, keyed by
# Oracle-uppercase table then column. ``create_all`` is check-first at *table*
# level, so a table created before a column was added to the model never gains it
# — which is why a schema predating the desired-state feature answered
# ORA-00904 "PANEL_SERVERS"."DESIRED_STATE" to every panel page that lists
# servers: all of them select that column. The DDL here is what
# migrations/002_panel_servers_desired_state.sql issues by hand;
# :func:`ensure_schema` issues it at startup instead, so a deploy needs no
# hand-run migration step and cannot be started without one.
#
# An entry is needed per column because ensure_schema will not invent DDL for a
# live shared table: a NOT NULL with no default would fail on a table with rows,
# and a foreign key or unique constraint is a lock and a backfill decision, not a
# spelling. A model column with no entry here is reported at startup instead.
_ADDITIVE_COLUMNS = {
    "PANEL_USERS": {
        # Nullable and with no default, which is the one shape of ADD that is
        # always metadata-only on a populated table: every existing account reads
        # NULL, meaning "no per-account grant — use the fleet figure", which is
        # exactly the behaviour they had before this column existed. NUMBER(4)
        # rather than a bare NUMBER because the value is clamped to 1000 on both
        # write and read, and a precision Oracle can hold in two bytes is smaller
        # in every row than the unconstrained NUMBER a Column(Integer) would emit.
        "CONTAINER_SLOTS": "NUMBER(4) NULL",
    },
    "PANEL_SERVERS": {
        # NUMBER rather than INTEGER: NUMBER is what SQLAlchemy's Oracle dialect
        # emits for Column(Integer), so a table built by create_all and a table
        # repaired here end up the same shape. On ATP an ADD of a NOT NULL column
        # carrying a DEFAULT is metadata-only — existing rows read 0 ("stopped",
        # which is the safe reading of intent) with no table rewrite.
        "DESIRED_STATE": "NUMBER DEFAULT 0 NOT NULL",
        "NODE_ID": "NUMBER NULL",
        # Nullable, no default: every existing row reads NULL, which means "no
        # delivery configured" — the same shape as CONTAINER_SLOTS above, so the
        # ADD is metadata-only even on a populated table. 2048 CHAR holds the
        # JSON wrapper plus two Fernet ciphertexts (a 512-char webhook URL
        # encrypts to ~760 bytes of base64).
        "DELIVERY_CONFIG": "VARCHAR2(2048 CHAR) NULL",
    },
}

# Oracle errors meaning "another process already did exactly this". Four panel
# processes (two workers on each of two load-balanced instances) start at once and
# every one of them runs ensure_schema, so losing the race is the ordinary case
# rather than an error: ORA-00955 is a table the winner created, ORA-01430 a
# column. Either way the state this call wanted is the state the schema is in.
_ALREADY_THERE = ("ORA-00955", "ORA-01430")

# Oracle errors meaning "another session holds the lock this DDL needs". Oracle
# commits DDL itself, so the winner is done in milliseconds and a loser that waits
# gets its turn.
_LOCKED = ("ORA-00054", "ORA-04021", "ORA-04020")

# Attempts per statement before giving up on the lock.
_DDL_TRIES = 8


async def _ddl(sql, *, describe):
    """Run one DDL statement, tolerating the four-process startup race.

    Each attempt takes its own connection: a failed statement leaves a
    SQLAlchemy transaction that has to be rolled back before the same connection
    accepts anything else, and the whole point here is to keep going after the
    failures that mean "already done".
    """
    from sqlalchemy import text

    for _ in range(_DDL_TRIES):
        try:
            async with engine.begin() as conn:
                await conn.execute(text(sql))
            print(f"[panel] schema: {describe}")
            return
        except Exception as exc:
            msg = str(exc)
            if any(tag in msg for tag in _ALREADY_THERE):
                return
            if not any(tag in msg for tag in _LOCKED):
                raise
            await asyncio.sleep(1.0)
    raise RuntimeError(f"could not lock the table to {describe} after {_DDL_TRIES} tries")


async def _create_missing_tables():
    from . import oracle_models  # noqa: F401  (import registers the tables)

    for _ in range(_DDL_TRIES):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            return
        except Exception as exc:
            msg = str(exc)
            # create_all does its own has_table check per table, so this is the
            # window between that check and the CREATE, not a repeat of it.
            if any(tag in msg for tag in _ALREADY_THERE):
                return
            if not any(tag in msg for tag in _LOCKED):
                raise
            await asyncio.sleep(1.0)
    raise RuntimeError(f"could not create the panel tables after {_DDL_TRIES} tries")


async def _rows(sql, **params):
    from sqlalchemy import text

    async with engine.connect() as conn:
        result = await conn.execute(text(sql), params)
        return [row[0].upper() for row in result]


async def ensure_schema():
    """Bring the panel's three tables up to what the models expect.

    Three things, all additive, all safe on every start:

    * a panel table this schema does not have at all is created by
      ``create_all`` — the "if it does not exist, create it" half;
    * a table that *is* there but predates a column the model has gained is
      ALTERed to add that column, from the DDL in :data:`_ADDITIVE_COLUMNS`.
      ``create_all`` checks at table level only, so it can never do this, and
      until now the only thing that did was a hand-run SQL migration — one that a
      deploy could, and did, start without;
    * a model column that is missing and has no DDL here is printed as a warning
      naming the column, so the next drift of this kind is a line in the startup
      log rather than an ORA-00904 a visitor finds.

    Runs on every Oracle-path start rather than behind PANEL_INIT_DB. What it
    issues is a CREATE for a table that is missing and an ADD for a column that
    is missing, so on the normal path — schema already matching the models — it
    issues no DDL at all and costs one catalog SELECT per panel table plus one.
    When something *is* missing, every process that notices converges on the same
    state (see _ALREADY_THERE), and the alternative was a panel that starts clean
    and then answers ORA-00904 to every page listing servers.
    """
    from . import oracle_models  # noqa: F401  (import registers the tables)

    wanted = {name.upper() for name in Base.metadata.tables}
    present = set(await _rows("SELECT table_name FROM user_tables")) & wanted
    missing = wanted - present
    if missing:
        print(f"[panel] schema: creating {', '.join(sorted(t.lower() for t in missing))}")
        await _create_missing_tables()

    for name, table in Base.metadata.tables.items():
        # A table create_all just built already carries every column its model
        # declares — and so does one the winner of that race built.
        if name.upper() not in present:
            continue
        have = set(
            await _rows(
                "SELECT column_name FROM user_tab_columns WHERE table_name = :t",
                t=name.upper(),
            )
        )
        known = _ADDITIVE_COLUMNS.get(name.upper(), {})
        # Compared against the model rather than against the spec, so a column
        # added to a model with no matching entry below is reported here instead of
        # being discovered by a visitor as ORA-00904.
        for column in table.columns:
            if column.name.upper() in have:
                continue
            column_type = known.get(column.name.upper())
            if not column_type:
                print(
                    f"[panel] WARNING: {name}.{column.name} is in the model but not in "
                    f"the database, and _ADDITIVE_COLUMNS in panel_app/database.py has "
                    f"no DDL for it. Every query selecting it will fail with ORA-00904 "
                    f"until the column is added (declared type: {column.type}).",
                    file=stderr,
                )
                continue
            if not _IDENTIFIER_RE.fullmatch(name.upper()) or not _IDENTIFIER_RE.fullmatch(column.name.upper()):
                raise ValueError(f"invalid SQL identifier in DDL: {name!r}.{column.name!r}")
            await _ddl(
                f"ALTER TABLE {name.upper()} ADD ({column.name.upper()} {column_type})",
                describe=f"added {name}.{column.name}",
            )


async def init_db():
    """Create the panel's tables — and only the panel's tables.

    The explicit, gated entry point, kept because ``migrations/README.md`` and
    both migration scripts tell an operator to start the panel once with
    PANEL_INIT_DB=1 to build a fresh schema. It is no longer the only way the
    panel's tables come into being: :func:`ensure_schema` runs on every start and
    creates a missing table itself, so this adds nothing on a normal boot.

    Importing :mod:`.oracle_models` registers ``PanelUser`` / ``PanelServer`` /
    ``PanelActivity`` on ``Base.metadata``; ``create_all`` is check-first, so a
    restart with them already present is a no-op.
    """
    if not _init_db_allowed():
        raise RuntimeError(
            "refusing to run panel DDL: PANEL_INIT_DB is not set. create_all here "
            "is DDL against the shared production schema and four processes (two "
            "workers on each of two instances) would race it."
        )
    await ensure_schema()


async def close_db():
    await engine.dispose()

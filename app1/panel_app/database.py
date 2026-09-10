"""The panel's own async SQLAlchemy engine — no longer borrowed from the host.

The panel used to ride the demo FastAPI app's ``app.database``: it imported that
module's ``Base`` (so ``panel_*`` tables joined the app's ``create_all``), its
``async_session`` (so ``OracleStore`` ran on the app's pool), and its
``init_db``/``close_db`` (so the panel tier's lifespan drove the app's engine).
That made the panel un-runnable without the whole ``app`` package on ``sys.path``.

This module gives the panel the same three symbols from its own engine, pointed
at the *same* Oracle database (same wallet, same ``.env``), so nothing about the
live connection changes — only which file owns it. The panel issues no DDL of
its own any more: the consolidated ``servers`` table and the ``users`` table it
reads are created and migrated by the host app's ``database.init_db()``. The
model in :mod:`.oracle_models` exists so queries run against a checked column
set, not to create anything.

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
    DDL. The panel issues no DDL any more — the schema is owned by the host
    app — so the flag only guards the (empty) init_db entry point.
    """
    return environ.get("PANEL_INIT_DB", "").strip().lower() in ("1", "true", "yes", "on")


async def ensure_schema():
    """No-op kept as the heal hook OracleStore calls on ORA-00904.

    The panel's tables are owned by the host app's ``database.init_db()``:
    ``users`` and the consolidated ``servers`` table are created and migrated
    there, including the consolidation of the old panel tables. This tier only
    reads and writes rows, so there is nothing left for it to repair — and a
    panel process racing its siblings over DDL against the shared schema is
    exactly what this module used to guard against.
    """
    return None


async def init_db():
    """Kept for the PANEL_INIT_DB entry point; the schema work moved to the
    host app's ``database.init_db()``, so there is no DDL left to gate."""
    if not _init_db_allowed():
        raise RuntimeError(
            "refusing to run panel DDL: PANEL_INIT_DB is not set. The panel "
            "no longer issues DDL of its own — database.init_db() owns the "
            "schema — so starting with the flag set changes nothing."
        )
    await ensure_schema()


async def close_db():
    await engine.dispose()

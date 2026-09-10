"""One async storage interface for the panel, with two backends.

``routes.py`` calls exactly one object — ``runtime.database`` — and both
backends expose the same coroutine methods returning the same plain dicts, so
selecting a backend is a config change and the route layer never knows which
one it got:

* :class:`OracleStore` (``PANEL_STORE=oracle``, the default when Oracle is on)
  reads the shared Oracle schema: accounts come from the main ``users`` table
  (through ``app/database.py``, which owns the decryption) and servers from
  the consolidated ``servers`` table. This is what makes the panel work across
  both load-balanced instances: a server created on instance A is listed by
  instance B.
* :class:`SqliteStore` (``PANEL_STORE=sqlite``) wraps the synchronous
  :class:`~panel_app.panel_database.PanelDatabase` in ``run_in_threadpool``. It
  exists for the laptop smoke test, where there is no Oracle connection.

Dicts, not ORM objects, are deliberate: the Jinja templates index rows like
``server.name`` and ``created_at`` is rendered directly, so every backend
normalises timestamps to the same ISO-8601 string SQLite produced.

The servers table keeps only identity, owner, intent and placement. The
runtime, version, image and startup command live inside the container and are
read from the node, so neither store can hand a database read out as
deployment detail.
"""

from datetime import datetime, timezone

from starlette.concurrency import run_in_threadpool


# Ceiling on one user's server list. This has to stay comfortably above
# MAX_SERVERS_PER_USER, because routes.py enforces that quota by counting the
# rows this returns — a cap at or below the quota would silently read as "under
# the limit" and let a user exceed it. It is a runaway guard, not a page size.
SERVER_LIST_MAX = 200

# Width of servers.name in the shared schema.
NAME_MAX_CHARS = 255

# Written into the user dicts the Oracle backend returns as ``password_hash``.
# It is not a valid PBKDF2 string, so no panel-local verify_password can ever
# accept it — Oracle-backed accounts are authenticated by the main site and
# nothing else.
EXTERNAL_PLACEHOLDER = "external:oracle"


def _clip_text(value, max_chars):
    """Clip text to what a ``VARCHAR2(max_chars)`` column accepts either way."""
    text = str(value)
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        text = text.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    text = text[:max_chars]
    encoded = text.encode("utf-8")
    if len(encoded) <= max_chars:
        return text
    return encoded[:max_chars].decode("utf-8", "ignore")


def _user_key(user_id) -> str:
    """Normalise a user id for binding and comparison.

    ``servers.uid`` holds the main site's own user id, so every id is bound as
    text. An unusable value normalises to ``""``, which matches no row, so a
    caller with junk gets "not found" instead of a driver error.
    """
    if user_id is None:
        return ""
    key = str(user_id).strip()
    return key if len(key) <= 36 else ""


def _utc_now() -> datetime:
    # Naive UTC: the schema's DATE columns have nowhere to keep an offset.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value) -> str:
    """Normalise a stored timestamp to the ISO string the templates render."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _main_user_dict(account):
    """A main-site users row in the shape the panel tier expects."""
    if not account:
        return None
    slots = account.get("container_slots")
    return {
        "id": account.get("uid"),
        "username": account.get("username") or "",
        "password_hash": EXTERNAL_PLACEHOLDER,
        # Left as None when the column is NULL rather than coerced to 0: the
        # two mean opposite things (no grant, versus hosting switched off),
        # and every reader of this key tells them apart.
        "container_slots": (None if slots is None else int(slots)),
        "created_at": _iso(account.get("created_at")),
    }


class SqliteStore:
    """Async facade over the synchronous SQLite :class:`PanelDatabase`."""

    def __init__(self, database):
        self._db = database
        # Exposed so the smoke test and the existing tests can still reach the
        # synchronous object directly.
        self.sync = database

    async def initialize(self):
        await run_in_threadpool(self._db.initialize)

    async def create_user(self, username, password_hash):
        return await run_in_threadpool(self._db.create_user, username, password_hash)

    async def ensure_user_by_id(self, user_id, username):
        import sqlite3

        from .auth import MirrorConflict

        key = _user_key(user_id)
        try:
            return await run_in_threadpool(self._db.ensure_user_by_id, key, username)
        except sqlite3.IntegrityError as exc:
            row = await run_in_threadpool(self._db.get_user, key)
            if row is None:
                raise MirrorConflict("panel user mirror row could not be written") from exc
            return row

    async def get_user_by_username(self, username):
        return await run_in_threadpool(self._db.get_user_by_username, username)

    async def get_user(self, user_id):
        return await run_in_threadpool(self._db.get_user, user_id)

    async def update_user_password(self, user_id, password_hash):
        return await run_in_threadpool(self._db.update_user_password, user_id, password_hash)

    async def can_place_new_server(self):
        # There is no node registry on this path and nothing to place onto: the
        # SQLite backend is the laptop smoke test, where the containers run on the
        # machine serving the panel. Unconditional True is the answer, not a stub.
        return True

    async def get_node_credentials(self, node_id):
        return None

    async def create_server(self, **kwargs):
        return await run_in_threadpool(lambda: self._db.create_server(**kwargs))

    async def list_servers_for_user(self, user_id):
        return await run_in_threadpool(self._db.list_servers_for_user, user_id)

    async def all_server_ids(self):
        fn = getattr(self._db, "all_server_ids", None)
        if fn is None:
            return []
        return await run_in_threadpool(fn)

    async def get_server_for_user(self, server_id, user_id):
        return await run_in_threadpool(self._db.get_server_for_user, server_id, user_id)

    async def delete_server_for_user(self, server_id, user_id):
        return await run_in_threadpool(self._db.delete_server_for_user, server_id, user_id)

    async def update_server_name(self, server_id, user_id, name):
        return await run_in_threadpool(self._db.update_server_name, server_id, user_id, name)

    async def update_server_state(self, server_id, user_id, running):
        return await run_in_threadpool(self._db.update_server_state, server_id, user_id, running)


class OracleStore:
    """Panel storage in the shared Oracle schema: main ``users`` + ``servers``."""

    def __init__(self, session_factory=None):
        # Injectable so tests can pass a sessionmaker bound to any engine.
        self._session_factory = session_factory
        # True after the first successful ensure_schema — gates the one-shot
        # self-healing retry below so a fresh process always tries the repair
        # once before giving up.
        self._schema_verified = False

    # -- plumbing ----------------------------------------------------------

    def _sessions(self):
        if self._session_factory is None:
            from .database import async_session

            self._session_factory = async_session
        return self._session_factory

    async def _heal_schema(self):
        if self._schema_verified:
            return
        from .database import ensure_schema

        self._schema_verified = True
        await ensure_schema()

    async def _run_with_heal(self, coro_factory):
        """Execute an async operation, healing the schema on ORA-00904 once."""
        try:
            return await coro_factory()
        except Exception as exc:
            msg = str(exc)
            if "ORA-00904" not in msg:
                raise
            await self._heal_schema()
            return await coro_factory()

    @staticmethod
    def _server_dict(row):
        if row is None:
            return None
        return {
            "id": row.id,
            "user_id": row.uid,
            "name": row.name,
            # The column is `status` — the owner's power intent — but the
            # routes and templates read it under its historical key.
            "desired_state": int(row.status or 0),
            "created_at": _iso(row.created_at),
            "node_id": None if row.node_id is None else int(row.node_id),
        }

    async def initialize(self):
        """No DDL here — database.init_db() owns the schema. Importing the
        models registers the table on the metadata ensure_schema compares."""
        from . import oracle_models  # noqa: F401  (import registers the table)

    # -- users -------------------------------------------------------------

    async def ensure_user_by_id(self, user_id, username):
        """Return the signed-in account's main-site row, or None.

        Panel sign-in comes through the main site's session, so the account
        row already exists by the time the panel asks — there is no mirror
        row left to write. A None answer reads as "not signed in" upstream.
        """
        return await self.get_user(user_id)

    async def get_user(self, user_id):
        key = _user_key(user_id)
        if not key:
            return None

        def _read():
            import database
            return _main_user_dict(database.get_user(key))

        return await run_in_threadpool(_read)

    async def get_user_by_username(self, username):
        normalized = (username or "").strip()
        if not normalized:
            return None

        def _read():
            import database
            return _main_user_dict(database.get_user_by_username(normalized))

        return await run_in_threadpool(_read)

    async def create_user(self, username, password_hash):
        # Panel-native accounts exist only in the SQLite smoke store; against
        # the shared schema an account is created by the main site's signup.
        raise ValueError(
            "panel-native accounts are not created in the Oracle store; "
            "sign up on the main site instead"
        )

    async def update_user_password(self, user_id, password_hash):
        # The main site owns the credential; this path only runs in the
        # local (SQLite) auth mode. Nothing to change here.
        return False

    # -- placement ---------------------------------------------------------

    async def can_place_new_server(self):
        """Whether any enabled node still has room for one more server.

        Answered by node_registry.placement_capacity_available — the same
        call the backend store reaches over HTTP — so both Oracle-backed
        backends answer from one implementation of the rule.
        """
        import node_registry

        return bool(await run_in_threadpool(node_registry.placement_capacity_available))

    async def get_node_credentials(self, node_id):
        import node_registry

        def _read():
            return node_registry.get_node_credentials(node_id)

        return await run_in_threadpool(_read)

    # -- servers -----------------------------------------------------------

    async def create_server(
        self, *, server_id, user_id, name, runtime=None, version=None,
        image=None, startup=None
    ):
        """Insert the server's identity row.

        runtime / version / image / startup are accepted for caller
        compatibility and deliberately not stored: the container carries them
        and the panel lists them from the node.
        """
        owner = _user_key(user_id)
        if not owner:
            # An ownerless row is the one shape of servers that no route could
            # ever reach again: every read is filtered by owner. Refuse before
            # the row exists — routes.py treats a ValueError here as "nothing
            # was created" and takes the container back down.
            raise ValueError("a server row requires an owner")

        async def _insert():
            import node_registry
            from .oracle_models import Server as _Server

            def _place():
                with node_registry._placement_mutex:
                    return node_registry.pick_node_for_new_server()

            try:
                node_id = await run_in_threadpool(_place)
            except node_registry.NodeCapacityError as exc:
                err = ValueError(str(exc))
                err.code = "node_capacity_exhausted"
                raise err from exc
            async with self._sessions()() as db:
                db.add(
                    _Server(
                        id=server_id,
                        uid=owner,
                        name=_clip_text((name or "").strip(), NAME_MAX_CHARS),
                        status=0,
                        created_at=_utc_now(),
                        node_id=node_id,
                    )
                )
                await db.commit()
            return node_id

        return await self._run_with_heal(_insert)

    async def list_servers_for_user(self, user_id):
        from sqlalchemy import select

        from .oracle_models import Server

        owner = _user_key(user_id)
        if not owner:
            return []

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(
                    select(Server)
                    .where(Server.uid == owner)
                    .order_by(Server.created_at.desc())
                    .limit(SERVER_LIST_MAX)
                )
                return [self._server_dict(row) for row in result.scalars().all()]

        return await self._run_with_heal(_query)

    async def all_server_ids(self):
        """Every live server id across all owners — the authoritative allowlist
        the node reconcile sweep checks its managed containers against. Not
        owner-scoped on purpose: an orphan has no owner row left to scope by,
        which is exactly why it needs reaping.
        """
        from sqlalchemy import select

        from .oracle_models import Server

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(select(Server.id))
                return [str(sid) for sid in result.scalars().all() if sid]

        return await self._run_with_heal(_query)

    async def get_server_for_user(self, server_id, user_id):
        from sqlalchemy import select

        from .oracle_models import Server

        owner = _user_key(user_id)
        if not owner or not server_id:
            # Both halves are required: the node agent performs no ownership
            # check of its own, so this pairing is the whole authorization.
            return None

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(
                    select(Server).where(Server.id == server_id, Server.uid == owner)
                )
                return self._server_dict(result.scalar_one_or_none())

        return await self._run_with_heal(_query)

    async def delete_server_for_user(self, server_id, user_id):
        from sqlalchemy import delete

        from .oracle_models import Server

        owner = _user_key(user_id)
        if not owner or not server_id:
            return False

        async def _do_delete():
            async with self._sessions()() as db:
                result = await db.execute(
                    delete(Server).where(Server.id == server_id, Server.uid == owner)
                )
                await db.commit()
                return (result.rowcount or 0) == 1

        return await self._run_with_heal(_do_delete)

    async def _update_server(self, server_id, user_id, values):
        from sqlalchemy import update

        from .oracle_models import Server

        owner = _user_key(user_id)
        if not owner or not server_id:
            return False

        async def _do_update():
            async with self._sessions()() as db:
                result = await db.execute(
                    update(Server)
                    .where(Server.id == server_id, Server.uid == owner)
                    .values(**values)
                )
                await db.commit()
                return (result.rowcount or 0) == 1

        return await self._run_with_heal(_do_update)

    async def update_server_name(self, server_id, user_id, name):
        return await self._update_server(
            server_id, user_id, {"name": _clip_text((name or "").strip(), NAME_MAX_CHARS)}
        )

    async def update_server_state(self, server_id, user_id, running):
        """Record the owner's last power intent: 1 running, 0 stopped.

        Written after the node accepts a power action, so the stored value tracks
        what was actually commanded rather than what was merely attempted. Read on
        every load so a stopped server stays presented as stopped.
        """
        return await self._update_server(
            server_id, user_id, {"status": int(bool(running))}
        )


def build_store(config, *, database=None, session_factory=None):
    """Pick the backend named by ``config.store``.

    ``database`` is the synchronous :class:`PanelDatabase` used by the sqlite
    backend; ``session_factory`` lets a test bind the Oracle backend to its own
    engine. Neither backend touches the network here — :meth:`initialize` does.
    """
    if config.store == "oracle":
        return OracleStore(session_factory=session_factory)
    if config.store == "backend":
        from .backend_store import BackendStore

        return BackendStore(config)
    return SqliteStore(database)

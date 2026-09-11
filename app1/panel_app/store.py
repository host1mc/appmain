"""One async storage interface for the panel, with two backends.

``routes.py`` calls exactly one object — ``runtime.database`` — through 24 call
sites. Both backends expose the *same* 18 coroutine methods returning the same
plain dicts, so selecting a backend is a config change and the route layer never
knows which one it got:

* :class:`OracleStore` (``PANEL_STORE=oracle``, the default when Oracle is on)
  keeps ``panel_users`` / ``panel_servers`` in the shared
  Oracle schema, reusing the app's existing async engine and connection pool.
  This is what makes the panel work across both load-balanced instances: a
  server created on instance A is listed by instance B.
* :class:`SqliteStore` (``PANEL_STORE=sqlite``) wraps the synchronous
  :class:`~panel_app.panel_database.PanelDatabase` in ``run_in_threadpool``. It
  exists for the laptop smoke test, where there is no Oracle connection.

Dicts, not ORM objects, are deliberate: the Jinja templates index rows like
``server.name`` / ``entry.created_at`` and ``created_at`` is rendered directly,
so every backend normalises timestamps to the same ISO-8601 string SQLite
produced.
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from starlette.concurrency import run_in_threadpool


# Written into a mirrored row's ``password_hash``, which is NOT NULL. It is not a
# valid PBKDF2 string, so panel-local verify_password can never accept it —
# mirrored users are authenticated by the main site and nothing else.
EXTERNAL_PLACEHOLDER = "external:oracle"

# Ceiling on one user's server list. This has to stay comfortably above
# MAX_SERVERS_PER_USER, because routes.py enforces that quota by counting the
# rows this returns — a cap at or below the quota would silently read as "under
# the limit" and let a user exceed it. It is a runaway guard, not a page size.
SERVER_LIST_MAX = 200

# Width of panel_users.username. oracle_models imports it for the column so the
# two cannot drift: the value the mirror writes comes from the main site's
# session, which this tier does not get to bound, so the clip below is the only
# thing standing between a long display name and ORA-12899 on the one INSERT that
# every first panel visit depends on.
USERNAME_MAX_CHARS = 100

# Width of the two id columns — panel_users.id and panel_servers.user_id, both
# VARCHAR2(36). The id that reaches _user_key on every request comes out of the
# main site's session dict, which this tier never validated.
USER_ID_MAX_CHARS = 36

# Width of panel_servers.image. Unlike name / runtime / version this one is never
# seen by a route's validation: it is whatever tag the node agent reported for the
# container it just built.
IMAGE_MAX_CHARS = 255

# Widths of the four panel_servers columns a route hands over as submitted text.
# Each of those routes does bound its field — but
# with len(), which counts characters, while the migration's VARCHAR2(n) counts
# bytes (see _clip_text). So the route ceilings are not the column ceilings:
# MAX_STARTUP_CHARS is 500 against 500 bytes, which one non-ASCII character in a
# long command already exceeds, and MAX_NAME_CHARS allows 80 characters that can
# weigh 320 bytes against 255. Clipping here rather than leaving ORA-12899 to the
# write matters most for startup: api_update_startup calls the node first, so a
# failed write leaves the container running the new command while the row — and
# therefore every page that displays it — keeps the old one.
NAME_MAX_CHARS = 255
RUNTIME_MAX_CHARS = 32
VERSION_MAX_CHARS = 32
STARTUP_MAX_CHARS = 500


def _clip_text(value, max_chars):
    """Clip text to what a ``VARCHAR2(max_chars)`` column accepts either way.

    SQLAlchemy's Oracle dialect emits ``VARCHAR2(n CHAR)``, but the hand-run
    migration that re-keyed these tables spells plain ``VARCHAR2(n)`` — byte
    semantics under the ATP default. Bounding both counts is therefore the only
    clip that holds whichever DDL built the column, and slicing the encoded form
    can leave a partial multi-byte sequence, which ``errors="ignore"`` drops.
    """
    text = str(value)
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        text = text.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    text = text[:max_chars]
    encoded = text.encode("utf-8")
    if len(encoded) <= max_chars:
        return text
    return encoded[:max_chars].decode("utf-8", "ignore")


def _user_key(user_id) -> str:
    """Normalise a panel user id for binding and comparison.

    ``panel_users.id`` is the main site's own VARCHAR2(36) user id — the panel
    mirrors that value rather than minting an integer of its own — so every id
    is bound as text. An unusable value normalises to ``""``, which matches no
    row, so a caller with junk gets "not found" instead of a driver error.

    Over-long is unusable too: the column is 36 wide, so no stored id can be
    longer and every read for one is already a guaranteed miss — while the mirror
    INSERT would instead raise ORA-12899 on the identity path, which is the one
    write a visitor cannot get past.
    """
    if user_id is None:
        return ""
    key = str(user_id).strip()
    return key if len(key) <= USER_ID_MAX_CHARS else ""


def _utc_now() -> datetime:
    # Naive UTC, matching app/models.py — SQLAlchemy renders DateTime as an
    # Oracle DATE, which has nowhere to keep an offset, so the driver would drop
    # the tzinfo of an aware value anyway. Writing what the app already writes
    # keeps the panel on a pattern this schema is known to accept. _iso() labels
    # the value UTC on the way back out.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value) -> str:
    """Normalise a stored timestamp to the ISO string the templates render."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        # Oracle DATE/TIMESTAMP round-trips as naive; label it UTC so the string
        # is unambiguous and matches what the SQLite backend stored.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _delivery_mode(raw) -> str:
    """The delivery mode out of a stored delivery_config blob, or "off".

    Only the mode leaves this layer. The webhook URL and bot token in the blob
    are ciphertext and stay that way: nothing renders them back into the page,
    so a session that can read the server detail page cannot read the secret.
    Malformed or absent JSON reads as "off" rather than raising — the column is
    written by this tier but the value predates nothing and may be NULL.
    """
    if not raw:
        return "off"
    try:
        config = json.loads(raw) if isinstance(raw, str) else raw
        mode = str(config.get("mode") or "off").strip().lower()
    except (ValueError, TypeError, AttributeError):
        return "off"
    return mode if mode in ("webhook", "bot", "off") else "off"


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
            # users.username is UNIQUE COLLATE NOCASE here, so this backend can
            # fail the same two ways OracleStore.ensure_user_by_id does. Split
            # them the same way, so a caller sees one behaviour per backend.
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
        # machine serving the panel. Unconditional True is the answer, not a stub —
        # it is also what the Oracle store answers while no node is registered.
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
        row = await run_in_threadpool(self._db.get_server_for_user, server_id, user_id)
        if row is not None:
            row["delivery_mode"] = _delivery_mode(row.get("delivery_config"))
        return row

    async def delete_server_for_user(self, server_id, user_id):
        return await run_in_threadpool(self._db.delete_server_for_user, server_id, user_id)

    async def update_server_startup(self, server_id, user_id, startup):
        return await run_in_threadpool(self._db.update_server_startup, server_id, user_id, startup)

    async def update_server_name(self, server_id, user_id, name):
        return await run_in_threadpool(self._db.update_server_name, server_id, user_id, name)

    async def update_server_version(self, server_id, user_id, runtime, version, image=None):
        return await run_in_threadpool(
            self._db.update_server_version, server_id, user_id, runtime, version, image
        )

    async def update_server_state(self, server_id, user_id, running):
        return await run_in_threadpool(self._db.update_server_state, server_id, user_id, running)

    async def update_server_delivery_config(self, server_id, user_id, delivery_config):
        return await run_in_threadpool(
            self._db.update_server_delivery_config,
            server_id,
            user_id,
            json.dumps(delivery_config) if delivery_config else None,
        )


class OracleStore:
    """Panel storage in the shared Oracle schema, on the app's async engine."""

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
        """Run ensure_schema and mark it done so future calls skip the retry.

        Called at most once per process lifetime — the first time an ORA-00904
        is caught.  If the heal itself fails, the exception propagates to the
        caller so the visitor sees a real error instead of an infinite loop.
        """
        if self._schema_verified:
            return
        from .database import ensure_schema

        self._schema_verified = True
        await ensure_schema()

    async def _run_with_heal(self, coro_factory):
        """Execute an async operation, healing the schema on ORA-00904 once.

        ``coro_factory`` is a callable returning a fresh coroutine so the retry
        can re-execute the full query (not replay a consumed one).
        """
        try:
            return await coro_factory()
        except Exception as exc:
            msg = str(exc)
            if "ORA-00904" not in msg:
                raise
            await self._heal_schema()
            return await coro_factory()

    @staticmethod
    def _user_dict(row):
        if row is None:
            return None
        return {
            "id": row.id,
            "username": row.username,
            "password_hash": row.password_hash,
            # Left as None when the column is NULL rather than coerced to 0: the
            # two mean opposite things (no grant, versus hosting switched off),
            # and every reader of this key tells them apart.
            "container_slots": (
                None if row.container_slots is None else int(row.container_slots)
            ),
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _server_dict(row):
        if row is None:
            return None
        return {
            "id": row.id,
            "user_id": row.user_id,
            "name": row.name,
            "runtime": row.runtime,
            "version": row.version,
            "image": row.image,
            "startup": row.startup,
            "memory_mb": int(row.memory_mb or 0),
            "cpu_percent": int(row.cpu_percent or 0),
            "desired_state": int(row.desired_state or 0),
            "delivery_mode": _delivery_mode(row.delivery_config),
            "created_at": _iso(row.created_at),
            "node_id": None if row.node_id is None else int(row.node_id),
        }

    async def initialize(self):
        """No-op as far as DDL goes — nothing reachable from here creates a table.

        Importing :mod:`panel_app.oracle_models` registers them on
        ``database.Base.metadata``, which is the metadata
        :func:`panel_app.database.ensure_schema` creates missing tables from and
        compares existing ones against. That call belongs to the tier's startup,
        not to this store, so the tables have to exist already by the time any
        query below runs.
        """
        from . import oracle_models  # noqa: F401  (import registers the tables)

    # -- users -------------------------------------------------------------

    async def create_user(self, username, password_hash):
        from sqlalchemy import func, select
        from sqlalchemy.exc import IntegrityError

        from .oracle_models import PanelUser

        normalized = (username or "").strip()
        if len(normalized) < 3 or len(normalized) > 32:
            raise ValueError("username must be between 3 and 32 characters")
        # 32 characters is up to 128 bytes, and panel_users.username is 100 wide
        # in byte terms — so the check above is not the column's bound. Clipped
        # before the duplicate lookup, not just before the INSERT, so both read
        # the value that is actually stored.
        normalized = _clip_text(normalized, USERNAME_MAX_CHARS)
        async with self._sessions()() as db:
            existing = await db.execute(
                select(PanelUser.id).where(func.lower(PanelUser.username) == normalized.lower())
            )
            if existing.scalar_one_or_none() is not None:
                raise ValueError("username is already registered")
            # panel_users.id has no Identity: it normally holds the main site's
            # own user id. A row created here has no upstream identity to borrow,
            # so it gets a UUID of the same shape instead.
            user_id = uuid4().hex
            row = PanelUser(
                id=user_id,
                username=normalized,
                password_hash=password_hash,
                created_at=_utc_now(),
            )
            db.add(row)
            try:
                await db.commit()
            except IntegrityError as exc:
                await db.rollback()
                raise ValueError("username is already registered") from exc
            return user_id

    async def ensure_user_by_id(self, user_id, username):
        """Mirror an already-authenticated identity, keyed by the caller's id.

        This is the single sign-in's landing point: ``user_id`` is the main site's
        own user id and becomes ``panel_users.id`` verbatim, so ``panel_servers``
        FK to a value the site already owns. Keying on the
        id rather than the username matters — the site stores usernames encrypted,
        so the display name in a session is not a stable key to upsert on.
        """
        from sqlalchemy import select
        from sqlalchemy.exc import IntegrityError

        from .auth import MirrorConflict
        from .oracle_models import PanelUser

        key = _user_key(user_id)
        if not key:
            return None
        async with self._sessions()() as db:
            result = await db.execute(select(PanelUser).where(PanelUser.id == key))
            row = result.scalar_one_or_none()
            if row is not None:
                return self._user_dict(row)
            row = PanelUser(
                id=key,
                username=_clip_text((username or "").strip() or key, USERNAME_MAX_CHARS),
                password_hash=EXTERNAL_PLACEHOLDER,
                created_at=_utc_now(),
            )
            db.add(row)
            try:
                await db.commit()
            except IntegrityError as exc:
                await db.rollback()
                # Either another instance mirrored the same identity between the
                # SELECT and the INSERT — in which case the row is now there and
                # returning it is correct — or a pre-migration row still holds
                # this username under an old id and the unique index on
                # lower(username) refused ours. The second case is a migration
                # that has not finished, so it is raised rather than papered over.
                result = await db.execute(select(PanelUser).where(PanelUser.id == key))
                row = result.scalar_one_or_none()
                if row is None:
                    raise MirrorConflict("panel user mirror row could not be written") from exc
            return self._user_dict(row)

    async def get_user_by_username(self, username):
        from sqlalchemy import func, select

        from .oracle_models import PanelUser

        async with self._sessions()() as db:
            result = await db.execute(
                select(PanelUser).where(
                    func.lower(PanelUser.username) == (username or "").strip().lower()
                )
            )
            return self._user_dict(result.scalar_one_or_none())

    async def get_user(self, user_id):
        from sqlalchemy import select

        from .oracle_models import PanelUser

        key = _user_key(user_id)
        if not key:
            return None

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(select(PanelUser).where(PanelUser.id == key))
                return self._user_dict(result.scalar_one_or_none())

        return await self._run_with_heal(_query)

    async def update_user_password(self, user_id, password_hash):
        from sqlalchemy import update

        from .oracle_models import PanelUser

        key = _user_key(user_id)
        if not key:
            return False
        async with self._sessions()() as db:
            result = await db.execute(
                update(PanelUser).where(PanelUser.id == key).values(password_hash=password_hash)
            )
            await db.commit()
            return (result.rowcount or 0) == 1

    # -- servers -----------------------------------------------------------

    async def can_place_new_server(self):
        """Whether any enabled node still has room for one more server.

        Answered by :func:`node_registry.placement_capacity_available` rather than
        by SQL of this store's own. That module is where placement is *decided* —
        ``pick_node_for_new_server`` selects the node from the identical predicate
        — so a second spelling of the rule here would be one that can drift out of
        agreement with the thing actually doing the placing: this probe would
        promise room the insert cannot find, or refuse while a node sat half empty.
        It is also the same call the ``backend`` store reaches over HTTP
        (``/api/panel-store/placement/probe`` wraps exactly this), so both
        Oracle-backed backends now answer from one implementation of the rule.

        The semantics inherited from it, every one of them its own and none of them
        invented here:

        * an empty ``nodes`` table means *no placement constraint*, not "full".
          Production has no node registered yet, and a deploy has to keep working
          until an operator adds one.
        * a node is a candidate only while ``enabled=1`` and ``capacity>0``, so a
          capacity of 0 reads as "closed to new placements" — the state
          ``node_registry.delete_node`` points an operator at instead of deleting a
          node that still hosts servers. NULL cannot reach that column
          (``NUMBER DEFAULT 0 NOT NULL``) and would read the same way if it did,
          since ``NULL > 0`` is unknown and drops the row.
        * a ``panel_servers`` row with no ``node_id`` counts against the
          lowest-numbered node, the default one. Every row this store writes is
          such a row — ``create_server`` below records no placement — so on a
          one-node fleet the count being compared is the whole panel.

        A ``nodes`` table that does not exist at all answers True there too, so
        nothing on this path has to run DDL against the shared schema to make the
        probe work. Anything else that goes wrong is left to raise: ``routes.py``
        logs it and creates the server anyway, which is the deliberate reading that
        a registry the panel cannot reach must not become a panel that refuses to
        deploy.
        """
        # Imported per call and run in a worker thread, for the reason
        # panel_settings.py gives for its own `import database`: node_registry
        # imports that module, which resolves its Oracle connection at import time
        # and is not importable at all on the SQLite path — and the registry's API
        # is blocking oracledb, which would stall the event loop if awaited inline.
        # Every settings read on the Oracle store path already goes through that
        # same import, so this asks nothing new of the running configuration.
        import node_registry

        return bool(await run_in_threadpool(node_registry.placement_capacity_available))

    async def get_node_credentials(self, node_id):
        import node_registry

        def _read():
            return node_registry.get_node_credentials(node_id)

        return await run_in_threadpool(_read)

    async def create_server(
        self, *, server_id, user_id, name, runtime, version, image, startup
    ):
        from .oracle_models import PanelServer

        owner = _user_key(user_id)
        if not owner:
            # An ownerless row is the one shape of panel_servers that no route
            # could ever reach again: every read is filtered by owner, while the
            # node agent resolves a container by its dchost.server_id label alone
            # and checks nothing. Refuse before the row exists — routes.py treats
            # a ValueError here as "nothing was created" and takes the container
            # back down.
            raise ValueError("a server row requires an owner")

        async def _insert():
            import node_registry
            from .oracle_models import PanelServer as _PanelServer

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
                    _PanelServer(
                        id=server_id,
                        user_id=owner,
                        name=_clip_text((name or "").strip(), NAME_MAX_CHARS),
                        runtime=_clip_text(runtime or "", RUNTIME_MAX_CHARS),
                        version=_clip_text(version or "", VERSION_MAX_CHARS),
                        image=_clip_text(image or "", IMAGE_MAX_CHARS),
                        startup=_clip_text((startup or "").strip(), STARTUP_MAX_CHARS),
                        memory_mb=300,
                        cpu_percent=35,
                        desired_state=0,
                        created_at=_utc_now(),
                        node_id=node_id,
                    )
                )
                await db.commit()
            return node_id

        return await self._run_with_heal(_insert)

    async def list_servers_for_user(self, user_id):
        from sqlalchemy import select

        from .oracle_models import PanelServer

        owner = _user_key(user_id)
        if not owner:
            return []

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(
                    select(PanelServer)
                    .where(PanelServer.user_id == owner)
                    .order_by(PanelServer.created_at.desc())
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

        from .oracle_models import PanelServer

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(select(PanelServer.id))
                return [str(sid) for sid in result.scalars().all() if sid]

        return await self._run_with_heal(_query)

    async def get_server_for_user(self, server_id, user_id):
        from sqlalchemy import select

        from .oracle_models import PanelServer

        owner = _user_key(user_id)
        if not owner or not server_id:
            # Both halves are required. Leaving the owner to Oracle's
            # empty-string-is-NULL rule happens to exclude every row, but that is
            # a dialect quirk holding up the only authorization check the product
            # has — the node agent performs none of its own.
            return None

        async def _query():
            async with self._sessions()() as db:
                result = await db.execute(
                    select(PanelServer).where(
                        PanelServer.id == server_id, PanelServer.user_id == owner
                    )
                )
                return self._server_dict(result.scalar_one_or_none())

        return await self._run_with_heal(_query)

    async def delete_server_for_user(self, server_id, user_id):
        from sqlalchemy import delete

        from .oracle_models import PanelServer

        owner = _user_key(user_id)
        if not owner or not server_id:
            return False

        async def _do_delete():
            async with self._sessions()() as db:
                result = await db.execute(
                    delete(PanelServer).where(
                        PanelServer.id == server_id, PanelServer.user_id == owner
                    )
                )
                await db.commit()
                return (result.rowcount or 0) == 1

        return await self._run_with_heal(_do_delete)

    async def _update_server(self, server_id, user_id, values):
        from sqlalchemy import update

        from .oracle_models import PanelServer

        owner = _user_key(user_id)
        if not owner or not server_id:
            return False

        async def _do_update():
            async with self._sessions()() as db:
                result = await db.execute(
                    update(PanelServer)
                    .where(PanelServer.id == server_id, PanelServer.user_id == owner)
                    .values(**values)
                )
                await db.commit()
                return (result.rowcount or 0) == 1

        return await self._run_with_heal(_do_update)

    async def update_server_startup(self, server_id, user_id, startup):
        return await self._update_server(
            server_id, user_id, {"startup": _clip_text((startup or "").strip(), STARTUP_MAX_CHARS)}
        )

    async def update_server_name(self, server_id, user_id, name):
        return await self._update_server(
            server_id, user_id, {"name": _clip_text((name or "").strip(), NAME_MAX_CHARS)}
        )

    async def update_server_version(self, server_id, user_id, runtime, version, image=None):
        values = {
            "runtime": _clip_text((runtime or "").strip().lower(), RUNTIME_MAX_CHARS),
            "version": _clip_text((version or "").strip(), VERSION_MAX_CHARS),
        }
        if image:
            # Optional because the node's reply is what carries the new tag, and
            # only the route holds that reply. Without it panel_servers.image keeps
            # the tag of the runtime the server no longer runs, which is the value
            # the dashboard and the server page display.
            values["image"] = _clip_text(image, IMAGE_MAX_CHARS)
        return await self._update_server(server_id, user_id, values)

    async def update_server_state(self, server_id, user_id, running):
        """Record the owner's last power intent: 1 running, 0 stopped.

        Written after the node accepts a power action, so the stored value tracks
        what was actually commanded rather than what was merely attempted. Read on
        every load so a stopped server stays presented as stopped.
        """
        return await self._update_server(
            server_id, user_id, {"desired_state": int(bool(running))}
        )

    async def update_server_delivery_config(self, server_id, user_id, delivery_config):
        """Persist the Discord delivery configuration JSON blob.

        ``delivery_config`` is a dict from routes.py with the webhook URL or bot
        token already encrypted via crypto_util — store.py never sees plaintext.
        Stored as JSON text; only the mode is read back out (see
        :func:`_delivery_mode`).
        """
        return await self._update_server(
            server_id,
            user_id,
            {"delivery_config": json.dumps(delivery_config) if delivery_config else None},
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

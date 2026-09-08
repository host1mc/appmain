"""Oracle tables for the panel, defined on the panel's own declarative ``Base``.

Registering them on :data:`panel_app.database.Base` is what puts them on the
metadata :func:`panel_app.database.ensure_schema` creates from and compares
against, so moving the panel onto Oracle needs no hand-written DDL against the
shared schema. Importing this module registers the tables but never creates them:
the panel tier's lifespan is what runs ensure_schema, and the host app's
``init_db()`` holds no declarative metadata so it will not create them either.
Every statement ensure_schema issues is additive and check-first, so a restart
against a schema that already matches these models runs no DDL at all.

Every name is prefixed ``panel_`` because the Oracle schema is shared: the
panel must not be able to collide with, or be mistaken for, the app's own
``users`` / ``items`` / ``todos`` tables.

Why the panel keeps its own ``panel_users`` table instead of pointing
``panel_servers.user_id`` at ``users.id``:

* the id it stores is the *main site's* own VARCHAR2(36) user id, handed over in
  a session the panel only reads — not a key in this app's ``users`` table.
* it keeps the panel's own rows off real app accounts — removing a panel user
  removes their server records, never an app login. Only the loopback console in
  ``admin/`` does that removing; this tier has no route that reaches another
  account's rows at all.

A mirrored row therefore holds an identity, not a credential: its
``password_hash`` is the unusable ``external:oracle`` placeholder and Oracle
remains the only thing that can authenticate the user.
"""

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    func,
)

from .database import Base
from .store import (
    ACTION_MAX_CHARS,
    DETAIL_MAX_CHARS,
    IMAGE_MAX_CHARS,
    NAME_MAX_CHARS,
    RUNTIME_MAX_CHARS,
    STARTUP_MAX_CHARS,
    USERNAME_MAX_CHARS,
    VERSION_MAX_CHARS,
)


class PanelUser(Base):
    __tablename__ = "panel_users"

    id = Column(String(36), primary_key=True)
    username = Column(String(USERNAME_MAX_CHARS), nullable=False)
    password_hash = Column(String(255), nullable=False)
    # How many hosting containers this one account may hold, when the admin
    # console has decided that for them specifically. Three states, and the
    # difference between two of them is why this is nullable rather than
    # defaulting to a number:
    #
    #   NULL  — nothing granted: the account gets the fleet-wide figure from
    #           settings (panel_limit_max_servers), which is 1.
    #   0     — hosting switched off for this account, which is a decision the
    #           admin made and not the absence of one.
    #   N     — exactly N, whatever the fleet figure happens to be.
    #
    # Collapsing NULL into 0 would make "not configured" and "banned from
    # hosting" the same row, so raising the fleet default would silently un-ban
    # every account that had been switched off. It also keeps the grant from
    # having to be re-applied whenever the fleet figure moves.
    #
    # A NUMBER holding a small integer, not the VARCHAR2 that users.slots uses
    # for the unrelated bot-slot count: the value is only ever compared against a
    # count, so storing it as text costs a conversion on every comparison and
    # admits '3 ' and 'three' as things that have to be defended against.
    container_slots = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False)


# SQLite spelled this ``username TEXT COLLATE NOCASE UNIQUE``. Oracle has no
# per-column collation, so the case-insensitive uniqueness is a function-based
# unique index and every lookup compares lower(username) to match it.
Index("ix_panel_users_username_lower", func.lower(PanelUser.username), unique=True)


class PanelServer(Base):
    __tablename__ = "panel_servers"

    id = Column(String(36), primary_key=True)
    user_id = Column(
        String(36),
        ForeignKey("panel_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(NAME_MAX_CHARS), nullable=False)
    runtime = Column(String(RUNTIME_MAX_CHARS), nullable=False)
    version = Column(String(VERSION_MAX_CHARS), nullable=False)
    image = Column(String(IMAGE_MAX_CHARS), nullable=True)
    startup = Column(String(STARTUP_MAX_CHARS), nullable=False)
    memory_mb = Column(Integer, nullable=False, default=300)
    cpu_percent = Column(Integer, nullable=False, default=35)
    # 1 = the owner last commanded this server running, 0 = stopped. This is the
    # panel's record of intent, not a live container status (that is read from the
    # node): it is written on every power action and read on load so a stopped
    # server stays presented as stopped across restarts and node outages, and so
    # nothing here silently starts a server the owner stopped. Defaults to 0
    # because create_server leaves the container in Docker's "created" state.
    # create_all builds this column on a fresh schema; an existing panel_servers
    # table gets it from database.ensure_schema at startup, because create_all is
    # check-first at table level and so cannot add a column to a table it finds
    # (migrations/002 is the same ALTER, by hand, for a panel that is not running).
    desired_state = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False)
    node_id = Column(Integer, nullable=True)
    # JSON blob holding {"mode": "webhook"|"bot"|"off", "webhook_url": <ciphertext>,
    # "bot_token": <ciphertext>} — encrypted before storage, decrypted on read by
    # routes. NULL means "no delivery configured".
    delivery_config = Column(String(2048), nullable=True)


class PanelActivity(Base):
    __tablename__ = "panel_activity"

    id = Column(Integer, Identity(always=False), primary_key=True)
    user_id = Column(
        String(36),
        ForeignKey("panel_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Not a foreign key: the audit trail has to outlive the server it describes,
    # so deleting a server must not cascade its history away.
    server_id = Column(String(36), nullable=True)
    action = Column(String(ACTION_MAX_CHARS), nullable=False)
    # Inline VARCHAR2 rather than a CLOB. SQLite spelled this TEXT, but the
    # activity page reads 200 rows at a time, so a LOB column would mean 200
    # out-of-line reads per page view. Most writes are short (a name, a
    # 100-character command slice); the joined upload list is the one that can
    # run long, and store.py truncates on write so it cannot fail the insert.
    detail = Column(String(DETAIL_MAX_CHARS), nullable=True)
    created_at = Column(DateTime, nullable=False)


Index("ix_panel_activity_user", PanelActivity.user_id, PanelActivity.created_at)

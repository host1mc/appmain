"""The one Oracle table the panel still owns a model for: ``servers``.

The old ``panel_users`` / ``panel_servers`` / ``panel_activity`` trio is gone.
Users are the main site's ``users`` rows — the panel reads them through
``app/database.py`` (which is also what decrypts the username), never through
a model of its own. Activity is not persisted at all.

``servers`` is the consolidated table database.py creates and migrates:
uid + name + status + placement, and nothing else. The runtime, version,
image and startup command live inside the container and are read from the
node, so this model — and any read of the table — exposes no deployment
detail.

The model is declared on the panel's own declarative ``Base`` so
:func:`panel_app.database.ensure_schema` can compare it against the schema,
but it never issues CREATE for it: database.py owns the DDL. Registering the
table here is what keeps the panel's queries on a checked column set.
"""

from sqlalchemy import Column, DateTime, Integer, String

from .database import Base
from .store import NAME_MAX_CHARS


class Server(Base):
    __tablename__ = "servers"

    id = Column(String(36), primary_key=True)
    # ``uid`` is a quoted identifier in the shared schema (Oracle reserves the
    # bare word), so the column must be written and read with quotes too.
    uid = Column("uid", String(10), nullable=False, index=True, quote=True)
    name = Column(String(NAME_MAX_CHARS), nullable=False)
    # 1 = the owner last commanded this server running, 0 = stopped. This is
    # the panel's record of intent, not a live container status (that is read
    # from the node): it is written on every power action and read on load so
    # a stopped server stays presented as stopped across restarts and node
    # outages, and so nothing here silently starts a server the owner stopped.
    status = Column(Integer, nullable=False, default=0)
    node_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False)

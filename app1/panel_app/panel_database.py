import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .store import EXTERNAL_PLACEHOLDER, SERVER_LIST_MAX


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    container_slots INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    runtime TEXT NOT NULL,
    version TEXT NOT NULL,
    image TEXT NOT NULL,
    startup TEXT NOT NULL,
    memory_mb INTEGER NOT NULL DEFAULT 300,
    cpu_percent INTEGER NOT NULL DEFAULT 35,
    desired_state INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_servers_user_id ON servers(user_id);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PanelDatabase:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            # CREATE TABLE IF NOT EXISTS leaves an already-created servers table
            # untouched, so a local DB from before desired_state existed keeps the
            # old shape. Add the column in place — SQLite ALTER TABLE ADD COLUMN is
            # cheap and the NOT NULL DEFAULT fills existing rows with 0 (stopped).
            # This only ever heals the smoke-test's own panel.db; the deployed
            # schema is the host app's consolidated servers table.
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(servers)").fetchall()
            }
            if "desired_state" not in columns:
                connection.execute(
                    "ALTER TABLE servers ADD COLUMN desired_state INTEGER NOT NULL DEFAULT 0"
                )
            # Same story for the per-account container grant: nullable and with no
            # default, so every existing row reads NULL, which is what "no grant,
            # use the fleet figure" is spelled as. Oracle keeps it on the main
            # users table (users.container_slots).
            user_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "container_slots" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN container_slots INTEGER")
            server_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(servers)").fetchall()
            }
            if "delivery_config" not in server_columns:
                connection.execute("ALTER TABLE servers ADD COLUMN delivery_config TEXT")

    def create_user(self, username: str, password_hash: str) -> str:
        normalized = (username or "").strip()
        if len(normalized) < 3 or len(normalized) > 32:
            raise ValueError("username must be between 3 and 32 characters")
        # users.id is no longer a rowid alias: it mirrors the main site's own
        # VARCHAR2(36) user id. A row created here has no upstream identity to
        # borrow, so it gets a UUID of the same shape.
        user_id = uuid4().hex
        try:
            with self.connect() as connection:
                connection.execute(
                    "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, normalized, password_hash, _utc_now()),
                )
                return user_id
        except sqlite3.IntegrityError as exc:
            raise ValueError("username is already registered") from exc

    def ensure_user_by_id(self, user_id: str, username: str):
        """Mirror an already-authenticated identity, keyed by the caller's id.

        The SQLite twin of :meth:`OracleStore.ensure_user_by_id`: ``user_id`` is
        the main site's own user id and is stored verbatim, so ``servers.user_id``
        and ``activity.user_id`` point at a value that site owns. An existing row
        is returned untouched.
        """
        key = str(user_id or "").strip()
        if not key:
            return None
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (key,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (
                        key,
                        (username or "").strip() or key,
                        EXTERNAL_PLACEHOLDER,
                        _utc_now(),
                    ),
                )
                row = connection.execute("SELECT * FROM users WHERE id = ?", (key,)).fetchone()
            return dict(row) if row else None

    def get_user_by_username(self, username: str):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                ((username or "").strip(),),
            ).fetchone()
            return dict(row) if row else None

    def get_user(self, user_id: str):
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def create_server(
        self,
        *,
        server_id: str,
        user_id: str,
        name: str,
        runtime: str,
        version: str,
        image: str,
        startup: str,
    ):
        owner = str(user_id or "").strip()
        if not owner:
            # Matches OracleStore.create_server: an ownerless row is unreachable
            # from every read in this class, which all filter by owner.
            raise ValueError("a server row requires an owner")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO servers (
                    id, user_id, name, runtime, version, image, startup,
                    memory_mb, cpu_percent, desired_state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 300, 100, 0, ?)
                """,
                (
                    server_id,
                    owner,
                    (name or "").strip(),
                    runtime,
                    version,
                    image,
                    (startup or "").strip(),
                    _utc_now(),
                ),
            )

    def list_servers_for_user(self, user_id: str):
        owner = str(user_id or "").strip()
        if not owner:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM servers WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (owner, SERVER_LIST_MAX),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_server_for_user(self, server_id: str, user_id: str):
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM servers WHERE id = ? AND user_id = ?",
                (server_id, owner),
            ).fetchone()
            return dict(row) if row else None

    def delete_server_for_user(self, server_id: str, user_id: str) -> bool:
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        with self.connect() as connection:
            cursor = connection.execute(
                "DELETE FROM servers WHERE id = ? AND user_id = ?",
                (server_id, owner),
            )
            return cursor.rowcount == 1

    def update_server_startup(self, server_id: str, user_id: str, startup: str) -> bool:
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE servers SET startup = ? WHERE id = ? AND user_id = ?",
                ((startup or "").strip(), server_id, owner),
            )
            return cursor.rowcount == 1

    def update_server_name(self, server_id: str, user_id: str, name: str) -> bool:
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE servers SET name = ? WHERE id = ? AND user_id = ?",
                ((name or "").strip(), server_id, owner),
            )
            return cursor.rowcount == 1

    def update_server_version(
        self, server_id: str, user_id: str, runtime: str, version: str, image=None
    ) -> bool:
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        sql = "UPDATE servers SET runtime = ?, version = ?"
        params = [(runtime or "").strip().lower(), (version or "").strip()]
        if image:
            # Optional for the same reason as in OracleStore: only the route holds
            # the node's reply, and that reply is what carries the new tag.
            sql += ", image = ?"
            params.append(str(image))
        sql += " WHERE id = ? AND user_id = ?"
        params.extend([server_id, owner])
        with self.connect() as connection:
            cursor = connection.execute(sql, tuple(params))
            return cursor.rowcount == 1

    def update_server_state(self, server_id: str, user_id: str, running) -> bool:
        """SQLite twin of :meth:`OracleStore.update_server_state`: 1 running, 0
        stopped. Written after the node accepts a power action, read on load."""
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE servers SET desired_state = ? WHERE id = ? AND user_id = ?",
                (int(bool(running)), server_id, owner),
            )
            return cursor.rowcount == 1

    def update_server_delivery_config(self, server_id: str, user_id: str, delivery_config) -> bool:
        """SQLite twin of :meth:`OracleStore.update_server_delivery_config`:
        the config arrives already JSON-encoded by the caller (store.py), so
        this stores it verbatim; ``None`` clears it."""
        owner = str(user_id or "").strip()
        if not owner or not server_id:
            return False
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE servers SET delivery_config = ? WHERE id = ? AND user_id = ?",
                (delivery_config, server_id, owner),
            )
            return cursor.rowcount == 1

    def update_user_password(self, user_id: str, password_hash: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
            return cursor.rowcount == 1

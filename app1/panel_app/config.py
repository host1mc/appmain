"""Panel configuration, read from the environment at mount time.

This mirrors the retired standalone Flask panel's ``create_app`` config block
but as a plain dataclass so it can be built once and stashed on ``app.state``.
Nothing here connects to a network or a database — it only reads env vars and,
if no signing secret is provided, materialises a local session key file.
"""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


# Everything the panel serves lives under this single URL prefix so it can never
# collide with the host app's routers (/auth, /items, /todos, /admin, /health).
MOUNT_PREFIX = "/panel"


_TRUE_TOKENS = {"1", "true", "yes", "on"}
_FALSE_TOKENS = {"0", "false", "no", "off"}


def as_bool(value, default: bool = False) -> bool:
    """Parse an env-var flag, falling back to ``default`` on anything unrecognised.

    Recognising only true-tokens and treating everything else as False made the
    string default at each call site survive absence but not a *bad* value: with
    ``as_bool(env.get("PANEL_HSTS", "true"))``, an empty or misspelled
    PANEL_HSTS silently dropped HSTS from the whole panel. Naming the fallback
    explicitly means a typo keeps the intended setting instead of quietly
    inverting a default-on switch.
    """
    token = str(value or "").strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    return default


def _app_data_dir() -> Path:
    # app/panel_app/config.py -> app/  (shared data/ dir with the Flask tiers,
    # where internal_auth.py writes internal.key)
    return Path(__file__).resolve().parents[1] / "data"


def _read_internal_token(env) -> str:
    """Read the stack's shared internal token. Never creates one.

    internal_auth.py owns that token and mints it on first use; the panel is only
    ever a caller, so a missing token means "not configured yet", not "make one".
    Minting here would hand the panel a value the Flask tiers do not know, and
    every session lookup would then be rejected with no clue why.
    """
    token = (env.get("INTERNAL_TOKEN") or "").strip()
    if token:
        return token
    try:
        return (_app_data_dir() / "internal.key").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _clamped_int(value, default: int, low: int, high: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


def _load_or_create_secret(path: str) -> str:
    secret_path = Path(path)
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(48)
    try:
        # Created 0o600 by open(2) rather than chmod'ed afterwards: writing first
        # left the secret readable by every local account for the window between
        # the two calls. O_EXCL also settles the race between two workers booting
        # at once — the loser reads the winner's key instead of both writing and
        # one of them holding a value the file no longer contains.
        fd = os.open(str(secret_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return secret_path.read_text(encoding="utf-8").strip()
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value


@dataclass
class PanelConfig:
    """Resolved panel settings. Build via :meth:`from_env`."""

    database_path: str = field(repr=False)
    # repr=False on all three bearer/signing secrets, on both internal addresses
    # and on the store path. The generated __repr__ would otherwise print them
    # verbatim into any traceback frame that renders locals or any log line that
    # formats the config, and internal_token is the shared bearer the whole stack
    # authenticates service-to-service on. field() with no default keeps these
    # required, so the dataclass field order is unchanged.
    secret_key: str = field(repr=False)
    node_url: str = field(repr=False)
    node_token: str = field(repr=False)
    allow_registration: bool
    max_servers_per_user: int
    session_cookie_secure: bool
    trust_proxy: bool
    max_content_length: int
    # "oracle": authenticate the login form against the host app's Oracle users
    #           (the single sign-in the product ships with).
    # "local":  authenticate against the panel's own SQLite users, so the whole
    #           UI can be smoke-tested on a laptop without touching live Oracle.
    auth_mode: str
    # "oracle": keep panel_users / panel_servers in the shared
    #           Oracle schema, so both load-balanced instances see the same rows.
    # "sqlite": per-instance SQLite file, for the laptop smoke test.
    store: str
    # Whether /panel answers with Strict-Transport-Security. Deliberately its
    # own switch rather than a read of session_cookie_secure: frontend.py returns
    # early for the panel proxy, so /panel is the one user-facing path that gets
    # none of the Flask tier's headers, and tying HSTS to a cookie flag left it
    # with no HSTS at all. A UA must ignore the header on a plain-HTTP response
    # (RFC 6797 s8.1), so defaulting it on costs a laptop run nothing.
    hsts: bool = True
    # Origin of the main site that owns the single sign-in, e.g.
    # "https://panel.example.com". The panel has no login of its own, so
    # /panel/logout hands the sign-out to that site. Empty means same origin —
    # which is also the only arrangement in which the site's session cookie is
    # sent to /panel at all, so it is the right default.
    main_site_url: str = ""
    # Origin of the Flask backend tier that owns the session store. The panel has
    # no session of its own: it reads the main site's sid through this tier's
    # internal-only ``GET /api/session/<sid>``.
    backend_url: str = field(default="http://127.0.0.1:8001", repr=False)
    # Shared bearer for that call (X-Internal-Token). Empty means the panel cannot
    # resolve a session at all, so a visitor who presents one is failed closed as
    # an outage — a 503 — rather than being silently treated as signed out.
    internal_token: str = field(default="", repr=False)
    # Name of the main site's session cookie — frontend.py's COOKIE_NAME. The
    # cookie is host-scoped, so /panel only ever receives it when it is served
    # from the same host as the Flask site.
    session_cookie_name: str = "session"
    # How long a resolved session is served from the in-process cache. Reading a
    # session through the backend API *slides its expiry forward*, so this
    # interval doubles as the keep-alive for someone browsing only the panel. It
    # is therefore clamped well under the backend's 3600s session TTL: cache for
    # longer than that and an active panel user is signed out of the whole site.
    session_cache_seconds: int = 300
    # Orphan-container reconcile sweep. A managed node container whose
    # panel_servers row was deleted while its node was unreachable outlives its
    # record, because deletion is push-based and never retried. The sweep lists
    # each node's containers and removes any whose id is not in the database.
    # Off by default: it deletes live containers, so an operator opts in once the
    # allowlist and cap are understood for their fleet. The interval is the gap
    # between sweeps; max_delete caps how many one sweep may remove per node, so
    # a partial DB read cannot cascade into a wipe.
    reconcile_enabled: bool = True
    reconcile_interval_seconds: int = 900
    reconcile_max_delete: int = 25

    @classmethod
    def from_env(cls, env=None) -> "PanelConfig":
        env = os.environ if env is None else env
        package_dir = Path(__file__).resolve().parent
        data_dir = Path(env.get("PANEL_DATA_DIR", str(package_dir / "data")))

        secret_key = env.get("PANEL_SECRET_KEY") or ""
        if not secret_key:
            secret_key = _load_or_create_secret(str(data_dir / "session.key"))

        auth_mode = (env.get("PANEL_AUTH_MODE", "oracle") or "oracle").strip().lower()
        if auth_mode not in {"oracle", "local"}:
            auth_mode = "oracle"

        # Default the store to whatever the host app is already using: with
        # Oracle on, the panel belongs in Oracle too (both instances share it);
        # with Oracle off there is no connection to use, so fall back to SQLite.
        oracle_available = as_bool(env.get("ORACLE_ENABLED", "false"))
        store = (env.get("PANEL_STORE", "") or "").strip().lower()
        if store not in {"oracle", "sqlite", "backend"}:
            store = "oracle" if oracle_available else "sqlite"

        return cls(
            database_path=env.get("PANEL_DATABASE_PATH", str(data_dir / "panel.db")),
            secret_key=secret_key,
            node_url=env.get("NODE_URL", "http://127.0.0.1:8081"),
            node_token=env.get("NODE_TOKEN", ""),
            allow_registration=as_bool(env.get("ALLOW_REGISTRATION", "false")),
            max_servers_per_user=_clamped_int(
                env.get("MAX_SERVERS_PER_USER"), default=1, low=0, high=1000
            ),
            session_cookie_secure=as_bool(env.get("PANEL_SECURE_COOKIES", "false")),
            trust_proxy=as_bool(env.get("PANEL_TRUST_PROXY", "false")),
            max_content_length=_clamped_int(
                env.get("PANEL_MAX_CONTENT_LENGTH"),
                default=150 * 1024 * 1024,
                low=1024 * 1024,
                high=512 * 1024 * 1024,
            ),
            auth_mode=auth_mode,
            store=store,
            hsts=as_bool(env.get("PANEL_HSTS", "true"), default=True),
            main_site_url=(env.get("PANEL_MAIN_SITE_URL", "") or "").strip().rstrip("/"),
            backend_url=(
                (env.get("BACKEND_URL", "") or "http://127.0.0.1:8001").strip().rstrip("/")
            ),
            internal_token=_read_internal_token(env),
            session_cookie_name=(env.get("SESSION_COOKIE_NAME", "") or "session").strip(),
            session_cache_seconds=_clamped_int(
                env.get("PANEL_SESSION_CACHE_SECONDS"), 300, 0, 3540
            ),
            reconcile_enabled=as_bool(env.get("PANEL_RECONCILE_ENABLED", "true")),
            reconcile_interval_seconds=_clamped_int(
                env.get("PANEL_RECONCILE_INTERVAL"), 900, 60, 86400
            ),
            reconcile_max_delete=_clamped_int(
                env.get("PANEL_RECONCILE_MAX_DELETE"), 25, 1, 100000
            ),
        )

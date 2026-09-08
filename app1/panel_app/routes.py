"""All panel routes, ported from the retired standalone Flask panel.

Built as a factory closing over the :class:`PanelRuntime` and :class:`PanelConfig`,
mirroring Flask's ``create_app``. Every route is a plain Starlette endpoint so the
panel stays a self-contained sub-application with no FastAPI/Depends coupling.

The synchronous seam (urllib ``NodeClient``) is always called through
``run_in_threadpool`` so the event loop never blocks; the storage layer is an
async store (:mod:`panel_app.store`) and is awaited directly. CSRF checks,
the IDOR ownership guard (``owned_server``), and the backend-IP seal (errors are
surfaced as generic ``NodeClientError`` text, never the node URL) are preserved
exactly as in the original.
"""

import io
import json
import logging
import re
import time
import traceback
import uuid
import zipfile
from http import client as http_client
from pathlib import Path, PurePosixPath
from urllib import error as urllib_error, parse, request as urlrequest
from urllib.parse import quote

import anyio
import anyio.to_thread
import asyncio

from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

# Cloudflare Turnstile siteverify, a standard-library-only leaf in the app root
# (app/ is on sys.path before panel_app is imported — see auth.py). Used to
# verify the deploy form's challenge server-side so a scripted client cannot
# spin up containers by posting straight to create_server.
import turnstile

from . import auth, id_mask, panel_security, templating
from .config import as_bool
from .maintenance import MAINTENANCE_PATH, RETRY_AFTER_SECONDS
from .node_client import NodeClientError, _NoRedirects
from .store import SERVER_LIST_MAX

# Unconfigured on purpose, like node_client's: with no handler attached logging
# falls through to the last-resort handler, which writes WARNING and above to
# stderr — the same stream the panel's other operator diagnostics use. This is
# where detail that is deliberately withheld from a user-facing message goes.
_log = logging.getLogger(__name__)

# One extracted archive may never exceed this (the per-server disk quota is
# 600 MB and extraction doubles nothing — archive bytes themselves are not
# stored). A member cap keeps a pathological archive from opening hundreds of
# thousands of files on the node.
ZIP_MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
ZIP_MAX_MEMBER_COUNT = 10000
# Ceiling on any one member. _extract_zip_members hands each member to
# node.upload_file as a single bytes object, so this — not the total above — is
# what bounds the panel process's peak memory during an extraction. Deflate
# compresses a run of identical bytes roughly 1000:1, so a request body well
# inside the upload limit can honestly declare a member of several hundred MB.
ZIP_MAX_MEMBER_BYTES = 32 * 1024 * 1024

# Ceilings for the individual request fields, all of them chosen to match the
# limit the node agent or the Oracle column already enforces, so the panel
# refuses a value locally instead of spending a node round-trip (or an Oracle
# bind that would raise) on something that can only be rejected.
MAX_PATH_CHARS = 4096
# node_agent/storage.py:write_text refuses a text write over 2 MiB of UTF-8, so
# forwarding more than this only wastes the transfer.
WRITE_MAX_CONTENT_BYTES = 2 * 1024 * 1024
# node_agent/server_manager.py caps both of these at 500, and panel_activity's
# detail column is 500 wide.
MAX_COMMAND_CHARS = 500
MAX_STARTUP_CHARS = 500
# panel_servers.name is VARCHAR2(255) but the node refuses anything over 80.
MAX_NAME_CHARS = 80
# panel_servers.runtime / .version are VARCHAR2(32).
MAX_RUNTIME_CHARS = 32
# node_agent clamps ``tail`` to 1..1000; refuse outside that rather than let the
# node coerce it.
MAX_TAIL_LINES = 1000
# Upper bound on a submitted password. There is no lower-level limit at all: the
# hash is computed in-process, so without this a body-sized string is fed
# straight to Argon2/PBKDF2.
MAX_PASSWORD_CHARS = 1024

# Every id the panel hands out is ``str(uuid.uuid4())`` (see create_server) and
# the node agent parses each one with ``uuid.UUID`` before it will act, so a
# value that is not UUID-shaped can only have been typed by a caller probing for
# somebody else's server. Checking the shape before the id reaches an Oracle
# bind or a node URL is what keeps a malformed path parameter from becoming a
# driver error instead of a 404. The dashes are optional here, but that only
# widens what reaches the ownership check: it compares the id to
# panel_servers.id exactly, so a 32-hex or upper-case spelling of a real id
# matches no row and lands on the same 404 as a made-up one.
_SERVER_ID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}\Z"
)
# Control characters have no place in a name, a path or a runtime id. They reach
# Docker labels and the node's filesystem, where they are legal and invisible.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Per-user, per-operation fixed-window ceilings for the routes whose cost is a
# node operation rather than a database row. RateLimitMiddleware already caps
# *all* state-changing panel requests at 60/minute per identity, but that is far
# too loose here: 60 reinstalls is 60 full dependency installs, and 60 archive
# extractions is up to 600,000 sequential node uploads, each holding a
# threadpool worker for its round-trip. Counters are per-process like the
# middleware's own, so the fleet-wide ceiling is twice what is written here.
_THROTTLES = {
    "reinstall": (3, 300),
    "extract": (6, 300),
    "upload": (30, 60),
    "create_server": (6, 300),
    "delete_server": (10, 300),
    "command": (30, 60),
    "power": (30, 60),
    "batch_power": (10, 60),
    # Mirrors the main site's api_renew guard (1 per day per account): the
    # renew extends the trial by a whole cycle, so one press a day is plenty and
    # a held button cannot walk the deadline forward indefinitely.
    "renew": (1, 86400),
}
_throttle_hits = {}
_THROTTLE_MAX_KEYS = 4096

# Per-server asyncio locks to serialize concurrent power/create actions
_server_locks: dict[str, asyncio.Lock] = {}
# Per-user asyncio locks to serialize quota check through insert
_user_create_locks: dict[str, asyncio.Lock] = {}
# Transient error messages from background container creations
_bg_create_errors: dict[str, str] = {}

# Every open console pins one threadpool thread for the life of the browser tab,
# blocked in read1 on the node agent's follow stream. Starlette's default pool is
# 40 threads and *every* synchronous call in this tier shares it — the whole
# NodeClient, the SQLite store, the settings read — so without a ceiling 40 open
# tabs starve the panel completely: no page renders, no power button works. A
# dedicated limiter caps what consoles can hold and leaves the rest of the pool
# for ordinary requests; a tab beyond the cap simply waits for a free slot.
_CONSOLE_THREADS = anyio.CapacityLimiter(12)

_CONSOLE_MAX_STREAM_BYTES = 64 * 1024 * 1024
_CONSOLE_MAX_FRAME_BYTES = 1024 * 1024
_CONSOLE_OPENER = urlrequest.build_opener(_NoRedirects).open


def _throttle(user_id, bucket):
    """Whether ``bucket`` may run for this user now, recording it when it may."""
    limit, window_seconds = _THROTTLES[bucket]
    window = int(time.monotonic() // window_seconds)
    key = (str(user_id), bucket)
    if len(_throttle_hits) > _THROTTLE_MAX_KEYS:
        # Every entry expires within one window on its own, so clearing the
        # table only hands out fresh windows early — better than growing without
        # bound in a long-lived worker.
        _throttle_hits.clear()
    recorded, count = _throttle_hits.get(key, (window, 0))
    if recorded != window:
        recorded, count = window, 0
    if count >= limit:
        return False
    _throttle_hits[key] = (recorded, count + 1)
    return True


def _form_text(form, key, default=""):
    """A multipart/urlencoded field as text.

    ``form.get`` returns an ``UploadFile`` when the client sends a field as a
    file part, and every caller here went on to call ``.strip()`` or ``len()`` on
    it — turning a rejection into an unhandled 500. A non-text value becomes
    ``""`` instead, which each caller already treats as invalid.
    """
    value = form.get(key, default)
    return value if isinstance(value, str) else ""


def _json_text(payload, key):
    """A JSON string field: ``""`` when absent, ``None`` when the wrong type.

    Callers used to write ``str(payload.get(key) or "")``, which renders a JSON
    object as its Python repr and then accepts that repr as if the user had
    typed it. ``None`` is the signal to reject.
    """
    value = payload.get(key)
    if value is None:
        return ""
    return value if isinstance(value, str) else None


def _is_form_post(request):
    """Whether this body is a browser form submit rather than the JSON fetch sends.

    ``api_power`` is the one JSON route a real ``<form>`` also targets — the
    dashboard's per-row power buttons, so they still work when q2.js has
    not run. Such a submit carries no ``X-CSRF-Token`` header and no JSON body, so
    reading it as JSON left the token nowhere to be found and the request could
    only be answered as a CSRF failure.
    """
    content_type = request.headers.get("content-type", "").lower()
    return content_type.startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    )


def _ws_origin_allowed(origin, host, main_site_url):
    """Whether a WebSocket handshake's ``Origin`` may open a console socket.

    CORS never applies to a handshake, and the browser attaches the site's
    session cookie to it regardless of which page opened it. Without this check
    any page on the internet could open a socket as a signed-in visitor and read
    their container logs, with SameSite=Lax the only thing in the way. Browsers
    always send Origin on a handshake, so a missing one is not a browser and is
    refused with the rest.

    Same origin is the arrangement the panel already requires: the session cookie
    is host-scoped, so it only reaches /panel when /panel is served from the
    site's own host (see ``PanelConfig.session_cookie_name``). PANEL_MAIN_SITE_URL
    is therefore the authority whenever it is set, and the Host header is the
    allowlist only when it is not: Host arrives from the client, so honouring it
    alongside a configured domain would let a forged Host carry a matching Origin
    in with it and pass this check on a name no operator ever configured.

    Only the host:port is compared, never the scheme: a TLS-terminating balancer
    forwards a plain-HTTP request whose Origin still says ``https``, and matching
    schemes would refuse every console behind one.
    """
    sent = (origin or "").strip()
    if not sent:
        return False
    try:
        parsed = parse.urlsplit(sent)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    sent_netloc = parsed.netloc.lower()
    configured = (main_site_url or "").strip()
    if configured:
        try:
            expected = parse.urlsplit(configured).netloc.lower()
        except ValueError:
            return False
        # Configured but unusable fails closed. Falling back to the client's Host
        # here would turn a typo in the env into the very bypass above.
        return bool(expected) and sent_netloc == expected
    return sent_netloc == (host or "").strip().lower()


# Past tense per power action, for the flash a form submit gets. Suffixing "ed"
# onto the action spells "stoped", and this is text the visitor reads.
_POWER_DONE = {
    "start": "started",
    "stop": "stopped",
    "restart": "restarted",
    "kill": "killed",
}


def _effective_status(node_status, desired_state):
    """The status to present for one server on the dashboard and status API.

    The node's live status is the truth whenever it has one, so a running server
    that has actually stopped still shows the real state. Only when the node
    offers nothing — it is unreachable, or no longer knows the container — does
    this fall back to the last power intent recorded in
    ``panel_servers.desired_state``: 1 shows "running", 0 shows "stopped". That is
    what keeps a stopped server presented as stopped across a node outage instead
    of the alarming "missing", and is why the intent is persisted at all.
    """
    status = (node_status or "").strip()
    if status and status != "missing":
        return status
    return "running" if int(desired_state or 0) else "stopped"


def _check_relative_path(raw, *, allow_root=False, allow_hidden=False):
    """Validate a browser-supplied file path, returning it unchanged.

    The node agent resolves every path against the server's own directory and
    refuses one that escapes it, so this is the outer of the two locks — the
    same arrangement ``_safe_dest`` gives the extract route. The value is
    returned verbatim rather than normalised so what the node receives is
    exactly what the client sent.
    """
    if not isinstance(raw, str):
        raise ValueError("path must be text")
    if len(raw) > MAX_PATH_CHARS:
        # PATH_MAX on the node, which is what actually bounds this: a folder
        # upload of a dependency tree legitimately produces long paths, so the cap
        # is there to bound the value, not to second-guess the filesystem.
        raise ValueError("path is too long")
    if _CONTROL_CHARS.search(raw):
        raise ValueError("path may not contain control characters")
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("path may not contain unpaired surrogate characters")
    if "\\" in raw:
        raise ValueError("path may not contain a backslash")
    stripped = raw.strip()
    if stripped.startswith("/"):
        raise ValueError("path must be relative to the server directory")
    cleaned = stripped.strip("/")
    if not cleaned:
        if allow_root:
            return raw
        raise ValueError("a path is required")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError("path may not leave the server directory")
    if not allow_hidden and any(part.startswith(".") for part in parts):
        raise ValueError("access to hidden files and directories is restricted")
    if not parts:
        raise ValueError("a path is required")
    if parts[0].endswith(":") or (len(parts[0]) == 2 and parts[0][1] == ":"):
        raise ValueError("path may not be a drive path")
    return raw


# Console streams from npm/Docker carry the terminal's escape sequences: CSI
# cursor moves and colors (\x1b[1G\x1b[0K, \x1b[31m…m), spinner glyphs, and OSC
# title changes (\x1b]0;…\x07). The panel's <pre> console renders them verbatim,
# so every streamed line comes out as escape-code garbage — most visibly in the
# npm error block printed when a server is stopped (SIGTERM). Strip them here,
# in one place, at the API edge.
_ANSI_ESCAPES = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"      # OSC strings (window titles)
    r"|\x1b\[[0-9;?]*[ -/]*[@-~]"             # CSI sequences (colors, moves)
    r"|\x1b[()][0-9A-Za-z]"                   # charset selects
    r"|\x1b[=>]"
)
_CONTROL_EXCEPT_NL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_console(text):
    """Make a container log stream safe to render in the panel console."""
    if not text:
        return ""
    cleaned = _ANSI_ESCAPES.sub("", text)
    return _CONTROL_EXCEPT_NL.sub("", cleaned).replace("\r\n", "\n").replace("\r", "\n")


def _safe_member_name(raw):
    """Return the relative member path or raise for anything escaping ``dest``."""
    if raw.startswith("/") or "\\" in raw:
        raise ValueError(f"archive member escapes the target directory: {raw!r}")
    if _CONTROL_CHARS.search(raw):
        # The same rule _check_relative_path applies to a browser-supplied path,
        # and for the same reason: these are legal and invisible on the node's
        # filesystem. Without it a NUL-bearing member is refused by the node
        # instead, which surfaces as an opaque 5xx mid-extraction rather than as
        # this route's 400 with the offending name in it.
        raise ValueError(f"archive member has a control character: {raw!r}")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError(f"archive member escapes the target directory: {raw!r}")
    if not parts:
        raise ValueError("archive contains an empty member path")
    if parts[0].endswith(":") or (len(parts[0]) == 2 and parts[0][1] == ":"):
        raise ValueError(f"archive member uses a drive path: {raw!r}")
    return PurePosixPath(*parts)


def _safe_dest(raw):
    """Return the extraction directory as a relative path, or raise.

    ``dest`` arrives from the browser and used to be handed straight to
    ``PurePosixPath``, so ``../../..`` made every member path escape the server's
    own directory before ``_safe_member_name`` — which only ever inspected the
    member — got a say. The node agent refuses such a path too; this is the outer
    of the two locks, and the panel should not be asking in the first place.
    """
    cleaned = (raw or "").strip().strip("/")
    if not cleaned:
        return PurePosixPath()
    if "\\" in cleaned:
        raise ValueError("destination folder may not contain a backslash")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError("destination folder may not leave the server directory")
    if not parts:
        return PurePosixPath()
    if parts[0].endswith(":") or (len(parts[0]) == 2 and parts[0][1] == ":"):
        raise ValueError("destination folder may not be a drive path")
    return PurePosixPath(*parts)


def _extract_zip_members(node, server_id, content, dest):
    """Extract one archive's members onto the node.

    The browser-supplied ZIP is validated wholesale (member count and total
    uncompressed size) before a single member is written, so a hostile archive
    cannot leak bytes to the node. Returns the number of files extracted.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile):
        raise ValueError("the uploaded file is not a valid ZIP archive")
    if len(infos) > ZIP_MAX_MEMBER_COUNT:
        raise ValueError(f"archive has more than {ZIP_MAX_MEMBER_COUNT} entries")
    total = sum(info.file_size for info in infos)
    if total > ZIP_MAX_UNCOMPRESSED_BYTES:
        raise ValueError("archive would extract to more than 512 MB")
    base = _safe_dest(dest)
    extracted = 0
    remaining = ZIP_MAX_UNCOMPRESSED_BYTES
    for info in infos:
        if info.is_dir():
            continue
        name = info.filename
        if "__MACOSX/" in name:
            continue
        try:
            member = base / _safe_member_name(name)
        except ValueError as exc:
            raise ValueError(str(exc))
        try:
            with archive.open(info, "r") as handle:
                # Read with a ceiling rather than read(): upload_file needs the whole
                # member as one bytes object, so this allocation is the extraction's
                # peak memory. The total cap above does not bound it — one honest
                # member may declare the entire 512 MB budget, and deflate compresses
                # a run of zeros so far that a 199 KB request body reaches it.
                cap = min(ZIP_MAX_MEMBER_BYTES, remaining)
                data = handle.read(cap + 1)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError):
            # A truncated local header or an unsupported compression method is a
            # property of the browser-supplied bytes, so it belongs with the
            # other validation failures rather than as an unhandled 500.
            raise ValueError(f"{name}: this archive entry could not be read")
        except RuntimeError:
            # zipfile signals a password-protected member this way.
            raise ValueError(f"{name}: encrypted archives are not supported")
        except (EOFError, OSError):
            raise ValueError(f"{name}: this archive entry could not be read")
        if len(data) > ZIP_MAX_MEMBER_BYTES:
            limit_mb = ZIP_MAX_MEMBER_BYTES // (1024 * 1024)
            raise ValueError(f"{name}: a single file may not exceed {limit_mb} MB")
        if len(data) > remaining:
            raise ValueError("archive expands to more than 512 MB")
        remaining -= len(data)
        node.upload_file(server_id, str(member), data)
        extracted += 1
    return extracted


# The main site's sign-out endpoint. It is GET-only and checks the site's own
# CSRF token in ``t``, so the panel forwards the token it has just validated.
MAIN_SITE_LOGOUT_PATH = "/user/logout"


def build_routes(runtime, config):
    db = runtime.database

    # The quota is enforced by counting the rows list_servers_for_user returns, and
    # that read is capped at SERVER_LIST_MAX. The configured limit is clamped only
    # to 1000, so a configured value above the row cap could never be reached: the
    # count saturates below it, create_server's check never fires, and the account
    # creates node containers without any limit. Clamped once here so the number
    # the pages display is the number that is actually enforced.
    def clamp_max_servers(settings):
        return min(settings.max_servers, SERVER_LIST_MAX)

    def user_max_servers(user, settings):
        """This account's server quota: its own grant, else the fleet figure.

        panel_users.container_slots is NULL for an account the admin console has
        said nothing about, and those get the fleet-wide limit — which is 1, so a
        new account holds one container until someone raises it deliberately. A
        number there, including 0, is a decision about this account specifically
        and wins over the fleet figure in both directions: it is how an account is
        granted more than everyone else, and how one is stopped from deploying at
        all without touching the fleet default that every other account reads.

        Clamped to the row cap for the same reason clamp_max_servers is: the count
        it is compared against comes from a read capped at SERVER_LIST_MAX, so a
        grant above that would never be reached and the check would never fire.
        """
        granted = (user or {}).get("container_slots")
        if granted is None:
            return clamp_max_servers(settings)
        return max(0, min(int(granted), SERVER_LIST_MAX))

    async def max_servers_now(user=None):
        """The enforced per-account server quota, from the database's snapshot."""
        return user_max_servers(user, await runtime.settings.load())

    def quota_step(used, limit):
        """How full the quota bar is, in tenths (0-10).

        The bar's width comes from a stylesheet class rather than a ``style``
        attribute, because /panel's CSP forbids inline style — and a class per
        whole percent would be 101 rules for a bar a few pixels tall. Tenths are
        the resolution that matters when the limit is single digits. One server
        out of many still lights the first tenth: a used quota that renders as an
        empty bar reads as "none", which is the one thing it is not.
        """
        if limit <= 0 or used <= 0:
            return 0
        return max(1, min(10, (10 * used) // limit))

    # -- small helpers -----------------------------------------------------

    def redirect_to(endpoint, status_code=303, **values):
        return RedirectResponse(templating.url_for(endpoint, **values), status_code=status_code)

    def wants_json(request):
        return request.headers.get("x-requested-with", "").lower() == "fetch"

    async def render(request, template_name, *, endpoint="", context=None, status_code=200, current_user=None):
        # Async, and it loads the settings snapshot itself, because base.html
        # renders the maintenance banner and the allocation figure on *every*
        # page: passing the snapshot per route would mean a route that forgot it
        # shows no banner while maintenance is on. The read is cached per process
        # (see panel_settings.CACHE_SECONDS), so this costs no round trip.
        return templating.render(
            request,
            template_name,
            endpoint=endpoint,
            context=context,
            status_code=status_code,
            config=config,
            current_user=current_user,
            settings=await runtime.settings.load(),
        )

    async def maintenance_block(request, message=None):
        """Refuse a state-changing request while maintenance mode is on.

        Returns the response to send, or ``None`` when the action may proceed, so
        a route reads ``blocked = await maintenance_block(request)``. JSON APIs
        get 503 with the operator's banner text; form posts get a flash and go
        back to the dashboard, which is where a panel user can see the banner.
        """
        settings = await runtime.settings.load()
        if settings.writes_allowed():
            return None
        text = message or settings.maintenance_message
        if _is_form_post(request):
            templating.flash(request, text, "error")
            return redirect_to("dashboard")
        # 503 rather than 403: this is a temporary refusal by the operator, and
        # Retry-After tells a client it is worth coming back.
        return JSONResponse(
            {"ok": False, "error": text},
            status_code=503,
            headers={"Retry-After": RETRY_AFTER_SECONDS},
        )

    async def feature_block(request, flag, message):
        """Refuse a request when the named feature switch is off.

        Same contract as :func:`maintenance_block`. Maintenance is checked first
        by the routes that use both, so this only ever reports its own switch.
        """
        settings = await runtime.settings.load()
        if bool(settings.flags.get(flag, True)):
            return None
        if _is_form_post(request):
            templating.flash(request, message, "error")
            return redirect_to("dashboard")
        return JSONResponse({"ok": False, "error": message}, status_code=403)

    def check_csrf(request, supplied):
        if not auth.csrf_ok(request, supplied):
            raise auth.CsrfError()

    def csrf_from(request, container):
        """The token this request presents, as text.

        ``hmac.compare_digest`` inside ``auth.csrf_ok`` raises ``TypeError`` for a
        non-string, and both sources here can produce one: a form field arrives
        as an ``UploadFile`` when the client sends it as a file part, and a JSON
        field can be any type. That turned every CSRF *rejection* on a crafted
        request into an unhandled 500, so the token is narrowed to text — and an
        empty string is what ``csrf_ok`` already refuses.
        """
        header = request.headers.get("x-csrf-token")
        if isinstance(header, str) and header:
            return header
        supplied = container.get("csrf_token", "")
        return supplied if isinstance(supplied, str) else ""

    async def json_body(request):
        try:
            payload = await request.json()
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}

    def bad_request(message, status_code=400):
        return JSONResponse({"ok": False, "error": message}, status_code=status_code)

    def throttled(bucket, message):
        retry_after = str(_THROTTLES[bucket][1])
        return JSONResponse(
            {"ok": False, "error": message},
            status_code=429,
            headers={"Retry-After": retry_after},
        )

    async def log_activity(user_id, action, server_id=None, detail=None):
        # Activity persistence is off by default: the store's activity table lives
        # in the shared backend database, and every power toggle / upload / command
        # would otherwise append a row to it for the life of the deployment. All
        # call sites route through this helper, so the early return disables the
        # whole audit trail in one place. The switch is the database-backed one
        # (PANEL_ACTIVITY_ENABLED is only the fallback when the settings table
        # cannot be read), so an operator can turn the trail on for both instances
        # without a restart.
        settings = await runtime.settings.load()
        if not settings.activity_log:
            return
        try:
            await db.log_activity(user_id, action, server_id=server_id, detail=detail)
        except Exception as exc:
            _log.warning(
                "activity %s for server %s not recorded (%s)",
                action, server_id, type(exc).__name__,
            )

    def server_id_of(request):
        """The validated ``server_id`` path parameter.

        Starlette's ``{server_id}`` matches any run of non-slash characters, so
        without this every server route handed an arbitrary string to an Oracle
        bind against a VARCHAR2(36) column and to a node URL. A 404 is the right
        answer either way: an id that cannot exist is indistinguishable from one
        that belongs to somebody else, which is also what ``owned_server``
        reports.
        """
        server_id = id_mask.unmask_server_id(request.path_params.get("server_id", ""))
        if not server_id:
            raise HTTPException(status_code=404)
        return server_id

    async def owned_server(server_id, user):
        server = await db.get_server_for_user(server_id, user["id"])
        if server is None:
            raise HTTPException(status_code=404)
        return server

    async def own_server_from(request, user):
        """Validate the path's server id and prove this user owns it.

        Every server-scoped route goes through here or ``own_server_client``, so
        the ownership check and the id validation cannot be forgotten
        independently of one another.
        """
        server_id = server_id_of(request)
        await owned_server(server_id, user)
        return server_id

    def node_id_of_server(server):
        if isinstance(server, dict):
            return server.get("node_id")
        if server is None:
            return None
        return getattr(server, "node_id", None)

    async def _node_address_of(server):
        """The host address(es) a server's node was registered at.

        Stored on the pending-deletion tombstone so the admin panel can show
        which host still holds a deferred container without a later registry
        lookup having to succeed. Empty when the node cannot be resolved —
        the tombstone's node_id label is then the only pointer.
        """
        node_id = node_id_of_server(server)
        if node_id is None:
            return ""
        try:
            import node_registry
            creds = await run_in_threadpool(
                lambda: node_registry.get_node_credentials(node_id)
            )
        except Exception:
            return ""
        hosts = []
        for origin in str((creds or {}).get("url") or "").split(","):
            host = (parse.urlsplit(origin.strip()).hostname or "").strip()
            if host and host not in hosts:
                hosts.append(host)
        return ",".join(hosts)

    async def client_for_node_id(node_id):
        router = getattr(runtime, "node_router", None)
        if router is None:
            raise NodeClientError(
                "no enabled node found in the database — register a node first"
            )
        return await router.client_for(node_id)

    async def reachable_client_for_node_id(node_id):
        router = getattr(runtime, "node_router", None)
        if router is None:
            raise NodeClientError(
                "no enabled node found in the database — register a node first"
            )
        return await router.reachable_client_for(node_id)


    async def _background_create(server_id, user_id, name, runtime_name, version, startup, allocation, placement, server_node):
        """Run the node create in background and update the DB.

        On failure the server row is removed so the dashboard does not list
        an unreachable, unbacked server. All errors are logged; activity is
        recorded on success. ``server_node`` is the client the deploy has already
        verified as answering, so the container lands on the node that was
        checked rather than on whatever a second resolution picks a moment later.
        """
        try:
            try:
                response = await run_in_threadpool(
                    lambda: server_node.create_server(
                        server_id=server_id,
                        name=name,
                        runtime=runtime_name,
                        version=version,
                        startup=startup,
                        memory_mb=allocation.memory_mb,
                        cpu_percent=allocation.cpu_percent,
                    )
                )
            except Exception as exc:
                err_msg = str(exc) or type(exc).__name__
                _log.warning("background create failed for %s: %s", server_id, exc)
                try:
                    import reviews_db
                    reviews_db.log_app_error(
                        "ContainerCreateFailed",
                        f"Node container creation failed for server {server_id}: {err_msg}",
                        stack_trace=traceback.format_exc(),
                        module="panel_app.routes",
                        flagged=1,
                        error_category="system_error",
                    )
                except Exception:
                    pass
                p_key = id_mask.public_server_key(server_id)
                _bg_create_errors[server_id] = f"Node container creation failed: {err_msg}"
                _bg_create_errors[p_key] = f"Node container creation failed: {err_msg}"
                try:
                    await run_in_threadpool(lambda: server_node.delete_server(server_id, purge=True))
                except Exception:
                    _log.warning("could not delete orphaned container on node for %s", server_id)
                try:
                    await db.delete_server_for_user(server_id, user_id)
                except Exception as drop_exc:
                    _log.warning(
                        "server %s row left behind after a failed bg create (%s)",
                        server_id, type(drop_exc).__name__,
                    )
                return

            image = ""
            if isinstance(response, dict):
                remote = response.get("server")
                if isinstance(remote, dict):
                    image = str(remote.get("image") or "").strip()
            try:
                await db.update_server_version(server_id, user_id, runtime_name, version, image=image or None)
            except Exception as exc:
                _log.warning("server %s image not recorded (bg): %s", server_id, type(exc).__name__)
            try:
                await run_in_threadpool(
                    lambda: server_node.update_container_config(
                        server_id,
                        {
                            "server_id": server_id,
                            "user_id": user_id,
                            "name": name,
                            "last_state": "running",
                            "state": "running",
                            "total_allocated_space": allocation.memory_mb,
                            "allocated_space": allocation.memory_mb,
                            "memory_mb": allocation.memory_mb,
                            "cpu_percent": allocation.cpu_percent,
                            "startup_parameters": startup,
                            "startup": startup,
                            "runtime": runtime_name,
                            "version": version,
                            "image": image or "",
                        },
                    )
                )
            except Exception as config_exc:
                _log.warning("failed to save .container_config.json for server %s: %s", server_id, config_exc)
            try:
                await log_activity(user_id, "server_created", server_id=server_id, detail=name)
            except Exception:
                _log.warning("failed to record activity for server %s", server_id)
        except Exception:
            _log.exception("unexpected error in background create for %s", server_id)
        finally:
            # Remove the temporary creating marker from the runtime cache so
            # subsequent status polls fetch the real state from the node.
            try:
                cache_key = str(placement or "")
                cache = runtime._node_list_caches.get(cache_key)
                if cache and isinstance(cache.get("data"), dict):
                    cache["data"].pop(server_id, None)
            except Exception:
                pass

    async def client_for_server(server):
        return await client_for_node_id(node_id_of_server(server))

    async def own_server_client(request, user):
        server_id = server_id_of(request)
        server = await owned_server(server_id, user)
        return server_id, await client_for_server(server)

    async def status_map_for(servers, *, blocking=True):
        keys = {}
        for server in servers:
            node_id = node_id_of_server(server)
            keys.setdefault(str(node_id or ""), node_id)
        if not keys:
            return {}
        # An unreachable node costs the caller its status decoration and nothing
        # else. Both callers read this map through _effective_status, which falls
        # back to the server's recorded desired_state for any id it has no entry
        # for, so an empty map renders the same rows. Letting the error out
        # instead meant one node the panel could not route to 500ed the whole
        # dashboard — and api_status_map with it, every six seconds.
        fan_out = getattr(runtime, "node_servers_for", None)
        if fan_out is None or keys.keys() == {""}:
            try:
                return await run_in_threadpool(
                    lambda: runtime.get_node_servers(blocking=blocking)
                )
            except NodeClientError:
                return {}
        merged = {}
        for cache_key, node_id in keys.items():
            # Per node, so one dead node does not blank the servers on the ones
            # that are answering.
            try:
                client = await client_for_node_id(node_id)
                merged.update(
                    await run_in_threadpool(lambda: fan_out(cache_key, client, blocking=blocking))
                )
            except NodeClientError as exc:
                _log.warning("status map for node %s unavailable: %s", node_id, exc)
        return merged

    async def gather(*factories):
        """Await independent things concurrently, results in argument order.

        Each argument is a zero-argument callable returning an awaitable, so a
        caller passes ``lambda: db.get(...)`` rather than a coroutine that would
        already have been created.

        A child's exception is captured and re-raised here rather than escaping
        the task group, because anyio wraps whatever a child raises in an
        ExceptionGroup — and Starlette matches handlers on the exception's own
        type, so a route's ``HTTPException(404)`` would have become a 500.
        BaseException is deliberately not caught: cancellation has to keep
        propagating through the group as itself.

        Only for work that does not contend for the same resource. Node-agent
        calls overlapped with an Oracle query are the intended use; two Oracle
        queries are not, because the panel's pool is two sessions per process
        (see panel_app.database) and a request that took both would be competing
        with every other request for the whole pool.
        """
        results = [None] * len(factories)
        errors = []

        async def run(index, factory):
            try:
                results[index] = await factory()
            except Exception as exc:
                errors.append(exc)

        async with anyio.create_task_group() as task_group:
            for index, factory in enumerate(factories):
                task_group.start_soon(run, index, factory)
        if errors:
            raise errors[0]
        return results

    async def node_json(call):
        """Run a synchronous node call and JSON-encode it, mapping errors."""
        try:
            return JSONResponse(await run_in_threadpool(call))
        except NodeClientError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=exc.status)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    # -- auth / entry ------------------------------------------------------

    async def index(request):
        return redirect_to("dashboard")

    async def favicon(request):
        return PlainTextResponse("", status_code=204)

    async def sw_js(request):
        """Serve the shared service worker script used by the host app.

        This keeps the browser's SW fetch happy even when the panel is mounted as a
        separate sub-app; a missing route here yields a 404 on the exact path many
        browsers probe automatically.
        """
        sw_path = Path(__file__).resolve().parents[1] / "sw.js"
        try:
            body = sw_path.read_bytes()
        except OSError:
            return PlainTextResponse("", status_code=404)
        return PlainTextResponse(body.decode("utf-8", "replace"), media_type="application/javascript")

    async def blocked_page(request):
        # The destination g7.js (panel copy) sends a visitor to when
        # PANEL_GUARD_MODE=gate finds a blocker. The main site's /blocked does
        # not exist on the panel mount, so before this route a gated panel
        # visitor landed on a 404 with no way back. The template's
        # data-guard="blocked" runs the same poll-and-forward boot: back to the
        # stored return path within 5 s of the blocker coming off.
        # No require_user here, deliberately: this page is how a blocked visitor
        # gets back, so gating it made recovery impossible for the signed-out —
        # LoginRequired sent them to the main site's login, and with that site's
        # guard also gating they were forwarded to its /blocked and bounced
        # between tiers instead. Nothing here is per-visitor to leak: the
        # template is static prose plus the mount prefix.
        return await render(request, "blocked.html", endpoint="blocked_page")

    async def blocked_clear(request):
        # The blocked page's guard script (g7.js returnHome) POSTs here before
        # sending a visitor back to their destination. On the main site this
        # drops the ad-wall session; the panel mount has no such session, so
        # this exists only to answer that POST with a 204 instead of the 404
        # that used to land in every recovering visitor's console. No auth and
        # no state: nothing here is per-visitor to act on.
        return PlainTextResponse("", status_code=204)

    async def maintenance_page(request):
        # Where MaintenanceMiddleware sends every browser request while the flag
        # is on. No require_user, for the same reason blocked_page has none: the
        # session middleware is installed *inside* that gate, so a signed-out
        # visitor arrives here without one, and requiring identity would bounce
        # them to the main site's login only for its "next" to send them back.
        #
        # 503, not 200: this is a real refusal, and the status is what keeps a
        # crawler or a monitor from recording the maintenance page as the panel.
        settings = await runtime.settings.load()
        if not settings.maintenance:
            # Reachable directly, and once the window closes a browser still
            # holding the page reloads into it (the template's meta refresh).
            # Forwarding rather than rendering a stale notice is what makes that
            # refresh the mechanism that returns the visitor to the panel.
            return redirect_to("dashboard")
        response = await render(
            request, "maintenance.html", endpoint="maintenance_page", status_code=503
        )
        response.headers["Retry-After"] = RETRY_AFTER_SECONDS
        return response

    async def logout(request):
        # There is no panel session to clear: the sid cookie belongs to the main
        # site, and only that site can invalidate the record behind it. So this
        # route hands the sign-out over rather than half-clearing it here.
        await auth.require_user(runtime, request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        # check_csrf has just proved a token exists and matches, so the hand-off
        # can never be reached with an empty ``t`` (which the main site ignores).
        # Prefer the main site's single-use sign-out token when the session
        # carries one — the main site accepts both, but the single-use one is
        # the one that cannot replay out of a captured URL. Sessions that never
        # rendered a main-site page fall back to the CSRF token.
        session = auth.flask_session(request)
        token = str(session.get("_logout_token") or "").strip() \
            or auth.flask_csrf_token(request)
        return RedirectResponse(
            f"{config.main_site_url}{MAIN_SITE_LOGOUT_PATH}?t={quote(str(token), safe='')}",
            status_code=303,
        )

    # -- home (retired; forwards to the dashboard) --------------------------

    async def home(request):
        # The landing page is gone. Everything it held is elsewhere already: the
        # "Create a server" card is the nav's Deploy server entry, and the quota
        # figure is on both the dashboard and the account page — so the page only
        # ever cost a click on the way to the dashboard. The path stays as a
        # forward so an existing bookmark, or a /panel/home link sent to someone,
        # still lands there instead of on a 404. No require_user here: the
        # dashboard performs that check, and doing it twice would send a
        # signed-out visitor back to this dead path after login.
        return redirect_to("dashboard")

    # -- dashboard / servers ----------------------------------------------

    async def _trial_status(user):
        """The host account's trial clock for the Renew card, or None.

        The panel has no trial of its own; it reads the host app's users row
        through the sync ``database`` module (lazy-imported so its Oracle DDL
        does not run at panel import time). Only meaningful when the login *is*
        the Oracle account — the local smoke-test users have no trial — so it is
        gated on auth_mode. Any failure returns None: a renew banner must never
        be the reason the dashboard 500s.
        """
        if config.auth_mode != "oracle":
            return None

        def _lookup():
            import database
            return database.get_user(user["id"])

        try:
            row = await run_in_threadpool(_lookup)
        except Exception as exc:
            _log.warning("trial status lookup failed: %s: %s", type(exc).__name__, exc)
            return None
        if not row or row.get("account_type") != "trial":
            return None
        expires_raw = row.get("trial_expires_at")
        days_left = None
        if expires_raw:
            try:
                import math
                from datetime import datetime, timezone
                exp = datetime.fromisoformat(str(expires_raw))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                total = (exp - datetime.now(timezone.utc)).total_seconds()
                days_left = max(0, math.ceil(total / 86400))
            except Exception:
                days_left = None
        stopped = bool(row.get("bot_stopped_at"))
        # Renew only opens inside the window before the turn-off date (an
        # already-stopped trial is inside its grace period, so always open).
        # renew_user enforces the same rule; this only decides what the card
        # offers. The window default lives in the renew_config file.
        try:
            import renew_config
            window = int(renew_config.RENEW_WINDOW_DAYS)
        except Exception:
            window = 3
        if stopped:
            renew_open = True
            opens_in = 0
        elif days_left is None:
            renew_open = True
            opens_in = 0
        else:
            renew_open = days_left <= window
            opens_in = max(0, days_left - window)
        return {
            "is_trial": True,
            "days_left": days_left,
            "stopped": stopped,
            "renew_open": renew_open,
            "renew_opens_in": opens_in,
            "renew_window_days": window,
        }

    async def dashboard(request):
        user = await auth.require_user(runtime, request)
        servers = await db.list_servers_for_user(user["id"])
        # blocking=False: this page must not wait on the node agent. See
        # PanelRuntime.node_servers_for — q2.js corrects the statuses from
        # /api/servers/status a tick later, and a stale or empty map renders the
        # same rows an unreachable agent would.
        node_map = await status_map_for(servers, blocking=False)
        statuses = {
            server["id"]: _effective_status(
                (node_map.get(server["id"], {}) or {}).get("status"),
                server.get("desired_state"),
            )
            for server in servers
        }
        node_install = {
            server["id"]: (node_map.get(server["id"], {}) or {}).get("install_status", "idle")
            for server in servers
        }
        running = sum(1 for status in statuses.values() if status == "running")
        # Per-server allocation comes from the settings snapshot rather than from
        # literals here, so the figures the dashboard totals up are the same ones
        # node_client requests when it creates a container.
        settings = await runtime.settings.load()
        stats = {
            "total": len(servers),
            "running": running,
            "memory_mb": len(servers) * settings.memory_mb,
            "storage_mb": len(servers) * settings.disk_mb,
            "cpu_percent": len(servers) * settings.cpu_percent,
        }
        max_servers = user_max_servers(user, settings)
        trial = await _trial_status(user)
        return await render(
            request,
            "dashboard.html",
            endpoint="dashboard",
            current_user=user,
            context={
                "servers": servers,
                "max_servers": max_servers,
                "statuses": statuses,
                "node_install": node_install,
                "stats": stats,
                "quota_step": quota_step(len(servers), max_servers),
                "trial": trial,
            },
        )

    async def renew(request):
        """Trial 'Renew' from the panel home.

        Extends the host account's trial by another cycle and restarts any
        server the inactivity policy stopped — the panel-native equivalent of
        the main site's POST /api/user/<id>/renew. Gated to Oracle trial
        accounts and throttled to once a day, matching that endpoint. Non-renewal
        is handled elsewhere (the host app resets a lapsed trial to fresh); this
        only offers the keep-alive.
        """
        user = await auth.require_user(runtime, request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        if config.auth_mode != "oracle":
            templating.flash(request, "Renewal is managed by your main account sign-in.", "error")
            return redirect_to("dashboard")
        if not _throttle(user["id"], "renew"):
            templating.flash(request, "You can renew once a day. Try again tomorrow.", "error")
            return redirect_to("dashboard")

        def _do():
            import database
            row = database.get_user(user["id"])
            if not row or row.get("account_type") != "trial":
                return "not_trial"
            return database.renew_user(user["id"])

        try:
            status = await run_in_threadpool(_do)
        except Exception as exc:
            _log.warning("renew failed for %s: %s: %s", user["id"], type(exc).__name__, exc)
            templating.flash(request, "Could not renew right now — please try again in a moment.", "error")
            return redirect_to("dashboard")
        if status == "renewed":
            await log_activity(user["id"], "trial_renewed")
            templating.flash(request, "Trial renewed — your servers keep running for another cycle.", "success")
        elif status == "too_early":
            templating.flash(request, "It's not time to renew yet — you can renew closer to your turn-off date.", "message")
        else:
            templating.flash(request, "Your account does not need renewal.", "message")
        return redirect_to("dashboard")

    async def batch_power(request):
        user = await auth.require_user(runtime, request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        action = _form_text(form, "action").strip().lower()
        if action not in {"start", "stop"}:
            raise HTTPException(status_code=400)
        if not _throttle(user["id"], "batch_power"):
            templating.flash(request, "Too many power requests — try again in a minute", "error")
            return redirect_to("dashboard")
        servers = await db.list_servers_for_user(user["id"])
        errors = []
        unrecorded = []
        for server in servers:
            # Resolving the node is inside the try so one node the panel cannot
            # route to costs its own servers and no others: outside it, the first
            # unreachable node abandoned the whole batch, including the servers on
            # nodes that were answering.
            try:
                server_node = await client_for_server(server)
                lock = _server_locks.setdefault(server["id"], asyncio.Lock())
                async with lock:
                    await run_in_threadpool(server_node.power, server["id"], action)
            except NodeClientError:
                errors.append(server["name"])
            else:
                # Same rule as api_power: persist intent only for the servers the
                # node actually powered, so a partial failure leaves the rest of
                # the fleet's recorded state accurate.
                try:
                    await db.update_server_state(server["id"], user["id"], action == "start")
                    new_state = "running" if action == "start" else "stopped"
                    await run_in_threadpool(
                        lambda: server_node.update_container_config(
                            server["id"],
                            {"last_state": new_state, "state": new_state, "last_power_action": action},
                        )
                    )
                except Exception as exc:
                    _log.warning(
                        "server %s power state not recorded (%s)",
                        server["id"], type(exc).__name__,
                    )
                    unrecorded.append(server["name"])
        await log_activity(
            user["id"], "batch_power",
            detail=f"{action}: {len(servers) - len(errors)}/{len(servers)} servers",
        )
        if errors:
            templating.flash(request, f"Could not {action} some servers: {', '.join(errors[:3])}", "error")
        elif servers:
            templating.flash(request, f"All {len(servers)} servers {_POWER_DONE[action]}", "success")
        else:
            templating.flash(request, "No servers to " + action, "error")
        if unrecorded:
            templating.flash(
                request,
                f"Some servers were {_POWER_DONE[action]}, but the panel could not "
                f"record it — {', '.join(unrecorded[:3])} may show the wrong status",
                "error",
            )
        return redirect_to("dashboard")

    async def new_server(request):
        user = await auth.require_user(runtime, request)
        # The catalog is an HTTP call to the node agent and the count is an Oracle
        # query, so overlapping them contends for nothing.
        (runtimes, _), servers = await gather(
            lambda: run_in_threadpool(runtime.cached_runtimes),
            lambda: db.list_servers_for_user(user["id"]),
        )
        current_count = len(servers)
        settings = await runtime.settings.load()
        return await render(
            request,
            "new_server.html",
            endpoint="new_server",
            current_user=user,
            context={
                "runtimes": runtimes,
                "current_count": current_count,
                "max_servers": user_max_servers(user, settings),
                "turnstile_site_key": turnstile.site_key() if turnstile.enabled() else "",
            },
        )

    async def create_server(request):
        user = await auth.require_user(runtime, request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        # Verify the Turnstile challenge before anything expensive runs.
        if not turnstile.verify(
            _form_text(form, "cf-turnstile-response"),
            auth.client_ip(request, config.trust_proxy),
        ):
            msg = "Verification failed — complete the challenge and try again"
            if wants_json(request):
                return JSONResponse({"ok": False, "error": msg}, status_code=400)
            templating.flash(request, msg, "error")
            return redirect_to("new_server")
        blocked = await maintenance_block(request)
        if blocked is None:
            blocked = await feature_block(
                request, "deploys", "New deployments are paused right now."
            )
        if blocked is not None:
            return blocked

        # Per-user lock serializes quota check → insert → post-check to close the
        # TOCTOU window where two concurrent requests both see under-quota then
        # both insert.
        lock = _user_create_locks.setdefault(str(user["id"]), asyncio.Lock())
        async with lock:
            current_count = len(await db.list_servers_for_user(user["id"]))
            max_servers = await max_servers_now(user)
            if current_count >= max_servers:
                msg = f"Server limit reached: you already have {current_count} of {max_servers} allowed servers."
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=400)
                templating.flash(request, msg, "error")
                return redirect_to("dashboard")
            if not _throttle(user["id"], "create_server"):
                msg = "Too many create attempts — try again in a few minutes"
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=429)
                templating.flash(request, msg, "error")
                return redirect_to("new_server")
            name = _form_text(form, "name").strip()
            rt = _form_text(form, "runtime").strip().lower()
            version = _form_text(form, "version").strip()
            startup = _form_text(form, "startup").strip()
            if (
                not name
                or len(name) > MAX_NAME_CHARS
                or _CONTROL_CHARS.search(name)
                or not startup
                or len(startup) > MAX_STARTUP_CHARS
                or _CONTROL_CHARS.search(startup)
            ):
                msg = "Enter a valid server name and startup command"
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=400)
                templating.flash(request, msg, "error")
                return redirect_to("new_server")
            if (
                not rt
                or not version
                or len(rt) > MAX_RUNTIME_CHARS
                or len(version) > MAX_RUNTIME_CHARS
                or _CONTROL_CHARS.search(rt)
                or _CONTROL_CHARS.search(version)
            ):
                msg = "Pick a valid runtime and version from the list"
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=400)
                templating.flash(request, msg, "error")
                return redirect_to("new_server")
            try:
                placeable = await db.can_place_new_server()
            except Exception as exc:
                _log.warning("new server placement probe failed, creating anyway: %s", exc)
                placeable = True
            if not placeable:
                msg = "No node capacity is available right now — please try again later or contact support"
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=503)
                templating.flash(
                    request,
                    msg,
                    "error",
                )
                return redirect_to("new_server")
            server_id = str(uuid.uuid4())
            allocation = await runtime.settings.load()
            try:
                placement = await db.create_server(
                    server_id=server_id, user_id=user["id"], name=name,
                    runtime=rt, version=version, image="", startup=startup,
                )
            except ValueError as exc:
                if getattr(exc, "code", None) == "node_capacity_exhausted":
                    message = "No capacity is available right now — please try again later or contact support"
                else:
                    message = f"Could not create server: {exc}"
                try:
                    import reviews_db
                    reviews_db.log_app_error("ContainerCreateDbError", message, module="panel_app.routes", flagged=1, error_category="system_error")
                except Exception:
                    pass
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": message}, status_code=400)
                templating.flash(request, message, "error")
                return redirect_to("new_server")
            except Exception as exc:
                _log.warning("new server row not created (%s)", type(exc).__name__)
                message = f"Database error creating server: {exc}"
                try:
                    import reviews_db
                    reviews_db.log_app_error("ContainerCreateDbError", message, stack_trace=traceback.format_exc(), module="panel_app.routes", flagged=1, error_category="system_error")
                except Exception:
                    pass
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": message}, status_code=500)
                templating.flash(request, message, "error")
                return redirect_to("new_server")

            if len(await db.list_servers_for_user(user["id"])) > max_servers:
                try:
                    await db.delete_server_for_user(server_id, user["id"])
                except Exception as drop_exc:
                    _log.warning(
                        "server %s row left behind after a quota rollback (%s)",
                        server_id, type(drop_exc).__name__,
                    )
                msg = f"Server limit reached: you already have {max_servers} allowed servers."
                if wants_json(request):
                    return JSONResponse({"ok": False, "error": msg}, status_code=400)
                templating.flash(request, msg, "error")
                return redirect_to("dashboard")

        try:
            server_node = await reachable_client_for_node_id(placement)
        except NodeClientError as exc:
            try:
                await db.delete_server_for_user(server_id, user["id"])
            except Exception as drop_exc:
                _log.warning(
                    "server %s row left behind after an unreachable node (%s)",
                    server_id, type(drop_exc).__name__,
                )
            node_err = str(exc) or "node is unreachable"
            _log.warning("server %s not created, node unavailable: %s", server_id, node_err)
            message = f"Hosting node error: {node_err}"
            try:
                import reviews_db
                reviews_db.log_app_error("ContainerCreateNodeError", f"Node unavailable for server {server_id}: {node_err}", module="panel_app.routes", flagged=1, error_category="system_error")
            except Exception:
                pass
            if wants_json(request):
                return JSONResponse({"ok": False, "error": message}, status_code=502)
            templating.flash(request, message, "error")
            return redirect_to("new_server")

        # Schedule the create to run in background; the reconcile sweep will
        # clean up orphans if something goes wrong on the node side.
        # Mark the server as "creating" in the runtime's in-memory node list
        # cache so the UI shows an in-progress state immediately.
        try:
            cache_key = str(placement or "")
            cache = runtime._node_list_caches.setdefault(cache_key, {"data": {}, "fetched_at": 0.0, "failed_at": 0.0})
            cache["data"][server_id] = {"id": server_id, "status": "created", "install_status": "running"}
            cache["fetched_at"] = time.time()
        except Exception:
            _log.exception("failed to set creating marker for %s", server_id)
        asyncio.create_task(_background_create(server_id, user["id"], name, rt, version, startup, allocation, placement, server_node))
        await log_activity(user["id"], "server_create_started", server_id=server_id, detail=name)
        if wants_json(request):
            # No flash on this path. q3.js narrates the deploy in its modal and
            # only opens the panel once the node confirms the container, so a
            # "creation started" flash queued here would be carried across that
            # navigation by FlashMiddleware and land on the panel of a server that
            # has already finished — telling the reader to wait for something they
            # are looking at.
            return JSONResponse(
                {
                    "ok": True,
                    "server_id": id_mask.mask_server_id(server_id),
                    "status_key": id_mask.public_server_key(server_id),
                    "server_url": templating.url_for("server_page", server_id=server_id),
                },
                status_code=202,
            )
        # The no-JS path lands on the panel while the container is still building,
        # so here the flash is the only thing that says so.
        templating.flash(request, "Server creation started - it may take a few minutes.", "success")
        return redirect_to("server_page", server_id=server_id)

    async def server_page(request):
        user = await auth.require_user(runtime, request)
        # The id is validated before either call so a malformed one still 404s
        # without a node round trip. Ownership (Oracle) and the catalog (node) are
        # independent, so they overlap; gather re-raises owned_server's 404 as
        # itself, and the catalog fetch it wasted is cached for the next caller.
        server_id = server_id_of(request)
        server, (runtimes, _) = await gather(
            lambda: owned_server(server_id, user),
            lambda: run_in_threadpool(runtime.cached_runtimes),
        )
        # Check whether the server is currently being created (background task)
        creating = False
        try:
            # Cache-only: create_server writes the in-progress marker for a fresh
            # deploy just before redirecting here, so the "being created" state is
            # painted with no node round trip at all. A cold direct visit reads no
            # marker and q4.js's first poll corrects the page a moment later.
            node_map = await status_map_for([server], blocking=False)
            info = (node_map.get(server["id"], {}) or {})
            if info.get("status") == "created" and info.get("install_status") == "running":
                creating = True
        except Exception:
            # Silence failures here: status polling will update soon.
            creating = False
        return await render(
            request,
            "server.html",
            endpoint="server_page",
            current_user=user,
            context={
                "server": server,
                "runtimes": runtimes,
                "creating": creating,
            },
        )

    async def delete_server(request):
        user = await auth.require_user(runtime, request)
        server_id = server_id_of(request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        server = await owned_server(server_id, user)
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        if not _throttle(user["id"], "delete_server"):
            templating.flash(request, "Too many delete requests — try again in a few minutes", "error")
            return redirect_to("server_page", server_id=server_id)
        # Slot first: a down agent must not trap the account. Drop the DB row
        # (quota + reconcile allowlist) before any node round-trip, then try a
        # quick physical delete. If the node does not answer, queue HeatWave.
        try:
            await db.delete_server_for_user(server_id, user["id"])
        except Exception as exc:
            _log.warning(
                "server %s row left behind after a delete (%s)",
                server_id, type(exc).__name__,
            )
            templating.flash(
                request,
                "Could not remove the server from your account right now — please try again shortly.",
                "error",
            )
            return redirect_to("server_page", server_id=server_id)
        await log_activity(user["id"], "server_deleted", server_id=server_id)

        node_reached = False
        try:
            server_node = await client_for_server(server)
            alive = await run_in_threadpool(server_node.ping)
            if alive:
                await run_in_threadpool(lambda: server_node.delete_server(server_id, purge=True))
                node_reached = True
        except NodeClientError as exc:
            if getattr(exc, "status", None) == 404:
                node_reached = True
            else:
                _log.warning(
                    "server %s: node unavailable at delete, deferring to the admin panel: %s",
                    server_id, exc,
                )
        except Exception as exc:
            _log.warning("server %s: node delete skipped (%s)", server_id, type(exc).__name__)

        if node_reached:
            templating.flash(request, "Server deleted", "success")
        else:
            try:
                import reviews_db
                reviews_db.enqueue_container_deletion(
                    server_id,
                    node_id=node_id_of_server(server),
                    node_ip=await _node_address_of(server),
                    node_name=await _node_name_of(server),
                    purge=True,
                )
            except Exception:
                pass
            templating.flash(
                request,
                "Server deleted. The hosting node is offline right now — its container is "
                "queued for removal and an admin will clear it from the node.",
                "success",
            )
        return redirect_to("dashboard")

    # -- JSON API ----------------------------------------------------------

    async def api_state(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        return await node_json(lambda: server_node.server_state(server_id))

    async def api_status_map(request):
        user = await auth.require_user(runtime, request)
        servers = await db.list_servers_for_user(user["id"])
        node_map = await status_map_for(servers)
        statuses = {}
        errors_out = {}
        for server in servers:
            s_id = server["id"]
            p_key = id_mask.public_server_key(s_id)
            info = node_map.get(s_id, {}) or {}
            s_err = _bg_create_errors.get(s_id) or _bg_create_errors.get(p_key) or info.get("error")
            status_val = "failed" if s_err else _effective_status(info.get("status"), server.get("desired_state"))
            statuses[p_key] = {
                "status": status_val,
                "install_status": info.get("install_status", "idle"),
                "known": bool(info) or bool(s_err),
                "error": s_err or "",
            }
            if s_err:
                errors_out[p_key] = s_err
        for key, err in list(_bg_create_errors.items()):
            errors_out[key] = err
        running = sum(1 for item in statuses.values() if item["status"] == "running")
        return JSONResponse({"ok": True, "servers": statuses, "errors": errors_out, "running": running, "total": len(servers)})

    async def api_logs(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        tail = request.query_params.get("tail", "250")
        # The node clamps this to 1..1000 by way of int(), so a non-numeric value
        # used to cost a round-trip before coming back as its 400. Refuse the
        # value here instead of letting it be coerced. isdecimal, not isdigit:
        # "²".isdigit() is true while int("²") raises, so the int() in the second
        # half of this condition was reachable with a ValueError nothing catches —
        # a 500 on a read of the caller's own logs.
        if not tail.isdecimal() or not 1 <= int(tail) <= MAX_TAIL_LINES:
            return bad_request(f"tail must be a number between 1 and {MAX_TAIL_LINES}")
        try:
            payload = await run_in_threadpool(lambda: server_node.logs(server_id, tail))
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        except ValueError as exc:
            return bad_request(str(exc))
        if not isinstance(payload, dict):
            return bad_request("node agent returned an unexpected response", 502)
        payload["logs"] = _sanitize_console(payload.get("logs", ""))
        return JSONResponse(payload)

    async def api_power(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        # Two body encodings reach this route. q2.js posts JSON with an
        # X-CSRF-Token header, and the dashboard's per-row power <form> — which
        # templating publishes api_power as an endpoint for, precisely so the
        # buttons work with no JavaScript — posts urlencoded with the token as a
        # field. Reading the body as JSON only left that submit empty, so
        # csrf_from found no token at all and every no-JS power click came back as
        # a CSRF failure while appearing to be wired up.
        as_form = _is_form_post(request)
        payload = await request.form() if as_form else await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        action = _json_text(payload, "action")
        action = (action or "").strip().lower()
        if action not in {"start", "stop", "restart", "kill"}:
            # Validate against the node's power contract before logging: the
            # action is concatenated into panel_activity.action (VARCHAR2(64)),
            # so an unbounded value would overflow the column on Oracle where
            # SQLite silently stored it. batch_power guards the same way.
            if as_form:
                templating.flash(request, "Unsupported power action", "error")
                return redirect_to("dashboard")
            return bad_request("unsupported power action")
        if not _throttle(user["id"], "power"):
            if as_form:
                templating.flash(request, "Too many power requests — slow down", "error")
                return redirect_to("dashboard")
            return throttled("power", "too many power requests — slow down")
        await log_activity(user["id"], "power_" + action, server_id=server_id)
        if as_form:
            # A form submit is a top-level navigation, so it is answered the way
            # the other form routes are. Returning the JSON body fetch() expects
            # would render the raw object as the page.
            try:
                lock = _server_locks.setdefault(server_id, asyncio.Lock())
                async with lock:
                    await run_in_threadpool(lambda: server_node.power(server_id, action))
            except (NodeClientError, ValueError) as exc:
                templating.flash(request, str(exc), "error")
            else:
                # Record intent only once the node accepted it, so a failed stop
                # does not leave the row claiming stopped while the container runs.
                try:
                    await db.update_server_state(server_id, user["id"], action in {"start", "restart"})
                    new_state = "running" if action in {"start", "restart"} else "stopped"
                    await run_in_threadpool(
                        lambda: server_node.update_container_config(
                            server_id,
                            {"last_state": new_state, "state": new_state, "last_power_action": action},
                        )
                    )
                except Exception as exc:
                    _log.warning(
                        "server %s power state not recorded (%s)",
                        server_id, type(exc).__name__,
                    )
                    reverse = "stop" if action in {"start", "restart"} else "start"
                    try:
                        await run_in_threadpool(lambda: server_node.power(server_id, reverse))
                    except Exception as rev_exc:
                        _log.warning(
                            "server %s compensation power(%s) failed (%s)",
                            server_id, reverse, type(rev_exc).__name__,
                        )
                    templating.flash(
                        request,
                        "The power action was applied, but the panel could not record "
                        "it — the status shown may be stale",
                        "error",
                    )
                templating.flash(request, f"Server {_POWER_DONE[action]}", "success")
            return redirect_to("dashboard")
        # JSON path (q2.js / q4.js fetch). Mirrors node_json's error
        # mapping so the same 4xx bodies reach the client, but records the new
        # intent on success — 1 for start/restart, 0 for stop/kill — so a stopped
        # server stays presented as stopped on the next load.
        try:
            lock = _server_locks.setdefault(server_id, asyncio.Lock())
            async with lock:
                result = await run_in_threadpool(lambda: server_node.power(server_id, action))
        except NodeClientError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=exc.status)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        try:
            await db.update_server_state(server_id, user["id"], action in {"start", "restart"})
            new_state = "running" if action in {"start", "restart"} else "stopped"
            await run_in_threadpool(
                lambda: server_node.update_container_config(
                    server_id,
                    {"last_state": new_state, "state": new_state, "last_power_action": action},
                )
            )
        except Exception as exc:
            _log.warning(
                "server %s power state not recorded (%s)",
                server_id, type(exc).__name__,
            )
            reverse = "stop" if action in {"start", "restart"} else "start"
            try:
                await run_in_threadpool(lambda: server_node.power(server_id, reverse))
            except Exception as rev_exc:
                _log.warning(
                    "server %s compensation power(%s) failed (%s)",
                    server_id, reverse, type(rev_exc).__name__,
                )
            if isinstance(result, dict):
                result["warning"] = (
                    "the power action was applied, but the panel could not record "
                    "it — the status shown may be stale"
                )
        return JSONResponse(result)

    async def api_command(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is None:
            blocked = await feature_block(
                request, "console", "The console is disabled right now."
            )
        if blocked is not None:
            return blocked
        command = _json_text(payload, "command")
        # The node caps this at 500 characters and runs it as the argv of a shell
        # inside the container. It was previously forwarded with no type check at
        # all, so a JSON number reached ``(command or "")[:100]`` below and raised
        # TypeError — a 500 rather than a 400.
        if command is None or not command.strip() or len(command) > MAX_COMMAND_CHARS:
            return bad_request(f"command must be between 1 and {MAX_COMMAND_CHARS} characters")
        if "\x00" in command:
            return bad_request("command must not contain a null byte")
        if not _throttle(user["id"], "command"):
            return throttled("command", "too many commands — slow down")
        await log_activity(user["id"], "command", server_id=server_id, detail=command[:100])
        return await node_json(lambda: server_node.send_stdin(server_id, command))

    async def api_update_startup(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        startup = _json_text(payload, "startup")
        startup = None if startup is None else startup.strip()
        if not startup or len(startup) > MAX_STARTUP_CHARS or _CONTROL_CHARS.search(startup):
            return bad_request(
                f"startup command must be between 1 and {MAX_STARTUP_CHARS} characters"
            )
        try:
            response = await run_in_threadpool(lambda: server_node.update_startup(server_id, startup))
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        try:
            await db.update_server_startup(server_id, user["id"], startup)
            await run_in_threadpool(
                lambda: server_node.update_container_config(
                    server_id,
                    {"startup_parameters": startup, "startup": startup},
                )
            )
        except Exception as exc:
            _log.warning(
                "server %s startup command not recorded (%s)",
                server_id, type(exc).__name__,
            )
            if isinstance(response, dict):
                response["warning"] = (
                    "the startup command was changed on the server, but the panel "
                    "could not record it — this page may still show the old value"
                )
        await log_activity(user["id"], "startup_changed", server_id=server_id, detail=startup[:100])
        return JSONResponse(response)

    async def api_rename(request):
        user = await auth.require_user(runtime, request)
        server_id = await own_server_from(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        name = _json_text(payload, "name")
        name = None if name is None else name.strip()
        if not name or len(name) > MAX_NAME_CHARS or _CONTROL_CHARS.search(name):
            return bad_request(f"server name must be between 1 and {MAX_NAME_CHARS} characters")
        await db.update_server_name(server_id, user["id"], name)
        await log_activity(user["id"], "server_renamed", server_id=server_id, detail=name)
        return JSONResponse({"ok": True, "name": name})

    async def api_update_image(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        rt = _json_text(payload, "runtime")
        version = _json_text(payload, "version")
        if rt is None or version is None:
            return bad_request("runtime and version must be text")
        rt = rt.strip().lower()
        version = version.strip()
        if not rt or not version:
            return bad_request("runtime and version are required")
        if (
            len(rt) > MAX_RUNTIME_CHARS
            or len(version) > MAX_RUNTIME_CHARS
            or _CONTROL_CHARS.search(rt)
            or _CONTROL_CHARS.search(version)
        ):
            # Checked here rather than left to the node: the node call runs first,
            # so anything it accepts reaches panel_servers.runtime / .version,
            # which are VARCHAR2(32). Oracle raises on overflow, and by then the
            # image has already been changed on the node.
            return bad_request(
                f"runtime and version must be at most {MAX_RUNTIME_CHARS} characters"
            )
        try:
            response = await run_in_threadpool(lambda: server_node.update_image(server_id, runtime=rt, version=version))
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        # The node's reply carries the tag it actually pulled. Persisting only
        # runtime/version left panel_servers.image holding the previous runtime's
        # tag, and that stale column is what the dashboard and server page show.
        image = ""
        if isinstance(response, dict):
            image = str(response.get("image") or "").strip()
        try:
            await db.update_server_version(
                server_id, user["id"], rt, version, image=image or None
            )
            await run_in_threadpool(
                lambda: server_node.update_container_config(
                    server_id,
                    {"runtime": rt, "version": version, "image": image or ""},
                )
            )
        except Exception as exc:
            _log.warning(
                "server %s runtime change not recorded (%s)",
                server_id, type(exc).__name__,
            )
            if isinstance(response, dict):
                response["warning"] = (
                    "the runtime was changed on the server, but the panel could "
                    "not record it — this page may still show the old version"
                )
        await log_activity(user["id"], "version_changed", server_id=server_id, detail=f"{rt} {version}")
        return JSONResponse(response)

    async def api_server_rebuild(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked

        # rt, not runtime: assigning to `runtime` anywhere in this function would
        # make it a local for the whole body, and the require_user call above reads
        # the closure's PanelRuntime before that assignment. Same spelling as
        # api_update_image above for the same reason.
        rt = _json_text(payload, "runtime")
        version = _json_text(payload, "version")
        startup = _json_text(payload, "startup")

        if rt is None or version is None or startup is None:
            return bad_request("runtime, version, and startup are required")

        rt = rt.strip().lower()
        version = version.strip()
        startup = startup.strip()

        if not rt or not version or not startup:
            return bad_request("runtime, version, and startup are required")

        if len(rt) > MAX_RUNTIME_CHARS or len(version) > MAX_RUNTIME_CHARS:
            return bad_request(f"runtime and version must be at most {MAX_RUNTIME_CHARS} characters")

        if len(startup) > MAX_STARTUP_CHARS or _CONTROL_CHARS.search(startup):
            return bad_request(
                f"startup command must be between 1 and {MAX_STARTUP_CHARS} characters"
            )

        # Check if server is currently running
        was_running = False
        try:
            server_info = await run_in_threadpool(lambda: server_node.server_state(server_id))
            live = server_info.get("server") if isinstance(server_info, dict) else None
            status = ""
            if isinstance(live, dict):
                status = str(live.get("status") or "")
            elif isinstance(server_info, dict):
                status = str(server_info.get("status") or server_info.get("state") or "")
            was_running = status.lower() == "running"
        except Exception:
            # If we can't determine state, assume not running to be safe
            pass

        # Stop server if running
        if was_running:
            try:
                await run_in_threadpool(server_node.power, server_id, "stop")
            except NodeClientError as exc:
                return bad_request(str(exc), exc.status)
            except Exception as exc:
                return bad_request(f"Failed to stop server: {exc}", 500)

        # Update image (runtime + version)
        try:
            image_response = await run_in_threadpool(
                lambda: server_node.update_image(server_id, runtime=rt, version=version)
            )
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        except Exception as exc:
            return bad_request(f"Failed to update image: {exc}", 500)

        # Update startup command
        try:
            startup_response = await run_in_threadpool(
                lambda: server_node.update_startup(server_id, startup)
            )
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        except Exception as exc:
            return bad_request(f"Failed to update startup: {exc}", 500)

        # Update database
        image = ""
        if isinstance(image_response, dict):
            image = str(image_response.get("image") or "").strip()

        try:
            await db.update_server_version(server_id, user["id"], rt, version, image=image or None)
            await db.update_server_startup(server_id, user["id"], startup)
        except Exception as exc:
            _log.warning(f"server {server_id} rebuild not recorded: {exc}")
            # Continue anyway - the node changes succeeded

        await log_activity(user["id"], "server_rebuilt", server_id=server_id, detail=f"{rt} {version} {startup[:50]}")

        return JSONResponse({
            "ok": True,
            "rebuilt": True,
            "runtime": rt,
            "version": version,
            "startup": startup,
            "was_running": was_running
        })

    async def api_reinstall(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        # A reinstall is a full dependency install on the node, so it gets a far
        # tighter ceiling than the middleware's blanket 60 state changes a minute.
        if not _throttle(user["id"], "reinstall"):
            return throttled("reinstall", "too many reinstalls — try again in a few minutes")
        try:
            response = await run_in_threadpool(lambda: server_node.reinstall(server_id))
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        await log_activity(user["id"], "server_reinstalled", server_id=server_id)
        return JSONResponse(response)

    async def api_install_status(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        try:
            payload = await run_in_threadpool(lambda: server_node.install_log(server_id))
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        except ValueError as exc:
            return bad_request(str(exc))
        if isinstance(payload, dict) and "log" in payload:
            payload["log"] = _sanitize_console(payload.get("log", ""))
        return JSONResponse(payload)

    async def api_files(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        path = request.query_params.get("path", "")
        try:
            # Empty is the file manager's root listing, so it stays valid.
            _check_relative_path(path, allow_root=True)
        except ValueError as exc:
            return bad_request(str(exc))
        return await node_json(lambda: server_node.list_files(server_id, path))

    async def api_file(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        # HEAD too: Starlette adds it to any route that declares GET, so without it
        # a HEAD falls through to the write branches below and is answered "invalid
        # CSRF token" — a 400 that describes a problem the caller does not have.
        if request.method in ("GET", "HEAD"):
            path = request.query_params.get("path", "")
            try:
                _check_relative_path(path)
            except ValueError as exc:
                return bad_request(str(exc))
            return await node_json(lambda: server_node.read_file(server_id, path))
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        try:
            path = _check_relative_path(payload.get("path"))
        except ValueError as exc:
            return bad_request(str(exc))
        if request.method == "PUT":
            content = _json_text(payload, "content")
            if content is None:
                return bad_request("content must be text")
            # The node refuses a text write over 2 MiB of UTF-8; measuring the
            # same way here means an oversized editor save is refused without
            # first shipping it across.
            if len(content.encode("utf-8", "surrogatepass")) > WRITE_MAX_CONTENT_BYTES:
                limit_mb = WRITE_MAX_CONTENT_BYTES // (1024 * 1024)
                return bad_request(f"a saved file may not exceed {limit_mb} MB")
            return await node_json(lambda: server_node.write_file(server_id, path, content))
        return await node_json(lambda: server_node.delete_path(server_id, path))

    async def api_directory(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        payload = await json_body(request)
        check_csrf(request, csrf_from(request, payload))
        blocked = await maintenance_block(request)
        if blocked is not None:
            return blocked
        try:
            path = _check_relative_path(payload.get("path"))
        except ValueError as exc:
            return bad_request(str(exc))
        return await node_json(lambda: server_node.create_directory(server_id, path))

    async def api_upload(request):
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        form = await request.form(max_files=5000, max_fields=15000)
        check_csrf(request, csrf_from(request, form))
        blocked = await maintenance_block(request)
        if blocked is None:
            blocked = await feature_block(
                request, "uploads", "File uploads are disabled right now."
            )
        if blocked is not None:
            return blocked
        files = form.getlist("files")
        paths = form.getlist("paths")
        if not files or len(files) != len(paths):
            return bad_request("Select one or more files to upload")
        if not _throttle(user["id"], "upload"):
            return throttled("upload", "too many uploads — slow down")
        # The destination of every part is the matching ``paths`` entry, not the
        # part's own filename, so each one is validated the same way an archive
        # member is: the node would refuse an escaping path, and this is the outer
        # of the two locks. Types are checked because a ``paths`` entry sent as a
        # file part, or a ``files`` entry sent as a text field, used to reach
        # json.dumps / .read() and raise as a 500 instead of a 400.
        for uploaded_file, path in zip(files, paths):
            if not hasattr(uploaded_file, "read"):
                return bad_request("each upload must be sent as a file part")
            try:
                _check_relative_path(path)
            except ValueError as exc:
                return bad_request(str(exc))
        uploaded = []
        try:
            for uploaded_file, path in zip(files, paths):
                content = await uploaded_file.read()
                await run_in_threadpool(lambda p=path, c=content: server_node.upload_file(server_id, p, c))
                uploaded.append(path)
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        await log_activity(user["id"], "files_uploaded", server_id=server_id, detail=", ".join(uploaded[:5]))
        return JSONResponse({"ok": True, "uploaded": uploaded}, status_code=201)

    async def api_extract(request):
        """Extract an uploaded ZIP into the server's file tree.

        The archive is unpacked on the panel side, member by member, through the
        same ``node.upload_file`` pipeline as a normal upload, so the node agent
        needs no new endpoint. The ZIP itself is never stored: the archive bytes
        arrive from the browser, are validated (no absolute paths, no ``..``, a
        total-size and member cap), and only the extracted members are written.
        """
        user = await auth.require_user(runtime, request)
        server_id, server_node = await own_server_client(request, user)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        blocked = await maintenance_block(request)
        if blocked is None:
            blocked = await feature_block(
                request, "uploads", "File uploads are disabled right now."
            )
        if blocked is not None:
            return blocked
        uploaded_zip = form.get("zip")
        if uploaded_zip is None or not hasattr(uploaded_zip, "read") or getattr(uploaded_zip, "size", 0) <= 0:
            return bad_request("select a ZIP file to extract")
        dest = _form_text(form, "dest").strip().strip("/")
        try:
            # ``dest`` is the file manager's current folder, so empty means root.
            _check_relative_path(dest, allow_root=True)
        except ValueError as exc:
            return bad_request(str(exc))
        # One extraction can be thousands of sequential node uploads, each holding
        # a threadpool worker, so this is capped well below the middleware's
        # blanket allowance for state changes.
        if not _throttle(user["id"], "extract"):
            return throttled("extract", "too many extractions — try again in a few minutes")
        content = await uploaded_zip.read()
        try:
            extracted = await run_in_threadpool(
                _extract_zip_members, server_node, server_id, content, dest
            )
        except NodeClientError as exc:
            return bad_request(str(exc), exc.status)
        except ValueError as exc:
            return bad_request(str(exc))
        await log_activity(user["id"], "zip_extracted", server_id=server_id, detail=dest or "/")
        return JSONResponse({"ok": True, "extracted": extracted}, status_code=201)

    async def activity_page(request):
        user = await auth.require_user(runtime, request)
        # The page reads the same switch log_activity writes under, so a trail
        # that is off renders empty rather than showing rows that stopped being
        # appended to at the moment it was switched off.
        settings = await runtime.settings.load()
        entries = await db.list_activity(user_id=user["id"]) if settings.activity_log else []
        return await render(
            request, "activity.html", endpoint="activity_page", current_user=user,
            context={"entries": entries},
        )

    async def account_page(request):
        user = await auth.require_user(runtime, request)
        servers = await db.list_servers_for_user(user["id"])
        max_servers = await max_servers_now(user)
        return await render(
            request, "account.html", endpoint="account_page", current_user=user,
            context={
                "server_count": len(servers),
                "max_servers": max_servers,
                "quota_step": quota_step(len(servers), max_servers),
                "password_local": config.auth_mode == "local",
            },
        )

    async def account_change_password(request):
        user = await auth.require_user(runtime, request)
        form = await request.form()
        check_csrf(request, csrf_from(request, form))
        if config.auth_mode != "local":
            # Oracle owns the password; the panel must not pretend to change it.
            templating.flash(request, "Your password is managed by your main account sign-in.", "error")
            return redirect_to("account_page")
        current_password = _form_text(form, "current_password")
        new_password = _form_text(form, "new_password")
        if len(current_password) > MAX_PASSWORD_CHARS or len(new_password) > MAX_PASSWORD_CHARS:
            # Both are hashed in-process, so without a ceiling the body-size limit
            # is the only bound on what Argon2/PBKDF2 is asked to chew through.
            templating.flash(request, f"Password may not exceed {MAX_PASSWORD_CHARS} characters", "error")
        elif not panel_security.verify_password(current_password, user["password_hash"]):
            templating.flash(request, "Current password is incorrect", "error")
        elif not new_password or len(new_password) < 8:
            templating.flash(request, "Password must be at least 8 characters", "error")
        else:
            try:
                await db.update_user_password(user["id"], panel_security.hash_password(new_password))
            except Exception as exc:
                _log.warning("password not updated: %s", exc)
                templating.flash(request, "Could not update the password — it was not changed", "error")
            else:
                await log_activity(user["id"], "password_changed")
                templating.flash(request, "Password updated", "success")
        return redirect_to("account_page")

    # No admin surface lives in this tier. Operator work — listing accounts,
    # deleting them, resetting a password — runs from the loopback-only console in
    # admin/, which reaches the same ATP schema directly. This tier is served from
    # several load-balanced instances against that one database, so an admin route
    # here would be the same privileged surface exposed N times over, each instance
    # trusting a role flag read from a shared table. The console needs no such
    # route: it is not network-reachable in the first place.

    # -- WebSocket: live console --------------------------------------------

    async def console_ws(websocket: WebSocket):
        """Stream container logs to the browser over a WebSocket.

        The Flask session middleware only runs for HTTP scopes, so the session
        cookie must be resolved manually here.  Once authenticated the handler
        opens a streaming connection to the node agent's ``/logs/follow`` SSE
        endpoint and forwards every chunk as a ``log`` message to the client.
        """
        # Reject a cross-site handshake ---------------------------------
        # Before authenticating: resolve_flask_session below spends a backend HTTP
        # call and an Oracle read, and a socket opened from another origin must
        # not be able to buy those.
        if not _ws_origin_allowed(websocket.headers.get("origin", ""),
                                  websocket.headers.get("host", ""),
                                  config.main_site_url):
            await websocket.close(code=4002, reason="forbidden origin")
            return

        # Authenticate --------------------------------------------------
        from .auth import resolve_flask_session, _FLASK_USER_ID_KEY
        data, unavailable = await resolve_flask_session(config, websocket)
        session = data if isinstance(data, dict) else {}
        uid = str(session.get(_FLASK_USER_ID_KEY) or "").strip()
        if not uid:
            await websocket.close(code=4001, reason="unauthenticated")
            return
        user = await db.get_user(uid)
        if user is None:
            await websocket.close(code=4001, reason="unauthenticated")
            return

        # Validate server id and ownership --------------------------------
        # The id is matched against the same pattern the HTTP routes use rather
        # than merely tested for emptiness: this handler binds it into an Oracle
        # query against a VARCHAR2(36) column, where an arbitrary string is a
        # driver error rather than a miss. owned_server is not reused because it
        # signals a miss with HTTPException, and the exception middleware answers
        # that with an HTTP response — which cannot be sent on a WebSocket scope.
        server_id = id_mask.unmask_server_id(websocket.path_params.get("server_id", ""))
        if not server_id:
            await websocket.close(code=4003, reason="missing server id")
            return
        srv = await db.get_server_for_user(server_id, user["id"])
        if srv is None:
            await websocket.close(code=4004, reason="server not found")
            return

        # The console switch closes the socket before it is accepted, which is
        # what the browser's onclose handler already reports as "console
        # unavailable" — there is no accepted connection to send an error frame
        # down. Reads are gated as well as writes here because attaching is what
        # holds a node connection open for the life of the tab.
        settings = await runtime.settings.load()
        if not settings.console:
            await websocket.close(code=4006, reason="console disabled")
            return

        # The node agent to stream from -----------------------------------
        # Same URL and bearer the NodeClient for this server's own node is built
        # from.
        try:
            server_node = await client_for_server(srv)
        except NodeClientError:
            # Same reason owned_server is not reused above: the exception middleware
            # answers with an HTTP response, which this scope cannot carry.
            await websocket.close(code=4005, reason="node agent unavailable")
            return
        node_url = (getattr(server_node, "base_url", "") or "").rstrip("/")
        node_token = getattr(server_node, "token", "") or ""
        if not node_url or not node_token:
            await websocket.close(code=4005, reason="node agent not configured")
            return

        await websocket.accept()
        await websocket.send_json({"type": "connected"})

        # Stream from node agent -----------------------------------------
        # ``since`` (unix seconds) is set after the owner clicks Clear view, so
        # the follow stream must not replay Docker's historical tail.
        since_raw = ""
        try:
            since_raw = str(websocket.query_params.get("since") or "").strip()
        except Exception:
            since_raw = ""
        since_val = None
        if since_raw:
            try:
                since_val = float(since_raw)
            except (TypeError, ValueError):
                since_val = None
        tail = 0 if since_val else 200
        follow_url = (
            f"{node_url}/api/v1/servers/{parse.quote(server_id, safe='')}/logs/follow"
            f"?tail={tail}"
        )
        if since_val and since_val > 0:
            follow_url += f"&since={since_val}"
        try:
            req = urlrequest.Request(
                follow_url,
                headers={
                    "Authorization": f"Bearer {node_token}",
                    "Accept": "text/event-stream",
                    "User-Agent": "DiscordHostPanel/1.0",
                },
            )
            resp = await run_in_threadpool(lambda: _CONSOLE_OPENER(req, timeout=60))
        except (
            urllib_error.URLError,
            TimeoutError,
            OSError,
            http_client.HTTPException,
            ValueError,
        ) as exc:
            # str(exc) on a URLError embeds the target it failed to reach — i.e.
            # NODE_URL, the node agent's host and port. The browser gets a fixed
            # message worded to match the websocket.close reason just below so the
            # error frame and the close reason agree; the real detail goes to the
            # log for operators.
            _log.warning("console follow-stream connect failed: %s", exc)
            try:
                await websocket.send_json(
                    {"type": "error", "message": "node agent unreachable"}
                )
            except Exception:
                pass
            await websocket.close(code=4002, reason="node agent unreachable")
            return

        # urlopen's timeout is the socket's, so it applies to every later read of
        # the body as well as to the connect. On a follow stream that is a
        # deadline on container silence: a bot idle for the timeout raised
        # TimeoutError mid-stream, and because http.client had already consumed
        # part of a chunk the socket was left unreadable ("cannot read from timed
        # out object") — so the console died on a healthy quiet server and the
        # browser reconnected on a 3s loop. The connect deadline above is what
        # bounds a hung node agent; blocking forever is correct once the stream is
        # established, and the socket closes when the client disconnects.
        try:
            await run_in_threadpool(lambda: resp.fp.raw._sock.settimeout(None))
        except (AttributeError, OSError):
            # Not fatal: only the idle-timeout behaviour above is lost.
            pass

        try:
            buf = ""
            streamed = 0
            while True:
                # read1, not read: read(4096) on a chunked response loops inside
                # http.client until it has all 4096 bytes or the stream ends, so a
                # bot printing one line every few seconds stayed invisible until
                # 4 KB had piled up — minutes of silence, then a wall of text.
                # read1 returns whatever one syscall yields, so a line reaches the
                # browser as soon as the node agent flushes it.
                # anyio.to_thread directly rather than run_in_threadpool, which
                # forwards **kwargs to the callable and so cannot pass a limiter.
                chunk = await anyio.to_thread.run_sync(
                    lambda: resp.read1(4096), limiter=_CONSOLE_THREADS
                )
                if not chunk:
                    break
                streamed += len(chunk)
                buf += chunk.decode("utf-8", errors="replace")
                # An SSE event ends at a blank line, but a partial read can split
                # one anywhere, so only whole events are consumed here and the
                # remainder stays buffered for the next read.
                while "\n\n" in buf:
                    raw_line, buf = buf.split("\n\n", 1)
                    lines = raw_line.split("\n")
                    if any(line.startswith("event:") for line in lines):
                        # The terminating "event:done" frame, which carries an
                        # empty data line of its own — so it cannot be told apart
                        # from a log frame by an empty payload.
                        continue
                    # One frame may carry several "data:" lines (a docker log chunk
                    # holding several lines is encoded that way). The newline
                    # between them belongs to the log text, not to the framing, so
                    # it is put back here — the browser appends this straight into
                    # a <pre>, and without it a whole frame ran onto one line.
                    data_lines = [line[5:] for line in lines if line.startswith("data:")]
                    if not data_lines:
                        # A keep-alive comment, not output. Tested for by the
                        # absence of a data line rather than by an empty payload:
                        # one empty data line is a blank line the container really
                        # printed, and reading that as a keep-alive dropped every
                        # gap in a stack trace.
                        continue
                    await websocket.send_json(
                        {"type": "log", "data": _sanitize_console("\n".join(data_lines) + "\n")}
                    )
                if (
                    streamed > _CONSOLE_MAX_STREAM_BYTES
                    or len(buf) > _CONSOLE_MAX_FRAME_BYTES
                ):
                    _log.warning(
                        "console follow-stream exceeded its byte ceiling: "
                        "server=%s streamed=%d buffered=%d",
                        server_id,
                        streamed,
                        len(buf),
                    )
                    try:
                        await websocket.send_json(
                            {"type": "error", "message": "console stream limit exceeded"}
                        )
                        await websocket.close(
                            code=4007, reason="console stream limit exceeded"
                        )
                    except Exception:
                        pass
                    break
        except (WebSocketDisconnect, OSError, http_client.HTTPException):
            # HTTPException covers IncompleteRead, which is what a chunked stream
            # raises when the node agent closes mid-response (container stopped,
            # agent restarted). It is not an OSError, so it used to escape this
            # handler and surface as an unhandled-error traceback per closed tab.
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass

    return [
        Route("/", index, methods=["GET"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
        Route("/sw.js", sw_js, methods=["GET"]),
        Route("/blocked", blocked_page, methods=["GET"]),
        Route("/blocked/clear", blocked_clear, methods=["POST"]),
        Route(MAINTENANCE_PATH, maintenance_page, methods=["GET"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/home", home, methods=["GET"]),
        Route("/dashboard", dashboard, methods=["GET"]),
        Route("/renew", renew, methods=["POST"]),
        Route("/servers/batch-power", batch_power, methods=["POST"]),
        Route("/servers/new", new_server, methods=["GET"]),
        Route("/servers", create_server, methods=["POST"]),
        Route("/servers/{server_id}", server_page, methods=["GET"]),
        Route("/servers/{server_id}/delete", delete_server, methods=["POST"]),
        Route("/api/servers/status", api_status_map, methods=["GET"]),
        Route("/api/servers/{server_id}/state", api_state, methods=["GET"]),
        Route("/api/servers/{server_id}/logs", api_logs, methods=["GET"]),
        Route("/api/servers/{server_id}/power", api_power, methods=["POST"]),
        Route("/api/servers/{server_id}/command", api_command, methods=["POST"]),
        Route("/api/servers/{server_id}/startup", api_update_startup, methods=["POST"]),
        Route("/api/servers/{server_id}/rename", api_rename, methods=["POST"]),
        Route("/api/servers/{server_id}/image", api_update_image, methods=["POST"]),
        Route("/api/servers/{server_id}/reinstall", api_reinstall, methods=["POST"]),
        Route("/api/servers/{server_id}/install", api_install_status, methods=["GET"]),
        Route("/api/servers/{server_id}/rebuild", api_server_rebuild, methods=["POST"]),
        Route("/api/servers/{server_id}/files", api_files, methods=["GET"]),
        Route("/api/servers/{server_id}/file", api_file, methods=["GET", "PUT", "DELETE"]),
        Route("/api/servers/{server_id}/directory", api_directory, methods=["POST"]),
        Route("/api/servers/{server_id}/upload", api_upload, methods=["POST"]),
        Route("/api/servers/{server_id}/extract", api_extract, methods=["POST"]),
        Route("/activity", activity_page, methods=["GET"]),
        Route("/account", account_page, methods=["GET"]),
        Route("/account/password", account_change_password, methods=["POST"]),
        WebSocketRoute("/ws/console/{server_id}", console_ws),
    ]
vers/{server_id}/directory", api_directory, methods=["POST"]),
        Route("/api/servers/{server_id}/upload", api_upload, methods=["POST"]),
        Route("/api/servers/{server_id}/extract", api_extract, methods=["POST"]),
        Route("/activity", activity_page, methods=["GET"]),
        Route("/account", account_page, methods=["GET"]),
        Route("/account/password", account_change_password, methods=["POST"]),
        WebSocketRoute("/ws/console/{server_id}", console_ws),
    ]

import base64
import errno
import json
import logging
import re
import threading
import time
from http import client as http_client
from urllib import error, parse, request


_log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

# Create is the one call that honestly outlasts DEFAULT_TIMEOUT: the agent pulls
# the runtime image inline when the node has not cached it yet
# (node_agent/docker_runtime.py:74), inside its own NODE_DOCKER_TIMEOUT of 120.
# Expiring here first is the worst way for that to end — a POST that timed out is
# never replayed, so the panel rolls the server row back while the agent goes on
# to finish the container, leaving an orphan for the reconcile sweep to reap and
# the owner with nothing. This has to stay above the node's Docker budget.
CREATE_TIMEOUT = 180

# A node's ``url`` column may list several addresses for the same agent. Four is
# well past the two the fleet needs (loopback + public hostname) and keeps the
# worst-case walk over a firewalled address bounded.
MAX_URL_CANDIDATES = 4

# How long an address that failed to connect is skipped for. It has to outlast a
# connect timeout comfortably: the public hostname of the host an agent runs on
# does not refuse from inside that host, it black-holes, so every attempt there
# costs the full DEFAULT_TIMEOUT. Without the skip the co-located instance would
# pay that on every single request.
URL_COOLDOWN_SECONDS = 60

# The cooldown above is keyed by address and shared by every client in the
# process, because almost nothing here reuses a client: node_router rebuilds on a
# cache miss and runtime._node_client_from_db builds a fresh one per catalog
# fetch. Held per instance, the skip was discarded before it could ever skip
# anything, so each new client walked the black-holed address again and paid
# PROBE_TIMEOUT for it — which is what pushed a cold catalog fetch past the
# deploy page's grace period and made that page claim the agent was unavailable
# until it was reloaded.
_dead_urls = {}
_dead_urls_lock = threading.Lock()

# The reachability probe is deliberately far tighter than a real request: it runs
# before the first call on a multi-address node, so a black-holed address must
# not stall the page that triggered it for a full timeout.
PROBE_TIMEOUT = 3

# A hostile or broken node agent must never be able to stream unbounded bytes
# into the panel process: every body is read with this ceiling and refused past
# it. Generous enough for the two largest replies the panel asks for — a
# 1000-line log tail and a source file read back through /file.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# The error body is only mined for one short string, so it gets a far tighter
# ceiling than a real response.
MAX_ERROR_BYTES = 64 * 1024

# routes.py surfaces this text to the browser and flashes.py stores it in a
# signed cookie, so what the agent supplies is bounded here rather than there.
MAX_ERROR_CHARS = 300

# The node agent pins every container to one memory/CPU allocation and refuses a
# create whose figures disagree with its own (node_agent/app.py:create_server), so
# these are what it enforces today. They are only the defaults here: create_server
# takes the figures the caller resolved from the shared settings table, so a
# console change that the node has not been rebuilt for is refused with the node's
# own "this node enforces N MB" message rather than quietly producing a container
# with a different allocation than the panel just displayed.
DEFAULT_MEMORY_MB = 300
DEFAULT_CPU_PERCENT = 35

# The node agent's per-file ceiling, checked here so an oversized part is refused
# before it is encoded. The agent enforces the same limit on the base64 length
# before decoding, and its own body cap is this figure inflated 4/3, so without a
# local check the panel spends a ~200 MB round trip to be told no. It also caps
# the copies in upload_file: base64 is 4/3, then json.dumps builds a str, then its
# UTF-8 encode — three more copies of the part on top of the bytes handed in.
MAX_UPLOAD_BYTES = 150 * 1024 * 1024


class NodeClientError(RuntimeError):
    def __init__(self, message, status=502, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


class _NoRedirects(request.HTTPRedirectHandler):
    """Refuse every redirect the node agent answers with.

    ``urllib`` follows redirects by default and copies the request headers onto
    the follow-up request, so a 302 from the agent would replay the bearer token
    at an attacker-chosen host and turn this client into an SSRF pivot. Returning
    ``None`` leaves the 3xx to be raised as an ``HTTPError`` instead of followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _timeout(value, fallback):
    """Never yield a falsy or non-numeric timeout.

    ``urllib`` reads ``None`` as "wait forever", which would pin a panel worker
    on a node agent that accepts the connection and then goes silent.
    """
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return fallback
    return seconds if seconds > 0 else fallback


# Errors that prove the request never reached the agent, so re-issuing it at
# another address for the same node cannot repeat a side effect.
_CONNECT_ERRNOS = frozenset(
    getattr(errno, name)
    for name in ("ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ENETDOWN",
                 "EHOSTDOWN", "EADDRNOTAVAIL", "ECONNABORTED", "ECONNRESET")
    if hasattr(errno, name)
)


def _is_connect_failure(exc) -> bool:
    """True when the agent provably never saw the request.

    This is what decides whether a failed attempt may be retried at the node's
    other address for a non-GET. A refused or unroutable connection is safe to
    re-issue; a *timeout* is not, because urllib cannot say whether it expired
    while connecting or after the request body was already accepted, and a
    replayed create would leave two containers behind.
    """
    reason = getattr(exc, "reason", None)
    for candidate in (reason, exc):
        if isinstance(candidate, ConnectionRefusedError):
            return True
        if isinstance(candidate, OSError) and candidate.errno in _CONNECT_ERRNOS:
            return True
        if candidate.__class__.__name__ == "gaierror":
            return True
    return False


def _speaks_agent(code, headers, raw) -> bool:
    """Whether an HTTP error response really came from a node agent.

    A node URL that omits the agent's port lands on whatever else the host
    publishes — usually the public site — and that site's 404 page or its
    redirect to https must not be mistaken for this node's verdict on the
    request, because mistaking it ends the address walk one address too early.
    The agent answers every error as a JSON object and never redirects, so
    anything else means the address is wrong rather than the request. Judged
    permissively in the agent's favour: a JSON content type is taken at its word
    even when the body did not survive, so a real agent error still reports as
    one instead of being retried elsewhere.
    """
    try:
        if 300 <= int(code) < 400:
            return False
    except (TypeError, ValueError):
        pass
    try:
        if "json" in (headers.get("Content-Type") or "").lower():
            return True
    except AttributeError:
        pass
    try:
        return isinstance(json.loads(raw.decode("utf-8")), dict)
    except (AttributeError, UnicodeDecodeError, ValueError):
        return False


def parse_node_urls(value) -> list:
    """The addresses in a node's ``url`` column, in preference order.

    A node may list more than one, separated by commas. They are alternative
    routes to the *same* agent rather than different nodes: the app instance that
    runs beside the agent has to reach it over loopback, while the other instance
    can only reach it by public hostname — and that public name black-holes from
    inside the host that publishes it. Both belong to one row so capacity is
    counted once.

    Validation here stays exactly as permissive per address as this client has
    always been; the strict canonical form is enforced by the registry on write.
    """
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
    else:
        items = [item.strip() for item in (value or "").split(",")]
    urls = []
    for item in items:
        if not item:
            continue
        parsed = parse.urlsplit(item)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("node URL must be an absolute HTTP(S) URL")
        if parsed.query or parsed.fragment:
            # Both would land in front of the path this client appends.
            raise ValueError("node URL must not carry a query string or fragment")
        cleaned = item.rstrip("/")
        if cleaned not in urls:
            urls.append(cleaned)
    if not urls:
        raise ValueError("node URL must be an absolute HTTP(S) URL")
    if len(urls) > MAX_URL_CANDIDATES:
        raise ValueError(f"a node URL lists at most {MAX_URL_CANDIDATES} addresses")
    return urls


def _segment(value) -> str:
    """One URL path segment, with ``/`` and a bare dot run encoded or refused.

    ``parse.quote`` leaves ``/``, ``.`` and ``..`` alone by default, so an id
    carrying them would otherwise walk out of the servers namespace and reach a
    different node-agent endpoint than the caller named.
    """
    segment = parse.quote(str(value), safe="")
    if not segment or segment.strip(".") == "":
        raise ValueError("invalid node resource id")
    return segment


def _text(value: str) -> str:
    """Drop anything that cannot survive a UTF-8 encode.

    ``json.loads`` accepts a lone surrogate, and both ``JSONResponse`` and
    ``HTMLResponse`` encode their body as UTF-8 — so agent text carrying one
    would raise while the panel builds the reply, long after this frame.
    """
    return value.encode("utf-8", "replace").decode("utf-8", "replace")


def _encodable(value):
    if isinstance(value, str):
        return value if value.isascii() else _text(value)
    if isinstance(value, dict):
        return {key: _encodable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_encodable(item) for item in value]
    return value


# The node agent writes its own filesystem paths into 4xx error text: a
# duplicate-name mkdir raises FileExistsError, and a missing target raises
# FileNotFoundError, whose str() embeds the node's real host path
# (/var/lib/dchost/servers/<uuid>/<name>). That path is the node's internal
# layout, not something a panel user may act on, but a logged-in user triggers
# it in one click by reusing a folder name — and _http_error below hands 4xx
# text straight to routes.py, which shows it in the browser and stores it in a
# signed flash cookie. So every absolute path (and anything host-address shaped,
# e.g. a bare host:port a future message might carry) is replaced with a
# placeholder before the text can leave this client. Prose survives, because the
# 4xx messages the user *can* act on — the node's "this node enforces N MB"
# figure and its 503 capacity message — carry no path and are left intact.
_HOST_LEAK_RE = re.compile(
    r"""
      (?:[A-Za-z]:)?(?:/|\\){1,2}[^\s'"]*(?:/|\\)[^\s'"/\\]*  # absolute fs path
    | \b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?                  # IPv4[:port]
    | (?<!\w)\[?
      (?:
          [0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6}
          ::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?
        | ::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6}
        | [0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){7}
      )
      (?:(?:\.\d{1,3}){3})?(?:\](?::\d{1,5})?)?               # [IPv6][:port]
    | \b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}:\d{1,5}\b            # host:port
    | \b(?:node-agent|snode)(?::\d{1,5})?(?![\w.-])           # internal label[:port]
    | \b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*
      \.(?:internal|localdomain|local|lan|vcn|oraclevcn\.com)
      (?::\d{1,5})?(?![\w-])(?!\.[A-Za-z0-9])                 # internal hostname[:port]
    """,
    re.VERBOSE,
)


def _redact_host_leak(text: str) -> str:
    """Strip absolute paths and host:port tokens out of node-authored text.

    The node agent's error strings are attacker-influenceable (the user picks
    the folder name that lands in a FileExistsError path) and are never trusted
    as prose past this point, so any token that reveals the node's filesystem
    layout or an internal address is replaced rather than quoted back.
    """
    return _HOST_LEAK_RE.sub("[redacted]", text)


def _redact_payload_host_leak(value):
    """Recursively redact host/path leaks from a decoded error payload.

    routes.py JSON-encodes ``NodeClientError.payload`` back to the browser, so a
    node that repeats the offending path under a second key (``path``, ``detail``)
    would reopen the hole the message redaction just closed. Strings are cleaned,
    containers are walked; other scalars pass through untouched.
    """
    if isinstance(value, str):
        return _redact_host_leak(value)
    if isinstance(value, dict):
        return {key: _redact_payload_host_leak(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_payload_host_leak(item) for item in value]
    return value


def _read_bounded(stream, limit):
    """Read at most ``limit`` bytes, refusing a body that wants to exceed it."""
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise NodeClientError("node agent response is too large")
    return raw


def _safe_status(code):
    """Clamp the agent's status into the error range routes.py can answer with.

    The code is echoed straight into a panel response, and a 1xx/2xx/3xx (or a
    204 that may not carry a body) would make the panel emit a reply that
    contradicts itself. 404 is preserved because delete_server keys on it.
    """
    try:
        code = int(code)
    except (TypeError, ValueError):
        return 502
    return code if 400 <= code <= 599 else 502


def _as_object(raw):
    """Decode a response body that every caller here treats as a JSON object."""
    if not raw:
        return {"ok": True}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise NodeClientError("node agent returned an unreadable response") from exc
    if not isinstance(data, dict):
        # Callers index the result (``.get("runtimes")``, ``payload["logs"]``),
        # so a list or a bare scalar would surface as an unhandled 500.
        raise NodeClientError("node agent returned an unexpected response")
    return _encodable(data)


class NodeClient:
    def __init__(self, base_url: str, token: str, *, timeout=DEFAULT_TIMEOUT, opener=None,
                 on_unreachable=None):
        self._urls = parse_node_urls(base_url)
        if not token:
            raise ValueError("node token is required")
        self.token = token
        self.timeout = _timeout(timeout, DEFAULT_TIMEOUT)
        self.opener = opener or request.build_opener(_NoRedirects).open
        self._active = 0
        self._probed = False
        self._probe_lock = threading.Lock()
        self._on_unreachable = on_unreachable

    @property
    def base_url(self):
        """The address currently in use — what a caller that builds its own
        request out of this client (the console log stream) must target."""
        return self._urls[self._active]

    @property
    def base_urls(self):
        return tuple(self._urls)

    def _mark_dead(self, url):
        with _dead_urls_lock:
            _dead_urls[url] = time.monotonic() + URL_COOLDOWN_SECONDS

    def _mark_live(self, index):
        with _dead_urls_lock:
            _dead_urls.pop(self._urls[index], None)
        self._active = index

    def _candidates(self):
        """``(index, address)`` to try, the one that last worked first."""
        order = [self._active] + [i for i in range(len(self._urls)) if i != self._active]
        now = time.monotonic()
        with _dead_urls_lock:
            live = [(i, self._urls[i]) for i in order if _dead_urls.get(self._urls[i], 0.0) <= now]
        if live:
            return live
        # Every address is inside its cooldown. Refusing here would fail the
        # request without a single attempt, so the cooldown is ignored and the
        # wire decides again.
        return [(i, self._urls[i]) for i in order]

    def _probe_url(self, base) -> bool:
        req = request.Request(
            f"{base}/health",
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": "DiscordHostPanel/1.0",
            },
        )
        try:
            with self.opener(req, timeout=PROBE_TIMEOUT) as response:
                raw = _read_bounded(response, MAX_ERROR_BYTES)
        except (error.HTTPError, error.URLError, TimeoutError, OSError,
                http_client.HTTPException, NodeClientError):
            return False
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        # ``/health`` is the agent's one unauthenticated route, so the identity in
        # the body is what makes this a probe for *this* service rather than for
        # "something answered". It matters most for the loopback address, where an
        # unrelated app on the same port would otherwise be adopted as the node.
        return isinstance(payload, dict) and payload.get("service") == "node-agent"

    def _ensure_active(self):
        """Pick a working address before the first real request.

        Only a multi-address node pays for this, and only once. Doing it up front
        rather than discovering the dead address through a failed call means the
        first thing the panel sends a node is not a create that timed out.

        Walks _candidates rather than the column order, so an address another
        client has already found black-holed is not probed ahead of the one that
        answered — the whole point of a cooldown that outlives a single client.
        """
        if self._probed or len(self._urls) == 1:
            return
        with self._probe_lock:
            if self._probed:
                return
            for index, base in self._candidates():
                if self._probe_url(base):
                    self._active = index
                    _log.info("NodeClient: node answered at %s", base)
                    break
                self._mark_dead(base)
                _log.info("NodeClient: no node agent at %s, trying the next address", base)
            self._probed = True

    def _request(self, method: str, path: str, payload=None, query=None, timeout=None):
        self._ensure_active()
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        deadline = _timeout(timeout, self.timeout)
        last_url = ""
        last_exc = None
        for index, base in self._candidates():
            url = f"{base}{path}"
            if query:
                url = f"{url}?{parse.urlencode(query)}"
            last_url = url
            req = request.Request(
                url,
                data=body,
                method=method,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": "DiscordHostPanel/1.0",
                },
            )
            try:
                with self.opener(req, timeout=deadline) as response:
                    raw = _read_bounded(response, MAX_RESPONSE_BYTES)
            except error.HTTPError as exc:
                # The agent answered, so this address is the live one and the
                # status is its verdict on the request. The node's other address
                # is the same agent and would answer identically, so a 4xx/5xx
                # ends the walk instead of extending it.
                try:
                    error_body = _read_bounded(exc, MAX_ERROR_BYTES)
                except (NodeClientError, OSError, http_client.HTTPException):
                    error_body = b""
                if _speaks_agent(exc.code, getattr(exc, "headers", None), error_body):
                    self._mark_live(index)
                    raise self._http_error(exc, error_body) from exc
                # Something answered here, but not the agent, so this address is
                # as dead as one that refused. _probed is cleared rather than
                # leaving recovery to the cooldown: once that lapses the walk
                # would order this address first again and poison another request.
                _log.warning("NodeClient: %s answered %s but is not a node agent",
                             url, exc.code)
                self._mark_dead(base)
                self._probed = False
                last_exc = exc
                if method == "GET":
                    continue
                # A non-GET is not replayed on the strength of a body that was
                # never meant to be parsed: an agent whose own error page is HTML
                # would be read as "not the agent" and the write repeated.
                break
            except (error.URLError, TimeoutError, OSError, http_client.HTTPException) as exc:
                err_msg = f"NodeClient: connection to {url} failed: {type(exc).__name__}: {exc}"
                try:
                    import reviews_db
                    reviews_db.log_app_error("NodeClientConnectionFailed", err_msg, module="node_client", flagged=1)
                    if reviews_db.is_console_debug_enabled():
                        _log.warning(err_msg)
                except Exception:
                    pass
                self._mark_dead(base)
                last_exc = exc
                if _is_connect_failure(exc) or method == "GET":
                    continue
                # A non-GET that timed out may already have taken effect. The
                # address is left marked dead so the next request moves over, but
                # this one is not replayed.
                break
            self._mark_live(index)
            return _as_object(raw)
        if self._on_unreachable is not None:
            try:
                self._on_unreachable(self)
            except Exception:
                _log.warning("NodeClient: on_unreachable callback failed", exc_info=True)
        raise NodeClientError(f"node agent is unavailable ({last_url})") from last_exc

    def _http_error(self, exc, raw=b"") -> NodeClientError:
        """Map an agent error response onto NodeClientError.

        Everything read here is attacker-controlled if the agent or a container
        that can reach it is compromised, so the status is clamped, the message
        must be a bounded string, and the node URL is never quoted back.
        """
        try:
            code = int(exc.code)
        except (TypeError, ValueError):
            code = 0
        if 300 <= code < 400:
            # Only reachable because _NoRedirects refuses to follow: the agent
            # answered a redirect where JSON was expected.
            return NodeClientError("node agent returned an unexpected redirect", status=502)
        status = _safe_status(code)
        payload = {}
        message = ""
        raw_message = ""
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, ValueError):
            decoded = None
        if isinstance(decoded, dict):
            payload = decoded
            candidate = decoded.get("error")
            if isinstance(candidate, str):
                candidate = candidate.strip()
                # Redacted before the truncation rather than after it: a path cut
                # across the MAX_ERROR_CHARS boundary can leave a fragment with too
                # few separators left for the pattern to recognise, which would leak
                # the prefix. The body this reads from is already bounded by
                # MAX_ERROR_BYTES, so matching the whole of it stays cheap.
                raw_message = _text(candidate[:MAX_ERROR_CHARS])
                message = _text(_redact_host_leak(candidate)[:MAX_ERROR_CHARS])
        if status >= 500 and status != 503:
            # A 5xx message is Docker daemon text: image ids, container ids and
            # absolute paths inside the node host. It goes to the log, not to the
            # browser, and payload is dropped with it so a caller that JSON-encodes
            # it cannot reopen the same leak. 503 is exempt because the agent
            # answers it from its concurrent-install gate, so the text is its own
            # capacity message and is the one thing there the user can act on.
            _log.error("node agent failed with %s: %s", status, raw_message or "no detail")
            return NodeClientError("the node agent could not complete that request", status=status)
        # 4xx (and the exempt 503) text reaches the browser and a flash cookie, so
        # it is redacted here at the one chokepoint every 4xx flows through rather
        # than at each surfacing site — a future node message cannot reopen the
        # hole by taking a different route out. The unredacted original still goes
        # to the log so operators keep the real path/host for diagnosis, but only
        # when the redaction actually fired: every mistyped filename is a 4xx, and
        # logging all of them would bury the one line that matters. payload is
        # walked too because routes.py JSON-encodes it, so a node that repeats the
        # path under another key would otherwise leak it there instead.
        if message != raw_message:
            _log.error("node agent %s message (redacted for browser): %s", status, raw_message)
        payload = _redact_payload_host_leak(payload)
        return NodeClientError(message or "node request failed", status=status, payload=payload)

    def catalog(self):
        return self._request("GET", "/api/v1/runtimes")

    def list_servers(self):
        return self._request("GET", "/api/v1/servers")

    def ping(self):
        """Whether any of this node's addresses has a live agent behind it.

        Used to decide whether to move on to the *next node in the fleet*, so it
        must not report a node dead only because the address that happens to be
        selected is the one this instance cannot route to.
        """
        self._ensure_active()
        for index, base in self._candidates():
            if self._probe_url(base):
                self._mark_live(index)
                return True
            self._mark_dead(base)
        return False

    def create_server(self, *, server_id, name, runtime, version, startup,
                      memory_mb=DEFAULT_MEMORY_MB, cpu_percent=DEFAULT_CPU_PERCENT):
        # CREATE_TIMEOUT is long enough to sit through an image pull, which is far
        # too long to spend finding out the agent is not there at all. A node that
        # lists a single address skips _ensure_active's probe, so a black-holed
        # address would burn the whole window; the cheap PROBE_TIMEOUT check that
        # multi-address nodes already get happens here for every node instead.
        if not self.ping():
            raise NodeClientError("node agent is unreachable")
        return self._request(
            "POST",
            "/api/v1/servers",
            {
                "id": server_id,
                "name": name,
                "runtime": runtime,
                "version": version,
                "startup": startup,
                "memory_mb": memory_mb,
                "cpu_percent": cpu_percent,
            },
            timeout=CREATE_TIMEOUT,
        )

    def server_state(self, server_id):
        return self._request("GET", f"/api/v1/servers/{_segment(server_id)}/state")

    def power(self, server_id, action):
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/power",
            {"action": action},
        )

    def logs(self, server_id, tail=200):
        return self._request(
            "GET",
            f"/api/v1/servers/{_segment(server_id)}/logs",
            query={"tail": max(1, min(int(tail), 1000))},
        )

    def run_command(self, server_id, command):
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/command",
            {"command": command},
        )

    def send_stdin(self, server_id, command):
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/stdin",
            {"command": command},
        )

    def update_startup(self, server_id, startup):
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/startup",
            {"startup": startup},
        )

    def update_image(self, server_id, *, runtime, version):
        # Changing the runtime can pull a new Docker image — same slow path
        # create_server guards with CREATE_TIMEOUT. The node agent allows up to
        # NODE_DOCKER_TIMEOUT=120 for the pull; we must stay above that so a
        # slow layer fetch isn't cut off by our own 30s cap.
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/image",
            {"runtime": runtime, "version": version},
            timeout=CREATE_TIMEOUT,
        )

    def install_log(self, server_id):
        return self._request("GET", f"/api/v1/servers/{_segment(server_id)}/install")

    def reinstall(self, server_id):
        return self._request("POST", f"/api/v1/servers/{_segment(server_id)}/install", {})

    def list_files(self, server_id, path=""):
        res = self._request(
            "GET",
            f"/api/v1/servers/{_segment(server_id)}/files",
            query={"path": path},
        )
        if isinstance(res, dict):
            for key in ("files", "entries", "data", "items"):
                if key in res and isinstance(res[key], list):
                    res[key] = [
                        item for item in res[key]
                        if not (
                            (isinstance(item, dict) and str(item.get("name", "")).startswith(".")) or
                            (isinstance(item, str) and str(item).startswith(".")) or
                            (isinstance(item, dict) and str(item.get("path", "")).split("/")[-1].startswith("."))
                        )
                    ]
        return res

    def read_file(self, server_id, path):
        return self._request(
            "GET",
            f"/api/v1/servers/{_segment(server_id)}/file",
            query={"path": path},
        )

    def write_file(self, server_id, path, content):
        return self._request(
            "PUT",
            f"/api/v1/servers/{_segment(server_id)}/file",
            {"path": path, "content": content},
        )

    def upload_file(self, server_id, path, content):
        # Refused here rather than by the agent: the check below is against the
        # raw bytes, while the agent measures the base64 that the next line
        # builds, so without this the panel encodes and ships ~200 MB to be told
        # no. The wording matches the agent's so the limit reads the same
        # whichever side answers.
        if len(content) > MAX_UPLOAD_BYTES:
            raise NodeClientError(
                "request body is too large — uploads are limited to "
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB per file",
                status=413,
            )
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/upload",
            {"path": path, "content": base64.b64encode(content).decode("ascii")},
        )

    def create_directory(self, server_id, path):
        return self._request(
            "POST",
            f"/api/v1/servers/{_segment(server_id)}/directory",
            {"path": path},
        )

    def delete_path(self, server_id, path):
        return self._request(
            "DELETE",
            f"/api/v1/servers/{_segment(server_id)}/file",
            {"path": path},
        )

    def delete_server(self, server_id, purge=False):
        return self._request(
            "DELETE",
            f"/api/v1/servers/{_segment(server_id)}",
            {"purge": bool(purge)},
        )

    def reconcile(self, known_ids, *, purge=True, max_delete=None, protect_ids=None):
        """Ask the node to remove any managed container whose id is not in
        ``known_ids`` — the authoritative list of live servers from the DB.

        ``protect_ids`` are ids the sweep must never remove even though the
        database no longer knows them: the pending-deletion tombstones waiting
        for an admin's manual confirm. The node skips them (container, data
        dir and install state alike) but keeps its guards keyed on
        ``known_ids`` alone.

        The node refuses an empty allowlist and an orphan count over
        ``max_delete``; those guards live there so every caller inherits them.
        """
        payload = {"known_ids": list(known_ids), "purge": bool(purge)}
        if protect_ids:
            payload["protect_ids"] = [str(i) for i in protect_ids if str(i).strip()]
        if max_delete is not None:
            payload["max_delete"] = int(max_delete)
        return self._request("POST", "/api/v1/reconcile", payload)

    def update_container_config(self, server_id, config_data):
        """Store/update container configuration inside .container_config.json in the container."""
        try:
            existing = {}
            try:
                res = self.read_file(server_id, ".container_config.json")
                if isinstance(res, dict) and "content" in res:
                    existing = json.loads(res["content"])
            except Exception:
                existing = {}
            if not isinstance(existing, dict):
                existing = {}
            existing.update(config_data)
            existing["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            content = json.dumps(existing, indent=2)
            return self.write_file(server_id, ".container_config.json", content)
        except Exception as exc:
            _log.warning("NodeClient: update_container_config failed for %s: %s", server_id, exc)
            return None


def build_node_client(url, token, *, on_unreachable=None):
    """A NodeClient for a node whose ``url`` column may list several addresses.

    Probing moved into the client itself, which walks the addresses per request
    and remembers which one worked. Choosing here instead charged every caller a
    round trip and then pinned that verdict for the whole of the router's cache
    TTL, so a node that came back stayed unreachable and one that went down
    stayed selected.

    Reachability is therefore no longer decided by whether this raises: a caller
    picking between *nodes* has to call :meth:`NodeClient.ping` to know.
    """
    return NodeClient(url, token, on_unreachable=on_unreachable)

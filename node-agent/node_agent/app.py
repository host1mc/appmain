import base64
import binascii
import os
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from .auth import authorized
from .catalog import public_catalog
from .container_spec import (
    CONTAINER_USER,
    CPU_PERCENT,
    INSTALL_TIMEOUT_SECONDS,
    LOG_DRIVER,
    LOG_MAX_FILES,
    LOG_MAX_SIZE,
    MEMORY_MB,
    PIDS_LIMIT,
    STORAGE_MB,
)
from .docker_runtime import DockerRuntime, _docker_timeout_seconds
from .disk_cleanup import start as _start_disk_cleanup
from .server_manager import (
    InstallCapacityError,
    ServerConflictError,
    ServerManager,
    ServerNotFoundError,
    _max_concurrent_installs,
)
from .storage import (
    MAX_DIRECTORY_ENTRIES,
    MAX_TEXT_FILE_BYTES,
    MAX_UPLOAD_BASE64_CHARS,
    MAX_UPLOAD_FILE_BYTES,
)

MAX_UPLOAD_FILE_MB = MAX_UPLOAD_FILE_BYTES // (1024 * 1024)

# The JSON envelope around the base64 string ("path", the keys, the quotes) on
# top of the largest content string that could still decode to an acceptable
# file. Derived from MAX_UPLOAD_FILE_BYTES so the body ceiling tracks the file
# ceiling: at a flat 210 MB it admitted about 10 MB of body per request that
# write_bytes was always going to reject, after get_json had already
# materialised it twice.
MAX_REQUEST_BODY_BYTES = MAX_UPLOAD_BASE64_CHARS + 64 * 1024


def _json_body(required=True):
    payload = request.get_json(silent=True)
    if payload is None and not required:
        # DELETE carries no body through some proxies, and purge/path are the
        # only fields those routes read.
        return {}
    if not isinstance(payload, dict):
        raise ValueError("a JSON object is required")
    return payload


def _fixed_int(payload, key, expected):
    """Read a numeric field that the node pins to one value.

    int(None) raises TypeError rather than ValueError, so a client that sent
    "memory_mb": null got a 500 out of the catch-all instead of a 400.
    """
    value = payload.get(key, expected)
    if value is None:
        return expected
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number") from exc


def _log_safe(value, limit=128):
    """Collapse a caller-controlled string down to one printable log field.

    request.path arrives URL-decoded, so a request line for /api%0a... carries a
    real newline. Logged verbatim, that let an unauthenticated caller write extra
    lines into the agent's log and forge entries around its own rejection.
    """
    return "".join(ch if ch.isprintable() else "?" for ch in str(value or "")[:limit])


def _env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


class RateLimiter:
    """Fixed-window per-client request limiter.

    The agent had no limit of any kind, so a leaked token — or a panel stuck in
    a retry loop — could drive unbounded docker exec, image pulls and disk
    walks. State is deliberately per-process: one agent runs per node, so there
    is nothing to coordinate with.
    """

    def __init__(self, limit, window_seconds, capacity=4096):
        self.limit = limit
        self.window = window_seconds
        self.capacity = capacity
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            window_start, count = self._hits.get(key, (now, 0))
            if now - window_start >= self.window:
                window_start, count = now, 0
            if count >= self.limit:
                return False, max(1, int(self.window - (now - window_start)))
            self._hits[key] = (window_start, count + 1)
            if len(self._hits) > self.capacity:
                self._prune(now)
            return True, 0

    def _prune(self, now):
        for key in [key for key, (start, _) in self._hits.items() if now - start >= self.window]:
            self._hits.pop(key, None)
        if len(self._hits) > self.capacity:
            # Every window is still live. Dropping the table hands out fresh
            # windows, which is the lesser evil against growing without bound.
            self._hits.clear()


def create_app(config=None, *, runtime=None):
    app = Flask(__name__)
    app.config.from_mapping(
        NODE_TOKEN=os.environ.get("NODE_TOKEN", ""),
        DATA_ROOT=os.environ.get("NODE_DATA_ROOT", "/home/ubuntu/dchost"),
        MAX_CONTENT_LENGTH=MAX_REQUEST_BODY_BYTES,
        JSON_SORT_KEYS=False,
        MAX_SERVERS=_env_int("NODE_MAX_SERVERS", 200, 1, 10_000),
        RATE_LIMIT_READ=_env_int("NODE_RATE_READ", 300, 10, 100_000),
        RATE_LIMIT_WRITE=_env_int("NODE_RATE_WRITE", 60, 5, 100_000),
        RATE_LIMIT_AUTH=_env_int("NODE_RATE_AUTH", 20, 3, 100_000),
    )
    if config:
        app.config.update(config)
    if not app.config["NODE_TOKEN"]:
        raise RuntimeError("NODE_TOKEN must be configured")
    if len(str(app.config["NODE_TOKEN"])) < 32 and not app.config.get("TESTING"):
        app.logger.warning(
            "NODE_TOKEN is shorter than 32 characters — this token is the only thing "
            "standing between the network and the Docker daemon"
        )

    manager = ServerManager(runtime or DockerRuntime(), Path(app.config["DATA_ROOT"]))
    app.extensions["server_manager"] = manager

    read_limiter = RateLimiter(app.config["RATE_LIMIT_READ"], 60)
    write_limiter = RateLimiter(app.config["RATE_LIMIT_WRITE"], 60)
    auth_limiter = RateLimiter(app.config["RATE_LIMIT_AUTH"], 60)
    app.extensions["rate_limiters"] = {
        "read": read_limiter,
        "write": write_limiter,
        "auth": auth_limiter,
    }

    def _client_key():
        # remote_addr only. The panel connects to this agent directly, so there
        # is no proxy whose forwarded-for header would be worth trusting — and
        # trusting one would let a caller pick its own rate-limit bucket.
        return request.remote_addr or "unknown"

    @app.before_request
    def reject_browser_origin():
        # This API is reachable only with the shared token and is never meant to
        # be called from a page. A request carrying Origin or Cookie is a browser
        # reaching somewhere it should not be, so refuse it rather than answer
        # with CORS headers.
        if request.path == "/health":
            return None
        if request.headers.get("Origin") or request.headers.get("Cookie"):
            return jsonify(ok=False, error="this API is not reachable from a browser"), 403
        return None

    @app.before_request
    def authenticate_api():
        if request.path == "/health":
            return None
        client = _client_key()
        if not authorized(request.headers.get("Authorization", ""), app.config["NODE_TOKEN"]):
            allowed, retry_after = auth_limiter.allow(("auth", client))
            if allowed:
                # Only the attempts that are still inside the window are logged.
                # Logging first meant a caller already being refused for rate
                # still bought a disk write per request, which is the cheapest
                # half of the flood to keep paying for.
                app.logger.warning(
                    "node agent rejected %s %s from %s: bad or missing bearer token",
                    _log_safe(request.method, 16),
                    _log_safe(request.path),
                    _log_safe(client, 64),
                )
            else:
                response = jsonify(ok=False, error="too many failed authentication attempts")
                response.headers["Retry-After"] = str(retry_after)
                return response, 429
            return jsonify(ok=False, error="unauthorized"), 401
        limiter = read_limiter if request.method in {"GET", "HEAD", "OPTIONS"} else write_limiter
        allowed, retry_after = limiter.allow((request.method in {"GET", "HEAD", "OPTIONS"}, client))
        if not allowed:
            response = jsonify(ok=False, error="rate limit exceeded — slow down")
            response.headers["Retry-After"] = str(retry_after)
            return response, 429
        return None

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Server"] = "node-agent"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    @app.errorhandler(ValueError)
    def bad_request(exc):
        return jsonify(ok=False, error=str(exc)), 400

    @app.errorhandler(FileNotFoundError)
    @app.errorhandler(ServerNotFoundError)
    def not_found(exc):
        if getattr(exc, "filename", None):
            return jsonify(ok=False, error="path does not exist"), 404
        return jsonify(ok=False, error=str(exc)), 404

    @app.errorhandler(FileExistsError)
    @app.errorhandler(ServerConflictError)
    def conflict(exc):
        if getattr(exc, "filename", None):
            return jsonify(ok=False, error="a file or directory already exists at that path"), 409
        return jsonify(ok=False, error=str(exc)), 409

    @app.errorhandler(InstallCapacityError)
    def install_capacity(exc):
        # Temporary, not the caller's fault and not a rate limit: the node is
        # already running as many install containers as it will admit.
        response = jsonify(ok=False, error=str(exc))
        response.headers["Retry-After"] = "30"
        return response, 503

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(exc):
        # Werkzeug's own 413 body is HTML, and the panel's node client requires a
        # JSON object — a text body reaches the owner as a generic failure.
        return (
            jsonify(
                ok=False,
                error=f"request body is too large — uploads are limited to {MAX_UPLOAD_FILE_MB} MB per file",
            ),
            413,
        )

    @app.errorhandler(404)
    def route_not_found(exc):
        # Werkzeug's routing 404 body is HTML; without this it fell through the
        # catch-all's HTTPException branch and reached the node client as a text
        # body instead of the JSON envelope every other error returns.
        return jsonify(ok=False, error="not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(exc):
        # Same as the 404 handler: keep routing errors on the JSON envelope
        # rather than Werkzeug's default HTML body.
        return jsonify(ok=False, error="method not allowed"), 405

    @app.errorhandler(Exception)
    def internal_error(exc):
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("node agent request failed")
        return jsonify(ok=False, error="node operation failed"), 500

    @app.get("/health")
    def health():
        return jsonify(ok=True, service="node-agent")

    @app.get("/api/v1/config")
    def node_config():
        """Everything this agent's behaviour is decided by, minus the token.

        The panel's node page could show what the registry stores about a node —
        its URL, its capacity, how many containers it holds — and nothing at all
        about what the node itself enforces. Answering "what does node 2 actually
        allow" meant reading this repo, that host's compose file and its .env.
        Every figure below is the live app.config value or the module constant the
        code paths use, never a copy, so the page cannot quote a limit the node
        stopped applying.

        The token is never included in any form. Its length is: reaching this
        route already required holding it, and "shorter than 32 characters" is the
        one thing about it an operator needs to see from a browser — the agent
        only says so today in a startup log line nobody reads.
        """
        info = getattr(manager.runtime, "daemon_info", None)
        reachable, docker_version = info() if callable(info) else (True, "")
        try:
            servers = len(manager.list_servers())
        except Exception:
            # A daemon that cannot list containers must not take the whole answer
            # down with it: the configuration is exactly what is worth reporting
            # at that moment. null is how the page knows the count is unknown
            # rather than genuinely zero.
            servers = None
        token = str(app.config.get("NODE_TOKEN") or "")
        return jsonify(
            ok=True,
            service="node-agent",
            data_root=str(app.config["DATA_ROOT"]),
            servers=servers,
            max_servers=app.config["MAX_SERVERS"],
            token={"length": len(token), "weak": len(token) < 32},
            docker={
                "reachable": reachable,
                "version": docker_version,
                "timeout_seconds": _docker_timeout_seconds(),
            },
            container={
                "memory_mb": MEMORY_MB,
                "cpu_percent": CPU_PERCENT,
                "storage_mb": STORAGE_MB,
                "pids_limit": PIDS_LIMIT,
                "user": CONTAINER_USER or "",
                "log_driver": LOG_DRIVER,
                "log_max_size": LOG_MAX_SIZE,
                "log_max_files": LOG_MAX_FILES,
            },
            limits={
                "rate_read_per_min": app.config["RATE_LIMIT_READ"],
                "rate_write_per_min": app.config["RATE_LIMIT_WRITE"],
                "rate_auth_per_min": app.config["RATE_LIMIT_AUTH"],
                "max_upload_file_mb": MAX_UPLOAD_FILE_MB,
                "max_request_body_mb": MAX_REQUEST_BODY_BYTES // (1024 * 1024),
                "max_text_file_mb": MAX_TEXT_FILE_BYTES // (1024 * 1024),
                "max_directory_entries": MAX_DIRECTORY_ENTRIES,
            },
            install={
                "timeout_seconds": INSTALL_TIMEOUT_SECONDS,
                "max_concurrent": _max_concurrent_installs(),
            },
            runtimes=public_catalog(),
        )

    @app.get("/api/v1/runtimes")
    def runtimes():
        return jsonify(ok=True, runtimes=public_catalog())

    @app.post("/api/v1/servers")
    def create_server():
        payload = _json_body()
        if _fixed_int(payload, "memory_mb", MEMORY_MB) != MEMORY_MB or _fixed_int(payload, "cpu_percent", CPU_PERCENT) != CPU_PERCENT:
            raise ValueError(f"this node enforces {MEMORY_MB} MB memory and {CPU_PERCENT}% CPU")
        # A backstop against a caller in a loop filling the host with containers.
        # Far above any real node's capacity at 300 MB each, so it never gets in
        # the way of legitimate provisioning.
        if len(manager.list_servers()) >= app.config["MAX_SERVERS"]:
            raise ServerConflictError("this node has reached its server limit")
        server = manager.create_server(payload)
        return jsonify(ok=True, server=server), 201

    @app.get("/api/v1/servers")
    def list_servers():
        return jsonify(ok=True, servers=manager.list_servers())

    @app.get("/api/v1/servers/<server_id>/state")
    def server_state(server_id):
        # state() already folds in runtime stats for a running container; asking
        # for them again cost a second stats sample, and each one takes about a
        # second because the daemon has to observe two CPU snapshots.
        return jsonify(ok=True, server=manager.state(server_id))

    @app.post("/api/v1/servers/<server_id>/power")
    def power(server_id):
        return jsonify(manager.power(server_id, _json_body().get("action")))

    @app.get("/api/v1/servers/<server_id>/logs")
    def logs(server_id):
        return jsonify(manager.logs(server_id, request.args.get("tail", 200)))

    @app.get("/api/v1/servers/<server_id>/logs/follow")
    def logs_follow(server_id):
        """SSE stream of new log lines. Client connects once; lines arrive in
        real time.  The stream ends when the container stops or the client
        disconnects.  ``since`` (optional Unix timestamp) skips older lines.
        ``tail`` (optional, default 200) limits the initial backfill.
        """
        from flask import Response, stream_with_context

        container = manager._container(server_id)
        since = request.args.get("since", type=float)
        tail = request.args.get("tail", 200, type=int)
        tail = max(1, min(tail, 1000))
        def generate():
            try:
                for chunk in manager.runtime.logs_follow(container, since=since, tail=tail):
                    # SSE ends an event at a blank line and requires every line of
                    # the payload to carry its own "data:" prefix. A docker log
                    # chunk routinely holds several lines, so interpolating it raw
                    # put unprefixed lines inside the frame (the panel drops those)
                    # and its embedded newline ended the event early — every line
                    # after the first in a chunk was lost.
                    lines = chunk.split("\n")
                    if len(lines) > 1 and lines[-1] == "":
                        # The trailing newline of the chunk, not a blank log line.
                        # Guarded on the count because a blank line of real output
                        # arrives as "" on its own: popping that too left nothing to
                        # send, so every empty line in a stack trace was swallowed
                        # and the console closed up gaps the container had printed.
                        lines.pop()
                    yield "".join(f"data:{line}\n" for line in lines) + "\n"
            except Exception:
                pass
            yield "event:done\ndata:\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/v1/servers/<server_id>/command")
    def command(server_id):
        return jsonify(manager.run_command(server_id, _json_body().get("command")))

    @app.post("/api/v1/servers/<server_id>/stdin")
    def console_stdin(server_id):
        return jsonify(manager.send_stdin(server_id, _json_body().get("command")))

    @app.post("/api/v1/servers/<server_id>/startup")
    def update_startup(server_id):
        return jsonify(manager.update_startup(server_id, _json_body().get("startup")))

    @app.post("/api/v1/servers/<server_id>/image")
    def update_image(server_id):
        payload = _json_body()
        return jsonify(manager.update_version(server_id, payload.get("runtime"), payload.get("version")))

    @app.get("/api/v1/servers/<server_id>/install")
    def install_status(server_id):
        report = manager.install_report(server_id)
        return jsonify(ok=True, status=report["status"], error=report["error"], log=report["log"])

    @app.post("/api/v1/servers/<server_id>/install")
    def reinstall(server_id):
        return jsonify(manager.reinstall(server_id))

    @app.get("/api/v1/servers/<server_id>/files")
    def files(server_id):
        storage = manager.storage(server_id)
        path = request.args.get("path", "")
        return jsonify(ok=True, path=path, entries=storage.list_directory(path))

    @app.get("/api/v1/servers/<server_id>/file")
    def read_file(server_id):
        path = request.args.get("path", "")
        return jsonify(ok=True, path=path, content=manager.storage(server_id).read_text(path))

    @app.put("/api/v1/servers/<server_id>/file")
    def write_file(server_id):
        payload = _json_body()
        manager.storage(server_id).write_text(payload.get("path", ""), payload.get("content"))
        return jsonify(ok=True)

    @app.post("/api/v1/servers/<server_id>/upload")
    def upload_file(server_id):
        payload = _json_body()
        encoded = payload.get("content", "")
        if not isinstance(encoded, str):
            raise ValueError("upload content must be a base64 string")
        # Length first. base64 expands by 4/3, so a longer string cannot decode
        # to a file write_bytes would accept, and refusing here saves decoding a
        # third ~150 MB copy of a body get_json has already materialised twice.
        if len(encoded) > MAX_UPLOAD_BASE64_CHARS:
            raise ValueError(f"uploaded file is larger than {MAX_UPLOAD_FILE_MB} MB")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("upload content must be valid base64") from exc
        manager.storage(server_id).write_bytes(payload.get("path", ""), content)
        return jsonify(ok=True), 201

    @app.post("/api/v1/servers/<server_id>/directory")
    def create_directory(server_id):
        manager.storage(server_id).create_directory(_json_body().get("path", ""))
        return jsonify(ok=True), 201

    @app.delete("/api/v1/servers/<server_id>/file")
    def delete_file(server_id):
        path = _json_body(required=False).get("path") or request.args.get("path", "")
        manager.storage(server_id).delete(path)
        return jsonify(ok=True)

    @app.delete("/api/v1/servers/<server_id>")
    def delete_server(server_id):
        purge = _json_body(required=False).get("purge", False)
        return jsonify(manager.remove(server_id, purge=bool(purge)))

    @app.post("/api/v1/reconcile")
    def reconcile():
        # The control plane posts the authoritative list of live server ids; any
        # managed container not in it is an orphan whose DB row was deleted while
        # this node was unreachable. "protect_ids" are the exception: ids whose
        # physical delete is deferred to an admin (the HeatWave pending-deletion
        # queue) — they are skipped, never reaped here. See ServerManager.reconcile
        # for the guards that stop a bad allowlist from wiping the node.
        body = _json_body()
        known_ids = body.get("known_ids")
        if not isinstance(known_ids, list):
            raise ValueError("known_ids must be a list of live server ids")
        protect_ids = body.get("protect_ids")
        if protect_ids is not None:
            if not isinstance(protect_ids, list):
                raise ValueError("protect_ids must be a list of server ids")
            protect_ids = [str(i).strip() for i in protect_ids if str(i).strip()]
        max_delete = body.get("max_delete")
        if max_delete is not None:
            max_delete = int(max_delete)
        purge = bool(body.get("purge", True))
        return jsonify(manager.reconcile(
            known_ids, purge=purge, max_delete=max_delete, protect_ids=protect_ids))

    _start_disk_cleanup()

    return app

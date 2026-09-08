import json
from http import client as http_client
from urllib import error, request as urlrequest

from starlette.concurrency import run_in_threadpool

from .auth import (
    MirrorConflict,
    SessionBackendUnavailable,
    _INTERNAL_HEADER,
    _backend_origin,
    _open_backend,
)


class BackendStoreError(RuntimeError):
    pass


class BackendStoreBusy(BackendStoreError):

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class BackendStoreValueError(ValueError):

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


_TIMEOUT_SECONDS = 7

_SCHEMA_TIMEOUT_SECONDS = 60

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

_RETRY_AFTER_HEADER = "Retry-After"

_RETRY_AFTER_MAX_SECONDS = 300

_USER_AGENT = "DiscordHostPanel/1.0"

_SCHEMA_ENSURE = "/api/panel-store/schema/ensure"
_USER_ENSURE = "/api/panel-store/user/ensure"
_USER_GET = "/api/panel-store/user/get"
_USER_BY_USERNAME = "/api/panel-store/user/by-username"
_USER_CREATE = "/api/panel-store/user/create"
_USER_PASSWORD = "/api/panel-store/user/password"
_PLACEMENT_PROBE = "/api/panel-store/placement/probe"
_NODE_CREDENTIALS = "/api/panel-store/node/credentials"
_SERVER_CREATE = "/api/panel-store/server/create"
_SERVER_LIST = "/api/panel-store/server/list"
_SERVER_GET = "/api/panel-store/server/get"
_SERVER_DELETE = "/api/panel-store/server/delete"
_SERVER_STARTUP = "/api/panel-store/server/startup"
_SERVER_NAME = "/api/panel-store/server/name"
_SERVER_VERSION = "/api/panel-store/server/version"
_SERVER_STATE = "/api/panel-store/server/state"
_ACTIVITY_LOG = "/api/panel-store/activity/log"
_ACTIVITY_LIST = "/api/panel-store/activity/list"


def _value_error(exc):
    reader = getattr(exc, "read", None)
    if reader is None:
        return None
    try:
        raw = reader(_MAX_RESPONSE_BYTES + 1)
    except (OSError, http_client.HTTPException, ValueError):
        return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > _MAX_RESPONSE_BYTES:
        return None
    try:
        body = json.loads(bytes(raw).decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(body, dict) or body.get("error") != "value_error":
        return None
    code = body.get("code")
    if not isinstance(code, str) or not code:
        code = None
    message = body.get("message")
    if not isinstance(message, str) or not message.strip():
        return BackendStoreValueError("the panel store rejected a value", code)
    return BackendStoreValueError(message, code)


def _retry_after_seconds(exc):
    headers = getattr(exc, "headers", None)
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    try:
        raw = getter(_RETRY_AFTER_HEADER)
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(raw, str):
        return None
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return min(value, _RETRY_AFTER_MAX_SECONDS)


def _raise_for_http_error(exc, path):
    if exc.code == 409:
        raise MirrorConflict("panel user mirror row could not be written") from exc
    if exc.code == 503:
        raise BackendStoreBusy(
            f"panel store call to {path} was shed while the backend database was busy",
            _retry_after_seconds(exc),
        ) from exc
    if exc.code == 400:
        value_error = _value_error(exc)
        if value_error is not None:
            raise value_error from exc
    raise BackendStoreError(f"panel store call to {path} returned {exc.code}") from exc


def _post(config, path, body, timeout):
    if not config.internal_token:
        raise BackendStoreError(f"panel store call to {path} has no internal token")
    try:
        origin = _backend_origin(config.backend_url)
    except SessionBackendUnavailable as exc:
        raise BackendStoreError(f"panel store call to {path} has no usable backend origin") from exc
    payload = json.dumps(body).encode("utf-8")
    req = urlrequest.Request(
        f"{origin}{path}",
        data=payload,
        method="POST",
        headers={
            _INTERNAL_HEADER: config.internal_token,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        },
    )
    try:
        with _open_backend(req, timeout=timeout) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise BackendStoreError(f"panel store call to {path} returned too much data")
            data = json.loads(raw.decode("utf-8"))
    except error.HTTPError as exc:
        _raise_for_http_error(exc, path)
    except (error.URLError, TimeoutError, OSError, http_client.HTTPException,
            ValueError) as exc:
        raise BackendStoreError(f"panel store call to {path} failed") from exc
    if not isinstance(data, dict) or data.get("ok") is not True:
        raise BackendStoreError(f"panel store call to {path} was not accepted")
    return data


def _row(payload, path, key):
    value = payload.get(key)
    if value is None or isinstance(value, dict):
        return value
    raise BackendStoreError(f"panel store call to {path} returned an unusable {key}")


def _rows(payload, path, key):
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise BackendStoreError(f"panel store call to {path} returned an unusable {key} list")
    return value


def _changed(payload, path):
    value = payload.get("changed")
    if not isinstance(value, bool):
        raise BackendStoreError(f"panel store call to {path} did not report whether a row changed")
    return value


def _can_place(payload, path):
    value = payload.get("can_place")
    if not isinstance(value, bool):
        raise BackendStoreError(f"panel store call to {path} did not report whether a server can be placed")
    return value


def _node_id(payload, path):
    value = payload.get("node_id")
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return None
    if value <= 0:
        return None
    return value


def _node_credentials(payload, path):
    node = _row(payload, path, "node")
    if node is None:
        return None
    url = node.get("url")
    token = node.get("token")
    if not isinstance(url, str) or not url or not isinstance(token, str) or not token:
        raise BackendStoreError(f"panel store call to {path} returned unusable node credentials")
    return {"url": url, "token": token}


def _user_id(payload, path):
    value = payload.get("user_id")
    if not isinstance(value, str) or not value:
        raise BackendStoreError(f"panel store call to {path} returned no user id")
    return value


class BackendStore:

    def __init__(self, config):
        self._config = config

    async def _call(self, path, body, timeout=_TIMEOUT_SECONDS):
        return await run_in_threadpool(_post, self._config, path, body, timeout)

    async def initialize(self):
        await self._call(_SCHEMA_ENSURE, {}, _SCHEMA_TIMEOUT_SECONDS)

    async def create_user(self, username, password_hash):
        payload = await self._call(
            _USER_CREATE,
            {"username": username, "password_hash": password_hash},
        )
        return _user_id(payload, _USER_CREATE)

    async def ensure_user_by_id(self, user_id, username):
        payload = await self._call(
            _USER_ENSURE,
            {"user_id": user_id, "username": username},
        )
        return _row(payload, _USER_ENSURE, "user")

    async def get_user_by_username(self, username):
        payload = await self._call(_USER_BY_USERNAME, {"username": username})
        return _row(payload, _USER_BY_USERNAME, "user")

    async def get_user(self, user_id):
        payload = await self._call(_USER_GET, {"user_id": user_id})
        return _row(payload, _USER_GET, "user")

    async def update_user_password(self, user_id, password_hash):
        payload = await self._call(
            _USER_PASSWORD, {"user_id": user_id, "password_hash": password_hash}
        )
        return _changed(payload, _USER_PASSWORD)

    async def can_place_new_server(self):
        payload = await self._call(_PLACEMENT_PROBE, {})
        return _can_place(payload, _PLACEMENT_PROBE)

    async def get_node_credentials(self, node_id):
        payload = await self._call(_NODE_CREDENTIALS, {"node_id": node_id})
        return _node_credentials(payload, _NODE_CREDENTIALS)

    async def create_server(self, *, server_id, user_id, name, runtime, version, image, startup):
        payload = await self._call(
            _SERVER_CREATE,
            {
                "server_id": server_id,
                "user_id": user_id,
                "name": name,
                "runtime": runtime,
                "version": version,
                "image": image,
                "startup": startup,
            },
        )
        return _node_id(payload, _SERVER_CREATE)

    async def list_servers_for_user(self, user_id):
        payload = await self._call(_SERVER_LIST, {"user_id": user_id})
        return _rows(payload, _SERVER_LIST, "servers")

    async def get_server_for_user(self, server_id, user_id):
        payload = await self._call(_SERVER_GET, {"server_id": server_id, "user_id": user_id})
        return _row(payload, _SERVER_GET, "server")

    async def delete_server_for_user(self, server_id, user_id):
        payload = await self._call(_SERVER_DELETE, {"server_id": server_id, "user_id": user_id})
        return _changed(payload, _SERVER_DELETE)

    async def update_server_startup(self, server_id, user_id, startup):
        payload = await self._call(
            _SERVER_STARTUP,
            {"server_id": server_id, "user_id": user_id, "startup": startup},
        )
        return _changed(payload, _SERVER_STARTUP)

    async def update_server_name(self, server_id, user_id, name):
        payload = await self._call(
            _SERVER_NAME, {"server_id": server_id, "user_id": user_id, "name": name}
        )
        return _changed(payload, _SERVER_NAME)

    async def update_server_version(self, server_id, user_id, runtime, version, image=None):
        payload = await self._call(
            _SERVER_VERSION,
            {
                "server_id": server_id,
                "user_id": user_id,
                "runtime": runtime,
                "version": version,
                "image": image,
            },
        )
        return _changed(payload, _SERVER_VERSION)

    async def update_server_state(self, server_id, user_id, running):
        payload = await self._call(
            _SERVER_STATE,
            {"server_id": server_id, "user_id": user_id, "running": running},
        )
        return _changed(payload, _SERVER_STATE)

    async def log_activity(self, user_id, action, server_id=None, detail=None):
        # BackendStore proxies to the backend's activity endpoints; this stub
        # mirrors the other stores since settings.activity_log gates the callers.
        pass

    async def list_activity(self, user_id, limit=200):
        # Stub: activity logging is disabled by settings.activity_log in routes.py.
        return []

"""Admin API: the hosting node registry.

Node CRUD now goes directly to Oracle via the local node_registry module, which
encrypts the agent token into token_enc, keeps the lowercase-name unique index
honest, and ALTERs its own columns in when they are missing.

The engine process is no longer required for node management.  Agent-backed
operations (config, live servers) still talk to the node agent directly, using
the same HTTP logic the engine had.
"""
import _bootstrap  # noqa: F401

import ipaddress
import json
from urllib.parse import urlsplit

import requests
from flask import Blueprint, render_template, request, jsonify

from crypto_util import looks_encrypted
import node_registry
import reviews_db
import auth

nodes_bp = Blueprint("admin_nodes", __name__)

NODE_NAME_MAX_CHARS = 64
NODE_URL_MAX_CHARS = 255
# The url column may hold several comma-separated failover origins.
NODE_URL_MAX_ORIGINS = 4
NODE_TOKEN_MAX_CHARS = 512
NODE_TOKEN_ENC_MAX_CHARS = 2000
NODE_CAPACITY_MAX = 999999

_URL_SCHEMES = ("http", "https")
_LOOPBACK_HOST_NAMES = ("localhost",)

CLEARTEXT_TOKEN_WARNING = (
    "This node's base URL is plain http:// to a host that is not loopback. "
    "Every control call to it sends the agent token in an "
    "Authorization: Bearer header, so the token crosses the network "
    "unencrypted — and that token grants full control of that host's container "
    "daemon. Use https:// unless the node is reachable only over loopback."
)

_AGENT_TIMEOUT = 8
_AGENT_CONFIG_MAX_BYTES = 64 * 1024
_AGENT_SERVERS_MAX_BYTES = 512 * 1024

_HTTP = requests.Session()
_HTTP.headers["User-Agent"] = "MCStatusHosting"


def _token_travels_cleartext(url):
    for origin in (url or "").split(","):
        origin = origin.strip()
        if not origin:
            continue
        parts = urlsplit(origin)
        if parts.scheme != "http":
            continue
        host = parts.hostname or ""
        if host in _LOOPBACK_HOST_NAMES:
            continue
        try:
            if ipaddress.ip_address(host).is_loopback:
                continue
        except ValueError:
            pass
        return True
    return False


def _node_name(value):
    if not isinstance(value, str):
        return None, "name must be text"
    text = value.strip()
    if not text or len(text) > NODE_NAME_MAX_CHARS:
        return None, ("the node name must be between 1 and "
                      f"{NODE_NAME_MAX_CHARS} characters")
    return text, None


def _node_origin(origin, prefix):
    parts = urlsplit(origin)
    if parts.scheme not in _URL_SCHEMES:
        return None, prefix + "the node URL must start with http:// or https://"
    if not parts.netloc or not parts.hostname:
        return None, prefix + "the node URL must include a host"
    if "@" in parts.netloc:
        return None, prefix + "the node URL must not embed credentials"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None, (prefix + "the node URL must be a bare origin, with no path, "
                      "no query and no fragment")
    try:
        port = parts.port
    except ValueError:
        return None, prefix + "the node URL has an unusable port"
    if port is not None and not 1 <= port <= 65535:
        return None, prefix + "the node URL has an unusable port"
    return parts.scheme + "://" + parts.netloc.lower(), None


def _node_url(value):
    if not isinstance(value, str):
        return None, "url must be text"
    text = value.strip()
    if not text:
        return None, "a node requires a base URL"
    candidates = [item.strip() for item in text.split(",") if item.strip()]
    if not candidates:
        return None, "a node requires a base URL"
    if len(candidates) > NODE_URL_MAX_ORIGINS:
        return None, (f"a node URL holds at most {NODE_URL_MAX_ORIGINS} "
                      "comma-separated origins")
    origins = []
    for candidate in candidates:
        # Name the offending origin only when there is more than one, so a
        # single-URL node keeps the message it has always produced.
        prefix = f"{candidate}: " if len(candidates) > 1 else ""
        origin, error = _node_origin(candidate, prefix)
        if error:
            return None, error
        if origin not in origins:
            origins.append(origin)
    joined = ",".join(origins)
    if len(joined) > NODE_URL_MAX_CHARS:
        return None, f"the node URL must be at most {NODE_URL_MAX_CHARS} characters"
    return joined, None


def _node_token(value):
    if not isinstance(value, str):
        return None, "token must be text"
    text = value.strip()
    if not text:
        return None, "a node requires an agent token"
    limit = (NODE_TOKEN_ENC_MAX_CHARS if looks_encrypted(text)
             else NODE_TOKEN_MAX_CHARS)
    if len(text) > limit:
        return None, f"the node token must be at most {limit} characters"
    return text, None


def _node_capacity(value):
    if isinstance(value, bool):
        return None, "capacity must be a whole number"
    if value is None or (isinstance(value, str) and not value.strip()):
        return None, ("capacity is required — 0 keeps the node registered "
                      "without letting new servers land on it")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None, "capacity must be a whole number"
    if parsed < 0 or parsed > NODE_CAPACITY_MAX:
        return None, f"capacity must be between 0 and {NODE_CAPACITY_MAX}"
    return parsed, None


def _body():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"ok": False, "error": "Invalid JSON body"}), 400)
    return data, None


def _reject(message):
    return jsonify({"ok": False, "error": message}), 400


def _ok(payload):
    return jsonify(payload), 200


def _err(message, code=400):
    return jsonify({"ok": False, "error": message}), code


# ── node agent HTTP helpers ────────────────────────────────────────────────

def _agent_origins(credentials):
    """The origins stored for a node, in the order they should be tried."""
    return [
        origin.rstrip("/")
        for origin in str((credentials or {}).get("url") or "").split(",")
        if origin.strip()
    ]


def _agent_get(node_id, credentials, path, max_bytes=_AGENT_CONFIG_MAX_BYTES):
    """GET path from a node agent. Returns (payload, problem); one is None."""
    origins = _agent_origins(credentials)
    token = (credentials or {}).get("token") or ""
    if not origins or not token:
        return None, {
            "code": "bad_request", "status": 400,
            "message": "This node has no usable stored credentials — re-register it.",
        }
    # A node may list a public address and a loopback one for the same agent. The
    # public address is a black hole from a host that publishes it, so a dead
    # address here means try the next, not give up on the node.
    for position, url in enumerate(origins):
        last = position == len(origins) - 1
        try:
            resp = _HTTP.request(
                "GET", f"{url}{path}",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/json"},
                timeout=_AGENT_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            with resp:
                body = resp.raw.read(max_bytes + 1, decode_content=True)
            status = resp.status_code
        except Exception:
            if not last:
                continue
            return None, {"code": "internal_error", "status": 502,
                          "message": "The node agent did not answer."}
        break
    if 300 <= status < 400:
        return None, {"code": "internal_error", "status": 502,
                      "message": "The node agent returned an unexpected redirect."}
    if len(body) > max_bytes:
        return None, {"code": "internal_error", "status": 502,
                      "message": "The node agent returned too much data."}
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return None, {"code": "internal_error", "status": 502,
                      "message": "The node agent returned an unreadable response."}
    if status >= 400 or not payload.get("ok"):
        if status == 401:
            return None, {
                "code": "bad_request", "status": 400,
                "message": ("The node rejected the stored token — it has been "
                            "rotated on that host. Re-register the node with "
                            "the current token."),
            }
        if status == 404:
            return None, {
                "code": "internal_error", "status": 502,
                "message": ("This node's agent does not have that endpoint — "
                            "it is running an older build. Redeploy the agent "
                            "on that host."),
            }
        return None, {"code": "internal_error", "status": 502,
                      "message": "The node agent could not answer."}
    return payload, None


def _agent_delete(node_id, credentials, path):
    """DELETE path on a node agent. Returns (payload, problem); one is None."""
    origins = _agent_origins(credentials)
    token = (credentials or {}).get("token") or ""
    if not origins or not token:
        return None, {
            "code": "bad_request", "status": 400,
            "message": "This node has no usable stored credentials.",
        }
    for position, url in enumerate(origins):
        last = position == len(origins) - 1
        try:
            resp = _HTTP.request(
                "DELETE", f"{url}{path}",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/json"},
                timeout=_AGENT_TIMEOUT,
                allow_redirects=False,
            )
            status = resp.status_code
            body = resp.text
        except requests.exceptions.ConnectionError:
            # The connection was never established, so nothing was deleted and
            # replaying this on the node's next address is safe.
            if not last:
                continue
            return None, {"code": "internal_error", "status": 502,
                          "message": "The node agent did not answer."}
        except Exception:
            # Anything else — a read timeout above all — may have deleted the
            # container already. Retrying is not safe, so report instead.
            return None, {"code": "internal_error", "status": 502,
                          "message": "The node agent did not answer."}
        break
    if status == 404:
        return {"ok": True, "already_gone": True}, None
    try:
        payload = json.loads(body)
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return None, {"code": "internal_error", "status": 502,
                      "message": "The node agent returned an unreadable response."}
    if status >= 400:
        return None, {"code": "internal_error", "status": 502,
                      "message": payload.get("error", "The node agent rejected the request.")}
    return payload, None


# ── page ────────────────────────────────────────────────────────────────────

@nodes_bp.route("/admin/nodes")
@auth.require_admin
def admin_nodes_page():
    return render_template("admin_nodes.html")


# ── JSON API ────────────────────────────────────────────────────────────────

@nodes_bp.route("/api/admin/nodes", methods=["GET"])
@auth.require_admin
def api_admin_list_nodes():
    try:
        nodes = node_registry.list_nodes_with_usage()
    except Exception as exc:
        return _err(f"Could not load the node registry: {exc}", 500)
    for node in nodes:
        if isinstance(node, dict):
            node["insecure_token_transport"] = _token_travels_cleartext(
                node.get("url"))
    return jsonify({"ok": True, "nodes": nodes,
                    "cleartext_token_warning": CLEARTEXT_TOKEN_WARNING})


@nodes_bp.route("/api/admin/nodes", methods=["POST"])
@auth.require_admin
def api_admin_create_node():
    data, problem = _body()
    if problem is not None:
        return problem
    name, message = _node_name(data.get("name"))
    if message:
        return _reject(message)
    url, message = _node_url(data.get("url"))
    if message:
        return _reject(message)
    token, message = _node_token(data.get("token"))
    if message:
        return _reject(message)
    capacity, message = _node_capacity(data.get("capacity"))
    if message:
        return _reject(message)

    try:
        node_id = node_registry.create_node(
            name=name, url=url, token=token, capacity=capacity)
    except Exception as exc:
        return _reject(str(exc))

    result = {"ok": True, "node_id": node_id, "url": url}
    result["insecure_token_transport"] = _token_travels_cleartext(url)
    if result["insecure_token_transport"]:
        result["warning"] = CLEARTEXT_TOKEN_WARNING
    return jsonify(result), 201


@nodes_bp.route("/api/admin/nodes/<int:node_id>/capacity", methods=["PUT"])
@auth.require_admin
def api_admin_set_node_capacity(node_id):
    data, problem = _body()
    if problem is not None:
        return problem
    capacity, message = _node_capacity(data.get("capacity"))
    if message:
        return _reject(message)
    try:
        changed = node_registry.update_node_capacity(node_id, capacity)
    except Exception as exc:
        return _reject(str(exc))
    if not changed:
        return _err("Node not found", 404)
    return jsonify({"ok": True, "capacity": capacity})


@nodes_bp.route("/api/admin/nodes/<int:node_id>/url", methods=["PUT"])
@auth.require_admin
def api_admin_set_node_url(node_id):
    data, problem = _body()
    if problem is not None:
        return problem
    url, message = _node_url(data.get("url"))
    if message:
        return _reject(message)
    try:
        changed = node_registry.update_node_url(node_id, url)
    except Exception as exc:
        return _reject(str(exc))
    if not changed:
        return _err("Node not found", 404)
    result = {"ok": True, "url": url}
    result["insecure_token_transport"] = _token_travels_cleartext(url)
    if result["insecure_token_transport"]:
        result["warning"] = CLEARTEXT_TOKEN_WARNING
    return jsonify(result)


@nodes_bp.route("/api/admin/nodes/<int:node_id>/enabled", methods=["PUT"])
@auth.require_admin
def api_admin_set_node_enabled(node_id):
    data, problem = _body()
    if problem is not None:
        return problem
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return _reject("enabled must be true or false")
    try:
        changed = node_registry.set_node_enabled(node_id, enabled)
    except Exception as exc:
        return _reject(str(exc))
    if not changed:
        return _err("Node not found", 404)
    return jsonify({"ok": True, "enabled": enabled})


@nodes_bp.route("/api/admin/nodes/<int:node_id>/config", methods=["GET"])
@auth.require_admin
def api_admin_node_config(node_id):
    """What node <id> itself says it enforces, read live from the agent."""
    try:
        credentials = node_registry.get_node_credentials(node_id)
    except Exception as exc:
        return _err(f"Could not read the node credentials: {exc}", 500)
    if not credentials:
        return _err("Node not found", 404)

    payload, trouble = _agent_get(node_id, credentials, "/api/v1/config")
    if trouble is not None:
        return _err(trouble["message"], trouble["status"])

    payload["node_id"] = node_id
    payload["url"] = ",".join(_agent_origins(credentials))
    payload["insecure_token_transport"] = _token_travels_cleartext(
        payload.get("url"))
    if payload["insecure_token_transport"]:
        payload["cleartext_token_warning"] = CLEARTEXT_TOKEN_WARNING
    return jsonify(payload)


@nodes_bp.route("/api/admin/nodes/<int:node_id>/servers", methods=["GET"])
@auth.require_admin
def api_admin_node_servers(node_id):
    """Which servers are on node <id>, who owns them, and what they are doing."""
    try:
        credentials = node_registry.get_node_credentials(node_id)
    except Exception as exc:
        return _err(f"Could not read the node credentials: {exc}", 500)
    if not credentials:
        return _err("Node not found", 404)

    schema_note = None
    try:
        servers = node_registry.list_servers_on_node(node_id)
    except node_registry.PanelSchemaMissing as exc:
        servers, schema_note = [], str(exc)
    except Exception as exc:
        return _err(f"Could not read the servers on this node: {exc}", 500)

    live, live_error = _agent_get(
        node_id, credentials, "/api/v1/servers",
        max_bytes=_AGENT_SERVERS_MAX_BYTES)

    seen = {}
    if live is not None:
        entries = live.get("servers")
        if isinstance(entries, list):
            for entry in entries:
                eid = str(entry.get("id") or "")
                if eid:
                    seen[eid] = entry

    merged = []
    for s in servers:
        sid = str(s.get("id") or "")
        live_entry = seen.pop(sid, None)
        # Only claim a container is gone when the node actually answered.
        merged.append({**s, "live": live_entry,
                       "container_missing": live is not None and live_entry is None})

    orphan_ids = list(seen.keys())
    for eid, entry in seen.items():
        merged.append({
            "id": eid,
            "name": entry.get("name", ""),
            "runtime": entry.get("runtime", ""),
            "version": entry.get("version", ""),
            "memory_mb": entry.get("memory_mb"),
            "cpu_percent": entry.get("cpu_percent"),
            "desired_state": entry.get("desired_state", ""),
            "created_at": entry.get("created_at", ""),
            "user_id": None,
            "username": None,
            "placed": False,
            "live": entry,
        })

    roster = {}
    for s in servers:
        owner = str(s.get("user_id") or "")
        if not owner:
            continue
        slot = roster.setdefault(
            owner, {"user_id": owner, "username": s.get("username"), "servers": 0})
        slot["servers"] += 1
        if not slot["username"]:
            slot["username"] = s.get("username")

    # The DB list is capped (newest first); say so when the registry holds
    # more for this node than are shown — the page renders a notice from it.
    truncated = False
    try:
        for node in (node_registry.list_nodes_with_usage() or []):
            if isinstance(node, dict) and int(node.get("id", -1)) == int(node_id):
                total = node.get("servers")
                if total is not None and int(total) > len(servers):
                    truncated = True
                break
    except Exception:
        pass
    result = {"ok": True, "servers": merged, "url": credentials.get("url", ""),
              "users": sorted(roster.values(), key=lambda u: -u["servers"]),
              "total": len(merged), "orphan_container_ids": orphan_ids,
              "agent_reachable": live is not None, "truncated": truncated}
    if live_error:
        result["live_error"] = live_error.get("message", "Agent unreachable")
    if schema_note:
        result["schema_note"] = schema_note
    return jsonify(result)


@nodes_bp.route("/api/admin/nodes/<int:node_id>", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_node(node_id):
    snap_name = ""
    snap_url = ""
    snap_token_enc = ""
    try:
        for node in node_registry.list_nodes():
            if node.get("id") == int(node_id):
                snap_name = str(node.get("name") or "")
                snap_url = str(node.get("url") or "")
                break
    except Exception:
        pass
    try:
        creds = node_registry.get_node_credentials(node_id)
        if creds:
            snap_url = str(creds.get("url") or snap_url)
            from crypto_util import encrypt
            token = creds.get("token") or ""
            if token:
                snap_token_enc = encrypt(token)
    except Exception:
        pass
    try:
        removed = node_registry.delete_node(node_id)
    except Exception as exc:
        return _reject(str(exc))
    if not removed:
        return _err("Node not found", 404)
    try:
        reviews_db.stamp_pending_node_identity(node_id, snap_name, snap_url)
        if snap_url or snap_token_enc or snap_name:
            reviews_db.retire_node(node_id, snap_name, snap_url, snap_token_enc)
    except Exception:
        pass
    return jsonify({"ok": True})


@nodes_bp.route("/api/admin/servers/<server_id>", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_server(server_id):
    """Delete a server: remove the container from the node AND the DB row."""
    server_id = (server_id or "").strip()
    if not server_id:
        return _err("Missing server_id", 400)

    try:
        row = node_registry.get_server(server_id)
    except Exception as exc:
        return _err(f"Could not read server: {exc}", 500)

    if not row:
        return _err("Server not found in database", 404)

    node_id = row.get("node_id")
    user_id = row.get("user_id")
    name = row.get("name", server_id)
    errors = []
    node_confirmed = False

    if node_id is not None:
        try:
            credentials = node_registry.get_node_credentials(node_id)
        except Exception:
            credentials = None
        if credentials:
            payload, problem = _agent_delete(
                node_id, credentials, f"/api/v1/servers/{server_id}?purge=true"
            )
            if problem:
                # 404 = already gone counts as confirmed; anything else leaves
                # the container on the node for the pending-deletion queue.
                if problem.get("status") == 404 or problem.get("already_gone"):
                    node_confirmed = True
                else:
                    errors.append(f"node agent: {problem.get('message', 'unknown error')}")
            else:
                node_confirmed = True
                if payload and payload.get("already_gone"):
                    node_confirmed = True
        else:
            errors.append("node is offline or unregistered — slot freed, container queued")
    else:
        node_confirmed = True

    try:
        node_registry.delete_server(server_id)
    except Exception as exc:
        errors.append(f"DB delete failed: {exc}")

    # Slot-first: DB row is gone; if the node delete was not confirmed,
    # tombstone in HeatWave with owner + reason so the admin queue shows
    # container id, username, node and cause after the node returns.
    if not node_confirmed:
        try:
            username = ""
            try:
                import database as db
                _u = db.get_user(user_id) or {}
                username = str(_u.get("username") or "")
            except Exception:
                username = ""
            node_name, node_ip = "", ""
            try:
                for n in (node_registry.list_nodes() or []):
                    if n.get("id") == node_id:
                        node_name = str(n.get("name") or "")
                        node_ip = str(n.get("url") or "")
                        break
            except Exception:
                pass
            if not node_ip:
                try:
                    retired = reviews_db.get_retired_node(node_id)
                    if retired:
                        node_name = node_name or str(retired.get("name") or "")
                        node_ip = str(retired.get("url") or "")
                except Exception:
                    pass
            reviews_db.enqueue_container_deletion(
                server_id, node_id=node_id if node_id is not None else "",
                node_ip=node_ip, node_name=node_name, purge=True,
                user_id=str(user_id or ""), username=username,
                server_name=str(name or ""), reason="admin_delete",
            )
        except Exception:
            pass

    if errors:
        return jsonify({"ok": False, "errors": errors}), 207

    return jsonify({"ok": True, "deleted": name})


# ── pending container deletions (node offline at delete time) ──────────────

def _pending_node_info(row):
    """Name and URL for a tombstone: stored HeatWave values first, then registry."""
    stored_name = str(row.get("node_name") or "").strip() or None
    stored_ip = str(row.get("node_ip") or "").strip() or None
    info = {"node_name": stored_name, "node_url": stored_ip}
    try:
        numeric = int(str(row.get("node_id") or "").strip())
    except (TypeError, ValueError):
        return info
    try:
        for node in node_registry.list_nodes():
            if node.get("id") == numeric:
                info["node_name"] = node.get("name") or stored_name
                info["node_url"] = node.get("url") or stored_ip
                return info
    except Exception:
        pass
    try:
        retired = reviews_db.get_retired_node(numeric)
    except Exception:
        retired = None
    if retired:
        info["node_name"] = info["node_name"] or (retired.get("name") or None)
        info["node_url"] = info["node_url"] or (retired.get("url") or None)
    return info


def _credentials_for_pending(row):
    """Live registry first; retired HeatWave row if the Oracle node is gone."""
    try:
        node_id = int(str(row.get("node_id") or "").strip())
    except (TypeError, ValueError):
        return None, "This entry carries no node id, so its node cannot be contacted."
    try:
        credentials = node_registry.get_node_credentials(node_id)
    except Exception:
        credentials = None
    if credentials:
        return credentials, None
    retired = None
    try:
        retired = reviews_db.get_retired_node(node_id)
    except Exception:
        retired = None
    url = (retired or {}).get("url") or str(row.get("node_ip") or "").strip()
    token = ""
    if retired and retired.get("token_enc"):
        try:
            from crypto_util import decrypt_strict, looks_encrypted
            enc = retired["token_enc"]
            token = decrypt_strict(enc) if looks_encrypted(enc) else enc
        except Exception:
            token = ""
    if url and token:
        return {"url": url, "token": token}, None
    if url and not token:
        return None, (
            "The node was removed from the registry and no agent token was "
            "kept. Re-register the node or clear this entry after deleting "
            "the container by hand."
        )
    return None, "The node for this entry is not registered any more"


@nodes_bp.route("/api/admin/pending-deletions", methods=["GET"])
@auth.require_admin
def api_admin_pending_deletions():
    """The manual-delete queue: containers whose node was offline at delete
    time. Their DB row and slot are already gone; only the physical removal on
    the node is left, and it happens here or not at all."""
    try:
        rows = reviews_db.list_container_deletions()
    except Exception as exc:
        return _err(f"Could not read the pending-deletion queue: {exc}", 500)
    pending = []
    for row in rows or []:
        info = _pending_node_info(row)
        pending.append({
            "server_id": row["server_id"],
            "node_id": row["node_id"],
            "node_ip": row["node_ip"],
            "purge": row["purge"],
            "requested_at": row["requested_at"],
            "node_name": info["node_name"],
            "node_url": info["node_url"],
            "user_id": row.get("user_id", ""),
            "username": row.get("username", ""),
            "server_name": row.get("server_name", ""),
            "reason": row.get("reason", "user_delete"),
        })
    return jsonify({"ok": True, "pending": pending, "total": len(pending)})


@nodes_bp.route("/api/admin/pending-deletions/<server_id>/delete", methods=["POST"])
@auth.require_admin
def api_admin_pending_delete_now(server_id):
    """Physically remove a queued container from its node, then clear the row.

    This is the confirm the whole queue exists for: nothing else may delete a
    tombstoned container (the panel's reconcile sweep skips these ids and the
    node's boot drain is off), so an operator's click here is the only
    automatic-free path that removes data.
    """
    server_id = (server_id or "").strip()
    if not server_id:
        return _err("Missing server_id", 400)

    row = reviews_db.get_container_deletion(server_id)
    if row is None:
        return _err("That container is not in the pending-deletion queue", 404)

    credentials, cred_err = _credentials_for_pending(row)
    if not credentials:
        return _err(cred_err or "The node for this entry is not registered any more", 404)

    try:
        node_id = int(str(row.get("node_id") or "").strip())
    except (TypeError, ValueError):
        node_id = 0

    purge = "true" if row.get("purge") else "false"
    payload, problem = _agent_delete(
        node_id, credentials, f"/api/v1/servers/{server_id}?purge={purge}")
    if problem is not None:
        return _err(
            problem.get("message", "The node agent could not delete the container."),
            problem.get("status", 502))

    # Only drop HeatWave after the agent confirmed delete or already-gone.
    removed = reviews_db.clear_container_deletions([server_id])
    result = {"ok": True, "server_id": server_id, "cleared": bool(removed)}
    if payload and payload.get("already_gone"):
        result["already_gone"] = True
    return jsonify(result)


@nodes_bp.route("/api/admin/pending-deletions/<server_id>/clear", methods=["POST"])
@auth.require_admin
def api_admin_pending_clear(server_id):
    """Drop a queue entry without touching any node.

    For a container an operator already removed by hand on the host, or an
    entry whose node is gone for good. The container, if one still exists
    somewhere, is left exactly as it is.
    """
    server_id = (server_id or "").strip()
    if not server_id:
        return _err("Missing server_id", 400)
    removed = reviews_db.clear_container_deletions([server_id])
    if not removed:
        return _err("That container is not in the pending-deletion queue", 404)
    return jsonify({"ok": True, "server_id": server_id})

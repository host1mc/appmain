"""
mc_status2.py
-------------
Fetch Minecraft server status and build Discord embed payloads.
This version exposes the documented fields so the UI can build richer widgets.
"""

from __future__ import annotations

import http.cookiejar
import ipaddress as _ipaddr
import json
import re
import random
import time
from datetime import datetime, timezone
from typing import Any

import requests

API_BASE = "https://api.mcstatus.io/v2/status"

# Anything an internal network would serve. The host goes straight into the
# mcstatus.io URL and that service probes whatever we point it at, so private,
# loopback, link-local, reserved and metadata-blocked literals must never reach
# it — otherwise a configured "192.168.1.1" turns the status bot into a
# delegated internal-network scanner.
def _blocked_target(addr) -> bool:
    # is_global is the catch-all: the named flags below miss ranges that are
    # equally not-a-public-server, such as the 100.64.0.0/10 carrier-NAT block,
    # which this interpreter reports as neither private nor reserved. The
    # explicit flags stay so the intent survives a change in what IANA marks
    # special-purpose.
    return (not addr.is_global
            or addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)

_DOTTED_QUAD_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})$")


def _validated_target(server_ip, server_port, edition):
    """Normalize and validate a server target before it goes into the
    mcstatus.io URL. Returns (host, port) or raises ValueError.
    """
    default_port = 19132 if (edition or "").lower() == "bedrock" else 25565
    try:
        port = int(server_port or 0) or default_port
    except (TypeError, ValueError):
        port = default_port
    if port < 1 or port > 65535:
        raise ValueError("Server port must be between 1 and 65535")

    host = str(server_ip or "").strip()
    if not host:
        raise ValueError("Server IP is required")
    if len(host) > 253 or any(char in host for char in "/?#@:[] \t\n\r"):
        raise ValueError("Server IP contains invalid characters")

    if _DOTTED_QUAD_RE.match(host):
        try:
            addr = _ipaddr.ip_address(host)
        except ValueError:
            raise ValueError("Server IP is not a valid IPv4 address") from None
        if _blocked_target(addr):
            raise ValueError(
                "Server IP must be a public address (private, loopback, "
                "link-local and reserved ranges are refused)")
        return host, port

    labels = host.rstrip(".").split(".")
    if len(labels) < 2 or any(not _HOSTNAME_LABEL_RE.match(label) for label in labels):
        raise ValueError("Server IP is not a valid hostname")
    # A real hostname's last label is a TLD, so it starts with a letter. Demanding
    # that (and a dot at all) is what keeps the legacy numeric spellings of an
    # IPv4 address off this path: "127.1", "2130706433", "0x7f.0.0.1" and
    # "0177.0.0.1" never match _DOTTED_QUAD_RE, so the private/loopback checks
    # above never saw them, yet inet_aton and every resolver expand them straight
    # back to the address those checks exist to refuse. The two-label rule also
    # drops the single-label internal names ("localhost", "metadata") that only
    # ever resolve to something private.
    if not labels[-1][:1].isalpha():
        raise ValueError("Server IP is not a valid hostname")
    return host, port


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    """Refuse every cookie: a status API has no session to keep, and this jar is
    shared by every bot for the lifetime of the process."""

    def set_ok(self, cookie, request):
        return False


# One session for the whole module. Every bare requests.get() builds and throws
# away a Session -> HTTPAdapter -> PoolManager -> SSLContext and does a full TLS
# handshake to the same host; at one call per bot per interval that is pure
# handshake latency, CPU and allocation churn. Reusing the pool removes that
# churn — it does not meaningfully lower steady-state RSS. Headers are set once
# here and never mutated per call, because the engine's worker thread and the
# request threads share this object; per-request extras go via headers= on the
# call itself.
_HTTP = requests.Session()
_HTTP.headers["User-Agent"] = "MCStatusHosting/1.0"
_HTTP.mount("http://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))
_HTTP.cookies.set_policy(_NoCookies())

# resp.json() reads the whole body first, and nothing about a response bounds it:
# a status service that streams (or is made to stream) gigabytes would have every
# byte allocated in a worker before the first field is parsed. The largest real
# response is dominated by the base64 favicon at ~16 KB, so a megabyte is ~60x
# headroom for a big modded server's plugin/mod/player lists and still a ceiling.
_MAX_RESPONSE_BYTES = 1048576


def _read_capped(resp):
    """The response body, or a RuntimeError once it passes the cap.

    Read in chunks so the cap is enforced as the bytes arrive rather than after
    they are already resident.
    """
    chunks = []
    total = 0
    for chunk in resp.iter_content(8192):
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise RuntimeError(
                "Minecraft status service returned an oversized response")
        chunks.append(chunk)
    return b"".join(chunks)


def _offline_status(host, port, edition, error):
    return {
        "online": False,
        "host": host,
        "port": port,
        "edition": edition,
        "error": str(error),
        "players_online": 0,
        "players_max": 0,
        "player_list": [],
        "version": "Unknown",
        "version_protocol": None,
        "motd": "",
        "motd_raw": "",
        "motd_html": "",
        "icon": None,
        "ip_address": None,
        "eula_blocked": None,
        "retrieved_at": None,
        "expires_at": None,
        "software": None,
        "plugins": [],
        "mods": [],
        "srv_record": None,
    }


def _text(value, default=""):
    return value if isinstance(value, str) else default


def _first_text(*values, default=""):
    for value in values:
        if isinstance(value, str) and value:
            return value
    return default


def fetch_status(server_ip: str, server_port: int = 25565, edition: str = "java", timeout: int = 10) -> dict[str, Any]:
    """Return a normalized status dict for the given server."""
    edition = (edition or "java").lower()
    if edition not in ("java", "bedrock"):
        edition = "java"

    host = (server_ip or "").strip()
    try:
        host, port = _validated_target(host, server_port, edition)
    except ValueError as exc:
        # A refused target is a configuration problem, not a fetch failure —
        # same shape as an offline server so the caller handles one case.
        return _offline_status(
            host, server_port or (19132 if edition == "bedrock" else 25565),
            edition, exc)
    url = f"{API_BASE}/{edition}/{host}:{port}"
    params = {"query": "true"} if edition == "java" else None

    for attempt in range(2):
        try:
            # stream=True so the body is not pulled in before _read_capped can
            # refuse it; the with block releases the connection either way,
            # including on the oversize raise.
            with _HTTP.get(url, timeout=timeout, params=params, stream=True) as resp:
                resp.raise_for_status()
                body = _read_capped(resp)
                try:
                    data = json.loads(body)
                except ValueError:
                    content_type = resp.headers.get("Content-Type", "unknown")
                    raise RuntimeError(
                        f"Minecraft status service returned an invalid response "
                        f"(HTTP {resp.status_code}, {content_type})"
                    )
            break
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt == 0:
                continue
            return _offline_status(host, port, edition, exc)
        except Exception as exc:
            return _offline_status(host, port, edition, exc)

    if not isinstance(data, dict):
        return _offline_status(
            host,
            port,
            edition,
            "Minecraft status service returned malformed JSON",
        )

    players = data.get("players") or {}
    version = data.get("version") or {}
    motd = data.get("motd") or {}
    if not isinstance(players, dict):
        players = {}
    if not isinstance(version, dict):
        version = {}
    if not isinstance(motd, dict):
        motd = {}

    player_list = []
    raw_players = players.get("list")
    if not isinstance(raw_players, list):
        raw_players = []
    for p in raw_players:
        if not isinstance(p, dict):
            continue
        name = _first_text(p.get("name_clean"), p.get("name"), p.get("name_raw"))
        if name:
            player_list.append(name)

    plugins = []
    raw_plugins = data.get("plugins")
    if not isinstance(raw_plugins, list):
        raw_plugins = []
    for plugin in raw_plugins:
        if isinstance(plugin, dict):
            plugins.append({
                "name": _text(plugin.get("name")),
                "version": _text(plugin.get("version")) or None,
            })

    mods = []
    raw_mods = data.get("mods")
    if not isinstance(raw_mods, list):
        raw_mods = []
    for mod in raw_mods:
        if isinstance(mod, dict):
            mods.append({
                "name": _text(mod.get("name")),
                "version": _text(mod.get("version")) or None,
            })

    # mcstatus.io returns the favicon as a base64 "data:" URI (~15.7 KB, 93% of the
    # stored row). Discord embed thumbnails and the user2.html preview both require
    # an http(s) URL, so a data: URI can never render — keep only https icons
    # (plain http is rejected: Discord refuses to render it, and an http icon is
    # one MITM away from anything that ever does).
    icon = data.get("icon")
    icon = icon if isinstance(icon, str) else ""
    icon = icon if icon.startswith("https://") else None
    srv_record = data.get("srv_record")
    if not isinstance(srv_record, dict):
        srv_record = None
    version_name = _first_text(
        version.get("name_clean"),
        version.get("name"),
        version.get("name_raw"),
        default="Unknown",
    )
    motd_clean = _text(motd.get("clean")).strip()

    return {
        "online": bool(data.get("online")),
        "host": data.get("host", host),
        "port": data.get("port", port),
        "edition": edition,
        "error": None,
        "players_online": players.get("online", 0) or 0,
        "players_max": players.get("max", 0) or 0,
        "player_list": player_list,
        "version": version_name,
        "version_protocol": version.get("protocol"),
        "motd": motd_clean,
        "motd_raw": _text(motd.get("raw")),
        "motd_html": _text(motd.get("html")),
        "icon": icon,
        "ip_address": data.get("ip_address"),
        "eula_blocked": data.get("eula_blocked"),
        "retrieved_at": data.get("retrieved_at"),
        "expires_at": data.get("expires_at"),
        "software": _text(data.get("software")) or None,
        "plugins": plugins,
        "mods": mods,
        "srv_record": srv_record,
        "fetched_at": time.time(),
    }


def _color_to_int(color: str) -> int:
    try:
        value = int((color or "#9b59b6").lstrip("#"), 16)
    except Exception:
        return 0x9B59B6
    # Discord rejects the whole message when color is outside 0..0xFFFFFF, so a
    # builder value like "#deadbeefdead" would stop the embed being posted at all
    # rather than post it in the wrong colour.
    return value if 0 <= value <= 0xFFFFFF else 0x9B59B6


# Discord validates every url/icon_url on an embed and 400s the entire message
# when one is not a usable http(s) URL — so an unchecked value from the builder
# takes the bot silently offline instead of just rendering nothing. Length is
# capped for the same reason.
_MAX_URL_LEN = 2048


def _safe_url(value):
    """An http(s) URL safe to hand Discord, or None."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > _MAX_URL_LEN:
        return None
    if not (value.startswith("https://") or value.startswith("http://")):
        return None
    if any(char in value for char in " \t\n\r"):
        return None
    return value


def _format_list(items, limit: int = 10):
    out = []
    for i, item in enumerate((items or [])[:limit]):
        if isinstance(item, dict):
            name = item.get("name") or "Unknown"
            version = item.get("version")
            out.append(f"{i + 1}. {name}" + (f" ({version})" if version else ""))
        else:
            out.append(f"{i + 1}. {item}")
    return "\n".join(out)


def _format_timestamp_ms(ms):
    if ms is None:
        return "Unknown"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(ms) / 1000))
    except Exception:
        return str(ms)


def _apply_display_style(value: str, widget: dict, status: dict, cfg: dict = None) -> str:
    style = str(widget.get("display_style") or widget.get("ip_style") or "auto").strip().lower()
    if style in ("auto", "plain"):
        return value
    if style == "backtick":
        return f"`{value}`"
    if style == "code":
        return f"```\n{value}\n```"
    if style == "template":
        tpl = str(widget.get("value") or "").strip()
        if not tpl:
            return value
        ph = _get_placeholders(widget, status, cfg)
        result = tpl.replace("{value}", value)
        for key, val in ph.items():
            result = result.replace("{" + key + "}", str(val or ""))
        return result
    return value


def _get_placeholders(widget: dict, status: dict, cfg: dict = None) -> dict:
    wtype = widget.get("type", "custom")
    h = str(status.get("host") or "")
    po = str(status.get("port") or "")
    s = status
    if s.get("online"):
        online_status = widget.get("online_text") or (cfg or {}).get("online_text", "🟢 ONLINE")
    else:
        online_status = widget.get("offline_text") or (cfg or {}).get("offline_text", "🔴 OFFLINE")
    base = {}
    mapping = {
        "status":     {"status": online_status},
        "ip":         {"host": h, "port": po, "ip": s.get("ip") or h, "ip_port": f"{h}:{po}", "edition": str(s.get("edition") or "")},
        "players":    {"online": s.get("players_online"), "max": s.get("players_max")},
        "playerlist": {"players": ", ".join(str(x) for x in (s.get("player_list") or [])), "count": len(s.get("player_list") or [])},
        "version":    {"version": s.get("version") or "Unknown"},
        "motd":       {"motd": s.get("motd") or "", "stripped": _strip_mc_color(s.get("motd") or "")},
        "software":   {"software": s.get("software") or "Unknown"},
        "plugins":    {"plugins": ", ".join(str(x.get("name", x)) for x in (s.get("plugins") or [])), "count": len(s.get("plugins") or [])},
        "mods":       {"mods": ", ".join(str(x.get("name", x)) for x in (s.get("mods") or [])), "count": len(s.get("mods") or [])},
        "srv_record": {"host": h, "port": po, "ip_port": f"{h}:{po}"},
        "ip_address": {"ip": s.get("ip_address") or "Unknown"},
        "eula_blocked": {"eula": "Yes" if s.get("eula_blocked") else "No"},
        "retrieved_at": {"time": s.get("retrieved_at") or "", "timestamp": _format_timestamp_ms(s.get("retrieved_at")) if s.get("retrieved_at") else ""},
        "expires_at":   {"time": s.get("expires_at") or "", "timestamp": _format_timestamp_ms(s.get("expires_at")) if s.get("expires_at") else ""},
        "custom":     {},
    }
    base.update(mapping.get(wtype, {}))
    return base


def _sanitize_discord_markdown(text: str) -> str:
    """No-op: Discord embed descriptions and field values support full markdown
    (headings, bold, italic, code, links, blockquotes, lists, emojis, etc.)."""
    return text


def _clamp(text, limit: int) -> str:
    """Truncate to Discord's per-part character limits. Slicing can land in the
    middle of a surrogate pair, so re-encode and drop the dangling half instead
    of emitting a half-pair that breaks json serialization."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit].encode("utf-8", "ignore").decode("utf-8", "ignore")


def _enforce_embed_total(embed: dict, limit: int = 6000) -> dict:
    """Clamp aggregate Discord embed text without removing field objects."""
    slots = []

    def add(container, key, minimum=1):
        value = container.get(key)
        if isinstance(value, str):
            slots.append((container, key, minimum))

    add(embed, "title")
    add(embed, "description", 0)
    for field in embed.get("fields") or []:
        if isinstance(field, dict):
            add(field, "name")
            add(field, "value")
    footer = embed.get("footer")
    if isinstance(footer, dict):
        add(footer, "text")
    author = embed.get("author")
    if isinstance(author, dict):
        add(author, "name")

    total = sum(len(container[key]) for container, key, _ in slots)
    excess = total - limit
    if excess <= 0:
        return embed

    slots.sort(
        key=lambda slot: len(slot[0][slot[1]]) - slot[2],
        reverse=True,
    )
    for container, key, minimum in slots:
        if excess <= 0:
            break
        value = container[key]
        reduction = min(excess, max(0, len(value) - minimum))
        if not reduction:
            continue
        target = len(value) - reduction
        if target == 0:
            container.pop(key, None)
        else:
            container[key] = _clamp(value, target) or "\u200b"
        excess -= reduction
    return embed


def _strip_mc_color(text: str) -> str:
    return re.sub(r"§.", "", text)


def _normalize_field_label(label: str) -> str:
    text = str(label or "").strip()
    return text


def _sanitize_widget(widget, index: int):
    if not isinstance(widget, dict):
        return None
    wtype = str(widget.get("type") or "").strip().lower()
    allowed = {
        "status", "ip", "players", "playerlist", "version", "motd", "software",
        "plugins", "mods", "srv_record", "ip_address", "eula_blocked",
        "retrieved_at", "expires_at", "custom", "separator",
    }
    if wtype not in allowed:
        return None

    out = {
        "id": str(widget.get("id") or f"widget-{index}").strip() or f"widget-{index}",
        "type": wtype,
        "label": _normalize_field_label(widget.get("label", "")),
        "inline": bool(widget.get("inline")),
        "enabled": widget.get("enabled", True) is not False,
    }
    color = widget.get("color")
    if color:
        out["color"] = color
    bg_color = widget.get("bg_color")
    if bg_color:
        out["bg_color"] = bg_color
    text_color = widget.get("text_color")
    if text_color:
        out["text_color"] = text_color
    show_when = str(widget.get("show_when") or "always").strip().lower()
    out["show_when"] = show_when if show_when in ("always", "online", "offline") else "always"
    padding = str(widget.get("padding") or "normal").strip().lower()
    out["padding"] = padding if padding in ("compact", "normal", "spacious") else "normal"
    prefix = widget.get("prefix")
    if prefix:
        out["prefix"] = prefix
    online_text = widget.get("online_text")
    if online_text:
        out["online_text"] = online_text
    offline_text = widget.get("offline_text")
    if offline_text:
        out["offline_text"] = offline_text
    align = str(widget.get("align") or "left").strip().lower()
    out["align"] = align if align in {"left", "center", "right"} else "left"
    ds = str(widget.get("display_style") or widget.get("ip_style") or "auto").strip().lower()
    if ds not in {"auto", "plain", "backtick", "code", "template"}:
        ds = "auto"
    if ds == "auto" and wtype in ("ip", "srv_record"):
        ds = "backtick"
    out["display_style"] = ds
    if wtype in {"custom"} or (wtype != "separator" and ds == "template"):
        out["value"] = str(widget.get("value", "") or "")
    if wtype == "playerlist":
        try:
            out["max_players_in_list"] = max(1, int(widget.get("max_players_in_list", 20) or 20))
        except Exception:
            out["max_players_in_list"] = 20
        style = str(widget.get("playerlist_style") or "code_numbered").strip().lower()
        out["playerlist_style"] = style if style in {"plain", "bullets", "numbered", "code", "code_numbered"} else "plain"
    if wtype in {"plugins", "mods"}:
        try:
            out["max_items"] = max(1, int(widget.get("max_items", 10) or 10))
        except Exception:
            out["max_items"] = 10
    return out


def _normalize_widgets(cfg):
    if not isinstance(cfg, dict):
        return []
    try:
        widgets = cfg.get("widgets")
        out = []
        if isinstance(widgets, list):
            for idx, widget in enumerate(widgets):
                clean = _sanitize_widget(widget, idx)
                if clean:
                    out.append(clean)
            return out

        legacy = []
        if cfg.get("show_ip", True):
            legacy.append({"id": "ip", "type": "ip", "label": cfg.get("ip_label", "🌐 IP & PORT"), "inline": False, "enabled": True})
        if cfg.get("show_players", True):
            legacy.append({"id": "players", "type": "players", "label": cfg.get("players_label", "👥 PLAYERS ONLINE"), "inline": False, "enabled": True})
        if cfg.get("show_playerlist", True):
            legacy.append({
                "id": "playerlist",
                "type": "playerlist",
                "label": cfg.get("playerlist_label", "📝 PLAYER LIST"),
                "inline": False,
                "enabled": True,
                "max_players_in_list": cfg.get("max_players_in_list", 20),
            })
        if cfg.get("show_version", True):
            legacy.append({"id": "version", "type": "version", "label": cfg.get("version_label", "🎮 VERSION"), "inline": False, "enabled": True})
        if cfg.get("show_motd", True):
            legacy.append({"id": "motd", "type": "motd", "label": cfg.get("motd_label", "📜 MOTD"), "inline": False, "enabled": True})
        legacy.append({"id": "status", "type": "status", "label": cfg.get("status_label", "💡 STATUS"), "inline": False, "enabled": True})
        return legacy
    except Exception:
        return []


def build_embed(embed_cfg: dict, status: dict) -> dict:
    """Build a Discord embed dict from config + live status."""
    try:
        cfg = embed_cfg or {}
        fields = []
        widgets = _normalize_widgets(cfg)

        for widget in widgets:
            if not widget.get("enabled", True):
                continue

            show_when = widget.get("show_when", "always")
            if show_when == "online" and not status.get("online"):
                continue
            if show_when == "offline" and status.get("online"):
                continue

            wtype = widget.get("type", "custom")

            if wtype == "separator":
                fields.append({"name": "\u200b", "value": "\u200b", "inline": False})
                continue
            label = widget.get("label") or {
                "status": "💡 STATUS",
                "ip": "🌐 IP & PORT",
                "players": "👥 PLAYERS ONLINE",
                "playerlist": "📝 PLAYER LIST",
                "version": "🎮 VERSION",
                "motd": "📜 MOTD",
                "software": "🧩 SOFTWARE",
                "plugins": "🔌 PLUGINS",
                "mods": "🧱 MODS",
                "srv_record": "🧭 SRV RECORD",
                "ip_address": "📡 IP ADDRESS",
                "eula_blocked": "⚠️ EULA BLOCKED",
                "retrieved_at": "🕒 RETRIEVED AT",
                "expires_at": "⌛ EXPIRES AT",
            }.get(wtype, "Custom Field")
            label = _normalize_field_label(label)
            label = _clamp(label, 256)

            inline = bool(widget.get("inline"))
            if wtype == "status":
                value = cfg.get("online_text", "🟢 ONLINE") if status.get("online") else cfg.get("offline_text", "🔴 OFFLINE")
            elif wtype == "ip":
                value = f"{status.get('host')}:{status.get('port')}"
            elif wtype == "players":
                value = f"{status.get('players_online', 0)} / {status.get('players_max', 0)}"
            elif wtype == "playerlist":
                maxlist = int(widget.get("max_players_in_list") or cfg.get("max_players_in_list", 20) or 20)
                plist = status.get("player_list", [])[:maxlist]
                style = str(widget.get("playerlist_style") or "code_numbered").strip().lower()
                names = [str(p) for p in plist if str(p).strip()]
                if not names:
                    value = "```\nNo players online\n```" if style in {"code", "code_numbered"} else "No players online"
                elif style == "bullets":
                    value = "\n".join(f"• {name}" for name in names)
                elif style == "numbered":
                    value = "\n".join(f"{i + 1}. {name}" for i, name in enumerate(names))
                elif style == "code":
                    value = f"```\n{chr(10).join(names)}\n```"
                elif style == "code_numbered":
                    value = f"```\n{chr(10).join(f'{i + 1}. {name}' for i, name in enumerate(names))}\n```"
                else:
                    value = "\n".join(names)
            elif wtype == "version":
                value = status.get("version", "Unknown")
                if status.get("version_protocol") is not None:
                    value = f"{value} (`{status.get('version_protocol')}`)"
            elif wtype == "motd":
                value = status.get("motd") or "No MOTD returned"
            elif wtype == "software":
                value = status.get("software") or "Unknown"
            elif wtype == "plugins":
                value = _format_list(status.get("plugins"), int(widget.get("max_items") or 10)) or "No plugins reported"
            elif wtype == "mods":
                value = _format_list(status.get("mods"), int(widget.get("max_items") or 10)) or "No mods reported"
            elif wtype == "srv_record":
                srv = status.get("srv_record") or {}
                srv_host = srv.get("host") if srv else None
                srv_port = srv.get("port") if srv else None
                value = f"{srv_host}:{srv_port}" if srv_host and srv_port else "No SRV record found"
            elif wtype == "ip_address":
                value = status.get("ip_address") or "Unknown"
            elif wtype == "eula_blocked":
                value = "Yes" if status.get("eula_blocked") else "No"
            elif wtype == "retrieved_at":
                value = _format_timestamp_ms(status.get("retrieved_at"))
            elif wtype == "expires_at":
                value = _format_timestamp_ms(status.get("expires_at"))
            else:
                value = widget.get("value", "\u200b")

            if status.get("online") and widget.get("online_text"):
                value = widget["online_text"]
            elif not status.get("online") and widget.get("offline_text"):
                value = widget["offline_text"]

            value = _apply_display_style(value, widget, status, cfg)

            if widget.get("prefix"):
                value = widget["prefix"] + " " + value

            align = widget.get("align", "left")
            # Migrate accidental HTML line-break strings from older builder
            # previews/configs into Discord's real newline format.
            value = re.sub(r"<br\s*/?\s*>", "\n", str(value or "\u200b"), flags=re.I)
            value = _sanitize_discord_markdown(value)
            fields.append({"name": label, "value": _clamp(value, 1024), "inline": inline})

        widgets_cfg = cfg.get("widgets")
        if not fields and not isinstance(widgets_cfg, list):
            fields.append({
                "name": cfg.get("status_label", "💡 STATUS"),
                "value": _sanitize_discord_markdown(
                    cfg.get("online_text", "🟢 ONLINE") if status.get("online") else cfg.get("offline_text", "🔴 OFFLINE")
                ),
                "inline": False,
            })

        render_as_description = bool(cfg.get("render_as_description"))

        # Discord caps embeds at 25 fields; any widget past that would 400 the
        # whole message, so drop the overflow.
        fields = fields[:25]

        # A non-string footer made this concatenation raise, which discarded the
        # whole embed for the error embed below.
        footer_text = cfg.get("footer", "Powered by MC Status Hosting")
        if not isinstance(footer_text, str):
            footer_text = "Powered by MC Status Hosting"
        embed = {
            "color": (random.randint(0x180000, 0xFFFFFF)
                      if cfg.get("rotate_accent_on_update")
                      else _color_to_int(cfg.get("color", "#9b59b6"))),
            "footer": {"text": _clamp(footer_text + "  •  " + time.strftime("%I:%M:%S %p"), 2048)},
        }

        if render_as_description:
            parts = []
            title = cfg.get("title", "🚨 SERVER STATUS")
            if title:
                parts.append(f"## {title}")
            if cfg.get("description"):
                parts.append(cfg["description"])
            for f in fields:
                name = f.get("name") or ""
                value = f.get("value") or ""
                if name.strip("​").strip() == "" and value.strip("​").strip() == "":
                    parts.append("")
                    continue
                block = f"### {name}" if name.strip("​").strip() else ""
                if value.strip("​").strip():
                    block = (block + "\n" + value) if block else value
                parts.append(block)
            embed["description"] = _clamp("\n".join(p for p in parts if p is not None), 4096)
        else:
            embed["title"] = _clamp(cfg.get("title", "🚨 SERVER STATUS"), 256)
            embed["fields"] = fields

        footer_icon = _safe_url(cfg.get("footer_icon_url"))
        if footer_icon:
            embed["footer"]["icon_url"] = footer_icon

        embed_url = _safe_url(cfg.get("url"))
        if embed_url:
            embed["url"] = embed_url

        if not render_as_description and cfg.get("description"):
            embed["description"] = _clamp(_sanitize_discord_markdown(cfg["description"]), 4096)

        if cfg.get("author_enabled"):
            author = {}
            if cfg.get("author_name"):
                author["name"] = _clamp(cfg["author_name"], 256)
            author_icon = _safe_url(cfg.get("author_icon_url"))
            if author_icon:
                author["icon_url"] = author_icon
            author_url = _safe_url(cfg.get("author_url"))
            if author_url:
                author["url"] = author_url
            if author:
                embed["author"] = author

        if cfg.get("image_enabled"):
            image_url = _safe_url(cfg.get("image_url"))
            if image_url:
                embed["image"] = {"url": image_url}

        if cfg.get("show_timestamp"):
            embed["timestamp"] = datetime.now(timezone.utc).isoformat()

        thumb_url = None
        if cfg.get("use_discord_icon"):
            thumb_url = _safe_url(cfg.get("discord_icon_url"))
        if not thumb_url and cfg.get("thumbnail", True) and status.get("icon"):
            icon = status.get("icon")
            if isinstance(icon, str) and icon.startswith("https://"):
                thumb_url = icon
        if thumb_url:
            embed["thumbnail"] = {"url": thumb_url}

        return _enforce_embed_total(embed)
    except Exception:
        # Never leak exception text into a public Discord channel — the embed is
        # posted where the bot's audience can read it.
        return {
            "title": _clamp("Embed Build Error", 256),
            "description": _clamp(
                "An unexpected error occurred while building the embed. "
                "Check your embed configuration.", 4096
            ),
            "color": 0xE74C3C,
            "footer": {"text": "MC Status Hosting"},
        }

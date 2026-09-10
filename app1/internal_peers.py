"""
internal_peers.py — restricts internal endpoints to the tiers allowed to call them.

Never compare ``request.remote_addr`` against the allowlist: ``backend.py`` runs
behind ProxyFix, which has already rewritten it to the visitor's ``X-Forwarded-For``
value, so a visitor could nominate their own tier identity by writing a header.
Only the pre-ProxyFix socket peer is authoritative.

Off unless configured — ``INTERNAL_PEERS`` unset allows every caller.
"""

import ipaddress
import os
import sys

ENV_VAR = "INTERNAL_PEERS"

_parsed_cache = {}
_refused_warned = set()
_open_warned = False


def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass


def _parse(raw: str) -> tuple:
    networks = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            _debug_print(f"[peers] ignoring unparseable {ENV_VAR} entry {part!r}",
                         file=sys.stderr, flush=True)
    return tuple(networks)


def networks() -> tuple:
    raw = (os.environ.get(ENV_VAR, "") or "").strip()
    if not raw:
        return ()
    cached = _parsed_cache.get(raw)
    if cached is None:
        cached = _parse(raw)
        _parsed_cache[raw] = cached
    return cached


def enabled() -> bool:
    return bool(networks())


def socket_peer(environ) -> str:
    original = environ.get("werkzeug.proxy_fix.orig") or {}
    if isinstance(original, dict):
        peer = original.get("REMOTE_ADDR") or ""
        if peer:
            return peer.strip()
    return (environ.get("REMOTE_ADDR") or "").strip()


def _address(value: str):
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def _warn_refused_once(peer: str) -> None:
    if peer in _refused_warned:
        return
    if len(_refused_warned) > 64:
        _refused_warned.clear()
    _refused_warned.add(peer)
    try:
        import reviews_db
        reviews_db.log_app_error("InternalPeerRefused", f"refused internal request from {peer!r}", module="internal_peers", flagged=1)
    except Exception:
        pass
    _debug_print(
        f"[peers] refused an internal request from {peer!r}: it carried a valid "
        f"token but is not listed in {ENV_VAR}. If this is one of our own tiers, "
        f"add its address to {ENV_VAR} or every internal call from it will fail.",
        file=sys.stderr, flush=True,
    )


def _warn_open_once() -> None:
    global _open_warned
    if _open_warned:
        return
    _open_warned = True
    raw = (os.environ.get(ENV_VAR, "") or "").strip()
    if any(part.strip() for part in raw.replace(";", ",").split(",")):
        reason = (
            f"{ENV_VAR} is set, but not one entry in it parsed as an IP address or "
            f"CIDR network, so the value is having no effect"
        )
    else:
        reason = f"{ENV_VAR} is not set"
    _debug_print(
        f"[peers] {ENV_VAR} is not pinning callers ({reason}). "
        f"Internal requests are accepted only from private, loopback or "
        f"link-local peers until {ENV_VAR} lists the fleet explicitly.",
        file=sys.stderr, flush=True,
    )


def peer_allowed(environ) -> bool:
    allowed = networks()
    peer = socket_peer(environ)
    address = _address(peer)
    if not allowed:
        # Unconfigured allowlist must not mean "the whole internet". Backend
        # is supposed to bind loopback/VCN; only those peers may present the
        # internal token until INTERNAL_PEERS is set.
        _warn_open_once()
        if address is None:
            return False
        return bool(
            address.is_private or address.is_loopback or address.is_link_local
        )
    if address is None:
        _warn_refused_once(peer or "<no address>")
        return False
    for network in allowed:
        if address.version == network.version and address in network:
            return True
    _warn_refused_once(peer)
    return False

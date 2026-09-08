"""cf_edge.py — Cloudflare's published edge ranges, and the peer test built on them.

Both web tiers need the same answer to one question: *did this request really
reach us through a Cloudflare edge?* Only then may a ``CF-*`` header be believed,
because a client that reaches the process without passing a genuine edge can
write those headers itself.

The tiers used to answer it separately — frontend.py held the range list and the
test, and panel_app/auth.py had no equivalent at all, so it believed
``X-Forwarded-For`` from any peer. One list in one place is what keeps them
agreeing, the same reason panel_app/auth.py reads TRUSTED_PROXY_HOPS from the
variable frontend.py reads rather than inventing its own.

    IMPORTANT, and the reason CF_TRUSTED_IPS exists:

    ``peer_is_cf`` tests the address that actually opened the TCP connection. In a
    deployment where Cloudflare proxies straight to this process, that peer *is* a
    Cloudflare edge and CF_IP_RANGES matches it. Behind a *second* terminating
    proxy — the OCI load balancer this fleet deploys behind, which terminates TLS
    again and appends its own X-Forwarded-For entry — the peer is the balancer,
    which is never on Cloudflare's network. Every CF-* header is then discarded
    on every request and the CF features quietly do nothing.

    That direction fails closed, so it is not a hole. But it does mean the
    operator MUST pin the balancer's own address range in CF_TRUSTED_IPS for the
    Cloudflare features to work at all. See README "Cloudflare bot & DDoS
    protection". frontend.py warns once per process when it discards a CF-*
    header, so the inert state is visible rather than silent.

This module is deliberately tiny and imports only the standard library, so the
panel can use it without pulling in Flask or anything from the ad stack. app/ is
on sys.path for the panel before panel_app is imported (asgi_panel.py and
start_panel.py both insert it), so the import is available in every entry point.
"""

import ipaddress as _ipaddr
import os

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app", ".env")


def _setting(name):
    """One config name, from the real environment or the shared .env.

    The environment wins, because main.py forwards its own to every tier, so a
    value set there is true fleet-wide. The .env is read as a fallback rather than
    ignored because nothing exports that file wholesale: asgi_panel.py
    load_dotenv()s it before importing panel_app, but the frontend loads no .env at
    all, so reading the environment alone is what lets the two tiers end up
    disagreeing.

    Parsed with stdlib open() to keep this module's no-dependency shape, and
    utf-8-sig because a BOM would otherwise attach itself to the first line's key
    name and stop that one name from ever matching. Scans per call rather than
    caching a dict, which is only safe because every caller is import-time (the
    assignment below, backend.py's CORS_ORIGINS, ads_config's ADSENSE_CLIENT) —
    do not call this on a request path.
    """
    val = (os.environ.get(name) or "").strip()
    if val:
        return val
    try:
        with open(_ENV_PATH, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, raw = line.split("=", 1)
                if key.strip() == name:
                    return raw.strip().strip("\"'")
    except OSError:
        # No .env at all is a valid deployment: everything set in the real
        # environment. It must still import.
        pass
    return ""


# Cloudflare's published edge ranges (https://www.cloudflare.com/ips/), baked in
# so a CF-* header is only trusted when the request's peer is actually one of our
# proxies ON Cloudflare's network. Ops may override with CF_TRUSTED_IPS
# (comma-separated CIDRs) when the published list moves before this file does, or
# when a terminating proxy sits between the edge and us; empty means "trust no
# peer for these headers".
CF_IP_RANGES = frozenset({
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
})

CF_TRUSTED_IPS = frozenset(
    cidr.strip() for cidr in
    _setting("CF_TRUSTED_IPS").split(",") if cidr.strip())

# Read once at import, so a change to the value needs a restart to take effect.
# Both the real environment and the shared .env are consulted, and that is the
# point: asgi_panel.py load_dotenv()s that file before it imports panel_app, while
# the frontend loads no .env at all. Reading only the environment would let a value
# set solely in the file apply to the panel and not the frontend — the two tiers
# disagreeing about who a request came from, which is the exact failure one shared
# module is here to prevent. Either location now reaches both.

# What a CF-* header's peer is checked against: the operator's pinned ranges
# REPLACE the published list when set. Replacement rather than union is the point
# — pinning the load balancer is how a fleet behind a second terminating proxy
# makes the headers usable at all, and unioning would leave every real Cloudflare
# edge trusted as a direct peer too, which in that topology it can no longer be.
HEADER_PEER_NETWORKS = CF_TRUSTED_IPS or CF_IP_RANGES

# What an intermediate X-Forwarded-For hop is checked against: a UNION, because a
# genuine Cloudflare edge does still appear in the chain the balancer appended to.
# Pinning the balancer for the header test above must not stop us recognising it.
EDGE_NETWORKS = CF_IP_RANGES | CF_TRUSTED_IPS


def peer_is_cf(peer, networks):
    """Whether ``peer`` sits in any CIDR of ``networks``.

    Tolerant of junk on both sides: an unparseable peer is simply not trusted,
    and a malformed CIDR is skipped rather than raising, so one typo in
    CF_TRUSTED_IPS cannot take a tier down at request time.
    """
    try:
        ip = _ipaddr.ip_address(peer)
    except ValueError:
        return False
    for cidr in networks:
        try:
            if ip in _ipaddr.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False

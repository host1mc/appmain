"""
edge_gate.py — WSGI flood detection, load shedding, and the site-entry challenge.

Why this is WSGI middleware and not a ``before_request`` hook
------------------------------------------------------------
Because a ``before_request`` hook is already too late to save anything.

``ServerSessionInterface.open_session`` runs when Flask **pushes the request
context**, which happens before flask-limiter, before the CSRF check, before the
browser-integrity hook, and before every ``before_request`` in the file. A
request carrying a session cookie has therefore already spent an internal HTTP
call and an Oracle SELECT by the time the first hook sees it — so a hook that
answers 429 has prevented nothing; it has only decided not to render a template
after the expensive part was paid for. ``session_cookie`` closed the *forged*
cookie case by making a bad tag rejectable with no I/O, but a flood of requests
carrying no cookie at all still buys a full Flask request context each.

Sitting in WSGI is what makes shedding actually cheap: a request refused here
costs a dict lookup, a little arithmetic, and a ~200-byte static body. No Flask
context, no session, no template, no database. That property is the whole design
constraint — a mitigation that costs real work per rejected request is not a
mitigation, it is a second attack surface with the defender paying for it.

Install order
-------------
``frontend.py`` wraps this **inside** ProxyFix::

    app.wsgi_app = edge_gate.Gate(app.wsgi_app, ...)   # inner
    app.wsgi_app = ProxyFix(app.wsgi_app, ...)         # outer, runs first

ProxyFix must stay outermost so that by the time this middleware runs,
``environ["REMOTE_ADDR"]`` is the address ProxyFix resolved through the trusted
hops, and the original socket peer is available at
``environ["werkzeug.proxy_fix.orig"]`` — exactly what ``_socket_peer()`` reads
inside the app. Reversing the order would key every counter on the load
balancer's address, collapsing the whole fleet's traffic into one bucket.

Why the client address is re-derived here instead of imported
------------------------------------------------------------
``frontend._get_client_ip()`` is the right logic but the wrong shape: it reads
Flask's ``request``, which does not exist yet at this layer. So the trust rules
are reproduced below against ``environ`` directly, over the same ``cf_edge``
networks the app uses.

Getting this wrong is not a cosmetic bug. The resolved address *is* the counter
key, so if a caller can choose it, they rotate it per request and every
threshold here becomes decorative. Hence the forwarded-chain check: when the
chain does not look like it genuinely arrived through our own proxies, the
forwarded entries are discarded and the counter keys on the real socket peer
instead — attributing a flood to the balancer is survivable, letting an attacker
pick their own bucket is not.

What it does, in order of cost
------------------------------
1. **Per-IP flood shedding.** More than ``GATE_IP_MAX`` requests in
   ``GATE_WINDOW`` seconds from one address ⇒ that address gets a static
   ``503`` with ``Retry-After`` for ``GATE_IP_COOLDOWN`` seconds. The socket
   stays open and the listener stays bound; this sheds load, it does not
   withdraw service. That is deliberate — see the note on hard close below.
2. **Global surge.** Total traffic over ``GATE_GLOBAL_MAX`` in the same window
   raises an "under load" flag, which promotes the entry challenge from
   ``suspicious`` to ``always`` for as long as it lasts and starts shedding
   unsolved anonymous page views first, sparing anyone holding a valid gate
   cookie.
3. **Site-entry challenge.** An unsolved visitor asking for an HTML page gets a
   self-contained Turnstile interstitial instead of the page.

Memory is bounded on purpose
----------------------------
The obvious implementation — a deque of timestamps per address — costs memory
proportional to the *request rate*, which means the counter grows fastest
exactly when it is under attack. This uses a fixed sliding-window counter
instead: five numbers per address regardless of rate, a hard cap on how many
addresses are tracked at once, and an amortised sweep rather than a scan per
request. The global counter is O(1) and unevadable, so it remains the backstop
if the per-address table ever saturates under a botnet.

Everything degrades toward availability
---------------------------------------
Any unexpected exception inside this middleware falls through to the wrapped
application. A bug in the flood defence must never be able to take the site down
by itself, so the failure mode is "protection stops working", never "site stops
answering".
"""

import base64
import hashlib
import hmac
import html
import ipaddress
import os
import secrets
import sys
import threading
import time
import urllib.parse

import cf_edge
import turnstile

# Nothing under these prefixes is ever challenged with an interstitial: they are
# either not navigations (so a challenge would break a client rather than ask a
# human a question), or they are the endpoints this module itself serves.
# /api/ and /panel are excluded because an HTML challenge in reply to an XHR or a
# proxied panel call is indistinguishable from a broken backend. They are still
# counted by the shedder, which is what actually protects them.
CHALLENGE_EXEMPT_PREFIXES = ("/static/", "/api/", "/panel", "/__gate/")

# Well-known paths that must keep answering to non-browser clients: the load
# balancer's health probe, crawler contracts, the PWA manifest and service
# worker, and the ads.txt an ad network fetches. Challenging any of these breaks
# something silently.
CHALLENGE_EXEMPT_EXACT = frozenset({
    "/health", "/robots.txt", "/sitemap.xml", "/ads.txt",
    "/site.webmanifest", "/sw.js", "/favicon.ico",
})

# The one path never shed, at any rate, from any address. If the OCI load
# balancer's probe is shed, the balancer concludes the instance is dead and moves
# every visitor to the other one — turning a flood against instance A into an
# outage of both. The probe is cheap and its source is the balancer, so it is
# exempt from counting entirely.
SHED_EXEMPT_EXACT = frozenset({"/health"})

GATE_COOKIE_NAME = "dch_gate"
_GATE_MAC_INFO = b"dch-edge-gate-cookie-v1"
_GATE_MAC_BYTES = 16

# A Turnstile token is ~2 KB. The verify endpoint reads a form body, so it needs
# a ceiling of its own: without one, POSTing a gigabyte to an unauthenticated
# endpoint is free denial of service against the thing meant to prevent it.
MAX_VERIFY_BODY = 8 * 1024

_key_cache = {}


_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app", ".env")


def _load_env_file(path):
    """The shared .env as a dict, or empty when there is no such file.

    Read once at import rather than per lookup. enabled() and mode() are consulted
    on every single request, including the flood path whose whole purpose is to
    stay cheap under load, and a file open per lookup would put syscalls exactly
    there. Editing the file therefore needs a restart, the same contract
    database.py's own _FILE_CFG has.

    utf-8-sig because a BOM would otherwise attach itself to the first line's key
    name and stop that one name from ever matching. A missing file is not an
    error: a deployment that sets everything in the real environment has no .env
    and must still boot.
    """
    cfg = {}
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, raw = line.split("=", 1)
                cfg[key.strip()] = raw.strip().strip("\"'")
    except OSError:
        pass
    return cfg


_FILE_CFG = _load_env_file(_ENV_PATH)


def _setting(name: str) -> str:
    """One config name, from the real environment or the shared .env.

    The environment wins, because main.py forwards its own to all five tiers. The
    .env is consulted at all because the tier that installs this middleware is the
    frontend, and the frontend loads no .env — so without this a GATE_* line in
    that file would be ignored in the one place it governs.
    """
    val = (os.environ.get(name) or "").strip()
    if val:
        return val
    return _FILE_CFG.get(name, "")


def _flag(name: str, default: str) -> bool:
    # An empty value counts as unset and takes the default, matching
    # crypto_util._env and turnstile: "" is what a blanked or commented-out line
    # leaves behind, not a deliberate choice. Write GATE_ENABLED=0 to mean off.
    return (_setting(name) or default).strip().lower() in (
        "1", "true", "yes", "on")


def _num(name: str, default: float) -> float:
    try:
        value = float(_setting(name) or default)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def enabled() -> bool:
    """Whether the middleware does anything at all.

    Defaults on, because with the thresholds below it is inert for legitimate
    traffic: the per-address ceiling sits far above what a browser loading pages
    produces, and the challenge stays dormant until Turnstile keys exist. Set
    ``GATE_ENABLED=0`` to remove it from the request path entirely.
    """
    return _flag("GATE_ENABLED", "1")


def mode() -> str:
    """When the site-entry challenge applies.

    ``suspicious`` (default) challenges only a visitor the detector has reason to
    doubt — anyone at all while the global surge flag is up. One tripping the
    per-address rate is shed with a 503 and ``Retry-After`` rather than
    challenged. Real visitors and crawlers never see it.

    ``always`` challenges every unsolved visitor on their first page view.

    What the Gate exempts from the challenge is the paths in
    ``CHALLENGE_EXEMPT_PREFIXES`` and ``CHALLENGE_EXEMPT_EXACT``, plus a bot
    Cloudflare itself verified. Nothing here looks at User-Agent: a UA test would
    be a one-header bypass of the whole gate, since anyone can claim to be
    Googlebot. ``frontend``'s own crawler handling is no help either — Flask is
    never entered when the Gate answers a request itself.

    A warning about ``always``, because it is what "gate the site entrance"
    literally means and it has a cost that is easy to miss: it challenges
    **Googlebot** too, and a crawler cannot solve a CAPTCHA, so the site
    deindexes. The verified-bot exemption is what prevents that, and it reads
    ``CF-Verified-Bot`` through ``cf_edge``'s peer test, where every ``CF-*``
    header is discarded while the socket peer is the OCI balancer rather than
    Cloudflare — so the exemption is inert, and ``always`` still deindexes, until
    ``CF_TRUSTED_IPS`` pins the balancer's range. Do not switch to ``always``
    before that is done.

    ``off`` keeps the shedder and disables the challenge.
    """
    value = (_setting("GATE_MODE") or "suspicious").strip().lower()
    return value if value in ("suspicious", "always", "off") else "suspicious"


def _cookie_ttl() -> float:
    return _num("GATE_COOKIE_TTL", 43200)


def _mac_key(token: str) -> bytes:
    key = _key_cache.get(token)
    if key is None:
        key = hmac.new(token.encode("utf-8", "surrogatepass"), _GATE_MAC_INFO,
                       hashlib.sha256).digest()
        _key_cache[token] = key
    return key


def _sign_gate(expiry: int, client_ip: str, token: str) -> str:
    """A gate cookie asserting that ``client_ip`` solved a challenge.

    Bound to the address as well as the expiry so a single solved cookie cannot
    be handed round a botnet and reused from thousands of hosts — which is
    exactly what an attacker would do with a cookie that only carried a
    timestamp. The cost is that a visitor changing network (mobile handoff,
    VPN toggle) is challenged again. That is acceptable friction for something
    which, in the default ``suspicious`` mode, only appears under attack.
    """
    payload = f"{expiry}|{client_ip}"
    digest = hmac.new(_mac_key(token), payload.encode("utf-8"),
                      hashlib.sha256).digest()[:_GATE_MAC_BYTES]
    tag = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{expiry}.{tag}"


def _verify_gate(raw: str, client_ip: str, token: str, now_wall: float) -> bool:
    """Whether a gate cookie is one we issued to this address and still valid."""
    if not isinstance(raw, str) or not raw or not token:
        return False
    expiry_text, found, _ = raw.partition(".")
    if not found:
        return False
    try:
        expiry = int(expiry_text)
    except (TypeError, ValueError):
        return False
    if expiry <= now_wall:
        return False
    # Compared as bytes, not as text: compare_digest raises TypeError for a str
    # holding any non-ASCII codepoint, and this value arrives through
    # HTTP_COOKIE, which the WSGI server hands over latin-1 decoded. Passing it
    # straight in turned a *rejection* into a TypeError, and __call__'s
    # except Exception answers that by handing the request to the application
    # untouched — so one high byte in the cookie skipped the challenge and the
    # surge shed entirely, silently, instead of failing the check. Encoded the
    # same way panel_app.auth.csrf_ok does it: "surrogatepass" is the form that
    # cannot itself raise on a lone surrogate and land back in that swallow.
    return hmac.compare_digest(
        raw.encode("utf-8", "surrogatepass"),
        _sign_gate(expiry, client_ip, token).encode("utf-8", "surrogatepass"),
    )


# ── client address resolution ────────────────────────────────────

def _cookie_value(environ, name: str) -> str:
    header = environ.get("HTTP_COOKIE", "") or ""
    if name not in header:
        return ""
    for part in header.split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip() == name:
            return value.strip()
    return ""


def _hop(value: str):
    """One X-Forwarded-For entry as an address, or None.

    Entries arrive as bare addresses, ``ip:port``, or ``[v6]:port`` depending on
    which proxy wrote them, so all three are unwrapped before parsing.
    """
    text = (value or "").strip()
    if not text:
        return None
    if text.startswith("["):
        text = text[1:].partition("]")[0]
    elif text.count(":") == 1:
        text = text.partition(":")[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _is_internal(addr) -> bool:
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def _chain_is_trustworthy(chain, hops: int) -> bool:
    """Whether the forwarded chain really came through ``hops`` proxies of ours.

    Each proxy appends the peer it heard from, so with N trusted hops the visitor
    sits N-th from the right and the N-1 entries to its right were written by our
    own infrastructure about each other — a Cloudflare edge address, or a private
    address inside the VCN. A public non-Cloudflare address in one of those slots
    means the request entered the chain somewhere unexpected, typically straight
    at the balancer with Cloudflare bypassed, and from that point every entry
    further left is just text the caller chose.

    This mirrors ``frontend._forwarded_chain_fault()``. The ambiguous case is
    treated as untrustworthy for the reason given there: the alternative lets a
    caller nominate their own counter key and step around every threshold here.
    """
    if hops < 2:
        return True
    if len(chain) < hops:
        return False
    for entry in chain[-(hops - 1):]:
        addr = _hop(entry)
        if addr is None:
            return False
        if _is_internal(addr):
            continue
        if cf_edge.peer_is_cf(str(addr), cf_edge.EDGE_NETWORKS):
            continue
        return False
    return True


def _socket_peer(environ) -> str:
    """The address that opened the connection, before ProxyFix rewrote it."""
    original = environ.get("werkzeug.proxy_fix.orig") or {}
    if isinstance(original, dict):
        peer = original.get("REMOTE_ADDR") or ""
        if peer:
            return peer
    return environ.get("REMOTE_ADDR", "") or ""


def client_ip(environ, hops: int) -> str:
    """The address this request is attributed to, for counting purposes.

    Prefers ``CF-Connecting-IP``, but only under the same two conditions the app
    applies: the socket peer must sit on Cloudflare's ranges (or one an operator
    pinned via ``CF_TRUSTED_IPS``), and the header must name a public address.
    Without the peer test the header is just client-supplied text, and trusting
    it would hand every caller a free choice of rate-limit bucket.

    Falls back to the ProxyFix-resolved ``REMOTE_ADDR``, and past that to the raw
    socket peer when the forwarded chain cannot be trusted.
    """
    peer = _socket_peer(environ)
    chain_raw = environ.get("HTTP_X_FORWARDED_FOR", "") or ""
    chain = [part for part in chain_raw.split(",") if part.strip()]
    trustworthy = _chain_is_trustworthy(chain, hops)

    if hops >= 1 and trustworthy:
        cf = (environ.get("HTTP_CF_CONNECTING_IP", "") or "").strip()
        if cf and cf_edge.peer_is_cf(peer, cf_edge.HEADER_PEER_NETWORKS):
            try:
                addr = ipaddress.ip_address(cf)
            except ValueError:
                addr = None
            if addr is not None and not addr.is_private and not addr.is_loopback \
                    and not addr.is_link_local and not addr.is_multicast \
                    and not addr.is_unspecified:
                return str(addr)
    if not trustworthy:
        # The chain is not ours to believe, so ProxyFix's REMOTE_ADDR was taken
        # from an entry the caller may have written. Count against the real peer.
        return peer
    return environ.get("REMOTE_ADDR", "") or peer


def _cf_verified_bot(environ) -> bool:
    if not cf_edge.peer_is_cf(_socket_peer(environ),
                              cf_edge.HEADER_PEER_NETWORKS):
        return False
    value = (environ.get("HTTP_CF_VERIFIED_BOT", "") or "").strip().lower()
    return value in ("1", "true", "yes", "on")


# ── the counters ─────────────────────────────────────────────────

class _RateTable:
    """Per-key sliding-window counters with bounded memory.

    Each key holds five numbers — window start, current count, previous count,
    blocked-until, last-seen — so memory is proportional to the number of
    *distinct addresses seen*, never to the request rate. The alternative (a
    timestamp deque per key) grows in step with the flood it is measuring, which
    makes the counter an amplifier of the attack it is supposed to detect.

    The two-bucket estimate is the standard sliding-window counter: the previous
    window's count is weighted by how much of it still overlaps the present one.
    It is approximate at the boundary and cheap everywhere, which is the correct
    trade for something on every request.
    """

    __slots__ = ("_window", "_max_tracked", "_rows", "_lock", "_next_sweep",
                 "_saturated")

    def __init__(self, window: float, max_tracked: int):
        self._window = window
        self._max_tracked = max_tracked
        self._rows = {}
        self._lock = threading.Lock()
        self._next_sweep = 0.0
        self._saturated = False

    def _roll(self, row, now):
        """Advance a row's windows to the present, then return its estimate."""
        elapsed = now - row[0]
        if elapsed >= 2 * self._window:
            row[0], row[1], row[2] = now, 0.0, 0.0
        elif elapsed >= self._window:
            row[0], row[2], row[1] = row[0] + self._window, row[1], 0.0
        overlap = 1.0 - ((now - row[0]) / self._window)
        if overlap < 0.0:
            overlap = 0.0
        return row[1] + (row[2] * overlap)

    def hit(self, key, now):
        """Count one request and report ``(estimate, blocked_until)``."""
        with self._lock:
            if now >= self._next_sweep:
                self._sweep(now)
            row = self._rows.get(key)
            if row is None:
                if len(self._rows) >= self._max_tracked:
                    # Table is full even after a sweep. Rather than grow without
                    # limit, refuse to allocate and let the global counter carry
                    # this request: it is O(1) and cannot be evaded by spreading
                    # across addresses, which is precisely the situation here.
                    self._saturated = True
                    return 0.0, 0.0
                row = [now, 0.0, 0.0, 0.0, now]
                self._rows[key] = row
            estimate = self._roll(row, now)
            row[1] += 1.0
            row[4] = now
            return estimate + 1.0, row[3]

    def block(self, key, now, seconds):
        with self._lock:
            row = self._rows.get(key)
            if row is not None:
                row[3] = now + seconds

    def saturated(self) -> bool:
        return self._saturated

    def _sweep(self, now):
        """Drop rows that can no longer affect a decision.

        Amortised: scheduled on a timer rather than run per request, so the cost
        is one pass every ``GATE_SWEEP_SECONDS`` regardless of traffic. Called
        with the lock already held.
        """
        self._next_sweep = now + _num("GATE_SWEEP_SECONDS", 30)
        horizon = max(self._window * 2, _num("GATE_IP_COOLDOWN", 60))
        dead = [key for key, row in self._rows.items()
                if now - row[4] > horizon and row[3] <= now]
        for key in dead:
            del self._rows[key]
        if len(self._rows) <= self._max_tracked:
            self._saturated = False
            return
        # Still over the cap with nothing stale left to drop, which means a
        # genuinely broad flood. Evict the least recently seen down to 80% so
        # there is headroom for new arrivals instead of thrashing at the limit.
        target = int(self._max_tracked * 0.8)
        for key, _row in sorted(self._rows.items(), key=lambda kv: kv[1][4]):
            if len(self._rows) <= target:
                break
            del self._rows[key]


class _GlobalRate:
    """One sliding-window counter for the whole process.

    Deliberately separate from ``_RateTable``: this is the measurement an
    attacker cannot dodge by spreading across source addresses, so it stays O(1)
    and always available even when the per-address table has saturated.
    """

    __slots__ = ("_window", "_row", "_lock")

    def __init__(self, window: float):
        self._window = window
        self._row = [0.0, 0.0, 0.0]
        self._lock = threading.Lock()

    def hit(self, now):
        with self._lock:
            row = self._row
            elapsed = now - row[0]
            if elapsed >= 2 * self._window:
                row[0], row[1], row[2] = now, 0.0, 0.0
            elif elapsed >= self._window:
                row[0], row[2], row[1] = row[0] + self._window, row[1], 0.0
            overlap = 1.0 - ((now - row[0]) / self._window)
            if overlap < 0.0:
                overlap = 0.0
            estimate = row[1] + (row[2] * overlap)
            row[1] += 1.0
            return estimate + 1.0


# ── hard close (opt-in last resort) ──────────────────────────────

_close_state = {"armed_since": 0.0, "closed_until": 0.0}
_close_lock = threading.Lock()
_listener_controller = False


def register_listener_controller() -> None:
    global _listener_controller
    _listener_controller = True


def listener_controller_present() -> bool:
    return _listener_controller


def hard_close_enabled() -> bool:
    """Whether a sustained flood may actually unbind the listener.

    Off by default, and it should stay off unless the alternative has been tried.
    Closing the socket looks like the strongest possible answer and is usually
    the weakest: the flood costs the attacker the same either way, while the site
    is now definitively down rather than degraded, so the mitigation finishes the
    job the attack started.

    It is worse than that in this deployment specifically. Two instances sit
    behind one OCI balancer. When A withdraws, the balancer moves *all* traffic
    to B — the flood included — so B crosses the same threshold moments later and
    both go dark. Shedding keeps both instances answering real visitors while
    dropping the flood, which is why it is the default and this is not.

    Volumetric traffic has to be stopped at the edge. See ``DDOS_RUNBOOK.md``.
    """
    return _flag("GATE_HARD_CLOSE", "0")


def note_pressure(global_rate: float, now: float) -> None:
    """Track whether the flood has been bad enough, for long enough, to close.

    Requires the rate to stay above the (much higher) close watermark for
    ``GATE_CLOSE_SUSTAIN`` seconds continuously — a single spike drops the timer
    back to zero. Without the sustain requirement a brief burst, or one noisy
    crawler, could unbind the public listener.
    """
    if not hard_close_enabled():
        return
    watermark = _num("GATE_CLOSE_RPS", 2000)
    sustain = _num("GATE_CLOSE_SUSTAIN", 20)
    with _close_lock:
        if _close_state["closed_until"] > now:
            return
        if global_rate < watermark:
            _close_state["armed_since"] = 0.0
            return
        if not _close_state["armed_since"]:
            _close_state["armed_since"] = now
            return
        if now - _close_state["armed_since"] >= sustain:
            _close_state["armed_since"] = 0.0
            if not _listener_controller:
                _warn_no_listener_controller(global_rate, watermark, sustain)
                return
            _close_state["closed_until"] = now + _num("GATE_CLOSE_COOLDOWN", 90)
            print(
                f"[gate] hard close armed: {global_rate:.0f} requests/window "
                f"sustained past {watermark:.0f} for {sustain:.0f}s. Listener "
                f"will reopen automatically after "
                f"{_num('GATE_CLOSE_COOLDOWN', 90):.0f}s.",
                file=sys.stderr, flush=True,
            )


def should_be_closed(now=None) -> bool:
    """Whether the listener should currently be unbound.

    Polled by ``frontend.serve()``'s supervisor. Self-clearing: it goes false on
    its own once the cooldown elapses, so a false positive costs one cooldown of
    downtime rather than an outage that lasts until somebody notices.
    """
    if not hard_close_enabled():
        return False
    with _close_lock:
        return _close_state["closed_until"] > (
            time.monotonic() if now is None else now)


def warn_if_hard_close_unsupported() -> None:
    if not hard_close_enabled():
        return
    if listener_controller_present():
        return
    _warn_no_listener_controller()


# ── the middleware ───────────────────────────────────────────────

def _retry_after() -> str:
    return str(int(_num("GATE_IP_COOLDOWN", 60)))


def _shed_body(retry_after: str) -> bytes:
    """The shed response body.

    Static bytes, no template, no formatting beyond the retry hint: this is the
    thing that has to stay cheap for shedding to be worth doing at all.
    """
    return (
        b"<!doctype html><meta charset=utf-8><title>Too many requests</title>"
        b"<style>body{font:16px system-ui;margin:12vh auto;max-width:32em;"
        b"padding:0 1.5em;color:#222}</style>"
        b"<h1>Too many requests</h1><p>This address is sending requests faster "
        b"than we serve them. Please wait " + retry_after.encode("ascii") +
        b" seconds and try again.</p>"
    )


class Gate:
    """Flood shedding and the site-entry challenge, in front of Flask."""

    def __init__(self, app, internal_token="", trusted_hops=2):
        self.app = app
        # The same shared internal token session_cookie derives from, for the
        # same deployment reason: both instances already hold an identical copy,
        # so a gate cookie solved on A verifies on B with no new environment
        # variable that could be set on one host and forgotten on the other.
        self.internal_token = internal_token or ""
        self.trusted_hops = trusted_hops
        window = _num("GATE_WINDOW", 10)
        self.window = window
        self.ips = _RateTable(window, int(_num("GATE_MAX_TRACKED", 20000)))
        self.total = _GlobalRate(window)
        self._surge_until = 0.0
        self._surge_lock = threading.Lock()

    # -- surge flag ------------------------------------------------

    def _note_global(self, now):
        """Update the global counter and the surge flag; report both."""
        rate = self.total.hit(now)
        ceiling = _num("GATE_GLOBAL_MAX", 600)
        with self._surge_lock:
            if rate >= ceiling:
                # Held for a window past the last trip so the flag does not
                # flicker on and off across the boundary, which would make the
                # challenge appear and vanish for real visitors mid-session.
                self._surge_until = now + self.window
            surging = self._surge_until > now
        note_pressure(rate, now)
        return rate, surging

    # -- challenge decisions ---------------------------------------

    def _challenge_applies(self, path):
        if not turnstile.enabled():
            return False
        if mode() == "off":
            return False
        if path in CHALLENGE_EXEMPT_EXACT:
            return False
        return not path.startswith(CHALLENGE_EXEMPT_PREFIXES)

    def _is_navigation(self, environ):
        """Whether this request is a browser asking for a page.

        Only navigations are challenged. Answering an XHR, a form POST or an
        image request with an HTML interstitial does not ask anyone a question —
        it corrupts the reply, and the client reports it as a broken site rather
        than as a challenge.
        """
        if environ.get("REQUEST_METHOD", "") not in ("GET", "HEAD"):
            return False
        accept = environ.get("HTTP_ACCEPT", "") or ""
        return "text/html" in accept or "*/*" == accept.strip()

    # -- responses -------------------------------------------------

    def _shed(self, environ, start_response):
        retry = _retry_after()
        body = _shed_body(retry)
        head = environ.get("REQUEST_METHOD", "") == "HEAD"
        start_response("503 Service Unavailable", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Retry-After", retry),
            ("Cache-Control", "no-store"),
            ("X-Robots-Tag", "noindex"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ])
        return [b""] if head else [body]

    def _interstitial(self, environ, start_response, client, path):
        """The challenge page, served entirely from WSGI.

        It carries **its own** tight Content-Security-Policy rather than
        inheriting the site's. The page policy has to be permissive enough for
        the ad networks (``frontend.py`` builds it with ``'strict-dynamic'`` and
        a per-request nonce); this page needs none of that, so it gets
        ``default-src 'none'`` plus exactly the two Cloudflare origins the widget
        requires. A challenge page is the wrong place to be running anything
        else.
        """
        nonce = secrets.token_urlsafe(16)
        target = _safe_next(environ)
        site = html.escape(turnstile.site_key(), quote=True)
        body = f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style nonce="{nonce}">body{{font:16px system-ui;margin:12vh auto;max-width:32em;
padding:0 1.5em;color:#222}}h1{{font-size:1.4rem}}.w{{margin:1.5em 0}}</style>
</head><body>
<h1>Just a moment</h1>
<p>We are checking your browser before letting you through. This usually takes a
few seconds and happens once.</p>
<form method="POST" action="/__gate/verify" id="gf" class="w">
<input type="hidden" name="next" value="{html.escape(target, quote=True)}">
<div class="cf-turnstile" data-sitekey="{site}" data-callback="gateSolved"></div>
<noscript><p>JavaScript is required to complete this check.</p></noscript>
</form>
<script nonce="{nonce}">function gateSolved(){{document.getElementById('gf').submit();}}</script>
<script nonce="{nonce}" src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body></html>""".encode("utf-8")
        head = environ.get("REQUEST_METHOD", "") == "HEAD"
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Content-Security-Policy",
             "default-src 'none'; "
             f"script-src 'nonce-{nonce}' https://challenges.cloudflare.com; "
             f"style-src 'nonce-{nonce}'; "
             "frame-src https://challenges.cloudflare.com; "
             "connect-src https://challenges.cloudflare.com; "
             "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            # Without this a crawler that reaches the challenge can index the
            # interstitial as the page's content.
            ("X-Robots-Tag", "noindex"),
            ("Referrer-Policy", "same-origin"),
        ])
        return [b""] if head else [body]

    def _verify(self, environ, start_response, client):
        """Handle ``POST /__gate/verify``: check the token, set the cookie."""
        if not turnstile.enabled():
            # Without keys there is nothing here to solve: _challenge_applies()
            # returns False on the same test, so the interstitial is never
            # served and the form that posts here is never rendered. Meanwhile
            # turnstile.verify() returns True without a network call when it is
            # unconfigured, so an empty POST would fall through and be issued a
            # real gate cookie — and a gate cookie is exactly what the surge
            # shed below reads as "solved". Without this guard an unconfigured
            # deployment hands any caller with curl a permanent exemption from
            # the only mitigation it has left.
            return self._redirect(start_response, "/", None)
        try:
            length = int(environ.get("CONTENT_LENGTH", "") or 0)
        except (TypeError, ValueError):
            length = 0
        if length < 0 or length > MAX_VERIFY_BODY:
            return self._redirect(start_response, "/", None)
        raw = environ["wsgi.input"].read(length) if length else b""
        fields = urllib.parse.parse_qs(raw.decode("utf-8", "replace"),
                                       keep_blank_values=True)
        token = (fields.get("cf-turnstile-response") or [""])[0]
        target = (fields.get("next") or ["/"])[0]
        if not turnstile.verify(token, client):
            # A failed solve returns to the challenge rather than to the target,
            # so a caller cannot treat this endpoint as a way past the gate.
            return self._redirect(start_response, _sanitise_next(target), None)
        expiry = int(time.time() + _cookie_ttl())
        cookie = _sign_gate(expiry, client, self.internal_token)
        secure = "; Secure" if environ.get("wsgi.url_scheme") == "https" else ""
        return self._redirect(
            start_response, _sanitise_next(target),
            f"{GATE_COOKIE_NAME}={cookie}; Path=/; Max-Age={int(_cookie_ttl())}; "
            f"HttpOnly; SameSite=Lax{secure}")

    def _redirect(self, start_response, location, cookie):
        headers = [
            ("Location", location),
            ("Content-Length", "0"),
            ("Cache-Control", "no-store"),
        ]
        if cookie:
            headers.append(("Set-Cookie", cookie))
        start_response("303 See Other", headers)
        return [b""]

    # -- entry point -----------------------------------------------

    def __call__(self, environ, start_response):
        if not enabled():
            return self.app(environ, start_response)
        try:
            return self._dispatch(environ, start_response)
        except Exception as exc:
            # Availability wins over protection. A defect in here must not be
            # able to do what the flood was trying to do, so any unexpected
            # error hands the request to the application untouched.
            _warn_internal_once(exc)
            return self.app(environ, start_response)

    def _dispatch(self, environ, start_response):
        path = environ.get("PATH_INFO", "") or "/"
        now = time.monotonic()
        client = client_ip(environ, self.trusted_hops)

        if path in SHED_EXEMPT_EXACT:
            return self.app(environ, start_response)

        rate, surging = self._note_global(now)
        count, blocked_until = self.ips.hit(client, now)

        if blocked_until > now:
            return self._shed(environ, start_response)
        if count >= _num("GATE_IP_MAX", 150):
            self.ips.block(client, now, _num("GATE_IP_COOLDOWN", 60))
            _warn_shed_once(client, count)
            return self._shed(environ, start_response)

        solved = _verify_gate(_cookie_value(environ, GATE_COOKIE_NAME), client,
                              self.internal_token, time.time())

        if path == "/__gate/verify" and environ.get("REQUEST_METHOD") == "POST":
            return self._verify(environ, start_response, client)

        if self._challenge_applies(path) and not solved \
                and self._is_navigation(environ):
            # Under a global surge every unsolved visitor is challenged
            # regardless of mode: that is the point at which the cost of asking
            # is lower than the cost of serving.
            if (mode() == "always" or surging) \
                    and not _cf_verified_bot(environ):
                return self._interstitial(environ, start_response, client, path)

        if surging and not solved and self._is_navigation(environ) \
                and not path.startswith(CHALLENGE_EXEMPT_PREFIXES) \
                and path not in CHALLENGE_EXEMPT_EXACT:
            # Surge with no challenge available (no Turnstile keys configured):
            # shed unsolved anonymous page views, which are the expensive ones,
            # and keep serving everything a real session or a solved cookie asks
            # for. Without keys this is the only lever left.
            if not _has_session_cookie(environ):
                return self._shed(environ, start_response)

        return self.app(environ, start_response)


def _has_session_cookie(environ) -> bool:
    """Whether the request carries something that looks like a logged-in session.

    Only a hint, and deliberately not a validation: the point is to prefer
    established visitors while shedding, and the cookie's real authentication
    happens in ``session_cookie.verify`` a layer later. Checking the tag here
    would mean deriving a key on the shed path, which is work this layer exists
    to avoid.
    """
    return "session=" in (environ.get("HTTP_COOKIE", "") or "")


def _safe_next(environ) -> str:
    """Where to send a visitor back to after they solve the challenge."""
    path = environ.get("PATH_INFO", "") or "/"
    query = environ.get("QUERY_STRING", "") or ""
    return _sanitise_next(f"{path}?{query}" if query else path)


def _sanitise_next(value: str) -> str:
    """A same-site path, or ``/``.

    The interstitial round-trips this through a form field, so it is
    visitor-controlled by the time it comes back. Anything not a plain rooted
    path is discarded: ``//evil.example`` is protocol-relative and
    ``https://evil.example`` absolute, and either would turn the gate into an
    open redirect that a phisher could point at the site's own domain.
    """
    text = (value or "").strip()
    if not text.startswith("/") or text.startswith("//"):
        return "/"
    if "\\" in text or "\n" in text or "\r" in text:
        return "/"
    if any(char > "\xff" for char in text):
        return "/"
    return text[:512]


_shed_warned = set()
_internal_warned = False
_no_controller_warned = False


def _warn_no_listener_controller(global_rate=None, watermark=None, sustain=None):
    global _no_controller_warned
    if _no_controller_warned:
        return
    if global_rate is None:
        headline = "WILL DO NOTHING HERE"
        cause = ("The flag is set, so a sustained flood is expected to withdraw "
                 "the listener, but")
        state = "will STAY BOUND and a flood will GO ON BEING SERVED"
    else:
        _no_controller_warned = True
        headline = "DID NOTHING"
        cause = (f"The flood reached {global_rate:.0f} requests/window and "
                 f"stayed past {watermark:.0f} for {sustain:.0f}s, which is the "
                 f"point the listener would have been withdrawn, but")
        state = "is STILL BOUND and the flood is STILL BEING SERVED"
    print(
        f"[gate] WARNING: GATE_HARD_CLOSE=1 {headline}. {cause} no listener "
        f"controller is registered in this process: nothing here can unbind "
        f"the socket and nothing is polling should_be_closed(), so the "
        f"listener {state}. Only frontend.serve()'s waitress path registers "
        f"one; under gunicorn (wsgi_frontend:application) it never runs. Load "
        f"shedding stays in effect and is the only mitigation running here. "
        f"Volumetric traffic has to be stopped at the edge - see "
        f"DDOS_RUNBOOK.md.",
        file=sys.stderr, flush=True,
    )


def _warn_shed_once(client, count):
    """One line per address the shedder starts refusing, capped in total.

    Capped because the log is a shared resource under exactly the conditions
    this fires in: a botnet spread over thousands of addresses would otherwise
    turn per-address logging into a disk-filling amplifier.
    """
    if len(_shed_warned) > 200 or client in _shed_warned:
        return
    _shed_warned.add(client)
    safe = "".join(ch for ch in str(client) if ch in "0123456789abcdefABCDEF.:")
    print(f"[gate] shedding {safe[:45]}: {count:.0f} requests in "
          f"{_num('GATE_WINDOW', 10):.0f}s", file=sys.stderr, flush=True)


def _warn_internal_once(exc):
    global _internal_warned
    if _internal_warned:
        return
    _internal_warned = True
    print(f"[gate] WARNING: internal error, requests are passing through "
          f"unfiltered ({type(exc).__name__}: {exc})",
          file=sys.stderr, flush=True)

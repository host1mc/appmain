"""
turnstile.py — Cloudflare Turnstile siteverify, as a standard-library leaf.

Why this exists
---------------
Two callers need to ask Cloudflare "was this token really issued to a human?":
``edge_gate``'s site-entry interstitial, which runs inside WSGI before Flask has
built a request context, and the ``/user/login`` and ``/user/register`` handlers,
which need the answer *before* they spend an Argon2 hash. Neither can share a
Flask-flavoured helper, so this module imports only the standard library and
takes everything it needs as arguments — the same reason ``cf_edge`` and
``session_cookie`` are shaped the way they are.

Why it matters for login specifically: Argon2id here is OWASP's baseline of
19 MiB and 2 passes (see ``database.py``'s note on the parameters). That cost is
deliberate against an offline cracker, but it is also a self-inflicted amplifier
if an unsolved request can reach it — a few hundred concurrent login POSTs with
garbage passwords will exhaust memory and CPU long before the database notices.
Verifying the token first means a flood pays Cloudflare's cost, not ours.

Failure policy
--------------
Fail **open** by default. ``siteverify`` is a network call to a third party, and
if Cloudflare's endpoint is unreachable the honest choices are "let everyone in"
or "let nobody log in". A CF outage locking every user out of the site — and out
of the panel — is a worse and much more likely outcome than the flood this is
meant to blunt, so an unreachable endpoint is treated as a pass and logged.
``TURNSTILE_FAIL_CLOSED=1`` inverts that for an operator who would rather be down
than open.

Note the asymmetry: only a *transport* failure fails open. A token that
Cloudflare actively rejects is a definitive ``False`` regardless of the flag,
because that answer did not depend on the network being healthy.

Configuration
-------------
Everything is off until keys are present. ``enabled()`` requires both a site key
and a secret key, so deploying this module changes no behaviour at all until an
operator sets them — there is no state in which a missing key silently blocks
traffic.
"""

import http.client
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# The shared .env, parsed with stdlib open() rather than python-dotenv so this
# module keeps its no-dependency shape. Same file crypto_util reads its key from.
# utf-8-sig because a BOM would otherwise attach itself to the first line's key
# name and stop that one name from ever matching.
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "fastapi-oracle-app", ".env")


def _load_env_file(path: str) -> dict:
    """The shared .env as a dict, or empty when there is no such file.

    Read once at import rather than per lookup: enabled() is called from
    edge_gate on the flood path, and a file open per request would put syscalls
    on the one path whose whole purpose is to stay cheap under load. Editing the
    file therefore needs a restart to take effect — the same contract
    database.py's own _FILE_CFG has.

    Missing is not an error. A deployment that sets everything in the real
    environment has no .env at all, and must still boot.
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

# A Turnstile token is a couple of kilobytes; the reply is a small JSON object.
# Both are bounded here so a hostile or wedged endpoint cannot stream unbounded
# bytes into the process, the same ceiling discipline node_client applies.
MAX_TOKEN_CHARS = 4096
MAX_RESPONSE_BYTES = 16 * 1024

# Short on purpose. This call sits in the request path of a login, so the
# timeout is a hard floor on how long a flood can pin a worker thread: at
# threads=8, a 30s timeout would let 8 stalled verifications freeze the tier.
DEFAULT_TIMEOUT = 4.0

_unreachable_warned = False
_disabled_warned = False


def _setting(name: str) -> str:
    """One config name, from the real environment or the shared .env.

    The environment wins, because main.py forwards its own to all five tiers and
    a value set there is true everywhere. The .env is the fallback rather than
    the only source for the opposite reason: nothing exports it wholesale —
    database.py parses it into a private dict on purpose, and the only
    load_dotenv is asgi_panel's — so a key left solely in that file would reach
    the panel, which has no Turnstile code, and not the frontend or the gate,
    which are the two callers that do.

    An empty value counts as unset, matching crypto_util._env: "" is what a
    blanked or commented-out line leaves behind, not a deliberate choice.
    """
    val = (os.environ.get(name) or "").strip()
    if val:
        return val
    return _FILE_CFG.get(name, "")


def _flag(name: str, default: str) -> bool:
    return (_setting(name) or default).strip().lower() in (
        "1", "true", "yes", "on")


# Cloudflare official testing keys (always pass). Never used unless
# TURNSTILE_TEST=1 — falling back to them in production made every login
# "protected" by a CAPTCHA that Cloudflare documents as always succeeding.
TEST_SITE_KEY = "1x00000000000000000000AA"
TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"


def _test_mode() -> bool:
    return _flag("TURNSTILE_TEST", "0")


def site_key() -> str:
    """The public key the widget is rendered with. Safe to put in HTML."""
    configured = _setting("TURNSTILE_SITE_KEY")
    if configured:
        return configured
    return TEST_SITE_KEY if _test_mode() else ""


def secret_key() -> str:
    """The private key siteverify is called with. Never leaves this process."""
    configured = _setting("TURNSTILE_SECRET_KEY")
    if configured:
        return configured
    return TEST_SECRET_KEY if _test_mode() else ""


def enabled() -> bool:
    """Whether Turnstile is configured well enough to be used at all.

    Both real keys are required. Dummy Cloudflare test keys do not count
    unless TURNSTILE_TEST=1 (local smoke tests only).
    """
    if not _flag("TURNSTILE_ENABLED", "1"):
        return False
    return bool(site_key() and secret_key())


def fail_closed() -> bool:
    """Whether an unreachable Cloudflare should refuse the request."""
    return _flag("TURNSTILE_FAIL_CLOSED", "0")


def _timeout() -> float:
    try:
        value = float(_setting("TURNSTILE_TIMEOUT") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return value if value > 0 else DEFAULT_TIMEOUT


def _warn_unreachable_once(reason: str) -> None:
    """Report a siteverify that could not be reached, once per process.

    Rate-limited to a single line because the situation that produces it — the
    endpoint being down — produces it on every single request, and a flood of
    identical lines would bury the log while telling an operator nothing the
    first line did not.
    """
    global _unreachable_warned
    if _unreachable_warned:
        return
    _unreachable_warned = True
    verdict = "refusing requests" if fail_closed() else "allowing requests through"
    print(
        f"[turnstile] siteverify unreachable ({reason}); {verdict}. "
        "Set TURNSTILE_FAIL_CLOSED=1 to refuse instead of allow.",
        file=sys.stderr, flush=True,
    )


def _warn_disabled_once() -> None:
    global _disabled_warned
    if _disabled_warned:
        return
    _disabled_warned = True
    if not _flag("TURNSTILE_ENABLED", "1"):
        return
    have_site = bool(site_key())
    have_secret = bool(secret_key())
    if have_site and have_secret:
        return
    if have_site or have_secret:
        missing = "TURNSTILE_SITE_KEY" if have_secret else "TURNSTILE_SECRET_KEY"
        detail = f"half-configured ({missing} is unset)"
    else:
        detail = "not configured (TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are unset)"
    print(
        f"[turnstile] {detail}; no CAPTCHA is enforced on login, registration "
        "or the site gate. Set both keys, or set TURNSTILE_ENABLED=0 to "
        "silence this.",
        file=sys.stderr, flush=True,
    )


def verify(token: str, remote_ip: str = "") -> bool:
    """Whether ``token`` is a Turnstile solution Cloudflare vouches for.

    ``remote_ip`` is optional and advisory — Cloudflare uses it to bind the
    solution to the client that produced it. It is only passed when the caller
    resolved a trustworthy address; handing it a forgeable one would make the
    check weaker, not stronger.

    Returns ``True`` when Turnstile is not configured, so every call site can be
    written as a plain guard without also testing ``enabled()``.
    """
    if not enabled():
        _warn_disabled_once()
        return True
    token = (token or "").strip()
    if not token or len(token) > MAX_TOKEN_CHARS:
        # No token, or one too long to be genuine: a definitive failure that
        # costs no network call. This is the common case under a flood.
        return False

    fields = {"secret": secret_key(), "response": token}
    if remote_ip:
        fields["remoteip"] = remote_ip
    body = urllib.parse.urlencode(fields, errors="surrogatepass").encode("ascii")
    req = urllib.request.Request(
        SITEVERIFY_URL,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "DiscordHost/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError,
            ValueError) as exc:
        # Transport failure, so we never learned Cloudflare's opinion. This is
        # the only branch the fail-open policy applies to.
        _warn_unreachable_once(type(exc).__name__)
        return not fail_closed()
    if len(raw) > MAX_RESPONSE_BYTES:
        _warn_unreachable_once("response too large")
        return not fail_closed()
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _warn_unreachable_once("unreadable response")
        return not fail_closed()
    # Cloudflare answered, so its verdict stands whatever the fail-open flag
    # says: a rejected token is rejected.
    return isinstance(decoded, dict) and decoded.get("success") is True

"""
session_cookie.py — authenticates the browser's session cookie.

Why this exists
---------------
``frontend.py``'s ``_valid_sid()`` checks that a session cookie is *shaped* like
one we would issue: hexadecimal, at most 64 characters. That is a path-traversal
guard — it stops a visitor interpolating ``../admin/...`` into the internal
``/api/session/{sid}`` URL — and it was never meant to prove the cookie is one we
actually minted. Nothing else did either, so any hex string was accepted as a
plausible session id, and ``ServerSessionInterface.open_session`` spent a real
backend HTTP call plus an Oracle SELECT finding out it did not exist.

That is a load amplifier, and an unusually cheap one to abuse:

  * ``open_session`` runs when Flask *pushes the request context*, which is before
    flask-limiter, before the CSRF hook, before the browser-integrity hook, and
    before every other ``before_request``. A request that is ultimately answered
    429 has therefore already paid for the database round trip — the rate limiter
    cannot protect this path, because the cost is incurred upstream of it.
  * A fresh random sid per request defeats any cache, negative or otherwise.
  * The same forged cookie sent to ``/panel/*`` is paid for twice: once in the
    frontend, and again in ``panel_app.auth.resolve_flask_session``.

Against an Oracle Always Free ATP, whose ~20 concurrent sessions are shared by
the whole fleet, that is the cheapest available way to exhaust the database.

The fix is to make a forgery detectable locally, with no I/O at all: the cookie
carries an HMAC over the session id, and a cookie whose tag does not verify is
treated as no session at all — no backend call, no Oracle read.

Cookie format
-------------
``<sid>.<tag>`` — the 48 hex characters ``_new_sid()`` already mints, a literal
dot, and a base64url tag. The alphabets cannot collide: the sid is hex and the
tag is base64url (``-`` and ``_``, never ``.``), so splitting on the separator is
unambiguous.

Only the bare sid is ever sent onward or stored. The tag lives exclusively in the
cookie, so ``/api/session/{sid}``, the ``sessions.id VARCHAR2(64)`` column and the
cross-tier hex contract documented on ``_new_sid()`` are all untouched by this.

Where the key comes from
------------------------
The caller passes the stack's shared internal token, and the signing key is
derived from it. That token is used rather than a signing secret of its own for a
deployment reason: both instances must already hold the *same* internal token or
no service-to-service call between them authenticates at all (see internal_auth's
module docstring), and the panel already resolves it too. A cookie signed on
instance A therefore verifies on instance B, and in the panel, with no extra
configuration — and, critically, no new environment variable that could be set on
one host and forgotten on the other, which would log every visitor out on every
second request through the balancer.

Deliberately NOT the Flask secret: ``data/flask_key.key`` is generated
per-instance by ``load_or_create_flask_secret``, which is harmless today because
sessions are stored server-side, but would make the two instances disagree about
every tag.

The derivation is domain-separated, so the signing key is not the internal token
itself and cannot be replayed as one if a tag were ever recovered.

This module imports only the standard library — no Flask, no app root — so both
the Flask tiers and the standalone panel can share it exactly the way they share
``cf_edge``, and neither can drift from the other's idea of a valid cookie.

Rollout
-------
``SESSION_COOKIE_MAC_GRACE=1`` also accepts a cookie carrying no tag, which is
every cookie already in a visitor's browser the moment this ships, and the
frontend re-issues it with a tag on the next response — so nobody is signed out
by the deploy. It defaults off, because one PERMANENT_SESSION_LIFETIME after that
deploy every live cookie is tagged and an untagged one is a forgery: honouring it
would leave the unauthenticated backend call and Oracle read above wide open to
anyone who simply omits the tag.

``SESSION_COOKIE_MAC=0`` disables the whole mechanism and restores the previous
behaviour exactly, as an escape hatch.
"""

import base64
import hashlib
import hmac
import os
import sys

# Separator between the session id and its tag. A dot cannot appear in either
# half (hex on the left, base64url on the right), so rsplit on it is exact.
SEPARATOR = "."

# Domain separation for the derived key. Bump the suffix to invalidate every
# outstanding tag at once — every cookie then fails verification and, with the
# grace off, every visitor is asked to sign in again.
_MAC_INFO = b"dch-session-cookie-mac-v1"

# 128 bits of tag, base64url-encoded to 22 characters. A forger gets no feedback
# beyond "signed out", so there is no online guessing channel worth widening the
# tag for, and a shorter cookie is a smaller header on every single request.
_MAC_BYTES = 16

_HEX = frozenset("0123456789abcdefABCDEF")

# Derived keys memoised by their source token. One sha256 per distinct token,
# and there is only ever one token in a process, so this stays a single entry.
_key_cache = {}
_mismatch_warned = False


def _flag(name: str, default: str) -> bool:
    return (os.environ.get(name, default) or "").strip().lower() in (
        "1", "true", "yes", "on")


def enabled() -> bool:
    """Whether cookies are signed and verified at all."""
    return _flag("SESSION_COOKIE_MAC", "1")


def grace_enabled() -> bool:
    """Whether a cookie with no tag is still accepted.

    Off by default: every cookie predating the signing deploy has long since aged
    out of one PERMANENT_SESSION_LIFETIME, so an untagged cookie now means a
    forgery that did not bother with a tag — and accepting it reopens exactly the
    unauthenticated backend call and Oracle read this module exists to refuse.
    Set ``SESSION_COOKIE_MAC_GRACE=1`` for the span of a rollout that has to keep
    honouring untagged cookies while they are re-issued with a tag.
    """
    return _flag("SESSION_COOKIE_MAC_GRACE", "0")


def _mac_key(token: str) -> bytes:
    """The signing key derived from the shared internal token."""
    key = _key_cache.get(token)
    if key is None:
        key = hmac.new(token.encode("utf-8", "surrogatepass"), _MAC_INFO,
                       hashlib.sha256).digest()
        _key_cache[token] = key
    return key


def _tag(sid: str, token: str) -> str:
    digest = hmac.new(_mac_key(token), sid.encode("ascii", "strict"),
                      hashlib.sha256).digest()[:_MAC_BYTES]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def sign(sid: str, token: str) -> str:
    """The cookie value to hand a browser for ``sid``.

    Returns the bare sid when signing is disabled or no token is configured, so
    the cookie this writes is always something this module's verify() accepts
    back given the same configuration.
    """
    if not sid or not token or not enabled():
        return sid
    return f"{sid}{SEPARATOR}{_tag(sid, token)}"


def _warn_mismatch_once(reason: str) -> None:
    """Report a tag that did not verify, once per process.

    Worth a line in the log because the honest explanations are very different:
    a forged or stale cookie is routine and is exactly what this module exists to
    reject cheaply, but the two instances holding *different* internal tokens
    would produce this on every request through the balancer while looking, from
    a visitor's side, like being randomly signed out. Rate-limited to one line so
    a flood of forgeries cannot itself fill the disk.
    """
    global _mismatch_warned
    if _mismatch_warned:
        return
    _mismatch_warned = True
    print(
        f"[session] cookie tag rejected ({reason}). Routine for a forged or "
        "expired cookie. If real visitors are being signed out, the tiers are "
        "deriving different keys - confirm every instance holds the same "
        "INTERNAL_TOKEN.",
        file=sys.stderr, flush=True,
    )


def verify(raw: str, token: str) -> str:
    """The authenticated session id inside a cookie value, or ``""``.

    An empty return means "treat this request as having no session": the caller
    must not fall back to using the raw cookie, because that is precisely the
    unauthenticated read this module exists to prevent.

    Shape is checked before the tag, so a tagged cookie which could never be a
    session id costs nothing to refuse; an untagged one skips both. With signing
    disabled, or no token to verify against, the raw value is returned unchanged
    — today's behaviour.
    """
    return verify_detail(raw, token)[0]


def verify_detail(raw: str, token: str):
    if not raw:
        return "", False
    if not token or not enabled():
        return raw, False
    # Both tiers pass a str from request.cookies, but the split below needs one:
    # bytes read straight from a header would raise TypeError here instead of
    # being refused as no session.
    if not isinstance(raw, str):
        return "", False
    sid, found, tag = raw.rpartition(SEPARATOR)
    if not found:
        # Untagged: either a cookie predating this module, or a forgery that did
        # not bother with a tag. The grace flag decides which assumption applies.
        if not grace_enabled():
            return "", False
        if len(raw) > 64 or any(char not in _HEX for char in raw):
            return "", False
        return raw, True
    if not sid or len(sid) > 64 or any(char not in _HEX for char in sid):
        return "", False
    # Compared as bytes: compare_digest raises TypeError on a str holding any
    # non-ASCII codepoint, and a cookie arrives decoded from header bytes. One
    # high byte in the tag was therefore an unhandled 500 at request-context
    # push, repeated on every request because the browser keeps re-sending the
    # cookie that caused it. surrogatepass so the encode cannot raise instead.
    if not hmac.compare_digest(
            tag.encode("utf-8", "surrogatepass"),
            _tag(sid, token).encode("utf-8", "surrogatepass")):
        _warn_mismatch_once("HMAC did not match")
        return "", False
    return sid, False

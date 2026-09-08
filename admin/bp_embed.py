"""bp_embed.py — embedded user session, same-origin reverse proxy.

The public site's session cookie (name "session", see app/frontend.py COOKIE_NAME)
is first-party only: it is issued with SameSite=Lax, so an iframe pointed at
panel.endevil.live from the console's own origin would never receive it, and a
console->frontend request without it is not logged in at all. Instead of framing
the site directly, this blueprint proxies it under /embed/* on the console's own
origin. The proxied pages, their /api/* XHRs and the session cookie all live on
one origin, so everything the browser sends on a normal visit to the site — the
CSRF token header, the device fingerprint, SameSite cookies — works unchanged.

Session lifecycle:

  1. The console's existing login-as endpoint mints a single-use ticket
     (db.create_session(token, ..., max_age=120)).
  2. GET /embed/impersonate/<token> burns the ticket, creates a fresh session
     row for the same user with _ip and _fp empty (so the site's session-interface
     binding checks in frontend.py never kill it — the console is not the user's
     real browser) and a seeded _csrf_token (the pages render it into the inline
     CSRF_TOKEN constant), stashes the sid in this console's Flask session, and
     302s into the iframe.
  3. Every later /embed/* request forwards to FRONTEND_URL with Cookie:
     session=<sid>, X-Forwarded-For: 127.0.0.1 (loopback is never a datacenter
     address, so the site's IP guard lets it through), and the browser's own
     CSRF/fingerprint headers.

Response rewriting, nothing more: strip X-Frame-Options (the site's DENY would
refuse to render inside the iframe), drop Set-Cookie (the console owns the
cookie jar — the site's session lives server-side and is identified by the sid
we already hold), keep the site's CSP (its 'self' resolves to the console origin,
which is exactly what the proxied page is), and re-point path-prefixed links
(/static/, /api/, /user, /blocked) plus absolute URLs on the frontend host onto
/embed/* so every navigation and XHR stays inside the proxy.

Not configured (FRONTEND_URL unset) the blueprint renders a plain error page and
forwards nothing. The console binds 127.0.0.1, so these routes are reachable
only from the operator's own machine.
"""

import _bootstrap  # noqa: F401

import os
import re
import secrets
import uuid
from urllib.parse import urlsplit

import requests
from flask import (
    Blueprint, redirect, render_template,
    request, session, Response as FlaskResponse,
)

import auth
import database as db

embed_bp = Blueprint("embed", __name__)

# The public frontend, read straight from the environment like admin_app.py does
# (importing admin_app for the constant would be circular).
FRONTEND_BASE = os.environ.get("FRONTEND_URL", "").strip().rstrip("/")
_FRONT_NETLOC = urlsplit(FRONTEND_BASE).netloc.lower()

# Must match app/frontend.py COOKIE_NAME. A different value here would send the
# site a cookie it does not read and the embed would render logged-out.
_SESSION_COOKIE = "session"

_IMP_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")

# Response headers the console must not replay. X-Frame-Options DENY would
# refuse to render the proxied page inside the iframe; Set-Cookie would plant a
# "session" cookie on the console's own origin, where it belongs to nobody;
# the rest are hop-by-hop or length/encoding claims that no longer hold once we
# have touched the body.
_DROP_RESP_HEADERS = {
    "content-length", "content-encoding", "connection", "keep-alive",
    "transfer-encoding", "server", "date", "set-cookie", "x-frame-options",
}

# Request headers forwarded on the browser's behalf. Everything else (Host,
# Cookie, X-Forwarded-*, Referer, Origin) is rebuilt or dropped: the site must
# see its own host, our sid, and the loopback source IP, not the console's.
_FORWARD_REQ_HEADERS = (
    "User-Agent", "Accept", "Accept-Language",
    "X-CSRF-Token", "X-Device-Fingerprint", "X-Requested-With", "Content-Type",
)

# Absolute URLs on the frontend host are re-pointed onto the proxy. Matched by
# netloc (host[:port]), which is what the frontend's own _external() would have
# used for links rendered with the panel host.
_ABS_FRONT_RE = (
    re.compile(r"https?://" + re.escape(_FRONT_NETLOC), re.IGNORECASE)
    if _FRONT_NETLOC else None
)

# Path-prefixed links. The leading slash is guarded so /embed/user stays
# untouched (preceded by '/'), absolute URLs survive (preceded by '.' or '/'),
# and only real references — in quotes, in JS string literals, after '=' — are
# rewritten. The lookahead keeps /user2-style fragments and words like
# "/staticly" out.
_REL_REWRITE_RE = re.compile(
    r"(?<![A-Za-z0-9_/.])(/(?:static|api|user|blocked))"
    r"(?=[/\"'`\s<>();?&#]|$)"
)

# One pool for the whole console process. Not a requests.Session: a Session
# would accumulate the site's Set-Cookie headers and replay one embedded user's
# sid cookie onto another's requests. Bare requests.request() is stateless.
_TIMEOUT = 60


def _error_page(message):
    """Inline error page, self-styled like the site's own minimal ones. Rendered
    inside the iframe, so it must not be a redirect or an API response."""
    esc = (message or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
            f"<title>Embed Unavailable</title>"
            f"<style>body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;"
            f"display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}"
            f".card{{max-width:520px;padding:24px;background:#161b22;border:1px solid #30363d;"
            f"border-radius:10px;line-height:1.5}}h1{{font-size:17px;margin:0 0 8px}}</style>"
            f"</head><body><div class=\"card\"><h1>Embed unavailable</h1>"
            f"<p>{esc}</p></div></body></html>")


def _rewrite_html(html):
    if _ABS_FRONT_RE:
        html = _ABS_FRONT_RE.sub("/embed", html)
    return _REL_REWRITE_RE.sub(r"/embed\1", html)


def _rewrite_location(loc):
    """A redirect target must stay inside the proxy, or the iframe leaves the
    console origin and the whole point (first-party cookies, CSRF) is lost."""
    if not loc:
        return loc
    if _ABS_FRONT_RE:
        new = _ABS_FRONT_RE.sub("/embed", loc, count=1)
        if new != loc:
            return new
    if loc.startswith("/"):
        return _REL_REWRITE_RE.sub(r"/embed\1", loc, count=1)
    return loc


def _short_error(ex):
    return " ".join(str(ex).split())[:200]


def _forward(path):
    """Forward one request to the frontend on behalf of the embedded session."""
    sid = session.get("_embed_sid") or ""
    if not sid:
        return _error_page(
            "No embedded session in this console session. Close this tab and "
            "use Login As User again.")
    if not FRONTEND_BASE:
        return _error_page(
            "FRONTEND_URL is not configured in admin/.env — the embedded view "
            "needs it to reach the public site.")

    headers = {
        "Cookie": f"{_SESSION_COOKIE}={sid}",
        "X-Forwarded-For": "127.0.0.1",
    }
    for name in _FORWARD_REQ_HEADERS:
        val = request.headers.get(name)
        if val:
            headers[name] = val

    url = f"{FRONTEND_BASE}/{path}" if path else f"{FRONTEND_BASE}/"
    try:
        resp = requests.request(
            request.method,
            url,
            headers=headers,
            data=request.get_data() if request.method not in ("GET", "HEAD") else None,
            params=request.args,
            allow_redirects=False,
            timeout=_TIMEOUT,
            proxies={"http": None, "https": None},
        )
    except requests.exceptions.SSLError:
        return _error_page(
            "The frontend refused this machine's TLS handshake. If its "
            "certificate is not signed by a public CA, add it to this "
            "machine's trust store.")
    except requests.RequestException as ex:
        return _error_page(f"Could not reach the frontend ({FRONTEND_BASE}): "
                           f"{_short_error(ex)}")

    keep = {}
    for k, v in resp.headers.items():
        if k.lower() not in _DROP_RESP_HEADERS:
            keep[k] = v
    if 300 <= resp.status_code < 400:
        loc = resp.headers.get("Location")
        if loc:
            keep["Location"] = _rewrite_location(loc)

    content = resp.content
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if content and ("text/html" in ctype or "application/xhtml+xml" in ctype):
        try:
            content = _rewrite_html(content.decode("utf-8", "replace")).encode("utf-8")
        except Exception:
            pass
    return FlaskResponse(content, status=resp.status_code, headers=keep)


@embed_bp.route("/admin/embed")
@auth.require_admin
def admin_embed_page():
    """The wrapper tab: a slim chrome bar over a full-viewport iframe whose
    src points at the ticket-consuming handoff route."""
    token = request.args.get("token", "")
    uid = request.args.get("uid", "")
    if not _IMP_TOKEN_RE.match(token):
        return _error_page("Missing or invalid impersonation ticket. "
                           "Go back and use Login As User again.")
    return render_template("admin_embed.html", token=token, uid=uid)


@embed_bp.route("/embed/impersonate/<token>")
@auth.require_admin
def embed_impersonate(token):
    """Burn the admin-minted ticket and open an embedded session for its user.

    Mirrors the public /impersonate/<token> route's hardening: the id is 256
    bits of secrets.token_urlsafe, the record dies on first use, and the
    _impersonator marker is written only by the admin's login-as endpoint. The
    difference is that the adopted session is created server-side with _ip and
    _fp empty — the site's binding checks compare against the browser that
    actually loads the pages, which here is the console's proxy, not the user's
    — and a seeded _csrf_token the pages will render back as their CSRF_TOKEN."""
    if not _IMP_TOKEN_RE.match(token):
        return _error_page("Invalid impersonation ticket.")
    data = db.get_session(token)
    # Burn the ticket either way — retrying the URL must never work twice.
    db.delete_session(token)
    if not isinstance(data, dict) or not data.get("_impersonator"):
        return _error_page("Impersonation ticket missing, expired or already used.")
    uid = str(data.get("user_id") or "")
    if not uid:
        return _error_page("Impersonation ticket carries no user.")
    new_sid = uuid.uuid4().hex
    db.create_session(new_sid, {
        "user_id": uid,
        "username": data.get("username") or "",
        "_impersonator": data.get("_impersonator"),
        "_ip": "",
        "_fp": "",
        "_csrf_token": secrets.token_urlsafe(32),
    })
    session["_embed_sid"] = new_sid
    return redirect("/embed/user")


@embed_bp.route("/embed/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@auth.require_admin
def embed_forward(path):
    return _forward(path)

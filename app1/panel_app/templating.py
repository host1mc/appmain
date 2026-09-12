"""Jinja templating with a Flask-compatibility shim.

The 9 templates were copied verbatim from the Flask panel, so they still call
``url_for('endpoint')``, ``csrf_token()``, ``get_flashed_messages()`` and read
``current_user`` / ``request.endpoint``.

Rather than rewrite the templates, we recreate that tiny surface here:

* ``url_for`` is a stateless endpoint→path map (a Jinja global).
* everything request-scoped (csrf token, flashes, current user, the endpoint
  used for nav highlighting) is injected per-render by :func:`render`, exactly
  like Flask's context processor.

All paths are emitted under the ``/panel`` mount prefix so links keep working
wherever the host app is served.
"""

import hashlib
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from starlette.requests import Request
from starlette.responses import HTMLResponse
from urllib.parse import quote

from . import auth, flashes, id_mask
from .config import MOUNT_PREFIX


_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
# Fully resolved, because static_version compares a resolved candidate path
# against it: an unresolved root would fail that comparison for every asset the
# moment this tree is reached through a symlink or a mapped drive.
_STATIC_DIR = (Path(__file__).resolve().parent / "static").resolve()

# filename -> ((size, mtime_ns), version token). The signature is what makes the
# cache safe to keep for the life of the process: an unchanged file costs one
# stat per url_for call, and a file edited in place is re-hashed on the next
# render rather than waiting for a restart.
_STATIC_VERSIONS = {}


def static_version(filename: str) -> str:
    """A short content hash for a static file, or ``""`` if it cannot be read.

    Static responses were cacheable for an hour at URLs with no version in them,
    so a browser holding the previous app.css kept using it for up to an hour
    after a deploy — long enough to be looking at a page whose stylesheet and
    markup disagree, with no way to tell that is what happened. A changed file is
    now a different URL and is fetched at once, while an unchanged one still comes
    from cache. Because the token pins the bytes, ``security_headers`` serves a
    tokened URL ``immutable`` for a year instead.

    Hashed by content rather than stamped with mtime because the fleet runs two
    instances: a deploy that copies identical bytes to both gives them different
    mtimes, so a visitor the balancer moves between them would re-download every
    asset on each hop.
    """
    name = str(filename or "").strip()
    if not name:
        return ""
    cached = _STATIC_VERSIONS.get(name)
    try:
        path = (_STATIC_DIR / name).resolve()
        # ``url_for`` quotes with safe="/", so a ".." in the filename survives
        # into this path. Only our own templates call this, so it is not an
        # untrusted input today — but a URL builder that reads whatever path it
        # is handed is not a thing to leave lying around. relative_to raises
        # ValueError, which the handler below already turns into "no version".
        path.relative_to(_STATIC_DIR)
        stat = path.stat()
        signature = (stat.st_size, stat.st_mtime_ns)
        if cached is not None and cached[0] == signature:
            return cached[1]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    except (OSError, ValueError):
        # Missing, unreadable, or outside the static root. Fall back to the last
        # known token if we have one, else emit the plain URL: an asset that 404s
        # is already a visible failure, and raising here would turn it into a 500
        # for the whole page.
        return cached[1] if cached else ""
    _STATIC_VERSIONS[name] = (signature, digest)
    return digest


# endpoint name -> path template (relative to the mount prefix). ``static`` is
# handled separately because it takes a ``filename`` keyword.
_ENDPOINTS = {
    "index": "/",
    "logout": "/logout",
    # Retired page: the route survives only to redirect to /dashboard, so nothing
    # should link here. Kept in the map so a stray url_for("home") resolves to the
    # real forwarding path rather than to the "#" an unknown endpoint returns.
    "home": "/home",
    "dashboard": "/dashboard",
    "new_server": "/servers/new",
    "create_server": "/servers",
    "batch_power": "/servers/batch-power",
    "server_page": "/servers/{server_id}",
    "delete_server": "/servers/{server_id}/delete",
    "api_status_map": "/api/servers/status",
    "account_page": "/account",
    "account_change_password": "/account/password",
    "api_power": "/api/servers/{server_id}/power",
}


def url_for(endpoint: str, **values) -> str:
    """Flask-style URL builder, scoped to the panel mount prefix."""
    if endpoint == "static":
        filename = values.get("filename", "")
        url = f"{MOUNT_PREFIX}/static/{quote(str(filename), safe='/')}"
        version = static_version(filename)
        # StaticFiles routes on the path and ignores the query, so this reaches
        # the same file while giving every cache a distinct key per revision.
        return f"{url}?v={version}" if version else url
    template = _ENDPOINTS.get(endpoint)
    if template is None:
        # Unknown endpoint: return a harmless anchor rather than raising inside
        # a template render (which would surface as an opaque 500).
        return "#"
    try:
        # safe="" keeps every value inside its own path segment: an id may not
        # smuggle a "/", nor start a "?" query or a "#" fragment, whether the
        # result lands in an href or in a redirect's Location header.
        public_values = {
            key: id_mask.mask_server_id(value) if key == "server_id" else value
            for key, value in values.items()
        }
        path = template.format(**{key: quote(str(value), safe="") for key, value in public_values.items()})
    except KeyError:
        return "#"
    return f"{MOUNT_PREFIX}{path}"


def _make_site_url(base: str):
    """Build a link to a page on the Flask site rather than on the panel.

    /help is served by the site, not by this app, and the
    panel also answers directly on its own loopback port — where a bare "/help"
    resolves against that port and finds nothing, because the panel mounts only
    /panel. Prefixing ``main_site_url`` sends it to the site's own origin, and an
    empty ``main_site_url`` leaves the path relative, which is what production
    wants: there the LB serves both from one host.
    """
    base = (base or "").rstrip("/")

    def site_url(path: str) -> str:
        path = str(path or "")
        # A protocol-relative "//host" would leave the site entirely, and
        # anything not rooted at "/" would resolve against the current page
        # instead of the site root. Neither is a link this builder may emit.
        if not path.startswith("/") or path.startswith("//"):
            return "#"
        return f"{base}{path}"

    return site_url


_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    # default=True so a template that is not .html/.xml is escaped as well:
    # select_autoescape leaves anything unmatched unescaped otherwise, which
    # would silently ship an unescaped page the day a .txt or .j2 is added.
    autoescape=select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    ),
)
_env.globals["url_for"] = url_for
_env.globals["public_server_id"] = id_mask.mask_server_id
_env.globals["public_server_key"] = id_mask.public_server_key
_env.globals["public_server_label"] = id_mask.public_server_label
# Constant mount prefix, exposed so base templates can publish it to JS via a
# <meta name="panel-base"> tag. Fetch helpers read it to build absolute API URLs.
_env.globals["panel_base"] = MOUNT_PREFIX


# Short badge letters for the runtime-icon chip, keyed by the node agent's
# runtime id. A map rather than a per-template ternary because the catalog now
# carries six runtimes: an "is it nodejs? else python" branch mislabelled every
# type past the first two as "PY". Anything unknown falls back to "?" so a
# runtime added on the node before this map does not render a wrong language.
_RUNTIME_BADGES = {
    "nodejs": "JS",
    "python": "PY",
    "ruby": "RB",
    "go": "GO",
    "php": "PHP",
    "bun": "BUN",
}


def runtime_badge(runtime_id) -> str:
    return _RUNTIME_BADGES.get(str(runtime_id or "").strip().lower(), "?")


_env.globals["runtime_badge"] = runtime_badge


class _EndpointRef:
    """Minimal stand-in for Flask's ``request`` in templates.

    Templates only ever read ``request.endpoint`` (for nav highlighting), so
    that is all we expose.
    """

    __slots__ = ("endpoint",)

    def __init__(self, endpoint: str):
        self.endpoint = endpoint


def csrf_token(request: Request) -> str:
    return auth.flask_csrf_token(request)


def flash(request: Request, message: str, category: str = "message") -> None:
    """Queue a one-shot flash message for this response (Flask-compatible shape)."""
    flashes.queue(request, category, message)


# Which ad-block guard panel pages arm, as static/g7.js reads it from
# <body data-guard>. "gate" redirects a blocked visitor away, "warn" is retired —
# showBanner() has no call sites left, so it redirects the same way — "off"
# computes the fingerprint and runs no ad-block UI or third-party probes at all.
# "blocked" is the blocked-page mode and is not a configuration value, so it is
# not accepted here.
#
# Same three members as database.AD_GUARD_MODES, restated rather than imported:
# the sync `database` module is not importable on the SQLite path (see
# panel_settings), and the one value still checked against this set —
# PANEL_GUARD_MODE, in _configured_guard_mode below — is resolved on exactly that
# path, by a panel_settings fallback that runs *because* nothing from `database`
# could be read. So it has to hold without it.
_GUARD_MODES = frozenset({"gate", "warn", "off"})

# The mode _configured_guard_mode falls back to when PANEL_GUARD_MODE is unset or
# names something this file does not implement. Kept out of PanelConfig so it stays
# a presentation concern of the template layer.
#
# The environment variable in front of it selects nothing any more, and neither
# does this constant. guard_mode() below answers "gate" for every visitor it
# does not downgrade, so there is nothing left here for an operator — in the console
# or in a unit file — to pick. What this constant still feeds is the one caller of
# _configured_guard_mode: panel_settings._env_guard_mode(), filling the guard_mode
# field of the snapshot it serves while the settings table is unreadable. Nothing
# reads that field to choose a mode any more, so nothing a visitor sees turns on
# this value today. It is "gate" because that is the armed state guard_mode()
# serves every visitor it does not downgrade: "warn" named the dismissible banner,
# and showBanner() in both g7.js copies now has no call sites, so a default
# naming it would be one no tier could honour the day something read this again —
# and on the panel the two are the same behaviour in any case, because no template
# emits #script-gate and there is no overlay for "gate" to hold. The live answer
# still has exactly one home, and it is the return statement in guard_mode().
_GUARD_MODE_DEFAULT = "gate"

_CRAWLER_UA_TOKENS = (
    "googlebot",
    "mediapartners-google",
    "adsbot-google",
    "google-inspectiontool",
)


def _configured_guard_mode(env=None) -> str:
    """``PANEL_GUARD_MODE`` when it names a mode this file implements, else the default.

    Nothing in this module calls this any more. guard_mode() no longer chooses
    between modes, so there is no fallback left for it to be, and the module-level
    ``_GUARD_MODE`` that used to hold its result at import time is gone with the
    tier that read it — PANEL_GUARD_MODE is therefore no longer read during import
    of this module at all.

    It survives because panel_settings._env_guard_mode() imports it by name, to fill
    the guard_mode field of the snapshot the panel serves while the settings table is
    unreadable. That import sits inside a bare ``except Exception`` which answers
    ``None``, so deleting this function would not raise anywhere a reader would ever
    see it: it would quietly turn that field into ``None`` on the one path that
    exists for a database outage, and leave a documented helper in the panel's data
    layer pointing at a name that no longer exists.
    """
    env = os.environ if env is None else env
    mode = (env.get("PANEL_GUARD_MODE", "") or "").strip().lower()
    return mode if mode in _GUARD_MODES else _GUARD_MODE_DEFAULT


def guard_mode(request: Request, settings=None) -> str:
    """The guard mode for this request, mirroring frontend.py's context processor.

    "gate" for a panel visitor, with two downgrades in front of it:

    1. **Crawlers are always downgraded to "off"**, whatever else is true. Same
       reason the Flask side does it: a crawler never fetches third-party ad
       scripts, so every bait comes back refused and it would be handed the
       ad-block treatment instead of the page. That is also why the site-wide
       decision below is not allowed to reach them — "gate" for Googlebot means the
       ad-block wall is what gets crawled and indexed in place of the panel, and
       the one page a review has to look at answers with a wall.
    2. **Ads off site-wide is also "off"**, when the snapshot says so explicitly.
       The Flask tier folds its master switch into the mode the same way, and
       gives the reason: with advertising switched off, a visitor with a blocker
       was still bounced to /blocked over ads that were never in the page. That
       used to be nearly harmless here, because the redirect had nowhere to land;
       routes.py's ``blocked_page`` now serves "/blocked" under the mount prefix,
       so "gate" is a real destination and this is a real bounce. Standing the
       guard down costs nothing an operator wanted: g7.js still computes the
       device fingerprint the API calls carry in every mode, and ``injectAds``
       still runs over the placeholders (of which the panel has none).

    Everything else is "gate", and that is not a setting any more. The
    ``ad_guard_mode`` row the admin console writes and ``PANEL_GUARD_MODE`` in the
    environment are both still stored, and neither is read here: a visitor running
    an ad blocker is sent to the /blocked page and cannot use the panel until it
    comes off, on both instances, whether or not the settings table can be reached
    at all. frontend.py's ``_inject_guard_mode`` makes the same unconditional
    decision for the Flask site, and the two staying in step is easier now that
    neither has a tier left that could disagree with the other.

    Nothing on a panel page is hidden waiting for the ad-block check, and that has
    not changed. g7.js's panel copy documents it at its "Reveal / redirect"
    block: the Flask site hides a guarded page behind a #script-gate overlay its
    templates paint, and no panel template emits that element nor any panel
    stylesheet a rule for it, so "gate" holds back nothing a visitor would
    otherwise see while the check is still running — a blocked visitor is
    redirected, and everyone else reads the page exactly as before. The redirect
    lands on routes.py's ``blocked_page`` at "/blocked" under the mount prefix,
    with blocked.html's ``data-guard="blocked"`` polling and forwarding back once
    the blocker comes off, rather than on the 404 it once did.

    Tier 2 tests ``is False`` rather than falsiness, and that is the whole of its
    correctness. ``None`` means the master switch was never read — an unreachable
    database, or the one read that failed while the rest of the snapshot stood —
    and a database the panel cannot reach must not silently disable ad-block
    detection site-wide. Failing open there costs a visitor with a blocker a trip
    to /blocked over ads that may not be running; failing closed would drop the
    guard for every visitor on the strength of a query error, which is the failure
    nobody would notice until the ad revenue moved. The open cost is larger than it
    was when this tier could fall through to a banner, and it is still the cheaper
    of the two: a trip to /blocked is visible to whoever it happens to and reverses
    the moment the row reads again, while a guard silently switched off by an
    outage looks exactly like a guard working.

    The Flask tier reaches that same end state by a different route, which is why
    this is an identity test and its equivalent there is not. Its cache seeds
    ``enabled`` to ``True`` and only ever replaces it with a real bool, so it has
    no "unknown" to represent and its ``not state["enabled"]`` is safe on
    falsiness. Here the unknown is a distinct third value, so falsiness would fold
    it in with an explicit "off" and invert the behaviour above. Anything that
    later flattens :attr:`~.panel_settings.PanelSettings.ads_enabled` to a bool
    breaks this tier silently — it would keep working for every case except the
    outage it exists for.

    Every mode this returns is now a literal written in this file, which is what
    keeps ``None`` out of ``data-guard``. The membership test against
    :data:`_GUARD_MODES` that used to do that job went with the tier that returned
    a snapshot value: a ``guard_mode`` row that fails to read is left as ``None``
    by panel_settings, and handing that straight back would reach a template as
    ``data-guard="None"`` — not one of the four literals g7.js knows, so the
    guard would neither gate nor warn nor stand down, on the render where the
    database was already in trouble. The property is structural rather than checked
    now, so it holds only while that stays true: a future tier that returns
    anything read from the snapshot has to validate it against :data:`_GUARD_MODES`
    again, because callers put this result into ``<body data-guard>`` unaltered.

    ``settings`` defaults to ``None`` so a caller that renders without a snapshot
    gets a usable mode rather than a TypeError. With no snapshot the master-switch
    read answers ``None``, which is not ``False``, so that render arms the guard.
    """
    ua = (request.headers.get("user-agent") or "").lower()
    if any(token in ua for token in _CRAWLER_UA_TOKENS):
        return "off"
    if getattr(settings, "ads_enabled", None) is False:
        return "off"
    return "gate"


def house_ads_enabled(settings=None) -> bool:
    """Whether this page may carry its first-party "house ad" promo slots.

    These are our own markup on our own origin — an ``<aside>`` and an ``<a>``, no
    third-party script, no popunder — which is the only advertising a panel page
    can host at all: ``security_headers``' CSP is ``script-src 'self'; style-src
    'self'`` with no ``unsafe-eval`` and no nonce, so a real ad network has nowhere
    to execute.

    Two switches, in this order:

    1. **The site-wide master switch, when it says so explicitly.** ``ads_enabled``
       is the one control the admin console owns for advertising fleet-wide, and it
       has to keep meaning that: an operator who turns ads off expects *all* of it
       gone, first-party promos included, without hunting for a second toggle.
    2. Otherwise the dedicated ``panel_flag_house_ads`` row, which is what lets the
       panel's promos be turned off on their own while site-wide advertising stays
       on. Default ``False`` here, so a snapshot from before that row existed shows
       nothing rather than a slot nobody asked for.

    Tier 1 tests ``is False`` rather than falsiness for the same reason
    :func:`guard_mode`'s tier 2 does, and it is worth saying that the stakes are
    not the same. ``ads_enabled`` is tri-state: ``True``/``False`` are an
    operator's answer and ``None`` means nobody could tell us — an unreachable
    database, or that one read failing while the rest of the snapshot stood. There,
    folding ``None`` in with an explicit off would disable ad-block detection over
    a query error; here it would merely hide a promo. But it would still hide it on
    the strength of a failed read, and the two functions have to agree about what
    ``None`` means, or a later reader has to work out which of them is the lie.

    Unlike :func:`guard_mode` this does *not* downgrade for crawlers and does not
    consult the guard state at all. There is nothing here for a blocker to refuse
    and nothing a crawler would fail to fetch, so the crawler downgrade would only
    strip our own markup out of the indexed page. And the guard was never the lever
    for this in any case: no ``data-guard`` value means "ads off" — ``off`` means
    "run no ad-block UI", and g7.js still runs ``injectAds()`` in it.

    ``getattr`` with defaults rather than attribute access because ``settings`` may
    be ``None`` on some render paths — base.html already defends that way at its
    ``settings.memory_mb`` and ``settings.maintenance`` reads — so a caller that
    renders without a snapshot gets ``False``, not a TypeError.
    """
    if getattr(settings, "ads_enabled", None) is False:
        return False
    return bool(getattr(settings, "house_ads", False))


def house_ads_visible(settings=None, session=None) -> bool:
    """Whether this render actually shows the house-ad promos for this visitor.

    Folds the per-user opt-out onto :func:`house_ads_enabled`'s site-wide answer:
    a signed-in visitor who turned ads off in their account never sees the promos,
    even while the site-wide master switch and ``panel_flag_house_ads`` are both on.
    Signed out, or no flag, falls through to the site-wide answer unchanged.

    The flag is ``users.ads_disabled`` — the same column the main site's ad stack
    honours — surfaced onto the main-site session by ``/api/session`` and read here
    off the session dict the panel already fetches once per request. So this stays a
    pure ``(snapshot, dict) -> bool`` read with no store call of its own, and the
    panel and the public pages can never disagree about one account's choice.
    """
    if not house_ads_enabled(settings):
        return False
    return not bool((session or {}).get("ads_disabled"))


def sidebar_collapsed(request: Request) -> bool:
    """Whether this render starts with the sidebar minimised to the icon rail.

    base.html puts the ``sidebar-collapsed`` class on ``<body>`` from this, so the
    server paints the rail the visitor last chose instead of painting the full
    sidebar and having q1.js snap it shut once the deferred bundle runs.

    Resolved here rather than read in the template because ``request`` in a
    template context is :class:`_EndpointRef`, whose ``__slots__`` expose
    ``endpoint`` and nothing else — there are no cookies on it to read, so
    ``request.cookies`` in a template would raise inside the render.

    Only the exact string ``"1"`` collapses; absent, empty or anything else is
    expanded. The value is attacker-controlled — anyone can set their own cookie —
    and never reaches the page: it is compared against that literal here and the
    template emits a fixed class name either way, so there is nothing to inject
    through.
    """
    return request.cookies.get("sb_collapsed") == "1"


def _make_get_flashed_messages(request: Request):
    def get_flashed_messages(with_categories: bool = False, category_filter=()):
        queued = flashes.drain(request)
        if category_filter:
            queued = [f for f in queued if f[0] in category_filter]
        if with_categories:
            return [(category, message) for category, message in queued]
        return [message for _category, message in queued]

    return get_flashed_messages


def _is_mobile_user_agent(request: Request) -> bool:
    """Check the browser user-agent in a template-safe way.

    The panel template context uses a lightweight ``request`` shim which exposes
    only ``endpoint`` and not the full Starlette request object. That is why a
    template cannot read ``request.user_agent`` here. We compute it once in the
    render layer and expose a plain boolean instead.
    """
    ua = (request.headers.get("user-agent") or "").lower()
    if not ua:
        return False
    mobile_tokens = (
        "android",
        "iphone",
        "ipad",
        "ipod",
        "mobile",
        "iemobile",
        "opera mini",
    )
    return any(token in ua for token in mobile_tokens)


def render(
    request: Request,
    template_name: str,
    *,
    endpoint: str = "",
    context=None,
    status_code: int = 200,
    config=None,
    current_user=None,
    settings=None,
) -> HTMLResponse:
    """Render a template with the Flask-compat context injected.

    ``current_user`` is the SQLite user dict (or ``None``), usually pulled from
    the request by the caller.

    ``settings`` is the resolved :class:`~.panel_settings.PanelSettings` snapshot.
    It is injected here rather than added to every route's own context dict
    because ``base.html`` reads it — the maintenance banner and the allocation
    figure in the topbar are on every page — so a route that forgot to pass it
    would render a page with no banner while maintenance was on. ``house_ads`` is
    resolved here for the same reason: base.html carries a promo slot on every
    page, so a route that resolved it for itself would drop the slot the moment one
    forgot to.
    """
    ctx = dict(context or {})
    ctx.setdefault("request", _EndpointRef(endpoint))
    ctx["csrf_token"] = lambda: csrf_token(request)
    ctx["get_flashed_messages"] = _make_get_flashed_messages(request)
    if isinstance(current_user, dict) and "password_hash" in current_user:
        # No template reads it, and a stored credential has no business sitting in
        # a render context where any future {{ current_user }} — or a debug
        # traceback rendering template locals — would print it. Copied rather than
        # popped in place: the caller's dict is the row the route still uses to
        # verify the current password on the change-password path.
        current_user = {k: v for k, v in current_user.items() if k != "password_hash"}
    import turnstile
    ctx.setdefault("turnstile_site_key", turnstile.site_key() if turnstile.enabled() else "")
    ctx["current_user"] = current_user
    ctx["guard_mode"] = guard_mode(request, settings)
    ctx["settings"] = settings
    ctx["house_ads"] = house_ads_visible(settings, auth.flask_session(request))
    ctx["sidebar_collapsed"] = sidebar_collapsed(request)
    ctx["is_mobile"] = _is_mobile_user_agent(request)
    ctx["site_url"] = _make_site_url(getattr(config, "main_site_url", ""))
    template = _env.get_template(template_name)
    html = template.render(**ctx)
    return HTMLResponse(html, status_code=status_code)

"""check_panel_house_ads.py — verify the panel's first-party "house ad" promo slots.

Companion to check_ad_settings.py (which asserts the Flask tier's ad settings
round-trip) and check_ad_gates.py (which prints that tier's gate matrix). This one
covers the *panel's* own advertising, which is a different thing entirely: /panel
serves ``script-src 'self'; style-src 'self'`` with no nonce and no unsafe-eval, so
no third-party ad network can execute there at all. The only advertising a panel
page can carry is our own markup on our own origin, and that is what these promo
slots are.

Six things it proves:

  1. ``house_ads`` is registered in PANEL_FLAGS on *both* sides — app/database.py
     and admin/database.py — with all three of label/default/detail, and the two
     copies agree on the default. The admin console's ``_snapshot()`` in
     admin/bp_panel.py reads ``meta["detail"]`` unguarded, so a missing key there
     is a 500 on the Panel Controls page rather than a cosmetic gap.
  2. ``templating.house_ads_enabled``'s full truth table, including the identity
     test that is the whole of its correctness (see group 2's comments).
  3. ``PanelSettings.house_ads`` reads the flag, and ``panel_settings._fallback``
     leaves the promos ON while refusing to fabricate a master-switch answer.
  4. The four templates that carry promo markup actually emit their slots, and
     emit *nothing* when the console has switched them off. That is the
     console-killable proof.
  4b. One promo per region, not per page. base.html's strip sits at the end of
     ``<main>`` and dashboard.html's card at the end of its content block, and the
     two share the same panel/line/inset treatment — so on the dashboard they
     rendered back-to-back and read as one box printed twice. base.html's
     ``request.endpoint != 'dashboard'`` guard is what stops that, and the
     strip+card sum being exactly 1 on every page is what proves the guard is still
     there. The other three slots occupy regions of their own — the sidebar column,
     the stat-cards grid, a layout rail — so each may sit alongside the closer; what
     is forbidden is two of the *same* treatment on one page, which is the shape a
     duplicate actually takes, and each page's exact slot set is pinned so a slot
     cannot go missing either.
  5. The security invariants: no ad-network hooks, no ad-blocker cosmetic-bait
     class names, no inline style/script, no off-origin URL, and zero new
     ``<script>`` tags.
  6. The panel CSP was not relaxed to make any of this work — which is the point
     of the whole exercise: advertising was added to the panel *without* loosening
     its security posture. And the converse, which the CSP half does not cover:
     that g7.js's ``NET_BAITS`` has not grown a host the panel's connect-src
     would refuse. A bait our own CSP cancels is indistinguishable from a
     blocker's refusal, so one such host flags every panel visitor as blocking.

Exit code 0 = every group passed, 1 = at least one assertion failed.

SAFE TO RUN ON THE PRODUCTION HOST. This script is static. It never connects to a
database, never starts a server, never runs the test suite, and never touches a
row. Three things make that a property of the code rather than a promise:

  * ``app/database.py`` and ``admin/database.py`` are **parsed with ast**, never
     imported. Importing ``database`` resolves an Oracle connection at import time
     and would open a pool against the live ATP; ``ast.literal_eval`` over the
     PANEL_FLAGS dict literal reads exactly the same information with no driver.
  * ``sys.modules`` is **poisoned** with a stub ``database`` (and ``oracledb``,
     and ``cx_Oracle``) before anything else is imported. Any attribute access on
     them raises AssertionError with a pointer back here, so if a future edit puts
     a real ``import database`` on a module path this script walks, this file fails
     loudly instead of dialling out. ``panel_settings.SettingsReader._read_sync``
     does its ``import database`` *inside the function* on purpose, so importing
     that module is safe — and nothing here calls ``_read_sync()`` or ``load()``.
  * ``panel_app.templating`` is imported for its pure functions, but the templates
     are rendered through a **local** ``jinja2.Environment``, not through
     ``templating.render()`` — that one needs a live Starlette Request.

Import-safety of the panel_app chain was established by reading it: config.py
reads env vars and (only from ``from_env()``, never at import) materialises a
local key file; auth.py's module scope is constants plus an env read plus a
urllib opener object that makes no request; flashes.py is constants; the package
``__init__`` pulls in routes/runtime/node_client/store/panel_database, none of
which connect at module scope. The poison stubs above are the belt on top of that
reading.

Run: python check_panel_house_ads.py
"""

import ast
import os
import re
import sys
import types
from pathlib import Path

HERE = Path(os.path.abspath(__file__)).parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

APP_DATABASE = HERE / "database.py"
ADMIN_DATABASE = HERE / "admin" / "database.py"
PANEL_DIR = HERE / "panel_app"
TEMPLATES_DIR = PANEL_DIR / "templates"
APP_CSS = PANEL_DIR / "static" / "app.css"
SECURITY_HEADERS = PANEL_DIR / "security_headers.py"

# Both copies of the ad-block guard. The panel's is the one whose probes run under
# the panel CSP; the main app's is the source the panel's is mirrored from, and the
# two are meant to carry an identical NET_BAITS list.
PANEL_FP_GUARD = PANEL_DIR / "static" / "g7.js"
APP_FP_GUARD = HERE / "static" / "g7.js"

# Every template that contains promo markup of its own. base.html carries the
# closing strip on every page plus the sidebar rail; dashboard.html carries the
# stat-cards filler and its own closing card; new_server.html and server.html each
# carry one tile in a rail their own layout leaves empty; account.html carries
# one mid-page tile between its summary and its password section.
PROMO_TEMPLATES = ("base.html", "dashboard.html", "new_server.html",
                   "server.html", "account.html")

# The ``endpoint`` values routes.py actually passes to templating.render(), which
# is what reaches a template as ``request.endpoint``. Four pages extend base.html
# (account, dashboard, new_server, server) and blocked.html does
# not, so these four are the whole surface the promo bar can appear on.
#
# Spelled exactly as routes.py spells them. The nav highlighting in base.html
# compares against these literals ("server_page", not "server"), so a fixture
# that invented a shorter name would render a nav with no active item and would
# not be standing in for a real page at all.
DASHBOARD_ENDPOINT = "dashboard"
NON_DASHBOARD_ENDPOINTS = (
    "new_server",     # new_server.html
    "server_page",    # server.html
    "account_page",   # account.html
)

# The endpoint each template is rendered under for the main body of group 4 and
# for group 5's sweeps. base.html is also rendered standalone under every endpoint
# below (see BASE_BY_ENDPOINT); account.html renders as itself under its own
# endpoint, and dashboard.html can only ever
# serve "dashboard", which is also the one endpoint that suppresses the inherited
# closing strip.
PRIMARY_ENDPOINT = {
    "base.html": "account_page",
    "account.html": "account_page",
    "dashboard.html": DASHBOARD_ENDPOINT,
    "new_server.html": "new_server",
    "server.html": "server_page",
}


# ── the Oracle poison ────────────────────────────────────────────────────────
# Planted before any panel import so a module-scope `import database` added by a
# future edit cannot reach the live ATP through this script. The module import
# itself succeeds (so a bare `import database` does not crash a file that only
# needs it lazily); touching any attribute is what fails.


class _PoisonModule(types.ModuleType):
    def __getattr__(self, name):
        raise AssertionError(
            f"check_panel_house_ads.py is static and must never reach Oracle, but "
            f"something read {self.__name__}.{name}. Either an import moved to "
            f"module scope, or this script called something it must not."
        )


for _poisoned in ("database", "oracledb", "cx_Oracle"):
    sys.modules[_poisoned] = _PoisonModule(_poisoned)


import jinja2  # noqa: E402


# ── result harness (same shape as check_ad_settings.py) ──────────────────────

_GROUPS = []
_NOTES = []


class Group:
    def __init__(self, name):
        self.name = name
        self.failures = []
        _GROUPS.append(self)

    def ok(self, cond, label):
        if not cond:
            self.failures.append(label)

    def eq(self, got, want, label):
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def no_raise(self, fn, label):
        try:
            return fn()
        except Exception as e:
            self.failures.append(f"{label}: raised {type(e).__name__}({e})")
            return None

    def report(self):
        status = "PASS" if not self.failures else "FAIL"
        print(f"[{status}] {self.name}")
        for f in self.failures:
            print(f"         - {f}")
        return not self.failures


def note(text):
    _NOTES.append(text)
    print(f"         (note: {text})")


# ── the pure imports ─────────────────────────────────────────────────────────
# panel_settings for PanelSettings/_fallback, templating for house_ads_enabled.
# Both are safe per the module docstring; if either ever stops being safe the
# import fails here and groups 2 and 3 degrade to a stated skip rather than this
# script becoming the thing that connected to production.

_IMPORT_ERROR = None
try:
    from panel_app import panel_settings as ps
    from panel_app import templating as tpl
except Exception as exc:  # pragma: no cover - the whole point is that it does not
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    ps = tpl = None

print()
print("=" * 72)
print("check_panel_house_ads.py — static verification, no Oracle, no server")
print("=" * 72)
if _IMPORT_ERROR is None:
    print("panel_app.panel_settings / panel_app.templating: imported (pure)")
else:
    print(f"panel_app import UNAVAILABLE ({_IMPORT_ERROR})")
    print("groups 2 and 3 will report as skipped; 1, 4, 5, 6 are AST/text-only")
print()


# ── group 1: the flag is registered on both sides ────────────────────────────
# Parsed, never imported: `import database` resolves an Oracle connection at
# import time and this host's Oracle is the live shared ATP.

g1 = Group("1. PANEL_FLAGS['house_ads'] is registered on both sides")


def _panel_flags_from_source(path):
    """PANEL_FLAGS as a plain dict, read out of the file with ast.

    Adjacent string literals in the ``detail`` values are folded by the parser
    into one Constant (comments between them are skipped by the tokenizer), so
    ``literal_eval`` handles the block verbatim.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "PANEL_FLAGS":
                return ast.literal_eval(node.value)
    raise AssertionError(f"no module-level PANEL_FLAGS assignment in {path}")


_flags = {}
for label, path in (("app", APP_DATABASE), ("admin", ADMIN_DATABASE)):
    got = g1.no_raise(lambda p=path: _panel_flags_from_source(p),
                      f"parse PANEL_FLAGS out of {label}/database.py")
    _flags[label] = got or {}

for label in ("app", "admin"):
    flags = _flags[label]
    g1.ok("house_ads" in flags, f"{label}/database.py PANEL_FLAGS has 'house_ads'")
    meta = flags.get("house_ads") or {}
    g1.ok(isinstance(meta, dict), f"{label}: house_ads value is a dict")
    # All three keys, not just the ones the panel reads. admin/bp_panel.py's
    # _snapshot() does meta["label"], meta["detail"] and meta["default"] with no
    # .get() and no default, so a flag missing any of them is a 500 on the Panel
    # Controls page — the very page an operator would open to switch this off.
    for key in ("label", "default", "detail"):
        g1.ok(key in meta, f"{label}: house_ads declares {key!r} "
                           f"(admin _snapshot reads meta[{key!r}] unguarded)")
    g1.ok(isinstance(meta.get("label"), str) and meta.get("label"),
          f"{label}: house_ads label is a non-empty string")
    g1.ok(isinstance(meta.get("detail"), str) and meta.get("detail"),
          f"{label}: house_ads detail is a non-empty string")
    g1.ok(isinstance(meta.get("default"), bool),
          f"{label}: house_ads default is a real bool")

# The two files are kept in step by a sync script, so a drift here means the sync
# did not run — and then the console would show one default while the panel
# enforced another.
g1.eq((_flags["app"].get("house_ads") or {}).get("default"),
      (_flags["admin"].get("house_ads") or {}).get("default"),
      "app and admin agree on the house_ads default")
g1.eq(sorted(_flags["app"]), sorted(_flags["admin"]),
      "app and admin declare the same PANEL_FLAGS key set")
g1.eq((_flags["app"].get("house_ads") or {}).get("default"), True,
      "house_ads defaults ON (matches panel_settings._fallback)")

# The settings row this resolves to. _panel_key formats "panel_{kind}_{name}", so
# the flag lands in `panel_flag_house_ads` — stated here because the console PUT
# and the panel read have to be talking about the same row.
_app_src = APP_DATABASE.read_text(encoding="utf-8")
g1.ok('return f"panel_{kind}_{name}"' in _app_src,
      "_panel_key still builds panel_<kind>_<name>, i.e. panel_flag_house_ads")


# ── group 2: the house_ads_enabled truth table ───────────────────────────────

g2 = Group("2. templating.house_ads_enabled truth table")


class FakeSettings:
    """Just the two attributes house_ads_enabled reads."""

    def __init__(self, ads_enabled, house_ads):
        self.ads_enabled = ads_enabled
        self.house_ads = house_ads


class NoHouseAds:
    """A snapshot from before the flag existed: ads_enabled only."""

    def __init__(self, ads_enabled=True):
        self.ads_enabled = ads_enabled


if tpl is None:
    g2.failures.append(f"skipped: panel_app.templating unavailable ({_IMPORT_ERROR})")
else:
    hae = tpl.house_ads_enabled

    TRUTH_TABLE = [
        # (ads_enabled, house_ads, expected, why)
        (True, True, True, "both on"),
        (True, False, False, "panel switch off, ads on"),
        # None is "the database could not tell us". A promo that shows during an
        # outage costs nothing; hiding the operator's own inventory because a
        # query errored is the wrong direction, so None must NOT kill it.
        (None, True, True, "master switch unreadable -> promos still show"),
        (None, False, False, "master switch unreadable, panel switch off"),
        # THE KEY ASSERTION. ads_enabled=False is an operator's explicit
        # site-wide "no advertising", and it has to keep meaning that: someone
        # who turns ads off expects all of it gone, first-party promos included,
        # without hunting for a second toggle. If this cell ever returns True the
        # master switch has stopped being a master switch.
        (False, True, False, "MASTER KILL: ads off site-wide beats the panel flag"),
        (False, False, False, "master kill with the panel flag off too"),
    ]
    for ads_enabled, house_ads, want, why in TRUTH_TABLE:
        got = hae(FakeSettings(ads_enabled, house_ads))
        g2.eq(got, want, f"ads_enabled={ads_enabled!r}, house_ads={house_ads!r} ({why})")
        g2.ok(got is True or got is False,
              f"ads_enabled={ads_enabled!r}, house_ads={house_ads!r} returns a real bool")

    # No snapshot at all. base.html already defends this way at its
    # settings.memory_mb read, and some render paths have no snapshot, so this
    # must answer False rather than raise.
    g2.eq(g2.no_raise(lambda: hae(None), "house_ads_enabled(None)"), False,
          "settings=None -> False (no snapshot must not raise)")
    g2.eq(g2.no_raise(lambda: hae(), "house_ads_enabled() with no argument"), False,
          "no settings argument at all -> False")

    # A snapshot object that predates the flag: getattr's default must carry it.
    g2.eq(hae(NoHouseAds(ads_enabled=True)), False,
          "object with no house_ads attribute -> False (getattr default)")
    g2.eq(hae(NoHouseAds(ads_enabled=None)), False,
          "no house_ads attribute, master switch unknown -> False")

    # ── the regression this group exists for ─────────────────────────────────
    # Tier 1 is `getattr(settings, "ads_enabled", None) is False`, an IDENTITY
    # test, not a falsiness test. ads_enabled is tri-state: True/False are an
    # operator's answer and None means nobody could tell us. Rewriting the test
    # as `if not settings.ads_enabled:` would fold None in with an explicit off
    # and hide the promos on the strength of a failed read — and it would keep
    # working for every other case, so nothing but this assertion would notice.
    #
    # 0 and "" are the sharpest form of the same check: falsy, but not the False
    # singleton, so they must NOT kill the promo. In CPython `0 is False` is
    # False even though `0 == False` is True, which is exactly the distinction
    # the implementation relies on.
    for falsy in (0, "", 0.0, [], {}, ()):
        g2.eq(hae(FakeSettings(falsy, True)), True,
              f"ads_enabled={falsy!r} is falsy but not False -> promo survives "
              f"('is False' identity test intact)")
    # And the mirror: the real False singleton still kills it. Asserted next to
    # the loop above so the pair reads as one statement — falsy is not off, off
    # is off.
    g2.eq(hae(FakeSettings(False, True)), False,
          "ads_enabled=False (the singleton) still kills it")
    # The same identity test guards guard_mode()'s tier 2, and the two functions
    # have to agree about what None means or a later reader has to work out which
    # of them is lying. Cheap to assert that the source still says so.
    _tpl_src = (PANEL_DIR / "templating.py").read_text(encoding="utf-8")
    g2.eq(_tpl_src.count('getattr(settings, "ads_enabled", None) is False'), 2,
          "both house_ads_enabled and guard_mode still use the 'is False' identity test")


# ── group 2b: house_ads_visible folds the per-user opt-out on top ─────────────
# house_ads_enabled is the site-wide answer; house_ads_visible is what a given
# render actually shows, and the only thing it adds is the account's own opt-out.
# The main site reads users.ads_disabled to switch its ad stack off per account;
# /api/session now surfaces that flag onto the session the panel borrows, and
# render() passes it here — so the panel and the public pages honour one and the
# same choice. Two directions must hold and they are NOT symmetric:
#   * the user layer can only ever take promos AWAY, never add them back — when
#     the site-wide gate is off, no session value may switch a promo on;
#   * the flag absent (signed out, or an account that never opted out) falls
#     through to the site-wide answer unchanged.

g2b = Group("2b. templating.house_ads_visible folds in the per-user opt-out")

if tpl is None:
    g2b.failures.append(f"skipped: panel_app.templating unavailable ({_IMPORT_ERROR})")
else:
    g2b.ok(hasattr(tpl, "house_ads_visible"), "templating exposes house_ads_visible")
    hav = tpl.house_ads_visible

    ON = FakeSettings(True, True)           # site-wide: promos allowed
    NONE_ON = FakeSettings(None, True)      # master switch unreadable, still allowed
    PANEL_OFF = FakeSettings(True, False)   # dedicated panel flag off
    MASTER_OFF = FakeSettings(False, True)  # operator killed ads site-wide

    # Site-wide ON, and what the visitor's own choice does to it. NONE_ON is here
    # because house_ads_enabled fails a None master switch OPEN, so the per-user
    # layer has to keep behaving over that tri-state, not just over a hard True.
    ON_TABLE = [
        (ON, None, True, "no session at all -> site-wide answer, promos show"),
        (ON, {}, True, "signed in, no ad flag -> promos show"),
        (ON, {"ads_disabled": 0}, True, "account has ads ON -> promos show"),
        (ON, {"ads_disabled": 1}, False, "account opted OUT -> no promos"),
        (ON, {"ads_disabled": True}, False, "opt-out as a real bool -> no promos"),
        # /api/session sends the flag as int 0/1 (db.get_user_ads_disabled returns
        # an int), but the read is `not bool(...)`, matching the main site's
        # `not bool(user_resp.get("ads_disabled"))`. Pin the typed cases so a later
        # switch to a str/None payload cannot silently flip a visitor's promos.
        (ON, {"ads_disabled": "1"}, False, "truthy non-int opt-out -> no promos"),
        (ON, {"ads_disabled": ""}, True, "falsy non-int -> promos show"),
        (ON, {"ads_disabled": None}, True, "explicit None flag -> promos show"),
        (NONE_ON, {"ads_disabled": 1}, False, "None master + opt-out -> no promos"),
        (NONE_ON, {}, True, "None master + no flag -> promos show (fails open)"),
    ]
    for settings, session, want, why in ON_TABLE:
        got = g2b.no_raise(lambda s=settings, se=session: hav(s, se),
                           f"house_ads_visible(<on>, {session!r})")
        g2b.eq(got, want, f"site allows, session={session!r} ({why})")
        g2b.ok(got is True or got is False,
               f"site allows, session={session!r} returns a real bool")

    # THE KEY ASSERTION — the mirror of group 2's MASTER KILL. When the site-wide
    # gate is off (master switch OR panel flag), NO session value may bring a promo
    # back: the per-user layer subtracts, it never adds. The sharp case is a user
    # who never opted out (ads_disabled=0) — house_ads is "off for everyone", and
    # their standing "ads on" must not override the operator.
    for off_settings, label in ((MASTER_OFF, "master switch off"),
                                (PANEL_OFF, "panel flag off")):
        for session in (None, {}, {"ads_disabled": 0}, {"ads_disabled": 1},
                        {"ads_disabled": False}):
            g2b.eq(g2b.no_raise(lambda s=off_settings, se=session: hav(s, se),
                                f"house_ads_visible(<{label}>, {session!r})"),
                   False,
                   f"site OFF ({label}) beats session={session!r} "
                   f"(user layer can only subtract, never add)")

    # No snapshot at all -> False, the same defence house_ads_enabled makes.
    g2b.eq(g2b.no_raise(lambda: hav(None, {"ads_disabled": 0}),
                        "house_ads_visible(None, ...)"), False,
           "settings=None -> False regardless of session")
    g2b.eq(g2b.no_raise(lambda: hav(), "house_ads_visible() with no args"), False,
           "no arguments at all -> False")

    # ── the wiring: render() actually consults the per-user gate ──────────────
    # The table proves the function is right; this proves render() calls it with
    # the borrowed session rather than the site-wide house_ads_enabled it used
    # before. A revert to house_ads_enabled(settings) there leaves every cell above
    # green while silently ignoring the account's choice in production.
    _tpl_src_2b = (PANEL_DIR / "templating.py").read_text(encoding="utf-8")
    g2b.eq(_tpl_src_2b.count(
        'ctx["house_ads"] = house_ads_visible(settings, auth.flask_session(request))'), 1,
        "render() sets house_ads from house_ads_visible(settings, the borrowed session)")
    g2b.eq(_tpl_src_2b.count('ctx["house_ads"] = house_ads_enabled('), 0,
           "render() no longer gates house_ads on the site-wide answer alone")

    # ── the source of the flag: /api/session surfaces users.ads_disabled ──────
    # Read as text, never imported: backend.py does `import database` at module
    # scope and this script is poisoned against reaching Oracle. The panel has no
    # other read path to users, so if this line goes the per-user gate degrades to
    # "site-wide only" — and every cell above still passes, because the borrowed
    # session simply never carries the key. Hence checking the producer too.
    _backend_src = (HERE / "backend.py").read_text(encoding="utf-8")
    g2b.ok('data["ads_disabled"] = db.get_user_ads_disabled(' in _backend_src,
           "api_get_session surfaces users.ads_disabled onto the borrowed session "
           "(the panel's only read path to the per-user flag)")


# ── group 3: PanelSettings and its fallback ──────────────────────────────────

g3 = Group("3. PanelSettings.house_ads and panel_settings._fallback")


class StubConfig:
    """The two PanelConfig attributes _fallback actually reads."""

    allow_registration = False
    max_servers_per_user = 2


if ps is None:
    g3.failures.append(f"skipped: panel_app.panel_settings unavailable ({_IMPORT_ERROR})")
else:
    def _snapshot(flags):
        # The constructor touches nothing external — it only stores what it is
        # handed — so building one directly is a pure operation.
        return ps.PanelSettings(
            flags=flags,
            limits={"max_servers": 1, "memory_mb": 300, "cpu_percent": 35, "disk_mb": 600},
            maintenance_message="",
            from_database=True,
        )

    g3.eq(_snapshot({"house_ads": True}).house_ads, True, "flags house_ads=True")
    g3.eq(_snapshot({"house_ads": False}).house_ads, False, "flags house_ads=False")
    g3.ok(_snapshot({"house_ads": True}).house_ads is True,
          "house_ads returns the True singleton, not a truthy value")
    # Absent key: a snapshot read from a database that has no such row yet must
    # answer False from the property rather than raising or leaking None into a
    # template's {% if %}.
    g3.eq(_snapshot({}).house_ads, False, "house_ads absent from flags -> False")
    g3.ok(_snapshot({}).house_ads is False, "absent key gives the False singleton")
    # And the property coerces, so a stored "1"/0/None cannot reach a template raw.
    g3.eq(_snapshot({"house_ads": 1}).house_ads, True, "truthy flag value coerces to True")
    g3.eq(_snapshot({"house_ads": None}).house_ads, False, "None flag value coerces to False")

    fb = g3.no_raise(lambda: ps._fallback(StubConfig()), "_fallback(StubConfig())")
    if fb is not None:
        # A database outage must leave the panel's own promos ON: the built-in
        # matches the PANEL_FLAGS default, so falling back does not quietly
        # switch off inventory nobody asked to switch off.
        g3.ok(fb.house_ads is True, "_fallback leaves house_ads ON during an outage")
        g3.ok(fb.flags.get("house_ads") is True, "_fallback flags dict carries house_ads=True")
        # ...and must NOT invent an answer for the master switch. None is the
        # only honest value here (there is no PANEL_ADS_ENABLED to resolve), and
        # it is the value both guard_mode() and house_ads_enabled() fail open on.
        # Writing True would reach the same behaviour today while claiming an
        # operator had confirmed ads are on — the one thing this path knows it
        # cannot establish.
        g3.ok(fb.ads_enabled is None,
              "_fallback leaves ads_enabled=None (does not fabricate a master-switch answer)")
        g3.eq(fb.from_database, False, "_fallback marks the snapshot as not from the database")
        if tpl is not None:
            # The two halves composed: an outage snapshot still shows promos.
            g3.eq(tpl.house_ads_enabled(fb), True,
                  "house_ads_enabled(_fallback snapshot) -> True (outage keeps promos)")


# ── group 4: the templates render the slot, and honour the switch ────────────
# Rendered through a local Environment rather than templating.render(), which
# needs a live Starlette Request. The globals and per-render context below are the
# same surface render() injects, stubbed.

g4 = Group("4. templates emit the promo when on and nothing at all when off")


def stub_url_for(endpoint, **values):
    """Stub of templating.url_for: same shape, no filesystem, no off-origin URL.

    The real one stats and hashes the static file to append a ?v= token. That is
    irrelevant here and would make the rendered output depend on the bytes of
    app.css, so this returns the plain mount-prefixed path.
    """
    if endpoint == "static":
        return f"/panel/static/{values.get('filename', '')}"
    tail = "/".join(str(v) for v in values.values())
    return f"/panel/{endpoint}" + (f"/{tail}" if tail else "")


def stub_site_url(path):
    """Stub of the ``site_url`` render() injects for the main-site promo links.

    Returns the bare path, which is what the real builder emits in production:
    ``main_site_url`` is empty there because the LB serves the site and the panel
    from one host. That is also the only form group 5 can check — it asserts the
    rendered promo carries no http(s):// URL, and a fixture that baked in a dev
    origin would put one there and make that cell unfalsifiable.
    """
    path = str(path or "")
    if not path.startswith("/") or path.startswith("//"):
        return "#"
    return path


class StubEndpointRef:
    """templating._EndpointRef: templates only read request.endpoint."""

    def __init__(self, endpoint):
        self.endpoint = endpoint


class StubSnapshot:
    """The settings surface base.html reads, for the panel_app-less path."""

    memory_mb = 300
    cpu_percent = 35
    disk_mb = 600
    maintenance = False
    maintenance_message = ""
    deploys = True
    ads_enabled = True
    house_ads = True


jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=jinja2.select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    ),
)
jenv.globals["url_for"] = stub_url_for
jenv.globals["panel_base"] = "/panel"
jenv.globals["site_url"] = stub_site_url

if tpl is not None:
    # The rest of render()'s global surface, taken from the real environment
    # rather than restubbed: runtime_badge and public_server_id are pure, and
    # were registered there after this harness was written — while they were
    # missing, every render of new_server.html and server.html below died as an
    # UndefinedError instead of checking anything. setdefault, so the three
    # stubs above keep winning over the real url_for/site_url, which need a
    # live Request.
    for _name, _value in tpl._env.globals.items():
        jenv.globals.setdefault(_name, _value)

if ps is not None:
    _RENDER_SETTINGS = ps.PanelSettings(
        # deploys=True so new_server.html renders its enabled form rather than the
        # "deployments are paused" branch: the fixture is meant to be the page a
        # real user sees, and a disabled form is a different set of markup.
        flags={"house_ads": True, "maintenance": False, "deploys": True},
        limits={"max_servers": 3, "memory_mb": 300, "cpu_percent": 35, "disk_mb": 600},
        maintenance_message="",
        from_database=True,
        guard_mode="warn",
        ads_enabled=True,
    )
else:
    _RENDER_SETTINGS = StubSnapshot()

# Whatever each template needs on top of the shared base context. Shaped as
# routes.py shapes it: plain dicts, because new_server.html pushes ``runtimes``
# through |tojson and server.html walks ``runtime_config.versions``.
EXTRA_CONTEXT = {
    "base.html": {},
    "account.html": {
        "server_count": 1,
        "max_servers": 3,
        "quota_step": 3,
    },
    "dashboard.html": {
        "stats": {"total": 1, "running": 1},
        "max_servers": 3,
        "servers": [],
        "statuses": {},
        "node_install": {},
        "quota_step": 3,
    },
    "new_server.html": {
        "runtimes": {"nodejs": {"label": "Node.js", "versions": ["20", "22"]}},
        "current_count": 1,
        "max_servers": 3,
    },
    "server.html": {
        "server": {
            "id": "srv-00000001",
            "name": "Music Bot",
            "image": "botdock/nodejs:20",
            "runtime": "nodejs",
            "version": "20",
            "startup": "node index.js",
            "memory_mb": 300,
            "cpu_percent": 35,
        },
        "runtimes": {"nodejs": {"label": "Node.js", "versions": ["20", "22"]}},
    },
}


def render(template_name, house_ads, endpoint):
    """Render one template as templating.render() would, for one endpoint.

    ``endpoint`` is a real parameter rather than a constant because base.html's
    promo bar is now gated on it: the bar is suppressed on the dashboard, so a
    fixture that rendered everything under one hardcoded endpoint could only ever
    see one side of that rule.
    """
    ctx = {
        "request": StubEndpointRef(endpoint),
        "csrf_token": lambda: "stub-csrf-token",
        "get_flashed_messages": lambda with_categories=False, category_filter=(): [],
        "current_user": {"id": "u-1", "username": "operator"},
        "settings": _RENDER_SETTINGS,
        "guard_mode": "warn",
        "house_ads": house_ads,
    }
    ctx.update(EXTRA_CONTEXT[template_name])
    return jenv.get_template(template_name).render(**ctx)


# Keyed (template, house_ads) and rendered under each template's PRIMARY_ENDPOINT.
# This is the canonical pair every existing cell and both of group 5's sweeps read.
RENDERED = {}
for name in PROMO_TEMPLATES:
    for flag in (True, False):
        html = g4.no_raise(
            lambda n=name, f=flag: render(n, f, PRIMARY_ENDPOINT[n]),
            f"render {name} with house_ads={flag} at endpoint={PRIMARY_ENDPOINT[name]!r}")
        RENDERED[(name, flag)] = html or ""

# base.html again under every endpoint it can serve, the dashboard included. This
# is the fixture the placement rule is asserted over.
BASE_BY_ENDPOINT = {}
for _ep in NON_DASHBOARD_ENDPOINTS + (DASHBOARD_ENDPOINT,):
    for flag in (True, False):
        html = g4.no_raise(
            lambda e=_ep, f=flag: render("base.html", f, e),
            f"render base.html with house_ads={flag} at endpoint={_ep!r}")
        BASE_BY_ENDPOINT[(_ep, flag)] = html or ""

for name in PROMO_TEMPLATES:
    on = RENDERED[(name, True)]
    off = RENDERED[(name, False)]
    g4.ok(on, f"{name} rendered non-empty with house_ads=True")
    g4.ok(off, f"{name} rendered non-empty with house_ads=False")
    g4.ok("house-promo" in on, f"{name}: promo markup present with house_ads=True")
    # Zero, not "fewer": the {% if %} must remove the element entirely, not hide
    # it. A slot left in the DOM behind a CSS rule is still a slot an operator
    # was told they had switched off.
    g4.eq(off.count("house-promo"), 0,
          f"{name}: ZERO occurrences of 'house-promo' with house_ads=False "
          f"(console-killable)")
    g4.ok(len(on) > len(off), f"{name}: the on-render is strictly larger than the off-render")

# The exact class names the change introduced, each asserted where it belongs, so
# a rename that half-lands (template edited, stylesheet not, or vice versa) shows
# up here rather than as an unstyled block in production.
EXPECTED_CLASSES = {
    "base.html": ("house-promo-rail", "house-promo-bar", "house-promo-eyebrow",
                  "house-promo-copy", "house-promo-cta"),
    "account.html": ("house-promo-tile",),
    "dashboard.html": ("house-promo-slot", "house-promo-card", "house-promo-body"),
    "new_server.html": ("house-promo-tile",),
    "server.html": ("house-promo-tile",),
}
for name, classes in EXPECTED_CLASSES.items():
    for klass in classes:
        g4.ok(klass in RENDERED[(name, True)], f"{name}: emits class {klass!r}")
        g4.eq(RENDERED[(name, False)].count(klass), 0,
              f"{name}: class {klass!r} entirely gone with house_ads=False")

# Every class the templates ask for has a rule in the stylesheet. A slot whose class
# never got a rule is invisible in production but passes every count above, and the
# reverse — a rule for a class no template emits — is dead weight that outlives a
# rename. Reported, not required, for the same reason group 5 only notes missing CSS:
# another agent may still be writing it.
PROMO_CLASSES = ("house-promo-bar", "house-promo-card", "house-promo-body",
                 "house-promo-rail", "house-promo-slot", "house-promo-tile",
                 "house-promo-eyebrow", "house-promo-copy", "house-promo-cta")

# The rest of the page is unaffected either way — the promo is additive, not a
# replacement for anything. Checked on a landmark each template must always have.
for name, landmark in (("base.html", "panel-shell"),
                       ("account.html", "account-summary"),
                       ("dashboard.html", "stat-cards"),
                       ("new_server.html", "deploy-layout"),
                       ("server.html", "details-grid")):
    g4.ok(landmark in RENDERED[(name, True)] and landmark in RENDERED[(name, False)],
          f"{name}: {landmark!r} present in both renders (promo is additive)")


# ── group 4b: one promo per region ───────────────────────────────────────────
# base.html's strip sits at the end of <main>, after {% block content %}, and
# dashboard.html's content block already ends in .house-promo-card. The two share
# the same panel/line/inset-sliver treatment, so on the dashboard they rendered
# back-to-back and read as the same box printed twice — and with the landing page
# retired the dashboard is every user's first screen, which made that duplicate
# the first thing anyone saw. Hence the `request.endpoint != 'dashboard'` guard on
# base.html's bar.
#
# The rule that generalises from it is one promo per *region*, not one per page.
# .house-promo-bar and .house-promo-card both close <main>, so they are the pair
# that may never coexist — their sum is exactly 1 on every page. The other three
# slots occupy regions of their own (the sidebar column, the stat-cards grid, a
# layout rail), so each may appear once alongside the closer without ever stacking
# against it. What is forbidden is two of the *same* treatment on one page, which
# is the shape a duplicate actually takes.
#
# The assertions below are therefore about which elements appear and about their
# per-treatment counts — never about a total being "small".

g4b = Group("4b. one promo per region (the dedup rule)")

# Every distinct treatment, i.e. every class that is an entire slot rather than a
# child of one. Counted separately because a duplicate is always a duplicate of one
# of these, and a bare total would let a page trade a lost slot for a doubled one.
TREATMENTS = ("house-promo-bar", "house-promo-card", "house-promo-rail",
              "house-promo-slot", "house-promo-tile")
# The two that close <main>. Mutually exclusive by construction.
CLOSERS = ("house-promo-bar", "house-promo-card")

# The bar appears on all four non-dashboard endpoints. Asserted per endpoint rather
# than once, because the guard is an endpoint comparison: a typo'd literal (or an
# `in` test that accidentally matched more than one name) would suppress the bar
# on a page that should carry it, and only a per-endpoint sweep would show which.
for ep in NON_DASHBOARD_ENDPOINTS:
    on = BASE_BY_ENDPOINT[(ep, True)]
    g4b.eq(on.count("house-promo-bar"), 1,
           f"base.html at endpoint={ep!r}: the bar IS emitted (non-dashboard page)")
    for klass in ("house-promo-eyebrow", "house-promo-copy", "house-promo-cta"):
        g4b.ok(klass in on, f"base.html at endpoint={ep!r}: emits {klass!r}")

# ...and is suppressed on the dashboard, with house_ads still fully ON. This is
# the cell that distinguishes "the bar stood down for placement" from "the promo
# was switched off": house_ads=True here, so the only thing that can remove it is
# the endpoint guard. The rail is asserted present in the same breath, because the
# guard is on the bar alone — a guard that had been written against the whole
# sidebar-plus-strip block would take the rail off the dashboard with it, and a
# bare "zero bars" cell could not tell the two apart.
dash_base_on = BASE_BY_ENDPOINT[(DASHBOARD_ENDPOINT, True)]
g4b.eq(dash_base_on.count("house-promo-bar"), 0,
       "base.html at endpoint='dashboard' with house_ads=True: ZERO "
       "'house-promo-bar' (the inherited strip stands down so it cannot double up "
       "with dashboard.html's card)")
g4b.eq(dash_base_on.count("house-promo-rail"), 1,
       "base.html at endpoint='dashboard': the sidebar rail is still emitted (the "
       "endpoint guard is on the closing strip only — the rail is in another region "
       "and cannot collide with the card)")
g4b.ok("panel-shell" in dash_base_on,
       "base.html at endpoint='dashboard': the rest of the page still renders "
       "(the guard removed the bar, not the layout)")

# The rail is on every page there is, dashboard included. It is the one slot with no
# placement exception, so it is the one whose absence anywhere is a bug.
for ep in NON_DASHBOARD_ENDPOINTS + (DASHBOARD_ENDPOINT,):
    g4b.eq(BASE_BY_ENDPOINT[(ep, True)].count("house-promo-rail"), 1,
           f"base.html at endpoint={ep!r}: exactly one sidebar rail")

# The dashboard keeps its own card and its own grid filler, and does not inherit
# the bar. Each half asserted, because any one alone is satisfiable by the wrong
# fix: dropping dashboard.html's card would also stop the doubling, and would be
# the wrong element to lose.
dash_on = RENDERED[("dashboard.html", True)]
g4b.eq(dash_on.count("house-promo-card"), 1,
       "dashboard.html: keeps its own .house-promo-card")
g4b.eq(dash_on.count("house-promo-slot"), 1,
       "dashboard.html: keeps its .house-promo-slot inside .stat-cards")
g4b.eq(dash_on.count("house-promo-bar"), 0,
       "dashboard.html: does NOT inherit base.html's .house-promo-bar")

# The two tiles, each in the rail its own layout leaves empty, each alongside the
# inherited strip rather than instead of it.
for name in ("new_server.html", "server.html"):
    html = RENDERED[(name, True)]
    g4b.eq(html.count("house-promo-tile"), 1, f"{name}: exactly one .house-promo-tile")
    g4b.eq(html.count("house-promo-bar"), 1,
           f"{name}: still inherits the closing strip (the tile is in a rail, not "
           f"at the end of <main>, so the two do not stack)")
    g4b.eq(html.count("house-promo-card"), 0,
           f"{name}: carries no .house-promo-card (that treatment is the "
           f"dashboard's, and it is the bar's alternative, not its neighbour)")

# ── the invariant worth stating directly ─────────────────────────────────────
# Per page: no treatment twice, and exactly one of the two closers. This is what
# fails if someone drops the request.endpoint guard from base.html (the dashboard
# gets bar+card, so CLOSERS sums to 2), adds a second copy of a slot to a page that
# already has one (that treatment goes to 2), or loses the strip from a page that
# should carry it (CLOSERS sums to 0). Counted per treatment rather than in total
# because both failure directions matter and they are not symmetric.
#
# Every page is its own real render where one exists, account.html included now
# that it carries a tile of its own. base.html is still rendered standalone
# under account_page as well, because that fixture is what holds the inherited
# rail+strip to their exact set on a page whose child adds a slot alongside.
PAGES_WITH_PROMO = [
    ("base.html@account_page", BASE_BY_ENDPOINT[("account_page", True)]),
    ("account.html@account_page", RENDERED[("account.html", True)]),
    ("dashboard.html@dashboard", RENDERED[("dashboard.html", True)]),
    ("new_server.html@new_server", RENDERED[("new_server.html", True)]),
    ("server.html@server_page", RENDERED[("server.html", True)]),
]
for label, html in PAGES_WITH_PROMO:
    counts = {k: html.count(k) for k in TREATMENTS}
    for klass, n in counts.items():
        g4b.ok(n <= 1, f"{label}: at most ONE {klass!r} on the page (got {n})")
    g4b.eq(sum(counts[k] for k in CLOSERS), 1,
           f"{label}: exactly ONE of {CLOSERS} closes <main> "
           f"(bar={counts['house-promo-bar']}, card={counts['house-promo-card']})")

# And the exact shape of each page, spelled out. The per-treatment rule above is a
# ceiling; this is the floor. Without it a page could quietly lose its rail or its
# tile and every cell so far would still pass, because "at most one" is satisfied by
# none. Read as: which slots does this page actually carry.
EXPECTED_SLOTS = {
    "base.html@account_page": {"house-promo-rail", "house-promo-bar"},
    "account.html@account_page": {"house-promo-rail", "house-promo-tile",
                                  "house-promo-bar"},
    "dashboard.html@dashboard": {"house-promo-rail", "house-promo-slot",
                                 "house-promo-card"},
    "new_server.html@new_server": {"house-promo-rail", "house-promo-tile",
                                   "house-promo-bar"},
    "server.html@server_page": {"house-promo-rail", "house-promo-tile",
                                "house-promo-bar"},
}
for label, html in PAGES_WITH_PROMO:
    present = {k for k in TREATMENTS if k in html}
    g4b.eq(present, EXPECTED_SLOTS[label], f"{label}: carries exactly its own slot set")

# The kill switch outranks the placement rule. Under every endpoint, on every
# template, house_ads=False leaves nothing at all — an operator who switches the
# promos off in the console must not be left with whichever slot the dedup happened
# to spare.
for ep in NON_DASHBOARD_ENDPOINTS + (DASHBOARD_ENDPOINT,):
    g4b.eq(BASE_BY_ENDPOINT[(ep, False)].count("house-promo"), 0,
           f"base.html at endpoint={ep!r} with house_ads=False: ZERO 'house-promo' "
           f"(kill switch outranks the placement rule)")
for name in PROMO_TEMPLATES:
    g4b.eq(RENDERED[(name, False)].count("house-promo"), 0,
           f"{name} with house_ads=False: ZERO 'house-promo'")

# No slot anywhere else. The invariants above only see the pages this script
# renders, so a promo added to any other template would satisfy every cell
# so far while putting two of the same treatment on that page in production.
# Scanning the whole template directory is what closes that: only the five in
# PROMO_TEMPLATES may contain promo markup at all.
for path in sorted(TEMPLATES_DIR.glob("*.html")):
    if path.name in PROMO_TEMPLATES:
        continue
    g4b.eq(path.read_text(encoding="utf-8").count("house-promo"), 0,
           f"{path.name}: contains no promo markup (only {PROMO_TEMPLATES} may, or "
           f"a page inherits the strip AND doubles a treatment of its own)")

# blocked.html is the ad-block interstitial: the one page whose whole purpose is
# to tell a visitor their blocker is the problem. An advertisement there would be
# absurd, and it is currently impossible only because the file is a standalone
# document rather than a child of base.html. That is a property of one line, so
# assert it -- the scan above proves the file carries no promo markup today, and
# this proves it cannot start inheriting the bar tomorrow.
_blocked = TEMPLATES_DIR / "blocked.html"
if _blocked.exists():
    _blocked_text = _blocked.read_text(encoding="utf-8")
    g4b.ok("{% extends" not in _blocked_text,
           "blocked.html is still a standalone document, so the ad-block "
           "interstitial can never inherit base.html's promo bar")
    g4b.ok(_blocked_text.lstrip().lower().startswith("<!doctype html>"),
           "blocked.html still opens its own document (a template that stopped "
           "being standalone would lose this before it gained an {% extends %})")


# ── group 5: the security invariants ─────────────────────────────────────────
# The most important group. Each forbidden token is here for a specific reason:
#
#   data-ad-src / data-ad-cfg / data-ad-kind
#       static/g7.js's injectAds() matches only `script[data-ad-src]` and
#       reads its config off data-ad-cfg/data-ad-kind. A promo element carrying
#       any of them could be hijacked into loading third-party creative — the one
#       thing the panel's CSP exists to prevent. First-party promo markup must be
#       invisible to that machinery.
#
#   ad-container / adsbygoogle / adsbox / ad-slot / pub_300x250 / banner_ad
#       These are ad-blocker *cosmetic-filter bait* — the class and id names
#       EasyList hides on sight, and the ones g7.js itself plants to detect
#       a blocker. Naming our own first-party promo any of them would mean a
#       visitor running a blocker silently loses the operator's own inventory,
#       with nothing in any log to explain it.
#
#   style= / <style / onclick / onerror / @import / javascript:
#       security_headers.CSP is `script-src 'self'; style-src 'self'` with no
#       nonce and no 'unsafe-inline'. Every one of these is refused by that policy
#       at runtime, so any of them appearing here is markup that silently does
#       nothing — a promo styled by an attribute the browser drops, or a CTA whose
#       handler never fires.
#
#   http:// or https://
#       default-src 'self' except the CSP's connect-src hosts. An off-origin URL in a
#       panel template or stylesheet is either refused or an unwanted third-party
#       request from a page that is supposed to have none.

g5 = Group("5. security invariants over the templates and the stylesheet")

FORBIDDEN = (
    "data-ad-src", "data-ad-cfg", "data-ad-kind",
    "ad-container", "adsbygoogle", "adsbox", "ad-slot",
    "pub_300x250", "banner_ad",
    "style=", "<style", "onclick", "onerror", "@import", "javascript:",
)
URL_RE = re.compile(r"https?://")

SCAN_TARGETS = [(name, TEMPLATES_DIR / name) for name in PROMO_TEMPLATES]
# The stylesheet is scanned but its *rules* are not required: another agent may
# still be writing them, and an unstyled promo is a cosmetic problem while a
# hijackable one is a security problem. So absence is a note, never a failure.
if APP_CSS.exists():
    SCAN_TARGETS.append(("static/app.css", APP_CSS))
else:
    note(f"{APP_CSS} does not exist yet — stylesheet scan skipped")

for label, path in SCAN_TARGETS:
    text = path.read_text(encoding="utf-8")
    for token in FORBIDDEN:
        g5.eq(text.count(token), 0, f"{label}: zero occurrences of {token!r}")
    urls = URL_RE.findall(text)
    g5.eq(len(urls), 0, f"{label}: zero http(s):// URLs (found {sorted(set(urls))})")

# Same sweep over what actually reaches a browser, which is the string that
# matters: a token could be assembled by a Jinja expression rather than written
# literally in the file.
for name in PROMO_TEMPLATES:
    html = RENDERED[(name, True)]
    for token in FORBIDDEN:
        g5.eq(html.count(token), 0, f"rendered {name}: zero occurrences of {token!r}")
    urls = URL_RE.findall(html)
    g5.eq(len(urls), 0, f"rendered {name}: zero http(s):// URLs (found {sorted(set(urls))})")

# Zero new script tags. base.html has exactly three — q1.js plus the two
# _guard.html includes (ads.js and g7.js) — and each child template adds its
# own through {% block scripts %}. The equality against the house_ads=False render
# is the drift-proof half of this: whatever the real baseline becomes, the promos
# must not move it.
SCRIPT_BASELINE = {"base.html": 3, "account.html": 3, "dashboard.html": 4,
                   "new_server.html": 5, "server.html": 4}
# What each child adds on top of base.html's three. For the failure message only.
SCRIPT_EXTRAS = {
    "base.html": "",
    "account.html": "",
    "dashboard.html": " + q2.js",
    "new_server.html": " + q3.js + the runtime-data JSON block",
    "server.html": " + q4.js",
}
# The only inline <script> shape allowed. `type="application/json"` is not a script
# type, so the browser parses the element as inert data and never consults
# script-src for it — which is how new_server.html can carry its runtime-data block
# under a policy with no nonce and no 'unsafe-inline'. The allowlist is deliberately
# this short: a missing type, `type="module"`, and `text/javascript` all *are*
# executable, would be refused at runtime, and must not appear.
DATA_SCRIPT_TYPES = ('type="application/json"', 'type="application/ld+json"')
for name in PROMO_TEMPLATES:
    on_count = RENDERED[(name, True)].count("<script")
    off_count = RENDERED[(name, False)].count("<script")
    g5.eq(on_count, off_count,
          f"{name}: the promo added ZERO <script> tags "
          f"(on={on_count}, off={off_count})")
    g5.eq(on_count, SCRIPT_BASELINE[name],
          f"{name}: still exactly {SCRIPT_BASELINE[name]} <script> tags "
          f"(q1.js + _guard.html's two{SCRIPT_EXTRAS[name]})")
    # And every one is either external and same-origin — servable under
    # script-src 'self' with no nonce — or one of the inert data blocks above.
    for tag in re.findall(r"<script[^>]*>", RENDERED[(name, True)]):
        if "src=" in tag:
            g5.ok("//" not in tag.replace('src="/panel', ""),
                  f"{name}: external <script> src is same-origin ({tag})")
        else:
            g5.ok(any(t in tag for t in DATA_SCRIPT_TYPES),
                  f"{name}: inline <script> is a non-executable data block rather "
                  f"than code ({tag})")
    # That exemption only holds while the block cannot close its own element: a
    # '</script' inside it would end the element early and hand the remainder to the
    # HTML parser as markup. Jinja's tojson escapes every '<' to its unicode escape
    # for exactly that reason, so assert the outcome rather than trusting the filter.
    for body in re.findall(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>",
                           RENDERED[(name, True)], re.S):
        g5.eq(body.count("<"), 0,
              f"{name}: inline data block holds no raw '<', so it cannot be broken "
              f"out of (tojson escapes it to \\u003c)")

# The stylesheet rules, reported rather than required (see above). Cross-checked
# against every class the templates actually emit, so a slot added to markup with no
# matching rule is surfaced instead of shipping as an unstyled box.
if APP_CSS.exists():
    css = APP_CSS.read_text(encoding="utf-8")
    missing = [k for k in PROMO_CLASSES if k not in css]
    if missing:
        note(f"static/app.css has no rules yet for {missing} — cosmetic only, and "
             f"the security invariants above hold regardless")
    # The reverse direction: a rule for a class nothing emits any more, which is
    # usually what a moved or deleted slot leaves behind.
    unused = [k for k in PROMO_CLASSES if k in css
              and not any(k in RENDERED[(n, True)] for n in PROMO_TEMPLATES)]
    if unused:
        note(f"static/app.css styles {unused}, which no template emits — dead "
             f"rules, not a failure")


# ── group 6: the CSP was not relaxed ─────────────────────────────────────────
# The whole purpose of this group. Adding advertising to a hardened surface is
# exactly the change that tends to arrive with an 'unsafe-inline' or a third-party
# host bolted onto script-src, and the promo slots would still look fine if it
# had. Read as text and parsed per directive — never imported for this, so the
# group holds even if panel_app becomes unimportable.
#
# pagead2.googlesyndication.com legitimately appears in connect-src: g7.js
# sends it one no-cors GET as ad-block bait, and a CSP refusal is
# indistinguishable from a blocker's refusal, so without that host every visitor
# is flagged as blocking. That is a *connect* permission and grants no execution.
# The assertion below is therefore per-directive, not a substring search over the
# whole policy: the host must be in connect-src's token set and must not appear
# anywhere in script-src's.

g6 = Group("6. panel CSP still forbids third-party and inline script")


def _csp_from_source(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "CSP":
                    return ast.literal_eval(node.value)
    raise AssertionError(f"no module-level CSP assignment in {path}")


CSP = g6.no_raise(lambda: _csp_from_source(SECURITY_HEADERS),
                  "parse the CSP constant out of security_headers.py") or ""

# directive name -> set of source-expression tokens.
DIRECTIVES = {}
for part in CSP.split(";"):
    part = part.strip()
    if not part:
        continue
    name, _, rest = part.partition(" ")
    DIRECTIVES[name.strip().lower()] = set(rest.split())

script_src = DIRECTIVES.get("script-src", set())
connect_src = DIRECTIVES.get("connect-src", set())
img_src = DIRECTIVES.get("img-src", set())
style_src = DIRECTIVES.get("style-src", set())

g6.ok("script-src 'self'" in CSP, "CSP text still contains \"script-src 'self'\"")
# Exact set equality, which is stronger than any ban list: it forbids hosts
# nobody has thought to blocklist yet.
g6.eq(script_src, {"'self'", "https://challenges.cloudflare.com"}, "script-src includes 'self' and https://challenges.cloudflare.com")
g6.eq(style_src, {"'self'"}, "style-src is EXACTLY {'self'} — no inline style, no CDN")

# The named bans, per directive. unsafe-eval/unsafe-inline are checked against the
# whole policy as well, because neither is acceptable in any directive here.
SCRIPT_SRC_BANNED = (
    "unsafe-eval", "unsafe-inline",
    "highperformanceformat", "effectivecpmnetwork", "adoric",
    "googlesyndication",
)
for banned in SCRIPT_SRC_BANNED:
    g6.ok(not any(banned in token for token in script_src),
          f"script-src contains no {banned!r} (script-src={sorted(script_src)})")
for banned in ("unsafe-eval", "unsafe-inline"):
    g6.eq(CSP.count(banned), 0, f"the whole CSP contains no {banned!r}")

# The bait host: required in connect-src, forbidden in script-src. This pair *is*
# the distinction — one directive grants a fetch, the other grants execution, and
# only the first is acceptable.
g6.ok("https://pagead2.googlesyndication.com" in connect_src,
      "connect-src still allows the bait host https://pagead2.googlesyndication.com "
      "(without it every visitor is misread as running a blocker)")
g6.ok(not any("googlesyndication" in token for token in script_src),
      "and that host is NOT in script-src (a fetch permission, never an execute one)")

# ── the converse: NET_BAITS may not outgrow the allowlist ────────────────────
# The pair above proves the CSP still ALLOWS that bait host. This proves the
# other direction, which nothing checked: that the bait list has not GROWN a host
# the CSP does not allow. The two are not interchangeable — every assertion above
# passes untouched when a second host is appended to NET_BAITS.
#
# Why it earns its own cells: probe() cannot distinguish our own CSP cancelling a
# request from a blocker refusing it, and NET_REFUSED_MIN wants two refusals. So
# two bait hosts missing from connect-src pin the verdict to "blocked" for every
# panel visitor, on every page, until someone edits the CSP — and one leaves the
# verdict resting on whether the remaining pair both refuse. The panel serves no
# ad units, so there is no second signal that could contradict it, and the
# visitor's only evidence is an interstitial telling them to turn off a blocker
# they may not be running.
#
# Text, not a parser: this is JavaScript. read_text() is universal-newline, so the
# panel copy's CRLF is already \n before the regex sees it and no \r can reach an
# entry — the LF/CRLF split between the two copies needs no handling here.

_NET_BAITS_BLOCK_RE = re.compile(r"var\s+NET_BAITS\s*=\s*\[(.*?)\]\s*;", re.S)
# Scheme-anchored deliberately. A bare quoted-string pattern would also match an
# apostrophe pair inside a comment added to the array ("EasyList's targets") and
# invent an entry; requiring the scheme right after the opening quote cannot. The
# backreference accepts either quote style, so a future edit switching to " parses.
_NET_BAIT_ENTRY_RE = re.compile(r"""(['"])(https?://[^'"]*)\1""")
# scheme+host, i.e. the form a CSP host-source token takes. Anchored at the start
# and stopped at the first /, ? or #, because the entries carry a path
# (.../pagead/js/adsbygoogle.js) and CSP matching is per-origin.
_ORIGIN_RE = re.compile(r"https?://[^/?#]+")


def _net_baits(path):
    """The NET_BAITS entries of an g7.js copy, in file order."""
    text = path.read_text(encoding="utf-8")
    block = _NET_BAITS_BLOCK_RE.search(text)
    if block is None:
        raise AssertionError(f"no `var NET_BAITS = [...]` array literal in {path}")
    return [m.group(2).strip() for m in _NET_BAIT_ENTRY_RE.finditer(block.group(1))]


def _bait_origin(entry):
    m = _ORIGIN_RE.match(entry)
    return m.group(0).lower() if m else None


_panel_baits = g6.no_raise(lambda: _net_baits(PANEL_FP_GUARD),
                           "parse NET_BAITS out of the panel's g7.js") or []
_app_baits = g6.no_raise(lambda: _net_baits(APP_FP_GUARD),
                         "parse NET_BAITS out of the main app's g7.js") or []

# Before trusting the extraction: a regex that found the block but matched no
# entries would make every cell below vacuously true, which is the one way this
# check can silently stop doing its job.
g6.ok(_panel_baits,
      f"the panel's NET_BAITS parsed to at least one entry (got {_panel_baits!r}) "
      f"— an empty read would make the cells below vacuous")

# THE ASSERTION. Every host the panel's guard probes must be one the panel's own
# CSP permits it to reach — via both connect-src (the old probe path) and
# img-src (the new probeNet() path that uses <img> tags to avoid
# ERR_BLOCKED_BY_CLIENT in the console).
for _entry in _panel_baits:
    _origin = _bait_origin(_entry)
    g6.ok(_origin in connect_src,
          f"panel NET_BAITS host {_origin} is allowed by the panel's connect-src "
          f"(connect-src={sorted(connect_src)}) — a bait our own CSP refuses is "
          f"indistinguishable from a blocker's refusal, so it burns this bait for "
          f"every panel visitor and two such hosts clear NET_REFUSED_MIN alone")
    g6.ok(_origin in img_src,
          f"panel NET_BAITS host {_origin} is also allowed by img-src "
          f"(img-src={sorted(img_src)}) — probeNet() uses <img> tags, so an "
          f"img-src refusal is indistinguishable from a blocker's refusal")

# The main app's copy is checked as PARITY, not as a CSP violation: the Flask
# tier's own connect-src is `'self' https:`, so a host added there is permitted at
# runtime and breaks nothing on that tier. It matters because the main copy is the
# source the panel copy is mirrored from — an author adds a bait host there first,
# and a panel-only check stays green right through the edit that creates the
# defect, firing only later when a sync propagates it. Equality here catches it at
# the keystroke, and reports the real fix (sync the two files) rather than accusing
# the main tier of violating a CSP that is not its own.
g6.eq(_app_baits, _panel_baits,
      "the two g7.js copies carry an identical NET_BAITS list "
      "(the panel copy is a mirror; a host added to only one is a latent break "
      "of whichever tier has not received it yet)")

# ...and named explicitly, so that if the copies are ever deliberately desynced
# the offending host is still reported against the allowlist by name rather than
# only as "the lists differ".
for _entry in _app_baits:
    _origin = _bait_origin(_entry)
    g6.ok(_origin in connect_src,
          f"main-app NET_BAITS host {_origin} is also allowed by the PANEL's "
          f"connect-src (connect-src={sorted(connect_src)}) — the Flask tier's own "
          f"connect-src is `'self' https:` and permits it, but the panel copy "
          f"shares this list and the panel pins exactly the bait hosts")
    g6.ok(_origin in img_src,
          f"main-app NET_BAITS host {_origin} is also allowed by the PANEL's "
          f"img-src (img-src={sorted(img_src)}) — probeNet() uses <img> tags, "
          f"so the panel's img-src must also list the bait hosts")

# Third-party host in script-src: allow 'self' and Cloudflare Turnstile script host.
for token in script_src:
    if token == "https://challenges.cloudflare.com":
        continue
    g6.ok(token.startswith("'") and token.endswith("'"),
          f"script-src token {token!r} is a quoted keyword, not a host")

# The rest of the policy the promos rely on staying put.
for directive, want in (("default-src", {"'self'"}),
                        ("object-src", {"'none'"}),
                        ("base-uri", {"'none'"}),
                        ("frame-ancestors", {"'none'"}),
                        ("form-action", {"'self'"})):
    g6.eq(DIRECTIVES.get(directive), want, f"{directive} unchanged")
g6.ok("img-src" in DIRECTIVES, "img-src is still declared")


# ── summary ─────────────────────────────────────────────────────────────────

print()
print("=" * 72)
ok = True
for grp in _GROUPS:
    ok = grp.report() and ok
print("=" * 72)
total = sum(len(x.failures) for x in _GROUPS)
print(f"{'ALL GROUPS PASS' if ok else f'FAILURES: {total}'}"
      f"   ({len(_GROUPS)} groups, {len(_NOTES)} note(s), "
      f"static only: no Oracle, no server, no suite)")

if not ok:
    print()
    print("Group 2's falsy-but-not-False cells and group 6 are the two that matter")
    print("most. Group 2 fails if house_ads_enabled's `is False` identity test was")
    print("rewritten as a falsiness test: ads_enabled is tri-state, and folding None")
    print("in with an explicit off hides the operator's own promos whenever a read")
    print("errors, while every other case keeps working. Group 6 fails if the panel's")
    print("CSP was relaxed to accommodate advertising -- which would defeat the whole")
    print("reason the promos are first-party markup in the first place -- or if")
    print("g7.js's NET_BAITS grew a host that connect-src does not allow, which")
    print("is the same defect from the other end: our own CSP cancels that probe,")
    print("netBaits() cannot tell that apart from a blocker refusing it, so the bait")
    print("is burned for every panel visitor and two of them flag one outright.")
    print()
    print("Group 4b's exactly-one-promo cells fail if base.html lost its")
    print("`request.endpoint != 'dashboard'` guard, or if a second slot was added to")
    print("a page that already has one. The bar and the card are visually identical,")
    print("so two on a page do not look like a bug -- they look like one box drawn")
    print("twice, on what is now every user's landing page.")

sys.exit(0 if ok else 1)

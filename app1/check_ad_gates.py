"""check_ad_gates.py — print the resolved ad/guard decision for every gate cell.

Companion to check_ad_settings.py: that one asserts the settings round-trip,
this one shows what the settings *do*. Stubs frontend._api so no backend is
needed, then walks guard mode x consent_required x session consent x page
switch x crawler and prints the resolved (ads, guard_mode, endpoint) triple for
each cell, plus the rendered markup for a handful of real routes.

Read the output rather than an exit code -- this is a matrix to eyeball when
changing a gate, not a pass/fail suite. It always exits 0 unless it crashes.
"""
import frontend

app = frontend.app
app.config["WTF_CSRF_ENABLED"] = False

BACKEND = {}


def fake_api(method, path, **kw):
    if path == "/api/settings/ad-zones":
        return dict(BACKEND["anon"], ok=True)
    if path == "/api/user/ad-zones":
        return dict(BACKEND["user"], ok=True)
    return {"ok": False}


frontend._api = fake_api

ZONES = {"leaderboard": True, "native": True}
NETWORKS = {"effective_cpm": True}
# The real map, mirroring database.AD_PAGES defaults: the content pages plus the
# four account pages on, only the two credential forms (login, register) off.
ALL_PAGES = {"index": True, "about": True, "hosting": True, "contact": True,
             "help": True, "blog": True, "blog_post": True,
             "terms": True, "privacy": True,
             "user_dashboard": True, "user_bot_editor": True,
             "user_bot_replies": True, "user_formatting": True,
             "user_login": False, "user_register": False}


def backend(guard_mode="gate", consent_required=False, pages=None,
            ads_enabled=True, user_pages=None, ads_disabled=False):
    BACKEND["anon"] = {"ads_enabled": ads_enabled, "zones": ZONES,
                       "networks": NETWORKS, "guard_mode": guard_mode,
                       "consent_required": consent_required,
                       "pages": ALL_PAGES if pages is None else pages}
    BACKEND["user"] = {"ads_disabled": ads_disabled, "zones": ZONES,
                       "networks": NETWORKS,
                       "pages": user_pages}
    frontend._ad_cache["at"] = 0.0     # force a refetch


def probe(url="/", consent=None, ua="Mozilla/5.0", user_id=None):
    with app.test_request_context(url, headers={"User-Agent": ua}):
        if consent:
            frontend.session["cookie_consent"] = consent
        if user_id:
            frontend.session["user_id"] = user_id
        ads = frontend._ads_permitted()
        mode = frontend._inject_guard_mode()["guard_mode"]
        ep = frontend._ad_page_endpoint()
        return ads, mode, ep


def row(label, *a, **kw):
    ads, mode, ep = probe(*a, **kw)
    print(f"  {label:<46} ads={'YES' if ads else 'no ':<3} "
          f"guard={mode:<5} endpoint={ep}")


CRAWLER = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

print("\n=== 1. guard_mode setting drives <body data-guard> ===")
for gm in ("gate", "warn", "off"):
    backend(guard_mode=gm)
    row(f"ad_guard_mode={gm!r}")
backend(guard_mode="hunter2")
row("ad_guard_mode='hunter2' (bad value -> default)")
backend(guard_mode=None)
row("ad_guard_mode=None (never fetched -> default)")

print("\n=== 2. consent_required off (the user's decision) ===")
backend(consent_required=False)
row("fresh session, no choice yet", consent=None)
row("visitor accepted", consent="accept")
row("visitor declined", consent="decline")

print("\n=== 3. consent_required ON (opt-in regime, admin-flipped) ===")
backend(consent_required=True)
row("fresh session, no choice yet", consent=None)
row("visitor accepted", consent="accept")
row("visitor declined", consent="decline")

print("\n=== 4. per-page switch ===")
backend()
row("/ (index, default_on)", "/")
row("/about (default_on)", "/about")
row("/user/login (user_login, default OFF)", "/user/login")
row("/user (user_dashboard, now default ON)", "/user")
row("/user/formatting (now default ON)", "/user/formatting")
backend(pages={**ALL_PAGES, "index": False})
row("/ with ad_page_index turned OFF in console", "/")
backend(pages={**ALL_PAGES, "user_login": True})
row("/user/login with ad_page_user_login turned ON", "/user/login")
row("/bogus-url-that-routes-nowhere", "/bogus-url-that-routes-nowhere")

print("\n=== 5. pages map absent (backend down / first render) ===")
backend(pages=None)
BACKEND["anon"]["pages"] = None
frontend._ad_cache["at"] = 0.0
row("pages=None -> content page fails open", "/")
row("pages=None on /user/login -> stays DENIED", "/user/login")
row("pages=None on /user -> now fails OPEN (no longer credential-only)", "/user")
row("pages=None on /about -> fails open", "/about")

print("\n=== 6. terms/privacy now carry their own switch ===")
backend()
row("/privacy (default_on row)", "/privacy")
row("/terms (default_on row)", "/terms")

print("\n=== 7. crawler always sees guard=off ===")
backend(guard_mode="gate")
row("Googlebot on /", "/", ua=CRAWLER)
row("Googlebot on /user/login (page off)", "/user/login", ua=CRAWLER)

print("\n=== 8. master switch + per-user override still win ===")
backend(ads_enabled=False, guard_mode="gate")
# _ads_permitted() answers "is this page allowed to carry ads", which the
# master switch deliberately does not decide -- the templates test
# ads_enabled themselves. So YES here is right; what matters is that the
# guard stands down, and that section 10 renders zero slots.
row("ads_enabled=0 (master off) -> guard MUST be off", "/")
backend(user_pages={k: False for k in ALL_PAGES}, ads_disabled=True)
row("signed-in user with All-Ads off", "/", user_id=7)
backend(user_pages=ALL_PAGES)
row("signed-in user, ads allowed", "/", user_id=7)

print("\n=== 9. masked_page resolves to its target's switch ===")
rules = sorted(r.rule for r in app.url_map.iter_rules()
               if r.endpoint == "masked_page")
print(f"  masked_page rules: {rules or '(none)'}")

print("\n=== 10. rendered markup: does an ad slot actually appear? ===")
import ads_config
ALL_ZONES = {k: True for k in ads_config.AD_UNITS}
ALL_NETWORKS = {k: True for k in ads_config.AD_NETWORKS}
ZONES, NETWORKS = ALL_ZONES, ALL_NETWORKS
backend(guard_mode="warn")
client = app.test_client()
for url in ("/", "/about", "/hosting", "/help", "/privacy"):
    r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    body = r.get_data(as_text=True)
    has_warn = 'data-guard="warn"' in body
    warn_str = 'yes' if has_warn else 'NO '
    print(f'  GET {url:<10} {r.status_code}  '
          f'data-ad-src={body.count("data-ad-src"):<2} '
          f'data-guard="warn"={warn_str}')

print("\n  same pages with ad_guard_mode='off' in the console:")
backend(guard_mode="off")
for url in ("/", "/about"):
    r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    body = r.get_data(as_text=True)
    has_off = 'data-guard="off"' in body
    off_str = 'yes' if has_off else 'NO '
    print(f'  GET {url:<10} {r.status_code}  '
          f'data-ad-src={body.count("data-ad-src"):<2} '
          f'data-guard="off"={off_str}')

print("\n  master switch off -> no ad markup at all, guard stands down:")
backend(ads_enabled=False, guard_mode="gate")
for url in ("/", "/about"):
    r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    b = r.get_data(as_text=True)
    has_off_b = 'data-guard="off"' in b
    off_str_b = 'yes' if has_off_b else 'NO '
    print(f'  GET {url:<10} {r.status_code}  '
          f'data-ad-src={b.count("data-ad-src"):<2} '
          f'data-guard="off"={off_str_b}')

print("\n=== 11. terms/privacy: is ad_head() now governable? ===")
# terms.html calls ad_head() with no ad_unit slots. Any head loader is governed
# by the same network toggles and page switches as other ad-bearing pages.
HEAD_MARK = "data-ad-src"
backend(guard_mode="warn")
for url in ("/terms", "/privacy"):
    r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    b = r.get_data(as_text=True)
    print(f"  switch ON   GET {url:<9} {r.status_code}  "
          f"head_loader={'yes' if HEAD_MARK in b else 'no '}")
backend(guard_mode="warn", pages={**ALL_PAGES, "terms": False, "privacy": False})
for url in ("/terms", "/privacy"):
    r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    b = r.get_data(as_text=True)
    has_off_terms = 'data-guard="off"' in b
    off_str_terms = 'yes' if has_off_terms else 'NO '
    print(f"  switch OFF  GET {url:<9} {r.status_code}  "
          f"head_loader={'yes' if HEAD_MARK in b else 'no '}  "
          f'data-guard="off"={off_str_terms}')

print("\n=== 12. every page template pins the guard and calls ad_scripts() ===")
# Sections 10-11 only reach the handful of routes named there, and nothing in the
# templates enforces the two halves of the contract: there is no base template
# and no {% include %}, so <body data-guard> and {{ ad_scripts() }} are pasted
# per page. A page that forgets either half does not fail loudly -- g7.js
# reads a missing or unrecognised mode as its own 'warn' fallback, so a page
# meant to be gated quietly degrades to a dismissible banner, and a page with no
# ad_scripts() loads neither the guard nor the fingerprint at all. So walk the
# template folder the app actually serves instead of a route list: a page added
# without the attribute cannot slip past by simply not being listed here.
import glob
import os
import re

TEMPLATE_DIR = os.path.join(app.root_path, app.template_folder)
# Page templates allowed to skip the contract, name -> why. Deliberately empty:
# an exemption has to be visible right here rather than hidden inside a silent
# skip, which is the failure mode this whole section exists to catch.
GUARD_EXEMPT = {}
# The literal modes a <body data-guard> may carry: every mode the Python tier
# will ever inject, plus "blocked", which blocked.html hard-codes and
# g7.js branches on (bootBlockedPage). _AD_GUARD_MODES has no row for it
# because it describes the operator-selectable modes, not the whole vocabulary.
GUARD_LITERALS = set(frontend._AD_GUARD_MODES) | {"blocked"}
# The only dynamic value that is safe, because _inject_guard_mode() guarantees
# this variable is a member of _AD_GUARD_MODES on every render.
GUARD_EXPRS = {"{{ guard_mode }}", "{{guard_mode}}"}

BODY_TAG_RE = re.compile(r"<body\b[^>]*>", re.I)
GUARD_ATTR_RE = re.compile(r"""data-guard\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
AD_SCRIPTS_RE = re.compile(r"\bad_scripts\s*\(\s*\)")

scanned = skipped = 0
offenders = []
for path in sorted(glob.glob(os.path.join(TEMPLATE_DIR, "**", "*.html"),
                             recursive=True)):
    name = os.path.relpath(path, TEMPLATE_DIR).replace("\\", "/")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    body_tag = BODY_TAG_RE.search(text)
    if "<html" not in text.lower() or not body_tag:
        # A fragment/partial has no <body> of its own to pin a mode to; it
        # renders inside a page that carries one, so it is not an offender.
        skipped += 1
        print(f"  {name:<26} skipped: fragment (no <html>/<body>)")
        continue
    if name in GUARD_EXEMPT:
        skipped += 1
        print(f"  {name:<26} EXEMPT: {GUARD_EXEMPT[name]}")
        continue
    scanned += 1
    attr = GUARD_ATTR_RE.search(body_tag.group(0))
    mode = attr.group(1).strip("\"'") if attr else None
    if mode is None:
        problem = "no data-guard on <body> (falls back to 'warn')"
    elif mode not in GUARD_LITERALS and mode not in GUARD_EXPRS:
        problem = f"data-guard={mode!r} is not an accepted mode"
    else:
        problem = None
    has_scripts = AD_SCRIPTS_RE.search(text) is not None
    if not has_scripts:
        problem = f"{problem} + no ad_scripts()" if problem else "no ad_scripts()"
    print(f"  {name:<26} guard={mode or '(none)':<18} "
          f"ad_scripts={'yes' if has_scripts else 'NO '}  "
          f"{'ok' if problem is None else 'MISSING'}")
    if problem is not None:
        offenders.append((name, problem))

print(f"\n  {scanned} page template(s) checked, {skipped} skipped "
      f"(fragments + exemptions), {len(offenders)} offending")
for name, problem in offenders:
    print(f"  MISSING  {name:<26} {problem}")


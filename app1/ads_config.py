"""Central ad placement config — the one file that owns every ad on the site.

This is the single source of truth for ad networks and ad units, laid out the
way ad networks publish their zones: a network has a loader, a unit references
a network plus an id/size, and a template just asks for a zone by name.
There is no ad markup left in the templates; frontend.py renders
`ad_head()` (the head loader) and `ad_unit('<zone>')` from this file.

Adding a unit:
  1. Add an entry under AD_UNITS (network id, kind, script URL, size, css).
  2. That is it. The CSP script-src host list is derived from
     ALLOWED_SCRIPT_HOSTS below, so a loader whose host is not listed there
     is a config error, not a silent browser block.

Adding a network (e.g. Adstera):
  1. Give it an entry under AD_NETWORKS (loader URL + zone id), and a
     matching row in database.AD_NETWORKS — get_resolved_ad_networks()
     only reports keys listed there, so a network missing from it has no
     console switch and is stuck at the default_on set here.
  2. ad_head_html() emits a network's head loader when its loader is set;
     it never reads AD_UNITS. Pointing a unit's "network" at the entry is
     a separate job: that is what the unit's own console network gate
     resolves against, which is why effectivecpm has an entry and no loader.

kinds:
  - "invoke"        highperformanceformat.com invoke.js banner (data-ad-cfg);
                    "container" adds the pre-container div the native unit
                    requires.
  - "plain"         a direct .js loader (effectivecpm popunders, social bar),
                    consumed by g7.js exactly like invoke units.
"""

import html
import re
from urllib.parse import urlsplit

import cf_edge

# The AdSense publisher id (ca-pub-…), from the environment rather than this
# file: it is per-deployment, it is the one ad id that also has to appear in
# ads.txt, and committing a placeholder would publish an ads.txt record that
# authorises nobody. Unset means the whole AdSense integration stays inert —
# empty loader, so ad_head_html() skips it and ALLOWED_SCRIPT_HOSTS never gains
# the host. Accepts either "pub-123" or "ca-pub-123" and normalises both.
#
# Read through cf_edge._setting rather than os.environ because the frontend tier
# loads no .env: os.environ alone would leave AdSense inert on the very tier that
# serves /ads.txt whenever the id was set in the shared file instead of exported.
_ADSENSE_CLIENT_RAW = cf_edge._setting("ADSENSE_CLIENT")
if _ADSENSE_CLIENT_RAW.startswith("ca-"):
    ADSENSE_PUB_ID = _ADSENSE_CLIENT_RAW[3:]
else:
    ADSENSE_PUB_ID = _ADSENSE_CLIENT_RAW
# This id is the one ad value that comes from outside the file, and it is
# interpolated into three sinks: an HTML attribute in ad_head_html(), the loader
# query string, and an ads.txt record. A stray quote breaks out of the attribute,
# and — because .strip() only trims the ends — an embedded newline appends a
# second ads.txt record, which authorises an arbitrary seller to sell this site's
# inventory. Publisher ids are only ever letters, digits and a dash, so anything
# else is a misconfiguration and leaves AdSense in its documented inert state.
if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", ADSENSE_PUB_ID or ""):
    ADSENSE_PUB_ID = ""
ADSENSE_CLIENT = f"ca-{ADSENSE_PUB_ID}" if ADSENSE_PUB_ID else ""

# The AdSense ad-slot id (data-ad-slot) for the responsive display unit below,
# from the environment like the publisher id: it comes from the AdSense
# dashboard (Ads > By ad unit), it is per-deployment, and committing a real one
# would publish another account's slot id. Digits only — anything else leaves
# the unit inert, the same as an unset variable.
_ADSENSE_SLOT_RAW = cf_edge._setting("ADSENSE_SLOT").strip()
ADSENSE_SLOT = _ADSENSE_SLOT_RAW if re.fullmatch(r"[0-9]{1,20}", _ADSENSE_SLOT_RAW) else ""

# The page-head loader scripts. Each network's tag is emitted by ad_head_html()
# into the <head> of every template. Every network is toggleable from the admin
# console (ad_network_<id> settings rows in database.AD_NETWORKS); "default_on"
# is the state until an admin ever flips it.
#
# Adstera is wired in but not configured: its loader/zone are blank because the
# zone id comes from the Adstera dashboard. Paste the tag script URL here (and
# mark it configured in database.AD_NETWORKS) and the admin console's Adstera
# switch becomes live; CSP hosts are derived, so nothing else needs editing.
#
# AdSense is configured by environment variable instead (ADSENSE_CLIENT), because
# its publisher id is also what /ads.txt has to publish. Its loader is therefore
# empty until that variable is set, which is the same not-configured state
# Adstera is in: the switch exists, nothing loads.
AD_NETWORKS = {
    # No head loader: every effectivecpm unit carries its own script, so there is
    # nothing to emit here and ad_head_html() skips it. The entry exists because
    # all nine AD_UNITS point their "network" at it — without it frontend.py's
    # per-unit network gate resolves an empty dict and falls back to a hardcoded
    # default instead of this one, so flipping default_on in database.AD_NETWORKS
    # would silently stop matching what the units actually do.
    "effectivecpm": {
        "label": "Monetag",
        "loader": "",
        "zone_id": "",
        "default_on": True,
    },
    "adstera": {
        "label": "Adstera",
        "loader": "",
        "zone_id": "",
        "default_on": False,
    },
    "adsense": {
        "label": "Google AdSense",
        "loader": (
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"
            f"?client={ADSENSE_CLIENT}"
        ) if ADSENSE_CLIENT else "",
        "zone_id": "",
        "default_on": True,
        # Google's own snippet carries crossorigin="anonymous"; without it the
        # script is fetched in no-cors mode and errors inside it are opaque.
        "extra_attrs": ('crossorigin="anonymous"',),
    },
}

AD_UNITS = {
    "leaderboard": {
        "label": "728×90 Leaderboard",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "b9ecaabfb2eb68535607db834ea25cd6/invoke.js",
        "key": "b9ecaabfb2eb68535607db834ea25cd6",
        "width": 728,
        "height": 90,
        "css": "ad-leaderboard",
    },
    "mobile": {
        "label": "320×50 Mobile",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "e2370e736cd72cd0487aacc9d159382a/invoke.js",
        "key": "e2370e736cd72cd0487aacc9d159382a",
        "width": 320,
        "height": 50,
        "css": "ad-mobile",
    },
    "native": {
        "label": "Native Banner",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://pl29657148.effectivecpmnetwork.com/"
               "80bbad99518bd76be2c470b305e22363/invoke.js",
        "key": "80bbad99518bd76be2c470b305e22363",
        "container": "container-80bbad99518bd76be2c470b305e22363",
        "css": "ad-native",
    },
    "banner_468x60": {
        "label": "Banner 468×60",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "932f5deb11bd8e5274d185a53771c6d9/invoke.js",
        "key": "932f5deb11bd8e5274d185a53771c6d9",
        "width": 468,
        "height": 60,
        "css": "ad-banner-468x60",
    },
    "banner_300x250": {
        "label": "Banner 300×250",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "fe48ed36a5a414ff4c45549d8ca1c70b/invoke.js",
        "key": "fe48ed36a5a414ff4c45549d8ca1c70b",
        "width": 300,
        "height": 250,
        "css": "ad-banner-300x250",
    },
    "banner_160x600": {
        "label": "Banner 160×600",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "1a73cccb5c8c1fc5eaaadabdf2337b43/invoke.js",
        "key": "1a73cccb5c8c1fc5eaaadabdf2337b43",
        "width": 160,
        "height": 600,
        "css": "ad-banner-160x600",
    },
    "banner_160x300": {
        "label": "Banner 160×300",
        "network": "effectivecpm",
        "kind": "invoke",
        "src": "https://www.highperformanceformat.com/"
               "0d4ff02a7517500c95db4b86644cda37/invoke.js",
        "key": "0d4ff02a7517500c95db4b86644cda37",
        "width": 160,
        "height": 300,
        "css": "ad-banner-160x300",
    },
    "popunder_entry": {
        "label": "Popunder (entry pages)",
        "network": "effectivecpm",
        "kind": "plain",
        "src": "https://pl29657147.effectivecpmnetwork.com/"
               "3c/a2/bc/3ca2bc2be8a9500d56483a6d3c9abef1.js",
    },
    "social_bar": {
        "label": "Social Bar",
        "network": "effectivecpm",
        "kind": "plain",
        "src": "https://pl29657149.effectivecpmnetwork.com/"
               "c3/64/7d/c3647d39705a5be0636159b629ed3da2.js",
    },
    "adsense_display": {
        "label": "AdSense Display (responsive)",
        "network": "adsense",
        "kind": "adsense",
        "css": "ad-adsense-display",
    },
}

def _script_url(url):
    """An https ad URL with a real host, or "" — the shape ad markup may carry.

    Adding a network means pasting a loader URL from a dashboard into the table
    above, and the two ways that goes wrong are both silent: an http:// loader is
    blocked as mixed content on an https page, and a URL whose host does not
    survive urlsplit contributes an empty entry to ALLOWED_SCRIPT_HOSTS, widening
    the CSP script-src instead of extending it. Refusing here turns either into
    the same not-configured state an unset loader already produces.
    """
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url or any(char in url for char in ' \t\n\r"\'<>'):
        return ""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        return ""
    return url


# Every script-src host the ad stack needs. Derived from the config so a new
# unit can never be added in one place and blocked by CSP in another.
ALLOWED_SCRIPT_HOSTS = sorted(
    ({urlsplit(_script_url(u.get("src"))).netloc for u in AD_UNITS.values()}
     | {urlsplit(_script_url(n.get("loader"))).netloc for n in AD_NETWORKS.values()})
    # Parenthesised because set difference binds tighter than union: without it
    # this reads as UNITS | (NETWORKS - {""}) and the rejected-unit "" that
    # _script_url exists to catch is never filtered out.
    - {""}
)

# portalfluently.com is the smart-feeder host the effectivecpm scripts inject
# (sfp.js → sbar.json → frames) after load; it is not referenced by any tag
# of ours, so it cannot be derived — listed here for the CSP builder.
SMART_FEEDER_HOST = "https://portalfluently.com"


def ad_head_html(nonce="", networks=None):
    """The <head> loader tags for every enabled network.

    networks maps network id -> enabled bool, exactly what the admin console
    writes and the backend resolves. None (no map fetched yet, or a caller
    without one) falls back to each network's config default — matching the
    fail-open behaviour of the ad cache: a backend blip should not change what
    renders. Networks without a loader are skipped regardless.
    """
    tags = []
    # Official site-ownership meta AdSense asks for during review. Harmless
    # when ads are off; Google's crawler looks for this on public pages.
    if ADSENSE_CLIENT:
        tags.append('<meta name="google-adsense-account" content="'
                    + html.escape(ADSENSE_CLIENT, quote=True) + '">')
    for net_id, net in AD_NETWORKS.items():
        loader = _script_url(net.get("loader"))
        if not loader:
            continue
        if networks is not None and not networks.get(net_id, net.get("default_on", True)):
            continue
        if networks is None and not net.get("default_on", True):
            continue
        attrs = [f'src="{html.escape(loader, quote=True)}"']
        if net.get("zone_id"):
            attrs.append(f'data-zone="{html.escape(str(net["zone_id"]), quote=True)}"')
        attrs.append("async")
        attrs.append("data-cfasync=\"false\"")
        attrs.extend(net.get("extra_attrs") or ())
        if nonce:
            attrs.append(f'nonce="{html.escape(str(nonce), quote=True)}"')
        tags.append("<script " + " ".join(attrs) + "></script>")
    return "\n  ".join(tags)


def ads_txt_body():
    """The /ads.txt file contents, or "" when no network needs one.

    Only sellers we are actually configured with are declared. An ads.txt that
    lists a publisher id we do not have would authorise an account that cannot
    serve, and an empty file is worse than none — Google treats a reachable but
    blank ads.txt as "nobody may sell this inventory", which suppresses bids. So
    the caller 404s on an empty return rather than serving an empty file.
    """
    lines = []
    if ADSENSE_PUB_ID:
        # f08c47fec0942fa0 is Google's own TAG certification id, identical for
        # every AdSense publisher — it identifies Google, not this account.
        lines.append(f"google.com, {ADSENSE_PUB_ID}, DIRECT, f08c47fec0942fa0")
    return "\n".join(lines) + "\n" if lines else ""


def ad_unit_html(key, nonce=""):
    """The full ad slot markup for one zone, or "" for an unknown key.

    The gate (zone toggle + per-user override) is applied by the caller
    (ad_unit() in frontend.py); this function only renders markup.
    """
    unit = AD_UNITS.get(key)
    if not unit:
        return ""
    if unit.get("kind") == "adsense":
        # Responsive AdSense display unit. Inert until the deployment provides
        # both the publisher id (loader + ads.txt) and the ad-slot id: serving
        # an <ins> without either would request ads for nobody. The push call
        # is a nonce script because the page CSP has no unsafe-inline.
        if not ADSENSE_CLIENT or not ADSENSE_SLOT:
            return ""
        nonce_attr = (f' nonce="{html.escape(str(nonce), quote=True)}"'
                      if nonce else "")
        return (
            f'<div class="ad-container {html.escape(str(unit.get("css", "")), quote=True)}">'
            f'<ins class="adsbygoogle" style="display:block"'
            f' data-ad-client="{html.escape(ADSENSE_CLIENT, quote=True)}"'
            f' data-ad-slot="{html.escape(ADSENSE_SLOT, quote=True)}"'
            f' data-ad-format="auto" data-full-width-responsive="true"></ins>'
            f"<script{nonce_attr}>(adsbygoogle=window.adsbygoogle||[]).push({{}});</script>"
            "</div>"
        )
    src = _script_url(unit.get("src"))
    if not src:
        return ""
    src_attr = html.escape(src, quote=True)
    if unit["kind"] == "invoke":
        # data-ad-cfg only exists on the sized banner units; the native unit
        # (pl29657148 effectivecpm invoke) is loaded without one, exactly as
        # the original markup shipped it.
        tag = f'<script type="text/plain" data-ad-src="{src_attr}"'
        if unit.get("key") and unit.get("width") and unit.get("height"):
            import json
            cfg = json.dumps({
                "key": unit["key"],
                "format": "iframe",
                "height": unit["height"],
                "width": unit["width"],
                "params": {},
            })
            # The attribute is single-quoted and json.dumps already escapes any
            # double quote inside a value, so escaping the delimiter and the
            # markup characters is what closes the breakout — and it leaves the
            # JSON's own double quotes untouched, keeping this attribute
            # byte-identical to the markup the networks were given.
            cfg_attr = html.escape(cfg, quote=False).replace("'", "&#x27;")
            tag += f" data-ad-cfg='{cfg_attr}'"
        tag += "></script>"
        if unit.get("container"):
            tag = f'<div id="{html.escape(str(unit["container"]), quote=True)}"></div>' + tag
        return f'<div class="ad-container {html.escape(str(unit["css"]), quote=True)}">{tag}</div>'
    kind_attr = ' data-ad-kind="popunder"' if key == "popunder_entry" else ""
    return f'<script type="text/plain" data-ad-src="{src_attr}"{kind_attr}></script>'

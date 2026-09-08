"""Admin API: full advertising control.

Eight switches control advertising, and five of them decide whether a zone
renders, first no wins (database.get_resolved_ad_zones): the global ads_enabled
master switch, the per-user "All Ads" toggle (users.ads_disabled), the
per-network switch that turns a head loader (Monetag / Adstera) on or off — when
EVERY network is off no advertising can work, so every zone resolves off too —
the global per-zone toggle, then that user's per-zone override. The settings
rows that back the global switches are encrypted at rest but the key names are
plaintext, and the per-user rows live in user_ad_zone_overrides — none of the
values here are sensitive, so nothing in this module decrypts.

The remaining three sit beside that chain rather than inside it, because each
decides something other than whether a zone is on:

  * the ad-block guard mode decides what a visitor running a blocker sees —
    "gate" redirects them to /blocked, "warn" shows a dismissible banner, "off"
    runs no detection at all;
  * consent-required decides whether the cookie banner must be *accepted*
    before any ad renders. It defaults off, so ads serve until a visitor
    explicitly declines; turning it on makes an unanswered banner mean no,
    which is what a deployment under consent rules wants. A decline is honoured
    either way — this switch only decides what silence means;
  * the per-page switches decide which pages may carry advertising at all,
    independently of the zones those pages share with everything else. The six
    account and credential pages default off, reproducing the hardcoded
    denylist they replace, but they are now a default an operator can overrule
    rather than a decision baked into frontend.py.

This console runs with direct database access; it is loopback-bound and
admin-only, so it is the one place every one of the eight switches can be
flipped."""
import _bootstrap  # noqa: F401

from flask import Blueprint, request, jsonify

import database as db
import auth

ads_bp = Blueprint("admin_ads", __name__)


def _zone_allowed(zone_key):
    return zone_key in db.AD_ZONES


def _page_allowed(endpoint):
    # AD_PAGES is an allowlist of ad-bearing endpoints, not merely a label map:
    # an endpoint missing from it has no row the site would ever consult, so
    # writing one would look like it worked and change nothing. Rejecting is the
    # honest answer, and it also stops a typo'd endpoint from parking a stale
    # ad_page_* row in settings.
    return endpoint in db.AD_PAGES


@ads_bp.route("/api/admin/ads", methods=["GET"])
@auth.require_admin
def api_admin_get_ads():
    zones = db.get_all_ad_zones()
    networks = [{"key": k, "label": v["label"], "enabled": db.get_network_enabled(k),
                 "configured": bool(v.get("configured"))}
                for k, v in db.AD_NETWORKS.items()]
    pages = db.get_all_ad_pages()
    return jsonify({
        "ok": True,
        "ads_enabled": db.get_ad_enabled(),
        "networks": networks,
        "zones": [{"key": k, "label": v["label"], "enabled": v["enabled"]}
                  for k, v in zones.items()],
        "guard_mode": db.get_ad_guard_mode(),
        # Shipped rather than hardcoded in the page so the console cannot drift
        # from the modes fp-guard.js actually understands: adding a mode is then
        # a database.py change alone.
        "guard_modes": list(db.AD_GUARD_MODES),
        # Still stored, still writable, still reported here — and no longer
        # consulted. Advertising is now unconditional with respect to visitor
        # consent: the master switch, the networks, the page, the zone and the
        # per-user toggles decide whether a zone renders, and this flag takes no
        # part in that. It stays in the payload because test_console.py asserts
        # the key and because a console tab left open would break without it, so
        # read the value as "what was last written here" and never as "what a
        # visitor is about to see".
        "consent_required": db.get_ad_consent_required(),
        # Already {endpoint: {label, enabled}}, which is the shape the page wants
        # keyed by endpoint — unlike zones and networks, nothing here needs the
        # key flattened into a list, and the endpoint is what the PUT path takes.
        "pages": pages,
    })


@ads_bp.route("/api/admin/ads/networks/<network>", methods=["PUT"])
@auth.require_admin
def api_admin_set_network(network):
    if network not in db.AD_NETWORKS:
        return jsonify({"ok": False, "error": "Unknown ad network"}), 400
    data = request.get_json(force=True)
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled must be true or false"}), 400
    db.set_network_enabled(network, enabled)
    return jsonify({"ok": True, "network": network, "enabled": enabled})


@ads_bp.route("/api/admin/ads", methods=["PUT"])
@auth.require_admin
def api_admin_set_ads():
    data = request.get_json(force=True)
    ads_enabled = data.get("ads_enabled")
    if not isinstance(ads_enabled, bool):
        return jsonify({"ok": False, "error": "ads_enabled must be true or false"}), 400
    db.set_ad_enabled(ads_enabled)
    return jsonify({"ok": True, "ads_enabled": ads_enabled})


@ads_bp.route("/api/admin/ads/zones/<zone_key>", methods=["PUT"])
@auth.require_admin
def api_admin_set_zone(zone_key):
    if not _zone_allowed(zone_key):
        return jsonify({"ok": False, "error": "Unknown ad zone"}), 400
    data = request.get_json(force=True)
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled must be true or false"}), 400
    db.set_ad_zone_enabled(zone_key, enabled)
    return jsonify({"ok": True, "zone": zone_key, "enabled": enabled})


@ads_bp.route("/api/admin/ads/guard-mode", methods=["PUT"])
@auth.require_admin
def api_admin_set_guard_mode():
    # This setter still writes, and writing it changes nothing a visitor
    # experiences. The guard is no longer operator-selectable: the site forces
    # "gate" whenever ads are permitted and enabled, and downgrades to "off" for
    # search crawlers and for requests that may carry no advertising, without ever
    # reading ad_guard_mode. The route is kept deliberately — the GET contract
    # test_console.py pins still includes guard_mode, and a deleted route would
    # 404 for any console tab still open — and the value is still persisted, so
    # whoever makes the choice live again finds it where it always was. Two things
    # to have in front of you while reading downwards: a PUT here changes the
    # stored row and nothing else, and the silent-degradation reasoning in the
    # comment below belongs to the era when this value was what fp-guard.js got
    # handed. The validation stays exactly as strict as when it mattered, because
    # an inert setting is no reason to start storing values nobody checked.
    data = request.get_json(force=True)
    mode = data.get("mode")
    # Checked against AD_GUARD_MODES here even though set_ad_guard_mode raises on
    # a bad mode, because the setter's ValueError would surface as a 500 and this
    # is operator input, not a bug. The valid modes go into the message: the guard
    # is the one ad setting whose wrong value degrades silently — fp-guard.js
    # falls back to banner mode on an attribute it does not recognise — so an
    # operator who mistypes should be told, not left with a site that quietly
    # stopped gating.
    if not isinstance(mode, str) or mode not in db.AD_GUARD_MODES:
        return jsonify({
            "ok": False,
            "error": "mode must be one of " + ", ".join(db.AD_GUARD_MODES),
        }), 400
    db.set_ad_guard_mode(mode)
    return jsonify({"ok": True, "guard_mode": mode})


@ads_bp.route("/api/admin/ads/consent", methods=["PUT"])
@auth.require_admin
def api_admin_set_consent_required():
    # Storage only, because advertising stopped depending on visitor consent: this
    # writes ad_consent_required and nothing downstream reads it, so an operator
    # who flips it and then reloads the site finds every ad exactly where it was.
    # The route survives for the same reasons the guard-mode route does — the GET
    # payload test_console.py pins still carries consent_required, and a console
    # tab left open would 404 on a route that vanished — and the row is kept so
    # the switch remains something a later deployment can revive. If you arrived
    # here from "I set this and nothing happened", that is the designed behaviour
    # and not a bug: what changes is what is stored, not what a visitor sees.
    data = request.get_json(force=True)
    required = data.get("required")
    # Same strict bool as every other switch here, and it matters more than most:
    # a truthy "0" or "false" string read as True would store the opposite of what
    # the operator asked for, and because nothing on the site reads this flag any
    # more, no rendering would ever betray the mistake — the wrong value would
    # simply sit in settings, uncontradicted, until someone made it live again.
    if not isinstance(required, bool):
        return jsonify({"ok": False, "error": "required must be true or false"}), 400
    db.set_ad_consent_required(required)
    return jsonify({"ok": True, "consent_required": required})


@ads_bp.route("/api/admin/ads/pages/<endpoint>", methods=["PUT"])
@auth.require_admin
def api_admin_set_page(endpoint):
    # 400 rather than 404, matching the zone route: the path is a known route and
    # the endpoint is a value in it that failed validation, not a missing
    # resource. 404 is reserved here for a user_id that does not exist.
    if not _page_allowed(endpoint):
        return jsonify({"ok": False, "error": "Unknown ad page"}), 400
    data = request.get_json(force=True)
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled must be true or false"}), 400
    db.set_ad_page_enabled(endpoint, enabled)
    return jsonify({"ok": True, "page": endpoint, "enabled": enabled})


@ads_bp.route("/api/admin/users/<user_id>/ads", methods=["GET"])
@auth.require_admin
def api_admin_get_user_ads(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    overrides = db.get_all_user_zone_overrides(user_id)
    return jsonify({
        "ok": True,
        "ads_enabled": db.get_ad_enabled(),
        "ads_disabled": db.get_user_ads_disabled(user_id),
        "resolved": db.get_resolved_ad_zones(user_id),
        "overrides": overrides,
        "zones": [{"key": k, "label": v["label"]}
                  for k, v in db.get_all_ad_zones().items()],
    })


@ads_bp.route("/api/admin/users/<user_id>/ads", methods=["PUT"])
@auth.require_admin
def api_admin_set_user_ads(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    data = request.get_json(force=True)
    ads_disabled = data.get("ads_disabled")
    if not isinstance(ads_disabled, bool):
        return jsonify({"ok": False, "error": "ads_disabled must be true or false"}), 400
    db.set_user_ads_disabled(user_id, ads_disabled)
    return jsonify({"ok": True, "ads_disabled": ads_disabled})


@ads_bp.route("/api/admin/users/<user_id>/ads/zones/<zone_key>", methods=["PUT"])
@auth.require_admin
def api_admin_set_user_zone(user_id, zone_key):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not _zone_allowed(zone_key):
        return jsonify({"ok": False, "error": "Unknown ad zone"}), 400
    data = request.get_json(force=True)
    enabled = data.get("enabled")
    if enabled is None:
        db.clear_user_zone_override(user_id, zone_key)
        return jsonify({"ok": True, "zone": zone_key, "enabled": None,
                        "cleared": True})
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled must be true, false or null"}), 400
    db.set_user_zone_override(user_id, zone_key, enabled)
    return jsonify({"ok": True, "zone": zone_key, "enabled": enabled})
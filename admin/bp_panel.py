"""Admin API: hosting panel controls.

/panel used to be configured entirely from its own process environment, so
changing what it allows meant editing a unit file and restarting both
load-balanced instances — and the two could disagree if only one was updated.
The controls now live in the shared settings table (database.PANEL_FLAGS /
PANEL_LIMITS), which both instances read, so this console changes them for the
whole fleet at once.

Nothing here is sensitive: every value is a boolean, a small integer, or the
maintenance notice text. The settings rows are encrypted at rest but the keys
are plaintext, and database.get_panel_settings() does the decrypting — so this
module never touches crypto, exactly like bp_ads.

Validation is deliberately strict about *types* and lenient about range: an
unknown flag or a non-boolean is rejected outright, while a limit outside its
declared bounds is clamped by the database layer and the clamped value is
returned, so the console always renders the number that is actually in force
rather than the one that was typed.
"""
import _bootstrap  # noqa: F401

from flask import Blueprint, request, jsonify

import database as db
import auth

panel_bp = Blueprint("admin_panel_controls", __name__)


def _snapshot():
    """The full control set, shaped for the page.

    One database read for everything (get_panel_settings), with the metadata
    each control declares folded in so the template does not hard-code a second
    copy of the labels — adding a flag in database.py makes it appear here.
    """
    settings = db.get_panel_settings()
    return {
        "ok": True,
        "flags": [
            {"key": key, "label": meta["label"], "detail": meta["detail"],
             "default": bool(meta["default"]),
             "enabled": settings["flags"].get(key, bool(meta["default"]))}
            for key, meta in db.PANEL_FLAGS.items()
        ],
        "limits": [
            {"key": key, "label": meta["label"], "unit": meta["unit"],
             "low": meta["low"], "high": meta["high"], "default": meta["default"],
             "value": settings["limits"].get(key, meta["default"])}
            for key, meta in db.PANEL_LIMITS.items()
        ],
        "maintenance_message": settings["maintenance_message"],
        "message_max": db.PANEL_MESSAGE_MAX_CHARS,
    }


@panel_bp.route("/api/admin/panel", methods=["GET"])
@auth.require_admin
def api_admin_get_panel():
    return jsonify(_snapshot())


@panel_bp.route("/api/admin/panel/flags/<flag>", methods=["PUT"])
@auth.require_admin
def api_admin_set_panel_flag(flag):
    if flag not in db.PANEL_FLAGS:
        return jsonify({"ok": False, "error": "Unknown panel flag"}), 400
    data = request.get_json(force=True, silent=True) or {}
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled must be true or false"}), 400
    db.set_panel_flag(flag, enabled)
    return jsonify({"ok": True, "flag": flag, "enabled": enabled})


@panel_bp.route("/api/admin/panel/limits/<limit>", methods=["PUT"])
@auth.require_admin
def api_admin_set_panel_limit(limit):
    spec = db.PANEL_LIMITS.get(limit)
    if not spec:
        return jsonify({"ok": False, "error": "Unknown panel limit"}), 400
    data = request.get_json(force=True, silent=True) or {}
    value = data.get("value")
    # bool is a subclass of int, so True would otherwise sail through as 1 and
    # silently set a limit to a value nobody typed.
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return jsonify({"ok": False, "error": "value must be a number"}), 400
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "value must be a whole number"}), 400
    # Reported rather than silently accepted: the database layer clamps on write
    # and on read, so a rejected-looking number would still change the setting.
    # Saying so up front means the operator learns the bound instead of guessing
    # why the value they sent came back different.
    if parsed < spec["low"] or parsed > spec["high"]:
        return jsonify({
            "ok": False,
            "error": f"{spec['label']} must be between {spec['low']} and "
                     f"{spec['high']} {spec['unit']}",
        }), 400
    stored = db.set_panel_limit(limit, parsed)
    return jsonify({"ok": True, "limit": limit, "value": stored})


@panel_bp.route("/api/admin/panel/maintenance-message", methods=["PUT"])
@auth.require_admin
def api_admin_set_maintenance_message():
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message")
    if not isinstance(message, str):
        return jsonify({"ok": False, "error": "message must be text"}), 400
    if len(message) > db.PANEL_MESSAGE_MAX_CHARS:
        return jsonify({
            "ok": False,
            "error": f"message must be {db.PANEL_MESSAGE_MAX_CHARS} characters or fewer",
        }), 400
    # An empty message restores the default instead of blanking the banner, so
    # the stored value is echoed back rather than the submitted one.
    stored = db.set_panel_maintenance_message(message)
    return jsonify({"ok": True, "message": stored})

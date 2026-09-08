"""Admin API: application errors from HeatWave — list, flag/unflag, purge old.
Mirrors bp_reviews.py; reads directly from reviews_db.
A HeatWave outage empties this page rather than breaking the console."""
import _bootstrap  # noqa: F401
from flask import Blueprint, request, jsonify
import auth
import reviews_db

errors_bp = Blueprint("admin_errors", __name__)


@errors_bp.route("/api/admin/errors", methods=["GET"])
@auth.require_admin
def api_admin_errors():
    # ?state=all|flagged|unflagged — the console's moderation buckets.
    state = (request.args.get("state") or "").strip().lower()
    if state not in ("all", "flagged", "unflagged"):
        state = "unflagged"
    category = (request.args.get("category") or "").strip().lower() or None
    limit = request.args.get("limit", default=200, type=int)
    offset = request.args.get("offset", default=0, type=int)
    only_flagged = state == "flagged"
    return jsonify({"ok": True,
                    "errors": reviews_db.get_app_errors(limit=limit, offset=offset,
                                                        only_flagged=only_flagged,
                                                        category=category),
                    "flagged": reviews_db.count_flagged_app_errors(category=category),
                    "store": reviews_db.health(),
                    "state": state, "limit": limit, "offset": offset})


@errors_bp.route("/api/admin/errors/flag", methods=["POST"])
@auth.require_admin
def api_admin_flag_error():
    data = request.get_json(force=True) or {}
    if not data.get("id"):
        return jsonify({"ok": False, "error": "id required"}), 400
    flag = bool(data.get("flag", True))
    ok = reviews_db.flag_app_error(data["id"], flagged=flag)
    return jsonify({"ok": ok, "flagged": reviews_db.count_flagged_app_errors()})


@errors_bp.route("/api/admin/errors/purge", methods=["POST"])
@auth.require_admin
def api_admin_purge_errors():
    data = request.get_json(force=True) or {}
    error_id = data.get("id")
    if error_id:
        deleted = reviews_db.delete_app_error(error_id)
        return jsonify({"ok": deleted > 0, "deleted": deleted})
    return jsonify({"ok": False, "error": "id required"}), 400


@errors_bp.route("/api/admin/config/console-debug", methods=["GET"])
@auth.require_admin
def api_admin_get_console_debug():
    return jsonify({"ok": True, "console_debug_enabled": reviews_db.is_console_debug_enabled()})


@errors_bp.route("/api/admin/config/console-debug", methods=["POST"])
@auth.require_admin
def api_admin_set_console_debug():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled", False))
    ok = reviews_db.set_console_debug_enabled(enabled)
    return jsonify({"ok": bool(ok), "console_debug_enabled": reviews_db.is_console_debug_enabled()})
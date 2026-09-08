"""Admin API: user reviews — list pending/all, approve, reject (delete).
Mirrors bp_devices.py; runs locally with direct database access.

Unlike every other admin blueprint, this one does not touch the ATP. Reviews
live on HeatWave (MySQL) in reviews_db.py, so nothing here goes through
database.py — see reviews_db.py's header for why the two stores are split.
A HeatWave outage empties this page rather than breaking the console.
"""
import _bootstrap  # noqa: F401
from flask import Blueprint, request, jsonify
import reviews_db
import auth

reviews_bp = Blueprint("admin_reviews", __name__)


@reviews_bp.route("/api/admin/reviews", methods=["GET"])
@auth.require_admin
def api_admin_reviews():
    # ?filter=pending|approved|all — the console's moderation buckets.
    # ?pending=1 is accepted as legacy shorthand for the pending bucket.
    state = (request.args.get("filter") or "").strip().lower()
    if state not in ("pending", "approved", "all"):
        state = "pending" if request.args.get("pending") in ("1", "true", "yes") else "all"
    limit = request.args.get("limit", default=200, type=int)
    offset = request.args.get("offset", default=0, type=int)
    return jsonify({"ok": True,
                    "reviews": reviews_db.get_reviews(limit=limit, offset=offset, state=state),
                    "pending": reviews_db.count_pending_reviews(),
                    "store": reviews_db.health(),
                    "filter": state, "limit": limit, "offset": offset})


@reviews_bp.route("/api/admin/reviews/approve", methods=["POST"])
@auth.require_admin
def api_admin_approve_review():
    data = request.get_json(force=True) or {}
    if not data.get("id"):
        return jsonify({"ok": False, "error": "id required"}), 400
    ok = reviews_db.approve_review(data["id"])
    return jsonify({"ok": ok, "pending": reviews_db.count_pending_reviews()})


@reviews_bp.route("/api/admin/reviews", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_review():
    data = request.get_json(force=True) or {}
    if not data.get("id"):
        return jsonify({"ok": False, "error": "id required"}), 400
    deleted = reviews_db.delete_review(data["id"])
    return jsonify({"ok": True, "deleted": deleted, "pending": reviews_db.count_pending_reviews()})

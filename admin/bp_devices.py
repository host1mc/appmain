"""Admin API: device flags, device policy and per-scope device caps. Ported
from backend.py; runs locally with direct database access."""
import _bootstrap  # noqa: F401
from flask import Blueprint, request, jsonify
import database as db
import auth
import reviews_db

devices_bp = Blueprint("admin_devices", __name__)


@devices_bp.route("/api/admin/device-flags", methods=["GET"])
@auth.require_admin
def api_device_flags():
    only_new = request.args.get("unreviewed") in ("1", "true", "yes")
    limit = request.args.get("limit", default=200, type=int)
    offset = request.args.get("offset", default=0, type=int)
    return jsonify({"ok": True,
                    "flags": db.get_device_events(limit=limit, offset=offset, only_unreviewed=only_new),
                    "unreviewed": db.count_unreviewed_device_events(),
                    "limit": limit, "offset": offset})


@devices_bp.route("/api/admin/device-flags/review", methods=["POST"])
@auth.require_admin
def api_review_device_flags():
    data = request.get_json(force=True) or {}
    ids = data.get("event_ids")
    if data.get("id"):
        ids = [data["id"]]
    db.review_device_events(event_ids=ids, user_id=data.get("user_id"))
    return jsonify({"ok": True, "unreviewed": db.count_unreviewed_device_events()})


@devices_bp.route("/api/admin/device-flags", methods=["DELETE"])
@auth.require_admin
def api_delete_device_flags():
    """Permanently delete flags — by explicit event ids, or every flag of one
    account. Deliberately mirrors review: a bare body deletes nothing."""
    data = request.get_json(force=True) or {}
    ids = data.get("event_ids")
    if data.get("id"):
        ids = [data["id"]]
    user_id = data.get("user_id")
    if not ids and not user_id:
        return jsonify({"ok": False, "error": "Nothing to delete"}), 400
    deleted = db.delete_device_events(event_ids=ids, user_id=user_id)
    return jsonify({"ok": True, "deleted": deleted,
                    "unreviewed": db.count_unreviewed_device_events()})


@devices_bp.route("/api/admin/flag-context", methods=["GET"])
@auth.require_admin
def api_flag_context():
    """Everything known about one flag, from every angle: the account, its bots,
    sessions and login history, the device it came from, the network it came
    from, and every other account sharing either. Drives the Flags page modal.

    A flag raised by a blocked signup has no account behind it, so user_id is
    optional — the device and network halves still resolve.
    """
    user_id = (request.args.get("user_id") or "").strip() or None
    lookup_hash = (request.args.get("lookup_hash") or "").strip() or None
    ip_address = (request.args.get("ip") or "").strip() or None

    out = {"ok": True, "user": None, "bots": [], "fingerprint": None,
           "sessions": [], "flags": [],
           "device_accounts": [], "ip_accounts": []}

    if user_id:
        user = db.get_user(user_id)
        if user:
            user.pop("password", None)
            banned, ban_reason = db.is_user_banned(user_id)
            user["is_banned"] = banned
            user["banned_reason"] = ban_reason
            out["user"] = user
            bots = reviews_db.get_user_bots(user_id)
            # get_user_bots decrypts every token; only the masked form may leave
            # this process.
            for b in bots:
                b.pop("token", None)
                b.pop("token_enc", None)
            out["bots"] = bots
            fp = db.fingerprint_status(user_id)
            out["fingerprint"] = fp
            out["sessions"] = db.get_user_sessions(user_id)
            out["flags"] = db.get_device_events(limit=100, user_id=user_id)
            lookup_hash = lookup_hash or fp.get("lookup_hash")
            ip_address = ip_address or fp.get("ip_address")

    if lookup_hash:
        out["device_accounts"] = [
            {"id": u.get("uid"), "username": u.get("username"),
             "email": u.get("email"), "display_name": u.get("display_name"),
             "account_type": u.get("account_type") or "trial",
             "is_banned": db._truthy(u.get("is_banned")),
             "created_at": u.get("created_at"), "bound_at": u.get("bound_at")}
            for u in db.accounts_on_device(lookup_hash=lookup_hash)
        ]
    if ip_address:
        out["ip_accounts"] = [
            {"id": u.get("uid"), "username": u.get("username"),
             "email": u.get("email"), "display_name": u.get("display_name"),
             "account_type": u.get("account_type") or "trial",
             "is_banned": db._truthy(u.get("is_banned")),
             "created_at": u.get("created_at")}
            for u in db.accounts_on_ip(ip_address)
        ]
    out["lookup_hash"] = lookup_hash
    out["ip_address"] = ip_address
    return jsonify(out)

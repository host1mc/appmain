"""Admin API: users and accounts. Ported from backend.py; runs locally with
direct database access, so there is no internal-auth hop."""
import _bootstrap  # noqa: F401
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify

import database as db
import engine_client  # noqa: F401
import auth
from bp_ops import _trial_expired, _nudge_engine

users_bp = Blueprint("admin_users", __name__)

_FLAG_COLUMNS = ("email_verified", "github_verified", "is_banned", "is_active", "ads_disabled")


def _normalize_user(u):
    """Oracle stores the flag columns as VARCHAR2 '0'/'1', so they arrive here
    as strings — and the string '0' is truthy in JavaScript, which made every
    unverified account render as "Verified" in the console. Real booleans at
    the API boundary keep the templates' plain `u.flag ? ... : ...` checks
    honest."""
    u.pop("password", None)
    for flag in _FLAG_COLUMNS:
        u[flag] = db._truthy(u.get(flag))
    return u


@users_bp.route("/api/admin/users", methods=["GET"])
@auth.require_admin
def api_list_users():
    users = db.list_users()
    return jsonify([_normalize_user(u) for u in users])


@users_bp.route("/api/admin/users", methods=["POST"])
@auth.require_admin
def api_create_user():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    display = (data.get("display_name") or "").strip()
    email = (data.get("email") or "").strip()
    email_verified = data.get("email_verified", False)
    slots = int(data.get("slots", 1))
    account_type = data.get("account_type", "trial")
    if account_type not in ("trial", "paid"):
        account_type = "trial"
    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required"}), 400
    ok, res = db.create_user(username, password, display, slots, email=email, account_type=account_type, email_verified=email_verified)
    if not ok:
        return jsonify({"ok": False, "error": res}), 400
    return jsonify({"ok": True, "user_id": res})


@users_bp.route("/api/admin/users/<user_id>", methods=["GET"])
@auth.require_admin
def api_user_detail(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    bots = db.get_user_bots(user_id)
    # get_user_bots decrypts every token; the page only ever displays the masked
    # form, so the plaintext must not leave this process. token_masked stays.
    for b in bots:
        b.pop("token", None)
        b.pop("token_enc", None)
    user = _normalize_user(user)
    fingerprint = db.fingerprint_status(user_id)
    shared = [
        {"id": u.get("uid"), "username": u.get("username"),
         "account_type": u.get("account_type") or "trial",
         "is_banned": db._truthy(u.get("is_banned")),
         "bound_at": u.get("bound_at")}
        for u in db.accounts_on_device(lookup_hash=fingerprint.get("lookup_hash"))
        if str(u.get("uid")) != str(user_id)
    ]
    return jsonify({"ok": True, "user": user, "bots": bots, "fingerprint": fingerprint,
                    "shared_accounts": shared,
                    "container_slots": db.get_panel_container_slots(user_id),
                    "container_slots_default": db.get_panel_limit("max_servers"),
                    "container_slots_high": db.PANEL_CONTAINER_SLOTS_HIGH,
                    "fingerprint_history": db.get_fingerprint_history(user_id, limit=50),
                    "flags": db.get_device_events(limit=200, offset=0, user_id=user_id)})


@users_bp.route("/api/admin/users/<user_id>", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_user(user_id):
    db.erase_user(user_id)
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/reset-fingerprint", methods=["POST"])
@auth.require_admin
def api_reset_fingerprint(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    db.reset_fingerprint(user_id)
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/slots", methods=["PUT"])
@auth.require_admin
def api_update_slots(user_id):
    data = request.get_json(force=True)
    slots = int(data.get("slots", 1))
    db.update_user_slots(user_id, slots)
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/container-slots", methods=["PUT"])
@auth.require_admin
def api_update_container_slots(user_id):
    """Grant this account a number of hosting containers, or clear the grant.

    A different thing from /slots above, which is the Minecraft status-bot slot
    count and cascades bot deletions off itself. This one only writes
    panel_users.container_slots, which /panel reads as its per-account server
    quota; null clears the grant so the account falls back to the fleet figure
    (the max_servers panel limit) and 0 switches hosting off for them.
    """
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    slots = data.get("slots")
    # bool is a subclass of int, so True would otherwise sail through as a grant
    # of one container that nobody typed. Empty string and null are how the page
    # spells "clear the grant".
    if isinstance(slots, bool) or not isinstance(slots, (int, float, str, type(None))):
        return jsonify({"ok": False, "error": "slots must be a number, or null to clear"}), 400
    high = db.PANEL_CONTAINER_SLOTS_HIGH
    if slots is not None and str(slots).strip():
        try:
            parsed = int(str(slots).strip())
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "slots must be a whole number"}), 400
        # Reported rather than clamped, for the reason bp_panel's limit route
        # gives: a clamped write still changes the grant, so the operator would
        # be told "ok" for a number that is not the one in force.
        if parsed < 0 or parsed > high:
            return jsonify({"ok": False,
                            "error": f"container slots must be between 0 and {high}"}), 400
    try:
        stored = db.set_panel_container_slots(user_id, slots)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "container_slots": stored,
                    "container_slots_default": db.get_panel_limit("max_servers")})


@users_bp.route("/api/admin/users/<user_id>/account-type", methods=["PUT"])
@auth.require_admin
def api_set_account_type(user_id):
    data = request.get_json(force=True)
    account_type = data.get("account_type", "trial")
    if account_type not in ("trial", "paid"):
        return jsonify({"ok": False, "error": "Invalid account type"}), 400
    db.set_user_account_type(user_id, account_type)
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/ban", methods=["POST"])
@auth.require_admin
def api_admin_ban_user(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    db.ban_user(user_id, "Banned by admin")
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/unban", methods=["POST"])
@auth.require_admin
def api_admin_unban_user(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    db.unban_user(user_id)
    return jsonify({"ok": True})


@users_bp.route("/api/admin/users/<user_id>/bots/stop-all", methods=["POST"])
@auth.require_admin
def api_admin_stop_all_bots(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    bots = db.get_user_bots(user_id)
    for bot in bots:
        db.set_bot_running(bot["id"], False)
    return jsonify({"ok": True, "stopped": len(bots)})


@users_bp.route("/api/admin/users/<user_id>/bots/start-all", methods=["POST"])
@auth.require_admin
def api_admin_start_all_bots(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    bots = db.get_user_bots(user_id)
    started = 0
    skipped = 0
    for bot in bots:
        if not bot.get("server_ip") or not bot.get("channel_id"):
            skipped += 1
            continue
        if _trial_expired(bot.get("uid")):
            skipped += 1
            continue
        db.set_bot_running(bot["id"], True)
        _nudge_engine(bot["id"])
        started += 1
    return jsonify({"ok": True, "started": started, "skipped": skipped})


@users_bp.route("/api/admin/users/<user_id>/extend-trial", methods=["POST"])
@auth.require_admin
def api_admin_extend_trial(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    # Must be the same clock database.py reads back with: is_trial_expired()
    # compares this column against the tz-aware _utcnow(), and a naive value
    # there raises a TypeError that is swallowed into "not expired" indefinitely.
    new_expiry = (db._utcnow() + timedelta(days=7)).isoformat()
    db.set_user_trial_expiry(user_id, new_expiry)
    return jsonify({"ok": True, "trial_expires_at": new_expiry})


@users_bp.route("/api/admin/users/<user_id>/trial-expiry", methods=["PUT"])
@auth.require_admin
def api_admin_set_trial_expiry(user_id):
    """Set this account's trial expiry to an explicit date and time, or clear it.

    Body {"trial_expires_at": "<ISO-8601 datetime>"} stores exactly that moment;
    {"trial_expires_at": null} (or "") clears the column so the trial never
    expires. A timezone-naive value is read as UTC, matching _parse_iso and
    is_trial_expired; the stored value is always tz-aware ISO, because
    is_trial_expired() compares the column against the tz-aware _utcnow() and a
    naive value there used to read as "not expired" indefinitely.
    """
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict) or "trial_expires_at" not in data:
        return jsonify({"ok": False,
                        "error": "trial_expires_at required (ISO datetime, or null to clear)"}), 400
    raw = data.get("trial_expires_at")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        db.set_user_trial_expiry(user_id, None)
        return jsonify({"ok": True, "trial_expires_at": None, "cleared": True})
    if not isinstance(raw, str):
        return jsonify({"ok": False,
                        "error": "trial_expires_at must be an ISO datetime string, or null to clear"}), 400
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return jsonify({"ok": False,
                        "error": "trial_expires_at is not a valid ISO datetime"}), 400
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    value = when.isoformat()
    db.set_user_trial_expiry(user_id, value)
    return jsonify({"ok": True, "trial_expires_at": value})


@users_bp.route("/api/admin/users/<user_id>/email-verified", methods=["PUT"])
@auth.require_admin
def api_set_email_verified(user_id):
    data = request.get_json(force=True)
    verified = bool(data.get("verified"))
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    db.verify_user_email(user_id, verified)
    return jsonify({"ok": True, "email_verified": verified})


@users_bp.route("/api/admin/users/<user_id>/login-as", methods=["POST"])
@auth.require_admin
def api_admin_login_as(user_id):
    """Mint a single-use impersonation ticket for this user.

    The record is written straight into the shared session store (the admin
    console runs with direct database access) and consumed by the frontend's
    /impersonate/<token> route, which deletes it on first use. Short TTL and
    one-time use keep a leaked URL useless after a single fetch."""
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    import secrets
    token = secrets.token_urlsafe(32)
    uid = str(user["uid"])
    username = user.get("username", "unknown")
    # There is no admin credential anymore (the console has no login), so the
    # impersonator marker identifies the source as the local loopback console.
    sess_data = {"user_id": uid, "username": username, "_impersonator": "console (loopback)"}
    db.create_session(token, sess_data, max_age=120)
    return jsonify({"ok": True, "token": token, "user_id": uid})


@users_bp.route("/api/admin/users/<user_id>/reset-password", methods=["POST"])
@auth.require_admin
def api_admin_reset_password(user_id):
    data = request.get_json(force=True)
    password = data.get("password") or ""
    user = db.get_user(user_id)
    if not user:
        return jsonify({"ok": False, "error": "Not found"}), 404
    ok, res = db.admin_set_user_password(user_id, password)
    if not ok:
        return jsonify({"ok": False, "error": res}), 400
    # The old password's cookies would otherwise keep working: kill every
    # session so the reset actually locks out whoever was signed in.
    revoked = len(db.get_user_sessions(user_id))
    db.delete_user_sessions(user_id)
    # The password itself is never echoed back, not even its length.
    return jsonify({"ok": True, "sessions_revoked": revoked})

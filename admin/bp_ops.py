"""Admin API: SMTP config, sessions, bot control and engine health.
Ported from backend.py; runs locally with direct database access."""
import _bootstrap  # noqa: F401
import smtplib
import email.mime.text
from flask import Blueprint, request, jsonify
import database as db
import engine_client
import auth

ops_bp = Blueprint("admin_ops", __name__)

# The only two values mc_status2.fetch_status() honours; anything else it
# silently rewrites to "java", so an unknown edition is rejected here instead of
# being stored and then ignored.
BOT_EDITIONS = ("java", "bedrock")

# engine.py's tick does max(15, update_interval), so a smaller number does not
# poll faster — it just misrepresents what the bot is doing. Reject it.
MIN_UPDATE_INTERVAL = 15


def _trial_expired(user_id):
    """The owner's trial state, or None when it cannot be determined.

    database.is_trial_expired() can raise on a row it cannot read. That is the
    vendored copy's behaviour and not this console's to patch, so an unanswerable
    trial state is reported as unknown rather than costing the operator the whole
    fleet view.
    """
    try:
        return db.is_trial_expired(user_id)
    except Exception:
        return None


def _profile_prefix(profile):
    """Map the UI profile name ("auth" | "warn") to the settings key prefix
    ("smtp" | "warn_smtp"). Anything else falls back to the login/OTP profile."""
    return "warn_smtp" if (profile or "auth") == "warn" else "smtp"


@ops_bp.route("/api/admin/smtp-config", methods=["GET"])
@auth.require_admin
def api_get_smtp_config():
    # get_smtp_config() returns plaintext (database.py decrypts on read), so the
    # credentials are dropped here rather than decrypted again: the form does not
    # need them back, and an empty field means "keep what is stored".
    prefix = _profile_prefix(request.args.get("profile", "auth"))
    cfg = db.get_smtp_config(prefix)
    has_user, has_pass = bool(cfg.get(prefix + "_user")), bool(cfg.get(prefix + "_pass"))
    cfg.pop(prefix + "_user", None)
    cfg.pop(prefix + "_pass", None)
    return jsonify({"ok": True, "config": cfg, "profile": prefix,
                    "has_user": has_user, "has_pass": has_pass})


@ops_bp.route("/api/admin/smtp-config", methods=["PUT"])
@auth.require_admin
def api_save_smtp_config():
    data = request.get_json(force=True)
    prefix = _profile_prefix(data.get("profile", request.args.get("profile", "auth")))
    host = data.get("host", "").strip()
    port = max(1, min(65535, int(data.get("port", 587))))
    user = data.get("user", "").strip()
    password = data.get("password", "")
    from_addr = data.get("from_addr", "").strip()
    if not host or not from_addr:
        return jsonify({"ok": False, "error": "Host and from address required"}), 400
    db.save_smtp_config(host, port, user, password, from_addr, prefix=prefix)
    return jsonify({"ok": True})


@ops_bp.route("/api/admin/smtp-test", methods=["POST"])
@auth.require_admin
def api_test_smtp():
    data = request.get_json(force=True, silent=True) or {}
    prefix = _profile_prefix(data.get("profile", request.args.get("profile", "auth")))
    to_addr = (data.get("to_addr") or "").strip()
    try:
        cfg = db.get_smtp_config(prefix)
        host = cfg.get(prefix + "_host")
        port = max(1, min(65535, int(cfg.get(prefix + "_port", 587))))
        # Already plaintext — get_smtp_config decrypts.
        user = cfg.get(prefix + "_user") or ""
        password = cfg.get(prefix + "_pass") or ""
        from_addr = cfg.get(prefix + "_from")
        if not host or not user or not password or not from_addr:
            return jsonify({"ok": False, "error": "SMTP not fully configured"}), 400
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            s.login(user, password)
            if to_addr:
                # Same construction as database._send_raw: the From header must
                # be present, or the provider stamps the authenticated account
                # (Gmail) and the test can't prove the saved From is honoured.
                tmsg = email.mime.text.MIMEText(
                    "This is a test email from the admin console.\n")
                tmsg["Subject"] = "SMTP test"
                tmsg["From"] = f"MC Status <{from_addr}>"
                tmsg["To"] = to_addr
                s.send_message(tmsg)
        if to_addr:
            return jsonify({"ok": True,
                            "message": f"Connection successful — test email sent to {to_addr}"})
        return jsonify({"ok": True, "message": "Connection successful"})
    except Exception as e:
        return jsonify({"ok": False, "error": "SMTP test failed: " + str(e)}), 400


@ops_bp.route("/api/admin/smtp-diagnose", methods=["GET"])
@auth.require_admin
def api_smtp_diagnose():
    prefix = _profile_prefix(request.args.get("profile", "auth"))
    cfg = db.get_smtp_config(prefix)
    return jsonify({
        "ok": True,
        "config_keys": list(cfg.keys()),
        "has_host": bool(cfg.get(prefix + "_host")),
        "has_user": bool(cfg.get(prefix + "_user")),
        "has_pass": bool(cfg.get(prefix + "_pass")),
        "db_type": "oracle",
    })


@ops_bp.route("/api/admin/sessions", methods=["GET"])
@auth.require_admin
def api_list_sessions():
    user_id = request.args.get("user_id")
    if user_id:
        sessions = db.get_user_sessions(user_id)
    else:
        sessions = db.get_all_sessions(limit=200)
    return jsonify({"ok": True, "sessions": sessions})


@ops_bp.route("/api/admin/sessions/<session_id>", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_session(session_id):
    db.delete_session(session_id)
    return jsonify({"ok": True})


@ops_bp.route("/api/admin/sessions/user/<user_id>/revoke-all", methods=["POST"])
@auth.require_admin
def api_revoke_user_sessions(user_id):
    db.delete_user_sessions(user_id)
    return jsonify({"ok": True})


# ── Admin bot control (delegated to the engine) ──

@ops_bp.route("/api/admin/engine/health", methods=["GET"])
@auth.require_admin
def api_admin_engine_health():
    payload, code = engine_client.health()
    return jsonify(payload), code


# Start/stop write the bots.running flag (1 = on, 0 = off) straight to the
# HeatWave bots store instead of delegating to engine_client: every engine
# re-reads list_running_bots() on each tick, so the flag is the single control
# surface — a console running on a different host than the engine, or an
# engine that is momentarily down, still applies. That is also what makes two
# deployments on two VPSes share one control: both watch the same rows.
#
# Bots are keyed by (uid, slot): there is no global bot id any more. URLs
# carry both halves, and batch bodies send "uid:slot" strings.

import reviews_db
from crypto_util import mask


def _parse_bot_ref(raw):
    """A "uid:slot" pair, or None when the string is not one."""
    text = str(raw or "").strip()
    if ":" not in text:
        return None
    uid, _sep, slot_text = text.partition(":")
    uid = uid.strip()
    if not uid:
        return None
    try:
        slot = int(slot_text)
    except (TypeError, ValueError):
        return None
    return uid, slot


def _set_bot_running_batch(refs, running):
    """Apply the flag to each "uid:slot". Returns {ref: {"ok"|"error"}}."""
    results = {}
    for raw in refs or []:
        ref = _parse_bot_ref(raw)
        key = str(raw)
        if ref is None:
            results[key] = {"error": "invalid id (expected uid:slot)"}
            continue
        uid, slot = ref
        bot = reviews_db.get_bot(uid, slot)
        if not bot:
            results[key] = {"error": "not found"}
            continue
        if running and _trial_expired(uid):
            results[key] = {"error": "trial expired"}
            continue
        if running and (not bot.get("server_ip") or not bot.get("channel_id")):
            results[key] = {"error": "missing server_ip or channel_id"}
            continue
        reviews_db.set_bot_running(uid, slot, running)
        if running:
            _nudge_engine(uid, slot)
        results[key] = {"ok": True}
    return results


def _nudge_engine(uid, slot):
    """Make a freshly started bot publish on the engine's very next tick.

    The flag alone is the source of truth and a down engine reconciles when it
    returns — but a stale tick lease would otherwise make the first publish
    wait out a full interval, and a restarted engine needs its process-local
    throttle dropped too. Both are what the engine's own start endpoint does,
    so best-effort mirror them here: never fail the admin response because the
    engine is unreachable or rejects the bot.
    """
    try:
        reviews_db.clear_bot_claim(uid, slot)
    except Exception:
        pass
    try:
        engine_client.start_bot(uid, slot)
    except Exception:
        pass


@ops_bp.route("/api/admin/bots/<uid>/<int:slot>/stop", methods=["POST"])
@auth.require_admin
def api_admin_stop_bot(uid, slot):
    if not reviews_db.get_bot(uid, slot):
        return jsonify({"ok": False, "error": "Bot not found"}), 404
    reviews_db.set_bot_running(uid, slot, False)
    return jsonify({"ok": True})


@ops_bp.route("/api/admin/bots/<uid>/<int:slot>/start", methods=["POST"])
@auth.require_admin
def api_admin_start_bot(uid, slot):
    bot_info = reviews_db.get_bot(uid, slot)
    if not bot_info:
        return jsonify({"ok": False, "error": "Bot not found"}), 404
    if _trial_expired(uid):
        return jsonify({"ok": False, "error": "Trial expired — cannot start bot"}), 403
    if not bot_info.get("server_ip") or not bot_info.get("channel_id"):
        return jsonify({"ok": False, "error": "Bot missing server_ip or channel_id"}), 400
    reviews_db.set_bot_running(uid, slot, True)
    _nudge_engine(uid, slot)
    return jsonify({"ok": True})


@ops_bp.route("/api/admin/bots/stop", methods=["POST"])
@auth.require_admin
def api_admin_batch_stop_bots():
    data = request.get_json(force=True, silent=True) or {}
    results = _set_bot_running_batch(data.get("ids"), False)
    return jsonify({"ok": True, "results": results})


@ops_bp.route("/api/admin/bots/start", methods=["POST"])
@auth.require_admin
def api_admin_batch_start_bots():
    data = request.get_json(force=True, silent=True) or {}
    results = _set_bot_running_batch(data.get("ids"), True)
    return jsonify({"ok": True, "results": results})


@ops_bp.route("/api/admin/bots/<uid>/<int:slot>", methods=["DELETE"])
@auth.require_admin
def api_admin_delete_bot(uid, slot):
    # Best-effort stop: a dead engine must not make bots undeletable.
    engine_client.stop_bot(uid, slot)
    reviews_db.set_bot_running(uid, slot, False)
    reviews_db.delete_bot(uid, slot)
    return jsonify({"ok": True})


# ── Fleet view and bot configuration ──

@ops_bp.route("/api/admin/bots", methods=["GET"])
@auth.require_admin
def api_admin_list_bots():
    # The engine runs on the fleet's host, not the operator's laptop, so a
    # refused connection is the normal case. engine_client.health() already
    # converts that into ({"ok": False, ...}, 503) rather than raising, and the
    # fleet table has to render either way — so the engine's verdict travels
    # inside this 200 instead of becoming the page's status code.
    engine_payload, _ = engine_client.health()

    # is_trial_expired() and get_user() open their own connection per call, and
    # one owner commonly runs several bots — memoise per user_id, not per row.
    owners, expired = {}, {}
    bots = []
    for row in reviews_db.list_all_bots():
        user_id = row.get("uid")
        if user_id not in owners:
            owner = db.get_user(user_id)
            owners[user_id] = owner["username"] if owner else None
            expired[user_id] = _trial_expired(user_id)
        bots.append({
            # Bots are addressed by (uid, slot); "id" stays as the slot for
            # display, and "ref" is what the mutating endpoints take.
            "id": row.get("slot_index"),
            "ref": f"{user_id}:{row.get('slot_index')}",
            "user_id": user_id,
            "username": owners[user_id],
            "trial_expired": expired[user_id],
            "name": row.get("name"),
            "server_ip": row.get("server_ip"),
            "server_port": row.get("server_port"),
            "edition": row.get("edition"),
            "update_interval": row.get("update_interval"),
            "channel_id": row.get("channel_id"),
            "message_id": row.get("message_id"),
            "last_error": row.get("last_error"),
            "running": bool(row.get("running")),
            # The row arrives with the decrypted token in it. Only the preview
            # crosses to the browser.
            "token_masked": mask(row.get("token")),
        })
    return jsonify({"ok": True, "bots": bots, "engine": engine_payload})


@ops_bp.route("/api/admin/bots/<uid>/<int:slot>/config", methods=["GET"])
@auth.require_admin
def api_admin_get_bot_config(uid, slot):
    bot = reviews_db.get_bot(uid, slot)
    if not bot:
        return jsonify({"ok": False, "error": "Not found"}), 404
    owner = db.get_user(uid)
    # Whitelisted field by field rather than popping `token`/`token_enc` off the
    # row: a column added to the bots store upstream must not become a new leak
    # here by default.
    return jsonify({"ok": True, "bot": {
        "id": bot.get("slot_index"),
        "ref": f"{uid}:{slot}",
        "user_id": uid,
        "username": owner["username"] if owner else None,
        "name": bot.get("name"),
        "server_ip": bot.get("server_ip"),
        "server_port": bot.get("server_port"),
        "edition": bot.get("edition"),
        "update_interval": bot.get("update_interval"),
        "guild_id": bot.get("guild_id"),
        "channel_id": bot.get("channel_id"),
        "slot_index": bot.get("slot_index"),
        "running": bool(bot.get("running")),
        "message_id": bot.get("message_id"),
        "embed": bot.get("embed"),
        "token_masked": bot.get("token_masked"),
    }})


@ops_bp.route("/api/admin/bots/<uid>/<int:slot>/config", methods=["PUT"])
@auth.require_admin
def api_admin_save_bot_config(uid, slot):
    bot = reviews_db.get_bot(uid, slot)
    if not bot:
        return jsonify({"ok": False, "error": "Not found"}), 404
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid JSON body"}), 400

    # save_bot_config is keyword-only and reads None as "leave alone", so only
    # the keys actually present in the body may be forwarded: passing
    # data.get(<field>) for every field would turn a partial edit into a full
    # one the moment the caller stops sending a field it does not manage.
    fields = {}
    for key in ("name", "server_ip", "guild_id", "channel_id"):
        if key in data:
            # save_bot_config calls .strip() on these, so they must be text.
            fields[key] = "" if data[key] is None else str(data[key])
    if "server_port" in data:
        try:
            port = int(data["server_port"])
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "server_port must be a number"}), 400
        if not 1 <= port <= 65535:
            return jsonify({"ok": False, "error": "server_port must be between 1 and 65535"}), 400
        fields["server_port"] = port
    if "edition" in data:
        edition = str(data["edition"] or "").strip().lower()
        if edition not in BOT_EDITIONS:
            return jsonify({"ok": False, "error": "edition must be java or bedrock"}), 400
        fields["edition"] = edition
    if "update_interval" in data:
        try:
            interval = int(data["update_interval"])
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "update_interval must be a number"}), 400
        if interval < MIN_UPDATE_INTERVAL:
            return jsonify({"ok": False, "error":
                            f"update_interval must be at least {MIN_UPDATE_INTERVAL} seconds"}), 400
        fields["update_interval"] = interval
    if "embed" in data:
        if not isinstance(data["embed"], dict):
            return jsonify({"ok": False, "error": "embed must be an object"}), 400
        fields["embed"] = data["embed"]
    # An empty token box means "keep the one already stored" — the edit form
    # never receives the real token, so it cannot echo it back.
    if str(data.get("token") or "").strip():
        fields["token"] = str(data["token"]).strip()

    if not fields:
        return jsonify({"ok": False, "error": "No fields to update"}), 400
    reviews_db.save_bot_config(uid, slot, **fields)

    # Field NAMES only. "token" says a new token was stored and nothing else.
    updated = sorted(fields)
    return jsonify({"ok": True, "updated": updated})


# ── Auto-ban toggle ──

@ops_bp.route("/api/admin/auto-ban", methods=["GET"])
@auth.require_admin
def api_admin_get_auto_ban():
    return jsonify({"ok": True, "auto_ban_enabled": db.get_auto_ban_enabled()})


@ops_bp.route("/api/admin/auto-ban", methods=["PUT"])
@auth.require_admin
def api_admin_set_auto_ban():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("auto_ban_enabled", False))
    db.set_auto_ban_enabled(enabled)
    return jsonify({"ok": True, "auto_ban_enabled": enabled})


# ── Sign-up toggles ──

@ops_bp.route("/api/admin/signup-password", methods=["GET"])
@auth.require_admin
def api_admin_get_signup_password():
    return jsonify({"ok": True, "signup_password_enabled": db.get_signup_password_enabled()})


@ops_bp.route("/api/admin/signup-password", methods=["PUT"])
@auth.require_admin
def api_admin_set_signup_password():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("signup_password_enabled", False))
    db.set_signup_password_enabled(enabled)
    return jsonify({"ok": True, "signup_password_enabled": enabled})


@ops_bp.route("/api/admin/signup-github", methods=["GET"])
@auth.require_admin
def api_admin_get_signup_github():
    return jsonify({"ok": True, "signup_github_enabled": db.get_signup_github_enabled()})


@ops_bp.route("/api/admin/signup-github", methods=["PUT"])
@auth.require_admin
def api_admin_set_signup_github():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("signup_github_enabled", False))
    db.set_signup_github_enabled(enabled)
    return jsonify({"ok": True, "signup_github_enabled": enabled})

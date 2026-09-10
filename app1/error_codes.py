"""
error_codes.py — the machine-readable error code catalog.

Every JSON error response across the stack (backend API, engine control API,
frontend proxy) carries a stable `code` string next to the human-readable
`error` message:

    {"ok": false, "code": "invalid_credentials", "error": "Invalid username or password"}

Frontends and tools can branch on the code without parsing display text; the
message keeps the detail a human wants to read.

A code is permanent. Once an API returns it, changing its meaning breaks every
consumer, so add a new code instead of repurposing an old one.

The one helper:

    err(code, message, status=400, **extra) -> (payload, status)

builds the standard error payload and HTTP status in one call. Flask accepts a
(dict, int) tuple directly, so routes can `return err(...)` without jsonify.
`extra` lands in the payload without replacing the standard envelope fields
(e.g. banned=True, reason=...).
"""

# ── common / HTTP ──────────────────────────────────────────────────────────
BAD_REQUEST = "bad_request"
UNAUTHORIZED = "unauthorized"
FORBIDDEN = "forbidden"
NOT_FOUND = "not_found"
INTERNAL_ERROR = "internal_error"
RATE_LIMITED = "rate_limited"
BODY_TOO_LARGE = "body_too_large"
INVALID_JSON = "invalid_json"
MISSING_FIELDS = "missing_fields"
NOT_AUTHORIZED = "not_authorized"
INTERNAL_ACCESS_REQUIRED = "internal_access_required"
SESSION_INVALID = "session_invalid"
SESSION_EXPIRED = "session_expired"
SESSION_NOT_FOUND = "session_not_found"
CSRF_INVALID = "csrf_invalid"
CSRF_SESSION_EXPIRED = "csrf_session_expired"
BACKEND_UNAVAILABLE = "backend_unavailable"
BACKEND_TIMEOUT = "backend_timeout"
PROXY_FAILED = "proxy_failed"
ENGINE_UNAVAILABLE = "engine_unavailable"
ENGINE_REQUEST_FAILED = "engine_request_failed"
ENGINE_BAD_RESPONSE = "engine_bad_response"

# ── auth / registration ────────────────────────────────────────────────────
INVALID_CREDENTIALS = "invalid_credentials"
BANNED = "banned"
ACCOUNT_DISABLED = "account_disabled"
EMAIL_UNVERIFIED = "email_unverified"
EMAIL_INVALID = "email_invalid"
EMAIL_MISMATCH = "email_mismatch"
OTP_INVALID = "otp_invalid"
OTP_SEND_FAILED = "otp_send_failed"
USERNAME_TAKEN = "username_taken"
USERNAME_INVALID = "username_invalid"
PASSWORD_TOO_SHORT = "password_too_short"
PASSWORD_TOO_LONG = "password_too_long"
USER_NOT_FOUND = "user_not_found"
REGISTRATION_FAILED = "registration_failed"
REGISTRATION_CLOSED = "registration_closed"
FINGERPRINT_INVALID = "fingerprint_invalid"
DEVICE_BLOCKED = "device_blocked"
DEVICE_ERROR = "device_error"
TURNSTILE_FAILED = "turnstile_failed"
TRIAL_EXPIRED = "trial_expired"
GITHUB_AUTH_FAILED = "github_auth_failed"
GITHUB_EMAIL_UNVERIFIED = "github_email_unverified"
GITHUB_ACCOUNT_TOO_NEW = "github_account_too_new"
GITHUB_DISABLED = "github_disabled"
TERMS_REQUIRED = "terms_required"

# ── bot / engine ───────────────────────────────────────────────────────────
BOT_NOT_FOUND = "bot_not_found"
BOT_MISSING_CONFIG = "bot_missing_config"
BOT_SAVE_FAILED = "bot_save_failed"
BOT_DISCORD_ERROR = "bot_discord_error"
BOT_PUBLISH_FAILED = "bot_publish_failed"
BOT_ASSETS_UNAVAILABLE = "bot_assets_unavailable"
PREVIEW_FAILED = "preview_failed"

# ── hosting servers (DC bot hosting) ──────────────────────────────────────
HOSTING_NOT_FOUND = "hosting_server_not_found"
HOSTING_LIMIT = "hosting_server_limit"
HOSTING_SAVE_FAILED = "hosting_server_save_failed"
HOSTING_ALREADY_RUNNING = "hosting_already_running"
HOSTING_START_FAILED = "hosting_start_failed"

# ── reviews ────────────────────────────────────────────────────────────────
REVIEW_RATING_INVALID = "review_rating_invalid"
REVIEW_TEXT_REQUIRED = "review_text_required"
REVIEW_TOO_LONG = "review_too_long"
REVIEW_SAVE_FAILED = "review_save_failed"


def err(code, message, status=400, **extra):
    """Standard error payload: ({"ok": False, "code": ..., "error": ...}, status).

    `extra` is merged into the payload without replacing `ok`, `code`, or
    `error`, e.g. err(BANNED, "BANNED", 403, banned=True, reason="...").
    Routes can return the tuple directly.
    """
    payload = {"ok": False, "code": code, "error": message}
    payload.update({key: value for key, value in extra.items()
                    if key not in payload})
    return payload, status

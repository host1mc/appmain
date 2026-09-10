"""
engine.py — the hosting engine (tier 3).

The process that actually *runs* the bots:

  * polls the status endpoint for every running bot on that bot's own update interval,
  * posts / edits each bot's status embed through the Discord REST API,
  * reads the running bot set from the database every tick, so a missed
    start/stop control call heals itself,
  * exposes a control API — 127.0.0.1:8002 by default, moved with ENGINE_BIND /
    ENGINE_PORT — that the backend and the admin console call to start or stop a
    bot, force a refresh, or render a preview.

The bots themselves stay offline in Discord by design: the engine only ever
talks to the Discord REST API. It holds no gateway connection and publishes no
presence.

One engine is still the intended layout, but it is no longer a correctness
requirement: every scheduled publish first takes a per-interval claim in the
bots store (reviews_db.claim_bot_tick), so a second engine cannot double-post a
bot or race over its message_id. It would only waste work — status polls and
ticks spent losing the claim.

The bots table lives in HeatWave (reviews_db): the engine reads decrypted bot
tokens from it and writes runtime state back. A HeatWave outage empties the
tick (no running bots to read), which is the degraded-but-safe shape of every
other reviews_db caller. Only the *frontend* is barred from touching the
database.

Every control route is gated on the shared internal token, and both callers are
our own processes: the backend, which authenticates the user and verifies bot
ownership before it proxies anything here, and the loopback-only admin console
(admin/), whose caller is the operator. The engine itself checks no
ownership.
"""

import hashlib
import http.cookiejar
import json
import os
import re
import sys
import threading
import time
import traceback
from datetime import datetime
from functools import wraps

import requests
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

import database as db
import internal_auth
import internal_peers
import error_codes as ec
import node_registry
import reviews_db
from mc_status2 import fetch_status, build_embed

ENGINE_PORT = int(os.environ.get("ENGINE_PORT", 8002))
# Interface the control API listens on. Loopback covers the single-host layout;
# the two-instance layout needs instance A's private interface address here so
# instance B's backend can reach it. Validated in _bind_host() — never a wildcard.
ENGINE_BIND = os.environ.get("ENGINE_BIND", "127.0.0.1").strip()
DISCORD_API = "https://discord.com/api/v10"
TICK_SECONDS = 5

# One connection pool for the whole process. A bare requests.<verb> builds a
# throwaway Session -> HTTPAdapter -> PoolManager -> SSLContext (~240 KB) and a
# fresh TLS handshake to discord.com for every call, then drops all of it — and
# every running bot pays that once per update interval. Reusing the pool buys
# back the handshakes and the allocation churn; steady RSS barely moves.
_HTTP = requests.Session()
_HTTP.headers["User-Agent"] = "MCStatusHosting"
_HTTP.mount("http://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=8, max_retries=0))


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    """One shared Session means one shared cookie jar, and it outlives every
    call. A Set-Cookie from Discord would be stored here and replayed on the
    next bot's request. Nothing we call needs a cookie, so refuse to store any."""

    def set_ok(self, cookie, request):
        return False


_HTTP.cookies.set_policy(_NoCookies())

# The callers here are the bot worker thread and the waitress request threads.
# Sharing one Session across them is only safe because its state is set once,
# above, and never mutated per call: the per-bot `Authorization: Bot <token>`
# travels as a headers= argument, so no bot's token is ever stored on the
# session or carried into the next bot's request. pool_maxsize caps the idle
# sockets the pool will hold — 8 is headroom over the worker plus two waitress
# threads.

# static_folder=None on purpose. Flask otherwise registers a GET
# /static/<path:filename> route, and a route it registers itself never passes
# through api_internal_required — it was the one unauthenticated way into this
# port, serving the frontend's asset directory (app/static/) plus a
# file-existence oracle over it. The engine renders no templates and serves no
# assets: every caller asks for /engine/... (engine_client.py, admin/engine_client.py).
app = Flask(__name__, static_folder=None)
app.config["ENV"] = "production"
# Hard ceiling on a request body, enforced by Flask before a route sees it.
# serve() passes waitress max_request_body_size, but wsgi_engine.py (gunicorn)
# has no equivalent, so under that entrypoint the /engine/preview body was
# unbounded. The 413 handler below renders the refusal as JSON.
app.config["MAX_CONTENT_LENGTH"] = 1048576

_started_at = time.time()
_last_update = {}
_last_update_lock = threading.Lock()
_stop_event = threading.Event()

# One lock per bot, held for the whole publish. The database lease keeps two
# *processes* off the same bot; this keeps the two threads inside this process
# off it — the worker thread and a waitress thread serving a manual refresh can
# otherwise both be inside process_bot for the same bot, and if message_id is
# still NULL they each POST a new Discord message instead of editing one.
_publish_locks = {}
_publish_locks_guard = threading.Lock()

# Cap concurrent upstream status fetches (mcstatus.io + Discord) across the
# worker thread and the control-API request threads. Each fetch can take up to
# ~20s, and without a cap a few previews could pin every control-API thread and
# freeze start/stop for the whole fleet.
_UPSTREAM_MAX_CONCURRENCY = 4
_UPSTREAM_SEM = threading.BoundedSemaphore(_UPSTREAM_MAX_CONCURRENCY)


def _fetch_status_guarded(*args, **kwargs):
    with _UPSTREAM_SEM:
        return fetch_status(*args, **kwargs)


def _last_update_get(bot_id):
    with _last_update_lock:
        return _last_update.get(bot_id, 0)


def _last_update_set(bot_id, ts=None):
    with _last_update_lock:
        _last_update[bot_id] = time.time() if ts is None else ts


def _last_update_pop(bot_id):
    with _last_update_lock:
        _last_update.pop(bot_id, None)


def _publish_lock(bot_id):
    with _publish_locks_guard:
        lock = _publish_locks.get(bot_id)
        if lock is None:
            lock = _publish_locks[bot_id] = threading.Lock()
        return lock


@app.errorhandler(400)
def _bad_request(e):
    return ec.err(ec.BAD_REQUEST, "Malformed or missing request body", 400)


@app.errorhandler(404)
def _not_found(e):
    return ec.err(ec.NOT_FOUND, "Endpoint not found", 404)


@app.errorhandler(413)
def _request_entity_too_large(e):
    return ec.err(ec.BODY_TOO_LARGE, "Request body too large", 413)


@app.errorhandler(500)
def _internal_error(e):
    return ec.err(ec.INTERNAL_ERROR, "Internal server error", 500)


DB_BUSY_RETRY_AFTER_SECONDS = max(1, int(os.environ.get("DB_BUSY_RETRY_AFTER_SECONDS", 5)))


@app.errorhandler(db.OraclePoolExhausted)
def _db_pool_exhausted(e):
    payload, status = ec.err(ec.BACKEND_UNAVAILABLE,
                             "Service temporarily unavailable. Please try again.", 503)
    response = jsonify(payload)
    response.status_code = status
    response.headers["Retry-After"] = str(DB_BUSY_RETRY_AFTER_SECONDS)
    return response


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


def api_internal_required(f):
    @wraps(f)
    def wrap(*a, **k):
        if not internal_auth.is_internal_request(request):
            return ec.err(ec.INTERNAL_ACCESS_REQUIRED, "Internal access required", 401)
        if not internal_peers.peer_allowed(request.environ):
            return ec.err(ec.INTERNAL_ACCESS_REQUIRED, "Internal access required", 401)
        return f(*a, **k)
    return wrap


# ── helpers ──

# Discord webhook URLs look like
#   https://discord.com/api/webhooks/{webhook_id}/{webhook_token}
# on discord.com, discordapp.com, canary.discord.com or ptb.discord.com.
# Strict on purpose: a bot configured with a malformed URL fails at start with
# a clear message instead of silently never posting. The optional /slack and
# /github suffixes are refused — those integrations take a different payload
# format and cannot render our embeds.
_WEBHOOK_RE = re.compile(
    r"^https://(?:discord\.com|discordapp\.com|canary\.discord\.com|ptb\.discord\.com)/"
    r"api/webhooks/[A-Za-z0-9]+/[A-Za-z0-9_-]+/?$")
# Requests exception text includes the request URL for connection failures,
# timeouts and some HTTP errors. A Discord webhook URL is itself a credential,
# so never let its token cross an error persistence or response boundary. Match
# both configured and versioned routes, including relative paths.
_WEBHOOK_CREDENTIAL_RE = re.compile(
    r"(/api(?:/v[0-9]+)?/webhooks/[A-Za-z0-9._~-]+/)"
    r"[A-Za-z0-9._~-]+",
    re.IGNORECASE,
)
_DISCORD_SNOWFLAKE_RE = re.compile(r"^[0-9]{1,20}$")

# Sent on every outbound Discord payload. Discord's default, when the field is
# absent, is to parse *every* mention in `content` — @everyone, @here, roles and
# users — so a bot owner could put @everyone in the ip-reply plain_text and have
# it fire on every trigger, and the trigger is typed by any member of the server.
# `{"parse": []}` suppresses resolution at the API boundary, which is the only
# place it can be done without corrupting legitimate text (an email address, a
# literal "@everyone" someone meant to write). The text itself is never rewritten.
# Carried on embed payloads too: embed fields do not resolve mentions today, but
# the suppression costs nothing and holds if a future payload grows a `content`.
_NO_MENTIONS = {"parse": []}

# A hostname is at most 253 characters and mc_status2 refuses anything that is
# not a hostname or literal address anyway; this only keeps a megabyte-long
# "server_ip" out of the resolver and out of the error text it would land in.
_PREVIEW_IP_MAX_LEN = 255

# bots.last_error is VARCHAR2(500). Everything written to it here is assembled
# from an exception or a Discord error message, neither of which has a length
# bound, and Oracle answers an over-long bind with ORA-12899 — so the runtime
# write that was recording the failure failed too, losing last_error *and*
# last_status *and* the tick lease stamp for that bot. Bounded in bytes, because
# the column is sized in bytes and Discord messages are not all ASCII.
_LAST_ERROR_MAX_BYTES = 500

_INFRA_ERROR_RE = re.compile(
    r"ORA-\d|DPY-\d|DPI-\d|oracle|\bTNS\b|tnsnames|sqlnet|\bwallet\b|"
    r"ewallet|cwallet|\(DESCRIPTION\s*=|\(ADDRESS\s*=|\bHOST\s*=|"
    r"\bPORT\s*=|\bSERVICE_NAME\s*=|\bSID\s*=|\bDSN\b|\btcps?://|"
    r"connect descriptor|\blistener\b|\bthin mode\b",
    re.IGNORECASE,
)
_GENERIC_INFRA_ERROR = "Internal service error. Please try again later."

# bots.last_status is a CLOB, and its content is whatever the queried Minecraft
# server chose to answer with: player_list, motd_raw/motd_html, plugins and mods
# are all unbounded in the upstream payload (a Java query returns the *full*
# player list, and a modded server its whole mod list). The server_ip is picked
# by the bot's owner, so a hostile or simply huge target could write hundreds of
# KB into the row on every update interval, on every tick, forever. Only the
# persisted copy is trimmed — the embed and the API response still see the whole
# status.
_STATUS_TEXT_MAX = 4096
_STATUS_LIST_MAX = 60
_STATUS_ITEM_TEXT_MAX = 128
_STATUS_KEY_MAX = 40


def _redact_webhook_credentials(value):
    return _WEBHOOK_CREDENTIAL_RE.sub(r"\1[REDACTED]", str(value))


def _bounded_error(value):
    """Webhook-redacted error text that fits bots.last_error."""
    text = _redact_webhook_credentials(value)
    if _INFRA_ERROR_RE.search(text):
        _log_internal_failure("infrastructure detail withheld from bots.last_error", value)
        return _GENERIC_INFRA_ERROR
    encoded = text.encode("utf-8")
    if len(encoded) <= _LAST_ERROR_MAX_BYTES:
        return text
    return encoded[:_LAST_ERROR_MAX_BYTES].decode("utf-8", "ignore")


# _redact_webhook_credentials substitutes webhook tokens and returns str(value)
# for everything else, so it is not a general-purpose redactor — using it as the
# user-facing message text published whatever else the exception happened to
# carry. That matters because every `except Exception` below can catch a store
# failure and not just a Discord one: reviews_db.get_bot, force_bot_claim and
# update_bot_runtime all sit inside those try blocks, and their connect errors
# quote hostnames, ports and database detail. None of that is internal-only
# either: engine_client._call returns the engine's JSON body untouched and
# backend.py answers the browser with jsonify(payload), so the engine's `error`
# string is rendered in the dashboard. Handlers therefore reply with fixed
# prose and send the real exception here, still webhook-redacted so a webhook
# token never reaches the log either.
def _debug_print(*args, **kwargs):
    try:
        import reviews_db
        if reviews_db.is_console_debug_enabled():
            print(*args, **kwargs)
    except Exception:
        pass


def _log_internal_failure(context, exc):
    """Record for operators an exception whose text must not reach the caller."""
    try:
        import reviews_db
        reviews_db.log_app_error("EngineInternalFailure", f"{context}: {exc}", module="engine", flagged=1)
    except Exception:
        pass
    _debug_print(f"[engine] {context}: {_redact_webhook_credentials(exc)}", file=sys.stderr)


def _bounded_status_item(item):
    """One entry of a status list — a player name, a plugin, a mod — capped.

    fetch_status builds these itself and every entry is flat ({"name",
    "version"} for plugins and mods, a bare string for a player), so a nested
    list or dict is not part of the shape and is dropped rather than walked.
    """
    if isinstance(item, str):
        return item[:_STATUS_ITEM_TEXT_MAX]
    if isinstance(item, dict):
        return {
            str(name)[:_STATUS_ITEM_TEXT_MAX]:
                (field[:_STATUS_ITEM_TEXT_MAX] if isinstance(field, str) else field)
            for name, field in list(item.items())[:_STATUS_LIST_MAX]
            if not isinstance(field, (dict, list))
        }
    return item


def _bounded_status(status):
    """A copy of the status dict with every unbounded field capped for storage."""
    if not isinstance(status, dict):
        return status
    out = {}
    for key, value in list(status.items())[:_STATUS_KEY_MAX]:
        if isinstance(value, str):
            out[key] = value[:_STATUS_TEXT_MAX]
        elif isinstance(value, list):
            out[key] = [_bounded_status_item(item)
                        for item in value[:_STATUS_LIST_MAX]]
        elif isinstance(value, dict):
            out[key] = _bounded_status_item(value)
        else:
            out[key] = value
    return out


class _WebhookMessageIdError(RuntimeError):
    pass


def _is_webhook_url(url):
    if not url:
        return False
    return bool(_WEBHOOK_RE.match(str(url).strip()))


def _missing_config(bot):
    """Human-readable list of the fields a bot needs before it can run.

    Webhook mode replaces the token/channel pair: the engine posts straight to
    the webhook URL, which carries its own credential. Everything else (server
    IP, …) is required either way.
    """
    missing = []
    if _use_webhook(bot):
        if not _is_webhook_url(bot["webhook_url"]):
            missing.append("valid webhook URL")
    else:
        if not bot.get("token"):
            missing.append("Discord bot token")
        if not bot.get("channel_id"):
            missing.append("Channel ID")
    if not bot.get("server_ip"):
        missing.append("Server IP")
    return missing


def _server_port(value, edition):
    if value is None or (isinstance(value, str) and not value.strip()):
        return 19132 if str(edition or "").lower() == "bedrock" else 25565
    return value


def _worker_headers(token):
    # Per call, never on the shared session: one bot's token must not be visible
    # to the next bot's request.
    return {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "MCStatusHosting",
    }


def _discord_request(method, url, **kwargs):
    """One outbound call to Discord, with redirect following turned off.

    Every URL the engine calls is a fixed endpoint — DISCORD_API, or a webhook
    URL matched against _WEBHOOK_RE at the moment of use — so a 3xx is never a
    hop worth taking. requests follows redirects by default and to any host, so
    a Location could aim the retry at an internal address (link-local metadata,
    another service on the private interface) or at an attacker's host, carrying
    the embed body on a 307/308 and, on a relative Location, the webhook token
    that is still in the path. Treat a redirect as an error: raise_for_status()
    does not, because 3xx is neither 4xx nor 5xx.
    """
    resp = _HTTP.request(method, url, allow_redirects=False, **kwargs)
    if 300 <= resp.status_code < 400:
        raise RuntimeError(
            f"Discord returned an unexpected redirect (HTTP {resp.status_code})")
    return resp


def _with_429_retry(call):
    """Run call(); on a 429 sleep per Retry-After (capped) and try once more.

    Discord rate-limits per bucket (channel, token, webhook). The engine has no
    backoff today, so a burst (several bots on one channel, or a webhook under
    pressure) turns into repeated 429s that read as last_error and hammer the
    very bucket that is already over. One bounded retry smooths that; anything
    still throttled fails loudly as before.
    """
    resp = call()
    if resp.status_code == 429:
        try:
            delay = float(resp.json().get("retry_after", 1.0))
        except Exception:
            delay = 1.0
        time.sleep(min(max(delay, 0.1), 10.0))
        resp = call()
    return resp


def _post_message(token, channel_id, embed):
    if not _DISCORD_SNOWFLAKE_RE.fullmatch(str(channel_id or "")):
        raise RuntimeError("Channel ID is not a Discord snowflake")
    url = f"{DISCORD_API}/channels/{channel_id}/messages"
    r = _with_429_retry(lambda: _discord_request(
        "POST", url,
        headers=_worker_headers(token),
        json={"embeds": [embed], "allowed_mentions": _NO_MENTIONS}, timeout=15))
    r.raise_for_status()
    try:
        data = r.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Discord returned an empty or invalid response while posting "
            f"(HTTP {r.status_code})"
        ) from exc
    if not isinstance(data, dict) or not data.get("id"):
        raise RuntimeError("Discord accepted the post but returned no message ID")
    # Same check _post_webhook already makes on its side. This value is stored in
    # bots.message_id and then interpolated into the edit URL every interval, so
    # take only a snowflake — not whatever length or shape the response held.
    message_id = data["id"]
    if not isinstance(message_id, str) or not _DISCORD_SNOWFLAKE_RE.fullmatch(message_id):
        raise RuntimeError("Discord returned a message ID that is not a snowflake")
    return message_id


def _edit_message(token, channel_id, message_id, embed):
    if not _DISCORD_SNOWFLAKE_RE.fullmatch(str(channel_id or "")):
        raise RuntimeError("Channel ID is not a Discord snowflake")
    url = f"{DISCORD_API}/channels/{channel_id}/messages/{message_id}"
    r = _with_429_retry(lambda: _discord_request(
        "PATCH", url,
        headers=_worker_headers(token),
        json={"embeds": [embed], "allowed_mentions": _NO_MENTIONS}, timeout=15))
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return message_id


def _discord_detail(exc):
    try:
        return _redact_webhook_credentials(exc.response.json().get("message", ""))
    except Exception:
        return _redact_webhook_credentials(exc)


def _bot_key(bot):
    """The process-local state key for a bot: its HeatWave identity (uid, slot).

    Bots no longer carry a global id — two users both own a slot 0 — so every
    in-process cache is keyed on the pair."""
    return (bot.get("uid"), bot.get("slot_index"))


_DELIVERY_TTL = 60
_delivery_cache = {}  # (uid, slot) -> (unix ts the entry expires at, flags dict)
_delivery_lock = threading.Lock()


def _use_webhook(bot):
    """True when this tick should post through the webhook, not the token pair.

    The owner's two switches live in HeatWave, which this loop must not query per
    bot per tick, so they are cached for _DELIVERY_TTL. Anything other than an
    explicit one-of-two choice — both set, neither set, HeatWave unreachable —
    keeps the historical precedence: a configured webhook URL wins.
    """
    if not bot.get("webhook_url"):
        return False
    if not bot.get("token") or not bot.get("channel_id"):
        return True
    key = _bot_key(bot)
    now = time.time()
    with _delivery_lock:
        cached = _delivery_cache.get(key)
        if cached and now < cached[0]:
            flags = cached[1]
        else:
            flags = None
    if flags is None:
        try:
            import reviews_db
            flags = reviews_db.get_bot_delivery(bot.get("uid"), bot.get("slot_index"))
        except Exception:
            # A HeatWave outage must not change how a bot publishes.
            flags = {"use_token": 0, "use_webhook": 0}
        with _delivery_lock:
            _delivery_cache[key] = (now + _DELIVERY_TTL, flags)
    if flags.get("use_webhook") and not flags.get("use_token"):
        return True
    if flags.get("use_token") and not flags.get("use_webhook"):
        return False
    return True


def _publish_detail(bot, exc):
    """Publish-path error text. 401 is the status an owner can act on, and which
    credential it names depends on the mode _publish_embed picked: a webhook URL
    wins over the token pair, so a webhook bot's 401 is its webhook and not its
    token. Discord's body for either is the unactionable "401: Unauthorized".
    """
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 401:
        if _use_webhook(bot):
            return ("Discord rejected the webhook URL. Recreate the webhook and "
                    "save the new URL.")
        return ("Unauthorized: Discord rejected the bot token. Re-enter the "
                "token for this bot.")
    return _discord_detail(exc)


def _post_webhook(webhook_url, embed):
    """Post a fresh status message through a Discord webhook.

    ``wait=true`` asks Discord for the created message object. Without its id,
    the engine cannot edit future updates, so malformed success responses fail
    instead of silently creating a new message every interval.
    """
    r = _with_429_retry(lambda: _discord_request(
        "POST", webhook_url,
        params={"wait": "true"},
        json={"embeds": [embed], "allowed_mentions": _NO_MENTIONS},
        timeout=15,
    ))
    r.raise_for_status()
    try:
        data = r.json()
    except ValueError as exc:
        raise _WebhookMessageIdError(
            f"Discord returned an empty or invalid webhook response "
            f"(HTTP {r.status_code})"
        ) from exc
    message_id = data.get("id") if isinstance(data, dict) else None
    if not isinstance(message_id, str) or not _DISCORD_SNOWFLAKE_RE.fullmatch(message_id):
        raise _WebhookMessageIdError(
            "Discord accepted the webhook post but returned no message ID"
        )
    return message_id


def _edit_webhook(webhook_url, message_id, embed):
    """Edit a status message previously posted through a webhook.

    Discord limits webhook message edits to a window after posting (404 also
    means the message was deleted), so both statuses come back as None and the
    caller re-posts a fresh message instead of failing the tick.
    """
    r = _with_429_retry(lambda: _discord_request(
        "PATCH", f"{webhook_url.rstrip('/')}/messages/{message_id}",
        json={"embeds": [embed], "allowed_mentions": _NO_MENTIONS}, timeout=15))
    if r.status_code in (403, 404):
        return None
    r.raise_for_status()
    return message_id


def _publish_embed(bot, status):
    """Post or edit the bot's status message. Returns the live message id.

    A configured webhook URL wins over the token/channel pair: the webhook is
    the explicit choice, the token pair is the fallback. The same message_id
    column serves both modes — a stale id (message deleted, or switched modes)
    is handled the same way on both paths: the edit returns None and the fresh
    message is posted.
    """
    embed = build_embed(bot.get("embed"), status)
    msg_id = bot.get("message_id")
    # A stored message_id only ever comes from a Discord response, and it is
    # interpolated into a URL path below. Anything that is not a snowflake is
    # treated as absent, so a fresh message is posted rather than a path built
    # out of it.
    if msg_id is not None and not _DISCORD_SNOWFLAKE_RE.fullmatch(str(msg_id)):
        msg_id = None
    if _use_webhook(bot):
        # Re-validated here, at the point of use, and not only in
        # _missing_config: the bot dict is re-read between that check and this
        # call — process_bot works on _tick's re-read, and engine_generate
        # re-reads inside the publish lock — so the URL that passed validation is
        # not necessarily the URL being posted to. Without this, an owner who
        # saved a new webhook_url inside that window had the engine POST the
        # embed to whatever host they named, following redirects from it.
        webhook_url = str(bot["webhook_url"]).strip()
        if not _is_webhook_url(webhook_url):
            raise RuntimeError("Webhook URL is not a Discord webhook URL")
        if msg_id:
            new_id = _edit_webhook(webhook_url, msg_id, embed)
            if new_id is None:
                new_id = _post_webhook(webhook_url, embed)
            return new_id
        return _post_webhook(webhook_url, embed)
    token = bot["token"]
    channel_id = bot["channel_id"]
    if msg_id:
        new_id = _edit_message(token, channel_id, msg_id, embed)
        # The message was deleted in Discord — start a fresh one.
        if new_id is None:
            new_id = _post_message(token, channel_id, embed)
        return new_id
    return _post_message(token, channel_id, embed)


# ── ip-reply (trigger word → channel reply) ─────────────────────

# Discord timestamps are ISO-8601 with a trailing 'Z'. Messages older than this
# window are ignored even on the first poll after an engine restart, so a fresh
# engine can never reply to the history of the channel.
_REPLY_WINDOW_SECONDS = 30
# Per-bot cooldown between replies, so a spammer cannot make the bot hammer the
# channel (or the rate limit).
_REPLY_COOLDOWN_SECONDS = 5
_REPLY_POLL_LIMIT = 8
# Message ids already replied to this process run. Bounded per bot so a busy
# channel cannot grow it without limit.
_REPLY_SEEN_MAX = 64

# 401/403/404 cannot clear itself on the next tick: the token was revoked, the
# bot lost access to the channel, or the channel is gone. Re-trying every
# TICK_SECONDS turns one broken bot into a permanent stream of rejected requests
# against a rate limit the whole fleet shares, so a hard failure parks that
# bot's poll long enough for an owner to fix the cause.
_REPLY_HARD_FAIL_BACKOFF_SECONDS = 300

_reply_seen = {}          # (uid, slot) -> {message_id: True, ...}, oldest first
_reply_last = {}          # (uid, slot) -> unix ts of last reply
_reply_last_poll = {}     # (uid, slot) -> unix ts of last channel poll
_reply_parked_until = {}  # (uid, slot) -> (unix ts the poll may retry after, cred marker)
_reply_state_lock = threading.Lock()


def _reply_seen_add(bot_id, msg_id):
    with _reply_state_lock:
        # A dict, not a set: a set has no insertion order, so list(seen)[:half]
        # below dropped an arbitrary half of the ids — whichever ones the hash
        # order happened to put first, which varies per process because str
        # hashing is randomised. The just-seen id could be evicted immediately
        # while a much older one stayed, and the bot replied to the same message
        # twice. Dict preserves insertion order, so the slice is the oldest half.
        seen = _reply_seen.setdefault(bot_id, {})
        seen[msg_id] = True
        if len(seen) > _REPLY_SEEN_MAX:
            # Drop the oldest half — insertion order is order of arrival.
            for old in list(seen)[: len(seen) // 2]:
                seen.pop(old, None)


def _reply_seen_has(bot_id, msg_id):
    with _reply_state_lock:
        return msg_id in _reply_seen.get(bot_id, ())


def _reply_cred_marker(bot):
    """Fingerprint of the credentials the poll uses. The park is stored with it
    so that changing the token or the channel — the two fixes for a parked bot —
    lifts the park on the next tick instead of after the whole backoff, which
    would otherwise read to the owner as the fix not having worked.
    """
    raw = f"{bot.get('token') or ''}|{bot.get('channel_id') or ''}"
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _reply_park(bot, now):
    with _reply_state_lock:
        _reply_parked_until[_bot_key(bot)] = (
            now + _REPLY_HARD_FAIL_BACKOFF_SECONDS, _reply_cred_marker(bot))


_REPLY_FORBIDDEN_HINT = {
    "poll": ("The bot cannot read that channel. Give it View Channel and "
             "Read Message History there."),
    "send": ("The bot cannot post in that channel. Give it Send Messages "
             "there."),
}


def _reply_http_detail(exc, stage):
    """(text for bots.last_error, whether to park the poll).

    Discord answers a rejected bot token with the body "401: Unauthorized" and
    _discord_detail hands that back verbatim, so the owner reading it in the
    dashboard cannot tell that it is their own token being refused or what to do
    about it. Each status an owner can act on gets prose that names the fix, and
    the ones that will keep failing until they act park the poll.
    """
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 401:
        return ("Unauthorized: Discord rejected the bot token. Re-enter the "
                "token for this bot."), True
    if status == 403:
        return _REPLY_FORBIDDEN_HINT[stage], True
    if status == 404:
        return "That channel no longer exists. Pick another channel.", True
    if status == 429:
        return "Discord is rate-limiting this bot. It will be retried.", False
    return _discord_detail(exc), False


def _expand_ip_reply(text, bot):
    """Fill the {ip} / {port} / {ip_port} / {edition} placeholders."""
    try:
        ip = (bot.get("server_ip") or "").strip()
        try:
            port = int(bot.get("server_port") or 25565)
        except (TypeError, ValueError):
            port = 25565
        edition = bot.get("edition") or "java"
        port_str = str(port)
        ip_port = ip + (":" + port_str if port != 25565 else "")
        return (str(text or "")
                .replace("{ip}", ip)
                .replace("{port}", port_str)
                .replace("{ip_port}", ip_port)
                .replace("{edition}", edition))
    except Exception:
        return str(text or "")


def _reply_config(bot):
    """The bot's ip-reply config, or the default when it is not an object.

    ip_reply_json is stored as whatever JSON the save request carried, and
    database.py only falls back to the default for a *falsy* decode — so a list
    or a string arrives here intact and every .get() below it is an
    AttributeError, once per bot per tick, forever.
    """
    cfg = bot.get("ip_reply")
    return cfg if isinstance(cfg, dict) else db.default_ip_reply()


def _ip_reply_embed(reply_cfg, bot):
    """The embed payload for one ip-reply, from the builder's config."""
    cfg = reply_cfg.get("embed") or {}
    if not isinstance(cfg, dict):
        cfg = {}
    embed = {}
    title = _expand_ip_reply(cfg.get("title"), bot)
    description = _expand_ip_reply(cfg.get("description"), bot)
    footer = _expand_ip_reply(cfg.get("footer"), bot)
    if title:
        embed["title"] = title[:256]
    if description:
        embed["description"] = description[:4096]
    color = str(cfg.get("color") or "#9b59b6").lstrip("#")
    try:
        if len(color) == 6:
            embed["color"] = int(color, 16)
    except ValueError:
        pass
    if footer:
        embed["footer"] = {"text": footer[:2048]}
    return embed


def _send_ip_reply(bot, message):
    """Post the reply for one trigger message. Returns True on success."""
    # Webhook-mode bots have no token; the ip-reply is a channel-message feature
    # and simply cannot work for them, so it is skipped rather than 401-hammering.
    if not bot.get("token") or not bot.get("channel_id"):
        return False
    reply_cfg = _reply_config(bot)
    payload = {}
    if reply_cfg.get("mode") == "embed":
        embed = _ip_reply_embed(reply_cfg, bot)
        if not embed:
            return False
        payload = {"embeds": [embed], "allowed_mentions": _NO_MENTIONS}
    else:
        text = _expand_ip_reply(reply_cfg.get("plain_text"), bot).strip()
        if not text:
            return False
        payload = {"content": text[:2000], "allowed_mentions": _NO_MENTIONS}
    channel_id = str(bot.get("channel_id") or "")
    if not _DISCORD_SNOWFLAKE_RE.fullmatch(channel_id):
        return False
    url = f"{DISCORD_API}/channels/{channel_id}/messages"
    r = _with_429_retry(lambda: _discord_request(
        "POST", url,
        headers=_worker_headers(bot["token"]), json=payload, timeout=15))
    r.raise_for_status()
    return True


def _reply_trigger_matches(content, trigger):
    try:
        text = (content or "").strip().lower()
        trig = (trigger or "ip").strip().lower()
        if not trig or not text:
            return False
        if text == trig:
            return True
        return text.startswith(trig + " ") or text.endswith(" " + trig)
    except Exception:
        return False


def _message_is_fresh(msg):
    try:
        created = msg.get("timestamp") or ""
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        age = time.time() - dt.timestamp()
        return 0 <= age <= _REPLY_WINDOW_SECONDS
    except Exception:
        return False


def _poll_ip_replies(bot):
    """One REST poll of the bot's channel: read recent messages, reply to any
    that match the trigger word. Runs in the tick loop, so failures are logged
    to the bot's last_error and never crash the worker."""
    bot_id = bot["id"]  # display label for log lines
    key = _bot_key(bot)
    uid, slot = bot.get("uid"), bot.get("slot_index")
    reply_cfg = _reply_config(bot)
    if not reply_cfg.get("enabled") or not bot.get("channel_id") or not bot.get("token"):
        return
    now = time.time()
    with _reply_state_lock:
        parked = _reply_parked_until.get(key)
        if parked:
            if parked[1] != _reply_cred_marker(bot):
                _reply_parked_until.pop(key, None)
            elif now < parked[0]:
                return
        last_poll = _reply_last_poll.get(key, 0)
        if now - last_poll < TICK_SECONDS:
            return
        _reply_last_poll[key] = now
    try:
        channel_id = str(bot["channel_id"] or "")
        if not _DISCORD_SNOWFLAKE_RE.fullmatch(channel_id):
            return
        url = f"{DISCORD_API}/channels/{channel_id}/messages?limit={_REPLY_POLL_LIMIT}"
        r = _discord_request(
            "GET", url, headers=_worker_headers(bot["token"]), timeout=15)
        r.raise_for_status()
        messages = r.json()
        # This endpoint returns an array. `or []` covered null and [], but a
        # truthy non-list body (a number, true, a bare string) reached the `for`
        # below as either a TypeError or an iteration over characters.
        if not isinstance(messages, list):
            messages = []
    except Exception as e:
        if isinstance(e, requests.HTTPError):
            detail, park = _reply_http_detail(e, "poll")
            if park:
                _reply_park(bot, now)
        else:
            # bots.last_error is a user-facing field, not just a log line:
            # backend.py's /api/user/bot/<id>/status returns it and user2.html
            # writes it straight into the page. A non-HTTPError here is a
            # transport, timeout or decode failure whose str() quotes the request
            # URL and socket detail and tells a bot owner nothing they can act
            # on, so only the fixed half is stored.
            _log_internal_failure(f"ip-reply poll failed for bot {bot_id}", e)
            detail = "could not reach Discord"
        reviews_db.update_bot_runtime(uid, slot, last_error=_bounded_error(f"ip-reply poll: {detail}"))
        return
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        msg_id = msg.get("id")
        if not msg_id or _reply_seen_has(key, msg_id):
            continue
        _reply_seen_add(key, msg_id)
        author = msg.get("author")
        # The {} default only applies when the key is *absent*: a JSON null, list,
        # string or number under "author" made .get("bot") an AttributeError, and
        # it escapes this function (the try above covers only the HTTP call) to
        # print a traceback and abort the rest of this poll's message list. A
        # message whose author is not an object also cannot be shown *not* to be a
        # bot, so it is skipped rather than replied to — a bot-to-bot reply loop is
        # the worse outcome.
        if not isinstance(author, dict) or author.get("bot"):
            continue
        if not _message_is_fresh(msg):
            continue
        if not _reply_trigger_matches(msg.get("content"), reply_cfg.get("trigger")):
            continue
        with _reply_state_lock:
            last = _reply_last.get(key, 0)
            if now - last < _REPLY_COOLDOWN_SECONDS:
                return
            _reply_last[key] = now
        try:
            _send_ip_reply(bot, msg)
        except requests.HTTPError as e:
            detail, park = _reply_http_detail(e, "send")
            if park:
                _reply_park(bot, now)
            reviews_db.update_bot_runtime(uid, slot, last_error=_bounded_error(f"ip-reply: {detail}"))
        except Exception as e:
            # Same reason as the poll's non-HTTPError branch above: what reaches
            # here is transport or database text, and last_error is rendered in
            # the dashboard.
            _log_internal_failure(f"ip-reply send failed for bot {bot_id}", e)
            reviews_db.update_bot_runtime(
                uid, slot, last_error=_bounded_error("ip-reply: could not reach Discord"))


def process_bot(bot):
    # The re-read can race a deletion (reviews_db.get_bot -> None, or a stale
    # dict missing its identity), and a bot vanishing mid-tick must not be a
    # traceback.
    if not bot or bot.get("uid") is None or bot.get("slot_index") is None:
        return
    uid, slot = bot["uid"], bot["slot_index"]
    if _missing_config(bot):
        reviews_db.update_bot_runtime(uid, slot, last_error="Missing config (token / channel id / webhook / server ip)")
        return
    edition = bot.get("edition", "java")
    status = _fetch_status_guarded(
        bot["server_ip"],
        _server_port(bot.get("server_port"), edition),
        edition,
    )
    try:
        msg_id = _publish_embed(bot, status)
        reviews_db.update_bot_runtime(uid, slot, message_id=msg_id,
                                      last_status=_bounded_status(status), last_error=None)
    except requests.HTTPError as e:
        reviews_db.update_bot_runtime(uid, slot, last_status=_bounded_status(status),
                                      last_error=_bounded_error(f"Discord error: {_publish_detail(bot, e)}"))
    except Exception as e:
        if isinstance(e, _WebhookMessageIdError):
            reviews_db.set_bot_running(uid, slot, False)
        reviews_db.update_bot_runtime(
            uid, slot,
            last_status=_bounded_status(status),
            last_error=_bounded_error(e),
        )


# ── worker loop ──

def _tick():
    now = time.time()
    running = db.list_running_bots()

    # Evict reply-state for bots that no longer exist (or were stopped): a
    # long-lived process with churned bots would otherwise grow these without
    # bound. Also evict the local update throttle so a re-created bot refreshes
    # promptly instead of waiting out a stale interval.
    with _reply_state_lock:
        live_keys = {_bot_key(b) for b in running}
        # Keyed on every reply-state dict, not only _reply_seen: a bot whose
        # poll never succeeded has a _reply_last_poll and a _reply_parked_until
        # entry but no seen-set, so it was never swept.
        for stale in (set(_reply_seen) | set(_reply_last) | set(_reply_last_poll)
                      | set(_reply_parked_until)) - live_keys:
            _reply_seen.pop(stale, None)
            _reply_last.pop(stale, None)
            _reply_last_poll.pop(stale, None)
            _reply_parked_until.pop(stale, None)

    active = []
    for bot in running:
        if db.is_trial_expired(bot.get("uid")):
            reviews_db.set_bot_running(bot.get("uid"), bot.get("slot_index"), False)
            _last_update_pop(_bot_key(bot))
            continue
        active.append(bot)

    for bot in active:
        # The ip-reply poll runs every tick, independent of the status update
        # interval: replies must land within the freshness window (~30s), and a
        # poll is a cheap GET against a per-channel rate limit that ticks can
        # never approach. It is also independent of the publish lease — a broken
        # poll (no permission, token, channel) must not veto the status embed.
        try:
            _poll_ip_replies(bot)
        except Exception as exc:
            try:
                import reviews_db
                reviews_db.log_app_error("PollIpRepliesFailed", f"ip-reply poll failed for bot {bot.get('uid')}/{bot.get('slot_index')}: {exc}", module="engine", flagged=1)
            except Exception:
                pass
            _debug_print(f"[engine] ip-reply poll failed for bot {bot.get('uid')}/{bot.get('slot_index')}: {exc}")
        key = _bot_key(bot)
        uid, slot = bot.get("uid"), bot.get("slot_index")
        try:
            interval = max(15, int(bot.get("update_interval") or 60))
        except (TypeError, ValueError):
            interval = 60
        # Free process-local pre-filter: skips the DB round-trip most ticks.
        if now - _last_update_get(key) < interval:
            continue
        # Cross-process lease: exactly one engine publishes this bot this
        # interval, so two engines cannot both POST a fresh Discord message
        # while message_id is still NULL and then fight over the stored id.
        if not reviews_db.claim_bot_tick(uid, slot, interval):
            continue
        try:
            # Re-read so message_id reflects whatever the last winner stored.
            with _publish_lock(key):
                process_bot(reviews_db.get_bot(uid, slot) or bot)
        except Exception as exc:
            try:
                reviews_db.log_app_error("BotUpdateFailed", f"bot {uid}/{slot} failed to update: {exc}", module="engine", flagged=1)
            except Exception:
                pass
            _debug_print(f"[engine] bot {uid}/{slot} failed to update: {exc}")
        # Stamp even on failure so one broken bot cannot hot-loop.
        _last_update_set(key, now)


def _run_worker():
    _debug_print("[engine] bot worker started")
    # init_db() can fail transiently (cold pool, schema check against a busy
    # database). Without a retry the worker thread would die here and the whole
    # fleet would freeze — bots stay running=1, never published, while the
    # control API keeps answering health as REACHABLE.
    while not _stop_event.is_set():
        try:
            db.init_db()
            break
        except Exception:
            traceback.print_exc()
            _stop_event.wait(10)
    while not _stop_event.is_set():
        try:
            _tick()
        except Exception:
            traceback.print_exc()
        _stop_event.wait(TICK_SECONDS)


def start_worker():
    t = threading.Thread(target=_run_worker, daemon=True, name="bot-worker")
    t.start()
    return t


def stop_worker():
    _stop_event.set()


# ── control API ──

@app.route("/engine/health", methods=["GET"])
@api_internal_required
def engine_health():
    return jsonify({
        "ok": True,
        "running_bots": sorted(f"{b.get('uid')}/{b.get('slot_index')}"
                               for b in db.list_running_bots()),
        "uptime": round(time.time() - _started_at, 3),
    })


@app.route("/engine/bot/<uid>/<int:slot>/start", methods=["POST"])
@api_internal_required
def engine_start_bot(uid, slot):
    bot = reviews_db.get_bot(uid, slot)
    if not bot:
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    missing = _missing_config(bot)
    if missing:
        return ec.err(ec.BOT_MISSING_CONFIG, "Missing: " + ", ".join(missing), 400)
    reviews_db.set_bot_running(uid, slot, True)
    # Clear the throttle so the next tick refreshes the embed immediately —
    # both the local one and the DB tick lease, which would otherwise veto the
    # first publish for up to one interval.
    _last_update_pop((uid, slot))
    reviews_db.clear_bot_claim(uid, slot)
    return jsonify({"ok": True})


@app.route("/engine/bot/<uid>/<int:slot>/stop", methods=["POST"])
@api_internal_required
def engine_stop_bot(uid, slot):
    reviews_db.set_bot_running(uid, slot, False)
    _last_update_pop((uid, slot))
    return jsonify({"ok": True})


@app.route("/engine/bot/<uid>/<int:slot>/generate", methods=["POST"])
@api_internal_required
def engine_generate(uid, slot):
    bot = reviews_db.get_bot(uid, slot)
    if not bot:
        return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
    missing = _missing_config(bot)
    if missing:
        return ec.err(ec.BOT_MISSING_CONFIG, "Missing: " + ", ".join(missing), 400)
    try:
        # Take the lease instead of dropping it. A manual refresh must publish
        # now, but clearing the lease would leave last_run NULL for the length of
        # this request — long enough for another instance's tick (every
        # TICK_SECONDS) to claim the bot and post a second embed alongside this
        # one. Stamping it forward reserves the bot for one interval, so this is
        # the only publish; update_bot_runtime below re-stamps it on success.
        with _publish_lock((uid, slot)):
            reviews_db.force_bot_claim(uid, slot)
            # Re-read inside the lock: a scheduled tick may have just finished
            # and stored a message_id, and publishing with the stale None would
            # POST a second message instead of editing that one.
            bot = reviews_db.get_bot(uid, slot) or bot
            edition = bot.get("edition", "java")
            status = _fetch_status_guarded(
                bot["server_ip"],
                _server_port(bot.get("server_port"), edition),
                edition,
            )
            msg_id = _publish_embed(bot, status)
            reviews_db.update_bot_runtime(uid, slot, message_id=msg_id,
                                          last_status=_bounded_status(status), last_error=None)
            reviews_db.set_bot_running(uid, slot, True)
        _last_update_set((uid, slot), time.time())
        return jsonify({"ok": True, "message_id": msg_id, "status": status})
    except requests.HTTPError as e:
        return ec.err(ec.BOT_DISCORD_ERROR, "Discord error: " + _discord_detail(e), 502)
    except _WebhookMessageIdError as e:
        reviews_db.set_bot_running(uid, slot, False)
        return ec.err(ec.BOT_PUBLISH_FAILED, _redact_webhook_credentials(e), 502)
    except db.OraclePoolExhausted:
        raise
    except Exception as e:
        # Reaches the browser: engine_client hands this JSON back unaltered and
        # backend.py jsonify()s it. A generic failure here must not leak the
        # raw database detail, so the user gets fixed prose and the real detail
        # goes to stderr.
        _log_internal_failure(f"generate failed for bot {uid}/{slot}", e)
        return ec.err(ec.BOT_PUBLISH_FAILED, "Could not publish the status embed.", 500)


@app.route("/engine/preview", methods=["POST"])
@api_internal_required
def engine_preview():
    try:
        data = request.get_json(force=True)
        if not isinstance(data, dict):
            return ec.err(ec.INVALID_JSON, "Invalid JSON body", 400)
        embed_cfg = data.get("embed") or db.default_embed()
        # Every field here arrives untyped: the backend's /api/user/preview hands
        # the browser's JSON straight to engine_client.preview without checking a
        # single type, so a logged-in caller picks the type of each one. A
        # non-object embed reached build_embed and a non-string server_ip reached
        # (server_ip or "").strip() — both AttributeError, i.e. a 500 for what is
        # a bad request.
        if not isinstance(embed_cfg, dict):
            return ec.err(ec.BAD_REQUEST, "embed must be a JSON object", 400)
        ip = data.get("server_ip")
        if ip is not None and not isinstance(ip, str):
            return ec.err(ec.BAD_REQUEST, "server_ip must be a string", 400)
        if ip and len(ip) > _PREVIEW_IP_MAX_LEN:
            return ec.err(ec.BAD_REQUEST, "server_ip is too long", 400)
        # Same normalisation fetch_status applies, done before the value is used
        # so a dict or a number cannot reach .lower() there.
        edition = str(data.get("edition") or "java").strip().lower()
        if edition not in ("java", "bedrock"):
            edition = "java"
        try:
            port = max(1, min(65535, int(_server_port(data.get("server_port"), edition))))
        except (TypeError, ValueError):
            return ec.err(ec.BAD_REQUEST, "server_port must be a number", 400)
        if not ip:
            status = {
                "online": True, "host": "play.example.net", "port": int(port or 25565),
                "edition": edition, "error": None, "players_online": 1, "players_max": 500,
                "player_list": ["abcname"], "version": "Paper 1.21.11", "motd": "",
                "icon": None,
            }
        else:
            status = _fetch_status_guarded(ip, port, edition)
        embed = build_embed(embed_cfg, status)
        return jsonify({"ok": True, "status": status, "embed": embed})
    except HTTPException:
        # request.get_json(force=True) reports a malformed body by raising
        # BadRequest, and HTTPException subclasses Exception — so the handler
        # below caught that 400 and answered 500 "Preview failed". Re-raise so
        # the registered 400 handler renders it.
        raise
    except db.OraclePoolExhausted:
        raise
    except Exception as e:
        # Same browser exposure as engine_generate: preview is reachable from the
        # dashboard's /api/user/preview and this string is rendered there. The
        # try wraps _fetch_status_guarded and build_embed, but an Oracle miss in
        # db.default_embed() would also land here with its connect descriptor in
        # the text, so the caller gets fixed prose and stderr keeps the detail.
        _log_internal_failure("preview failed", e)
        return ec.err(
            ec.PREVIEW_FAILED,
            "Preview failed. Please try again.",
            500,
        )


@app.route("/engine/bot/<uid>/<int:slot>/assets", methods=["POST"])
@api_internal_required
def engine_assets(uid, slot):
    try:
        bot = reviews_db.get_bot(uid, slot)
        if not bot:
            return ec.err(ec.BOT_NOT_FOUND, "Bot not found", 404)
        if not bot.get("token") or not bot.get("guild_id"):
            return ec.err(ec.BOT_MISSING_CONFIG, "Missing Discord token or guild ID", 400)
    except db.OraclePoolExhausted:
        raise
    except Exception as e:
        # This try wraps the bots-store read and nothing else, so anything
        # caught here is a store failure; the browser gets fixed prose and the
        # raw detail goes to stderr.
        _log_internal_failure(f"assets lookup failed for bot {uid}/{slot}", e)
        return ec.err(ec.INTERNAL_ERROR, "Could not load this bot. Please try again.", 500)
    headers = {
        "Authorization": f"Bot {bot['token']}",
        "User-Agent": "MCStatusHosting (discord-assets)",
    }
    guild_id = bot["guild_id"]
    if not _DISCORD_SNOWFLAKE_RE.fullmatch(str(guild_id or "")):
        return ec.err(ec.BOT_MISSING_CONFIG, "Guild ID is not a Discord snowflake", 400)
    try:
        guild_res = _discord_request(
            "GET", f"{DISCORD_API}/guilds/{guild_id}", headers=headers, timeout=15)
        guild_res.raise_for_status()
        guild = guild_res.json()
        emojis_res = _discord_request(
            "GET", f"{DISCORD_API}/guilds/{guild_id}/emojis", headers=headers, timeout=15)
        emojis_res.raise_for_status()
        emojis = emojis_res.json()
        if not isinstance(guild, dict) or not isinstance(emojis, list):
            raise RuntimeError("Malformed Discord response")
    except requests.HTTPError as exc:
        status_code = getattr(exc.response, "status_code", None)
        detail = _discord_detail(exc)
        if status_code == 401:
            detail = "Unauthorized Discord token."
        return ec.err(ec.BOT_DISCORD_ERROR, f"Discord error: {detail}", 400)
    except Exception as exc:
        # A refused connection, timeout or DNS failure is upstream of Discord —
        # 502, not a client-side 400.
        # The HTTPError branch above is what carries the detail a user can act on;
        # what reaches here is transport text (resolver state, socket addresses,
        # proxy target) that names hosts this tier talks to and helps nobody, so
        # it is logged rather than returned.
        _log_internal_failure(f"assets fetch failed for bot {uid}/{slot}", exc)
        return ec.err(
            ec.BOT_ASSETS_UNAVAILABLE,
            "Could not reach Discord. Please try again.",
            502,
        )
    icon = guild.get("icon")
    guild_icon_url = None
    if icon:
        ext = "gif" if str(icon).startswith("a_") else "png"
        guild_icon_url = f"https://cdn.discordapp.com/icons/{guild_id}/{icon}.{ext}?size=256"
    normalized_emojis = []
    for emoji in emojis or []:
        if not isinstance(emoji, dict):
            continue
        emoji_id = emoji.get("id")
        if not emoji_id:
            continue
        ext = "gif" if emoji.get("animated") else "png"
        emoji_name = emoji.get("name") or f"emoji-{emoji_id}"
        normalized_emojis.append({
            "id": emoji_id,
            "name": emoji_name,
            "animated": bool(emoji.get("animated")),
            "url": f"https://cdn.discordapp.com/emojis/{emoji_id}.{ext}?size=48&quality=lossless",
            "token": f"<{('a' if emoji.get('animated') else '')}:{emoji_name}:{emoji_id}>",
        })
    return jsonify({
        "ok": True,
        "guild_name": guild.get("name"),
        "guild_icon_url": guild_icon_url,
        "emojis": normalized_emojis,
    })


_NODE_SECRET_MIN_SCRUB = 8


def _node_safe_text(value, secret=None):
    text = _redact_webhook_credentials(value)
    raw = secret if isinstance(secret, str) else ""
    for candidate in {raw, raw.strip()}:
        if len(candidate) >= _NODE_SECRET_MIN_SCRUB:
            text = text.replace(candidate, "[REDACTED]")
    return text


def _node_error(context, exc, message, secret=None):
    detail = _node_safe_text(exc, secret)
    if isinstance(exc, ValueError) and not _INFRA_ERROR_RE.search(detail):
        return ec.err(ec.BAD_REQUEST, detail, 400)
    _log_internal_failure(context, detail)
    return ec.err(ec.INTERNAL_ERROR, message, 500)


def _node_schema_ready():
    try:
        node_registry.ensure_node_schema()
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        _log_internal_failure("node registry schema check failed", exc)
        return ec.err(
            ec.INTERNAL_ERROR,
            "Could not prepare the node registry. Please try again.",
            500,
        )
    return None


@app.route("/engine/nodes", methods=["GET"])
@api_internal_required
def engine_nodes():
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    try:
        nodes = [
            {
                "id": node["id"],
                "name": node["name"],
                "url": node["url"],
                "capacity": node["capacity"],
                "enabled": node["enabled"],
                "created_at": node["created_at"],
                "servers": node["servers"],
                "free": node["free"],
            }
            for node in node_registry.list_nodes_with_usage()
        ]
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error("node list failed", exc, "Could not load the node registry.")
    return jsonify({"ok": True, "nodes": nodes})


@app.route("/engine/nodes", methods=["POST"])
@api_internal_required
def engine_node_create():
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return ec.err(ec.INVALID_JSON, "Invalid JSON body", 400)
    name = data.get("name")
    url = data.get("url")
    token = data.get("token")
    for field, value in (("name", name), ("url", url), ("token", token)):
        if value is not None and not isinstance(value, str):
            return ec.err(ec.BAD_REQUEST, f"{field} must be a string", 400)
    for field, value in (("name", name), ("token", token)):
        if isinstance(value, str) and any("\ud800" <= ch <= "\udfff" for ch in value):
            return ec.err(
                ec.BAD_REQUEST,
                f"{field} must not contain unpaired surrogate characters",
                400,
            )
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    try:
        node_id = node_registry.create_node(
            name=name,
            url=url,
            token=token,
            capacity=data.get("capacity"),
        )
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error(
            "node create failed", exc, "Could not create the node.", secret=token)
    return jsonify({"ok": True, "node_id": node_id})


@app.route("/engine/nodes/<int:node_id>/capacity", methods=["POST"])
@api_internal_required
def engine_node_capacity(node_id):
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return ec.err(ec.INVALID_JSON, "Invalid JSON body", 400)
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    try:
        changed = node_registry.update_node_capacity(node_id, data.get("capacity"))
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error(
            f"node {node_id} capacity update failed", exc,
            "Could not update the node capacity.")
    if not changed:
        return ec.err(ec.NOT_FOUND, "Node not found", 404)
    return jsonify({"ok": True})


@app.route("/engine/nodes/<int:node_id>/enabled", methods=["POST"])
@api_internal_required
def engine_node_enabled(node_id):
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return ec.err(ec.INVALID_JSON, "Invalid JSON body", 400)
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return ec.err(ec.BAD_REQUEST, "enabled must be true or false", 400)
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    try:
        changed = node_registry.set_node_enabled(node_id, enabled)
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error(
            f"node {node_id} enabled update failed", exc,
            "Could not update the node.")
    if not changed:
        return ec.err(ec.NOT_FOUND, "Node not found", 404)
    return jsonify({"ok": True, "enabled": enabled})


@app.route("/engine/nodes/<int:node_id>/delete", methods=["POST"])
@api_internal_required
def engine_node_delete(node_id):
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    try:
        removed = node_registry.delete_node(node_id)
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error(
            f"node {node_id} delete failed", exc, "Could not delete the node.")
    if not removed:
        return ec.err(ec.NOT_FOUND, "Node not found", 404)
    return jsonify({"ok": True})


# The only two places in the engine that call a node agent. Every other node
# route here reads or writes the registry row; a node's *configuration* and the
# containers actually running on it are only known to the node, so those are read
# from there. Kept short and bounded: the agent holds the token that controls that
# host's container daemon, so a wedged or hostile node must not be able to pin an
# engine thread or hand back a body big enough to matter.
_NODE_CONFIG_TIMEOUT = 8
_NODE_CONFIG_MAX_BYTES = 64 * 1024

# A node at capacity holds a few hundred containers and the agent reports three
# short fields per container, so this is roughly an order of magnitude of slack
# over the largest honest reply.
_NODE_SERVERS_MAX_BYTES = 512 * 1024


def _node_agent_origins(credentials):
    """The origins stored for a node, in the order they should be tried.

    The url column may hold several comma-separated addresses for one agent —
    typically a public hostname and a loopback one — because a host cannot reach
    the public name it publishes itself.
    """
    return [
        origin.rstrip("/")
        for origin in str((credentials or {}).get("url") or "").split(",")
        if origin.strip()
    ]


def _node_agent_get(node_id, credentials, path, max_bytes=_NODE_CONFIG_MAX_BYTES):
    """GET `path` from a node agent. Returns (payload, problem); one is None.

    `problem` is a dict of the code, message and status a caller should report,
    so the two routes below can disagree about how much a dead node matters: the
    config route has nothing to show without the agent and turns this into its
    error, while the server list still has the registry rows and folds it into a
    warning beside them.
    """
    origins = _node_agent_origins(credentials)
    token = (credentials or {}).get("token") or ""
    if not origins or not token:
        return None, {
            "code": ec.BAD_REQUEST, "status": 400,
            "message": "This node has no usable stored credentials — re-register it.",
        }
    for position, url in enumerate(origins):
        last = position == len(origins) - 1
        try:
            resp = _HTTP.request(
                "GET",
                f"{url}{path}",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/json"},
                timeout=_NODE_CONFIG_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            with resp:
                body = resp.raw.read(max_bytes + 1, decode_content=True)
            status = resp.status_code
        except Exception as exc:
            # Only the exception type is logged. requests puts the full URL in its
            # message, and on a redirect or a proxy error it can carry the request
            # headers with it — that is the agent token.
            _log_internal_failure(
                f"node {node_id} agent GET failed", type(exc).__name__)
            if not last:
                continue
            return None, {"code": ec.INTERNAL_ERROR, "status": 502,
                          "message": "The node agent did not answer."}
        break
    if 300 <= status < 400:
        # allow_redirects=False makes this reachable: a Location could aim the
        # retry — bearer header and all — at any host the engine can see.
        return None, {"code": ec.INTERNAL_ERROR, "status": 502,
                      "message": "The node agent returned an unexpected redirect."}
    if len(body) > max_bytes:
        return None, {"code": ec.INTERNAL_ERROR, "status": 502,
                      "message": "The node agent returned too much data."}
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return None, {"code": ec.INTERNAL_ERROR, "status": 502,
                      "message": "The node agent returned an unreadable response."}
    if status >= 400 or not payload.get("ok"):
        # 401 is the one an operator can act on directly: the stored token no
        # longer matches the one the agent boots with, which is what a rotated
        # NODE_TOKEN looks like from here.
        if status == 401:
            return None, {
                "code": ec.BAD_REQUEST, "status": 400,
                "message": ("The node rejected the stored token — it has been "
                            "rotated on that host. Re-register the node with "
                            "the current token."),
            }
        if status == 404:
            # An agent too old to have the route. Worth saying plainly, because
            # the fix is a redeploy of that host and nothing else looks like it.
            return None, {
                "code": ec.INTERNAL_ERROR, "status": 502,
                "message": ("This node's agent does not have that endpoint — "
                            "it is running an older build. Redeploy the agent "
                            "on that host."),
            }
        return None, {"code": ec.INTERNAL_ERROR, "status": 502,
                      "message": "The node agent could not answer."}
    return payload, None


def _node_credentials_or_problem(node_id):
    """(credentials, error_response). Shared by the two agent-backed routes."""
    try:
        credentials = node_registry.get_node_credentials(node_id)
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return None, _node_error(
            f"node {node_id} credential read failed", exc,
            "Could not read the node credentials.")
    if not credentials:
        return None, ec.err(ec.NOT_FOUND, "Node not found", 404)
    return credentials, None


@app.route("/engine/nodes/<int:node_id>/config", methods=["GET"])
@api_internal_required
def engine_node_config(node_id):
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    credentials, failure = _node_credentials_or_problem(node_id)
    if failure is not None:
        return failure
    payload, trouble = _node_agent_get(node_id, credentials, "/api/v1/config")
    if trouble is not None:
        return ec.err(trouble["code"], trouble["message"], trouble["status"])
    payload["node_id"] = node_id
    payload["url"] = ",".join(_node_agent_origins(credentials))
    return jsonify(payload)


@app.route("/engine/nodes/<int:node_id>/servers", methods=["GET"])
@api_internal_required
def engine_node_servers(node_id):
    """The containers on node <id>, each with its owner and its live state.

    Two sources, deliberately joined here rather than in the console: the
    registry says which servers were *placed* on this node and who owns them,
    and the agent says which containers are *actually* on that host and what
    they are doing. Either alone is misleading — a row whose container was
    removed by hand still bills against the node's capacity, and a container
    whose row was deleted keeps holding memory that nothing will ever reclaim.

    The agent half is best-effort on purpose. A node whose host is down is
    exactly when an operator needs to see what was on it, so a failed probe
    becomes `live_error` beside the rows instead of replacing them.
    """
    problem = _node_schema_ready()
    if problem is not None:
        return problem
    credentials, failure = _node_credentials_or_problem(node_id)
    if failure is not None:
        return failure
    url = ",".join(_node_agent_origins(credentials))

    schema_note = None
    try:
        servers = node_registry.list_servers_on_node(node_id)
    except node_registry.PanelSchemaMissing as exc:
        servers, schema_note = [], str(exc)
    except db.OraclePoolExhausted:
        raise
    except Exception as exc:
        return _node_error(
            f"node {node_id} server list failed", exc,
            "Could not read the servers on this node.")

    live, live_error = _node_agent_get(
        node_id, credentials, "/api/v1/servers",
        max_bytes=_NODE_SERVERS_MAX_BYTES)

    # id -> what the agent says about it. A container the agent reports without
    # an id is dropped by its own list(), so every key here is usable.
    seen = {}
    if live is not None:
        entries = live.get("servers")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                key = str(entry.get("id") or "")
                if key:
                    seen[key] = {
                        "status": str(entry.get("status") or "") or None,
                        "install_status": str(entry.get("install_status") or "")
                        or None,
                    }

    for server in servers:
        found = seen.pop(server["id"], None)
        # None when the agent could not be reached at all, False when it
        # answered and did not have this container. The page has to tell those
        # apart: the second one is a real inconsistency, the first is a symptom.
        if live is None:
            server["container"] = None
            server["container_missing"] = None
        else:
            server["container"] = found
            server["container_missing"] = found is None

    # Whatever is left in `seen` is a container with no row behind it. Only the
    # id is reported, not the display name the agent carries: that name is
    # user-supplied text from whoever created it, and it has no owner here to
    # attribute it to.
    orphans = sorted(seen.keys())

    owners = {}
    for server in servers:
        user_id = server.get("user_id")
        if user_id is None:
            continue
        row = owners.setdefault(
            user_id,
            {"user_id": user_id, "username": server.get("username"),
             "servers": 0},
        )
        row["servers"] += 1
    users = sorted(
        owners.values(),
        key=lambda row: (-row["servers"], (row["username"] or "").lower()),
    )

    return jsonify({
        "ok": True,
        "node_id": node_id,
        "url": url,
        "servers": servers,
        "total": len(servers),
        "truncated": len(servers) >= node_registry.SERVER_LIST_MAX,
        "users": users,
        "orphan_container_ids": orphans,
        "agent_reachable": live is not None,
        "live_error": live_error["message"] if live_error else None,
        "schema_note": schema_note,
    })


def _bind_host():
    """The validated ENGINE_BIND value, or exit 2.

    A wildcard bind is refused outright rather than warned about. Every control
    route can start or stop any bot, and the only thing in front of them is the
    shared internal token, sent in cleartext over HTTP — on a wildcard bind
    anyone who can reach the port and read one call owns the fleet. The intended
    value is one specific private interface address (instance A's, for the
    two-instance layout); loopback is the default.
    """
    host = ENGINE_BIND
    if host in ("", "0.0.0.0", "::", "[::]", "*"):
        _debug_print(
            f"[engine] refusing to start: ENGINE_BIND={host!r} would expose the control API "
            "beyond this host. It can start and stop any bot behind a cleartext shared token. "
            "Set ENGINE_BIND to a specific private interface address, or leave it unset for "
            "127.0.0.1.",
            file=sys.stderr,
        )
        sys.exit(2)
    return host


def init():
    """One-time startup: prove the shared internal token resolves, ensure the
    schema exists, and start the bot worker ticking. Called by both serve()
    (waitress) and wsgi_engine.py (gunicorn), because under gunicorn the module
    import is the only hook that runs — serve() itself is never called there.
    Not idempotent: start_worker() spawns a thread, so the engine must run as
    exactly one worker process.
    """
    internal_auth.get_internal_token()
    db.init_db()
    start_worker()


def serve():
    from waitress import serve as wserve
    host = _bind_host()
    init()
    _debug_print(f"[engine] control API on http://{host}:{ENGINE_PORT}")
    try:
        wserve(
            app,
            host=host,
            port=ENGINE_PORT,
            threads=8,
            connection_limit=100,
            channel_timeout=30,
            max_request_body_size=1048576,
            expose_tracebacks=False,
            ident="MCStatusEngine",
        )
    finally:
        stop_worker()


if __name__ == "__main__":
    serve()

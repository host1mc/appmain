"""
admin_app.py — Flask app shell for the local-only admin tool.

What this module owns:
  * the admin page routes ported out of frontend.py: panel,
    user detail, fingerprint, flags
  * a new read-only /admin/database page showing the resolved DB connection,
    plus its POST /api/admin/db/test probe
  * two pages with no counterpart in frontend.py: /admin/bots (the fleet of
    running bots, with per-bot edit/start/stop/delete) and /admin/account (the
    admin's own console password)
  * app construction: the secret key (auth.install_secret_key) and the three
    blueprints (users, devices, ops) that own every other
    /api/admin/... rule

Unlike frontend.py, this tier imports `database` and calls it directly: no HTTP
hop to the backend, no internal-auth token, no session proxying. Nothing here
is safe to expose, and nothing here is exposed — the launcher binds loopback
(127.0.0.1) only, so the app is reachable from this machine alone.

Impersonation (/admin/login-as/<user_id>) is deliberately not ported: it worked
by writing a user session cookie into the admin's browser, which cannot cross
from a local app into the public site's session store.
"""

import _bootstrap  # noqa: F401

import os

from flask import (
    Flask, render_template, request, redirect, url_for, abort, jsonify,
)

import database as db

# ADMIN_DATA_DIR lets a console running on the same machine as the app share the
# app's own data directory instead of this folder's. Must happen before the first
# query, and it is a no-op when the variable is unset.
_bootstrap.apply_external_data_dir(db)

import auth
from bp_users import users_bp
from bp_devices import devices_bp
from bp_ops import ops_bp
from bp_ads import ads_bp
from bp_embed import embed_bp
from bp_reviews import reviews_bp
from bp_errors import errors_bp
from bp_panel import panel_bp
from bp_nodes import nodes_bp

ERROR_MAX_CHARS = 200

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1048576
auth.install_secret_key(app)

app.register_blueprint(users_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(ops_bp)
app.register_blueprint(ads_bp)
app.register_blueprint(embed_bp)
app.register_blueprint(reviews_bp)
app.register_blueprint(errors_bp)
app.register_blueprint(panel_bp)
app.register_blueprint(nodes_bp)


# ── pages ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("admin_panel"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # The login page is gone: the console is loopback-only, so this route just
    # forwards anywhere that still points at it.
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout")
def admin_logout():
    return redirect(url_for("admin_panel"))


@app.route("/admin")
@auth.require_admin
def admin_panel():
    return render_template("admin.html")


@app.route("/admin/user/<user_id>")
@auth.require_admin
def admin_user_detail(user_id):
    # The page fetches the record itself from /api/admin/users/<id>.
    return render_template("admin_user_detail.html", user_id=user_id)


@app.route("/admin/fingerprint/<user_id>")
@auth.require_admin
def admin_fingerprint(user_id):
    user = db.get_user(user_id)
    if not user:
        abort(404)
    # Credential columns never reach a template.
    user.pop("password", None)
    user.pop("hashed_password", None)
    # fingerprint_status() decrypts the device payload, prefers the
    # fingerprints.ip_address column and only falls back to the IP inside the
    # encrypted detail for rows written before that column existed. Payloads
    # with no `screen` block come back as-is; the template tolerates that.
    fp = db.fingerprint_status(user_id)
    return render_template("admin_fingerprint.html", user=user, fp=fp)


@app.route("/admin/flags")
@auth.require_admin
def admin_flags():
    return render_template("admin_flags.html")


@app.route("/admin/errors")
@auth.require_admin
def admin_errors():
    return render_template("admin_errors.html")


@app.route("/admin/reviews")
@auth.require_admin
def admin_reviews():
    return render_template("admin_reviews.html")


@app.route("/admin/ads")
@auth.require_admin
def admin_ads():
    # The page fetches everything itself from /api/admin/ads.
    return render_template("admin_ads.html")


@app.route("/admin/panel")
@auth.require_admin
def admin_panel_controls():
    # The page fetches everything itself from /api/admin/panel, so the control
    # metadata stays in database.py rather than being duplicated in the template.
    return render_template("admin_panel_controls.html")


@app.route("/admin/bots")
@auth.require_admin
def admin_bots():
    # The page fetches the fleet itself from /api/admin/bots, so a dead engine
    # degrades inside the page instead of breaking this route.
    return render_template("admin_bots.html")


@app.route("/admin/account")
@auth.require_admin
def admin_account():
    return render_template("admin_account.html")


# ── database page ───────────────────────────────────────────────────────────

def _secret_display(value):
    """Never rendered, not even partially. db.mask() leaks the first and last
    four characters, which is fine for a token in a log line and not fine for a
    DB password on a page — knowing whether it is set is all this page needs."""
    return "(set — hidden)" if value else "(not set)"


def _pool_rows():
    """Pool numbers read off the live pool. The pool is created lazily, so
    before the first Oracle query there is nothing to read."""
    pool = getattr(db, "_ORACLE_POOL", None)
    if pool is None:
        return [("Connection pool", "not opened yet (created on first query)")]
    rows = []
    for label, attr in (
        ("Pool min", "min"),
        ("Pool max", "max"),
        ("Pool increment", "increment"),
        ("Pool idle timeout", "timeout"),
        ("Pool connections open", "opened"),
        ("Pool connections busy", "busy"),
    ):
        val = getattr(pool, attr, None)
        if val is not None:
            rows.append((label, str(val)))
    return rows or [("Connection pool", "open (no statistics available)")]


@app.route("/admin/database")
@auth.require_admin
def admin_database():
    cfg = getattr(db, "_ORACLE_CFG", None) or {}
    oracle_enabled = bool(getattr(db, "_ORACLE_ENABLED", False))

    status = "Oracle (Autonomous DB via wallet)"

    info = {
        "backend": "Oracle",
        "status": status,
        "oracle_enabled": oracle_enabled,
        "read_only": True,
        "note": "Read-only view of this process's resolved connection. "
                "Passwords are never shown.",
    }

    rows = [
        ("Active backend", info["backend"]),
        ("Status", status),
        ("ORACLE_ENABLED", "true" if oracle_enabled else "false"),
        ("Oracle DSN / service", cfg.get("dsn") or "(not configured)"),
        ("Oracle user", cfg.get("user") or "(not configured)"),
        ("Oracle password", _secret_display(cfg.get("password"))),
        ("Wallet directory", cfg.get("wallet_dir") or "(not configured)"),
        ("Wallet password", _secret_display(cfg.get("wallet_password"))),
    ]
    rows.extend(_pool_rows())

    return render_template("admin_database.html", info=info, rows=rows)


def _short_error(ex):
    """Message safe to hand a browser: no DSN, no credentials, truncated."""
    msg = " ".join(str(ex).split()) or type(ex).__name__
    cfg = getattr(db, "_ORACLE_CFG", None) or {}
    for secret in (cfg.get("password"), cfg.get("wallet_password"),
                   cfg.get("dsn"), cfg.get("user")):
        if secret:
            msg = msg.replace(secret, "***")
    if len(msg) > ERROR_MAX_CHARS:
        msg = msg[:ERROR_MAX_CHARS - 3] + "..."
    return msg


@app.route("/api/admin/db/test", methods=["POST"])
@auth.require_admin
def api_admin_db_test():
    conn = None
    try:
        conn = db._user_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM dual")
        row = cur.fetchone()
        result = row[0] if row else None
        if result is not None and not isinstance(result, (int, float, str, bool)):
            result = str(result)  # Oracle hands back Decimal for NUMBER
        return jsonify({"ok": True, "result": result, "backend": "oracle"})
    except Exception as ex:
        return jsonify({"ok": False, "error": _short_error(ex)})
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

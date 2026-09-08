"""
auth.py — authentication for the local-only admin app.

The console binds loopback (127.0.0.1) only and is launched by hand on one box,
so there is no login and no stored admin credential: `require_admin` is a
passthrough and every page opens directly. `install_secret_key` stays so the
console's own session (e.g. the embedded-user-session proxy) survives restarts.
"""

import _bootstrap

import functools
import os

# This folder's own data directory — the same one the vendored crypto_util and
# internal_auth derive from their file location. Nothing here reaches outside it.
_DATA_DIR = _bootstrap.DATA_DIR

# Used when the operator has copied the fleet's flask_key.key in. Not required:
# console sessions are local to this app, so a key of its own is fine.
_SHARED_KEY_FILE = os.path.join(_DATA_DIR, "flask_key.key")
# Our own key, used only when the shared one does not exist yet.
_OWN_KEY_FILE = os.path.join(_DATA_DIR, "admin_flask_key.key")


def require_admin(f):
    """Passthrough: the console is loopback-only, so there is no login gate.

    The decorator is kept so every route keeps the same shape it always had —
    removing the checks removed the only credential-facing surface of a tool
    that is bound to 127.0.0.1 and started by hand.
    """
    @functools.wraps(f)
    def wrap(*a, **k):
        return f(*a, **k)
    return wrap


def install_secret_key(app):
    """Set app.secret_key from disk, generating a key on first run.

    Reuses `data/flask_key.key` if the operator copied the fleet's one in,
    otherwise keeps its own `data/admin_flask_key.key` so sessions survive a
    restart. Sharing is not required — nothing signs a cookie for both this
    console and the public site. The key value is never printed or logged.
    """
    if os.path.exists(_SHARED_KEY_FILE):
        with open(_SHARED_KEY_FILE) as f:
            key = f.read().strip()
        if key:
            app.secret_key = key
            return

    if os.path.exists(_OWN_KEY_FILE):
        with open(_OWN_KEY_FILE) as f:
            key = f.read().strip()
        if key:
            app.secret_key = key
            return

    key = os.urandom(32).hex()
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(_OWN_KEY_FILE, "w") as f:
        f.write(key)
    app.secret_key = key

"""
_bootstrap.py — everything that must happen before `database` is imported.

This folder is standalone. The five modules it shares with the hosting app —
`database.py`, `crypto_util.py`, `engine_client.py`, `internal_auth.py`,
`creds.py` — are byte-identical *copies* living right here, recorded in
VENDOR.json and refreshed by `sync_from_app.py`. Nothing outside this directory
is imported, so the folder can be zipped, copied to the operator's laptop and run
with no checkout of the app anywhere on the machine.

Import order is not a style question here. `database._load_config()` resolves the
Oracle connection *at import time*, and `crypto_util` opens the Fernet key at
import time too, so anything that changes where those two look has to run first.
Every module in this folder imports `_bootstrap` on its first line, which makes
that true regardless of which one Python reaches first.

What it does:

  1. puts this directory on sys.path, so the flat sibling imports work from any
     working directory;
  2. loads `.env` into os.environ;
  3. resolves a relative ORACLE_WALLET_DIR to an absolute path under this folder
     — see `_absolutise_wallet`.

Configuration precedence, highest first:

  1. the real process environment — a shell `set` / `export` always wins
  2. `admin_console/.env`                     — the operator's own machine
  3. `admin_console/fastapi-oracle-app/.env`  — only if the whole folder was
     copied here from the app; the vendored database.py reads it itself

Every name is documented in `.env.example`.

State lives under `admin_console/data/`, and by construction rather than by
configuration: the vendored modules derive their data directory from their own
file location, and their own file location is now this folder. So `secret.key`
and `internal.key` both land there. Copy the servers'
`data/secret.key` in before the first real run — without the identical key every
encrypted value in the shared database reads as blank.

Importing this module has no effect other than mutating sys.path and os.environ.
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
ENV_PATH = os.path.join(HERE, ".env")

# One entry, this folder: the app's modules are vendored here, so there is no
# repo root to add and no way to accidentally import a different copy.
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def load_env_file(path=ENV_PATH):
    """Read a KEY=VALUE file into os.environ without overwriting anything.

    setdefault semantics, deliberately: a value already in the environment came
    from the operator's shell and outranks a file. Same minimal parser as
    `database._load_config()` — comments, blanks and surrounding quotes — kept
    dependency-free rather than pulling in python-dotenv for one file.

    Returns the list of names it set, for the launcher's banner.
    """
    if not os.path.exists(path):
        return []
    applied = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip().strip("\"'")
            if not key:
                continue
            if key not in os.environ:
                os.environ[key] = val
                applied.append(key)
    return applied


def _absolutise_wallet():
    """Make a relative ORACLE_WALLET_DIR mean something in a standalone folder.

    The vendored database.py joins a relative wallet path onto
    `<its own dir>/fastapi-oracle-app/`, which is a directory the app's repo has
    and this folder does not. So `./Wallet_ATP` would resolve to
    `admin_console/fastapi-oracle-app/Wallet_ATP` and fail on a wallet the
    operator dropped in `admin_console/Wallet_ATP`.

    Both layouts are legitimate — copying the app's whole `fastapi-oracle-app/`
    folder here is the least error-prone way to bring a wallet across — so try
    both and take whichever exists. An absolute path passes through os.path.join
    untouched, which is what makes this work at all. If neither candidate exists
    the path is still absolutised, so the error the operator sees names a
    directory they can go and look at.

    Returns the resolved directory, or "" when Oracle is not configured.
    """
    if os.environ.get("ORACLE_ENABLED", "").strip().lower() != "true":
        return ""
    raw = (os.environ.get("ORACLE_WALLET_DIR") or "./Wallet_ATP").strip()
    if os.path.isabs(raw):
        return raw
    candidates = (
        os.path.abspath(os.path.join(HERE, raw)),
        os.path.abspath(os.path.join(HERE, "fastapi-oracle-app", raw)),
    )
    resolved = next((c for c in candidates if os.path.isdir(c)), candidates[0])
    os.environ["ORACLE_WALLET_DIR"] = resolved
    return resolved


def _differs(path_a, path_b):
    """True when both files exist and their bytes are not the same.

    Compared as bytes and never printed: this is called on Fernet keys.
    """
    try:
        with open(path_a, "rb") as a, open(path_b, "rb") as b:
            return a.read() != b.read()
    except OSError:
        return False


def external_data_dir():
    """The app's own `data/` directory, when the console runs on the same machine.

    The standalone layout derives everything from this folder. When the app is on
    this machine, `ADMIN_DATA_DIR=<app>/data` points the console at the app's own
    data directory instead, so both share one set of keys.

    `crypto_util` opens `<its dir>/data/secret.key`
    at *import* time, so it cannot be redirected afterwards — the key is copied in
    here instead, before anything imports it, and only when this folder does not
    already have one. A console holding a different key would read every encrypted
    value as blank, which looks like data loss rather than a misconfiguration.

    Returns the resolved directory, or "" when the variable is not set.
    """
    raw = (os.environ.get("ADMIN_DATA_DIR") or "").strip()
    if not raw:
        return ""
    resolved = os.path.abspath(os.path.expanduser(raw))
    src_key = os.path.join(resolved, "secret.key")
    own_key = os.path.join(DATA_DIR, "secret.key")
    if os.path.isfile(src_key) and not os.path.exists(own_key):
        os.makedirs(DATA_DIR, exist_ok=True)
        shutil.copyfile(src_key, own_key)
        try:
            os.chmod(own_key, 0o600)
        except Exception:
            pass
        print(f"[admin] copied secret.key from {resolved} — encrypted values will read")
    elif os.path.isfile(src_key) and _differs(src_key, own_key):
        # The copy above only ever fires once, so a console that generated its own
        # key on an earlier dry run keeps it — and then reads every encrypted value
        # in the app's database as blank, which looks exactly like data loss. Say so
        # rather than letting the operator diagnose empty fields.
        print(f"[admin] WARNING: {own_key} is not the key in {resolved}. Encrypted "
              "values (settings, bot tokens, channel ids) will read as blank or "
              "raise. Delete this folder's data/secret.key and start again to adopt "
              "the app's key.", file=sys.stderr)
    return resolved


def apply_external_data_dir(db_module):
    """Point an imported `database` at EXTERNAL_DATA_DIR. No-op when unset.

    DATA_DIR is module-level in database.py and only read when a path under it is
    needed, so reassigning it after import is enough — unlike the Fernet key,
    which is already built by then and is handled in external_data_dir().
    """
    if not EXTERNAL_DATA_DIR:
        return False
    db_module.DATA_DIR = EXTERNAL_DATA_DIR
    return True


def vendor_problems():
    """Drift in the vendored modules, as a list of strings — empty when clean.

    A stale copy of `database.py` is the one kind of drift that can corrupt data
    rather than merely fail: it would read and write a schema the fleet has moved
    past. So the launcher prints this before it serves. Never raises — a missing
    manifest is worth a warning, not worth denying an operator the console.
    """
    try:
        import sync_from_app
        return sync_from_app.check()
    except Exception as exc:
        return [f"could not verify the vendored modules: {type(exc).__name__}: {exc}"]


ENV_APPLIED = load_env_file()
WALLET_DIR = _absolutise_wallet()
EXTERNAL_DATA_DIR = external_data_dir()

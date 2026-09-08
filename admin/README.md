# admin_console — the operator's admin console

The public website has no admin surface at all: `frontend.py` serves no `/admin`
page and `backend.py` serves no `/api/admin/*` route, by design. Everything an
operator used to do on the website happens here instead, in a separate Flask app
that runs on the operator's own machine and talks straight to the shared Oracle
database.

It binds `127.0.0.1` and nothing else. That is not a setting — it is the security
control. The app can read every user's record and start or stop any bot, and its
only protection is that nothing off this machine can reach it.

This folder is **self-contained**. It imports nothing from outside itself: the
four modules it shares with the hosting app are vendored copies living right
here. Zip the folder, copy it to a machine with no checkout of the app anywhere
on it, install the requirements, and it runs.

## Run it

From *inside* this folder:

```bash
cd admin_console
pip install -r requirements.txt
cp .env.example .env      # then fill in the ATP details
python start_admin.py     # http://127.0.0.1:8003
```

Open <http://127.0.0.1:8003/admin> — the console has no login gate: it binds
loopback only, so it opens straight into the panel (the old
`/admin/login` page was removed and now redirects here). `main.py` never
starts this process; launch it when you need it and stop it afterwards.
`ADMIN_PORT` moves the port; the host is deliberately not configurable.

## The vendored modules

`database.py`, `crypto_util.py`, `engine_client.py` and `internal_auth.py` are
**copies** of the hosting app's files, byte-for-byte. They are the app's data
layer, and a copy of a schema layer that drifts from the real one is worse than
no copy at all: the console would read columns that no longer exist, or miss the
encryption of ones that do — on the fleet's live database.

So `VENDOR.json` records a sha256 and byte count per file plus the source commit,
branch and whether that checkout was dirty when the copy was taken.
`start_admin.py` re-checks those hashes on every start and prints a warning
naming any file that no longer matches. It warns rather than refuses: an operator
mid-upgrade still needs to get in.

```bash
python sync_from_app.py --check                  # verify the copies against VENDOR.json
python sync_from_app.py --repo <path-to-app>     # re-copy from a checkout, re-record hashes
python sync_from_app.py --repo <path> --check    # would a re-copy change anything?
```

Exit status is 0 when everything agrees and 1 when it does not, so `--check` can
be wired into a release step.

**Never edit the vendored copies in this folder.** Edit them in the app, commit
there, then re-run `--repo`. A local fix here is invisible to the fleet and gets
overwritten by the next sync.

## What the operator brings to the machine

1. **Python dependencies** — `pip install -r requirements.txt` from this folder.
   `oracledb` is in there; it is imported only when `ORACLE_ENABLED=true`.
2. **The wallet.** Unzip the ATP instance wallet and point `ORACLE_WALLET_DIR` at
   the folder holding `tnsnames.ora`. An absolute path is used as given, which is
   usually what you want on a laptop. A *relative* path is tried in two places
   and the first that exists wins: against this folder (`admin_console/Wallet_ATP`
   for `./Wallet_ATP`), then against `admin_console/fastapi-oracle-app/` — that
   second candidate exists so you can copy the app's whole `fastapi-oracle-app/`
   folder in here, wallet and `.env` and all, which is the least error-prone way
   to bring a wallet across. If neither exists the path is still absolutised, so
   the error names a directory you can go and look at.
3. **`data/secret.key`, copied byte-for-byte from the servers.** Every bot token,
   every value in the settings table and every stored device payload is
   Fernet-encrypted with that one key, so without the *identical* file every
   encrypted value in the shared database is unreadable to this console. It does
   not fail loudly everywhere either: `crypto_util.decrypt()` returns `""` on a
   bad key, so a freshly generated one makes pages render blank tokens and blank
   settings, and saving any of those pages writes that emptiness back. Copy the
   file in before the first real run — if it is absent, `crypto_util` silently
   generates a new one.
4. **`data/internal.key`** only if you drive bots through the engine from here
   (`ENGINE_URL`, default `http://127.0.0.1:8002`) — the engine's control API
   checks that shared token, and a locally generated one will not match it.
   Everything except the bot-control buttons works without it.

Refer to those two files by name only. Do not print them, `cat` them, paste them
into a chat or an issue, or commit them; `data/` is gitignored.

State lives in `admin_console/data/` by construction, not by configuration: the
vendored modules derive their data directory from their own file location, and
that location is now this folder. `secret.key`, `internal.key` and the flask key
all land there.

`data/flask_key.key` is reused when present, otherwise the console keeps its own
`data/admin_flask_key.key`. That choice only affects how long an admin login
survives a restart — nothing signs a cookie for both this console and the site.

## It refuses to start on the wrong database

The failure this guards against is invisible from the UI: a console that never
reached the shared database would still render every page, report every save as a
success, and change nothing that reaches the fleet. So `_preflight()` in
`start.py` exits **2** rather than serving, when

- no Oracle connection is configured, or
- the test query (`SELECT 1 FROM dual`) fails.

The test query matters because the Oracle pool is lazy: without it a bad wallet
path or an expired password would surface on the operator's first click instead
of at startup.

`database.py` itself also raises at import unless `ORACLE_ENABLED` is true, so
there is no configuration in which the console runs without Oracle.

## Configuration precedence

`_bootstrap.py` loads the env file before `database` resolves anything, and sets
nothing that is already in the environment. Highest first:

1. the real process environment — a shell `set` / `export` always wins
2. `admin_console/.env` — the operator's own machine
3. `admin_console/fastapi-oracle-app/.env` — only if you copied that folder here
   from the app; the vendored `database.py` reads it itself, relative to its own
   location

So the console can be pointed at the shared database without the deployment's env
file existing at all. See `.env.example` for every name.

## What is in here

| file | role |
|---|---|
| `start_admin.py` | waitress launcher, loopback bind, vendor-drift warning, database preflight |
| `admin_app.py` | app shell, the admin pages, read-only `/admin/database` and its test probe |
| `auth.py` | `require_admin` passthrough (no login), Flask secret key |
| `bp_users.py` | user list and detail, ban, slots, account type, trials |
| `bp_devices.py` | device caps, device flags, fingerprints |
| `bp_ops.py` | sessions, admin log, SMTP config and test, engine health |
| `_bootstrap.py` | sys.path, `.env` loading, wallet-path resolution, drift check |
| `sync_from_app.py` | vendor the app's four modules / verify them |
| `VENDOR.json` | recorded sha256, byte count and source commit per vendored file |
| `requirements.txt` | this folder's own dependency set |
| `.env.example` | template for `.env`; every setting documented |
| `database.py` | **copy of the app's file** — schema, queries, Oracle resolution |
| `crypto_util.py` | **copy of the app's file** — Fernet encrypt/decrypt over `data/secret.key` |
| `engine_client.py` | **copy of the app's file** — HTTP client for the engine control API |
| `internal_auth.py` | **copy of the app's file** — shared engine token from `data/internal.key` |
| `templates/` | the seven admin pages, including `admin_database.html` |
| `static/` | `style.css` and `fp-guard.js` |
| `data/` | created on first run: keys and the flask key |

## Deliberately absent

- **Impersonation ("Login as user").** It worked by writing a *user* session
  cookie into the admin's browser, which cannot cross from a local app to the
  public site's session store. Removed rather than faked.
- **Editing the Oracle connection.** `/admin/database` shows the resolved
  connection read-only and never renders a password, not even partially — a
  masked password on a page is still four characters at each end. Change the
  connection in the env file.
- **A public port.** No reverse proxy, no tunnel, no `0.0.0.0`. If you need the
  console from another machine, forward the port over SSH; do not rebind it.

Enforcement stays on the public tiers: bans, device caps and flags are applied
where the users are, on the next request. Only the editing lives here.

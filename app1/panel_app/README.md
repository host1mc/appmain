# Bot-hosting panel (mounted sub-application)

The panel is a self-contained Starlette app mounted at `/panel` on its own tier's
host router. It has its own signed flash cookie, strict-CSP middleware, static
mount, exception handlers, and its own three tables — none of which touch the
host app's routers, JWT auth, or existing Oracle tables.

The mount happens unconditionally in `app/asgi_panel.py`, this tier's own ASGI
module:

```python
from panel_app import mount_panel

application = Starlette(lifespan=_lifespan)
_PANEL_APP = mount_panel(application, _CONFIG)
```

There is no activation switch: `PANEL_UI_ENABLED` has no reader anywhere in the
live tree, so setting or unsetting it changes nothing. The tier serves nothing but
`/panel` — that host router exists only to carry the mount prefix every panel URL
is built from.

## Activation

1. `pip install -r requirements.txt` (adds `jinja2` and `itsdangerous`).
2. Add to `.env`. Everything below except `PANEL_UI_ENABLED`, `PANEL_TRUST_PROXY`,
   `PANEL_AUTH_MODE` and the keys the single sign-in and the ad-block guard added
   (`BACKEND_URL`, `INTERNAL_TOKEN`, `SESSION_COOKIE_NAME`, `PANEL_MAIN_SITE_URL`,
   `PANEL_SESSION_CACHE_SECONDS`, `PANEL_GUARD_MODE`) was already carried over
   from the retired standalone panel and sits in a delimited block at the end of
   the file — check there before adding a key, because a duplicate silently wins
   over the earlier one.

   | Setting | Value | Notes |
   | --- | --- | --- |
   | `PANEL_UI_ENABLED` | `true` | **Dead — nothing reads it.** `asgi_panel.py:178` mounts the panel unconditionally, so the tier starts with it set, unset or misspelled. |
   | `PANEL_SECRET_KEY` | 48+ random chars | **Must be identical on every app instance** (see below). |
   | `NODE_URL` | node agent base URL | Server-side only; never sent to the browser. |
   | `NODE_TOKEN` | node agent token | Enables the real node client. |
   | `PANEL_REQUIRE_NODE` | `true` | Refuse to start with a demo node in production. |
   | `PANEL_SECURE_COOKIES` | `true` | Sets `Secure` + HSTS. Required behind HTTPS. |
   | `PANEL_TRUST_PROXY` | `true` | Read the client IP from `X-Forwarded-For` behind the LB. |
   | `MAX_SERVERS_PER_USER` | e.g. `1` | Per-account server cap. |
   | `BACKEND_URL` | e.g. `http://127.0.0.1:8001` | Flask backend tier that owns the session store; where `GET /api/session/<sid>` is resolved. Server-side only. |
   | `INTERNAL_TOKEN` | the stack's shared internal token | Sent as `X-Internal-Token` on that call. Falls back to `app/data/internal.key`, so it usually needs no entry here; the panel never creates one. Missing, a visitor holding a session cookie gets a 503 rather than being silently signed out. |
   | `SESSION_COOKIE_NAME` | `session` | Must match `frontend.py`'s `COOKIE_NAME`. |
   | `PANEL_MAIN_SITE_URL` | main site origin | Where a signed-out visitor and a sign-out are handed to. Empty means same origin — correct in production, where the panel and the site answer on one host and port behind the LB. |
   | `PANEL_SESSION_CACHE_SECONDS` | `300` | How long one resolved session is reused. Clamped to 0-3540. |
   | `PANEL_GUARD_MODE` | `gate` | **Read, but nothing acts on it.** `templating.guard_mode()` returns the literal `gate` for every panel page, downgraded to `off` only for a search crawler or when ads are off site-wide; `warn` was retired server-side on both tiers, reversibly (`_GUARD_MODES` still mirrors `database.AD_GUARD_MODES`). `templating.py` still resolves this variable from the environment, not from `PanelConfig`, but only into `PanelSettings.guard_mode` on the settings-table fallback path — and nothing reads that field, so setting this changes nothing a visitor sees. |

3. Restart the app. The panel is at `/panel`, which redirects to `/panel/dashboard`; a
   visitor with no main-site session is sent to that site's `/user/login`.

The panel has no sign-in of its own. A visitor logs in on the main Flask site at
`/user/login`, which mints a server-side session and drops its raw id (a
`uuid4().hex`) in the `session` cookie; because `/panel` is served from the same
host, that cookie reaches the panel too. Every panel request resolves it through
the backend tier's internal `GET /api/session/<sid>` and mirrors the identity into
the panel's own `panel_users` table, keyed by **the main site's own user id** —
stored verbatim, so `panel_servers.user_id` points at
a value that site already owns (`ensure_user_by_id`). The username is only
carried along for display: the main site keeps it encrypted at rest, so it is not
a stable key to mirror on. Every call into the backend is a read — the panel can
neither create, extend nor destroy a session — and sign-out is handed back to the
main site's `/user/logout`. Reading a session slides its expiry forward, so that
round-trip doubles as the keep-alive for someone browsing only the panel, which is
why `PANEL_SESSION_CACHE_SECONDS` is clamped to 0-3540: well under the backend's
3600 s session TTL.

**`/panel` must be served from the same host as the Flask site.** `frontend.py`'s
`save_session` sets the cookie with `get_cookie_domain(app)` and nothing in the
stack sets `SESSION_COOKIE_DOMAIN`, so the cookie is host-scoped: a browser on
`panel.example.com` never sends the session it was given by `example.com`. There
is no error to find afterwards — the panel simply reads no cookie, so every
visitor looks signed out and is bounced to a login they have already completed.

The panel therefore never verifies a password: a mirrored row's `password_hash` is
the unusable `external:oracle` placeholder, and the panel's own change-password
path is refused unless `PANEL_AUTH_MODE=local`. There is no
registration and no first-run setup route, and `ALLOW_REGISTRATION` is left in
`.env` only for continuity — nothing reads it any more.

**There is no admin surface in this tier.** Operator work — listing accounts,
deleting them, resetting a password — runs from the loopback-only console in
`admin/`, which reaches the same ATP schema directly. This tier is served from
several load-balanced instances against that one database, so an admin route here
would be the same privileged surface exposed N times over. Nothing in this tier
grants administrative privileges.

## Storage

`PANEL_STORE` picks the backend behind `runtime.database`. Both expose the same
coroutine surface returning the same plain dicts (`panel_app/store.py`), so the
route layer never knows which one it got. Every read on that surface is scoped to
one owner — there is no cross-tenant method left in this tier.

| `PANEL_STORE` | Backend | Use |
| --- | --- | --- |
| `oracle` | `panel_users`, `panel_servers` in the shared Oracle schema, on the app's existing async engine and pool | Deployed. Both LB instances see the same rows. |
| `sqlite` | Per-instance `panel.db` file | Laptop smoke test only. |

Unset, it follows the host app: `oracle` when `ORACLE_ENABLED=true`, else
`sqlite` — so there is normally no reason to set it. It is independent of
`PANEL_AUTH_MODE`, which no longer picks a sign-in — there is only the main
site's — and now decides nothing but whether the panel's own password paths
answer at all.

The two tables are declared on the panel's own `Base`
(`panel_app/oracle_models.py`), and `panel_app/database.py::ensure_schema` — which
the panel tier's lifespan calls at startup — creates any that are missing and
ALTERs a model column an existing table predates into place. **Nothing here runs
hand-written DDL beyond that additive set**: a model column with no entry in
`_ADDITIVE_COLUMNS` is reported as a startup warning, not invented, and anything
that would retype or constrain an existing column is still a script in
`fastapi-oracle-app/migrations/`. On a schema that already matches the models,
startup issues no DDL at all.

**On a deployment that already has these tables, re-key them before this code
ships.** `panel_users.id` was an integer identity and the `user_id` column
that references it was the matching `NUMBER`; both are now `VARCHAR2(36)`
holding the main site's UUID. Because `create_all` is check-first it will not alter a table
that exists, so the columns have to be migrated by hand and no script for it ships
here. The order is not a preference: the new code binds a UUID string against
those columns, and against a `NUMBER` column Oracle answers ORA-01722 (invalid
number) on the first query, while the old code cannot read the migrated schema
either. No version works against both, so the migration runs first, with the
panel tier stopped — nothing gates the mount, so no switch can hold it off.

One Oracle-specific difference from the SQLite spelling, in
`oracle_models.py`: `username`'s case-insensitive uniqueness is a function-based
unique index on `lower(username)` (Oracle has no per-column `COLLATE NOCASE`, so
every lookup compares `lower(username)` to match it).

## Multi-instance

* **`PANEL_SECRET_KEY` must be byte-identical on all instances.** It signs the
  short-lived `panel_flash` cookie. If it is left unset each instance generates
  its own key into `PANEL_DATA_DIR/session.key`, so a flash set by one instance
  fails to validate on the other and is dropped — a status banner silently goes
  missing whenever the LB moves someone across the redirect that carries it. Being
  signed in is unaffected: identity comes from the main site's session, not from
  any cookie the panel mints.
* **Storage is shared, so no sticky sessions are needed** with the default
  `oracle` store: a server created through instance A is listed by instance B.
  Setting `PANEL_STORE=sqlite` on a multi-instance deployment reintroduces the
  split — that file is per-instance.
* `ensure_user_by_id` re-reads the row by id after a unique-constraint violation,
  so two instances mirroring the same identity at the same moment converge on one
  row rather than one of them 500ing. The one violation it will not absorb is a
  pre-migration row holding the same username under an old id: that is a migration
  that has not finished, so it is raised rather than worked around.
* **Static asset URLs carry a content hash**, minted by
  `templating.static_version` and appended as `?v=<10 hex>`. It is a hash of the
  bytes rather than an mtime so both instances derive the same token for the same
  file — an mtime stamp would differ per instance and a visitor the LB moved would
  re-download every asset on each hop. A URL that carries a token is served
  `max-age=31536000, immutable` (that URL can only ever mean those bytes); a bare
  one keeps the previous conservative hour, which is also what an unreadable file
  falls back to.

## Local smoke test (no Oracle, no live node)

The filesystem demo node is gone — the panel always talks to the real node
agent at `NODE_URL` with `NODE_TOKEN`, and refuses to start without one. A
laptop smoke test still avoids Oracle with `PANEL_STORE=sqlite`, which keeps the
panel's own rows in a local file that never imports SQLAlchemy.

Identity cannot be faked locally, though: the panel has no login, so the Flask
frontend and backend tiers have to be running too and you have to sign in on the
site at `/user/login` first. Cookies ignore the port, so a session minted by the
site on `127.0.0.1:5000` is sent to a panel on `127.0.0.1:8099` — the host is what
has to match — but the redirect for a signed-out visitor does not, so point
`PANEL_MAIN_SITE_URL` at the site's own port. `INTERNAL_TOKEN` is picked up from
`app/data/internal.key`, the same file those tiers use, so on a machine that has
already run them it needs no setting.

```bash
pip install jinja2 itsdangerous
PANEL_STORE=sqlite \
PANEL_DATA_DIR=/tmp/panel-smoke \
NODE_TOKEN=<agent token> \
NODE_URL=http://127.0.0.1:8081 \
BACKEND_URL=http://127.0.0.1:8001 \
PANEL_MAIN_SITE_URL=http://127.0.0.1:5000 \
ORACLE_ENABLED=false \
PANEL_PORT=8099 \
python start_panel.py
```

Then walk `/panel`:

1. `/panel` redirects to `/panel/dashboard` once the site's session cookie resolves —
   with no session it redirects to the site's `/user/login` instead. `/panel/home`
   is retired and forwards to the dashboard too.
2. The dashboard shows the fleet stats and the server list, and links to **Deploy
   server**.
3. "Create a server" lists the demo runtime images (Node.js, Python) and deploys.
   The startup command prefills with the runtime's default (`npm install && node
   index.js` for Node.js, `pip install -r requirements.txt && python main.py` for
   Python).
4. Check the browser console is clean — a CSP error there means an inline
   `<script>`/`style=` slipped into a template.

Point `PANEL_DATA_DIR` at a scratch directory so the demo never writes next to
the deployed panel's own database.

## Tests

The panel's tests live with the app's, as `tests/test_panel_*.py`:

| File | Covers |
| --- | --- |
| `test_panel_security.py` | PBKDF2 hashing, and that the mirrored-Oracle placeholder can never verify |
| `test_panel_database.py` | SQLite layer, including `ensure_user_by_id` (the main-site mirror) |
| `test_panel_store.py` | Backend selection from `PANEL_STORE`/`ORACLE_ENABLED`, that both backends expose the same coroutine surface, and the SQLite adapter's async round-trip |
| `test_panel_node_client.py` | Node-agent HTTP client, driven through an injected opener |
| `test_panel_app.py` | Every route end-to-end, through a mounted panel |

The first five are stdlib-only. `test_panel_app.py` drives
`starlette.testclient.TestClient`, which needs **`httpx`** — deliberately kept
out of `requirements.txt` so the live instances do not carry a test-only
dependency. Without it that module skips itself rather than failing:

```bash
pip install httpx
python -m unittest discover -s tests -t . -v
```

None of them open an Oracle connection, reach the node agent, or touch Docker:
both suites that need storage pin `PANEL_STORE=sqlite` against a temporary file,
and `test_panel_app.py` mounts the panel with `PANEL_AUTH_MODE=local` and an
injected fake node client. `OracleStore`'s queries are therefore unexercised —
only its method surface is asserted, since running them needs the live shared
database.

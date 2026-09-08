# Minecraft Status Bot Hosting — *Presented by Endevil*

A web application that lets users design a **Discord Minecraft server-status
embed** with a live visual builder, plug in their own server IP + Discord bot
token, and have a single background engine host & auto-refresh the embed 24/7
using the Minecraft server status service.

---

## 🏛 Architecture

Four processes, strictly layered. **The frontend never touches the database.**
Every value a visitor sees arrives over HTTP from the backend, and the backend
is the only tier that opens a database connection for web traffic.

```
   browser
      │  HTTP :5000
      ▼
┌─────────────┐   HTTP :8001   ┌────────────┐              ┌──────────┐
│  frontend   │ ─────────────► │  backend   │ ───────────► │ database │
│  (web/HTML) │                │  (data API)│              │ (Oracle) │
└─────────────┘                └─────┬──────┘              │          │
   no DB access                      │ HTTP :8002          └────▲─────┘
                                     ▼                          │
                              ┌────────────┐                    │
                              │   engine   │ ───────────────────┘
                              │ (runs bots)│
                              └─────┬──────┘
                                    ▼
                       Discord REST API, server status
```

| Tier | Port | Owns |
|------|------|------|
| **database** | — | Schema creation and the maintenance sweeps (expired sessions, expired OTPs, expired trial bots). |
| **backend** | `127.0.0.1:8001` | All data access and all authorization. The session store lives here. |
| **engine** | `127.0.0.1:8002` | Everything that runs a bot: the server status polling and the embed post/edit loop over the Discord REST API. |
| **frontend** | `0.0.0.0:5000` | HTML rendering, the browser session cookie, and an `/api/*` reverse proxy to the backend. No database access at all. |

Only the frontend is bound to a public interface. The backend and engine listen
on a private interface only — loopback by default, `BACKEND_BIND` / `ENGINE_BIND`
elsewhere. The admin app is a fifth process that sits outside this stack: local
to the operator's machine, loopback only, not started by `main.py`.

### Why the engine talks to the database directly

The engine is a **backend-tier peer**, not a client of the backend. It needs
*decrypted* Discord bot tokens; exposing token decryption over HTTP would be
strictly worse for security than letting the engine read the database itself.
The layering rule that matters is the one the browser can reach: **the frontend
is barred from the database**, and it is.

### How the tiers authenticate each other

* **Browser → frontend** — the `session` cookie, backed by a server-side
  session record held by the backend.
* **Frontend/engine → backend**, **backend → engine** — a shared secret in the
  `X-Internal-Token` header, generated once into `data/internal.key` on first
  boot (see `internal_auth.py`). Endpoints marked internal-only (the session
  store, registration discard) accept nothing else.
* The frontend's `/api/*` proxy **never** attaches the internal token, and it
  refuses to forward internal-only paths. A visitor cannot borrow the
  frontend's privileges by asking it to proxy something.

### Self-healing bot state

The backend calls the engine immediately on start/stop so the UI feels
instant, and the engine *also* reads the running bot set from
`list_running_bots()` on every 5-second tick. A control call lost to an engine
restart heals itself on the next tick, and a dead engine never blocks a
database write — `engine_client` turns an unreachable engine into a `503`
payload instead of an exception, so the config save has already landed and bot
deletion proceeds.

### Config encryption

Discord bot tokens, the SMTP username and password, and the stored device
fingerprints are Fernet-encrypted at rest today. In this change set *every*
config value in the database becomes encrypted as well.

The consequence is worth stating plainly: `data/secret.key` is then required to
read **any** setting. Losing it no longer just orphans bot tokens — it orphans
the whole configuration, so it has to be backed up alongside the database and
kept with it.

Columns that SQL filters, joins or sorts on stay plaintext by necessity: Fernet
is non-deterministic, so the same input encrypts to a different ciphertext
every time and a `WHERE` clause against it cannot match. None of those columns
is a secret.

---

## 🚀 Run it

```bash
pip install -r requirements.txt
python main.py
```

Open <http://localhost:5000>. `main.py` starts all four tiers in dependency
order and shuts them all down on Ctrl+C.

To run a tier on its own — separate services, separate machines, separate
restart policies — use its startup file:

```bash
python start_database.py    # schema + maintenance daemon
python start_backend.py     # data API on 8001
python start_engine.py      # bot engine on 8002
python start_frontend.py    # public web on 5000
```

Boot order matters on a cold database: `start_database.py` creates the schema
and the shared internal token. After that the tiers can restart in any order.

### Configuration (environment variables)

| Variable | Default | Used by |
|----------|---------|---------|
| `FRONTEND_PORT` | `5000` | frontend |
| `BACKEND_PORT` | `8001` | backend |
| `ENGINE_PORT` | `8002` | engine |
| `BACKEND_URL` | `http://127.0.0.1:8001` | frontend |
| `ENGINE_URL` | `http://127.0.0.1:8002` | backend |
| `DB_MAINTENANCE_INTERVAL` | `60` (seconds) | database |
| `TIERS` | unset — all four | `main.py`: comma-separated subset of the tier labels it prints on startup. Unknown names abort the boot. |
| `BACKEND_BIND` | `127.0.0.1` | backend: the interface it listens on. |
| `ENGINE_BIND` | `127.0.0.1` | engine: the interface it listens on. |
| `TRUSTED_PROXY_HOPS` | `2` | frontend and panel: how many proxy hops to trust when resolving the client IP. `2` is the default — the Cloudflare edge and the OCI load balancer, each appending one `X-Forwarded-For` entry. Lowering it to `1` also switches off the edge-bypass detection (`_forwarded_chain_fault` needs two hops to have anything to compare), so a caller hitting the balancer directly would be believed; `0` trusts none and treats the peer address as the client. |
| `CF_TRUSTED_IPS` | unset — Cloudflare's published ranges | frontend and panel: comma-separated CIDRs whose peer may set `CF-*` headers. **Required for the Cloudflare features to do anything behind a second terminating proxy** — see "Cloudflare bot & DDoS protection" below. Replaces the published list for that test; the forwarded-chain test unions the two. Set it in the **real environment**, not only in `.env`: the panel loads that file and the frontend does not, so an `.env`-only value would apply to one tier and not the other. |
| `PANEL_TRUST_PROXY` | `false` | panel: whether to read the client IP from `X-Forwarded-For`/`CF-Connecting-IP` at all. Even when true the forwarded value is only believed from a peer that is private/loopback or a Cloudflare edge (`panel_app/auth.py: _peer_may_forward`), so it states intent, not trust. |
| `RATELIMIT_STORAGE_URI` | unset — per-process memory | frontend, backend: where the rate limiter keeps its counters. Set to `redis://host:6379/0` so both tiers share one bucket. |
| `WSGI_SERVER` | unset — waitress | `main.py`: set to `gunicorn` (Linux only) to run the frontend, backend and engine tiers under gunicorn via the `wsgi_*.py` entrypoints instead of waitress. The database daemon has no WSGI app and always runs as `start_database.py`. |
| `ADMIN_PORT` | `8003` | the local admin app. |

`TIERS` and `ADMIN_PORT` are read by the code today (`main.py`, and
`admin_console/start_admin.py`, which reads `ADMIN_PORT` from the console's own
`admin_console/.env` rather than from this table's environment).
`BACKEND_BIND`, `ENGINE_BIND`,
`TRUSTED_PROXY_HOPS` and `RATELIMIT_STORAGE_URI` arrive with the rest of this
change set — until then the backend and engine hardcode `127.0.0.1`.

#### Rate-limit storage in production

Unset, each process keeps its own counters in memory: they reset on restart, and
the frontend and backend each grant a visitor a full allowance, so every limit
below is effectively doubled. Point both tiers at one Redis to fix that:

```
RATELIMIT_STORAGE_URI=redis://127.0.0.1:6379/0
```

`main.py` passes its environment to every child (`_child_env`), so exporting it
once before boot covers all four tiers. There is no `.env` loader in this tier —
set it in the service unit, container env, or shell that launches `main.py`.

Both limiters are constructed with `in_memory_fallback_enabled=True`: if Redis is
configured but unreachable, they degrade to per-process counters instead of
erroring, so a Redis outage cannot take login offline. The trade is that limits
stop being shared for the duration. A 3s connect timeout keeps a hung Redis from
stalling requests.

The brute-force-sensitive limits (already in place, unchanged) are
`3/min; 10/hour; 20/day` on OTP send and registration, and `10/min` on login —
these are the ones that only bite correctly once storage is shared.

### WSGI entrypoints (gunicorn / uWSGI)

Each web tier is a plain Flask app — which is already a WSGI application — and
ships a gunicorn-style entrypoint next to its waitress launcher:

| file | serves | example gunicorn command |
|---|---|---|
| `wsgi_frontend.py` | the public web tier | `gunicorn --workers 2 --threads 4 --bind 127.0.0.1:5000 wsgi_frontend:application` |
| `wsgi_backend.py` | the internal API | `gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8001 wsgi_backend:application` |
| `wsgi_engine.py` | the engine control API | `gunicorn --workers 1 --threads 2 --bind 10.0.0.1:8002 wsgi_engine:application` |

Notes:

* `wsgi_engine.py` must run with **exactly one worker**: `engine.init()` starts
  the bot loop thread at import time, and two workers would mean two loops
  ticking against the fleet.
* `main.py` can boot all four tiers under gunicorn with one switch —
  `WSGI_SERVER=gunicorn python main.py` (or `TIERS=...` for a subset). It spawns
  gunicorn with the worker/thread/bind table above, keeps waitress otherwise,
  and always runs the database daemon via `start_database.py`. It refuses to
  start the backend or engine on a wildcard `--bind` under gunicorn, mirroring
  the tiers' own `_bind_host()` guard.
* Each entrypoint calls the tier's `init()` at import time — the only hook
  gunicorn guarantees — so the shared internal token, schema check, and (for
  the engine) the bot worker start exactly as they did under `serve()`.
* The waitress launchers (`main.py`, `start_*.py`) remain the default and keep
  calling the same `init()`; the two paths cannot drift.
* The wildcard-bind refusals (`_bind_host()` in backend.py / engine.py) only
  guard the waitress path — under gunicorn, pass a safe `--bind` yourself
  (loopback, or a specific private interface); never `0.0.0.0`.

### The standalone admin console

Admin lives off the public site. `admin_console/` is a separate, self-contained
Flask app the administrator runs on their own machine — it is not one of the
app's processes, and `main.py` never starts it:

```bash
cd admin_console
python start_admin.py                # http://127.0.0.1:8003
```

* It binds `127.0.0.1` only, and the host is hardcoded rather than configurable
  — being unreachable from the network is the control that protects it.
* It is **standalone**: it carries byte-identical vendored copies of
  `database.py`, `crypto_util.py`, `engine_client.py` and `internal_auth.py`
  instead of importing them from the repo root. `admin_console/VENDOR.json`
  records a sha256 per file plus the source commit, and
  `python sync_from_app.py --check` verifies them (`--repo <path>` refreshes
  them from a checkout of this app).
* Its configuration comes from `admin_console/.env` and its state from
  `admin_console/data/`; it also ships its own `templates/`, `static/` and
  `requirements.txt`.
* It calls its own copy of `database.py` directly: no backend hop, no internal
  token, no session proxying.
* It carries the admin pages, the `/api/admin/*` handlers, and a read-only
  database page that shows the resolved Oracle connection (DSN, user, wallet
  directory, pool counters) with every password masked.

**Impersonation ("Login as user") is deleted, not rebuilt.** It worked by
writing a user session cookie into the admin's own browser, and that cannot
cross from a local app to the public site's session store.

Only *editing* moved. Enforcement stays on the public tiers: bans, device caps
and signup/login flags are still checked by the backend on every request.
`/api/admin/engine/health` now lives in the admin console
(`admin_console/bp_ops.py`) and reaches the engine through its vendored
`engine_client`, the same as before.

The public-site admin surface is gone: `frontend.py` serves no `/admin/*`
routes, holds no admin session flag, and the admin templates have been deleted
from `templates/`.

### Running two instances behind one load balancer

Six processes across two hosts:

| Instance | Processes |
|----------|-----------|
| **A** | database, backend, engine, frontend (`python main.py`) |
| **B** | backend, frontend (`TIERS=backend,frontend python main.py`), with `ENGINE_URL` pointed at instance A's engine |

* **The engine and the database maintenance daemon are fleet singletons.** A
  second engine would duplicate every bot's publish loop and race on
  `message_id`; a second maintenance daemon would double the sweeps. Run exactly
  one of each, on instance A.
* `data/secret.key`, `data/internal.key` and `data/flask_key.key` must be
  **byte-identical on both instances** — copied, not regenerated. A mismatched
  `secret.key` does not raise: `crypto_util.decrypt` swallows the failure and
  returns an empty string, so instance B's bots quietly report missing config
  instead of failing loudly.
* Instance A's engine bind must be the **private interface address, never
  `0.0.0.0`**. The engine control API can start and stop any bot, and its only
  protection is a shared token sent in cleartext over HTTP.
* Rate limits are **per process** unless `RATELIMIT_STORAGE_URI` points at a
  Redis both instances can see; until then every published limit is effectively
  doubled across two instances. With Redis configured the limiters still fall
  back to per-process counters during a Redis outage, so an outage loosens the
  limits rather than blocking logins.
* **Both instances must point at the same Oracle database.** Oracle is the only
  backend, so a misconfigured instance fails to start rather than drifting onto
  a database of its own.

### Cloudflare bot & DDoS protection (free tier)

The free Cloudflare plan already covers the network-level DDoS — volumetric
mitigation runs at the edge on every plan, nothing to configure in this repo.
The free bot tooling is worth turning on in the dashboard (Security → Bots):

* **Super Bot Fight Mode** — challenges unverified bots with a JavaScript
  challenge. Free on all plans; this is the main DDoS-adjacent bot defence.
* **Browser Integrity Check** — tags requests that imitate a browser but fail
  CF's fingerprint with `CF-Browser-Integrity: fail`. The app enforces it
  itself (`frontend.py:_enforce_browser_integrity`): a failed *page view*
  gets a 403 even when the edge setting is left on "log only", so the free
  detection cannot be ignored on the way in. API, static, feeds and `/panel`
  are exempt.
* **Verified bots** — CF validates Googlebot & co. against their published
  reverse-IP/ASN/DNS records and adds `CF-Verified-Bot(-Name)`. The app reads
  those headers through `_cf_header()`, which discards them unless the
  request's peer really is a Cloudflare edge (or a range you pinned via
  `CF_TRUSTED_IPS`) — a client that bypasses the edge cannot claim to be
  Googlebot. Verified-bot status is what the ad gate uses to recognise real
  crawlers, which the old UA-string check alone allowed anyone to spoof.
* **WAF custom / rate-limiting rules** (free plan limits apply) — keep the
  edge rules as the first line; the app's own per-IP/per-account limiters
  (`RATELIMIT_STORAGE_URI` shared) are the backstop behind the edge.

The trust model is the same one the IP handling already uses: `TRUSTED_PROXY_HOPS`
(2 = Cloudflare + the OCI load balancer) governs `X-Forwarded-*`, and the
`CF-*` headers are only honoured from a socket peer on Cloudflare's published
edge ranges.

> **You must set `CF_TRUSTED_IPS` for any of the above to take effect in this
> fleet.** The peer test reads the address that opened the TCP connection. Where
> Cloudflare proxies straight to the app, that peer *is* an edge and the published
> ranges match it. Behind a **second** terminating proxy — the OCI load balancer,
> which terminates TLS again and appends its own `X-Forwarded-For` entry — the peer
> is the balancer, which is never on Cloudflare's network. Cloudflare sets the
> header, the balancer forwards it intact, and the app then discards it. Super Bot
> Fight Mode's verdict, Browser Integrity Check and verified-bot detection are all
> **inert** until the balancer's own range is pinned in `CF_TRUSTED_IPS`.
>
> This direction fails closed — an attacker gains nothing — but the features look
> configured while doing nothing, so the frontend now logs one `[fe] WARNING:` per
> discarded header name per process. If you see it, that is this. It stays quiet
> once the range is pinned.
>
> Pinning replaces the published list for the `CF-*` peer test, deliberately: in
> that topology a Cloudflare edge is no longer a direct peer, so continuing to
> trust one would trust an address that can no longer legitimately appear there.
> The forwarded-chain check unions both sets instead, because a genuine edge does
> still appear inside the chain the balancer appended to.

Two things this repo cannot do for you: the edge settings themselves (Super Bot
Fight Mode, Browser Integrity Check, WAF and rate-limiting rules, DDoS posture)
are dashboard state in the Cloudflare zone, and nothing here can confirm they are
on or that the zone is proxied. What the app guarantees is that when Cloudflare
*does* state a verdict, this stack honours it and cannot be lied to about it.

### Default admin login
```
username: admin
password: admin123
```

---

## ✨ Features

- **Landing page** — headline, *Presented by Endevil*, short info, and a
  **User Login** button. There is no **Admin Login** button — the public
  admin surface is gone.
- **Admin panel** — the standalone loopback-only console (`admin_console/`), run
  by hand on the administrator's machine, not on the public site.
  - Create users (username, display name, password).
  - Live user list; click a user for full info (created date, last login, bot
    config, running state, last update, errors) and their device fingerprint.
  - Start / Stop a user's bot, **Delete bot**, **Delete user**.
  - Signup/login flags, device and IP caps, admin action log.
  - Read-only database page: the resolved connection, passwords masked.
  - Engine health check (`/api/admin/engine/health`, served by the local app).
- **Registration** — email OTP verification (`@gmail.com` / `@outlook.com`),
  plus one-account-per-device enforcement via a browser fingerprint.
- **User dashboard / embed builder**
  - Visual builder for the Discord status card (title, color, footer, field
    labels, online/offline text, toggle fields, player-list size…).
  - Server IP / Port / Edition, Discord bot token, Guild ID, Channel ID,
    update interval.
  - **Live Discord-style preview** that pulls real data from the status endpoint and
    renders the embed as Discord shows it.
  - The bots appear **offline** in Discord's member list, with no activity text,
    by design — the embed is posted and edited over the Discord REST API. The
    four presence columns (`presence_status`, `activity_type`, `activity_name`,
    `activity_enabled`) are still in the `bots` schema but nothing reads or
    writes them, so values saved before the feature was removed survive if it
    ever returns.
  - **Start Hosting** → the engine picks the bot up on its next tick and begins
    refreshing the embed.
- **Security** — Discord bot tokens are encrypted at rest (Fernet). The
  plaintext token is never sent to the browser. Passwords are PBKDF2-hashed.
  Sessions are bound to the device fingerprint and to the TCP peer address the
  frontend sees (`request.remote_addr`). Behind a load balancer that peer
  address is the balancer's, identical for every visitor, so the IP half of the
  binding relies on `TRUSTED_PROXY_HOPS` (default `2`) to resolve the real
  client IP; the fingerprint half applies either way. Datacenter/proxy IPs are blocked at the
  frontend.

---

## 🧭 Usage flow

1. In the local admin app, create a user (or let them register with OTP).
2. Give the user their credentials — they log in on the public site themselves.
3. In the dashboard, fill in the server IP, Discord bot token, guild &
   channel IDs, design the embed, and click **View Live Preview**.
4. Click **Save**, then **Start Hosting**.
5. The engine posts the embed to the Discord channel and keeps editing that
   same message every *update interval* seconds (minimum 15).

> The Discord bot must be invited to your server with permission to **View
> Channel** and **Send / Read Message History** in the target channel.

---

## 📁 Project structure

| File | Purpose |
|------|---------|
| `main.py` | Orchestrator — starts the four tiers as subprocesses (`TIERS` selects a subset). Never starts the admin app. |
| `start_database.py` | Tier 1 startup: schema + maintenance daemon. |
| `start_backend.py` | Tier 2 startup: the data API. |
| `start_engine.py` | Tier 3 startup: the bot engine. |
| `start_frontend.py` | Tier 4 startup: the public web server. |
| `frontend.py` | Flask web tier: pages, session cookie, `/api/*` proxy. **No DB access.** |
| `backend.py` | Flask data API: all database access and all authorization. |
| `engine.py` | The hosting engine: status polling, embed publishing over the Discord REST API, control API. |
| `engine_client.py` | The backend's thin HTTP client for the engine. |
| `internal_auth.py` | Shared-secret token for service-to-service calls. |
| `database.py` | Data layer (users, bots, sessions, OTPs, settings) over Oracle. |
| `admin_console/` | The loopback-only admin console — **standalone**: byte-identical vendored copies of the data layer (`database.py`, `crypto_util.py`, `engine_client.py`, `internal_auth.py`, tracked in `VENDOR.json`), plus its own `templates/`, `static/`, `.env` and `requirements.txt`. Pages and `/api/admin/*`; run with `python start_admin.py` from inside the folder. |
| `mc_status2.py` | Server status fetch + Discord embed builder. |
| `crypto_util.py` | Fernet encryption for tokens, SMTP credentials, fingerprints — and, in this change set, every config value. |
| `templates/` | Jinja templates for the landing, auth and user pages. The admin templates are gone from here — the console has its own `admin_console/templates/`. |
| `static/style.css` | Dark Discord-inspired UI. |
| `data/` | `secret.key` (token encryption), `internal.key` (service token), `flask_key.key`. |

> **Keep `data/` private** — `internal.key` is the service-to-service password,
> and once config encryption lands `secret.key` decrypts the entire
> configuration, not just stored bot tokens. Back it up with the database: lose
> it and every setting is unreadable. Add `data/` to `.gitignore` for real
> deployments.

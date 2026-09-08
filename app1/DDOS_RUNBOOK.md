# DDoS / flood mitigation runbook

Operational guide for the origin-side flood controls added in `app/`
(`session_cookie.py`, `edge_gate.py`, `turnstile.py`, built on the existing
`cf_edge.py`). These modules make a forged or flooding request cheap to reject
*before* Flask builds a request context, a backend HTTP call, or an Oracle
SELECT. They are inert for legitimate traffic at their default thresholds.

They are **not** a substitute for edge protection. Read "What this does NOT
protect against" at the end before relying on any of it.

The controls are only as good as the deployment around them. The items below
are ordered by impact. Numbers 1, 2 and 5 are the ones that, left undone,
silently defeat everything else.

---

## 1. Lock the origin (highest impact)

The frontend binds `0.0.0.0:5000` on purpose (`frontend.py:3048-3049`, port from
`FRONTEND_PORT`, default `5000` at `frontend.py:61`). There is **no
`FRONTEND_BIND`** — the host is hard-coded `0.0.0.0` because this is the one tier
meant to be publicly reachable. Every other tier refuses a wildcard bind
(`sys.exit(2)`; see §5 and §8), so the frontend is the only intentional public
surface.

That surface is behind Cloudflare **only by DNS**. If anyone learns the origin
IP — from a TLS certificate log, an email header, an old DNS record, a leaked
config, a `Host`-header probe — they connect straight to `:5000` and **every**
Cloudflare control (WAF, Super Bot Fight Mode, rate limiting, Browser Integrity
Check) is bypassed in one step. Origin IP secrecy is not a defense; a
firewall is.

**Action — OCI security list / NSG on the frontend instances:**

- Allow ingress to TCP `5000` **only** from:
  - Cloudflare's published IPv4 + IPv6 ranges (https://www.cloudflare.com/ips/ —
    the same list baked into `cf_edge.CF_IP_RANGES`), and
  - the OCI load balancer's subnet CIDR (the LB is the actual TCP peer; see §2).
- Deny `5000` from `0.0.0.0/0` otherwise. Default-deny, allow-list the two
  sources above.
- Do the same for any port the LB health-probes on.
- Keep this list in sync when Cloudflare publishes new ranges — a stale allow
  list silently drops real edge traffic; a too-wide one reopens the bypass.

If the LB and app are in the same VCN, the app's `5000` should accept **only**
the LB subnet, and the LB's public listener should accept only Cloudflare. Do
not leave `5000` reachable from the public internet under any circumstance.

**Breaks if not done:** the entire Cloudflare tier — and every control in §3 —
is one `curl http://<origin-ip>:5000/` away from being irrelevant.

---

## 2. Pin `CF_TRUSTED_IPS` (subtle, currently load-bearing)

Read `cf_edge.py:14-29` and `72-77`. This is the trap that makes several
Cloudflare features **silently inert** in this topology.

**The mechanism.** `cf_edge.peer_is_cf()` tests the address that actually opened
the TCP connection. Cloudflare's protections (`CF-Connecting-IP`,
`CF-Verified-Bot`, and every other `CF-*` header) are trusted **only** when that
socket peer is on a trusted network. Behind the OCI load balancer, the LB
terminates TLS and re-originates the connection, so the socket peer this process
sees **is the balancer, never a Cloudflare edge**. With `CF_TRUSTED_IPS` empty,
`HEADER_PEER_NETWORKS` is just the published Cloudflare list (`cf_edge.py:72`),
the balancer is not in it, and so **every `CF-*` header is discarded on every
request**. `frontend.py` warns once per process when it drops a `CF-*` header, so
the inert state is visible in the log rather than silent.

**What goes inert while unpinned:** verified-bot detection (`CF-Verified-Bot`),
`CF-Connecting-IP` as the true client address, and by extension anything in the
app that keys off the real client behind the edge. Cloudflare-side Super Bot
Fight Mode and Browser Integrity Check still *run at the edge*, but the origin
can no longer read their verdicts, and `edge_gate`'s verified-bot exemption
(§below) cannot fire.

**The subtlety you must get right** (`cf_edge.py:67-77`): pinning
`CF_TRUSTED_IPS` behaves **differently for the two tests**:

- `HEADER_PEER_NETWORKS = CF_TRUSTED_IPS or CF_IP_RANGES` — pinning **REPLACES**
  the published list for the header-peer test. This is deliberate: behind a
  second terminating proxy the real Cloudflare edges are *no longer* your direct
  peer, so unioning them would leave them wrongly trusted as direct peers.
- `EDGE_NETWORKS = CF_IP_RANGES | CF_TRUSTED_IPS` — pinning **UNIONS** with the
  published list for the forwarded-chain test (`_chain_is_trustworthy`), because
  a genuine Cloudflare edge *does* still appear inside the `X-Forwarded-For`
  chain the balancer appended to, and must still be recognised there.

So: set `CF_TRUSTED_IPS` to the **balancer's** own source range(s) — the
addresses the balancer uses when it connects to the app. Not Cloudflare's
ranges (those stay built in for the chain test via the union).

**Action:**

- Determine the LB's egress/source CIDR toward the app tier.
- Set `CF_TRUSTED_IPS=<lb-cidr>[,<lb-cidr2>...]` (comma-separated CIDRs).
- Set it in the **real process environment**, not only in a `.env`
  (`cf_edge.py:58-66`): the panel reads `.env` via `load_dotenv`, but the
  frontend reads the real environment only. A value in `.env` alone applies to
  the panel and **not** the frontend, so the two tiers disagree about who a
  request came from. `main.py` forwards its own environment to every tier — set
  it there, or set it in both places.
- After setting, confirm the "discarded CF-* header" warning stops appearing
  (see §8 verification).

**Do NOT enable `GATE_MODE=always` before this is done** (`edge_gate.py:161-189`).
`always` challenges *every* unsolved navigation on first page view — including
**Googlebot**, which cannot solve a CAPTCHA, so the site deindexes. The only
thing that spares crawlers is the verified-bot exemption, which depends on
`CF-Verified-Bot`, which is discarded until `CF_TRUSTED_IPS` pins the balancer.
Order is mandatory: pin first, then (only if needed) switch to `always`.

**Breaks if not done:** bot detection and true-client-IP attribution are off;
switching to `always` first will deindex the site.

---

## 3. Cloudflare zone settings

These are the volumetric backstop the origin cannot replace (see final note).
Configure in the Cloudflare dashboard for the zone:

- **Super Bot Fight Mode:** ON. Challenge/block definitely-automated and
  verified-bot-impersonator traffic. (Origin can only honour its verdict once §2
  is done.)
- **Browser Integrity Check:** set to **Block**, not Log. Log mode observes and
  does nothing; Block is what actually sheds headless/abusive clients at the
  edge.
- **Rate-limiting rules** (edge, per true client IP — the layer that works even
  when the origin firewall in §1 is the only thing between the flood and `:5000`):
  - `/user/login` — this path fronts an Argon2id verify (19 MiB / 2 passes; see
    `turnstile.py:14-19`). Each unsolved POST is a self-inflicted memory/CPU
    amplifier. Rate-limit aggressively (e.g. a few POST/min per IP).
  - `/api/auth/*` — same reasoning; auth endpoints are the expensive path.
  - Consider `/user/register` too (same Argon2 cost).
- **Cache rules for `/static/`:** cache aggressively at the edge so static asset
  floods are absorbed by Cloudflare and never reach the origin. `/static/` is
  already challenge-exempt at the origin (`edge_gate.CHALLENGE_EXEMPT_PREFIXES`),
  so edge caching is the only thing that offloads it.

---

## 4. Redis for shared rate limiting

Both Flask limiters read `RATELIMIT_STORAGE_URI` (frontend `frontend.py:613`,
backend `backend.py:191`); unset falls back to per-process in-memory storage,
and both set `in_memory_fallback_enabled=True` (`frontend.py:615`,
`backend.py:193`) so a configured-but-unreachable Redis degrades to memory
rather than failing. `frontend.py:648-653` prints a stderr WARNING when the URI
is unset — treat that warning as "limits are not shared yet."

**Why it matters.** With no shared store, every published limit is enforced
**per process**. Under gunicorn with N workers per instance across 2 instances,
the real ceiling is roughly `N × 2 ×` the nominal number, and a client whose
requests land on different workers is counted separately each time. The
per-process node-agent limiter is fine because one agent runs per node
(`app.py:76-80`), but the frontend/backend fleet needs a shared store to make
any published number mean what it says.

**Action:**

- Run one Redis, self-hosted on **instance A**.
- Bind it to the **private VCN address only** — never `0.0.0.0`, never a public
  interface. Add an OCI security-list rule allowing `6379` only from instance
  B's private address; deny otherwise. A public Redis is an unauthenticated
  remote data store and a second origin-discovery vector.
- Set `maxmemory` to a bounded value and `maxmemory-policy allkeys-lru`, so a
  key-space flood evicts instead of OOMing the instance the frontend also runs
  on.
- Point **both** instances at A's private address:
  `RATELIMIT_STORAGE_URI=redis://<A-private-ip>:6379/0` in the real environment
  of every frontend and backend process. Instance A points at itself via the
  same private address (not loopback) so the config is identical on both hosts.
- Optionally add `socket_connect_timeout` is already set to 3s
  (`frontend.py:614`) so a Redis stall cannot pin request threads.

**Breaks if not done:** every rate limit in §3's origin counterpart, plus
flask-limiter decorators, is multiplied by the worker count — the effective
ceiling is several times the nominal one, and login/auth limits are the ones
that matter most.

---

## 5. 🔴 node-agent — most urgent item, and it is OUTSIDE `app/`

This is the highest-severity finding in the tree and it was **deliberately not
code-changed**, because the constraint for this work was "own only files under
`app/`." `node-agent/` is a separate service. It must be fixed by an operator.

**What it is.** `node-agent` exposes the host's Docker daemon over HTTP behind a
single shared bearer token, with **no per-server ownership check** — the token
is all-or-nothing host control. Its own `.env.example:40-43` states plainly:
*"This port is full control of the host's Docker daemon behind one shared bearer
token … It must never be reachable from the internet."*

**The live misconfiguration.** Compare the shipped `.env` against its own
template:

| Setting | `.env.example` (safe) | `.env` (live) | Effect |
|---|---|---|---|
| `NODE_PUBLISH_ADDRESS` | `127.0.0.1` (`.env.example:46`) | `0.0.0.0` (`.env:12`) | Publishes `8081` on **every** interface |
| `NODE_BIND` | `0.0.0.0` (correct *inside* the container) | `0.0.0.0` (`.env:2`) | waitress binds all interfaces in-container |

`docker-compose.yml:9` publishes `"${NODE_PUBLISH_ADDRESS:-0.0.0.0}:...:8081"`,
so the live `.env` maps `8081` to `0.0.0.0` on the host. Anyone who reaches that
port and holds (or guesses/leaks) the token gets **host root** via the Docker
socket (`docker-compose.yml:11` bind-mounts `/var/run/docker.sock`).

**It only warns, it does not refuse.** `run.py:19-30` prints a one-line WARNING
on a wildcard bind and serves anyway. Contrast every internal tier in `app/`,
which calls `sys.exit(2)` on a wildcard bind (backend `backend.py:2048`, engine
`engine.py:1303`, panel `asgi_panel.py:200`, gunicorn path `main.py:170`).
node-agent is the one tier that will happily come up wide-open.

**`NODE_URL` is public + cleartext.** `app/fastapi-oracle-app/.env:35` sets
`NODE_URL=http://20.189.72.43:8081` — a **public IP over plain HTTP**. So the
bearer token that grants host root traverses the network unencrypted to a
public address. (The panel's own default is the safe `http://127.0.0.1:8081`,
`panel_app/config.py:185` — the live `.env` overrides it to the public IP.)

**Container port publishing.** Verified: managed bot containers use
`network_mode="bridge"` (`container_spec.py:139`, `docker_runtime.py:211`) and
declare **no `ports` / no `PortBindings`** — they do not publish ports on
`0.0.0.0`. That part is fine. The exposure is the agent's own `8081`, not the
child containers.

**Fix (operator, on the node host):**

1. Set `NODE_PUBLISH_ADDRESS=127.0.0.1` in `node-agent/.env` when the panel runs
   on the same host; otherwise set it to the **specific private/VPN address** the
   panel reaches the node on. Never `0.0.0.0`.
2. Firewall TCP `8081` (OCI security list) to allow **only** the panel host's
   address; default-deny.
3. Change `NODE_URL` (in `app/fastapi-oracle-app/.env`) to the private address,
   and put TLS in front of `8081` (or keep it on a private link) so the token
   never crosses the network in cleartext. Rotate `NODE_TOKEN` after closing the
   port, since it has been exposed.
4. Consider making `run.py` refuse rather than warn on a public publish, to match
   every `app/` tier — but that is a code change in `node-agent/`, out of scope
   here; the firewall + `.env` fix is what closes the hole today.

**Breaks if not done:** a single reachable request to `8081` with the token is
host root. This outranks every other item in this document.

---

## 6. `db_admin` exposure

`db_admin/app.py` is an **unauthenticated Flask development server** with
destructive database powers.

- **Entry:** `db_admin/app.py:859` — `app.run(host=a.host, port=a.port,
  debug=a.debug)`. Port default **`8004`** (`app.py:856`), host default
  `127.0.0.1` (`app.py:855`) — **but `--host 0.0.0.0` is explicitly supported and
  advertised** (module docstring), and it runs on the Werkzeug dev server, so
  `--debug` turns on the interactive debugger (RCE console) if reachable.
- **Auth: none.** No login, token, or `@login_required` anywhere in the file.
  `app.secret_key` exists only for flash messages. Every route is open to anyone
  who reaches the port.
- **Capability:** arbitrary `SELECT`/`WITH` via `POST /api/query`
  (`app.py:758-782`, read-only guard is a prefix check only); row delete, bulk
  delete-all, `DROP TABLE … PURGE`, `PURGE RECYCLEBIN`
  (`app.py:644,659,674-686,689`), guarded only by a confirmation form field;
  **decrypts encrypted columns** for display (`app.py:370` via
  `crypto_util.decrypt`) and CSV-exports any table. It loads the ATP
  credentials and wallet from `../app/fastapi-oracle-app/.env` (`app.py:32,94-98`).
- **CSRF: none.** All state-changing routes are plain POST forms with no token —
  a cross-site POST could trigger `drop_table`/`delete_all` if an operator has
  the page open and reachable.

**Fix:** never launch with `--host 0.0.0.0`. Bind loopback only, and reach it
through an SSH tunnel from the operator's machine. Firewall `8004` closed to all
external sources (OCI security list default-deny). Never run with `--debug` on a
reachable interface. Treat this tool as a break-glass console: start it when
needed, stop it after. (The sibling `admin/` console at `8003` hard-codes
loopback and cannot be reconfigured to bind wide — `admin/start.py:96` — so the
acute exposure risk is `db_admin`, which accepts a wildcard bind.)

---

## 7. Information leak — node error bodies expose the host filesystem (fix outside `app/`)

A logged-in panel user can make the node reveal its filesystem layout by reusing
a folder name.

**Mechanism.** `node_agent/storage.py:191-196` `create_directory()` calls
`directory.mkdir(parents=True, exist_ok=False)`. When the directory already
exists, Python raises an OS-level `FileExistsError` whose `str()` embeds the
**full absolute path** — `/var/lib/dchost/servers/<uuid>/<name>` (the node's data
root, `NODE_DATA_ROOT`, default `/var/lib/dchost/servers` per `app.py:115`).
`node_agent/app.py:218-221` then returns `str(exc)` verbatim as the **409 body**.
`FileNotFoundError` paths in the same module (`storage.py:126,203`) use static
messages, but the `mkdir` case leaks the real path, and the 404/409 handlers
return the exception string directly. So a user who POSTs a directory create for
a name that already exists gets the node's internal path back in the response.

**Correct fix (in `node-agent/`):** stop putting host paths in error bodies —
raise `FileExistsError("directory already exists")` (static message) in
`create_directory`, and/or have the `app.py` 404/409 handlers return a fixed
string rather than `str(exc)`. This is the authoritative fix and it is outside
`app/`, so it was not code-changed here.

**Defense in depth already in `app/`:** `panel_app/node_client.py` redacts
absolute paths and host:port tokens out of node-authored 4xx text at the panel
boundary before it reaches the browser (`_redact_host_leak` /
`_redact_payload_host_leak`, `node_client.py:136-161`, applied at
`node_client.py:277,298`; the unredacted original still goes to the panel log for
diagnosis). That closes the browser-facing hole even while the node still
emits paths — but it is a second line, not the fix. Anything that reaches the
node's `8081` directly (see §5) still sees the raw path, which is one more reason
that port must not be reachable.

---

## 8. Verification checklist

Walk this after applying the above. Each step confirms a specific control is
actually live, not merely configured.

1. **Origin is firewalled (§1).** From a host *outside* Cloudflare and outside
   the VCN, `curl -m 5 http://<origin-ip>:5000/` must time out or be refused. If
   it returns the site, `5000` is still open to the world.
2. **`CF-*` headers are trusted (§2).** Tail the frontend log for the once-per-
   process "discarded CF-* header" / CF-trust warning from `cf_edge`/`frontend`.
   After pinning `CF_TRUSTED_IPS` to the balancer range and restarting, that
   warning must **not** reappear on subsequent requests. Confirm the value is in
   the frontend's real environment (e.g. it appears in `/proc/<pid>/environ` of a
   frontend worker), not only in a `.env`.
3. **Rate limits are shared, not per-process (§4).** Confirm
   `RATELIMIT_STORAGE_URI` is set on every frontend/backend process and the
   "storage not configured" WARNING (`frontend.py:649`) is gone. Then drive a
   burst of requests to a rate-limited route and watch the counter in Redis
   (`redis-cli MONITOR` or `KEYS 'LIMITER*'`) increment — if Redis stays empty,
   the limiter fell back to memory and limits are still per-worker.
4. **node-agent `8081` is unreachable from outside (§5).** From any host that is
   not the panel host, `curl -m 5 http://<node-ip>:8081/health` must fail. From
   the panel host it should return `{"ok": true, "service": "node-agent"}`.
   Confirm `NODE_PUBLISH_ADDRESS` is `127.0.0.1` or the private address, and that
   `docker compose ps` shows `8081` bound to that address, not `0.0.0.0`.
   Confirm `NODE_URL` no longer points at a public IP over `http://`.
5. **`db_admin` is closed (§6).** `curl -m 5 http://<origin-ip>:8004/` from
   outside must fail. Confirm the process, if running, bound `127.0.0.1` and was
   not started with `--host 0.0.0.0` or `--debug`.
6. **Redis is private (§4).** From outside the VCN, `redis-cli -h <A-ip> ping`
   must fail; from instance B's private address it must return `PONG`.
7. **Session-cookie MAC is active (§9 table).** Hand-craft a cookie
   `session=deadbeef` (a plausible-shaped hex sid with no `.tag`) with grace
   **off** and confirm it is treated as no session (no backend/Oracle round trip
   in the logs). With grace on it is accepted during rollout — that is expected.
8. **Gate is shedding, not challenging by default.** With Turnstile keys unset,
   confirm `GATE_MODE` is `suspicious` (default) and that ordinary browsing sees
   no interstitial. Drive >`GATE_IP_MAX` (150) requests/`GATE_WINDOW` (10s) from
   one IP and confirm a `503` with `Retry-After` and the static shed body.
9. **Turnstile inert until keys set.** With `TURNSTILE_SITE_KEY`/
   `TURNSTILE_SECRET_KEY` unset, confirm no challenge appears anywhere — the
   whole challenge path is dormant (`turnstile.enabled()` requires both keys).

---

## 9. Environment variable reference

Defaults and effects verified against `edge_gate.py`, `turnstile.py`,
`session_cookie.py`, `cf_edge.py`. Booleans accept `1/true/yes/on`.

### `edge_gate.py` — flood shedding + site-entry challenge

| Var | Default | Effect |
|---|---|---|
| `GATE_ENABLED` | `1` | Master switch. `0` removes the middleware from the request path entirely. |
| `GATE_MODE` | `suspicious` | When the interstitial applies. `suspicious`: only rate-tripping IPs, or everyone while a global surge is up. `always`: every unsolved navigation (⚠️ deindexes crawlers — see §2). `off`: shedder only, no challenge. |
| `GATE_WINDOW` | `10` | Sliding-window length (s) for the per-IP and global counters. |
| `GATE_IP_MAX` | `150` | Requests per window from one address before it is shed. |
| `GATE_IP_COOLDOWN` | `60` | Seconds a shed address stays blocked; also the `Retry-After` value on the shed 503. |
| `GATE_GLOBAL_MAX` | `600` | Total requests/window that raises the surge flag (promotes challenge to `always` and starts shedding unsolved anonymous page views). |
| `GATE_MAX_TRACKED` | `20000` | Max distinct addresses tracked at once; on saturation the O(1) global counter carries the load. |
| `GATE_SWEEP_SECONDS` | `30` | Amortised interval between stale-row sweeps of the per-IP table. |
| `GATE_COOKIE_TTL` | `43200` | Lifetime (s) of a solved-gate cookie (12h). Cookie is HMAC-bound to the solver's IP. |
| `GATE_HARD_CLOSE` | `0` | Allow a sustained flood to actually unbind the listener. **Leave off** (see final note). |
| `GATE_CLOSE_RPS` | `2000` | Global rate/window that arms hard close (only if enabled). |
| `GATE_CLOSE_SUSTAIN` | `20` | Seconds the rate must stay above the watermark before the listener closes. |
| `GATE_CLOSE_COOLDOWN` | `90` | Seconds the listener stays unbound before auto-reopening. |

### `turnstile.py` — Cloudflare Turnstile siteverify (inert until both keys set)

| Var | Default | Effect |
|---|---|---|
| `TURNSTILE_ENABLED` | `1` | Gate on the mechanism, but `enabled()` still requires both keys below — with either unset, Turnstile does nothing. |
| `TURNSTILE_SITE_KEY` | *(empty)* | Public widget key, rendered into the interstitial HTML. |
| `TURNSTILE_SECRET_KEY` | *(empty)* | Secret used for the server-side siteverify call. Never sent to the browser. |
| `TURNSTILE_FAIL_CLOSED` | `0` | On a *transport* failure to Cloudflare, `0` fails **open** (allow), `1` fails **closed** (refuse). A token Cloudflare actively rejects is always a hard fail regardless. |
| `TURNSTILE_TIMEOUT` | `4.0` | Seconds a siteverify call may take. Kept short: it sits in the login path, so it is the floor on how long a flood can pin a worker thread. |

### `session_cookie.py` — HMAC-signed session cookie

| Var | Default | Effect |
|---|---|---|
| `SESSION_COOKIE_MAC` | `1` | Sign/verify the session cookie with an HMAC so a forged `session=<hex>` is rejected with **zero I/O** (no backend call, no Oracle SELECT). `0` restores the previous unsigned behaviour. |
| `SESSION_COOKIE_MAC_GRACE` | `1` | During rollout, also accept an untagged cookie (every cookie already in a browser when this shipped). Turn **off** after one `PERMANENT_SESSION_LIFETIME` has elapsed, at which point untagged cookies are refused too. |

### `cf_edge.py` — Cloudflare edge trust (pre-existing, load-bearing here)

| Var | Default | Effect |
|---|---|---|
| `CF_TRUSTED_IPS` | *(empty)* | Comma-separated CIDRs. **Replaces** the published CF list for the header-peer test, **unions** it for the forwarded-chain test (§2). Must be the **balancer's** source range in this topology or all `CF-*` headers are discarded. Set in the real environment, not only `.env`. |
| `TRUSTED_PROXY_HOPS` | `2` | Trusted proxy hops for ProxyFix / client-IP resolution (frontend `frontend.py:118`, panel `panel_app/auth.py:68-73`). The backend uses a **separately named** `BACKEND_TRUSTED_PROXY_HOPS`, default `1` (`backend.py:57`). |

### Related config being added by other agents — set these, but verify names before scripting

Confirmed present in the tree today:

| Var | Default | Status / effect |
|---|---|---|
| `RATELIMIT_STORAGE_URI` | *(unset → `memory://`)* | **Present** — read by both limiters (`frontend.py:613`, `backend.py:191`). Point at Redis (§4). |
| `ORACLE_POOL_TIMEOUT` | `5` (s) | **Present** — Oracle pool wait timeout (`database.py`), applied with `POOL_GETMODE_TIMEDWAIT`. Bounds how long a request waits for a free DB session under load. |
| `ORACLE_POOL_MAX` | per-tier (backend/frontend `4`, engine/database `2`; `main.py` sets `2` for backend/engine under gunicorn) | **Present** — max Oracle pool size. Keep the fleet total under the ATP's ~20 shared sessions. |
| `PANEL_LIMIT_CONCURRENCY` | `64` | **Present** — uvicorn concurrency cap on the panel (`asgi_panel.py:237,286`). |
| `PANEL_TIMEOUT_KEEP_ALIVE` | `5` | **Present** — panel keep-alive seconds (`asgi_panel.py:238,289`). |
| `PANEL_LIMIT_MAX_REQUESTS` | `0` (unlimited) | **Present** — worker recycle after N requests (`asgi_panel.py:239`). |
| `PANEL_BACKLOG` | `128` | **Present** — panel listen backlog (`asgi_panel.py:240,294`). |
| `RATELIMIT_RETRY_AFTER_SECONDS` | `60` | **Present** — `Retry-After` value on the backend's 429 (`backend.py:293,305`). Floored at 1. The frontend computes its own from the breached limit's window instead (see below). |
| `HEALTH_CACHE_TTL` | `8.0` (s) | **Present** — how long one `/health` dependency verdict is reused process-wide (`frontend.py:1874`). Capped at 60. Keeps the balancer's polling from running a probe per request. |
| `HEALTH_PROBE_TIMEOUT` | `3.0` (s) | **Present** — timeout on the `/health` backend probe (`frontend.py:1875`). Bounds how long a wedged backend can hold the probe. |
| `PANEL_PROXY_TIMEOUT` | `8.0` (s) | **Present** — timeout on the frontend's proxied call to the panel (`frontend.py:103,1547`). Bounds how long a stalled panel can pin a frontend worker thread. |
| `AD_CACHE_TTL` | `45.0` (s) | **Present** — TTL on the frontend's cached ad-settings lookup (`frontend.py:2471`). Capped at 300. Keeps page renders off the backend/Oracle path under load. |

Present but **not env-configurable** — panel GET rate limits are hard-coded in
`panel_app/security_headers.py` `RateLimitMiddleware`: GET/HEAD/OPTIONS **600**
per **60s**, mutating verbs **60** per 60s (constructor defaults, instantiated at
`panel_app/__init__.py:188` passing only `trust_proxy`). There is no
`PANEL_RATE*` env var; changing these needs a code edit. The middleware **does**
emit `Retry-After` on its 429 (`security_headers.py:198-206`).

**`Retry-After` on 429s — now present on every tier.** Both Flask tiers emit it:

- `backend.py:296-306` — `errorhandler(429)` builds the response explicitly so a
  header can be hung on it, and sets `Retry-After` from
  `RATELIMIT_RETRY_AFTER_SECONDS` (default `60`, `backend.py:293`). Fixed rather
  than computed: flask-limiter only derives an exact reset time with header
  injection enabled, which it is not here, and a value guessed too low invites
  the instant retry the header exists to prevent.
- `frontend.py:670-687` — `errorhandler(429)` reads the breached limit's own
  window via `e.limit.limit.get_expiry()` and clamps it to `[60, 3600]`,
  defaulting to `60` if that lookup fails. The window, not a live reset time, on
  purpose: reading the latter costs a storage round trip on exactly the path a
  flood is already hammering, and the daily default limit's window is a full
  86400s, hence the clamp.

Already present before those: `panel_app/security_headers.py:198-206`,
`edge_gate.py:670` (shed 503, value = `GATE_IP_COOLDOWN`), and the node-agent
limiter. No tier now answers 429 without a back-off hint.

**`/health` dependency check — now present on the frontend.**
`frontend.py:1981-1986` returns `200 {"ok": true}` when the backend dependency
answers and `503 {"ok": false}` when it does not, so an instance whose backend or
Oracle is gone drops out of the OCI balancer's rotation instead of staying green
while it can only serve errors — but only for as long as shedding can help:
after `HEALTH_FAIL_MAX_SECONDS` (default `90.0`s, `frontend.py:1887`) of
continuous failure the verdict flips back to `200 {"ok": false, "degraded":
true}` (`_health_verdict`, `:1962-1970`), because draining every instance of a
fleet whose shared dependency is down empties the balancer rather than
protecting anything. Still `@limiter.exempt`, and still cheap: the
verdict is cached process-wide by `_dependencies_ok()` (`frontend.py:1895-1959`)
for `HEALTH_CACHE_TTL` (default `8.0`s, capped at 60) with a probe timeout of
`HEALTH_PROBE_TIMEOUT` (default `3.0`s), so the balancer's few-second polling
never runs a probe per request — an expensive health endpoint is its own denial
of service. A cold process reports healthy until its first probe lands, so a
deploy does not flap out of rotation for one TTL.

Note the interaction with §8 and the final note: `/health` remains exempt from
shedding (`edge_gate.py:118-123`), so a flood can never *fake* a 503 here — only
a genuinely dead dependency produces one.

Still **absent** (do not assume): `backend.py` has no `/health` route at all, and
the panel has none; the node-agent's own `/health` (`node_agent/app.py:263`)
reports liveness only, not dependencies.

---

## What this does NOT protect against

- **Volumetric / L3–L4 floods.** Everything in `app/` is origin-side mitigation:
  it makes each *application* request cheap to reject, but it still requires the
  packet to arrive and a socket to accept it. A genuine volumetric attack — bandwidth
  or SYN flood large enough to saturate the link or the LB — must be absorbed
  **at the edge** (Cloudflare, §3). The origin controls buy survival against
  application-layer floods that slip past the edge, not against raw volume.
- **A leaked origin IP (§1) or a reachable `8081` (§5)** bypasses the edge
  entirely. No origin control compensates for either; they are firewall
  problems.
- **Withdrawing an instance makes things worse, which is why hard-close is off.**
  `GATE_HARD_CLOSE` defaults to `0` (`edge_gate.py:503-520`). Closing the
  listener looks like the strongest response and is the weakest here: the two
  instances sit behind one OCI balancer, so when instance A unbinds, the balancer
  moves **all** traffic — the flood included — to instance B, which then crosses
  the same threshold and goes dark too, taking both down. Shedding (a static 503,
  socket kept open, listener kept bound) keeps both instances answering real
  visitors while dropping the flood, which is why it is the default. Do not enable
  hard close to "fight harder" — it finishes the job the attack started.
- **The `/health` probe is deliberately never shed** (`edge_gate.py:118-123`):
  shedding it would make the balancer declare the instance dead and shift every
  visitor (and the flood) to the other one — the same both-down failure mode.

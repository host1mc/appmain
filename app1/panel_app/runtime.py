"""Panel runtime state — the long-lived objects a mounted panel needs.

One :class:`PanelRuntime` is built at mount time and stashed on ``app.state``.
It owns the storage handle, the node client, and the two short-lived caches —
exactly the closures ``create_app`` kept alive in the
Flask panel, lifted onto an object so the async routes can reach them.

``database`` is an async store (see :mod:`panel_app.store`): Oracle-backed by
default so both load-balanced instances share the same rows, SQLite-backed for
the laptop smoke test. Routes always ``await`` it.

The node client is synchronous (urllib / filesystem). Routes call these helpers
through ``starlette.concurrency.run_in_threadpool`` so the event loop never blocks.
"""

import logging
import os
import threading
import time

from .config import PanelConfig

_log = logging.getLogger(__name__)
from .node_client import NodeClient, NodeClientError, build_node_client
from .node_router import NodeRouter
from .panel_database import PanelDatabase
from .panel_settings import SettingsReader
from .store import build_store


CATALOG_TTL = 60
CATALOG_FAILURE_BACKOFF = 30
# How long a render may wait on a catalog it holds no copy of. A reachable agent
# answers in milliseconds, so this costs the healthy path nothing; an unreachable
# one is firewalled rather than refusing, so its connect sits until the node
# client's own timeout. That is the whole of the stall on the deploy and server
# pages — the stale-while-revalidate path in get_catalog cannot cover it, because
# a cache that has never once been filled has nothing stale to serve, so every
# visit past the failure backoff paid a full node timeout. Past this the page
# renders without the catalog and the fetch finishes behind it, so the next load
# has it.
CATALOG_COLD_WAIT = 1.5

NODE_LIST_TTL = 30
NODE_LIST_FAILURE_BACKOFF = 30

# The runtime list the deploy page falls back to when no catalog has ever been
# fetched. A reachable agent's own catalog replaces this on the first fetch and is
# the only thing that decides what can actually be built — this exists so the
# deploy form is never rendered empty. A cold cache used to hand the page nothing,
# which meant an empty runtime grid, a disabled submit and a banner explaining
# that to a customer; now the page is always complete and the node is asked
# whether it can build the chosen runtime at deploy time, where a refusal has
# something to report to.
#
# Mirrors node-agent/node_agent/catalog.py, in the shape public_catalog() returns.
# That package is deployed to the hosting node, not here, so it cannot be
# imported — test_fallback_runtimes.py compares the two and fails on drift.
FALLBACK_RUNTIMES = {
    "nodejs": {
        "label": "Node.js",
        "versions": ["18", "20", "22", "24"],
        "default_version": "22",
        "default_startup": "npm install && node index.js",
    },
    "python": {
        "label": "Python",
        "versions": ["3.10", "3.11", "3.12", "3.13"],
        "default_version": "3.13",
        "default_startup": "pip install -r requirements.txt && python main.py",
    },
    "ruby": {
        "label": "Ruby",
        "versions": ["3.1", "3.2", "3.3", "3.4"],
        "default_version": "3.3",
        "default_startup": "bundle install && ruby main.rb",
    },
    "go": {
        "label": "Go",
        "versions": ["1.21", "1.22", "1.23", "1.24"],
        "default_version": "1.23",
        "default_startup": "go run .",
    },
    "php": {
        "label": "PHP",
        "versions": ["8.1", "8.2", "8.3", "8.4"],
        "default_version": "8.3",
        "default_startup": "php main.php",
    },
    "bun": {
        "label": "Bun",
        "versions": ["1", "1.1", "1.2"],
        "default_version": "1",
        "default_startup": "bun install && bun run index.ts",
    },
}


class PanelRuntime:
    def __init__(self, config: PanelConfig, *, node_client=None, store=None, session_factory=None):
        self.config = config

        if store is None:
            # The SQLite file is only created for the sqlite backend; the Oracle
            # backend never touches the filesystem.
            sync_database = None
            if config.store == "sqlite":
                sync_database = PanelDatabase(config.database_path)
                sync_database.initialize()
            store = build_store(config, database=sync_database, session_factory=session_factory)
        self.database = store

        if node_client is None:
            if not config.node_token:
                raise RuntimeError(
                    "NODE_TOKEN must be configured: the panel talks to the real "
                    "node agent only — the filesystem demo node has been removed"
                )
            node_client = NodeClient(config.node_url, config.node_token)
        self.node_client = node_client
        self.node_router = NodeRouter(self.database, config)

        self._catalog_cache = {"data": None, "fetched_at": 0.0, "failed_at": 0.0}
        self._node_list_caches = {}
        self._catalog_refreshing = False
        self._catalog_done = None
        self._catalog_started = 0.0
        self._node_list_refreshing = set()

        # These caches are read from worker threads (routes reach them through
        # run_in_threadpool), so without a lock every concurrent miss made its own
        # node call: a cold cache and four tabs meant four round trips, and the
        # cache only spared the requests that arrived after the first one had
        # already stored its answer. One holder fetches, the rest wait and take
        # what it stored. Separate locks so a server-list fetch cannot be held up
        # behind a catalog fetch.
        self._catalog_lock = threading.Lock()
        self._node_list_lock = threading.Lock()
        # Guards the catalog's refreshing flag and completion event as a pair. A
        # caller that read the flag and then took the event could otherwise be
        # handed the event of a thread that had already finished and cleared it,
        # and would wait out the whole grace period for a fetch that was over.
        self._catalog_state_lock = threading.Lock()

        # The database-backed controls (maintenance mode, feature switches,
        # allocation figures). Reads are cached and fall back to `config` when the
        # shared settings table cannot be reached — see panel_settings.
        self.settings = SettingsReader(config)

        # Background fleet health check: pings every enabled node on an interval
        # and records one deduplicated app_errors row per unreachable node, with
        # the node's id, name and URL so the console names the offender. A fleet
        # with no enabled nodes runs no checks and writes nothing. Every failure
        # is swallowed — this thread must never take a page down with it.
        threading.Thread(
            target=self._reachability_loop,
            name="panel-node-reachability",
            daemon=True,
        ).start()

    # -- fleet reachability check ------------------------------------------

    REACHABILITY_INTERVAL_DEFAULT = 300
    REACHABILITY_INTERVAL_MIN = 60

    def _reachability_interval(self):
        try:
            value = int(os.environ.get("NODE_REACHABILITY_CHECK_SECONDS", "") or self.REACHABILITY_INTERVAL_DEFAULT)
        except (TypeError, ValueError):
            value = self.REACHABILITY_INTERVAL_DEFAULT
        return max(self.REACHABILITY_INTERVAL_MIN, value)

    def _log_node_problem(self, error_type, message):
        # reviews_db.log_app_error deduplicates on (type, message, module,
        # reason), so a node that stays down produces one row, not one per sweep.
        # It also prints nothing unless console debug is enabled.
        try:
            import reviews_db
            reviews_db.log_app_error(
                error_type, message, module="panel_runtime", flagged=1,
                flag_reason="node_health",
            )
        except Exception:
            pass

    def check_node_reachability(self):
        """Ping every enabled node; one DB error row per unreachable one.

        Silent by design: a healthy fleet — or no nodes at all — produces no
        output and no rows. Nothing here raises.
        """
        try:
            import node_registry
            nodes = [n for n in (node_registry.list_nodes() or []) if n.get("enabled")]
        except Exception:
            return {"checked": 0, "down": []}
        summary = {"checked": len(nodes), "down": []}
        for node in nodes:
            nid = node.get("id")
            name = str(node.get("name") or f"node {nid}")
            try:
                creds = node_registry.get_node_credentials(nid)
            except Exception as exc:
                self._log_node_problem(
                    "NodeCredentialsUnreadable",
                    f"node {nid} '{name}': stored credentials could not be read ({type(exc).__name__})",
                )
                summary["down"].append(nid)
                continue
            if not creds or not creds.get("url") or not creds.get("token"):
                self._log_node_problem(
                    "NodeCredentialsMissing",
                    f"node {nid} '{name}' has no stored URL or token — re-register it",
                )
                summary["down"].append(nid)
                continue
            try:
                client = build_node_client(creds["url"], creds["token"])
            except (ValueError, NodeClientError):
                self._log_node_problem(
                    "NodeURLUnusable",
                    f"node {nid} '{name}' at {creds['url']}: the URL is unusable",
                )
                summary["down"].append(nid)
                continue
            if client.ping():
                continue
            self._log_node_problem(
                "NodeUnreachable",
                f"node {nid} '{name}' at {creds['url']} did not answer its health probe",
            )
            summary["down"].append(nid)
        return summary

    def _reachability_loop(self):
        while True:
            time.sleep(self._reachability_interval())
            try:
                self.check_node_reachability()
            except Exception:
                pass

    # -- catalog / runtimes ------------------------------------------------

    def get_catalog(self):
        cache = self._catalog_cache
        now = time.time()
        data = cache["data"]
        if data is not None and now - cache["fetched_at"] < CATALOG_TTL:
            return data
        if data is not None:
            # Stale, not missing — so serve it and refresh behind the request. The
            # catalog is the node agent's list of runtime images, which changes
            # when that agent is redeployed and not otherwise; a page rendering a
            # copy of it a minute old is correct. Blocking one visitor per TTL on a
            # round trip to discover nothing had changed is what made the deploy
            # and server pages stall, and with two load-balanced instances holding
            # separate caches it was two visitors per TTL.
            self._refresh_catalog_soon(now)
            return data
        if now - cache["failed_at"] < CATALOG_FAILURE_BACKOFF:
            raise NodeClientError("node agent is unreachable")
        # Nothing cached at all, so there is no stale copy the path above could
        # have served. Hand the fetch to a background thread and wait a bounded
        # moment for it, rather than holding the render open for however long the
        # node client is willing to wait on a connect. Concurrent cold callers all
        # get the same event back, so exactly one of them fetches.
        waitable = self._refresh_catalog_soon(now)
        if waitable is not None:
            done, budget = waitable
            if budget > 0:
                done.wait(budget)
        data = cache["data"]
        if data is not None:
            return data
        raise NodeClientError("node agent is unreachable")

    def _fetch_catalog(self):
        """Fetch and store the catalog. Callers hold ``_catalog_lock``."""
        cache = self._catalog_cache
        try:
            client = self._catalog_client()
            data = client.catalog()
        except NodeClientError as exc:
            # Operational errors are logged to HeatWave DB and flagged
            try:
                import reviews_db
                reviews_db.log_app_error(
                    error_type="NodeCatalogFetchFailed",
                    message=f"catalog fetch failed: {exc}",
                    module="panel_app",
                    flagged=1,
                    flag_reason="node_unreachable"
                )
                if reviews_db.is_console_debug_enabled():
                    _log.warning("catalog fetch failed: %s", exc)
            except Exception:
                pass
            cache["failed_at"] = time.time()
            raise
        except Exception as exc:
            try:
                import reviews_db
                reviews_db.log_app_error(
                    error_type="NodeCatalogFetchFailed",
                    message=f"_fetch_catalog failed with non-node error: {type(exc).__name__}: {exc}",
                    module="panel_app",
                    flagged=1,
                    flag_reason="node_error"
                )
                if reviews_db.is_console_debug_enabled():
                    _log.warning("_fetch_catalog failed with non-node error: %s: %s", type(exc).__name__, exc)
            except Exception:
                pass
            cache["failed_at"] = time.time()
            raise NodeClientError("node agent is unreachable") from exc
        cache["data"] = data
        cache["fetched_at"] = time.time()
        cache["failed_at"] = 0.0
        return data

    def _catalog_client(self):
        """Return a node client from the first enabled database node.

        Only reads nodes from the Oracle ``NODES`` table — the .env
        NODE_URL/NODE_TOKEN are never used here.  The catalog is a global
        property of any reachable node, so the first one that answers is fine.
        Raises NodeClientError if no enabled node is configured in the database.
        """
        return self._node_client_from_db()

    def _node_client_from_db(self):
        """Build a NodeClient from the first reachable enabled database node.

        Tries every enabled node in order, pinging each one (including
        comma-separated failover URLs).  Returns the first reachable client.
        Raises NodeClientError if no enabled node is reachable.
        """
        from .node_client import build_node_client
        try:
            import node_registry
            nodes = node_registry.list_nodes()
        except NodeClientError:
            raise
        except Exception as exc:
            _log.warning("node_registry lookup failed: %s: %s", type(exc).__name__, exc)
            raise NodeClientError(
                "failed to query node registry: " + str(exc)[:200]
            ) from exc
        _log.debug("node_registry returned %d node(s)", len(nodes))
        last_exc = None
        for node in nodes:
            if not node.get("enabled"):
                continue
            nid = node.get("id")
            try:
                creds = node_registry.get_node_credentials(nid)
            except NodeClientError:
                raise
            except Exception as exc:
                _log.warning(
                    "get_node_credentials(%s) failed: %s: %s",
                    nid, type(exc).__name__, exc,
                )
                continue
            if creds and creds.get("url") and creds.get("token"):
                _log.info("resolved node %s url=%s", nid, creds["url"])
                try:
                    client = build_node_client(creds["url"], creds["token"])
                except (ValueError, NodeClientError) as exc:
                    _log.warning("node %s has an unusable URL: %s", nid, exc)
                    last_exc = exc
                    continue
                # build_node_client no longer decides reachability, so the check
                # that moves on to the next node happens here. ping walks every
                # address the node lists, so a node is only skipped when none of
                # them answers — not merely because this instance cannot route to
                # the one that happens to be listed first.
                if not client.ping():
                    try:
                        import reviews_db
                        if reviews_db.is_console_debug_enabled():
                            _log.warning("node %s answered on none of its addresses", nid)
                    except Exception:
                        pass
                    continue
                return client
        err_msg = "no reachable node in the database — all nodes are down"
        try:
            import reviews_db
            reviews_db.log_app_error(
                error_type="NoReachableNodeError",
                message=err_msg,
                module="panel_app",
                flagged=1,
                flag_reason="all_nodes_down"
            )
        except Exception:
            pass
        raise NodeClientError(err_msg)

    def _all_node_clients(self):
        """Every enabled node as ``(node_id, NodeClient)``.

        Reconcile must reach *every* node, not just the first that answers the
        way the catalog probe does: an orphan container can outlive its DB row
        on any node in the fleet. Falls back to the .env single-node client when
        the registry is empty or unreachable, which is the same node the deploy
        path targets on a one-node install.

        Supports comma-separated URLs in the ``url`` column: each URL is tried
        in order and the first reachable one is used.  This lets both a public
        hostname (for VPS B) and ``http://127.0.0.1:8081`` (for VPS A which
        hosts the node agent) coexist in one row.
        """
        clients = []
        try:
            import node_registry
            nodes = node_registry.list_nodes()
        except Exception as exc:
            _log.warning("reconcile: node registry lookup failed: %s: %s", type(exc).__name__, exc)
            nodes = []
        for node in nodes:
            if not node.get("enabled"):
                continue
            nid = node.get("id")
            try:
                creds = node_registry.get_node_credentials(nid)
            except Exception as exc:
                _log.warning("reconcile: credentials for node %s failed: %s", nid, exc)
                continue
            if creds and creds.get("url") and creds.get("token"):
                try:
                    clients.append((nid, build_node_client(creds["url"], creds["token"])))
                except (ValueError, NodeClientError) as exc:
                    _log.warning("reconcile: node %s all URLs unreachable: %s", nid, exc)
        if not clients:
            if self.config.node_token and self.config.node_token.strip():
                clients.append(("env", self.node_client))
        return clients

    async def reconcile_orphans(self, *, max_delete=None):
        """Delete node containers whose id no longer exists in the database.

        The database is the source of truth: a managed container with no
        ``panel_servers`` row is an orphan whose row was deleted while its node
        was unreachable, so the push DELETE never landed. Builds the
        authoritative allowlist once and hands it to every node.

        Deferred deletes are the exception: a container whose HeatWave tombstone
        is still queued was already logically deleted by its owner, and its
        physical removal is an admin decision made in the admin panel. Those
        ids travel as ``protect_ids`` so no sweep pass may touch them — the
        automatic path can never destroy data a person has not confirmed.

        Fail-safe on a bad DB read: ``all_server_ids()`` raises on a closed or
        failing connection (``OracleStore`` heal-retries only ORA-00904 and
        re-raises everything else), and that exception propagates out of here
        before any node is contacted — so nothing is deleted, the sweep just
        retries next cycle. ``known is None`` is a secondary net for a store
        that returns None rather than raising. ``max_delete`` bounds each node's
        deletions so a partial allowlist cannot wipe a node in one pass. Finally,
        each node refuses an *empty* allowlist while it still has managed
        containers (see ``ServerManager.reconcile``): so even if this panel is
        pointed at a fresh/backup database after an operator failover and reads
        an empty ``panel_servers``, the nodes keep the servers the old database
        knew rather than wiping them. The guarantee therefore holds at both ends.
        """
        from starlette.concurrency import run_in_threadpool

        if not self.config.reconcile_enabled:
            return {"ok": True, "disabled": True, "nodes": {}}

        known = await self.database.all_server_ids()
        if known is None:
            _log.warning("reconcile: allowlist query returned None — skipping sweep")
            return {"ok": False, "error": "no allowlist"}
        # Tombstoned ids (deferred deletes waiting for an admin's manual
        # confirm in the admin panel) are handed to the sweep as protected:
        # their DB row is already gone, so without this they would read as
        # orphans and be auto-deleted — exactly the data loss this queue
        # exists to prevent. Best-effort: with HeatWave down the sweep falls
        # back to its pre-tombstone behavior.
        protect_ids = []
        try:
            import reviews_db
            rows = await run_in_threadpool(reviews_db.list_container_deletions)
            protect_ids = [row["server_id"] for row in (rows or []) if row.get("server_id")]
        except Exception as exc:
            _log.warning("reconcile: pending-deletion lookup failed: %s: %s", type(exc).__name__, exc)
        cap = max_delete if max_delete is not None else self.config.reconcile_max_delete
        summary = {"ok": True, "known": len(known), "nodes": {}}
        if protect_ids:
            summary["protected"] = len(protect_ids)
        for nid, client in self._all_node_clients():
            try:
                result = await run_in_threadpool(
                    lambda c=client: c.reconcile(
                        known, purge=True, max_delete=cap, protect_ids=protect_ids
                    )
                )
                summary["nodes"][str(nid)] = result
                if result.get("removed"):
                    _log.info("reconcile: node %s removed %d orphan(s): %s",
                              nid, len(result["removed"]), result["removed"])
                    # A node only reports tombstoned ids removed when the
                    # protect list could not be loaded (HeatWave was down), so
                    # the removal already happened — clear those rows so the
                    # admin queue stays honest.
                    try:
                        import reviews_db
                        reviews_db.clear_container_deletions(result["removed"])
                    except Exception:
                        pass
                if result.get("refused"):
                    _log.warning("reconcile: node %s refused: %s", nid, result["refused"])
            except Exception as exc:
                cause = exc.__cause__
                cause_str = f" (cause: {type(cause).__name__}: {cause})" if cause else ""
                err_msg = f"reconcile: node {nid} sweep failed: {type(exc).__name__}: {exc}{cause_str}"
                try:
                    import reviews_db
                    reviews_db.log_app_error("ReconcileSweepFailed", err_msg, module="panel_runtime", flagged=1)
                    if reviews_db.is_console_debug_enabled():
                        _log.warning(err_msg)
                except Exception:
                    pass
                summary["nodes"][str(nid)] = {"ok": False, "error": str(exc)[:200]}
        return summary

    def _refresh_catalog_soon(self, now):
        """Start a catalog fetch unless one is pointless or already running.

        Returns ``(event, seconds)``: the event the fetching thread sets when it is
        done, and how much of the cold-start grace period that fetch has left. A
        caller holding no cached copy waits on the fetch's own remaining budget
        rather than restarting the clock when it arrives. ``None`` means there is
        no fetch in flight to wait for.
        """
        if now - self._catalog_cache["failed_at"] < CATALOG_FAILURE_BACKOFF:
            return None
        with self._catalog_state_lock:
            if self._catalog_refreshing:
                # Measured from when that fetch started, not from now: an agent
                # that takes longer than the grace period to fail would otherwise
                # stall every arrival for the whole of it, one after another, for
                # as long as the doomed connect lasted.
                remaining = CATALOG_COLD_WAIT - (time.monotonic() - self._catalog_started)
                return self._catalog_done, max(0.0, remaining)
            done = threading.Event()
            self._catalog_refreshing = True
            self._catalog_done = done
            self._catalog_started = time.monotonic()
            try:
                threading.Thread(
                    target=self._refresh_catalog,
                    args=(done,),
                    name="panel-catalog-refresh",
                    daemon=True,
                ).start()
            except RuntimeError:
                # Interpreter shutdown, or the process is out of threads. A stale
                # copy has already been returned above where there was one, and a
                # cold caller falls through to its own fast failure.
                self._catalog_refreshing = False
                self._catalog_done = None
                return None
            return done, CATALOG_COLD_WAIT

    def _refresh_catalog(self, done):
        # Non-blocking: holding the lock means another thread is fetching this
        # same catalog, and waiting to repeat its work would keep this thread
        # alive for the length of a node round trip to no purpose.
        try:
            if not self._catalog_lock.acquire(blocking=False):
                return
            try:
                self._fetch_catalog()
            except NodeClientError:
                pass
            finally:
                self._catalog_lock.release()
        finally:
            # Set on every exit, the bail above included: a cold caller is waiting
            # on this event, and leaving it unset would cost that caller the whole
            # grace period for a fetch this thread never made.
            with self._catalog_state_lock:
                self._catalog_refreshing = False
                if self._catalog_done is done:
                    self._catalog_done = None
            done.set()

    def cached_runtimes(self):
        try:
            runtimes = self.get_catalog().get("runtimes", {})
            # node_client guarantees the top level is a dict and nothing more, so
            # the value under "runtimes" is still whatever the agent sent. Callers
            # and templates walk it as a mapping.
            return (runtimes if isinstance(runtimes, dict) else {}), ""
        except NodeClientError as exc:
            cached = (self._catalog_cache["data"] or {}).get("runtimes", {})
            if not isinstance(cached, dict) or not cached:
                cached = FALLBACK_RUNTIMES
            return cached, str(exc)

    # -- node server list --------------------------------------------------

    def get_node_servers(self, *, blocking=True):
        client = self._node_client_from_db()
        return self.node_servers_for("", client, blocking=blocking)

    def node_servers_for(self, cache_key, client, *, blocking=True):
        # setdefault, not get-then-assign: two threads missing the same key at once
        # each built their own cache dict and one of them was dropped along with
        # the fetch it had just stored.
        cache = self._node_list_caches.setdefault(
            cache_key, {"data": {}, "fetched_at": 0.0, "failed_at": 0.0}
        )
        now = time.time()
        # Keyed on having fetched rather than on the payload: an agent with no
        # servers answers {}, and testing that for truth means the empty answer is
        # never cached and every request re-queries the agent.
        if cache["fetched_at"] and now - cache["fetched_at"] < NODE_LIST_TTL:
            return cache["data"]
        if now - cache["failed_at"] < NODE_LIST_FAILURE_BACKOFF:
            return {}
        if not blocking:
            # How the dashboard's HTML render asks. Live status is decorative
            # there: q2.js polls /api/servers/status on load and every 6 s
            # after, and _effective_status already falls back to the server's
            # recorded desired_state for any id the map has no entry for — so an
            # unreachable agent renders the same page whether this waited or not,
            # and a reachable one is corrected within a tick. Waiting cost a full
            # list_servers timeout on the first render of every back-off window.
            self._refresh_node_servers_soon(cache_key, client)
            return cache["data"]
        with self._node_list_lock:
            # As in get_catalog: the thread that held the lock has already asked
            # the agent, so re-check before asking it again.
            now = time.time()
            if cache["fetched_at"] and now - cache["fetched_at"] < NODE_LIST_TTL:
                return cache["data"]
            if now - cache["failed_at"] < NODE_LIST_FAILURE_BACKOFF:
                return {}
            try:
                response = client.list_servers()
                by_id = self._servers_by_id(response.get("servers", []))
            except NodeClientError:
                cache["failed_at"] = time.time()
                return {}
            cache["data"] = by_id
            cache["fetched_at"] = now
            cache["failed_at"] = 0.0
            return by_id

    def _refresh_node_servers_soon(self, cache_key, client):
        # As with the catalog, this flag only keeps a busy page from starting one
        # thread per request. A racing reader that slips past it blocks on
        # _node_list_lock and then finds the cache already filled, so a duplicate
        # costs a waiting thread rather than a second round trip.
        if cache_key in self._node_list_refreshing:
            return
        self._node_list_refreshing.add(cache_key)
        try:
            threading.Thread(
                target=self._refresh_node_servers,
                args=(cache_key, client),
                name="panel-node-list-refresh",
                daemon=True,
            ).start()
        except RuntimeError:
            # Interpreter shutdown, or out of threads. The caller already has the
            # cached copy, so there is nothing to report.
            self._node_list_refreshing.discard(cache_key)

    def _refresh_node_servers(self, cache_key, client):
        try:
            # The blocking path owns the lock, the store and the failure
            # back-off, and it answers an unreachable agent with {} rather than
            # raising, so there is nothing left for this thread to handle.
            self.node_servers_for(cache_key, client)
        finally:
            self._node_list_refreshing.discard(cache_key)

    @staticmethod
    def _servers_by_id(servers):
        """Index the agent's server list by id, skipping anything unusable.

        Only the top level of an agent response is known to be a dict, so the list
        under "servers" is unvalidated: a bare string in it, or an entry with no
        id, would raise past the ``NodeClientError`` handler above and turn every
        page that lists servers into a 500.
        """
        by_id = {}
        if not isinstance(servers, list):
            return by_id
        for item in servers:
            if not isinstance(item, dict):
                continue
            server_id = item.get("id")
            if isinstance(server_id, str) and server_id:
                by_id[server_id] = item
        return by_id

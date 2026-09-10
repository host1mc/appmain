import logging
import time

from starlette.concurrency import run_in_threadpool

from .node_client import NodeClient, NodeClientError, build_node_client


_log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 300

CACHE_FAIL_TTL_SECONDS = 30

CACHE_MAX_ENTRIES = 64

# How long the chosen default node is reused. The pick used to be latched for the
# life of the process, so a node that went down was never given up and — worse —
# a resolution that found nothing because the DB was briefly unreachable made the
# panel report "no enabled node" until it was restarted.
DEFAULT_TTL_SECONDS = 300

# A failed resolution is cached far more briefly than a good one: it is usually a
# transient DB or network fault, and retrying soon is cheap.
DEFAULT_FAIL_TTL_SECONDS = 15

_USE_DEFAULT = object()


class NodeRouter:
    def __init__(self, store, config):
        self._store = store
        self._config = config
        self._default_client = None
        self._default_expires_at = 0.0
        self._cache = {}

    def _nodes_by_free_capacity(self, node_registry):
        """Enabled nodes, the ones with room for another container first.

        Placement and reachability are two separate questions and the fleet needs
        both answered: a full node is no use for a deploy, and a node whose agent
        cannot be reached is no use for anything. Full nodes are ordered last
        rather than dropped, because the panel also needs a client for reads — the
        runtime catalog above all — so a fleet whose every node is full still has
        to render its pages.
        """
        try:
            nodes = node_registry.list_nodes_with_usage()
        except Exception as exc:
            _log.warning(
                "node_router: node usage unavailable (%s); ordering by id only",
                type(exc).__name__,
            )
            nodes = node_registry.list_nodes()

        def _free(node):
            try:
                return max(int(node.get("capacity") or 0) - int(node.get("servers") or 0), 0)
            except (TypeError, ValueError):
                return 0

        enabled = [node for node in nodes if node.get("enabled")]
        enabled.sort(key=lambda node: (0 if _free(node) > 0 else 1, node.get("id") or 0))
        return enabled

    async def _resolve_default_client(self):
        """Build a NodeClient from the first reachable enabled node in the database.

        Tries every enabled node, including comma-separated failover URLs.
        Called lazily on first use, then cached.  Never falls back to the
        .env NODE_URL/NODE_TOKEN — only the database is the source of truth.
        """
        if self._default_expires_at > time.monotonic():
            return self._default_client
        client = None
        try:
            import node_registry
            nodes = self._nodes_by_free_capacity(node_registry)
            _log.debug("node_router: %d enabled node(s) to try", len(nodes))
            for node in nodes:
                nid = node.get("id")
                try:
                    creds = node_registry.get_node_credentials(nid)
                except Exception as exc:
                    _log.warning("node_router: credentials for node %s failed: %s", nid, exc)
                    continue
                if creds and creds.get("url") and creds.get("token"):
                    try:
                        candidate = build_node_client(
                            creds["url"],
                            creds["token"],
                            on_unreachable=self._invalidate_default,
                        )
                    except (ValueError, NodeClientError) as exc:
                        _log.warning("node_router: node %s has an unusable URL: %s", nid, exc)
                        continue
                    # build_node_client no longer decides reachability, so the
                    # check that moves this loop on to the next node in the fleet
                    # happens here. ping walks every address the node lists, so a
                    # node is only skipped when none of them answers.
                    if not candidate.ping():
                        continue
                    client = candidate
                    _log.info("node_router: resolved default node %s url=%s", nid, candidate.base_url)
                    break
            if client is None and len(nodes) > 0:
                try:
                    import reviews_db
                    reviews_db.log_app_error(
                        error_type="NodeRouterError",
                        message=f"node_router: no reachable node in database ({len(nodes)} enabled)",
                        module="node_router",
                        flagged=1,
                        flag_reason="no_reachable_node"
                    )
                    if reviews_db.is_console_debug_enabled():
                        _log.warning("node_router: no reachable node in database (%d enabled)", len(nodes))
                except Exception:
                    pass
        except Exception as exc:
            _log.warning("node_router: could not resolve default node from database: %s: %s", type(exc).__name__, exc)
        self._default_client = client
        self._default_expires_at = time.monotonic() + (
            DEFAULT_TTL_SECONDS if client is not None else DEFAULT_FAIL_TTL_SECONDS
        )
        return client

    def _invalidate_default(self, client=None):
        """Drop the memoised default node so the next call re-picks from the DB.

        Handed to every client this router builds: a node that stops answering
        part-way through its cache window is given up on the first failed request
        rather than at the end of the window.
        """
        if client is None or client is self._default_client:
            self._default_expires_at = 0.0

    @property
    def default_client(self):
        return self._default_client

    def _cached(self, key):
        entry = self._cache.get(key)
        if entry is None:
            return None
        client, fetched_at, ttl = entry
        if time.monotonic() - fetched_at >= ttl:
            self._cache.pop(key, None)
            return None
        return client

    def _remember(self, key, client, ttl):
        self._cache.pop(key, None)
        self._cache[key] = (client, time.monotonic(), ttl)
        while len(self._cache) > CACHE_MAX_ENTRIES:
            self._cache.pop(next(iter(self._cache)))

    async def _fall_back(self, key):
        self._remember(key, _USE_DEFAULT, CACHE_FAIL_TTL_SECONDS)
        default = await self._resolve_default_client()
        if default is None:
            # Resolution is lazy, so reaching here before the default has ever
            # been picked used to hand the caller None and fail as an
            # AttributeError inside whichever route asked.
            raise NodeClientError(
                "no enabled node found in the database — register a node first"
            )
        return default

    async def client_for(self, node_id):
        if not node_id:
            default = await self._resolve_default_client()
            if default is None:
                raise NodeClientError(
                    "no enabled node found in the database — register a node first"
                )
            return default
        key = str(node_id)
        cached = self._cached(key)
        if cached is _USE_DEFAULT:
            default = await self._resolve_default_client()
            if default is None:
                raise NodeClientError(
                    "no enabled node found in the database — register a node first"
                )
            return default
        if cached is not None:
            if cached.ping():
                return cached
            _log.warning("node %s cached client is unreachable; using the default node client", key)
            self._cache.pop(key, None)
            return await self._fall_back(key)
        try:
            credentials = await self._store.get_node_credentials(node_id)
        except Exception as exc:
            _log.warning(
                "node %s credentials unavailable (%s); using the default node client",
                key,
                type(exc).__name__,
            )
            return await self._fall_back(key)
        if not credentials:
            return await self._fall_back(key)
        try:
            client = build_node_client(
                credentials["url"],
                credentials["token"],
                on_unreachable=lambda _client, _key=key: self._cache.pop(_key, None),
            )
        except (KeyError, TypeError, ValueError, NodeClientError) as exc:
            _log.warning(
                "node %s has unusable stored credentials (%s); using the default node client",
                key,
                type(exc).__name__,
            )
            return await self._fall_back(key)
        self._remember(key, client, CACHE_TTL_SECONDS)
        return client

    async def reachable_client_for(self, node_id):
        """Like :meth:`client_for`, but the node has answered just now.

        client_for serves a memoised default without probing it, and a client it
        builds from stored credentials is not probed either, so a node that went
        down inside the cache window was first discovered by whichever call
        needed it. For a deploy that call is the create, which happens after the
        server row exists — so the row had to be rolled back again. Asking here
        instead turns a stale pick into one re-resolution.

        A named ``node_id`` is verified but never substituted: that node is the
        one the row points at, and putting the container somewhere else would
        strand it when the named node came back. Only a placement the store left
        open is re-picked, which is the one where nothing has been decided yet.
        """
        client = await self.client_for(node_id)
        if await run_in_threadpool(client.ping):
            return client
        if node_id:
            self._cache.pop(str(node_id), None)
            raise NodeClientError("the node this server is placed on is not answering")
        _log.warning("node_router: default node stopped answering; re-picking for placement")
        self._default_expires_at = 0.0
        retry = await self._resolve_default_client()
        if retry is None or not await run_in_threadpool(retry.ping):
            raise NodeClientError(
                "no reachable node found in the database — please try again shortly"
            )
        return retry

"""test_node_url_cooldown.py — the address cooldown has to outlive one client.

Run: python app/panel_app/test_node_url_cooldown.py

Nothing in the panel reuses a NodeClient: node_router rebuilds on a cache miss
and runtime._node_client_from_db builds a fresh one per catalog fetch. So a
cooldown held per instance skipped nothing, and every new client re-probed the
black-holed address for the full PROBE_TIMEOUT — which is what pushed a cold
catalog fetch past the deploy page's grace period. This check fails if that
memory goes back to being per instance, or if _ensure_active starts walking the
column order again instead of the live-first candidates.

Loads node_client.py by path on purpose: importing panel_app resolves an Oracle
connection, and this check must not touch a database.
"""

import importlib.util
import io
import json
import sys
from pathlib import Path
from urllib import error

_spec = importlib.util.spec_from_file_location(
    "_node_client_under_test", Path(__file__).with_name("node_client.py")
)
node_client = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = node_client
_spec.loader.exec_module(node_client)

DEAD = "http://203.0.113.9:8081"
LIVE = "http://127.0.0.1:8081"
URLS = f"{DEAD},{LIVE}"
TOKEN = "t" * 32


class _Body(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _opener(attempts):
    """An opener that black-holes DEAD and answers as the agent on LIVE."""

    def open_(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        attempts.append(url)
        if url.startswith(DEAD):
            raise error.URLError(TimeoutError("timed out"))
        return _Body(json.dumps({"service": "node-agent", "ok": True}).encode())

    return open_


def _client(attempts):
    return node_client.NodeClient(URLS, TOKEN, opener=_opener(attempts))


def _reset():
    with node_client._dead_urls_lock:
        node_client._dead_urls.clear()


def main():
    _reset()

    first = []
    assert _client(first).ping() is True, "the live address must answer"
    assert any(u.startswith(DEAD) for u in first), "the dead address is probed once"

    # The point of the whole change: a *different* client must inherit the verdict.
    second = []
    assert _client(second).ping() is True
    assert not any(u.startswith(DEAD) for u in second), (
        f"a new client re-probed the address already known dead: {second}"
    )

    # And a real request on a fresh client goes straight to the live address.
    third = []
    assert _client(third).catalog() == {"service": "node-agent", "ok": True}
    assert not any(u.startswith(DEAD) for u in third), (
        f"a request walked the dead address again: {third}"
    )

    # An expired cooldown puts the address back in the walk, or a node that came
    # back would stay skipped for as long as the process lived.
    with node_client._dead_urls_lock:
        node_client._dead_urls[DEAD] = 0.0
    fourth = []
    _client(fourth).ping()
    assert any(u.startswith(DEAD) for u in fourth), "an expired cooldown must lapse"

    # Every address cooling down at once still yields the full walk rather than
    # failing a request without one attempt.
    _reset()
    with node_client._dead_urls_lock:
        for url in (DEAD, LIVE):
            node_client._dead_urls[url] = float("inf")
    fifth = []
    client = _client(fifth)
    assert len(client._candidates()) == 2, "an all-dead node still gets a walk"
    assert client.ping() is True, "the live address must still be reachable"

    _reset()
    print("ok")


if __name__ == "__main__":
    main()

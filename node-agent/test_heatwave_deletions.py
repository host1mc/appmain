"""Hermetic self-check for the node-side HeatWave pending-deletion drain.

Stubs _cfg and _connect so it never touches HeatWave or Docker; verifies the
present-membership filter, the clear-only-what-was-removed rule, that a
ServerNotFound (LookupError) still clears the row while any other remove error
keeps it, and the disabled/empty no-op paths. Run: python test_heatwave_deletions.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "node_agent"))
import heatwave_deletions as hd


class FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    def __init__(self, rows):
        self.cur = FakeCursor(rows)
        self.committed = 0
        self.closed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed += 1

    def close(self):
        self.closed = True


class FakeRuntime:
    def __init__(self, present):
        self._present = present

    def list(self):
        return [{"id": i} for i in self._present]


class FakeManager:
    def __init__(self, present, errors=None):
        self.runtime = FakeRuntime(present)
        self.removed = []
        self._errors = errors or {}

    def remove(self, server_id, purge=False):
        self.removed.append((server_id, purge))
        exc = self._errors.get(server_id)
        if exc is not None:
            raise exc
        return {"ok": True}


def _wire(rows, present, errors=None):
    conn = FakeConn(rows)
    hd._cfg = lambda: {"ok": 1}
    hd._connect = lambda cfg: conn
    mgr = FakeManager(present, errors)
    return mgr, conn


def _delete_call(conn):
    for sql, params in conn.cur.calls:
        if sql.lstrip().upper().startswith("DELETE"):
            return sql, params
    return None, None


def test_only_present_are_removed_and_cleared():
    # a,c hosted here; b hosted elsewhere -> only a,c removed and cleared.
    mgr, conn = _wire([("a", 1), ("b", 1), ("c", 0)], present={"a", "c"})
    hd.drain(mgr)
    assert mgr.removed == [("a", True), ("c", False)]
    sql, params = _delete_call(conn)
    assert sql.strip().startswith("DELETE FROM pending_container_deletions")
    assert "IN (%s,%s)" in sql
    assert params == ["a", "c"]
    assert conn.committed == 1
    assert conn.closed is True


def test_purge_flag_coerced_from_tinyint():
    mgr, conn = _wire([("a", 1), ("c", 0)], present={"a", "c"})
    hd.drain(mgr)
    assert mgr.removed == [("a", True), ("c", False)]


def test_not_found_still_clears_row():
    mgr, conn = _wire([("a", 1)], present={"a"},
                      errors={"a": LookupError("gone")})
    hd.drain(mgr)
    _, params = _delete_call(conn)
    assert params == ["a"]  # LookupError => still ours, still cleared


def test_other_error_keeps_row():
    mgr, conn = _wire([("a", 1), ("c", 1)], present={"a", "c"},
                      errors={"a": RuntimeError("docker down")})
    hd.drain(mgr)
    _, params = _delete_call(conn)
    assert params == ["c"]  # a failed to remove -> its row is left to retry
    assert conn.committed == 1


def test_nothing_removed_means_no_delete_no_commit():
    mgr, conn = _wire([("a", 1)], present={"a"},
                      errors={"a": RuntimeError("docker down")})
    hd.drain(mgr)
    sql, _ = _delete_call(conn)
    assert sql is None
    assert conn.committed == 0


def test_no_present_containers_never_connects():
    connected = {"n": 0}

    def _boom(cfg):
        connected["n"] += 1
        raise AssertionError("must not connect when nothing is hosted here")

    hd._cfg = lambda: {"ok": 1}
    hd._connect = _boom
    hd.drain(FakeManager(present=set()))
    assert connected["n"] == 0


def test_disabled_is_total_noop():
    hd._cfg = lambda: None
    hd._connect = lambda cfg: (_ for _ in ()).throw(AssertionError("no connect"))
    hd.drain(FakeManager(present={"a"}))  # returns before touching runtime/connect


if __name__ == "__main__":
    _cfg, _connect = hd._cfg, hd._connect
    try:
        for name, fn in sorted(globals().items()):
            if name.startswith("test_") and callable(fn):
                fn()
                print(f"ok  {name}")
    finally:
        hd._cfg, hd._connect = _cfg, _connect
    print("ALL PASS")

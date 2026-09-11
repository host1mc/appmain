"""Self-check for reviews_db pending-container-deletion helpers.

Stubs _conn so it never touches HeatWave; verifies the SQL/param binding
(the IN-clause placeholder generation is the real footgun) and the
degrade-to-no-op paths. Run: python test_pending_deletions.py
"""
import reviews_db


class FakeCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 0
        self.rows = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        # emulate a DELETE ... IN (...) affecting one row per bound id
        if sql.lstrip().upper().startswith("DELETE"):
            self.rowcount = len([k for k in (params or {}) if k.startswith("id")])

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.cur = FakeCursor()
        self.committed = 0

    def cursor(self, *a, **k):
        return self.cur

    def commit(self):
        self.committed += 1

    def close(self):
        pass


def _run(fn, conn):
    reviews_db._conn = lambda: conn
    return fn()


def test_enqueue_binds_and_coerces():
    conn = FakeConn()
    ok = _run(
        lambda: reviews_db.enqueue_container_deletion(
            "srv1", node_id=5, node_ip="10.0.0.9,127.0.0.1", node_name="edge-1",
            purge=True, user_id="u1", username="alice", server_name="mc-1",
            reason="retention"),
        conn,
    )
    assert ok is True
    sql, params = conn.cur.calls[-1]
    assert "INSERT INTO pending_container_deletions" in sql
    assert "node_ip" in sql
    assert "ON DUPLICATE KEY UPDATE" in sql
    assert params == {"s": "srv1", "n": "5", "nm": "edge-1",
                      "ip": "10.0.0.9,127.0.0.1",
                      "p": 1, "now": params["now"],
                      "u": "u1", "un": "alice", "sn": "mc-1", "r": "retention"}
    assert conn.committed == 1


def test_enqueue_purge_false_and_none_node():
    conn = FakeConn()
    _run(lambda: reviews_db.enqueue_container_deletion("srv2", node_id=None, purge=False), conn)
    _, params = conn.cur.calls[-1]
    assert params["n"] == ""
    assert params["ip"] == ""
    assert params["p"] == 0


def test_enqueue_clamps_long_ip():
    conn = FakeConn()
    _run(lambda: reviews_db.enqueue_container_deletion(
        "srv3", node_ip="x" * 400), conn)
    _, params = conn.cur.calls[-1]
    assert len(params["ip"]) == 255


def test_list_normalizes_rows():
    conn = FakeConn()
    conn.cur.rows = [
        {"server_id": "srv1", "node_id": 5, "node_name": "edge-1",
         "node_ip": "10.0.0.9",
         "purge": 1, "requested_at": "2026-01-01T00:00:00Z",
         "user_id": "u1", "username": "alice", "server_name": "mc-1",
         "reason": "banned"},
        {"server_id": None, "node_id": None, "node_name": None, "node_ip": None,
         "purge": 0, "requested_at": None, "user_id": None, "username": None,
         "server_name": None, "reason": None},
    ]
    rows = _run(reviews_db.list_container_deletions, conn)
    sql, _ = conn.cur.calls[-1]
    assert "SELECT server_id, node_id, node_name, node_ip, `purge`, requested_at" in sql
    assert "user_id" in sql and "reason" in sql
    assert "ORDER BY requested_at" in sql
    assert rows == [
        {"server_id": "srv1", "node_id": "5", "node_name": "edge-1",
         "node_ip": "10.0.0.9",
         "purge": True, "requested_at": "2026-01-01T00:00:00Z",
         "user_id": "u1", "username": "alice", "server_name": "mc-1",
         "reason": "banned"},
        {"server_id": "", "node_id": "", "node_name": "", "node_ip": "",
         "purge": False, "requested_at": "",
         "user_id": "", "username": "", "server_name": "",
         "reason": "user_delete"},
    ]


def test_clear_placeholders_match_params():
    conn = FakeConn()
    n = _run(lambda: reviews_db.clear_container_deletions(["a", "b", "c"]), conn)
    sql, params = conn.cur.calls[-1]
    assert "IN (%(id0)s,%(id1)s,%(id2)s)" in sql
    assert params == {"id0": "a", "id1": "b", "id2": "c"}
    # every placeholder in the SQL has a matching param key
    for i in range(3):
        assert f"%(id{i})s" in sql
    assert n == 3
    assert conn.committed == 1


def test_clear_filters_blanks_and_none():
    conn = FakeConn()
    n = _run(lambda: reviews_db.clear_container_deletions([None, "", "x"]), conn)
    _, params = conn.cur.calls[-1]
    assert params == {"id0": "x"}
    assert n == 1


def test_clear_empty_is_noop():
    conn = FakeConn()
    assert _run(lambda: reviews_db.clear_container_deletions([]), conn) == 0
    assert conn.cur.calls == []  # never touched the connection


def test_degrade_when_conn_none():
    reviews_db._conn = lambda: None
    assert reviews_db.enqueue_container_deletion("s", node_id="1") is False
    assert reviews_db.clear_container_deletions(["s"]) == 0
    assert reviews_db.list_container_deletions() == []


if __name__ == "__main__":
    _orig = reviews_db._conn
    try:
        for name, fn in sorted(globals().items()):
            if name.startswith("test_") and callable(fn):
                fn()
                print(f"ok  {name}")
    finally:
        reviews_db._conn = _orig
    print("ALL PASS")

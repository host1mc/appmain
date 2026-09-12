"""Runnable check for the device_events repeat-sighting bump.

    python test_device_event_dedup.py

The helper is loaded out of database.py by name instead of importing the
module: `import database` opens the live Oracle ATP and runs schema DDL, which
is not something a check may do.
"""

import ast
import os
import re

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.py")
NAME = "_device_event_bump"


def load(name):
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            ns = {}
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, "exec"), ns)
            return ns[name]
    raise AssertionError(f"{name} is no longer a top-level function in database.py")


def binds(sql):
    return set(re.findall(r":(\w+)", sql))


def main():
    bump = load(NAME)

    sql, p = bump("DETAILS-CIPHERTEXT", "IP-CIPHERTEXT", False, "2026-09-12T10:00:00", 7)
    assert sql.startswith("UPDATE device_events SET "), sql
    assert sql.endswith(" WHERE id=:id"), sql
    assert "occurrences = NVL(occurrences,1) + 1" in sql, sql
    assert p["id"] == 7 and p["cat"] == "2026-09-12T10:00:00", p
    assert p["det"] == "DETAILS-CIPHERTEXT" and p["ip"] == "IP-CIPHERTEXT", p
    # a bind with no value is ORA/DPY-4010 at runtime, and this SET clause is
    # assembled piecemeal, so the two halves have to be checked against each
    # other on every branch rather than eyeballed once.
    assert binds(sql) == set(p), (binds(sql), set(p))

    # a repeat that carries no new context must leave the old context alone,
    # not overwrite it with NULL
    sql, p = bump(None, None, False, "t", 1)
    assert "details=" not in sql and "ip_address=" not in sql, sql
    assert binds(sql) == set(p), (binds(sql), set(p))

    sql, p = bump("D", None, False, "t", 1)
    assert "details=" in sql and "ip_address=" not in sql, sql
    assert binds(sql) == set(p), (binds(sql), set(p))

    # blocked climbs and never downgrades: an allowed repeat of a flag that was
    # blocked once must not clear the block
    for flag, want in ((True, 1), (False, 0), (None, 0), (1, 1)):
        sql, p = bump(None, None, flag, "t", 1)
        assert "blocked = GREATEST(NVL(blocked,0), :bl)" in sql, sql
        assert p["bl"] == want, (flag, p["bl"])

    print("device event dedup bump OK")


if __name__ == "__main__":
    main()

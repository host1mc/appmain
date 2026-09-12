"""Runnable check for the shared-IP index key.

    python test_ip_lookup.py

The helper is loaded out of database.py by name instead of importing the
module: `import database` opens the live Oracle ATP and runs schema DDL, which
is not something a check may do. lookup_hash() is keyed off the encryption key,
so it is stubbed with an identity marker here — what this checks is which
address gets an index value at all, and what string it is computed over.
"""

import ast
import ipaddress
import os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.py")
NAME = "_ip_lookup"


def load(name):
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            # The real lookup_hash is keyed; returning its input verbatim makes
            # the canonical string the helper hashes visible to the assertions.
            ns = {"ipaddress": ipaddress, "lookup_hash": lambda s: s}
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, "exec"), ns)
            return ns[name]
    raise AssertionError(f"{name} is no longer a top-level function in database.py")


def main():
    ip_lookup = load(NAME)

    # Nothing that identifies a visitor gets an index value. Loopback is the one
    # that caused the bug: address resolution falling back to the peer recorded
    # 127.0.0.1 for everyone, and one shared index value made unrelated accounts
    # read as "same IP".
    for bad in ("127.0.0.1", "::1", "10.0.0.9", "192.168.1.5", "172.16.0.1",
                "100.64.3.9", "169.254.1.1", "fe80::1", "0.0.0.0", "::",
                "", None, "not-an-ip", "1.2.3.4.5", "localhost", "  "):
        assert ip_lookup(bad) is None, (bad, ip_lookup(bad))

    # The address from the report still indexes, and its value is unchanged by
    # canonicalisation — stored index values stay matchable without a rebuild.
    reported = "2401:4900:577c:4e4c:c41f:45eb:4797:cde4"
    assert ip_lookup(reported) == reported, ip_lookup(reported)

    # One host, several spellings, one index value: otherwise the same visitor
    # on two logins looks like two addresses and the shared-IP check misses it.
    for group in (
        ("2401:4900:577c:4e4c:c41f:45eb:4797:cde4",
         "2401:4900:577C:4E4C:C41F:45EB:4797:CDE4",
         " 2401:4900:577c:4e4c:c41f:45eb:4797:cde4 "),
        ("2401:4900::1", "2401:4900:0:0:0:0:0:1", "2401:4900:0000::0001"),
        ("1.2.3.4", "::ffff:1.2.3.4", "::ffff:102:304"),
        ("2401:4900::1%eth0", "2401:4900::1"),
    ):
        keys = {ip_lookup(s) for s in group}
        assert len(keys) == 1, (group, keys)
        assert None not in keys, group

    # Two different routable hosts must not collapse onto one key.
    assert ip_lookup("1.2.3.4") != ip_lookup("1.2.3.5")
    assert ip_lookup(reported) != ip_lookup("1.2.3.4")

    # An IPv6 visitor and an IPv4 visitor share no index value — the reported
    # symptom, asserted directly.
    assert ip_lookup(reported) != ip_lookup("49.36.183.7")

    print("ip lookup OK")


if __name__ == "__main__":
    main()

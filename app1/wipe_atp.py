"""wipe_atp.py — drop every object in the ATP schema. ONE-SHOT OPERATOR TOOL.

    THIS DESTROYS ALL DATA IN THE ORACLE ATP SCHEMA. THERE IS NO UNDO.

Dropped: every table in USER_TABLES (CASCADE CONSTRAINTS PURGE), then every
view, sequence and standalone procedure/function/trigger the schema owns, then
the recycle bin. The schema is left completely empty.

The schema is rebuilt EMPTY on the next tier startup: database.py's init_db()
guards each CREATE TABLE with an existence check (database.py:267-268), and
panel_app/database.py's ensure_schema() recreates the panel_* tables. So the
table DEFINITIONS come back automatically; the ROWS are gone forever.

Deliberately self-contained: it does NOT import database.py, because importing
that module runs _load_config() and _ensure_oracle_cols() at module scope
(database.py:638, 655-660) and would open a connection and re-create tables as a
side effect of the import. The env/wallet bootstrap below is a copy of
database.py:100-155 so the connection shape stays identical.

Usage:
    python wipe_atp.py                 # dry run: inventory + row counts, no changes
    python wipe_atp.py --apply         # destructive; prompts for a typed phrase
    python wipe_atp.py --apply --yes   # destructive, no prompt (for a wrapper script)

Run it with the stack STOPPED. Every tier calls init_db() at startup and holds a
pool, so a running tier will both block the DDL and immediately re-create tables.

Exit codes: 0 ok / 1 error / 2 refused (bad confirmation, or objects left over).
"""

import argparse
import os
import sys

CONFIRM_PHRASE = "DROP EVERYTHING"

_HERE = os.path.dirname(os.path.abspath(__file__))
# Same path database.py:78-79 uses. The .env lives in the fastapi-oracle-app
# directory and its name is hardcoded in five modules, so it is not relocatable.
_ENV_PATH = os.path.join(_HERE, "fastapi-oracle-app", ".env")
_FILE_CFG = {}


def _load_env_file():
    """Parse the shared .env. utf-8-sig because the file carries a BOM."""
    try:
        if not os.path.exists(_ENV_PATH):
            return
        with open(_ENV_PATH, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                _FILE_CFG[k.strip()] = v.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass


def _setting(name, default=""):
    """Real environment first, then the .env, then the default — database.py's order."""
    return os.environ.get(name) or _FILE_CFG.get(name) or default


def _required_setting(name):
    value = _setting(name)
    if not value:
        raise KeyError(name)
    return value


def _connect():
    """One plain connection, mirroring database.py's wallet arguments."""
    import oracledb

    oracledb.defaults.fetch_lobs = False
    oracledb.defaults.connect_timeout = 10
    wallet_dir = os.path.abspath(
        os.path.join(_HERE, "fastapi-oracle-app",
                     _setting("ORACLE_WALLET_DIR", "./Wallet_ATP")))
    os.environ["TNS_ADMIN"] = wallet_dir
    return oracledb.connect(
        user=_required_setting("ORACLE_USER"),
        password=_required_setting("ORACLE_PASSWORD"),
        dsn=_required_setting("ORACLE_DSN"),
        config_dir=wallet_dir,
        wallet_location=wallet_dir,
        wallet_password=_setting("ORACLE_WALLET_PASSWORD", ""),
    )


def _rows(cur, sql):
    cur.execute(sql)
    return [r[0] for r in cur.fetchall()]


def _inventory(cur):
    """Every droppable object the schema owns, by category."""
    return {
        # Nested/IOT-overflow tables disappear with their parent and cannot be
        # dropped directly, so they are excluded here.
        "tables": _rows(cur, """
            SELECT table_name FROM user_tables
             WHERE nested = 'NO'
               AND (iot_type IS NULL OR iot_type != 'IOT_OVERFLOW')
             ORDER BY table_name
        """),
        "views": _rows(cur, "SELECT view_name FROM user_views ORDER BY view_name"),
        "sequences": _rows(cur, "SELECT sequence_name FROM user_sequences ORDER BY sequence_name"),
        "mviews": _rows(cur, "SELECT mview_name FROM user_mviews ORDER BY mview_name"),
        # Triggers on a dropped table go with it; only schema-level ones need care.
        "triggers": _rows(cur, """
            SELECT trigger_name FROM user_triggers
             WHERE base_object_type NOT IN ('TABLE', 'VIEW') ORDER BY trigger_name
        """),
        "plsql": _rows(cur, """
            SELECT object_name FROM user_objects
             WHERE object_type IN ('PROCEDURE', 'FUNCTION', 'PACKAGE', 'TYPE')
               AND object_name NOT LIKE 'SYS_%' ORDER BY object_name
        """),
    }


def _row_count(cur, table):
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{table}"')
        return cur.fetchone()[0]
    except Exception as e:  # unreadable is not fatal for an inventory
        return f"? ({str(e).splitlines()[0][:60]})"


def _drop_tables(cur, tables):
    """Drop in repeated passes so foreign-key order does not matter.

    CASCADE CONSTRAINTS already removes inbound FKs, so one pass is normally
    enough; the loop is there for the cases it is not (a table locked by a
    straggler process, for instance).
    """
    remaining, errors = list(tables), []
    while remaining:
        failed, progressed = [], False
        for t in remaining:
            try:
                cur.execute(f'DROP TABLE "{t}" CASCADE CONSTRAINTS PURGE')
                print(f"  dropped table  {t}")
                progressed = True
            except Exception as e:
                failed.append((t, str(e).splitlines()[0]))
        if not progressed:
            errors = failed
            break
        remaining = [t for t, _ in failed]
    return errors


def _drop_simple(cur, kind, names):
    errors = []
    for n in names:
        try:
            cur.execute(f'DROP {kind} "{n}"')
            print(f"  dropped {kind.lower():14s} {n}")
        except Exception as e:
            errors.append((n, str(e).splitlines()[0]))
    return errors


def main():
    ap = argparse.ArgumentParser(description="Drop every object in the ATP schema.")
    ap.add_argument("--apply", action="store_true",
                    help="actually drop. Without this, nothing is changed.")
    ap.add_argument("--yes", action="store_true",
                    help="skip the typed confirmation (implies --apply)")
    args = ap.parse_args()
    apply = args.apply or args.yes

    _load_env_file()
    if _setting("ORACLE_ENABLED", "false").strip().lower() != "true":
        print("ORACLE_ENABLED is not true in the environment or .env — refusing.")
        return 1

    try:
        conn = _connect()
    except KeyError as e:
        print(f"missing required setting: {e}")
        return 1
    except Exception as e:
        print(f"could not connect: {e}")
        return 1

    try:
        cur = conn.cursor()
        user = _rows(cur, "SELECT USER FROM dual")[0]
        inv = _inventory(cur)
        total = sum(len(v) for v in inv.values())

        print(f"\nschema: {user}")
        print(f"dsn:    {_setting('ORACLE_DSN')[:40]}...\n")

        if not total:
            print("schema is already empty — nothing to do.")
            return 0

        print(f"{len(inv['tables'])} tables:")
        grand = 0
        for t in inv["tables"]:
            n = _row_count(cur, t)
            if isinstance(n, int):
                grand += n
            print(f"  {t:32s} {n:>12}")
        for kind in ("views", "mviews", "sequences", "triggers", "plsql"):
            if inv[kind]:
                print(f"\n{len(inv[kind])} {kind}: {', '.join(inv[kind])}")
        print(f"\ntotal rows across readable tables: {grand}")

        if not apply:
            print("\nDRY RUN — nothing was changed.")
            print("Re-run with --apply to drop all of the above.")
            return 0

        print("\n" + "!" * 72)
        print(f"About to DROP {total} objects and DESTROY {grand} rows in {user}.")
        print("This includes live user accounts, bots, hosting servers and backups.")
        print("THERE IS NO UNDO.")
        print("!" * 72)

        if not args.yes:
            try:
                typed = input(f'\nType exactly "{CONFIRM_PHRASE}" to proceed: ')
            except (EOFError, KeyboardInterrupt):
                print("\naborted.")
                return 2
            if typed.strip() != CONFIRM_PHRASE:
                print("phrase did not match — aborted, nothing changed.")
                return 2

        print("\ndropping...")
        errors = []
        # Views and materialized views first: they can depend on tables.
        errors += [("VIEW " + n, e) for n, e in _drop_simple(cur, "VIEW", inv["views"])]
        errors += [("MVIEW " + n, e) for n, e in
                   _drop_simple(cur, "MATERIALIZED VIEW", inv["mviews"])]
        errors += [("TABLE " + n, e) for n, e in _drop_tables(cur, inv["tables"])]
        for kind, key in (("SEQUENCE", "sequences"), ("TRIGGER", "triggers")):
            errors += [(f"{kind} {n}", e) for n, e in _drop_simple(cur, kind, inv[key])]
        for name in inv["plsql"]:
            # object_type is needed to form the right DROP; re-read it per object.
            cur.execute("SELECT object_type FROM user_objects WHERE object_name = :n "
                        "AND ROWNUM = 1", {"n": name})
            row = cur.fetchone()
            if row:
                errors += [(f"{row[0]} {n}", e)
                           for n, e in _drop_simple(cur, row[0], [name])]

        # DDL is auto-committed by Oracle; this is belt-and-braces.
        conn.commit()
        try:
            cur.execute("PURGE RECYCLEBIN")
            print("  purged recyclebin")
        except Exception as e:
            print(f"  recyclebin purge failed (harmless): {str(e).splitlines()[0]}")

        left = _inventory(cur)
        left_total = sum(len(v) for v in left.values())
        print("\n" + "=" * 72)
        if errors:
            print(f"{len(errors)} object(s) could not be dropped:")
            for name, err in errors:
                print(f"  {name}: {err}")
        if left_total:
            print(f"\n{left_total} object(s) REMAIN in {user}:")
            for kind, names in left.items():
                if names:
                    print(f"  {kind}: {', '.join(names)}")
            print("\nIf tables reappeared, a tier is running and re-created them.")
            print("Stop the stack and re-run.")
            return 2
        print(f"{user} is now empty. {total} objects dropped.")
        print("The next tier startup will recreate the tables, empty.")
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

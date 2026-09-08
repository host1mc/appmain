"""delete_databases.py — drop all data in all backends (Oracle ATP + MongoDB + MySQL HeatWave).

    THIS DESTROYS ALL DATA. THERE IS NO UNDO.

Oracle ATP: drops every table, view, sequence, trigger, and PL/SQL object,
then purges the recycle bin. Schema is rebuilt empty on next tier startup.

MongoDB (via Oracle Database API for MongoDB): drops all collections in each
shard database. Data is recreated on next tier startup.

MySQL HeatWave: drops the ENTIRE database. Database is recreated on next
tier startup by reviews_db._ensure_database() and _ensure_schema().

Usage:
    python delete_databases.py                     # dry run: inventory + row counts
    python delete_databases.py --apply             # destructive; prompts for confirmation
    python delete_databases.py --apply --yes       # destructive, no prompt
    python delete_databases.py --oracle-only       # only touch Oracle ATP
    python delete_databases.py --heatwave-only     # only touch MySQL HeatWave
    python delete_databases.py --mongo-only        # only touch MongoDB shards
    python delete_databases.py --mongo-only --apply

Run with the stack STOPPED. Every tier calls init_db() at startup and holds
connections, so a running tier will block DDL and immediately re-create tables.

Exit codes: 0 ok / 1 error / 2 refused
"""

import argparse
import os
import re
import sys

CONFIRM_PHRASE = "DROP EVERYTHING"

_HERE = os.path.dirname(os.path.abspath(__file__))
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
    return os.environ.get(name) or _FILE_CFG.get(name) or default


def _required_setting(name):
    value = _setting(name)
    if not value:
        raise KeyError(name)
    return value


# ── Oracle ATP ──────────────────────────────────────────────────


def _oracle_connect():
    import oracledb
    oracledb.defaults.fetch_lobs = False
    oracledb.defaults.connect_timeout = 10
    wallet_dir = os.path.abspath(
        os.path.join(_HERE, "fastapi-oracle-app",
                     _setting("ORACLE_WALLET_DIR", "./Wallet_ATP")))
    wallet_present = any(os.path.isfile(os.path.join(wallet_dir, name))
                         for name in ("cwallet.sso", "ewallet.pem", "ewallet.p12"))
    connect_kwargs = dict(
        user=_required_setting("ORACLE_USER"),
        password=_required_setting("ORACLE_PASSWORD"),
        dsn=_required_setting("ORACLE_DSN"),
    )
    if wallet_present:
        os.environ["TNS_ADMIN"] = wallet_dir
        connect_kwargs.update(
            config_dir=wallet_dir,
            wallet_location=wallet_dir,
            wallet_password=_setting("ORACLE_WALLET_PASSWORD", ""),
        )
    return oracledb.connect(**connect_kwargs)


def _rows(cur, sql):
    cur.execute(sql)
    return [r[0] for r in cur.fetchall()]


def _oracle_inventory(cur):
    return {
        "tables": _rows(cur, """
            SELECT table_name FROM user_tables
             WHERE nested = 'NO'
               AND (iot_type IS NULL OR iot_type != 'IOT_OVERFLOW')
             ORDER BY table_name
        """),
        "views": _rows(cur, "SELECT view_name FROM user_views ORDER BY view_name"),
        "sequences": _rows(cur, "SELECT sequence_name FROM user_sequences ORDER BY sequence_name"),
        "mviews": _rows(cur, "SELECT mview_name FROM user_mviews ORDER BY mview_name"),
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


def _oracle_row_count(cur, table):
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{table}"')
        return cur.fetchone()[0]
    except Exception as e:
        return f"? ({str(e).splitlines()[0][:60]})"


def _oracle_drop_tables(cur, tables):
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


def _oracle_drop_simple(cur, kind, names):
    errors = []
    for n in names:
        try:
            cur.execute(f'DROP {kind} "{n}"')
            print(f"  dropped {kind.lower():14s} {n}")
        except Exception as e:
            errors.append((n, str(e).splitlines()[0]))
    return errors


def wipe_oracle(apply):
    """Drop every object in the Oracle ATP schema. Returns exit code."""
    if _setting("ORACLE_ENABLED", "false").strip().lower() != "true":
        print("[oracle] ORACLE_ENABLED is not true — skipping.")
        return 0

    try:
        conn = _oracle_connect()
    except KeyError as e:
        print(f"[oracle] missing required setting: {e}")
        return 1
    except Exception as e:
        print(f"[oracle] could not connect: {e}")
        return 1

    try:
        cur = conn.cursor()
        user = _rows(cur, "SELECT USER FROM dual")[0]
        inv = _oracle_inventory(cur)
        total = sum(len(v) for v in inv.values())

        print(f"\n[oracle] schema: {user}")
        print(f"[oracle] dsn:    {_setting('ORACLE_DSN')[:40]}...\n")

        if not total:
            print("[oracle] schema is already empty — nothing to do.")
            return 0

        grand = 0
        print(f"{len(inv['tables'])} tables:")
        for t in inv["tables"]:
            n = _oracle_row_count(cur, t)
            if isinstance(n, int):
                grand += n
            print(f"  {t:32s} {n:>12}")
        for kind in ("views", "mviews", "sequences", "triggers", "plsql"):
            if inv[kind]:
                print(f"\n{len(inv[kind])} {kind}: {', '.join(inv[kind])}")
        print(f"\ntotal rows across readable tables: {grand}")

        if not apply:
            print("\n[oracle] DRY RUN — nothing was changed.")
            return 0

        print("\n" + "!" * 72)
        print(f"About to DROP {total} objects and DESTROY {grand} rows in {user}.")
        print("THERE IS NO UNDO.")
        print("!" * 72)

        print("\n[oracle] dropping...")
        errors = []
        errors += [("VIEW " + n, e) for n, e in _oracle_drop_simple(cur, "VIEW", inv["views"])]
        errors += [("MVIEW " + n, e) for n, e in
                   _oracle_drop_simple(cur, "MATERIALIZED VIEW", inv["mviews"])]
        errors += [("TABLE " + n, e) for n, e in _oracle_drop_tables(cur, inv["tables"])]
        for kind, key in (("SEQUENCE", "sequences"), ("TRIGGER", "triggers")):
            errors += [(f"{kind} {n}", e) for n, e in _oracle_drop_simple(cur, kind, inv[key])]
        for name in inv["plsql"]:
            cur.execute("SELECT object_type FROM user_objects WHERE object_name = :n "
                        "AND ROWNUM = 1", {"n": name})
            row = cur.fetchone()
            if row:
                errors += [(f"{row[0]} {n}", e)
                           for n, e in _oracle_drop_simple(cur, row[0], [name])]

        conn.commit()
        try:
            cur.execute("PURGE RECYCLEBIN")
            print("  purged recyclebin")
        except Exception as e:
            print(f"  recyclebin purge failed (harmless): {str(e).splitlines()[0]}")

        left = _oracle_inventory(cur)
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
        print(f"[oracle] {user} is now empty. {total} objects dropped.")
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── MongoDB (Oracle Database API for MongoDB) ───────────────────


def _load_mongo_uris():
    """Load DB_0..DB_64 MongoDB URIs from config."""
    uris = {}
    for idx in range(0, 65):
        uri = _setting(f"DB_{idx}", "").strip()
        if uri and (uri.startswith("mongodb://") or uri.startswith("mongodb+srv://")):
            uris[idx] = uri
    return uris


def _mongo_client(uri):
    from pymongo import MongoClient
    return MongoClient(uri, serverSelectionTimeoutMS=5000)


def wipe_mongo(apply):
    """Drop all collections in each MongoDB shard. Returns exit code."""
    uris = _load_mongo_uris()
    if not uris:
        print("[mongo] no DB_<n> MongoDB URIs configured — skipping.")
        return 0

    print(f"\n[mongo] found {len(uris)} shard(s): {', '.join(f'DB_{i}' for i in uris)}")

    shard_info = {}
    for idx, uri in uris.items():
        try:
            client = _mongo_client(uri)
            # The Oracle Database API for MongoDB may not support list_database_names.
            # Try it; if it fails, report the shard as connected but unlistable.
            try:
                dbs = [d for d in client.list_database_names()
                       if d not in ("admin", "local", "config")]
            except Exception:
                dbs = []
            total_docs = 0
            collections = []
            for db_name in dbs:
                try:
                    db = client[db_name]
                    for coll_name in db.list_collection_names():
                        try:
                            count = db[coll_name].estimated_document_count()
                        except Exception:
                            count = "?"
                        collections.append((db_name, coll_name, count))
                        if isinstance(count, int):
                            total_docs += count
                except Exception:
                    pass
            shard_info[idx] = {
                "databases": dbs,
                "collections": collections,
                "total_docs": total_docs,
                "client": client,
            }
        except Exception as e:
            print(f"[mongo] DB_{idx}: could not connect: {e}")
            shard_info[idx] = {"error": str(e)}

    grand_total = 0
    for idx, info in shard_info.items():
        if "error" in info:
            print(f"\n  DB_{idx}: ERROR — {info['error']}")
            continue
        print(f"\n  DB_{idx}: {len(info['databases'])} database(s), "
              f"{len(info['collections'])} collection(s)")
        for db_name, coll_name, count in info["collections"]:
            print(f"    {db_name}.{coll_name}: {count} docs")
        grand_total += info["total_docs"]

    print(f"\n[mongo] total documents across all shards: {grand_total}")

    if not any("collections" in info and info["collections"]
               for info in shard_info.values()):
        print("[mongo] all shards already empty — nothing to do.")
        # Close any open clients
        for info in shard_info.values():
            client = info.get("client")
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        return 0

    if not apply:
        print("\n[mongo] DRY RUN — nothing was changed.")
        for info in shard_info.values():
            client = info.get("client")
            if client:
                try:
                    client.close()
                except Exception:
                    pass
        return 0

    print("\n" + "!" * 72)
    print(f"About to DROP all collections in {len(uris)} MongoDB shard(s).")
    print(f"Total documents to destroy: {grand_total}")
    print("THERE IS NO UNDO.")
    print("!" * 72)

    print("\n[mongo] dropping...")
    errors = []
    for idx, info in shard_info.items():
        if "error" in info or "collections" not in info:
            continue
        client = info.get("client")
        if not client:
            continue
        try:
            for db_name in info["databases"]:
                try:
                    db = client[db_name]
                    for coll_name in db.list_collection_names():
                        try:
                            db[coll_name].drop()
                            print(f"  dropped  DB_{idx} {db_name}.{coll_name}")
                        except Exception as e:
                            errors.append((f"DB_{idx} {db_name}.{coll_name}", str(e)))
                except Exception as e:
                    errors.append((f"DB_{idx} {db_name}", str(e)))
        except Exception as e:
            errors.append((f"DB_{idx}", str(e)))
        finally:
            try:
                client.close()
            except Exception:
                pass

    print("\n" + "=" * 72)
    if errors:
        print(f"{len(errors)} collection(s) could not be dropped:")
        for name, err in errors:
            print(f"  {name}: {err}")
    else:
        print(f"[mongo] all shards wiped. {grand_total} documents destroyed.")
    return 0


# ── MySQL HeatWave ──────────────────────────────────────────────


_DB_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,63}$")


def _heatwave_connect_kwargs():
    host = _setting("MYSQL_HOST").strip()
    if not host:
        return None
    try:
        port = int(_setting("MYSQL_PORT", "3306"))
    except (TypeError, ValueError):
        port = 3306
    ssl_ca = _setting("MYSQL_SSL_CA").strip()
    if not ssl_ca:
        raise ValueError("MYSQL_SSL_CA is required when MYSQL_HOST is configured")
    # Resolve relative path
    if not os.path.isabs(ssl_ca):
        for base in (os.path.join(_HERE, "fastapi-oracle-app"),
                     _HERE):
            candidate = os.path.abspath(os.path.join(base, ssl_ca))
            if os.path.exists(candidate):
                ssl_ca = candidate
                break
        else:
            ssl_ca = os.path.abspath(os.path.join(
                os.path.join(_HERE, "fastapi-oracle-app"), ssl_ca))
    return {
        "host": host,
        "port": port,
        "user": _setting("MYSQL_USER", "admin").strip(),
        "password": _setting("MYSQL_PASSWORD"),
        "connection_timeout": 10,
        "charset": "utf8mb4",
        "ssl_ca": ssl_ca,
        "ssl_verify_cert": True,
        "ssl_verify_identity": False,
    }


def wipe_heatwave(apply):
    """Drop the entire MySQL HeatWave database. Returns exit code."""
    kwargs = _heatwave_connect_kwargs()
    if kwargs is None:
        print("[heatwave] MYSQL_HOST is not set — skipping.")
        return 0

    db_name = _setting("MYSQL_DATABASE", "dchost").strip()
    if not _DB_NAME_RE.fullmatch(db_name):
        print(f"[heatwave] invalid database name: {db_name!r}")
        return 1

    import mysql.connector
    try:
        conn = mysql.connector.connect(**kwargs)
    except Exception as e:
        print(f"[heatwave] could not connect: {e}")
        return 1

    try:
        cur = conn.cursor()

        # Check if database exists
        cur.execute("SHOW DATABASES")
        existing = [row[0] for row in cur.fetchall()]
        if db_name not in existing:
            print(f"[heatwave] database `{db_name}` does not exist — nothing to do.")
            return 0

        # Inventory: list all tables in the database
        cur.execute(f"SHOW TABLES IN `{db_name}`")
        all_tables = [row[0] for row in cur.fetchall()]

        if not all_tables:
            print(f"[heatwave] database `{db_name}` is already empty — nothing to do.")
            return 0

        # Get row counts
        total_rows = 0
        table_counts = []
        for tbl in all_tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM `{db_name}`.`{tbl}`")
                count = cur.fetchone()[0]
                table_counts.append((tbl, count))
                total_rows += count
            except Exception as e:
                table_counts.append((tbl, f"? ({e})"))

        print(f"\n[heatwave] database: {db_name}")
        print(f"{len(all_tables)} tables:")
        for tbl, count in table_counts:
            print(f"  {tbl:32s} {count:>12}")
        print(f"\ntotal rows: {total_rows}")

        if not apply:
            print("\n[heatwave] DRY RUN — nothing was changed.")
            return 0

        print("\n" + "!" * 72)
        print(f"About to DROP DATABASE `{db_name}` — ALL {len(all_tables)} tables and "
              f"{total_rows} rows will be DESTROYED.")
        print("THERE IS NO UNDO.")
        print("!" * 72)

        print("\n[heatwave] dropping database...")
        try:
            cur.execute(f"DROP DATABASE `{db_name}`")
            print(f"  dropped database  {db_name}")
        except Exception as e:
            print(f"  FAILED to drop database: {e}")
            conn.rollback()
            return 1

        conn.commit()

        # Verify
        cur.execute("SHOW DATABASES")
        databases = [row[0] for row in cur.fetchall()]

        print("\n" + "=" * 72)
        if db_name in databases:
            print(f"[heatwave] database `{db_name}` STILL EXISTS.")
            print("If it reappeared, a tier is running and re-created it.")
            print("Stop the stack and re-run.")
            return 2
        print(f"[heatwave] database `{db_name}` fully deleted. "
              f"{len(all_tables)} tables and {total_rows} rows destroyed.")
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Main ────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description="Drop all data in Oracle ATP, MongoDB, and/or MySQL HeatWave.")
    ap.add_argument("--apply", action="store_true",
                    help="actually drop. Without this, nothing is changed.")
    ap.add_argument("--yes", action="store_true",
                    help="skip the typed confirmation (implies --apply)")
    ap.add_argument("--oracle-only", action="store_true",
                    help="only wipe Oracle ATP")
    ap.add_argument("--heatwave-only", action="store_true",
                    help="only wipe MySQL HeatWave")
    ap.add_argument("--mongo-only", action="store_true",
                    help="only wipe MongoDB shards")
    args = ap.parse_args()
    apply = args.apply or args.yes

    _load_env_file()

    do_oracle = not (args.heatwave_only or args.mongo_only)
    do_heatwave = not (args.oracle_only or args.mongo_only)
    do_mongo = not (args.oracle_only or args.heatwave_only)

    if args.oracle_only and args.heatwave_only:
        print("cannot use both --oracle-only and --heatwave-only")
        return 1
    if args.oracle_only and args.mongo_only:
        print("cannot use both --oracle-only and --mongo-only")
        return 1
    if args.heatwave_only and args.mongo_only:
        print("cannot use both --heatwave-only and --mongo-only")
        return 1

    if apply and not args.yes:
        print("\n" + "!" * 72)
        print("This will DESTROY data in one or more databases.")
        print("THERE IS NO UNDO.")
        print("!" * 72)
        try:
            typed = input(f'\nType exactly "{CONFIRM_PHRASE}" to proceed: ')
        except (EOFError, KeyboardInterrupt):
            print("\naborted.")
            return 2
        if typed.strip() != CONFIRM_PHRASE:
            print("phrase did not match — aborted, nothing changed.")
            return 2

    rc = 0
    if do_oracle:
        r = wipe_oracle(apply)
        if r:
            rc = r
    if do_mongo:
        r = wipe_mongo(apply)
        if r:
            rc = r
    if do_heatwave:
        r = wipe_heatwave(apply)
        if r:
            rc = r

    if rc == 0 and apply:
        print("\n" + "=" * 72)
        print("All databases wiped. The next tier startup will recreate tables empty.")
    return rc


if __name__ == "__main__":
    sys.exit(main())

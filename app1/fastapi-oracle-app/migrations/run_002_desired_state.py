"""Run migration 002 (panel_servers.desired_state) without SQLcl or SQL*Plus.

No longer required: `panel_app/database.py::ensure_schema` issues this same ALTER
on every panel start, so starting the panel applies it. This script remains for
applying it while the panel stays down, and for the verify output below.

002_panel_servers_desired_state.sql is written for a SQL client that understands
PROMPT / SET SERVEROUTPUT / "/" terminators. Neither `sql` nor `sqlplus` is
necessarily installed on a deploy or dev host, but python-oracledb always is —
it is what the app tiers connect with. This script issues the same single guarded
ALTER against the same wallet, DSN and schema the panel itself uses, so what it
changes is what the SQL script would have changed.

It is read-only unless --apply is passed. A bare run prints the preflight and
exits, which is the SQL script's section 1; --apply adds section 2 and 3.

    python run_002_desired_state.py            # preflight only, changes nothing
    python run_002_desired_state.py --apply    # add the column, then verify

Stop the panel tier on both load-balanced instances first, per migrations/README.
Both modes are safe to re-run: the ALTER is guarded by a check for the column, so
a second --apply finds it present and does nothing.
"""

import sys
from pathlib import Path

# The .env and the wallet live in the fastapi-oracle-app tree, and the wallet path
# inside that .env is relative to it. Resolving both from this file's location
# means the script does not care what the cwd is when it is invoked.
_APP_DIR = Path(__file__).resolve().parent.parent

TABLE = "PANEL_SERVERS"
COLUMN = "DESIRED_STATE"
# NUMBER rather than the model's Integer spelling: this is what SQLAlchemy's
# Oracle dialect emits for Column(Integer), so a table built by create_all and a
# table migrated by this script end up with the same type.
ADD_COLUMN = f"ALTER TABLE {TABLE} ADD ({COLUMN} NUMBER DEFAULT 0 NOT NULL)"


def _connect_args():
    from dotenv import dotenv_values

    env = dotenv_values(_APP_DIR / ".env")
    missing = [k for k in ("ORACLE_USER", "ORACLE_PASSWORD", "ORACLE_DSN") if not env.get(k)]
    if missing:
        raise SystemExit(f"missing from {_APP_DIR / '.env'}: {', '.join(missing)}")
    wallet = (_APP_DIR / env.get("ORACLE_WALLET_DIR", "./Wallet_ATP")).resolve()
    if not wallet.is_dir():
        raise SystemExit(f"wallet directory not found: {wallet}")
    # The connect shape proved by app/database.py::_oracle_pool — config_dir and
    # wallet_location both point at the wallet and the wallet password is handed
    # over explicitly. Without them the thin driver stalls in TLS mutual auth
    # instead of failing, so a wrong shape here looks like a hang, not an error.
    return {
        "user": env["ORACLE_USER"],
        "password": env["ORACLE_PASSWORD"],
        "dsn": env["ORACLE_DSN"],
        "config_dir": str(wallet),
        "wallet_location": str(wallet),
        "wallet_password": env.get("ORACLE_WALLET_PASSWORD", "") or None,
    }


def _table_exists(cursor):
    cursor.execute("SELECT COUNT(*) FROM user_tables WHERE table_name = :t", t=TABLE)
    return cursor.fetchone()[0] > 0


def _column(cursor):
    cursor.execute(
        "SELECT data_type, nullable, data_default FROM user_tab_columns "
        "WHERE table_name = :t AND column_name = :c",
        t=TABLE,
        c=COLUMN,
    )
    return cursor.fetchone()


def main(apply_changes):
    import oracledb

    oracledb.defaults.connect_timeout = 10
    args = _connect_args()
    print(f"[002] {args['user']}@{args['dsn']} (wallet {args['config_dir']})")

    with oracledb.connect(**args) as connection:
        with connection.cursor() as cursor:
            print("\n-- preflight ------------------------------------------------")
            if not _table_exists(cursor):
                # create_all would build the table already carrying the column, so
                # adding it here would be the wrong half of the job.
                print(f"{TABLE} does not exist in this schema.")
                print("Do NOT run this. Start the panel — ensure_schema creates")
                print("panel_servers already carrying the column.")
                return 1
            print(f"{TABLE}: present")

            existing = _column(cursor)
            if existing:
                data_type, nullable, default = existing
                print(f"{COLUMN}: present ({data_type}, nullable={nullable}, default={default})")
                print("\nNothing to do — this migration has already been applied.")
                return 0
            print(f"{COLUMN}: MISSING  <-- this is what breaks /panel/dashboard")

            cursor.execute(f"SELECT COUNT(*) FROM {TABLE}")
            rows = cursor.fetchone()[0]
            print(f"{TABLE} rows: {rows} (each reads desired_state = 0 until its next power action)")

            if not apply_changes:
                print("\nRead-only run. Re-run with --apply to execute:")
                print(f"  {ADD_COLUMN}")
                return 0

            print("\n-- migrate --------------------------------------------------")
            print(f"  > {ADD_COLUMN}")
            # On ATP 19c+ an ADD of NOT NULL with a DEFAULT is metadata-only:
            # existing rows read 0 without a table rewrite. Oracle commits DDL
            # itself, so there is no commit to issue and nothing to roll back.
            cursor.execute(ADD_COLUMN)

            print("\n-- verify ---------------------------------------------------")
            confirmed = _column(cursor)
            if not confirmed:
                print(f"{COLUMN} still absent after the ALTER — investigate before restarting.")
                return 1
            data_type, nullable, default = confirmed
            print(f"{COLUMN}: {data_type}, nullable={nullable}, default={default}")

            # A NULL here would mean the NOT NULL default did not take, which is
            # the one outcome that would leave int(row.desired_state or 0) lying.
            cursor.execute(f"SELECT COUNT(*) FROM {TABLE} WHERE {COLUMN} IS NULL")
            nulls = cursor.fetchone()[0]
            print(f"rows with NULL {COLUMN}: {nulls} (expected 0)")

            cursor.execute(
                f"SELECT {COLUMN}, COUNT(*) FROM {TABLE} GROUP BY {COLUMN} ORDER BY {COLUMN}"
            )
            for state, count in cursor.fetchall():
                print(f"  desired_state={state}: {count} server(s)")

            print("\nDone. /panel/dashboard should answer on the next request.")
            return 0


if __name__ == "__main__":
    sys.exit(main(apply_changes="--apply" in sys.argv[1:]))

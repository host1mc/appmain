"""
check_mysql.py — verify the reviews (MySQL HeatWave) connection and schema.

Reads the same configuration reviews_db.py uses (fastapi-oracle-app/.env or
real env vars), connects, and reports:
    - whether reviews are enabled and where they point (password masked)
    - server/version + TLS state of the connection
    - the `reviews` table's existence and schema
    - row counts (approved / pending / total)
    - a round-trip write test (inserts then deletes a throwaway row)

Exit code 0 = everything OK, 1 = checks failed or disabled.

Usage:  python check_mysql.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mysql.connector
import reviews_db


def mask(value):
    """Password-ish values render as '***' when non-empty."""
    return "***" if value else "(empty)"


# Marker written into the round-trip probe row. users.id is VARCHAR2(36) and
# UUID-shaped, so this can never collide with a real reviewer, which is what makes
# it safe to delete by — and deleting by a marker instead of by lastrowid is what
# makes the cleanup idempotent. The insert has to be committed for the probe to
# prove anything, so without that a failure between the commit and the delete
# leaves an approved=0 row in the live moderation queue for good.
PROBE_USER_ID = "chkprobe10"


def _delete_probe_rows(conn):
    """Delete every probe row, including any an earlier run left behind.

    Returns the number removed, or -1 if the delete itself failed. Never raises:
    it runs on the failure path too, where throwing would hide the error that got
    us there and strand the row regardless.
    """
    try:
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM reviews WHERE uid=%(id)s", {"id": PROBE_USER_ID})
            conn.commit()
            return cur.rowcount
        finally:
            cur.close()
    except Exception as ex:
        print(f"           WARNING: could not delete the probe row: {ex}")
        return -1


def main():
    print("=" * 60)
    print(" MySQL HeatWave (reviews) connection check")
    print("=" * 60)

    if not reviews_db.enabled():
        print()
        print("FAIL: reviews are DISABLED — MYSQL_HOST is not set.")
        print("      Add MYSQL_HOST (and MYSQL_PASSWORD) to")
        print(f"      {reviews_db._ENV_PATH} or the process environment.")
        return 1

    cfg = reviews_db._CFG
    print(f" host     : {cfg['host']}:{cfg['port']}")
    print(f" user     : {cfg['user']}")
    print(f" password : {mask(cfg['password'])}")
    print(f" database : {cfg['database']}")
    print(f" ssl_ca   : {mask(cfg['ssl_ca'])}")

    try:
        reviews_db._ensure_database()
        connect_kwargs = reviews_db._connect_kwargs()
        connect_kwargs["database"] = cfg["database"]
        conn = mysql.connector.connect(**connect_kwargs)
    except Exception as ex:
        print()
        print(f"FAIL: could not connect: {ex}")
        return 1

    try:
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT VERSION() AS v")
        version = cur.fetchone()["v"]
        print(f" server   : MySQL {version}")

        cur.execute("SHOW STATUS LIKE 'Ssl_cipher'")
        row = cur.fetchone()
        cipher = row["Value"] if row else None
        if isinstance(cipher, (bytes, bytearray)):
            # The connector hands some status values back as bytes, which would
            # make the concatenation below raise and report the TLS verdict as a
            # generic query error.
            cipher = cipher.decode("utf-8", "replace")
        cipher = (cipher or "").strip()
        print(f" TLS      : {'yes (' + cipher + ')' if cipher else 'NO — plaintext connection!'}")
        if not cipher:
            print()
            print("FAIL: server connection did not negotiate TLS")
            conn.close()
            return 1

        reviews_db._ensure_schema(conn)

        cur.execute("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'reviews'")
        has_table = cur.fetchone()["n"] > 0
        print(f" table    : {'exists' if has_table else 'MISSING (created automatically on first review)'}")

        if has_table:
            cur.execute("SELECT column_name AS column_name, column_type AS column_type, is_nullable AS is_nullable FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'reviews' ORDER BY CAST(ordinal_position AS UNSIGNED)")
            print(" columns  :")
            for col in cur.fetchall():
                null = "" if col["is_nullable"] == "YES" else " NOT NULL"
                print(f'             {col["column_name"]:<14} {col["column_type"]}{null}')

            cur.execute("SELECT COUNT(*) AS n FROM reviews")
            total = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM reviews WHERE approved=1")
            approved = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM reviews WHERE approved=0")
            pending = cur.fetchone()["n"]
            print(f" rows     : {total} total  ({approved} approved, {pending} pending)")

        print(" write    : testing INSERT + DELETE round-trip ...")
        try:
            cur.execute(
                "INSERT INTO reviews(uid, author_name, rating, body, approved, created_at) VALUES(%(id)s, %(name)s, 5, %(body)s, 0, %(now)s)",
                {
                    "id": PROBE_USER_ID,
                    "name": "check",
                    "body": "round-trip probe",
                    "now": reviews_db._now(),
                },
            )
            conn.commit()
        finally:
            removed = _delete_probe_rows(conn)
        if removed < 1:
            print("           FAIL — the probe row was committed but not deleted")
            print()
            print("RESULT: FAIL")
            conn.close()
            return 1
        print("           OK — insert + delete succeeded")
        print()
        print("RESULT: PASS")
    except Exception as ex:
        print()
        print(f"FAIL: query error: {ex}")
        try:
            conn.close()
        except Exception:
            return 1
        return 1

    try:
        conn.close()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
rekey_encrypted.py — bring every encrypted value in the database under one key.

Why this exists
---------------
`crypto_util` opens `<its own directory>/data/secret.key`. The admin console
vendors a copy of that module, so running it generated a *second* Fernet key in
`admin/data/secret.key` while both tiers talked to the same Oracle database.
Every settings row the console then wrote (ad flags, admin password, SMTP) is
ciphertext the app cannot read, and `_dec_or_raw` uses `decrypt_strict`, so the
app raises `InvalidToken` instead of silently blanking the value.

What it does
------------
Scans every column that holds Fernet ciphertext, and for each value:

  * decrypts under the primary key        -> leave alone
  * decrypts under a retired/legacy key   -> re-encrypt under the primary key
  * decrypts under nothing                -> report, never touch

"Primary" is whatever `crypto_util` itself loaded, so this can never disagree
with the running app. Retired keys come from ENCRYPTION_KEYS_OLD (which is how
rotate_key.py hands the previous key over) plus any stray `data/secret.key` a
tier generated for itself.

Dry run by default; `--apply` writes. It is idempotent: a second run has
nothing left to do. Plaintext is never printed, and keys are identified by
fingerprint.

    python rekey_encrypted.py                      # report
    python rekey_encrypted.py --apply              # fix
    python rekey_encrypted.py --legacy path/to.key # extra key to try
"""

import argparse
import base64
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

import crypto_util  # noqa: E402
import database as db  # noqa: E402

FERNET_PREFIX = crypto_util.FERNET_PREFIX
GCM_PREFIX = crypto_util.GCM_PREFIX

# Both at-rest formats, as (prefix, length) for the SQL head comparisons below.
# Every prefix test in this file covers both, because this script is what decides
# whether a retired key is still needed: a format it cannot see reports clean, and
# --retire-old then drops the only key that could read those rows. That is the
# same failure the missing fingerprint_history entry caused, and it does not care
# which format made a row invisible.
ENCRYPTED_PREFIXES = (FERNET_PREFIX, GCM_PREFIX)

# Additional authenticated data for GCM columns. Empty, and it has to stay empty
# until this script can be told which context each column was written with:
# decryption fails on any mismatch, so a context adopted in database.py without
# the identical string here would make the column unrecoverable on the next
# rotation. crypto_util.encrypt() takes the argument; no column passes one.
GCM_CONTEXT = ""

# Every table/column pair written through encrypt()/_enc_or_none() in
# database.py. (table, primary key column, [encrypted columns])
# users.username / display_name / email, banned_reason, IPs, sessions and OTP
# columns were added later; legacy plaintext rows are skipped by the prefix
# check below and upgraded by database._migrate_at_rest_encryption() instead.
TARGETS = (
    ("settings", "key", ("value",)),
    ("fingerprints", "id", ("fingerprint_hash", "device_info_enc",
                            "ip_address")),
    ("device_events", "id", ("username", "fingerprint_enc",
                             "device_info_enc", "ip_address", "details")),
    ("sessions", "id", ("data", "ip_address", "user_agent")),
    ("otp_codes", "id", ("email", "code")),
    ("users", "id", ("username", "display_name", "email", "banned_reason")),
    # A hosted server's name, start command and source (database.py:3147-3148).
    ("hosting_servers", "id", ("name", "start_command", "code")),
)

# Keyed lookup-hash index columns, as (table, pk, ((ciphertext column, index
# column, casefold), ...)).
#
# lookup_hash() is an HMAC whose key is derived from the encryption key, so every
# one of these goes stale the instant the key changes — even for a row whose
# ciphertext this run leaves alone. A stale index is not a read error: the row is
# still there and still decrypts, and nothing can ever find it again. Login by
# username/email, accounts_on_ip, the OTP lookup and the fingerprint-history
# dedupe all match on these columns and all silently return "no such row".
#
# database.py only backfills these WHERE the column IS NULL (database.py:850,
# 906, 955), so a stale non-null hash has no other repair path. This file is it.
LOOKUP_INDEXES = (
    ("users", "id", (("username", "username_lookup_hash", False),
                     ("username", "username_ci_lookup_hash", True),
                     ("email", "email_lookup_hash", False))),
    ("fingerprints", "id", (("ip_address", "ip_lookup_hash", False),)),
    # database.py:1542; database.py:1537/1561 select pending codes by it.
    ("otp_codes", "id", (("email", "email_lookup_hash", False),)),
)

# Index columns whose value does not depend on the encryption key, and which must
# therefore never be rewritten with lookup_hash(). database.py:_fp_lookup() is a
# plain, unkeyed SHA-256 over the device fingerprint, so these survive a rotation
# untouched. Listed explicitly so the gate below can tell "known to be safe" from
# "nobody has classified this yet".
UNKEYED_LOOKUP_COLUMNS = (
    ("fingerprints", "lookup_hash"),
    ("device_events", "lookup_hash"),
)

# Rows per fetch and per commit. Both matter on an Always Free ATP that is
# size-capped and shares a ~20-session budget with five live tiers: fetchall()
# over hosting_backups or sessions pulls every retained CLOB payload into memory
# at once, and one commit per table holds an UNDO segment open for the whole
# rewrite while the live tiers compete for it.
BATCH_ROWS = 200

_INDEXED_TABLES = {t: spec for t, _pk, spec in LOOKUP_INDEXES}

def _read_key_file(path):
    with open(path, "rb") as fh:
        return fh.read().strip()


def _default_legacy_paths():
    """Key files other tiers may have generated for themselves: the admin
    console's, this app's own (when ENCRYPTION_KEY outranks it), plus any
    *.legacy file an earlier rotation parked next to a key."""
    root = os.path.dirname(HERE)
    candidates = [
        os.path.join(HERE, "data", "secret.key"),
        os.path.join(root, "admin", "data", "secret.key"),
        os.path.join(root, "admin_console", "data", "secret.key"),
    ]
    for data_dir in (os.path.join(HERE, "data"),
                     os.path.join(root, "admin", "data")):
        if not os.path.isdir(data_dir):
            continue
        for name in sorted(os.listdir(data_dir)):
            if name.startswith("secret.key.") and "legacy" in name:
                candidates.append(os.path.join(data_dir, name))
    return [p for p in candidates if os.path.isfile(p)]


def build_keys(args):
    """(primary Fernet, primary label, [(label, Fernet)] older keys, [GCM keys]).

    Deduplicated by fingerprint, not by path: the same key reached through two
    files is one key, and the primary is never also tried as a legacy.

    The GCM list is the same key materials run through crypto_util._gcm_key, in
    the same order — primary first — so one rotation moves both at-rest formats
    and neither list can end up holding a key the other lacks.
    """
    primary_material = crypto_util._PRIMARY
    primary = Fernet(primary_material)
    primary_label = (f"{crypto_util._PRIMARY_ORIGIN} "
                     f"[{crypto_util.key_fingerprint(primary_material)}]")

    older = []
    gcm_keys = [crypto_util._gcm_key(primary_material)]
    seen = {crypto_util.key_fingerprint(primary_material)}
    # Retired keys first: a rotation in progress is the common case.
    sources = [("ENCRYPTION_KEYS_OLD", k) for k in crypto_util._RETIRED]
    for path in list(args.legacy) + _default_legacy_paths():
        real = os.path.abspath(path)
        try:
            sources.append((real, _read_key_file(real)))
        except OSError as exc:
            print(f"[rekey] skipping {real}: {exc}")

    for origin, material in sources:
        fingerprint = crypto_util.key_fingerprint(material)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        try:
            older.append((f"{origin} [{fingerprint}]", Fernet(material)))
        except Exception as exc:
            print(f"[rekey] skipping {origin}: not a Fernet key ({exc})")
            continue
        gcm_keys.append(crypto_util._gcm_key(material))
    return primary, primary_label, older, gcm_keys


def _table_exists(cur, table):
    try:
        cur.execute(f"SELECT 1 FROM {table} WHERE 1=0")
        return True
    except Exception:
        return False


def _row_value(row, idx, name):
    if hasattr(row, "keys"):
        return row[name]
    return row[idx]


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _validate_id(name):
    if not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return name


# Column types that can hold a Fernet token. NUMBER/DATE/RAW/BLOB cannot, so
# they are not worth a scan.
_TEXT_TYPES = ("VARCHAR2", "NVARCHAR2", "CHAR", "NCHAR", "CLOB", "NCLOB")


def _unclassified_index_columns(cur):
    """Lookup-hash index columns nobody has classified as keyed or unkeyed.

    The ciphertext scan below cannot see these. A lookup-hash column holds 64 hex
    characters, which carries neither at-rest prefix, so a column full of stale
    HMACs looks exactly like a column full of correct ones and MAX(CASE ... LIKE
    prefix) never fires. That is the hole a column-content check cannot close:
    add panel_users.username_lookup_hash and the ciphertext gate reports clean,
    --retire-old proceeds, and every panel login stops matching with no error.

    So this asks user_tab_columns for the columns by NAME instead, which fires on
    the migration that adds one rather than on the first row written through it —
    before there is any data to lose. Every hit must appear in either
    LOOKUP_INDEXES (rewritten here) or UNKEYED_LOOKUP_COLUMNS (key-independent).
    """
    known = {(t.upper(), c.upper())
             for t, _pk, spec in LOOKUP_INDEXES for _src, c, _cf in spec}
    known |= {(t.upper(), c.upper()) for t, c in UNKEYED_LOOKUP_COLUMNS}
    cur.execute(
        "SELECT table_name, column_name FROM user_tab_columns "
        "WHERE (column_name = 'LOOKUP_HASH' OR column_name LIKE '%\\_LOOKUP\\_HASH' "
        "ESCAPE '\\') AND table_name NOT LIKE 'BIN$%' "
        "ORDER BY table_name, column_name"
    )
    return [(r[0], r[1]) for r in cur.fetchall()
            if (r[0].upper(), r[1].upper()) not in known]


def _unclassified_enc_columns(cur):
    """Columns named like ciphertext (*_ENC) that TARGETS does not walk.

    Same reasoning as _unclassified_index_columns: by name, not by content, so an
    empty table or a migration that has not backfilled yet cannot slip past. The
    naming convention is database.py's own — token_enc, device_info_enc,
    fingerprint_enc — and every column matching it today is already in TARGETS,
    so this gate is clear until someone adds one and forgets this file.
    """
    covered = {(t.upper(), c.upper()) for t, _pk, cols in TARGETS for c in cols}
    cur.execute(
        "SELECT table_name, column_name FROM user_tab_columns "
        "WHERE column_name LIKE '%\\_ENC' ESCAPE '\\' "
        "AND table_name NOT LIKE 'BIN$%' ORDER BY table_name, column_name"
    )
    return [(r[0], r[1]) for r in cur.fetchall()
            if (r[0].upper(), r[1].upper()) not in covered]


def _uncovered_encrypted_columns(cur):
    """(table, column) pairs holding Fernet ciphertext that TARGETS omits.

    TARGETS is hand-maintained, and the cost of it falling behind database.py is
    not merely a skipped table. rotate_key.py --retire-old re-runs this scan and
    reads only the exit code, so an unlisted table reports clean, the key that
    still decrypts it is dropped from ENCRYPTION_KEYS_OLD, and its rows become
    unreadable with no way back. Ask the database what is encrypted rather than
    trusting the list to be current.

    One pass per table, not per column: every candidate column becomes a
    MAX(CASE) in the same SELECT, so a table costs a single scan and the result
    still says which of its columns matched.
    """
    covered = {(t.upper(), c.upper()) for t, _pk, cols in TARGETS for c in cols}
    placeholders = ", ".join(f"'{t}'" for t in _TEXT_TYPES)
    cur.execute(
        "SELECT table_name, column_name, data_type FROM user_tab_columns "
        f"WHERE data_type IN ({placeholders}) "
        # Dropped tables still sitting in the recycle bin are queryable, and
        # reporting them would make this gate impossible to clear.
        "AND table_name NOT LIKE 'BIN$%' "
        "ORDER BY table_name, column_id"
    )
    candidates = {}
    for row in cur.fetchall():
        table, column, data_type = row[0], row[1], row[2]
        if (table.upper(), column.upper()) in covered:
            continue
        candidates.setdefault(table, []).append((column, data_type))

    found = []
    for table, columns in candidates.items():
        tests = []
        for column, data_type in columns:
            checks = []
            for i, prefix in enumerate(ENCRYPTED_PREFIXES):
                if data_type.endswith("CLOB"):
                    # SUBSTR on a CLOB yields a CLOB, which will not compare against
                    # a bind; DBMS_LOB.SUBSTR yields a plain string.
                    head = f'DBMS_LOB.SUBSTR("{column}", {len(prefix)}, 1)'
                else:
                    head = f'SUBSTR("{column}", 1, {len(prefix)})'
                checks.append(f"{head} = :p{i}")
            tests.append(
                f"MAX(CASE WHEN {' OR '.join(checks)} THEN 1 ELSE 0 END)")
        try:
            cur.execute(f'SELECT {", ".join(tests)} FROM "{table}"',
                        {f"p{i}": p for i, p in enumerate(ENCRYPTED_PREFIXES)})
            row = cur.fetchone() or ()
        except Exception as exc:
            # A view, a table this user cannot read, or a type that resists the
            # comparison. Say so rather than letting it pass as examined.
            print(f"    ? {table}: could not check for encrypted columns ({exc})")
            found.append((table, "(unchecked)"))
            continue
        for (column, _type), matched in zip(columns, row):
            if matched:
                found.append((table, column))
    return found


def _gcm_parts(val):
    """(nonce, sealed) for a GCM token, or None when it is malformed."""
    try:
        blob = base64.urlsafe_b64decode(val[len(GCM_PREFIX):].encode("ascii"))
    except Exception:
        return None
    if len(blob) < crypto_util.GCM_NONCE_BYTES + crypto_util.GCM_TAG_BYTES:
        return None
    return blob[:crypto_util.GCM_NONCE_BYTES], blob[crypto_util.GCM_NONCE_BYTES:]


def _decrypt_any(val, primary, older, gcm_keys):
    """(plaintext bytes, read_by_primary) for a token in either at-rest format.

    (None, False) when nothing this run holds can read it — which is what the
    caller reports as unreadable and what --retire-old must never see ignored.
    Both formats try the primary key first and the retired ones after, so
    "read_by_primary" means the same thing regardless of format.
    """
    if val.startswith(GCM_PREFIX):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        parts = _gcm_parts(val)
        if parts is None:
            return None, False
        nonce, sealed = parts
        aad = GCM_CONTEXT.encode("utf-8")
        for index, key in enumerate(gcm_keys):
            try:
                return AESGCM(key).decrypt(nonce, sealed, aad), index == 0
            except Exception:
                continue
        return None, False

    raw = val.encode("utf-8")
    try:
        return primary.decrypt(raw), True
    except InvalidToken:
        pass
    for _label, fernet in older:
        try:
            return fernet.decrypt(raw), False
        except InvalidToken:
            continue
    return None, False


def _stale_format(val) -> bool:
    """Whether a value is in the format new writes no longer use.

    Rewriting these is what makes flipping crypto_util.ENCRYPTION_FORMAT a
    supported operation instead of a trap: without it the database keeps both
    formats indefinitely, and every retired key stays permanently required
    because some row somewhere is still the only thing that needs it.
    """
    if crypto_util.ENCRYPTION_FORMAT == "gcm":
        return not val.startswith(GCM_PREFIX)
    return val.startswith(GCM_PREFIX)


def _encrypt_primary(plaintext: bytes, primary, gcm_key: bytes) -> str:
    """Re-encrypt under the primary key, in the format new writes use."""
    if crypto_util.ENCRYPTION_FORMAT == "gcm":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(crypto_util.GCM_NONCE_BYTES)
        sealed = AESGCM(gcm_key).encrypt(nonce, plaintext,
                                         GCM_CONTEXT.encode("utf-8"))
        return GCM_PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode("ascii")
    return primary.encrypt(plaintext).decode("utf-8")


def _existing_columns(cur, table):
    """Column names actually present on a table, upper-cased.

    Several of the columns below were added by ALTER after the table shipped
    (otp_codes.email_lookup_hash, fingerprints.ip_lookup_hash), so a schema that
    has not run that migration is missing them. Naming one in a SELECT raises
    ORA-00904 and aborts the whole walk — which, mid-rotation, stops the rekey
    with some tables converted and some not.
    """
    cur.execute("SELECT column_name FROM user_tab_columns WHERE table_name=:t",
                {"t": table.upper()})
    return {r[0].upper() for r in cur.fetchall()}


def _expected_index(plain, casefold):
    return crypto_util.lookup_hash(plain.casefold() if casefold else plain)


def process_table(conn, table, pk, columns, primary, older, gcm_keys, apply,
                  present=None):
    """Scan one table, and when `apply` is set, rewrite it in bounded batches.

    Returns (rows_seen, ok, fixable, unreadable, stale_index, written).

    Streams with fetchmany(BATCH_ROWS) instead of fetchall(): hosting_backups
    holds every retained backup payload and sessions.data is a CLOB per live
    session, so materialising a whole table is unbounded memory against a
    size-capped ATP. Commits per batch for the matching reason — one commit per
    table holds an UNDO segment open for the length of a full rewrite while five
    live tiers compete for it.

    Ciphertext and the lookup-hash index that points at it go into the SAME
    UPDATE, so no commit can land between them. That is the safety property that
    matters: a row whose ciphertext was rotated but whose index was not still
    exists and still decrypts, and nothing can ever find it again.
    """
    if present is not None:
        columns = tuple(c for c in columns if c.upper() in present)
        spec = tuple(s for s in _INDEXED_TABLES.get(table, ())
                     if s[1].upper() in present and s[0].upper() in present)
    else:
        spec = _INDEXED_TABLES.get(table, ())
    if not columns:
        return 0, 0, 0, 0, 0, 0
    index_cols = [idx for _src, idx, _cf in spec]
    select_cols = list(columns) + index_cols
    _validate_id(table)
    _validate_id(pk)
    for c in select_cols:
        _validate_id(c)
    write_cur = conn.cursor() if apply else None
    cur = conn.cursor()
    cur.arraysize = BATCH_ROWS
    cur.execute(f"SELECT {pk}, {', '.join(select_cols)} FROM {table}")

    seen = ok = fixable = unreadable = stale_index = written = 0
    pending = 0
    try:
        while True:
            rows = cur.fetchmany(BATCH_ROWS)
            if not rows:
                break
            for row in rows:
                seen += 1
                key_val = _row_value(row, 0, pk)
                sets = {}
                plain_by_col = {}
                for i, col in enumerate(columns, start=1):
                    val = _row_value(row, i, col)
                    if not isinstance(val, str) or not val.startswith(ENCRYPTED_PREFIXES):
                        continue
                    recovered, from_primary = _decrypt_any(val, primary, older, gcm_keys)
                    if recovered is None:
                        # Never re-encrypt what could not be read. decrypt()
                        # would have handed back "" here and encrypt("") would
                        # have destroyed the value while reporting success.
                        unreadable += 1
                        print(f"    ! {table}.{col} [{pk}={key_val}] no key decrypts this value")
                        continue
                    plain_by_col[col] = recovered.decode("utf-8", "replace")
                    if from_primary and not _stale_format(val):
                        ok += 1
                        continue
                    fixable += 1
                    sets[col] = _encrypt_primary(recovered, primary, gcm_keys[0])
                for offset, (src, idx_col, casefold) in enumerate(spec):
                    plain = plain_by_col.get(src)
                    if not plain:
                        # NULL, still-plaintext, or unreadable. Writing
                        # lookup_hash("") would file every such row under one
                        # index entry and collide them.
                        continue
                    stored = _row_value(row, len(columns) + 1 + offset, idx_col)
                    fresh = _expected_index(plain, casefold)
                    if stored != fresh:
                        stale_index += 1
                        sets[idx_col] = fresh
                if not sets or not apply:
                    continue
                binds = {f"v{n}": v for n, v in enumerate(sets.values())}
                binds["k"] = key_val
                for c in sets.keys():
                    _validate_id(c)
                assignments = ", ".join(f"{c}=:v{n}"
                                        for n, c in enumerate(sets.keys()))
                _validate_id(pk)
                write_cur.execute(
                    f"UPDATE {table} SET {assignments} WHERE {pk}=:k", binds)
                written += 1
                pending += 1
            if apply and pending:
                conn.commit()
                pending = 0
        if apply and pending:
            conn.commit()
    finally:
        cur.close()
        if write_cur is not None:
            write_cur.close()
    return seen, ok, fixable, unreadable, stale_index, written


def _self_check():
    """Static consistency between the two tables above.

    A table listed in LOOKUP_INDEXES but missing from TARGETS would never have
    its index rewritten, because the refresh now rides along with the ciphertext
    walk rather than running as a second pass. Fail here rather than silently
    doing nothing.
    """
    walked = {t for t, _pk, _cols in TARGETS}
    problems = []
    for table, _pk, spec in LOOKUP_INDEXES:
        if table not in walked:
            problems.append(f"{table} has lookup indexes but is not in TARGETS")
            continue
        columns = next(c for t, _p, c in TARGETS if t == table)
        for src, idx_col, _cf in spec:
            if src not in columns:
                problems.append(
                    f"{table}.{idx_col} indexes {table}.{src}, which TARGETS "
                    "does not decrypt")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--apply", action="store_true",
                    help="write the re-encrypted values (default: report only)")
    ap.add_argument("--legacy", action="append", default=[],
                    help="extra key file to try when decrypting (repeatable)")
    args = ap.parse_args()

    problems = _self_check()
    if problems:
        for problem in problems:
            print(f"[rekey] BUG in this file: {problem}")
        return 1

    primary, primary_label, older, gcm_keys = build_keys(args)
    print(f"[rekey] store=oracle  primary key={primary_label}")
    print(f"[rekey] new ciphertext format={crypto_util.ENCRYPTION_FORMAT} "
          f"(both formats are read; values in the other one are rewritten)")
    for label, _f in older:
        print(f"[rekey] also trying={label}")
    if not older:
        print("[rekey] no older keys available — values written under a "
              "different key cannot be recovered here; set ENCRYPTION_KEYS_OLD "
              "or point --legacy at the key that wrote them")

    totals = {"ok": 0, "fixable": 0, "unreadable": 0, "stale_index": 0,
              "written": 0}
    uncovered = []
    unclassified = []
    conn = db._user_conn()
    try:
        cur = conn.cursor()
        for table, pk, columns in TARGETS:
            if not _table_exists(cur, table):
                print(f"  {table:15s} (absent)")
                continue
            seen, ok, fixable, unreadable, stale_index, written = process_table(
                conn, table, pk, columns, primary, older, gcm_keys, args.apply,
                present=_existing_columns(cur, table))
            totals["ok"] += ok
            totals["fixable"] += fixable
            totals["unreadable"] += unreadable
            totals["stale_index"] += stale_index
            totals["written"] += written
            note = ""
            if written:
                note = "  -> rewritten"
            elif fixable or stale_index:
                note = "  -> run with --apply"
            print(f"  {table:15s} rows={seen:<6d} ok={ok:<5d} "
                  f"rewrite={fixable:<5d} stale_idx={stale_index:<5d} "
                  f"unreadable={unreadable}{note}")
        uncovered = _uncovered_encrypted_columns(cur)
        unclassified = ([("index", t, c) for t, c in _unclassified_index_columns(cur)]
                        + [("ciphertext", t, c) for t, c in _unclassified_enc_columns(cur)])
    finally:
        conn.close()

    print(f"\n[rekey] readable={totals['ok']}  rewrite={totals['fixable']}  "
          f"stale_index={totals['stale_index']}  "
          f"unreadable={totals['unreadable']}  written={totals['written']}")
    if unclassified:
        # By column name, so this fires on the migration that adds a column
        # rather than on the first row written through it. A lookup-hash column
        # carries neither at-rest prefix, so the content scan below can never see
        # one — and a rotation that leaves one behind makes its rows unfindable.
        for kind, table, column in sorted(unclassified):
            print(f"[rekey] UNCLASSIFIED {kind} column: {table}.{column}")
        print("[rekey] this file does not know about the column(s) above. Add "
              "each to LOOKUP_INDEXES (keyed, must be rewritten), "
              "UNKEYED_LOOKUP_COLUMNS (key-independent) or TARGETS "
              "(ciphertext), and re-run before retiring any key.")
        return 1
    if uncovered:
        # Before the rewrite/unreadable checks: those describe values this run
        # examined, and the point here is that some were never examined at all.
        # Exiting non-zero is what stops rotate_key.py --retire-old from reading
        # an incomplete scan as proof the previous key is redundant.
        listing = ", ".join(f"{t}.{c}" for t, c in sorted(uncovered))
        print(f"[rekey] UNLISTED encrypted columns not covered by this scan: "
              f"{listing}")
        print("[rekey] these hold ciphertext that a rotation would leave under "
              "the previous key. Add them to TARGETS in this file (table, "
              "primary key column, columns) and re-run before retiring any key.")
        return 1
    if (totals["fixable"] or totals["stale_index"]) and not args.apply:
        print("[rekey] dry run — nothing was changed. Re-run with --apply.")
        return 1
    if totals["unreadable"]:
        print("[rekey] some values decrypt under no available key. Find the key "
              "that wrote them, or clear those rows and set them again.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

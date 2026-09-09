#!/usr/bin/env python3
"""
keyenv.py -- check, and optionally align, the encryption keys of the app1 and
admin tiers so they share one Fernet keyring.

Why this exists: crypto_util resolves data/secret.key relative to its own file,
so app1 and the admin console can silently end up holding *different* keys
against the *same* Oracle database. Whichever tier did not write a row then
reads it as InvalidToken -- the "decrypt failed ... under key <fp>" error. This
tool shows each tier's key fingerprint side by side, and can write one shared
key into both so every row decrypts everywhere.

It reads only the on-disk, plaintext-at-rest sources crypto_util reads:

    app1 :  app1/fastapi-oracle-app/.env    then  app1/data/secret.key
    admin:  admin/.env                      then  admin/data/secret.key

with precedence ENCRYPTION_KEY > ENCRYPTION_PASSPHRASE(+SALT) > secret.key,
exactly as crypto_util._primary_key does. A systemd credential or an exported
ENCRYPTION_KEY OUTRANKS these and this tool cannot see them; if the fingerprints
here disagree with what the running app reports, the live key lives in one of
those and must be aligned there instead.

Fingerprints are the only key-derived thing this program prints. Key material is
written into .env files (each backed up first) and never shown.

    python keyenv.py            # interactive menu: 1 = check, 2-4 = align, 5 = finalize (one key)
    python keyenv.py --align --apply               # non-interactive: align both tiers to app1's key
    python keyenv.py --align --primary admin --apply
    python keyenv.py --align --new --apply         # fresh shared key, old kept decrypt-only

Exit status: check is 0 when all tiers agree else 1; align is 0 on success; 2 on
usage error.

The scrypt cost, the fingerprint prefix and the resolution order below mirror
crypto_util.py. Keep them in step if that file's SCRYPT_* or prefix ever change,
or the fingerprints printed here stop matching the app's.
"""

import argparse
import base64
import hashlib
import os
import shutil
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_MAXMEM = 2 ** 15, 8, 1, 64 * 1024 * 1024
_FP_PREFIX = b"dc-hostfnal/fernet-key/v1|"


def tiers():
    return {
        "app1": {
            "env_file": os.path.join(ROOT, "app1", "fastapi-oracle-app", ".env"),
            "key_file": os.path.join(ROOT, "app1", "data", "secret.key"),
        },
        "admin": {
            "env_file": os.path.join(ROOT, "admin", ".env"),
            "key_file": os.path.join(ROOT, "admin", "data", "secret.key"),
        },
    }


def fp(material):
    if isinstance(material, str):
        material = material.encode("utf-8")
    return hashlib.sha256(_FP_PREFIX + material).hexdigest()[:16]


def valid_fernet(material):
    """True when material is urlsafe-base64 of exactly 32 bytes (a Fernet key)."""
    if isinstance(material, str):
        material = material.encode("utf-8")
    try:
        return len(base64.urlsafe_b64decode(material)) == 32
    except Exception:
        return False


def parse_env(path):
    """name -> value from a .env, same rules as crypto_util._env / _bootstrap."""
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, raw = line.split("=", 1)
                out[key.strip()] = raw.strip().strip("\"'")
    except OSError:
        pass
    return out


def derive_passphrase(passphrase, salt):
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt.encode("utf-8"),
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                         maxmem=SCRYPT_MAXMEM)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def read_key_file(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("ascii").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def resolve_tier(tier):
    """Effective key state of one tier, from its .env and secret.key only.

    Returns primary (str|None), origin, retired [str], notes [str], and
    materials [str] -- every distinct key found here, for building the union.
    """
    envf = parse_env(tier["env_file"])
    notes = []
    primary, origin = None, ""

    enc = (envf.get("ENCRYPTION_KEY") or "").strip()
    passph = (envf.get("ENCRYPTION_PASSPHRASE") or "").strip()
    filekey = read_key_file(tier["key_file"])

    if enc:
        if valid_fernet(enc):
            primary, origin = enc, "ENCRYPTION_KEY (.env)"
        else:
            notes.append(f"ENCRYPTION_KEY in {tier['env_file']} is not a valid Fernet key")
    elif passph:
        salt = (envf.get("ENCRYPTION_SALT") or "").strip()
        if len(passph) >= 16 and salt:
            primary, origin = derive_passphrase(passph, salt), "ENCRYPTION_PASSPHRASE (scrypt)"
        else:
            notes.append("ENCRYPTION_PASSPHRASE present but under 16 chars or missing ENCRYPTION_SALT")
    elif filekey:
        if valid_fernet(filekey):
            primary, origin = filekey, "data/secret.key"
        else:
            notes.append(f"{tier['key_file']} is not a valid Fernet key")

    if primary is None and not notes:
        notes.append("no key on disk -- a runtime start would GENERATE its own key here "
                     "(guaranteed mismatch)")

    # A secret.key that is not the primary is dormant now, but may have written
    # rows before ENCRYPTION_KEY was set: its ciphertext only reads if the key
    # stays in the keyring, so alignment must fold it into ENCRYPTION_KEYS_OLD.
    if primary is not None and filekey and valid_fernet(filekey) and filekey != primary:
        notes.append(f"dormant data/secret.key present (fp {fp(filekey)}); its rows only "
                     "decrypt while it is kept in ENCRYPTION_KEYS_OLD")

    retired = []
    for chunk in (envf.get("ENCRYPTION_KEYS_OLD") or "").split(","):
        chunk = chunk.strip()
        if chunk and valid_fernet(chunk):
            retired.append(chunk)

    materials = ([primary] if primary else []) + list(retired)
    if filekey and valid_fernet(filekey):
        materials.append(filekey)

    return {"env_file": tier["env_file"], "primary": primary, "origin": origin,
            "retired": retired, "notes": notes, "materials": materials}


def _union(resolved, canonical):
    """Ordered distinct keys, canonical first, then every other key discovered."""
    seen, ordered = set(), []
    for m in [canonical] + [m for r in resolved.values() for m in r["materials"]]:
        if m and m not in seen:
            seen.add(m)
            ordered.append(m)
    return ordered


def cmd_check(resolved):
    print("Encryption key fingerprints (never the keys themselves):\n")
    fps = []
    for name, r in resolved.items():
        if r["primary"]:
            print(f"  {name:6}  primary {fp(r['primary'])}  [{r['origin']}]")
            fps.append(fp(r["primary"]))
        else:
            print(f"  {name:6}  primary  --  (none resolvable on disk)")
            fps.append(None)
        for rk in r["retired"]:
            print(f"          retired {fp(rk)}  [ENCRYPTION_KEYS_OLD]")
        for note in r["notes"]:
            print(f"          ! {note}")
    print()
    if (os.environ.get("ENCRYPTION_KEY") or "").strip():
        print("  ! ENCRYPTION_KEY is exported in THIS shell. On the real hosts an exported\n"
              "    var or a systemd credential outranks .env and this tool cannot read it,\n"
              "    so the app's live key may differ from what is shown above.\n")

    primaries = [f for f in fps if f]
    if len(primaries) == len(fps) and len(set(primaries)) == 1:
        print(f"OK: all tiers share primary {primaries[0]} -- a row written by one tier "
              "decrypts on the other.")
        return 0
    print("MISMATCH: the tiers do not share one primary key. Because BOTH tiers write\n"
          "(app1 signup, admin console create/ban), ciphertext AND search indexes exist\n"
          "under each tier's own key. Align them with:\n"
          "    python keyenv.py --align --apply             (both adopt app1's key)\n"
          "    python keyenv.py --align --primary admin --apply\n"
          "Align keeps every key as decrypt-only, so all ciphertext still READS. But\n"
          "lookup_hash indexes (login by email/username, OTP, fingerprint match) key off\n"
          "the primary ALONE, so rows the other tier hashed go stale -- after aligning you\n"
          "MUST run rekey_encrypted.py --apply to rebuild them. If the key that WROTE the\n"
          "live rows is not shown above it lives in a systemd credential or exported var\n"
          "-- add it to ENCRYPTION_KEYS_OLD there.")
    return 1


def rewrite_env(path, updates):
    """Replace/insert the given names in a .env, preserving every other line.

    Backs the file up first (it holds a plaintext key), then writes. Returns the
    backup path, or "" when the file did not exist yet.
    """
    lines = []
    backup = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = f"{path}.bak.keyenv.{stamp}"
        shutil.copyfile(path, backup)

    seen, out = set(), []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in updates:
                out.append(f"{k}={updates[k]}\n")
                seen.add(k)
                continue
        out.append(line)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}\n")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.writelines(out)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return backup


def plan_align(resolved, primary_choice, new):
    """Pick the shared primary (generated once for --new) and the keys to retire.

    Returns (canonical, source, retired) or None when the chosen tier has no key.
    Computing the key here, once, is why the menu can show a --new fingerprint and
    then write that same key instead of minting a second one.
    """
    if new:
        canonical, src = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"), "newly generated"
    else:
        canonical = resolved[primary_choice]["primary"]
        if not canonical:
            return None
        src = f"{primary_choice}'s current key"
    return canonical, src, _union(resolved, canonical)[1:]


def print_plan(canonical, src, retired, resolved):
    print(f"Plan: shared primary = {fp(canonical)} ({src})")
    for rk in retired:
        print(f"      keep retired  = {fp(rk)}")
    if not retired:
        print("      (no other keys found; ENCRYPTION_KEYS_OLD will be empty)")
    print()
    for name, r in resolved.items():
        print(f"  {name:6}  ENCRYPTION_KEY -> {fp(canonical)}   ({r['env_file']})")
    if retired:
        print("\n  WARNING: both tiers write (app1 signup, admin create/ban), so some rows\n"
              "  were hashed under a key about to become retired. Their ciphertext still\n"
              "  decrypts, but lookup_hash indexes key off the PRIMARY alone -- login, OTP\n"
              "  and fingerprint lookups will miss those rows until rekey_encrypted.py\n"
              "  --apply rebuilds them. Adopt whichever tier wrote the most rows to\n"
              "  re-hash the fewest.")


def _write_both(resolved, canonical, retired):
    updates = {"ENCRYPTION_KEY": canonical, "ENCRYPTION_KEYS_OLD": ",".join(retired)}
    for name, r in resolved.items():
        backup = rewrite_env(r["env_file"], updates)
        tail = f"  (backup {os.path.basename(backup)})" if backup else "  (created)"
        print(f"  wrote {r['env_file']}{tail}")


def write_align(canonical, retired, resolved):
    _write_both(resolved, canonical, retired)
    print("\nWrote both .env files; every prior key is kept, so all ciphertext still reads.")
    if retired:
        print("REQUIRED next: run rekey_encrypted.py --apply to rebuild lookup_hash indexes\n"
              "under the new primary, or login/OTP/fingerprint lookups will miss rows the\n"
              "other tier hashed. Restart both tiers first. If a row still fails to DECRYPT,\n"
              "its writing key was not on disk here -- add it to ENCRYPTION_KEYS_OLD.")
    else:
        print("All tiers already shared one key; no rows were stale. Restart both tiers.")


def finalize_single_key(resolved):
    """Plan the collapse to ONE key: keep the shared primary, drop every retired
    key. Returns (canonical, dropped) when both tiers already share a primary, or
    a reason string to refuse. Dropping a key is only safe once rekey_encrypted.py
    --apply has re-encrypted every row onto that primary -- any row still under a
    dropped key becomes permanently unreadable.
    """
    primaries = {name: r["primary"] for name, r in resolved.items()}
    if any(p is None for p in primaries.values()):
        return "Cannot finalize: a tier has no resolvable key. Run Check (1) first."
    if len(set(primaries.values())) != 1:
        return ("Cannot finalize: the tiers do NOT share one primary yet. Align them\n"
                "(2/3/4) and run rekey_encrypted.py --apply FIRST, then finalize.")
    canonical = next(iter(primaries.values()))
    return canonical, _union(resolved, canonical)[1:]


def cmd_align(resolved, primary_choice, new, apply):
    plan = plan_align(resolved, primary_choice, new)
    if plan is None:
        print(f"error: tier '{primary_choice}' has no resolvable key to adopt; use --new "
              "or --primary the other tier", file=sys.stderr)
        return 2
    canonical, src, retired = plan
    print_plan(canonical, src, retired, resolved)
    if not apply:
        print("\nDry run -- nothing written. Re-run with --apply to write both .env files.")
        return 0
    write_align(canonical, retired, resolved)
    return 0


def _prompt(msg):
    """input().strip(), or None on EOF / Ctrl-C (piped or closed stdin) so the
    caller can quit rather than spin on a repeated default."""
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def interactive_menu(resolved):
    ALIGN = {"2": ("app1", False), "3": ("admin", False), "4": (None, True)}
    while True:
        print("\nENDHOST encryption keys -- app1 + admin\n"
              "  1) Check env         (read-only: fingerprints + verdict)\n"
              "  2) Align to app1's key   (recommended)\n"
              "  3) Align to admin's key\n"
              "  4) Align to a NEW key    (rotate; keeps old keys decrypt-only)\n"
              "  5) Finalize: use ONE key only  (drop retired -- after rekey)\n"
              "  q) Quit")
        choice = _prompt("Select [1]: ")
        if choice is None or choice.lower() == "q":
            return 0
        choice = choice or "1"                       # bare Enter = the safe default
        if choice == "1":
            cmd_check(resolved)
            continue
        if choice == "5":
            res = finalize_single_key(resolved)
            if isinstance(res, str):
                print("\n" + res)
                continue
            canonical, dropped = res
            if not dropped:
                print(f"\nAlready single-key ({fp(canonical)}) on both tiers -- nothing to drop.")
                continue
            print(f"\nFinalize: keep ONLY {fp(canonical)}; drop every retired key.")
            for d in dropped:
                print(f"          DROP {fp(d)}   (any row still under it becomes unreadable)")
            print("\nSafe ONLY after rekey_encrypted.py --apply moved every row onto the primary.\n"
                  "Dropping a key is IRREVERSIBLE for rows still encrypted under it.")
            ans = _prompt("Type DROP to remove these keys, anything else to cancel: ")
            if ans is not None and ans.upper() == "DROP":
                _write_both(resolved, canonical, [])
                print("\nBoth tiers now hold ONE key -- restart both. If a login/decrypt fails\n"
                      "after this, a row was still under a dropped key: restore the .bak file\n"
                      "and re-run rekey_encrypted.py --apply before finalizing again.")
            else:
                print("Cancelled -- nothing written.")
            return 0
        if choice not in ALIGN:
            print("  ? pick 1, 2, 3, 4, 5 or q")
            continue
        primary_choice, new = ALIGN[choice]
        plan = plan_align(resolved, primary_choice or "app1", new)
        if plan is None:
            print(f"  tier '{primary_choice}' has no key on disk to adopt -- pick another option.")
            continue
        canonical, src, retired = plan
        print()
        print_plan(canonical, src, retired, resolved)
        print("\nThis WRITES both live .env files -- a live-prod key change.")
        ans = _prompt("Type APPLY to write, anything else to cancel: ")
        if ans is not None and ans.upper() == "APPLY":
            write_align(canonical, retired, resolved)
        else:
            print("Cancelled -- nothing written.")
        return 0


def selftest():
    import tempfile
    z = base64.urlsafe_b64encode(bytes(32)).decode()
    assert fp(z) == "fca27fd0e37be214", fp(z)              # locks the prefix
    k1 = base64.urlsafe_b64encode(b"\x01" * 32).decode()
    k2 = base64.urlsafe_b64encode(b"\x02" * 32).decode()
    assert fp(k1) != fp(k2) and fp(k1) == fp(k1)
    assert valid_fernet(k1) and not valid_fernet("not-a-key")

    with tempfile.TemporaryDirectory() as d:
        env = os.path.join(d, ".env")
        keyf = os.path.join(d, "data", "secret.key")
        os.makedirs(os.path.dirname(keyf))
        with open(env, "w") as fh:
            fh.write(f"FOO=1\n# comment\nENCRYPTION_KEY={k1}\nENCRYPTION_KEYS_OLD={k2}\n")
        with open(keyf, "w") as fh:
            fh.write(z)

        r = resolve_tier({"env_file": env, "key_file": keyf})
        assert r["primary"] == k1 and r["retired"] == [k2], r          # .env key beats file
        assert any("dormant" in n for n in r["notes"])                 # z is dormant
        assert {k1, k2, z} <= set(r["materials"])

        bak = rewrite_env(env, {"ENCRYPTION_KEY": k2, "ENCRYPTION_KEYS_OLD": k1})
        txt = open(env).read()
        assert "FOO=1" in txt and "# comment" in txt                   # other lines kept
        assert f"ENCRYPTION_KEY={k2}" in txt and os.path.exists(bak)   # replaced + backed up

        r2 = resolve_tier({"env_file": os.path.join(d, "absent"), "key_file": keyf})
        assert r2["primary"] == z and r2["origin"] == "data/secret.key", r2   # file fallback
        r3 = resolve_tier({"env_file": os.path.join(d, "absent"), "key_file": os.path.join(d, "absent")})
        assert r3["primary"] is None and any("GENERATE" in n for n in r3["notes"])

    resolved = {"app1": {"materials": [k1]}, "admin": {"materials": [k2, z]}}
    u = _union(resolved, k1)
    assert u[0] == k1 and set(u) == {k1, k2, z} and len(u) == len(set(u)), u

    # plan_align: adopt a tier -> that tier's key is primary, the rest retire;
    # --new -> a fresh key, distinct from both, retiring both; no key -> None.
    pa = {"app1": {"primary": k1, "materials": [k1]},
          "admin": {"primary": k2, "materials": [k2, z]}}
    c, _s, ret = plan_align(pa, "app1", False)
    assert c == k1 and set(ret) == {k2, z}, (c, ret)
    cn, _sn, retn = plan_align(pa, "app1", True)
    assert cn not in (k1, k2, z) and valid_fernet(cn) and set(retn) == {k1, k2, z}
    assert plan_align({"app1": {"primary": None, "materials": []}}, "app1", False) is None

    # finalize: shared primary -> drop the retired keys; mismatch / missing -> refuse.
    c2, dropped = finalize_single_key({"app1": {"primary": k1, "materials": [k1, k2]},
                                       "admin": {"primary": k1, "materials": [k1]}})
    assert c2 == k1 and dropped == [k2], (c2, dropped)
    assert isinstance(finalize_single_key({"app1": {"primary": k1, "materials": [k1]},
                                           "admin": {"primary": k2, "materials": [k2]}}), str)
    assert isinstance(finalize_single_key({"app1": {"primary": None, "materials": []},
                                           "admin": {"primary": k1, "materials": [k1]}}), str)
    print("selftest OK")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Check/align the app1 and admin encryption keys (fingerprints only).")
    ap.add_argument("--align", action="store_true",
                    help="align both tiers onto one primary key (bare run shows a menu instead)")
    ap.add_argument("--primary", choices=("app1", "admin"), default="app1",
                    help="whose existing key becomes the shared primary (default: app1)")
    ap.add_argument("--new", action="store_true",
                    help="generate a fresh shared primary; keep all current keys decrypt-only")
    ap.add_argument("--apply", action="store_true",
                    help="actually write the .env files (without it, --align is a dry run)")
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    resolved = {name: resolve_tier(t) for name, t in tiers().items()}
    if args.align:
        return cmd_align(resolved, args.primary, args.new, args.apply)
    if sys.stdin.isatty():
        return interactive_menu(resolved)
    return cmd_check(resolved)


if __name__ == "__main__":
    sys.exit(main())

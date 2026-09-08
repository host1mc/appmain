"""
rotate_key.py — replace the encryption key with a brand new one, with no window
where anything in the database is unreadable.

A rotation is two changes that cannot happen at the same instant: the key the
fleet writes with, and the ciphertext already sitting in Oracle. Doing only the
first is what produces `InvalidToken` on the next settings read. So this script
does them in the one order that is always recoverable:

  1. generate a fresh Fernet key (32 random bytes, never printed, never logged);
  2. write it into every tier's .env as ENCRYPTION_KEY, and demote the *previous*
     key to ENCRYPTION_KEYS_OLD — decrypt-only, so every existing value keeps
     reading while it is still encrypted under it;
  3. record ENCRYPTION_KEY_FINGERPRINT, a truncated SHA-256 of the new key, so a
     tier that somehow loads a different key refuses to start instead of writing
     ciphertext its siblings cannot read;
  4. re-encrypt every stored value under the new key (rekey_encrypted.py --apply,
     in a fresh process — crypto_util resolves the key once at import);
  5. verify: both tiers report the new fingerprint, and nothing in the database
     still needs an old key.

Only after step 5 passes is the old key redundant, and `--retire-old` drops it.
Until then the .env holds both, which is the whole point: if step 4 dies halfway
the database is a mix of old and new ciphertext and *both* still decrypt.

    python rotate_key.py                # show what would change
    python rotate_key.py --apply        # rotate
    python rotate_key.py --retire-old   # drop ENCRYPTION_KEYS_OLD once verified

Backups of every .env are written next to it as .env.bak-<timestamp>. Secrets are
never printed: keys are identified by fingerprint only.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

from cryptography.fernet import Fernet

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import creds  # noqa: E402
import crypto_util  # noqa: E402

# The two files that actually carry the key. crypto_util reads the first one
# itself; admin/_bootstrap.py loads the second into os.environ before it imports
# its vendored copy of crypto_util.
APP_ENV = crypto_util.ENV_PATH
ADMIN_ENV = os.path.join(os.path.dirname(HERE), "admin", ".env")

# Names this script owns in those files.
KEY_NAME = "ENCRYPTION_KEY"
OLD_NAME = "ENCRYPTION_KEYS_OLD"
FP_NAME = "ENCRYPTION_KEY_FINGERPRINT"
MANAGED = (KEY_NAME, OLD_NAME, FP_NAME)

# How many superseded keys to keep. Each one is another key that can still
# decrypt this database, so the list is a liability once the rekey has run;
# two is enough to survive a rotation that was interrupted by an earlier one.
MAX_RETIRED = 2

BANNER = ("# Encryption key, managed by app/rotate_key.py. Every tier sharing "
          "this\n# database must hold the same ENCRYPTION_KEY; "
          "ENCRYPTION_KEYS_OLD is\n# decrypt-only and exists so a rotation can "
          "be interrupted safely.")

# Children must take the key from the .env files this script just wrote, not
# from an ENCRYPTION_* left in this process's environment (which is the *older*
# value and outranks .env).
CHILD_DROP = (KEY_NAME, OLD_NAME, FP_NAME, "ENCRYPTION_PASSPHRASE")


def _read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def _value_of(lines, name):
    """Last uncommented NAME=... in a .env, or ''. Last wins, as with a parser
    that assigns as it reads."""
    found = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        if key.strip() == name:
            found = val.strip().strip("\"'")
    return found


def _upsert(path, values):
    """Set NAME=value for each entry, in place, keeping comments and order.

    Existing assignments are rewritten where they stand — a comment above a line
    is explaining that line, and moving the line away from it loses the
    explanation. Names not present yet are appended under BANNER. Written to a
    temp file and os.replace()d so an interrupted write cannot leave a tier with
    half a key.
    """
    lines = _read_lines(path)
    remaining = dict(values)
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in values:
                if key in remaining:
                    new = remaining.pop(key)
                    if new:
                        out.append(f"{key}={new}")
                continue  # empty or duplicate value -> drop the line entirely
        out.append(line)

    appended = [k for k, v in remaining.items() if v]
    if appended:
        if out and out[-1].strip():
            out.append("")
        out.append(BANNER)
        for key in MANAGED:
            if key in remaining and remaining[key]:
                out.append(f"{key}={remaining[key]}")

    tmp = path + ".tmp"
    # The temp file carries its own mode, and os.replace() replaces the inode —
    # so a .env that was 0600 comes out with whatever the umask gave the temp
    # file, usually 0644. That silently world-reads the key this script just
    # wrote. Create it 0600 and restore the original mode explicitly.
    try:
        original_mode = os.stat(path).st_mode & 0o777
    except OSError:
        original_mode = 0o600
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out).rstrip("\n") + "\n")
    try:
        os.chmod(tmp, original_mode)
    except OSError:
        pass  # Windows / non-POSIX filesystems
    os.replace(tmp, path)
    return appended


def _backup(path):
    """Copy a .env aside before rewriting it.

    The copy holds the key that is about to be superseded, in plaintext, and it
    stays on disk indefinitely. shutil.copyfile() creates the destination with
    the umask's mode and only then could it be tightened, so the key material is
    briefly world-readable; create the file 0600 first and write into it.
    """
    dest = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with open(path, "rb") as src, os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(src, out)
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
    return dest


def _blocking_overrides():
    """Reasons the .env files this script writes are not what the fleet reads.

    crypto_util._env() resolves each name from a systemd credential first, then
    the process environment, then .env — so .env is the *lowest* precedence of
    the three. Rewriting it while either of the others supplies ENCRYPTION_KEY
    changes nothing the fleet actually loads, and does it while writing fresh
    plaintext key material to disk.

    That is worse than a no-op. The children this script spawns drop ENCRYPTION_*
    from their environment (CHILD_DROP), so the rekey and the fingerprint probe
    both read the new .env key and report a clean, agreeing rotation — while the
    live services, which have no such scrubbing, are still on the old key. The
    verification would pass and the fleet would be broken.
    """
    reasons = []
    for name in (KEY_NAME, OLD_NAME, "ENCRYPTION_PASSPHRASE"):
        if creds.get(name):
            reasons.append(
                f"{name} comes from a systemd credential, which outranks .env. "
                "Rotate it in the credential store (see creds.py and deploy/), "
                "not here.")
    if os.environ.get(KEY_NAME):
        reasons.append(
            f"{KEY_NAME} is exported in this process's environment and outranks "
            ".env. Unset it and let .env carry the key, or update the "
            "shell/service definition that exports it.")
    if os.environ.get("ENCRYPTION_PASSPHRASE"):
        reasons.append(
            "ENCRYPTION_PASSPHRASE is exported in this process's environment. A "
            "passphrase-derived key is not rotated by writing ENCRYPTION_KEY.")
    return reasons


def _targets(extra):
    """The .env files to rewrite. The app's is required — it is the one
    crypto_util reads directly — the console's is rewritten when present."""
    paths, missing, seen = [], [], set()
    for path in [APP_ENV, ADMIN_ENV] + list(extra):
        real = os.path.abspath(path)
        if real in seen:
            continue
        seen.add(real)
        (paths if os.path.isfile(real) else missing).append(real)
    return paths, missing


def _retired_value(previous, existing):
    """The new ENCRYPTION_KEYS_OLD: previous key first, then whatever was already
    listed, deduplicated by material.

    Raises when the result would exceed MAX_RETIRED instead of truncating it.
    Truncating is silent permanent data loss: two interrupted rotations put K1 and
    K0 in the list, a third demotes K2 and drops K0 off the end, and every row
    still encrypted under K0 becomes unreadable with no error at any point. The
    list is only allowed to shrink through --retire-old, which refuses while any
    row still needs an entry.
    """
    keys, seen = [], set()
    for material in [previous] + [c.strip().encode("utf-8")
                                  for c in existing.split(",") if c.strip()]:
        if not material or material in seen:
            continue
        seen.add(material)
        keys.append(material.decode("utf-8"))
    if len(keys) > MAX_RETIRED:
        raise RuntimeError(
            f"{OLD_NAME} would hold {len(keys)} keys "
            f"({', '.join(crypto_util.key_fingerprint(k) for k in keys)}), over "
            f"the limit of {MAX_RETIRED}. Dropping one would make any row still "
            "encrypted under it permanently unreadable. Finish the rotation "
            "already in progress first: `python rekey_encrypted.py --apply`, "
            "then `python rotate_key.py --retire-old`.")
    return ",".join(keys)


def _child_env():
    env = dict(os.environ)
    for name in CHILD_DROP:
        env.pop(name, None)
    return env


def _run(argv, cwd=HERE, quiet=False):
    """Run a child that must resolve the key itself. Returns (rc, output)."""
    proc = subprocess.run([sys.executable] + argv, cwd=cwd, env=_child_env(),
                          capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    if not quiet:
        for line in output.strip().splitlines():
            print(f"    | {line}")
    return proc.returncode, output


FP_PROBE = ("import crypto_util, sys; "
            "sys.stdout.write(crypto_util.key_fingerprint())")


def _probe(cwd, code):
    """Run a one-liner and return (stdout, everything) — stdout alone, because
    crypto_util narrates its key source on stderr and the two would otherwise
    concatenate into a fingerprint that matches nothing."""
    proc = subprocess.run([sys.executable, "-c", code], cwd=cwd, env=_child_env(),
                          capture_output=True, text=True)
    return proc.stdout.strip(), ((proc.stdout or "") + (proc.stderr or "")).strip()


def _tier_fingerprints():
    """What key each tier resolves, in a fresh process. {label: fingerprint|error}"""
    admin_dir = os.path.dirname(ADMIN_ENV)
    tiers = {"app": (HERE, FP_PROBE)}
    if os.path.isdir(admin_dir):
        tiers["admin console"] = (admin_dir, "import _bootstrap; " + FP_PROBE)
    out = {}
    for label, (cwd, code) in tiers.items():
        value, full = _probe(cwd, code)
        out[label] = value if len(value) == 16 else f"FAILED: {full[-300:]}"
    return out


def _report_tiers(expected):
    print("[rotate] key each tier resolves now:")
    agreed = True
    for label, fingerprint in _tier_fingerprints().items():
        match = fingerprint == expected
        agreed = agreed and match
        print(f"    {label:14s} {fingerprint}  {'ok' if match else 'MISMATCH'}")
    return agreed


def show_plan(paths, missing, current_fp, origin):
    print(f"[rotate] current key {current_fp} (from {origin})")
    for path in paths:
        lines = _read_lines(path)
        held = _value_of(lines, KEY_NAME)
        held_fp = crypto_util.key_fingerprint(held) if held else "(not set)"
        retired = _value_of(lines, OLD_NAME)
        count = len([c for c in retired.split(",") if c.strip()])
        print(f"    {path}\n        {KEY_NAME}={held_fp}  "
              f"{OLD_NAME}={count} key(s)  "
              f"{FP_NAME}={_value_of(lines, FP_NAME) or '(not set)'}")
    for path in missing:
        print(f"    {path} (absent, skipped)")
    # Ask each tier what it resolves *before* changing anything: a tier that
    # cannot answer (an old vendored copy of crypto_util, a folder that will not
    # import) is a tier the rotation would leave behind holding a dead key.
    _report_tiers(current_fp)
    for reason in _blocking_overrides():
        print(f"[rotate] BLOCKED: {reason}")


def rotate(paths, previous, previous_fp):
    """Generate a new key, write it everywhere, re-encrypt, verify."""
    blocking = _blocking_overrides()
    if blocking:
        print("[rotate] REFUSING to rotate — the files this script writes are "
              "not where the fleet reads its key from:")
        for reason in blocking:
            print(f"    - {reason}")
        return 1

    new_key = Fernet.generate_key()
    new_fp = crypto_util.key_fingerprint(new_key)
    print(f"[rotate] new key {new_fp} generated (the key itself is never printed)")

    # Work out every file's new contents before touching any of them. _upsert is
    # atomic per file but the loop is not, so a _retired_value refusal on the
    # second .env would otherwise leave the first one already rotated and the
    # tiers split across two different keys.
    planned = []
    try:
        for path in paths:
            lines = _read_lines(path)
            planned.append((path, {
                KEY_NAME: new_key.decode("utf-8"),
                OLD_NAME: _retired_value(previous, _value_of(lines, OLD_NAME)),
                FP_NAME: new_fp,
            }))
    except RuntimeError as exc:
        print(f"[rotate] REFUSING: {exc}")
        return 1

    for path, values in planned:
        backup = _backup(path)
        added = _upsert(path, values)
        note = f", added {', '.join(added)}" if added else ""
        print(f"[rotate] wrote {path} (backup {os.path.basename(backup)}{note})")

    print(f"[rotate] re-encrypting stored values under {new_fp} "
          f"(previous key {previous_fp} stays readable until this succeeds)")
    rc, _ = _run(["rekey_encrypted.py", "--apply"])
    if rc != 0:
        print("\n[rotate] FAILED during re-encryption. Nothing is lost: both keys "
              f"are in {OLD_NAME}/{KEY_NAME}, so every value still decrypts. Fix "
              "the error above and re-run `python rotate_key.py --apply`, or "
              "restore the .env.bak-* files to go back.")
        return 1

    print("[rotate] verifying")
    if not _report_tiers(new_fp):
        print("[rotate] FAILED: a tier does not resolve the new key. Its .env was "
              "not rewritten, or its environment exports an older key.")
        return 1
    rc, out = _run(["rekey_encrypted.py"], quiet=True)
    summary = [ln for ln in out.splitlines() if ln.startswith("[rekey] readable=")]
    print(f"    {summary[-1] if summary else out.strip()[-200:]}")
    for line in out.splitlines():
        if "UNLISTED" in line or "UNCLASSIFIED" in line:
            print(f"    | {line}")
    if rc != 0:
        print("[rotate] FAILED: the verification scan did not come back clean — "
              "see the lines above. The previous key is still in "
              f"{OLD_NAME}, so nothing is lost.")
        return 1

    print(f"\n[rotate] done. Key {previous_fp} -> {new_fp}, every stored value "
          "re-encrypted.\n[rotate] restart the stack (python main.py) — running "
          "processes hold the old key in memory.\n[rotate] once it is healthy, "
          "run `python rotate_key.py --retire-old` to drop the previous key.")
    return 0


def retire_old(paths):
    """Drop ENCRYPTION_KEYS_OLD, but only once nothing needs it."""
    listed = [p for p in paths if _value_of(_read_lines(p), OLD_NAME)]
    if not listed:
        print(f"[rotate] no {OLD_NAME} set anywhere — nothing to retire.")
        return 0

    blocking = _blocking_overrides()
    if blocking:
        # Retiring is the irreversible half of a rotation. If .env is not where
        # the key comes from, this scan was run against a different key than the
        # fleet's and its verdict says nothing about what the fleet can read.
        print("[rotate] REFUSING to retire — the key does not come from the "
              "files this script manages:")
        for reason in blocking:
            print(f"    - {reason}")
        return 1

    print(f"[rotate] checking the database still reads without the old key(s)")
    rc, out = _run(["rekey_encrypted.py"], quiet=True)
    for line in out.splitlines():
        if (line.startswith("[rekey] readable=") or " unreadable=" in line
                or "UNLISTED" in line or "UNCLASSIFIED" in line):
            print(f"    | {line}")
    if rc != 0:
        print(f"[rotate] REFUSING: values still need an older key, or some are "
              "not covered by the scan. Run `python rekey_encrypted.py` and "
              "resolve what it reports first.")
        return 1

    for path in listed:
        backup = _backup(path)
        _upsert(path, {OLD_NAME: ""})
        print(f"[rotate] removed {OLD_NAME} from {path} "
              f"(backup {os.path.basename(backup)})")
    print("[rotate] the previous key can no longer decrypt this database. "
          "Delete any stray data/secret.key holding it.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--apply", action="store_true",
                    help="generate a new key and re-encrypt (default: report only)")
    ap.add_argument("--retire-old", action="store_true",
                    help=f"drop {OLD_NAME} once the rekey is verified")
    ap.add_argument("--env", action="append", default=[],
                    help="another .env file carrying the key (repeatable)")
    args = ap.parse_args()

    paths, missing = _targets(args.env)
    if not os.path.isfile(APP_ENV):
        print(f"[rotate] {APP_ENV} does not exist — that file is where the app "
              "reads its key. Create it first.")
        return 1

    previous = crypto_util._PRIMARY
    previous_fp = crypto_util.key_fingerprint(previous)

    if args.retire_old:
        return retire_old(paths)

    show_plan(paths, missing, previous_fp, crypto_util._PRIMARY_ORIGIN)
    if not args.apply:
        print("\n[rotate] dry run — nothing was changed. Re-run with --apply to "
              "generate a new key, rewrite the files above and re-encrypt every "
              "stored value.")
        return 0
    return rotate(paths, previous, previous_fp)


if __name__ == "__main__":
    sys.exit(main())

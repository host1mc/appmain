"""
sync_from_app.py — refresh the vendored copies of the hosting app's modules.

This folder is standalone: it runs on the operator's machine with no checkout of
the hosting app present. The price is that modules are *copies* —

    database.py  reviews_db.py  crypto_util.py  engine_client.py
    internal_auth.py  creds.py  error_codes.py  renew_config.py  cf_edge.py

— and a copy of a schema layer that drifts from the real one is worse than no
copy at all: the console would read columns that no longer exist, or miss the
encryption of ones that do. So the copies are recorded in VENDOR.json with a
sha256 each and the source commit, `_bootstrap` warns when a local edit has
touched one, and this script is how they are updated.

    python sync_from_app.py --check                 # verify against VENDOR.json
    python sync_from_app.py --repo <path-to-app>    # re-copy and re-record
    python sync_from_app.py --repo <path> --check    # would a re-copy change anything?

Exit status is 0 when everything agrees and 1 when it does not, so it can be
wired into a release step.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "VENDOR.json")

# Every module the console imports that belongs to the hosting app. Anything
# added here must be import-safe with no repo around it.
VENDORED = ("database.py", "reviews_db.py", "crypto_util.py", "engine_client.py",
            "internal_auth.py", "creds.py", "error_codes.py", "renew_config.py",
            "cf_edge.py")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest():
    if not os.path.exists(MANIFEST):
        return {}
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)


def _git(repo, *args):
    try:
        out = subprocess.run(("git", "-C", repo) + args, capture_output=True, text=True,
                             timeout=15)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def check(repo=None):
    """Report drift. Returns a list of problems, empty when all is well."""
    manifest = read_manifest()
    recorded = manifest.get("files", {})
    problems = []

    if not recorded:
        return ["VENDOR.json is missing or records no files — run --repo <path> once"]

    for name in VENDORED:
        local = os.path.join(HERE, name)
        if not os.path.exists(local):
            problems.append(f"{name}: vendored copy is missing")
            continue
        have = sha256(local)
        want = recorded.get(name, {}).get("sha256")
        if not want:
            problems.append(f"{name}: not recorded in VENDOR.json — "
                            f"drift is not being checked (sha256 {have[:12]})")
        elif have != want:
            problems.append(f"{name}: edited locally since it was vendored "
                            f"(sha256 {have[:12]}, recorded {want[:12]})")
        if repo:
            source = os.path.join(repo, name)
            if not os.path.exists(source):
                problems.append(f"{name}: not found in {repo}")
            elif sha256(source) != have:
                problems.append(f"{name}: the app's copy has moved on — re-run without --check")
    return problems


def sync(repo):
    repo = os.path.abspath(repo)
    missing = [n for n in VENDORED if not os.path.exists(os.path.join(repo, n))]
    if missing:
        print(f"[sync] {repo} does not look like the hosting app: missing {', '.join(missing)}",
              file=sys.stderr)
        return 1

    files = {}
    for name in VENDORED:
        source = os.path.join(repo, name)
        target = os.path.join(HERE, name)
        # Byte-for-byte, no injected banner: the whole point is that the hash
        # can be compared against the app's file without normalising anything.
        shutil.copyfile(source, target)
        files[name] = {"sha256": sha256(target), "bytes": os.path.getsize(target)}
        print(f"[sync] {name}  {files[name]['bytes']} bytes  {files[name]['sha256'][:12]}")

    manifest = {
        "_comment": "Copies of the hosting app's modules. Do not edit them here — "
                    "edit them in the app and re-run sync_from_app.py.",
        "source_path": repo,
        "source_commit": _git(repo, "rev-parse", "HEAD") or "(not a git checkout)",
        "source_branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD") or "",
        "source_dirty": bool(_git(repo, "status", "--porcelain")),
        "synced_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"[sync] recorded {len(files)} files at {manifest['source_commit'][:12]}"
          + (" (working tree dirty)" if manifest["source_dirty"] else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--repo", help="path to a checkout of the hosting app")
    ap.add_argument("--check", action="store_true",
                    help="verify only; never write")
    args = ap.parse_args()

    if args.repo and not args.check:
        return sync(args.repo)

    problems = check(args.repo)
    if problems:
        print("[sync] drift found:")
        for p in problems:
            print("  " + p)
        return 1
    manifest = read_manifest()
    print(f"[sync] {len(VENDORED)} vendored modules match VENDOR.json "
          f"(app commit {str(manifest.get('source_commit'))[:12]}, "
          f"synced {manifest.get('synced_at')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

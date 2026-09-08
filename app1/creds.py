"""
creds.py — read secrets systemd decrypted for us, instead of from a file we own.

Why this exists
---------------
`ENCRYPTION_KEY` decrypts every bot token and every settings row in the shared
database, and until now it lived as plaintext in two .env files. Anything that
could read those files — a backup, a stray `grep`, a coding agent pointed at the
repo, anyone with the operator's shell — had the key. The filesystem was the only
thing guarding it.

systemd-creds moves that boundary. The key is stored on disk *encrypted*, against
the host's TPM2 where one exists and against /var/lib/systemd/credential.secret
otherwise. At service start systemd decrypts it into $CREDENTIALS_DIRECTORY: a
ramfs mount, mode 0400, owned by the service user, unmounted when the unit stops.
So the plaintext never touches persistent storage, never appears in `ps`, is not
inherited by unrelated processes, and the file left on disk is useless if copied
to another machine.

    /etc/dc-hostfnal/encryption_key.cred     ciphertext, safe at rest, backed up
    $CREDENTIALS_DIRECTORY/encryption_key    plaintext, ramfs, only while running

What this does *not* do: hide the key from code running as the service user on
the running host. That process must decrypt the database, so it must hold the
key. What it stops is the key outliving the process — on disk, in a backup, in a
repo, in a tarball copied to a laptop. Past that boundary the answer is a
passphrase typed at boot (ENCRYPTION_PASSPHRASE, already supported in
crypto_util) or a remote KMS, and both cost unattended restarts.

Reading is the whole API
------------------------
`get("ENCRYPTION_KEY")` looks for `$CREDENTIALS_DIRECTORY/encryption_key` —
systemd credential names are conventionally lowercase, and the mapping from the
variable name is mechanical so callers never spell a filename. Absent directory,
absent file, unreadable file: returns "". Every caller already has a fallback
chain, and a credential that is simply not configured must not be an error —
that is the Windows dev box, where CREDENTIALS_DIRECTORY is never set and this
module quietly does nothing.

Installing is a shell job, not a Python one: deploy/install-credentials.sh wraps
`systemd-creds encrypt`. Nothing here ever writes a secret anywhere.
"""

import os
import re

# systemd sets this for a unit carrying LoadCredential=/LoadCredentialEncrypted=.
# Its absence is the normal case off-Linux and in development, not a failure.
DIR_VAR = "CREDENTIALS_DIRECTORY"
_VARIABLE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def directory() -> str:
    """The live credentials directory, or "" when the process has none."""
    return (os.environ.get(DIR_VAR) or "").strip()


def credential_name(var: str) -> str:
    """Environment-variable name -> systemd credential name. ENCRYPTION_KEY ->
    encryption_key. Mechanical, so no caller has to hardcode a path."""
    if not isinstance(var, str) or not _VARIABLE_NAME_RE.fullmatch(var.strip()):
        return ""
    return var.strip().lower()


def get(var: str) -> str:
    """The credential backing `var`, or "" if there isn't one.

    Read fresh every call rather than cached at import: systemd mounts the
    directory before exec, but a caller may import this module in a process that
    was handed credentials later, and the read is a few microseconds off ramfs.

    Never raises. A malformed or unreadable credential returns "" and lets the
    caller's existing fallback run — the alternative is a tier that cannot boot
    because of a file it was not required to have.
    """
    base = directory()
    if not base:
        return ""
    name = credential_name(var)
    if not name:
        return ""
    path = os.path.join(base, name)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except (OSError, UnicodeError):
        return ""


def available(var: str) -> bool:
    """True when `var` is backed by a credential. For startup banners: it says
    where a secret came from without printing any part of it."""
    return bool(get(var))


def describe() -> str:
    """One line naming which credentials are present — never their values.

    Worth printing at boot. The failure this catches is a unit that lost its
    LoadCredentialEncrypted= line during an edit: every tier silently falls back
    to the .env that was supposed to have been scrubbed, and nothing looks wrong
    until you notice the key is in plaintext again.
    """
    base = directory()
    if not base:
        return "no systemd credentials (CREDENTIALS_DIRECTORY unset)"
    try:
        names = sorted(os.listdir(base))
    except OSError as exc:
        return f"credentials directory {base} is unreadable ({exc.__class__.__name__})"
    return (f"{len(names)} systemd credential(s) from {base}: {', '.join(names)}"
            if names else f"credentials directory {base} is empty")

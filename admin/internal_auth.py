"""
internal_auth.py
----------------
Shared secret used to authenticate *service-to-service* calls inside the
stack (frontend -> backend internal endpoints, backend -> engine control API).

The token is read from a systemd credential first, then the INTERNAL_TOKEN
environment variable. In a two-instance deployment both hosts need the same
value, so they trust each other's calls.

Prefer the credential. This token is a bearer secret for every internal endpoint
in the stack, and the other two homes for it are plaintext at rest: an
environment variable is readable from /proc and inherited by every child process,
and data/internal.key is a file on disk that survives in backups. A credential is
ciphertext on disk that systemd decrypts into ramfs for one unit (see creds.py).

As a last fallback the token lives in data/internal.key and is created atomically
on first use so that several components booting at the same time cannot each
write a different key. That path stays for development and for the Windows box;
in production the credential outranks it.

This is what keeps the tiers honest: browsers never see this token, so any
request that carries it must have come from one of our own processes.
"""

import os
import string
import tempfile
from contextlib import contextmanager

import creds

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEY_PATH = os.path.join(DATA_DIR, "internal.key")

INTERNAL_HEADER = "X-Internal-Token"

_cached = None


def _set_private_permissions(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX filesystems


@contextmanager
def _key_file_lock(path: str):
    """Serialize fallback-token initialization and recovery across processes."""
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    _set_private_permissions(lock_path)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _write_complete(fd: int, material: bytes):
    view = memoryview(material)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("failed to write internal token")
        view = view[written:]
    os.fsync(fd)


_TOKEN_MAX_LEN = 512


def _validated_configured_token(token: str, source: str) -> str:
    """Reject a credential/env token that could never work as a header value.

    internal_headers() puts this string straight into an outbound header, so a
    control character in it is a header-injection hazard, and a non-ASCII one can
    never authenticate anything: an HTTP header value is transported as latin-1
    while is_internal_request compares UTF-8 bytes, so the two sides cannot
    agree. Both are configuration mistakes that otherwise surface as every
    internal call failing with no clue why, so fail the tier at boot instead.
    Neither message includes any part of the token.
    """
    if len(token) > _TOKEN_MAX_LEN:
        raise RuntimeError(
            f"INTERNAL_TOKEN from {source} is longer than "
            f"{_TOKEN_MAX_LEN} characters")
    if any(char < "!" or char > "~" for char in token):
        raise RuntimeError(
            f"INTERNAL_TOKEN from {source} contains a character that cannot be "
            "sent in an HTTP header value")
    return token


def _validated_file_token(raw: str) -> str:
    token = raw.strip()
    if len(token) != 64 or any(char not in string.hexdigits for char in token):
        raise RuntimeError(
            f"{KEY_PATH} is not a valid 64-character hexadecimal internal token")
    return token


def _read_file_token() -> str:
    with open(KEY_PATH, encoding="ascii") as f:
        return _validated_file_token(f.read())


def _create_file_token(token: str) -> str:
    material = token.encode("ascii")
    try:
        fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _read_file_token()
    write_error = None
    try:
        _write_complete(fd, material)
    except Exception as exc:
        write_error = exc
    finally:
        os.close(fd)
    if write_error is not None:
        try:
            os.unlink(KEY_PATH)
        except OSError:
            pass
        raise write_error
    _set_private_permissions(KEY_PATH)
    return _read_file_token()


def _replace_empty_file_token(token: str) -> str:
    material = token.encode("ascii")
    fd, temp_path = tempfile.mkstemp(prefix=".internal.key.", dir=DATA_DIR)
    try:
        _set_private_permissions(temp_path)
        _write_complete(fd, material)
        os.close(fd)
        fd = -1
        os.replace(temp_path, KEY_PATH)
        _set_private_permissions(KEY_PATH)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
    return _read_file_token()


def _generate():
    import secrets
    return secrets.token_hex(32)


def _derived_fleet_token() -> str:
    """A token both hosts compute the same, or "" when there is nothing shared
    to derive it from.

    data/internal.key is per-filesystem, so on the two-instance deployment
    each host invents its own token. session_cookie.sign/verify key off this
    value, so a cookie signed by one host fails the HMAC on the other,
    open_session treats it as forged and returns an empty session, and the
    next form post comes back "Request Expired" — for about half the requests
    a round-robin load balancer hands out.

    ENCRYPTION_KEY is already required to be byte-identical on every host, or
    the tiers could not read each other's rows out of the shared database, so
    it is something to converge on without asking the operator for a second
    secret. One-way through SHA-256 with a domain label, which also lands on
    exactly the 64 hex characters the file format already validates.

    Still ranks below the credential and the env var: an explicitly configured
    token keeps winning.
    """
    import cf_edge
    shared = (creds.get("ENCRYPTION_KEY") or
              cf_edge._setting("ENCRYPTION_KEY")).strip()
    if not shared:
        return ""
    import hashlib
    return hashlib.sha256(
        b"endhost.internal.token.v1|" + shared.encode("utf-8")).hexdigest()


def get_internal_token() -> str:
    """Read the shared internal token: credential, env var, fleet-derived, file."""
    global _cached
    if _cached:
        return _cached
    cred_token = (creds.get("INTERNAL_TOKEN") or "").strip()
    if cred_token:
        _cached = _validated_configured_token(cred_token, "the systemd credential")
        return _cached
    env_token = (os.environ.get("INTERNAL_TOKEN") or "").strip()
    if env_token:
        _cached = _validated_configured_token(
            env_token, "the INTERNAL_TOKEN environment variable")
        return _cached
    derived = _derived_fleet_token()
    if derived:
        _cached = derived
        return _cached
    os.makedirs(DATA_DIR, exist_ok=True)
    with _key_file_lock(KEY_PATH):
        try:
            _cached = _read_file_token()
        except FileNotFoundError:
            _cached = _create_file_token(_validated_file_token(_generate()))
        except RuntimeError:
            with open(KEY_PATH, "rb") as f:
                if f.read().strip():
                    raise
            _cached = _replace_empty_file_token(
                _validated_file_token(_generate()))
    return _cached


def internal_headers() -> dict:
    """Headers a caller adds to reach an internal-only endpoint."""
    return {INTERNAL_HEADER: get_internal_token()}


def is_internal_request(request) -> bool:
    """True when a Flask request carries the shared internal token."""
    import hmac
    sent = request.headers.get(INTERNAL_HEADER, "")
    if not isinstance(sent, str) or not sent:
        return False
    # Compared as bytes: hmac.compare_digest raises TypeError on a str that is
    # not ASCII-only, and Werkzeug decodes header bytes as latin-1, so a single
    # high byte in this header turned every guarded route into a 500.
    return hmac.compare_digest(
        sent.encode("utf-8", "surrogatepass"),
        get_internal_token().encode("utf-8", "surrogatepass"),
    )

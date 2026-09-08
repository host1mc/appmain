"""
crypto_util.py
---------------
Handles full encryption / decryption of sensitive data at rest: Discord bot
tokens, and every value in the settings table (admin credentials, SMTP, ad and
device policy).

Key material, highest precedence first:

  1. ENCRYPTION_KEY        a urlsafe-base64 32-byte Fernet key (recommended)
  2. ENCRYPTION_PASSPHRASE stretched into a key with scrypt; needs
     + ENCRYPTION_SALT     a salt, and refuses a short passphrase
  3. data/secret.key       generated on first run — the single-tier fallback

Each name is read from a systemd credential first, then from the process
environment, then from the same fastapi-oracle-app/.env the database config comes
from. Credentials come first because they are the only one of the three that is
not plaintext at rest: `systemd-creds` stores ciphertext on disk, bound to the
host TPM2, and systemd decrypts it into a ramfs $CREDENTIALS_DIRECTORY for this
unit alone (see creds.py, and deploy/ for the units). On a box without systemd
that lookup is an unset variable and the .env path is unchanged.

That .env fallback is load-order, not preference: `database._load_config()` is
what reads that file and it imports this module before it runs, so a key living
only in .env would arrive too late.

Rotation. ENCRYPTION_KEYS_OLD is a comma-separated list of retired keys used for
*decrypt only* (MultiFernet), so values still under a previous key keep reading
while rekey_encrypted.py rewrites them. New ciphertext always uses the primary
key. rotate_key.py drives the whole cycle; it *reads* ENCRYPTION_KEYS_OLD through
the same three-source lookup as every other name here, but it has no
credential-write path: it writes the rotated key in plaintext into .env and leaves
plaintext .env.bak-* copies beside it, so file mode is all that protects them.
That also means rotate_key.py cannot rotate a key that arrives from a credential
or an exported environment variable — those outrank .env, so rewriting .env would
change nothing the fleet loads, and the script refuses rather than reporting a
rotation it did not perform.

Two ciphertext formats. Fernet (AES-128-CBC + HMAC-SHA256) is what the database
holds today and what encrypt() writes by default. ENCRYPTION_FORMAT=gcm switches
new writes to AES-256-GCM, which is also the only one of the two that can bind
additional authenticated data — see encrypt()'s `context`. Reads accept both
formats unconditionally, so the switch needs no flag day; what it does need is
`rekey_encrypted.py --apply` afterwards, because until every row is converted the
database holds a mix and each retired key stays required by whichever rows still
use it. Set the same value on every tier: they share one database, and a tier left
on the other value keeps writing the format the others are migrating away from.

Fingerprints, never keys. key_fingerprint() is a domain-separated SHA-256 over
the key material, truncated — safe to log and to compare. Set
ENCRYPTION_KEY_FINGERPRINT and every tier refuses to start unless it holds that
exact key. This is the failure this module could not previously see: it resolves
data/secret.key relative to its own file, so a second copy elsewhere (the admin
console vendors one) generated a second key against the same database and wrote
ciphertext the app raised InvalidToken on.
"""

import base64
import hashlib
import hmac
import os
import sys
from contextlib import contextmanager
from cryptography.fernet import Fernet, MultiFernet, InvalidToken

import creds

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEY_PATH = os.path.join(DATA_DIR, "secret.key")
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fastapi-oracle-app", ".env")

# scrypt cost for passphrase-derived keys. n=2^15 is ~100ms and 32 MB per
# derivation on a normal box: paid once at import, and expensive enough that a
# leaked .env is not a wordlist away from the key.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSPHRASE = 16


def _set_private_permissions(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX filesystems


@contextmanager
def _key_file_lock(path: str):
    """Serialize fallback-key initialization across processes."""
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
            raise OSError("failed to write encryption key")
        view = view[written:]
    os.fsync(fd)


def _read_file_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        encoded = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{path} is not a valid Fernet key ({exc})") from exc
    return _validated(encoded, path)


def _env(name: str) -> str:
    """One config name, from a systemd credential, the environment, or .env.

    Credentials outrank both. A .env is plaintext at rest and an environment
    variable is readable from /proc and inherited by every child; a credential is
    ciphertext on disk that systemd decrypts into ramfs for this unit alone. When
    the deployment took the trouble to provide one, it is the answer — otherwise
    scrubbing the .env would be undone by whichever stale copy is still exported.

    Off systemd this is a dict lookup against an unset variable and the old
    behaviour resumes unchanged.
    """
    val = creds.get(name)
    if val:
        return val
    val = (os.environ.get(name) or "").strip()
    if val:
        return val
    try:
        with open(ENV_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, raw = line.split("=", 1)
                if key.strip() == name:
                    return raw.strip().strip("\"'")
    except OSError:
        pass
    return ""


def _validated(key: str, origin: str) -> bytes:
    material = key.strip().encode("utf-8")
    try:
        Fernet(material)  # raises unless 32 urlsafe-base64-encoded bytes
    except Exception as exc:
        raise RuntimeError(
            f"{origin} is not a valid Fernet key ({exc}). Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc
    return material


def _derive_from_passphrase(passphrase: str, salt: str) -> bytes:
    """scrypt(passphrase, salt) -> Fernet key.

    A passphrase carries only the entropy someone typed, so the KDF is
    deliberately expensive and a short one is refused rather than stretched into
    false confidence. The salt is not a secret; it only has to be fixed, because
    changing it changes the key.
    """
    if len(passphrase) < MIN_PASSPHRASE:
        raise RuntimeError(
            f"ENCRYPTION_PASSPHRASE must be at least {MIN_PASSPHRASE} characters")
    if not salt:
        raise RuntimeError(
            "ENCRYPTION_PASSPHRASE needs ENCRYPTION_SALT — any fixed, non-secret "
            "string; changing it changes the key")
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt.encode("utf-8"),
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                         maxmem=SCRYPT_MAXMEM)
    return base64.urlsafe_b64encode(raw)


def _primary_key() -> tuple:
    """The key new ciphertext is written with, and where it came from."""
    env_key = _env("ENCRYPTION_KEY")
    if env_key:
        origin = ("ENCRYPTION_KEY (systemd credential)"
                  if creds.get("ENCRYPTION_KEY") else "ENCRYPTION_KEY")
        return _validated(env_key, "ENCRYPTION_KEY"), origin

    passphrase = _env("ENCRYPTION_PASSPHRASE")
    if passphrase:
        return (_derive_from_passphrase(passphrase, _env("ENCRYPTION_SALT")),
                "ENCRYPTION_PASSPHRASE (scrypt)")

    os.makedirs(DATA_DIR, exist_ok=True)
    with _key_file_lock(KEY_PATH):
        try:
            return _read_file_key(KEY_PATH), KEY_PATH
        except FileNotFoundError:
            key = _validated(Fernet.generate_key().decode("ascii"), KEY_PATH)
            try:
                fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                return _read_file_key(KEY_PATH), KEY_PATH
            write_error = None
            try:
                _write_complete(fd, key)
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
            return _read_file_key(KEY_PATH), KEY_PATH


def _retired_keys() -> list:
    """Decrypt-only keys from ENCRYPTION_KEYS_OLD, newest first.

    A rotation is two steps that cannot be simultaneous: swap the key, then
    rewrite the rows. Between them the database holds ciphertext under both, so
    the old key stays readable — and only readable — until rekey_encrypted.py
    has finished, at which point the entry can be dropped.
    """
    keys = []
    for chunk in _env("ENCRYPTION_KEYS_OLD").split(","):
        chunk = chunk.strip()
        if chunk:
            keys.append(_validated(chunk, "ENCRYPTION_KEYS_OLD"))
    return keys


def _debug_print(*args, **kwargs):
    # Env only: importing reviews_db here used to open HeatWave at module load.
    if os.environ.get("CONSOLE_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
        print(*args, **kwargs)


def key_fingerprint(material: bytes = None) -> str:
    """Short, non-secret identity of a key: 16 hex of a domain-separated SHA-256.

    Safe to print, log and paste into a ticket. Two tiers that agree here hold
    the same key; two that disagree are the InvalidToken bug, visible before it
    corrupts anything instead of after.
    """
    material = _PRIMARY if material is None else material
    if isinstance(material, str):
        material = material.encode("utf-8")
    return hashlib.sha256(b"dc-hostfnal/fernet-key/v1|" + material).hexdigest()[:16]


def lookup_hash(value: str) -> str:
    """Keyed, non-reversible index for a value whose stored copy is encrypted.

    Fernet ciphertext is never equal to itself twice, so a Fernet-encrypted
    username cannot be matched on. This HMAC-SHA256 (64 hex chars) is the
    searchable side: identical plaintext always yields the same index, and the
    index alone cannot be reversed because the HMAC key is derived from the
    encryption key itself — a leaked database without the key cannot dictionary-
    attack common usernames, unlike the plain SHA-256 used for random device
    fingerprints.

    A key rotation changes the index for every row, so rotate_key.py /
    rekey_encrypted.py must rewrite the index column alongside the ciphertext.
    """
    if value is None:
        value = ""
    key = hashlib.sha256(b"dc-hostfnal/lookup-index/v1|" + _PRIMARY).digest()
    return hmac.new(key, value.encode("utf-8", "surrogatepass"),
                    hashlib.sha256).hexdigest()


_PRIMARY, _PRIMARY_ORIGIN = _primary_key()
_RETIRED = _retired_keys()

# MultiFernet encrypts with the first key and decrypts with any of them — which
# is exactly the rotation contract: write new, keep reading old.
_fernet = MultiFernet([Fernet(_PRIMARY)] + [Fernet(k) for k in _RETIRED])


def _verify_expected_fingerprint():
    """Refuse to run on the wrong key when we were told which one is right.

    Optional, and worth setting: ENCRYPTION_KEY_FINGERPRINT turns "this tier
    quietly holds a different key" from a corruption you find in a traceback
    weeks later into a startup failure with the two fingerprints side by side.
    """
    expected = _env("ENCRYPTION_KEY_FINGERPRINT").strip().lower()
    if not expected:
        return
    actual = key_fingerprint()
    if expected != actual.lower():
        raise RuntimeError(
            "encryption key mismatch: ENCRYPTION_KEY_FINGERPRINT expects "
            f"{expected}, this process loaded {actual} (from {_PRIMARY_ORIGIN}). "
            "Refusing to start rather than write ciphertext the other tiers "
            "cannot read. Align the key, or rotate with app/rotate_key.py."
        )


def _warn_if_key_file_shadowed():
    """Say when data/secret.key exists but is not the key in use.

    Silence here is how the two-key failure hides: an operator copies a key file
    between tiers, sees no change because ENCRYPTION_KEY outranks it, and the
    mismatch only surfaces later as InvalidToken from a settings read. Compares
    fingerprints, prints no key material.
    """
    if _PRIMARY_ORIGIN == KEY_PATH or not os.path.exists(KEY_PATH):
        return
    try:
        with open(KEY_PATH, "rb") as fh:
            stale = fh.read().strip()
    except OSError:
        return
    if stale and not hmac.compare_digest(stale, _PRIMARY):
        _debug_print(f"[crypto] {_PRIMARY_ORIGIN} is in use; {KEY_PATH} holds a "
                     f"different key ({key_fingerprint(stale)}) and is ignored - "
                     "delete it, or make it match.", file=sys.stderr)


_verify_expected_fingerprint()
_warn_if_key_file_shadowed()
_debug_print(f"[crypto] key {key_fingerprint()} from {_PRIMARY_ORIGIN}"
             + (f", {len(_RETIRED)} retired key(s) accepted for decrypt" if _RETIRED else ""),
             file=sys.stderr)
_debug_print(f"[crypto] {creds.describe()}", file=sys.stderr)

# Every Fernet token starts with version byte 0x80 + an 8-byte big-endian
# timestamp, which in urlsafe-base64 always renders as this literal prefix.
# It is the only cheap way to tell "already encrypted" from "still plaintext",
# which is what makes a no-migration rollout possible.
FERNET_PREFIX = "gAAAAA"

# AES-256-GCM tokens carry their own prefix. The "." is what makes the two
# formats impossible to confuse: urlsafe-base64 never emits one, so no Fernet
# token can start with this and no GCM token can start with FERNET_PREFIX.
#
# Both are read, always. Only one is written, and which one is ENCRYPTION_FORMAT:
# "fernet" (the default) keeps writing AES-128-CBC+HMAC, "gcm" writes
# AES-256-GCM. It defaults off because switching the write format on a populated
# database is a migration, not a setting — see rekey_encrypted.py, which converts
# existing rows and whose coverage gate tests for both prefixes.
GCM_PREFIX = "gcm1."
GCM_NONCE_BYTES = 12
# AES-GCM's tag is a fixed 16 bytes, so nonce + tag is the smallest a token can
# be (an empty plaintext); anything shorter is malformed, not merely unreadable.
GCM_TAG_BYTES = 16

ENCRYPTION_FORMAT = (_env("ENCRYPTION_FORMAT") or "fernet").strip().lower()
if ENCRYPTION_FORMAT not in ("fernet", "gcm"):
    raise RuntimeError(
        f"ENCRYPTION_FORMAT={ENCRYPTION_FORMAT!r} is not recognised; use "
        "'fernet' (AES-128-CBC+HMAC, the default) or 'gcm' (AES-256-GCM)")


def _gcm_key(material: bytes) -> bytes:
    """A 256-bit AES-GCM key from one Fernet key's material.

    Domain-separated SHA-256 over the same key bytes, so GCM introduces no
    second secret to store, distribute or rotate: ENCRYPTION_KEY and
    ENCRYPTION_KEYS_OLD keep being the only inputs, and a key rotation moves both
    formats at once. The label is what stops this value from ever coinciding with
    the lookup-index key derived in lookup_hash().
    """
    return hashlib.sha256(b"dc-hostfnal/aes256gcm/v1|" + material).digest()


_GCM_KEYS = [_gcm_key(_PRIMARY)] + [_gcm_key(k) for k in _RETIRED]


def looks_encrypted(value) -> bool:
    return isinstance(value, str) and (value.startswith(FERNET_PREFIX)
                                       or value.startswith(GCM_PREFIX))


def _gcm_encrypt(plaintext: str, context: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(GCM_NONCE_BYTES)
    sealed = AESGCM(_GCM_KEYS[0]).encrypt(
        nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
    return GCM_PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode("ascii")


def _gcm_decrypt(token: str, context: str) -> str:
    """Decrypt a GCM token under the primary key or any retired one.

    Raises InvalidToken on failure so the two formats report the same way and
    decrypt()/decrypt_strict() need no special case for either.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        blob = base64.urlsafe_b64decode(token[len(GCM_PREFIX):].encode("ascii"))
    except Exception as exc:
        raise InvalidToken(str(exc)) from exc
    if len(blob) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise InvalidToken("GCM token is too short to hold a nonce and a tag")
    nonce, sealed = blob[:GCM_NONCE_BYTES], blob[GCM_NONCE_BYTES:]
    aad = context.encode("utf-8")
    for key in _GCM_KEYS:
        try:
            plain = AESGCM(key).decrypt(nonce, sealed, aad)
        except Exception:
            continue
        # Outside the try: a token this key authenticated is this key's, and
        # reporting an undecodable plaintext as "no key authenticates it" would
        # send an operator hunting a key problem that does not exist.
        return plain.decode("utf-8")
    raise InvalidToken("no available key authenticates this GCM token")


def encrypt(plaintext: str, context: str = "") -> str:
    """Encrypt a string -> base64 token string (safe to store in DB).

    `context` is additional authenticated data: it is not stored in the token and
    not secret, but decryption fails unless the same value is supplied. Pass the
    field's location ("users.email") and a token cannot be lifted from one column
    into another and still read back. It is ignored by the Fernet format, which
    has nowhere to put it — so a value written under "fernet" and read back with
    a context still decrypts, and only rows rewritten as GCM start binding it.
    """
    if plaintext is None:
        plaintext = ""
    if ENCRYPTION_FORMAT == "gcm":
        return _gcm_encrypt(plaintext, context)
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(token: str, context: str = "") -> str:
    """Decrypt a stored token back to plaintext. Returns '' on failure."""
    if not token:
        return ""
    try:
        if isinstance(token, str) and token.startswith(GCM_PREFIX):
            return _gcm_decrypt(token, context)
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        preview = token[:12] if isinstance(token, str) else f"<{type(token).__name__}>"
        try:
            import reviews_db
            reviews_db.log_app_error("CryptoDecryptFailed", f"decrypt failed for {preview}... key {key_fingerprint()}: {exc}", module="crypto_util", flagged=1)
        except Exception:
            pass
        _debug_print(f"[crypto] decrypt failed for {preview}... - this process holds "
                     f"key {key_fingerprint()}; the value was written under another one "
                     "(see ENCRYPTION_KEYS_OLD / rekey_encrypted.py)", file=sys.stderr)
        return ""


def decrypt_strict(token: str, context: str = "") -> str:
    """Decrypt, or raise InvalidToken.

    decrypt() returning '' is fine for a display field like a masked bot token,
    but it is data loss for anything the app *acts* on — a blank admin password
    hash or a blank SMTP host reads as "not configured" and the failure is
    invisible. Callers that stored ciphertext on purpose use this instead, so a
    rotated/missing data/secret.key fails loudly rather than silently blanking
    every setting in the database.
    """
    if isinstance(token, str) and token.startswith(GCM_PREFIX):
        return _gcm_decrypt(token, context)
    return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def mask(plaintext: str) -> str:
    """Return a masked preview of a secret for display in the UI."""
    if not plaintext:
        return ""
    if len(plaintext) <= 8:
        return "•" * len(plaintext)
    return plaintext[:4] + "•" * (len(plaintext) - 8) + plaintext[-4:]

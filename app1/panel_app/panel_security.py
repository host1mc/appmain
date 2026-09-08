"""Panel-local password hashing (PBKDF2-SHA256).

Byte-for-byte the scheme from the standalone Flask panel. The panel checks no
credentials in any mode — it has no sign-in of its own — so the only caller left
is the account change-password path in ``routes.py``, which refuses before
hashing anything unless ``PANEL_AUTH_MODE=local`` (laptop smoke-testing). Under
the default ``oracle`` mode nothing here runs, and a mirrored row carries an
intentionally unusable placeholder hash instead.
"""

import base64
import hashlib
import hmac
import secrets
import sys


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 600_000

# Upper bound on a password this module will do KDF work for. routes.py checks
# MAX_PASSWORD_CHARS before it calls either function, so this is the backstop for
# any other caller: without it the only limit is the request body size, which
# PanelConfig defaults to 150 MB.
PASSWORD_MAX_CHARS = 1024

# Ceiling on the iteration count verify_password will honour out of a stored
# hash. Well clear of PASSWORD_ITERATIONS so any hash this module ever minted
# still verifies.
PASSWORD_MAX_ITERATIONS = 5_000_000

# Argon2id for new hashes when argon2-cffi is installed, PBKDF2 otherwise. The
# import is optional because this module is imported while the panel tier boots,
# and a missing package must not stop the panel from starting. OWASP's Argon2id
# baseline: 19 MiB, 2 passes, 1 lane.
try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.low_level import Type as _Argon2Type

    _ARGON2 = _Argon2Hasher(time_cost=2, memory_cost=19456, parallelism=1,
                            hash_len=32, salt_len=16, type=_Argon2Type.ID)
except Exception:
    _ARGON2 = None


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if len(password) > PASSWORD_MAX_CHARS:
        raise ValueError(f"password must be at most {PASSWORD_MAX_CHARS} characters")
    if _ARGON2 is not None:
        return _ARGON2.hash(password.encode("utf-8", "surrogatepass"))
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8", "surrogatepass"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return "$".join(
        (
            PASSWORD_SCHEME,
            str(PASSWORD_ITERATIONS),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    if not isinstance(encoded, str) or not encoded:
        return False
    if not isinstance(password, str) or len(password) > PASSWORD_MAX_CHARS:
        # Past the ceiling hash_password enforces, nothing can match a stored
        # value, so this is the answer the checks below would reach anyway —
        # without paying for an Argon2id or a 600k-iteration PBKDF2 first.
        return False
    if encoded.startswith("$argon2"):
        if _ARGON2 is None:
            # Written by an instance that had argon2-cffi, read by one that does
            # not. Returning False silently is indistinguishable from a wrong
            # password, and behind the load balancer that presents as the same
            # password working on one instance and not the other — so say why.
            print("[panel] cannot verify an Argon2id hash: argon2-cffi is not "
                  "installed in this tier", file=sys.stderr)
            return False
        try:
            return _ARGON2.verify(encoded, password.encode("utf-8", "surrogatepass"))
        except Exception:
            return False
    try:
        scheme, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(iterations_text)
        if not 0 < iterations <= PASSWORD_MAX_ITERATIONS:
            # The cost comes out of the stored string, so a corrupted or hand-set
            # row would otherwise decide how long this call runs. Out of range is
            # not a real hash, and the alternative is a wedged threadpool worker.
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8", "surrogatepass"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        return False

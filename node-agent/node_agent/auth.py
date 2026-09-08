import hmac


def _token_bytes(value) -> bytes:
    # hmac.compare_digest refuses two str arguments unless both are pure ASCII:
    # a token carrying any non-ASCII character raised TypeError, which the app's
    # catch-all turned into a 500 instead of the 401 a bad token deserves.
    # Comparing bytes has no such restriction and stays constant-time.
    if isinstance(value, bytes):
        return value
    return str(value or "").encode("utf-8", errors="surrogateescape")


def authorized(authorization_header: str, expected_token: str) -> bool:
    if not expected_token or not authorization_header:
        return False
    scheme, separator, supplied = str(authorization_header).partition(" ")
    if not separator or scheme.lower() != "bearer":
        return False
    supplied = supplied.strip()
    if not supplied:
        return False
    expected_token = expected_token.strip()
    return hmac.compare_digest(_token_bytes(supplied), _token_bytes(expected_token))

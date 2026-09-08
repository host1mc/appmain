"""Masked server identifiers for browser-facing panel URLs."""

import re
from cryptography.fernet import InvalidToken

import crypto_util


_SERVER_ID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}\Z"
)
_CONTEXT = "panel.server_id.url.v1"


def mask_server_id(server_id: str) -> str:
    """Return an encrypted public token for a real server UUID."""
    value = str(server_id or "").strip()
    if not value:
        return ""
    return crypto_util.encrypt(value, context=_CONTEXT)


def unmask_server_id(value: str) -> str:
    """Resolve a public token back to the real server UUID.

    Legacy UUID URLs are still accepted so existing bookmarks and in-flight pages
    do not break during rollout; new links are emitted masked.
    """
    raw = str(value or "").strip()
    if _SERVER_ID_RE.match(raw):
        return raw
    try:
        server_id = crypto_util.decrypt_strict(raw, context=_CONTEXT).strip()
    except (InvalidToken, ValueError, TypeError):
        return ""
    return server_id if _SERVER_ID_RE.match(server_id) else ""


def public_server_key(server_id: str) -> str:
    """Stable non-reversible key used only to match status JSON to DOM rows."""
    value = str(server_id or "").strip()
    return crypto_util.lookup_hash(f"panel.server_id.status.v1:{value}")[:32] if value else ""


def public_server_label(server_id: str) -> str:
    """Short display label that does not reveal the real UUID prefix."""
    key = public_server_key(server_id)
    return key[:8] if key else ""

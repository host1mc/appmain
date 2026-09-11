"""
github_policy.py — the editable requirements for GitHub sign-in / sign-up.

This is the one file that decides who may use "Continue with GitHub".
Edit the values below, restart the backend, done.

Requirements, in the order backend.py enforces them:

  1. GitHub OAuth must succeed (client id/secret/callback come from the
     environment via cf_edge settings, not from here).
  2. REQUIRE_VERIFIED_EMAIL — the GitHub account must expose at least one
     address GitHub itself marks `verified`. Primary is preferred; any
     verified address is accepted unless REQUIRE_PRIMARY_EMAIL is True.
  3. ALLOWED_EMAIL_DOMAINS — the chosen address must belong to one of these
     domains. This mirrors password registration (database.py EMAIL_RE),
     so a GitHub address and a password-signup address always describe the
     same account space: same verified email -> same account.
  4. MIN_ACCOUNT_AGE_DAYS — the GitHub account must be at least this old.
     Throwaway accounts are the cheap way around a ban.
  5. The address must not be on the persistent email ban list, the device/IP
     must pass the same fingerprint policy as password registration, and for
     brand-new accounts the visitor must accept the Terms (forwarded as
     `agreed` from the register page).

Notes:
  - backend.py reads this file once at import, so every change needs a
    backend restart (same as every other setting).
  - The "too new" message is built from MIN_ACCOUNT_AGE_DAYS automatically;
    no other file needs editing when you change the age.
  - Password registration keeps its own domain list at database.py EMAIL_RE.
    If you change ALLOWED_EMAIL_DOMAINS here, change EMAIL_RE there too,
    otherwise the two login methods stop agreeing on what an email is.
"""

import re

# --- email requirements -----------------------------------------------------

# Only these domains may sign in with GitHub. Lowercase, no "@".
ALLOWED_EMAIL_DOMAINS = ("gmail.com", "outlook.com")

# The GitHub account must have a GitHub-verified email. Turning this off is
# not supported by the login flow (there would be nothing to identify the
# account by) — it exists here so the requirement is visible, not optional.
REQUIRE_VERIFIED_EMAIL = True

# When True, only the address GitHub marks `primary` is accepted. When False
# (default), the primary verified address is preferred but any verified
# address works.
REQUIRE_PRIMARY_EMAIL = False

# --- account-age requirement ------------------------------------------------

# Reject GitHub accounts younger than this (in days). 90 ~= 3 months.
MIN_ACCOUNT_AGE_DAYS = 90

# What to do when GitHub gives no usable account age (missing or unparseable
# `created_at`). True = reject (fail closed: every real account has one).
# False = let it through (fail open: only use while debugging).
FAIL_CLOSED_ON_MISSING_CREATED_AT = True


# --- derived helpers (no need to edit below this line) ----------------------

def _build_email_re():
    escaped = [re.escape(d.strip().lower()) for d in ALLOWED_EMAIL_DOMAINS if d.strip()]
    return re.compile(r"^[a-zA-Z0-9._%+\-]+@(" + "|".join(escaped) + r")$",
                      re.IGNORECASE)


EMAIL_RE = _build_email_re()


def email_allowed(email):
    """True when this address may use GitHub sign-in."""
    if not email:
        return False
    return bool(EMAIL_RE.match(email.strip().lower()))


def allowed_domains_label():
    """Human-readable domain list for error messages, e.g. '@gmail.com or @outlook.com'."""
    return " or ".join("@" + d for d in ALLOWED_EMAIL_DOMAINS)

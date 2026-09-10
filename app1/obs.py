"""Optional Sentry error/performance instrumentation, shared by the frontend
and backend tiers.

A no-op unless SENTRY_DSN is set, and it never fails a boot: a missing
sentry-sdk or a bad DSN is logged and swallowed, the same way database.py
treats the optional argon2 dependency. send_default_pii stays False on purpose
— this app stores emails, IP addresses and bot tokens, none of which may leak
into an error tracker."""
import os
import sys

import cf_edge

_started = False


def _debug(msg):
    if os.environ.get("CONSOLE_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
        print(msg, file=sys.stderr)


def init_sentry(component):
    """Initialise Sentry for one tier if SENTRY_DSN is configured. Idempotent
    per process, so it is safe to call from both serve() and the gunicorn
    wsgi import path."""
    global _started
    if _started:
        return
    dsn = (cf_edge._setting("SENTRY_DSN") or "").strip()
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
    except Exception as e:
        _debug(f"[obs] SENTRY_DSN set but sentry-sdk is unavailable: {e}")
        return
    try:
        traces = float(cf_edge._setting("SENTRY_TRACES_SAMPLE_RATE") or 0)
    except (TypeError, ValueError):
        traces = 0.0
    try:
        sentry_sdk.init(
            dsn=dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=traces,
            environment=(cf_edge._setting("SENTRY_ENVIRONMENT") or "production").strip(),
            send_default_pii=False,
        )
        sentry_sdk.set_tag("component", component)
        _started = True
        _debug(f"[obs] Sentry initialised for {component}")
    except Exception as e:
        _debug(f"[obs] Sentry init failed: {e}")

"""
start_panel.py — Tier 4 of 5: the hosting panel UI.

Serves the panel at /panel and nothing else. The panel has no sign-in of its own:
a visitor logs in on the frontend tier, and the panel resolves that session
through the backend tier's internal API — so this tier is useless without the
backend, and it has to be served from the same host as the frontend, because the
session cookie it reads is host-scoped.

Listens on 127.0.0.1:8000 by default (PANEL_BIND / PANEL_PORT). Loopback because
the frontend is what publishes it; a wildcard bind is refused outright.

Unlike the other tiers this one is ASGI, so it runs under uvicorn rather than
waitress. Everything it needs — the panel_app tree's code, the shared .env and
wallet, and the shared internal token — is set up at import of asgi_panel, which
is also the gunicorn entrypoint for this tier.

Run: python start_panel.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def serve():
    import db_env_report
    db_env_report.print_db_env_report("panel")

    # asgi_panel resolves the internal token itself, because the panel's config
    # needs the value handed to it rather than just present on disk — so there is
    # no internal_auth.get_internal_token() call here, unlike the other tiers.
    import asgi_panel
    asgi_panel.serve()


if __name__ == "__main__":
    serve()

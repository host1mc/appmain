"""
start_frontend.py — Tier 4 of 4: the public web server.

Renders the HTML, holds the browser session cookie, and proxies /api/* to the
backend. It has NO database access whatsoever — no `database` import, no
`crypto_util`, no database handle. Every byte of data it renders arrives over
HTTP from the backend.

This is the only tier bound to 0.0.0.0 (port 5000).

Run: python start_frontend.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import internal_auth
import db_env_report


def serve():
    db_env_report.print_db_env_report("frontend")
    internal_auth.get_internal_token()
    import frontend
    frontend.serve()


if __name__ == "__main__":
    serve()

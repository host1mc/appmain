"""
start_backend.py — Tier 2 of 4: the API / data-access server.

The only tier that talks to the database on behalf of a browser. It owns
authentication, authorization and every `database` call, and delegates all
Discord / status calls to the engine.

Listens on 127.0.0.1:8001 (loopback only — it is never exposed publicly;
the frontend proxies to it).

Run: python start_backend.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import internal_auth
import db_env_report


def serve():
    db_env_report.print_db_env_report("backend")
    internal_auth.get_internal_token()
    import backend
    backend.serve()


if __name__ == "__main__":
    serve()

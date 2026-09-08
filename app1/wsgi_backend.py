"""gunicorn/uWSGI entrypoint for the internal backend API tier.

Serves the same Flask app as start_backend.py (waitress). Gunicorn on the
Linux host, two instances behind the LB, e.g.:

    gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8001 wsgi_backend:application

backend.init() runs at import time: it resolves the shared internal token and
calls db.init_db() (idempotent, so running it once per worker is safe). The
wildcard-bind refusal in _bind_host() only guards the waitress path — under
gunicorn the operator must supply a safe --bind (loopback, or a specific
private interface for the two-instance layout); never 0.0.0.0. The frontend
hops it trusts are fixed by TRUSTED_PROXY_HOPS.
"""

import backend

backend.init()

application = backend.app

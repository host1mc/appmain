"""gunicorn/uWSGI entrypoint for the public frontend tier.

The tier is a plain Flask app — and Flask *is* a WSGI application, so
`application` is the WSGI callable a server hands requests to. The waitress
launcher (start_frontend.py / main.py) stays the default for the Windows dev
box and for `python main.py`; this file is the systemd/gunicorn path on the
Linux host:

    gunicorn --workers 2 --threads 4 --bind 127.0.0.1:5000 wsgi_frontend:application

frontend.init() runs at import time (the only hook gunicorn guarantees), so the
shared internal token is resolved here just as serve() resolved it. The load
balancer must still forward X-Forwarded-For and X-Forwarded-Proto;
TRUSTED_PROXY_HOPS governs how many of those hops are believed, exactly as with
waitress. Sessions live in the backend DB, not in-process, so multiple workers
share one session store with no sticky sessions required.
"""

import frontend
import edge_gate

frontend.init()

application = frontend.app

edge_gate.warn_if_hard_close_unsupported()

"""gunicorn/uWSGI entrypoint for the engine's control API tier.

Serves the same Flask app as start_engine.py (waitress). The engine is a fleet
singleton — one instance runs it — and its bot worker thread is started by
engine.init() at import time, so:

    gunicorn --workers 1 --threads 2 --bind 10.0.0.1:8002 wsgi_engine:application

IMPORTANT: exactly one worker. start_worker() spawns the bot loop, and
engine.init() is not idempotent — two workers would mean two bot loops ticking
against the fleet. If the worker is ever restarted under load the thread dies
with it and the next import starts a fresh one. The wildcard-bind refusal in
_bind_host() only guards the waitress path; under gunicorn the operator must
supply a safe --bind (loopback, or the private interface the backends reach it
on); never 0.0.0.0.
"""

import engine

engine.init()

application = engine.app

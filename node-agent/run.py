import os
from pathlib import Path

from dotenv import load_dotenv

from waitress import serve

from node_agent.app import MAX_REQUEST_BODY_BYTES, create_app

load_dotenv(Path(__file__).resolve().parent / ".env")

application = create_app()


if __name__ == "__main__":
    host = os.environ.get("NODE_BIND", "0.0.0.0")
    port = int(os.environ.get("NODE_PORT", "8081"))
    print(f"node-agent: serving on http://{host}:{port}", flush=True)
    if host in {"0.0.0.0", "::", "*", ""}:
        # Inside the container this is correct and intended (see .env.example).
        # It is worth one line on startup anyway: this port is full control of
        # the host's Docker daemon behind a single bearer token, so whether it is
        # actually reachable from the internet comes down to NODE_PUBLISH_ADDRESS
        # and the firewall — neither of which this process can see.
        print(
            "node-agent: WARNING bound to every interface. Confirm port "
            f"{port} is published only to the panel's address (NODE_PUBLISH_ADDRESS) "
            "and closed at the firewall.",
            flush=True,
        )
    serve(
        application,
        host=host,
        port=port,
        # Every open console tab holds one thread here for its whole lifetime,
        # blocked in the /logs/follow generator. At the old default of 8, roughly
        # 8 open consoles starved every other route on this agent — including
        # /health, which is what the panel uses to decide the node is up.
        threads=int(os.environ.get("NODE_THREADS", "32")),
        max_request_body_size=MAX_REQUEST_BODY_BYTES + 1024 * 1024,
    )

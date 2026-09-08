# Discord Host Node Agent

Run this service on every backend VPS that will host bot containers. It is the
only service that talks to Docker. Every managed server is fixed to 300 MB RAM,
one CPU core (shown as 100% CPU in the panel), and a 600 MB storage quota per
server (the panel reports the quota instead of host disk usage).

## Backend VPS setup

```bash
cp .env.example .env
# Set a long random NODE_TOKEN in .env.
docker compose up -d --build
```

The included Compose file exposes the agent on `NODE_PUBLISH_ADDRESS`, which
defaults to `0.0.0.0` so the panel can reach it at this host's public/VPN
address. Restrict the port with a firewall, or set that value to the backend
VPS private/VPN address when the panel runs on another machine. Then set the
panel's `NODE_URL` to the corresponding address.

Container files are persisted under `/home/ubuntu/dchost/<server-uuid>`.
The Docker images offered by the agent are allowlisted in
`node_agent/catalog.py`.

## Install lifecycle (Pterodactyl-style)

Creating a server kicks off a one-shot install container that runs the
runtime's install script (`npm install` for Node with a mandatory
`package.json`, `pip install -r requirements.txt` for Python with a mandatory
`bot.py`/`main.py`) with the data directory mounted at `/home/container`.
Until that install finishes, the server reports `install_status: "running"`
and **start is refused**; a failed install blocks start with a clear error and
asks for a reinstall. Install state persists in `<id>.install.json`; installs
interrupted by an agent restart are marked failed on boot, and the last ~40 KB
of install output are available via the install-log endpoint.

## API

All `/api/v1/*` requests require `Authorization: Bearer <NODE_TOKEN>`.

- `GET /api/v1/runtimes`
- `POST /api/v1/servers`
- `GET /api/v1/servers/<id>/state`
- `POST /api/v1/servers/<id>/power`
- `GET /api/v1/servers/<id>/logs`
- `POST /api/v1/servers/<id>/command`
- `GET /api/v1/servers/<id>/install` — install status + install log
- `POST /api/v1/servers/<id>/install` — reinstall (only when stopped)
- File listing, reading, writing, directory creation, and deletion endpoints
- `DELETE /api/v1/servers/<id>`

import os
import re
import uuid
from pathlib import Path


MEMORY_MB = 300
CPU_PERCENT = 35
STORAGE_MB = 600
MEMORY_BYTES = MEMORY_MB * 1024 * 1024
STORAGE_BYTES = STORAGE_MB * 1024 * 1024
# Derived from CPU_PERCENT so the enforced quota and the figure the panel shows
# cannot drift apart: Docker counts 1_000_000_000 nano CPUs to one core, so one
# percent of a core is 10_000_000.
NANO_CPUS = CPU_PERCENT * 10_000_000

# Named rather than written straight into the spec below, so /api/v1/config can
# report the ceiling a container is actually given instead of a second copy of
# the number that could drift from it.
PIDS_LIMIT = 128

# Container log persistence. Docker's default json-file driver grows without
# bound, and every server restart appends to the same file. Containers are set
# to keep no logs at all (driver "none") — the panel console then shows nothing,
# because it reads these logs. Operators who want the console back can opt into
# rotation-bounded logs with DCHOST_LOG_DRIVER=json-file (optionally tuning
# DCHOST_LOG_MAX_SIZE / DCHOST_LOG_MAX_FILES).
LOG_DRIVER = os.environ.get("DCHOST_LOG_DRIVER", "none").strip().lower() or "none"
LOG_MAX_SIZE = os.environ.get("DCHOST_LOG_MAX_SIZE", "1m").strip() or "1m"
LOG_MAX_FILES = os.environ.get("DCHOST_LOG_MAX_FILES", "2").strip() or "2"

# Containers run as a non-root uid. Their data directory is bind-mounted from
# the host, so a root process inside would create host files owned by root that
# neither the agent nor the next container could rewrite. Set
# DCHOST_CONTAINER_USER=uid:gid to override, or to empty to fall back to
# whatever user the image itself declares.
CONTAINER_USER = os.environ.get("DCHOST_CONTAINER_USER", "1000:1000").strip()


def _positive_int(name, default, minimum):
    try:
        value = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


# A dependency install that never returns (npm waiting on an unreachable
# registry) used to pin its worker thread for ever and leave the server stuck
# reporting "installing", which blocks start and reinstall alike.
INSTALL_TIMEOUT_SECONDS = _positive_int("DCHOST_INSTALL_TIMEOUT", 900, 60)


def _container_uid_gid():
    """(uid, gid) implied by CONTAINER_USER, or (None, None) when unusable."""
    if not CONTAINER_USER:
        return None, None
    uid, _, gid = CONTAINER_USER.partition(":")
    try:
        return int(uid), int(gid or uid)
    except (TypeError, ValueError):
        return None, None



def _log_config():
    """Docker logging options for a managed container."""
    if LOG_DRIVER == "none":
        return {"type": "none"}
    return {"type": "json-file", "config": {"max-size": LOG_MAX_SIZE, "max-file": LOG_MAX_FILES}}


def _no_log_env():
    """Set inside containers so their tooling also stops persisting logs."""
    return {
        "npm_config_logs_max": "0",
        "npm_config_update_notifier": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _no_cache_env():
    """Set inside containers so their package managers persist no cache.

    HOME is the bind-mounted server directory, so npm's default cache lands in
    /home/container/.npm — charged against the server's own disk quota, on top of
    a node_modules that already holds every one of those packages unpacked.
    Pointing the cache at /tmp puts it in the container's writable layer, which
    is thrown away with the container instead of kept for the life of the server.
    pip is the same story: the install script passes --no-cache-dir, but a bot
    that installs something itself at run time does not.
    """
    return {
        "npm_config_cache": "/tmp/.npm",
        "PIP_NO_CACHE_DIR": "1",
        "XDG_CACHE_HOME": "/tmp/.cache",
    }


def _load_user_env(data_directory):
    """Load KEY=VALUE pairs from a .env file in the server's data directory.

    Variables set here are injected into the container so that bot code which
    reads os.environ (or process.env) picks them up without needing the file
    itself to be on a specific path.  System variables (HOME, TERM, …) are
    added *after* the user's, so they cannot be overridden.
    """
    env_path = Path(data_directory) / ".env"
    env = {}
    try:
        text = env_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return env
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # Strip surrounding quotes (single or double) if present on both sides
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        env[key] = value
    return env


def _valid_server_id(server_id: str) -> str:
    try:
        return str(uuid.UUID(server_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("server id must be a UUID") from exc


def _container_name(server_id: str) -> str:
    return f"dchost_{re.sub(r'[^a-fA-F0-9]', '', server_id).lower()}"


def build_container_spec(server_id, name, image, startup, data_directory, runtime="nodejs", version=""):
    normalized_id = _valid_server_id(server_id)
    startup = (startup or "").strip()
    if not startup:
        raise ValueError("startup command is required")
    if len(startup) > 500:
        raise ValueError("startup command is too long")
    if len(name or "") > 128:
        raise ValueError("server name is too long")
    if len(runtime or "") > 32:
        raise ValueError("runtime is too long")
    if len(version or "") > 32:
        raise ValueError("runtime version is too long")

    return {
        "image": image,
        "name": _container_name(normalized_id),
        "hostname": f"bot-{normalized_id[:8]}",
        "log_config": _log_config(),
        "command": ["/bin/sh", "-lc", startup],
        "working_dir": "/home/container",
        "environment": {
            "SERVER_MEMORY_MB": str(MEMORY_MB),
            "HOME": "/home/container",
            "TERM": "xterm-256color",
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            **_load_user_env(data_directory),
            **_no_log_env(),
            **_no_cache_env(),
        },
        "volumes": {
            str(data_directory): {
                "bind": "/home/container",
                "mode": "rw",
            }
        },
        "mem_limit": MEMORY_BYTES,
        "memswap_limit": MEMORY_BYTES,
        "nano_cpus": NANO_CPUS,
        "pids_limit": PIDS_LIMIT,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "network_mode": "bridge",
        "restart_policy": {"Name": "on-failure"},
        "stdin_open": True,
        "tty": True,
        **({"user": CONTAINER_USER} if CONTAINER_USER else {}),
        "labels": {
            "dchost.managed": "true",
            "dchost.server_id": normalized_id,
            "dchost.display_name": (name or "Discord bot")[:128],
            "dchost.startup": startup[:500],
            "dchost.runtime": (runtime or "nodejs")[:32],
            "dchost.version": (version or "")[:32],
        },
        "detach": True,
    }

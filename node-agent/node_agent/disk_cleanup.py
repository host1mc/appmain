"""Background disk cleanup for the node VPS.

Runs as a daemon thread started by the Flask app.  Handles:
  1. Old log files in /var/log
  2. Docker container log files (json-file driver)
  3. Docker dangling images, build cache, unused networks, dangling volumes
  4. /tmp files older than a configurable age
  5. Orphan containers whose server directory no longer exists on disk

Environment variables:
    LOG_CLEANUP_MAX_AGE_HOURS   — delete log files older than this (default 72)
    LOG_CLEANUP_INTERVAL_MIN    — minutes between sweeps (default 60)
    LOG_CLEANUP_MAX_BYTES       — cap on /var/log total size; oldest files are
                                  removed when exceeded (default 209715200 = 200MB)
    DISK_CLEANUP_TMP_MAX_AGE_H  — delete /tmp files older than this (default 48)
    DISK_CLEANUP_DOCKER_PRUNE   — 1 to run docker system prune (default 1)
    DISK_CLEANUP_DOCKER_LOG_MB  — truncate any container log above this (default 200)
    DISK_CLEANUP_RECONCILE      — 1 to auto-delete orphan containers (default 1)
    DISK_CLEANUP_DATA_ROOT      — server data dir (default /home/ubuntu/dchost)
"""

import glob
import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import docker

_LOGGER = logging.getLogger(__name__)

_MAX_AGE_HOURS = int(os.environ.get("LOG_CLEANUP_MAX_AGE_HOURS", 72))
_INTERVAL_MIN = int(os.environ.get("LOG_CLEANUP_INTERVAL_MIN", 60))
_MAX_BYTES = int(os.environ.get("LOG_CLEANUP_MAX_BYTES", 200 * 1024 * 1024))
_TMP_MAX_AGE_H = int(os.environ.get("DISK_CLEANUP_TMP_MAX_AGE_H", 48))
_DOCKER_PRUNE = os.environ.get("DISK_CLEANUP_DOCKER_PRUNE", "1").strip() not in ("0", "false", "no")
_DOCKER_LOG_MAX_MB = int(os.environ.get("DISK_CLEANUP_DOCKER_LOG_MB", 200))
_RECONCILE = os.environ.get("DISK_CLEANUP_RECONCILE", "1").strip() not in ("0", "false", "no")
_DATA_ROOT = os.environ.get("NODE_DATA_ROOT", "/home/ubuntu/dchost")

_DOCKER_LOG_DIR = "/var/lib/docker/containers"
_VAR_LOG = "/var/log"
_TMP = "/tmp"

_VAR_LOG_PATTERNS = [
    _VAR_LOG + "/*.log",
    _VAR_LOG + "/*.log.*",
    _VAR_LOG + "/*.gz",
    _VAR_LOG + "/*.1",
    _VAR_LOG + "/*.old",
    _VAR_LOG + "/*.xz",
    _VAR_LOG + "/journal/*",
    _VAR_LOG + "/apt/*",
    _VAR_LOG + "/dpkg/*",
    _VAR_LOG + "/cloud-init*",
    _VAR_LOG + "/unattended-upgrades/*",
]


def _now():
    return time.time()


def _remove_if_old(path, max_age_seconds):
    try:
        age = _now() - os.path.getmtime(path)
        if age > max_age_seconds:
            os.remove(path)
            _LOGGER.info("disk_cleanup: removed %s (age %.0fh)", path, age / 3600)
            return True
    except OSError:
        pass
    return False


# ── /var/log ────────────────────────────────────────────────────────────────

def _clean_var_log(max_age_seconds):
    removed = 0
    for pattern in _VAR_LOG_PATTERNS:
        for path in glob.glob(pattern):
            if os.path.isfile(path) and _remove_if_old(path, max_age_seconds):
                removed += 1
    return removed


def _var_log_total_bytes():
    total = 0
    try:
        for entry in os.scandir(_VAR_LOG):
            if entry.is_file():
                total += entry.stat().st_size
    except OSError:
        pass
    return total


# ── Docker container logs ───────────────────────────────────────────────────

def _clean_docker_logs(max_age_seconds):
    removed = 0
    if not os.path.isdir(_DOCKER_LOG_DIR):
        return 0
    max_bytes = _DOCKER_LOG_MAX_MB * 1024 * 1024
    for container_dir in os.listdir(_DOCKER_LOG_DIR):
        log_file = os.path.join(_DOCKER_LOG_DIR, container_dir, container_dir + "-json.log")
        if not os.path.isfile(log_file):
            continue
        try:
            size = os.path.getsize(log_file)
            age = _now() - os.path.getmtime(log_file)
            if age > max_age_seconds or (max_bytes and size > max_bytes):
                with open(log_file, "w"):
                    pass
                reason = "age %.0fh" % (age / 3600) if age > max_age_seconds else "size %dMB" % (size // (1024 * 1024))
                _LOGGER.info("disk_cleanup: truncated %s (%s)", log_file, reason)
                removed += 1
        except OSError:
            continue
    return removed


# ── Docker system prune ─────────────────────────────────────────────────────

def _docker_prune():
    """Reclaim disk from dangling images, build cache, unused networks and
    dangling volumes.

    Deliberately NOT `docker system prune` / `docker container prune`: those
    remove *every* stopped container, and a managed server the user merely
    stopped (or one deployed but not yet started) is a stopped container.
    power("start") re-attaches to the existing container — _container() raises
    if it is gone and nothing recreates it — so pruning it bricks the server
    until a rebuild. Orphan containers are reaped by _clean_orphan_containers()
    (keyed by whether the data dir still exists), which spares a stopped-but-
    known server; this prune only touches the non-container resources.
    """
    if not _DOCKER_PRUNE:
        return
    for cmd in (
        ["docker", "image", "prune", "-f"],
        ["docker", "builder", "prune", "-f"],
        ["docker", "network", "prune", "-f"],
        ["docker", "volume", "prune", "-f"],
    ):
        label = " ".join(cmd[1:3])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and r.stdout.strip():
                _LOGGER.info("disk_cleanup: docker %s — %s", label, r.stdout.strip().splitlines()[-1])
        except FileNotFoundError:
            return
        except Exception:
            _LOGGER.exception("disk_cleanup: docker %s failed", label)


# ── journald ────────────────────────────────────────────────────────────────

def _journal_vacuum():
    """Vacuum journald logs to the same size cap."""
    if not _MAX_BYTES:
        return
    try:
        r = subprocess.run(
            ["journalctl", "--vacuum-size=%dM" % (_MAX_BYTES // (1024 * 1024),)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode == 0 and r.stdout.strip():
            _LOGGER.info("disk_cleanup: journalctl vacuum — %s", r.stdout.strip().splitlines()[-1])
    except FileNotFoundError:
        pass
    except Exception:
        _LOGGER.exception("disk_cleanup: journalctl vacuum failed")


# ── /tmp ────────────────────────────────────────────────────────────────────

def _clean_tmp(max_age_seconds):
    removed = 0
    if not os.path.isdir(_TMP):
        return 0
    for entry in os.scandir(_TMP):
        try:
            if entry.is_file(follow_symlinks=False):
                age = _now() - entry.stat(follow_symlinks=False).st_mtime
                if age > max_age_seconds:
                    os.remove(entry.path)
                    removed += 1
            elif entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                age = _now() - entry.stat(follow_symlinks=False).st_mtime
                if age > max_age_seconds:
                    import shutil
                    shutil.rmtree(entry.path, ignore_errors=True)
                    removed += 1
        except OSError:
            continue
    return removed


# ── orphan containers ────────────────────────────────────────────────────────

def _clean_orphan_containers():
    """Remove managed containers whose server data directory no longer exists,
    and any leftover install containers (they are transient by nature)."""
    if not _RECONCILE:
        return 0
    try:
        client = docker.from_env()
    except Exception:
        return 0
    data_root = Path(_DATA_ROOT)
    data_root_ok = data_root.is_dir()
    existing_dirs = {d.name for d in data_root.iterdir() if d.is_dir()} if data_root_ok else set()
    removed = 0
    for container in client.containers.list(all=True, filters={"label": "dchost.managed=true"}):
        labels = container.labels or {}
        # Install containers are transient — remove any that survived past startup.
        if labels.get("dchost.install"):
            try:
                container.remove(force=True)
                _LOGGER.info("disk_cleanup: removed leftover install container %s", container.short_id)
                removed += 1
            except Exception as exc:
                _LOGGER.warning("disk_cleanup: failed to remove install container %s: %s", container.short_id, exc)
            continue
        # A missing/unmounted data root makes existing_dirs empty, which would
        # mark every running server an orphan and wipe the whole node. That is
        # an infra fault, not a delete signal — skip dir-based reaping until the
        # root is back. (Same refusal principle as ServerManager.reconcile.)
        if not data_root_ok:
            continue
        server_id = labels.get("dchost.server_id", "")
        if server_id and server_id not in existing_dirs:
            try:
                container.remove(force=True)
                _LOGGER.info("disk_cleanup: removed orphan container %s (no dir in %s)", server_id, _DATA_ROOT)
                removed += 1
            except Exception as exc:
                _LOGGER.warning("disk_cleanup: failed to remove orphan %s: %s", server_id, exc)
    return removed


def _sweep():
    max_age_seconds = _MAX_AGE_HOURS * 3600

    var_removed = _clean_var_log(max_age_seconds)
    docker_removed = _clean_docker_logs(max_age_seconds)

    if _MAX_BYTES:
        while _var_log_total_bytes() > _MAX_BYTES:
            oldest = None
            oldest_age = 0
            for pattern in _VAR_LOG_PATTERNS:
                for path in glob.glob(pattern):
                    if not os.path.isfile(path):
                        continue
                    try:
                        age = _now() - os.path.getmtime(path)
                        if age > oldest_age:
                            oldest = path
                            oldest_age = age
                    except OSError:
                        continue
            if oldest is None:
                break
            if _remove_if_old(oldest, 0):
                var_removed += 1
            else:
                break

    tmp_removed = _clean_tmp(_TMP_MAX_AGE_H * 3600)
    _docker_prune()
    _journal_vacuum()
    orphan_removed = _clean_orphan_containers()

    return var_removed, docker_removed, tmp_removed, orphan_removed


def _loop():
    interval = max(60, _INTERVAL_MIN) * 60
    while True:
        time.sleep(interval)
        try:
            v, d, t, o = _sweep()
            parts = []
            if v:
                parts.append(f"{v} /var/log files")
            if d:
                parts.append(f"{d} docker logs truncated")
            if t:
                parts.append(f"{t} /tmp entries")
            if o:
                parts.append(f"{o} orphan containers")
            if parts:
                _LOGGER.info("disk_cleanup: %s", ", ".join(parts))
        except Exception:
            _LOGGER.exception("disk_cleanup: sweep failed")


def start():
    t = threading.Thread(target=_loop, name="disk-cleanup", daemon=True)
    t.start()
    _LOGGER.info(
        "disk_cleanup: started (log_age=%dh, tmp_age=%dh, interval=%dm, docker_prune=%s)",
        _MAX_AGE_HOURS, _TMP_MAX_AGE_H, _INTERVAL_MIN, _DOCKER_PRUNE,
    )

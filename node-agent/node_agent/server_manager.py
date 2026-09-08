import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .catalog import resolve_image
from .container_spec import CPU_PERCENT, MEMORY_BYTES, MEMORY_MB, NANO_CPUS, STORAGE_BYTES, STORAGE_MB, build_container_spec
from .docker_runtime import visible_line
from .install_scripts import install_script
from .storage import ServerStorage


_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_CONCURRENT_INSTALLS = 4

# Ceiling on the error text kept for the panel. Docker's own strings quote host
# paths, image digests and daemon internals, and this one is stored, returned by
# /install and shown to the server's owner.
MAX_STORED_ERROR_CHARS = 200


class ServerNotFoundError(LookupError):
    pass


class ServerConflictError(RuntimeError):
    pass


class InstallCapacityError(RuntimeError):
    """Every concurrent-install slot on this node is taken."""


def _max_concurrent_installs():
    """How many dependency installs may run at once.

    Each one starts a container with the same 300 MB limit as a real server, so
    without a ceiling the write rate limit alone allowed 60 of them a minute —
    about 18 GB. Read at call time, not import time, because run.py loads .env
    after importing the app.
    """
    try:
        value = int(os.environ.get("NODE_MAX_CONCURRENT_INSTALLS", "") or DEFAULT_MAX_CONCURRENT_INSTALLS)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_CONCURRENT_INSTALLS
    return max(1, min(64, value))


def _server_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("server id must be a UUID") from exc


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe_error(exc, fallback):
    """A short, safe message for the panel, with the real one logged locally.

    Only the exceptions the agent raises itself carry text an owner can act on
    (an unsupported runtime, a quota, a missing file). Everything else — Docker
    API errors above all — is replaced by `fallback` and logged in full here,
    the same trade the app's catch-all handler makes for HTTP responses.
    """
    if isinstance(exc, (ValueError, LookupError)):
        message = " ".join(str(exc).split())
        if message:
            return message[:MAX_STORED_ERROR_CHARS]
    _LOGGER.exception("node agent background operation failed (%s)", type(exc).__name__)
    return fallback


class ServerManager:
    def __init__(self, runtime, data_root):
        self.runtime = runtime
        self.data_root = Path(data_root).resolve()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self._installs = {}
        # Installs run on daemon threads while HTTP workers read the same state,
        # and waitress serves several requests at once: unsynchronised, two
        # concurrent reinstalls both passed the "already running" check and ran
        # two install containers over one bind mount.
        self._state_lock = threading.RLock()
        self._server_locks = {}
        self._max_concurrent_installs = _max_concurrent_installs()
        self._install_slots = threading.BoundedSemaphore(self._max_concurrent_installs)
        self._reconcile_interrupted_installs()
        self._drain_pending_deletions()

    def _reserve_install_slot(self):
        """Claim one concurrent-install slot, or refuse the request outright.

        Refusing rather than queueing is deliberate. The only place a queue
        could wait is the waitress worker holding the request, and NODE_THREADS
        of those blocked on installs starve every other route including
        /health — which is what the panel pings to decide whether this node is
        alive at all. A 503 the panel can show and the owner can retry is
        cheaper than a fleet-wide stall.
        """
        if not self._install_slots.acquire(blocking=False):
            raise InstallCapacityError(
                f"this node is already running {self._max_concurrent_installs} dependency "
                "installs — wait for one to finish and try again"
            )

    def _release_install_slot(self):
        try:
            self._install_slots.release()
        except ValueError:  # pragma: no cover - defensive
            pass

    def _server_lock(self, server_id):
        """Serialise power and rebuild operations for one server."""
        with self._state_lock:
            lock = self._server_locks.get(server_id)
            if lock is None:
                lock = threading.RLock()
                self._server_locks[server_id] = lock
            return lock

    def _install_state_path(self, server_id):
        return self.data_root / f"{server_id}.install.json"

    @staticmethod
    def _normalized_ids(ids):
        """Canonical UUIDs for the members of ``ids`` that are valid ones.

        reconcile compares present-container and known-server ids as the raw
        strings it was handed, but the install-state files are named by the
        canonical ``_server_id`` spelling. Comparing file ids against a
        normalized set keeps a legitimately-known server's file from being
        swept just because the database and the filename disagree on casing or
        hyphenation.
        """
        normalized = set()
        for value in ids:
            try:
                normalized.add(_server_id(value))
            except ValueError:
                continue
        return normalized

    def _reconcile_interrupted_installs(self):
        # Reap first: an install container outlives the process that started it,
        # because run_install removes it in a finally that a kill never reaches.
        # Marking the state "failed" below without removing the container leaves
        # the node believing nothing is installing while a container still holds
        # 300 MB and an open writer on the bind mount the next reinstall uses —
        # two processes writing one node_modules tree. Unconditional at startup is
        # safe: one agent runs per node and waitress serves from a single process,
        # so no install of ours can be in flight this early.
        reap = getattr(self.runtime, "remove_install_containers", None)
        if reap is not None:
            try:
                reaped = reap()
            except Exception:
                _LOGGER.exception("node agent could not reap interrupted install containers")
            else:
                if reaped:
                    _LOGGER.warning(
                        "node agent removed %s install container(s) left by an interrupted run",
                        reaped,
                    )
        for state_file in self.data_root.glob("*.install.json"):
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(state, dict):
                continue
            server_id = None
            for candidate in (state.get("id"), state_file.stem.removesuffix(".install")):
                try:
                    server_id = _server_id(candidate)
                except ValueError:
                    continue
                break
            if server_id is None:
                # Every other reader keys this table on the normalized id, so an
                # entry stored under any other spelling is invisible to them: the
                # server reports "idle" while carrying an install that never
                # finished, and power("start") stops refusing it. State files
                # written before ids were normalized hold whatever spelling the
                # caller sent, and an id that is not a string at all raised
                # TypeError on the assignment below — reached from __init__, so
                # the agent would not start at all.
                _LOGGER.warning(
                    "node agent ignoring install state file with no usable server id: %s",
                    state_file.name,
                )
                continue
            if state.get("status") == "running":
                state["status"] = "failed"
                state["error"] = "installation was interrupted by a node restart — reinstall the server"
                self._save_install_state(server_id, state)
            self._installs[server_id] = state

    def _drain_pending_deletions(self):
        # app1 queues a HeatWave tombstone for a container it could not confirm
        # deleted while this node was offline. Deletion from that queue is
        # MANUAL: an admin confirms it in the admin panel, and app1's reconcile
        # sweep is told to skip tombstoned ids — so nothing removes the
        # container automatically. This boot drain is therefore OFF by default;
        # set DRAIN_HEATWAVE_PENDING=1 to restore the old behavior of removing
        # queued containers at startup (useful only when the admin panel cannot
        # reach this node but HeatWave can). Best-effort either way — no
        # HeatWave configured, no driver installed, or an unreachable endpoint
        # all degrade to a no-op.
        enabled = (os.environ.get("DRAIN_HEATWAVE_PENDING") or "").strip().lower()
        if enabled not in ("1", "true", "yes", "on"):
            return
        try:
            from . import heatwave_deletions
            heatwave_deletions.drain(self)
        except Exception:
            _LOGGER.exception("node agent pending-deletion drain failed")

    def _save_install_state(self, server_id, state):
        state_path = self._install_state_path(server_id)
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({**state, "id": server_id}, indent=2), encoding="utf-8")
        temporary.replace(state_path)

    def _install_state(self, server_id):
        with self._state_lock:
            state = self._installs.get(server_id)
            return dict(state) if state else {"status": "idle"}

    def _set_install_state(self, server_id, state):
        with self._state_lock:
            self._installs[server_id] = dict(state)
            self._save_install_state(server_id, state)

    def _forget_install_state(self, server_id):
        """Drop install state for a deleted server.

        Left behind, the record kept the dict growing for the lifetime of the
        process and a server recreated under the same id inherited the old
        server's "failed" status, which then refused to start it.
        """
        with self._state_lock:
            self._installs.pop(server_id, None)
        try:
            self._install_state_path(server_id).unlink()
        except OSError:
            pass

    def storage(self, server_id, *, create=False):
        """Storage for a server that already exists.

        ServerStorage used to create its own root, so every file route made a
        directory for whatever UUID it was handed — which let a caller seed
        files into an id before the server was created. create_server then bind
        mounts the directory it finds, and _seed_files skips its own seeding
        because the directory is not empty. Only create_server passes create.

        Existence is judged by the data directory rather than by asking Docker:
        create_server is the only thing that brings the directory into being, a
        stat is far cheaper than an API call on a route the panel polls, and it
        keeps file listings working when the daemon itself is slow.
        """
        root = self.data_root / _server_id(server_id)
        if not create and not root.is_dir():
            raise ServerNotFoundError("server does not exist on this node")
        return ServerStorage(root, create=create)

    def _container(self, server_id):
        normalized_id = _server_id(server_id)
        container = self.runtime.get(normalized_id)
        if container is None:
            raise ServerNotFoundError("server container does not exist")
        if hasattr(container, "reload"):
            container.reload()
        return container

    @staticmethod
    def _container_labels(container):
        labels = getattr(container, "labels", None)
        if not isinstance(labels, dict):
            labels = getattr(container, "spec", {}).get("labels", {})
        return labels or {}

    @staticmethod
    def _container_image(container):
        image = getattr(container, "image", None)
        if image is None:
            image = getattr(container, "spec", {}).get("image")
        if image is None or isinstance(image, str):
            return image
        # docker-py hands back an Image object here, but a spec needs a name the
        # daemon can resolve: passing the object through made every rebuild
        # (update_startup, update_version) fail inside images.get().
        tags = getattr(image, "tags", None) or []
        if tags:
            return tags[0]
        return getattr(image, "id", None) or str(image)

    def _seed_files(self, storage, runtime):
        if storage.list_directory(""):
            return
        if runtime == "nodejs":
            storage.write_text(
                "package.json",
                json.dumps(
                    {
                        "name": "discord-bot",
                        "private": True,
                        "version": "1.0.0",
                        "dependencies": {},
                        "scripts": {"start": "node index.js"},
                    },
                    indent=2,
                )
                + "\n",
            )
            storage.write_text(
                "index.js",
                "console.log('Bot is online!');\n"
                "\n"
                "process.on('SIGINT', () => {\n"
                "    console.log('Shutting down...');\n"
                "    process.exit(0);\n"
                "});\n"
                "\n"
                "setInterval(() => {}, 60_000);\n",
            )
        elif runtime == "python":
            storage.write_text(
                "main.py",
                "import time\n"
                "import signal\n"
                "import sys\n"
                "\n"
                "print('Bot is online!', flush=True)\n"
                "\n"
                "def shutdown(sig, frame):\n"
                "    print('Shutting down...', flush=True)\n"
                "    sys.exit(0)\n"
                "\n"
                "signal.signal(signal.SIGINT, shutdown)\n"
                "signal.signal(signal.SIGTERM, shutdown)\n"
                "\n"
                "while True:\n"
                "    time.sleep(60)\n",
            )
            storage.write_text(
                "requirements.txt",
                "# Add your dependencies here, for example:\n"
                "# discord.py>=2.0\n"
                "# requests>=2.28\n",
            )
        elif runtime == "ruby":
            storage.write_text(
                "main.rb",
                "puts 'Bot is online!'\n"
                "$stdout.flush\n"
                "\n"
                "trap('INT') { puts 'Shutting down...'; exit 0 }\n"
                "trap('TERM') { puts 'Shutting down...'; exit 0 }\n"
                "\n"
                "loop { sleep 60 }\n",
            )
            storage.write_text(
                "Gemfile",
                "source 'https://rubygems.org'\n"
                "\n"
                "# Add your gems here, for example:\n"
                "# gem 'discordrb'\n",
            )
        elif runtime == "go":
            storage.write_text(
                "go.mod",
                "module discord-bot\n"
                "\n"
                "go 1.23\n",
            )
            storage.write_text(
                "main.go",
                "package main\n"
                "\n"
                "import (\n"
                "\t\"fmt\"\n"
                "\t\"os\"\n"
                "\t\"os/signal\"\n"
                "\t\"syscall\"\n"
                ")\n"
                "\n"
                "func main() {\n"
                "\tfmt.Println(\"Bot is online!\")\n"
                "\tsig := make(chan os.Signal, 1)\n"
                "\tsignal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)\n"
                "\t<-sig\n"
                "\tfmt.Println(\"Shutting down...\")\n"
                "}\n",
            )
        elif runtime == "php":
            storage.write_text(
                "main.php",
                "<?php\n"
                "echo \"Bot is online!\\n\";\n"
                "\n"
                "pcntl_async_signals(true);\n"
                "pcntl_signal(SIGINT, function () { echo \"Shutting down...\\n\"; exit(0); });\n"
                "pcntl_signal(SIGTERM, function () { echo \"Shutting down...\\n\"; exit(0); });\n"
                "\n"
                "while (true) { sleep(60); }\n",
            )
        elif runtime == "bun":
            storage.write_text(
                "package.json",
                json.dumps(
                    {
                        "name": "discord-bot",
                        "private": True,
                        "version": "1.0.0",
                        "module": "index.ts",
                        "type": "module",
                        "dependencies": {},
                        "scripts": {"start": "bun run index.ts"},
                    },
                    indent=2,
                )
                + "\n",
            )
            storage.write_text(
                "index.ts",
                "console.log('Bot is online!');\n"
                "\n"
                "process.on('SIGINT', () => {\n"
                "    console.log('Shutting down...');\n"
                "    process.exit(0);\n"
                "});\n"
                "\n"
                "setInterval(() => {}, 60_000);\n",
            )

    def create_server(self, payload):
        server_id = _server_id(payload.get("id"))
        if self.runtime.get(server_id) is not None:
            raise ServerConflictError("server container already exists")
        existing_root = self.data_root / server_id
        if existing_root.is_dir() and any(existing_root.iterdir()):
            raise ServerConflictError("this server id already has a data directory on this node")
        name = str(payload.get("name") or "").strip()
        runtime = str(payload.get("runtime") or "").strip().lower()
        version = str(payload.get("version") or "").strip()
        startup = str(payload.get("startup") or "").strip()
        if not name or len(name) > 80:
            raise ValueError("server name must be between 1 and 80 characters")
        image = resolve_image(runtime, version)
        # Claim the install slot before anything exists on disk or in Docker, so
        # a busy node answers "try again" without leaving a container behind
        # that never got its dependencies.
        self._reserve_install_slot()
        container = None
        seeded_root = False
        try:
            storage = self.storage(server_id, create=True)
            seeded_root = True
            self._seed_files(storage, runtime)
            storage.ensure_owner()
            spec = build_container_spec(
                server_id=server_id,
                name=name,
                image=image,
                startup=startup,
                data_directory=storage.root,
                runtime=runtime,
                version=version,
            )
            container = self.runtime.create(spec)
            self.start_install(server_id, runtime, image, slot_reserved=True)
        except BaseException:
            # Roll back anything already created so a failed create (pull error,
            # install failure) leaves nothing behind. Otherwise the orphaned
            # container/data dir trip the conflict guards above and block every
            # retry until reconcile eventually reaps them. Best-effort and in
            # reverse order; never mask the original failure.
            if container is not None:
                try:
                    self.runtime.remove(container, force=True)
                except Exception:
                    _LOGGER.warning("create_server rollback: could not remove container for %s", server_id)
            if seeded_root:
                try:
                    root = self.data_root / server_id
                    if root.is_dir():
                        self.storage(server_id).remove_root()
                except Exception:
                    _LOGGER.warning("create_server rollback: could not remove data dir for %s", server_id)
            self._release_install_slot()
            raise
        return {
            "id": server_id,
            "container_id": container.id,
            "name": name,
            "runtime": runtime,
            "version": version,
            "image": image,
            "startup": startup,
            "status": getattr(container, "status", "created"),
            "install_status": "running",
            "memory_mb": MEMORY_MB,
            "cpu_percent": CPU_PERCENT,
            "storage_mb": STORAGE_MB,
        }

    def start_install(self, server_id, runtime, image, slot_reserved=False):
        normalized_id = _server_id(server_id)
        state = {
            "status": "running",
            "image": image,
            "script": install_script(runtime),
            "started_at": _utc_now(),
            "log": "",
            "error": "",
        }
        with self._server_lock(normalized_id):
            # Re-check under the lock. reinstall() checks too, but between its
            # check and this call a second request could slip in and start a
            # rival install container over the same bind mount.
            if self._install_state(normalized_id).get("status") == "running":
                raise ValueError("installation is already in progress")
            if not slot_reserved:
                self._reserve_install_slot()
            try:
                self._set_install_state(normalized_id, state)
                thread = threading.Thread(
                    target=self._run_install,
                    args=(normalized_id, image, state["script"]),
                    daemon=True,
                )
                thread.start()
            except BaseException:
                # Nothing is going to run _run_install, so nothing would move
                # this off "running" or hand the slot back — the server would
                # report an install that is not happening, for ever.
                if not slot_reserved:
                    self._release_install_slot()
                self._set_install_state(
                    normalized_id,
                    {
                        **state,
                        "status": "failed",
                        "error": "the node could not start the installation — reinstall the server",
                        "finished_at": _utc_now(),
                    },
                )
                raise

    def _run_install(self, server_id, image, script):
        state = self._install_state(server_id)
        try:
            storage = self.storage(server_id)
            # The install container runs as the non-root container user, so the
            # seeded files have to be handed over before npm or pip writes here.
            storage.ensure_owner()
            from .container_spec import _no_cache_env, _no_log_env, _load_user_env
            exit_code, output = self.runtime.run_install(
                image=image,
                command=script,
                volumes={str(storage.root): {"bind": "/home/container", "mode": "rw"}},
                environment={"HOME": "/home/container", "TERM": "xterm-256color",
                             **_load_user_env(storage.root),
                             **_no_log_env(), **_no_cache_env()},
                mem_limit=MEMORY_BYTES,
                nano_cpus=NANO_CPUS,
            )
            output = (output or "").strip()
            state["log"] = output[-20000:]
            state["finished_at"] = _utc_now()
            if exit_code == 0:
                state["status"] = "success"
                state["error"] = ""
            else:
                state["status"] = "failed"
                last_line = output.splitlines()[-1] if output else ""
                # A summary for the panel only; state["log"] still carries the
                # whole build output, which is what the install view renders.
                state["error"] = (
                    last_line[:MAX_STORED_ERROR_CHARS]
                    or f"installation exited with code {exit_code}"
                )
        except Exception as exc:  # pragma: no cover - defensive
            state["status"] = "failed"
            state["error"] = _safe_error(exc, "installation failed on this node")
            state["finished_at"] = _utc_now()
        finally:
            # The install container is gone either way by here, so give the slot
            # back before writing the final state.
            self._release_install_slot()
        self._set_install_state(server_id, state)

    def reinstall(self, server_id):
        normalized_id = _server_id(server_id)
        with self._server_lock(normalized_id):
            container = self._container(normalized_id)
            if getattr(container, "status", "") == "running":
                raise ValueError("stop the server before reinstalling it")
            current = self._install_state(normalized_id)
            if current.get("status") == "running":
                raise ValueError("installation is already in progress")
            labels = self._container_labels(container)
            image = self._container_image(container)
            self.start_install(normalized_id, labels.get("dchost.runtime", "nodejs"), image)
            return {"ok": True, "install_status": "running"}

    def install_report(self, server_id):
        """Install status without the container inspect and disk walk state() does.

        The panel polls this every second or two while a build runs, and state()
        pays for a docker inspect plus a full walk of the server directory on
        every call — neither of which the install view uses.
        """
        normalized_id = _server_id(server_id)
        state = self._install_state(normalized_id)
        return {
            "status": state.get("status", "idle"),
            "error": state.get("error", ""),
            "log": state.get("log", ""),
        }

    def update_startup(self, server_id, startup):
        startup = str(startup or "").strip()
        if not startup or len(startup) > 500:
            raise ValueError("startup command must be between 1 and 500 characters")
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        labels = self._container_labels(container)
        if labels.get("dchost.startup") == startup and getattr(container, "status", "") == "running":
            return {
                "ok": True,
                "id": normalized_id,
                "startup": startup,
                "status": getattr(container, "status", "running"),
            }
        new_container = self._rebuild(
            normalized_id,
            image=self._container_image(container),
            name=labels.get("dchost.display_name", "Discord bot"),
            startup=startup,
            runtime=labels.get("dchost.runtime", "nodejs"),
            version=labels.get("dchost.version", ""),
            start=getattr(container, "status", "") == "running",
        )
        return {
            "ok": True,
            "id": normalized_id,
            "startup": startup,
            "status": getattr(new_container, "status", "running"),
        }

    def update_version(self, server_id, runtime, version):
        runtime = str(runtime or "").strip().lower()
        version = str(version or "").strip()
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        labels = self._container_labels(container)
        image = resolve_image(runtime, version)
        was_running = getattr(container, "status", "") == "running"
        if (
            was_running
            and labels.get("dchost.runtime") == runtime
            and labels.get("dchost.version") == version
            and self._container_image(container) == image
        ):
            return {
                "ok": True,
                "id": normalized_id,
                "runtime": runtime,
                "version": version,
                "image": image,
                "status": getattr(container, "status", "running"),
            }
        startup = str(labels.get("dchost.startup") or "").strip()
        if not startup:
            raise ValueError(
                "this server's container has no startup command recorded — "
                "set the startup command before changing the runtime version"
            )
        new_container = self._rebuild(
            normalized_id,
            image=image,
            name=labels.get("dchost.display_name", "Discord bot"),
            startup=startup,
            runtime=runtime,
            version=version,
            start=was_running,
        )
        return {
            "ok": True,
            "id": normalized_id,
            "runtime": runtime,
            "version": version,
            "image": image,
            "status": getattr(new_container, "status", "running"),
        }

    def _rebuild(self, server_id, image, name, startup, runtime="nodejs", version="", start=False):
        spec = build_container_spec(
            server_id=server_id,
            name=name,
            image=image,
            startup=startup,
            data_directory=self.data_root / server_id,
            runtime=runtime,
            version=version,
        )
        with self._server_lock(server_id):
            container = self._container(server_id)
            previous_labels = self._container_labels(container)
            previous_image = self._container_image(container)
            if getattr(container, "status", "") == "running":
                container.stop(timeout=10)
            self.runtime.remove(container, force=True)
            try:
                new_container = self.runtime.create(spec)
            except Exception:
                # The old container is already gone at this point. Put an
                # equivalent one back from the labels captured above, so an
                # unpullable image or a daemon hiccup cannot leave the owner
                # with no container at all.
                self._restore_container(server_id, previous_labels, previous_image, start)
                raise
            if start:
                new_container.start()
            return new_container

    def _restore_container(self, server_id, labels, image, start):
        try:
            rollback = build_container_spec(
                server_id=server_id,
                name=labels.get("dchost.display_name", "Discord bot"),
                image=image,
                startup=(labels.get("dchost.startup") or "").strip() or "sleep infinity",
                data_directory=self.data_root / server_id,
                runtime=labels.get("dchost.runtime", "nodejs"),
                version=labels.get("dchost.version", ""),
            )
            restored = self.runtime.create(rollback)
            if start:
                restored.start()
        except Exception:  # pragma: no cover - defensive
            # Both the rebuild and the rollback failed, so this server now has no
            # container at all. The caller re-raises the original rebuild error,
            # which says nothing about the rollback, so record the fact where the
            # panel can still read it: install_report needs no container to
            # answer, unlike state(). The traceback stays server-side.
            _LOGGER.exception("node agent could not restore the container for server %s", server_id)
            try:
                self._set_install_state(
                    server_id,
                    {
                        **self._install_state(server_id),
                        "status": "failed",
                        "error": (
                            "the node removed this server's old container and could not build a "
                            "replacement — delete the server and create it again"
                        ),
                        "finished_at": _utc_now(),
                    },
                )
            except Exception:
                _LOGGER.exception("node agent could not record the failed rollback for server %s", server_id)

    def state(self, server_id):
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        storage = self.storage(normalized_id)
        disk_used = storage.usage_bytes()
        # Keyed by the canonical id, which is what start_install writes. uuid.UUID
        # accepts several spellings of one id — uppercase, no hyphens, braces, a
        # urn:uuid: prefix — so looking the state up under the caller's spelling
        # missed it and returned the "idle" default while a build was still
        # running, which is what the panel reads to decide a server is ready.
        install = self._install_state(normalized_id)
        result = {
            "id": normalized_id,
            "container_id": container.id,
            "status": getattr(container, "status", "unknown"),
            "install_status": install.get("status", "idle"),
            "install_error": install.get("error", ""),
            "started_at": getattr(container, "attrs", {}).get("State", {}).get("StartedAt", ""),
            "disk_used_bytes": disk_used,
            "disk_total_bytes": STORAGE_BYTES,
            "disk_free_bytes": max(0, STORAGE_BYTES - disk_used),
        }
        if result["status"] == "running":
            result.update(self.runtime.stats(container))
        return result

    def install_log(self, server_id):
        return self._install_state(_server_id(server_id)).get("log", "")

    def list_servers(self):
        entries = self.runtime.list()
        for entry in entries:
            entry["install_status"] = self._install_state(entry["id"]).get("status", "idle")
        return entries

    def _validate_startable(self, server_id, container):
        labels = self._container_labels(container)
        startup = (labels.get("dchost.startup") or "").strip().lower()
        if startup.split() and startup.split()[0] == "npm":
            names = {entry["name"] for entry in self.storage(server_id).list_directory("")}
            if "package.json" not in names:
                raise ValueError(
                    "startup uses npm, but package.json is missing from /home/container — upload your bot files first"
                )

    def power(self, server_id, action):
        action = str(action or "").strip().lower()
        if action not in {"start", "stop", "restart", "kill"}:
            raise ValueError("unsupported power action")
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        # Without this lock a double-clicked Start (or a Start racing a Restart)
        # sent both actions to the daemon against the status each had read
        # before the other landed.
        with self._server_lock(normalized_id):
            if hasattr(container, "reload"):
                container.reload()
            if action == "start":
                install = self._install_state(normalized_id)
                if install.get("status") == "running":
                    raise ValueError("server is still installing — wait for installation to finish before starting")
                if install.get("status") == "failed":
                    raise ValueError(
                        f"installation failed: {install.get('error') or 'unknown error'} — fix the files and reinstall"
                    )
                self._validate_startable(normalized_id, container)
                container.start()
            elif action == "stop":
                container.stop(timeout=10)
            elif action == "restart":
                container.restart(timeout=10)
            else:
                container.kill()
            if hasattr(container, "reload"):
                container.reload()
            status = getattr(container, "status", None) or (
                "running" if action in {"start", "restart"} else "stopped"
            )
            return {"ok": True, "status": status}

    def logs(self, server_id, tail=200):
        container = self._container(server_id)
        tail = max(1, min(int(tail), 1000))
        output = self.runtime.logs(container, tail=tail)
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        # The console's initial backfill, and it goes into the same <pre> the
        # follow stream feeds — so it needs the same treatment for the carriage
        # returns a tty container's output carries, or the first screenful is
        # double-spaced and every progress bar arrives as all of its frames at
        # once, while everything after it (from the stream) is clean.
        output = "\n".join(visible_line(line) for line in output.split("\n"))
        return {"ok": True, "logs": output}

    def stats(self, server_id):
        container = self._container(server_id)
        result = dict(self.runtime.stats(container))
        result.update({"ok": True, "status": getattr(container, "status", "unknown")})
        return result

    def run_command(self, server_id, command):
        command = str(command or "").strip()
        if not command or len(command) > 500:
            raise ValueError("command must be between 1 and 500 characters")
        if "\x00" in command:
            raise ValueError("command must not contain null bytes")
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        # Docker exec only attaches to a running container, and a freshly created
        # server is left stopped until the owner starts it. Without this guard the
        # SDK raises a 409 APIError, which lands on the app's catch-all handler and
        # reaches the console as an opaque "node operation failed".
        status = getattr(container, "status", "unknown")
        if status != "running":
            if self._install_state(normalized_id).get("status") == "running":
                raise ValueError(
                    "server is still installing — wait for installation to finish before running commands"
                )
            raise ValueError(
                f"console commands run inside a running container — start the server first (status: {status})"
            )
        return self.runtime.run_command(container, command)

    def send_stdin(self, server_id, command):
        command = str(command or "").strip()
        if not command or len(command) > 500:
            raise ValueError("command must be between 1 and 500 characters")
        if "\x00" in command:
            raise ValueError("command must not contain null bytes")
        normalized_id = _server_id(server_id)
        container = self._container(normalized_id)
        status = getattr(container, "status", "unknown")
        if status != "running":
            if self._install_state(normalized_id).get("status") == "running":
                raise ValueError(
                    "server is still installing — wait for installation to finish before running commands"
                )
            raise ValueError(
                f"console commands go to a running server — start it first (status: {status})"
            )
        return self.runtime.send_stdin(container, command)

    def remove(self, server_id, purge=False):
        normalized_id = _server_id(server_id)
        with self._server_lock(normalized_id):
            container = self._container(normalized_id)
            if getattr(container, "status", "") in {"running", "restarting", "paused"}:
                container.stop(timeout=10)
            self.runtime.remove(container, force=bool(purge))
            if purge:
                # A purge whose data directory is already gone still has a
                # container to delete, so it must not 404 on the storage lookup.
                root = self.data_root / normalized_id
                if root.is_dir():
                    self.storage(normalized_id).remove_root()
            self._forget_install_state(normalized_id)
            try:
                self.runtime.prune_images()
            except Exception:
                pass
            return {"ok": True, "purged": bool(purge)}

    def reconcile(self, known_ids, *, purge=True, max_delete=None, protect_ids=None):
        """Remove managed containers whose server id is not in ``known_ids``.

        Also reaps two container-less leftovers whose id the database no longer
        knows: orphan ``*.install.json`` state files, and (when ``purge``) orphan
        data directories — a server's dir left behind after its container was
        already gone, which no other cleanup path reaches.

        ``known_ids`` is the authoritative set of live server ids from the
        control-plane database. A managed container the database no longer
        knows about is an orphan: its row was deleted while this node was
        unreachable, so the push-based DELETE never landed and the container
        outlived its record.

        ``protect_ids`` are the exception to that rule: ids the control plane
        has already logically deleted but whose physical removal is deferred to
        an admin (the HeatWave pending-deletion queue). They are skipped here —
        container, data dir and install state alike — so the only path that
        removes them is the admin panel's explicit delete. The guards below
        stay keyed on ``known_ids`` alone, so a protect list can never stand in
        for a real allowlist.

        The node cannot tell a legitimately-empty database from a failed read,
        so two guards stop a bad allowlist from wiping every container: an empty
        ``known_ids`` while containers are present is refused outright, and an
        orphan count above ``max_delete`` (when set) is refused. The caller is
        expected to pass a set it trusts and a cap sized to the fleet.
        """
        known = {str(i).strip() for i in (known_ids or []) if str(i).strip()}
        protected = {str(i).strip() for i in (protect_ids or []) if str(i).strip()}
        present = [str(e.get("id") or "").strip() for e in self.runtime.list()]
        present = [i for i in present if i]
        orphans = [i for i in present if i not in known and i not in protected]

        # Install-state files whose server is neither in the database nor backed
        # by a container here. A container orphan's file is removed by remove()
        # below; this catches the ones with no container left to route through
        # it — a file left by an interrupted delete, or by the ServerNotFound
        # branch — which the container-only orphan logic never sees.
        known_normalized = self._normalized_ids(known)
        present_normalized = self._normalized_ids(present)
        protected_normalized = self._normalized_ids(protected)
        orphan_state_files = []
        for state_file in self.data_root.glob("*.install.json"):
            try:
                sid = _server_id(state_file.stem.removesuffix(".install"))
            except ValueError:
                continue
            if (sid in known_normalized or sid in present_normalized
                    or sid in protected_normalized):
                continue
            orphan_state_files.append(sid)

        # Orphan data directories: a server dir on disk whose id the database no
        # longer knows and that has no container here. reconcile keys off
        # containers (runtime.list) and disk_cleanup's orphan sweep keys off "dir
        # gone" — so a dir whose container was already removed (a crash, a manual
        # docker rm, an earlier prune) is seen by neither and lingers forever.
        # Reap it here, under the same trusted allowlist, and under the same
        # protect exception: a deferred delete's dir is the data an admin has
        # not yet confirmed losing. Only while purging: the dir is the data.
        # Ids backed by a container are excluded — those are the container
        # orphans the loop below already purges the dir for.
        orphan_dirs = []
        if purge and self.data_root.is_dir():
            for entry in self.data_root.iterdir():
                if not entry.is_dir():
                    continue
                try:
                    sid = _server_id(entry.name)
                except ValueError:
                    continue
                if (sid in known_normalized or sid in present_normalized
                        or sid in protected_normalized):
                    continue
                orphan_dirs.append(sid)

        result = {"ok": True, "checked": len(present), "orphans": orphans,
                  "removed": [], "refused": None}
        if protected:
            result["protected"] = sorted(protected)
        if not orphans and not orphan_state_files and not orphan_dirs:
            return result
        # An empty allowlist while managed containers or their data dirs are
        # present is refused outright. It is far likelier a failed control-plane
        # read — or a fresh backup database promoted after the primary went down
        # (an operator failover), which has not yet been told about the servers
        # still running here — than a real "delete every server on this node".
        # A genuine wipe still goes one server at a time through remove(); this
        # node never deletes its whole fleet on a blanket empty push. This is the
        # guard that makes a dead/swapped control-plane DB non-destructive.
        if not known and (orphans or orphan_dirs):
            result["ok"] = False
            result["refused"] = (
                f"empty allowlist with {len(orphans)} container(s) and "
                f"{len(orphan_dirs)} data dir(s) present — refusing to purge"
            )
            _LOGGER.warning(
                "reconcile refused: empty allowlist with %d container(s), %d data dir(s) present",
                len(orphans), len(orphan_dirs),
            )
            return result
        # max_delete caps how many deletions one pass may do — a blast-radius
        # limit against a bad control-plane read. It is NOT all-or-nothing: we
        # delete up to the cap this pass (containers first, leftover budget to
        # dirs) and leave the rest for the next pass, so a large legitimate
        # backlog (e.g. a user who deleted 30 servers while the node was down)
        # drains across passes instead of stalling forever above the cap.
        deletions = len(orphans) + len(orphan_dirs)
        if max_delete is not None and deletions > max_delete:
            result["capped"] = f"orphan count {deletions} exceeds max_delete {max_delete}; deleting {max_delete} this pass"
            _LOGGER.warning(
                "reconcile capped: %d orphans exceed max_delete %s; deleting %d this pass, rest next pass",
                deletions, max_delete, max_delete,
            )
            orphans = orphans[:max_delete]
            budget_left = max_delete - len(orphans)
            orphan_dirs = orphan_dirs[:budget_left]
        removed = []
        for sid in orphans:
            try:
                self.remove(sid, purge=purge)
                removed.append(sid)
                _LOGGER.info("reconcile removed orphan container %s", sid)
            except ServerNotFoundError:
                # Vanished between the list and the remove — already gone, which
                # is the state reconcile was driving toward, so count it done.
                # remove() never reached _forget_install_state, so drop the
                # state file here or it lingers under a now-container-less id.
                try:
                    self._forget_install_state(_server_id(sid))
                except ValueError:
                    pass
                removed.append(sid)
            except Exception as exc:
                _LOGGER.warning("reconcile failed to remove %s: %s: %s", sid, type(exc).__name__, exc)
        result["removed"] = removed

        # Reap the container-less orphan state files found above. remove() has
        # already dropped the files of any container orphan it deleted, so these
        # are only the ones that had no container to begin with.
        swept = 0
        for sid in orphan_state_files:
            self._forget_install_state(sid)
            swept += 1
        if swept:
            result["install_state_files_removed"] = swept

        # Also remove any leftover install containers — they are transient and
        # have no dchost.server_id, so the orphan logic above never sees them.
        try:
            reaped = self.runtime.remove_install_containers()
            if reaped:
                result["install_containers_removed"] = reaped
        except Exception:
            pass

        # Reap the orphan data directories found above. There is no container to
        # route through remove(), so drop the tree via the same storage path a
        # purge uses. A sibling *.install.json, if any, is a separate file the
        # state-file sweep above already removed.
        dirs_removed = []
        for sid in orphan_dirs:
            try:
                root = self.data_root / sid
                if root.is_dir():
                    self.storage(sid).remove_root()
                dirs_removed.append(sid)
                _LOGGER.info("reconcile removed orphan data dir %s (no container, not in database)", sid)
            except Exception as exc:
                _LOGGER.warning("reconcile failed to remove orphan dir %s: %s: %s",
                                sid, type(exc).__name__, exc)
        if dirs_removed:
            result["data_dirs_removed"] = dirs_removed

        return result

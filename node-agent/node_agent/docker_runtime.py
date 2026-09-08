import codecs
import os


DEFAULT_DOCKER_TIMEOUT_SECONDS = 120

# Longest run of output the follow stream will hold waiting for a newline before
# releasing it as a line of its own. A container that writes megabytes without
# ever ending a line must not grow this buffer without bound, and an interactive
# prompt should still reach the console eventually.
MAX_LOG_LINE_CHARS = 8192


def visible_line(line):
    """The text a terminal would leave on screen for one log line.

    Managed containers run with a tty, so their log stream carries CRLF endings
    and the carriage returns a progress bar uses to redraw its own line. Kept
    verbatim, that CR reaches the panel's <pre> as a second line break — a blank
    line between every log line — and an npm or pip progress bar arrives as every
    frame it ever drew, concatenated into one enormous line. Only the text after
    the last CR survives, which is what the terminal would be showing.
    """
    if "\r" not in line:
        return line
    line = line.rstrip("\r")
    return line.rsplit("\r", 1)[-1]


def _docker_timeout_seconds():
    """Deadline for every Docker API call this client makes.

    Without one, an image pull or a stats sample against a slow registry or a
    wedged daemon pins its waitress worker indefinitely, and NODE_THREADS of
    those starve the whole agent — including /health, which is what the panel
    pings to decide whether this node is alive at all. Read here rather than at
    import time because run.py loads .env after importing the app.
    """
    try:
        value = int(os.environ.get("NODE_DOCKER_TIMEOUT", "") or DEFAULT_DOCKER_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        value = DEFAULT_DOCKER_TIMEOUT_SECONDS
    return max(10, value)


class DockerRuntime:
    def __init__(self, client=None):
        if client is None:
            try:
                import docker
            except ImportError as exc:
                raise RuntimeError("install the docker Python package") from exc
            client = docker.from_env(timeout=_docker_timeout_seconds())
        self.client = client
        self.client.ping()

    def daemon_info(self):
        """(reachable, version) for the daemon behind this runtime.

        Never raises. /api/v1/config reports this, and an agent whose daemon has
        gone away still has to be able to answer what it is configured to do —
        that answer is the most useful one there is at exactly that moment.
        """
        try:
            return True, str((self.client.version() or {}).get("Version") or "")
        except Exception:
            return False, ""

    def create(self, spec):
        image = spec["image"]
        try:
            self.client.images.get(image)
        except Exception:
            try:
                self.client.images.pull(image)
            except Exception as exc:
                raise ValueError("this node could not pull the runtime image") from exc
        try:
            if "log_config" in spec:
                try:
                    return self.client.containers.create(**spec)
                except Exception:
                    # Retry without the log driver, but against a copy. The caller
                    # keeps this spec to rebuild the container later, and deleting
                    # the key in place dropped the setting from every later create.
                    retry = {key: value for key, value in spec.items() if key != "log_config"}
                    return self.client.containers.create(**retry)
            return self.client.containers.create(**spec)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("this node could not create the container") from exc

    def get(self, server_id):
        try:
            matches = self.client.containers.list(
                all=True,
                filters={"label": f"dchost.server_id={server_id}"},
            )
        except Exception as exc:
            raise ValueError("this node could not talk to its Docker daemon") from exc
        return matches[0] if matches else None

    def list(self):
        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": "dchost.managed=true"},
            )
        except Exception as exc:
            raise ValueError("this node could not talk to its Docker daemon") from exc
        servers = []
        for container in containers:
            labels = container.labels or {}
            servers.append(
                {
                    "id": labels.get("dchost.server_id", ""),
                    "name": labels.get("dchost.display_name", ""),
                    "status": getattr(container, "status", "unknown"),
                    "runtime": labels.get("dchost.runtime", ""),
                    "version": labels.get("dchost.version", ""),
                    "memory_mb": labels.get("dchost.memory_mb"),
                    "cpu_percent": labels.get("dchost.cpu_percent"),
                    "desired_state": labels.get("dchost.desired_state", ""),
                    "created_at": (getattr(container, "attrs", None) or {}).get("Created", ""),
                }
            )
        return [server for server in servers if server["id"]]

    def remove(self, container, force=False):
        try:
            container.remove(force=force, v=True)
        except Exception as exc:
            message = str(exc).lower()
            if "no such" in message or "not found" in message:
                return
            raise ValueError("this node could not remove the container") from exc

    def logs(self, container, tail=200):
        try:
            return container.logs(stdout=True, stderr=True, tail=tail, timestamps=True)
        except Exception as exc:
            message = str(exc).lower()
            if "logging driver" in message or "does not support reading" in message:
                raise ValueError(
                    "this node stores no container logs (log driver 'none') — "
                    "set DCHOST_LOG_DRIVER=json-file on the node agent to enable the console log view"
                ) from exc
            raise

    def logs_follow(self, container, since=None, tail=200):
        """Yield complete log lines as they appear (generator).

        Used by the streaming /logs/follow endpoint.  ``since`` is a Unix
        timestamp (seconds); lines produced before that are skipped.  ``tail``
        limits how many lines of backfill are sent before the stream switches
        to live-only mode.

        ``stream=True`` is what makes docker-py hand back a generator over the
        daemon's chunked response. ``follow=True`` alone still buffers the whole
        body and only returns once the container stops, so the console showed
        nothing at all for a running server.

        What that generator hands back is not a line, and for a managed container
        it is not even a string: these containers are created with a tty, and for
        a tty docker-py streams the raw response through _stream_raw_result, whose
        chunk size is one byte. Yielding those through untouched put every single
        byte of output on a console line of its own ("1", newline, "2", newline)
        and decoded each byte separately, so every non-ASCII character became a
        pair of replacement marks. Both are fixed by assembling here: an
        incremental decoder carries a multi-byte sequence across a chunk boundary,
        and a buffer holds a partial line until its newline arrives. One line per
        yield also collapses what was a frame, a WebSocket message and a DOM write
        per byte down to one per line.
        """
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        buffer = ""
        # Docker/json-file and Python input() both hold a prompt until a newline.
        # Waiting only on "\n" meant `input("Do you like Python? ")` never reached
        # the panel. Idle-flush the partial line so the prompt shows while the
        # process waits on stdin.
        incoming = queue.Queue()
        _END = object()

        def _reader():
            try:
                for chunk in container.logs(
                    stdout=True, stderr=True, follow=True, stream=True, since=since,
                    tail=tail, timestamps=True
                ):
                    incoming.put(chunk)
            except Exception as exc:
                incoming.put(exc)
            finally:
                incoming.put(_END)

        worker = threading.Thread(target=_reader, name="dchost-logs-follow", daemon=True)
        worker.start()
        try:
            while True:
                try:
                    item = incoming.get(timeout=0.12)
                except queue.Empty:
                    if buffer:
                        yield visible_line(buffer)
                        buffer = ""
                    continue
                if item is _END:
                    break
                if isinstance(item, Exception):
                    raise item
                chunk = item
                if isinstance(chunk, bytes):
                    chunk = decoder.decode(chunk)
                if not chunk:
                    continue
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    yield visible_line(line)
                if len(buffer) > MAX_LOG_LINE_CHARS:
                    yield visible_line(buffer)
                    buffer = ""
        except Exception as exc:
            message = str(exc).lower()
            if "logging driver" in message or "does not support reading" in message:
                raise ValueError(
                    "this node stores no container logs (log driver 'none') — "
                    "set DCHOST_LOG_DRIVER=json-file on the node agent to enable the console log view"
                ) from exc
            raise
        else:
            # Whatever the container wrote without a closing newline before the
            # stream ended — usually the reason it stopped. Deliberately not in a
            # finally: closing a browser tab throws GeneratorExit in at the yield
            # above, and a generator that yields again while unwinding that raises
            # "generator ignored GeneratorExit" — an error per closed console.
            tail_text = buffer + decoder.decode(b"", True)
            if tail_text:
                yield visible_line(tail_text)

    def run_command(self, container, command):
        try:
            result = container.exec_run(
                ["/bin/sh", "-lc", command],
                stdout=True,
                stderr=True,
                demux=False,
            )
        except Exception as exc:
            # A crash-looping bot can exit between the manager's status check and
            # this exec. Docker answers 409 there; translate it so the console
            # shows the reason instead of a generic node failure.
            if "not running" in str(exc).lower():
                raise ValueError(
                    "the container stopped before the command could run — start the server and try again"
                ) from exc
            raise
        output = result.output
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {"ok": result.exit_code == 0, "exit_code": result.exit_code, "output": output}

    def send_stdin(self, container, text):
        # Pterodactyl-style live console: write one line to the running
        # container's stdin. The container runs with stdin_open=True and
        # stdin_once unset (docker-py default False), so the daemon keeps stdin
        # open across attach/detach — we attach, write the line, and close our
        # client side between commands. We must NOT half-close (shutdown of the
        # write side): that delivers EOF to the process and stops a server that
        # treats stdin EOF as "quit". A tty container takes raw bytes on stdin.
        try:
            sock = container.attach_socket(params={"stdin": 1, "stream": 1})
        except Exception as exc:
            if "not running" in str(exc).lower():
                raise ValueError(
                    "the container stopped before the command could run — start the server and try again"
                ) from exc
            raise
        try:
            raw = getattr(sock, "_sock", sock)
            raw.sendall((text + "\n").encode("utf-8"))
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return {"ok": True}

    def run_install(self, image, command, volumes, environment, mem_limit, nano_cpus):
        from .container_spec import CONTAINER_USER, INSTALL_TIMEOUT_SECONDS
        spec = dict(
            image=image,
            command=["/bin/sh", "-lc", command],
            detach=True,
            stdin_open=True,
            tty=True,
            working_dir="/home/container",
            environment=environment,
            volumes=volumes,
            mem_limit=mem_limit,
            memswap_limit=mem_limit,
            nano_cpus=nano_cpus,
            pids_limit=128,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            network_mode="bridge",
            # The install log is the only feedback an owner gets when a build
            # fails, and Docker refuses to read logs back from a container whose
            # driver is "none" — the managed default. Reading them raised, so the
            # install was recorded as failed even when the command had succeeded.
            # This container is removed the moment the install ends, so json-file
            # here cannot grow without bound.
            log_config={"type": "json-file", "config": {"max-size": "8m", "max-file": "1"}},
            labels={"dchost.managed": "true", "dchost.install": "true"},
            **({"user": CONTAINER_USER} if CONTAINER_USER else {}),
        )
        try:
            container = self.client.containers.create(**spec)
        except Exception:
            # Mirror create()'s fallback: a docker-py build that rejects the
            # logging kwarg must not fail every dependency install. Drop the log
            # driver and lose only the captured install log, not the install.
            retry = {key: value for key, value in spec.items() if key != "log_config"}
            container = self.client.containers.create(**retry)
        try:
            container.start()
            timed_out = False
            try:
                exit_code = int(container.wait(timeout=INSTALL_TIMEOUT_SECONDS).get("StatusCode", 0))
            except Exception:
                # wait() gives up by raising a read timeout rather than returning.
                timed_out = True
                exit_code = 124
                try:
                    container.kill()
                except Exception:
                    pass
            output = container.logs(stdout=True, stderr=True, tail=2000)
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            if timed_out:
                output = (output or "") + (
                    f"\nERROR: installation ran longer than {INSTALL_TIMEOUT_SECONDS}s and was stopped.\n"
                )
            return exit_code, output
        finally:
            container.remove(force=True)

    def remove_install_containers(self):
        """Remove dependency-install containers left behind by a kill.

        run_install deletes its container in a ``finally``, which does not run if
        the process is killed mid-install. The container then keeps running with
        the server's directory still bind mounted — holding its 300 MB, its pid
        allowance and a writer on the very files the next reinstall writes. It
        carries no ``dchost.server_id`` label, so ``list()`` filters it out and
        every other cleanup path here is keyed by server id: nothing reaped it.
        Returns how many were removed, for the startup log.
        """
        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": "dchost.install=true"},
            )
        except Exception:
            # Reaping is best-effort startup hygiene; a daemon that cannot answer
            # here must not stop the agent from serving.
            return 0
        removed = 0
        for container in containers:
            try:
                container.remove(force=True)
            except Exception:
                continue
            removed += 1
        return removed

    def prune_images(self):
        """Remove images not used by any container.

        Called after server deletions so disk space is reclaimed. Only removes
        dangling (untagged) and unreferenced images — images still in use by a
        running or stopped container are kept.
        """
        try:
            result = self.client.images.prune(filters={"dangling": False})
            return len(result.get("ImagesDeleted", []))
        except Exception:
            return 0

    def stats(self, container):
        # A wedged Docker daemon used to leave container.stats(stream=False)
        # blocking indefinitely, which meant the panel saw a blank "0%" / "0 KB/s"
        # usage line for the whole time the daemon was slow and the page only
        # recovered after a manual refresh. Stats reads are time-bounded by the
        # client timeout set in __init__; we surface any failure as zeroed fields
        # rather than propagating, so the panel can keep rendering what it has
        # and the next poll recovers automatically.
        try:
            data = container.stats(stream=False)
        except Exception:
            return {
                "cpu_percent": 0.0,
                "memory_bytes": 0,
                "memory_limit": 0,
                "network_rx_bytes": 0,
                "network_tx_bytes": 0,
            }
        cpu_total = data.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        previous_cpu = data.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        system_total = data.get("cpu_stats", {}).get("system_cpu_usage", 0)
        previous_system = data.get("precpu_stats", {}).get("system_cpu_usage", 0)
        online_cpus = data.get("cpu_stats", {}).get("online_cpus") or len(
            data.get("cpu_stats", {}).get("cpu_usage", {}).get("percpu_usage", [])
        ) or 1
        cpu_delta = cpu_total - previous_cpu
        system_delta = system_total - previous_system
        cpu_percent = 0.0
        if cpu_delta > 0 and system_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0

        memory = data.get("memory_stats", {})
        usage = int(memory.get("usage", 0))
        cache = int(memory.get("stats", {}).get("inactive_file", 0))
        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_bytes": max(0, usage - cache),
            "memory_limit": int(memory.get("limit", 0)),
            "network_rx_bytes": sum(
                int(item.get("rx_bytes", 0)) for item in data.get("networks", {}).values()
            ),
            "network_tx_bytes": sum(
                int(item.get("tx_bytes", 0)) for item in data.get("networks", {}).values()
            ),
        }

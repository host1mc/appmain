import tempfile
import unittest
from pathlib import Path

from node_agent.app import create_app


class FakeContainer:
    def __init__(self, spec):
        self.id = "container-1234567890"
        self.status = "created"
        self.spec = spec

    def start(self):
        self.status = "running"

    def stop(self, timeout=10):
        self.status = "exited"

    def restart(self, timeout=10):
        self.status = "running"

    def kill(self):
        self.status = "dead"


class FakeRuntime:
    def __init__(self):
        self.containers = {}
        self.follow_chunks = ["ready\n"]
        self.follow_calls = []

    def create(self, spec):
        container = FakeContainer(spec)
        self.containers[spec["labels"]["dchost.server_id"]] = container
        return container

    def get(self, server_id):
        return self.containers.get(server_id)

    def list(self):
        return [
            {
                "id": spec["labels"]["dchost.server_id"],
                "name": spec["labels"]["dchost.display_name"],
                "status": container.status,
            }
            for spec, container in [(c.spec, c) for c in self.containers.values()]
        ]

    def remove(self, container, force=False):
        server_id = container.spec["labels"]["dchost.server_id"]
        self.containers.pop(server_id, None)

    def logs(self, container, tail=200):
        return b"ready\n"

    def logs_follow(self, container, since=None, tail=200):
        # Deliberately shaped like a real docker log stream: chunks arrive with
        # arbitrary line boundaries, and one chunk routinely holds several lines.
        self.follow_calls.append({"since": since, "tail": tail})
        yield from self.follow_chunks

    def stats(self, container):
        return {
            "cpu_percent": 1.5,
            "memory_bytes": 2 * 1024 * 1024,
            "memory_limit": 300 * 1024 * 1024,
            "network_rx_bytes": 128,
            "network_tx_bytes": 64,
        }

    def run_command(self, container, command):
        return {"ok": True, "exit_code": 0, "output": f"ran: {command}\n"}

    def run_install(self, image, command, volumes, environment, mem_limit, nano_cpus):
        return 0, "installed dependencies\n"


class NodeAgentAppTests(unittest.TestCase):
    def setUp(self):
        # See test_server_manager: daemon install threads can still be writing
        # under this directory when tearDown removes it.
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.runtime = FakeRuntime()
        self.app = create_app(
            {
                "TESTING": True,
                "NODE_TOKEN": "test-node-token",
                "DATA_ROOT": str(Path(self.temp_dir.name) / "servers"),
            },
            runtime=self.runtime,
        )
        self.client = self.app.test_client()
        self.headers = {"Authorization": "Bearer test-node-token"}
        self.server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _wait_install(self, server_id, timeout=5):
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            state = self.client.get(
                f"/api/v1/servers/{server_id}/state",
                headers=self.headers,
            ).get_json()["server"]
            if state["install_status"] != "running":
                return state
            time.sleep(0.01)
        raise AssertionError("installation did not finish in time")

    def _create_server(self, server_id=None):
        """Create a server and wait for its install, returning its id."""
        server_id = server_id or self.server_id
        response = self.client.post(
            "/api/v1/servers",
            headers=self.headers,
            json={
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
                "memory_mb": 300,
                "cpu_percent": 35,
            },
        )
        self.assertEqual(response.status_code, 201)
        self._wait_install(server_id)
        return server_id

    def test_health_is_public_but_api_requires_bearer_token(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/runtimes").status_code, 401)
        response = self.client.get("/api/v1/runtimes", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("nodejs", response.get_json()["runtimes"])

    def test_create_state_logs_command_and_file_flow(self):
        response = self.client.post(
            "/api/v1/servers",
            headers=self.headers,
            json={
                "id": self.server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
                "memory_mb": 300,
                "cpu_percent": 35,
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["server"]["status"], "created")
        self.assertEqual(response.get_json()["server"]["install_status"], "running")

        install_state = self._wait_install(self.server_id)
        self.assertEqual(install_state["install_status"], "success")

        started = self.client.post(
            f"/api/v1/servers/{self.server_id}/power",
            headers=self.headers,
            json={"action": "start"},
        ).get_json()
        self.assertEqual(started["status"], "running")

        state = self.client.get(
            f"/api/v1/servers/{self.server_id}/state",
            headers=self.headers,
        ).get_json()["server"]
        self.assertEqual(state["memory_limit"], 300 * 1024 * 1024)
        self.assertEqual(state["disk_total_bytes"], 600 * 1024 * 1024)
        self.assertGreaterEqual(state["disk_free_bytes"], 0)

        logs = self.client.get(
            f"/api/v1/servers/{self.server_id}/logs",
            headers=self.headers,
        ).get_json()
        self.assertEqual(logs["logs"], "ready\n")

        command = self.client.post(
            f"/api/v1/servers/{self.server_id}/command",
            headers=self.headers,
            json={"command": "npm install"},
        ).get_json()
        self.assertIn("npm install", command["output"])

        startup = self.client.post(
            f"/api/v1/servers/{self.server_id}/startup",
            headers=self.headers,
            json={"startup": "node bot.js"},
        ).get_json()
        self.assertEqual(startup["startup"], "node bot.js")
        self.assertEqual(startup["status"], "running")

        image = self.client.post(
            f"/api/v1/servers/{self.server_id}/image",
            headers=self.headers,
            json={"runtime": "nodejs", "version": "20"},
        ).get_json()
        self.assertEqual(image["version"], "20")
        self.assertIn("20", image["image"])
        self.assertEqual(image["status"], "running")

        self.client.put(
            f"/api/v1/servers/{self.server_id}/file",
            headers=self.headers,
            json={"path": "config.json", "content": "{}\n"},
        )
        listing = self.client.get(
            f"/api/v1/servers/{self.server_id}/files",
            headers=self.headers,
        ).get_json()
        self.assertTrue(any(entry["name"] == "config.json" for entry in listing["entries"]))

        upload = self.client.post(
            f"/api/v1/servers/{self.server_id}/upload",
            headers=self.headers,
            json={"path": "assets/bot.png", "content": "iVBORw0KGgo="},
        )
        self.assertEqual(upload.status_code, 201)
        uploaded = Path(self.temp_dir.name) / "servers" / self.server_id / "assets" / "bot.png"
        self.assertEqual(uploaded.read_bytes(), b"\x89PNG\r\n\x1a\n")

    def test_logs_follow_streams_sse_frames_per_line(self):
        """Every log line reaches the client as its own prefixed SSE data line.

        A docker chunk holding several lines used to be interpolated raw, which
        put unprefixed lines inside the frame and ended the event early at the
        embedded blank line — so only the first line of such a chunk survived.
        """
        self._create_server()
        self.runtime.follow_chunks = ["first\n", "line A\nline B\nline C\n", "partial"]

        response = self.client.get(
            f"/api/v1/servers/{self.server_id}/logs/follow?tail=50",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["Content-Type"].startswith("text/event-stream"))
        self.assertEqual(response.headers["X-Accel-Buffering"], "no")
        body = response.get_data(as_text=True)

        # Every payload line carries its own prefix, and no log text is lost.
        self.assertIn("data:line A\ndata:line B\ndata:line C\n\n", body)
        self.assertIn("data:first\n\n", body)
        self.assertIn("data:partial\n\n", body)
        self.assertTrue(body.endswith("event:done\ndata:\n\n"))
        self.assertEqual(self.runtime.follow_calls[0]["tail"], 50)

    def test_logs_follow_clamps_tail_and_survives_runtime_error(self):
        self._create_server()
        self.client.get(
            f"/api/v1/servers/{self.server_id}/logs/follow?tail=99999",
            headers=self.headers,
        )
        self.assertEqual(self.runtime.follow_calls[0]["tail"], 1000)

        self.runtime.follow_calls.clear()
        self.client.get(
            f"/api/v1/servers/{self.server_id}/logs/follow?tail=0&since=1710000000",
            headers=self.headers,
        )
        self.assertEqual(self.runtime.follow_calls[0]["tail"], 0)
        self.assertEqual(self.runtime.follow_calls[0]["since"], 1710000000.0)

        def boom(container, since=None, tail=200):
            yield "before the failure\n"
            raise RuntimeError("docker went away")

        self.runtime.logs_follow = boom
        body = self.client.get(
            f"/api/v1/servers/{self.server_id}/logs/follow",
            headers=self.headers,
        ).get_data(as_text=True)
        # The partial output is kept and the stream still terminates cleanly.
        self.assertIn("data:before the failure\n\n", body)
        self.assertTrue(body.endswith("event:done\ndata:\n\n"))

    def test_logs_follow_requires_bearer_token(self):
        self._create_server()
        response = self.client.get(f"/api/v1/servers/{self.server_id}/logs/follow")
        self.assertEqual(response.status_code, 401)

    def test_resource_override_is_rejected_and_unknown_route_stays_404(self):
        response = self.client.post(
            "/api/v1/servers",
            headers=self.headers,
            json={
                "id": self.server_id,
                "name": "Oversized Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
                "memory_mb": 1024,
                "cpu_percent": 200,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/missing", headers=self.headers).status_code, 404)

    def test_list_servers_returns_managed_containers(self):
        self.client.post(
            "/api/v1/servers",
            headers=self.headers,
            json={
                "id": self.server_id,
                "name": "Music Bot",
                "runtime": "python",
                "version": "3.13",
                "startup": "python bot.py",
                "memory_mb": 300,
                "cpu_percent": 35,
            },
        )
        self._wait_install(self.server_id)

        listing = self.client.get("/api/v1/servers", headers=self.headers).get_json()

        self.assertEqual(listing["ok"], True)
        self.assertEqual(len(listing["servers"]), 1)
        self.assertEqual(listing["servers"][0]["id"], self.server_id)
        self.assertEqual(listing["servers"][0]["name"], "Music Bot")
        self.assertEqual(listing["servers"][0]["status"], "created")
        self.assertIn(listing["servers"][0]["install_status"], ("running", "success"))

    def test_start_is_refused_while_installing_and_reinstall_runs_again(self):
        self.client.post(
            "/api/v1/servers",
            headers=self.headers,
            json={
                "id": self.server_id,
                "name": "Installing Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
                "memory_mb": 300,
                "cpu_percent": 35,
            },
        )

        self._wait_install(self.server_id)
        install = self.client.get(
            f"/api/v1/servers/{self.server_id}/install",
            headers=self.headers,
        ).get_json()
        self.assertEqual(install["status"], "success")
        self.assertIn("installed dependencies", install["log"])

        started = self.client.post(
            f"/api/v1/servers/{self.server_id}/power",
            headers=self.headers,
            json={"action": "start"},
        ).get_json()
        self.assertEqual(started["status"], "running")

        reinstalled = self.client.post(
            f"/api/v1/servers/{self.server_id}/install",
            headers=self.headers,
            json={},
        )
        self.assertEqual(reinstalled.status_code, 400)
        self.assertIn("stop the server", reinstalled.get_json()["error"])

        self.client.post(
            f"/api/v1/servers/{self.server_id}/power",
            headers=self.headers,
            json={"action": "stop"},
        )
        reinstalled = self.client.post(
            f"/api/v1/servers/{self.server_id}/install",
            headers=self.headers,
            json={},
        )
        self.assertEqual(reinstalled.status_code, 200)
        self.assertEqual(reinstalled.get_json()["install_status"], "running")
        self.assertEqual(self._wait_install(self.server_id)["install_status"], "success")


if __name__ == "__main__":
    unittest.main()

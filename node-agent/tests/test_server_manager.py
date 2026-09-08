import tempfile
import time
import unittest
from pathlib import Path

from node_agent import server_manager


class FakeContainer:
    def __init__(self, container_id, spec):
        self.id = container_id
        self.name = spec["name"]
        self.status = "created"
        self.spec = spec
        self.start_count = 0

    def start(self):
        self.start_count += 1
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
        self.created_specs = []
        self.removed = []
        self.install_gate = None
        self.install_exit_code = 0
        self.install_output = "installed dependencies\n"

    def create(self, spec):
        container = FakeContainer("container-1", spec)
        self.containers[spec["labels"]["dchost.server_id"]] = container
        self.created_specs.append(spec)
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
        self.removed.append((container.id, force))
        for key, existing in list(self.containers.items()):
            if existing.id == container.id:
                del self.containers[key]
                break

    def logs(self, container, tail=200):
        return b"booted\nready\n"

    def stats(self, container):
        return {"cpu_percent": 0.8, "memory_bytes": 1024, "memory_limit": 300 * 1024 * 1024}

    def run_command(self, container, command):
        return {"ok": True, "exit_code": 0, "output": f"ran: {command}\n"}

    def run_install(self, image, command, volumes, environment, mem_limit, nano_cpus):
        if self.install_gate is not None:
            self.install_gate.wait(timeout=5)
        return self.install_exit_code, self.install_output


class ServerManagerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(server_manager, "ServerManager"), "ServerManager is not implemented")
        # Installs run on daemon threads that write install state under this
        # directory. One can still be finishing when tearDown removes the tree,
        # and Windows refuses to rmdir a directory that is not yet empty.
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.runtime = FakeRuntime()
        self.manager = server_manager.ServerManager(self.runtime, Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def _wait_install(self, server_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.manager.state(server_id)["install_status"] != "running":
                return self.manager.state(server_id)
            time.sleep(0.01)
        raise AssertionError("installation did not finish in time")

    def test_create_server_resolves_image_and_creates_stopped_with_fixed_limits(self):
        result = self.manager.create_server(
            {
                "id": "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb",
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )

        self.assertEqual(result["id"], "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb")
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["install_status"], "running")
        spec = self.runtime.created_specs[0]
        self.assertEqual(spec["image"], "node:22-alpine")
        self.assertEqual(spec["mem_limit"], 300 * 1024 * 1024)
        self.assertEqual(spec["nano_cpus"], 350_000_000)
        self.assertEqual(self.runtime.containers[result["id"]].start_count, 0)

        self.assertEqual(self._wait_install(result["id"])["install_status"], "success")
        self.assertEqual(self.manager.power(result["id"], "start")["status"], "running")
        self.assertEqual(self.runtime.containers[result["id"]].start_count, 1)

    def test_failed_create_rolls_back_and_allows_retry(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        payload = {
            "id": server_id, "name": "Doomed Bot", "runtime": "nodejs",
            "version": "22", "startup": "npm start",
        }

        boom = RuntimeError("image pull failed")
        original_create = self.runtime.create
        def failing_create(spec):
            raise boom
        self.runtime.create = failing_create

        with self.assertRaises(RuntimeError):
            self.manager.create_server(payload)

        # Nothing left behind: no container, no data dir, install slot freed.
        self.assertNotIn(server_id, self.runtime.containers)
        self.assertFalse((self.manager.data_root / server_id).is_dir())

        # Retry now succeeds — the conflict guards do not block it, proving the
        # rollback fully cleared the failed attempt.
        self.runtime.create = original_create
        result = self.manager.create_server(payload)
        self.assertEqual(result["id"], server_id)
        self.assertIn(server_id, self.runtime.containers)

    def test_start_is_refused_while_installing(self):
        import threading

        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        gate = threading.Event()
        self.runtime.install_gate = gate
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Installing Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )

        deadline = time.time() + 5
        while self.manager.state(server_id)["install_status"] != "running" and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.manager.state(server_id)["install_status"], "running")

        with self.assertRaisesRegex(ValueError, "still installing"):
            self.manager.power(server_id, "start")

        gate.set()
        self.assertEqual(self._wait_install(server_id)["install_status"], "success")
        self.assertEqual(self.manager.power(server_id, "start")["status"], "running")

    def test_failed_install_blocks_start_until_reinstall_succeeds(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Broken Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)
        package_json = self.manager.storage(server_id).root / "package.json"
        package_json.unlink()

        self.runtime.install_exit_code = 1
        self.runtime.install_output = "npm error could not read package.json\n"
        self.manager.reinstall(server_id)
        state = self._wait_install(server_id)
        self.assertEqual(state["install_status"], "failed")
        self.assertIn("could not read package.json", state["install_error"])

        with self.assertRaisesRegex(ValueError, "installation failed"):
            self.manager.power(server_id, "start")

        package_json.write_text('{"name":"bot","scripts":{"start":"node index.js"}}\n', encoding="utf-8")
        self.runtime.install_exit_code = 0
        self.runtime.install_output = "installed dependencies\n"
        self.manager.reinstall(server_id)
        self.assertEqual(self._wait_install(server_id)["install_status"], "success")
        self.assertEqual(self.manager.power(server_id, "start")["status"], "running")

    def test_interrupted_install_is_marked_failed_on_restart(self):
        import threading

        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        gate = threading.Event()
        self.runtime.install_gate = gate
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Interrupted Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )

        deadline = time.time() + 5
        while self.manager.state(server_id)["install_status"] != "running" and time.time() < deadline:
            time.sleep(0.01)
        restarted = server_manager.ServerManager(self.runtime, Path(self.temp_dir.name))
        gate.set()
        self._wait_install(server_id)

        self.assertEqual(restarted.state(server_id)["install_status"], "failed")
        self.assertIn("interrupted", restarted.state(server_id)["install_error"])

    def test_power_logs_stats_and_remove_delegate_to_runtime(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)

        self.assertEqual(self.manager.power(server_id, "stop")["status"], "exited")
        self.assertEqual(self.manager.logs(server_id, 20)["logs"], "booted\nready\n")
        self.assertEqual(self.manager.stats(server_id)["memory_limit"], 300 * 1024 * 1024)
        self.assertTrue(self.manager.remove(server_id, purge=False)["ok"])
        self.assertEqual(self.runtime.removed, [("container-1", False)])

    def test_remove_stops_restarting_crash_loop_container(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Crash Bot",
                "runtime": "python",
                "version": "3.13",
                "startup": "python bot.py",
            }
        )
        self._wait_install(server_id)
        self.manager.power(server_id, "start")
        container = self.runtime.containers[server_id]
        container.status = "restarting"

        self.assertTrue(self.manager.remove(server_id, purge=False)["ok"])
        self.assertEqual(container.status, "exited")
        self.assertEqual(self.runtime.removed, [("container-1", False)])

    def test_start_refuses_npm_when_package_json_is_missing(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Broken Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)
        package_json = self.manager.storage(server_id).root / "package.json"
        if package_json.exists():
            package_json.unlink()

        with self.assertRaisesRegex(ValueError, "package.json"):
            self.manager.power(server_id, "start")
        self.assertEqual(self.runtime.containers[server_id].start_count, 0)

        self.manager.storage(server_id).write_text("package.json", "{}\n")
        self.assertEqual(self.manager.power(server_id, "start")["status"], "running")

    def test_console_command_requires_a_running_container(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )

        # Still installing: the container exists but has never been started.
        with self.assertRaisesRegex(ValueError, "still installing"):
            self.manager.run_command(server_id, "ls -la")

        self._wait_install(server_id)

        # Install finished, server left stopped — this is the state a freshly
        # deployed server sits in, and docker exec cannot attach to it.
        with self.assertRaisesRegex(ValueError, "start the server first"):
            self.manager.run_command(server_id, "ls -la")

        self.manager.power(server_id, "start")
        self.assertEqual(self.manager.run_command(server_id, "ls -la")["output"], "ran: ls -la\n")

        # A crashed bot goes back to refusing, with the status in the message.
        self.manager.power(server_id, "stop")
        with self.assertRaisesRegex(ValueError, "exited"):
            self.manager.run_command(server_id, "ls -la")

    def test_console_command_rejects_empty_and_oversized_input(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)
        self.manager.power(server_id, "start")

        for bad in ("", "   ", None, "x" * 501):
            with self.assertRaisesRegex(ValueError, "between 1 and 500"):
                self.manager.run_command(server_id, bad)

    def test_update_startup_recreates_container_with_new_command(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)
        self.manager.power(server_id, "start")

        result = self.manager.update_startup(server_id, "node bot.js")
        self.assertEqual(result["status"], "running")
        self.assertEqual(self.runtime.created_specs[-1]["command"], ["/bin/sh", "-lc", "node bot.js"])
        self.assertEqual(self.runtime.removed, [("container-1", True)])
        self.assertEqual(self.runtime.created_specs[-1]["labels"]["dchost.server_id"], server_id)

    def test_update_version_rebuilds_with_new_image_preserving_startup(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "nodejs",
                "version": "22",
                "startup": "npm start",
            }
        )
        self._wait_install(server_id)
        self.manager.power(server_id, "start")

        result = self.manager.update_version(server_id, "nodejs", "20")

        self.assertEqual(result["version"], "20")
        self.assertEqual(result["image"], "node:20-alpine")
        self.assertEqual(result["status"], "running")
        spec = self.runtime.created_specs[-1]
        self.assertEqual(spec["image"], "node:20-alpine")
        self.assertEqual(spec["command"], ["/bin/sh", "-lc", "npm start"])

    def test_update_version_on_stopped_server_stays_stopped(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "python",
                "version": "3.13",
                "startup": "python bot.py",
            }
        )
        self._wait_install(server_id)

        result = self.manager.update_version(server_id, "python", "3.12")

        self.assertEqual(result["status"], "created")
        self.assertEqual(self.runtime.containers[server_id].start_count, 0)

    def test_state_reports_storage_quota_instead_of_host_disk(self):
        server_id = "85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"
        self.manager.create_server(
            {
                "id": server_id,
                "name": "Music Bot",
                "runtime": "python",
                "version": "3.13",
                "startup": "python bot.py",
            }
        )

        state = self.manager.state(server_id)

        self.assertEqual(state["disk_total_bytes"], 600 * 1024 * 1024)
        self.assertGreaterEqual(state["disk_used_bytes"], 0)
        self.assertEqual(
            state["disk_free_bytes"],
            600 * 1024 * 1024 - state["disk_used_bytes"],
        )


    def _seed_container(self, server_id, name="Seeded Bot"):
        spec = {
            "name": name,
            "labels": {"dchost.server_id": server_id, "dchost.display_name": name},
        }
        container = FakeContainer(f"c-{server_id}", spec)
        self.runtime.containers[server_id] = container
        return container

    def test_reconcile_removes_only_orphans_absent_from_the_allowlist(self):
        import uuid

        keep_a, keep_b, orphan = (str(uuid.uuid4()) for _ in range(3))
        self._seed_container(keep_a)
        self._seed_container(keep_b)
        self._seed_container(orphan)

        result = self.manager.reconcile([keep_a, keep_b], purge=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["checked"], 3)
        self.assertEqual(result["orphans"], [orphan])
        self.assertEqual(result["removed"], [orphan])
        self.assertEqual([cid for cid, _ in self.runtime.removed], [f"c-{orphan}"])

    def test_reconcile_refuses_empty_allowlist_with_containers_present(self):
        import uuid

        orphan_a, orphan_b = (str(uuid.uuid4()) for _ in range(2))
        self._seed_container(orphan_a)
        self._seed_container(orphan_b)

        # An empty allowlist while containers are live is a failed control-plane
        # read or a fresh/backup database promoted after a failover, not a real
        # "delete every server" — so it is refused, not obeyed.
        result = self.manager.reconcile([], purge=True)

        self.assertFalse(result["ok"])
        self.assertIn("empty allowlist", result["refused"])
        self.assertEqual(result["removed"], [])
        self.assertEqual(self.runtime.removed, [])

    def test_reconcile_refuses_empty_allowlist_with_orphan_data_dirs(self):
        import uuid

        orphan = str(uuid.uuid4())
        (self.manager.data_root / orphan).mkdir()

        result = self.manager.reconcile([], purge=True)

        self.assertFalse(result["ok"])
        self.assertIn("empty allowlist", result["refused"])
        self.assertTrue((self.manager.data_root / orphan).exists())

    def test_reconcile_caps_orphan_deletions_and_drains_next_pass(self):
        import uuid

        for _ in range(3):
            self._seed_container(str(uuid.uuid4()))

        # First pass: 3 orphans, cap 2 — deletes 2, defers 1 (does NOT refuse).
        result = self.manager.reconcile([str(uuid.uuid4())], purge=True, max_delete=2)
        self.assertTrue(result["ok"])
        self.assertIn("max_delete", result["capped"])
        self.assertEqual(len(result["removed"]), 2)
        self.assertEqual(len(self.runtime.removed), 2)

        # Second pass drains the remaining orphan; backlog converges.
        result2 = self.manager.reconcile([str(uuid.uuid4())], purge=True, max_delete=2)
        self.assertTrue(result2["ok"])
        self.assertEqual(len(result2["removed"]), 1)
        self.assertEqual(len(self.runtime.removed), 3)

    def test_reconcile_reaps_container_less_orphan_state_files(self):
        import uuid

        keep, orphan = str(uuid.uuid4()), str(uuid.uuid4())
        # Two install-state files with no container: one whose server is still
        # in the database, one whose server the database no longer knows.
        self.manager._set_install_state(keep, {"status": "success"})
        self.manager._set_install_state(orphan, {"status": "failed"})

        result = self.manager.reconcile([keep], purge=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["install_state_files_removed"], 1)
        self.assertFalse(self.manager._install_state_path(orphan).exists())
        self.assertTrue(self.manager._install_state_path(keep).exists())

    def test_reconcile_reaps_state_files_on_empty_allowlist(self):
        import uuid

        orphan = str(uuid.uuid4())
        self.manager._set_install_state(orphan, {"status": "failed"})

        result = self.manager.reconcile([], purge=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["install_state_files_removed"], 1)
        self.assertFalse(self.manager._install_state_path(orphan).exists())

    def test_reconcile_removes_container_less_orphan_data_dirs(self):
        import uuid

        keep, orphan = str(uuid.uuid4()), str(uuid.uuid4())
        # Bare data directories with no container: one the database still knows,
        # one it does not. Neither the container-orphan logic nor disk_cleanup
        # reaches a container-less dir — only the dir sweep does.
        (self.manager.data_root / keep).mkdir()
        (self.manager.data_root / orphan).mkdir()

        result = self.manager.reconcile([keep], purge=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["data_dirs_removed"], [orphan])
        self.assertFalse((self.manager.data_root / orphan).exists())
        self.assertTrue((self.manager.data_root / keep).exists())

    def test_reconcile_leaves_orphan_data_dirs_when_not_purging(self):
        import uuid

        orphan = str(uuid.uuid4())
        (self.manager.data_root / orphan).mkdir()

        result = self.manager.reconcile([str(uuid.uuid4())], purge=False)

        self.assertTrue(result["ok"])
        self.assertNotIn("data_dirs_removed", result)
        self.assertTrue((self.manager.data_root / orphan).exists())

    def test_reconcile_counts_orphan_data_dirs_against_max_delete(self):
        import uuid

        for _ in range(3):
            (self.manager.data_root / str(uuid.uuid4())).mkdir()

        # Dirs count against the same cap: 3 orphan dirs, cap 2 — reaps 2 this
        # pass, leaves 1, does not refuse. Second pass drains the last one.
        result = self.manager.reconcile([str(uuid.uuid4())], purge=True, max_delete=2)
        self.assertTrue(result["ok"])
        self.assertIn("max_delete", result["capped"])
        self.assertEqual(len(result["data_dirs_removed"]), 2)
        self.assertEqual(sum(1 for p in self.manager.data_root.iterdir() if p.is_dir()), 1)

        result2 = self.manager.reconcile([str(uuid.uuid4())], purge=True, max_delete=2)
        self.assertTrue(result2["ok"])
        self.assertEqual(len(result2["data_dirs_removed"]), 1)
        self.assertEqual(sum(1 for p in self.manager.data_root.iterdir() if p.is_dir()), 0)

    def test_reconcile_protects_deferred_deletions(self):
        import uuid

        keep, orphan, deferred = (str(uuid.uuid4()) for _ in range(3))
        self._seed_container(keep)
        self._seed_container(orphan)
        self._seed_container(deferred)

        result = self.manager.reconcile([keep], purge=True, protect_ids=[deferred])

        # A tombstoned container reads as an orphan (its DB row is gone), but
        # the sweep must skip it: only an admin's manual confirm may remove it.
        self.assertTrue(result["ok"])
        self.assertEqual(result["orphans"], [orphan])
        self.assertEqual(result["removed"], [orphan])
        self.assertEqual(result["protected"], [deferred])
        self.assertIn(deferred, self.runtime.containers)
        self.assertNotIn(orphan, self.runtime.containers)

    def test_reconcile_protection_never_stands_in_for_an_allowlist(self):
        import uuid

        deferred, unprotected = str(uuid.uuid4()), str(uuid.uuid4())
        self._seed_container(deferred)
        self._seed_container(unprotected)

        result = self.manager.reconcile([], purge=True, protect_ids=[deferred])

        # An empty allowlist is still refused even though a protect list was
        # supplied: protection exempts ids from the sweep, it never authorizes
        # one, so a failed control-plane read cannot become a selective wipe.
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["refused"])
        self.assertIn(deferred, self.runtime.containers)
        self.assertIn(unprotected, self.runtime.containers)

    def test_reconcile_protects_deferred_data_dirs_and_state_files(self):
        import uuid

        keep, orphan, deferred = (str(uuid.uuid4()) for _ in range(3))
        (self.manager.data_root / keep).mkdir()
        (self.manager.data_root / orphan).mkdir()
        (self.manager.data_root / deferred).mkdir()
        self.manager._set_install_state(orphan, {"status": "failed"})
        self.manager._set_install_state(deferred, {"status": "failed"})

        result = self.manager.reconcile([keep], purge=True, protect_ids=[deferred])

        self.assertTrue(result["ok"])
        self.assertEqual(result["data_dirs_removed"], [orphan])
        self.assertFalse((self.manager.data_root / orphan).exists())
        self.assertTrue((self.manager.data_root / deferred).exists())
        self.assertFalse(self.manager._install_state_path(orphan).exists())
        self.assertTrue(self.manager._install_state_path(deferred).exists())


if __name__ == "__main__":
    unittest.main()

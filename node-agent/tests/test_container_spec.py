import unittest

from node_agent import container_spec


class ContainerSpecTests(unittest.TestCase):
    def test_spec_enforces_fixed_resource_limits_and_runtime_command(self):
        self.assertTrue(hasattr(container_spec, "build_container_spec"), "build_container_spec is not implemented")

        spec = container_spec.build_container_spec(
            server_id="85d8a5f9-4be2-4784-91c4-b4e80ea93fcb",
            name="Music Bot",
            image="node:22-alpine",
            startup="npm start",
            data_directory="/srv/discord-host/servers/85d8a5f9-4be2-4784-91c4-b4e80ea93fcb",
        )

        self.assertEqual(spec["name"], "dchost_85d8a5f94be2478491c4b4e80ea93fcb")
        self.assertEqual(spec["mem_limit"], 300 * 1024 * 1024)
        self.assertEqual(spec["nano_cpus"], 350_000_000)
        self.assertEqual(spec["command"], ["/bin/sh", "-lc", "npm start"])
        self.assertEqual(spec["working_dir"], "/home/container")
        self.assertEqual(spec["volumes"]["/srv/discord-host/servers/85d8a5f9-4be2-4784-91c4-b4e80ea93fcb"]["bind"], "/home/container")
        self.assertIn("ALL", spec["cap_drop"])
        self.assertIn("no-new-privileges:true", spec["security_opt"])

    def test_invalid_server_id_or_empty_startup_is_rejected(self):
        self.assertTrue(hasattr(container_spec, "build_container_spec"), "build_container_spec is not implemented")

        with self.assertRaises(ValueError):
            container_spec.build_container_spec("../escape", "Bad", "node:22-alpine", "npm start", "/tmp/data")
        with self.assertRaises(ValueError):
            container_spec.build_container_spec("85d8a5f9-4be2-4784-91c4-b4e80ea93fcb", "Bad", "node:22-alpine", "", "/tmp/data")


if __name__ == "__main__":
    unittest.main()

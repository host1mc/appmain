import tempfile
import unittest
from pathlib import Path
from unittest import mock

from node_agent import storage


class SafeStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resolve_path_keeps_files_inside_server_directory(self):
        self.assertTrue(hasattr(storage, "resolve_server_path"), "resolve_server_path is not implemented")

        resolved = storage.resolve_server_path(self.root, "src/bot.py")

        self.assertEqual(resolved, self.root / "src" / "bot.py")

    def test_resolve_path_rejects_traversal_and_absolute_paths(self):
        self.assertTrue(hasattr(storage, "resolve_server_path"), "resolve_server_path is not implemented")

        for candidate in ("../secret", "src/../../secret", "/etc/passwd", "C:\\Windows\\system.ini"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    storage.resolve_server_path(self.root, candidate)

    def test_write_and_list_text_file(self):
        self.assertTrue(hasattr(storage, "ServerStorage"), "ServerStorage is not implemented")
        manager = storage.ServerStorage(self.root)

        manager.write_text("src/bot.py", "print('ready')\n")
        listing = manager.list_directory("src")

        self.assertEqual(manager.read_text("src/bot.py"), "print('ready')\n")
        self.assertEqual(listing[0]["name"], "bot.py")
        self.assertFalse(listing[0]["is_directory"])

    def test_write_binary_file_creates_nested_folders(self):
        manager = storage.ServerStorage(self.root)

        manager.write_bytes("assets/icons/bot.png", b"\x89PNG\r\n\x1a\n")

        self.assertEqual((self.root / "assets" / "icons" / "bot.png").read_bytes(), b"\x89PNG\r\n\x1a\n")

    def test_upload_hands_the_file_and_its_new_folders_to_the_container_user(self):
        manager = storage.ServerStorage(self.root)
        chowned = []

        with mock.patch.object(storage, "_container_uid_gid", return_value=(1000, 1000)), \
                mock.patch.object(storage.os, "lchown", lambda path, uid, gid: chowned.append((path, uid, gid)), create=True):
            manager.write_bytes("archive/index.js", b"console.log(1)\n")

        self.assertEqual(
            [Path(path) for path, _, _ in chowned],
            [manager.root / "archive" / "index.js", manager.root / "archive", manager.root],
        )
        self.assertTrue(all((uid, gid) == (1000, 1000) for _, uid, gid in chowned))

    def test_hand_over_survives_a_chown_the_agent_is_not_allowed_to_make(self):
        manager = storage.ServerStorage(self.root)

        def refuse(path, uid, gid):
            raise PermissionError("agent is not root")

        with mock.patch.object(storage, "_container_uid_gid", return_value=(1000, 1000)), \
                mock.patch.object(storage.os, "lchown", refuse, create=True):
            manager.write_text("bot.py", "print('ready')\n")

        self.assertEqual(manager.read_text("bot.py"), "print('ready')\n")


if __name__ == "__main__":
    unittest.main()

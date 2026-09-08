import unittest

from node_agent import catalog


class RuntimeCatalogTests(unittest.TestCase):
    def test_supported_runtime_resolves_to_allowlisted_image(self):
        self.assertTrue(hasattr(catalog, "resolve_image"), "resolve_image is not implemented")

        self.assertEqual(catalog.resolve_image("nodejs", "22"), "node:22-alpine")
        self.assertEqual(catalog.resolve_image("python", "3.13"), "python:3.13-alpine")
        self.assertEqual(catalog.resolve_image("ruby", "3.3"), "ruby:3.3-alpine")
        self.assertEqual(catalog.resolve_image("go", "1.23"), "golang:1.23-alpine")
        self.assertEqual(catalog.resolve_image("php", "8.3"), "php:8.3-alpine")
        self.assertEqual(catalog.resolve_image("bun", "1"), "oven/bun:1-alpine")

    def test_unknown_runtime_or_version_is_rejected(self):
        self.assertTrue(hasattr(catalog, "resolve_image"), "resolve_image is not implemented")

        with self.assertRaises(ValueError):
            catalog.resolve_image("nodejs", "latest")
        with self.assertRaises(ValueError):
            catalog.resolve_image("cobol", "85")
        with self.assertRaises(ValueError):
            catalog.resolve_image("ruby", "2.7")

    def test_catalog_exposes_default_startup_commands(self):
        self.assertTrue(hasattr(catalog, "public_catalog"), "public_catalog is not implemented")

        runtimes = catalog.public_catalog()

        self.assertEqual(runtimes["nodejs"]["default_startup"], "npm install && node index.js")
        self.assertEqual(runtimes["python"]["default_startup"], "pip install -r requirements.txt && python main.py")


if __name__ == "__main__":
    unittest.main()

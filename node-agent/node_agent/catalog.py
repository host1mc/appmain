RUNTIMES = {
    "nodejs": {
        "label": "Node.js",
        "versions": {
            "18": "node:18-alpine",
            "20": "node:20-alpine",
            "22": "node:22-alpine",
            "24": "node:24-alpine",
        },
        "default_version": "22",
        "default_startup": "npm install && node index.js",
    },
    "python": {
        "label": "Python",
        "versions": {
            "3.10": "python:3.10-alpine",
            "3.11": "python:3.11-alpine",
            "3.12": "python:3.12-alpine",
            "3.13": "python:3.13-alpine",
        },
        "default_version": "3.13",
        "default_startup": "pip install -r requirements.txt && python main.py",
    },
    "ruby": {
        "label": "Ruby",
        "versions": {
            "3.1": "ruby:3.1-alpine",
            "3.2": "ruby:3.2-alpine",
            "3.3": "ruby:3.3-alpine",
            "3.4": "ruby:3.4-alpine",
        },
        "default_version": "3.3",
        "default_startup": "bundle install && ruby main.rb",
    },
    "go": {
        "label": "Go",
        "versions": {
            "1.21": "golang:1.21-alpine",
            "1.22": "golang:1.22-alpine",
            "1.23": "golang:1.23-alpine",
            "1.24": "golang:1.24-alpine",
        },
        "default_version": "1.23",
        "default_startup": "go run .",
    },
    "php": {
        "label": "PHP",
        "versions": {
            "8.1": "php:8.1-alpine",
            "8.2": "php:8.2-alpine",
            "8.3": "php:8.3-alpine",
            "8.4": "php:8.4-alpine",
        },
        "default_version": "8.3",
        "default_startup": "php main.php",
    },
    "bun": {
        "label": "Bun",
        "versions": {
            "1": "oven/bun:1-alpine",
            "1.1": "oven/bun:1.1-alpine",
            "1.2": "oven/bun:1.2-alpine",
        },
        "default_version": "1",
        "default_startup": "bun install && bun run index.ts",
    },
}


def resolve_image(runtime: str, version: str) -> str:
    runtime_config = RUNTIMES.get((runtime or "").strip().lower())
    if not runtime_config:
        raise ValueError("unsupported runtime")
    image = runtime_config["versions"].get((version or "").strip())
    if not image:
        raise ValueError("unsupported runtime version")
    return image


def public_catalog():
    return {
        runtime: {
            "label": config["label"],
            "versions": list(config["versions"].keys()),
            "default_version": config["default_version"],
            "default_startup": config["default_startup"],
        }
        for runtime, config in RUNTIMES.items()
    }

"""No-secret startup report for database-related environment settings."""

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / "fastapi-oracle-app" / ".env"
SHARD_SCAN_MAX = 64

SECRET_NAMES = {
    "ORACLE_PASSWORD",
    "ORACLE_WALLET_PASSWORD",
    "ENCRYPTION_KEY",
    "ENCRYPTION_PASSPHRASE",
    "ENCRYPTION_KEYS_OLD",
    "NODE_TOKEN",
    "INTERNAL_TOKEN",
}


def _read_env_file():
    data = {}
    try:
        with ENV_PATH.open(encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass
    return data


def _merged_env():
    file_env = _read_env_file()
    merged = dict(file_env)
    for key, value in os.environ.items():
        if value:
            merged[key] = value
    return merged, file_env


def _is_true(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _state(env, name, *, required=False):
    value = str(env.get(name, "") or "").strip()
    if value:
        return f"{name}=set" if name in SECRET_NAMES else f"{name}=set({len(value)} chars)"
    return f"{name}=MISSING" if required else f"{name}=unset"


def print_db_env_report(tier="app"):
    try:
        import reviews_db
        if not reviews_db.is_console_debug_enabled():
            return
    except Exception:
        return
    env, file_env = _merged_env()
    oracle_enabled = _is_true(env.get("ORACLE_ENABLED"))
    oracle_required = oracle_enabled
    shards = []
    invalid_shards = []
    for idx in range(SHARD_SCAN_MAX + 1):
        key = f"DB_{idx}"
        value = str(env.get(key, "") or "").strip()
        if not value:
            continue
        if value.startswith(("mongodb://", "mongodb+srv://")):
            shards.append(key)
        else:
            invalid_shards.append(key)

    source = str(ENV_PATH) if file_env else "process environment only"
    print(f"[{tier}] DB env check: source={source}", file=sys.stderr)
    print(
        f"[{tier}] DB env check: ORACLE_ENABLED={'true' if oracle_enabled else 'false'}; "
        + ", ".join(
            [
                _state(env, "ORACLE_USER", required=oracle_required),
                _state(env, "ORACLE_PASSWORD", required=oracle_required),
                _state(env, "ORACLE_DSN", required=oracle_required),
                _state(env, "ORACLE_WALLET_DIR"),
                _state(env, "ORACLE_WALLET_PASSWORD"),
            ]
        ),
        file=sys.stderr,
    )
    print(
        f"[{tier}] DB env check: Mongo shards initialized={len(shards)}"
        + (f" ({', '.join(shards)})" if shards else "")
        + (f"; invalid={', '.join(invalid_shards)}" if invalid_shards else ""),
        file=sys.stderr,
    )
    print(
        f"[{tier}] DB env check: PANEL_STORE={env.get('PANEL_STORE') or 'auto'}; "
        f"PANEL_AUTH_MODE={env.get('PANEL_AUTH_MODE') or 'oracle'}; "
        + ", ".join(
            [
                _state(env, "PANEL_DATABASE_PATH"),
                _state(env, "ORACLE_POOL_MAX"),
                _state(env, "PANEL_ORACLE_POOL_MAX"),
            ]
        ),
        file=sys.stderr,
    )

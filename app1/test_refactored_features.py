"""
test_refactored_features.py — Verification test suite for ATP user encryption,
HeatWave review embed storage, app error logging & admin flagging, and hidden
container configuration & file hiding.
"""

import os
import re
import json
import sqlite3
import sys
import types
import tempfile
from unittest.mock import MagicMock

# Set mock env so database.py can import
os.environ["ORACLE_ENABLED"] = "true"
os.environ["ORACLE_USER"] = "mock_user"
os.environ["ORACLE_PASSWORD"] = "mock_pass"
os.environ["ORACLE_DSN"] = "mock_dsn"

try:
    import oracledb
except ImportError:
    oracledb = types.ModuleType("oracledb")
    oracledb.defaults = types.SimpleNamespace(fetch_lobs=True, connect_timeout=0)
    oracledb.DatabaseError = type("DatabaseError", (Exception,), {})
    sys.modules["oracledb"] = oracledb

oracledb.create_pool = MagicMock()

import database as db
import crypto_util
import reviews_db
from panel_app.node_client import NodeClient
from panel_app.routes import _check_relative_path


class SQLiteWrapper:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self, dictionary=False):
        return MySQLCursorWrapper(self._conn.cursor(), dictionary=dictionary)

    def commit(self):
        self._conn.commit()

    def close(self):
        pass


class MySQLCursorWrapper:
    def __init__(self, cur, dictionary=False):
        self._cur = cur
        self.dictionary = dictionary

    def execute(self, sql, params=None):
        sql = re.sub(r'FETCH FIRST (\d+) ROWS ONLY', r'LIMIT \1', sql, flags=re.IGNORECASE)
        if params is not None and isinstance(params, dict):
            # convert %(name)s to :name
            sql = re.sub(r'%\((\w+)\)s', r':\1', sql)
            # convert NOW() or CURRENT_TIMESTAMP
            sql = sql.replace("NOW()", "CURRENT_TIMESTAMP")
        elif params is not None and isinstance(params, (list, tuple)):
            sql = sql.replace("%s", "?")
            sql = sql.replace("NOW()", "CURRENT_TIMESTAMP")
        try:
            return self._cur.execute(sql, params or ())
        except Exception as e:
            print("SQL EXECUTE ERROR:", e, "SQL:", sql, "PARAMS:", params)
            raise

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        if self.dictionary:
            return dict(row) if hasattr(row, "keys") else row
        return tuple(row) if hasattr(row, "keys") else row

    def fetchall(self):
        rows = self._cur.fetchall()
        if not rows:
            return []
        if self.dictionary:
            return [dict(r) if hasattr(r, "keys") else r for r in rows]
        return [tuple(r) if hasattr(r, "keys") else r for r in rows]

    @property
    def lastrowid(self):
        return self._cur.lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description


def test_atp_user_schema_and_encryption():
    print("Testing ATP User Schema & Encryption...")

    # Create SQLite in-memory database matching users table schema
    sqlite_conn = sqlite3.connect(":memory:")
    sqlite_conn.row_factory = sqlite3.Row
    cur = sqlite_conn.cursor()

    cur.execute("""
        CREATE TABLE users (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36),
            username VARCHAR(255) NOT NULL,
            username_lookup_hash VARCHAR(64) UNIQUE,
            username_ci_lookup_hash VARCHAR(64),
            email VARCHAR(255),
            email_lookup_hash VARCHAR(64) UNIQUE,
            password VARCHAR(255),
            display_name VARCHAR(255),
            slots VARCHAR(10) DEFAULT '1',
            tier VARCHAR(32) DEFAULT 'trial',
            account_type VARCHAR(32) DEFAULT 'trial',
            is_active INTEGER DEFAULT 1,
            is_banned INTEGER DEFAULT 0,
            ads_disabled INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            trial_ends_at VARCHAR(32),
            trial_expires_at VARCHAR(32),
            created_at VARCHAR(32),
            ban_reason VARCHAR(1000),
            unbanned_at VARCHAR(32),
            unban_reason VARCHAR(1000),
            embed_slots INTEGER DEFAULT 1,
            container_slots INTEGER DEFAULT 1,
            discord_bot_token TEXT,
            webhook_token TEXT,
            fingerprint_ip TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id VARCHAR(36),
            slot_index INTEGER DEFAULT 0,
            name VARCHAR(255),
            server_ip VARCHAR(255),
            server_port INTEGER,
            edition VARCHAR(32),
            token VARCHAR(255),
            token_enc TEXT,
            guild_id VARCHAR(64),
            channel_id VARCHAR(64),
            webhook_url VARCHAR(512),
            update_interval INTEGER DEFAULT 60,
            running INTEGER DEFAULT 0,
            last_run VARCHAR(32),
            last_error TEXT,
            last_status TEXT,
            embed_json TEXT,
            ip_reply_json TEXT,
            created_at VARCHAR(32)
        )
    """)
    cur.execute("CREATE TABLE sessions (id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(36), data TEXT, created_at VARCHAR(32))")
    cur.execute("CREATE TABLE fingerprints (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id VARCHAR(36), fingerprint VARCHAR(255))")
    cur.execute("CREATE TABLE device_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id VARCHAR(36))")
    cur.execute("CREATE TABLE user_ad_zone_overrides (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id VARCHAR(36))")
    cur.execute("CREATE TABLE user_ad_disabled (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id VARCHAR(36))")
    sqlite_conn.commit()

    # Mock db._oracle_conn to return sqlite_conn wrapper
    db._oracle_conn = lambda: SQLiteWrapper(sqlite_conn)

    # Test user creation
    username = "testuser_enc"
    password = "Password123!"
    display = "Test User Enc"
    email = "testuser_enc@gmail.com"

    ok, user_id = db.create_user(
        username=username,
        password=password,
        display_name=display,
        slots=1,
        email=email,
        account_type="trial",
    )
    assert ok, f"User creation failed: {user_id}"

    user = db.get_user(user_id)
    assert user is not None, "get_user returned None"
    assert user["id"] == user["user_id"], f"id ({user['id']}) != user_id ({user['user_id']})"

    # Test token update
    bot_token = "bot_token_secret_123"
    webhook = "https://discord.com/api/webhooks/123/xyz"
    db.update_user_atp_tokens(user_id, discord_bot_token=bot_token, webhook_token=webhook)

    # Test fingerprint_ip update
    fp_ip = "hash_fp_123_192.168.1.1"
    db.update_user_atp_fingerprint_ip(user_id, fp_ip)

    # Test slots update
    db.update_user_atp_slots(user_id, embed_slots=5, container_slots=3)

    # Retrieve user and verify decrypted values
    updated_user = db.get_user(user_id)
    assert updated_user["discord_bot_token"] == bot_token, f"Decrypted bot_token mismatch: {updated_user.get('discord_bot_token')}"
    assert updated_user["webhook_token"] == webhook, f"Decrypted webhook mismatch: {updated_user.get('webhook_token')}"
    assert updated_user["fingerprint_ip"] == fp_ip, f"Decrypted fingerprint_ip mismatch: {updated_user.get('fingerprint_ip')}"
    assert updated_user["embed_slots"] == 5
    assert updated_user["container_slots"] == 3

    # Check raw ciphertext in database
    cur.execute("SELECT discord_bot_token, webhook_token, fingerprint_ip FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    assert row[0] != bot_token, "bot_token is stored in plaintext!"
    assert row[1] != webhook, "webhook_token is stored in plaintext!"
    assert row[2] != fp_ip, "fingerprint_ip is stored in plaintext!"

    # Clean up user
    try:
        db.delete_user(user_id)
    except Exception:
        pass
    sqlite_conn.close()
    print("  ✓ ATP User Schema & Encryption verified!")


def test_heatwave_reviews_embed_json_and_errors():
    print("Testing HeatWave Review Embed Storage & Error Logging...")

    # Mock HeatWave MySQL pool using SQLite
    hw_conn = sqlite3.connect(":memory:")
    hw_conn.row_factory = sqlite3.Row
    cur = hw_conn.cursor()

    cur.execute("""
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id VARCHAR(64) NOT NULL,
            author_name VARCHAR(100) NOT NULL,
            rating INTEGER NOT NULL,
            body TEXT NOT NULL,
            approved INTEGER DEFAULT 0,
            status VARCHAR(20) DEFAULT 'pending',
            embed_json LONGTEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE app_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            error_type VARCHAR(255) NOT NULL,
            error_category VARCHAR(50) DEFAULT 'system_error',
            message TEXT,
            stack_trace TEXT,
            module VARCHAR(100) DEFAULT 'app',
            flag_reason VARCHAR(255),
            flagged INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    hw_conn.commit()

    reviews_db._ENABLED = True
    reviews_db._SCHEMA_READY = True
    mock_pool = MagicMock()
    mock_pool.get_connection.side_effect = lambda: SQLiteWrapper(hw_conn)
    reviews_db._pool = lambda: mock_pool

    # Test embed_json in create_review
    embed_data = {
        "title": "Awesome Bot",
        "description": "This bot status page is amazing!",
        "color": "#7289da"
    }
    user_id = "test_rev_user_123"
    author_name = "Reviewer One"
    rating = 5
    body = "Great service and super fast setup!"

    ok = reviews_db.create_review(
        user_id=user_id,
        author_name=author_name,
        rating=rating,
        body=body,
        embed_json=embed_data
    )
    assert ok, "create_review failed"

    all_revs = reviews_db.get_reviews(state="all")
    found = None
    for r in all_revs:
        if r.get("user_id") == user_id:
            found = r
            break

    assert found is not None, "Created review not found"
    assert found.get("embed_json") == embed_data or found.get("embed") == embed_data, f"embed_json mismatch: {found.get('embed_json')}"
    assert int(found.get("approved") or 0) == 1, "Review was not auto-approved by default"

    # Test 1 review per user limit (updating existing user review)
    ok_update = reviews_db.create_review(
        user_id=user_id,
        author_name=author_name,
        rating=4,
        body="Updated review text",
        embed_json=embed_data
    )
    assert ok_update, "Updating existing user review failed"
    revs_after = reviews_db.get_approved_reviews()
    user_revs = [r for r in revs_after if r.get("author_name") == author_name]
    assert len(user_revs) == 1, f"User has more than 1 review: {len(user_revs)}"

    # Test app_errors logging & admin flagging
    error_type = "ZeroDivisionError"
    message = "division by zero"
    stack_trace = "Traceback:\n  x = 1 / 0\nZeroDivisionError: division by zero"
    module = "backend"

    err_id = reviews_db.log_app_error(
        error_type=error_type,
        message=message,
        stack_trace=stack_trace,
        module=module,
        flagged=1
    )
    assert err_id > 0, "log_app_error failed to return valid ID"

    errors = reviews_db.get_app_errors(limit=50, only_flagged=True)
    found_err = None
    for e in errors:
        if e.get("id") == err_id:
            found_err = e
            break

    assert found_err is not None, "Logged error not found"
    assert found_err["error_type"] == error_type
    assert found_err["message"] == message
    assert found_err["module"] == module
    assert found_err["flagged"] == 1

    flagged_count = reviews_db.count_flagged_app_errors()
    assert flagged_count >= 1

    ok = reviews_db.flag_app_error(err_id, flagged=0)
    assert ok

    deleted = reviews_db.delete_app_error(err_id)
    assert deleted > 0

    # Test HeatWave app_config and console debug toggle
    reviews_db.set_console_debug_enabled(False)
    assert not reviews_db.is_console_debug_enabled(), "Console debug should be disabled"

    reviews_db.set_console_debug_enabled(True)
    assert reviews_db.is_console_debug_enabled(), "Console debug should be enabled"

    reviews_db.set_console_debug_enabled(False)
    assert not reviews_db.is_console_debug_enabled(), "Console debug should be disabled again"

    # Test catalog fetch / node errors being logged to HeatWave DB
    node_err_id = reviews_db.log_app_error(
        error_type="NodeCatalogFetchFailed",
        message="catalog fetch failed: no reachable node in the database — all nodes are down",
        module="panel_app",
        flagged=1,
        flag_reason="node_down"
    )
    assert node_err_id > 0, "Node error logging to HeatWave DB failed"
    node_errs = reviews_db.get_app_errors(only_flagged=True)
    found_node_err = any(e.get("id") == node_err_id for e in node_errs)
    assert found_node_err, "Catalog fetch error was not found in HeatWave DB app_errors"

    hw_conn.close()
    print("  ✓ HeatWave Review Embed Storage & App Error Logging verified!")


def test_container_hidden_config_and_file_hiding():
    print("Testing Container Hidden Configuration & File Hiding...")

    # Test file path validation for hidden files
    try:
        _check_relative_path(".container_config.json", allow_hidden=False)
        assert False, "_check_relative_path should have raised ValueError for hidden file"
    except ValueError as e:
        assert "hidden" in str(e).lower()

    try:
        _check_relative_path("subfolder/.env", allow_hidden=False)
        assert False, "_check_relative_path should have raised ValueError for hidden dotfile in folder"
    except ValueError as e:
        assert "hidden" in str(e).lower()

    normal = _check_relative_path("server.properties")
    assert normal == "server.properties"

    # Test NodeClient.list_files filtering
    class MockNodeClient(NodeClient):
        def __init__(self):
            self._urls = ["http://127.0.0.1:9000"]
            self.token = "mock"
            self.timeout = 1
            self._active = 0

        def _request(self, method, path, payload=None, query=None, timeout=None):
            if path.endswith("/files"):
                return {
                    "ok": True,
                    "files": [
                        {"name": "server.jar", "size": 1024, "is_dir": False},
                        {"name": ".container_config.json", "size": 256, "is_dir": False},
                        {"name": ".env", "size": 100, "is_dir": False},
                        {"name": "plugins", "size": 0, "is_dir": True},
                        {"name": ".git", "size": 0, "is_dir": True}
                    ]
                }
            elif path.endswith("/file") and method == "GET":
                return {"ok": True, "content": "{}"}
            elif path.endswith("/file") and method == "PUT":
                return {"ok": True}
            return {"ok": True}

    client = MockNodeClient()
    res = client.list_files("server_123")
    filenames = [item["name"] for item in res["files"]]
    assert ".container_config.json" not in filenames, f"Hidden file in list_files: {filenames}"
    assert ".env" not in filenames, f"Hidden file in list_files: {filenames}"
    assert ".git" not in filenames, f"Hidden directory in list_files: {filenames}"
    assert "server.jar" in filenames
    assert "plugins" in filenames

    # Test update_container_config
    written_data = {}
    def mock_write_file(server_id, path, content):
        nonlocal written_data
        written_data[path] = json.loads(content)
        return {"ok": True}

    client.write_file = mock_write_file
    client.update_container_config("server_123", {
        "server_id": "server_123",
        "last_state": "running",
        "total_allocated_space": 300,
        "startup_parameters": "java -Xmx300M -jar server.jar"
    })

    assert ".container_config.json" in written_data
    cfg = written_data[".container_config.json"]
    assert cfg["server_id"] == "server_123"
    assert cfg["last_state"] == "running"
    assert cfg["total_allocated_space"] == 300
    assert cfg["startup_parameters"] == "java -Xmx300M -jar server.jar"
    assert "updated_at" in cfg

    print("  ✓ Container Hidden Configuration & File Hiding verified!")


def test_is_admin_removal():
    print("Testing Complete Removal of is_admin across Codebase...")
    import inspect
    import backend
    import panel_data
    import panel_app.panel_database as pdb
    import panel_app.store as pstore
    import panel_app.backend_store as bstore

    # Verify method signatures do not accept is_admin
    assert "is_admin" not in inspect.signature(panel_data.ensure_user_by_id).parameters
    assert "is_admin" not in inspect.signature(panel_data.create_user).parameters
    assert "is_admin" not in inspect.signature(pdb.PanelDatabase.ensure_user_by_id).parameters
    assert "is_admin" not in inspect.signature(pdb.PanelDatabase.create_user).parameters
    assert "is_admin" not in inspect.signature(pstore.OracleStore.ensure_user_by_id).parameters
    assert "is_admin" not in inspect.signature(pstore.OracleStore.create_user).parameters
    assert "is_admin" not in inspect.signature(bstore.BackendStore.ensure_user_by_id).parameters
    assert "is_admin" not in inspect.signature(bstore.BackendStore.create_user).parameters

    # Verify PanelUser model has no is_admin attribute
    from panel_app.oracle_models import PanelUser
    assert not hasattr(PanelUser, "is_admin")

    print("  ✓ Complete Removal of is_admin verified!")


def test_repeat_registration_flagging():
    print("Testing Multi-Account Repeat Registration Flagging...")
    hw_conn = sqlite3.connect(":memory:")
    hw_conn.row_factory = sqlite3.Row
    cur = hw_conn.cursor()

    cur.execute("""
        CREATE TABLE app_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            error_type VARCHAR(255) NOT NULL,
            error_category VARCHAR(50) DEFAULT 'system_error',
            message TEXT,
            stack_trace TEXT,
            module VARCHAR(100) DEFAULT 'app',
            flag_reason VARCHAR(255),
            flagged INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    hw_conn.commit()

    reviews_db._ENABLED = True
    reviews_db._SCHEMA_READY = True
    mock_pool = MagicMock()
    mock_pool.get_connection.side_effect = lambda: SQLiteWrapper(hw_conn)
    reviews_db._pool = lambda: mock_pool

    err_id = reviews_db.log_app_error(
        error_type="MultiAccountRegistrationFlag",
        message="Multiple accounts detected for username 'user2' on same fingerprint/IP",
        stack_trace=json.dumps({"attempted_username": "user2", "flag_reason": "same_device"}),
        module="registration",
        flagged=1,
        flag_reason="same_device"
    )
    assert err_id > 0

    errors = reviews_db.get_app_errors(only_flagged=True)
    assert len(errors) == 1
    assert errors[0]["error_type"] == "MultiAccountRegistrationFlag"
    assert errors[0]["flag_reason"] == "same_device"
    assert errors[0]["flagged"] == 1
    print("  ✓ Multi-Account Repeat Registration Flagging verified!")


def test_argon2_otp_and_email_templates():
    print("Testing Argon2id OTP Hashing & Email Templates...")
    import email_templates

    # Test Email Template Generation
    subj, plain, html_out = email_templates.build_otp_email("user@example.com", "123456")
    assert "123456" in plain
    assert "123456" in html_out
    assert "Security Verification Code" in html_out

    subj_w, plain_w, html_w = email_templates.build_welcome_email("user@example.com", "testuser")
    assert "testuser" in plain_w
    assert "Welcome" in subj_w

    # Test Argon2id OTP Hashing
    sqlite_conn = sqlite3.connect(":memory:")
    sqlite_conn.row_factory = sqlite3.Row
    cur = sqlite_conn.cursor()
    cur.execute("""
        CREATE TABLE otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255),
            email_lookup_hash VARCHAR(64),
            code VARCHAR(255),
            purpose VARCHAR(64),
            expires_at VARCHAR(64),
            created_at VARCHAR(64),
            attempts INTEGER DEFAULT 0,
            used INTEGER DEFAULT 0
        )
    """)
    sqlite_conn.commit()

    db._oracle_conn = lambda: SQLiteWrapper(sqlite_conn)

    email = "test_argon2_otp@example.com"
    code = db.generate_otp(email, purpose="register")
    assert code is not None and len(code) == 6

    # Verify code is stored as Argon2id hash in database
    cur.execute("SELECT code FROM otp_codes WHERE email_lookup_hash = ?", (db.lookup_hash(email),))
    stored_hash = cur.fetchone()[0]
    assert stored_hash.startswith("$argon2id$"), f"OTP code is not hashed with Argon2id: {stored_hash}"

    # Verify correct OTP code succeeds
    ok = db.verify_otp(email, code, purpose="register", mark_used=True)
    assert ok, "Argon2id OTP verification failed for correct code"

    # Verify invalid OTP code fails
    ok_bad = db.verify_otp(email, "999999", purpose="register")
    assert not ok_bad, "Argon2id OTP verification passed for invalid code"

    sqlite_conn.close()
    print("  ✓ Argon2id OTP Hashing & Email Templates verified!")


def test_engine_webhook_interval_scheduling():
    print("Testing Engine Webhook & Recurring Interval Scheduling...")
    import engine
    from datetime import datetime, timedelta, timezone

    sqlite_conn = sqlite3.connect(":memory:")
    sqlite_conn.row_factory = sqlite3.Row
    cur = sqlite_conn.cursor()
    cur.execute("""
        CREATE TABLE bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id VARCHAR(36),
            name VARCHAR(255),
            server_ip VARCHAR(255),
            server_port INTEGER DEFAULT 25565,
            edition VARCHAR(32) DEFAULT 'java',
            token_enc VARCHAR(500),
            guild_id VARCHAR(255),
            channel_id VARCHAR(255),
            webhook_url VARCHAR(500),
            update_interval INTEGER DEFAULT 60,
            message_id VARCHAR(255),
            embed_json VARCHAR(4000),
            ip_reply_json VARCHAR(4000),
            running INTEGER DEFAULT 0,
            last_run VARCHAR(64),
            last_status VARCHAR(4000),
            last_error VARCHAR(4000),
            updated_at VARCHAR(64)
        )
    """)
    sqlite_conn.commit()

    db._oracle_conn = lambda: SQLiteWrapper(sqlite_conn)

    # Insert a test bot with webhook URL and update_interval = 30s
    webhook_url = "https://discord.com/api/webhooks/123456/test_token"
    cur.execute("""
        INSERT INTO bots(user_id, server_ip, webhook_url, update_interval, running)
        VALUES('u-test', 'play.example.com', ?, 30, 0)
    """, (db.encrypt(webhook_url),))
    sqlite_conn.commit()
    bot_id = cur.lastrowid

    # Test initial claim when last_run is NULL
    ok_first_claim = db.claim_bot_tick(bot_id, 30)
    assert ok_first_claim, "Initial claim_bot_tick failed for new bot"

    # Immediately subsequent claim_bot_tick should be refused (interval not elapsed)
    ok_immediate_claim = db.claim_bot_tick(bot_id, 30)
    assert not ok_immediate_claim, "claim_bot_tick should refuse immediate re-claim before interval"

    # Verify that when interval (30s) elapses, claim_bot_tick succeeds
    now_dt = db._shared_utcnow()
    past_dt = now_dt - timedelta(seconds=35)
    cur.execute("UPDATE bots SET last_run=? WHERE id=?", (past_dt.isoformat(), bot_id))
    sqlite_conn.commit()

    ok_elapsed_claim = db.claim_bot_tick(bot_id, 30)
    assert ok_elapsed_claim, "claim_bot_tick failed after interval elapsed"

    # Verify set_bot_running works and list_running_bots returns active bot
    db.set_bot_running(bot_id, True)
    running_bots = db.list_running_bots()
    assert any(b["id"] == bot_id for b in running_bots), "Bot was not returned in list_running_bots when running=1"

    sqlite_conn.close()
    print("  ✓ Engine Webhook & Recurring Interval Scheduling verified!")


if __name__ == "__main__":
    test_atp_user_schema_and_encryption()
    test_heatwave_reviews_embed_json_and_errors()
    test_container_hidden_config_and_file_hiding()
    test_is_admin_removal()
    test_repeat_registration_flagging()
    test_argon2_otp_and_email_templates()
    test_engine_webhook_interval_scheduling()
    print("\nALL REFACTORED FEATURES VERIFIED SUCCESSFULLY! 🎉")

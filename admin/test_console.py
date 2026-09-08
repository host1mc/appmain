"""
test_console.py — drive every page and every API of the local admin console.

The console has no HTTP hop to mock and no engine to stand up: it imports
`database` directly, so a Flask test client is enough to exercise the whole
surface. That is the point of this check — the console is the only way the
project is administered now, so "the page renders" and "the write actually
landed in the database" have to be verified together rather than by clicking.

Oracle is the only backend, so there is no throwaway file to run against any
more and isolation has to be engineered. This suite REFUSES TO RUN unless it can
prove three things, in order (see `_require_isolated_schema`):

  1. ADMIN_TEST_ALLOW_ORACLE=1 — the operator opted in on purpose
  2. ADMIN_TEST_ORACLE_USER matches the schema the wallet actually connects as —
     the wallet, not this file, decides where writes go, so the operator has to
     name the schema they expect and be right about it
  3. a `zz_test_schema_marker` row exists in that schema's settings table — a
     human plants this once, by hand, in a disposable schema. Production does not
     have one and cannot grow one by accident, so this is the check that keeps a
     stray wallet from turning a test run into a production write.

Any of those failing is a hard exit before a single fixture is created. The
suite never runs DDL and never DROPs or TRUNCATEs: fixtures are additive rows
carrying a per-run `zz_test_<uuid>_` prefix, and teardown deletes exactly those.
The settings table is global and has no tenant column, so the keys this suite
writes (the admin credential, SMTP, the ad switches) are snapshotted as raw
ciphertext up front and written back verbatim in a `finally`.

What it asserts, beyond status codes:
  * every page and API answers without any session — the console's only
    control is the loopback bind, so everything has to hold without a login
  * every write is read back out of the database, not just acknowledged
  * the SMTP GET never returns the credentials, and /admin/database never
    renders a password
  * every action lands in the admin log

Run: ADMIN_TEST_ALLOW_ORACLE=1 ADMIN_TEST_ORACLE_USER=<schema> python test_console.py
     → "admin console self-check OK"
"""

import os
import sys
import uuid

# The console reaches the engine over HTTP. Nothing is listening here, and that is
# a case the fleet page has to survive — point it somewhere that refuses fast.
os.environ["ENGINE_URL"] = "http://127.0.0.1:1"

RUN_ID = uuid.uuid4().hex[:8]
PREFIX = f"zz_test_{RUN_ID}_"
USERNAME = PREFIX + "consoleuser"

# The marker a human plants by hand in a disposable schema. Never written here:
# if this suite could create it, it would create it in production too.
MARKER_KEY = "zz_test_schema_marker"

# The ad page whose per-page switch phase_ads flips. Named up here rather than
# inside the phase because TOUCHED_SETTINGS has to snapshot the row that phase
# writes, and the two must not drift apart. "index" is the steadiest entry in
# database.AD_PAGES — the site's home page, ad-bearing and on by default.
AD_PAGE = "index"

# Global settings rows this suite overwrites. There is no tenant column on
# `settings`, so these are saved as raw ciphertext and restored verbatim. Keys
# that have never been written belong here too — the guard, consent and per-page
# switches usually have no row at all until this suite writes one — because
# _snapshot_settings records absence explicitly and _restore_settings deletes an
# absent key rather than inventing a row for it.
TOUCHED_SETTINGS = (
    "smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from",
    "ads_enabled",
    "ad_zone_social_bar", "ad_zone_banner_160x300", "ad_zone_banner_468x60",
    "ad_zone_banner_300x250", "ad_zone_native", "ad_zone_banner_160x600",
    "ad_zone_leaderboard", "ad_zone_mobile", "ad_zone_popunder_entry",
    "ad_guard_mode", "ad_consent_required", f"ad_page_{AD_PAGE}",
)


def _refuse(reason):
    """Fail closed. Isolation is unproven, so nothing has been created yet."""
    print("!" * 72)
    print("[test_console] REFUSING TO RUN — test isolation is not established")
    print(f"[test_console] reason: {reason}")
    print("[test_console] This suite writes users, bots and settings. Oracle is the")
    print("[test_console] only backend and the ATP is shared, so it will not run")
    print("[test_console] without proof it is pointed at a disposable schema.")
    print("!" * 72)
    sys.exit(2)


if os.environ.get("ADMIN_TEST_ALLOW_ORACLE", "").strip() != "1":
    _refuse("ADMIN_TEST_ALLOW_ORACLE=1 is not set. A bare `python test_console.py` "
            "does not get to touch Oracle.")

EXPECT_USER = (os.environ.get("ADMIN_TEST_ORACLE_USER") or "").strip()
if not EXPECT_USER:
    _refuse("ADMIN_TEST_ORACLE_USER is not set. Name the schema you expect to "
            "write to, so a mis-pointed wallet is a refusal and not a surprise.")

# Oracle is the only backend now; the module raises at import if it is disabled.
os.environ["ORACLE_ENABLED"] = "true"

import admin_app  # noqa: E402  (imports _bootstrap, which reads the env above)
import database as db  # noqa: E402

FAILED = []


def check(label, cond, extra=""):
    if cond:
        print(f"  ok   {label}")
    else:
        FAILED.append(label)
        print(f"  FAIL {label} {extra}")


def body(resp):
    """Decoded JSON, or {} for a page response — keeps the call sites short."""
    try:
        return resp.get_json(silent=True) or {}
    except Exception:
        return {}


def _scalar(row):
    return None if row is None else row[0]


def _require_isolated_schema():
    """Prove the connection lands in a disposable schema, or exit non-zero.

    Runs before any fixture exists, so a refusal leaves nothing behind.
    """
    if not getattr(db, "_ORACLE_ENABLED", False):
        _refuse("database._ORACLE_ENABLED is false — Oracle did not come up, and "
                "there is no other backend to fall back to.")
    conn = None
    try:
        conn = db._user_conn()
    except Exception as ex:
        _refuse(f"could not open an Oracle connection: {type(ex).__name__}: {ex}")
    try:
        cur = conn.cursor()
        cur.execute("SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual")
        actual = str(_scalar(cur.fetchone()) or "")
        if actual.upper() != EXPECT_USER.upper():
            _refuse(f"connected as schema {actual!r}, but ADMIN_TEST_ORACLE_USER "
                    f"says {EXPECT_USER!r}. The wallet decides where writes go, "
                    "and it disagrees with you.")
        cur.execute("SELECT COUNT(*) FROM settings WHERE key=:k", {"k": MARKER_KEY})
        if int(_scalar(cur.fetchone()) or 0) != 1:
            _refuse(f"schema {actual!r} has no {MARKER_KEY!r} row in `settings`. "
                    "Plant one by hand in a disposable schema to mark it as safe "
                    "to write to:  INSERT INTO settings(key,value) "
                    f"VALUES('{MARKER_KEY}','yes'); COMMIT;")
    finally:
        conn.close()
    print(f"[test_console] isolation OK: schema {EXPECT_USER}, marker present, "
          f"fixtures prefixed {PREFIX}")


def _snapshot_settings(keys):
    """Raw ciphertext of every global key this suite overwrites.

    Read and restored raw, never through get_setting/set_setting: a decrypt and
    re-encrypt round trip would rewrite stored ciphertext under whichever key
    this machine happens to hold. Missing keys are recorded as absent so restore
    can delete rather than invent a row.
    """
    conn = db._user_conn()
    try:
        cur = conn.cursor()
        snap = {}
        for key in keys:
            cur.execute("SELECT value FROM settings WHERE key=:k", {"k": key})
            row = cur.fetchone()
            snap[key] = (row is not None, _scalar(row))
        return snap
    finally:
        conn.close()


def _restore_settings(snap):
    """Put every touched global key back exactly as it was found."""
    conn = db._user_conn()
    try:
        cur = conn.cursor()
        for key, (existed, value) in snap.items():
            cur.execute("DELETE FROM settings WHERE key=:k", {"k": key})
            if existed:
                cur.execute("INSERT INTO settings(key,value) VALUES(:k,:v)",
                            {"k": key, "v": value})
        conn.commit()
    finally:
        conn.close()


def _cleanup(user_id, sids):
    """Delete every row this run created. Safe to call twice, and never fatal.

    delete_user() covers users, bots, fingerprints and sessions; device_events
    and the zone overrides are keyed by user_id but are not in its sweep, so they
    are removed here. Deletes are by this run's own ids only — no TRUNCATE, no
    DDL, nothing that touches another run's rows.
    """
    conn = None
    try:
        conn = db._user_conn()
        cur = conn.cursor()
        if user_id is not None:
            uid = str(user_id)
            cur.execute("DELETE FROM device_events WHERE user_id=:id", {"id": uid})
            cur.execute("DELETE FROM user_ad_zone_overrides WHERE user_id=:id", {"id": uid})
            cur.execute("DELETE FROM sessions WHERE user_id=:id", {"id": uid})
        for sid in sids:
            cur.execute("DELETE FROM sessions WHERE id=:id", {"id": sid})
        # Any user this run seeded, by its own unique prefix.
        cur.execute("SELECT id FROM users WHERE username LIKE :p", {"p": PREFIX + "%"})
        stale = [str(r[0]) for r in cur.fetchall()]
        for stale_id in stale:
            cur.execute("DELETE FROM device_events WHERE user_id=:id", {"id": stale_id})
            cur.execute("DELETE FROM user_ad_zone_overrides WHERE user_id=:id", {"id": stale_id})
        conn.commit()
        for stale_id in stale:
            db.delete_user(stale_id)
    except Exception as ex:
        print(f"[test_console] WARNING: cleanup did not complete: "
              f"{type(ex).__name__}: {ex}")
        print(f"[test_console] look for rows named {PREFIX}* and remove them by hand")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


PAGES = ("/admin", "/admin/flags", "/admin/bots", "/admin/ads",
         "/admin/account", "/admin/database")

# No row can carry these, so they exercise the not-found paths. Oracle keys users
# by a uuid string, so the old numeric 999999 would not have matched a real row
# either — but a well-formed uuid proves the 404 is "no such user" and not a
# rejected id format.
MISSING_ID = str(uuid.uuid4())


def phase_auth(c):
    """No login gate: pages and APIs answer directly. The console binds
    loopback and is started by hand, so the old login routes only forward."""
    r = c.get("/admin")
    check("/admin opens without signing in", r.status_code == 200, r.status_code)
    r = c.get("/api/admin/users")
    check("an API call works without a session", r.status_code == 200, r.status_code)
    check("it answers JSON", isinstance(r.get_json(), list), r.data[:60])
    r = c.get("/admin/login")
    check("the old login page forwards to the panel", r.status_code == 302
          and "/admin" in (r.headers.get("Location") or ""),
          (r.status_code, r.headers.get("Location")))
    r = c.post("/admin/login", data={"username": "admin", "password": "wrong-one"})
    check("login credentials are ignored, it still forwards", r.status_code == 302
          and "/admin" in (r.headers.get("Location") or ""),
          (r.status_code, r.headers.get("Location")))
    r = c.get("/admin/logout")
    check("logout forwards to the panel", r.status_code == 302
          and "/admin" in (r.headers.get("Location") or ""),
          (r.status_code, r.headers.get("Location")))


def phase_pages(c, user_id):
    """Every page renders for a signed-in admin."""
    for path in PAGES:
        r = c.get(path)
        check(f"GET {path} renders", r.status_code == 200, r.status_code)
    r = c.get(f"/admin/user/{user_id}")
    check("GET /admin/user/<id> renders", r.status_code == 200, r.status_code)
    r = c.get(f"/admin/fingerprint/{user_id}")
    check("GET /admin/fingerprint/<id> renders", r.status_code == 200, r.status_code)
    check("an unknown user's fingerprint page is 404",
          c.get(f"/admin/fingerprint/{MISSING_ID}").status_code == 404)


def phase_users(c, user_id):
    """The user tab. Every write is read back out of the database."""
    r = c.get("/api/admin/users")
    users = r.get_json()
    check("the user list is a JSON array", isinstance(users, list) and users, r.status_code)
    check("no password column reaches the browser",
          all("password" not in u for u in users), [k for k in users[0]])

    r = c.get(f"/api/admin/users/{user_id}")
    d = body(r)
    check("the user detail call answers", d.get("ok") is True, r.status_code)
    check("it carries bots, fingerprint and flags",
          "bots" in d and "fingerprint" in d and "flags" in d, sorted(d))
    check("no plaintext bot token reaches the browser",
          all("token" not in b and "token_enc" not in b for b in d.get("bots", [])),
          [sorted(b) for b in d.get("bots", [])][:1])
    check("the masked token is what the page gets instead",
          all("token_masked" in b for b in d.get("bots", [])))

    c.put(f"/api/admin/users/{user_id}/slots", json={"slots": 3})
    check("slots landed in the database", db.get_user(user_id)["slots"] == 3,
          db.get_user(user_id)["slots"])
    c.put(f"/api/admin/users/{user_id}/account-type", json={"account_type": "paid"})
    check("account type landed", db.get_user(user_id)["account_type"] == "paid",
          db.get_user(user_id)["account_type"])
    r = c.put(f"/api/admin/users/{user_id}/account-type", json={"account_type": "gold"})
    check("an unknown account type is rejected", r.status_code == 400, r.status_code)

    c.post(f"/api/admin/users/{user_id}/ban")
    check("the ban landed", db.is_user_banned(user_id)[0])
    c.post(f"/api/admin/users/{user_id}/unban")
    check("the unban landed", not db.is_user_banned(user_id)[0])

    c.put(f"/api/admin/users/{user_id}/email-verified", json={"verified": True})
    check("email verification landed", db._truthy(db.get_user(user_id).get("email_verified")))
    r = c.post(f"/api/admin/users/{user_id}/extend-trial")
    check("extend-trial returns the new expiry", bool(body(r).get("trial_expires_at")), body(r))

    r = c.post(f"/api/admin/users/{user_id}/reset-password",
               json={"password": "brand-new-pw-1"})
    check("the password reset succeeds", body(r).get("ok") is True, body(r))
    check("the new user password works", bool(db.verify_user(USERNAME, "brand-new-pw-1")))
    check("the reset never echoes the password", "brand-new-pw-1" not in r.get_data(as_text=True))

    check("an unknown user id is 404", c.get(f"/api/admin/users/{MISSING_ID}").status_code == 404)


def phase_devices(c, user_id):
    """Device flags and the full-info context behind the flag list."""
    db.log_device_event("console_selfcheck", user_id=user_id, username=USERNAME,
                        fingerprint_hash="b" * 64, ip_address="203.0.113.11",
                        details={"reason": "seeded by the self-check"})
    r = c.get("/api/admin/device-flags")
    d = body(r)
    check("the flags call answers", d.get("ok") is True, sorted(d))
    check("it no longer carries a policy or limits",
          "policy" not in d and "limits" not in d, sorted(d))
    check("the seeded event is in the flag list",
          any(f.get("event_type") == "console_selfcheck" for f in d.get("flags", [])),
          [f.get("event_type") for f in d.get("flags", [])][:3])
    check("the event details decrypted on the way out",
          any((f.get("details") or {}).get("reason") == "seeded by the self-check"
              for f in d.get("flags", [])))
    unreviewed_before = d.get("unreviewed")

    # This run's own event, not merely the first console_selfcheck in the table:
    # the schema is shared between runs and reviewing someone else's row would
    # make the unreviewed-count check below depend on what else is in flight.
    seeded = next((f for f in d.get("flags", [])
                   if f.get("event_type") == "console_selfcheck"
                   and f.get("username") == USERNAME), None)
    check("the flag carries the lookup hash the info button needs",
          bool((seeded or {}).get("lookup_hash")))

    r = c.get("/api/admin/flag-context", query_string={
        "user_id": user_id, "lookup_hash": (seeded or {}).get("lookup_hash"),
        "ip": "203.0.113.11"})
    ctx = body(r)
    check("the flag context answers", ctx.get("ok") is True, sorted(ctx))
    check("it carries the account", (ctx.get("user") or {}).get("username") == USERNAME,
          (ctx.get("user") or {}).get("username"))
    check("it never leaks the password hash", "password" not in (ctx.get("user") or {}))
    check("it never leaks a plaintext bot token",
          all("token" not in b for b in ctx.get("bots", [])))
    for key in ("device_accounts", "ip_accounts", "sessions", "flags", "bots"):
        check(f"the context includes {key}", isinstance(ctx.get(key), list), ctx.get(key))
    check("the account's own flags came back",
          any(f.get("event_type") == "console_selfcheck" for f in ctx.get("flags", [])))

    r = c.get("/api/admin/flag-context", query_string={"ip": "203.0.113.11"})
    check("a flag with no account behind it still resolves",
          body(r).get("ok") is True and body(r).get("user") is None, body(r).get("user"))

    r = c.post("/api/admin/device-flags/review", json={"id": (seeded or {}).get("id")})
    check("reviewing a flag lowers the unreviewed count",
          body(r).get("unreviewed", 99) < (unreviewed_before or 99),
          (unreviewed_before, body(r).get("unreviewed")))

    check("the policy endpoint is gone",
          c.put("/api/admin/device-policy", json={}).status_code == 404)
    check("the limit-create endpoint is gone",
          c.post("/api/admin/device-limits", json={}).status_code == 404)
    check("the limit-delete endpoint is gone",
          c.delete("/api/admin/device-limits/1").status_code == 404)


def phase_ops(c, user_id, bot_id, sids):
    """SMTP, sessions, the fleet page, bot config and the admin's own password."""
    r = c.put("/api/admin/smtp-config", json={"host": "smtp.console.test", "port": 587,
                                              "user": "ops@console.test",
                                              "password": "smtp-pw-console",
                                              "from_addr": "noreply@console.test"})
    check("the SMTP config saves", body(r).get("ok") is True, body(r))
    r = c.get("/api/admin/smtp-config")
    text, d = r.get_data(as_text=True), body(r)
    check("the SMTP GET never returns the password", "smtp-pw-console" not in text)
    check("the SMTP GET never returns the username", "ops@console.test" not in text)
    check("it reports that both are stored instead",
          d.get("has_user") is True and d.get("has_pass") is True, d)
    check("the host still comes back for the form",
          d.get("config", {}).get("smtp_host") == "smtp.console.test", d.get("config"))
    check("the stored password is the one the mailer will use",
          db.get_smtp_config().get("smtp_pass") == "smtp-pw-console")
    r = c.put("/api/admin/smtp-config", json={"host": "", "port": 587, "from_addr": ""})
    check("an empty host is rejected", r.status_code == 400, r.status_code)
    r = c.get("/api/admin/smtp-diagnose")
    check("the diagnose call answers without leaking",
          body(r).get("has_pass") is True and "smtp-pw-console" not in r.get_data(as_text=True),
          body(r))

    sid_one, sid_two = sids
    db.create_session(sid_one, {"user_id": str(user_id)},
                      ip_address="203.0.113.13", user_agent="selfcheck")
    r = c.get("/api/admin/sessions")
    check("the session list answers",
          any(s.get("id") == sid_one for s in body(r).get("sessions", [])), body(r))
    r = c.get(f"/api/admin/sessions?user_id={user_id}")
    check("it filters by user", len(body(r).get("sessions", [])) >= 1, body(r))
    c.delete(f"/api/admin/sessions/{sid_one}")
    check("deleting a session removes it", db.get_session(sid_one) is None)
    db.create_session(sid_two, {"user_id": str(user_id)}, ip_address="203.0.113.13")
    c.post(f"/api/admin/sessions/user/{user_id}/revoke-all")
    check("revoke-all clears the user's sessions", db.get_user_sessions(user_id) == [],
          db.get_user_sessions(user_id))

    r = c.get("/api/admin/engine/health")
    check("a dead engine is reported, not raised", body(r).get("ok") is False, body(r))
    r = c.get("/api/admin/bots")
    d = body(r)
    check("the fleet page still answers with the engine down",
          r.status_code == 200 and d.get("ok") is True, r.status_code)
    check("the engine's verdict travels inside the 200",
          d.get("engine", {}).get("ok") is False, d.get("engine"))
    check("no plaintext bot token reaches the fleet table",
          all("token" not in b for b in d.get("bots", [])), [sorted(b) for b in d.get("bots", [])][:1])

    r = c.get(f"/api/admin/bots/{bot_id}/config")
    d = body(r)
    check("the bot config loads", d.get("ok") is True, d)
    check("it carries no token, only the mask",
          "token" not in d.get("bot", {}) and "token_masked" in d.get("bot", {}), sorted(d.get("bot", {})))
    r = c.put(f"/api/admin/bots/{bot_id}/config",
              json={"server_ip": "edited.console.test", "server_port": 25570,
                    "edition": "bedrock", "update_interval": 60})
    check("the bot config saves", body(r).get("ok") is True, body(r))
    b = db.get_bot(bot_id)
    check("the edit landed and decrypts",
          b["server_ip"] == "edited.console.test" and b["server_port"] == 25570
          and b["edition"] == "bedrock" and b["update_interval"] == 60, b.get("server_ip"))
    check("a field the request omitted was left alone", b["name"] == "Bot #1", b["name"])
    for bad in ({"server_port": 99999}, {"edition": "pocket"}, {"update_interval": 5},
                {"embed": "not-an-object"}):
        r = c.put(f"/api/admin/bots/{bot_id}/config", json=bad)
        check(f"config rejects {sorted(bad)[0]}={list(bad.values())[0]}",
              r.status_code == 400, r.status_code)
    r = c.put(f"/api/admin/bots/{bot_id}/config", json={})
    check("an empty config body is rejected", r.status_code == 400, r.status_code)

    r = c.post("/api/admin/db/test")
    check("the DB test probe succeeds",
          body(r).get("ok") is True and body(r).get("backend") == "oracle", body(r))


def phase_ads(c, user_id):
    """Global and per-user advertising control."""
    zone = "banner_468x60"
    r = c.get("/api/admin/ads")
    d = body(r)
    check("the ads overview answers", d.get("ok") is True, d)
    check("it carries the master switch and every zone",
          isinstance(d.get("ads_enabled"), bool)
          and len(d.get("zones", [])) == len(db.AD_ZONES),
          sorted(d))
    check("a zone row has key, label and enabled",
          all({"key", "label", "enabled"} <= set(z.keys()) for z in d.get("zones", [])),
          sorted(d.get("zones", [])[:1]) or None)
    check("it carries the guard, consent and per-page switches too",
          {"guard_mode", "guard_modes", "consent_required", "pages"} <= set(d),
          sorted(d))
    check("the guard mode is one the client understands",
          d.get("guard_mode") in db.AD_GUARD_MODES, d.get("guard_mode"))
    check("the mode list is shipped from the database, not the page",
          d.get("guard_modes") == list(db.AD_GUARD_MODES), d.get("guard_modes"))
    check("consent-required is a real boolean",
          isinstance(d.get("consent_required"), bool), d.get("consent_required"))
    # Unlike zones, pages arrive keyed by endpoint — that key is what the PUT
    # path takes, so the map is the shape and there is no "key" field in a row.
    check("every ad page is listed, keyed by endpoint",
          isinstance(d.get("pages"), dict)
          and set(d.get("pages", {})) == set(db.AD_PAGES),
          sorted(d.get("pages", {})))
    check("a page row has a label and a boolean switch",
          all({"label", "enabled"} <= set(v) and isinstance(v["enabled"], bool)
              for v in d.get("pages", {}).values()),
          list(d.get("pages", {}).items())[:1] or None)

    r = c.put("/api/admin/ads", json={"ads_enabled": False})
    check("the master switch flips off", body(r).get("ok") is True, body(r))
    check("off landed in the database", db.get_ad_enabled() is False)
    r = c.put("/api/admin/ads", json={"ads_enabled": "yes"})
    check("a non-boolean master switch is rejected", r.status_code == 400, r.status_code)
    c.put("/api/admin/ads", json={"ads_enabled": True})

    r = c.put(f"/api/admin/ads/zones/{zone}", json={"enabled": False})
    check("a zone flips off globally", body(r).get("ok") is True, body(r))
    check("the zone toggle landed", db.get_ad_zone_enabled(zone) is False)
    r = c.put("/api/admin/ads/zones/not_a_real_zone", json={"enabled": False})
    check("an unknown zone is rejected", r.status_code == 400, r.status_code)
    r = c.put(f"/api/admin/ads/zones/{zone}", json={"enabled": "no"})
    check("a non-boolean zone value is rejected", r.status_code == 400, r.status_code)
    c.put(f"/api/admin/ads/zones/{zone}", json={"enabled": True})

    # Every mode, not just one: a bad value here degrades silently — fp-guard.js
    # falls back to banner mode on an attribute it does not recognise — so the
    # round trip has to be proven for each of them rather than assumed.
    for mode in db.AD_GUARD_MODES:
        r = c.put("/api/admin/ads/guard-mode", json={"mode": mode})
        check(f"guard mode {mode} is accepted", body(r).get("ok") is True, body(r))
        check(f"guard mode {mode} landed", db.get_ad_guard_mode() == mode,
              db.get_ad_guard_mode())
    r = c.put("/api/admin/ads/guard-mode", json={"mode": "banner"})
    check("an unknown guard mode is rejected", r.status_code == 400, r.status_code)
    r = c.put("/api/admin/ads/guard-mode", json={"mode": True})
    check("a non-string guard mode is rejected", r.status_code == 400, r.status_code)
    check("a rejected mode left the stored one alone",
          db.get_ad_guard_mode() == db.AD_GUARD_MODES[-1], db.get_ad_guard_mode())
    c.put("/api/admin/ads/guard-mode", json={"mode": db.AD_GUARD_MODE_DEFAULT})

    r = c.put("/api/admin/ads/consent", json={"required": True})
    check("consent can be made required", body(r).get("ok") is True, body(r))
    check("required landed in the database", db.get_ad_consent_required() is True)
    r = c.put("/api/admin/ads/consent", json={"required": False})
    check("consent can be made optional again", body(r).get("ok") is True, body(r))
    check("optional landed too", db.get_ad_consent_required() is False)
    r = c.put("/api/admin/ads/consent", json={"required": "yes"})
    check("a non-boolean consent value is rejected", r.status_code == 400, r.status_code)
    c.put("/api/admin/ads/consent", json={"required": False})

    r = c.put(f"/api/admin/ads/pages/{AD_PAGE}", json={"enabled": False})
    check("a page can be denied advertising", body(r).get("ok") is True, body(r))
    check("the page switch landed", db.get_ad_page_enabled(AD_PAGE) is False)
    r = c.put(f"/api/admin/ads/pages/{AD_PAGE}", json={"enabled": True})
    check("the page can be allowed again", body(r).get("ok") is True, body(r))
    check("the page is on in the database", db.get_ad_page_enabled(AD_PAGE) is True)
    check("the overview agrees with the getter",
          body(c.get("/api/admin/ads")).get("pages", {}).get(AD_PAGE, {}).get("enabled")
          is True, body(c.get("/api/admin/ads")).get("pages", {}).get(AD_PAGE))
    r = c.put("/api/admin/ads/pages/not_a_real_page", json={"enabled": False})
    check("an unknown page endpoint is rejected", r.status_code == 400, r.status_code)
    r = c.put(f"/api/admin/ads/pages/{AD_PAGE}", json={"enabled": "off"})
    check("a non-boolean page value is rejected", r.status_code == 400, r.status_code)
    # Back to the default AD_PAGES ships for this page, not a hardcoded True: the
    # switch only overrules a default, and the map is what owns it.
    c.put(f"/api/admin/ads/pages/{AD_PAGE}",
          json={"enabled": bool(db.AD_PAGES[AD_PAGE].get("default_on"))})

    r = c.get(f"/api/admin/users/{user_id}/ads")
    d = body(r)
    check("the per-user ad view answers", d.get("ok") is True, d)
    check("it carries master, override, resolved and zone map",
          {"ads_enabled", "ads_disabled", "resolved", "overrides", "zones"} <= set(d),
          sorted(d))
    check("the anonymous zone map labels the zones",
          all({"key", "label"} <= set(z.keys()) for z in d.get("zones", [])))

    r = c.put(f"/api/admin/users/{user_id}/ads", json={"ads_disabled": True})
    check("per-user ads can be disabled", body(r).get("ok") is True, body(r))
    check("the per-user toggle landed", db.get_user_ads_disabled(user_id) is True)
    check("resolution reflects it", body(c.get(f"/api/admin/users/{user_id}/ads"))
          .get("resolved", {}).get(zone) is False, body(c.get(f"/api/admin/users/{user_id}/ads")))
    r = c.put(f"/api/admin/users/{user_id}/ads", json={"ads_disabled": "x"})
    check("a non-boolean per-user toggle is rejected", r.status_code == 400, r.status_code)
    c.put(f"/api/admin/users/{user_id}/ads", json={"ads_disabled": False})

    r = c.put(f"/api/admin/users/{user_id}/ads/zones/{zone}", json={"enabled": False})
    check("a per-user zone override can be set off", body(r).get("ok") is True, body(r))
    check("the override landed", db.get_all_user_zone_overrides(user_id) == {zone: False},
          db.get_all_user_zone_overrides(user_id))
    r = c.put(f"/api/admin/users/{user_id}/ads/zones/{zone}", json={"enabled": True})
    check("the override can be flipped back on", body(r).get("ok") is True, body(r))
    r = c.put(f"/api/admin/users/{user_id}/ads/zones/{zone}", json={})
    check("an empty body clears the override", body(r).get("cleared") is True, body(r))
    check("the override is gone", db.get_all_user_zone_overrides(user_id) == {},
          db.get_all_user_zone_overrides(user_id))
    r = c.put(f"/api/admin/users/{user_id}/ads/zones/nope", json={"enabled": True})
    check("an unknown per-user zone is rejected", r.status_code == 400, r.status_code)
    r = c.put(f"/api/admin/users/{MISSING_ID}/ads", json={"ads_disabled": True})
    check("an unknown user is 404", r.status_code == 404, r.status_code)


def phase_account_page(c):
    """The Account page renders without credential machinery behind it."""
    r = c.get("/admin/account")
    check("the Account page renders", r.status_code == 200, r.status_code)
    r = c.post("/api/admin/account/password", json={"current": "x", "new": "y" * 10})
    check("the old password endpoint is gone", r.status_code == 404, r.status_code)


def main():
    sids = (f"{PREFIX}sid1", f"{PREFIX}sid2")
    user_id = None
    settings_snapshot = _snapshot_settings(TOUCHED_SETTINGS)
    try:
        ok, res = db.create_user(USERNAME, "console-pw-1", "Console User", 1,
                                 email=f"{PREFIX}user@console.test")
        if not ok:
            print(f"could not seed a user: {res}")
            return 1
        user_id = res
        bot_id = db.get_user_bots(user_id)[0]["id"]

        c = admin_app.app.test_client()
        print("\n── auth ──")
        phase_auth(c)
        print("\n── pages ──")
        phase_pages(c, user_id)
        print("\n── users ──")
        phase_users(c, user_id)
        print("\n── ads ──")
        phase_ads(c, user_id)
        print("\n── devices ──")
        phase_devices(c, user_id)
        print("\n── ops ──")
        phase_ops(c, user_id, bot_id, sids)
        print("\n── account page ──")
        phase_account_page(c)

        # Logout is a no-op now (there is no session to drop) — the delete
        # below still works because the loopback console trusts its operator.
        c.get("/admin/logout")
        r = c.delete(f"/api/admin/users/{user_id}")
        check("a logged-out console still trusts the operator", body(r).get("ok") is True, body(r))
        check("the user is gone", db.get_user(user_id) is None)
    finally:
        # Runs on a failing check, an exception and a clean pass alike — a half-run
        # suite must not leave fixtures behind.
        _cleanup(user_id, sids)
        _restore_settings(settings_snapshot)

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed:")
        for f in FAILED:
            print("  - " + f)
        return 1
    print("admin console self-check OK")
    return 0


if __name__ == "__main__":
    _require_isolated_schema()
    sys.exit(main())

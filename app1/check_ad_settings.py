"""check_ad_settings.py — verify the admin-controlled ad settings round-trip.

Proves the four database.py getter/setter pairs the admin console drives survive
a full round trip through the *real* functions, that the two backend ad-zones
endpoints serialize them, and that frontend.py's restated copies of the
constants have not drifted -- all with no live Oracle and no row touched.

Exit code 0 = every group passed, 1 = at least one assertion failed.

database.py refuses to import at all with ORACLE_ENABLED unset (line 655-658:
"No database backend available"), so it cannot simply be disabled. Instead a
fake `oracledb` module is planted in sys.modules before the import, together
with dummy ORACLE_* values in os.environ so the real credentials in
fastapi-oracle-app/.env are never even read. The import-time schema bootstrap
then runs against the fake driver: every "SELECT COUNT(*) FROM user_tables"
answers 1 ("already there") so nothing is created, and every ALTER is
swallowed. No socket is opened and no real row is touched.

On top of that the three seams the ad code actually uses are replaced:

    database.get_setting   -> reads a plain dict
    database.set_setting   -> writes a plain dict, storing the value VERBATIM
                              (no str() coercion) so the "1"/"0" assertions are
                              real rather than laundered by the stub
    database._user_conn    -> a fake connection whose cursor answers the
                              LIKE 'ad_page_%' / 'ad_zone_%' / 'ad_network_%'
                              queries out of that same dict

Run: python check_ad_settings.py
"""

import os
import re
import sys
import types
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ── the stand-in settings table (defined first: the fake driver reads it) ────

SETTINGS = {}

# Test knobs for the fake connection.
_CONN_MODE = {"rows": "tuple", "explode": None}


class DictRow(dict):
    """A row that looks like an Oracle dict-cursor row (has .keys())."""


class FakeCursor:
    """Answers exactly the two shapes of query this code path issues.

    The ad readers all do `SELECT key, value FROM settings WHERE key LIKE
    '<prefix>%'`, which is served from SETTINGS. The import-time schema
    bootstrap does `SELECT COUNT(*) FROM user_tables/user_indexes/...`, which
    always answers 1 so nothing is created, and DDL, which is swallowed.
    """

    def __init__(self):
        self.description = None
        self._rows = []

    def execute(self, sql, params=None):
        low = sql.lower()
        m = re.search(r"like '([a-z_]+)%'", low)
        if m and "from settings" in low:
            if _CONN_MODE["explode"]:
                raise _CONN_MODE["explode"]
            prefix = m.group(1)
            # Oracle reports column names upper-cased; database.py lowercases
            # cur.description itself, so mirroring that is part of the test.
            self.description = [("KEY",), ("VALUE",)]
            pairs = [(k, v) for k, v in SETTINGS.items() if k.startswith(prefix)]
            if _CONN_MODE["rows"] == "dict":
                self._rows = [DictRow(key=k, value=v) for k, v in pairs]
            else:
                self._rows = [(k, v) for k, v in pairs]
        elif "count(*)" in low:
            self.description = [("COUNT",)]
            self._rows = [(1,)]
        else:
            self.description = [("X",)]
            self._rows = []

    def executemany(self, sql, seq):
        pass

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def setinputsizes(self, *a, **k):
        pass

    def close(self):
        pass


class FakeConn:
    def cursor(self):
        return FakeCursor()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class _FakePool:
    def acquire(self):
        return FakeConn()

    def close(self, *a, **k):
        pass


# Plant the fake driver and dummy credentials BEFORE importing database, so
# _load_config() flips _ORACLE_ENABLED on without reading the real wallet or
# .env credentials, and _oracle_pool() builds a pool that opens no socket.
_fake_oracledb = types.ModuleType("oracledb")
_fake_oracledb.defaults = types.SimpleNamespace(fetch_lobs=True, connect_timeout=0)
_fake_oracledb.create_pool = lambda **kw: _FakePool()
_fake_oracledb.connect = lambda **kw: FakeConn()
_fake_oracledb.DatabaseError = type("DatabaseError", (Exception,), {})
_fake_oracledb.init_oracle_client = lambda *a, **k: None
sys.modules["oracledb"] = _fake_oracledb

os.environ["ORACLE_ENABLED"] = "true"
os.environ["ORACLE_USER"] = "test_user_never_used"
os.environ["ORACLE_PASSWORD"] = "test_password_never_used"
os.environ["ORACLE_DSN"] = "test_dsn_never_used"
os.environ["ORACLE_WALLET_PASSWORD"] = ""

import database as db  # noqa: E402

assert db._user_conn().__class__ is FakeConn, "fake driver did not take effect"


# ── result harness ──────────────────────────────────────────────────────────

_GROUPS = []


class Group:
    def __init__(self, name):
        self.name = name
        self.failures = []
        _GROUPS.append(self)

    def ok(self, cond, label):
        if not cond:
            self.failures.append(label)

    def eq(self, got, want, label):
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def raises(self, exc, fn, label):
        try:
            fn()
        except exc:
            return
        except Exception as e:
            self.failures.append(f"{label}: raised {type(e).__name__}({e}) not {exc.__name__}")
            return
        self.failures.append(f"{label}: did not raise {exc.__name__}")

    def no_raise(self, fn, label):
        try:
            return fn()
        except Exception as e:
            self.failures.append(f"{label}: raised {type(e).__name__}({e})")
            return None

    def report(self):
        status = "PASS" if not self.failures else "FAIL"
        print(f"[{status}] {self.name}")
        for f in self.failures:
            print(f"         - {f}")
        return not self.failures


# ── the seam stubs ──────────────────────────────────────────────────────────


def fake_get_setting(key, default=None):
    return SETTINGS[key] if key in SETTINGS else default


def fake_set_setting(key, value):
    # Verbatim on purpose. The real set_setting does encrypt(str(value)), which
    # would turn a stray Python True into "True" and hide the bug this test is
    # looking for. Storing what database.py actually handed us keeps assertion
    # group 4 honest.
    SETTINGS[key] = value


_REAL = {
    "get_setting": db.get_setting,
    "set_setting": db.set_setting,
    "_user_conn": db._user_conn,
    "get_ad_enabled": db.get_ad_enabled,
    "get_user_ads_disabled": db.get_user_ads_disabled,
}

db.get_setting = fake_get_setting
db.set_setting = fake_set_setting
db._user_conn = lambda: FakeConn()


# ── expectations ────────────────────────────────────────────────────────────
# frontend.py's original rule denied advertising on six endpoints. That has since
# changed by an explicit product decision: the four account pages users work in
# now default ON (they already carry ad slots), and only the two credential forms
# stay OFF. DEFAULT_OFF is that intended default, written out literally so this
# group is an independent check on AD_PAGES rather than a mirror of it -- if a
# default_on disagrees with what we meant to ship, group 1 fails. Only the key set
# comes from AD_PAGES, which is unavoidable: that table defines which pages exist.
DEFAULT_OFF = ("user_login", "user_register")

# Kept only to document what the change moved. Four of these now advertise; the
# tuple is no longer the current default, just the historical starting point.
DENIED_ORIGINALLY = ("user_login", "user_register", "user_dashboard",
                     "user_bot_editor", "user_bot_replies", "user_formatting")

VIRGIN_PAGES = {ep: (ep not in DEFAULT_OFF) for ep in db.AD_PAGES}


# ── group 1: an unwritten settings table ships the intended defaults ─────────

g1 = Group("1. an unwritten settings table ships the intended defaults")
SETTINGS.clear()

g1.eq(db.get_ad_guard_mode(), "gate", "get_ad_guard_mode() default")
g1.eq(db.AD_GUARD_MODE_DEFAULT, "gate", "AD_GUARD_MODE_DEFAULT constant")
g1.eq(tuple(db.AD_GUARD_MODES), ("gate", "warn", "off"), "AD_GUARD_MODES vocabulary")
g1.eq(db.get_ad_consent_required(), False, "get_ad_consent_required() default")
g1.ok(db.get_ad_consent_required() is False, "get_ad_consent_required() returns a real bool")

# Every endpoint the change touched must still exist in the table.
for ep in DENIED_ORIGINALLY:
    g1.ok(ep in db.AD_PAGES, f"AD_PAGES still contains {ep!r}")

# Literal defaults, independent of AD_PAGES["default_on"]: the two credential
# forms OFF, every other page ON.
for ep in DEFAULT_OFF:
    g1.eq(db.get_ad_page_enabled(ep), False, f"intended default: {ep} OFF")
for ep in db.AD_PAGES:
    if ep not in DEFAULT_OFF:
        g1.eq(db.get_ad_page_enabled(ep), True, f"intended default: {ep} ON")

g1.eq(db.get_all_ad_page_settings(), {}, "get_all_ad_page_settings() on empty table")
g1.eq(db.get_resolved_ad_pages(), VIRGIN_PAGES, "get_resolved_ad_pages() on empty table")
g1.eq({k: v["enabled"] for k, v in db.get_all_ad_pages().items()}, VIRGIN_PAGES,
      "get_all_ad_pages() enabled flags on empty table")
g1.ok(all(isinstance(v.get("label"), str) and v["label"]
          for v in db.get_all_ad_pages().values()),
      "get_all_ad_pages() every page carries a non-empty label")

# The two credential forms that still default OFF, re-checked through the fully
# resolved answer rather than the single-page getter.
resolved = db.get_resolved_ad_pages()
for ep in DEFAULT_OFF:
    g1.eq(resolved[ep], False, f"{ep} still denied by default")

g1.eq(SETTINGS, {}, "no getter wrote to the settings table")


# ── group 2: every setter round-trips through its getter ────────────────────

g2 = Group("2. setter -> getter round trip for every valid value")

for mode in ("gate", "warn", "off", "gate"):
    SETTINGS.clear()
    db.set_ad_guard_mode(mode)
    g2.eq(db.get_ad_guard_mode(), mode, f"guard mode round trip {mode!r}")

for required in (True, False, True):
    SETTINGS.clear()
    db.set_ad_consent_required(required)
    g2.eq(db.get_ad_consent_required(), required, f"consent_required round trip {required!r}")

for ep in VIRGIN_PAGES:
    for enabled in (True, False, True):
        SETTINGS.clear()
        db.set_ad_page_enabled(ep, enabled)
        g2.eq(db.get_ad_page_enabled(ep), enabled, f"page {ep!r} round trip {enabled!r}")
        g2.eq(db.get_all_ad_page_settings().get(ep), enabled,
              f"page {ep!r} visible to get_all_ad_page_settings as {enabled!r}")
        g2.eq(db.get_all_ad_pages()[ep]["enabled"], enabled,
              f"page {ep!r} visible to get_all_ad_pages as {enabled!r}")
        g2.eq(db.get_resolved_ad_pages()[ep], enabled,
              f"page {ep!r} visible to get_resolved_ad_pages as {enabled!r}")

# The whole table flipped away from its defaults at once, both row styles.
for style in ("tuple", "dict"):
    _CONN_MODE["rows"] = style
    SETTINGS.clear()
    inverted = {ep: (not want) for ep, want in VIRGIN_PAGES.items()}
    for ep, want in inverted.items():
        db.set_ad_page_enabled(ep, want)
    g2.eq(db.get_all_ad_page_settings(), inverted,
          f"all {len(VIRGIN_PAGES)} pages inverted, {style} cursor rows")
    g2.eq(db.get_resolved_ad_pages(), inverted,
          f"all {len(VIRGIN_PAGES)} pages inverted resolve, {style} cursor rows")
_CONN_MODE["rows"] = "tuple"

# A page an admin never touched keeps its default while its neighbours change.
SETTINGS.clear()
db.set_ad_page_enabled("user_login", True)
g2.eq(db.get_ad_page_enabled("user_login"), True, "partial write: user_login on")
g2.eq(db.get_ad_page_enabled("user_register"), False,
      "partial write: untouched user_register keeps default")
g2.eq(db.get_ad_page_enabled("index"), True,
      "partial write: untouched index keeps default")


# ── group 3: unknown values and unknown endpoints ───────────────────────────

g3 = Group("3. unknown mode / unknown endpoint handling")
SETTINGS.clear()

g3.raises(ValueError, lambda: db.set_ad_guard_mode("nonsense"),
          "set_ad_guard_mode('nonsense')")
g3.eq(SETTINGS, {}, "rejected guard mode wrote nothing")

g3.raises(ValueError, lambda: db.set_ad_page_enabled("no_such_endpoint", True),
          "set_ad_page_enabled('no_such_endpoint', True)")
g3.eq(SETTINGS, {}, "rejected page endpoint wrote nothing")

got = g3.no_raise(lambda: db.get_ad_page_enabled("no_such_endpoint"),
                  "get_ad_page_enabled('no_such_endpoint')")
g3.eq(got, False, "get_ad_page_enabled('no_such_endpoint') answer")

for bad in ("", None, "GATE", "warn ", "blocked"):
    g3.raises(ValueError, lambda b=bad: db.set_ad_guard_mode(b),
              f"set_ad_guard_mode({bad!r})")
for bad in ("", None, "INDEX", "ad_page_index"):
    g3.raises(ValueError, lambda b=bad: db.set_ad_page_enabled(b, True),
              f"set_ad_page_enabled({bad!r}, True)")

# Validated on read too: a corrupt/hand-edited row must not reach <body data-guard>.
SETTINGS.clear()
SETTINGS["ad_guard_mode"] = "nonsense"
g3.eq(db.get_ad_guard_mode(), "gate", "corrupt stored guard mode falls back to default")
SETTINGS["ad_guard_mode"] = None
g3.eq(db.get_ad_guard_mode(), "gate", "NULL stored guard mode falls back to default")

# A typo'd row must not enable advertising anywhere: AD_PAGES is the allowlist.
SETTINGS.clear()
SETTINGS["ad_page_no_such_endpoint"] = "1"
SETTINGS["ad_page_admin_console"] = "1"
g3.eq(db.get_all_ad_page_settings(), {},
      "typo'd ad_page_* rows are filtered out by the AD_PAGES allowlist")
g3.eq(db.get_resolved_ad_pages(), VIRGIN_PAGES,
      "typo'd ad_page_* rows do not disturb the resolved answer")

# A value that is neither "1" nor "0" reads as off rather than truthy.
SETTINGS.clear()
SETTINGS["ad_page_index"] = "yes"
g3.eq(db.get_ad_page_enabled("index"), False,
      "non-'1' stored page value reads as off, not truthy")
SETTINGS.clear()
SETTINGS["ad_consent_required"] = "true"
g3.eq(db.get_ad_consent_required(), False,
      "non-'1' stored consent value reads as off, not truthy")


# ── group 4: storage format is "1"/"0" strings, not Python bools ────────────

g4 = Group("4. booleans persist as the exact strings '1'/'0'")

SETTINGS.clear()
db.set_ad_consent_required(True)
v = SETTINGS.get("ad_consent_required")
g4.eq(sorted(SETTINGS), ["ad_consent_required"], "consent setter wrote exactly one key")
g4.eq(v, "1", "ad_consent_required=True stored value")
g4.eq(type(v).__name__, "str", "ad_consent_required=True stored type")
g4.ok(v is not True, "ad_consent_required=True stored as string, not Python True")

SETTINGS.clear()
db.set_ad_consent_required(False)
v = SETTINGS.get("ad_consent_required")
g4.eq(v, "0", "ad_consent_required=False stored value")
g4.eq(type(v).__name__, "str", "ad_consent_required=False stored type")
g4.ok(v is not False, "ad_consent_required=False stored as string, not Python False")

for ep in VIRGIN_PAGES:
    SETTINGS.clear()
    db.set_ad_page_enabled(ep, True)
    v = SETTINGS.get(f"ad_page_{ep}")
    g4.eq(sorted(SETTINGS), [f"ad_page_{ep}"], f"page {ep!r} setter wrote exactly one key")
    g4.eq(v, "1", f"ad_page_{ep} True stored value")
    g4.eq(type(v).__name__, "str", f"ad_page_{ep} True stored type")
    SETTINGS.clear()
    db.set_ad_page_enabled(ep, False)
    v = SETTINGS.get(f"ad_page_{ep}")
    g4.eq(v, "0", f"ad_page_{ep} False stored value")
    g4.eq(type(v).__name__, "str", f"ad_page_{ep} False stored type")

# Truthy/falsey non-bools must still normalise to "1"/"0".
SETTINGS.clear()
db.set_ad_page_enabled("index", 1)
g4.eq(SETTINGS.get("ad_page_index"), "1", "truthy non-bool normalises to '1'")
db.set_ad_page_enabled("index", 0)
g4.eq(SETTINGS.get("ad_page_index"), "0", "falsey non-bool normalises to '0'")
db.set_ad_page_enabled("index", None)
g4.eq(SETTINGS.get("ad_page_index"), "0", "None normalises to '0'")

SETTINGS.clear()
db.set_ad_guard_mode("warn")
g4.eq(SETTINGS, {"ad_guard_mode": "warn"}, "guard mode stored as the plain mode string")

# What the real set_setting writes is encrypt(str(value)); prove the bulk reader
# decrypts it, so the format assertions above describe the real column too.
g4b = Group("4b. real Fernet ciphertext rows decrypt through get_all_ad_page_settings")
try:
    from crypto_util import encrypt as _encrypt, looks_encrypted as _looks_encrypted

    SETTINGS.clear()
    SETTINGS["ad_page_user_login"] = _encrypt("1")
    SETTINGS["ad_page_index"] = _encrypt("0")
    # Not a hardcoded prefix: crypto_util writes AES-GCM ("gcm1.") now and Fernet
    # ("gAAAAA") historically, and _dec_or_raw gates on this same predicate.
    g4b.ok(_looks_encrypted(SETTINGS["ad_page_user_login"]),
           f"test fixture really is ciphertext "
           f"({str(SETTINGS['ad_page_user_login'])[:12]!r}...)")
    g4b.ok(SETTINGS["ad_page_user_login"] not in ("1", "0"),
           "test fixture is not plaintext")
    for style in ("tuple", "dict"):
        _CONN_MODE["rows"] = style
        g4b.eq(db.get_all_ad_page_settings(),
               {"user_login": True, "index": False},
               f"encrypted rows decrypt, {style} cursor rows")
    _CONN_MODE["rows"] = "tuple"
    exp = dict(VIRGIN_PAGES, user_login=True, index=False)
    g4b.eq(db.get_resolved_ad_pages(), exp, "encrypted rows resolve correctly")
except ImportError as e:
    print(f"         (skipped: crypto_util unavailable: {e})")


# ── group 5: master switch and per-user override dominate ───────────────────

g5 = Group("5. master switch and per-user override kill every page")

# Every page explicitly ON, so a False can only come from the overrides.
SETTINGS.clear()
for ep in VIRGIN_PAGES:
    db.set_ad_page_enabled(ep, True)
all_on = {ep: True for ep in VIRGIN_PAGES}
g5.eq(db.get_resolved_ad_pages(), all_on, "baseline: every page explicitly on")

db.get_ad_enabled = lambda: False
try:
    g5.eq(db.get_resolved_ad_pages(), {ep: False for ep in VIRGIN_PAGES},
          "master switch off -> every page False (anonymous)")
    g5.eq(db.get_resolved_ad_pages("u-1"), {ep: False for ep in VIRGIN_PAGES},
          "master switch off -> every page False (logged in)")
finally:
    db.get_ad_enabled = _REAL["get_ad_enabled"]

g5.eq(db.get_resolved_ad_pages(), all_on, "master switch restored -> pages on again")

_UAD_CALLS = []


def fake_uad(user_id):
    _UAD_CALLS.append(user_id)
    if user_id is None:
        raise AssertionError("get_user_ads_disabled called with user_id=None")
    return True


db.get_user_ads_disabled = fake_uad
try:
    g5.eq(db.get_resolved_ad_pages("u-42"), {ep: False for ep in VIRGIN_PAGES},
          "per-user ads_disabled -> every page False for that user")
    g5.eq(_UAD_CALLS, ["u-42"], "per-user check consulted once with the user id")
    _UAD_CALLS.clear()
    g5.eq(db.get_resolved_ad_pages(), all_on,
          "anonymous resolution unaffected by a user's override")
    g5.eq(_UAD_CALLS, [], "anonymous resolution never consults get_user_ads_disabled")
finally:
    db.get_user_ads_disabled = _REAL["get_user_ads_disabled"]

# get_all_ad_pages is the console view and is deliberately NOT gated by the
# master switch -- it must keep showing the stored rows so an admin can still
# see and edit them while ads are globally off.
db.get_ad_enabled = lambda: False
try:
    g5.eq({k: v["enabled"] for k, v in db.get_all_ad_pages().items()}, all_on,
          "console view (get_all_ad_pages) still shows stored rows with ads off")
finally:
    db.get_ad_enabled = _REAL["get_ad_enabled"]


# ── group 6: the bulk query fails OPEN ──────────────────────────────────────

g6 = Group("6. get_all_ad_page_settings fails open when its query raises")

SETTINGS.clear()
for ep in VIRGIN_PAGES:
    db.set_ad_page_enabled(ep, True)

_CONN_MODE["explode"] = RuntimeError("ORA-00942: table or view does not exist")
try:
    got = g6.no_raise(db.get_all_ad_page_settings, "get_all_ad_page_settings() with a raising query")
    g6.eq(got, {}, "returns an empty mapping instead of propagating")
    got = g6.no_raise(db.get_all_ad_pages, "get_all_ad_pages() with a raising query")
    g6.eq({k: v["enabled"] for k, v in (got or {}).items()}, VIRGIN_PAGES,
          "get_all_ad_pages() falls back to the AD_PAGES defaults")
    got = g6.no_raise(db.get_resolved_ad_pages, "get_resolved_ad_pages() with a raising query")
    g6.eq(got, VIRGIN_PAGES, "get_resolved_ad_pages() falls back to the AD_PAGES defaults")
    # Failing open here means falling back to defaults, and the defaults keep
    # the two credential forms OFF -- so a broken query cannot start serving ads
    # on the sign-in page.
    for ep in DEFAULT_OFF:
        g6.eq((got or {}).get(ep), False, f"fail-open keeps {ep} denied")
finally:
    _CONN_MODE["explode"] = None

g6.eq(db.get_all_ad_page_settings(), {ep: True for ep in VIRGIN_PAGES},
      "query recovers after the failure")


# ── group 7: backend endpoint serialization ─────────────────────────────────

g7 = Group("7. backend /api/settings/ad-zones and /api/user/ad-zones serialization")

REQUIRED_KEYS = ("ads_enabled", "networks", "zones", "guard_mode", "consent_required", "pages")

# Static code-read assertion first: it holds whether or not the test client runs.
try:
    import inspect

    import backend  # noqa: E402

    for fname in ("api_ad_zones", "api_user_ad_zones"):
        fn = getattr(backend, fname, None)
        if fn is None:
            g7.failures.append(f"backend.{fname} not found")
            continue
        src = inspect.getsource(inspect.unwrap(fn))
        for key in REQUIRED_KEYS:
            g7.ok(f'"{key}"' in src, f"code-read: backend.{fname} serializes {key!r}")
    rules = {str(r.rule) for r in backend.app.url_map.iter_rules()}
    g7.ok("/api/settings/ad-zones" in rules, "route /api/settings/ad-zones is registered")
    g7.ok("/api/user/ad-zones" in rules, "route /api/user/ad-zones is registered")
    _BACKEND_OK = True
except Exception as e:
    _BACKEND_OK = False
    g7.failures.append(f"could not import backend for the code read: {type(e).__name__}: {e}")
    traceback.print_exc()

# Now the live client, with the db layer still stubbed.
g7live = Group("7b. backend endpoints executed against the stubbed db layer")

if not _BACKEND_OK:
    g7live.failures.append("skipped: backend did not import")
else:
    from flask import g as flask_g

    SETTINGS.clear()
    db.set_ad_guard_mode("warn")
    db.set_ad_consent_required(True)
    db.set_ad_page_enabled("user_login", True)
    db.set_ad_page_enabled("index", False)
    EXPECT_PAGES = dict(VIRGIN_PAGES, user_login=True, index=False)

    client = backend.app.test_client()

    r = client.get("/api/settings/ad-zones")
    g7live.eq(r.status_code, 200, f"/api/settings/ad-zones status (body={r.data[:400]!r})")
    body = r.get_json() if r.status_code == 200 else {}
    body = body or {}
    for key in REQUIRED_KEYS:
        g7live.ok(key in body, f"anonymous payload contains {key!r}")
    g7live.eq(body.get("ok"), True, "anonymous payload ok flag")
    g7live.eq(body.get("guard_mode"), "warn", "anonymous guard_mode reflects the stored row")
    g7live.eq(body.get("consent_required"), True,
              "anonymous consent_required reflects the stored row")
    g7live.eq(body.get("pages"), EXPECT_PAGES, "anonymous pages payload")
    g7live.eq(body.get("ads_enabled"), True, "anonymous ads_enabled")
    g7live.ok(isinstance(body.get("networks"), dict), "anonymous networks is an object")
    g7live.ok(isinstance(body.get("zones"), dict), "anonymous zones is an object")
    g7live.ok(all(isinstance(v, bool) for v in (body.get("pages") or {}).values()),
              "anonymous pages values are JSON booleans")

    # The authenticated twin. Only the auth seam is stubbed; the route body and
    # the whole db resolution path below it are the real thing.
    def fake_authenticate():
        flask_g.current_user_id = "u-42"
        return "u-42", None

    _saved = (backend._authenticate, db.is_user_banned, db.is_user_active,
              db.get_user_ads_disabled)
    backend._authenticate = fake_authenticate
    db.is_user_banned = lambda uid: (False, None)
    db.is_user_active = lambda uid: True
    db.get_user_ads_disabled = lambda uid: False
    try:
        r = client.get("/api/user/ad-zones", headers={"X-Session-Id": "sess-1"})
        g7live.eq(r.status_code, 200, f"/api/user/ad-zones status (body={r.data[:400]!r})")
        body = (r.get_json() if r.status_code == 200 else {}) or {}
        for key in REQUIRED_KEYS:
            g7live.ok(key in body, f"user payload contains {key!r}")
        g7live.ok("ads_disabled" in body, "user payload contains 'ads_disabled'")
        g7live.eq(body.get("guard_mode"), "warn", "user guard_mode reflects the stored row")
        g7live.eq(body.get("consent_required"), True,
                  "user consent_required reflects the stored row")
        g7live.eq(body.get("pages"), EXPECT_PAGES, "user pages payload")

        # A user with ads switched off gets every page False through the HTTP layer.
        db.get_user_ads_disabled = lambda uid: True
        r = client.get("/api/user/ad-zones", headers={"X-Session-Id": "sess-1"})
        body = (r.get_json() if r.status_code == 200 else {}) or {}
        g7live.eq(body.get("pages"), {ep: False for ep in VIRGIN_PAGES},
                  "user with ads_disabled gets every page False over HTTP")
        g7live.eq(body.get("ads_disabled"), True, "user ads_disabled flag serialized")
        g7live.eq(body.get("guard_mode"), "warn",
                  "guard_mode is site-wide and survives a per-user opt-out")
    finally:
        (backend._authenticate, db.is_user_banned, db.is_user_active,
         db.get_user_ads_disabled) = _saved


# ── group 8: cross-tier constant drift ──────────────────────────────────────
# frontend.py deliberately does not import database (different tier), so it
# restates the guard vocabulary and the default-off page list by hand. Its own
# comment says the vocabulary check is load-bearing: g7.js reads a mode it
# does not recognise as "warn", so a mode present in database.AD_GUARD_MODES but
# missing from frontend._AD_GUARD_MODES would silently show every visitor the
# blocker banner instead of what the operator chose.

g8 = Group("8. frontend.py restated constants have not drifted from database.py")
try:
    import frontend  # noqa: E402

    g8.eq(tuple(frontend._AD_GUARD_MODES), tuple(db.AD_GUARD_MODES),
          "frontend._AD_GUARD_MODES matches database.AD_GUARD_MODES")
    g8.eq(frontend._AD_GUARD_MODE_DEFAULT, db.AD_GUARD_MODE_DEFAULT,
          "frontend._AD_GUARD_MODE_DEFAULT matches database.AD_GUARD_MODE_DEFAULT")

    db_off = {ep for ep, meta in db.AD_PAGES.items() if not meta.get("default_on")}
    fe_off = set(frontend._AD_PAGES_DEFAULT_OFF)
    # Only the unsafe direction is an error. frontend.py documents that a page
    # added as default_on=False but missed here is merely allowed during a
    # backend outage; the reverse -- frontend denying a page database defaults ON
    # -- would blank advertising on a content page and is a real defect.
    g8.eq(sorted(fe_off - db_off), [],
          "frontend deny-list contains no page that database defaults ON")
    if sorted(db_off - fe_off):
        print(f"         (note: default_on=False in database but not restated in "
              f"frontend._AD_PAGES_DEFAULT_OFF: {sorted(db_off - fe_off)} -- "
              f"documented as the safe direction, allowed only during an outage)")
except Exception as e:
    g8.failures.append(f"could not import frontend: {type(e).__name__}: {e}")


# ── group 9: an undecryptable row must not flip a default-ON page OFF ────────
# Both readers are fed the *same* unreadable row and must agree. The single-page
# getter treats "row present but unreadable" as "no usable row" and returns the
# AD_PAGES default; the bulk reader compares None == "1" and returns False. For a
# default_on=True page those are opposite answers, and the bulk reader is the one
# every render and both HTTP endpoints actually use.
#
# get_setting is stubbed FAITHFULLY here -- the real one returns
# _dec_or_raw(raw), i.e. None for a present-but-unreadable row -- so the
# divergence is database.py's, not the stub's.

g9 = Group("9. present-but-undecryptable row does not silently disable a "
           "default-ON page")

_UNREADABLE = "gcm1." + "A" * 40  # real ciphertext prefix, body will not decrypt


def faithful_get_setting(key, default=None):
    if key not in SETTINGS:
        return default
    return db._dec_or_raw(SETTINGS[key])


db.get_setting = faithful_get_setting
try:
    g9.eq(db._dec_or_raw(_UNREADABLE), None,
          "premise: _dec_or_raw returns None for an unreadable row")

    # The bulk reader's documented contract is that a row it cannot use is LEFT
    # OUT, so the caller defaults it from AD_PAGES — that is how it agrees with
    # the single-page getter, which branches on None and returns default_on. So
    # assert the omission and then assert the resolved answers match, rather than
    # expecting the raw map to carry a value it is specified not to carry.
    for ep in ("index", "user_login"):
        SETTINGS.clear()
        SETTINGS[f"ad_page_{ep}"] = _UNREADABLE
        one = db.get_ad_page_enabled(ep)
        raw = db.get_all_ad_page_settings()
        res = db.get_resolved_ad_pages()[ep]
        g9.eq(ep in raw, False,
              f"{ep!r}: an unreadable row is omitted, not read as off")
        g9.eq(res, one,
              f"{ep!r}: get_resolved_ad_pages agrees with get_ad_page_enabled")
        g9.eq(res, bool(db.AD_PAGES[ep]["default_on"]),
              f"{ep!r}: and that answer is the page's default_on")

    # Same root cause, reached without any key rotation: a NULL value column.
    for ep in ("index", "user_login"):
        SETTINGS.clear()
        SETTINGS[f"ad_page_{ep}"] = None
        one = db.get_ad_page_enabled(ep)
        raw = db.get_all_ad_page_settings()
        g9.eq(ep in raw, False, f"{ep!r}: NULL value column -- row omitted")
        g9.eq(db.get_resolved_ad_pages()[ep], one,
              f"{ep!r}: NULL value column -- readers agree after defaulting")

    # The network reader carried the same divergence and was fixed with it.
    for net in tuple(db.AD_NETWORKS)[:2]:
        SETTINGS.clear()
        SETTINGS[f"ad_network_{net}"] = _UNREADABLE
        g9.eq(net in db.get_all_network_settings(), False,
              f"{net!r}: unreadable ad_network_ row is omitted too")
        g9.eq(db.get_resolved_ad_networks()[net], db.get_network_enabled(net),
              f"{net!r}: network readers agree after defaulting")

    # The same shape on the guard mode, which validates on read and so is immune.
    SETTINGS.clear()
    SETTINGS["ad_guard_mode"] = _UNREADABLE
    g9.eq(db.get_ad_guard_mode(), "gate",
          "unreadable ad_guard_mode row falls back to the default (validated on read)")
finally:
    db.get_setting = fake_get_setting
    SETTINGS.clear()


# ── summary ─────────────────────────────────────────────────────────────────

print()
print("=" * 72)
ok = True
for grp in _GROUPS:
    ok = grp.report() and ok
print("=" * 72)
total = sum(len(x.failures) for x in _GROUPS)
print(f"{'ALL GROUPS PASS' if ok else f'FAILURES: {total}'}"
      f"   ({len(_GROUPS)} groups, no live Oracle: fake oracledb driver)")

if not ok:
    print()
    print("Group 9 is a regression guard, not a spec item. It covers a defect this")
    print("test found and that has since been fixed: get_all_ad_page_settings and")
    print("get_all_network_settings compared an undecryptable value to '1', which")
    print("reads as off, while their single-key getters branch on None and fall back")
    print("to the configured default. For a default-on page the two readers gave")
    print("opposite answers, and the bulk one is what renders -- so a key rotation")
    print("would have blanked the content pages while the console showed them on.")
    print("Both now omit an unusable row so the caller defaults it. A failure here")
    print("means that fix has been undone.")

sys.exit(0 if ok else 1)

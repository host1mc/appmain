"""The panel's live settings, read from the shared database rather than the env.

:class:`~.config.PanelConfig` is built once per process from environment
variables, so everything it decides is fixed until the process restarts. That was
wrong for the controls an operator actually wants to change: putting the panel
into maintenance, closing registration, or lowering a container's memory meant
editing a unit file and restarting *both* load-balanced instances — and if only
one was restarted, the two disagreed with nothing to show why.

Those controls now live in the ``settings`` table that the Flask tiers and the
admin console already share (``database.PANEL_FLAGS`` / ``PANEL_LIMITS``), so one
write from the console applies to every instance. This module is the panel's
read side of that.

The ad-block guard mode rides along on the same snapshot even though it is not a
``panel_*`` row: it is the site-wide ``ad_guard_mode`` the Flask tier reads, and
the panel used to resolve it from ``PANEL_GUARD_MODE`` at import — which meant
the console could not move it here at all. Carrying it on the snapshot puts it
behind the same one-read-per-cache-window as everything else instead of giving
the template layer its own database call per render.

The ``ads_enabled`` master switch rides along for the same reason and to answer
the same question. The Flask tier folds it into the guard mode it publishes, so
turning ads off site-wide also stands its ad-block detection down; the panel read
neither, so it kept arming the guard over advertising that was no longer in any
page. Both rows now arrive together, which is also what keeps them consistent:
resolving them from two different reads at two different moments is how one
instance ends up gating on a master switch the other has already seen flipped.

Three things it deliberately does:

* **Caches.** Every request would otherwise open an Oracle connection just to ask
  whether maintenance is on. One read per :data:`CACHE_SECONDS` per process is
  enough — a control flipped in the console reaches both instances within that
  window, which is the same order of delay as the console's own refresh.
* **Fails open, to the environment.** ``database`` is the *sync* Oracle module,
  and it is not importable at all on the SQLite laptop path. Anything that goes
  wrong — no module, no wallet, a query error — falls back to the values
  ``PanelConfig`` already resolved from the environment, so a database the panel
  cannot reach makes the panel behave exactly as it did before this module
  existed, rather than taking it down or silently locking every account out.
* **Never blocks the loop.** ``database.get_panel_settings`` is synchronous
  (oracledb), so :func:`load` is awaited through ``run_in_threadpool`` exactly
  like the node client.
"""

import asyncio
import time

from starlette.concurrency import run_in_threadpool


# How long one process serves a cached copy. Short enough that flipping
# maintenance mode in the console takes effect promptly on both instances,
# long enough that a page render costs no Oracle round trip of its own. Every
# control on the snapshot inherits that window: a guard mode written in the
# console reaches both instances within CACHE_SECONDS of the write, which is why
# nothing here needs to be told when the console has changed something.
CACHE_SECONDS = 15

# Only consulted when the database cannot answer; see the module docstring. Keys
# match database.PANEL_FLAGS / PANEL_LIMITS so a fallback dict and a real one are
# interchangeable to callers.
_FALLBACK_MESSAGE = (
    "The panel is in maintenance. Your servers keep running; changes are "
    "paused for a short while."
)

_BACKEND_SETTINGS_READ = "/api/panel-store/settings/read"


class PanelSettings:
    """One resolved snapshot of the panel's controls.

    Attribute access rather than raw dicts so a route reads
    ``settings.maintenance`` and a template ``settings.memory_mb`` — and a key
    that the database has never had still answers, from the fallback.
    """

    __slots__ = ("flags", "limits", "maintenance_message", "from_database", "guard_mode",
                 "ads_enabled")

    def __init__(self, flags, limits, maintenance_message, *, from_database, guard_mode=None,
                 ads_enabled=None):
        self.flags = flags
        self.limits = limits
        self.maintenance_message = maintenance_message
        # Lets the pages say "environment defaults" instead of quietly presenting
        # fallback numbers as though an operator had chosen them.
        self.from_database = from_database
        # The ad-block guard mode the console has set, carried here rather than
        # read by the template layer for the same reason maintenance is: this is
        # the one place per process that talks to the settings table. ``None``
        # means "nobody could tell us" — it is not a mode. Nothing reads this
        # field: templating.guard_mode() returns its own literal either way.
        self.guard_mode = guard_mode
        # The site-wide ``ads_enabled`` master switch, on the snapshot for the
        # same reason the guard mode is. Three states, and the third is the point:
        # ``True``/``False`` are an operator's answer, and ``None`` means nobody
        # could tell us. templating.guard_mode() only stands the guard down on an
        # explicit ``False`` — see its docstring for why ``None`` must fail open.
        self.ads_enabled = ads_enabled

    # -- flags -------------------------------------------------------------

    @property
    def maintenance(self):
        return bool(self.flags.get("maintenance"))

    @property
    def registration(self):
        return bool(self.flags.get("registration"))

    @property
    def deploys(self):
        return bool(self.flags.get("deploys"))

    @property
    def uploads(self):
        return bool(self.flags.get("uploads"))

    @property
    def console(self):
        return bool(self.flags.get("console"))

    @property
    def house_ads(self):
        return bool(self.flags.get("house_ads"))

    # -- limits ------------------------------------------------------------

    @property
    def max_servers(self):
        return int(self.limits.get("max_servers", 0))

    @property
    def memory_mb(self):
        return int(self.limits.get("memory_mb", 0))

    @property
    def cpu_percent(self):
        return int(self.limits.get("cpu_percent", 0))

    @property
    def disk_mb(self):
        return int(self.limits.get("disk_mb", 0))

    # -- derived -----------------------------------------------------------

    def writes_allowed(self):
        """Whether state-changing actions may proceed at all.

        Maintenance mode is the single gate every mutating route consults, so the
        question is asked in one place instead of each route re-deriving it.
        """
        return not self.maintenance


def _env_guard_mode():
    """The guard mode recorded when the settings table cannot be read.

    Deferred to :mod:`.templating` instead of restating its literal here. The
    environment variable and the panel's default for it belong to the template
    layer — a second copy of ``"gate"`` in this module would be right today and
    wrong the first time only one of the two was edited. Nothing reads the
    ``guard_mode`` field this fills, though: templating.guard_mode() returns its
    own literal for every visitor, so this value arms no guard and a divergent
    copy would be a latent inconsistency rather than a behaviour change.

    Imported inside the function rather than at module scope for two reasons: at
    import time ``templating`` builds the Jinja environment and pulls in
    ``auth``/``cf_edge``, which is a lot of work for one string on a module every
    route imports; and this is the panel's data layer importing its presentation
    layer, so keeping the edge inside a call is what stops a future
    ``templating`` -> ``panel_settings`` import (an isinstance check, a default
    snapshot) from becoming a cycle.

    Answers ``None`` if that import or the read fails at all. :func:`_fallback`
    runs *inside* ``load()``'s except handler, so an exception raised from here
    would escape as the failure of the very call that exists to keep the panel
    rendering through a database outage. ``None`` costs nothing downstream:
    nothing reads the field either value fills.
    """
    try:
        from .templating import _configured_guard_mode

        return _configured_guard_mode()
    except Exception:
        return None


def _fallback(config):
    """The snapshot to serve when the settings table cannot be read.

    Mirrors what the panel did before it had database-backed controls: the
    environment's own values, and the built-in allocation figures for the rows
    that never had an environment variable in the first place.
    """
    return PanelSettings(
        flags={
            "maintenance": False,
            "registration": bool(getattr(config, "allow_registration", False)),
            "deploys": True,
            "uploads": True,
            "console": True,
            # True, like deploys/uploads above and unlike ads_enabled below: the
            # built-in matches the PANEL_FLAGS default, so an unreadable database
            # does not quietly switch the panel's own promos off. Guessing is safe
            # here precisely because it is not safe there — a promo slot that shows
            # or does not show during an outage costs nothing, while inventing an
            # answer for the site-wide master switch would misreport a decision an
            # operator actually made.
            "house_ads": True,
        },
        limits={
            "max_servers": int(getattr(config, "max_servers_per_user", 1)),
            "memory_mb": 300,
            "cpu_percent": 35,
            "disk_mb": 600,
        },
        maintenance_message=_FALLBACK_MESSAGE,
        from_database=False,
        guard_mode=_env_guard_mode(),
        # Deliberately None rather than True. There is no PANEL_ADS_ENABLED to
        # resolve the way _env_guard_mode() resolves PANEL_GUARD_MODE, so the only
        # honest answer on this path is "nobody could tell us" — and None is the
        # value templating.guard_mode() already fails open on, so the guard stays
        # armed exactly as it did before the snapshot carried this switch.
        #
        # Writing True would reach the same behaviour today and be a worse record
        # of why: it would claim an operator had confirmed ads are on, which is
        # the one thing this path knows it cannot establish. Any later consumer
        # that needs to tell "on" from "unknown" — a page that wants to say
        # "environment defaults" about this row the way from_database does about
        # the others — would then have no way to.
        ads_enabled=None,
    )


class SettingsReader:
    """Cached access to the panel's database-backed controls.

    One instance lives on :class:`~.runtime.PanelRuntime` for the process. It is
    not thread-safe by design: the worst a race can do is two threadpool workers
    both refreshing the same snapshot, and either answer is correct.
    """

    def __init__(self, config):
        self._config = config
        self._cached = None
        self._fetched_at = 0.0
        self._refresh_lock = None
        self._refresh_loop = None
        self._generation = 0
        # Set once, on the first failure, so a panel running without the sync
        # database module logs the reason a single time instead of on every page.
        self._warned = False
        # Same idea, for the guard-mode read alone: it can fail while the rest of
        # the snapshot is perfectly good, and that is worth saying once.
        self._guard_warned = False
        # And its own flag again for the master switch, rather than sharing
        # _guard_warned. The two reads hit different rows through different
        # functions and fail independently — `ad_guard_mode` through
        # get_ad_guard_mode, `ads_enabled` through get_ad_enabled — so a shared
        # flag would mean whichever failed first silenced the other's message for
        # the life of the process. That is precisely the case where the log matters
        # most: the two failures resolve differently (a dead guard-mode read keeps
        # the guard armed on the environment's mode, a dead master-switch read
        # keeps it armed by failing open), so an operator reading one line would
        # draw the wrong conclusion about which control is actually live.
        self._ads_warned = False

    def _read_backend(self):
        from .backend_store import BackendStoreError, _TIMEOUT_SECONDS, _post

        payload = _post(self._config, _BACKEND_SETTINGS_READ, {}, _TIMEOUT_SECONDS)
        raw = payload.get("settings")
        if not isinstance(raw, dict):
            raise BackendStoreError(
                f"panel store call to {_BACKEND_SETTINGS_READ} returned unusable settings"
            )
        return raw

    def _read_sync(self):
        if self._config.store == "backend":
            return self._read_backend()
        # Imported here, not at module scope: `database` resolves its Oracle
        # connection at import time, and on the SQLite smoke-test path it is not
        # importable at all. A module-scope import would make this file — and so
        # every route that reads a setting — unusable there.
        import database

        raw = dict(database.get_panel_settings())
        # Two more queries, on purpose. Neither row is a panel_* control, so
        # get_panel_settings' LIKE 'panel_%' never matches them: `ad_guard_mode`
        # and `ads_enabled` are the site-wide ad settings the Flask tier reads, and
        # the panel needs both to decide what its pages arm. All three reads happen
        # in one threadpool hop here rather than one per request, so the cost is
        # three round trips per CACHE_SECONDS, not per page.
        #
        # Each is caught separately rather than left to load()'s handler, because
        # the reads are not worth the same. Falling the whole snapshot back to the
        # environment resets `maintenance` to False — an operator who has paused
        # the panel would find it taking writes again — and it would be absurd to
        # spend that on either ad setting. So a read that fails leaves its own field
        # as None and the database-backed controls stand; templating.guard_mode()
        # resolves each None on its own terms.
        try:
            raw["guard_mode"] = database.get_ad_guard_mode()
        except Exception as exc:
            if not self._guard_warned:
                self._guard_warned = True
                print(
                    "[panel] settings: ad guard mode unreadable "
                    f"({type(exc).__name__}: {exc}); using PANEL_GUARD_MODE. "
                    "The rest of the panel's controls are unaffected."
                )
            raw["guard_mode"] = None
        # The master switch, in its own handler for the same reason and with the
        # opposite resolution: a guard mode that cannot be read falls back to a
        # mode, while a master switch that cannot be read must not be guessed at
        # all. None here means templating.guard_mode() leaves the guard armed
        # rather than standing it down, which is the direction that costs an
        # unnecessary banner instead of silently disabling detection site-wide.
        try:
            raw["ads_enabled"] = bool(database.get_ad_enabled())
        except Exception as exc:
            if not self._ads_warned:
                self._ads_warned = True
                print(
                    "[panel] settings: ads master switch unreadable "
                    f"({type(exc).__name__}: {exc}); leaving the ad-block guard "
                    "armed. The rest of the panel's controls are unaffected."
                )
            raw["ads_enabled"] = None
        return raw

    def _refresh_lock_for_loop(self):
        loop = asyncio.get_running_loop()
        if self._refresh_lock is None or self._refresh_loop is not loop:
            self._refresh_lock = asyncio.Lock()
            self._refresh_loop = loop
        return self._refresh_lock

    async def load(self):
        """The current snapshot, from cache when it is fresh enough."""
        now = time.time()
        cached = self._cached
        if cached is not None and now - self._fetched_at < CACHE_SECONDS:
            return cached

        lock = self._refresh_lock_for_loop()
        waited = lock.locked()
        if waited and cached is not None:
            return cached

        async with lock:
            now = time.time()
            cached = self._cached
            if cached is not None and (waited or now - self._fetched_at < CACHE_SECONDS):
                return cached
            generation = self._generation

            try:
                raw = await run_in_threadpool(self._read_sync)
                snapshot = PanelSettings(
                    flags=dict(raw.get("flags") or {}),
                    limits=dict(raw.get("limits") or {}),
                    maintenance_message=raw.get("maintenance_message") or _FALLBACK_MESSAGE,
                    from_database=True,
                    # database.get_ad_guard_mode validates on read, so this is already
                    # one of its known modes; templating re-checks it anyway rather
                    # than trusting a value that crossed a process boundary.
                    guard_mode=raw.get("guard_mode"),
                    # True, False, or None when the read failed. Passed through as-is:
                    # the difference between "an operator turned ads off" and "we could
                    # not ask" is exactly what templating.guard_mode() needs to fail
                    # open on, so it must not be flattened to a bool here.
                    ads_enabled=raw.get("ads_enabled"),
                )
            except Exception as exc:
                # Deliberately broad: ImportError (no sync database module), an
                # Oracle failure, and a malformed row all mean the same thing to the
                # panel — serve the environment's values and stay up.
                if not self._warned:
                    self._warned = True
                    print(
                        "[panel] settings: falling back to the environment "
                        f"({type(exc).__name__}: {exc}). The admin console's Panel "
                        "Controls page will not affect this instance until the "
                        "shared database is readable from it."
                    )
                snapshot = _fallback(self._config)

            # Cached either way, so a database that is down does not mean an Oracle
            # attempt on every single request.
            if generation == self._generation:
                self._cached = snapshot
                self._fetched_at = now
            return snapshot

    def invalidate(self):
        """Drop the cache so the next read goes to the database."""
        self._generation += 1
        self._cached = None
        self._fetched_at = 0.0

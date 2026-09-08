# migrations/

Hand-run SQL against the Oracle ATP. The app's own automatic DDL is
`Base.metadata.create_all` in `app/database.py::init_db`, and that is
**check-first at table level**: it creates tables that do not exist and never
looks inside one that does. So any change to a column, constraint or index on a
table that already exists in the live schema has to arrive as a script in this
directory.

The one exception is the panel's three tables. `panel_app/database.py::
ensure_schema` runs on every panel start and is *column*-aware: it creates a
`panel_*` table the schema is missing and ALTERs in a model column an existing
one predates, from the DDL in `_ADDITIVE_COLUMNS`. So 002 below is applied
automatically now — it is kept for a panel that is not running, and for the
verification queries. `PANEL_INIT_DB` no longer gates that (it only gates the
explicit `init_db()`); the races two load-balanced instances create are handled
by tolerating ORA-00955 / ORA-01430 and retrying the lock errors. A panel model
column with no `_ADDITIVE_COLUMNS` entry is *not* invented — it is reported as a
startup warning naming the column, and needs a script here.

## Scripts

| # | Script | What it changes | Run when |
|---|--------|-----------------|----------|
| 001 | `001_panel_user_ids_to_varchar2_36.sql` | `panel_users.id`, `panel_servers.user_id`, `panel_activity.user_id`: `NUMBER` → `VARCHAR2(36)`. Also creates `ix_panel_users_username_lower` if missing. | The `panel_*` tables already exist in Oracle from before the single sign-in. Not needed on a schema that has never had them. |
| 002 | `002_panel_servers_desired_state.sql` | Adds `panel_servers.desired_state` (`NUMBER DEFAULT 0 NOT NULL`): the panel's record of whether a server was last commanded running (1) or stopped (0). | Applied automatically by `ensure_schema` on every panel start. Run by hand only against a stopped panel, or to verify. |
| 003 | `003_panel_servers_cpu_percent_35.sql` | Restates the `panel_servers.cpu_percent` of existing rows from `100` to `35` (and corrects a stored column `DEFAULT` if the schema has one). | Any `panel_servers` row still reads `100`. `ensure_schema` cannot do this one: the column already exists, and the change is to its data. |

## 001 — why it exists

The panel used to have its own sign-in and minted its own integer user ids. It no
longer does: a visitor authenticates on the Flask site, and the panel resolves
that session through the backend's `GET /api/session/<sid>`. The id it stores is
now the **main site's** `VARCHAR2(36)` user id.

`app/panel/oracle_models.py` already declares all three columns `String(36)`.
On a fresh schema that is the whole story. On a schema whose `panel_*` tables
predate the change, `create_all` sees three tables that exist and does nothing —
so the first panel request by any signed-in user tries to write a 36-character
UUID into a `NUMBER` column. That raises `ORA-01722: invalid number`, which is a
`DatabaseError` and **not** the `IntegrityError` that `store.py::ensure_user_by_id`
catches, so it surfaces as an unhandled 500 on every panel page for every user.

Running 001 is what stands between the rewrite and a working first request.

## Deciding whether you need it

```sql
SELECT table_name, column_name, data_type, char_length
  FROM user_tab_columns
 WHERE table_name = 'PANEL_USERS' AND column_name = 'ID';
```

* **No rows** — the tables are not there. Do **not** run 001. Start the panel once
  with `PANEL_INIT_DB=1` and `create_all` builds all three correctly keyed.
* **`NUMBER`** — run 001.
* **`VARCHAR2` / 36** — already done. 001 detects this and exits without changes,
  so running it again is harmless.

## Running 001

Stop the panel tier on **both** instances first (`TIERS=` without `panel`, or stop
the whole stack). Nothing else needs to stop: 001 touches no table the Flask tiers
use, and the Flask session store is untouched, so signed-in users stay signed in.

```
sql <user>/<password>@<dsn> @001_panel_user_ids_to_varchar2_36.sql
```

The script is in four sections. Section 1 is read-only preflight — **read its
output before letting section 2 run**, in particular the row counts, the
`max_id_chars` line, and the duplicate-username list. Section 2 does the work and
echoes every statement it executes. Section 3 verifies. Section 4 is prose about
the rows that were already there, and executes nothing.

Take a backup first. On ATP a timestamp is enough, since a PITR clone or Data Pump
can bring the three tables back:

```sql
SELECT SYSTIMESTAMP FROM dual;
```

## If it fails partway

**Do not roll back.** Oracle commits after every DDL statement, so section 2
cannot be one transaction — but every step in it is guarded by a check of the
state it is about to change, which makes the block re-runnable. Read the echoed
statements to see where it stopped, fix that cause, and run the script again: it
resumes from where it stopped rather than repeating what it already did. A run
that finds nothing left to do says `Nothing to do` and changes nothing.

Two failures are expected enough to be handled explicitly, both raised **before**
any change:

* `ORA-20001` — an existing id needs more than 36 characters. Nothing realistic
  causes this; it is a refusal rather than a silent truncation.
* `ORA-20002` — two `panel_users` rows collide case-insensitively, so
  `ix_panel_users_username_lower` cannot be created. The re-key itself is already
  complete and committed at that point; only the index step remains. Section 4
  has the rename to resolve it.

## After it succeeds

Section 4 covers this in detail; the short version:

Every pre-existing panel user is still present, with its old integer id
stringified (`'7'`). Those ids came from the panel's own sequence, so no site
session will ever present one — those accounts cannot be signed in to and their
servers cannot be reached. Their `password_hash` is inert too: there is no login
form left to check it against.

They are not only dead weight. `panel_users.username` is unique on
`LOWER(username)`, so a leftover row named `arya` blocks mirroring the site
account that also calls itself `arya` — that visitor gets a **409
(`MirrorConflict`) on every panel page**, indefinitely. Decide what happens to
those rows before reopening the panel: re-point them at the real site ids (the
only option that keeps a customer's servers, and it needs a Python script because
the site stores usernames as randomized Fernet ciphertext), leave them, or delete
them. Section 4 spells out all three.

## Two things 001 changes that are not the re-key

Worth knowing, because a schema migrated by 001 is not byte-identical to one built
fresh by `create_all`:

1. **Constraint names.** The model declares the PK and both FKs unnamed, so Oracle
   had named them `SYS_C00…`. 001 cannot reproduce a system name, so it puts them
   back as `PK_PANEL_USERS`, `FK_PANEL_SERVERS_USER` and `FK_PANEL_ACTIVITY_USER`.
   Nothing in the panel refers to a constraint by name, and `create_all` still
   sees the tables as existing, so this is cosmetic. The index names are
   unaffected — 001 reads each one before dropping its column and puts it back
   under the same name.
2. **Column order.** Oracle cannot retype a populated column in place, so 001 adds
   a staging column, copies, drops the original and renames — which leaves the
   re-keyed column last in the table rather than in its declared position. The ORM
   addresses columns by name, so nothing reads it positionally.

## 002 — why it exists

The panel kept no record of whether a server was *meant* to be running: it read
every status live from the node agent. So a server the owner stopped could reappear
as running — the node host rebooted, or the container exited on its own and
Docker's old `unless-stopped` policy revived it — and the panel had nothing that
said it should have stayed down.

`panel_servers.desired_state` is that record: `1` = last commanded running, `0` =
stopped. `routes.py` writes it on every accepted power action (start/restart → 1,
stop/kill → 0, create → 0) and reads it on load, so a stopped server stays
presented as stopped (`routes._effective_status`), and nothing here silently
starts one the owner stopped. It pairs with the node-agent change from
`unless-stopped` to `on-failure` in `node_agent/container_spec.py`, which stops the
daemon resurrecting a container on reboot or clean exit while still restarting one
that crashes.

`app/panel_app/oracle_models.py` declares the column
(`Column(Integer, nullable=False, default=0)`). On a fresh schema `create_all`
builds it. On an existing `panel_servers`, `create_all` sees the table and does
nothing — so the ALTER has to come from somewhere else. That somewhere is now
`panel_app/database.py::ensure_schema` at panel startup; 002 is the same ALTER for
an operator who would rather do it against a stopped panel.

### Deciding whether you need it

Start the panel and read its log: `[panel] schema: added panel_servers.desired_state`
means it is done. The query below answers the same question directly.

```sql
SELECT column_name, data_type, nullable
  FROM user_tab_columns
 WHERE table_name = 'PANEL_SERVERS' AND column_name = 'DESIRED_STATE';
```

* **No `PANEL_SERVERS` table** — the panel has never run on Oracle. Do **not** run
  002; starting the panel creates `panel_servers` already carrying the column.
* **No rows for `DESIRED_STATE`** — starting the panel adds it. Run 002 only if you
  want it added while the panel stays down.
* **One row** — already done. 002 detects this and exits without changes, so
  running it again is harmless.

### Running 002

Stop the panel tier on **both** instances first. 002 touches no table the Flask
tiers use.

```
sql <user>/<password>@<dsn> @002_panel_servers_desired_state.sql
```

Section 1 is read-only preflight, section 2 adds the column (a metadata-only
default on ATP, so no table rewrite; every existing row reads `0`), section 3
verifies.

If neither `sql` nor `sqlplus` is installed on the host, `run_002_desired_state.py`
issues the same guarded ALTER through python-oracledb, reading the same `.env` and
wallet the app tiers use. It is read-only until `--apply`:

```
python run_002_desired_state.py            # preflight only
python run_002_desired_state.py --apply    # add the column, then verify
``` Every pre-existing server reads `0` (stopped) until its owner next starts
it — harmless, because the live node status still wins on the dashboard whenever
the node is reachable.

## 003 — why it exists

The node's per-container CPU quota dropped from a full core to 35% of one.
`node_agent/container_spec.py` now reads `CPU_PERCENT = 35` and derives
`NANO_CPUS` from it (`350_000_000`), the agent refuses a create that asks for
anything else, and the panel sends and stores `35` for every server made from
here on.

That leaves the rows already in `panel_servers`, which still read `100`.
`server.html` renders that stored number as the server's CPU limit and
`routes.py` sums it for the dashboard's allocation total, so without 003 every
pre-existing server advertises a full core it no longer gets, and the total is
overstated by 65 points per server.

This is the first script here that `ensure_schema` cannot cover, and the reason
is worth stating: `cpu_percent` is not a *missing* column, it is an existing
column holding the wrong number. `ensure_schema` is additive DDL only and issues
no DML at all, by contract — putting a data backfill in it would make every
panel start a writer of customer rows.

### Deciding whether you need it

```sql
SELECT cpu_percent, COUNT(*) AS servers
  FROM panel_servers
 GROUP BY cpu_percent;
```

* **`ORA-00942`** — the panel has never run on Oracle. Do **not** run 003;
  starting the panel builds `panel_servers`, and the model supplies `35` on every
  insert.
* **Any group other than 35** — run 003.
* **A single group of 35** — already done. 003 detects this, says
  `Nothing to do` and changes nothing, so running it again is harmless.

### Running 003

The panel tier does **not** need to stop. `cpu_percent` is display-only — no code
branches on it — so a partially applied run cannot leave the panel broken, and a
page rendered mid-run is at worst showing a number that is about to change.
Running it while the tier is quiet just keeps the before/after counts clean.

```
sql <user>/<password>@<dsn> @003_panel_servers_cpu_percent_35.sql
```

Section 1 is read-only preflight, section 2 issues one `UPDATE` bounded to the
rows that are actually wrong, and section 3 verifies.

Section 2 also corrects the column's stored `DEFAULT`, but only if there already
is one. `oracle_models.py` declares `default=35`, which SQLAlchemy applies in
Python, so `create_all` emits no DDL default and a fresh schema carries none —
inventing one here would leave a migrated schema differing from a fresh one for
nothing, since the column is `NOT NULL` and an insert that omits it fails with
`ORA-01400` either way. (The SQLite store is the other way round:
`panel_database.py` spells `DEFAULT 35` into its `CREATE TABLE`.)

### What 003 does not do

It corrects what the panel *displays*. A container's real quota is fixed by
Docker when the container is created, so a container built before the change
keeps its 1.0-CPU quota until it is rebuilt. `ServerManager._rebuild` is what
applies a new spec, and it is reached from `update_startup` and `update_version`
— so re-saving a server's startup command in the panel (or changing its runtime
version) is what moves it onto the new cap.

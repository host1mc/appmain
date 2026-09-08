-- =====================================================================
-- 003_panel_servers_cpu_percent_35.sql
--
-- Restate one column's stored value on panel_servers:
--
--     panel_servers.cpu_percent   100 -> 35
--
-- WHY. The node agent's per-container CPU quota dropped from a full core to 35%
-- of one: node_agent/container_spec.py now reads CPU_PERCENT = 35 and derives
-- NANO_CPUS from it (35 * 10_000_000 = 350_000_000 nano CPUs), and the agent
-- rejects a create that asks for anything else. The panel already sends and
-- stores 35 for every server created from here on
-- (panel_app/node_client.py, panel_app/store.py, panel_app/oracle_models.py).
--
-- This script is only about rows that already exist. They still read 100, and
-- panel_app/templates/server.html renders that stored number as the server's
-- CPU limit while routes.py sums it for the dashboard's allocation total — so
-- without this, every pre-existing server advertises a full core it no longer
-- gets, and the total is overstated by 65 points per server.
--
-- NOT ENOUGH ON ITS OWN. This corrects what the panel *displays*. What the
-- container actually gets is fixed when Docker creates the container, so a
-- container built before the change keeps its 1.0-CPU quota until it is rebuilt.
-- ServerManager._rebuild is what applies a new spec, and it is reached from
-- update_startup and update_version — so re-saving a server's startup command in
-- the panel is enough to move it onto the new cap.
--
-- WHY ensure_schema CANNOT DO THIS. panel_app/database.py::ensure_schema is
-- strictly additive by contract: it creates a missing panel table and ALTERs in
-- a missing model column, and issues no DML at all. cpu_percent is not a missing
-- column — it is an existing column holding the wrong number, and a data
-- backfill there would make every panel start a writer of customer rows.
--
-- WHEN THIS IS NOT NEEDED. If panel_servers does not exist in Oracle yet, do
-- not run this — start the panel once with PANEL_INIT_DB=1 and create_all builds
-- the table, and the model supplies 35 on every insert. It is likewise a no-op
-- once every row reads 35, so running it again is harmless.
--
-- SAFETY. One UPDATE, bounded to the rows that do not already read 35 and
-- committed by the anonymous block. The column DEFAULT is only corrected if the
-- schema already carries one (see section 2) — no default is invented, so a
-- schema migrated by this script still matches one built fresh by create_all.
-- No other column, row or object is touched, and nothing is dropped. Row counts
-- are reported before and after. cpu_percent is display-only in the panel — no
-- code branches on it — so a partially applied run cannot put the panel in a
-- broken state.
--
-- HOW TO RUN. Against the ATP as the panel's own schema owner. The panel tier
-- does not need to stop; a page rendered mid-run is at worst showing a number
-- that is about to change. Running it while the tier is quiet keeps the
-- before/after counts clean.
--
--     sql <user>/<password>@<dsn> @003_panel_servers_cpu_percent_35.sql
--
-- Read section 1's output before letting section 2 run.
-- =====================================================================

SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 200
SET PAGESIZE 200
SET FEEDBACK ON

PROMPT
PROMPT =====================================================================
PROMPT 1. PREFLIGHT  (read-only — nothing below changes anything)
PROMPT =====================================================================

PROMPT
PROMPT -- Does panel_servers exist at all. Zero rows here means the panel has
PROMPT -- never run on Oracle: stop, and use PANEL_INIT_DB=1 instead.
SELECT table_name
  FROM user_tables
 WHERE table_name = 'PANEL_SERVERS';

PROMPT
PROMPT -- The column itself. Expected NUMBER, nullable N, and an *empty*
PROMPT -- data_default: the model declares default=35, which SQLAlchemy applies
PROMPT -- in Python, so create_all emits no DDL default. A 100 here means
PROMPT -- something did set one, and section 2 restates it to 35.
SELECT column_name, data_type, data_default, nullable
  FROM user_tab_columns
 WHERE table_name = 'PANEL_SERVERS'
   AND column_name = 'CPU_PERCENT';

PROMPT
PROMPT -- How many rows section 2 will restate.
PROMPT -- (Skipped silently if panel_servers does not exist yet.)
DECLARE
  l_n     NUMBER := 0;
  l_stale NUMBER := 0;
  l_rows  NUMBER := 0;
BEGIN
  SELECT COUNT(*) INTO l_n FROM user_tables WHERE table_name = 'PANEL_SERVERS';
  IF l_n = 0 THEN
    DBMS_OUTPUT.PUT_LINE('panel_servers does not exist — nothing to report.');
    RETURN;
  END IF;
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM panel_servers' INTO l_rows;
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM panel_servers'
                 || ' WHERE cpu_percent <> 35 OR cpu_percent IS NULL' INTO l_stale;
  DBMS_OUTPUT.PUT_LINE('panel_servers rows: ' || l_rows
                       || ' — ' || l_stale || ' not yet reading 35');
END;
/

PROMPT
PROMPT -- The current distribution, for the record.
SELECT cpu_percent, COUNT(*) AS servers
  FROM panel_servers
 GROUP BY cpu_percent
 ORDER BY cpu_percent;

PROMPT
PROMPT =====================================================================
PROMPT 2. MIGRATION
PROMPT =====================================================================
PROMPT

DECLARE
  c_servers CONSTANT VARCHAR2(128) := 'PANEL_SERVERS';
  c_cpu     CONSTANT VARCHAR2(128) := 'CPU_PERCENT';
  c_target  CONSTANT NUMBER        := 35;
  g_steps   NUMBER := 0;
  l_rows    NUMBER := 0;
  l_default VARCHAR2(4000);

  PROCEDURE ddl(p_sql VARCHAR2) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE('  > ' || p_sql);
    EXECUTE IMMEDIATE p_sql;
    g_steps := g_steps + 1;
  END ddl;

  FUNCTION table_exists(p_table VARCHAR2) RETURN BOOLEAN IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n FROM user_tables WHERE table_name = p_table;
    RETURN n > 0;
  END table_exists;

  FUNCTION column_exists(p_table VARCHAR2, p_column VARCHAR2) RETURN BOOLEAN IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n FROM user_tab_columns
     WHERE table_name = p_table AND column_name = p_column;
    RETURN n > 0;
  END column_exists;

  -- data_default is a LONG: it cannot be passed through a SQL function at all
  -- (SUBSTR on it raises ORA-00932), and selecting it straight into a PL/SQL
  -- VARCHAR2 is the one conversion Oracle does allow. NULL means the column
  -- carries no stored default, which is what create_all leaves behind.
  FUNCTION stored_default(p_table VARCHAR2, p_column VARCHAR2) RETURN VARCHAR2 IS
    l_value VARCHAR2(4000);
  BEGIN
    SELECT data_default INTO l_value
      FROM user_tab_columns
     WHERE table_name = p_table AND column_name = p_column;
    RETURN TRIM(l_value);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN NULL;
  END stored_default;
BEGIN
  IF NOT table_exists(c_servers) THEN
    DBMS_OUTPUT.PUT_LINE('panel_servers does not exist — nothing to migrate.');
    DBMS_OUTPUT.PUT_LINE('Start the panel once with PANEL_INIT_DB=1 instead: create_all');
    DBMS_OUTPUT.PUT_LINE('builds panel_servers, and the model supplies 35 on insert.');
    RETURN;
  END IF;

  IF NOT column_exists(c_servers, c_cpu) THEN
    DBMS_OUTPUT.PUT_LINE('panel_servers.cpu_percent does not exist — nothing to migrate.');
    DBMS_OUTPUT.PUT_LINE('That is older than 001; do not continue without checking the table.');
    RETURN;
  END IF;

  -- 1. The existing rows. Bounded to the ones that are actually wrong, so a
  --    re-run updates nothing.
  EXECUTE IMMEDIATE 'UPDATE panel_servers SET cpu_percent = :v'
                 || ' WHERE cpu_percent <> :v OR cpu_percent IS NULL'
    USING c_target, c_target;
  l_rows := SQL%ROWCOUNT;
  IF l_rows > 0 THEN
    g_steps := g_steps + 1;
    DBMS_OUTPUT.PUT_LINE('  > UPDATE panel_servers SET cpu_percent = 35 (' || l_rows || ' row(s))');
  END IF;
  COMMIT;

  -- 2. Any stored column DEFAULT — restated, never invented. The model's
  --    default=35 is applied in Python, so create_all emits no DDL default and a
  --    fresh schema has none; adding one here would leave a migrated schema
  --    differing from a fresh one for no gain, since the column is NOT NULL and
  --    an INSERT that omits it fails with ORA-01400 either way. A schema that
  --    does carry a default (from an older model, or an earlier hand-run script)
  --    would keep handing out 100, which is what this corrects. Metadata only:
  --    no row is rewritten.
  l_default := stored_default(c_servers, c_cpu);
  IF l_default IS NULL THEN
    DBMS_OUTPUT.PUT_LINE('  . cpu_percent carries no stored DEFAULT, which is what');
    DBMS_OUTPUT.PUT_LINE('    create_all leaves behind — not inventing one.');
  ELSIF l_default <> TO_CHAR(c_target) THEN
    ddl('ALTER TABLE ' || c_servers || ' MODIFY (' || c_cpu || ' DEFAULT ' || c_target || ')');
  END IF;

  DBMS_OUTPUT.PUT_LINE('');
  IF g_steps = 0 THEN
    DBMS_OUTPUT.PUT_LINE('Nothing to do — every row already reads 35.');
  ELSE
    DBMS_OUTPUT.PUT_LINE('Done: ' || g_steps || ' change(s). Section 3 verifies the result.');
  END IF;
END;
/

PROMPT
PROMPT =====================================================================
PROMPT 3. VERIFY  (read-only)
PROMPT =====================================================================

PROMPT
PROMPT -- Expected: one row, CPU_PERCENT / NUMBER / nullable N. data_default
PROMPT -- stays empty unless the schema already carried one, in which case it
PROMPT -- now reads 35.
SELECT column_name, data_type, data_default, nullable
  FROM user_tab_columns
 WHERE table_name = 'PANEL_SERVERS'
   AND column_name = 'CPU_PERCENT';

PROMPT
PROMPT -- Expected: no rows. Anything here is a server still advertising a quota
PROMPT -- the node no longer grants it.
SELECT id, cpu_percent
  FROM panel_servers
 WHERE cpu_percent <> 35
    OR cpu_percent IS NULL;

PROMPT
PROMPT -- Expected: a single group, 35, covering every server.
SELECT cpu_percent, COUNT(*) AS servers
  FROM panel_servers
 GROUP BY cpu_percent
 ORDER BY cpu_percent;

PROMPT
PROMPT =====================================================================
PROMPT AFTER THIS SCRIPT
PROMPT =====================================================================
PROMPT
PROMPT Containers created before the change still hold their old 1.0-CPU quota:
PROMPT the limit is fixed when Docker creates the container. Re-saving a
PROMPT server's startup command (or changing its runtime version) rebuilds it
PROMPT onto the new spec; nothing else needs to be done to it.
PROMPT
PROMPT =====================================================================
PROMPT ROLLBACK
PROMPT =====================================================================
PROMPT
PROMPT Only meaningful together with reverting CPU_PERCENT in
PROMPT node_agent/container_spec.py and the panel's 35s, since the number here is
PROMPT what the panel advertises for a quota the node enforces:
PROMPT
PROMPT     UPDATE panel_servers SET cpu_percent = 100;
PROMPT     COMMIT;
PROMPT
PROMPT Add the DEFAULT back only if section 1 showed the schema had one:
PROMPT
PROMPT     ALTER TABLE panel_servers MODIFY (cpu_percent DEFAULT 100);
PROMPT
PROMPT On ATP a pre-change timestamp is enough to recover the table wholesale if
PROMPT needed (Data Pump or a PITR clone):
PROMPT
PROMPT     SELECT SYSTIMESTAMP FROM dual;
PROMPT

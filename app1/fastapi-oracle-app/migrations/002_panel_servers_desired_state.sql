-- =====================================================================
-- 002_panel_servers_desired_state.sql
--
-- Add one column to panel_servers:
--
--     panel_servers.desired_state  NUMBER DEFAULT 0 NOT NULL
--
-- 1 = the owner last commanded this server running, 0 = stopped.
--
-- WHY. The panel used to hold no record of whether a server was meant to be
-- running: every status it showed was read live from the node agent, so a
-- server the owner stopped could come back — after the node rebooted, or after
-- the container exited on its own and Docker's old unless-stopped policy revived
-- it — and the panel had nothing to say it should have stayed down. This column
-- is the panel's record of intent. routes.py writes it on every accepted power
-- action (1 on start/restart, 0 on stop/kill, 0 at create) and reads it on load,
-- so a stopped server stays presented as stopped and nothing silently restarts
-- one the owner stopped. It pairs with the node-agent change from unless-stopped
-- to on-failure (node_agent/container_spec.py), which stops the daemon
-- resurrecting a container on reboot or clean exit.
--
-- app/panel_app/oracle_models.py already declares this column
-- (PanelServer.desired_state = Column(Integer, nullable=False, default=0)) —
-- this script brings an existing panel_servers table up to it.
-- Base.metadata.create_all cannot: it is check-first at table level, so it sees
-- a panel_servers that exists and does nothing to its columns.
--
-- WHEN THIS IS NOT NEEDED. If the panel has only ever run on the SQLite store,
-- panel_servers does not exist in Oracle yet. Do not run this. Start the panel
-- once with PANEL_INIT_DB=1 and create_all builds panel_servers already carrying
-- desired_state. The script detects that case and exits without touching
-- anything. It is likewise a no-op if the column is already present, so it is
-- safe to run again.
--
-- SAFETY. This is a single ADD COLUMN. On ATP (19c+) an ADD of a NOT NULL column
-- with a DEFAULT is a metadata-only operation — existing rows read 0 without a
-- table rewrite. The change is guarded by a check for the column, so a re-run
-- finds it present and does nothing. The statement it executes is echoed.
--
-- No row is changed in any other way and nothing is dropped. Every existing
-- server is recorded as stopped (0); the owner's next start records 1. A server
-- that is actually running when this runs will read "stopped" as intent until
-- its next power action — harmless, because the live node status still wins on
-- the dashboard whenever the node is reachable (see routes._effective_status).
--
-- HOW TO RUN. Against the ATP as the panel's own schema owner, in a window where
-- the panel tier is stopped (both load-balanced instances). Nothing else needs
-- to stop: this touches no table the Flask tiers use.
--
--     sql <user>/<password>@<dsn> @002_panel_servers_desired_state.sql
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
PROMPT -- Is desired_state already there. One row means this script is a no-op.
PROMPT -- Expected type NUMBER, nullable N, default 0 once section 2 has run.
SELECT column_name, data_type, data_default, nullable
  FROM user_tab_columns
 WHERE table_name = 'PANEL_SERVERS'
   AND column_name = 'DESIRED_STATE';

PROMPT
PROMPT -- How many rows will be stamped with the 0 default, for the record.
PROMPT -- (Skipped silently if panel_servers does not exist yet.)
DECLARE
  l_n    NUMBER := 0;
  l_rows NUMBER := 0;
BEGIN
  SELECT COUNT(*) INTO l_n FROM user_tables WHERE table_name = 'PANEL_SERVERS';
  IF l_n = 0 THEN
    DBMS_OUTPUT.PUT_LINE('panel_servers does not exist — nothing to report.');
    RETURN;
  END IF;
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM panel_servers' INTO l_rows;
  DBMS_OUTPUT.PUT_LINE('panel_servers rows: ' || l_rows
                       || ' (each will read desired_state = 0 until its next power action)');
END;
/

PROMPT
PROMPT =====================================================================
PROMPT 2. MIGRATION
PROMPT =====================================================================
PROMPT

DECLARE
  c_servers CONSTANT VARCHAR2(128) := 'PANEL_SERVERS';
  g_steps   NUMBER := 0;

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
BEGIN
  IF NOT table_exists(c_servers) THEN
    DBMS_OUTPUT.PUT_LINE('panel_servers does not exist — nothing to migrate.');
    DBMS_OUTPUT.PUT_LINE('Start the panel once with PANEL_INIT_DB=1 instead: create_all');
    DBMS_OUTPUT.PUT_LINE('builds panel_servers already carrying desired_state.');
    RETURN;
  END IF;

  -- The whole migration: add the column if it is not already there. DEFAULT 0
  -- fills existing rows (stopped), NOT NULL matches the model. On ATP this is a
  -- metadata-only default, so it does not rewrite the table.
  IF NOT column_exists(c_servers, 'DESIRED_STATE') THEN
    ddl('ALTER TABLE ' || c_servers
        || ' ADD (DESIRED_STATE NUMBER DEFAULT 0 NOT NULL)');
  END IF;

  DBMS_OUTPUT.PUT_LINE('');
  IF g_steps = 0 THEN
    DBMS_OUTPUT.PUT_LINE('Nothing to do — panel_servers.desired_state already exists.');
  ELSE
    DBMS_OUTPUT.PUT_LINE('Done: ' || g_steps || ' statement(s). Section 3 verifies the result.');
  END IF;
END;
/

PROMPT
PROMPT =====================================================================
PROMPT 3. VERIFY  (read-only)
PROMPT =====================================================================

PROMPT
PROMPT -- Expected: one row, DESIRED_STATE / NUMBER / nullable N / default 0.
SELECT column_name, data_type, data_length, data_default, nullable
  FROM user_tab_columns
 WHERE table_name = 'PANEL_SERVERS'
   AND column_name = 'DESIRED_STATE';

PROMPT
PROMPT -- Expected: no rows. Every server should read a 0 or 1 desired_state;
PROMPT -- a NULL would mean the NOT NULL default did not take.
SELECT id, desired_state
  FROM panel_servers
 WHERE desired_state IS NULL;

PROMPT
PROMPT -- The starting distribution, for the record: every pre-existing row reads
PROMPT -- 0 (stopped) until its owner next starts it.
SELECT desired_state, COUNT(*) AS servers
  FROM panel_servers
 GROUP BY desired_state
 ORDER BY desired_state;

PROMPT
PROMPT =====================================================================
PROMPT ROLLBACK
PROMPT =====================================================================
PROMPT
PROMPT This adds a column and changes nothing else, so reversing it is a single
PROMPT drop — the panel code tolerates the column's absence only if it is also
PROMPT rolled back to before this feature, so drop it only together with that:
PROMPT
PROMPT     ALTER TABLE panel_servers DROP COLUMN desired_state;
PROMPT
PROMPT On ATP a pre-change timestamp is enough to recover the table wholesale if
PROMPT needed (Data Pump or a PITR clone):
PROMPT
PROMPT     SELECT SYSTIMESTAMP FROM dual;

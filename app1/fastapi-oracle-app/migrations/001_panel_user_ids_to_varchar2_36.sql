-- =====================================================================
-- 001_panel_user_ids_to_varchar2_36.sql
--
-- Re-key the panel's three user id columns from NUMBER to VARCHAR2(36):
--
--     panel_users.id         (primary key)
--     panel_servers.user_id  (FK -> panel_users.id ON DELETE CASCADE)
--     panel_activity.user_id (FK -> panel_users.id ON DELETE CASCADE)
--
-- and create ix_panel_users_username_lower if it is missing, which on a schema
-- this old it probably is — see section 2e.
--
-- WHY. The panel used to mint its own integer user ids, because it had its own
-- sign-in. It no longer has one: a visitor logs in on the Flask site and the
-- panel resolves that session through the backend, so the id it now stores is
-- the *main site's* VARCHAR2(36) user id, handed over already authenticated.
-- app/panel/oracle_models.py already declares all three columns String(36) —
-- this script is what brings a schema created by the older model up to it.
-- Base.metadata.create_all cannot: it is check-first at table level, so it sees
-- three tables that exist and does nothing at all.
--
-- WHEN THIS IS NOT NEEDED. If the panel has only ever run on the SQLite store,
-- these tables do not exist in Oracle yet. Do not run this. Start the panel
-- once with PANEL_INIT_DB=1 and create_all will build all three already keyed
-- VARCHAR2(36). The script detects that case and exits without touching
-- anything.
--
-- SAFETY. Oracle commits after every DDL statement, so this cannot be one
-- transaction and a failure halfway leaves a half-migrated schema. Every step
-- is therefore guarded by a check of the state it is about to change, which
-- makes the whole block re-runnable: fix whatever failed, run it again, and it
-- resumes from where it stopped. Each statement it executes is echoed, so the
-- log shows exactly how far it got. A re-run that finds nothing to do says so
-- and changes nothing.
--
-- No row is deleted and no id is invented. Existing ids are carried across as
-- TRIM(TO_CHAR(id)), which preserves referential integrity by construction: the
-- same function applied to parent and child yields the same string on both
-- sides. See section 4 for what those carried-over rows then mean.
--
-- HOW TO RUN. Against the ATP as the panel's own schema owner, in a window
-- where the panel tier is stopped (both load-balanced instances). Nothing else
-- needs to stop: this touches no table the Flask tiers use.
--
--     sql <user>/<password>@<dsn> @001_panel_user_ids_to_varchar2_36.sql
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
PROMPT -- Which of the three tables exist at all. Zero rows here means the
PROMPT -- panel has never run on Oracle: stop, and use PANEL_INIT_DB=1 instead.
SELECT table_name
  FROM user_tables
 WHERE table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
 ORDER BY table_name;

PROMPT
PROMPT -- Current types of the three columns being re-keyed. NUMBER means this
PROMPT -- script has work to do; VARCHAR2(36) means that column is already done.
PROMPT -- identity_column matters only as a warning: an identity id has a
PROMPT -- sequence behind it that is dropped with the column.
SELECT t.table_name,
       t.column_name,
       t.data_type,
       t.data_precision,
       t.char_length,
       t.nullable,
       c.identity_column
  FROM user_tab_columns t
  JOIN user_tab_cols c
    ON c.table_name = t.table_name
   AND c.column_name = t.column_name
 WHERE (t.table_name = 'PANEL_USERS'    AND t.column_name = 'ID')
    OR (t.table_name = 'PANEL_SERVERS'  AND t.column_name = 'USER_ID')
    OR (t.table_name = 'PANEL_ACTIVITY' AND t.column_name = 'USER_ID')
 ORDER BY t.table_name, t.column_name;

PROMPT
PROMPT -- Constraints that have to come off and go back on. The PK and both FKs
PROMPT -- are unnamed in the model, so Oracle named them SYS_C…; the block in
PROMPT -- section 2 resolves them from here rather than hardcoding them, and
PROMPT -- puts them back under the explicit names shown in section 3.
SELECT c.table_name,
       c.constraint_name,
       c.constraint_type,
       c.delete_rule,
       c.status
  FROM user_constraints c
 WHERE c.table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
   AND c.constraint_type IN ('P', 'R')
 ORDER BY c.table_name, c.constraint_type, c.constraint_name;

PROMPT
PROMPT -- Indexes on the columns being dropped. Oracle drops an index with its
PROMPT -- column, so section 2 recreates each one under the name it finds here.
SELECT ic.index_name,
       ic.table_name,
       ic.column_name,
       ic.column_position,
       i.uniqueness
  FROM user_ind_columns ic
  JOIN user_indexes i
    ON i.index_name = ic.index_name
 WHERE ic.table_name IN ('PANEL_SERVERS', 'PANEL_ACTIVITY')
   AND ic.column_name = 'USER_ID'
 ORDER BY ic.table_name, ic.index_name, ic.column_position;

PROMPT
PROMPT -- Is the case-insensitive uniqueness on username there at all? Expected
PROMPT -- one row, UNIQUE. Zero rows is likely on a schema this old and section 2
PROMPT -- creates it: create_all skips an existing table wholesale, indexes
PROMPT -- included, so an index added to the model after the table was first
PROMPT -- created was never applied. The panel depends on it — it is what turns a
PROMPT -- name already taken into a 409 instead of two rows claiming one name.
SELECT i.index_name, i.uniqueness, i.index_type, e.column_expression
  FROM user_indexes i
  LEFT JOIN user_ind_expressions e
    ON e.index_name = i.index_name
 WHERE i.table_name = 'PANEL_USERS'
 ORDER BY i.index_name;

PROMPT
PROMPT -- Names that already collide case-insensitively. Expected no rows: each
PROMPT -- one blocks the unique index in section 2, which will refuse to run
PROMPT -- until they are resolved by hand (see section 4).
DECLARE
  l_n NUMBER := 0;
BEGIN
  SELECT COUNT(*) INTO l_n FROM user_tables WHERE table_name = 'PANEL_USERS';
  IF l_n = 0 THEN
    DBMS_OUTPUT.PUT_LINE('panel_users does not exist — nothing to report.');
    RETURN;
  END IF;
  FOR r IN (SELECT LOWER(username) AS lname, COUNT(*) AS cnt
              FROM panel_users
             GROUP BY LOWER(username)
            HAVING COUNT(*) > 1) LOOP
    DBMS_OUTPUT.PUT_LINE('  DUPLICATE username ' || RPAD(r.lname, 34)
                         || ' rows: ' || r.cnt);
  END LOOP;
END;
/

PROMPT
PROMPT -- How much data is at stake, and whether every id still fits in 36
PROMPT -- characters once stringified. max_id_chars above 36 aborts section 2.
DECLARE
  l_rows NUMBER;
  l_len  NUMBER;
BEGIN
  FOR t IN (SELECT table_name FROM user_tables
             WHERE table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
             ORDER BY table_name) LOOP
    EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM ' || t.table_name INTO l_rows;
    DBMS_OUTPUT.PUT_LINE(RPAD(t.table_name, 18) || ' rows: ' || l_rows);
  END LOOP;

  FOR c IN (SELECT column_name FROM user_tab_columns
             WHERE table_name = 'PANEL_USERS' AND column_name = 'ID'
               AND data_type = 'NUMBER') LOOP
    EXECUTE IMMEDIATE 'SELECT NVL(MAX(LENGTH(TRIM(TO_CHAR(id)))), 0) FROM panel_users'
      INTO l_len;
    DBMS_OUTPUT.PUT_LINE('panel_users     max_id_chars: ' || l_len || '  (limit 36)');
  END LOOP;
END;
/

PROMPT
PROMPT -- The rows that will still be there afterwards but can no longer be
PROMPT -- signed in to, because their id is a panel-local integer that no site
PROMPT -- session will ever present. Read section 4 before deciding about them.
PROMPT -- (Skipped silently if panel_users does not exist yet.)
DECLARE
  l_n NUMBER := 0;
BEGIN
  SELECT COUNT(*) INTO l_n FROM user_tables WHERE table_name = 'PANEL_USERS';
  IF l_n = 0 THEN
    DBMS_OUTPUT.PUT_LINE('panel_users does not exist — nothing to report.');
    RETURN;
  END IF;
  FOR r IN (SELECT username, cnt FROM (
              SELECT u.username,
                     (SELECT COUNT(*) FROM panel_servers s WHERE s.user_id = u.id) AS cnt
                FROM panel_users u
               ORDER BY u.username
            ) WHERE ROWNUM <= 50) LOOP
    DBMS_OUTPUT.PUT_LINE('  pre-mirror user ' || RPAD(r.username, 34) || ' servers: ' || r.cnt);
  END LOOP;
END;
/

PROMPT
PROMPT =====================================================================
PROMPT 2. MIGRATION
PROMPT =====================================================================
PROMPT

DECLARE
  c_users    CONSTANT VARCHAR2(128) := 'PANEL_USERS';
  c_servers  CONSTANT VARCHAR2(128) := 'PANEL_SERVERS';
  c_activity CONSTANT VARCHAR2(128) := 'PANEL_ACTIVITY';

  -- Explicit names for what goes back on. The originals were SYS_C…, which is
  -- not a name anything can be written against, so the constraints are renamed
  -- as a side effect of this migration. Nothing in the panel refers to a
  -- constraint by name, and create_all stays a no-op regardless, because it
  -- only ever checks whether the table exists.
  c_pk_users CONSTANT VARCHAR2(128) := 'PK_PANEL_USERS';
  c_fk_srv   CONSTANT VARCHAR2(128) := 'FK_PANEL_SERVERS_USER';
  c_fk_act   CONSTANT VARCHAR2(128) := 'FK_PANEL_ACTIVITY_USER';

  -- This one is not renamed: it is spelled out in the model, so a schema built
  -- by create_all already carries exactly this name.
  c_ix_uname CONSTANT VARCHAR2(128) := 'IX_PANEL_USERS_USERNAME_LOWER';

  g_steps NUMBER := 0;

  -- All variables before the first subprogram: PL/SQL requires subprograms to
  -- come last in a declarative part.
  l_srv_idx VARCHAR2(128);
  l_act_idx VARCHAR2(128);
  l_len     NUMBER;
  l_dupes   NUMBER;
  l_rekey   BOOLEAN;

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

  FUNCTION col_type(p_table VARCHAR2, p_column VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(128);
  BEGIN
    SELECT data_type INTO v
      FROM user_tab_columns
     WHERE table_name = p_table AND column_name = p_column;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN NULL;   -- column is not there
  END col_type;

  FUNCTION col_nullable(p_table VARCHAR2, p_column VARCHAR2) RETURN BOOLEAN IS
    v VARCHAR2(1);
  BEGIN
    SELECT nullable INTO v
      FROM user_tab_columns
     WHERE table_name = p_table AND column_name = p_column;
    RETURN v = 'Y';
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN FALSE;
  END col_nullable;

  FUNCTION has_pk(p_table VARCHAR2) RETURN BOOLEAN IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n FROM user_constraints
     WHERE table_name = p_table AND constraint_type = 'P';
    RETURN n > 0;
  END has_pk;

  FUNCTION has_fk_on(p_table VARCHAR2, p_column VARCHAR2) RETURN BOOLEAN IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n
      FROM user_constraints c
      JOIN user_cons_columns cc
        ON cc.constraint_name = c.constraint_name
     WHERE c.table_name = p_table
       AND c.constraint_type = 'R'
       AND cc.column_name = p_column;
    RETURN n > 0;
  END has_fk_on;

  FUNCTION index_exists(p_index VARCHAR2) RETURN BOOLEAN IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n FROM user_indexes WHERE index_name = p_index;
    RETURN n > 0;
  END index_exists;

  -- The name of the index leading on p_column, so it can be put back as it
  -- was. Falls back to the name SQLAlchemy would have generated, which is what
  -- a schema built by create_all actually has.
  FUNCTION index_name_on(p_table VARCHAR2, p_column VARCHAR2, p_default VARCHAR2)
    RETURN VARCHAR2 IS
    v VARCHAR2(128);
  BEGIN
    SELECT index_name INTO v FROM (
      SELECT ic.index_name
        FROM user_ind_columns ic
       WHERE ic.table_name = p_table
         AND ic.column_name = p_column
         AND ic.column_position = 1
       ORDER BY ic.index_name
    ) WHERE ROWNUM = 1;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
  END index_name_on;

  PROCEDURE drop_fks_on(p_table VARCHAR2, p_column VARCHAR2) IS
  BEGIN
    FOR c IN (
      SELECT DISTINCT c.constraint_name
        FROM user_constraints c
        JOIN user_cons_columns cc
          ON cc.constraint_name = c.constraint_name
       WHERE c.table_name = p_table
         AND c.constraint_type = 'R'
         AND cc.column_name = p_column
    ) LOOP
      ddl('ALTER TABLE ' || p_table || ' DROP CONSTRAINT ' || c.constraint_name);
    END LOOP;
  END drop_fks_on;

  -- The NUMBER -> VARCHAR2(36) swap itself, minus the constraint work: add a
  -- staging column, copy, drop the original, rename the staging column into its
  -- place. Oracle cannot retype a populated column in place, so this dance is
  -- the whole reason the script exists. It leaves the column at the end of the
  -- table rather than in its declared position — cosmetic, and the ORM addresses
  -- columns by name.
  PROCEDURE retype_to_varchar36(p_table VARCHAR2, p_column VARCHAR2) IS
    l_staging CONSTANT VARCHAR2(128) := p_column || '_NEW';
  BEGIN
    IF col_type(p_table, p_column) = 'NUMBER'
       AND col_type(p_table, l_staging) IS NULL THEN
      ddl('ALTER TABLE ' || p_table || ' ADD (' || l_staging || ' VARCHAR2(36))');
    END IF;

    -- Re-runnable while both columns exist, and the only statement here that is
    -- not DDL: it needs its own COMMIT, because the next DDL would otherwise
    -- commit it as a side effect and hide a failure.
    IF col_type(p_table, p_column) = 'NUMBER'
       AND col_type(p_table, l_staging) IS NOT NULL THEN
      DBMS_OUTPUT.PUT_LINE('  > UPDATE ' || p_table || ' SET ' || l_staging
                           || ' = TRIM(TO_CHAR(' || p_column || '))');
      EXECUTE IMMEDIATE 'UPDATE ' || p_table || ' SET ' || l_staging
                        || ' = TRIM(TO_CHAR(' || p_column || '))';
      COMMIT;
      g_steps := g_steps + 1;
      ddl('ALTER TABLE ' || p_table || ' DROP COLUMN ' || p_column);
    END IF;

    IF col_type(p_table, l_staging) IS NOT NULL
       AND col_type(p_table, p_column) IS NULL THEN
      ddl('ALTER TABLE ' || p_table || ' RENAME COLUMN ' || l_staging
          || ' TO ' || p_column);
    END IF;

    IF col_type(p_table, p_column) LIKE 'VARCHAR2%'
       AND col_nullable(p_table, p_column) THEN
      ddl('ALTER TABLE ' || p_table || ' MODIFY (' || p_column
          || ' VARCHAR2(36) NOT NULL)');
    END IF;
  END retype_to_varchar36;
BEGIN
  IF NOT table_exists(c_users) THEN
    DBMS_OUTPUT.PUT_LINE('panel_users does not exist — nothing to migrate.');
    DBMS_OUTPUT.PUT_LINE('Start the panel once with PANEL_INIT_DB=1 instead: create_all');
    DBMS_OUTPUT.PUT_LINE('builds all three tables already keyed VARCHAR2(36).');
    RETURN;
  END IF;

  -- Abort before the first change if any id would not survive stringification.
  -- Nothing realistic trips this (these are small sequence values); it is here
  -- so the failure is a clean refusal rather than a truncation halfway through.
  IF col_type(c_users, 'ID') = 'NUMBER' THEN
    EXECUTE IMMEDIATE 'SELECT NVL(MAX(LENGTH(TRIM(TO_CHAR(id)))), 0) FROM ' || c_users
      INTO l_len;
    IF l_len > 36 THEN
      RAISE_APPLICATION_ERROR(
        -20001,
        'panel_users has an id needing ' || l_len || ' characters; VARCHAR2(36) '
        || 'cannot hold it. Widen the model before migrating.');
    END IF;
  END IF;

  -- Resolved before anything is dropped: dropping the column takes the index
  -- with it, and after that its name is unknowable.
  l_srv_idx := index_name_on(c_servers, 'USER_ID', 'IX_PANEL_SERVERS_USER_ID');
  l_act_idx := index_name_on(c_activity, 'USER_ID', 'IX_PANEL_ACTIVITY_USER');

  -- Is any column still to be re-keyed, or left mid-swap by an earlier run?
  -- This is what 2a keys off, so that a script run against a schema which is
  -- already correct does not drop two healthy foreign keys just to put them
  -- straight back. Every other step guards itself on its own state.
  l_rekey := col_type(c_users, 'ID') = 'NUMBER'
             OR col_type(c_users, 'ID_NEW') IS NOT NULL
             OR col_type(c_servers, 'USER_ID') = 'NUMBER'
             OR col_type(c_servers, 'USER_ID_NEW') IS NOT NULL
             OR col_type(c_activity, 'USER_ID') = 'NUMBER'
             OR col_type(c_activity, 'USER_ID_NEW') IS NOT NULL;

  -- ---- 2a. release the children -----------------------------------------
  -- Both FKs have to come off before the parent PK can be dropped (ORA-02273),
  -- and they are re-added in 2d once the new PK exists.
  IF l_rekey THEN
    IF table_exists(c_servers) THEN
      drop_fks_on(c_servers, 'USER_ID');
    END IF;
    IF table_exists(c_activity) THEN
      drop_fks_on(c_activity, 'USER_ID');
    END IF;
  END IF;

  -- ---- 2b. panel_users.id ------------------------------------------------
  IF col_type(c_users, 'ID') = 'NUMBER' AND has_pk(c_users) THEN
    -- DROP INDEX is explicit rather than relied upon: the backing index is
    -- dropped with an auto-created PK anyway, but saying so keeps the outcome
    -- the same if it was ever created by hand.
    ddl('ALTER TABLE ' || c_users || ' DROP PRIMARY KEY DROP INDEX');
  END IF;

  retype_to_varchar36(c_users, 'ID');

  IF NOT has_pk(c_users) THEN
    ddl('ALTER TABLE ' || c_users || ' ADD CONSTRAINT ' || c_pk_users
        || ' PRIMARY KEY (ID)');
  END IF;

  -- ---- 2c. the two child columns ----------------------------------------
  IF table_exists(c_servers) THEN
    retype_to_varchar36(c_servers, 'USER_ID');
    IF NOT index_exists(l_srv_idx) THEN
      ddl('CREATE INDEX ' || l_srv_idx || ' ON ' || c_servers || ' (USER_ID)');
    END IF;
  END IF;

  IF table_exists(c_activity) THEN
    retype_to_varchar36(c_activity, 'USER_ID');
    -- Composite, and in this order: the activity page pulls one user's rows
    -- newest-first, so user_id has to lead and created_at has to follow.
    IF NOT index_exists(l_act_idx) THEN
      ddl('CREATE INDEX ' || l_act_idx || ' ON ' || c_activity
          || ' (USER_ID, CREATED_AT)');
    END IF;
  END IF;

  -- ---- 2d. put the FKs back ---------------------------------------------
  -- ON DELETE CASCADE both times, as the model declares: deleting a panel user
  -- has to take their servers and their history with it. Added ENABLE VALIDATE
  -- (Oracle's default), so each one is checked against existing rows as it goes
  -- on — the migration's own proof that the copy kept both sides in step.
  IF table_exists(c_servers) AND NOT has_fk_on(c_servers, 'USER_ID') THEN
    ddl('ALTER TABLE ' || c_servers || ' ADD CONSTRAINT ' || c_fk_srv
        || ' FOREIGN KEY (USER_ID) REFERENCES ' || c_users
        || ' (ID) ON DELETE CASCADE');
  END IF;

  IF table_exists(c_activity) AND NOT has_fk_on(c_activity, 'USER_ID') THEN
    ddl('ALTER TABLE ' || c_activity || ' ADD CONSTRAINT ' || c_fk_act
        || ' FOREIGN KEY (USER_ID) REFERENCES ' || c_users
        || ' (ID) ON DELETE CASCADE');
  END IF;

  -- ---- 2e. the case-insensitive uniqueness on username -------------------
  -- Not part of the re-key, but missing for the same reason it is: create_all
  -- skips an existing table wholesale, so an Index() added to the model after
  -- the table was first created was never applied. The panel needs it — it is
  -- what makes a name already held under another id a 409 (MirrorConflict)
  -- rather than two rows claiming one name, which would make get_user_by_username
  -- return whichever the optimiser reached first. SQLite spelled this
  -- COLLATE NOCASE UNIQUE; Oracle has no per-column collation, so it is a
  -- function-based index and every lookup compares LOWER(username) to match.
  IF NOT index_exists(c_ix_uname) THEN
    -- Refuse rather than let ORA-01452 abort the block: the duplicates are a
    -- data question, and the operator needs to see which names they are before
    -- deciding. Everything above this point is already committed, and re-running
    -- resumes here.
    EXECUTE IMMEDIATE
      'SELECT COUNT(*) FROM (SELECT LOWER(username) FROM ' || c_users
      || ' GROUP BY LOWER(username) HAVING COUNT(*) > 1)' INTO l_dupes;
    IF l_dupes > 0 THEN
      RAISE_APPLICATION_ERROR(
        -20002,
        l_dupes || ' username(s) in panel_users collide case-insensitively, so the '
        || 'unique index cannot be created. The re-key itself is complete and '
        || 'committed. Resolve the duplicates listed in section 1, then run this '
        || 'script again — it resumes at this step.');
    END IF;
    ddl('CREATE UNIQUE INDEX ' || c_ix_uname || ' ON ' || c_users
        || ' (LOWER(USERNAME))');
  END IF;

  DBMS_OUTPUT.PUT_LINE('');
  IF g_steps = 0 THEN
    DBMS_OUTPUT.PUT_LINE('Nothing to do — the schema is already keyed VARCHAR2(36).');
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
PROMPT -- Expected: three rows, all VARCHAR2 / char_length 36 / nullable N.
SELECT table_name, column_name, data_type, char_length, nullable
  FROM user_tab_columns
 WHERE (table_name = 'PANEL_USERS'    AND column_name = 'ID')
    OR (table_name = 'PANEL_SERVERS'  AND column_name = 'USER_ID')
    OR (table_name = 'PANEL_ACTIVITY' AND column_name = 'USER_ID')
 ORDER BY table_name, column_name;

PROMPT
PROMPT -- Expected: no rows. A staging column left behind means the block
PROMPT -- stopped partway — run section 2 again, it resumes.
SELECT table_name, column_name
  FROM user_tab_columns
 WHERE table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
   AND column_name IN ('ID_NEW', 'USER_ID_NEW')
 ORDER BY table_name, column_name;

PROMPT
PROMPT -- Expected: PK_PANEL_USERS (P), plus FK_PANEL_SERVERS_USER and
PROMPT -- FK_PANEL_ACTIVITY_USER (R, delete_rule CASCADE), all status ENABLED.
SELECT table_name, constraint_name, constraint_type, delete_rule, status, validated
  FROM user_constraints
 WHERE table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
   AND constraint_type IN ('P', 'R')
 ORDER BY table_name, constraint_type, constraint_name;

PROMPT
PROMPT -- Expected: the servers index on USER_ID, the activity index on
PROMPT -- (USER_ID, CREATED_AT) in that order, and IX_PANEL_USERS_USERNAME_LOWER
PROMPT -- as UNIQUE / FUNCTION-BASED NORMAL. A missing unique index there means
PROMPT -- section 2e refused over duplicate names — read its error.
SELECT ic.index_name, ic.table_name, ic.column_name, ic.column_position, i.uniqueness
  FROM user_ind_columns ic
  JOIN user_indexes i ON i.index_name = ic.index_name
 WHERE ic.table_name IN ('PANEL_USERS', 'PANEL_SERVERS', 'PANEL_ACTIVITY')
 ORDER BY ic.table_name, ic.index_name, ic.column_position;

PROMPT
PROMPT -- The function-based index reports its column as a SYS_NC… placeholder
PROMPT -- above, so its expression is confirmed separately. Expected: one row,
PROMPT -- LOWER("USERNAME").
SELECT index_name, column_position, column_expression
  FROM user_ind_expressions
 WHERE table_name = 'PANEL_USERS'
 ORDER BY index_name, column_position;

PROMPT
PROMPT -- Expected: no rows. Any orphan means the FK went on unvalidated.
SELECT 'panel_servers' AS tab, s.id, s.user_id
  FROM panel_servers s
 WHERE NOT EXISTS (SELECT 1 FROM panel_users u WHERE u.id = s.user_id)
UNION ALL
SELECT 'panel_activity', TO_CHAR(a.id), a.user_id
  FROM panel_activity a
 WHERE NOT EXISTS (SELECT 1 FROM panel_users u WHERE u.id = a.user_id);

PROMPT
PROMPT =====================================================================
PROMPT 4. AFTERWARDS: the rows that were already there
PROMPT =====================================================================
PROMPT
PROMPT Nothing above deletes anything, so every pre-existing panel user is still
PROMPT present with its integer id stringified ('7' and so on). Those ids came
PROMPT from the panel's own sequence and no site session will ever present one,
PROMPT so those accounts cannot be signed in to and their servers cannot be
PROMPT reached. Their password_hash is equally inert: there is no login form left
PROMPT to check it against.
PROMPT
PROMPT They are not merely dead weight, and this is the part worth deciding
PROMPT before reopening the panel. panel_users.username carries a UNIQUE index on
PROMPT lower(username), so a leftover row named 'arya' blocks mirroring the site
PROMPT account that also calls itself 'arya' — the mirror fails and that visitor
PROMPT gets a 409 (MirrorConflict) on every panel page, indefinitely.
PROMPT
PROMPT If section 2e refused, the collision is already among the old rows
PROMPT themselves — two panel accounts differing only in case, which the schema
PROMPT allowed while it had no unique index. Neither can be signed in to any more,
PROMPT so renaming one is enough to let the index go on; that is the smallest
PROMPT change and it destroys nothing:
PROMPT
PROMPT     -- SUBSTR because username is VARCHAR2(100) and the suffix carries a
PROMPT     -- 36-char id; 40 + 5 + 36 always fits.
PROMPT     UPDATE panel_users
PROMPT        SET username = SUBSTR(username, 1, 40) || '-dup-' || id
PROMPT      WHERE LOWER(username) IN (SELECT LOWER(username) FROM panel_users
PROMPT                                GROUP BY LOWER(username) HAVING COUNT(*) > 1)
PROMPT        AND id <> (SELECT MIN(id) FROM panel_users u2
PROMPT                    WHERE LOWER(u2.username) = LOWER(panel_users.username));
PROMPT     COMMIT;
PROMPT
PROMPT Then run this script again; it resumes at 2e.
PROMPT
PROMPT Three ways out, in order of preference:
PROMPT
PROMPT   a. Re-point them at the real site ids. This is the only option that
PROMPT      keeps a customer's servers. It cannot be done in SQL: the site
PROMPT      stores users.username as randomized Fernet ciphertext, so there is
PROMPT      no join to make, and the only way from a plaintext name to a site id
PROMPT      is the keyed HMAC in the app's lookup_hash() with ENCRYPTION_KEY
PROMPT      loaded. Write that as a one-off Python script against the same .env,
PROMPT      resolve each name to its site id, and UPDATE panel_users SET id =
PROMPT      :site_id — the FKs cascade the change to both child tables only if
PROMPT      they were declared ON UPDATE CASCADE, which Oracle does not support,
PROMPT      so update the children explicitly in the same transaction.
PROMPT   b. Leave them. Safe for data, but the 409 above is live for any name
PROMPT      collision, and the admin page keeps listing accounts nobody owns.
PROMPT   c. Delete them. Both child tables cascade, so this also destroys those
PROMPT      servers' records. Irreversible.
PROMPT
PROMPT (c) is deliberately not executed here. Run it by hand, after a backup,
PROMPT only once you have decided:
PROMPT
PROMPT     -- every account that predates the mirror, i.e. holds a real hash
PROMPT     -- rather than the placeholder a mirrored row carries
PROMPT     DELETE FROM panel_users WHERE password_hash <> 'external:oracle';
PROMPT     COMMIT;
PROMPT
PROMPT =====================================================================
PROMPT ROLLBACK
PROMPT =====================================================================
PROMPT
PROMPT There is no automatic rollback, and reversing the retype is not the same
PROMPT as undoing it: any row the panel wrote after the migration holds a 36-char
PROMPT site id that TO_NUMBER cannot convert, so going back means deciding what
PROMPT happens to those rows first. Take a backup before section 2 — on ATP, a
PROMPT timestamp is enough, since Data Pump or a PITR clone can bring the three
PROMPT tables back:
PROMPT
PROMPT     SELECT SYSTIMESTAMP FROM dual;
PROMPT
PROMPT If section 2 fails partway, do not roll back. Read its echoed statements
PROMPT to see where it stopped, fix that, and run it again — every step is
PROMPT guarded, so it resumes rather than repeating.

-- =============================================================================================================
-- 1. DB 환경 탐지 및 세션 변수 설정
-- 환경 상태 (0: Self-Managed DB, 1: AWS Aurora, 2: AWS RDS, 3: Azure Flexible Server)
-- =============================================================================================================
DO $$
DECLARE
    v_env_state INT;
BEGIN
    -- AWS Aurora PostgreSQL 탐지 (Aurora 전용 확장 확인)
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rdswriteforwarduser') THEN
        v_env_state := 1; -- AWS Aurora
    -- AWS RDS for PostgreSQL 탐지 (rdsadmin 역할 확인) 
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rdsadmin') THEN
        v_env_state := 2; -- AWS RDS
    -- Azure Database for PostgreSQL Flexible Server 탐지 (azure_pg_admin 역할 확인)
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin') THEN
        v_env_state := 3; -- Azure
    -- 위 조건에 해당 없으면 Self-Managed DB
    ELSE
        v_env_state := 0; -- Self-Managed DB (On-Premise)
    END IF;

    -- 탐지된 환경 상태를 세션 변수 'db_env.state'에 저장
    PERFORM set_config('db_env.state', v_env_state::text, false);
END;
$$;

-- DB 환경 출력
-- SELECT
--     CASE current_setting('db_env.state', true)
--         WHEN '0' THEN '[INFO] 탐지된 환경: Self-Managed DB (State=0)'
--         WHEN '1' THEN '[INFO] 탐지된 환경: AWS Aurora PostgreSQL (State=1)'
--         WHEN '2' THEN '[INFO] 탐지된 환경: AWS RDS for PostgreSQL (State=2)'
--         WHEN '3' THEN '[INFO] 탐지된 환경: Azure Flexible Server (State=3)'
--         ELSE '[WARN] 환경을 탐지할 수 없습니다.'
--     END AS "실행 환경";



SELECT '[';

---- DBM-001_1
SELECT '{"DBM-001_1":{';
SELECT '"QUERY": "SELECT name, setting FROM pg_settings WHERE name=''password_encryption'';",';
SELECT '"RESULT": [';
SELECT CONCAT('{"setting_name": "', name, '", "value" : "', setting, '"},') FROM pg_settings WHERE name='password_encryption';
SELECT ']}},';

---- DBM-001_2
CREATE OR REPLACE FUNCTION get_dbm_001_2_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    RETURN NEXT E'{"DBM-001_2":{\n';
    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolpassword FROM pg_authid WHERE rolcanlogin=''t''",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolpassword FROM pg_authid WHERE rolcanlogin = 't' LOOP
            RETURN NEXT format('{"rolname": %L, "rolpassword" : %L},', v_record.rolname, v_record.rolpassword);
        END LOOP;
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT rolname FROM pg_roles WHERE rolcanlogin=''t'' AND rolname NOT IN (''rdsadmin'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname FROM pg_roles WHERE rolcanlogin = 't' AND rolname NOT IN ('rdsadmin') LOOP
            RETURN NEXT format('{"rolname": %L, "rolpassword" : "[PROTECTED]", "NOTE":"rolpassword is not accessible on managed DB"},', v_record.rolname);
        END LOOP;
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname FROM pg_roles WHERE rolcanlogin=''t'' AND rolname NOT IN (''azure_pg_admin'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname FROM pg_roles WHERE rolcanlogin = 't' AND rolname NOT IN ('azure_pg_admin') LOOP
            RETURN NEXT format('{"rolname": %L, "rolpassword" : "[PROTECTED]", "NOTE":"rolpassword is not accessible on managed DB"},', v_record.rolname);
        END LOOP;
    END IF;
    RETURN NEXT E'\n]}},\n'; RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_001_2_formatted_result();
DROP FUNCTION get_dbm_001_2_formatted_result();



---- DBM-003
CREATE OR REPLACE FUNCTION get_dbm_003_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    RETURN NEXT E'{"DBM-003":{\n';
    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''rdsadmin'', ''rds_superuser'', ''rds_replication'', ''rds_iam'', ''rds_password'', ''rds_ad'', ''rds_extension'', ''rdswriteforwarduser'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'rdsadmin', 'rds_superuser', 'rds_replication', 'rds_iam', 'rds_password', 'rds_ad', 'rds_extension', 'rdswriteforwarduser') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''azure_pg_admin'', ''azuresu'', ''replication'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'azure_pg_admin', 'azuresu', 'replication') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    END IF;
    RETURN NEXT E'\n]}},\n'; RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_003_formatted_result();
DROP FUNCTION get_dbm_003_formatted_result();


---- DBM-004
CREATE OR REPLACE FUNCTION get_dbm_004_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    RETURN NEXT E'{"DBM-004":{\n';
    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_authid WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_authid WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres') LOOP
            RETURN NEXT format('{"rolname": %L, "rolsuper": %L, "rolcreatedb": %L, "rolcreaterole": %L},', v_record.rolname, v_record.rolsuper, v_record.rolcreatedb, v_record.rolcreaterole);
        END LOOP;
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''rdsadmin'', ''rds_superuser'', ''rds_replication'', ''rds_iam'', ''rds_password'', ''rds_ad'', ''rds_extension'', ''rdswriteforwarduser'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'rdsadmin', 'rds_superuser', 'rds_replication', 'rds_iam', 'rds_password', 'rds_ad', 'rds_extension', 'rdswriteforwarduser') LOOP
            RETURN NEXT format('{"rolname": %L, "rolsuper": %L, "rolcreatedb": %L, "rolcreaterole": %L},', v_record.rolname, v_record.rolsuper, v_record.rolcreatedb, v_record.rolcreaterole);
        END LOOP;
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''azure_pg_admin'', ''azuresu'', ''replication'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'azure_pg_admin', 'azuresu', 'replication') LOOP
            RETURN NEXT format('{"rolname": %L, "rolsuper": %L, "rolcreatedb": %L, "rolcreaterole": %L},', v_record.rolname, v_record.rolsuper, v_record.rolcreatedb, v_record.rolcreaterole);
        END LOOP;
    END IF;
    RETURN NEXT E'\n]}},\n'; RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_004_formatted_result();
DROP FUNCTION get_dbm_004_formatted_result();


---- DBM-005
CREATE OR REPLACE FUNCTION get_dbm_005_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_record RECORD;
    v_data_sample TEXT;
BEGIN
    RETURN NEXT E'{"DBM-005":{\n';
    RETURN NEXT E'"QUERY": "SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE (column_name ILIKE ''%PASS%'' OR column_name ILIKE ''%PWD%'' OR column_name ILIKE ''%PSWD%'' OR column_name ILIKE ''%SSN%'' OR column_name ILIKE ''%JUMIN%'' OR column_name ILIKE ''%CARD%'') AND data_type IN (''character'', ''character varying'', ''text'') AND table_schema NOT IN (''pg_catalog'', ''information_schema'', ''pg_toast'')",\n';
    RETURN NEXT E'"RESULT": [\n';

    FOR v_record IN
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE (column_name ILIKE '%PASS%' OR column_name ILIKE '%PWD%' OR column_name ILIKE '%PSWD%' OR column_name ILIKE '%SSN%' OR column_name ILIKE '%JUMIN%' OR column_name ILIKE '%CARD%')
          AND data_type IN ('character', 'character varying', 'text')
          AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    LOOP
        BEGIN
            EXECUTE format(
                'SELECT string_agg(DISTINCT %I::text, '', '') FROM (SELECT %I FROM %I.%I LIMIT 10) AS subquery',
                v_record.column_name, v_record.column_name, v_record.table_schema, v_record.table_name
            )
            INTO v_data_sample;
            IF v_data_sample IS NOT NULL AND v_data_sample ~ '^[a-zA-Z0-9]{6,12}$' THEN
                RETURN NEXT format('{"TABLE_SCHEMA": %L, "TABLE_NAME": %L, "COLUMN_NAME": %L, "RESULT": %L},',
                                   v_record.table_schema, v_record.table_name, v_record.column_name, v_data_sample);
            END IF;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Permission denied for %.%. Skipping.', v_record.table_schema, v_record.table_name;
            WHEN others THEN
                RAISE NOTICE 'Error on %.%. Skipping. Error: %', v_record.table_schema, v_record.table_name, SQLERRM;
        END;
    END LOOP;
    RETURN NEXT E'\n]}},\n';
    RETURN;
END;
$$ LANGUAGE plpgsql;



---- DBM-006(인터뷰)

---- DBM-007
SELECT E'{"DBM-007":{\n\n"QUERY": "SELECT name, setting FROM pg_settings WHERE name=''shared_preload_libraries'';",\n"RESULT": [\n\n';
SELECT CASE WHEN setting LIKE '%passwordcheck%' THEN format('{"setting_name": %L, "value" : %L},', name, setting) ELSE '"passwordcheck.so is not loaded."' END FROM pg_settings WHERE name='shared_preload_libraries';
SELECT E'\n]}},\n';


---- DBM-008
CREATE OR REPLACE FUNCTION get_dbm_008_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    RETURN NEXT E'{"DBM-008":{\n';
    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''rdsadmin'', ''rds_superuser'', ''rds_replication'', ''rds_iam'', ''rds_password'', ''rds_ad'', ''rds_extension'', ''rdswriteforwarduser'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'rdsadmin', 'rds_superuser', 'rds_replication', 'rds_iam', 'rds_password', 'rds_ad', 'rds_extension', 'rdswriteforwarduser') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''azure_pg_admin'', ''azuresu'', ''replication'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'azure_pg_admin', 'azuresu', 'replication') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    END IF;
    RETURN NEXT E'\n]}},\n'; RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_008_formatted_result();
DROP FUNCTION get_dbm_008_formatted_result();



---- DBM-009
SELECT '{"DBM-009":{';
SELECT '"QUERY": "SELECT name, setting FROM pg_settings WHERE name=''idle_in_transaction_session_timeout'';",';
SELECT '"RESULT": [';
SELECT CONCAT('{"setting_name": "', name, '", "value" : "', setting, '"},') FROM pg_settings WHERE name='idle_in_transaction_session_timeout';
SELECT ']}},';

---- DBM-011
CREATE OR REPLACE FUNCTION get_dbm_011_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT;
    v_record RECORD;
    v_pgaudit RECORD;
    v_pgaudit_settings TEXT;
BEGIN
    RETURN NEXT E'{"DBM-011":{\n';

    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT name, setting FROM pg_settings WHERE name=''shared_preload_libraries'';",\n';
        RETURN NEXT E'"RESULT": [\n';

        FOR v_record IN
            SELECT name, setting
            FROM pg_settings
            WHERE name = 'shared_preload_libraries'
        LOOP
            v_pgaudit_settings := (
                SELECT string_agg(format('{"name": "%s", "value": "%s"}', name, setting), ', ')
                FROM pg_settings
                WHERE name LIKE 'pgaudit%'
            );

            IF v_record.setting LIKE '%pgaudit%' THEN
                RETURN NEXT format('{"setting_name": %L, "value": %L, "pgaudit_settings": [%s]},', v_record.name, v_record.setting, COALESCE(v_pgaudit_settings, ''));
            ELSE
                RETURN NEXT format('{"setting_name": %L, "value": %L, "pgaudit_settings": []},', v_record.name, v_record.setting);
            END IF;
        END LOOP;
        RETURN NEXT E'\n]}},\n';
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT name, setting FROM pg_settings WHERE name=''shared_preload_libraries'';",\n';
        RETURN NEXT E'"RESULT": [\n';

        FOR v_record IN
            SELECT name, setting
            FROM pg_settings
            WHERE name = 'shared_preload_libraries'
        LOOP
            v_pgaudit_settings := (
                SELECT string_agg(format('{"name": "%s", "value": "%s"}', name, setting), ', ')
                FROM pg_settings
                WHERE name LIKE 'pgaudit%'
            );

            IF v_record.setting LIKE '%pgaudit%' THEN
                RETURN NEXT format('{"setting_name": %L, "value": %L, "pgaudit_settings": [%s]},', v_record.name, v_record.setting, COALESCE(v_pgaudit_settings, ''));
            ELSE
                RETURN NEXT format('{"setting_name": %L, "value": %L, "pgaudit_settings": []},', v_record.name, v_record.setting);
            END IF;
        END LOOP;
        RETURN NEXT E'\n],';
        RETURN NEXT E'"NOTE": "For audit log upload settings, refer to the PISM-011 script results."\n';
        RETURN NEXT E'}},\n';
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "Check Azure Server Parameters for PGAUDIT in azure.extensions and related pgaudit.* settings.",\n';
        RETURN NEXT E'"RESULT": [\n';
        
        v_pgaudit_settings := (
            SELECT string_agg(format('{"name": %L, "value": %L}', name, setting), ', ')
            FROM pg_settings
            WHERE name LIKE 'pgaudit%'
        );

        FOR v_record IN
            SELECT name, setting FROM pg_settings WHERE name = 'azure.extensions'
        LOOP
            IF v_record.setting ILIKE '%PGAUDIT%' THEN
                RETURN NEXT format('{"pgaudit_status": "Loaded", "source_parameter": %L, "value": %L, "pgaudit_settings": [%s]}', v_record.name, v_record.setting, COALESCE(v_pgaudit_settings, ''));
            ELSE
                RETURN NEXT format('{"pgaudit_status": "Not Loaded", "source_parameter": %L, "value": %L, "pgaudit_settings": []}', v_record.name, v_record.setting);
            END IF;
        END LOOP;
        RETURN NEXT E'\n],';
        RETURN NEXT E'"NOTE": "For audit log upload settings, refer to the PISM-011 script results."\n';
        RETURN NEXT E'}},\n';
    END IF;
    RETURN;
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_011_formatted_result();
DROP FUNCTION get_dbm_011_formatted_result();


-- DBM-013 // (Self-Managed DB: pg_hba.conf에서 접속 IP 제한 여부 확인, CSP Managed DB: 클라우드 관리체계(PISM-013) 스크립트 결과 참고)


---- DBM-015
CREATE OR REPLACE FUNCTION get_dbm_015_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    -- 015_1
    RETURN NEXT E'{"DBM-015_1":{\n"QUERY": "SELECT table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee=''PUBLIC'' AND (table_schema=''pg_catalog'' and privilege_type != ''SELECT'');",",\n"RESULT": [\n';
    FOR v_record IN SELECT table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee='PUBLIC' AND table_schema='pg_catalog' AND privilege_type <> 'SELECT' LOOP
        RETURN NEXT format('{"table_catalog": %L, "table_schema" : %L, "table_name" : %L, "privilege_type" : %L},', v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 015_2
    RETURN NEXT E'{"DBM-015_2":{\n"QUERY": "SELECT routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges where grantee=''PUBLIC'' AND (specific_schema=''public'' OR routine_catalog=''public'')",\n"RESULT": [\n';
    FOR v_record IN SELECT routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges WHERE grantee='PUBLIC' AND (specific_schema='public' OR routine_catalog='public') LOOP
         RETURN NEXT format('{"routine_catalog": %L, "routine_schema": %L, "routine_name": %L, "privilege_type": %L},', v_record.routine_catalog, v_record.routine_schema, v_record.routine_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 015_3
    RETURN NEXT E'{"DBM-015_3":{\n"QUERY": "SELECT table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee=''PUBLIC'' AND (table_schema NOT IN (''pg_catalog'', ''information_schema'') AND privilege_type != ''SELECT'');",\n"RESULT": [\n';
    FOR v_record IN SELECT table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee='PUBLIC' AND (table_schema NOT IN ('pg_catalog', 'information_schema') AND privilege_type <> 'SELECT') LOOP
        RETURN NEXT format('{"table_catalog": %L, "table_schema" : %L, "table_name" : %L, "column_name": %L, "privilege_type": %L},', v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.column_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';
    
    RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_015_formatted_result();
DROP FUNCTION get_dbm_015_formatted_result();


---- DBM-016
SELECT '{"DBM-016":{';
SELECT '"QUERY": "SELECT VERSION();",';
SELECT '"RESULT": [';
SELECT CONCAT('{"version": "', VERSION(), '"},');
SELECT ']}},';

---- DBM-017
CREATE OR REPLACE FUNCTION get_dbm_017_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_exclude_users TEXT[]; v_record RECORD; 
BEGIN
    IF v_env_state IN (1, 2) THEN v_exclude_users := ARRAY['postgres', 'rdsadmin'];
    ELSIF v_env_state = 3 THEN v_exclude_users := ARRAY['postgres', 'azure_pg_admin', 'azuresu', 'replication'];
    ELSE v_exclude_users := ARRAY['postgres'];
    END IF;
    RETURN NEXT E'{"DBM-017_1":{\n"QUERY": "SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE table_schema=''pg_catalog'' and grantee!=''postgres'' and privilege_type!= ''SELECT'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE table_schema='pg_catalog' AND NOT(grantee = ANY(v_exclude_users)) AND privilege_type <> 'SELECT' LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog" : %L, "table_schema" : %L, "table_name" : %L, "privilege_type" : %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';
    RETURN NEXT E'{"DBM-017_2":{\n"QUERY": "SELECT * FROM information_schema.column_privileges WHERE table_schema=''pg_catalog'' and grantee!=''postgres'' and privilege_type!= ''SELECT'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE table_schema='pg_catalog' AND NOT(grantee = ANY(v_exclude_users)) AND privilege_type <> 'SELECT' LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog" : %L, "table_schema" : %L, "table_name" : %L, "column_name": %L, "privilege_type" : %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.column_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';
    RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_017_formatted_result();
DROP FUNCTION get_dbm_017_formatted_result();



---- DBM-019(인터뷰)

---- DBM-020
CREATE OR REPLACE FUNCTION get_dbm_020_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT; v_record RECORD; 
BEGIN
    RETURN NEXT E'{"DBM-020":{\n';
    IF v_env_state = 0 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_authid WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state IN (1, 2) THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''rdsadmin'', ''rds_superuser'', ''rds_replication'', ''rds_iam'', ''rds_password'', ''rds_ad'', ''rds_extension'', ''rdswriteforwarduser'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'rdsadmin', 'rds_superuser', 'rds_replication', 'rds_iam', 'rds_password', 'rds_ad', 'rds_extension', 'rdswriteforwarduser') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    ELSIF v_env_state = 3 THEN
        RETURN NEXT E'"QUERY": "SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN (''pg_monitor'', ''pg_read_all_settings'', ''pg_read_all_stats'', ''pg_stat_scan_tables'', ''pg_signal_backend'', ''postgres'', ''azure_pg_admin'', ''azuresu'', ''replication'')",\n';
        RETURN NEXT E'"RESULT": [\n';
        FOR v_record IN SELECT rolname, rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname NOT IN ('pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables', 'pg_signal_backend', 'postgres', 'azure_pg_admin', 'azuresu', 'replication') LOOP
            RETURN NEXT format('{"rolname": %L, "rolcanlogin": %L, "rolvaliduntil": %L},', v_record.rolname, v_record.rolcanlogin, v_record.rolvaliduntil);
        END LOOP;
    END IF;
    RETURN NEXT E'\n]}},\n'; RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_020_formatted_result();
DROP FUNCTION get_dbm_020_formatted_result();




-- DBM-022 (Self-Managed DB: 서버 스크립트 참고, CSP Managed DB: 클라우드 관리체계(PISM-046) 스크립트 참고) 

---- DBM-024
CREATE OR REPLACE FUNCTION get_dbm_024_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT;
    v_exclude_users TEXT[];
    v_record RECORD; 
BEGIN
    -- 환경별로 제외할 사용자 목록 설정
    IF v_env_state IN (1, 2) THEN v_exclude_users := ARRAY['postgres', 'rdsadmin'];
    ELSIF v_env_state = 3 THEN v_exclude_users := ARRAY['postgres', 'azure_pg_admin', 'azuresu', 'replication'];
    ELSE v_exclude_users := ARRAY['postgres'];
    END IF;
    
    -- 024_1
    RETURN NEXT E'{"DBM-024_1":{\n"QUERY": "SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee!=''postgres'' and is_grantable=''YES'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE is_grantable='YES' AND NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog": %L, "table_schema": %L, "table_name": %L, "privilege_type": %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 024_2
    RETURN NEXT E'{"DBM-024_2":{\n"QUERY": "SELECT * FROM information_schema.column_privileges WHERE grantee!=''postgres'' and is_grantable=''YES'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE is_grantable='YES' AND NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog": %L, "table_schema": %L, "table_name": %L, "column_name": %L, "privilege_type": %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.column_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 024_3
    RETURN NEXT E'{"DBM-024_3":{\n"QUERY": "SELECT grantee, routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges where grantee!=''postgres'' and is_grantable=''YES'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges WHERE is_grantable='YES' AND NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "routine_catalog": %L, "routine_schema": %L, "routine_name": %L, "privilege_type": %L},', v_record.grantee, v_record.routine_catalog, v_record.routine_schema, v_record.routine_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';
    
    RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_024_formatted_result();
DROP FUNCTION get_dbm_024_formatted_result();



---- DBM-025 (삭제)


-- DBM-026 // (Self-Managed DB: 서버 스크립트 참고, CSP Managed DB: N/A)

---- DBM-028
CREATE OR REPLACE FUNCTION get_dbm_028_formatted_result()
RETURNS SETOF TEXT AS $$
DECLARE
    v_env_state INT := current_setting('db_env.state', true)::INT;
    v_exclude_users TEXT[];
    v_record RECORD; 
BEGIN
    -- 환경별로 제외할 사용자 목록 설정
    IF v_env_state IN (1, 2) THEN v_exclude_users := ARRAY['postgres', 'PUBLIC', 'pg_monitor', 'rdsadmin'];
    ELSIF v_env_state = 3 THEN v_exclude_users := ARRAY['postgres', 'PUBLIC', 'pg_monitor', 'azure_pg_admin'];
    ELSE v_exclude_users := ARRAY['postgres', 'PUBLIC', 'pg_monitor'];
    END IF;

    -- 028_1
    RETURN NEXT E'{"DBM-028_1":{\n"QUERY": "SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee NOT IN (''postgres'', ''PUBLIC'', ''pg_monitor'');",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog": %L, "table_schema": %L, "table_name": %L, "privilege_type": %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 028_2
    RETURN NEXT E'{"DBM-028_2":{\n"QUERY": "SELECT grantee, table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee NOT IN (''postgres'', ''PUBLIC'', ''pg_monitor'');",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, table_catalog, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "table_catalog": %L, "table_schema": %L, "table_name": %L, "column_name": %L, "privilege_type": %L},', v_record.grantee, v_record.table_catalog, v_record.table_schema, v_record.table_name, v_record.column_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}},\n';

    -- 028_3 
    RETURN NEXT E'{"DBM-028_3":{\n"QUERY": "SELECT routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges where grantee!=''postgres'' and is_grantable=''YES'';",\n"RESULT": [\n';
    FOR v_record IN SELECT grantee, routine_catalog, routine_schema, routine_name, privilege_type FROM information_schema.routine_privileges WHERE NOT(grantee = ANY(v_exclude_users)) LOOP
        RETURN NEXT format('{"grantee": %L, "routine_catalog": %L, "routine_schema": %L, "routine_name": %L, "privilege_type": %L},', v_record.grantee, v_record.routine_catalog, v_record.routine_schema, v_record.routine_name, v_record.privilege_type);
    END LOOP;
    RETURN NEXT E'\n]}}';

    RETURN; 
END;
$$ LANGUAGE plpgsql;
SELECT * FROM get_dbm_028_formatted_result();
DROP FUNCTION get_dbm_028_formatted_result();


-- DBM-032 (Self-Managed DB: pg_hba.conf, AWS RDS: Parameter groups(ssl, rds.force_ssl), AWS Aurora: Parameter groups(rds.force_ssl), Azure: Server Parameters(require_secure_transport))


SELECT E'\n]';
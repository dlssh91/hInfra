SET FEEDBACK OFF
SET WRAP OFF
SET LINESIZE 32000
SET LONG 32000
SET LONGCHUNKSIZE 32000
SET SERVEROUTPUT ON FORMAT WRAP
SET trimspool ON
SET VERIFY OFF
SET HEADING OFF


SET TERMOUT OFF
-- 환경 상태를 저장할 변수 설정 (0: Self-Managed, 1: AWS RDS(CSP Managed))
COLUMN db_env_state_col NEW_VALUE db_environment_state

-- RDSADMIN 사용자의 존재 여부로 환경을 판단
SELECT
    CASE
        WHEN COUNT(1) > 0 THEN 1 -- RDS 환경
        ELSE 0 -- Self-Managed DB
    END AS db_env_state_col
FROM
    DBA_USERS
WHERE
    USERNAME = 'RDSADMIN';
SET TERMOUT ON



BEGIN
DBMS_OUTPUT.put_line('[');
END;
/

-- DBM-001
DECLARE
    result_line sys.user$%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM sys.user$ WHERE name IN (SELECT username FROM dba_users WHERE account_status = 'OPEN');
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-001":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, password, spare4 FROM sys.user$ WHERE name IN (SELECT username FROM dba_users WHERE account_status=`OPEN`);",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","password":"' || result_line.password || '","spare4":"' || result_line.spare4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-003 (12~)
DECLARE
    result_line dba_users%ROWTYPE;
    CURSOR result_cur_onprem IS SELECT * FROM dba_users;
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT * FROM dba_users WHERE USERNAME NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');
BEGIN
    IF &db_environment_state = 0 THEN
        DBMS_OUTPUT.put_line('{"DBM-003_12c":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT username, account_status, expiry_date, last_login FROM dba_users",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_onprem;
            LOOP
                FETCH result_cur_onprem INTO result_line;
                EXIT  WHEN result_cur_onprem%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_line.username || '","account_status":"' || result_line.account_status || '","expiry_date":"' || TO_CHAR(result_line.expiry_date, 'YYYY-MM-DD') || '","last_login":"' || result_line.last_login || '"},');
            END LOOP;
        CLOSE result_cur_onprem;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state = 1 THEN 
        DBMS_OUTPUT.put_line('{"DBM-003_12c":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT username, account_status, expiry_date, last_login FROM dba_users WHERE USERNAME NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_line.username || '","account_status":"' || result_line.account_status || '","expiry_date":"' || TO_CHAR(result_line.expiry_date, 'YYYY-MM-DD') || '","last_login":"' || result_line.last_login || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-004_01
DECLARE
    result_line dba_role_privs%ROWTYPE;
    CURSOR result_cur_onprem IS SELECT * FROM dba_role_privs WHERE granted_role='DBA';
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT * FROM dba_role_privs WHERE granted_role='DBA' AND GRANTEE NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');
BEGIN
    DBMS_OUTPUT.put_line('{"DBM-004_1":{');
    IF &db_environment_state = 0 THEN 
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, granted_role, admin_option, default_role FROM dba_role_privs",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_onprem;
            LOOP
                FETCH result_cur_onprem INTO result_line;
                EXIT  WHEN result_cur_onprem%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","granted_role":"' || result_line.granted_role || '","admin_option":"' || result_line.admin_option || '","default_role":"' || result_line.default_role || '"},');
            END LOOP;
        CLOSE result_cur_onprem;
    ELSIF &db_environment_state = 1 THEN 
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, granted_role, admin_option, default_role FROM dba_role_privs WHERE GRANTEE NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","granted_role":"' || result_line.granted_role || '","admin_option":"' || result_line.admin_option || '","default_role":"' || result_line.default_role || '"},');
            END LOOP;
        CLOSE result_cur_rds;
    END IF;
    DBMS_OUTPUT.put_line(']}},');
END;
/


-- DBM-004_02
DECLARE
    result_line V$PWFILE_USERS%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM V$PWFILE_USERS WHERE sysdba='TRUE';
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-004_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT username FROM V$PWFILE_USERS WHERE sysdba=`TRUE`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_line.username ||'"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-004_03
DECLARE
    result_line DBA_SYS_PRIVS%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-004_3":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, privilege FROM DBA_SYS_PRIVS",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-005
DECLARE
    result_line dba_tab_columns%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM dba_tab_columns WHERE 1=1 AND char_length > 1 AND owner <> 'SYS'
        AND SUBSTR(table_name, 1, 1) <> '_' AND SUBSTR(table_name, 1, 4) <> 'BIN$' AND (owner, table_name)
        NOT IN (SELECT owner, object_name FROM dba_objects WHERE status = 'INVALID')
        AND data_type not in ('BLOB','CLOB','NCLOB','BFILE')
        AND (column_name like '%PASS%' OR column_name like '%PWD%' OR column_name like '%PSWD%' OR column_name like '%JUMIN%');

    TYPE RefCurTyp IS REF CURSOR;
    cv RefCurTyp;
    p   VARCHAR2(4000);

BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-005":{');
        DBMS_OUTPUT.put_line('"QUERY": "----",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"owner":"' || result_line.owner || '","table_name":"' || result_line.table_name || '","column_name":"' || result_line.column_name || '","column_data":[');
                    OPEN cv FOR 'SELECT ' || result_line.column_name || ' FROM ' || result_line.owner || '."' || result_line.table_name || '"  WHERE rownum <=10';
                    LOOP
                        FETCH cv INTO p;
                        EXIT WHEN cv%NOTFOUND;
                            dbms_output.put_line('"'|| p ||'",');
                    END LOOP;
                    CLOSE cv;
                    DBMS_OUTPUT.PUT_LINE(']},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-006
DECLARE
    result_col1 dba_users.username%TYPE;
    result_col2 dba_users.profile%TYPE;
    result_col3 dba_profiles.resource_name%TYPE;
    result_col4 dba_profiles.limit%TYPE;

    CURSOR result_cur IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='FAILED_LOGIN_ATTEMPTS' or b.resource_name='PASSWORD_LOCK_TIME');
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='FAILED_LOGIN_ATTEMPTS' or b.resource_name='PASSWORD_LOCK_TIME') AND a.username NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-006":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = `OPEN` and a.profile = b.profile and (b.resource_name=`FAILED_LOGIN_ATTEMPTS` or b.resource_name=`PASSWORD_LOCK_TIME`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-006":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = `OPEN` and a.profile = b.profile and (b.resource_name=`FAILED_LOGIN_ATTEMPTS` or b.resource_name=`PASSWORD_LOCK_TIME` AND a.username NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`))",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-007_01
DECLARE
    result_col1 dba_users.username%TYPE;
    result_col2 dba_users.profile%TYPE;
    result_col3 dba_profiles.resource_name%TYPE;
    result_col4 dba_profiles.limit%TYPE;

    CURSOR result_cur IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and b.resource_name='PASSWORD_VERIFY_FUNCTION';
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and b.resource_name='PASSWORD_VERIFY_FUNCTION' AND a.username NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');

BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-007_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and b.resource_name=`PASSWORD_VERIFY_FUNCTION`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-007_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and b.resource_name=`PASSWORD_VERIFY_FUNCTION` AND a.username NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-007_02
DECLARE
    v_func_name   USER_SOURCE.name%TYPE;
    v_full_text   CLOB; 

    v_first_record BOOLEAN := TRUE;

    CURSOR result_cur IS SELECT name, LISTAGG(text, '') WITHIN GROUP (ORDER BY line) AS full_text FROM USER_SOURCE WHERE TYPE = 'FUNCTION' AND NAME LIKE '%VERIFY%' GROUP BY name;

BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-007_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, LISTAGG(text, '''') WITHIN GROUP (ORDER BY line) FROM USER_SOURCE WHERE TYPE=`FUNCTION` AND NAME LIKE `%VERIFY%` GROUP BY name",');
        DBMS_OUTPUT.put_line('"RESULT": [');

        OPEN result_cur;
        LOOP
            FETCH result_cur INTO v_func_name, v_full_text;
            EXIT WHEN result_cur%NOTFOUND;

            IF NOT v_first_record THEN
                DBMS_OUTPUT.PUT(',');
            END IF;

            v_full_text := REPLACE(v_full_text, '\\', '\\\\');
            v_full_text := REPLACE(v_full_text, '"', '\"');
            v_full_text := REPLACE(v_full_text, CHR(10), '\n');

            DBMS_OUTPUT.PUT('{"function_name":"' || v_func_name || '","text":"' || v_full_text || '"}');

            v_first_record := FALSE;
        END LOOP;
        CLOSE result_cur;

        DBMS_OUTPUT.put_line(''); 
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-008_1
DECLARE
    result_line sys.user$%ROWTYPE;
    CURSOR result_cur IS SELECT * FROM sys.user$ WHERE name in (SELECT username FROM dba_users WHERE account_status = 'OPEN');
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT * FROM sys.user$ WHERE name in (SELECT username FROM dba_users WHERE account_status = 'OPEN') AND name NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');
        -- SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-008_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, ptime FROM sys.user$ WHERE name in (SELECT username FROM dba_users WHERE account_status = `OPEN`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","ptime":"' || result_line.ptime || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-008_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, ptime FROM sys.user$ WHERE name in (SELECT username FROM dba_users WHERE account_status = `OPEN`) AND name NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`);",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","ptime":"' || result_line.ptime || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-008_2
DECLARE
    result_col1 dba_users.username%TYPE;
    result_col2 dba_users.profile%TYPE;
    result_col3 dba_profiles.resource_name%TYPE;
    result_col4 dba_profiles.limit%TYPE;

    CURSOR result_cur IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='PASSWORD_LIFE_TIME' or b.resource_name='PASSWORD_GRACE_TIME');
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='PASSWORD_LIFE_TIME' or b.resource_name='PASSWORD_GRACE_TIME') AND a.username NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');

BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-008_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and (b.resource_name=`PASSWORD_LIFE_TIME` or b.resource_name=`PASSWORD_GRACE_TIME`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-008_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and (b.resource_name=`PASSWORD_LIFE_TIME` or b.resource_name=`PASSWORD_GRACE_TIME`) AND a.username NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-009
DECLARE
    result_col1 dba_users.username%TYPE;
    result_col2 dba_users.profile%TYPE;
    result_col3 dba_profiles.resource_name%TYPE;
    result_col4 dba_profiles.limit%TYPE;

    CURSOR result_cur IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='IDLE_TIME' or b.resource_name='CONNECT_TIME');
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status = 'OPEN' and a.profile = b.profile and (b.resource_name='IDLE_TIME' or b.resource_name='CONNECT_TIME') AND a.username NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');

BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-009":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and (b.resource_name=`IDLE_TIME` or b.resource_name=`CONNECT_TIME`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');

    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-009":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.resource_name, b.limit FROM dba_users a, dba_profiles b where a.account_status =`OPEN` and a.profile = b.profile and (b.resource_name=`IDLE_TIME` or b.resource_name=`CONNECT_TIME`) AND a.username NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

    

-- DBM-011
DECLARE
    result_line gv$parameter%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM gv$parameter WHERE name = 'audit_trail';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-011":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, value FROM gv$parameter WHERE name=`audit_trail`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","value":"' || result_line.value || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');

    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-011":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, value FROM gv$parameter WHERE name=`audit_trail`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","value":"' || result_line.value || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line('],');
        DBMS_OUTPUT.put_line('"NOTE": "For audit log upload settings, refer to the PISM-011 script results."');
        DBMS_OUTPUT.put_line('}},');
    END IF;
END;
/


-- DBM-012 // (Self-Managed DB: listener.ora 참고, AWS RDS: N/A)


-- DBM-013 // (Self-Managed DB: sqlnet.ora 참고, AWS RDS: 클라우드 관리체계(PISM-013) 스크립트 결과 참고)


-- DBM-014
DECLARE
    result_line gv$parameter%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM gv$parameter WHERE name = 'os_roles' or name = 'remote_os_roles' or name = 'remote_os_authent';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-014":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM gv$parameter WHERE name = `os_roles` or name = `remote_os_roles` or name = `remote_os_authent`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","value":"' || result_line.value || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-015_1
DECLARE
    result_col1 dba_role_privs.grantee%TYPE;
    result_col2 dba_role_privs.granted_role%TYPE;
    CURSOR result_cur
    IS
        SELECT grantee, granted_role FROM dba_role_privs WHERE grantee='PUBLIC';
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-015_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, granted_role FROM dba_role_privs WHERE grantee=`PUBLIC`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_col1 || '","granted_role":"' || result_col2 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-015_2
DECLARE
    result_col1 DBA_SYS_PRIVS.grantee%TYPE;
    result_col2 DBA_SYS_PRIVS.PRIVILEGE%TYPE;

    CURSOR result_cur
    IS
        SELECT grantee, privilege FROM DBA_SYS_PRIVS WHERE GRANTEE='PUBLIC';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-015_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, privilege FROM DBA_SYS_PRIVS WHERE GRANTEE=`PUBLIC`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"GRANTEE":"' || result_col1 || '","PRIVILEGE":"' || result_col2 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-015_3
DECLARE
    result_line dba_tab_privs%ROWTYPE;
    CURSOR result_cur IS SELECT * FROM dba_tab_privs WHERE grantee ='PUBLIC' AND OWNER NOT IN ('ORDDATA','OLAPSYS','CTXSYS','DVSYS','SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'XDB', 'GSMADMIN_INTERNAL', 'DVF', 'APEX_040200');
    CURSOR result_cur_rds IS SELECT * FROM dba_tab_privs WHERE grantee ='PUBLIC' AND OWNER NOT IN ('ORDDATA','OLAPSYS','CTXSYS','DVSYS','SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'XDB', 'GSMADMIN_INTERNAL', 'DVF', 'APEX_040200', 'RDSADMIN');
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-015_3":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE grantee =`PUBLIC` AND OWNER NOT IN (`ORDDATA`,`OLAPSYS`,`CTXSYS`,`DVSYS`,`SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `XDB`, `GSMADMIN_INTERNAL`, `DVF`, `APEX_040200`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee  || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","TABLE_NAME":"' || result_line.TABLE_NAME || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-015_3":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE grantee =`PUBLIC` AND OWNER NOT IN (`ORDDATA`,`OLAPSYS`,`CTXSYS`,`DVSYS`,`SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `XDB`, `GSMADMIN_INTERNAL`, `DVF`, `APEX_040200`, `RDSADMIN`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee  || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","TABLE_NAME":"' || result_line.TABLE_NAME || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-016 (12c, 19c)
DECLARE
    result_line dba_registry_sqlpatch%ROWTYPE;
    CURSOR result_cur
    IS
--    SELECT LISTAGG(banner, chr(10)) WITHIN GROUP (ORDER  BY banner) AS version_info FROM v$version;
    SELECT * FROM SYS.DBA_REGISTRY_SQLPATCH;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-16_12c":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT patch_id, flags, status, action, description FROM sys.dba_registry_sqlpatch",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"patch_id":"'|| result_line.patch_id || '","flags":"'  || result_line.flags || '","status":"' || result_line.status || '","action":"' || result_line.action || '","description":"' || result_line.description || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-017
DECLARE
    result_line dba_tab_privs%ROWTYPE;
    CURSOR result_cur IS SELECT * FROM dba_tab_privs WHERE (owner='SYS' OR table_name LIKE 'DBA_%') AND privilege <> 'EXECUTE' AND grantee NOT IN ('PUBLIC', 'AQ_ADMINISTRATOR_ROLE', 'AQ_USER_ROLE', 'AURORA$JIS$UTILITY$', 'OSE$HTTP$ADMIN','TRACESVR', 'CTXSYS', 'DBA', 'DELETE_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE','EXP_FULL_DATABASE', 'GATHER_SYSTEM_STATISTICS', 'HS_ADMIN_ROLE', 'IMP_FULL_DATABASE','LOGSTDBY_ADMINISTRATOR', 'MDSYS','ODM', 'OEM_MONITOR', 'OLAPSYS', 'ORDSYS', 'OUTLN','RECOVERY_CATALOG_OWNER', 'SELECT_CATALOG_ROLE', 'SNMPAGENT', 'SYSTEM', 'WKSYS','WKUSER', 'WMSYS', 'WM_ADMIN_ROLE', 'XDB', 'LBACSYS', 'PERFSTAT', 'XDBADMIN', 'XS_CACHE_ADMIN', 'SYSKM', 'SYSBACKUP', 'ORACLE_OCM', 'PDB_DBA', 'OPTIMIZER_PROCESSING_RATE', 'HS_ADMIN_SELECT_ROLE', 'GSMUSER_ROLE', 'ADM_PARALLEL_EXECUTE_TASK','APEX_040200','APPQOSSYS','AUDIT_ADMIN','AUDIT_VIEWER','CAPTURE_ADMIN','CDB_DBA','DBFS_ROLE','DBSNMP','DVSYS','DV_ACCTMGR','DV_MONITOR','DV_SECANALYST','EM_EXPRESS_BASIC','GSMADMIN_INTERNAL','OLAP_XS_ADMIN','ORDPLUGINS','SYSDG') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') ORDER BY grantee;
    CURSOR result_cur_rds IS SELECT * FROM dba_tab_privs WHERE (owner='SYS' OR table_name LIKE 'DBA_%') AND privilege <> 'EXECUTE' AND grantee NOT IN ('PUBLIC', 'AQ_ADMINISTRATOR_ROLE', 'AQ_USER_ROLE', 'AURORA$JIS$UTILITY$', 'OSE$HTTP$ADMIN','TRACESVR', 'CTXSYS', 'DBA', 'DELETE_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE','EXP_FULL_DATABASE', 'GATHER_SYSTEM_STATISTICS', 'HS_ADMIN_ROLE', 'IMP_FULL_DATABASE','LOGSTDBY_ADMINISTRATOR', 'MDSYS','ODM', 'OEM_MONITOR', 'OLAPSYS', 'ORDSYS', 'OUTLN','RECOVERY_CATALOG_OWNER', 'SELECT_CATALOG_ROLE', 'SNMPAGENT', 'SYSTEM', 'WKSYS','WKUSER', 'WMSYS', 'WM_ADMIN_ROLE', 'XDB', 'LBACSYS', 'PERFSTAT', 'XDBADMIN', 'XS_CACHE_ADMIN', 'SYSKM', 'SYSBACKUP', 'ORACLE_OCM', 'PDB_DBA', 'OPTIMIZER_PROCESSING_RATE', 'HS_ADMIN_SELECT_ROLE', 'GSMUSER_ROLE', 'ADM_PARALLEL_EXECUTE_TASK','APEX_040200','APPQOSSYS','AUDIT_ADMIN','AUDIT_VIEWER','CAPTURE_ADMIN','CDB_DBA','DBFS_ROLE','DBSNMP','DVSYS','DV_ACCTMGR','DV_MONITOR','DV_SECANALYST','EM_EXPRESS_BASIC','GSMADMIN_INTERNAL','OLAP_XS_ADMIN','ORDPLUGINS','SYSDG','RDSADMIN') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') ORDER BY grantee;
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-017":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE (owner=`SYS` OR table_name LIKE `DBA_%`) AND privilege <> `EXECUTE` AND grantee NOT IN (`PUBLIC`, `AQ_ADMINISTRATOR_ROLE`, `AQ_USER_ROLE`, `AURORA$JIS$UTILITY$`, `OSE$HTTP$ADMIN`,`TRACESVR`, `CTXSYS`, `DBA`, `DELETE_CATALOG_ROLE`, `EXECUTE_CATALOG_ROLE`,`EXP_FULL_DATABASE`, `GATHER_SYSTEM_STATISTICS`, `HS_ADMIN_ROLE`, `IMP_FULL_DATABASE`,`LOGSTDBY_ADMINISTRATOR`, `MDSYS`,`ODM`, `OEM_MONITOR`, `OLAPSYS`, `ORDSYS`, `OUTLN`,`RECOVERY_CATALOG_OWNER`, `SELECT_CATALOG_ROLE`, `SNMPAGENT`, `SYSTEM`, `WKSYS`,`WKUSER`, `WMSYS`, `WM_ADMIN_ROLE`, `XDB`, `LBACSYS`, `PERFSTAT`, `XDBADMIN`, `XS_CACHE_ADMIN`, `SYSKM`, `SYSBACKUP`, `ORACLE_OCM`, `PDB_DBA`, `OPTIMIZER_PROCESSING_RATE`, `HS_ADMIN_SELECT_ROLE`, `GSMUSER_ROLE`, `ADM_PARALLEL_EXECUTE_TASK`,`APEX_040200`,`APPQOSSYS`,`AUDIT_ADMIN`,`AUDIT_VIEWER`,`CAPTURE_ADMIN`,`CDB_DBA`,`DBFS_ROLE`,`DBSNMP`,`DVSYS`,`DV_ACCTMGR`,`DV_MONITOR`,`DV_SECANALYST`,`EM_EXPRESS_BASIC`,`GSMADMIN_INTERNAL`,`OLAP_XS_ADMIN`,`ORDPLUGINS`,`SYSDG`) AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role=`DBA`) ORDER BY grantee;",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee  || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","TABLE_NAME":"' || result_line.TABLE_NAME || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-017":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE (owner=`SYS` OR table_name LIKE `DBA_%`) AND privilege <> `EXECUTE` AND grantee NOT IN (`PUBLIC`, `AQ_ADMINISTRATOR_ROLE`, `AQ_USER_ROLE`, `AURORA$JIS$UTILITY$`, `OSE$HTTP$ADMIN`,`TRACESVR`, `CTXSYS`, `DBA`, `DELETE_CATALOG_ROLE`, `EXECUTE_CATALOG_ROLE`,`EXP_FULL_DATABASE`, `GATHER_SYSTEM_STATISTICS`, `HS_ADMIN_ROLE`, `IMP_FULL_DATABASE`,`LOGSTDBY_ADMINISTRATOR`, `MDSYS`,`ODM`, `OEM_MONITOR`, `OLAPSYS`, `ORDSYS`, `OUTLN`,`RECOVERY_CATALOG_OWNER`, `SELECT_CATALOG_ROLE`, `SNMPAGENT`, `SYSTEM`, `WKSYS`,`WKUSER`, `WMSYS`, `WM_ADMIN_ROLE`, `XDB`, `LBACSYS`, `PERFSTAT`, `XDBADMIN`, `XS_CACHE_ADMIN`, `SYSKM`, `SYSBACKUP`, `ORACLE_OCM`, `PDB_DBA`, `OPTIMIZER_PROCESSING_RATE`, `HS_ADMIN_SELECT_ROLE`, `GSMUSER_ROLE`, `ADM_PARALLEL_EXECUTE_TASK`,`APEX_040200`,`APPQOSSYS`,`AUDIT_ADMIN`,`AUDIT_VIEWER`,`CAPTURE_ADMIN`,`CDB_DBA`,`DBFS_ROLE`,`DBSNMP`,`DVSYS`,`DV_ACCTMGR`,`DV_MONITOR`,`DV_SECANALYST`,`EM_EXPRESS_BASIC`,`GSMADMIN_INTERNAL`,`OLAP_XS_ADMIN`,`ORDPLUGINS`,`SYSDG`,`RDSADMIN`) AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role=`DBA`) ORDER BY grantee;",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee  || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","TABLE_NAME":"' || result_line.TABLE_NAME || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-019
DECLARE
    result_col1 dba_users.username%TYPE;
    result_col2 dba_users.profile%TYPE;
    result_col3 dba_profiles.resource_name%TYPE;
    result_col4 dba_profiles.limit%TYPE;

    CURSOR result_cur IS SELECT a.username, a.profile, b.RESOURCE_NAME, b.LIMIT FROM dba_users a, DBA_PROFILES b WHERE a.account_status = 'OPEN' and a.profile = b.profile and b.resource_name IN ('PASSWORD_REUSE_MAX', 'PASSWORD_REUSE_TIME');
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT a.username, a.profile, b.RESOURCE_NAME, b.LIMIT FROM dba_users a, DBA_PROFILES b WHERE a.account_status = 'OPEN' and a.profile = b.profile and b.resource_name IN ('PASSWORD_REUSE_MAX', 'PASSWORD_REUSE_TIME') AND a.username NOT IN ('RDSADMIN', 'SYS', 'SYSTEM');

BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-019":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.RESOURCE_NAME, b.LIMIT FROM dba_users a, DBA_PROFILES b WHERE a.account_status = `OPEN` and a.profile = b.profile and b.resource_name IN (`PASSWORD_REUSE_MAX`, `PASSWORD_REUSE_TIME`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-019":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT a.username, a.profile, b.RESOURCE_NAME, b.LIMIT FROM dba_users a, DBA_PROFILES b WHERE a.account_status = `OPEN` and a.profile = b.profile and b.resource_name IN (`PASSWORD_REUSE_MAX`, `PASSWORD_REUSE_TIME`) AND a.username NOT IN (`RDSADMIN`, `SYS`, `SYSTEM`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3, result_col4;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_col1 || '","profile":"' || result_col2 || '","resource_name":"' || result_col3 || '","limit":"' || result_col4 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');        
    END IF;
END;
/


-- DBM-020 (12c)
DECLARE
    result_line dba_users%ROWTYPE;
    CURSOR result_cur IS SELECT * FROM dba_users;
    -- RDS의 경우 SYS, SYSTEM, RDSADMIN 계정으로 사용자의 로그인이 불가하므로 제외
    CURSOR result_cur_rds IS SELECT * FROM dba_users WHERE username NOT IN ('SYS', 'SYSTEM', 'RDSADMIN');
        --SELECT username, account_status, expiry_date, last_login FROM dba_users;
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-020_12c":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT username, account_status, expiry_date, last_login FROM dba_users",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_line.username || '","account_status":"' || result_line.account_status || '","expiry_date":"' || TO_CHAR(result_line.expiry_date, 'YYYY-MM-DD') || '","last_login":"' || result_line.last_login || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-020_12c":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT username, account_status, expiry_date, last_login FROM dba_users NOT IN (`SYS`, `SYSTEM`, `RDSADMIN`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"username":"' || result_line.username || '","account_status":"' || result_line.account_status || '","expiry_date":"' || TO_CHAR(result_line.expiry_date, 'YYYY-MM-DD') || '","last_login":"' || result_line.last_login || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-022 (Self-Managed DB: 설정파일 퍼미션 확인, AWS RDS: 클라우드 관리체계(PISM-046) 스크립트 결과 참고) 

-- DBM-024_1
DECLARE
    result_line DBA_SYS_PRIVS%ROWTYPE;
    CURSOR result_cur
    IS
    SELECT * FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES';
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-024_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, privilege, ADMIN_OPTION FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION=`YES`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '","ADMIN_OPTION":"' || result_line.ADMIN_OPTION || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-024_2
DECLARE
    result_line dba_role_privs%ROWTYPE;
    CURSOR result_cur
    IS
    SELECT * FROM dba_role_privs WHERE ADMIN_OPTION='YES';
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-024_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, granted_role, ADMIN_OPTION FROM dba_role_privs WHERE ADMIN_OPTION=`YES`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","granted_role":"' || result_line.granted_role || '","ADMIN_OPTION":"' || result_line.ADMIN_OPTION || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-024_3
DECLARE
    result_line dba_tab_privs%ROWTYPE;
    CURSOR result_cur
    IS
    SELECT * FROM dba_tab_privs WHERE grantable='YES' AND owner NOT IN ('GSMADMIN_INTERNAL','XDB', 'SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'APEX_040200') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND grantee NOT IN ('APEX_040200') ORDER BY grantee;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-024_3":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, privilege, owner, table_name, grantable FROM dba_tab_privs WHERE grantable=`YES` AND owner NOT IN (`GSMADMIN_INTERNAL`,`XDB`, `SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `APEX_040200`) AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role=`DBA`) AND grantee NOT IN (`APEX_040200`) ORDER BY grantee;",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","table_name":"' || result_line.table_name || '","grantable":"' || result_line.grantable ||'"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-026 // (Self-Managed DB: 서버 스크립트 확인(umask 값 확인), AWS RDS: N/A)


-- DBM-028_1
DECLARE
    result_col1 dba_objects.owner%TYPE;
    result_col2 dba_objects.OBJECT_NAME%TYPE;
    result_col3 dba_objects.OBJECT_TYPE%TYPE; -- object type 추가

    CURSOR result_cur IS SELECT owner, OBJECT_NAME, OBJECT_TYPE FROM dba_objects WHERE owner NOT IN ('GSMADMIN_INTERNAL','XDB', 'SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'APEX_040200','DVF', 'PUBLIC', 'OUTLN', 'CTXSYS', 'OLAPSYS', 'FLOWS_FILES', 'ORACLE_OCM', 'DVSYS', 'AUDSYS', 'DBSNMP', 'OJVMSYS', 'APPQOSSYS', 'ORDDATA', 'SI_INFORMTN_SCHEMA' );
    CURSOR result_cur_rds IS SELECT owner, OBJECT_NAME, OBJECT_TYPE FROM dba_objects WHERE owner NOT IN ('GSMADMIN_INTERNAL','XDB', 'SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'APEX_040200','DVF', 'PUBLIC', 'OUTLN', 'CTXSYS', 'OLAPSYS', 'FLOWS_FILES', 'ORACLE_OCM', 'DVSYS', 'AUDSYS', 'DBSNMP', 'OJVMSYS', 'APPQOSSYS', 'ORDDATA', 'SI_INFORMTN_SCHEMA', 'RDSADMIN' );
    --SELECT owner, OBJECT_NAME FROM dba_objects WHERE owner NOT IN ('GSMADMIN_INTERNAL','XDB', 'SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'APEX_040200','DVF', 'PUBLIC', 'OUTLN', 'CTXSYS', 'OLAPSYS', 'FLOWS_FILES', 'ORACLE_OCM', 'DVSYS', 'AUDSYS', 'DBSNMP', 'OJVMSYS', 'APPQOSSYS', 'ORDDATA', 'SI_INFORMTN_SCHEMA' );

BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-028_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT owner, OBJECT_NAME FROM dba_objects WHERE owner NOT IN (`GSMADMIN_INTERNAL`,`XDB`, `SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `APEX_040200`,`DVF`, `PUBLIC`, `OUTLN`, `CTXSYS`, `OLAPSYS`, `FLOWS_FILES`, `ORACLE_OCM`, `DVSYS`, `AUDSYS`, `DBSNMP`, `OJVMSYS`, `APPQOSSYS`, `ORDDATA`, `SI_INFORMTN_SCHEMA` )",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_col1, result_col2, result_col3;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"owner":"' || result_col1 || '","object_name":"' || result_col2 || '","object_type":"' || result_col3 || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');

    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-028_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT owner, OBJECT_NAME FROM dba_objects WHERE owner NOT IN (`GSMADMIN_INTERNAL`,`XDB`, `SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `APEX_040200`,`DVF`, `PUBLIC`, `OUTLN`, `CTXSYS`, `OLAPSYS`, `FLOWS_FILES`, `ORACLE_OCM`, `DVSYS`, `AUDSYS`, `DBSNMP`, `OJVMSYS`, `APPQOSSYS`, `ORDDATA`, `SI_INFORMTN_SCHEMA`, `RDSADMIN` )",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_col1, result_col2, result_col3;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"owner":"' || result_col1 || '","object_name":"' || result_col2 || '","object_type":"' || result_col3 || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/


-- DBM-028_2
DECLARE
    result_line dba_tab_privs%ROWTYPE;
    CURSOR result_cur IS SELECT * FROM dba_tab_privs WHERE OWNER NOT IN ('ORDDATA','OLAPSYS','CTXSYS','DVSYS','SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'XDB', 'GSMADMIN_INTERNAL', 'DVF', 'APEX_040200', 'FLOWS_FILES', 'OUTLN','DBSNMP','APPQOSSYS');
    CURSOR result_cur_rds IS SELECT * FROM dba_tab_privs WHERE OWNER NOT IN ('ORDDATA','OLAPSYS','CTXSYS','DVSYS','SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM', 'WMSYS','SDB','LBACSYS', 'XDB', 'GSMADMIN_INTERNAL', 'DVF', 'APEX_040200', 'FLOWS_FILES', 'OUTLN','DBSNMP','APPQOSSYS','RDSADMIN');
        --SELECT grantee, privilege, owner, TABLE_NAME FROM dba_tab_privs WHERE TABLE_NAME='AUD$';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0) THEN
        DBMS_OUTPUT.put_line('{"DBM-028_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE OWNER NOT IN (`ORDDATA`,`OLAPSYS`,`CTXSYS`,`DVSYS`,`SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `XDB`, `GSMADMIN_INTERNAL`, `DVF`, `APEX_040200`, `FLOWS_FILES`, `OUTLN`,`DBSNMP`,`APPQOSSYS`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","table_name":"' || result_line.table_name || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');

    ELSIF &db_environment_state IN (1) THEN
        DBMS_OUTPUT.put_line('{"DBM-028_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT * FROM dba_tab_privs WHERE OWNER NOT IN (`ORDDATA`,`OLAPSYS`,`CTXSYS`,`DVSYS`,`SYS`,`MDSYS`,`ORDPLUGINS`,`ORDSYS`,`SYSTEM`, `WMSYS`,`SDB`,`LBACSYS`, `XDB`, `GSMADMIN_INTERNAL`, `DVF`, `APEX_040200`, `FLOWS_FILES`, `OUTLN`,`DBSNMP`,`APPQOSSYS`,`RDSADMIN`)",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur_rds;
            LOOP
                FETCH result_cur_rds INTO result_line;
                EXIT  WHEN result_cur_rds%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","table_name":"' || result_line.table_name || '"},');
            END LOOP;
        CLOSE result_cur_rds;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/



-- DBM-029
DECLARE
    result_line gv$parameter%ROWTYPE;
    CURSOR result_cur
    IS
        SELECT * FROM gv$parameter WHERE name = 'resource_limit';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-029":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT name, value FROM gv$parameter WHERE name=`resource_limit`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"name":"' || result_line.name || '","value":"' || result_line.value || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-030_1
DECLARE
    result_line dba_tables%ROWTYPE;
    CURSOR result_cur
    IS
        Select * from dba_tables where table_name='AUD$';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-030_1":{');
        DBMS_OUTPUT.put_line('"QUERY": "Select owner from dba_tables where table_name=`AUD$`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"table":"' || 'AUD$' || '","owner":"' || result_line.owner || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

-- DBM-030_2
DECLARE
    result_line dba_tab_privs%ROWTYPE;
    CURSOR result_cur
    IS
        --SELECT grantee, privilege, owner, TABLE_NAME FROM dba_tab_privs WHERE TABLE_NAME='AUD$';
        SELECT * FROM dba_tab_privs WHERE TABLE_NAME='AUD$';
        --SELECT grantee, privilege FROM DBA_SYS_PRIVS;
BEGIN
    IF &db_environment_state IN (0, 1) THEN
        DBMS_OUTPUT.put_line('{"DBM-030_2":{');
        DBMS_OUTPUT.put_line('"QUERY": "SELECT grantee, privilege, owner, table_name from dba_tab_privs WHERE TABLE_NAME=`AUD$`",');
        DBMS_OUTPUT.put_line('"RESULT": [');
        OPEN result_cur;
            LOOP
                FETCH result_cur INTO result_line;
                EXIT  WHEN result_cur%NOTFOUND;
                    DBMS_OUTPUT.PUT_LINE('{"grantee":"' || result_line.grantee || '","privilege":"' || result_line.privilege || '","owner":"' || result_line.owner || '","table_name":"' || result_line.table_name || '"},');
            END LOOP;
        CLOSE result_cur;
        DBMS_OUTPUT.put_line(']}},');
    END IF;
END;
/

BEGIN
DBMS_OUTPUT.put_line(']');
END;
/

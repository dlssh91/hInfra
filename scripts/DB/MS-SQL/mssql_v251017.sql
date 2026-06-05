
-- 0: Self-Managed(설치형 DB), 1: CSP-Managed (AWS RDS)
DECLARE @db_environment_state INT;

IF DB_ID('rdsadmin') IS NOT NULL
    SET @db_environment_state = 1; -- CSP-Managed (AWS RDS)
ELSE
    SET @db_environment_state = 0; -- Self-Managed

SET NOCOUNT ON
PRINT('[')
-- DBM-001
BEGIN
    DECLARE @dbm001_var1 VARCHAR(MAX), @dbm001_var2 VARCHAR(MAX), @dbm001_var3 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, CONVERT(varchar(MAX), password_hash, 1), is_disabled FROM sys.sql_logins;

    IF @db_environment_state = 0 -- CSP-Managed: N/A
    BEGIN
        PRINT('{"DBM-001":{')
        PRINT('"QUERY": "SELECT name, password_hash, is_disabled FROM sys.sql_logins;",')
        PRINT('"RESULT": [')

        OPEN result_cur
        FETCH NEXT FROM result_cur INTO @dbm001_var1, @dbm001_var2, @dbm001_var3
            WHILE @@FETCH_STATUS = 0
            BEGIN
                PRINT(CONCAT('{"name":"', @dbm001_var1, '", "password_hash":"', @dbm001_var2, '", "is_disabled":"', @dbm001_var3, '"}, '))
                FETCH NEXT FROM result_cur INTO @dbm001_var1, @dbm001_var2, @dbm001_var3
            END;
        CLOSE result_cur
        PRINT(']}},')
    END
    DEALLOCATE result_cur;
END

-- DBM-003_1
BEGIN
    DECLARE @dbm003_var1 VARCHAR(MAX), @dbm003_var2 VARCHAR(MAX), @dbm003_var3 VARCHAR(MAX), @dbm003_var4 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins
        WHERE (
            (@db_environment_state = 0 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##'))
            OR
            (@db_environment_state = 1 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##', 'rdsa'))
        );
    PRINT('{"DBM-003_1":{')
    IF @db_environment_state = 0 
        PRINT('"QUERY": "SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins WHERE name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`);",')
    ELSE
        PRINT('"QUERY": "SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins WHERE name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`, `rdsa`);",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm003_var1, @dbm003_var2, @dbm003_var3, @dbm003_var4
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm003_var1, '", "created_date":"', @dbm003_var2, '", "modify_date":"', @dbm003_var3, '", "is_disabled":"', @dbm003_var4 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm003_var1, @dbm003_var2, @dbm003_var3, @dbm003_var4
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END

-- DBM-003_2
BEGIN
    DECLARE @dbm003_var5 VARCHAR(MAX), @dbm003_var6 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT login_name, MAX(login_time) FROM sys.dm_exec_sessions 
        WHERE (
            (@db_environment_state = 0 AND login_name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##'))
            OR
            (@db_environment_state = 1 AND login_name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##', 'rdsa'))
        ) GROUP BY login_name;

    PRINT('{"DBM-003_2":{')
    IF @db_environment_state = 0 
        PRINT('"QUERY": "SELECT login_name, MAX(login_time) FROM sys.dm_exec_sessions WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`) GROUP BY login_name;",')
    ELSE
        PRINT('"QUERY": "SELECT login_name, MAX(login_time) FROM sys.dm_exec_sessions WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`, `rdsa`) GROUP BY login_name;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm003_var5, @dbm003_var6
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm003_var5, '", "last_login_time":"', @dbm003_var6,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm003_var5, @dbm003_var6
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END


-- DBM-004
BEGIN
    DECLARE @dbm004_var1 VARCHAR(MAX), @dbm004_var2 VARCHAR(MAX), @dbm004_var3 VARCHAR(MAX), @dbm004_var4 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, sysadmin, serveradmin, securityadmin FROM sys.syslogins;

    PRINT('{"DBM-004":{')
    PRINT('"QUERY": "SELECT name, sysadmin, serveradmin, securityadmin FROM sys.syslogins;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm004_var1, @dbm004_var2, @dbm004_var3, @dbm004_var4
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm004_var1, '", "sysadmin":"', @dbm004_var2, '", "serveradmin":"', @dbm004_var3, '", "securityadmin":"', @dbm004_var4 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm004_var1, @dbm004_var2, @dbm004_var3, @dbm004_var4
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END


-- DBM-005 
BEGIN
    -- DROP TABLE IF EXISTS #fsi_dbm005_tableinfo
    IF OBJECT_ID(N'tempdb..#fsi_dbm005_tableinfo', N'U') IS NOT NULL
    DROP TABLE #fsi_dbm005_tableinfo

    CREATE TABLE #fsi_dbm005_tableinfo (
        database_name VARCHAR(128),
        schema_name VARCHAR(128),
        table_name VARCHAR(128),
        column_name VARCHAR(128)
    )
    DECLARE @dbm005_dbname VARCHAR(MAX)
    DECLARE @dbm005_feed_query VARCHAR(MAX)
    DECLARE dbm005_dbname_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT DISTINCT name FROM sys.sysdatabases
        WHERE (
            (@db_environment_state = 0)
            OR
            (@db_environment_state = 1 AND name NOT IN ('model'))
        );

    OPEN dbm005_dbname_cursor
    FETCH NEXT FROM dbm005_dbname_cursor INTO @dbm005_dbname
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @dbm005_feed_query =
                'INSERT INTO #fsi_dbm005_tableinfo
                SELECT '''+@dbm005_dbname+''' AS ''database_name'',
                    s.name AS ''schema_name'',
                    t.name AS ''table_name'',
                    c.name AS ''column_name''
                FROM '+@dbm005_dbname+'.sys.schemas s,
                    '+@dbm005_dbname+'.sys.tables t,
                    '+@dbm005_dbname+'.sys.columns c
                WHERE s.schema_id = t.schema_id
                AND t.object_id = c.object_id
                AND c.collation_name IS NOT NULL
                AND (c.name LIKE ''%PSWD%''
                    OR c.name LIKE ''%PASS%''
                    OR c.name LIKE ''%PW%''
                    OR c.name LIKE ''%jumin%'')'
            EXEC (@dbm005_feed_query)
            FETCH NEXT FROM dbm005_dbname_cursor INTO @dbm005_dbname
        END
    CLOSE dbm005_dbname_cursor
    DEALLOCATE dbm005_dbname_cursor
END

BEGIN
    -- DROP TABLE IF EXISTS #fsi_dbm005_result
    IF OBJECT_ID(N'tempdb..#fsi_dbm005_result', N'U') IS NOT NULL
    DROP TABLE #fsi_dbm005_result

    CREATE TABLE #fsi_dbm005_result (
        database_name VARCHAR(128),
        schema_name VARCHAR(128),
        table_name VARCHAR(128),
        column_name VARCHAR(128),
        sample VARCHAR(MAX)
    )
    DECLARE @dbm005_schema_name VARCHAR(128)
    DECLARE @dbm005_table_name VARCHAR(128)
    DECLARE @dbm005_column_name VARCHAR(128)
    DECLARE dbm005_sample_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT database_name, schema_name, table_name, column_name FROM #fsi_dbm005_tableinfo

    OPEN dbm005_sample_cursor
    FETCH NEXT FROM dbm005_sample_cursor INTO @dbm005_dbname, @dbm005_schema_name, @dbm005_table_name, @dbm005_column_name
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @dbm005_feed_query =
                'INSERT INTO #fsi_dbm005_result VALUES (
                    '''+@dbm005_dbname+''',
                    '''+@dbm005_schema_name+''',
                    '''+@dbm005_table_name+''',
                    '''+@dbm005_column_name+''',
                    (SELECT STUFF((
                        SELECT CAST('','' AS VARCHAR(1))+t.'+@dbm005_column_name
                    +' FROM (
                            SELECT DISTINCT TOP 10 '+@dbm005_column_name
                        +' FROM '+@dbm005_dbname+'.'+@dbm005_schema_name+'.'+@dbm005_table_name
                    +') t FOR XML PATH('''')), 1, 1, ''''))
                )'
            EXEC (@dbm005_feed_query)
            FETCH NEXT FROM dbm005_sample_cursor INTO @dbm005_dbname, @dbm005_schema_name, @dbm005_table_name, @dbm005_column_name
        END

    CLOSE dbm005_sample_cursor
    DEALLOCATE dbm005_sample_cursor
END

BEGIN
    DECLARE @dbm005_sample VARCHAR(MAX)
    DECLARE dbm005_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT database_name, schema_name, table_name, column_name, sample FROM #fsi_dbm005_result

    PRINT('{"DBM-005":{')
    PRINT('"QUERY": "",')
    PRINT('"RESULT": [')

    OPEN dbm005_cursor
    FETCH NEXT FROM dbm005_cursor INTO @dbm005_dbname, @dbm005_schema_name, @dbm005_table_name, @dbm005_column_name, @dbm005_sample
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"dbname":"', @dbm005_dbname, '", "schema_name":"', @dbm005_schema_name, '", "table_name":"', @dbm005_table_name, '", "column_name":"', @dbm005_column_name, '", "sample":"',@dbm005_sample ,'"}, '))

            FETCH NEXT FROM dbm005_cursor INTO @dbm005_dbname, @dbm005_schema_name, @dbm005_table_name, @dbm005_column_name, @dbm005_sample
        END

    CLOSE dbm005_cursor
    DEALLOCATE dbm005_cursor
    PRINT(']}},')
    DROP TABLE #fsi_dbm005_tableinfo
    DROP TABLE #fsi_dbm005_result;
END


-- DBM-006
BEGIN
    DECLARE @dbm006_var1 VARCHAR(MAX), @dbm006_var2 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, is_policy_checked from sys.sql_logins
        WHERE (
            (@db_environment_state = 0 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##'))
            OR
            (@db_environment_state = 1 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##', 'rdsa'))
        );

    PRINT('{"DBM-006":{')
    IF @db_environment_state = 0 
        PRINT('"QUERY": "SELECT name, is_policy_checked from sys.sql_logins WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`);",')
    ELSE
        PRINT('"QUERY": "SELECT name, is_policy_checked from sys.sql_logins WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`, `rdsa`);",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm006_var1, @dbm006_var2
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm006_var1, '", "is_policy_checked":"', @dbm006_var2 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm006_var1, @dbm006_var2
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END


-- DBM-007
BEGIN
    DECLARE @dbm007_var1 VARCHAR(MAX), @dbm007_var2 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, is_policy_checked from sys.sql_logins
        WHERE (
            (@db_environment_state = 0 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##'))
            OR
            (@db_environment_state = 1 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##', 'rdsa'))
        );

    PRINT('{"DBM-007":{')
    IF @db_environment_state = 0 
        PRINT('"QUERY": "SELECT name, is_policy_checked from sys.sql_logins WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`);",')
    ELSE
        PRINT('"QUERY": "SELECT name, is_policy_checked from sys.sql_logins WHERE login_name NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`, `rdsa`);",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm007_var1, @dbm007_var2
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm007_var1, '", "is_policy_checked":"', @dbm007_var2 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm007_var1, @dbm007_var2
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END


-- DBM-008
BEGIN
    DECLARE @dbm008_var1 VARCHAR(MAX), @dbm008_var2 VARCHAR(MAX), @dbm008_var3 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, CONVERT(DATE, LOGINPROPERTY(name, 'PasswordLastSetTime')), DATEDIFF(DD,  CONVERT(SMALLDATETIME, LOGINPROPERTY(name, 'PasswordLastSetTime')), GETDATE()) FROM sys.server_principals where type ='S' and is_disabled = 0;

    PRINT('{"DBM-008":{')
    PRINT('"QUERY": "SELECT PasswordLastSetTime, days_after_changed from sys.server_principals WHERE type =''S'' and is_disabled = 0;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm008_var1, @dbm008_var2, @dbm008_var3
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm008_var1, '", "PasswordLastSetTime":"', @dbm008_var2, '", "days_after_changed":"', @dbm008_var3 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm008_var1, @dbm008_var2, @dbm008_var3
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END


-- DBM-009
--BEGIN
--    DECLARE @dbm009_var1 VARCHAR(MAX), @dbm009_var2 VARCHAR(MAX)
--    DECLARE result_cur CURSOR LOCAL FOR SELECT name, CONVERT(varchar(MAX), value) FROM sys.configurations where name LIKE '%remote query timeout%'

--    PRINT('{"DBM-009":{')
--    PRINT('"QUERY": "SELECT name, value FROM sys.configurations where name LIKE ''%remote query timeout%'';",')
--    PRINT('"RESULT": [')

--    OPEN result_cur
--    FETCH NEXT FROM result_cur INTO @dbm009_var1, @dbm009_var2
--        WHILE @@FETCH_STATUS = 0
--        BEGIN
--            PRINT(CONCAT('{"name":"', @dbm009_var1, '", "value":"', @dbm009_var2, '"}, '))
--            FETCH NEXT FROM result_cur INTO @dbm009_var1, @dbm009_var2
--        END;
--    CLOSE result_cur
--    DEALLOCATE result_cur;
--    PRINT(']}},')
--END
-- DBM-009 // DATEDIFF(MINUTE, sys.dm_exec_sessions.last_request_end_time, GETDATE()) AS idle_minutes로 판단하도록 변경
BEGIN
    DECLARE @session_id INT, @login_name NVARCHAR(128), @host_name NVARCHAR(128), @status NVARCHAR(30), @connect_time DATETIME, @last_request_end_time DATETIME, @idle_minutes INT;

    DECLARE result_cur CURSOR LOCAL FOR SELECT s.session_id, s.login_name, s.host_name, s.status, c.connect_time, s.last_request_end_time, DATEDIFF(MINUTE, s.last_request_end_time, GETDATE()) AS idle_minutes FROM sys.dm_exec_sessions AS s JOIN sys.dm_exec_connections AS c ON s.session_id = c.session_id WHERE s.is_user_process = 1 AND s.session_id <> @@SPID AND s.login_name <> 'NT AUTHORITY\SYSTEM' ORDER BY idle_minutes DESC;

    PRINT('{"DBM-009":{')
    PRINT('"QUERY": "SELECT s.session_id, s.login_name, s.host_name, s.status, c.connect_time, s.last_request_end_time, DATEDIFF(MINUTE, s.last_request_end_time, GETDATE()) AS idle_minutes FROM sys.dm_exec_sessions AS s JOIN sys.dm_exec_connections AS c ON s.session_id = c.session_id WHERE s.is_user_process = 1 AND s.session_id <> @@SPID AND s.login_name <> ''NT AUTHORITY\\SYSTEM'' ORDER BY idle_minutes DESC;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @session_id, @login_name, @host_name, @status, @connect_time, @last_request_end_time, @idle_minutes

    WHILE @@FETCH_STATUS = 0
    BEGIN
        PRINT(CONCAT('{"session_id":"', @session_id,'", "login_name":"', @login_name,'", "host_name":"', @host_name,'", "status":"', @status,'", "connect_time":"', ISNULL(CONVERT(VARCHAR, @connect_time, 126), 'N/A'),'", "last_request_end_time":"', ISNULL(CONVERT(VARCHAR, @last_request_end_time, 126), 'N/A'),'", "idle_minutes":"', ISNULL(CAST(@idle_minutes AS VARCHAR(20)), 'N/A'),'"}, '));
        FETCH NEXT FROM result_cur INTO @session_id, @login_name, @host_name, @status, @connect_time, @last_request_end_time, @idle_minutes
    END;
    CLOSE result_cur
    DEALLOCATE result_cur;

    PRINT(']}},')
END


-- DBM-011
BEGIN
    DECLARE @dbm011_var1 VARCHAR(MAX), @dbm011_var2 VARCHAR(MAX), @dbm011_var3 VARCHAR(MAX), @dbm011_var4 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT a.name, d.audit_action_name, s.create_date, s.modify_date FROM sys.server_audits AS a JOIN sys.server_audit_specifications AS s ON a.audit_guid = s.audit_guid JOIN sys.server_audit_specification_details AS d ON s.server_specification_id = d.server_specification_id WHERE s.is_state_enabled = 1


    PRINT('{"DBM-011":{')
    PRINT('"QUERY": "SELECT a.name, d.audit_action_name, s.create_date, s.modify_date FROM sys.server_audits AS a JOIN sys.server_audit_specifications AS s ON a.audit_guid = s.audit_guid JOIN sys.server_audit_specification_details AS d ON s.server_specification_id = d.server_specification_id WHERE s.is_state_enabled = 1;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm011_var1, @dbm011_var2, @dbm011_var3, @dbm011_var4
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"audit_name":"', @dbm011_var1, '", "audit_action":"', @dbm011_var2, '", "create_date":"', @dbm011_var3, '", "modify_date":"', @dbm011_var4, '"}, '))
            FETCH NEXT FROM result_cur INTO @dbm011_var1, @dbm011_var2, @dbm011_var3, @dbm011_var4
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT('],')
    PRINT('"NOTE": "For audit log upload settings, refer to the PISM-011 script results.",')
    PRINT('}},')
END


-- DBM-013 // (Self-Managed: windows 방화벽 확인, CSP-Managed: 클라우드 관리체계(PISM-013) 스크립트 결과 참고)

-- DBM-015
BEGIN
    DECLARE @dbm015_var1 VARCHAR(MAX), @dbm015_var2 VARCHAR(MAX), @dbm015_var3 VARCHAR(MAX), @dbm015_var4 VARCHAR(MAX), @dbm015_var5 VARCHAR(MAX), @dbm015_var6 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT l.name, (SELECT name FROM sys.server_principals WHERE grantor_principal_id = principal_id), sp.state_desc, sp.class_desc, sp.permission_name, e.name FROM sys.server_permissions AS sp JOIN sys.server_principals AS l ON sp.grantee_principal_id = l.principal_id LEFT JOIN sys.endpoints AS e ON sp.major_id = e.endpoint_id WHERE l.name = 'public' AND sp.state_desc != 'DENY';

    PRINT('{"DBM-015":{')
    PRINT('"QUERY": "SELECT l.name, (SELECT name FROM sys.server_principals WHERE grantor_principal_id = principal_id), sp.state_desc, sp.class_desc, sp.permission_name, e.name FROM sys.server_permissions AS sp JOIN sys.server_principals AS l ON sp.grantee_principal_id = l.principal_id LEFT JOIN sys.endpoints AS e ON sp.major_id = e.endpoint_id WHERE l.name = ''public'' AND sp.state_desc != ''DENY'';",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm015_var1, @dbm015_var2, @dbm015_var3, @dbm015_var4, @dbm015_var5, @dbm015_var6
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"grantee":"', @dbm015_var1, '", "grantor":"', @dbm015_var2, '", "state":"', @dbm015_var3, '", "class":"', @dbm015_var4, '", "permission_name":"', @dbm015_var5, '", "endpoint_permission_name":"',@dbm015_var6, '"}, '))
            FETCH NEXT FROM result_cur INTO @dbm015_var1, @dbm015_var2, @dbm015_var3, @dbm015_var4, @dbm015_var5, @dbm015_var6
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END



-- DBM-016
BEGIN
    DECLARE @dbm016_var1 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT @@VERSION;

    PRINT('{"DBM-016":{')
    PRINT('"QUERY": "SELECT @@VERSION;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm016_var1
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"version_info":"', @dbm016_var1, '"}, '))
            FETCH NEXT FROM result_cur INTO @dbm016_var1
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END

-- DBM-017
BEGIN
    -- DROP TABLE IF EXISTS #fsi_dbm017_tableinfo
    IF OBJECT_ID(N'tempdb..#fsi_dbm017_tableinfo', N'U') IS NOT NULL
    DROP TABLE #fsi_dbm017_tableinfo

    CREATE TABLE #fsi_dbm017_tableinfo (
        database_name VARCHAR(MAX),
        grantee VARCHAR(MAX),
        grantor VARCHAR(MAX),
        permname VARCHAR(MAX),
		schsema_name VARCHAR(MAX),
		name VARCHAR(MAX)
    )

    EXECUTE sp_msforeachdb 'INSERT INTO #fsi_dbm017_tableinfo
    SELECT ''?'' AS ''database'', u.name AS ''grantee'', (SELECT name FROM sys.database_principals WHERE sp.grantor_principal_id = principal_id) AS ''grantor'', SCHEMA_NAME(o.schema_id) AS ''Schema'', sp.permission_name, o.name
    FROM [?].sys.database_permissions sp
    LEFT JOIN [?].sys.all_objects o ON sp.major_id = o.object_id
    JOIN [?].sys.database_principals u ON sp.grantee_principal_id = u.principal_id WHERE u.name <> ''public'' and sp.permission_name <> ''CONNECT''
    and o.type=''S'''

    DECLARE @dbm017_var1 VARCHAR(MAX), @dbm017_var2 VARCHAR(MAX), @dbm017_var3 VARCHAR(MAX), @dbm017_var4 VARCHAR(MAX), @dbm017_var5 VARCHAR(MAX), @dbm017_var6 VARCHAR(MAX)

    DECLARE dbm017_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT database_name, grantee, grantor, schsema_name, permname, name FROM #fsi_dbm017_tableinfo

    PRINT('{"DBM-017":{')
    PRINT('"QUERY": "",')
    PRINT('"RESULT": [')

    OPEN dbm017_cursor
    FETCH NEXT FROM dbm017_cursor INTO @dbm017_var1, @dbm017_var2, @dbm017_var3, @dbm017_var4, @dbm017_var5, @dbm017_var6
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"dbname":"', @dbm017_var1, '", "grantee":"', @dbm017_var2, '", "grantor":"', @dbm017_var3, '", "permisson":"', @dbm017_var4,'", "schsema":"', @dbm017_var5, '", "table_name":"',@dbm017_var6 ,'"}, '))

            FETCH NEXT FROM dbm017_cursor INTO @dbm017_var1, @dbm017_var2, @dbm017_var3, @dbm017_var4, @dbm017_var5, @dbm017_var6
        END

    CLOSE dbm017_cursor
    DEALLOCATE dbm017_cursor
    PRINT(']}},')
    DROP TABLE #fsi_dbm017_tableinfo;
END

-- DBM-019 
IF @db_environment_state = 0 -- CSP-Managed: AWS Secrets Manager, IAM 등 확인(스크립트X)
BEGIN
    DECLARE @dbm019_var1 VARCHAR(MAX), @dbm019_var2 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, is_policy_checked from sys.sql_logins;

    PRINT('{"DBM-019":{')
    PRINT('"QUERY": "SELECT name, is_policy_checked from sys.sql_logins;",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm019_var1, @dbm019_var2
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm019_var1, '", "is_policy_checked":"', @dbm019_var2 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm019_var1, @dbm019_var2
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END

-- DBM-020
BEGIN
    DECLARE @dbm020_var1 VARCHAR(MAX), @dbm020_var2 VARCHAR(MAX), @dbm020_var3 VARCHAR(MAX), @dbm020_var4 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins
        WHERE (
            (@db_environment_state = 0 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##'))
            OR
            (@db_environment_state = 1 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##', 'rdsa'))
        );

    PRINT('{"DBM-020":{')
    IF @db_environment_state = 0
        PRINT('"QUERY": "SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`);",')
    ELSE
        PRINT('"QUERY": "SELECT name, create_date, modify_date, is_disabled FROM sys.sql_logins NOT IN (`##MS_PolicyTsqlExecutionLogin##`, `##MS_PolicyEventProcessingLogin##`, `rdsa`);",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm020_var1, @dbm020_var2, @dbm020_var3, @dbm020_var4
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm020_var1, '", "created_date":"', @dbm020_var2, '", "modify_date":"', @dbm020_var3, '", "is_disabled":"', @dbm020_var4 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm020_var1, @dbm020_var2, @dbm020_var3, @dbm020_var4
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END

-- DBM-021 // (Self-Managed: 콘솔에서 확인, CSP-Managed: N/A)

-- DBM-024 
BEGIN
    -- DROP TABLE IF EXISTS #fsi_dbm024_tableinfo
    IF OBJECT_ID(N'tempdb..#fsi_dbm024_tableinfo', N'U') IS NOT NULL
    DROP TABLE #fsi_dbm024_tableinfo

    CREATE TABLE #fsi_dbm024_tableinfo (
        database_name VARCHAR(MAX),
        grantee VARCHAR(MAX),
        grantor VARCHAR(MAX),
        permname VARCHAR(MAX),
		schsema_name VARCHAR(MAX),
		name VARCHAR(MAX)
    )

    EXECUTE sp_msforeachdb 'INSERT INTO #fsi_dbm024_tableinfo
    SELECT ''?'' AS ''database'', u.name AS ''grantee'', (SELECT name FROM sys.database_principals WHERE sp.grantor_principal_id = principal_id) AS ''grantor'', SCHEMA_NAME(o.schema_id) AS ''Schema'', sp.permission_name, o.name
    FROM [?].sys.database_permissions sp
    LEFT JOIN [?].sys.all_objects o ON sp.major_id = o.object_id
    JOIN [?].sys.database_principals u ON sp.grantee_principal_id = u.principal_id WHERE u.name <> ''public'' and sp.permission_name <> ''CONNECT'' AND sp.state_desc=''GRANT_WITH_GRANT_OPTION'''

    DECLARE @dbm024_var1 VARCHAR(MAX), @dbm024_var2 VARCHAR(MAX), @dbm024_var3 VARCHAR(MAX), @dbm024_var4 VARCHAR(MAX), @dbm024_var5 VARCHAR(MAX), @dbm024_var6 VARCHAR(MAX)

    DECLARE dbm024_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT database_name, grantee, grantor, schsema_name, permname, name FROM #fsi_dbm024_tableinfo

    PRINT('{"DBM-024":{')
    PRINT('"QUERY": "SELECT * FROM sys.database_permissions WHERE state_desc=''GRANT_WITH_GRATION_OPTION''",')
    PRINT('"RESULT": [')

    OPEN dbm024_cursor
    FETCH NEXT FROM dbm024_cursor INTO @dbm024_var1, @dbm024_var2, @dbm024_var3, @dbm024_var4, @dbm024_var5, @dbm024_var6
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"dbname":"', @dbm024_var1, '", "grantee":"', @dbm024_var2, '", "grantor":"', @dbm024_var3, '", "permisson":"', @dbm024_var4,'", "schsema":"', @dbm024_var5, '", "table_name":"',@dbm024_var6 ,'"}, '))

            FETCH NEXT FROM dbm024_cursor INTO @dbm024_var1, @dbm024_var2, @dbm024_var3, @dbm024_var4, @dbm024_var5, @dbm024_var6
        END

    CLOSE dbm024_cursor
    DEALLOCATE dbm024_cursor
    PRINT(']}},')

    DROP TABLE #fsi_dbm024_tableinfo;
END


-- DBM-028
BEGIN
    -- DROP TABLE IF EXISTS #fsi_dbm028_tableinfo
    IF OBJECT_ID(N'tempdb..#fsi_dbm028_tableinfo', N'U') IS NOT NULL
    DROP TABLE #fsi_dbm028_tableinfo

    CREATE TABLE #fsi_dbm028_tableinfo (
        database_name VARCHAR(MAX),
        grantee VARCHAR(MAX),
        grantor VARCHAR(MAX),
        permname VARCHAR(MAX),
		schsema_name VARCHAR(MAX),
		name VARCHAR(MAX)
    )

    EXECUTE sp_msforeachdb 'INSERT INTO #fsi_dbm028_tableinfo
    SELECT ''?'' AS ''database'', u.name AS ''grantee'', (SELECT name FROM sys.database_principals WHERE sp.grantor_principal_id = principal_id) AS ''grantor'', SCHEMA_NAME(o.schema_id) AS ''Schema'', sp.permission_name, o.name  AS ''table_name''
    FROM [?].sys.database_permissions sp
    LEFT JOIN [?].sys.all_objects o ON sp.major_id = o.object_id
    JOIN [?].sys.database_principals u ON sp.grantee_principal_id = u.principal_id WHERE u.name <> ''public'' and sp.permission_name <> ''CONNECT'' '

    DECLARE @dbm028_var1 VARCHAR(MAX), @dbm028_var2 VARCHAR(MAX), @dbm028_var3 VARCHAR(MAX), @dbm028_var4 VARCHAR(MAX), @dbm028_var5 VARCHAR(MAX), @dbm028_var6 VARCHAR(MAX)

    DECLARE dbm028_cursor CURSOR LOCAL STATIC READ_ONLY FORWARD_ONLY FOR SELECT database_name, grantee, grantor, schsema_name, permname, name FROM #fsi_dbm028_tableinfo

    PRINT('{"DBM-028":{')
    PRINT('"QUERY": "",')
    PRINT('"RESULT": [')

    OPEN dbm028_cursor
    FETCH NEXT FROM dbm028_cursor INTO @dbm028_var1, @dbm028_var2, @dbm028_var3, @dbm028_var4, @dbm028_var5, @dbm028_var6
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"dbname":"', @dbm028_var1, '", "grantee":"', @dbm028_var2, '", "grantor":"', @dbm028_var3, '", "permisson":"', @dbm028_var4,'", "schsema":"', @dbm028_var5, '", "table_name":"',@dbm028_var6 ,'"}, '))

            FETCH NEXT FROM dbm028_cursor INTO @dbm028_var1, @dbm028_var2, @dbm028_var3, @dbm028_var4, @dbm028_var5, @dbm028_var6
        END

    CLOSE dbm028_cursor
    DEALLOCATE dbm028_cursor
    PRINT(']}},')

    DROP TABLE #fsi_dbm028_tableinfo;
END

-- DBM-031 
IF @db_environment_state = 0 -- CSP-Managed: N/A
BEGIN
    DECLARE @dbm031_var1 VARCHAR(MAX), @dbm031_var2 VARCHAR(MAX), @dbm031_var3 VARCHAR(MAX), @dbm031_var4 VARCHAR(MAX)
    DECLARE result_cur CURSOR LOCAL FOR SELECT name, CONVERT(varchar(MAX), password_hash, 1), is_disabled, is_policy_checked FROM sys.sql_logins WHERE name='sa';

    PRINT('{"DBM-031":{')
    PRINT('"QUERY": "SELECT name, password_hash, is_disabled, is_policy_checked FROM sys.sql_logins WHERE name=''sa'';",')
    PRINT('"RESULT": [')

    OPEN result_cur
    FETCH NEXT FROM result_cur INTO @dbm031_var1, @dbm031_var2, @dbm031_var3, @dbm031_var4
        WHILE @@FETCH_STATUS = 0
        BEGIN
            PRINT(CONCAT('{"name":"', @dbm031_var1, '", "password_hash":"', @dbm031_var2, '", "is_disabled":"', @dbm031_var3, '", "is_policy_checked":"', @dbm031_var4 ,'"}, '))
            FETCH NEXT FROM result_cur INTO @dbm031_var1, @dbm031_var2, @dbm031_var3, @dbm031_var4
        END;
    CLOSE result_cur
    DEALLOCATE result_cur;
    PRINT(']}},')
END

PRINT(']')

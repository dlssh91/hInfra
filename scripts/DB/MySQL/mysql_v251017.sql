-- =============================================================================================================
-- Self-Managed DB(설치형)가 아닌, CSP-Managed DB(CSP 관리형; AWS Aurora MySQL, AWS RDS MySQL, Azure MySQL)를 사용하는 경우
-- 스크립트를 수행하는 계정이 프로시저 생성/삭제 권한을 보유한 DB명을 입력 
-- * 입력 예시
--  - (Self-Managed DB) USE mysql;
--  - (CSP-Managed DB) USE <DB name>; 
USE mysql;
-- =============================================================================================================

SET CHARSET utf8;
SET @version_major = (SELECT CAST(VERSION() AS UNSIGNED));
SET @version_minor = (SELECT CAST(SUBSTRING(VERSION(), 3, 1) AS UNSIGNED));
SET @sql_mode='NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION,PIPES_AS_CONCAT';

DELIMITER //
DROP PROCEDURE IF EXISTS detect_and_set_environment //
CREATE PROCEDURE detect_and_set_environment()
BEGIN
    -- DB 환경 판단 (0: Self-Managed DB, 1: AWS Aurora MySQL, 2: AWS RDS MySQL, 3: Azure MySQL flexible server)
    IF (SELECT COUNT(1) FROM performance_schema.global_variables WHERE variable_name = 'aurora_version' > 0) THEN
        SET @db_environment_state = 1; -- Aurora
    ELSEIF (SELECT COUNT(1) FROM mysql.user WHERE user = 'rdsadmin' AND host = 'localhost' > 0) THEN
        SET @db_environment_state = 2; -- RDS
    ELSEIF (SELECT COUNT(1) FROM mysql.user WHERE user = 'azure_superuser' AND host = '127.0.0.1' > 0) THEN
        SET @db_environment_state = 3; -- Azure
    ELSE
        SET @db_environment_state = 0; -- Self-Managed DB
    END IF;
END //
DELIMITER ;




-- CALL detect_and_set_environment();
-- DROP PROCEDURE detect_and_set_environment;

-- -- DB 환경 출력
-- SELECT
--     CASE @db_environment_state
--         WHEN 0 THEN '[INFO] 탐지된 환경: Self-Managed DB (State=0)'
--         WHEN 1 THEN '[INFO] 탐지된 환경: AWS Aurora MySQL (State=1)'
--         WHEN 2 THEN '[INFO] 탐지된 환경: AWS RDS MySQL (State=2)'
--         WHEN 3 THEN '[INFO] 탐지된 환경: Azure MySQL Flexible Server (State=3)'
--     END AS '실행 환경';



SELECT '[';

DROP PROCEDURE IF EXISTS fsi_mysql_001_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_001_3a8241()
BEGIN
    DECLARE t_host, t_user, t_plugin, t_passwordhash, t_password_expired TEXT;
    DECLARE done INT DEFAULT FALSE;

    DECLARE result_cur1 CURSOR FOR SELECT `Host`, `User`, `password`, `plugin`, `password_expired` FROM mysql.user;
    DECLARE result_cur2 CURSOR FOR SELECT `Host`, `User`, `authentication_string`, `plugin`, `account_locked` FROM mysql.user;
    DECLARE result_cur_aws CURSOR FOR SELECT `Host`, `User`, `authentication_string`, `plugin`, `account_locked` FROM mysql.user WHERE `User` NOT IN ('rdsadmin');
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;


    IF @db_environment_state in (0,1,2,3) THEN
        SELECT '{"DBM-001":{';
        
        IF @version_major > 5 OR (@version_major = 5 AND @version_minor >= 7) THEN
            SELECT '"QUERY": "SELECT Host, User, password, plugin, account_locked FROM mysql.user", ';
            SELECT '"RESULT": [';
            OPEN result_cur2;
            cur_loop: LOOP
                FETCH result_cur2 INTO t_host, t_user, t_passwordhash, t_plugin, t_password_expired;
                    IF done THEN
                        LEAVE cur_loop;
                    ELSE
                        SELECT CONCAT('{"HOST": "', COALESCE(t_host, ''), '","USER": "', COALESCE(t_user, ''),'","AUTHENTICATION_STRING": "', COALESCE(REPLACE(t_passwordhash,'\"',''), ''), '","PLUGIN": "', COALESCE(t_plugin, ''), '","ACCOUNT_LOCKED": "', COALESCE(t_password_expired, ''),'"},');
                    END IF;
            END LOOP;
            CLOSE result_cur2;
        ELSE
            SELECT '"QUERY": "SELECT Host, User, password, plugin, password_expired FROM mysql.user", ';
            SELECT '"RESULT": [';
            OPEN result_cur1;
            cur_loop: LOOP
            FETCH result_cur1 INTO t_host, t_user, t_passwordhash, t_plugin, t_password_expired;
                IF done THEN
                    LEAVE cur_loop;
                ELSE
                    SELECT CONCAT('{"HOST": "', COALESCE(t_host,''), '","USER": "', COALESCE(t_user,''),'","PASSWORD": "', COALESCE(t_passwordhash,''), '","PLUGIN": "', COALESCE(t_plugin,''), '","PASSWORD_EXPIRED": "', COALESCE(t_password_expired,''),'"},');
                END IF;
            END LOOP;
            CLOSE result_cur1;
        END IF;
        SELECT ']}},';
    END IF;
END//
DELIMITER ;

CALL fsi_mysql_001_3a8241();
DROP PROCEDURE fsi_mysql_001_3a8241;


-- DBM-003
DROP PROCEDURE IF EXISTS fsi_mysql_003_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_003_3a8241()
    BEGIN
        DECLARE t_host, t_user, t_plugin, t_password_expired TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur1 CURSOR FOR SELECT `Host`, `User`, `plugin`, `password_expired` FROM mysql.user;
        DECLARE result_cur2 CURSOR FOR SELECT `Host`, `User`, `plugin`, `account_locked` FROM mysql.user;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN
            
            SELECT '{"DBM-003":{';
            
            IF @version_major > 5 OR (@version_major = 5 AND @version_minor >= 7) THEN
                SELECT '"QUERY": "SELECT Host, User, password, account_locked FROM mysql.user", ';
                SELECT '"RESULT": [';
                OPEN result_cur2;
                cur_loop: LOOP
                    FETCH result_cur2 INTO t_host, t_user, t_plugin, t_password_expired;
                        IF done THEN
                            LEAVE cur_loop;
                        ELSE
                            SELECT CONCAT('{"HOST": "', COALESCE(t_host,''), '","USER": "', COALESCE(t_user,''), '","PLUGIN": "', COALESCE(t_plugin,''), '","ACCOUNT_LOCKED": "', COALESCE(t_password_expired,''),'"},');
                        END IF;
                END LOOP;
                CLOSE result_cur2;
            ELSE
                SELECT '"QUERY": "SELECT Host, User, password, account_locked FROM mysql.user", ';
                SELECT '"RESULT": [';
                OPEN result_cur1;
                cur_loop: LOOP
                FETCH result_cur1 INTO t_host, t_user, t_plugin, t_password_expired;
                    IF done THEN
                        LEAVE cur_loop;
                    ELSE
                        SELECT CONCAT('{"HOST": "', COALESCE(t_host,''), '","USER": "', COALESCE(t_user,''), '","PLUGIN": "', COALESCE(t_plugin,''), '","PASSWORD_EXPIRED": "', COALESCE(t_password_expired,''),'"},');
                    END IF;
                END LOOP;
                CLOSE result_cur1;
            END IF;
            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_003_3a8241();
DROP PROCEDURE fsi_mysql_003_3a8241;

-- DBM-004
DROP PROCEDURE IF EXISTS fsi_mysql_004_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_004_3a8241()
    BEGIN
        DECLARE t_grantee, t_privilege_type TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN

            SELECT '{"DBM-004":{';
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;
            CLOSE result_cur;
            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_004_3a8241();
DROP PROCEDURE fsi_mysql_004_3a8241;





-- DBM-005
DROP PROCEDURE IF EXISTS fsi_mysql_005_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_005_3a8241()
    BEGIN
        DECLARE t_table_schema, t_table_name, t_column_name, t_v_result TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;

        DECLARE result_cur CURSOR FOR SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
            WHERE DATA_TYPE IN ('char', 'varchar', 'tinytext', 'text')
            AND ( COLUMN_NAME LIKE '%PASS%' OR COLUMN_NAME LIKE '%PWD%' OR COLUMN_NAME LIKE '%PSWD%')
            AND TABLE_SCHEMA NOT IN ('mysql');

        DECLARE result_cur2 CURSOR FOR SELECT T_SCHEMA, T_TABLE, T_COLUMN, T_RESULT FROM FSI_TMP_TABLE_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN
            
            DROP TEMPORARY TABLE IF EXISTS FSI_TMP_TABLE_3A8241;
            CREATE TEMPORARY TABLE FSI_TMP_TABLE_3A8241 (
                T_SCHEMA VARCHAR(64),
                T_TABLE VARCHAR(64),
                T_COLUMN VARCHAR(64),
                T_RESULT TEXT
            );

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_table_schema, t_table_name, t_column_name;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        -- SET @var_tmp_fsi_3a8241 = CONCAT("INSERT INTO FSI_TMP_TABLE_3A8241 VALUE ('", t_table_schema, "','", t_table_name, "','", t_column_name, "',", "(SELECT GROUP_CONCAT(", t_column_name, ") FROM ", t_table_schema, ".", t_table_name, " LIMIT 10)",")");

                        SET @var_tmp_fsi_3a8241 = CONCAT("INSERT INTO FSI_TMP_TABLE_3A8241 VALUE ('", t_table_schema, "','", t_table_name, "','", t_column_name, "',","(SELECT GROUP_CONCAT(DISTINCT ",t_column_name, ") FROM ", t_table_schema, ".", t_table_name, " ", "LIMIT 10)",")");


                        PREPARE stmt FROM @var_tmp_fsi_3a8241;
                        EXECUTE stmt;
                        DEALLOCATE PREPARE stmt;
                    END IF;
            END LOOP;

            SELECT '{"DBM-005":{';
            
            SELECT '"QUERY": "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE DATA_TYPE IN (''char'', ''varchar'', ''tinytext'', ''text'') AND (COLUMN_NAME LIKE ''%PASS%'' OR COLUMN_NAME LIKE ''%PWD%'' OR COLUMN_NAME LIKE ''%PSWD%'') AND TABLE_SCHEMA NOT IN (''mysql'')", ';
            SELECT '"RESULT": [';
            SET done = FALSE;

            OPEN result_cur2;
            cur_loop: LOOP
                FETCH result_cur2 INTO t_table_schema, t_table_name, t_column_name, t_v_result;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur2;
                    ELSE
                        SELECT CONCAT('{"TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''), '","RESULT": "', COALESCE(t_v_result,''), '"},');
                    END IF;
            END LOOP;
            SELECT ']}},';
            DROP TEMPORARY TABLE IF EXISTS FSI_TMP_TABLE_3A8241;
        END IF;
    END//

DELIMITER ;
CALL fsi_mysql_005_3a8241();
DROP PROCEDURE fsi_mysql_005_3a8241;


-- DBM-006
DROP PROCEDURE IF EXISTS fsi_mysql_006_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_006_3a8241()
    BEGIN
        DECLARE t_user, t_host, t_user_attributes, t_failed_login_attempts, t_password_lock_time_days TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT User, Host, JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts') as User_attributes FROM mysql.user;
        DECLARE result_cur_aurora CURSOR FOR SELECT User, Host, JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts') as failed_login_attempts, JSON_EXTRACT(User_attributes, '$.Password_locking.password_lock_time_days') as password_lock_time_days FROM mysql.user;

        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-006":{';
            
            SELECT '"QUERY": "SELECT User, Host, User_attributes FROM mysql.user", ';
            SELECT '"RESULT": [';

            IF @version_major >= 8 THEN
                OPEN result_cur;
                cur_loop: LOOP
                    FETCH result_cur INTO t_user, t_host, t_user_attributes;
                        IF done THEN
                            LEAVE cur_loop;
                            CLOSE result_cur;
                        ELSE
                            SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '","USER_ATTRIBUTES": "', COALESCE(t_user_attributes, ''), '"},');
                        END IF;
                END LOOP;
            ELSE
                SELECT '"User_attributes is supported for version v8.019 later"';
            END IF;

            SELECT ']}},';
        ELSEIF @db_environment_state in (1,2,3) THEN

            SELECT '{"DBM-006":{';
            
            SELECT '"QUERY": "SELECT User, Host, failed_login_attempts, password_lock_time_days FROM mysql.user", ';
            SELECT '"RESULT": [';

            IF @version_major >= 8 THEN
                OPEN result_cur_aurora;
                cur_loop: LOOP
                    FETCH result_cur_aurora INTO t_user, t_host, t_failed_login_attempts, t_password_lock_time_days;
                        IF done THEN
                            LEAVE cur_loop;
                            CLOSE result_cur_aurora;
                        ELSE
                            SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '","FAILED_LOGIN_ATTEMPTS": "', COALESCE(t_failed_login_attempts, ''), '","PASSWORD_LOCK_TIME_DAYS": "', COALESCE(t_password_lock_time_days, ''), '"},');
                        END IF;
                END LOOP;
            ELSE
                SELECT '"User_attributes is supported for version v8.019 later"';
            END IF;

            SELECT ']}},';

        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_006_3a8241();
DROP PROCEDURE fsi_mysql_006_3a8241;




-- DBM-007
DROP PROCEDURE IF EXISTS fsi_mysql_007_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_007_3a8241()
    BEGIN
        DECLARE t_variable_name, t_value, v_table_name TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1) THEN
            

            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "validate_password%";');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-007":{';
            
            SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `validate_password%`", ');
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count=0 THEN
                            SELECT '"validate_password.so plugin is not loaded!"';
                        END IF;
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
            SELECT ']}},';
        
        ELSEIF @db_environment_state in (2) THEN
            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT(
                'CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ',
                v_table_name,
                ' WHERE VARIABLE_NAME LIKE "validate_password%";'
            );
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-007":{';
            
            SELECT '"QUERY": "SHOW VARIABLES LIKE ''validate_password%''", ';
            SELECT '"RESULT": [';
            
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count = 0 THEN
                            SELECT '"No validate_password variables found (component may not be active)."';
                        END IF;
                        LEAVE cur_loop;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            CLOSE result_cur;

            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
            SELECT ']}},';
        ELSEIF @db_environment_state in (3) THEN
            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT(
                'CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ',
                v_table_name,
                ' WHERE VARIABLE_NAME LIKE "validate_password%";'
            );
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-007":{';
            
            SELECT '"QUERY": "SHOW VARIABLES LIKE ''validate_password%''", ';
            SELECT '"RESULT": [';
            
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count = 0 THEN
                            SELECT '"No validate_password variables found (component may not be active)."';
                        END IF;
                        LEAVE cur_loop;
                    END IF;
                    SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                    SET v_loop_count = v_loop_count + 1;
            END LOOP;
            CLOSE result_cur;

            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
            SELECT ']}},';
        END IF;
    END//

DELIMITER ;
CALL fsi_mysql_007_3a8241();
DROP PROCEDURE fsi_mysql_007_3a8241;






-- DBM-008_1 // 비밀번호 마지막 변경 시간
DROP PROCEDURE IF EXISTS fsi_mysql_008_1_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_008_1_3a8241()
    BEGIN
        DECLARE t_user, t_host, t_password_last_changed TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT Host, User, DATE_FORMAT(password_last_changed, '%Y-%m-%d') FROM mysql.user;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN
            

            SELECT '{"DBM-008_1":{';
            
            SELECT '"QUERY": "SELECT Host, User, password_last_changed FROM mysql.user", ';
            SELECT '"RESULT": [';

            IF @version_major > 5 OR (@version_major >= 5 AND @version_minor >= 7) THEN
                OPEN result_cur;
                cur_loop: LOOP
                    FETCH result_cur INTO t_user, t_host, t_password_last_changed;
                        IF done THEN
                            LEAVE cur_loop;
                            CLOSE result_cur;
                        ELSE
                            SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '","PASSWORD_LAST_CHANGED": "', COALESCE(t_password_last_changed, ''), '"},');
                        END IF;
                END LOOP;
            ELSE
                SELECT '"password_last_changed is supported for version v5.7 later"';
            END IF;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_008_1_3a8241();
DROP PROCEDURE fsi_mysql_008_1_3a8241;


-- DBM-008_2 // 비밀번호 변경 주기 설정
DROP PROCEDURE IF EXISTS fsi_mysql_008_2_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_008_2_3a8241()
    BEGIN
        DECLARE var_name VARCHAR(64);
        DECLARE var_value VARCHAR(1024);
        DECLARE done INT DEFAULT FALSE;

        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'default_password_lifetime';
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (1,2) THEN
            

            SELECT '{"DBM-008_2":{';
            
            SELECT '"QUERY": "SHOW GLOBAL VARIABLES LIKE \'default_password_lifetime\'", '; -- Azure는 0에서 변경 불
            SELECT '"RESULT": [';

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO var_name, var_value;

                IF done THEN
                    LEAVE cur_loop;
                END IF;

                SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(var_name, 'default_password_lifetime'), '", "VALUE": "', COALESCE(var_value, '0'), '"}');

            END LOOP;
            CLOSE result_cur;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_008_2_3a8241();
DROP PROCEDURE fsi_mysql_008_2_3a8241;


-- DBM-009
DROP PROCEDURE IF EXISTS fsi_mysql_009_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_009_3a8241()
    BEGIN
        DECLARE t_variable_name, t_value, v_table_name TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN

            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "%timeout%";');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-009":{';
            
            SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `%timeout%`", ');
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT ']}},';
            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
        END IF;
    END//

DELIMITER ;
CALL fsi_mysql_009_3a8241();
DROP PROCEDURE fsi_mysql_009_3a8241;


-- DBM-010 (X)

-- DBM-011
DROP PROCEDURE IF EXISTS fsi_mysql_011_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_011_3a8241()
    BEGIN
        DECLARE t_variable_name, t_value, v_table_name TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN
         
            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "%audit_log%";');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-011":{';
            
            SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `%audit_log%`", ');
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count=0 THEN
                            SELECT '"audit_log.so plugin is not loaded!"'; -- (audit_log.so is supported in enterprise edition only)"';
                        END IF;
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT ']}},';
            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
        ELSEIF @db_environment_state in (1,2,3) THEN
         
            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "%audit_log%";');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-011":{';
            
            SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `%audit_log%`", ');
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count=0 THEN
                            SELECT '"audit_log.so plugin is not loaded!"'; -- (audit_log.so is supported in enterprise edition only)"';
                        END IF;
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT '], ';
            SELECT '"NOTE": "For audit log upload settings, refer to the PISM-011 script results."';
            SELECT '}},';
            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
        END IF;
    END//

DELIMITER ;
CALL fsi_mysql_011_3a8241();
DROP PROCEDURE fsi_mysql_011_3a8241;

-- DBM-012 (X)


-- DBM-013
DROP PROCEDURE IF EXISTS fsi_mysql_013_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_013_3a8241()
    BEGIN
        DECLARE t_user, t_host TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT Host, User FROM mysql.user;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN
        
            SELECT '{"DBM-013":{';
            
            SELECT '"QUERY": "SELECT Host, User FROM mysql.user", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_host, t_user;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '"},');
                    END IF;
            END LOOP;
            SELECT ']}},';
        ELSEIF @db_environment_state in (1,2,3) THEN
        
            SELECT '{"DBM-013":{';
            
            SELECT '"QUERY": "SELECT Host, User FROM mysql.user", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_host, t_user;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '"},');
                    END IF;
            END LOOP;
            SELECT '], '
            SELECT '"NOTE": "For public access settings, refer to the PISM-013 script."';
            SELECT '}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_013_3a8241();
DROP PROCEDURE fsi_mysql_013_3a8241;

-- DBM-014 (X)
-- DBM-015 (X)

-- DBM-016
DROP PROCEDURE IF EXISTS fsi_mysql_016_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_016_3a8241()
    BEGIN
        DECLARE t_variable_name, t_value, v_table_name TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN
        
            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "%version%";');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-016":{';
            
            SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `%version%`", ');
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT ']}},';
            DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
        END IF;
    END//

DELIMITER ;
CALL fsi_mysql_016_3a8241();
DROP PROCEDURE fsi_mysql_016_3a8241;


-- DBM-017_1 // 전역 수준
DROP PROCEDURE IF EXISTS fsi_mysql_017_1_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_017_1_3a8241()
    BEGIN
        DECLARE t_grantee, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        
        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-017_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN ( mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost) AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';

        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-017_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN ( mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, "rds_superuser_role@%") AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN

            SELECT '{"DBM-017_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN ( mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, azure_superuser@localhost, azure_superuser@127.0.0.1) AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_017_1_3a8241();
DROP PROCEDURE fsi_mysql_017_1_3a8241;


-- DBM-017_2 // DB수준 권한(시스템 테이블 :: 'information_schema', 'performance_schema', 'sys', 'mysql', 'rdsadmin')
DROP PROCEDURE IF EXISTS fsi_mysql_017_2_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_017_2_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE (GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'")) AND TABLE_SCHEMA IN ('information_schema', 'performance_schema', 'sys', 'mysql');
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE (GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'")) AND TABLE_SCHEMA IN ('information_schema', 'performance_schema', 'sys', 'mysql', 'rdsadmin');
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,3) THEN            

            SELECT '{"DBM-017_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE (GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)) AND TABLE_SCHEMA IN (information_schema, performance_schema, sys, mysql)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';

        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-017_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE (GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%)) AND TABLE_SCHEMA IN (information_schema, performance_schema, sys, mysql, rdsadmin)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_017_2_3a8241();
DROP PROCEDURE fsi_mysql_017_2_3a8241;



-- DBM-017_3 // 테이블 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_017_3_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_017_3_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'") AND TABLE_SCHEMA IN ('information_schema', 'performance_schema', 'sys', 'mysql');
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE (GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'")) AND TABLE_SCHEMA IN ('information_schema', 'performance_schema', 'sys', 'mysql', 'rdsadmin');
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,3) THEN

            SELECT '{"DBM-017_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost) AND TABLE_SCHEMA IN (information_schema, performance_schema, sys, mysql)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-017_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%) AND TABLE_SCHEMA IN (information_schema, performance_schema, sys, mysql, rdsadmin)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_table_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_017_3_3a8241();
DROP PROCEDURE fsi_mysql_017_3_3a8241;


-- DBM-017_4 // 칼럼 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_017_4_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_017_4_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;    

        IF @db_environment_state in (0,3) THEN

            SELECT '{"DBM-017_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)", ';
            SELECT '"RESULT": [';

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN
            SELECT '{"DBM-017_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%)", ';
            SELECT '"RESULT": [';

            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_017_4_3a8241();
DROP PROCEDURE fsi_mysql_017_4_3a8241;


-- DBM-019
DROP PROCEDURE IF EXISTS fsi_mysql_019_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_019_3a8241()
    BEGIN
        DECLARE t_variable_name, t_value, v_table_name TEXT;
        DECLARE v_loop_count INT DEFAULT 0;

        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN

            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME IN ("password_history", "password_reuse_interval");');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-019":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count=0 THEN
                            SELECT '"password_history is supported for version v8.0 later", ';
                            SELECT '"password_reuse_interval is supported for version v8.0 later"';
                        END IF;
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1) THEN
            SELECT '{"DBM-019":{';
            SELECT '"NOTE": "Check AWS Secrets Manager, IAM, etc. (as AWS Aurora MySQL lacks a native password reuse prevention feature)."';
            SELECT '}},';
        
        ELSEIF @db_environment_state in (2) THEN

            IF @version_major=5 and @version_minor=6 THEN
                SET v_table_name = 'information_schema.global_variables';
            ELSE
                SET v_table_name = 'performance_schema.global_variables';
            END IF;

            SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME IN ("password_history", "password_reuse_interval");');
            PREPARE stmt FROM @var_tmp_fsi_3a8241;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SET @var_tmp_fsi_3a8241 = NULL;

            SELECT '{"DBM-019":{';
            
            SELECT '"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME IN (''password_history'', ''password_reuse_interval'')", ';
            SELECT '"RESULT": [';
            
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_variable_name, t_value;
                    IF done THEN
                        IF v_loop_count=0 THEN
                            SELECT '"password_history is supported for version v8.0 later", ';
                            SELECT '"password_reuse_interval is supported for version v8.0 later"';
                        END IF;
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
                        SET v_loop_count = v_loop_count + 1;
                    END IF;
            END LOOP;
            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN
            SELECT '{"DBM-019":{';
            SELECT '"NOTE": "Check AWS Secrets Manager, IAM, etc. (as Azure Database for MySQL Flexible Server lacks a native password reuse prevention feature)."';
            SELECT '}},';
        END IF;
        DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
    END//

DELIMITER ;
CALL fsi_mysql_019_3a8241();
DROP PROCEDURE fsi_mysql_019_3a8241;

-- DBM-020
DROP PROCEDURE IF EXISTS fsi_mysql_020_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_020_3a8241()
    BEGIN
        DECLARE t_user, t_host, t_plugin TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT Host, User, plugin FROM mysql.user;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0,1,2,3) THEN
            SELECT '{"DBM-020":{';
            
            SELECT '"QUERY": "SELECT Host, User, plugin FROM mysql.user", ';
            SELECT '"RESULT": [';

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_host, t_user, t_plugin;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"USER": "', COALESCE(t_user,''), '","HOST": "', COALESCE(t_host,''), '","PLUGIN": "', COALESCE(t_plugin, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_020_3a8241();
DROP PROCEDURE fsi_mysql_020_3a8241;


-- DBM-021 (X)

-- DBM-022 (Self-Managed DB: 서버 스크립트 참고, CSP Managed DB: 클라우드 관리체계 스크립트(PISM-046) 결과 참고) 

-- DBM-024_1 // 전역 권한
DROP PROCEDURE IF EXISTS fsi_mysql_024_1_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_024_1_3a8241()
    BEGIN
        DECLARE t_grantee, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES' AND GRANTEE NOT LIKE "%'root'@'%";
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES' AND GRANTEE NOT LIKE "'root'@'%" AND GRANTEE NOT IN ("'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES' AND GRANTEE NOT LIKE "'root'@'%" AND GRANTEE NOT IN ("'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN
            
            SELECT '{"DBM-024_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE=`YES` AND GRANTEE NOT LIKE `%root@%`", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN
            
            SELECT '{"DBM-024_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE=`YES` AND GRANTEE NOT LIKE `%root@%`" AND GRANTEE NOT IN (rdsadmin@localhost, rds_superuser_role@%), ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN
            
            SELECT '{"DBM-024_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE=`YES` AND GRANTEE NOT LIKE `%root@%`" AND GRANTEE NOT IN (azure_superuser@localhost, azure_superuser@127.0.0.1), ';
            SELECT '"RESULT": [';
            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_024_1_3a8241();
DROP PROCEDURE fsi_mysql_024_1_3a8241;



-- DBM-024_2 // DB수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_024_2_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_024_2_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE IS_GRANTABLE = 'YES';
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        IF @db_environment_state in (0,1,2,3) THEN

            SELECT '{"DBM-024_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE IS_GRANTABLE=`YES`", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_024_2_3a8241();
DROP PROCEDURE fsi_mysql_024_2_3a8241;



-- DBM-024_3 // 테이블 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_024_3_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_024_3_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE IS_GRANTABLE = 'YES';
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        IF @db_environment_state in (0,1,2,3) THEN

            SELECT '{"DBM-024_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE IS_GRANTABLE=`YES`", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_024_3_3a8241();
DROP PROCEDURE fsi_mysql_024_3_3a8241;


-- DBM-024_4 // 칼럼 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_024_4_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_024_4_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE IS_GRANTABLE = 'YES';
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        IF @db_environment_state in (0,1,2,3) THEN

            SELECT '{"DBM-024_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE IS_GRANTABLE=`YES`", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type, t_is_gratable;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '","IS_GRANTABLE": "', COALESCE(t_is_gratable, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_024_4_3a8241();
DROP PROCEDURE fsi_mysql_024_4_3a8241;





-- -- DBM-025
-- DROP PROCEDURE IF EXISTS fsi_mysql_025_3a8241;
-- DELIMITER //
-- CREATE PROCEDURE fsi_mysql_025_3a8241()
--     BEGIN
--         DECLARE t_variable_name, t_value, v_table_name TEXT;
--         DECLARE v_loop_count INT DEFAULT 0;

--         DECLARE done INT DEFAULT FALSE;
--         DECLARE result_cur CURSOR FOR SELECT VARIABLE_NAME, VARIABLE_VALUE FROM FSI_TMP_VIEW_3A8241;
--         DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
--         IF @db_environment_state in (0,1,2,3) THEN

--             IF @version_major=5 and @version_minor=6 THEN
--                 SET v_table_name = 'information_schema.global_variables';
--             ELSE
--                 SET v_table_name = 'performance_schema.global_variables';
--             END IF;

--             SET @var_tmp_fsi_3a8241 = CONCAT('CREATE OR REPLACE VIEW FSI_TMP_VIEW_3A8241 as SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name ,' WHERE VARIABLE_NAME LIKE "%version%";');
--             PREPARE stmt FROM @var_tmp_fsi_3a8241;
--             EXECUTE stmt;
--             DEALLOCATE PREPARE stmt;
--             SET @var_tmp_fsi_3a8241 = NULL;

--             SELECT '{"DBM-025":{';
            
--             SELECT CONCAT('"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM ', v_table_name, ' WHERE VARIABLE_NAME LIKE `%version%`", ');
--             SELECT '"RESULT": [';
--             OPEN result_cur;
--             cur_loop: LOOP
--                 FETCH result_cur INTO t_variable_name, t_value;
--                     IF done THEN
--                         LEAVE cur_loop;
--                         CLOSE result_cur;
--                     ELSE
--                         SELECT CONCAT('{"VARIABLE_NAME": "', COALESCE(t_variable_name,''), '","VARIABLE_VALUE": "', COALESCE(t_value,''), '"},');
--                         SET v_loop_count = v_loop_count + 1;
--                     END IF;
--             END LOOP;
--             SELECT ']}},';
--             DROP VIEW IF EXISTS FSI_TMP_VIEW_3A8241;
--         END IF;
--     END//

-- DELIMITER ;
-- CALL fsi_mysql_025_3a8241();
-- DROP PROCEDURE fsi_mysql_025_3a8241;


-- DBM-026 // (Self-Managed DB: 서버 스크립트 참고, CSP Managed DB: N/A)

-- DBM-028_1 // 전역 권한
DROP PROCEDURE IF EXISTS fsi_mysql_028_1_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_028_1_3a8241()
    BEGIN
        DECLARE t_grantee, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'") AND PRIVILEGE_TYPE NOT IN ("USAGE");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-028_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost) AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-028_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%) AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN

            SELECT '{"DBM-028_1":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, azure_superuser@localhost, azure_superuser@127.0.0.1) AND PRIVILEGE_TYPE NOT IN (`USAGE`)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''),'"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_028_1_3a8241();
DROP PROCEDURE fsi_mysql_028_1_3a8241;



-- DBM-028_2 // DB수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_028_2_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_028_2_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-028_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-028_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN

            SELECT '{"DBM-028_2":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, azure_superuser@localhost, azure_superuser@127.0.0.1)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_table_schema, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_028_2_3a8241();
DROP PROCEDURE fsi_mysql_028_2_3a8241;



-- DBM-028_3 // 테이블 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_028_3_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_028_3_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_privilege_type, t_is_gratable TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN
            
            SELECT '{"DBM-028_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)", ';
            SELECT '"RESULT": [';
            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (1,2) THEN
            
            SELECT '{"DBM-028_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, rdsadmin@localhost, rds_superuser_role@%)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_table_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN
            
            SELECT '{"DBM-028_3":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost, azure_superuser@localhost, azure_superuser@127.0.0.1)", ';
            SELECT '"RESULT": [';
            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_table_schema, t_table_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_028_3_3a8241();
DROP PROCEDURE fsi_mysql_028_3_3a8241;


-- DBM-028_4 // 칼럼 수준 권한
DROP PROCEDURE IF EXISTS fsi_mysql_028_4_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_028_4_3a8241()
    BEGIN
        DECLARE t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'");
        DECLARE result_cur_aws CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'rdsadmin'@'localhost'", "'rds_superuser_role'@'%'");
        DECLARE result_cur_azure CURSOR FOR SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE "%'root'@'%" AND GRANTEE NOT IN ("'mysql.infoschema'@'localhost'", "'mysql.session'@'localhost'", "'mysql.sys'@'localhost'", "'azure_superuser'@'localhost'", "'azure_superuser'@'127.0.0.1'");
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-028_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, mysql.sys@localhost)", ';
            SELECT '"RESULT": [';

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        ELSEIF @db_environment_state in (1,2) THEN

            SELECT '{"DBM-028_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, rdsadmin@localhost, rds_superuser_role@%)", ';
            SELECT '"RESULT": [';

            OPEN result_cur_aws;
            cur_loop: LOOP
                FETCH result_cur_aws INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_aws;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        ELSEIF @db_environment_state in (3) THEN

            SELECT '{"DBM-028_4":{';
            
            SELECT '"QUERY": "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES WHERE GRANTEE NOT LIKE %root@% AND GRANTEE NOT IN (mysql.infoschema@localhost, mysql.session@localhost, azure_superuser@localhost, azure_superuser@127.0.0.1)", ';
            SELECT '"RESULT": [';

            OPEN result_cur_azure;
            cur_loop: LOOP
                FETCH result_cur_azure INTO t_grantee, t_table_schema, t_table_name, t_column_name, t_privilege_type;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur_azure;
                    ELSE
                        SELECT CONCAT('{"GRANTEE": "', COALESCE(t_grantee,''), '","TABLE_SCHEMA": "', COALESCE(t_table_schema,''), '","TABLE_NAME": "', COALESCE(t_table_name,''), '","COLUMN_NAME": "', COALESCE(t_column_name,''),'","PRIVILEGE_TYPE": "', COALESCE(t_privilege_type,''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_028_4_3a8241();
DROP PROCEDURE fsi_mysql_028_4_3a8241;

-- DBM-029 (X): No 'Ignore all resource limit' flag in MySQL
-- DBM-030 (X): no 'audit' concept in MySQL GPL
-- DBM-031 (X)
-- DBM-032 (X)



-- DBM-033 :  new 2022, CSP Managed DB: N/A
DROP PROCEDURE IF EXISTS fsi_mysql_033_3a8241;
DELIMITER //
CREATE PROCEDURE fsi_mysql_033_3a8241()
    BEGIN
        DECLARE t_host, t_user, t_password, t_port TEXT;
        DECLARE done INT DEFAULT FALSE;
        DECLARE result_cur CURSOR FOR SELECT Host, User_name, User_password, Port FROM mysql.slave_master_info;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        IF @db_environment_state in (0) THEN

            SELECT '{"DBM-033":{';
            
            SELECT '"QUERY": "SELECT Host, User_name, User_password, Port FROM mysql.slave_master_info", ';
            --  SELECT Host, User_name, User_password, Port FROM mysql.slave_master_info;

            SELECT '"RESULT": [';

            OPEN result_cur;
            cur_loop: LOOP
                FETCH result_cur INTO t_host, t_user, t_password, t_port;
                    IF done THEN
                        LEAVE cur_loop;
                        CLOSE result_cur;
                    ELSE
                        SELECT CONCAT('{"HOST": "', COALESCE(t_host,''), '","USER": "', COALESCE(t_user,''), '","PASSWORD": "', COALESCE(t_password,''), '","PORT": "', COALESCE(t_port, ''), '"},');
                    END IF;
            END LOOP;

            SELECT ']}},';
        
        END IF;
    END//
DELIMITER ;

CALL fsi_mysql_033_3a8241();
DROP PROCEDURE fsi_mysql_033_3a8241;
SELECT ']';


from judge_tool.profile import (
    get_profile, CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB, DB_POSTGRESQL,
)


def test_db_mysql_registered():
    p = get_profile("db_mysql")
    assert p is DB_MYSQL
    assert p.sheet_name == "데이터베이스"
    assert p.parser == "db_json"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True


def test_db_variants_columns():
    v = DB_MYSQL.variants
    assert v["mysql_rds"].applicability_col == 17
    assert v["mysql_rds"].standard_col == 37
    assert v["mysql_rds"].method_col == 38
    assert v["mysql_aurora"].applicability_col == 18
    assert v["mysql_azure"].applicability_col == 19
    # DB는 eval_type 컬럼 없음
    assert v["mysql_rds"].eval_type_col is None


def test_db_variant_from_filename():
    assert DB_MYSQL.variant_from_filename("mysql_result_rds.txt") == "mysql_rds"
    assert DB_MYSQL.variant_from_filename("mysql_result_aurora.txt") == "mysql_aurora"
    assert DB_MYSQL.variant_from_filename("mysql_result_azure.txt") == "mysql_azure"
    assert DB_MYSQL.variant_from_filename("mysql_result.txt") is None  # 온프렘 미지원


def test_cloud_profile_defaults_unchanged():
    assert CLOUD.evidence_mode == "preclassified"
    assert CLOUD.status_available is True
    assert CLOUD.flag_vulnerable_for_review is False
    # cloud VariantSpec은 eval_type_col 보유, applicability_col 없음
    assert CLOUD.variants["AWS"].eval_type_col == 11
    assert CLOUD.variants["AWS"].applicability_col is None


def test_empty_means_good_set():
    assert "DBM-017" in DB_MYSQL.empty_means_good
    assert "DBM-028" in DB_MYSQL.empty_means_good
    assert "DBM-024" in DB_MYSQL.empty_means_good  # IS_GRANTABLE='YES' 필터
    assert "DBM-004" not in DB_MYSQL.empty_means_good


# ── 신규 DBMS 프로파일 회귀 테스트 ──────────────────────────────────────────

def test_new_profiles_registered():
    for key, profile_obj in [
        ("db_oracle", DB_ORACLE),
        ("db_mssql", DB_MSSQL),
        ("db_mariadb", DB_MARIADB),
        ("db_postgresql", DB_POSTGRESQL),
    ]:
        p = get_profile(key)
        assert p is profile_obj
        assert p.sheet_name == "데이터베이스"
        assert p.parser == "db_json"
        assert p.evidence_mode == "raw"
        assert p.status_available is False
        assert p.flag_vulnerable_for_review is True


def test_oracle_columns():
    v = DB_ORACLE.variants["oracle_rds"]
    assert v.applicability_col == 13
    assert v.standard_col == 29
    assert v.method_col == 30
    assert v.eval_type_col is None
    assert "DBM-005" in DB_ORACLE.empty_means_good
    assert "DBM-017" in DB_ORACLE.empty_means_good
    assert "DBM-024" in DB_ORACLE.empty_means_good
    assert "DBM-028" not in DB_ORACLE.empty_means_good


def test_mssql_columns():
    v = DB_MSSQL.variants["mssql_rds"]
    assert v.applicability_col == 15
    assert v.standard_col == 33
    assert v.method_col == 34
    assert "DBM-005" in DB_MSSQL.empty_means_good
    assert "DBM-015" in DB_MSSQL.empty_means_good
    assert "DBM-024" in DB_MSSQL.empty_means_good


def test_mariadb_columns():
    v = DB_MARIADB.variants["mariadb_rds"]
    assert v.applicability_col == 21
    assert v.standard_col == 45
    assert v.method_col == 46
    assert "DBM-005" in DB_MARIADB.empty_means_good
    assert "DBM-024" in DB_MARIADB.empty_means_good
    assert "DBM-017" not in DB_MARIADB.empty_means_good  # MariaDB는 목록조회형


def test_postgresql_columns():
    vs = DB_POSTGRESQL.variants
    assert vs["pg_rds"].applicability_col == 23
    assert vs["pg_rds"].standard_col == 49
    assert vs["pg_rds"].method_col == 50
    assert vs["pg_aurora"].applicability_col == 24
    assert vs["pg_aurora"].standard_col == 51
    assert vs["pg_azure"].applicability_col == 25
    assert vs["pg_azure"].standard_col == 53
    assert "DBM-005" in DB_POSTGRESQL.empty_means_good
    assert "DBM-015" in DB_POSTGRESQL.empty_means_good
    assert "DBM-017" in DB_POSTGRESQL.empty_means_good
    assert "DBM-024" in DB_POSTGRESQL.empty_means_good


def test_new_profiles_variant_from_filename():
    assert DB_ORACLE.variant_from_filename("oracle_result_rds.txt") == "oracle_rds"
    assert DB_MSSQL.variant_from_filename("mssql_result_rds.txt") == "mssql_rds"
    assert DB_MARIADB.variant_from_filename("mariadb_result_rds.txt") == "mariadb_rds"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_rds.txt") == "pg_rds"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_aurora.txt") == "pg_aurora"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_azure.txt") == "pg_azure"
    assert DB_POSTGRESQL.variant_from_filename("unknown.txt") is None

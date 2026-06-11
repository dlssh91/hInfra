from judge_tool.profile import (
    get_profile, CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB,
    DB_POSTGRESQL, DB_TIBERO,
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
    # 네이티브 지원 추가: 접미사 없는 파일명은 네이티브로 식별(과거 None → 변경).
    assert DB_MYSQL.variant_from_filename("mysql_result.txt") == "mysql_native"


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


# ── 네이티브(온프레미스) 변형 회귀 테스트 ────────────────────────────────────

def test_native_variant_columns():
    assert DB_ORACLE.variants["oracle_native"].applicability_col == 12
    assert DB_ORACLE.variants["oracle_native"].standard_col == 27
    assert DB_ORACLE.variants["oracle_native"].method_col == 28
    assert DB_MSSQL.variants["mssql_native"].applicability_col == 14
    assert DB_MSSQL.variants["mssql_native"].standard_col == 31
    assert DB_MSSQL.variants["mssql_native"].method_col == 32
    assert DB_MYSQL.variants["mysql_native"].applicability_col == 16
    assert DB_MYSQL.variants["mysql_native"].standard_col == 35
    assert DB_MARIADB.variants["mariadb_native"].applicability_col == 20
    assert DB_MARIADB.variants["mariadb_native"].standard_col == 43
    assert DB_POSTGRESQL.variants["pg_native"].applicability_col == 22
    assert DB_POSTGRESQL.variants["pg_native"].standard_col == 47


def test_native_vs_cloud_filename_no_collision():
    # longest-match: 접미사 없는 파일명은 네이티브, 클라우드 접미사는 클라우드.
    assert DB_ORACLE.variant_from_filename("oracle_result.txt") == "oracle_native"
    assert DB_ORACLE.variant_from_filename("oracle_result_rds.txt") == "oracle_rds"
    assert DB_MSSQL.variant_from_filename("mssql_result.txt") == "mssql_native"
    assert DB_MSSQL.variant_from_filename("mssql_result_rds.txt") == "mssql_rds"
    assert DB_MARIADB.variant_from_filename("mariadb_result.txt") == "mariadb_native"
    assert DB_MARIADB.variant_from_filename("mariadb_result_rds.txt") == "mariadb_rds"
    # PG는 네이티브 + 3종 클라우드가 모두 'postgresql_result' 부분집합.
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result.txt") == "pg_native"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_rds.txt") == "pg_rds"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_aurora.txt") == "pg_aurora"
    assert DB_POSTGRESQL.variant_from_filename("postgresql_result_azure.txt") == "pg_azure"


# ── Tibero 구조 스텁(배제) ───────────────────────────────────────────────────

def test_tibero_registered_but_excluded():
    p = get_profile("db_tibero")
    assert p is DB_TIBERO
    assert p.excluded is True
    v = p.variants["tibero"]
    assert v.applicability_col == 26
    assert v.standard_col == 55
    assert v.method_col == 56
    assert p.variant_from_filename("tibero_result.txt") == "tibero"


def test_other_profiles_not_excluded():
    for prof in (CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB, DB_POSTGRESQL):
        assert prof.excluded is False


# ── M1. variant_from_filename 모호성 가드 회귀 테스트 ───────────────────────

def test_ambiguous_rds_prefix_returns_none():
    """'rds_mysql_result.txt': rds 토큰이 파일명 앞에 있고 mysql_native가
    최장 매치이면 모호 가드가 발동해 None을 반환해야 한다."""
    assert DB_MYSQL.variant_from_filename("rds_mysql_result.txt") is None


def test_ambiguous_rds_dash_returns_none():
    """'mysql_result-rds.txt': 대시로 구분된 rds 토큰도 클라우드 힌트로 인식해
    네이티브 최장 매치를 덮어쓰고 None을 반환해야 한다."""
    assert DB_MYSQL.variant_from_filename("mysql_result-rds.txt") is None


def test_normal_native_filename_unchanged():
    """정상 네이티브 파일명(클라우드 토큰 없음)은 여전히 네이티브를 반환해야 한다."""
    assert DB_MYSQL.variant_from_filename("mysql_result.txt") == "mysql_native"
    assert DB_ORACLE.variant_from_filename("oracle_result.txt") == "oracle_native"


def test_normal_cloud_rds_filename_unchanged():
    """정상 클라우드 파일명(클라우드 접미사 있음)은 클라우드 변형을 그대로 반환해야 한다."""
    assert DB_MYSQL.variant_from_filename("mysql_result_rds.txt") == "mysql_rds"
    assert DB_MYSQL.variant_from_filename("mysql_result_rds_backup.txt") == "mysql_rds"


def test_guard_word_boundary_no_false_positive():
    """단어경계 검사: 'rds'가 다른 단어(passwords·standards·records)에 묻힌
    경우는 클라우드 토큰으로 오인하지 않고 네이티브를 반환해야 한다."""
    assert DB_MYSQL.variant_from_filename(
        "mysql_result_passwords.txt") == "mysql_native"
    assert DB_MYSQL.variant_from_filename(
        "mysql_result_standards.txt") == "mysql_native"
    assert DB_ORACLE.variant_from_filename(
        "oracle_result_records.txt") == "oracle_native"

from judge_tool.profile import get_profile, CLOUD, DB_MYSQL


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

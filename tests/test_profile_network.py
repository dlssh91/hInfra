"""네트워크 장비 프로파일 구조 테스트 (작업④).

평가기준 '네트워크 장비' 시트 컬럼 매핑(확인된 사실)과 프로파일 속성을 고정한다.
"""
import pytest

from judge_tool.profile import (
    get_profile, NETWORK,
    CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB, DB_POSTGRESQL,
    DB_TIBERO, SERVER,
)


def test_network_registered():
    p = get_profile("network")
    assert p is NETWORK
    assert p.sheet_name == "네트워크 장비"
    assert p.header_row == 4
    assert p.data_start_row == 5
    assert p.id_col == 2
    assert p.name_col == 7
    assert p.risk_col == 8
    assert p.parser == "network_xml"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True
    assert p.excluded is False
    assert p.empty_means_good == frozenset()


def test_network_variants_set():
    assert set(NETWORK.variants) == {"cisco", "generic"}


def test_network_cisco_spec():
    cisco = NETWORK.variants["cisco"]
    assert cisco.name == "cisco"
    assert cisco.applicability_col == 33
    assert cisco.standard_col == 18
    assert cisco.method_col == 19
    assert cisco.applies_when_standard is False
    assert cisco.eval_type_col is None
    assert cisco.filename_markers == ()


def test_network_generic_spec():
    generic = NETWORK.variants["generic"]
    assert generic.name == "generic"
    assert generic.applicability_col is None
    assert generic.applies_when_standard is True
    assert generic.standard_col == 18
    assert generic.method_col == 19
    assert generic.eval_type_col is None
    assert generic.filename_markers == ()


def test_network_filename_detection_always_none():
    """파일명 기반 식별은 항상 None — 내용 기반(detect_variant) 폴백 전제."""
    assert NETWORK.variant_from_filename("cisco_net.xml") is None
    assert NETWORK.variant_from_filename("router-2026.xml") is None
    assert NETWORK.variant_from_filename("NET-result.xml") is None


def test_network_normalize_id():
    assert NETWORK.normalize_id("NET-001") == "NET-001"
    assert NETWORK.normalize_id("NET-1") == "NET-001"
    assert NETWORK.normalize_id("net_045") == "NET-045"
    assert NETWORK.normalize_id("NET-009") == "NET-009"


# ── 회귀가드: CLOUD/DB5종/SERVER 전 변형 applies_when_standard is False ────────

@pytest.mark.parametrize("profile_obj,vname", [
    (CLOUD, "AWS"),
    (CLOUD, "Azure"),
    (DB_MYSQL, "mysql_native"),
    (DB_MYSQL, "mysql_rds"),
    (DB_MYSQL, "mysql_aurora"),
    (DB_MYSQL, "mysql_azure"),
    (DB_ORACLE, "oracle_native"),
    (DB_ORACLE, "oracle_rds"),
    (DB_MSSQL, "mssql_native"),
    (DB_MSSQL, "mssql_rds"),
    (DB_MARIADB, "mariadb_native"),
    (DB_MARIADB, "mariadb_rds"),
    (DB_POSTGRESQL, "pg_native"),
    (DB_POSTGRESQL, "pg_rds"),
    (DB_POSTGRESQL, "pg_aurora"),
    (DB_POSTGRESQL, "pg_azure"),
    (DB_TIBERO, "tibero"),
    (SERVER, "aix"),
    (SERVER, "hpux"),
    (SERVER, "linux"),
    (SERVER, "solaris"),
    (SERVER, "win"),
])
def test_other_profiles_applies_when_standard_false(profile_obj, vname):
    """NETWORK generic 외 모든 기존 변형은 applies_when_standard=False(기본값)."""
    vspec = profile_obj.variants[vname]
    assert vspec.applies_when_standard is False, (
        f"{profile_obj.key}.{vname} applies_when_standard이 True로 변경됨 — 회귀!"
    )

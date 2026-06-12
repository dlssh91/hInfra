"""ISS(정보보호시스템 장비) 프로파일 구조 테스트 (작업②).

profile.py의 ISS 상수와 get_profile("iss") 등록을 고정한다.
"""
import pytest

from judge_tool.profile import (
    ISS,
    get_profile,
    CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB, DB_POSTGRESQL,
    DB_TIBERO, SERVER, NETWORK,
)


def test_iss_registered():
    p = get_profile("iss")
    assert p is ISS
    assert p.sheet_name == "정보보호시스템 장비"
    assert p.header_row == 4
    assert p.data_start_row == 5
    assert p.id_col == 2
    assert p.name_col == 7
    assert p.risk_col == 8
    assert p.parser == "fw_policy_xlsx"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True
    assert p.excluded is False
    assert p.empty_means_good == frozenset()


def test_iss_variants_set():
    assert set(ISS.variants) == {"fw"}


def test_iss_fw_spec():
    fw = ISS.variants["fw"]
    assert fw.name == "fw"
    assert fw.standard_col == 18
    assert fw.method_col == 19
    assert fw.applicability_col == 12
    assert fw.eval_type_col is None
    assert fw.applies_when_standard is False
    assert fw.filename_markers == ()


def test_iss_filename_detection_always_none():
    """파일명 기반 식별은 항상 None — detect_variant 폴백 전제."""
    assert ISS.variant_from_filename("fw_policy.xlsx") is None
    assert ISS.variant_from_filename("secui_policy.xlsx") is None
    assert ISS.variant_from_filename("paloalto_2026.xlsx") is None


def test_iss_normalize_id():
    assert ISS.normalize_id("ISS-030") == "ISS-030"
    assert ISS.normalize_id("ISS-30") == "ISS-030"
    assert ISS.normalize_id("iss_030") == "ISS-030"
    assert ISS.normalize_id("ISS-041") == "ISS-041"
    assert ISS.normalize_id("iss_041_1") == "ISS-041"  # 하위인덱스 제거


def test_iss_key():
    assert ISS.key == "iss"


# ── 회귀 가드: ISS.fw는 applies_when_standard=False (기본값) ────────────────────

def test_iss_fw_applies_when_standard_false():
    assert ISS.variants["fw"].applies_when_standard is False


# ── 회귀 가드: 기존 프로파일들의 applies_when_standard=False 유지 ───────────────

@pytest.mark.parametrize("profile_obj,vname", [
    (CLOUD, "AWS"),
    (CLOUD, "Azure"),
    (DB_MYSQL, "mysql_native"),
    (DB_MYSQL, "mysql_rds"),
    (DB_ORACLE, "oracle_native"),
    (DB_ORACLE, "oracle_rds"),
    (DB_MSSQL, "mssql_native"),
    (DB_MSSQL, "mssql_rds"),
    (DB_MARIADB, "mariadb_native"),
    (DB_MARIADB, "mariadb_rds"),
    (DB_POSTGRESQL, "pg_native"),
    (DB_POSTGRESQL, "pg_rds"),
    (DB_TIBERO, "tibero"),
    (SERVER, "linux"),
    (SERVER, "win"),
    (ISS, "fw"),
])
def test_applies_when_standard_false_regression(profile_obj, vname):
    vspec = profile_obj.variants[vname]
    assert vspec.applies_when_standard is False, (
        f"{profile_obj.key}.{vname} applies_when_standard이 True로 변경됨 — 회귀!"
    )

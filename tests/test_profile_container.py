"""컨테이너 가상화 시스템 프로파일 구조 테스트 (작업⑤).

profile.py의 CONTAINER 상수와 get_profile("container") 등록을 고정한다.
"""
import pytest

from judge_tool.profile import (
    CONTAINER,
    get_profile,
    CLOUD, DB_MYSQL, DB_ORACLE, DB_MSSQL, DB_MARIADB, DB_POSTGRESQL,
    DB_TIBERO, SERVER, NETWORK, ISS,
)


def test_container_registered():
    p = get_profile("container")
    assert p is CONTAINER
    assert p.sheet_name == "컨테이너 가상화 시스템"
    assert p.header_row == 4
    assert p.data_start_row == 5
    assert p.id_col == 2
    assert p.name_col == 7
    assert p.risk_col == 8
    assert p.parser == "container_xml"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True
    assert p.excluded is False
    assert p.empty_means_good == frozenset()


def test_container_variants_set():
    expected = {
        "k8s_master", "k8s_worker",
        "eks_master", "eks_worker",
        "aks_master", "aks_worker",
        "ocp_master", "ocp_worker",
        "docker_linux",
    }
    assert set(CONTAINER.variants) == expected


# ─ 변형별 컬럼 계약 ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("vname,app_col,std_col,mth_col,marker", [
    ("k8s_master",  12, 22, 21, "k8s_master"),
    ("k8s_worker",  13, 24, 23, "k8s_worker"),
    ("eks_master",  14, 26, 25, "eks_master"),
    ("eks_worker",  15, 28, 27, "eks_worker"),
    ("aks_master",  16, 30, 29, "aks_master"),
    ("aks_worker",  17, 32, 31, "aks_worker"),
    ("ocp_master",  18, 34, 33, "ocp_master"),
    ("ocp_worker",  19, 36, 35, "ocp_worker"),
    ("docker_linux",20, 38, 37, "docker_linux"),
])
def test_variant_spec(vname, app_col, std_col, mth_col, marker):
    vspec = CONTAINER.variants[vname]
    assert vspec.name == vname
    assert vspec.applicability_col == app_col
    assert vspec.standard_col == std_col
    assert vspec.method_col == mth_col
    assert vspec.eval_type_col is None
    assert vspec.applies_when_standard is False
    assert marker in vspec.filename_markers


def test_container_filename_detection():
    """파일명 마커 기반 변형 식별."""
    assert CONTAINER.variant_from_filename("k8s_master_result.xml") == "k8s_master"
    assert CONTAINER.variant_from_filename("prcc_k8s_worker_2026.xml") == "k8s_worker"
    assert CONTAINER.variant_from_filename("eks_master_scan.xml") == "eks_master"
    assert CONTAINER.variant_from_filename("docker_linux_check.xml") == "docker_linux"


def test_container_filename_no_marker():
    """마커 없는 파일명 → None."""
    assert CONTAINER.variant_from_filename("report.xml") is None
    assert CONTAINER.variant_from_filename("container_result.xml") is None


def test_container_filename_longest_match():
    """k8s_master vs k8s_worker — 최장 매치가 이긴다."""
    # k8s_master 파일명 → k8s_master 선택 (k8s_worker 매치 안 됨)
    assert CONTAINER.variant_from_filename("k8s_master_report.xml") == "k8s_master"
    assert CONTAINER.variant_from_filename("k8s_worker_report.xml") == "k8s_worker"


def test_container_normalize_id():
    assert CONTAINER.normalize_id("PRCC-001") == "PRCC-001"
    assert CONTAINER.normalize_id("PRCC-1") == "PRCC-001"
    assert CONTAINER.normalize_id("prcc_001") == "PRCC-001"
    assert CONTAINER.normalize_id("PRCC-050") == "PRCC-050"
    assert CONTAINER.normalize_id("prcc_050_1") == "PRCC-050"  # 하위 인덱스 제거


def test_container_key():
    assert CONTAINER.key == "container"


# ── 회귀 가드: 기존 프로파일 applies_when_standard=False 유지 ───────────────────

@pytest.mark.parametrize("profile_obj,vname", [
    (CLOUD,         "AWS"),
    (CLOUD,         "Azure"),
    (DB_MYSQL,      "mysql_native"),
    (DB_ORACLE,     "oracle_native"),
    (DB_MSSQL,      "mssql_native"),
    (DB_MARIADB,    "mariadb_native"),
    (DB_POSTGRESQL, "pg_native"),
    (DB_TIBERO,     "tibero"),
    (SERVER,        "linux"),
    (ISS,           "fw"),
    (CONTAINER,     "k8s_master"),
    (CONTAINER,     "docker_linux"),
])
def test_applies_when_standard_false_regression(profile_obj, vname):
    vspec = profile_obj.variants[vname]
    assert vspec.applies_when_standard is False, (
        f"{profile_obj.key}.{vname} applies_when_standard이 True로 변경됨 — 회귀!"
    )


def test_network_generic_still_applies_when_standard_true():
    """NETWORK generic 유일하게 True — 다른 변형들과 구분."""
    assert NETWORK.variants["generic"].applies_when_standard is True

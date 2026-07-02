import unicodedata

import pytest

from judge_tool.profile import (
    CLOUD, _PLATFORM_ALIASES, _PROFILES, _alias_hit, get_profile,
    guess_profile, list_profile_keys,
)


def test_normalize_id_strips_subindex():
    assert CLOUD.normalize_id("pism_001") == "PISM-001"
    assert CLOUD.normalize_id("pism_037_1") == "PISM-037"
    assert CLOUD.normalize_id("pism_046_3") == "PISM-046"


def test_variant_from_filename():
    assert CLOUD.variant_from_filename("aws_report_20251223_hinno.xml") == "AWS"
    assert CLOUD.variant_from_filename("azure_report_20251121.xml") == "Azure"
    assert CLOUD.variant_from_filename("random.xml") is None


def test_profile_columns():
    assert CLOUD.sheet_name == "클라우드 관리체계"
    aws = CLOUD.variants["AWS"]
    assert (aws.eval_type_col, aws.standard_col, aws.method_col) == (11, 17, 13)


def test_get_profile():
    assert get_profile("cloud") is CLOUD


def test_get_profile_unknown_raises():
    with pytest.raises(KeyError):
        get_profile("nope")


def test_azure_columns():
    az = CLOUD.variants["Azure"]
    assert (az.eval_type_col, az.standard_col, az.method_col) == (12, 18, 14)
    assert az.filename_markers == ("azure_report",)


# --------------------------------------------------------------------------
# --profile 자동추정 (guess_profile) — 마커→프로파일 매핑 / 확장자 폴백 / 모호성
# --------------------------------------------------------------------------

def test_guess_profile_by_cloud_marker():
    assert guess_profile("aws_report_20251223_hinno.xml") == ("cloud", ("cloud",))
    assert guess_profile("azure_report_20251121.xml") == ("cloud", ("cloud",))


def test_guess_profile_by_db_engine_marker():
    """DB는 같은 엔진의 native/rds/aurora/azure 마커가 모두 같은 프로파일로
    수렴해야 한다(마커가 여러 개 매칭돼도 profile_key 기준으로는 유일)."""
    assert guess_profile("mysql_result.json") == ("db_mysql", ("db_mysql",))
    assert guess_profile("mysql_result_rds.json") == ("db_mysql", ("db_mysql",))
    assert guess_profile("oracle_result_rds.txt") == ("db_oracle", ("db_oracle",))
    assert guess_profile("mssql_result.json") == ("db_mssql", ("db_mssql",))
    assert guess_profile("mariadb_result.json") == ("db_mariadb", ("db_mariadb",))
    assert guess_profile("postgresql_result_aurora.json") == (
        "db_postgresql", ("db_postgresql",))


def test_guess_profile_by_container_marker():
    assert guess_profile("k8s_master_20260101.xml") == (
        "container", ("container",))
    assert guess_profile("docker_linux_web01.xml") == (
        "container", ("container",))


def test_guess_profile_excludes_tibero_excluded_profile():
    """db_tibero는 excluded=True → 마커 역인덱스에 등록되지 않아 추정되지 않는다."""
    guessed, candidates = guess_profile("tibero_result.json")
    assert guessed is None
    assert "db_tibero" not in candidates


def test_guess_profile_ext_unique_xlsx_maps_to_iss():
    """마커 미매칭 + .xlsx 확장자는 iss(방화벽 정책)만의 유일한 폴백이다."""
    assert guess_profile("firewall_policy_20260101.xlsx") == ("iss", ("iss",))


def test_guess_profile_ext_json_ambiguous_without_marker():
    guessed, candidates = guess_profile("unknown_result.json")
    assert guessed is None
    assert set(candidates) == {
        "db_mysql", "db_oracle", "db_mssql", "db_mariadb", "db_postgresql"}


def test_guess_profile_ext_xml_ambiguous_without_marker():
    guessed, candidates = guess_profile("host01-s-20260101.xml")
    assert guessed is None
    assert "cloud" in candidates and "server" in candidates


def test_guess_profile_unrecognized_extension_cannot_guess():
    guessed, candidates = guess_profile("notes.txt")
    assert guessed is None
    assert candidates == ()


def test_list_profile_keys_excludes_tibero():
    keys = list_profile_keys()
    assert "db_tibero" not in keys
    assert "cloud" in keys and "iss" in keys


# --------------------------------------------------------------------------
# Stage B: 플랫폼 별칭 기반 프로파일 자동인지
# (설계서 docs/superpowers/specs/2026-07-03-filename-recognition-design.md §6)
# --------------------------------------------------------------------------

def test_guess_profile_alias_success_english_and_korean():
    assert guess_profile("MySQL점검.txt") == ("db_mysql", ("db_mysql",))
    # 별칭 승리: 확장자만 보면 .xlsx→iss로 오추정되나 오라클 별칭이 우선한다.
    assert guess_profile("오라클_result.xlsx") == ("db_oracle", ("db_oracle",))
    assert guess_profile("linux_web1.xml") == ("server", ("server",))
    assert guess_profile("방화벽정책.xlsx") == ("iss", ("iss",))
    assert guess_profile("cisco_backbone.xml") == ("network", ("network",))
    assert guess_profile("docker_host01.xml") == ("container", ("container",))
    assert guess_profile("vmware_esxi01.xml") == ("osvirt", ("osvirt",))
    assert guess_profile("tomcat_was01.xml") == ("webwas", ("webwas",))
    assert guess_profile("AWS점검결과.xml") == ("cloud", ("cloud",))


def test_guess_profile_alias_handles_nfd_korean_filename():
    """macOS 드래그앤드롭 등으로 들어온 NFD(자모 분해) 한글 파일명도
    NFC 정규화를 거쳐 별칭 매칭이 성립해야 한다."""
    nfd_name = unicodedata.normalize("NFD", "오라클점검.txt")
    assert guess_profile(nfd_name) == ("db_oracle", ("db_oracle",))


def test_guess_profile_alias_ambiguous_fail_safe():
    """별칭이 2개 이상 프로파일에 동시 매칭되면 거짓 라우팅 대신 모호로
    처리해 (None, 후보) 를 반환해야 한다."""
    guessed, candidates = guess_profile("mysql_on_linux.json")
    assert guessed is None
    assert set(candidates) == {"db_mysql", "server"}

    guessed, candidates = guess_profile("리눅스_아파치.xml")
    assert guessed is None
    assert set(candidates) == {"server", "webwas"}

    guessed, candidates = guess_profile("oracle_linux.xml")
    assert guessed is None
    assert set(candidates) == {"db_oracle", "server"}


def test_guess_profile_alias_false_positive_guard():
    """경계검사·금지토큰 목록 덕에 아래 파일명들은 별칭이 단일/모호 확정을
    만들어내지 않아야 한다(winter/darwin 경계차단, ids/ips/checkpoint/weeks/
    wafer 금지·경계차단) — 별칭이 전혀 매칭되지 않으므로 Stage C 확장자
    폴백까지 그대로 내려가 일반 확장자 후보군만 나와야 한다(별칭발 오탐이
    후보를 좁히거나 단일 확정을 만들지 않음을 확인)."""
    assert guess_profile("winter_report.txt") == (None, ())
    assert guess_profile("darwin_notes.txt") == (None, ())

    xml_ext_candidates = {
        "cloud", "container", "server", "network", "iss_device", "osvirt", "webwas"}
    json_ext_candidates = {
        "db_mysql", "db_oracle", "db_mssql", "db_mariadb", "db_postgresql"}

    # ids/ips는 금지 토큰 → iss_device 별칭 오발동 없이 .xml 확장자 후보군 그대로.
    guessed, candidates = guess_profile("user_ids.xml")
    assert guessed is None
    assert set(candidates) == xml_ext_candidates

    guessed, candidates = guess_profile("server_ips.xml")
    assert guessed is None
    assert set(candidates) == xml_ext_candidates

    # checkpoint는 금지 토큰 → .json 확장자 DB 후보군 그대로(별칭 개입 없음).
    guessed, candidates = guess_profile("checkpoint_dump.json")
    assert guessed is None
    assert set(candidates) == json_ext_candidates

    # weeks/wafer는 eks/waf 경계차단 → container/iss_device 별칭 오발동 없이
    # .xml 확장자 후보군 그대로.
    guessed, candidates = guess_profile("weeks_summary.xml")
    assert guessed is None
    assert set(candidates) == xml_ext_candidates

    guessed, candidates = guess_profile("wafer_data.xml")
    assert guessed is None
    assert set(candidates) == xml_ext_candidates


def test_guess_profile_concrete_marker_still_wins_over_alias():
    """구체마커(Stage A)가 매칭되면 별칭 스캔(Stage B)은 아예 수행되지 않아야
    한다 — linux_mysql_result.json은 mysql_result 마커로 db_mysql 단일 확정."""
    assert guess_profile("linux_mysql_result.json") == ("db_mysql", ("db_mysql",))


def test_guess_profile_db_cloud_refinement():
    """DB 엔진 별칭 + aws/azure 별칭이 동시 매칭되면 cloud를 제거해 DB
    프로파일로 단일 확정한다(§2 DB-클라우드 정제). 순수 클라우드 별칭만
    매칭되면 cloud로 확정, DB+비-aws/azure cloud 별칭(cloud/클라우드)이 섞이면
    정제하지 않고 모호로 남긴다."""
    assert guess_profile("mysql_azure_점검.txt") == ("db_mysql", ("db_mysql",))
    assert guess_profile("azure_점검.xml") == ("cloud", ("cloud",))
    guessed, candidates = guess_profile("azure_linux.xml")
    assert guessed is None
    assert set(candidates) == {"cloud", "server"}


def test_variant_from_filename_alias_fallback():
    assert CLOUD.variant_from_filename("AWS점검.xml") == "AWS"
    assert CLOUD.variant_from_filename("aws_azure.xml") is None

    db_mysql = get_profile("db_mysql")
    assert db_mysql.variant_from_filename("mysql_rds_점검.txt") == "mysql_rds"
    assert db_mysql.variant_from_filename("MySQL점검.txt") is None
    # 기존 가드 회귀: 네이티브 최장매치 + 클라우드 토큰 독립단어 → None 불변.
    assert db_mysql.variant_from_filename("rds_mysql_result.txt") is None

    server = get_profile("server")
    assert server.variant_from_filename("linux.xml") is None


def test_platform_alias_table_invariants():
    """별칭표 불변식: (a) excluded(db_tibero) 미포함, (b) 모든 키가 _PROFILES에
    존재하고 excluded가 아님, (c) 서로 다른 프로파일의 ascii 토큰이 경계규칙상
    상호 미매칭(페어와이즈)."""
    assert "db_tibero" not in _PLATFORM_ALIASES

    for key in _PLATFORM_ALIASES:
        assert key in _PROFILES, f"{key}가 _PROFILES에 없음"
        assert _PROFILES[key].excluded is False, f"{key}는 excluded 프로파일"

    for profile_a, tokens_a in _PLATFORM_ALIASES.items():
        for profile_b, tokens_b in _PLATFORM_ALIASES.items():
            if profile_a == profile_b:
                continue
            for token_a in tokens_a:
                for token_b in tokens_b:
                    assert not _alias_hit(token_b, token_a), (
                        f"{profile_a}의 토큰 '{token_a}'가 "
                        f"{profile_b}의 토큰 '{token_b}' 매칭과 충돌")

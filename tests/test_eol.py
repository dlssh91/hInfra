"""eol.py — DBM-025 EOL / DBM-016 패치 결정론 판정 테스트."""
import datetime

from judge_tool.eol import judge_eol, judge_patch, _series, _ver_tuple
from judge_tool.models import EvidenceItem, ResourceEvidence

TODAY = datetime.date(2026, 6, 10)


def _items(item_id, evidence):
    res = ResourceEvidence(resource_id="r1", status="info",
                           detail="", evidence=evidence)
    return {item_id: EvidenceItem(item_id=item_id, variant="v",
                                  resources=[res])}


def test_series_mapping():
    assert _series("mysql", "8.4.4") == "8.4"
    assert _series("mariadb", "11.4.4") == "11.4"
    assert _series("postgresql", "17.4") == "17"
    assert _series("oracle", "19.26.0.0.250121") == "19"
    assert _series("mssql", "2019") == "2019"


def test_series_mapping_postgresql_9x_uses_two_part_major():
    """PostgreSQL 10 이전(9.x)은 마이너까지가 시리즈 단위(9.6 != 9.5),
    parts[0]만 취하면 전부 '9'로 뭉개져 eol.yaml '9.6' 키를 못 찾는 버그가
    있었다(2026-07-11 EoS 커버리지 보강 중 발견 → _series() 예외 처리 추가)."""
    assert _series("postgresql", "9.6.24") == "9.6"
    assert _series("postgresql", "9.5.25") == "9.5"
    assert _series("postgresql", "10.23") == "10"


def test_mysql_supported_version_good():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "양호"
    assert "8.4.4" in r["rationale"]


def test_mysql_eol_passed_defers_not_vulnerable():
    """커뮤니티 EOL 경과(MySQL 8.0, 2026-04-30)는 '취약' 단정이 아니라
    판단보류 — 단, 사후관리 절차 미확인 시 취약 기본 처분을 문구로 명시(xlsx 정합).
    관리형 서비스는 Extended Support 등 별도 lifecycle이 있어 verdict는 보류 유지."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "서비스 지원 종료(EoS) 확인" in r["rationale"]
    assert "경과" in r["rationale"]
    # 문구: 사후관리 절차 미확인 시 취약 기본 처분 명시 (xlsx 정합)
    assert "확인되지 않으면 취약" in r["rationale"]


def test_stale_table_warning_attached():
    """as_of가 180일 넘게 경과하면 판정 신뢰 불가 경고가 붙는다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    far_future = datetime.date(2027, 6, 10)
    r = judge_eol("db_mysql", items, today=far_future)
    assert r is not None
    assert "갱신 필요" in r["rationale"]


def test_fresh_table_no_staleness_warning():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert "갱신 필요" not in r["rationale"]


def test_postgresql_version_good():
    items = _items("DBM-016",
                   '{"version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu"}')
    r = judge_eol("db_postgresql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "양호"


def test_mssql_version_good():
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2019 (RTM-CU32)"}')
    r = judge_eol("db_mssql", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_oracle_version_good():
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 19.26.0.0.250121"}')
    r = judge_eol("db_oracle", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_mariadb_version_good():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "VERSION","VARIABLE_VALUE": "11.4.4-MariaDB-log"}')
    r = judge_eol("db_mariadb", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_version_in_other_item_found():
    """버전이 DBM-025가 아닌 임의 항목에 있어도 전수 탐색으로 발견."""
    items = _items("DBM-099",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None and r["verdict"] == "양호"


def test_admin_tls_version_not_false_positive():
    """admin_tls_version 같은 유사 변수명은 버전으로 오인하지 않는다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "admin_tls_version",'
                   '"VARIABLE_VALUE": "TLSv1.2,TLSv1.3"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_unknown_series_returns_none():
    """mysql 5.7은 2026-07-11 갱신으로 eol.yaml에 등재됐으므로(EoS 커버리지
    보강), 진짜 미등재 시리즈(4.1)로 '테이블 미수록→None' 계약을 검증한다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "4.1.44"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_unknown_profile_returns_none():
    assert judge_eol("cloud", {}, today=TODAY) is None


def test_no_version_evidence_returns_none():
    items = _items("DBM-016", '{"no": "version here"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_rationale_cites_as_of_date():
    """rationale에 테이블 기준일이 포함되어 평가자가 갱신 여부를 알 수 있다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert "EOL 테이블 기준일" in r["rationale"]


# ---------------------------------------------------------------------------
# judge_patch — DBM-016 패치 대조
# ---------------------------------------------------------------------------

def test_ver_tuple_numeric_compare():
    assert _ver_tuple("17.4") < _ver_tuple("17.10")   # 문자열 비교였다면 반대
    assert _ver_tuple("8.4.9") > _ver_tuple("8.4.4")


def test_patch_behind_flagged():
    """현재 8.4.4 < 시리즈 최신 8.4.9 → 미적용 후보, verdict는 판단보류."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_patch("db_mysql", items)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "미적용 후보" in r["rationale"]
    assert "8.4.9" in r["rationale"]


def test_patch_current_is_latest():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.9"}')
    r = judge_patch("db_mysql", items)
    assert r["verdict"] == "판단보류"
    assert "최신 패치 수준" in r["rationale"]


def test_patch_mssql_compares_build_number():
    """MSSQL은 연도(2019)가 아닌 빌드 번호(15.0.x)로 대조한다."""
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2019 (RTM-CU32) '
                   '(KB5054833) - 15.0.4430.1 (X64)"}')
    r = judge_patch("db_mssql", items)
    assert r is not None
    assert "15.0.4430.1" in r["rationale"]
    assert "15.0.4470.1" in r["rationale"]
    assert "미적용 후보" in r["rationale"]


def test_patch_oracle_hint_generated():
    """Oracle 19c: eol.yaml latest=19.28.0.0.250715 등록 후
    judge_patch가 '미적용 후보' 힌트를 생성하고 verdict=판단보류를 반환한다.
    (구: latest 미수록 → None 폴백. 2026-06-17 oracle-config.json 기준일로 latest 등록.)"""
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 19.26.0.0.250121"}')
    r = judge_patch("db_oracle", items)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "19.26.0.0.250121" in r["rationale"]
    assert "19.28.0.0.250715" in r["rationale"]
    assert "미적용 후보" in r["rationale"]


# ---------------------------------------------------------------------------
# M2. 네이티브/클라우드 분기 문구 테스트
# ---------------------------------------------------------------------------

def test_eol_native_variant_no_cloud_phrase():
    """네이티브 variant 전달 시 rationale에 '관리형 서비스'가 포함되지 않아야 한다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    r = judge_eol("db_mysql", items, today=TODAY, variant="mysql_native")
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "관리형 서비스" not in r["rationale"]
    assert "벤더 Extended Support 계약" in r["rationale"]
    assert "내부 사후 관리 절차" in r["rationale"]


def test_eol_cloud_variant_preserves_existing_phrase():
    """클라우드 variant(또는 기본값 None) 전달 시 기존 관리형 서비스 문구가 유지된다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    # variant=None(기본값) — 기존 동작 보존
    r_default = judge_eol("db_mysql", items, today=TODAY)
    assert r_default is not None
    assert "관리형 서비스" in r_default["rationale"]

    # variant 명시적으로 클라우드 전달
    r_rds = judge_eol("db_mysql", items, today=TODAY, variant="mysql_rds")
    assert r_rds is not None
    assert "관리형 서비스" in r_rds["rationale"]


def test_patch_native_variant_no_cloud_phrase():
    """네이티브 variant 전달 시 judge_patch rationale에 '관리형 서비스'가 없어야 한다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_patch("db_mysql", items, variant="mysql_native")
    assert r is not None
    assert "관리형 서비스" not in r["rationale"]
    assert "벤더 권고 패치 적용 절차" in r["rationale"]


def test_patch_cloud_variant_preserves_existing_phrase():
    """클라우드 variant 전달 시 기존 패치 채널 문구가 유지된다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r_default = judge_patch("db_mysql", items)
    assert r_default is not None
    assert "관리형 서비스" in r_default["rationale"]


# ---------------------------------------------------------------------------
# 신선도 강등(옵션 C) 회귀핀 — DBM-025 staleness demotion
# ---------------------------------------------------------------------------

def _make_table_with_as_of(as_of_date):
    """실제 eol.yaml 구조를 그대로 쓰되 as_of만 교체한 캐시 딕셔너리를 반환."""
    import judge_tool.eol as eol_mod
    import copy
    original = eol_mod._load_table()
    patched = copy.deepcopy(original)
    patched["as_of"] = as_of_date
    return patched


def test_staleness_demotion_fresh_yields_good(monkeypatch):
    """지원중 버전 + as_of 오늘-1일(신선) → 양호."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2026, 6, 18)
    as_of = today - datetime.timedelta(days=1)  # 1일 경과, 신선
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(as_of))
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "양호", f"신선 as_of → 양호 기대, got {r['verdict']}"
    assert r["confidence"] == 0.9


def test_staleness_demotion_stale_yields_defer(monkeypatch):
    """지원중 버전 + as_of 오늘-200일(stale >180일) → 판단보류(강등)."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2026, 6, 18)
    as_of = today - datetime.timedelta(days=200)  # 200일 경과, 오래됨
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(as_of))
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "판단보류", f"stale as_of → 판단보류 기대, got {r['verdict']}"
    assert r["confidence"] == 0.5
    assert "200" in r["rationale"] or "기준선 노후" in r["rationale"]
    assert "eol.yaml 갱신" in r["rationale"]
    assert str(as_of) in r["rationale"]


def test_staleness_demotion_eol_passed_unaffected(monkeypatch):
    """EOL 경과 버전 → stale 여부와 무관하게 판단보류(불변)."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2026, 6, 18)
    as_of = today - datetime.timedelta(days=200)
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(as_of))
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "서비스 지원 종료(EoS) 확인" in r["rationale"]  # EOL 경과 분기 메시지


def test_staleness_demotion_as_of_none_yields_defer(monkeypatch):
    """as_of=None → 기준일 불명, 양호 단정 불가 → 판단보류."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2026, 6, 18)
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(None))
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "판단보류", f"as_of None → 판단보류 기대, got {r['verdict']}"
    assert "기준일을 알 수 없어" in r["rationale"]


def test_staleness_demotion_realdata_1day_still_good():
    """실데이터: eol.yaml as_of=2026-07-11, today=2026-07-12 → 1일 경과(신선) → 양호 불변."""
    today = datetime.date(2026, 7, 12)
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "양호", (
        f"실데이터 1일 경과(신선) → 양호 기대. eol.yaml as_of=2026-07-11. got {r['verdict']}"
    )


def test_defer_or_eol_preserves_verdict_with_empty_own_section():
    """DBM-025 자기 섹션이 비어 있고 버전이 타 항목에 있어도 EOL 판정의
    verdict(양호)가 reconcile '증거 없음' 가드에 덮어써지지 않는다.

    회귀: 2026-06-10 실데이터 검증에서 EOL 양호 판정이 빈 더미 item 때문에
    판단보류로 강제되는 버그 발견.
    """
    from judge_tool.main import _defer_or_eol, JudgeContext
    from judge_tool.models import Criterion
    from judge_tool.profile import DB_MYSQL

    crit = Criterion(
        item_id="DBM-025", item_name="EOL", risk=3.0, variant="mysql_rds",
        eval_type="", standard="기준", method="방법", applicable=True,
        label="D", eol_check=True, canned_message="폴백 메시지")
    empty_item = EvidenceItem(item_id="DBM-025", variant="mysql_rds",
                              resources=[])
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')

    ctx = JudgeContext(profile=DB_MYSQL, profile_key="db_mysql", client=None,
                       items=items, variant="mysql_rds")
    j = _defer_or_eol(crit, empty_item, ctx)
    assert j.verdict == "양호", "EOL 양호 판정이 보존되어야 함"
    assert "[EOL 자동판정]" in j.rationale
    assert "[자동 판단보류" not in j.rationale
    # 테이블 기반 자동판정은 파서 status 동작과 무관하게 항상 검토 대상
    assert j.needs_review is True


# ---------------------------------------------------------------------------
# EoS 커버리지 보강 (2026-07-11, [[patch-eol-baseline-policy]])
# 미등재였던 주요 EoS 경과 버전(oracle 11g/18c, mysql 5.6/5.7, mssql 2012,
# postgresql 9.6~12, mariadb 10.1~10.5) 등재 회귀핀.
# 실데이터 today는 eol.yaml as_of(2026-07-11)와 같은 날 기준으로 검증한다.
# ---------------------------------------------------------------------------

REAL_TODAY = datetime.date(2026, 7, 11)


def test_oracle_11g_now_registered_eol_passed_defers():
    """oracle 11.2(11g) EoS(2020-12-31 경과) 신규 등재 → 판단보류(사유 명확화),
    구버전은 '테이블 미수록'이 아니라 'EoS 확인'으로 귀결되어야 한다."""
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 11.2.0.4.250121"}')
    r = judge_eol("db_oracle", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "서비스 지원 종료(EoS) 확인" in r["rationale"]
    assert "2020-12-31" in r["rationale"]


def test_oracle_18c_now_registered_eol_passed_defers():
    """oracle 18c EoS(2021-06-30 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016", '{"description":"Oracle Database 18c Enterprise"}')
    r = judge_eol("db_oracle", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "서비스 지원 종료(EoS) 확인" in r["rationale"]
    assert "2021-06-30" in r["rationale"]


def test_mysql57_now_registered_eol_passed_defers():
    """mysql 5.7 EoS(2023-10-31 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "5.7.44"}')
    r = judge_eol("db_mysql", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "서비스 지원 종료(EoS) 확인" in r["rationale"]
    assert "2023-10-31" in r["rationale"]


def test_mysql56_now_registered_eol_passed_defers():
    """mysql 5.6 EoS(2021-02-05 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "5.6.51"}')
    r = judge_eol("db_mysql", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2021-02-05" in r["rationale"]


def test_mssql2012_now_registered_eol_passed_defers():
    """mssql 2012 EoS(2022-07-12 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2012 (SP4)"}')
    r = judge_eol("db_mssql", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2022-07-12" in r["rationale"]


def test_postgresql12_now_registered_eol_passed_defers():
    """postgresql 12 EoS(2024-11-14 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016", '{"version": "PostgreSQL 12.20 on x86_64"}')
    r = judge_eol("db_postgresql", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2024-11-14" in r["rationale"]


def test_postgresql96_now_registered_eol_passed_defers():
    """postgresql 9.6 EoS(2021-11-11 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016", '{"version": "PostgreSQL 9.6.24 on x86_64"}')
    r = judge_eol("db_postgresql", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2021-11-11" in r["rationale"]


def test_mariadb104_now_registered_eol_passed_defers():
    """mariadb 10.4 EoS(2024-06-18 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "VERSION","VARIABLE_VALUE": "10.4.34-MariaDB"}')
    r = judge_eol("db_mariadb", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2024-06-18" in r["rationale"]


def test_mariadb101_now_registered_eol_passed_defers():
    """mariadb 10.1 EoS(2020-10-17 경과) 신규 등재 → 판단보류(사유 명확화)."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "VERSION","VARIABLE_VALUE": "10.1.48-MariaDB"}')
    r = judge_eol("db_mariadb", items, today=REAL_TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "2020-10-17" in r["rationale"]


def test_oracle_12x_still_unregistered_by_design():
    """oracle 12.1/12.2는 시리즈 키 충돌(_series가 parts[0]만 취해 둘 다 '12')
    + 소스별 종료일 확신 부족으로 의도적으로 미등재 상태를 유지한다."""
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 12.1.0.2.250121"}')
    assert judge_eol("db_oracle", items, today=REAL_TODAY) is None


def test_mariadb106_still_unregistered_by_design():
    """mariadb 10.6은 현재일(2026-07-11)에 근접한 EoS라 일자 확신 부족으로
    의도적으로 미등재 상태를 유지한다(오탐 방지)."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "VERSION","VARIABLE_VALUE": "10.6.20-MariaDB"}')
    assert judge_eol("db_mariadb", items, today=REAL_TODAY) is None


# --- 신규 등재 항목의 '지원중 fresh→양호' / 'stale as_of→강등' 분기 회귀 ---
# (신규 등재는 전부 과거 EoS 사례이므로, 로직 경로 자체를 검증하기 위해
#  today를 해당 항목의 eol 이전으로 앞당겨 '가상 지원중' 상태를 만든다.)

def test_newly_registered_series_fresh_before_eol_yields_good(monkeypatch):
    """mysql 5.7(신규 등재, eol=2023-10-31) — today를 eol 이전(2023-06-01)으로
    앞당기고 as_of를 그 하루 전(신선)으로 맞추면 '지원중+fresh' 분기로 양호."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2023, 6, 1)
    as_of = today - datetime.timedelta(days=1)
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(as_of))
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "5.7.30"}')
    r = judge_eol("db_mysql", items, today=today)
    assert r is not None
    assert r["verdict"] == "양호", f"신규 등재+지원중+fresh → 양호 기대, got {r['verdict']}"
    assert r["confidence"] == 0.9


def test_newly_registered_series_stale_as_of_demotes_to_defer(monkeypatch):
    """mssql 2012(신규 등재, eol=2022-07-12) — today를 eol 이전으로 앞당기되
    as_of를 200일 넘게 오래된 상태로 맞추면 '지원중'이어도 stale 강등→판단보류."""
    import judge_tool.eol as eol_mod
    today = datetime.date(2022, 1, 1)
    as_of = today - datetime.timedelta(days=200)
    monkeypatch.setattr(eol_mod, "_table_cache", _make_table_with_as_of(as_of))
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2012 (SP4)"}')
    r = judge_eol("db_mssql", items, today=today)
    assert r is not None
    assert r["verdict"] == "판단보류", f"stale as_of → 판단보류 기대, got {r['verdict']}"
    assert "기준선 노후" in r["rationale"]

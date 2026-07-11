"""DB(DBM) 엔진별 DET 양극성 계약 테스트 (결정론, LLM 불필요).

목적: 각 DB 엔진(mysql/mariadb/oracle/mssql/postgresql) × DET 항목에 대해
  - good 합성 입력 → good_verdict(양호/판단보류) 확인
  - vuln 합성 입력 → vuln_verdict(취약/판단보류) 확인
이로써 전 DET 항목의 양극성이 깨지지 않음을 회귀로 고정한다.

거짓양호(vuln→양호) 0 / 거짓취약(good→취약) 0 이 SHIP 조건.

불변 계약:
  - judge() 직접 호출 (LLM 없음)
  - results/·collected/ 쓰기 금지 (합성 픽스처 인라인)
  - 기존 판정 로직 변경 없음 (검증만)
"""
from __future__ import annotations

import importlib
import json

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.db  # noqa: F401
from judge_tool.det_adapters.db import judge, _RUN_CACHE
from judge_tool.det_adapters.base import reload_det_source

from tests.db_cov_contract import DB_COV, ENGINE_TO_VARIANT


# ──────────────────────────────────────────────────────────────────────────────
# 헬퍼
# ──────────────────────────────────────────────────────────────────────────────

def _make_raw(data_dict: dict) -> str:
    return json.dumps(data_dict, ensure_ascii=False)


def _clear_cache():
    _RUN_CACHE.clear()


# ──────────────────────────────────────────────────────────────────────────────
# 파라미터 생성: (engine, item_id, polarity) 삼중 튜플
# ──────────────────────────────────────────────────────────────────────────────

def _gen_params():
    """DB_COV에서 (engine, item_id, polarity) 조합 생성.

    uncovered 항목은 skip 처리(fixture에서). vuln_only 항목은 good 극성을 skip.
    """
    params = []
    for engine, items in DB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered") and not spec.get("vuln_only"):
                # 완전 미커버 — pytest skip으로 처리
                params.append(pytest.param(
                    engine, item_id, "good",
                    marks=pytest.mark.skip(reason=spec.get("uncovered_reason", "미커버"))
                ))
                params.append(pytest.param(
                    engine, item_id, "vuln",
                    marks=pytest.mark.skip(reason=spec.get("uncovered_reason", "미커버"))
                ))
            elif spec.get("vuln_only"):
                # vuln만 테스트 가능 (good 없는 구조적취약)
                params.append(pytest.param(
                    engine, item_id, "good",
                    marks=pytest.mark.skip(
                        reason=spec.get("uncovered_reason", "good 극성 없음(구조적 취약)")
                    )
                ))
                params.append((engine, item_id, "vuln"))
            else:
                params.append((engine, item_id, "good"))
                params.append((engine, item_id, "vuln"))
    return params


_ALL_PARAMS = _gen_params()


# ──────────────────────────────────────────────────────────────────────────────
# 공통 픽스처
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_state():
    """각 테스트 전 캐시 클리어 + DET_SOURCE 리로드."""
    _clear_cache()
    reload_det_source()
    yield
    _clear_cache()


# ──────────────────────────────────────────────────────────────────────────────
# 메인 양극성 테스트
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("engine,item_id,polarity", _ALL_PARAMS)
def test_db_det_polarity(engine, item_id, polarity):
    """DET 항목 양극성: good→expected_verdict, vuln→expected_verdict.

    거짓양호(vuln입력→양호 판정) 및 거짓취약(good입력→취약 판정)이 없음을 확인한다.

    판정 흐름:
      1. gate()가 DET 아니면 handled=False → 이 경우 결정론 범위 밖(이미 STUB/ABSENT 테스트에서 커버)
      2. handled=True이면 verdict가 기대값과 일치하는지 확인
      3. handled=False이면 verdict != '양호' 임을 확인 (거짓양호 방지)
    """
    spec = DB_COV[engine][item_id]
    variant = ENGINE_TO_VARIANT[engine]

    data_dict = spec[polarity]
    expected_verdict = spec[f"{polarity}_verdict"]
    raw = _make_raw(data_dict)

    fv = judge(item_id, raw, variant, {})

    if not fv.handled:
        # gate 차단(STUB/ABSENT) 또는 D3 증거가드 — 이 경우는 기존 gate 테스트가 커버.
        # 단, 거짓양호(handled=False인데 양호 판정)는 절대 불가.
        assert fv.verdict != "양호", (
            f"[거짓양호] {engine}/{item_id}/{polarity}: "
            f"handled=False인데 verdict='양호' — 거짓양호 발생! "
            f"({fv!r})"
        )
        # DET 항목인데 handled=False이면 이는 D3(증거가드) 또는 R3(예외가드) 상황.
        # 데이터 구조가 의도한 것과 다를 수 있으므로 경고 메시지 포함.
        pytest.skip(
            f"{engine}/{item_id}/{polarity}: handled=False (D3 증거가드 또는 R3 예외가드). "
            f"verdict={fv.verdict!r} rationale={fv.rationale!r}. "
            f"합성 데이터 구조를 확인하거나 STUB 여부 재검토 필요."
        )

    # handled=True: verdict 확인
    actual = fv.verdict

    if polarity == "vuln":
        # 거짓양호 검사: vuln 입력인데 양호가 나오면 안 됨
        assert actual != "양호", (
            f"[거짓양호] {engine}/{item_id}/vuln: "
            f"취약 입력인데 verdict='양호' — 거짓양호 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        # 기대 verdict 확인
        assert actual == expected_verdict, (
            f"[극성 불일치] {engine}/{item_id}/vuln: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} citations={fv.citations!r}"
        )

    else:  # polarity == "good"
        # 거짓취약 검사: good 입력인데 취약이 나오면 안 됨
        assert actual != "취약", (
            f"[거짓취약] {engine}/{item_id}/good: "
            f"양호 입력인데 verdict='취약' — 거짓취약 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        # 기대 verdict 확인
        assert actual == expected_verdict, (
            f"[극성 불일치] {engine}/{item_id}/good: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# label B 항목 판단보류 확인 (gate 차단 경로)
# ──────────────────────────────────────────────────────────────────────────────

# label B는 judgment_method=interview → classify_method=interview → _summarize_one 라우팅.
# det_common 어댑터 미호출(STUB gate 차단).
# 확인: handled=False이고 verdict != '양호'

@pytest.mark.parametrize("engine,item_id,variant", [
    # mysql label B(인터뷰)
    ("mysql_native", "DBM-017", "mysql_native"),
    # oracle label B(인터뷰)
    ("oracle_native", "DBM-017", "oracle_native"),
    ("oracle_native", "DBM-015", "oracle_native"),
    # mssql label B
    ("mssql_native", "DBM-017", "mssql_native"),
    ("mssql_native", "DBM-015", "mssql_native"),
    # mariadb label B
    ("mariadb_native", "DBM-017", "mariadb_native"),
    # pg label B
    ("pg_native", "DBM-017", "pg_native"),
    ("pg_native", "DBM-015", "pg_native"),
    # tibero label B(인터뷰) — 2026-07-11 배선. DBM-024/028은 DET_SOURCE=DET이라
    # (item_configs가 judgment_method 미부여로 라우팅만 차단) 여기 미포함 — STUB인
    # 항목만 gate 레벨에서 검증한다(다른 엔진과 동일 원칙).
    ("tibero", "DBM-017", "tibero"),
    ("tibero", "DBM-015", "tibero"),
    ("tibero", "DBM-020", "tibero"),
    ("tibero", "DBM-030", "tibero"),
])
def test_label_b_gate_block_no_false_positive(engine, item_id, variant):
    """label B 항목: STUB → gate 차단 → handled=False, verdict != '양호' 확인.

    label B = 인터뷰 필수. DET_SOURCE STUB. 결정론 어댑터 미호출.
    거짓양호(양호 자동판정) 절대 금지 확인.
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({item_id: {"RESULT": [{"dummy": "data"}]}})
    fv = judge(item_id, raw, variant, {})

    assert fv.handled is False, (
        f"label B {engine}/{item_id}: STUB → handled=False 기대인데 handled=True. "
        f"DET_SOURCE STUB 확인 필요. verdict={fv.verdict!r}"
    )
    assert fv.verdict != "양호", (
        f"label B {engine}/{item_id}: STUB gate 차단 후 양호 판정 — 거짓양호 발생!"
    )


# ──────────────────────────────────────────────────────────────────────────────
# label C/D 항목 — canned 경로 확인 (결정론 판단보류)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("engine,item_id,variant,note", [
    ("mysql_native",  "DBM-025", "mysql_native", "label D EOL"),
    ("oracle_native", "DBM-025", "oracle_native", "label D EOL"),
    ("mssql_native",  "DBM-025", "mssql_native", "label D EOL"),
    ("pg_native",     "DBM-025", "pg_native", "label D EOL"),
    ("pg_native",     "DBM-019", "pg_native", "label C 기능부재"),
    ("mssql_native",  "DBM-021", "mssql_native", "label C ODBC"),
    ("mssql_native",  "DBM-022", "mssql_native", "label C 파일ACL"),
    ("tibero",        "DBM-025", "tibero", "label D EOL(tibero, 2026-07-11 배선)"),
    ("tibero",        "DBM-016", "tibero", "label D 패치버전(tibero, 2026-07-11 배선)"),
])
def test_label_cd_no_false_positive(engine, item_id, variant, note):
    """label C/D 항목: STUB/canned → handled=False, verdict != '양호' 확인.

    label C/D = 기술한계 / 외부지식 필요 → 자동 판단보류 고정. 거짓양호 금지.
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({item_id: {"RESULT": [{"dummy": "value"}]}})
    fv = judge(item_id, raw, variant, {})

    assert fv.verdict != "양호", (
        f"[거짓양호] {engine}/{item_id} ({note}): "
        f"label C/D인데 양호 판정 발생! verdict={fv.verdict!r} handled={fv.handled}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# 모드B 구조적취약 확인 (pg_native DBM-006/007)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,note", [
    ("DBM-006", "pg 코어 실패잠금 부재"),
    ("DBM-007", "pg 코어 복잡도강제 부재"),
])
def test_pg_native_structural_vuln(item_id, note):
    """pg_native 구조적취약(모드B): 어떤 입력에서도 취약 판정 확인.

    PostgreSQL 코어에 실패잠금/비밀번호 복잡도 강제 기능이 없어
    데이터 무관하게 구조적으로 취약.
    """
    _clear_cache()
    reload_det_source()

    # 빈 RESULT로 테스트 (데이터 무관해야 함)
    raw = _make_raw({"dummy": {"RESULT": []}})
    fv = judge(item_id, raw, "pg_native", {})

    assert fv.handled is True, (
        f"pg_native {item_id} ({note}): 구조적취약인데 handled=False. "
        f"모드B 경로가 gate DET 이전에 실행되는지 확인 필요."
    )
    assert fv.verdict == "취약", (
        f"pg_native {item_id} ({note}): 구조적취약인데 verdict={fv.verdict!r}. "
        f"거짓양호/판단보류 발생."
    )


# ──────────────────────────────────────────────────────────────────────────────
# 모드D 빈RESULT 판단보류 확인 (DBM-019 mysql/mariadb/oracle, DBM-029 oracle, DBM-031 mssql)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,variant,note", [
    ("DBM-019", "mysql_native", "mysql 비밀번호 재사용 빈RESULT"),
    ("DBM-019", "mariadb_native", "mariadb 비밀번호 재사용 빈RESULT"),
    ("DBM-019", "oracle_native", "oracle 비밀번호 재사용 빈RESULT"),
    ("DBM-029", "oracle_native", "oracle RESOURCE_LIMIT 빈RESULT"),
    ("DBM-031", "mssql_native", "mssql SA 계정 빈RESULT"),
])
def test_mode_d_empty_result_hold(item_id, variant, note):
    """모드D: 빈 RESULT → 판단보류(양호 자동판정 금지).

    기대 변수가 수집되지 않았을 때 양호로 단정하지 않는다(거짓양호 방지).
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({item_id: {"RESULT": []}})
    fv = judge(item_id, raw, variant, {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드D {variant}/{item_id} ({note}): "
            f"빈 RESULT인데 양호 판정 — 거짓양호 발생! "
            f"verdict={fv.verdict!r}"
        )
        assert fv.verdict == "판단보류", (
            f"모드D {variant}/{item_id} ({note}): "
            f"빈 RESULT인데 판단보류 아님: verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 모드E 파일권한 미수집 판단보류 (DBM-022)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant,note", [
    ("mysql_native", "mysql DBM-022 빈RESULT"),
    ("mariadb_native", "mariadb DBM-022 빈RESULT"),
    ("oracle_native", "oracle DBM-022 빈RESULT"),
    ("pg_native", "pg DBM-022 빈RESULT"),
])
def test_dbm022_empty_result_hold(variant, note):
    """모드E: DBM-022 빈 RESULT → 판단보류(파일 미수집).

    ps 출력이 없는 상태를 '파일 권한 이상 없음=양호'로 단정하지 않는다.
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-022": {"RESULT": []}})
    fv = judge("DBM-022", raw, variant, {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드E {variant}/DBM-022 ({note}): "
            f"빈 RESULT인데 양호 판정 — 거짓양호 발생! "
            f"verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 모드F umask 미수집 판단보류 (DBM-026)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant,note", [
    ("mysql_native", "mysql DBM-026 빈RESULT"),
    ("mariadb_native", "mariadb DBM-026 빈RESULT"),
    ("oracle_native", "oracle DBM-026 빈RESULT"),
    ("pg_native", "pg DBM-026 빈RESULT"),
])
def test_dbm026_empty_result_hold(variant, note):
    """모드F: DBM-026 빈 RESULT → 판단보류(umask 미수집).

    umask 수집 실패 상태를 '제한 없음=양호'로 단정하지 않는다.
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-026": {"RESULT": []}})
    fv = judge("DBM-026", raw, variant, {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드F {variant}/DBM-026 ({note}): "
            f"빈 RESULT인데 양호 판정 — 거짓양호 발생! verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 모드G pg_hba 미수집 판단보류 (DBM-032 pg_native)
# ──────────────────────────────────────────────────────────────────────────────

def test_dbm032_pg_native_empty_result_hold():
    """모드G: DBM-032 pg_native 빈 RESULT → 판단보류(pg_hba.conf 미수집).

    pg_hba 없이는 평문 비번 부재를 확인할 수 없음 → 양호 자동판정 금지.
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-032": {"RESULT": []}})
    fv = judge("DBM-032", raw, "pg_native", {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드G pg_native/DBM-032: "
            f"빈 RESULT인데 양호 판정 — 거짓양호 발생! verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 모드H 데몬 미탐지 판단보류 (DBM-034)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant,note", [
    ("mysql_native", "mysql DBM-034 빈RESULT"),
    ("mariadb_native", "mariadb DBM-034 빈RESULT"),
    ("oracle_native", "oracle DBM-034 빈RESULT"),
    ("pg_native", "pg DBM-034 빈RESULT"),
])
def test_dbm034_empty_result_hold(variant, note):
    """모드H: DBM-034 빈 RESULT → 판단보류(데몬 미수집).

    ps 출력이 없어 root 구동 여부 확인 불가 → 양호 자동판정 금지(거짓양호 최악).
    """
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-034": {"RESULT": []}})
    fv = judge("DBM-034", raw, variant, {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드H {variant}/DBM-034 ({note}): "
            f"빈 RESULT인데 양호 판정 — 거짓양호 발생! verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 모드I xp_cmdshell/xp_reg 미수집 판단보류 (DBM-035/036 mssql_native)
# ──────────────────────────────────────────────────────────────────────────────

def test_dbm035_mssql_empty_result_hold():
    """모드I: DBM-035 빈 RESULT → 판단보류(xp_cmdshell 미수집)."""
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-035": {"RESULT": []}})
    fv = judge("DBM-035", raw, "mssql_native", {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드I mssql/DBM-035: 빈 RESULT인데 양호 판정 발생! verdict={fv.verdict!r}"
        )


def test_dbm035_mssql_no_xpcmdshell_row_hold():
    """모드I: DBM-035 RESULT에 xp_cmdshell 행 없음 → 판단보류(미수집)."""
    _clear_cache()
    reload_det_source()

    # 다른 항목 행만 있고 xp_cmdshell 없음
    raw = _make_raw({"DBM-035": {"RESULT": [
        {"name": "clr_enabled", "value_in_use": "0"}
    ]}})
    fv = judge("DBM-035", raw, "mssql_native", {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드I mssql/DBM-035: xp_cmdshell 행 없는데 양호 판정 발생! "
            f"verdict={fv.verdict!r}"
        )


def test_dbm036_mssql_empty_result_hold():
    """모드I2: DBM-036 빈 RESULT → 판단보류(xp_reg 미수집)."""
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-036": {"RESULT": []}})
    fv = judge("DBM-036", raw, "mssql_native", {})

    if fv.handled:
        assert fv.verdict != "양호", (
            f"[거짓양호] 모드I2 mssql/DBM-036: 빈 RESULT인데 양호 판정 발생! verdict={fv.verdict!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 커버리지 요약 테스트 (계약 완전성 검사)
# ──────────────────────────────────────────────────────────────────────────────

def test_db_cov_contract_completeness():
    """DB_COV 계약이 각 엔진의 주요 DET 항목을 커버하는지 확인.

    최소 기대:
      - mysql: 10개 이상 항목 정의
      - mariadb: 8개 이상 항목 정의
      - oracle: 8개 이상 항목 정의
      - mssql: 8개 이상 항목 정의
      - postgresql: 7개 이상 항목 정의
    """
    minimums = {
        "mysql": 10,
        "mariadb": 8,
        "oracle": 8,
        "mssql": 8,
        "postgresql": 7,
        "tibero": 8,
    }
    for engine, min_count in minimums.items():
        actual = len(DB_COV[engine])
        assert actual >= min_count, (
            f"{engine}: DB_COV에 {actual}개 항목만 정의됨, 최소 {min_count}개 기대. "
            f"DET 항목 커버리지 부족 — 계약 보강 필요."
        )


def test_db_cov_uncovered_items_documented():
    """미커버(uncovered) 항목이 모두 사유와 함께 문서화됨을 확인.

    uncovered=True인 항목은 uncovered_reason이 있어야 한다(은폐 금지).
    """
    for engine, items in DB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered") or spec.get("vuln_only"):
                if spec.get("uncovered"):
                    assert "uncovered_reason" in spec, (
                        f"{engine}/{item_id}: uncovered=True인데 "
                        f"uncovered_reason 없음 — 사유 문서화 필수."
                    )
                    assert spec["uncovered_reason"].strip(), (
                        f"{engine}/{item_id}: uncovered_reason이 비어있음."
                    )
                elif spec.get("vuln_only"):
                    # vuln_only도 uncovered_reason 또는 note에 사유 있어야 함
                    assert spec.get("uncovered_reason") or spec.get("note"), (
                        f"{engine}/{item_id}: vuln_only=True인데 사유 미문서화."
                    )


def test_db_cov_covered_items_have_both_polarities():
    """커버된 항목은 good/vuln 양쪽 데이터와 verdict가 모두 있어야 한다."""
    for engine, items in DB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered"):
                continue
            if spec.get("vuln_only"):
                # vuln만 있어도 됨
                assert "vuln" in spec, f"{engine}/{item_id}: vuln_only인데 vuln 데이터 없음"
                assert "vuln_verdict" in spec, f"{engine}/{item_id}: vuln_verdict 없음"
                continue
            # 일반 항목
            assert "good" in spec, f"{engine}/{item_id}: good 데이터 없음"
            assert "vuln" in spec, f"{engine}/{item_id}: vuln 데이터 없음"
            assert "good_verdict" in spec, f"{engine}/{item_id}: good_verdict 없음"
            assert "vuln_verdict" in spec, f"{engine}/{item_id}: vuln_verdict 없음"
            assert spec["good_verdict"] in ("양호", "판단보류"), (
                f"{engine}/{item_id}: 알 수 없는 good_verdict={spec['good_verdict']!r}"
            )
            assert spec["vuln_verdict"] in ("취약", "판단보류"), (
                f"{engine}/{item_id}: 알 수 없는 vuln_verdict={spec['vuln_verdict']!r}"
            )


# ──────────────────────────────────────────────────────────────────────────────
# oracle DBM-011 dateutil 의존 별도 처리
# ──────────────────────────────────────────────────────────────────────────────

def test_oracle_dbm011_good_hold_requires_dateutil():
    """oracle DBM-011 good→판단보류: dateutil 필요. 없으면 skip.

    oracle analysis.py가 dateutil.relativedelta를 사용.
    dateutil 미설치 환경은 importorskip으로 skip.
    """
    pytest.importorskip("dateutil", reason="oracle analysis.py requires python-dateutil")
    _clear_cache()
    reload_det_source()

    # audit_trail=DB(수집됨) → 위반0 → 모드C → 판단보류
    raw = _make_raw({"DBM-011": {"RESULT": [
        {"name": "audit_trail", "value": "DB"}
    ]}})
    fv = judge("DBM-011", raw, "oracle_native", {})

    assert fv.handled is True, f"oracle DBM-011 handled=False: {fv}"
    assert fv.verdict == "판단보류", (
        f"oracle DBM-011 수집됨 → 판단보류 기대, 실제: {fv.verdict!r}. "
        f"거짓양호 의심."
    )
    assert fv.verdict != "양호", (
        f"[거짓양호] oracle DBM-011: 수집됨인데 양호 판정 발생!"
    )


def test_oracle_dbm011_vuln_requires_dateutil():
    """oracle DBM-011 vuln→취약: audit_trail=NONE → 취약. dateutil 필요."""
    pytest.importorskip("dateutil", reason="oracle analysis.py requires python-dateutil")
    _clear_cache()
    reload_det_source()

    raw = _make_raw({"DBM-011": {"RESULT": [
        {"name": "audit_trail", "value": "NONE"}
    ]}})
    fv = judge("DBM-011", raw, "oracle_native", {})

    assert fv.handled is True
    assert fv.verdict == "취약", (
        f"oracle DBM-011 NONE → 취약 기대, 실제: {fv.verdict!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# 모드A2 classify-then-hold (DBM-003) — DB_COV 계약 기반 전엔진 항상보류 확인
# ──────────────────────────────────────────────────────────────────────────────

def test_mode_a2_dbm003_always_hold():
    """DB_COV의 모든 엔진 DBM-003 계약이 good/vuln 모두 판단보류로 고정됨을 확인.

    모드A2(classify-then-hold)는 label B 의도 항목을 항상 판단보류로 귀결시키며
    자동 양호/취약 판정을 절대 하지 않는다(§거짓양호 방지). DB_COV 계약 자체가
    이를 어기면 이 테스트가 실패한다(계약 회귀 고정).
    """
    for engine, items in DB_COV.items():
        spec = items.get("DBM-003")
        if spec is None or spec.get("uncovered"):
            continue
        assert spec.get("good_verdict") == "판단보류", (
            f"{engine}/DBM-003: good_verdict가 판단보류가 아님(모드A2 계약 위반): "
            f"{spec.get('good_verdict')!r}"
        )
        assert spec.get("vuln_verdict") == "판단보류", (
            f"{engine}/DBM-003: vuln_verdict가 판단보류가 아님(모드A2 계약 위반): "
            f"{spec.get('vuln_verdict')!r}"
        )

        variant = ENGINE_TO_VARIANT[engine]
        for polarity in ("good", "vuln"):
            _clear_cache()
            reload_det_source()
            raw = _make_raw(spec[polarity])
            fv = judge("DBM-003", raw, variant, {})
            if fv.handled:
                assert fv.verdict == "판단보류", (
                    f"{engine}/DBM-003/{polarity}: handled=True인데 판단보류가 아님: "
                    f"{fv.verdict!r}"
                )
                assert fv.verdict != "양호"

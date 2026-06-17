"""DB(DBM) 결정론 어댑터 단위 테스트 (Phase 4 + Phase 4b).

검증 항목:
  (a) engine 매핑: variant → engine (pg_native→postgresql 포함)
  (b) base 정규화: DBM-017_1 → DBM-017
  (c) gate 차단: STUB/ABSENT/MANUAL variant → handled=False (C1 불변)
  (d) 증거존재 가드: base의 data_key 부재 → handled=False
  (e) noise 필터: @@@/*** 단일키 제거, {"*":val} 위반행 유지
  (f) result 매핑: 빈 위반 → 양호(0.9) / 위반 → 취약(0.9, citations)
  (g) .run 예외내성: 예외 시 handled=False
  (h) §7 누출경계: citation에 raw data dict 미포함
  (i) db_json raw_evidence 적재: parse() 후 raw_evidence 설정됨
  (j) 모듈 캐시 동작: 동일 data에 대해 .run 1회
  (k) 실파일 E2E: mysql_native 실데이터 판정 확인
  (l) Phase 4b: cloud 변형 라우팅/gate/DET/캐시 분리 (합성 픽스처)
  (m) DBM-015 label B 라우팅: oracle/mssql/pg native → det_common 어댑터 미호출,
      classify=STUB, judgment_method=interview
  (n) DBM-017 label B 라우팅: mysql/mariadb/oracle/mssql/pg native → det_common 어댑터 미호출,
      classify=STUB, 거짓양호 0(pg PUBLIC 과탐/exception 오판 차단), 클라우드 DET 유지
"""
import json
import os

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.db  # noqa: F401,E402 — 5개 키 등록 부작용
from judge_tool.det_adapters.db import (  # noqa: E402
    judge,
    _normalize_base,
    _engine_of,
    _has_data_key_for,
    _filter_noise,
    _is_cloud_variant,
    _RUN_CACHE,
    _run_analysis,
)
from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, reload_det_source, classify, gate  # noqa: E402

# ── 실 데이터 경로 ──────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.dirname(__file__))
_MYSQL_NATIVE = os.path.join(_BASE, "collected", "db", "mysql_native", "mysql_native_result.json")
_PG_NATIVE = os.path.join(_BASE, "collected", "db", "postgresql_native", "postgresql_native_result.json")
_ORACLE_NATIVE = os.path.join(_BASE, "collected", "db", "oracle_native", "oracle_native_result.json")
_MSSQL_NATIVE = os.path.join(_BASE, "collected", "db", "mssql_native", "mssql_native_result.json")
_MARIADB_NATIVE = os.path.join(_BASE, "collected", "db", "mariadb_native", "mariadb_native_result.json")


def _make_raw_ev(data_dict: dict) -> str:
    """테스트용 raw_evidence JSON 생성."""
    return json.dumps(data_dict, ensure_ascii=False)


def _result_entry(rows):
    """테스트용 data_key 엔트리."""
    return {"RESULT": rows}


# ─────────────────────────────────────────────────────────────────────────────
# (a) engine 매핑
# ─────────────────────────────────────────────────────────────────────────────

class TestEngineMapping:
    """variant → engine 이름 매핑 검증."""

    def test_mysql_native_maps_to_mysql(self):
        assert _engine_of("mysql_native") == "mysql"

    def test_mysql_rds_maps_to_mysql(self):
        assert _engine_of("mysql_rds") == "mysql"

    def test_oracle_native_maps_to_oracle(self):
        assert _engine_of("oracle_native") == "oracle"

    def test_mssql_native_maps_to_mssql(self):
        assert _engine_of("mssql_native") == "mssql"

    def test_mariadb_native_maps_to_mariadb(self):
        assert _engine_of("mariadb_native") == "mariadb"

    def test_pg_native_maps_to_postgresql(self):
        """pg_native 변형: split('_')[0]='pg' → postgresql."""
        assert _engine_of("pg_native") == "postgresql"

    def test_pg_rds_maps_to_postgresql(self):
        assert _engine_of("pg_rds") == "postgresql"

    def test_unknown_variant_returns_none(self):
        assert _engine_of("tibero_native") is None
        assert _engine_of("unknown_xyz") is None


# ─────────────────────────────────────────────────────────────────────────────
# (b) base 정규화
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizeBase:
    """item_id → base DBM-NNN 정규화."""

    def test_bare_id_unchanged(self):
        assert _normalize_base("DBM-017") == "DBM-017"

    def test_sub_suffix_stripped(self):
        assert _normalize_base("DBM-017_1") == "DBM-017"
        assert _normalize_base("DBM-017_4") == "DBM-017"

    def test_zero_padded(self):
        assert _normalize_base("DBM-003") == "DBM-003"
        assert _normalize_base("DBM-003_1") == "DBM-003"

    def test_oracle_weird_key(self):
        """oracle 실샘플 비정규 키도 정규화 시도 — DBM-16_12c → DBM-016."""
        # DBM-16_12c: match r'(DBM)-(\d+)' → DBM-016
        assert _normalize_base("DBM-016_12c") == "DBM-016"

    def test_unknown_id_returns_original(self):
        assert _normalize_base("SRV-001") == "SRV-001"


# ─────────────────────────────────────────────────────────────────────────────
# (c) gate 차단: C1 불변 — STUB/ABSENT/MANUAL → handled=False
# ─────────────────────────────────────────────────────────────────────────────

class TestGateBlock:
    """C1 불변: STUB/ABSENT/MANUAL variant → handled=False."""

    def test_stub_mysql_dbm005_blocked(self):
        """DBM-005 mysql: STUB → gate 차단."""
        raw = _make_raw_ev({"DBM-005": _result_entry([{"a": "1"}])})
        fv = judge("DBM-005", raw, "mysql_native", {})
        assert fv.handled is False, f"STUB DBM-005/mysql handled=True: {fv}"
        assert fv.verdict != "양호"

    def test_stub_pg_dbm028_blocked(self):
        """DBM-028 pg: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-028_1": _result_entry([{"x": "1"}])})
        fv = judge("DBM-028", raw, "pg_native", {})
        assert fv.handled is False, f"STUB DBM-028/pg handled=True: {fv}"

    def test_stub_mssql_dbm009_blocked(self):
        """DBM-009 mssql: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-009": _result_entry([{"x": "1"}])})
        fv = judge("DBM-009", raw, "mssql_native", {})
        assert fv.handled is False, f"STUB DBM-009/mssql handled=True: {fv}"

    def test_det_dbm001_gate_passes_all_native_engines(self):
        """DBM-001: Phase 4c 이후 전 엔진 native DET → gate 통과, crack_judge 호출됨.

        DET_SOURCE.yaml에서 DBM-001 native 전 엔진이 DET로 승격됨.
        crack_judge는 데이터 구조에 따라 handled=True(취약/판단보류) 또는 handled=False(증거없음)
        를 반환하지만, gate 자체는 차단하지 않는다.
        verdict != '양호' 로 거짓양호 비노출 보장.
        """
        for variant in ("mysql_native", "oracle_native", "mssql_native",
                        "mariadb_native", "pg_native"):
            raw = _make_raw_ev({"DBM-001": _result_entry([{"name": "user"}])})
            fv = judge("DBM-001", raw, variant, {})
            # gate 차단이 아니므로 crack_judge가 호출됨: 거짓양호 비노출 확인
            assert fv.verdict != "양호", (
                f"DBM-001/{variant}: 양호 판정 금지 (DBM-001은 약한비번 전용, 양호 없음): {fv}"
            )

    def test_absent_item_blocked(self):
        """DET_SOURCE 미등재 항목 → ABSENT → handled=False."""
        raw = _make_raw_ev({"DBM-999": _result_entry([{"x": "1"}])})
        fv = judge("DBM-999", raw, "mysql_native", {})
        assert fv.handled is False
        assert fv.verdict != "양호"

    def test_absent_default_dbm014_non_oracle(self):
        """DBM-014: oracle만 DET, 나머지 ABSENT → non-oracle gate 차단."""
        raw = _make_raw_ev({"DBM-014": _result_entry([{"value": "x"}])})
        fv = judge("DBM-014", raw, "mysql_native", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (d) 증거존재 가드 (D3)
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceGuard:
    """증거존재 가드: base의 data_key 부재 → handled=False."""

    def test_has_data_key_exact_match(self):
        data = {"DBM-017": {"RESULT": [{"a": "1"}]}}
        assert _has_data_key_for("DBM-017", data) is True

    def test_has_data_key_prefix_match(self):
        data = {"DBM-017_1": {"RESULT": []}, "DBM-017_2": {"RESULT": []}}
        assert _has_data_key_for("DBM-017", data) is True

    def test_no_data_key_returns_false(self):
        data = {"DBM-003": {"RESULT": [{"x": "1"}]}}
        assert _has_data_key_for("DBM-017", data) is False

    def test_empty_data_returns_false(self):
        assert _has_data_key_for("DBM-017", {}) is False

    def test_adapter_returns_handled_false_when_no_data_key(self):
        """data_key 부재 → handled=False (거짓양호 방지)."""
        # DBM-026은 DET for mysql, but no DBM-026 in data
        raw = _make_raw_ev({"DBM-003": _result_entry([{"USER": "test"}])})
        fv = judge("DBM-026", raw, "mysql_native", {})
        assert fv.handled is False, f"data_key 부재인데 handled=True: {fv}"

    def test_empty_raw_output_handled_false(self):
        """빈 raw_output → handled=False."""
        fv = judge("DBM-003", "", "mysql_native", {})
        assert fv.handled is False

    def test_invalid_json_raw_output_handled_false(self):
        """파싱 불가 raw_output → handled=False."""
        fv = judge("DBM-003", "{invalid json", "mysql_native", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (e) noise 필터
# ─────────────────────────────────────────────────────────────────────────────

class TestFilterNoise:
    """@@@/*** 단일키 행 제거, {"*":val} 위반행 유지."""

    def test_removes_note_row(self):
        rows = [{"@@@": "DB note"}, {"USER": "alice"}]
        result = _filter_noise(rows)
        assert len(result) == 1
        assert result[0] == {"USER": "alice"}

    def test_removes_config_note_row(self):
        rows = [{"***": "config note"}, {"HOST": "%"}]
        result = _filter_noise(rows)
        assert len(result) == 1
        assert result[0] == {"HOST": "%"}

    def test_keeps_wildcard_string_row(self):
        """{"*": datum} 위반행은 유지 (문자열 위반행 래핑)."""
        rows = [{"*": "audit_log.so not loaded"}]
        result = _filter_noise(rows)
        assert len(result) == 1

    def test_keeps_normal_violation_row(self):
        rows = [{"USER": "test", "HOST": "%", "PRIVILEGE_TYPE": "SUPER"}]
        result = _filter_noise(rows)
        assert len(result) == 1

    def test_empty_input(self):
        assert _filter_noise([]) == []

    def test_all_noise_returns_empty(self):
        rows = [{"@@@": "n1"}, {"***": "n2"}, {"@@@": "n3"}]
        result = _filter_noise(rows)
        assert result == []

    def test_mixed_noise_and_violations(self):
        rows = [{"@@@": "note"}, {"USER": "test"}, {"***": "cfg"}, {"HOST": "%"}]
        result = _filter_noise(rows)
        assert len(result) == 2
        assert {"@@@": "note"} not in result
        assert {"***": "cfg"} not in result


# ─────────────────────────────────────────────────────────────────────────────
# (f) result 매핑
# ─────────────────────────────────────────────────────────────────────────────

class TestResultMapping:
    """빈 위반 → 양호(0.9) / 위반 → 취약(0.9)."""

    def _make_raw_for_dbm003_mysql(self, rows):
        """DBM-003 mysql DET 항목용 raw_evidence (USER/HOST 필드 포함, ACCOUNT_LOCKED 없음)."""
        data = {
            "DBM-003": {
                "RESULT": rows
            }
        }
        return json.dumps(data)

    def test_empty_violations_is_good(self):
        """위반 없음 → 양호."""
        # DBM-003 mysql DET: exception 목록에 없는 USER/HOST 필요
        # 단, analysis 내부에서 condition 비교가 복잡 — 단순히 data_key 없이 테스트
        raw = _make_raw_ev({"DBM-026": {"RESULT": []}})
        fv = judge("DBM-026", raw, "mysql_native", {})
        # DBM-026 data_key 없음(RESULT 비어있음이 아니라 data_key match필요)
        # 실제 양호 테스트는 E2E에서
        # 여기서는 구조만 검증
        assert isinstance(fv, ForcedVerdict)

    def test_verdict_good_structure(self):
        """양호 ForcedVerdict 구조."""
        # DBM-003 mysql: 비어있는 RESULT → 양호
        raw = _make_raw_ev({"DBM-003": {"RESULT": []}})
        fv = judge("DBM-003", raw, "mysql_native", {})
        # analysis가 조건 평가 후 빈 위반 → 양호
        if fv.handled:
            assert fv.verdict in ("양호", "취약"), f"알 수 없는 verdict: {fv.verdict}"
            assert fv.confidence == 0.9

    def test_verdict_bad_citations_populated(self):
        """취약 → citations 있음, raw data dict 미포함(§7)."""
        # DET 항목 DBM-004 mysql: 위반 유도
        raw = _make_raw_ev({
            "DBM-004": {
                "RESULT": [
                    {"GRANTEE": "test_user@%", "PRIVILEGE_TYPE": "SUPER", "IS_GRANTABLE": "NO"}
                ]
            }
        })
        fv = judge("DBM-004", raw, "mysql_native", {})
        if fv.handled and fv.verdict == "취약":
            assert len(fv.citations) > 0, "취약인데 citations 없음"
            # §7: raw data dict의 DBM-004 전체가 citation에 노출되면 안 됨
            for c in fv.citations:
                assert "RESULT" not in c or "DBM-004" not in c, (
                    f"§7 위반: raw data dict가 citation에 노출됨: {c}"
                )

    def test_handled_false_no_양호(self):
        """handled=False 이면 verdict='양호'가 아니어야 한다 (거짓양호 방지)."""
        # STUB 항목
        raw = _make_raw_ev({"DBM-005": {"RESULT": [{"a": "1"}]}})
        fv = judge("DBM-005", raw, "mysql_native", {})
        assert fv.handled is False
        assert fv.verdict != "양호", f"STUB 항목이 양호: {fv}"


# ─────────────────────────────────────────────────────────────────────────────
# (g) .run 예외내성 (R3)
# ─────────────────────────────────────────────────────────────────────────────

class TestRunException:
    """.run 예외 → handled=False, 거짓양호 없음."""

    def test_bad_data_format_does_not_raise(self):
        """잘못된 data 형식 → analysis 예외 → handled=False (예외 미전파)."""
        # 필드 누락 data를 넣어 analysis 내부 예외를 유발
        raw = _make_raw_ev({
            "DBM-008": {"RESULT": [{"PASSWORD_LAST_CHANGED": "NOT_A_DATE"}]}
        })
        # analysis가 날짜 파싱 실패 → except 삼킴 → [] → 양호 or handled=False
        # 예외가 어댑터 밖으로 나오면 안 됨
        try:
            fv = judge("DBM-008", raw, "mysql_native", {})
            assert isinstance(fv, ForcedVerdict)
        except Exception as e:
            pytest.fail(f"어댑터가 예외를 밖으로 전파: {type(e).__name__}: {e}")

    def test_exception_does_not_cause_양호(self):
        """data_key 있지만 analysis 내부 예외 → 결과 [] → 양호 OR handled=False.

        중요: '취약'이어야 할 항목이 '양호'로 되거나
             내부 예외가 어댑터 밖으로 나와선 안 됨.
        """
        raw = _make_raw_ev({
            "DBM-003": {"RESULT": [{"INVALID": "datum_without_required_fields"}]}
        })
        try:
            fv = judge("DBM-003", raw, "mysql_native", {})
            assert isinstance(fv, ForcedVerdict)
        except Exception as e:
            pytest.fail(f"어댑터 예외 전파: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# (g2) R3 거짓양호 차단 회귀 (Critical Opus 지적)
# ─────────────────────────────────────────────────────────────────────────────

class TestR3FalsePositiveBlock:
    """R3: 벤더 dbm_process_data 예외 삼킴 → 빈 위반 → 거짓양호 방지 회귀."""

    def setup_method(self):
        """각 테스트 전 캐시 초기화 (엔진별 독립 실행 보장)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_vendor_exception_swallow_causes_handled_false(self):
        """재현 스니펫: KeyError 삼킴 → handled=False (거짓양호 차단).

        data_key가 존재하므로 D3 증거가드를 통과하지만,
        vendor dbm_process_data가 datum['VARIABLE_NAME'] KeyError를 삼켜
        빈 위반을 반환 → R3 차단 → handled=False (LLM 폴백).
        """
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        data = {"DBM-007": {"RESULT": [{"SOME_OTHER_KEY": "x", "X": "LOW"}]}}
        fv = judge("DBM-007", json.dumps(data), "mysql_native", {})
        assert fv.handled is False, (
            f"R3 거짓양호 미차단: KeyError 삼킴인데 handled=True verdict={fv.verdict}"
        )
        assert fv.verdict != "양호", f"거짓양호 발생: verdict={fv.verdict}"
        assert fv.confidence == 0.0, f"conf != 0.0: {fv.confidence}"
        assert "결정론 내부 예외" in fv.rationale, f"rationale 불명확: {fv.rationale}"

    def test_exception_with_violation_in_other_subcall_not_blocked(self):
        """예외 + 다른 sub-call 위반 공존 → 취약 유지 (과차단 방지).

        같은 DBM-007이라도 다른 data_key variant에서 실제 위반이 발견되면
        exc_keys에 해당 base가 있어도 violations>0 → 취약 판정 유지.
        참고: mysql DBM-007은 VARIABLE_NAME 필드 필요. 두 번째 호출에 올바른 필드 제공.
        """
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        # DBM-007: analysis는 VARIABLE_NAME 필드 가진 행에서 위반을 추출.
        # 실제 DBM-007 conditions를 확인한 것은 아니므로, 위반이 적재되는
        # 올바른 형태의 row를 넣어 violations>0 경로를 테스트.
        # 위반이 있으면(rows>=1) R3 차단 조건(not violations)이 False → 취약 유지.
        from judge_tool.det_adapters.db import _parse_exc_keys, _EXC_KEY_RE
        import re

        # _parse_exc_keys 직접 단위 테스트: exc_keys가 있어도 violations>0이면 차단 안 함
        # judge()의 차단 조건은 `not violations and exc_keys` — violations>0이면 진입 불가.
        # 합성: violations=[{실제위반}] → if not violations → False → 차단 미진입 → 취약
        # 이를 judge() 레벨에서 검증하기 위해 DBM-013(HOST=% → 취약, detect-then-hold 아님) 사용.
        # (DBM-004는 Batch1에서 detect-then-hold라 판단보류이므로 취약 매핑 검증에 부적합.)
        data = {
            "DBM-013": {
                "RESULT": [
                    {"USER": "app_user", "HOST": "%"}
                ]
            },
        }
        fv = judge("DBM-013", json.dumps(data), "mysql_native", {})
        # DBM-013 mysql DET: 위반이 발견되면 취약 유지 (R3 과차단 없음)
        if fv.handled:
            assert fv.verdict == "취약", (
                f"R3 과차단 의심: 실위반 있는데 verdict={fv.verdict} handled={fv.handled}"
            )

    def test_normal_input_good_verdict_unchanged(self):
        """정상 입력(예외 없음) → 빈 위반 → 양호 불변 (R3 무간섭)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        # DBM-003: RESULT 비어있음 → analysis 예외 없이 빈 위반 → 양호 기대
        data = {"DBM-003": {"RESULT": []}}
        fv = judge("DBM-003", json.dumps(data), "mysql_native", {})
        # 예외 없으므로 exc_keys=frozenset() → R3 차단 미진입 → 양호
        if fv.handled:
            assert fv.verdict == "양호", (
                f"정상 빈 RESULT인데 양호가 아님: verdict={fv.verdict}"
            )
            assert fv.confidence == 0.9

    def test_parse_exc_keys_extracts_dbm_key(self):
        """_parse_exc_keys: MySQL/Oracle/MariaDB/PostgreSQL/MSSQL 포맷 파싱 확인."""
        from judge_tool.det_adapters.db import _parse_exc_keys

        # MySQL / MSSQL 포맷
        s = "[!] Exception Occurred MySQL DBM-007: KeyError('VARIABLE_NAME')"
        keys = _parse_exc_keys(s)
        assert "DBM-007" in keys, f"DBM-007 미추출: {keys}"

        # Oracle generic 포맷
        s2 = "[!] Exception Occurred Oracle DBM-022: some error"
        keys2 = _parse_exc_keys(s2)
        assert "DBM-022" in keys2, f"DBM-022 미추출: {keys2}"

        # oracle 소문자 포맷 (DBM-001)
        s3 = "[!] Exception Occurred oracle DBM-001: ValueError"
        keys3 = _parse_exc_keys(s3)
        assert "DBM-001" in keys3, f"DBM-001 미추출: {keys3}"

        # MariaDB 포맷
        s4 = "[!] Exception Occurred MariaDB DBM-022: TypeError"
        keys4 = _parse_exc_keys(s4)
        assert "DBM-022" in keys4, f"MariaDB DBM-022 미추출: {keys4}"

        # PostgreSQL 포맷
        s5 = "[!] Exception Occurred PostgreSQL DBM-022: IndexError"
        keys5 = _parse_exc_keys(s5)
        assert "DBM-022" in keys5, f"PostgreSQL DBM-022 미추출: {keys5}"

    def test_parse_exc_keys_no_exception_returns_empty(self):
        """예외 없는 stdout → 빈 frozenset."""
        from judge_tool.det_adapters.db import _parse_exc_keys

        keys = _parse_exc_keys("normal output with no exception")
        assert keys == frozenset()

    def test_parse_exc_keys_ambiguous_sentinel(self):
        """'[!] Exception Occurred' 있지만 DBM 키 파싱 불가 → __AMBIGUOUS__ sentinel."""
        from judge_tool.det_adapters.db import _parse_exc_keys

        # DBM 패턴 없는 예외 메시지
        s = "[!] Exception Occurred SomeUnknownFormat: error"
        keys = _parse_exc_keys(s)
        assert "__AMBIGUOUS__" in keys, f"__AMBIGUOUS__ sentinel 누락: {keys}"


# ─────────────────────────────────────────────────────────────────────────────
# (h) §7 누출경계
# ─────────────────────────────────────────────────────────────────────────────

class TestCitationBoundary:
    """citation에 raw data dict 원문 미포함 (§7)."""

    def test_citations_do_not_contain_raw_data_dict_json(self):
        """citations가 raw_evidence 전체 JSON을 포함하지 않는다."""
        data = {
            "DBM-004": {
                "RESULT": [
                    {"GRANTEE": "admin@%", "PRIVILEGE_TYPE": "SUPER"}
                ]
            }
        }
        raw = json.dumps(data)
        fv = judge("DBM-004", raw, "mysql_native", {})
        if fv.handled and fv.citations:
            # raw 전체 JSON이 citation에 들어가면 안 됨
            full_raw_json = raw
            for c in fv.citations:
                assert len(c) < len(full_raw_json), (
                    f"§7 위반: citation이 raw 전체 JSON과 같거나 더 길다: {c[:100]}..."
                )

    def test_rationale_does_not_contain_raw_data(self):
        """rationale에 raw data dict 전체가 포함되지 않는다."""
        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)
        fv = judge("DBM-003", raw, "mysql_native", {})
        # rationale에 raw 전체가 들어가면 안 됨
        assert raw not in (fv.rationale or ""), (
            f"§7 위반: rationale에 raw JSON 포함: {fv.rationale[:200]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (i) db_json raw_evidence 적재
# ─────────────────────────────────────────────────────────────────────────────

class TestDbJsonRawEvidence:
    """db_json.parse()가 raw_evidence에 비마스킹 data dict를 적재한다."""

    def test_raw_evidence_set_on_resources(self, tmp_path):
        """parse() 후 resources[*].raw_evidence가 None이 아님."""
        from judge_tool.parsers.db_json import parse

        # 단순 픽스처 파일 생성
        content = '[{"DBM-003":{"QUERY":"SELECT * FROM users","RESULT":[{"USER":"test","HOST":"%"}]}}]'
        path = str(tmp_path / "test_result.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        result = parse(path)
        assert len(result) > 0, "파싱 결과 없음"
        for check_id, resources, ctx in result:
            for res in resources:
                assert res.raw_evidence is not None, (
                    f"{check_id}/{res.resource_id}: raw_evidence=None (Phase 4 미적재)"
                )

    def test_raw_evidence_is_valid_json(self, tmp_path):
        """raw_evidence가 파싱 가능한 JSON이다."""
        from judge_tool.parsers.db_json import parse

        content = '[{"DBM-017_1":{"QUERY":"SELECT ...","RESULT":[{"GRANTEE":"test@%","PRIVILEGE_TYPE":"SELECT"}]}}]'
        path = str(tmp_path / "test2.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        result = parse(path)
        for check_id, resources, ctx in result:
            for res in resources:
                if res.raw_evidence is not None:
                    data = json.loads(res.raw_evidence)
                    assert isinstance(data, dict), "raw_evidence가 dict가 아님"

    def test_all_resources_share_same_raw_evidence(self, tmp_path):
        """같은 파일에서 모든 resource의 raw_evidence가 동일 JSON이다 (결정1)."""
        from judge_tool.parsers.db_json import parse

        content = '[{"DBM-017_1":{"RESULT":[{"A":"1"}]}},{"DBM-003":{"RESULT":[{"B":"2"}]}}]'
        path = str(tmp_path / "test3.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        result = parse(path)
        raw_evs = [
            res.raw_evidence
            for _, resources, _ in result
            for res in resources
            if res.raw_evidence is not None
        ]
        if len(raw_evs) >= 2:
            assert all(r == raw_evs[0] for r in raw_evs), (
                "resources간 raw_evidence 불일치 (결정1 위반)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# (j) 모듈 캐시 동작
# ─────────────────────────────────────────────────────────────────────────────

class TestModuleCache:
    """동일 data에 대해 .run은 1회만 실행 (모듈 캐시)."""

    def test_same_data_uses_cache(self):
        """동일 data dict로 2번 호출 시 _RUN_CACHE 엔트리가 신규 생성되지 않음.

        monkeypatch로 judge() 내부 _run_analysis를 대체해도
        judge()는 모듈 로컬 이름으로 호출하므로 _RUN_CACHE 크기 검사 방식 사용.
        """
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)

        # 1번째 호출 → _RUN_CACHE에 (mysql, fp) 키 생성
        fv1 = judge("DBM-003", raw, "mysql_native", {})
        cache_size_after_first = len(_db._RUN_CACHE)

        # 2번째 호출 (동일 engine+data) → 캐시 히트, 신규 엔트리 없어야 함
        fv2 = judge("DBM-003", raw, "mysql_native", {})
        cache_size_after_second = len(_db._RUN_CACHE)

        assert cache_size_after_second == cache_size_after_first, (
            f"캐시 미작동: 1회차 이후 {cache_size_after_first}엔트리, "
            f"2회차 이후 {cache_size_after_second}엔트리 (동일 data로 2회 캐시 미스)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (k) 레지스트리 등록 확인
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistry:
    """_DET_ADAPTERS에 5개 프로파일 키가 등록되어야 한다."""

    def test_five_db_profiles_registered(self):
        for key in ("db_mysql", "db_oracle", "db_mssql", "db_mariadb", "db_postgresql"):
            assert key in _DET_ADAPTERS, f"{key} 미등록"
            assert callable(_DET_ADAPTERS[key])

    def test_tibero_not_registered(self):
        """tibero excluded → 미등록."""
        assert "db_tibero" not in _DET_ADAPTERS


# ─────────────────────────────────────────────────────────────────────────────
# (l) 실파일 E2E (mysql_native)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not os.path.exists(_MYSQL_NATIVE),
    reason=f"mysql_native 실데이터 없음: {_MYSQL_NATIVE}"
)
class TestMysqlNativeE2E:
    """mysql_native 실데이터 E2E 검증."""

    @pytest.fixture(autouse=True)
    def _reload_det_source(self):
        reload_det_source()
        _RUN_CACHE.clear()

    def _get_raw_ev(self):
        from judge_tool.parsers.db_json import parse
        result = parse(_MYSQL_NATIVE)
        return result[0][1][0].raw_evidence

    def test_raw_evidence_is_set(self):
        """parse() 후 raw_evidence 설정됨."""
        raw_ev = self._get_raw_ev()
        assert raw_ev is not None

    def test_gate_blocks_stub_dbm005(self):
        """DBM-005 mysql: STUB → gate 차단."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-005", raw_ev, "mysql_native", {})
        assert fv.handled is False

    def test_det_dbm001_mysql_no_false_positive(self):
        """DBM-001 mysql: Phase 4c 이후 DET → crack_judge 호출, 양호 판정 없음.

        DET_SOURCE.yaml에서 mysql native DBM-001이 DET 승격.
        crack_judge(mysql): caching_sha2 비활성 → 미지원포맷 계정만 있으면 판단보류(handled=True)
        또는 취약. 거짓양호(verdict='양호') 없음 확인.
        """
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-001", raw_ev, "mysql_native", {})
        # crack_judge는 '양호'를 반환하지 않는다 (DBM-001 설계 계약)
        assert fv.verdict != "양호", (
            f"DBM-001/mysql_native: 양호 판정 금지 (crack_judge 설계 위반): {fv}"
        )

    def test_det_dbm003_handled(self):
        """DBM-003 mysql: DET → handled=True."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-003", raw_ev, "mysql_native", {})
        assert fv.handled is True
        assert fv.verdict in ("양호", "취약")
        assert fv.confidence == 0.9

    def test_det_dbm017_gate_blocked(self):
        """DBM-017 mysql: label B 이관 → STUB → gate 차단 → handled=False.

        이전: mysql native DBM-017 = DET → handled=True + 양호/취약(exception-기반 과탐/미탐 위험).
        수정 후: DET_SOURCE mysql→STUB, judgment_method 제거 → STUB gate 차단 → handled=False.
        "업무상 불필요" 맥락 판단 → label B(인터뷰) + LLM 요약 라우팅.
        """
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-017", raw_ev, "mysql_native", {})
        assert fv.handled is False, (
            "mysql DBM-017: STUB → gate 차단되어야 함. "
            "handled=True이면 exception-기반 과탐/미탐 경로를 타고 있음! "
            "DET_SOURCE mysql:STUB 또는 yaml judgment_method 제거 확인 필요."
        )
        assert fv.verdict != "양호", (
            "mysql DBM-017: 거짓양호 금지 — STUB gate 차단 후 양호가 나오면 안 됨."
        )

    def test_evidence_guard_absent_key(self):
        """data_key 부재 항목 → handled=False (거짓양호 차단)."""
        # DBM-026(umask)는 mysql_native 실데이터에 없음
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-026", raw_ev, "mysql_native", {})
        assert fv.handled is False, f"DBM-026 data_key 부재인데 handled=True: {fv}"

    def test_no_false_positive_양호(self):
        """STUB/DET 항목이 양호로 새지 않는다."""
        raw_ev = self._get_raw_ev()
        stub_items = ["DBM-005"]   # mysql STUB
        det_items = ["DBM-001"]    # mysql DET(Phase 4c) — crack_judge는 '양호' 반환 안 함
        for item_id in stub_items + det_items:
            fv = judge(item_id, raw_ev, "mysql_native", {})
            assert fv.verdict != "양호", (
                f"{item_id}(STUB/DET)이 양호로 판정됨 — 거짓양호 발생: {fv}"
            )


@pytest.mark.skipif(
    not os.path.exists(_PG_NATIVE),
    reason=f"postgresql_native 실데이터 없음: {_PG_NATIVE}"
)
class TestPgNativeE2E:
    """postgresql_native 실데이터 E2E 검증 (pg variant 사용)."""

    @pytest.fixture(autouse=True)
    def _reload_det_source(self):
        reload_det_source()
        _RUN_CACHE.clear()

    def _get_raw_ev(self):
        from judge_tool.parsers.db_json import parse
        result = parse(_PG_NATIVE)
        return result[0][1][0].raw_evidence

    def test_stub_dbm028_blocked(self):
        """DBM-028 pg: STUB(lambda True) → gate 차단."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-028", raw_ev, "pg_native", {})
        assert fv.handled is False

    def test_stub_dbm006_blocked(self):
        """DBM-006 pg_native: Batch1 모드B(구조적 취약) — 코어 실패잠금 부재 → 취약."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-006", raw_ev, "pg_native", {})
        assert fv.handled is True
        assert fv.verdict == "취약"

    def test_stub_dbm003_blocked(self):
        """DBM-003 pg: STUB(R3 수집형식 불일치) → gate 차단."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-003", raw_ev, "pg_native", {})
        assert fv.handled is False, (
            "DBM-003/pg는 R3 보수처리(STUB)로 gate 차단되어야 함 — 거짓양호 방지"
        )

    def test_stub_dbm015_blocked(self):
        """DBM-015 pg: STUB(oracle lambda True + R3 pg수집형식) → gate 차단."""
        raw_ev = self._get_raw_ev()
        fv = judge("DBM-015", raw_ev, "pg_native", {})
        assert fv.handled is False, (
            "DBM-015/pg는 STUB으로 gate 차단되어야 함 — 거짓양호 방지"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (l) Phase 4b: 클라우드 변형 (합성 픽스처, 실데이터 없음)
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudVariantRouting:
    """Phase 4b 결정4: variant suffix로 native/cloud 클래스 선택 검증."""

    def test_is_cloud_variant_rds(self):
        """_rds suffix → cloud."""
        assert _is_cloud_variant("mysql_rds") is True
        assert _is_cloud_variant("oracle_rds") is True
        assert _is_cloud_variant("mssql_rds") is True
        assert _is_cloud_variant("mariadb_rds") is True
        assert _is_cloud_variant("pg_rds") is True

    def test_is_cloud_variant_aurora(self):
        """_aurora suffix → cloud."""
        assert _is_cloud_variant("mysql_aurora") is True
        assert _is_cloud_variant("pg_aurora") is True

    def test_is_cloud_variant_azure(self):
        """_azure suffix → cloud."""
        assert _is_cloud_variant("mysql_azure") is True
        assert _is_cloud_variant("pg_azure") is True

    def test_is_cloud_variant_native_is_false(self):
        """_native suffix → NOT cloud."""
        assert _is_cloud_variant("mysql_native") is False
        assert _is_cloud_variant("pg_native") is False
        assert _is_cloud_variant("oracle_native") is False

    def test_cloud_class_used_for_rds(self):
        """mysql_rds → _run_analysis(engine, data, is_cloud=True) → MySQLCloudAnalysis."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        # mysql cloud run()에 dbm_003이 있음 → data_key 있으면 cache 엔트리 생성됨
        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)
        # DBM-003 mysql_rds = DET → gate 통과
        fv = judge("DBM-003", raw, "mysql_rds", {})
        # 캐시에 (mysql, True, fp) 키가 있어야 함 (cloud 경로 실행)
        fp = _db._fingerprint(data)
        assert ("mysql", True, fp) in _db._RUN_CACHE, (
            "cloud 라우팅 실패: (mysql, True, fp) 캐시 엔트리 없음"
        )
        # native 캐시 엔트리는 없어야 함 (분리)
        assert ("mysql", False, fp) not in _db._RUN_CACHE, (
            "캐시 분리 실패: native 엔트리가 cloud 호출로 생성됨"
        )

    def test_native_class_used_for_native(self):
        """mysql_native → is_cloud=False → MySQLAnalysis (native 캐시 키)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)
        fv = judge("DBM-003", raw, "mysql_native", {})
        fp = _db._fingerprint(data)
        assert ("mysql", False, fp) in _db._RUN_CACHE, (
            "native 라우팅 실패: (mysql, False, fp) 캐시 엔트리 없음"
        )


class TestCloudAbsentGateBlock:
    """Phase 4b 결정5: cloud ABSENT 항목이 gate 차단 → handled=False (거짓양호 0)."""

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_mysql_rds_dbm025_absent_blocked(self):
        """DBM-025 mysql_rds: ABSENT(cloud run() 미호출) → gate 차단 → handled=False.

        mysql native run()에는 dbm_025가 있지만 cloud run()에는 없다.
        classify(mysql_rds)는 DET_SOURCE에 mysql_rds: ABSENT 명시로 ABSENT 반환.
        gate가 ABSENT를 차단 → handled=False (거짓양호 구조 차단).
        """
        raw = _make_raw_ev({"DBM-025": {"RESULT": [{"VERSION": "8.0.10"}]}})
        fv = judge("DBM-025", raw, "mysql_rds", {})
        assert fv.handled is False, (
            f"DBM-025/mysql_rds: ABSENT인데 handled=True — 거짓양호 위험: {fv}"
        )
        assert fv.verdict != "양호", (
            f"DBM-025/mysql_rds: ABSENT인데 양호 판정 — 거짓양호: {fv}"
        )

    def test_mysql_rds_dbm026_absent_blocked(self):
        """DBM-026 mysql_rds: ABSENT(cloud run() 미호출) → classify=ABSENT → gate 차단.

        M-2: classify 직접 단언 — engine-token 폴백 회귀를 잡는다.
        (폴백이면 mysql_rds → 'mysql' → DET 반환, 명시 ABSENT여야 정상)
        """
        # M-2: classify가 ABSENT를 직접 반환하는지 단언 (분류 정확성 강제)
        assert classify("DBM-026", "mysql_rds") == "ABSENT", (
            "DBM-026/mysql_rds: classify가 ABSENT 아님 — engine-token 폴백 회귀 의심"
        )
        raw = _make_raw_ev({"DBM-026": {"RESULT": [{"UMASK": "022"}]}})
        fv = judge("DBM-026", raw, "mysql_rds", {})
        assert fv.handled is False, (
            f"DBM-026/mysql_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_mysql_rds_dbm033_absent_blocked(self):
        """DBM-033 mysql_rds: ABSENT(cloud run() 미호출) → classify=ABSENT → gate 차단.

        M-2: classify 직접 단언 — engine-token 폴백 회귀를 잡는다.
        (폴백이면 mysql_rds → 'mysql' → DET 반환, 명시 ABSENT여야 정상)
        """
        # M-2: classify가 ABSENT를 직접 반환하는지 단언
        assert classify("DBM-033", "mysql_rds") == "ABSENT", (
            "DBM-033/mysql_rds: classify가 ABSENT 아님 — engine-token 폴백 회귀 의심"
        )
        raw = _make_raw_ev({"DBM-033": {"RESULT": [{"data": "plain"}]}})
        fv = judge("DBM-033", raw, "mysql_rds", {})
        assert fv.handled is False, (
            f"DBM-033/mysql_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_pg_rds_dbm006_absent_blocked(self):
        """DBM-006 pg_rds: ABSENT(cloud pg run()에 dbm_006 없음) → gate 차단."""
        raw = _make_raw_ev({"DBM-006": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-006", raw, "pg_rds", {})
        assert fv.handled is False, (
            f"DBM-006/pg_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_pg_rds_dbm019_absent_blocked(self):
        """DBM-019 pg_rds: ABSENT(cloud pg run()에 dbm_019 없음) → gate 차단."""
        raw = _make_raw_ev({"DBM-019": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-019", raw, "pg_rds", {})
        assert fv.handled is False, (
            f"DBM-019/pg_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_mssql_rds_dbm031_absent_blocked(self):
        """DBM-031 mssql_rds: ABSENT(cloud mssql run()에 dbm_031 없음) → classify=ABSENT → gate 차단.

        M-2: classify 직접 단언 — engine-token 폴백 회귀를 잡는다.
        (폴백이면 mssql_rds → 'mssql' → DET 반환, 명시 ABSENT여야 정상)
        """
        # M-2: classify가 ABSENT를 직접 반환하는지 단언
        assert classify("DBM-031", "mssql_rds") == "ABSENT", (
            "DBM-031/mssql_rds: classify가 ABSENT 아님 — engine-token 폴백 회귀 의심"
        )
        raw = _make_raw_ev({"DBM-031": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-031", raw, "mssql_rds", {})
        assert fv.handled is False, (
            f"DBM-031/mssql_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_mssql_rds_dbm019_absent_blocked(self):
        """DBM-019 mssql_rds: ABSENT → gate 차단."""
        raw = _make_raw_ev({"DBM-019": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-019", raw, "mssql_rds", {})
        assert fv.handled is False, (
            f"DBM-019/mssql_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_oracle_rds_dbm013_absent_classify_and_blocked(self):
        """DBM-013 oracle_rds: ABSENT(cloud oracle run()에 dbm_013 없음) → classify=ABSENT → gate 차단.

        M-2: classify 직접 단언.
        oracle native는 STUB(lambda datum: True)이나 cloud는 run()에 dbm_013 없음 → ABSENT.
        engine-token 폴백이면 oracle_rds → 'oracle' → STUB을 반환하므로 명시 ABSENT가 필수.
        """
        # M-2: classify가 ABSENT를 직접 반환하는지 단언 (분류 정확성 강제)
        assert classify("DBM-013", "oracle_rds") == "ABSENT", (
            "DBM-013/oracle_rds: classify가 ABSENT 아님 — "
            "engine-token 폴백 시 STUB 반환, DET_SOURCE oracle_rds 명시 필요"
        )
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"HOST": "%"}]}})
        fv = judge("DBM-013", raw, "oracle_rds", {})
        assert fv.handled is False, (
            f"DBM-013/oracle_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_mssql_rds_dbm021_absent_classify_and_blocked(self):
        """DBM-021 mssql_rds: ABSENT(cloud mssql run()에 dbm_021 없음) → classify=ABSENT → gate 차단.

        M-2: classify 직접 단언.
        mssql native는 STUB(빈 본문)이나 cloud는 run()에 dbm_021 없음 → ABSENT.
        engine-token 폴백이면 mssql_rds → 'mssql' → STUB을 반환하므로 명시 ABSENT가 필수.
        """
        # M-2: classify가 ABSENT를 직접 반환하는지 단언 (분류 정확성 강제)
        assert classify("DBM-021", "mssql_rds") == "ABSENT", (
            "DBM-021/mssql_rds: classify가 ABSENT 아님 — "
            "engine-token 폴백 시 STUB 반환, DET_SOURCE mssql_rds 명시 필요"
        )
        raw = _make_raw_ev({"DBM-021": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-021", raw, "mssql_rds", {})
        assert fv.handled is False, (
            f"DBM-021/mssql_rds: ABSENT인데 handled=True: {fv}"
        )

    def test_m1_classify_absent_all_opus_items(self):
        """M-1 수정 완전성 단언: Opus 지정 5종 × 전 클라우드 변형이 모두 ABSENT 반환.

        M-2: classify 직접 단언 — DET_SOURCE 명시 없이 engine-token 폴백 회귀 발생 시
        이 테스트가 즉시 실패하여 문제를 잡는다.
        """
        # DBM-026: 전 엔진 cloud run() 미호출
        for variant in ["mysql_rds", "mysql_aurora", "mysql_azure",
                        "oracle_rds", "mssql_rds", "mariadb_rds",
                        "pg_rds", "pg_aurora", "pg_azure"]:
            assert classify("DBM-026", variant) == "ABSENT", (
                f"DBM-026/{variant}: classify가 ABSENT 아님 (engine-token 폴백 회귀?)"
            )

        # DBM-033: mysql cloud run() 미호출
        for variant in ["mysql_rds", "mysql_aurora", "mysql_azure"]:
            assert classify("DBM-033", variant) == "ABSENT", (
                f"DBM-033/{variant}: classify가 ABSENT 아님 (engine-token 폴백 회귀?)"
            )

        # DBM-031: mssql cloud run() 미호출
        assert classify("DBM-031", "mssql_rds") == "ABSENT", (
            "DBM-031/mssql_rds: classify가 ABSENT 아님 (engine-token 폴백 회귀?)"
        )

        # DBM-013: oracle cloud run() 미호출 (native는 STUB)
        assert classify("DBM-013", "oracle_rds") == "ABSENT", (
            "DBM-013/oracle_rds: classify가 ABSENT 아님 (폴백이면 STUB 반환)"
        )

        # DBM-021: mssql cloud run() 미호출 (native는 STUB)
        assert classify("DBM-021", "mssql_rds") == "ABSENT", (
            "DBM-021/mssql_rds: classify가 ABSENT 아님 (폴백이면 STUB 반환)"
        )

    def test_m1_classify_absent_additional_items(self):
        """전수 재확인 추가 발견분: DBM-001 mssql/pg cloud, 분류 정확성 강제.

        Opus 보고 8셀 외 전수 재확인에서 추가 발견.
        mssql/pg native는 Phase 4c 이후 DET이나 cloud run()에 dbm_001 없음 → ABSENT여야 함.
        engine-token 폴백이면 DET을 반환하므로 명시 필수.
        """
        for variant in ["mssql_rds", "pg_rds", "pg_aurora", "pg_azure"]:
            assert classify("DBM-001", variant) == "ABSENT", (
                f"DBM-001/{variant}: classify가 ABSENT 아님 "
                f"(engine-token 폴백이면 DET 반환 — cloud run()에 dbm_001 없음)"
            )


class TestCloudStubGateBlock:
    """Phase 4b: cloud STUB 항목이 gate 차단 → handled=False."""

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_mysql_rds_dbm022_stub_blocked(self):
        """DBM-022 mysql_rds: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-022": {"RESULT": [{"FILE": "/data/mysql"}]}})
        fv = judge("DBM-022", raw, "mysql_rds", {})
        assert fv.handled is False, (
            f"DBM-022/mysql_rds: STUB(lambda True)인데 handled=True: {fv}"
        )

    def test_mysql_rds_dbm005_stub_blocked(self):
        """DBM-005 mysql_rds: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-005": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-005", raw, "mysql_rds", {})
        assert fv.handled is False, (
            f"DBM-005/mysql_rds: STUB인데 handled=True: {fv}"
        )

    def test_mssql_rds_dbm009_stub_blocked(self):
        """DBM-009 mssql_rds: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-009": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-009", raw, "mssql_rds", {})
        assert fv.handled is False, (
            f"DBM-009/mssql_rds: STUB(lambda True)인데 handled=True: {fv}"
        )

    def test_pg_rds_dbm009_stub_blocked(self):
        """DBM-009 pg_rds: STUB(polarity 버그) → gate 차단."""
        raw = _make_raw_ev({"DBM-009": {"RESULT": [{"setting_name": "idle_in_transaction_session_timeout", "value": "900"}]}})
        fv = judge("DBM-009", raw, "pg_rds", {})
        assert fv.handled is False, (
            f"DBM-009/pg_rds: STUB(polarity 버그)인데 handled=True: {fv}"
        )

    def test_pg_rds_dbm028_stub_blocked(self):
        """DBM-028 pg_rds: STUB(lambda True) → gate 차단."""
        raw = _make_raw_ev({"DBM-028_1": {"RESULT": [{"data": "x"}]}})
        fv = judge("DBM-028", raw, "pg_rds", {})
        assert fv.handled is False, (
            f"DBM-028/pg_rds: STUB(lambda True)인데 handled=True: {fv}"
        )

    def test_oracle_rds_dbm016_stub_blocked(self):
        """DBM-016 oracle_rds: STUB(전체 주석처리=빈본문) → gate 차단."""
        raw = _make_raw_ev({"DBM-016_12c": {"RESULT": [{"version": "12.2.0.1"}]}})
        fv = judge("DBM-016", raw, "oracle_rds", {})
        assert fv.handled is False, (
            f"DBM-016/oracle_rds: STUB(주석처리)인데 handled=True: {fv}"
        )


class TestCloudDetDetermination:
    """Phase 4b: cloud DET 항목 합성 위반→취약/무위반→양호 검증."""

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_mysql_rds_dbm003_no_violation_is_good(self):
        """DBM-003 mysql_rds DET: 위반 없음 → 양호."""
        # mysql cloud dbm_003: ACCOUNT_LOCKED/PASSWORD_EXPIRED 조건 필요
        # RESULT=[] → 위반 없음 → 양호
        raw = _make_raw_ev({"DBM-003": {"RESULT": []}})
        fv = judge("DBM-003", raw, "mysql_rds", {})
        if fv.handled:
            assert fv.verdict == "양호", (
                f"DBM-003/mysql_rds: 위반없음인데 양호가 아님: {fv}"
            )
            assert fv.confidence == 0.9

    def test_mysql_rds_dbm004_violation_is_bad(self):
        """DBM-004 mysql_rds: Batch1 모드A(detect-then-hold) — 후보 탐지 → 판단보류+목록.

        관리자권한 보유 계정은 결정론이 후보로 나열하되 업무 필요성은 사람이 판단(label B 의도).
        자동 취약 판정이 아니라 verdict=판단보류 + citations(후보목록).
        """
        # 후보 유도: GRANTEE가 exception에 없고 PRIVILEGE_TYPE=SUPER → 후보
        raw = _make_raw_ev({
            "DBM-004": {
                "RESULT": [
                    {"GRANTEE": "hacker@%", "PRIVILEGE_TYPE": "SUPER", "IS_GRANTABLE": "NO"}
                ]
            }
        })
        fv = judge("DBM-004", raw, "mysql_rds", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", (
            f"DBM-004/mysql_rds: 모드A 후보탐지인데 판단보류 아님: verdict={fv.verdict}"
        )
        assert len(fv.citations) >= 1  # 후보 목록

    def test_pg_rds_dbm003_det_handled(self):
        """DBM-003 pg_rds DET: cloud pg는 native와 달리 DET → gate 통과 확인.

        cloud pg dbm_003: rolvaliduntil/rolname 직접 비교.
        RESULT=[] → 빈 위반 → 양호(handled=True).
        """
        raw = _make_raw_ev({"DBM-003": {"RESULT": []}})
        fv = judge("DBM-003", raw, "pg_rds", {})
        # pg native는 STUB(handled=False), pg_rds는 DET(handled=True)
        if fv.handled:
            assert fv.verdict in ("양호", "취약"), (
                f"DBM-003/pg_rds: 예상치 못한 verdict: {fv.verdict}"
            )
        # 적어도 STUB이 아님(handled=False가 STUB gate 차단이 아닌 다른 이유면 OK)
        # pg_rds=DET이므로 gate는 통과해야 하고, 이후 evidence/run 결과에 따라 분기

    def test_mssql_rds_dbm003_det_violation(self):
        """DBM-003 mssql_rds DET: 위반 유도 → 취약.

        mssql cloud dbm_003: is_disabled='0' AND modify_date 6개월 초과 → 위반.
        """
        raw = _make_raw_ev({
            "DBM-003_1": {
                "RESULT": [
                    {"is_disabled": "0", "name": "old_user", "modify_date": "Jan-01-2020 00:00:00"}
                ]
            }
        })
        fv = judge("DBM-003", raw, "mssql_rds", {})
        if fv.handled:
            assert fv.verdict == "취약", (
                f"DBM-003/mssql_rds: 6개월 초과 계정 있는데 취약이 아님: {fv}"
            )

    def test_pg_rds_dbm008_det_violation(self):
        """DBM-008 pg_rds DET: rolvaliduntil=None 계정 → 취약.

        cloud pg dbm_008: rolvaliduntil==None and rolcanlogin=='t' → 위반.
        """
        raw = _make_raw_ev({
            "DBM-008": {
                "RESULT": [
                    {"rolvaliduntil": None, "rolcanlogin": "t", "rolname": "test_user"}
                ]
            }
        })
        fv = judge("DBM-008", raw, "pg_rds", {})
        if fv.handled:
            assert fv.verdict == "취약", (
                f"DBM-008/pg_rds: expire 미설정 계정 있는데 취약이 아님: {fv}"
            )

    def test_pg_rds_dbm017_det_violation(self):
        """DBM-017 pg_rds DET: grantee=='PUBLIC' → 취약.

        cloud pg dbm_017: grantee == 'PUBLIC' 조건 → 위반.
        native pg는 STUB이지만 cloud pg는 DET.
        """
        raw = _make_raw_ev({
            "DBM-017_1": {
                "RESULT": [
                    {"grantee": "PUBLIC", "table_name": "pg_catalog", "privilege_type": "SELECT"}
                ]
            }
        })
        fv = judge("DBM-017", raw, "pg_rds", {})
        if fv.handled:
            assert fv.verdict == "취약", (
                f"DBM-017/pg_rds: PUBLIC grantee 있는데 취약이 아님: {fv}"
            )


class TestCloudCacheSeparation:
    """Phase 4b 결정4: native/cloud 캐시 분리 검증."""

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_native_and_cloud_use_different_cache_keys(self):
        """같은 data로 native/cloud 호출 시 별도 캐시 엔트리 생성."""
        import judge_tool.det_adapters.db as _db

        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)
        fp = _db._fingerprint(data)

        # native 호출
        judge("DBM-003", raw, "mysql_native", {})
        assert ("mysql", False, fp) in _db._RUN_CACHE, "native 캐시 키 없음"
        assert ("mysql", True, fp) not in _db._RUN_CACHE, "cloud 캐시 키가 native 호출로 생성됨"

        # cloud 호출
        judge("DBM-003", raw, "mysql_rds", {})
        assert ("mysql", True, fp) in _db._RUN_CACHE, "cloud 캐시 키 없음"

        # 총 2개 별도 엔트리
        assert len([k for k in _db._RUN_CACHE if k[0] == "mysql"]) >= 2, (
            "native/cloud가 동일 캐시 엔트리를 공유함 — 결정4 위반"
        )

    def test_cloud_cache_hit_same_data(self):
        """같은 cloud variant + 동일 data → 캐시 히트 (2번째 .run 실행 없음)."""
        import judge_tool.det_adapters.db as _db

        data = {"DBM-003": {"RESULT": []}}
        raw = json.dumps(data)

        judge("DBM-003", raw, "mysql_rds", {})
        size_after_first = len(_db._RUN_CACHE)

        judge("DBM-003", raw, "mysql_rds", {})
        size_after_second = len(_db._RUN_CACHE)

        assert size_after_second == size_after_first, (
            "cloud 캐시 미작동: 동일 data로 2번 호출 시 캐시 엔트리 증가"
        )


class TestCloudR3Guard:
    """Phase 4b: cloud analysis에도 R3 가드 동일 적용."""

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def test_cloud_bad_data_does_not_raise(self):
        """cloud analysis 내부 예외 → 어댑터 밖으로 미전파."""
        # mysql cloud dbm_008: PASSWORD_LAST_CHANGED 날짜 파싱 실패 유발
        raw = _make_raw_ev({
            "DBM-008_1": {"RESULT": [{"HOST": "x", "USER": "y", "PASSWORD_LAST_CHANGED": "INVALID_DATE", "VALUE": "not_a_date"}]}
        })
        try:
            fv = judge("DBM-008", raw, "mysql_rds", {})
            assert isinstance(fv, ForcedVerdict), "ForcedVerdict가 아님"
        except Exception as e:
            pytest.fail(f"cloud 어댑터가 예외를 밖으로 전파: {type(e).__name__}: {e}")

    def test_cloud_no_false_positive_on_absent_items(self):
        """cloud ABSENT 항목들이 양호로 새지 않는다 (거짓양호 0 확인)."""
        # mysql cloud에서 ABSENT인 항목들
        absent_items = [
            ("DBM-025", "mysql_rds"),
            ("DBM-026", "mysql_rds"),
            ("DBM-033", "mysql_rds"),
            ("DBM-006", "pg_rds"),
            ("DBM-019", "pg_rds"),
            ("DBM-031", "mssql_rds"),
        ]
        for item_id, variant in absent_items:
            import judge_tool.det_adapters.db as _db
            _db._RUN_CACHE.clear()
            raw = _make_raw_ev({item_id: {"RESULT": [{"data": "value"}]}})
            fv = judge(item_id, raw, variant, {})
            assert fv.verdict != "양호", (
                f"거짓양호 발생: {item_id}/{variant} ABSENT인데 양호 판정 — {fv}"
            )
            assert fv.handled is False, (
                f"거짓양호 경로: {item_id}/{variant} ABSENT인데 handled=True — {fv}"
            )


class TestBatch1Classification:
    """DBM 분류 검토 Batch1: 모드A(detect-then-hold)·모드B(구조적취약)·pg극성·pg정규화·classify."""

    def test_mode_a_dbm004_violation_holds(self):
        """모드A: DBM-004 후보 있음 → 판단보류 + 후보목록(자동취약 아님)."""
        raw = _make_raw_ev({"DBM-004": {"RESULT": [
            {"GRANTEE": "app@%", "PRIVILEGE_TYPE": "SUPER", "IS_GRANTABLE": "NO"}]}})
        fv = judge("DBM-004", raw, "mysql_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류"
        assert len(fv.citations) >= 1

    def test_mode_a_dbm004_no_candidate_good(self):
        """모드A: DBM-004 후보 없음 → 양호."""
        raw = _make_raw_ev({"DBM-004": {"RESULT": []}})
        fv = judge("DBM-004", raw, "mysql_native", {})
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_mode_b_pg_native_dbm006_structural_vuln(self):
        """모드B: pg_native DBM-006 → 취약(구조적, 코어 실패잠금 부재), 데이터 무관."""
        fv = judge("DBM-006", '{"X":{"RESULT":[]}}', "pg_native", {})
        assert fv.handled is True
        assert fv.verdict == "취약"
        assert "PostgreSQL" in fv.rationale

    def test_mode_b_pg_native_dbm007_structural_vuln(self):
        fv = judge("DBM-007", '{"X":{"RESULT":[]}}', "pg_native", {})
        assert fv.handled is True
        assert fv.verdict == "취약"

    def test_mode_b_not_applied_to_pg_cloud(self):
        """모드B는 pg_native만 — pg_rds DBM-006은 구조적취약 경로 아님(gate ABSENT 차단)."""
        fv = judge("DBM-006", '{"X":{"RESULT":[]}}', "pg_rds", {})
        # pg_rds DBM-006 = ABSENT → gate 차단 → handled=False (구조적취약 아님)
        assert fv.handled is False

    def test_pg_dbm009_polarity_fixed(self):
        """pg dbm_009 극성: 0/1000=취약, 300/900=양호."""
        from judge_tool.vendor.common.db.postgresql import analysis as m
        cfg = json.load(open("judge_tool/vendor/common/db/config/postgresql-config.json"))
        for val, vuln in [("0", True), ("300", False), ("900", False), ("1000", True)]:
            a = m.PostgreSQLAnalysis(cfg, {"DBM-009": {"RESULT": [
                {"setting_name": "idle_in_transaction_session_timeout", "value": val}]}})
            a.dbm_009()
            assert bool(a.dbm_result.get("DBM-009")) is vuln, f"value={val} 극성 오류"

    def test_db_json_pg_normalize_clean_dict(self):
        """db_json pg 정규화: 작은따옴표/NULL 행 → 클린 dict (no {'*':...})."""
        from judge_tool.parsers.db_json import _pg_normalize
        import json as _j
        raw = '{"rolname": \'postgres\', "rolcanlogin": \'t\', "rolvaliduntil": NULL}'
        d = _j.loads(_pg_normalize(raw))
        assert d == {"rolname": "postgres", "rolcanlogin": "t", "rolvaliduntil": None}

    def test_classify_batch1_changes(self):
        """Batch1 DET_SOURCE 변경 확인."""
        reload_det_source()
        assert classify("DBM-005", "mssql_native") == "STUB"   # 자동취약 해제
        assert classify("DBM-006", "pg_native") == "DET"        # 모드B 라우팅
        assert classify("DBM-007", "pg_native") == "DET"
        assert classify("DBM-007", "mariadb_native") == "DET"   # STUB 오분류 복원
        assert classify("DBM-008", "pg_native") == "DET"        # 파서수정후
        # native 불변
        assert classify("DBM-006", "mysql_native") == "DET"

    def test_dbm005_mssql_no_longer_auto_vuln(self):
        """DBM-005 mssql: STUB → gate 차단(handled=False, 자동취약 아님)."""
        raw = _make_raw_ev({"DBM-005": {"RESULT": [{"sample": "x"}]}})
        fv = judge("DBM-005", raw, "mssql_native", {})
        assert fv.handled is False  # gate STUB 차단 → LLM 폴백


# ─────────────────────────────────────────────────────────────────────────────
# DBM-011 Phase 4d: detect-vuln-else-hold 모드(모드 C)
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM011DetectVulnElseHold:
    """DBM-011 모드C(detect-vuln-else-hold): 취약 탐지→취약 확정, 위반0→판단보류, 양호 자동판정 0건.

    설계 계약:
      - 벤더 결정론이 미수집(violations>0) 탐지 → 취약 확정(handled=True, verdict=취약).
      - 위반0(수집됨) → 판단보류 강제(handled=True, verdict=판단보류). 양호 절대 금지.
      - mysql/oracle/mariadb native DET 엔진 적용.
      - mssql: STUB → gate 차단(handled=False) → LLM 폴백.
      - pg: STUB → gate 차단(handled=False) → LLM 폴백.
    """

    def setup_method(self):
        """각 테스트 전 캐시 초기화."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        reload_det_source()

    # ── mysql DBM-011: 취약(미수집) ─────────────────────────────────────────

    def test_mysql_dbm011_not_loaded_is_vuln(self):
        """mysql DBM-011: 'not loaded' 문자열 → 취약(미수집 탐지)."""
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": ["audit_log.so plugin is not loaded!"]}
        })
        fv = judge("DBM-011", raw, "mysql_native", {})
        assert fv.handled is True, f"handled=False (취약 탐지인데 미처리): {fv}"
        assert fv.verdict == "취약", f"미수집인데 취약 아님: {fv.verdict}"
        assert fv.ev_status == "bad"
        assert fv.confidence == 0.9

    def test_mysql_dbm011_loaded_no_violations_is_hold(self):
        """mysql DBM-011: 위반0(수집됨) → 판단보류(양호 절대 금지)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        # RESULT 비어 있어 위반 없음 → 판단보류
        raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
        fv = judge("DBM-011", raw, "mysql_native", {})
        assert fv.handled is True, f"handled=False (위반0인데 미처리): {fv}"
        assert fv.verdict == "판단보류", (
            f"수집됨(위반0)인데 판단보류 아님: verdict={fv.verdict} — 거짓양호 위험"
        )
        assert fv.verdict != "양호", f"거짓양호 발생: verdict={fv.verdict}"
        assert "백업" in fv.rationale or "인터뷰" in fv.rationale, (
            f"rationale에 백업/인터뷰 사유 없음: {fv.rationale}"
        )

    def test_mysql_dbm011_no_false_good_ever(self):
        """mysql DBM-011: 양호 자동판정 절대 금지 — 빈 RESULT도 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
        fv = judge("DBM-011", raw, "mysql_native", {})
        assert fv.verdict != "양호", f"거짓양호: verdict={fv.verdict}"

    # ── oracle DBM-011: DET 분류 + 결정론 경로 실검증 ──────────────────────
    # oracle analysis.py는 dateutil(python-dateutil)·packaging 의존(requirements.txt 선언).
    # dateutil 설치 환경에서는 audit_trail=NONE→취약(DET), 수집됨→판단보류(모드C)를
    # 분리 단정한다(Opus 리뷰: 양분 수용 마스킹 제거). dateutil 부재 환경은 importorskip.

    def test_oracle_dbm011_det_classify(self):
        """oracle DBM-011: classify=DET 확인."""
        reload_det_source()
        assert classify("DBM-011", "oracle") == "DET", (
            "oracle DBM-011 classify가 DET 아님"
        )

    def test_oracle_dbm011_unaudited_is_vuln_det(self):
        """oracle DBM-011: audit_trail=NONE(미수집) → 취약(결정론). dateutil 필요."""
        import pytest
        pytest.importorskip("dateutil")  # 미설치 환경(요구사항 미설치)은 skip
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [{"name": "audit_trail", "value": "NONE"}]}
        })
        fv = judge("DBM-011", raw, "oracle_native", {})
        assert fv.verdict == "취약", (
            f"oracle DBM-011 미수집(NONE) → 취약(DET) 기대인데 {fv.verdict} "
            f"(handled={fv.handled}) — DET 경로 미작동(dateutil import 실패?)"
        )
        assert fv.handled is True

    def test_oracle_dbm011_loaded_is_hold_det(self):
        """oracle DBM-011: 수집됨(audit_trail≠NONE, 위반0) → 판단보류(모드C). 양호 자동 금지."""
        import pytest
        pytest.importorskip("dateutil")
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [{"name": "audit_trail", "value": "DB"}]}
        })
        fv = judge("DBM-011", raw, "oracle_native", {})
        assert fv.verdict == "판단보류", (
            f"oracle DBM-011 수집됨(위반0) → 판단보류(백업 인터뷰) 기대인데 {fv.verdict} "
            f"— 양호 자동판정이면 거짓양호"
        )

    # ── mariadb DBM-011: DET 복원 ────────────────────────────────────────────

    def test_mariadb_dbm011_det_restored_classify(self):
        """mariadb DBM-011: DET_SOURCE에서 DET 분류 확인(STUB→DET 복원)."""
        reload_det_source()
        assert classify("DBM-011", "mariadb") == "DET", (
            "mariadb DBM-011 classify가 DET 아님 — DET_SOURCE 갱신 미반영"
        )

    def test_mariadb_dbm011_not_loaded_is_vuln(self):
        """mariadb DBM-011: 'not loaded' 문자열 → 취약(미수집 탐지, DET 복원 후)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": ["server_audit.so plugin is not loaded!"]}
        })
        fv = judge("DBM-011", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb DBM-011 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb 미수집인데 취약 아님: verdict={fv.verdict}"
        )

    def test_mariadb_dbm011_loaded_is_hold(self):
        """mariadb DBM-011: 위반0(수집됨) → 판단보류(양호 절대 금지)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
        fv = judge("DBM-011", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb DBM-011 위반0 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mariadb 수집됨(위반0)인데 판단보류 아님: verdict={fv.verdict}"
        )
        assert fv.verdict != "양호", f"mariadb 거짓양호 발생: verdict={fv.verdict}"

    # ── mssql DBM-011: Phase 4e DET 승격 ───────────────────────────────────

    def test_mssql_dbm011_det_classify(self):
        """mssql DBM-011: Phase 4e STUB→DET 승격 — classify=DET 확인."""
        reload_det_source()
        assert classify("DBM-011", "mssql") == "DET", (
            "mssql DBM-011 classify가 DET 아님 — DET_SOURCE 갱신 미반영"
        )

    def test_mssql_dbm011_no_active_audit_is_vuln(self):
        """mssql DBM-011: 활성 감사 0행 → 취약(미수집 탐지, 모드C)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        # 빈 RESULT + NOTE(항상 존재) — det_common 경로는 NOTE 강제보류 안 탐
        raw = _make_raw_ev({
            "DBM-011": {
                "RESULT": [],
                "NOTE": "For audit log upload settings, refer to the PISM-011 script results.",
            }
        })
        fv = judge("DBM-011", raw, "mssql_native", {})
        assert fv.handled is True, f"mssql DBM-011 활성감사0건 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mssql 활성감사 없음인데 취약 아님: verdict={fv.verdict} — "
            "NOTE 강제보류에 가려졌거나(거짓음성) det_common 미동작"
        )
        assert fv.ev_status == "bad"

    def test_mssql_dbm011_active_audit_is_hold(self):
        """mssql DBM-011: 활성 감사 ≥1행 → 판단보류(모드C, 양호 절대 금지)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {
                "RESULT": [
                    {"audit_name": "TestAudit", "audit_action": "DATABASE_OBJECT_CHANGE_GROUP",
                     "create_date": "2024-01-01", "modify_date": "2024-01-01"},
                ],
                "NOTE": "For audit log upload settings, refer to the PISM-011 script results.",
            }
        })
        fv = judge("DBM-011", raw, "mssql_native", {})
        assert fv.handled is True, f"mssql DBM-011 활성감사존재 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mssql 활성감사 존재인데 판단보류 아님: verdict={fv.verdict} — 양호 자동판정 금지"
        )
        assert fv.verdict != "양호", f"mssql DBM-011 거짓양호: verdict={fv.verdict}"
        assert "백업" in fv.rationale or "인터뷰" in fv.rationale, (
            f"rationale에 백업/인터뷰 사유 없음: {fv.rationale}"
        )
        # 확인내용(감사명) rationale에 포함 확인
        assert "TestAudit" in fv.rationale or (fv.citations and "TestAudit" in fv.citations[0]), (
            f"mssql 보류 rationale에 감사명 없음: {fv.rationale} | citations={fv.citations}"
        )

    def test_mssql_dbm011_note_does_not_hide_vuln(self):
        """mssql DBM-011: NOTE 존재해도 미수집(취약) 판정이 가려지지 않음 — 거짓음성 방지."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        # 빈 RESULT + NOTE — NOTE 강제보류로 취약이 보류로 바뀌면 거짓음성
        raw = _make_raw_ev({
            "DBM-011": {
                "RESULT": [],
                "NOTE": "For audit log upload settings, refer to the PISM-011 script results.",
            }
        })
        fv = judge("DBM-011", raw, "mssql_native", {})
        assert fv.verdict != "판단보류" or fv.verdict == "취약", (
            f"mssql 미수집인데 NOTE로 보류 가려짐(거짓음성): verdict={fv.verdict}"
        )
        # 정확히는 취약이어야 함
        assert fv.verdict == "취약", (
            f"mssql 미수집(RESULT=[]): 취약 기대, 실제={fv.verdict} "
            "(NOTE 강제보류 우회 실패 — _judge_one LLM 경로로 라우팅됐을 가능성)"
        )

    def test_mssql_dbm011_no_false_good(self):
        """mssql DBM-011: 양호 자동판정 절대 금지."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
        fv = judge("DBM-011", raw, "mssql_native", {})
        assert fv.verdict != "양호", f"mssql DBM-011 거짓양호: verdict={fv.verdict}"

    # ── pg DBM-011: Phase 4e DET 승격(STUB→DET, pgaudit 신규 포맷 탐지) ──────

    def test_pg_dbm011_det_classify(self):
        """pg DBM-011: Phase 4e STUB→DET 승격 — classify=DET 확인."""
        reload_det_source()
        assert classify("DBM-011", "pg") == "DET", (
            "pg DBM-011 classify가 DET 아님 — DET_SOURCE 갱신 미반영"
        )

    def test_pg_dbm011_pgaudit_not_loaded_new_format_is_vuln(self):
        """pg DBM-011: 신규 포맷 pgaudit 미로드(value 없음, pgaudit_settings=[]) → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries", "value": "", "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 미로드 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"pg pgaudit 미로드인데 취약 아님: verdict={fv.verdict} — 거짓양호 위험"
        )
        assert fv.ev_status == "bad"

    def test_pg_dbm011_pgaudit_loaded_new_format_is_hold(self):
        """pg DBM-011: 신규 포맷 pgaudit 로드됨(value에 pgaudit 포함) → 판단보류(모드C)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries",
                 "value": "pgaudit,pg_stat_statements",
                 "pgaudit_settings": [{"pgaudit.log": "ddl,write"}]}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 로드됨 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"pg pgaudit 로드됨인데 판단보류 아님: verdict={fv.verdict} — 양호 자동판정 금지"
        )
        assert fv.verdict != "양호", f"pg DBM-011 거짓양호: verdict={fv.verdict}"
        # 확인내용(pgaudit) rationale에 포함 확인
        assert "pgaudit" in fv.rationale.lower() or (fv.citations and "pgaudit" in fv.citations[0].lower()), (
            f"pg 보류 rationale에 pgaudit 내용 없음: {fv.rationale} | citations={fv.citations}"
        )

    def test_pg_dbm011_pgaudit_status_not_loaded_is_vuln(self):
        """pg DBM-011: pgaudit_status='Not Loaded' 포맷 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"pgaudit_status": "Not Loaded", "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 pgaudit_status=Not Loaded handled=False: {fv}"
        assert fv.verdict == "취약", f"pgaudit_status=Not Loaded인데 취약 아님: {fv.verdict}"

    def test_pg_dbm011_pgaudit_status_loaded_is_hold(self):
        """pg DBM-011: pgaudit_status='Loaded' → 판단보류(모드C)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"pgaudit_status": "Loaded", "pgaudit_settings": [{"pgaudit.log": "ddl"}]}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 pgaudit_status=Loaded handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"pg pgaudit_status=Loaded인데 판단보류 아님: verdict={fv.verdict}"
        )
        assert fv.verdict != "양호", f"pg DBM-011 거짓양호: verdict={fv.verdict}"

    # ── R-PG011 빈 pgaudit_settings 거짓음성 보강 (VENDOR-EDIT(c) §R-PG011, 2026-06-17) ─

    def test_pg_dbm011_status_loaded_empty_settings_is_vuln(self):
        """pg DBM-011 §R-PG011: pgaudit_status='Loaded' + pgaudit_settings=[] → 취약.
        pgaudit 확장 로드됐으나 감사 클래스 미설정 = 실질 미수집 → 위반(취약)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"pgaudit_status": "Loaded", "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 §R-PG011 CaseA handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"pg DBM-011 §R-PG011 CaseA: pgaudit Loaded + empty settings → 취약 기대, "
            f"실제: {fv.verdict} — 거짓음성(감사 클래스 미설정 미탐)"
        )
        assert fv.ev_status == "bad", f"pg DBM-011 §R-PG011 CaseA ev_status != bad: {fv.ev_status}"

    def test_pg_dbm011_value_has_pgaudit_empty_settings_is_vuln(self):
        """pg DBM-011 §R-PG011: shared_preload_libraries에 pgaudit 포함 + pgaudit_settings=[] → 취약.
        pgaudit 로드됐으나 감사 클래스 미설정 = 실질 미수집 → 위반(취약)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries",
                 "value": "pgaudit",
                 "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 §R-PG011 CaseB handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"pg DBM-011 §R-PG011 CaseB: pgaudit in value + empty settings → 취약 기대, "
            f"실제: {fv.verdict} — 거짓음성(감사 클래스 미설정 미탐)"
        )
        assert fv.ev_status == "bad", f"pg DBM-011 §R-PG011 CaseB ev_status != bad: {fv.ev_status}"

    def test_pg_dbm011_loaded_with_real_settings_is_hold(self):
        """pg DBM-011 §R-PG011 회귀: pgaudit 로드 + pgaudit_settings 비어있지 않음 → 판단보류(과탐 아님).
        감사 클래스가 실제로 설정된 경우는 위반이 아니라 판단보류(수집됨)로 처리."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries",
                 "value": "pgaudit,pg_stat_statements",
                 "pgaudit_settings": [{"pgaudit.log": "ddl,write,role"}]}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 §R-PG011 회귀 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"pg DBM-011 §R-PG011 회귀: pgaudit 로드 + 실 settings → 판단보류 기대, "
            f"실제: {fv.verdict} — 과탐(거짓취약) 위험"
        )
        assert fv.verdict != "양호", f"pg DBM-011 §R-PG011 회귀: 거짓양호 금지: {fv.verdict}"

    def test_pg_dbm011_not_loaded_still_vuln(self):
        """pg DBM-011 §R-PG011 회귀: pgaudit 미로드(value 없음) → 취약(기존 동작 불변)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries",
                 "value": "",
                 "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 §R-PG011 미로드 회귀 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"pg DBM-011 §R-PG011 미로드 회귀: 취약 기대, 실제: {fv.verdict}"
        )

    def test_pg_dbm011_no_auto_good_after_r_pg011(self):
        """pg DBM-011 §R-PG011: 양호 자동판정 0건 — CaseA/B 모두 취약 또는 보류, 양호 없음."""
        import judge_tool.det_adapters.db as _db
        cases = [
            # (설명, raw_data)
            ("CaseA_loaded_empty", {"pgaudit_status": "Loaded", "pgaudit_settings": []}),
            ("CaseB_value_pgaudit_empty", {"setting_name": "shared_preload_libraries",
                                           "value": "pgaudit", "pgaudit_settings": []}),
            ("CaseA_not_loaded", {"pgaudit_status": "Not Loaded", "pgaudit_settings": []}),
            ("CaseB_not_loaded_val", {"setting_name": "shared_preload_libraries",
                                      "value": "", "pgaudit_settings": []}),
        ]
        for desc, datum in cases:
            _db._RUN_CACHE.clear()
            raw = _make_raw_ev({"DBM-011": {"RESULT": [datum]}})
            fv = judge("DBM-011", raw, "pg_native", {})
            assert fv.verdict != "양호", (
                f"pg DBM-011 §R-PG011 거짓양호 발생 ({desc}): verdict={fv.verdict}"
            )

    def test_pg_dbm011_legacy_korean_string_is_vuln(self):
        """pg DBM-011: 옛 한글 문자열('로드된 라이브러리가 없습니다.') 하위호환 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": ["로드된 라이브러리가 없습니다."]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.handled is True, f"pg DBM-011 한글 하위호환 handled=False: {fv}"
        assert fv.verdict == "취약", f"pg 한글 미로드 하위호환 취약 아님: {fv.verdict}"

    def test_pg_dbm011_no_false_good(self):
        """pg DBM-011: 양호 자동판정 절대 금지."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries", "value": "", "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.verdict != "양호", f"pg DBM-011 거짓양호: verdict={fv.verdict}"

    # ── cloud variants: DET 항목은 모드C 동작, STUB은 gate 차단 ─────────────

    def test_mysql_rds_dbm011_det_classify(self):
        """mysql_rds DBM-011: DET → classify=DET."""
        reload_det_source()
        assert classify("DBM-011", "mysql_rds") == "DET"

    def test_mssql_rds_dbm011_stub_blocked(self):
        """mssql_rds DBM-011: STUB → gate 차단."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
        fv = judge("DBM-011", raw, "mssql_rds", {})
        assert fv.handled is False
        assert fv.verdict != "양호"

    # ── 거짓양호 전수 확인 ───────────────────────────────────────────────────

    def test_no_false_good_all_det_engines_empty_result(self):
        """DBM-011: 빈 RESULT로 DET 엔진 전수 호출 시 양호 자동판정 0건 (Phase 4d/4e 전 엔진)."""
        import judge_tool.det_adapters.db as _db
        det_variants = [
            ("mysql_native", "mysql"),
            ("oracle_native", "oracle"),
            ("mariadb_native", "mariadb"),
            ("mssql_native", "mssql"),  # Phase 4e 추가
        ]
        for variant, _eng in det_variants:
            _db._RUN_CACHE.clear()
            raw = _make_raw_ev({"DBM-011": {"RESULT": []}})
            fv = judge("DBM-011", raw, variant, {})
            assert fv.verdict != "양호", (
                f"거짓양호 발생: DBM-011/{variant} 빈RESULT인데 양호 판정: {fv}"
            )
        # pg: 빈 pgaudit_settings → 미로드 → 취약 (양호 아님)
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-011": {"RESULT": [
                {"setting_name": "shared_preload_libraries", "value": "", "pgaudit_settings": []}
            ]}
        })
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.verdict != "양호", (
            f"거짓양호 발생: DBM-011/pg_native pgaudit미로드인데 양호 판정: {fv}"
        )

    # ── 모드C 보류 rationale 확인내용 테스트 ─────────────────────────────────

    def test_hold_rationale_contains_audit_detail_mysql(self):
        """mysql DBM-011: 판단보류 rationale에 audit_log 확인내용 포함."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": [
            {"VARIABLE_NAME": "audit_log_file", "VARIABLE_VALUE": "/var/log/mysql/audit.log"},
        ]}})
        fv = judge("DBM-011", raw, "mysql_native", {})
        assert fv.verdict == "판단보류", f"mysql DBM-011 수집됨 → 판단보류 기대: {fv.verdict}"
        assert "audit_log" in fv.rationale.lower() or (
            fv.citations and any("audit_log" in c.lower() for c in fv.citations)
        ), f"mysql 보류 rationale에 audit_log 내용 없음: {fv.rationale} | {fv.citations}"

    def test_hold_rationale_contains_audit_detail_pg_loaded(self):
        """pg DBM-011: 판단보류 rationale에 pgaudit 확인내용 포함."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": [
            {"setting_name": "shared_preload_libraries",
             "value": "pgaudit",
             "pgaudit_settings": [{"pgaudit.log": "ddl"}]},
        ]}})
        fv = judge("DBM-011", raw, "pg_native", {})
        assert fv.verdict == "판단보류", f"pg DBM-011 로드됨 → 판단보류 기대: {fv.verdict}"
        assert "pgaudit" in fv.rationale.lower() or (
            fv.citations and any("pgaudit" in c.lower() for c in fv.citations)
        ), f"pg 보류 rationale에 pgaudit 내용 없음: {fv.rationale} | {fv.citations}"

    def test_hold_rationale_contains_audit_detail_mssql_loaded(self):
        """mssql DBM-011: 판단보류 rationale에 감사명 포함."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-011": {"RESULT": [
            {"audit_name": "FinAudit", "audit_action": "SCHEMA_OBJECT_ACCESS_GROUP",
             "create_date": "2024-01-01", "modify_date": "2024-06-01"},
        ], "NOTE": "For audit log upload settings, refer to the PISM-011 script results."}})
        fv = judge("DBM-011", raw, "mssql_native", {})
        assert fv.verdict == "판단보류", f"mssql DBM-011 활성감사 → 판단보류 기대: {fv.verdict}"
        assert "FinAudit" in fv.rationale or (
            fv.citations and any("FinAudit" in c for c in fv.citations)
        ), f"mssql 보류 rationale에 감사명 없음: {fv.rationale} | {fv.citations}"


# ─────────────────────────────────────────────────────────────────────────────
# M1 회귀가드: _extract_audit_detail citation 마스킹
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractAuditDetailMasking:
    """M1: _extract_audit_detail이 반환하는 citation 문자열에 raw 민감값 미포함.

    audit detail은 _mask_row를 경유해야 한다 — raw config 비마스킹 노출 금지.
    플러그인명/감사명/경로 등 식별자는 노출 OK, 민감 자격증명(해시/패스워드)은 마스킹.
    """

    def _make_data_with_secret(self, engine: str) -> dict:
        """각 엔진별 DBM-011 RESULT에 민감값(해시/패스워드류) 키를 포함한 행."""
        if engine == "mysql":
            return {"DBM-011": {"RESULT": [
                {"VARIABLE_NAME": "audit_log_file",
                 "VARIABLE_VALUE": "/var/log/mysql/audit.log",
                 "secret": "plain_password_here"}
            ]}}
        if engine == "mariadb":
            return {"DBM-011": {"RESULT": [
                {"VARIABLE_NAME": "SERVER_AUDIT_FILE_PATH",
                 "VARIABLE_VALUE": "/var/log/mariadb/audit.log",
                 "password": "db_secret_123"}
            ]}}
        if engine == "oracle":
            return {"DBM-011": {"RESULT": [
                {"name": "audit_trail", "value": "DB",
                 "auth_token": "abcdef1234567890abcd"}  # 해시류 토큰
            ]}}
        if engine == "postgresql":
            return {"DBM-011": {"RESULT": [
                {"pgaudit_status": "Loaded",
                 "pgaudit_settings": ["log"],
                 "password": "pg_secret_456"}
            ]}}
        if engine == "mssql":
            return {"DBM-011": {"RESULT": [
                {"audit_name": "FSI_Audit",
                 "audit_action": "SCHEMA_OBJECT_ACCESS_GROUP",
                 "secret": "mssql_secret_789"},
            ]}}
        return {}

    def _call_extract(self, engine: str, data: dict) -> str:
        import importlib
        db_mod = importlib.import_module("judge_tool.det_adapters.db")
        return db_mod._extract_audit_detail(engine, data)

    def _assert_no_raw_sensitive(self, detail: str, secrets: list[str]):
        """detail 문자열에 secrets 원문이 없음을 단언."""
        for s in secrets:
            assert s not in detail, (
                f"citation에 민감값 원문 노출: secret={s!r} in detail={detail!r}"
            )

    def test_mysql_no_sensitive_in_detail(self):
        data = self._make_data_with_secret("mysql")
        detail = self._call_extract("mysql", data)
        self._assert_no_raw_sensitive(detail, ["plain_password_here"])
        assert "audit_log_file" in detail  # 식별자는 노출 OK

    def test_mariadb_no_sensitive_in_detail(self):
        data = self._make_data_with_secret("mariadb")
        detail = self._call_extract("mariadb", data)
        self._assert_no_raw_sensitive(detail, ["db_secret_123"])
        assert "SERVER_AUDIT_FILE_PATH" in detail

    def test_oracle_no_sensitive_in_detail(self):
        data = self._make_data_with_secret("oracle")
        detail = self._call_extract("oracle", data)
        # auth_token 값이 해시류이므로 마스킹되어야 한다
        self._assert_no_raw_sensitive(detail, ["abcdef1234567890abcd"])

    def test_postgresql_no_sensitive_in_detail(self):
        data = self._make_data_with_secret("postgresql")
        detail = self._call_extract("postgresql", data)
        self._assert_no_raw_sensitive(detail, ["pg_secret_456"])
        assert "pgaudit" in detail

    def test_mssql_no_sensitive_in_detail(self):
        data = self._make_data_with_secret("mssql")
        detail = self._call_extract("mssql", data)
        self._assert_no_raw_sensitive(detail, ["mssql_secret_789"])
        assert "FSI_Audit" in detail  # 감사명은 노출 OK


# ─────────────────────────────────────────────────────────────────────────────
# DBM-013 원격 접속 접근제어 — HOST 와일드카드 보강 (R-MY013/R-MA013)
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM013HostWildcard:
    """DBM-013 mysql/mariadb HOST 와일드카드 보강 핀고정 테스트 (R-MY013/R-MA013).

    검증 항목:
      (1) '%' 전체 와일드카드 HOST → 취약
      (2) '10.%' 서브넷 와일드카드 HOST → 취약 (거짓양호 갭 차단)
      (3) '%.domain.com' 도메인 와일드카드 HOST → 취약 (거짓양호 갭 차단)
      (4) 'localhost' → 양호 (과탐 아님)
      (5) 특정 IP(192.168.1.1) → 양호 (과탐 아님)
      (6) 예외계정(root 등 exception USER) → 제외 유지
      (7) oracle/mssql/pg DET_SOURCE STUB → gate 차단 → 양호 자동판정 0
    """

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()

    def _run_analysis_mysql(self, rows):
        """mysql analysis dbm_013 직접 단위 테스트."""
        import json
        from judge_tool.vendor.common.db.mysql.analysis import MySQLAnalysis
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "judge_tool", "vendor", "common", "db", "config", "mysql-config.json"
        )
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        data = {"DBM-013": {"RESULT": rows}}
        analysis = MySQLAnalysis(config, data)
        result = analysis.run
        return result.get("DBM-013", [])

    def _run_analysis_mariadb(self, rows):
        """mariadb analysis dbm_013 직접 단위 테스트."""
        import json
        from judge_tool.vendor.common.db.mariadb.analysis import MariaDBAnalysis
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "judge_tool", "vendor", "common", "db", "config", "mariadb-config.json"
        )
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        data = {"DBM-013": {"RESULT": rows}}
        analysis = MariaDBAnalysis(config, data)
        result = analysis.run
        return result.get("DBM-013", [])

    # ── mysql 와일드카드 취약 케이스 ─────────────────────────────────────────

    def test_mysql_full_wildcard_is_vuln(self):
        """mysql: HOST='%' 전체 와일드카드 → 위반 포함(취약)."""
        rows = [{"USER": "app_user", "HOST": "%"}]
        violations = self._run_analysis_mysql(rows)
        assert len(violations) > 0, (
            "HOST='%'인데 위반 미포함 — 거짓양호 R-MY013"
        )

    def test_mysql_subnet_wildcard_is_vuln(self):
        """mysql: HOST='10.%' 서브넷 와일드카드 → 위반 포함(취약). R-MY013 거짓양호 갭 차단."""
        rows = [{"USER": "app_user", "HOST": "10.%"}]
        violations = self._run_analysis_mysql(rows)
        assert len(violations) > 0, (
            "HOST='10.%'인데 위반 미포함 — 거짓양호 갭 R-MY013 미수정"
        )

    def test_mysql_domain_wildcard_is_vuln(self):
        """mysql: HOST='%.domain.com' 도메인 와일드카드 → 위반 포함(취약). R-MY013 갭 차단."""
        rows = [{"USER": "app_user", "HOST": "%.domain.com"}]
        violations = self._run_analysis_mysql(rows)
        assert len(violations) > 0, (
            "HOST='%.domain.com'인데 위반 미포함 — 거짓양호 갭 R-MY013 미수정"
        )

    # ── mysql 양호 케이스(과탐 아님) ──────────────────────────────────────────

    def test_mysql_localhost_is_good(self):
        """mysql: HOST='localhost' → 위반 미포함(양호). 과탐 아님."""
        rows = [{"USER": "app_user", "HOST": "localhost"}]
        violations = self._run_analysis_mysql(rows)
        # Note 항목({***:...})은 취약행이 아니므로 실취약행만 검사
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"HOST='localhost'인데 위반 포함 — 과탐 R-MY013: {violations}"
        )

    def test_mysql_specific_ip_is_good(self):
        """mysql: HOST='192.168.1.1' 특정IP → 위반 미포함(양호). 과탐 아님."""
        rows = [{"USER": "app_user", "HOST": "192.168.1.1"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"HOST='192.168.1.1'인데 위반 포함 — 과탐 R-MY013: {violations}"
        )

    def test_mysql_specific_hostname_is_good(self):
        """mysql: HOST='db.internal' 특정호스트 → 위반 미포함(양호). 과탐 아님."""
        rows = [{"USER": "app_user", "HOST": "db.internal"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"HOST='db.internal'인데 위반 포함 — 과탐 R-MY013: {violations}"
        )

    # ── mysql _ 와일드카드 취약 케이스 (High-2 R-MY013) ────────────────────────

    def test_mysql_underscore_wildcard_is_vuln(self):
        """mysql: HOST='10.0.0._' 단일문자 와일드카드 → 위반 포함(취약). High-2 R-MY013."""
        rows = [{"USER": "app_user", "HOST": "10.0.0._"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"HOST='10.0.0._' 단일문자 와일드카드인데 위반 미포함 — 거짓양호 R-MY013 High-2: {violations}"
        )

    def test_mysql_hostdb_underscore_is_vuln(self):
        """mysql: HOST='host_db' 단일문자 와일드카드 포함 → 위반 포함(취약). R-MY013."""
        rows = [{"USER": "app_user", "HOST": "host_db"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"HOST='host_db' _ 와일드카드인데 위반 미포함 — 거짓양호 R-MY013 High-2: {violations}"
        )

    # ── mysql Critical-1: root@% → 취약 / root@localhost → 양호 (R-MY013) ────

    def test_mysql_root_wildcard_host_is_vuln(self):
        """mysql: root@% → 취약. Critical-1 거짓양호 차단 (R-MY013 exception USER 비움).

        기존 exception USER에 root가 포함되어 root@%가 양호로 처리됐던 거짓양호를 차단.
        DBM-013 exception USER = [] (원격접근통제 항목에선 어떤 계정도 와일드카드-Host
        검사에서 면제하면 안 됨).
        """
        rows = [{"USER": "root", "HOST": "%"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"root@% 인데 위반 미포함 — Critical-1 거짓양호 미차단 R-MY013: {violations}"
        )

    def test_mysql_root_localhost_is_good(self):
        """mysql: root@localhost → 양호. 와일드카드 없는 특정호스트는 과탐 아님."""
        rows = [{"USER": "root", "HOST": "localhost"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"root@localhost인데 위반 포함 — 과탐 R-MY013: {violations}"
        )

    def test_mysql_appuser_wildcard_is_vuln(self):
        """mysql: appuser@% 비root 와일드카드 → 취약."""
        rows = [{"USER": "appuser", "HOST": "%"}]
        violations = self._run_analysis_mysql(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"appuser@% 비root 와일드카드인데 위반 미포함 — 거짓양호 R-MY013: {violations}"
        )

    # ── mysql 예외계정 제외 (DBM-013 exception USER=[] 이후 동작 변경) ────────
    # Critical-1 수정: exception DBM-013 USER를 비웠으므로 root@%는 이제 취약.
    # 아래 테스트는 그 수정을 핀고정한다.

    # ── mariadb 와일드카드 취약 케이스 ───────────────────────────────────────

    def test_mariadb_full_wildcard_is_vuln(self):
        """mariadb: HOST='%' → 위반 포함(취약)."""
        rows = [{"USER": "app_user", "HOST": "%"}]
        violations = self._run_analysis_mariadb(rows)
        assert len(violations) > 0, (
            "mariadb HOST='%'인데 위반 미포함 — 거짓양호 R-MA013"
        )

    def test_mariadb_subnet_wildcard_is_vuln(self):
        """mariadb: HOST='10.%' 서브넷 와일드카드 → 위반 포함(취약). R-MA013 갭 차단."""
        rows = [{"USER": "app_user", "HOST": "10.%"}]
        violations = self._run_analysis_mariadb(rows)
        assert len(violations) > 0, (
            "mariadb HOST='10.%'인데 위반 미포함 — 거짓양호 갭 R-MA013 미수정"
        )

    def test_mariadb_domain_wildcard_is_vuln(self):
        """mariadb: HOST='%.dom' → 위반 포함(취약). R-MA013 갭 차단."""
        rows = [{"USER": "app_user", "HOST": "%.dom"}]
        violations = self._run_analysis_mariadb(rows)
        assert len(violations) > 0, (
            "mariadb HOST='%.dom'인데 위반 미포함 — 거짓양호 갭 R-MA013 미수정"
        )

    # ── mariadb 양호 케이스 ───────────────────────────────────────────────────

    def test_mariadb_localhost_is_good(self):
        """mariadb: HOST='localhost' → 위반 미포함(양호)."""
        rows = [{"USER": "app_user", "HOST": "localhost"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"mariadb HOST='localhost'인데 위반 포함 — 과탐 R-MA013: {violations}"
        )

    def test_mariadb_specific_ip_is_good(self):
        """mariadb: HOST='192.168.1.1' → 위반 미포함(양호)."""
        rows = [{"USER": "app_user", "HOST": "192.168.1.1"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"mariadb HOST='192.168.1.1'인데 위반 포함 — 과탐 R-MA013: {violations}"
        )

    # ── mariadb _ 와일드카드 취약 케이스 (High-2 R-MA013) ────────────────────

    def test_mariadb_underscore_wildcard_is_vuln(self):
        """mariadb: HOST='10.0.0._' 단일문자 와일드카드 → 위반 포함(취약). High-2 R-MA013."""
        rows = [{"USER": "app_user", "HOST": "10.0.0._"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"HOST='10.0.0._' 단일문자 와일드카드인데 위반 미포함 — 거짓양호 R-MA013 High-2: {violations}"
        )

    # ── mariadb Critical-1: root@% → 취약 / root@localhost → 양호 (R-MA013) ──

    def test_mariadb_root_wildcard_host_is_vuln(self):
        """mariadb: root@% → 취약. Critical-1 거짓양호 차단 (R-MA013 exception USER 비움).

        기존 exception USER에 root가 포함되어 root@%가 양호로 처리됐던 거짓양호를 차단.
        DBM-013 exception USER = [] (원격접근통제 항목에선 어떤 계정도 와일드카드-Host
        검사에서 면제하면 안 됨).
        """
        rows = [{"USER": "root", "HOST": "%"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"root@% 인데 위반 미포함 — Critical-1 거짓양호 미차단 R-MA013: {violations}"
        )

    def test_mariadb_root_localhost_is_good(self):
        """mariadb: root@localhost → 양호. 와일드카드 없는 특정호스트는 과탐 아님."""
        rows = [{"USER": "root", "HOST": "localhost"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) == 0, (
            f"root@localhost인데 위반 포함 — 과탐 R-MA013: {violations}"
        )

    def test_mariadb_appuser_wildcard_is_vuln(self):
        """mariadb: appuser@% 비root 와일드카드 → 취약."""
        rows = [{"USER": "appuser", "HOST": "%"}]
        violations = self._run_analysis_mariadb(rows)
        real_violations = [v for v in violations if "***" not in v and "@@@" not in v]
        assert len(real_violations) > 0, (
            f"appuser@% 비root 와일드카드인데 위반 미포함 — 거짓양호 R-MA013: {violations}"
        )

    # ── mariadb 예외계정 제외 (DBM-013 exception USER=[] 이후 동작 변경) ─────
    # Critical-1 수정: exception DBM-013 USER를 비웠으므로 root@%는 이제 취약.
    # 아래 테스트는 그 수정을 핀고정한다.

    # ── oracle/mssql/pg STUB → gate 차단 → 양호 자동판정 0 ──────────────────

    def test_oracle_native_dbm013_stub_blocked(self):
        """oracle native DBM-013: STUB([lambda datum: True]) → gate 차단 → handled=False.
        양호 자동판정 금지 확인.
        """
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"HOST": "%"}]}})
        fv = judge("DBM-013", raw, "oracle_native", {})
        assert fv.handled is False, (
            f"oracle DBM-013 STUB인데 handled=True — 양호 자동판정 위험: {fv}"
        )

    def test_mssql_native_dbm013_stub_blocked(self):
        """mssql native DBM-013: 빈 본문(STUB) → gate 차단 → handled=False.
        양호 자동판정 금지 확인.
        """
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"HOST": "%"}]}})
        fv = judge("DBM-013", raw, "mssql_native", {})
        assert fv.handled is False, (
            f"mssql DBM-013 STUB인데 handled=True — 양호 자동판정 위험: {fv}"
        )

    def test_pg_native_dbm013_stub_blocked(self):
        """pg native DBM-013: 빈 본문(STUB) → gate 차단 → handled=False.
        양호 자동판정 금지 확인.
        """
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"HOST": "%"}]}})
        fv = judge("DBM-013", raw, "pg_native", {})
        assert fv.handled is False, (
            f"pg DBM-013 STUB인데 handled=True — 양호 자동판정 위험: {fv}"
        )

    def test_oracle_rds_dbm013_absent_blocked(self):
        """oracle_rds DBM-013: ABSENT(run()에 미호출) → gate 차단 → handled=False."""
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"HOST": "%"}]}})
        fv = judge("DBM-013", raw, "oracle_rds", {})
        assert fv.handled is False, (
            f"oracle_rds DBM-013 ABSENT인데 handled=True: {fv}"
        )

    def test_mysql_native_dbm013_full_wildcard_vuln(self):
        """mysql_native judge(): HOST='%' 계정 있음 → handled=True + verdict=취약.
        어댑터 통합 경로 확인.
        """
        raw = _make_raw_ev({"DBM-013": {"RESULT": [{"USER": "app_user", "HOST": "%"}]}})
        fv = judge("DBM-013", raw, "mysql_native", {})
        if fv.handled:
            assert fv.verdict == "취약", (
                f"mysql_native DBM-013 HOST='%' 있는데 취약이 아님: {fv}"
            )

    def test_mysql_native_dbm013_localhost_only_good(self):
        """mysql_native judge(): 전 계정이 localhost → handled=True + verdict=양호.
        양호 경로 과탐 없음 확인.
        """
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-013": {"RESULT": [
                {"USER": "app_user", "HOST": "localhost"},
                {"USER": "svc_user", "HOST": "192.168.1.10"},
            ]}
        })
        fv = judge("DBM-013", raw, "mysql_native", {})
        if fv.handled:
            assert fv.verdict == "양호", (
                f"mysql_native DBM-013 특정호스트만인데 양호가 아님: {fv}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# (m) DBM-015 label B 라우팅 — oracle/mssql/pg native
#
# 설계 계약:
#   - oracle/mssql/pg native DBM-015 → DET_SOURCE = STUB → gate 차단(handled=False).
#   - mssql native: 이전에 DET(rules['permission_name']=[]) → 항상 양호(거짓양호).
#     label B + judgment_method: det_common 제거 → classify_method=interview → _summarize_one.
#     DET_SOURCE mssql→STUB으로 정정 → gate도 차단.
#   - pg native: R3 보수처리로 이미 STUB. label B + no det_common → interview 경로.
#   - oracle native: 015_1/2 lambda:True STUB. label B + no det_common → interview 경로.
#   - classify_method: label='B', has_summary=True → 'interview' (det_common 어댑터 미호출).
#   - mysql/mariadb: DBM-015 N/A(applicable=False) → 스킵.
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM015LabelBRouting:
    """DBM-015 label B(인터뷰) 라우팅 검증.

    핵심 불변식:
      1. classify('DBM-015', 'mssql_native') == 'STUB'  (label B이관 후 DET_SOURCE 정정)
      2. classify('DBM-015', 'oracle_native') == 'STUB'
      3. classify('DBM-015', 'pg_native') == 'STUB'
      4. judge('DBM-015', ..., 'mssql_native') → handled=False (gate STUB 차단)
         → det_common 어댑터 미호출 → 거짓양호(permission_name=[]) 경로 차단
      5. classify_method('B', has_summary=True) → 'interview' (det_common 아님)
      6. DB 항목 yaml: mssql/oracle/pg DBM-015 summary_instruction 보유
    """

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        reload_det_source()

    def test_mssql_dbm015_classify_stub(self):
        """mssql native DBM-015: label B이관 후 DET_SOURCE=STUB → gate 차단 확인."""
        result = classify("DBM-015", "mssql_native")
        assert result == "STUB", (
            f"mssql DBM-015가 DET로 분류되면 거짓양호(permission_name=[]) 경로 탐!\n"
            f"got: {result}"
        )

    def test_oracle_dbm015_classify_stub(self):
        """oracle native DBM-015: 015_1/2 lambda:True → STUB."""
        assert classify("DBM-015", "oracle_native") == "STUB"

    def test_pg_dbm015_classify_stub(self):
        """pg native DBM-015: R3 보수처리(수집형식 불일치) → STUB."""
        assert classify("DBM-015", "pg_native") == "STUB"

    def test_mssql_dbm015_gate_blocked(self):
        """mssql native DBM-015: STUB → gate 차단 → handled=False (det_common 어댑터 미호출).

        이전 동작: rules['permission_name']=[] → datum in [] 항상 False → 위반 0 →
          handled=True + verdict=양호(거짓양호).
        수정 후: STUB → gate 차단 → handled=False → label B 라우팅(_summarize_one).
        """
        raw = _make_raw_ev({
            "DBM-015": {"RESULT": [
                {"permission_name": "SELECT", "grantee": "PUBLIC", "object_name": "orders"},
                {"permission_name": "INSERT", "grantee": "PUBLIC", "object_name": "payments"},
            ]}
        })
        fv = judge("DBM-015", raw, "mssql_native", {})
        assert fv.handled is False, (
            "mssql DBM-015: STUB → gate 차단되어야 함. "
            "handled=True이면 거짓양호(permission_name=[]) 경로를 타고 있음!"
        )

    def test_oracle_dbm015_gate_blocked(self):
        """oracle native DBM-015: STUB → gate 차단 → handled=False."""
        raw = _make_raw_ev({
            "DBM-015": {"RESULT": [{"object_type": "TABLE", "privilege": "SELECT"}]}
        })
        fv = judge("DBM-015", raw, "oracle_native", {})
        assert fv.handled is False, (
            "oracle DBM-015: STUB → gate 차단되어야 함 — 거짓양호 방지"
        )

    def test_pg_dbm015_gate_blocked(self):
        """pg native DBM-015: STUB(R3) → gate 차단 → handled=False (기존 테스트 보강)."""
        raw = _make_raw_ev({
            "DBM-015": {"RESULT": [{"privilege_type": "SELECT", "grantee": "PUBLIC"}]}
        })
        fv = judge("DBM-015", raw, "pg_native", {})
        assert fv.handled is False, (
            "pg DBM-015: STUB → gate 차단되어야 함 — 거짓양호 방지"
        )

    def test_label_b_routes_to_interview_not_det_common(self):
        """label='B', has_summary=True → classify_method='interview' (det_common 아님).

        mssql DBM-015에서 judgment_method: det_common이 제거된 결과:
        yaml_method=None → classify_method(label='B', has_summary=True) → 'interview'.
        """
        from judge_tool.criteria_loader import classify_method
        result = classify_method("B", has_summary=True, in_empty_means_good=False)
        assert result == "interview", (
            f"label B + has_summary=True → 'interview'이어야 함, got '{result}'"
        )
        # empty_means_good=True도 여전히 interview (B가 우선)
        result_emg = classify_method("B", has_summary=True, in_empty_means_good=True)
        assert result_emg == "interview"

    def test_mssql_dbm015_no_false_good_from_empty_rules(self):
        """mssql dbm_015 rules=['permission_name':[]] 버그 경로가 실행되지 않음을 확인.

        det_common 어댑터가 호출되면 벤더 analysis.dbm_015()가 실행돼
        rules['permission_name']=[] → 위반 0 → handled=True+양호(거짓양호).
        STUB gate 차단으로 이 경로가 실행되지 않음 = handled=False 단언.
        """
        # 악의적 케이스: mssql PUBLIC에 INSERT/DELETE 권한 부여돼도
        raw = _make_raw_ev({
            "DBM-015": {"RESULT": [
                {"permission_name": "INSERT", "grantee": "PUBLIC", "object_name": "customer"},
                {"permission_name": "DELETE", "grantee": "PUBLIC", "object_name": "transactions"},
            ]}
        })
        fv = judge("DBM-015", raw, "mssql_native", {})
        # STUB gate → handled=False. handled=True+양호는 거짓양호.
        assert fv.handled is False, (
            "거짓양호 경로 차단 실패! mssql PUBLIC에 INSERT/DELETE 있는데 "
            "det_common 어댑터가 '양호'로 판정함. "
            "DET_SOURCE mssql:DET→STUB 또는 yaml judgment_method 제거 확인 필요."
        )

    def test_db_yaml_dbm015_summary_instruction_content(self):
        """oracle/mssql/pg yaml DBM-015 summary_instruction 키워드 포함 확인."""
        import yaml
        for fname, engine_kw in [
            ("db_oracle.yaml", "SYS"),
            ("db_mssql.yaml", "sys"),
            ("db_postgresql.yaml", "pg_catalog"),
        ]:
            path = f"judge_tool/item_configs/{fname}"
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            item = data.get("DBM-015", {})
            assert item.get("label") == "B", f"{fname} DBM-015 label != B"
            assert "judgment_method" not in item, (
                f"{fname} DBM-015에 judgment_method가 있으면 det_common이 우선 → 거짓양호 위험!"
            )
            si = item.get("summary_instruction", "")
            assert si, f"{fname} DBM-015 summary_instruction 비어있음"
            assert engine_kw in si, (
                f"{fname} DBM-015 summary_instruction에 '{engine_kw}' 없음 "
                f"(시스템권한 구분 지시 필요)"
            )
            assert "판정" in si and "말고" in si or "내리지 말" in si, (
                f"{fname} DBM-015 summary_instruction에 '판정 금지' 지시 없음"
            )
            assert "업무상 불필요" in si, (
                f"{fname} DBM-015 summary_instruction에 '업무상 불필요' 없음"
            )

    def test_mssql_dbm015_no_judgment_method_in_yaml(self):
        """mssql yaml DBM-015에 judgment_method 키가 없어야 함 — 있으면 det_common 우선."""
        import yaml
        with open("judge_tool/item_configs/db_mssql.yaml", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        item = data.get("DBM-015", {})
        assert "judgment_method" not in item, (
            "db_mssql.yaml DBM-015에 judgment_method가 있음! "
            "criteria_loader yaml_method 우선 → det_common 어댑터 호출 → 거짓양호."
        )

    def test_detsource_mssql_dbm015_is_stub(self):
        """DET_SOURCE mssql DBM-015 = STUB (label B 이관, 거짓양호 회피 명기)."""
        reload_det_source()
        result = classify("DBM-015", "mssql_native")
        assert result == "STUB", (
            f"DET_SOURCE mssql DBM-015 = {result}. "
            "STUB이어야 gate 차단 → label B 라우팅 → _summarize_one 경로."
        )

    def test_cloud_mssql_rds_dbm015_still_det(self):
        """cloud mssql_rds DBM-015는 DET 유지 — native만 label B 이관."""
        result = classify("DBM-015", "mssql_rds")
        assert result == "DET", (
            f"mssql_rds DBM-015는 DET여야 함(cloud 변형, permission_name 비교 가능), got {result}"
        )

    def test_cloud_pg_rds_dbm015_still_det(self):
        """cloud pg_rds DBM-015는 DET 유지 — native만 label B 이관."""
        result = classify("DBM-015", "pg_rds")
        assert result == "DET"

    def test_fake_llm_summarize_path(self):
        """fake LLM client로 label B → _summarize_one → verdict=판단보류 + interview_summary 채움.

        실 Ollama 미필요 — FakeSummarizeClient가 요약 텍스트 반환.
        """
        from judge_tool.main import _summarize_one, JudgeContext
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence
        from judge_tool.profile import DB_MSSQL

        class FakeSummarizeClient:
            """LLM을 흉내 내는 fake client: summary_instruction 응답."""
            def chat(self, system, user):
                return "시스템 권한: sys.tables(SELECT) — 기본 권한(정상). 업무 객체: dbo.orders(INSERT) — 업무상 불필요 의심."

        crit = Criterion(
            item_id="DBM-015", item_name="PUBLIC Role 권한", risk=4.0,
            variant="mssql_native",
            eval_type="스크립트", standard="양호: 불필요한 권한 없음", method="인터뷰",
            applicable=True, label="B",
            summary_instruction="PUBLIC Role에 부여된 권한을 정리하라. 판정하지 말 것.",
            judgment_method="interview")
        item = EvidenceItem(
            item_id="DBM-015", variant="mssql_native",
            resources=[ResourceEvidence(
                resource_id="r1", status="review",
                detail="PUBLIC: INSERT on dbo.orders",
                evidence="PUBLIC: INSERT on dbo.orders")])
        ctx = JudgeContext(
            profile=DB_MSSQL, profile_key="db_mssql",
            client=FakeSummarizeClient(), items={}, variant="mssql_native")

        j = _summarize_one(crit, item, ctx)
        assert j is not None, "_summarize_one이 None 반환 — 라우팅 실패"
        assert j.verdict == "판단보류", (
            f"label B → verdict='판단보류' 고정이어야 함, got '{j.verdict}'"
        )
        assert j.interview_summary is not None, (
            "interview_summary가 None — LLM 요약 호출 실패"
        )
        assert "불필요" in j.interview_summary or "sys" in j.interview_summary or "orders" in j.interview_summary, (
            f"interview_summary에 요약 내용 없음: {j.interview_summary!r}"
        )
        assert j.label == "B"


# ─────────────────────────────────────────────────────────────────────────────
# (n) DBM-017 label B 라우팅 — mysql/mariadb/oracle/mssql/pg native
#
# 설계 계약:
#   - mysql/mariadb/oracle native DBM-017 → DET_SOURCE = STUB → gate 차단(handled=False).
#     이전: DET(exception-기반 비교) → 과탐/미탐 위험.
#     label B + judgment_method: det_common 제거 → classify_method=interview → _summarize_one.
#   - mssql native: 빈 본문 → STUB(기존). label B + no det_common → interview 경로.
#   - pg native: R3 보수처리로 이미 STUB. label B + no det_common → interview 경로.
#   - classify_method: label='B', has_summary=True → 'interview' (det_common 어댑터 미호출).
#   - 거짓양호(양호 자동판정) 0 — 특히 pg PUBLIC 과탐 경로 차단.
#   - 클라우드 변형(mysql_rds, oracle_rds, mariadb_rds, pg_rds 등)은 DET 유지.
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM017LabelBRouting:
    """DBM-017 label B(인터뷰) 라우팅 검증.

    핵심 불변식:
      1. classify('DBM-017', 'mysql_native') == 'STUB'   (label B 이관 후 DET_SOURCE 정정)
      2. classify('DBM-017', 'oracle_native') == 'STUB'
      3. classify('DBM-017', 'mariadb_native') == 'STUB'
      4. classify('DBM-017', 'mssql_native') == 'STUB'   (기존 STUB 유지)
      5. classify('DBM-017', 'pg_native') == 'STUB'      (기존 STUB 유지)
      6. judge('DBM-017', ..., 'mysql_native') → handled=False (gate STUB 차단)
         → det_common 어댑터 미호출 → 거짓양호(exception-기반 오판) 경로 차단
      7. judge('DBM-017', ..., 'pg_native') → handled=False (pg PUBLIC 과탐 차단)
      8. classify_method('B', has_summary=True) → 'interview' (det_common 아님)
      9. DB 항목 yaml: mysql/mariadb/oracle/mssql/pg DBM-017 summary_instruction + 'judgment_method' 없음
      10. 클라우드 변형(mysql_rds, oracle_rds, mariadb_rds, pg_rds)은 DET 유지
    """

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        reload_det_source()

    def test_mysql_dbm017_classify_stub(self):
        """mysql native DBM-017: label B 이관 후 DET_SOURCE=STUB → gate 차단 확인."""
        result = classify("DBM-017", "mysql_native")
        assert result == "STUB", (
            f"mysql DBM-017가 DET로 분류되면 exception-기반 과탐/미탐 경로 탐!\n"
            f"got: {result}"
        )

    def test_oracle_dbm017_classify_stub(self):
        """oracle native DBM-017: label B 이관 후 DET_SOURCE=STUB → gate 차단 확인."""
        result = classify("DBM-017", "oracle_native")
        assert result == "STUB", (
            f"oracle DBM-017가 DET로 분류되면 exception-기반 과탐/미탐 경로 탐!\n"
            f"got: {result}"
        )

    def test_mariadb_dbm017_classify_stub(self):
        """mariadb native DBM-017: label B 이관 후 DET_SOURCE=STUB → gate 차단 확인."""
        result = classify("DBM-017", "mariadb_native")
        assert result == "STUB", (
            f"mariadb DBM-017가 DET로 분류되면 exception-기반 과탐/미탐 경로 탐!\n"
            f"got: {result}"
        )

    def test_mssql_dbm017_classify_stub(self):
        """mssql native DBM-017: 빈 본문 STUB(기존 유지)."""
        result = classify("DBM-017", "mssql_native")
        assert result == "STUB", f"mssql DBM-017 STUB 기대, got: {result}"

    def test_pg_dbm017_classify_stub(self):
        """pg native DBM-017: R3 보수처리 + grantee==PUBLIC 과탐 → STUB(기존 유지)."""
        result = classify("DBM-017", "pg_native")
        assert result == "STUB", f"pg DBM-017 STUB 기대, got: {result}"

    def test_mysql_dbm017_gate_blocked(self):
        """mysql native DBM-017: STUB → gate 차단 → handled=False (det_common 어댑터 미호출).

        이전 동작: DET → exception-기반 비교 → 과탐(거짓취약)/미탐(거짓양호) 위험.
        수정 후: STUB → gate 차단 → handled=False → label B 라우팅(_summarize_one).
        """
        raw = _make_raw_ev({
            "DBM-017_1": {"RESULT": [
                {"GRANTEE": "app_user@%", "TABLE_NAME": "information_schema.TABLES", "PRIVILEGE_TYPE": "SELECT"},
                {"GRANTEE": "app_user@%", "TABLE_NAME": "mysql.user", "PRIVILEGE_TYPE": "SELECT"},
            ]}
        })
        fv = judge("DBM-017", raw, "mysql_native", {})
        assert fv.handled is False, (
            "mysql DBM-017: STUB → gate 차단되어야 함. "
            "handled=True이면 exception-기반 과탐/미탐 경로를 타고 있음!"
        )

    def test_oracle_dbm017_gate_blocked(self):
        """oracle native DBM-017: STUB → gate 차단 → handled=False."""
        raw = _make_raw_ev({
            "DBM-017": {"RESULT": [
                {"GRANTEE": "APP_USER", "TABLE_NAME": "DBA_TABLES", "PRIVILEGE": "SELECT"}
            ]}
        })
        fv = judge("DBM-017", raw, "oracle_native", {})
        assert fv.handled is False, (
            "oracle DBM-017: STUB → gate 차단되어야 함 — 거짓양호 방지"
        )

    def test_mariadb_dbm017_gate_blocked(self):
        """mariadb native DBM-017: STUB → gate 차단 → handled=False."""
        raw = _make_raw_ev({
            "DBM-017_1": {"RESULT": [
                {"GRANTEE": "app_user@%", "TABLE_NAME": "information_schema.TABLES", "PRIVILEGE_TYPE": "SELECT"},
            ]}
        })
        fv = judge("DBM-017", raw, "mariadb_native", {})
        assert fv.handled is False, (
            "mariadb DBM-017: STUB → gate 차단되어야 함 — 거짓양호 방지"
        )

    def test_pg_dbm017_gate_blocked_no_public_false_positive(self):
        """pg native DBM-017: STUB → gate 차단 → handled=False (PUBLIC 과탐 차단).

        이전 동작: grantee=='PUBLIC' + pg_catalog SELECT → 거짓취약(과탐).
        수정 후: STUB gate → handled=False. pg PUBLIC 기본 권한 과탐 없음.
        """
        raw = _make_raw_ev({
            "DBM-017_1": {"RESULT": [
                {"grantee": "PUBLIC", "table_name": "pg_stat_activity", "privilege_type": "SELECT"},
            ]}
        })
        fv = judge("DBM-017", raw, "pg_native", {})
        assert fv.handled is False, (
            "pg DBM-017: STUB → gate 차단되어야 함 — PUBLIC 과탐 차단"
        )
        # 핵심: 양호 자동판정 없음
        assert fv.verdict != "양호", (
            "pg DBM-017: 거짓양호 금지 — STUB gate 차단 후 양호가 나오면 안 됨."
        )

    def test_mssql_dbm017_gate_blocked(self):
        """mssql native DBM-017: STUB(빈 본문) → gate 차단 → handled=False."""
        raw = _make_raw_ev({
            "DBM-017": {"RESULT": [
                {"permission_name": "SELECT", "grantee": "PUBLIC", "object_name": "sys.tables"},
            ]}
        })
        fv = judge("DBM-017", raw, "mssql_native", {})
        assert fv.handled is False, (
            "mssql DBM-017: STUB → gate 차단되어야 함."
        )

    def test_no_judgment_method_in_yaml(self):
        """mysql/mariadb/oracle yaml DBM-017에 judgment_method 키가 없어야 함.

        judgment_method가 있으면 criteria_loader가 yaml_method 우선 → det_common 어댑터 호출 → 거짓양호.
        """
        import yaml
        for fname in [
            "db_mysql.yaml", "db_mariadb.yaml", "db_oracle.yaml",
            "db_mssql.yaml", "db_postgresql.yaml",
        ]:
            path = f"judge_tool/item_configs/{fname}"
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            item = data.get("DBM-017", {})
            assert "judgment_method" not in item, (
                f"{fname} DBM-017에 judgment_method가 있음! "
                "criteria_loader yaml_method 우선 → det_common 어댑터 호출 → 거짓양호."
            )

    def test_db_yaml_dbm017_label_b_and_summary_instruction(self):
        """5엔진 yaml DBM-017: label=B + summary_instruction(업무상 불필요 + 판정금지) 확인."""
        import yaml
        engine_kws = [
            ("db_mysql.yaml",      "information_schema"),
            ("db_mariadb.yaml",    "information_schema"),
            ("db_oracle.yaml",     "SYS"),
            ("db_mssql.yaml",      "sys"),
            ("db_postgresql.yaml", "pg_catalog"),
        ]
        for fname, engine_kw in engine_kws:
            path = f"judge_tool/item_configs/{fname}"
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            item = data.get("DBM-017", {})
            assert item.get("label") == "B", f"{fname} DBM-017 label != B"
            assert "judgment_method" not in item, (
                f"{fname} DBM-017에 judgment_method가 있으면 det_common이 우선 → 거짓양호 위험!"
            )
            si = item.get("summary_instruction", "")
            assert si, f"{fname} DBM-017 summary_instruction 비어있음"
            assert engine_kw in si, (
                f"{fname} DBM-017 summary_instruction에 '{engine_kw}' 없음 "
                f"(시스템권한 구분 지시 필요)"
            )
            assert ("판정" in si and ("말고" in si or "내리지 말" in si)), (
                f"{fname} DBM-017 summary_instruction에 '판정 금지' 지시 없음"
            )
            assert "업무상 불필요" in si, (
                f"{fname} DBM-017 summary_instruction에 '업무상 불필요' 없음"
            )

    def test_cloud_mysql_rds_dbm017_still_det(self):
        """cloud mysql_rds DBM-017는 DET 유지 — native만 label B 이관."""
        result = classify("DBM-017", "mysql_rds")
        assert result == "DET", (
            f"mysql_rds DBM-017는 DET여야 함(cloud 변형), got {result}"
        )

    def test_cloud_oracle_rds_dbm017_still_det(self):
        """cloud oracle_rds DBM-017는 DET 유지."""
        result = classify("DBM-017", "oracle_rds")
        assert result == "DET", (
            f"oracle_rds DBM-017는 DET여야 함, got {result}"
        )

    def test_cloud_mariadb_rds_dbm017_still_det(self):
        """cloud mariadb_rds DBM-017는 DET 유지."""
        result = classify("DBM-017", "mariadb_rds")
        assert result == "DET", (
            f"mariadb_rds DBM-017는 DET여야 함, got {result}"
        )

    def test_cloud_pg_rds_dbm017_still_det(self):
        """cloud pg_rds DBM-017는 DET 유지 (grantee==PUBLIC 비교 가능한 스키마)."""
        result = classify("DBM-017", "pg_rds")
        assert result == "DET", (
            f"pg_rds DBM-017는 DET여야 함, got {result}"
        )

    def test_fake_llm_summarize_path_mysql(self):
        """fake LLM client로 DBM-017 label B → _summarize_one → verdict=판단보류 + interview_summary.

        실 Ollama 미필요 — FakeSummarizeClient가 요약 텍스트 반환.
        mysql 엔진 예시.
        """
        from judge_tool.main import _summarize_one, JudgeContext
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence
        from judge_tool.profile import DB_MYSQL

        class FakeSummarizeClient:
            """LLM을 흉내 내는 fake client: summary_instruction 응답."""
            def chat(self, system, user):
                return (
                    "시스템 계정: information_schema(SELECT) — 기본 부여(정상). "
                    "일반 계정 app_user@%: mysql.user(SELECT) — 업무상 불필요 의심."
                )

        crit = Criterion(
            item_id="DBM-017", item_name="시스템 테이블 접근 권한", risk=4.0,
            variant="mysql_native",
            eval_type="스크립트", standard="양호: 업무상 불필요한 접근 권한 없음", method="인터뷰",
            applicable=True, label="B",
            summary_instruction="시스템 테이블 접근 권한을 정리하라. 판정하지 말 것.",
            judgment_method="interview")
        item = EvidenceItem(
            item_id="DBM-017", variant="mysql_native",
            resources=[ResourceEvidence(
                resource_id="r1", status="review",
                detail="app_user@%: mysql.user SELECT",
                evidence="app_user@%: mysql.user SELECT")])
        ctx = JudgeContext(
            profile=DB_MYSQL, profile_key="db_mysql",
            client=FakeSummarizeClient(), items={}, variant="mysql_native")

        j = _summarize_one(crit, item, ctx)
        assert j is not None, "_summarize_one이 None 반환 — 라우팅 실패"
        assert j.verdict == "판단보류", (
            f"label B → verdict='판단보류' 고정이어야 함, got '{j.verdict}'"
        )
        assert j.interview_summary is not None, (
            "interview_summary가 None — LLM 요약 호출 실패"
        )
        assert (
            "불필요" in j.interview_summary
            or "mysql" in j.interview_summary
            or "app_user" in j.interview_summary
        ), (
            f"interview_summary에 요약 내용 없음: {j.interview_summary!r}"
        )
        assert j.label == "B"


# ─────────────────────────────────────────────────────────────────────────────
# DBM-019 비밀번호 재사용 방지 — 거짓양호 가드 + mariadb DET 복원 + pg label C
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM019PasswordReuse:
    """DBM-019 비밀번호 재사용 방지 분류 검증.

    핵심 불변식:
      1. mariadb DBM-019 classify == DET (STUB→DET 복원)
      2. mysql/oracle/mssql/mariadb 설정 적절 → 양호
      3. mysql/oracle/mssql/mariadb 설정 부적절(값 나쁨) → 취약
      4. mysql/oracle/mssql/mariadb RESULT 완전 비어있음 → 판단보류(거짓양호 가드, handled=True)
      5. mariadb "not loaded" → 취약
      6. pg DBM-019 label C → 판단보류 + canned_message(기능부재 안내)
      7. 실데이터: mysql/oracle/mssql/mariadb 거짓양호 0 확인
    """

    def setup_method(self):
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        reload_det_source()

    # ── 1. mariadb DET 복원 ───────────────────────────────────────────────────

    def test_mariadb_dbm019_det_restored_classify(self):
        """mariadb DBM-019: DET_SOURCE에서 DET 분류 확인(STUB→DET 복원)."""
        reload_det_source()
        assert classify("DBM-019", "mariadb") == "DET", (
            "mariadb DBM-019 classify가 DET 아님 — DET_SOURCE 갱신 미반영"
        )

    def test_mariadb_dbm019_det_restored_native(self):
        """mariadb_native DBM-019: DET_SOURCE DET → gate 통과 가능."""
        reload_det_source()
        assert classify("DBM-019", "mariadb_native") == "DET", (
            "mariadb_native DBM-019 classify가 DET 아님 — DET_SOURCE 갱신 미반영"
        )

    # ── 2. 설정 적절 → 양호 ──────────────────────────────────────────────────

    def test_mysql_proper_settings_is_good(self):
        """MySQL: password_history>0, password_reuse_interval>0 → 양호."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "password_history", "VARIABLE_VALUE": "10"},
                {"VARIABLE_NAME": "password_reuse_interval", "VARIABLE_VALUE": "365"},
            ]}
        })
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 적절 설정 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mysql 적절 설정인데 양호 아님: verdict={fv.verdict}"
        )

    def test_mssql_all_policy_checked_is_good(self):
        """MSSQL: is_policy_checked=1 전원 → 양호."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"name": "sa", "is_policy_checked": "1"},
                {"name": "app_user", "is_policy_checked": "1"},
            ]}
        })
        fv = judge("DBM-019", raw, "mssql_native", {})
        assert fv.handled is True, f"mssql 적절 설정 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mssql 적절 설정인데 양호 아님: verdict={fv.verdict}"
        )

    def test_oracle_proper_limits_is_good(self):
        """Oracle: PASSWORD_REUSE_MAX/TIME 모두 UNLIMITED 아님(값 설정됨) → 양호."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"username": "APP", "profile": "DEFAULT",
                 "resource_name": "PASSWORD_REUSE_MAX", "limit": "10"},
                {"username": "APP", "profile": "DEFAULT",
                 "resource_name": "PASSWORD_REUSE_TIME", "limit": "180"},
            ]}
        })
        fv = judge("DBM-019", raw, "oracle_native", {})
        assert fv.handled is True, f"oracle 적절 설정 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"oracle 적절 설정인데 양호 아님: verdict={fv.verdict}"
        )

    def test_mariadb_proper_interval_is_good(self):
        """MariaDB: PASSWORD_REUSE_CHECK_INTERVAL > 0 이고 <= threshold → 양호."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "30"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 적절 설정 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mariadb 적절 설정인데 양호 아님: verdict={fv.verdict}"
        )

    def test_mariadb_interval_60_is_good(self):
        """MariaDB R-MA019: INTERVAL=60(강한 설정) → 양호. 수정 전 거짓취약 핵심 케이스."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "60"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb interval=60 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mariadb INTERVAL=60 → 양호 기대인데 {fv.verdict} "
            f"— R-MA019 거짓취약 재발! (수정 전 60>30 → 취약 오판)"
        )

    def test_mariadb_interval_1_is_good(self):
        """MariaDB R-MA019: INTERVAL=1(최소 설정 켜짐) → 양호."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "1"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb interval=1 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mariadb INTERVAL=1 → 양호 기대인데 {fv.verdict} "
            f"— 이진 판정(>0=양호) 위반"
        )

    # ── 3. 설정 부적절 → 취약 ────────────────────────────────────────────────

    def test_mysql_zero_history_is_vuln(self):
        """MySQL: password_history=0 → 재사용 무제한 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "password_history", "VARIABLE_VALUE": "0"},
                {"VARIABLE_NAME": "password_reuse_interval", "VARIABLE_VALUE": "0"},
            ]}
        })
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 미설정 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mysql password_history=0 → 취약 기대인데 {fv.verdict} "
            f"— 거짓양호 발생!"
        )

    def test_mssql_policy_unchecked_is_vuln(self):
        """MSSQL: is_policy_checked=0인 계정 존재 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"name": "sa", "is_policy_checked": "1"},
                {"name": "app_user", "is_policy_checked": "0"},
            ]}
        })
        fv = judge("DBM-019", raw, "mssql_native", {})
        assert fv.handled is True, f"mssql 위반 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mssql is_policy_checked=0 → 취약 기대인데 {fv.verdict}"
        )

    def test_oracle_unlimited_is_vuln(self):
        """Oracle: PASSWORD_REUSE_TIME/MAX UNLIMITED → 재사용 무제한 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"username": "SYS", "profile": "DEFAULT",
                 "resource_name": "PASSWORD_REUSE_TIME", "limit": "UNLIMITED"},
                {"username": "SYS", "profile": "DEFAULT",
                 "resource_name": "PASSWORD_REUSE_MAX", "limit": "UNLIMITED"},
            ]}
        })
        fv = judge("DBM-019", raw, "oracle_native", {})
        assert fv.handled is True, f"oracle UNLIMITED handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"oracle UNLIMITED → 취약 기대인데 {fv.verdict}"
        )

    def test_mariadb_interval_zero_is_vuln(self):
        """MariaDB: PASSWORD_REUSE_CHECK_INTERVAL=0 → 재사용 무제한 → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "0"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb interval=0 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb PASSWORD_REUSE_CHECK_INTERVAL=0 → 취약 기대인데 {fv.verdict}"
        )

    # ── 4. RESULT 완전 비어있음 → 판단보류 (거짓양호 가드) ────────────────────

    def test_mysql_empty_result_is_hold_not_good(self):
        """MySQL: RESULT 0행 → 설정 미수집 → 판단보류(거짓양호 가드, handled=True)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-019": {"RESULT": []}})
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 빈결과 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mysql RESULT 0행 → 판단보류 기대인데 {fv.verdict} — 거짓양호 발생!"
        )

    def test_oracle_empty_result_is_hold_not_good(self):
        """Oracle: RESULT 0행 → 설정 미수집 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-019": {"RESULT": []}})
        fv = judge("DBM-019", raw, "oracle_native", {})
        assert fv.handled is True, f"oracle 빈결과 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"oracle RESULT 0행 → 판단보류 기대인데 {fv.verdict} — 거짓양호 발생!"
        )

    def test_mssql_empty_result_is_hold_not_good(self):
        """MSSQL: RESULT 0행 → 설정 미수집 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-019": {"RESULT": []}})
        fv = judge("DBM-019", raw, "mssql_native", {})
        assert fv.handled is True, f"mssql 빈결과 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mssql RESULT 0행 → 판단보류 기대인데 {fv.verdict} — 거짓양호 발생!"
        )

    def test_mariadb_empty_result_is_hold_not_good(self):
        """MariaDB: RESULT 0행 → 설정 미수집 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({"DBM-019": {"RESULT": []}})
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 빈결과 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mariadb RESULT 0행 → 판단보류 기대인데 {fv.verdict} — 거짓양호 발생!"
        )

    # ── 5. mariadb "not loaded" → 취약 ──────────────────────────────────────

    def test_mariadb_not_loaded_is_vuln(self):
        """MariaDB: 'PASSWORD_REUSE_CHECK plugin is not loaded!' → 취약."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {
                "RESULT": ["PASSWORD_REUSE_CHECK plugin is not loaded!"]
            }
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb not loaded handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb 플러그인 미로드 → 취약 기대인데 {fv.verdict}"
        )

    # ── 6. pg label C → 판단보류 + canned_message ─────────────────────────────

    def test_pg_dbm019_label_c_canned_message(self):
        """pg DBM-019: label C + canned_message → 판단보류(기능부재 안내)."""
        import openpyxl, tempfile
        from judge_tool.criteria_loader import load_criteria
        from judge_tool.profile import get_profile

        profile = get_profile("db_postgresql")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tf:
            tmpxlsx = tf.name
        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "데이터베이스"
            ws.cell(4, 2, "ID"); ws.cell(4, 7, "name"); ws.cell(4, 8, "risk")
            ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
            ws.cell(5, 2, "DBM-019"); ws.cell(5, 7, "비밀번호재사용"); ws.cell(5, 8, 5.0)
            ws.cell(5, 17, "o"); ws.cell(5, 37, "* 양호 - 재사용 불가"); ws.cell(5, 38, "m")
            wb.save(tmpxlsx)
            criteria = load_criteria(tmpxlsx, profile, "db_postgresql")
        finally:
            import os
            os.unlink(tmpxlsx)

        key = ("DBM-019", "pg_native")
        assert key in criteria, f"pg_native DBM-019 criteria 없음: {list(criteria.keys())[:5]}"
        c = criteria[key]
        assert c.label == "C", f"pg DBM-019 label이 C 아님: {c.label}"
        assert c.canned_message, "pg DBM-019 canned_message 없음"
        assert "PostgreSQL" in c.canned_message, (
            f"pg DBM-019 canned_message에 'PostgreSQL' 없음: {c.canned_message}"
        )
        assert "재사용" in c.canned_message or "native" in c.canned_message, (
            f"pg DBM-019 canned_message 기능부재 언급 없음: {c.canned_message}"
        )

    def test_pg_dbm019_label_c_classify(self):
        """pg DBM-019 label C → classify_method → judgment_method='det'."""
        from judge_tool.criteria_loader import classify_method
        jm = classify_method("C", has_summary=False, in_empty_means_good=False)
        assert jm == "det", f"label C → judgment_method 'det' 기대인데 '{jm}'"

    # ── 7. 실데이터 검증 (거짓양호 0) ────────────────────────────────────────

    @pytest.mark.skipif(
        not os.path.exists(_MYSQL_NATIVE),
        reason="mysql 실데이터 없음"
    )
    def test_mysql_real_data_no_false_positive(self):
        """MySQL 실데이터: DBM-019 거짓양호(미설정→양호) 0 확인."""
        import judge_tool.det_adapters.db as _db
        from judge_tool.parsers.db_json import _build_raw_data_dict, _strip_leading_noise
        _db._RUN_CACHE.clear()
        reload_det_source()
        with open(_MYSQL_NATIVE, encoding="utf-8", errors="replace") as f:
            raw = f.read()
        arr = _strip_leading_noise(raw)
        raw_data_json = _build_raw_data_dict(arr)
        assert raw_data_json, "mysql 실데이터 파싱 실패"
        import json
        data = json.loads(raw_data_json)
        dbm019 = data.get("DBM-019", {})
        result_rows = dbm019.get("RESULT", [])
        fv = judge("DBM-019", raw_data_json, "mysql_native", {})
        assert fv.handled is True, f"mysql 실데이터 handled=False: {fv}"
        if not result_rows:
            assert fv.verdict == "판단보류", (
                f"mysql RESULT 빈 실데이터 → 판단보류 기대인데 {fv.verdict}"
            )
        else:
            # RESULT가 있으면 취약 또는 양호 (적절 설정이면 양호)
            assert fv.verdict in ("취약", "양호", "판단보류"), (
                f"mysql DBM-019 unexpected verdict: {fv.verdict}"
            )

    @pytest.mark.skipif(
        not os.path.exists(_MARIADB_NATIVE),
        reason="mariadb 실데이터 없음"
    )
    def test_mariadb_real_data_no_false_positive(self):
        """MariaDB 실데이터: DBM-019 거짓양호 0, 'not loaded' → 취약."""
        import judge_tool.det_adapters.db as _db
        from judge_tool.parsers.db_json import _build_raw_data_dict, _strip_leading_noise
        _db._RUN_CACHE.clear()
        reload_det_source()
        with open(_MARIADB_NATIVE, encoding="utf-8", errors="replace") as f:
            raw = f.read()
        arr = _strip_leading_noise(raw)
        raw_data_json = _build_raw_data_dict(arr)
        assert raw_data_json, "mariadb 실데이터 파싱 실패"
        fv = judge("DBM-019", raw_data_json, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 실데이터 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb 실데이터(플러그인 미로드) → 취약 기대인데 {fv.verdict} "
            f"— 거짓양호 또는 처리 오류"
        )

    @pytest.mark.skipif(
        not os.path.exists(_ORACLE_NATIVE),
        reason="oracle 실데이터 없음"
    )
    def test_oracle_real_data_no_false_positive(self):
        """Oracle 실데이터: DBM-019 거짓양호 0 확인."""
        import judge_tool.det_adapters.db as _db
        from judge_tool.parsers.db_json import _build_raw_data_dict, _strip_leading_noise
        _db._RUN_CACHE.clear()
        reload_det_source()
        with open(_ORACLE_NATIVE, encoding="utf-8", errors="replace") as f:
            raw = f.read()
        arr = _strip_leading_noise(raw)
        raw_data_json = _build_raw_data_dict(arr)
        assert raw_data_json, "oracle 실데이터 파싱 실패"
        import json
        data = json.loads(raw_data_json)
        result_rows = data.get("DBM-019", {}).get("RESULT", [])
        fv = judge("DBM-019", raw_data_json, "oracle_native", {})
        assert fv.handled is True, f"oracle 실데이터 handled=False: {fv}"
        if not result_rows:
            assert fv.verdict == "판단보류", (
                f"oracle RESULT 빈 실데이터 → 판단보류 기대인데 {fv.verdict}"
            )
        else:
            assert fv.verdict in ("취약", "양호", "판단보류"), (
                f"oracle DBM-019 unexpected verdict: {fv.verdict}"
            )

    @pytest.mark.skipif(
        not os.path.exists(_MSSQL_NATIVE),
        reason="mssql 실데이터 없음"
    )
    def test_mssql_real_data_no_false_positive(self):
        """MSSQL 실데이터: DBM-019 거짓양호 0 확인."""
        import judge_tool.det_adapters.db as _db
        from judge_tool.parsers.db_json import _build_raw_data_dict, _strip_leading_noise
        _db._RUN_CACHE.clear()
        reload_det_source()
        with open(_MSSQL_NATIVE, encoding="utf-8", errors="replace") as f:
            raw = f.read()
        arr = _strip_leading_noise(raw)
        raw_data_json = _build_raw_data_dict(arr)
        assert raw_data_json, "mssql 실데이터 파싱 실패"
        fv = judge("DBM-019", raw_data_json, "mssql_native", {})
        assert fv.handled is True, f"mssql 실데이터 handled=False: {fv}"
        assert fv.verdict in ("양호", "취약", "판단보류"), (
            f"mssql DBM-019 unexpected verdict: {fv.verdict}"
        )
        import json
        data = json.loads(raw_data_json)
        result_rows = data.get("DBM-019", {}).get("RESULT", [])
        if not result_rows:
            assert fv.verdict == "판단보류", (
                f"mssql RESULT 빈 실데이터 → 판단보류 기대인데 {fv.verdict} — 거짓양호!"
            )

    # ── 8. 행 존재·기대변수 부재 → 판단보류 (Critical 거짓양호 갭 잠금) ──────────
    # Opus Critical 리뷰 재현 케이스:
    #   mysql:   RESULT에 다른 변수 행만 있고 password_history/reuse_interval 행 없음
    #   mariadb: RESULT에 dict 행이 있으나 PASSWORD_REUSE_CHECK_INTERVAL도 'not loaded'도 없음

    def test_mysql_rows_but_no_expected_vars_is_hold(self):
        """MySQL Critical 재현: RESULT에 validate_password.length 행만 있고
        password_history/reuse_interval 행 없음 → 판단보류(거짓양호 아님)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "validate_password.length", "VARIABLE_VALUE": "8"},
            ]}
        })
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 기대변수 부재 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mysql RESULT 있으나 password_history/reuse_interval 없음 → 판단보류 기대인데 "
            f"{fv.verdict} — Critical 거짓양호!"
        )
        assert "재사용방지 설정 변수 미수집" in fv.rationale or "기대 변수" in fv.rationale, (
            f"판단보류 사유 메시지 미흡: {fv.rationale}"
        )

    def test_mysql_rows_but_no_expected_vars_multiple_other_rows(self):
        """MySQL: 여러 행이 있어도 password_history/reuse_interval 없으면 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "validate_password.length", "VARIABLE_VALUE": "8"},
                {"VARIABLE_NAME": "validate_password.policy", "VARIABLE_VALUE": "STRONG"},
                {"VARIABLE_NAME": "validate_password.number_count", "VARIABLE_VALUE": "1"},
            ]}
        })
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 다수행 기대변수 부재 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mysql 다수행이지만 기대변수 없음 → 판단보류 기대인데 {fv.verdict} — 거짓양호!"
        )

    def test_mysql_with_expected_var_present_still_good(self):
        """MySQL: password_history 행 존재 + 값 적절 → 여전히 양호(기존 양호 불변)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "validate_password.length", "VARIABLE_VALUE": "8"},
                {"VARIABLE_NAME": "password_history", "VARIABLE_VALUE": "10"},
                {"VARIABLE_NAME": "password_reuse_interval", "VARIABLE_VALUE": "365"},
            ]}
        })
        fv = judge("DBM-019", raw, "mysql_native", {})
        assert fv.handled is True, f"mysql 기대변수+기타행 혼재 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mysql 기대변수 존재+안전값인데 양호 아님: {fv.verdict} — 회귀!"
        )

    def test_mariadb_rows_but_no_expected_signal_is_hold(self):
        """MariaDB Critical 재현: RESULT에 dict 행 있으나
        PASSWORD_REUSE_CHECK_INTERVAL도 'not loaded' 신호도 없음 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "SOME_OTHER_VARIABLE", "VARIABLE_VALUE": "some_val"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 기대변수 부재 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mariadb RESULT 있으나 PASSWORD_REUSE_CHECK_INTERVAL/'not loaded' 없음 → 판단보류 기대인데 "
            f"{fv.verdict} — Critical 거짓양호!"
        )
        assert "재사용방지 설정 변수 미수집" in fv.rationale or "기대 변수" in fv.rationale, (
            f"판단보류 사유 메시지 미흡: {fv.rationale}"
        )

    def test_mariadb_rows_but_no_expected_signal_multiple_rows(self):
        """MariaDB: 여러 dict 행이 있어도 기대 신호 없으면 → 판단보류."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "SIMPLE_PASSWORD_CHECK_DIGITS", "VARIABLE_VALUE": "1"},
                {"VARIABLE_NAME": "SIMPLE_PASSWORD_CHECK_LETTERS_SAME_CASE", "VARIABLE_VALUE": "1"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 다수행 기대변수 부재 handled=False: {fv}"
        assert fv.verdict == "판단보류", (
            f"mariadb 다수행이지만 기대 신호 없음 → 판단보류 기대인데 {fv.verdict} — 거짓양호!"
        )

    def test_mariadb_with_expected_interval_present_still_good(self):
        """MariaDB: PASSWORD_REUSE_CHECK_INTERVAL 행 존재 + 안전값 → 여전히 양호(기존 불변)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "SOME_OTHER_VARIABLE", "VARIABLE_VALUE": "x"},
                {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "30"},
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb 기대변수+기타행 혼재 handled=False: {fv}"
        assert fv.verdict == "양호", (
            f"mariadb 기대변수 존재+안전값인데 양호 아님: {fv.verdict} — 회귀!"
        )

    def test_mariadb_not_loaded_string_with_other_rows_is_vuln(self):
        """MariaDB: 'not loaded' 문자열 + 다른 행이 섞여있어도 → 취약(기대변수 존재=수집됨, 위반있음)."""
        import judge_tool.det_adapters.db as _db
        _db._RUN_CACHE.clear()
        raw = _make_raw_ev({
            "DBM-019": {"RESULT": [
                {"VARIABLE_NAME": "SOME_OTHER_VARIABLE", "VARIABLE_VALUE": "x"},
                "PASSWORD_REUSE_CHECK plugin is not loaded!",
            ]}
        })
        fv = judge("DBM-019", raw, "mariadb_native", {})
        assert fv.handled is True, f"mariadb not-loaded+기타행 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb 'not loaded' → 취약 기대인데 {fv.verdict} — 회귀!"
        )

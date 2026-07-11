"""모드 J(테이블 주도 fail-closed 미수집 가드) 회귀 테스트.

배경(docs/superpowers/specs/2026-07-03-falsegood-audit.md §2 공통신규 / §F3 / §F4):
  db.py 어댑터의 최종 경로는 "위반0 → 양호"(judge() 결과 매핑 최하단)이다.
  이 경로는 RESULT 0행(수집 자체 실패)이나, RESULT에 행은 있지만 항목이 확인해야
  할 기대 변수/파라미터 행이 전혀 없는 경우(다른 항목만 수집됨 등)에도 그대로
  "위반0"으로 떨어져 거짓양호를 만든다.

  모드 J는 `_MODE_J_ITEMS` 테이블(base → {engine: checker} | None)로 이 케이스를
  판단보류로 강등한다:
    - DBM-008, DBM-013: 0행 체크만(엔진 무관 checker 없음, None).
    - DBM-009(F3): mysql/mariadb/oracle/postgresql 엔진별 기대 타임아웃 변수 checker.
    - DBM-014(F4): oracle 기대 파라미터명(os_roles/remote_os_roles/remote_os_authent) checker.

  과교정 가드: 정상 양호(기대행 존재 + 위반0)는 그대로 양호 유지되어야 하고,
  위반이 있으면(모드J는 위반0일 때만 개입) 기존 취약 판정이 그대로 나와야 한다.

⚠️ 범위: judge_tool/vendor/, item_configs/*.yaml, main.py, models.py, webui/,
tests/test_det_adapters_db.py는 이 작업에서 수정하지 않는다(병렬 작업 충돌 방지).
이 파일은 신규 파일이며 기존 테스트를 건드리지 않는다.
"""
from __future__ import annotations

import json

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.db  # noqa: F401 — 5개 키 등록 부작용
from judge_tool.det_adapters.db import judge, _RUN_CACHE, _MODE_J_ITEMS, _base_result_rows
from judge_tool.det_adapters.base import reload_det_source

from tests.db_cov_contract import ENGINE_TO_VARIANT


def _make_raw(data_dict: dict) -> str:
    return json.dumps(data_dict, ensure_ascii=False)


@pytest.fixture(autouse=True)
def _reset_state():
    """각 테스트 전 캐시 클리어 + DET_SOURCE 리로드(다른 스위트와 동일 패턴)."""
    _RUN_CACHE.clear()
    reload_det_source()
    yield
    _RUN_CACHE.clear()


# ──────────────────────────────────────────────────────────────────────────────
# _MODE_J_ITEMS 테이블 자체 회귀(구조 고정)
# ──────────────────────────────────────────────────────────────────────────────

class TestModeJTable:
    def test_registered_items(self):
        assert set(_MODE_J_ITEMS.keys()) == {
            "DBM-005", "DBM-006", "DBM-007", "DBM-008", "DBM-009", "DBM-013", "DBM-014",
        }

    def test_zero_row_only_items(self):
        assert _MODE_J_ITEMS["DBM-013"] is None

    def test_dbm008_engine_checkers_present(self):
        """DBM-008 잔여검증 L2(2026-07-11): 엔진별 기대필드 checker 등록 확인."""
        checkers = _MODE_J_ITEMS["DBM-008"]
        assert set(checkers.keys()) == {"mysql", "oracle", "mariadb", "mssql", "postgresql"}

    def test_dbm009_engine_checkers_present(self):
        checkers = _MODE_J_ITEMS["DBM-009"]
        assert set(checkers.keys()) == {"mysql", "mariadb", "oracle", "postgresql"}

    def test_dbm014_engine_checkers_present(self):
        checkers = _MODE_J_ITEMS["DBM-014"]
        assert set(checkers.keys()) == {"oracle"}

    def test_dbm005_engine_checkers_present(self):
        """F7: DET_SOURCE 전수 확인 결과 DBM-005 DET는 mssql_rds(cloud) 유일 —
        mssql만 checker 등록(다른 엔진은 STUB/ABSENT라 judge()에 도달하지 않음)."""
        checkers = _MODE_J_ITEMS["DBM-005"]
        assert set(checkers.keys()) == {"mssql"}

    def test_dbm006_engine_checkers_present(self):
        checkers = _MODE_J_ITEMS["DBM-006"]
        assert set(checkers.keys()) == {"mysql", "mariadb", "oracle", "mssql"}

    def test_dbm007_engine_checkers_present(self):
        """mariadb는 미등록(0행 체크만 fallback) — 기존 R3 벤더버그(수집형식 불일치로
        KeyError 삼켜짐) 영역 확대를 피하기 위해 checker를 추가하지 않음(관찰만)."""
        checkers = _MODE_J_ITEMS["DBM-007"]
        assert set(checkers.keys()) == {"mysql", "oracle", "mssql"}

    def test_base_result_rows_concats_base_and_suffixed_keys(self):
        data = {
            "DBM-009": {"RESULT": [{"a": 1}]},
            "DBM-009_1": {"RESULT": [{"a": 2}]},
            "DBM-999": {"RESULT": [{"a": 3}]},  # 무관 키 — 포함되면 안 됨
        }
        rows = _base_result_rows("DBM-009", data)
        assert rows == [{"a": 1}, {"a": 2}]


# ──────────────────────────────────────────────────────────────────────────────
# DBM-008 — 0행 가드 + 엔진별 기대필드 checker (L2, 2026-07-11)
# ──────────────────────────────────────────────────────────────────────────────

# engine: (good_row, unrelated_row(기대행 아님, 다른 항목 혼입 시뮬레이션), vuln_row)
_DBM008_CASES = {
    "mysql": (
        {"USER": "app_user", "HOST": "localhost", "PASSWORD_LAST_CHANGED": "2099-01-01"},
        {"USER": "app_user", "HOST": "localhost", "ACCOUNT_LOCKED": "N"},
        {"USER": "old_user", "HOST": "localhost", "PASSWORD_LAST_CHANGED": "2000-01-01"},
    ),
    "mariadb": (
        {"VARIABLE_NAME": "DEFAULT_PASSWORD_LIFETIME", "VARIABLE_VALUE": "90"},
        {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "900"},
        {"VARIABLE_NAME": "DEFAULT_PASSWORD_LIFETIME", "VARIABLE_VALUE": "0"},
    ),
    "oracle": (
        {"name": "oracle_user", "ptime": "19-May-26"},
        {"resource_name": "IDLE_TIME", "profile": "DEFAULT", "limit": "30"},
        {"name": "oracle_user", "ptime": "19-Jun-25"},
    ),
    "mssql": (
        {"name": "sa", "days_after_changed": "0"},
        {"name": "sa", "is_policy_checked": "1"},
        {"name": "old_user", "days_after_changed": "180"},
    ),
    "postgresql": (
        {"rolvaliduntil": "2099-01-01 00:00:00+09", "rolcanlogin": "t", "rolname": "app_user"},
        {"rolname": "app_role", "rolsuper": "f"},
        {"rolvaliduntil": None, "rolcanlogin": "t", "rolname": "app_user"},
    ),
}

# oracle만 실제 vendor data_key가 'DBM-008_1'(ptime 기반)이라 다른 4엔진('DBM-008'
# 그대로)과 wrapping key가 다르다 — 틀린 key로 감싸면 vendor가 아예 스킵해 위반이
# 나올 수 없는 케이스까지 우연히 '통과'해버려 검증력이 없다(실제로 vuln_row가
# 취약 판정을 못 받는 것으로 드러남). 엔진별 정확한 data_key로 감싼다.
_DBM008_DATA_KEY: dict = {
    "mysql": "DBM-008", "mariadb": "DBM-008", "oracle": "DBM-008_1",
    "mssql": "DBM-008", "postgresql": "DBM-008",
}


@pytest.mark.parametrize("engine", ["mysql", "mariadb", "oracle", "mssql", "postgresql"])
class TestModeJDbm008:
    def test_zero_rows_hold(self, engine):
        raw = _make_raw({_DBM008_DATA_KEY[engine]: {"RESULT": []}})
        fv = judge("DBM-008", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-008 {engine} 0행인데 판단보류 아님: {fv}"

    def test_missing_expected_field_hold(self, engine):
        """RESULT에 행은 있으나 기대 필드가 하나도 없음(다른 항목 행 혼입 등) →
        부분수집 → 거짓양호 금지(수정 전엔 위반0 → 양호로 새던 케이스).

        mysql/mssql/postgresql은 vendor가 기대 필드를 조건문에서 직접 참조
        (`datum['PASSWORD_LAST_CHANGED']`/`datum['days_after_changed']`/
        `datum['rolvaliduntil']`)하므로 그 필드가 없는 행은 모드J 이전에 KeyError →
        R3가 먼저 handled=False로 차단할 수 있다(DBM-006과 동일 사유). 어느 경로든
        거짓양호만 없으면 안전 — 두 경로 모두 허용한다.
        """
        _, unrelated_row, _ = _DBM008_CASES[engine]
        raw = _make_raw({_DBM008_DATA_KEY[engine]: {"RESULT": [unrelated_row]}})
        fv = judge("DBM-008", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.verdict != "양호", (
            f"[거짓양호] DBM-008 {engine} 기대필드 부재인데 양호 판정: {fv}"
        )
        if fv.handled:
            assert fv.verdict == "판단보류", f"DBM-008 {engine} 기대필드 부재: {fv}"

    def test_expected_field_present_stays_good(self, engine):
        """기대필드 존재 + 위반0 → 양호 유지(과교정 없음 — 정상 양호 보존)."""
        good_row, _, _ = _DBM008_CASES[engine]
        raw = _make_raw({_DBM008_DATA_KEY[engine]: {"RESULT": [good_row]}})
        fv = judge("DBM-008", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-008 {engine} 정상행인데 양호 아님: {fv}"

    def test_violation_bypasses_guard(self, engine):
        """위반이 있으면 모드J는 개입하지 않고 기존 취약 판정을 유지한다."""
        _, _, vuln_row = _DBM008_CASES[engine]
        raw = _make_raw({_DBM008_DATA_KEY[engine]: {"RESULT": [vuln_row]}})
        fv = judge("DBM-008", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-008 {engine} 위반행인데 취약 아님: {fv}"


class TestModeJDbm008OracleMultiKey:
    """oracle DBM-008은 data_key가 DBM-008_1(ptime)/DBM-008_2(PASSWORD_LIFE_TIME)
    2개로 나뉜다(mysql/mariadb/mssql/postgresql은 단일 data_key) — L1/L2에서 확인된
    oracle 고유의 '부분수집'(한쪽 sub-key만 존재) 케이스를 직접 검증한다."""

    def test_only_1_present_still_good(self):
        """DBM-008_1(ptime)만 있고 DBM-008_2 자체가 없어도 _1만으로 기대필드 충족
        → 양호 유지(과교정 아님 — _2 부재를 미수집으로 오인하지 않음)."""
        raw = _make_raw({"DBM-008_1": {"RESULT": [
            {"name": "oracle_user", "ptime": "19-May-26"}
        ]}})
        fv = judge("DBM-008", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-008 oracle _1만 존재인데 양호 아님: {fv}"

    def test_only_2_present_still_good(self):
        """DBM-008_2(PASSWORD_LIFE_TIME, limit 필드)만 있어도 기대필드 충족 →
        양호 유지."""
        raw = _make_raw({"DBM-008_2": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "PASSWORD_LIFE_TIME", "limit": "180"}
        ]}})
        fv = judge("DBM-008", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-008 oracle _2만 존재인데 양호 아님: {fv}"

    def test_2_has_only_grace_time_rows_still_good(self):
        """DBM-008_2에 PASSWORD_GRACE_TIME 행만 있고 PASSWORD_LIFE_TIME 행이 없어도
        'profile'+'limit' 스키마 자체는 존재(DBM-007 oracle checker와 동일 관용구,
        resource_name 값은 검사하지 않음) → 기대변수 존재로 인정 → 위반0이면 양호
        유지(동작보존 — R-OR008 기존 회귀 test_det_adapters_db.py::
        TestF1Dbm008VendorDataKey::test_oracle_dbm008_2_password_grace_time_not_a_violation
        와 일관됨: GRACE_TIME행은 vendor 조건에서 자연 배제되는 정상 케이스이지
        미수집 신호가 아니다)."""
        raw = _make_raw({"DBM-008_2": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "PASSWORD_GRACE_TIME", "limit": "7"}
        ]}})
        fv = judge("DBM-008", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "양호", (
            f"DBM-008 oracle GRACE_TIME행만 있는데 양호 아님: {fv}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# DBM-013 — 0행 체크만 (F5, 대표 엔진 mysql/mariadb)
# ──────────────────────────────────────────────────────────────────────────────

class TestModeJDbm013:
    def test_mysql_zero_rows_hold(self):
        raw = _make_raw({"DBM-013": {"RESULT": []}})
        fv = judge("DBM-013", raw, "mysql_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-013 mysql 0행인데 판단보류 아님: {fv}"

    def test_mariadb_zero_rows_hold(self):
        raw = _make_raw({"DBM-013": {"RESULT": []}})
        fv = judge("DBM-013", raw, "mariadb_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-013 mariadb 0행인데 판단보류 아님: {fv}"

    def test_mysql_good_row_stays_good(self):
        raw = _make_raw({"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "localhost"}
        ]}})
        fv = judge("DBM-013", raw, "mysql_native", {})
        assert fv.verdict == "양호", f"DBM-013 mysql localhost인데 양호 아님: {fv}"

    def test_mysql_violation_bypasses_guard(self):
        raw = _make_raw({"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "%"}
        ]}})
        fv = judge("DBM-013", raw, "mysql_native", {})
        assert fv.verdict == "취약", f"DBM-013 mysql HOST=%%인데 취약 아님: {fv}"


# ──────────────────────────────────────────────────────────────────────────────
# DBM-009(F3) — 0행 / 기대행부재 / 기대행존재+양호 / 위반→취약, 4엔진 전수
# ──────────────────────────────────────────────────────────────────────────────

_DBM009_CASES = {
    # engine: (good_row, unrelated_row(기대행 아님), vuln_row)
    "mysql": (
        {"VARIABLE_NAME": "wait_timeout", "VARIABLE_VALUE": "900"},
        {"VARIABLE_NAME": "max_connections", "VARIABLE_VALUE": "151"},
        {"VARIABLE_NAME": "wait_timeout", "VARIABLE_VALUE": "9999"},
    ),
    "mariadb": (
        {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "900"},
        {"VARIABLE_NAME": "MAX_CONNECTIONS", "VARIABLE_VALUE": "151"},
        {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "9999"},
    ),
    "oracle": (
        {"profile": "DEFAULT", "resource_name": "IDLE_TIME", "limit": "30"},
        {"profile": "DEFAULT", "resource_name": "SESSIONS_PER_USER", "limit": "10"},
        {"profile": "DEFAULT", "resource_name": "IDLE_TIME", "limit": "UNLIMITED"},
    ),
    "postgresql": (
        {"setting_name": "idle_in_transaction_session_timeout", "value": "900"},
        {"setting_name": "statement_timeout", "value": "0"},
        {"setting_name": "idle_in_transaction_session_timeout", "value": "0"},
    ),
}


@pytest.mark.parametrize("engine", ["mysql", "mariadb", "oracle", "postgresql"])
class TestModeJDbm009:
    def test_zero_rows_hold(self, engine):
        raw = _make_raw({"DBM-009": {"RESULT": []}})
        fv = judge("DBM-009", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-009 {engine} 0행인데 판단보류 아님: {fv}"

    def test_missing_expected_variable_hold(self, engine):
        """RESULT에 행은 있으나 기대 타임아웃 변수가 하나도 없음 → 판단보류(미수집)."""
        _, unrelated_row, _ = _DBM009_CASES[engine]
        raw = _make_raw({"DBM-009": {"RESULT": [unrelated_row]}})
        fv = judge("DBM-009", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", (
            f"DBM-009 {engine} 기대행 부재인데 판단보류 아님: {fv}"
        )

    def test_expected_variable_present_stays_good(self, engine):
        """기대행 존재 + 위반0 → 양호 유지(과교정 없음 — 정상 양호 보존)."""
        good_row, _, _ = _DBM009_CASES[engine]
        raw = _make_raw({"DBM-009": {"RESULT": [good_row]}})
        fv = judge("DBM-009", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-009 {engine} 정상행인데 양호 아님: {fv}"

    def test_violation_bypasses_guard(self, engine):
        """위반이 있으면 모드J는 개입하지 않고 기존 취약 판정을 유지한다."""
        _, _, vuln_row = _DBM009_CASES[engine]
        raw = _make_raw({"DBM-009": {"RESULT": [vuln_row]}})
        fv = judge("DBM-009", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-009 {engine} 위반행인데 취약 아님: {fv}"


# ──────────────────────────────────────────────────────────────────────────────
# DBM-014(F4) — oracle 전용, 0행 / 기대행부재 / 기대행존재+양호 / 위반→취약
# ──────────────────────────────────────────────────────────────────────────────

class TestModeJDbm014:
    def test_oracle_zero_rows_hold(self):
        raw = _make_raw({"DBM-014": {"RESULT": []}})
        fv = judge("DBM-014", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-014 oracle 0행인데 판단보류 아님: {fv}"

    def test_oracle_missing_expected_param_hold(self):
        """os_roles/remote_os_roles/remote_os_authent 행이 하나도 없음 → 판단보류."""
        raw = _make_raw({"DBM-014": {"RESULT": [
            {"name": "audit_trail", "value": "FALSE"}
        ]}})
        fv = judge("DBM-014", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", (
            f"DBM-014 oracle 기대 파라미터 부재인데 판단보류 아님: {fv}"
        )

    def test_oracle_expected_param_present_stays_good(self):
        """os_roles=FALSE(정상 비활성) 존재 + 위반0 → 양호 유지."""
        raw = _make_raw({"DBM-014": {"RESULT": [
            {"name": "os_roles", "value": "FALSE"}
        ]}})
        fv = judge("DBM-014", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-014 oracle os_roles=FALSE인데 양호 아님: {fv}"

    def test_oracle_violation_bypasses_guard(self):
        """value != 'FALSE' → 위반 존재 → 모드J 미개입, 기존 취약 판정 유지."""
        raw = _make_raw({"DBM-014": {"RESULT": [
            {"name": "remote_os_authent", "value": "TRUE"}
        ]}})
        fv = judge("DBM-014", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-014 oracle remote_os_authent=TRUE인데 취약 아님: {fv}"


# ──────────────────────────────────────────────────────────────────────────────
# DBM-005(F7) — mssql_rds(cloud) 전용, 0행 / sample필드부재 / sample=null(양호) / 위반→취약
# ──────────────────────────────────────────────────────────────────────────────

class TestModeJDbm005:
    def test_mssql_rds_zero_rows_hold(self):
        raw = _make_raw({"DBM-005": {"RESULT": []}})
        fv = judge("DBM-005", raw, "mssql_rds", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-005 mssql_rds 0행인데 판단보류 아님: {fv}"

    def test_mssql_rds_missing_sample_field_hold(self):
        """RESULT에 행은 있으나 'sample' 필드가 없음(DBM-005와 무관한 행) → 거짓양호 금지.

        vendor cloud_analysis.py의 dbm_005는 `datum['sample']`을 무조건 직접 접근하므로
        'sample' 키가 아예 없는 행은 모드J의 checker 분기에 도달하기 전에 KeyError →
        R3(벤더 예외 삼킴 차단, db.py)가 먼저 handled=False로 막는다(같은 필드를
        checker도 존재검사하므로 "존재하되 checker만 실패"인 경로가 원천적으로 없음).
        어느 경로든 거짓양호(양호 판정)만 없으면 안전 — 두 경로 모두 허용한다.
        """
        raw = _make_raw({"DBM-005": {"RESULT": [
            {"unrelated_field": "x"}
        ]}})
        fv = judge("DBM-005", raw, "mssql_rds", {})
        assert fv.verdict != "양호", (
            f"[거짓양호] DBM-005 mssql_rds 기대필드(sample) 부재인데 양호 판정: {fv}"
        )
        if fv.handled:
            assert fv.verdict == "판단보류", f"DBM-005 mssql_rds 기대필드 부재: {fv}"

    def test_mssql_rds_sample_null_stays_good(self):
        """sample=None(샘플 없음=진짜 양호) + 위반0 → 양호 유지(과교정 없음)."""
        raw = _make_raw({"DBM-005": {"RESULT": [
            {"table": "app.users", "column": "email", "sample": None}
        ]}})
        fv = judge("DBM-005", raw, "mssql_rds", {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-005 mssql_rds sample=None인데 양호 아님: {fv}"

    def test_mssql_rds_violation_bypasses_guard(self):
        """sample이 not None(평문 샘플 존재) → 위반 → 모드J 미개입, 기존 취약 판정 유지."""
        raw = _make_raw({"DBM-005": {"RESULT": [
            {"table": "app.users", "column": "pwd", "sample": "plaintext123"}
        ]}})
        fv = judge("DBM-005", raw, "mssql_rds", {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-005 mssql_rds sample 존재인데 취약 아님: {fv}"


# ──────────────────────────────────────────────────────────────────────────────
# DBM-006(F6) — 로그인 실패잠금, 4엔진(mysql/mariadb/oracle/mssql) 전수
# ──────────────────────────────────────────────────────────────────────────────

_DBM006_CASES = {
    # engine: (good_row, unrelated_row(기대행 아님), vuln_row)
    "mysql": (
        {"USER": "root", "HOST": "localhost", "USER_ATTRIBUTES": ""},
        {"USER": "app_user", "HOST": "localhost", "PASSWORD_LAST_CHANGED": "2099-01-01"},
        {"USER": "app_user", "HOST": "localhost", "USER_ATTRIBUTES": ""},
    ),
    "mariadb": (
        {"VARIABLE_NAME": "MAX_PASSWORD_ERRORS", "VARIABLE_VALUE": "5"},
        {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "900"},
        {"VARIABLE_NAME": "MAX_PASSWORD_ERRORS", "VARIABLE_VALUE": "10"},
    ),
    "oracle": (
        {"profile": "DEFAULT", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "10"},
        {"profile": "DEFAULT", "resource_name": "IDLE_TIME", "limit": "30"},
        {"profile": "DEFAULT", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "UNLIMITED"},
    ),
    "mssql": (
        {"is_policy_checked": "1", "name": "sa"},
        {"days_after_changed": "0", "name": "sa"},
        {"is_policy_checked": "0", "name": "sa"},
    ),
}


@pytest.mark.parametrize("engine", ["mysql", "mariadb", "oracle", "mssql"])
class TestModeJDbm006:
    def test_zero_rows_hold(self, engine):
        raw = _make_raw({"DBM-006": {"RESULT": []}})
        fv = judge("DBM-006", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-006 {engine} 0행인데 판단보류 아님: {fv}"

    def test_missing_expected_field_hold(self, engine):
        """RESULT에 행은 있으나 기대 필드가 하나도 없음 → 거짓양호 금지.

        oracle/mariadb는 vendor 조건이 값 비교 전에 필드 존재를 요구하지 않아
        (동일 스키마의 다른 값) 모드J checker 분기(handled=True, 판단보류)에 도달한다.
        mysql/mssql은 vendor가 checker와 동일한 필드를 조건문에서 무조건 직접
        참조(`datum['USER_ATTRIBUTES']`/`datum['is_policy_checked']`)하므로 그 필드가
        없는 행은 모드J 이전에 KeyError → R3가 먼저 handled=False로 차단한다(같은
        필드를 모드J checker도 존재검사하므로 "존재하되 checker만 실패"인 경로가
        원천적으로 없음). 어느 경로든 거짓양호만 없으면 안전 — 두 경로 모두 허용한다.
        """
        _, unrelated_row, _ = _DBM006_CASES[engine]
        raw = _make_raw({"DBM-006": {"RESULT": [unrelated_row]}})
        fv = judge("DBM-006", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.verdict != "양호", (
            f"[거짓양호] DBM-006 {engine} 기대필드 부재인데 양호 판정: {fv}"
        )
        if fv.handled:
            assert fv.verdict == "판단보류", f"DBM-006 {engine} 기대필드 부재: {fv}"

    def test_expected_field_present_stays_good(self, engine):
        """기대필드 존재 + 위반0 → 양호 유지(과교정 없음 — 정상 양호 보존)."""
        good_row, _, _ = _DBM006_CASES[engine]
        raw = _make_raw({"DBM-006": {"RESULT": [good_row]}})
        fv = judge("DBM-006", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-006 {engine} 정상행인데 양호 아님: {fv}"

    def test_violation_bypasses_guard(self, engine):
        """위반이 있으면 모드J는 개입하지 않고 기존 취약 판정을 유지한다."""
        _, _, vuln_row = _DBM006_CASES[engine]
        raw = _make_raw({"DBM-006": {"RESULT": [vuln_row]}})
        fv = judge("DBM-006", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-006 {engine} 위반행인데 취약 아님: {fv}"


# ──────────────────────────────────────────────────────────────────────────────
# DBM-007(F6) — 비밀번호 복잡도, mysql/mssql(양극성 전수) + oracle(판단보류 상한 고정)
# ──────────────────────────────────────────────────────────────────────────────

_DBM007_CASES = {
    "mysql": (
        {"VARIABLE_NAME": "validate_password.policy", "VARIABLE_VALUE": "STRONG"},
        {"VARIABLE_NAME": "max_connections", "VARIABLE_VALUE": "151"},
        {"VARIABLE_NAME": "validate_password.policy", "VARIABLE_VALUE": "LOW"},
    ),
    "mssql": (
        {"is_policy_checked": "1", "name": "sa"},
        {"days_after_changed": "0", "name": "sa"},
        {"is_policy_checked": "0", "name": "sa"},
    ),
}


@pytest.mark.parametrize("engine", ["mysql", "mssql"])
class TestModeJDbm007(object):
    def test_zero_rows_hold(self, engine):
        raw = _make_raw({"DBM-007": {"RESULT": []}})
        fv = judge("DBM-007", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-007 {engine} 0행인데 판단보류 아님: {fv}"

    def test_missing_expected_field_hold(self, engine):
        """mssql은 vendor가 checker와 동일 필드(is_policy_checked)를 무조건 직접
        참조하므로 그 필드가 없는 행은 모드J 이전에 KeyError → R3가 먼저
        handled=False로 차단한다(TestModeJDbm006와 동일 사유). 어느 경로든
        거짓양호만 없으면 안전 — 두 경로 모두 허용한다."""
        _, unrelated_row, _ = _DBM007_CASES[engine]
        raw = _make_raw({"DBM-007": {"RESULT": [unrelated_row]}})
        fv = judge("DBM-007", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.verdict != "양호", (
            f"[거짓양호] DBM-007 {engine} 기대필드 부재인데 양호 판정: {fv}"
        )
        if fv.handled:
            assert fv.verdict == "판단보류", f"DBM-007 {engine} 기대필드 부재: {fv}"

    def test_expected_field_present_stays_good(self, engine):
        good_row, _, _ = _DBM007_CASES[engine]
        raw = _make_raw({"DBM-007": {"RESULT": [good_row]}})
        fv = judge("DBM-007", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "양호", f"DBM-007 {engine} 정상행인데 양호 아님: {fv}"

    def test_violation_bypasses_guard(self, engine):
        good_row, unrelated_row, vuln_row = _DBM007_CASES[engine]
        raw = _make_raw({"DBM-007": {"RESULT": [vuln_row]}})
        fv = judge("DBM-007", raw, ENGINE_TO_VARIANT[engine], {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-007 {engine} 위반행인데 취약 아님: {fv}"


class TestModeJDbm007OracleHoldOrVuln:
    """oracle DBM-007 (OBS-OR007 수정 완료, 2026-07-11):

    과거: exception.profile/limit=[] → 'not in []'이 항상 True라 행 존재만으로
    무조건 위반(거짓취약 vendor 버그, KNOWN_BUGS.md R-OR007). 수정 후:
    vendor rules.DBM-007.limit=['NULL']로 "검증함수 미할당(NULL)"만 실제 위반으로
    탐지한다. 함수가 할당된 경우(limit!='NULL') 내용 적정성은 결정론 불가이므로
    db.py 모드C2(oracle 한정 detect-vuln-else-hold)가 위반0을 양호 대신 판단보류로
    강제한다 — 즉 oracle DBM-007은 여전히 자동 '양호'에 도달하지 않는다(의도된 설계,
    거짓양호 회피 최우선). 0행(미수집)은 모드J가 별도로 판단보류 처리한다."""

    def test_oracle_zero_rows_hold(self):
        raw = _make_raw({"DBM-007_1": {"RESULT": []}})
        fv = judge("DBM-007", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", f"DBM-007 oracle 0행인데 판단보류 아님: {fv}"

    def test_oracle_verify_function_null_is_vuln(self):
        """limit=='NULL'(검증함수 미할당) → 실제 위반 → 취약(수정된 결정론)."""
        raw = _make_raw({"DBM-007_1": {"RESULT": [
            {"profile": "DEFAULT", "limit": "NULL"}
        ]}})
        fv = judge("DBM-007", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "취약", f"DBM-007 oracle limit=NULL인데 취약 아님: {fv}"

    def test_oracle_verify_function_assigned_is_hold_not_good(self):
        """limit!='NULL'(검증함수 할당됨) → 위반0이나 함수 내용(복잡도 적정성)을
        결정론으로 확인 불가 — 양호가 아니라 판단보류여야 한다(거짓양호 회피,
        모드C2 회귀 고정). 임의의 숫자값('5')처럼 함수명이 아닌 값이 와도 동일하게
        판단보류(자동 양호 금지)가 유지되는지 확인."""
        raw = _make_raw({"DBM-007_1": {"RESULT": [
            {"profile": "DEFAULT", "limit": "5"}
        ]}})
        fv = judge("DBM-007", raw, "oracle_native", {})
        assert fv.handled is True
        assert fv.verdict == "판단보류", (
            f"DBM-007 oracle 함수할당(limit!=NULL)인데 판단보류 아님(양호로 자동판정?): {fv}"
        )

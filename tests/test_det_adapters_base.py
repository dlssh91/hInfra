"""det_adapters/base.py 단위테스트.

검증:
  - classify 조회 계약 (default/variants/엔진토큰폴백/미지항목→ABSENT)
  - gate() STUB/ABSENT/UNREACHABLE/MANUAL → handled=False, verdict≠양호 (§18.6 e)
  - DBM-005 mysql → STUB → handled=False 케이스
  - 가짜 adapter가 호출되지 않음(common 미호출 단언)
  - 실 DET_SOURCE.yaml 존재 시 로드·파싱 가드 테스트 (skipif)
"""
import os

import pytest

# 테스트 픽스처 경로
_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "det_source_test.yaml"
)
# 실 DET_SOURCE.yaml 경로
_REAL_DET_SOURCE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "judge_tool", "vendor", "common", "DET_SOURCE.yaml"
)


@pytest.fixture(autouse=True)
def load_test_fixture():
    """각 테스트 전에 테스트 픽스처를 로드하고, 테스트 후 실 파일로 복원."""
    from judge_tool.det_adapters import base as det_base
    det_base.reload_det_source(_FIXTURE_PATH)
    yield
    # 복원 (실 파일 없으면 빈 dict로 폴백 — reload_det_source 기본 동작)
    det_base.reload_det_source()


class TestClassify:
    """classify() 조회 계약 검증."""

    def test_default_det(self):
        """default: DET 항목 → 'DET' 반환."""
        from judge_tool.det_adapters.base import classify
        assert classify("SRV-001", "linux") == "DET"

    def test_default_det_any_variant(self):
        """default만 있으면 variant 무관 동일 결과."""
        from judge_tool.det_adapters.base import classify
        assert classify("SRV-001", "win") == "DET"
        assert classify("SRV-001", "aix") == "DET"

    def test_variants_direct_match(self):
        """variants에 variant 직접 매칭."""
        from judge_tool.det_adapters.base import classify
        assert classify("SRV-069", "linux") == "DET"
        assert classify("SRV-069", "aix") == "MANUAL"
        assert classify("SRV-069", "win") == "ABSENT"

    def test_variants_engine_token_fallback(self):
        """엔진토큰 폴백: 'mysql_native' → split('_')[0]='mysql' → 'STUB'."""
        from judge_tool.det_adapters.base import classify
        assert classify("DBM-005", "mysql_native") == "STUB"
        assert classify("DBM-005", "pg_aurora") == "STUB"
        assert classify("DBM-005", "mssql_rds") == "DET"

    def test_variants_direct_beats_engine_token(self):
        """직접 매칭이 엔진토큰보다 우선."""
        from judge_tool.det_adapters.base import classify
        # mysql은 직접 매칭
        assert classify("DBM-005", "mysql") == "STUB"
        # mssql은 직접 매칭 → DET
        assert classify("DBM-005", "mssql") == "DET"

    def test_absent_unknown_item(self):
        """미지 항목(items에 없음) → 'ABSENT'."""
        from judge_tool.det_adapters.base import classify
        assert classify("SRV-999", "linux") == "ABSENT"
        assert classify("UNKNOWN-001", "win") == "ABSENT"

    def test_absent_unknown_variant_in_variants(self):
        """variants에 없고 default도 없으면 'ABSENT'."""
        from judge_tool.det_adapters.base import classify
        # SRV-069 variants에 'unknown_os' 없고 default 없음
        assert classify("SRV-069", "unknown_os") == "ABSENT"

    def test_unreachable(self):
        """UNREACHABLE 항목."""
        from judge_tool.det_adapters.base import classify
        assert classify("PRCV-027", "linux") == "UNREACHABLE"

    def test_manual(self):
        """MANUAL 항목."""
        from judge_tool.det_adapters.base import classify
        assert classify("SRV-022", "linux") == "MANUAL"


class TestIsDeterministic:
    """is_deterministic() = classify=='DET' 만 True."""

    def test_det_is_true(self):
        from judge_tool.det_adapters.base import is_deterministic
        assert is_deterministic("SRV-001", "linux") is True

    def test_stub_is_false(self):
        from judge_tool.det_adapters.base import is_deterministic
        assert is_deterministic("DBM-005", "mysql") is False

    def test_absent_is_false(self):
        from judge_tool.det_adapters.base import is_deterministic
        assert is_deterministic("SRV-999", "linux") is False

    def test_manual_is_false(self):
        from judge_tool.det_adapters.base import is_deterministic
        assert is_deterministic("SRV-022", "linux") is False

    def test_unreachable_is_false(self):
        from judge_tool.det_adapters.base import is_deterministic
        assert is_deterministic("PRCV-027", "linux") is False


class TestGate:
    """gate() §18.1 C1 거짓 양호 차단 게이트."""

    def test_det_returns_none(self):
        """DET 항목 → None 반환(어댑터 진행 허용)."""
        from judge_tool.det_adapters.base import gate
        assert gate("SRV-001", "linux") is None

    def test_stub_handled_false(self):
        """STUB → handled=False, verdict≠양호 (§18.6 e)."""
        from judge_tool.det_adapters.base import gate
        result = gate("DBM-005", "mysql")
        assert result is not None
        assert result.handled is False
        assert result.verdict != "양호"

    def test_absent_handled_false(self):
        """ABSENT → handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("SRV-999", "linux")
        assert result is not None
        assert result.handled is False
        assert result.verdict != "양호"

    def test_unreachable_handled_false(self):
        """UNREACHABLE → handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("PRCV-027", "linux")
        assert result is not None
        assert result.handled is False
        assert result.verdict != "양호"

    def test_manual_handled_false(self):
        """MANUAL → handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("SRV-022", "linux")
        assert result is not None
        assert result.handled is False
        assert result.verdict != "양호"

    def test_dbm005_mysql_stub_not_good(self):
        """DBM-005 mysql=STUB → handled=False, verdict≠양호 (§18.4/§18.6 e)."""
        from judge_tool.det_adapters.base import gate
        result = gate("DBM-005", "mysql")
        assert result is not None
        assert result.handled is False
        assert result.verdict != "양호", "STUB 항목이 양호로 누출되면 안 됨(§18.1 C1)"

    def test_dbm005_mssql_det_none(self):
        """DBM-005 mssql=DET → gate None(어댑터 진행 가능)."""
        from judge_tool.det_adapters.base import gate
        assert gate("DBM-005", "mssql") is None

    # ── 사용자결정(2026-06-16): DET-PARTIAL 패스스루 신규 계약 ─────────────────

    def test_det_partial_returns_none(self):
        """DET-PARTIAL 항목 → gate None(어댑터 진행 허용) — DET-PARTIAL 패스스루."""
        from judge_tool.det_adapters.base import gate
        # SRV-021: default=DET-PARTIAL (테스트 픽스처에 등록)
        result = gate("SRV-021", "linux")
        assert result is None, (
            f"DET-PARTIAL은 gate 통과(None)여야 하나 handled={getattr(result, 'handled', 'N/A')!r} — "
            "DET-PARTIAL 패스스루 계약 위반"
        )

    def test_det_partial_no_good_verdict_leaked(self):
        """DET-PARTIAL gate 통과 시 양호 verdict가 gate에서 직접 나오지 않음(None 반환)."""
        from judge_tool.det_adapters.base import gate
        result = gate("SRV-073", "linux")
        # gate가 None이면 양호 누출 없음(어댑터가 처리). ForcedVerdict라면 양호가 아님을 단언.
        assert result is None or result.verdict != "양호", (
            "DET-PARTIAL gate에서 양호 직접 반환 — 거짓양호 위험"
        )

    # ── C1 불변: STUB/ABSENT/MANUAL/UNREACHABLE은 여전히 차단 ────────────────────

    def test_c1_stub_still_blocked(self):
        """C1 불변: STUB(DBM-005 mysql) → 여전히 handled=False (완화가 STUB으로 새지 않음)."""
        from judge_tool.det_adapters.base import gate
        result = gate("DBM-005", "mysql")
        assert result is not None, "STUB은 gate 차단(C1 불변)"
        assert result.handled is False, f"STUB → handled=False이어야 함: {result.handled!r}"
        assert result.verdict != "양호", "STUB이 양호로 누출 — C1 위반"

    def test_c1_absent_still_blocked(self):
        """C1 불변: ABSENT(미지 항목) → 여전히 handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("SRV-UNKNOWN-9999", "linux")
        assert result is not None, "ABSENT는 gate 차단(C1 불변)"
        assert result.handled is False
        assert result.verdict != "양호"

    def test_c1_manual_still_blocked(self):
        """C1 불변: MANUAL(SRV-022) → 여전히 handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("SRV-022", "linux")
        assert result is not None, "MANUAL은 gate 차단(C1 불변)"
        assert result.handled is False
        assert result.verdict != "양호"

    def test_c1_unreachable_still_blocked(self):
        """C1 불변: UNREACHABLE(PRCV-027) → 여전히 handled=False."""
        from judge_tool.det_adapters.base import gate
        result = gate("PRCV-027", "linux")
        assert result is not None, "UNREACHABLE은 gate 차단(C1 불변)"
        assert result.handled is False
        assert result.verdict != "양호"

    def test_gate_does_not_call_adapter(self):
        """gate()는 어댑터를 호출하지 않는다(common 미호출 단언)."""
        from judge_tool.det_adapters import base as det_base
        from judge_tool.det_adapters.base import gate as det_gate

        called = []

        def fake_adapter(item_id, raw, variant, thresholds, *, context=None):
            called.append(item_id)
            from judge_tool.det_adapters.base import ForcedVerdict
            return ForcedVerdict(verdict="양호", confidence=0.9,
                                 rationale="fake", handled=True)

        # 가짜 어댑터 등록
        det_base._DET_ADAPTERS["test_profile"] = fake_adapter
        try:
            # gate는 어댑터를 호출하지 않는다
            result = det_gate("DBM-005", "mysql")  # STUB → handled=False
            assert result is not None and not result.handled
            assert called == [], "gate()가 어댑터를 호출해서는 안 됨"
        finally:
            det_base._DET_ADAPTERS.pop("test_profile", None)


class TestGetAdapter:
    """get_adapter() — Phase 0→Phase 1 전환 확인."""

    def test_phase1_server_adapter_registered(self):
        """Phase 1: server 어댑터가 등록되어 있어야 한다."""
        # server.py import 시 _DET_ADAPTERS["server"] 등록 부작용 발생
        import judge_tool.det_adapters.server  # noqa: F401
        from judge_tool.det_adapters.base import get_adapter
        assert get_adapter("server") is not None, "Phase 1: server 어댑터가 등록되지 않음"
        # db_mysql / cloud 어댑터는 아직 미등록(Phase 2+)
        assert get_adapter("db_mysql") is None
        assert get_adapter("cloud") is None
        assert get_adapter("") is None


@pytest.mark.skipif(
    not os.path.exists(_REAL_DET_SOURCE_PATH),
    reason="실 DET_SOURCE.yaml이 없음(Phase 0 정상 — Phase 1 이후 활성화)"
)
class TestRealDETSourceLoad:
    """실 DET_SOURCE.yaml 존재 시 로드·파싱 가드."""

    def test_real_file_loads(self):
        """실 DET_SOURCE.yaml이 있으면 로드 후 items dict를 반환."""
        from judge_tool.det_adapters import base as det_base
        det_base.reload_det_source(_REAL_DET_SOURCE_PATH)
        items = det_base._DET_SOURCE.get("items", {})
        assert isinstance(items, dict), "items는 dict여야 함"

    def test_real_file_classify_returns_string(self):
        """실 파일 로드 후 classify()가 문자열을 반환."""
        from judge_tool.det_adapters import base as det_base
        det_base.reload_det_source(_REAL_DET_SOURCE_PATH)
        result = det_base.classify("SRV-001", "linux")
        assert isinstance(result, str)
        assert result in {"DET", "STUB", "UNREACHABLE", "ABSENT", "MANUAL", "DET-PARTIAL"}

"""_det_common_handler 스모크 테스트 (Phase 0 동작 불변 검증).

검증:
  - _HANDLERS에 "det_common" 키 존재
  - Phase 0(어댑터 미등록): _det_common_handler가 _judge_one 경로로 폴백
  - JudgeContext.thresholds 기본값 빈 dict
  - Criterion.thresholds 기본값 빈 dict
"""
import pytest
from dataclasses import fields
from unittest.mock import MagicMock, patch


class TestHandlerRegistry:
    """_HANDLERS 레지스트리 검증."""

    def test_det_common_registered(self):
        """_HANDLERS에 'det_common'이 등록되어 있다."""
        from judge_tool.main import _HANDLERS
        assert "det_common" in _HANDLERS, "'det_common' 핸들러가 등록되지 않음"

    def test_det_common_handler_is_callable(self):
        """등록된 핸들러가 callable이다."""
        from judge_tool.main import _HANDLERS
        handler = _HANDLERS["det_common"]
        assert callable(handler)


class TestJudgeContextThresholds:
    """JudgeContext.thresholds 기본값 검증."""

    def test_thresholds_default_empty_dict(self):
        """thresholds를 지정하지 않으면 빈 dict다."""
        from judge_tool.main import JudgeContext
        ctx = JudgeContext(
            profile=MagicMock(),
            profile_key="server",
            client=MagicMock(),
            items={},
            variant="linux",
        )
        assert ctx.thresholds == {}, "thresholds 기본값은 빈 dict여야 함"

    def test_thresholds_can_be_set(self):
        """thresholds를 직접 지정할 수 있다."""
        from judge_tool.main import JudgeContext
        th = {"SRV-069": {"password_max_age_days": 90}}
        ctx = JudgeContext(
            profile=MagicMock(),
            profile_key="server",
            client=MagicMock(),
            items={},
            variant="linux",
            thresholds=th,
        )
        assert ctx.thresholds == th

    def test_existing_ctx_fields_unchanged(self):
        """기존 JudgeContext 필드(profile/profile_key/client/items/variant)가 유지된다."""
        from judge_tool.main import JudgeContext
        ctx_fields = {f.name for f in fields(JudgeContext)}
        assert "profile" in ctx_fields
        assert "profile_key" in ctx_fields
        assert "client" in ctx_fields
        assert "items" in ctx_fields
        assert "variant" in ctx_fields
        assert "thresholds" in ctx_fields


class TestCriterionThresholds:
    """Criterion.thresholds/thresholds_source 기본값 검증."""

    def test_criterion_thresholds_default(self):
        """Criterion.thresholds 기본값은 빈 dict다."""
        from judge_tool.models import Criterion
        crit = Criterion(
            item_id="SRV-001", item_name="test", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
        )
        assert crit.thresholds == {}

    def test_criterion_thresholds_source_default(self):
        """Criterion.thresholds_source 기본값은 None이다."""
        from judge_tool.models import Criterion
        crit = Criterion(
            item_id="SRV-001", item_name="test", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
        )
        assert crit.thresholds_source is None


class TestDetCommonPhase0Fallback:
    """Phase 0(어댑터 미등록) _det_common_handler → _judge_one 폴백."""

    def test_phase0_calls_judge_one(self):
        """어댑터 없으면 _judge_one이 호출된다."""
        from judge_tool.main import _det_common_handler, JudgeContext
        from judge_tool.models import Criterion, EvidenceItem, Judgment

        # 가짜 Judgment 반환값
        fake_judgment = Judgment(
            item_id="SRV-001", item_name="test", variant="linux",
            risk=None, verdict="판단보류", confidence=0.0,
            rationale="fake", cited_evidence=[], scope="스크립트 전체",
            management_review_needed=False, script_status=None,
            agreement="N/A", needs_review=True,
        )

        crit = Criterion(
            item_id="SRV-001", item_name="test", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
            judgment_method="det_common",
        )
        item = EvidenceItem(item_id="SRV-001", variant="linux")
        ctx = JudgeContext(
            profile=MagicMock(
                status_available=False,
                flag_vulnerable_for_review=False,
                empty_means_good=set(),
            ),
            profile_key="server",
            client=MagicMock(),
            items={},
            variant="linux",
        )

        with patch("judge_tool.main._judge_one", return_value=fake_judgment) as mock_judge_one:
            result = _det_common_handler(crit, item, ctx)

        mock_judge_one.assert_called_once_with(crit, item, ctx)
        assert result is fake_judgment

    def test_phase1_server_adapter_in_registry(self):
        """Phase 1: server 어댑터가 레지스트리에 등록되어 있어야 한다.
        db_mysql / cloud 어댑터는 Phase 2+에서 등록 예정."""
        import judge_tool.det_adapters.server  # noqa: F401 — 등록 부작용
        from judge_tool.det_adapters import base as det_base
        # Phase 1: server 어댑터 등록됨
        assert det_base.get_adapter("server") is not None, "Phase 1: server 어댑터 미등록"
        # db_mysql / cloud 어댑터는 아직 미등록
        assert det_base.get_adapter("db_mysql") is None
        assert det_base.get_adapter("cloud") is None

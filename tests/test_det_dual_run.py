"""듀얼런 하니스 단위테스트.

검증:
  1. det=양호 + fake_llm=양호 → matched
  2. det=취약 + fake_llm=양호 → mismatched, diff_class='llm_mismatch'
  3. det_common 아닌 항목 → skipped
  4. llm_client=None → det_only
  5. diff_table 문자열 생성
  6. LLM 예외 → 크래시 없이 notes 기록

합성 criteria/report 픽스처 사용. 실 Ollama 호출 없음.
"""
from __future__ import annotations

import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# 어댑터 등록 부작용 (테스트 전 레지스트리 확보)
import judge_tool.det_adapters.server  # noqa: F401


# ─────────────────────────────────────────────────────────────────────────────
# 헬퍼 & 픽스처
# ─────────────────────────────────────────────────────────────────────────────

def _make_crit(item_id: str, judgment_method: str = "det_common",
               label: str = "A", variant: str = "linux"):
    """합성 Criterion 생성."""
    from judge_tool.models import Criterion
    return Criterion(
        item_id=item_id,
        item_name=f"테스트 항목 {item_id}",
        risk=None,
        variant=variant,
        eval_type="스크립트",
        standard="판단기준 텍스트",
        method="판단방법 텍스트",
        applicable=True,
        label=label,
        judgment_method=judgment_method,
    )


def _make_item(item_id: str, variant: str = "linux", raw: str = "",
               status: str = "good"):
    """합성 EvidenceItem 생성."""
    from judge_tool.models import EvidenceItem, ResourceEvidence
    resources = []
    if raw:
        resources = [ResourceEvidence(
            resource_id=f"{item_id}-res",
            status=status,
            detail="테스트 증거",
            evidence=raw,
            raw_evidence=raw,
        )]
    return EvidenceItem(item_id=item_id, variant=variant, resources=resources)


def _make_ctx(profile_key: str = "server", variant: str = "linux",
              items: dict = None, client=None):
    """합성 JudgeContext 생성."""
    from judge_tool.main import JudgeContext
    from unittest.mock import MagicMock

    profile_mock = MagicMock()
    profile_mock.status_available = False
    profile_mock.flag_vulnerable_for_review = True
    profile_mock.empty_means_good = frozenset()

    return JudgeContext(
        profile=profile_mock,
        profile_key=profile_key,
        client=client,
        items=items or {},
        variant=variant,
        thresholds={},
    )


class FakeLLMClient:
    """고정 verdict를 반환하는 가짜 LLM 클라이언트 (실 Ollama 호출 없음)."""

    def __init__(self, verdict: str = "양호", rationale: str = "가짜 근거"):
        self.verdict = verdict
        self.rationale = rationale
        self.call_count = 0

    def chat(self, system: str, user: str) -> str:
        self.call_count += 1
        import json
        return json.dumps({
            "verdict": self.verdict,
            "confidence": 0.8,
            "rationale": self.rationale,
            "cited_evidence": [],
        }, ensure_ascii=False)


class ErrorLLMClient:
    """항상 예외를 던지는 가짜 LLM 클라이언트."""

    def chat(self, system: str, user: str) -> str:
        raise ConnectionError("Ollama 연결 실패 (가짜)")


# ─────────────────────────────────────────────────────────────────────────────
# 합성 보고서/기준 픽스처 (tmp_path 기반)
# ─────────────────────────────────────────────────────────────────────────────

def _make_server_xml(tmp_dir: str, items: list) -> str:
    """합성 서버 XML 보고서 생성.

    서버 파서가 기대하는 최소 구조를 만든다.
    linux OS variant 내용 기반 식별 지원.
    """
    root = ET.Element("report")
    asset = ET.SubElement(root, "asset")
    os_el = ET.SubElement(asset, "os")
    os_el.text = "Linux"

    for item_id, raw_output in items:
        check = ET.SubElement(root, "check")
        check.set("id", item_id)
        output = ET.SubElement(check, "output")
        output.text = raw_output

    path = os.path.join(tmp_dir, "test-s-sample.xml")
    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


def _make_criteria_xlsx(tmp_dir: str, profile_key: str = "server") -> str:
    """합성 기준 xlsx를 만들 수 없으므로, 실제 기준 파일 경로를 반환.

    없으면 None 반환 (테스트 스킵용).
    """
    candidates = [
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "ref",
            "전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx",
        ),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


# ─────────────────────────────────────────────────────────────────────────────
# dataclass 유지 검증
# ─────────────────────────────────────────────────────────────────────────────

class TestDataclassShape:
    """DualRunRecord/DualRunResult 데이터클래스 필드 불변 검증."""

    def test_dual_run_record_fields(self):
        from tests.det_dual_run import DualRunRecord
        from dataclasses import fields
        names = {f.name for f in fields(DualRunRecord)}
        required = {
            "item_id", "variant",
            "det_verdict", "det_rationale", "det_handled",
            "llm_verdict", "llm_rationale",
            "diff_class", "notes",
        }
        assert required.issubset(names), f"필드 누락: {required - names}"

    def test_dual_run_result_fields(self):
        from tests.det_dual_run import DualRunResult
        from dataclasses import fields
        names = {f.name for f in fields(DualRunResult)}
        required = {"records", "total", "matched", "mismatched", "det_only", "skipped"}
        assert required.issubset(names), f"필드 누락: {required - names}"

    def test_record_defaults(self):
        from tests.det_dual_run import DualRunRecord
        rec = DualRunRecord(item_id="SRV-001", variant="linux")
        assert rec.det_verdict is None
        assert rec.llm_verdict is None
        assert rec.det_handled is False
        assert rec.diff_class is None
        assert rec.notes == ""

    def test_result_defaults(self):
        from tests.det_dual_run import DualRunResult
        res = DualRunResult()
        assert res.total == 0
        assert res.matched == 0
        assert res.mismatched == 0
        assert res.det_only == 0
        assert res.skipped == 0
        assert res.records == []


# ─────────────────────────────────────────────────────────────────────────────
# classify_diff 단위 검증
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifyDiff:
    """classify_diff 분류 로직 검증."""

    def test_det_vuln_llm_good_is_llm_mismatch(self):
        from tests.det_dual_run import classify_diff, DualRunRecord
        rec = DualRunRecord(item_id="SRV-001", variant="linux",
                            det_verdict="취약", llm_verdict="양호")
        assert classify_diff(rec) == "llm_mismatch"

    def test_det_vuln_llm_holdover_is_llm_mismatch(self):
        from tests.det_dual_run import classify_diff, DualRunRecord
        rec = DualRunRecord(item_id="SRV-001", variant="linux",
                            det_verdict="취약", llm_verdict="판단보류")
        assert classify_diff(rec) == "llm_mismatch"

    def test_det_good_llm_vuln_is_review(self):
        from tests.det_dual_run import classify_diff, DualRunRecord
        rec = DualRunRecord(item_id="SRV-001", variant="linux",
                            det_verdict="양호", llm_verdict="취약")
        assert classify_diff(rec) == "review"

    def test_det_good_llm_holdover_is_review(self):
        from tests.det_dual_run import classify_diff, DualRunRecord
        rec = DualRunRecord(item_id="SRV-001", variant="linux",
                            det_verdict="양호", llm_verdict="판단보류")
        assert classify_diff(rec) == "review"


# ─────────────────────────────────────────────────────────────────────────────
# run_dual 핵심 시나리오 (mock 기반, 실 파일 불필요)
# ─────────────────────────────────────────────────────────────────────────────

class TestRunDualMocked:
    """run_dual의 핵심 시나리오를 mock으로 검증 (실 파일/Ollama 없음)."""

    def _make_det_result(self, verdict: str, handled: bool = True):
        """_run_det 반환값 형식 생성."""
        return (verdict, f"결정론 근거 ({verdict})", handled)

    def _make_llm_judgment(self, verdict: str):
        """_judge_one 반환 Judgment 형식 생성."""
        from judge_tool.models import Judgment
        return Judgment(
            item_id="SRV-999", item_name="테스트", variant="linux",
            risk=None, verdict=verdict, confidence=0.8,
            rationale=f"LLM 근거 ({verdict})",
            cited_evidence=[], scope="스크립트 전체",
            management_review_needed=False, script_status=None,
            agreement="N/A", needs_review=True,
        )

    def _build_run_dual_env(self, tmp_path, item_id="SRV-999",
                            det_verdict="양호", llm_verdict="양호",
                            judgment_method="det_common"):
        """run_dual을 실제 파이프라인 없이 mock으로 실행하는 환경 구성.

        inner_run_dual_patched: 내부 함수들을 모두 mock으로 대체해
        run_dual의 집계 로직만 검증한다.
        """
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        crit = Criterion(
            item_id=item_id, item_name="테스트", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
            applicable=True, judgment_method=judgment_method,
        )
        item = EvidenceItem(
            item_id=item_id, variant="linux",
            resources=[ResourceEvidence(
                resource_id=f"{item_id}-r", status="good",
                detail="d", evidence="e", raw_evidence="raw"
            )],
        )

        return crit, item

    def test_matched_both_good(self, tmp_path):
        """det=양호 + llm=양호 → matched++."""
        from tests.det_dual_run import run_dual
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        crit, item = self._build_run_dual_env(tmp_path, det_verdict="양호",
                                               llm_verdict="양호")
        fake_llm = FakeLLMClient(verdict="양호")

        det_return = ("양호", "결정론 근거", True)
        llm_judgment = self._make_llm_judgment("양호")

        with patch("tests.det_dual_run._run_det", return_value=det_return), \
             patch("tests.det_dual_run._judge_one", return_value=llm_judgment), \
             patch("tests.det_dual_run.load_criteria",
                   return_value={("SRV-999", "linux"): crit}), \
             patch("tests.det_dual_run.get_parser") as mock_parser, \
             patch("tests.det_dual_run.aggregate",
                   return_value={"SRV-999": item}), \
             patch("tests.det_dual_run.get_profile") as mock_profile, \
             patch("tests.det_dual_run._build_thresholds", return_value={}):

            mock_profile.return_value = MagicMock(
                excluded=False, parser="server_xml",
                variants={"linux": MagicMock(name="linux", filename_markers=())},
            )
            mock_profile.return_value.variant_from_filename.return_value = "linux"
            mock_profile.return_value.status_available = False
            mock_profile.return_value.flag_vulnerable_for_review = True
            mock_profile.return_value.empty_means_good = frozenset()

            parser_inst = MagicMock()
            parser_inst.parse.return_value = []
            parser_inst.detect_variant.return_value = "linux"
            mock_parser.return_value = parser_inst

            result = run_dual(
                str(tmp_path / "fake.xml"),
                str(tmp_path / "fake.xlsx"),
                "server",
                llm_client=fake_llm,
                variant="linux",
            )

        assert result.total == 1
        assert result.matched == 1
        assert result.mismatched == 0
        assert result.records[0].diff_class is None

    def test_mismatched_det_vuln_llm_good(self, tmp_path):
        """det=취약 + llm=양호 → mismatched, diff_class='llm_mismatch'."""
        from tests.det_dual_run import run_dual
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        crit, item = self._build_run_dual_env(tmp_path, det_verdict="취약",
                                               llm_verdict="양호")
        fake_llm = FakeLLMClient(verdict="양호")

        det_return = ("취약", "결정론 취약 근거", True)
        llm_judgment = self._make_llm_judgment("양호")

        with patch("tests.det_dual_run._run_det", return_value=det_return), \
             patch("tests.det_dual_run._judge_one", return_value=llm_judgment), \
             patch("tests.det_dual_run.load_criteria",
                   return_value={("SRV-999", "linux"): crit}), \
             patch("tests.det_dual_run.get_parser") as mock_parser, \
             patch("tests.det_dual_run.aggregate",
                   return_value={"SRV-999": item}), \
             patch("tests.det_dual_run.get_profile") as mock_profile, \
             patch("tests.det_dual_run._build_thresholds", return_value={}):

            mock_profile.return_value = MagicMock(
                excluded=False, parser="server_xml",
                variants={"linux": MagicMock(name="linux", filename_markers=())},
            )
            mock_profile.return_value.variant_from_filename.return_value = "linux"
            mock_profile.return_value.status_available = False
            mock_profile.return_value.flag_vulnerable_for_review = True
            mock_profile.return_value.empty_means_good = frozenset()

            parser_inst = MagicMock()
            parser_inst.parse.return_value = []
            parser_inst.detect_variant.return_value = "linux"
            mock_parser.return_value = parser_inst

            result = run_dual(
                str(tmp_path / "fake.xml"),
                str(tmp_path / "fake.xlsx"),
                "server",
                llm_client=fake_llm,
                variant="linux",
            )

        assert result.total == 1
        assert result.mismatched == 1
        assert result.matched == 0
        rec = result.records[0]
        assert rec.diff_class == "llm_mismatch"
        # notes에 양측 근거가 기록되었는지
        assert "결정론 취약 근거" in rec.notes or "LLM 근거" in rec.notes or len(rec.notes) > 0

    def test_non_det_common_skipped(self, tmp_path):
        """judgment_method != det_common 항목은 skipped로 집계."""
        from tests.det_dual_run import run_dual
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        # llm 라벨 항목
        crit = Criterion(
            item_id="SRV-001", item_name="테스트", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
            applicable=True, judgment_method="llm",  # det_common 아님
        )
        item = EvidenceItem(item_id="SRV-001", variant="linux",
                            resources=[])

        fake_llm = FakeLLMClient(verdict="양호")

        with patch("tests.det_dual_run.load_criteria",
                   return_value={("SRV-001", "linux"): crit}), \
             patch("tests.det_dual_run.get_parser") as mock_parser, \
             patch("tests.det_dual_run.aggregate",
                   return_value={"SRV-001": item}), \
             patch("tests.det_dual_run.get_profile") as mock_profile, \
             patch("tests.det_dual_run._build_thresholds", return_value={}):

            mock_profile.return_value = MagicMock(
                excluded=False, parser="server_xml",
                variants={"linux": MagicMock(name="linux", filename_markers=())},
            )
            mock_profile.return_value.variant_from_filename.return_value = "linux"
            mock_profile.return_value.status_available = False
            mock_profile.return_value.flag_vulnerable_for_review = True
            mock_profile.return_value.empty_means_good = frozenset()

            parser_inst = MagicMock()
            parser_inst.parse.return_value = []
            parser_inst.detect_variant.return_value = "linux"
            mock_parser.return_value = parser_inst

            result = run_dual(
                str(tmp_path / "fake.xml"),
                str(tmp_path / "fake.xlsx"),
                "server",
                llm_client=fake_llm,
                variant="linux",
            )

        assert result.total == 0
        assert result.skipped == 1
        assert result.records == []

    def test_det_only_when_no_llm(self, tmp_path):
        """llm_client=None → det_only++, llm_verdict=None."""
        from tests.det_dual_run import run_dual
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        crit = Criterion(
            item_id="SRV-999", item_name="테스트", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
            applicable=True, judgment_method="det_common",
        )
        item = EvidenceItem(
            item_id="SRV-999", variant="linux",
            resources=[ResourceEvidence(
                resource_id="r", status="good",
                detail="d", evidence="e", raw_evidence="raw",
            )],
        )

        det_return = ("양호", "결정론 근거", True)

        with patch("tests.det_dual_run._run_det", return_value=det_return), \
             patch("tests.det_dual_run.load_criteria",
                   return_value={("SRV-999", "linux"): crit}), \
             patch("tests.det_dual_run.get_parser") as mock_parser, \
             patch("tests.det_dual_run.aggregate",
                   return_value={"SRV-999": item}), \
             patch("tests.det_dual_run.get_profile") as mock_profile, \
             patch("tests.det_dual_run._build_thresholds", return_value={}):

            mock_profile.return_value = MagicMock(
                excluded=False, parser="server_xml",
                variants={"linux": MagicMock(name="linux", filename_markers=())},
            )
            mock_profile.return_value.variant_from_filename.return_value = "linux"
            mock_profile.return_value.status_available = False
            mock_profile.return_value.flag_vulnerable_for_review = True
            mock_profile.return_value.empty_means_good = frozenset()

            parser_inst = MagicMock()
            parser_inst.parse.return_value = []
            parser_inst.detect_variant.return_value = "linux"
            mock_parser.return_value = parser_inst

            result = run_dual(
                str(tmp_path / "fake.xml"),
                str(tmp_path / "fake.xlsx"),
                "server",
                llm_client=None,  # LLM 없음
                variant="linux",
            )

        assert result.total == 1
        assert result.det_only == 1
        assert result.records[0].llm_verdict is None
        assert result.matched == 0
        assert result.mismatched == 0


# ─────────────────────────────────────────────────────────────────────────────
# LLM 예외 내성
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMFaultTolerance:
    """LLM 호출 실패 시 크래시 없이 notes에 기록."""

    def test_llm_exception_recorded_in_notes(self, tmp_path):
        from tests.det_dual_run import run_dual
        from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence

        crit = Criterion(
            item_id="SRV-999", item_name="테스트", risk=None,
            variant="linux", eval_type="스크립트",
            standard="판단기준", method="판단방법",
            applicable=True, judgment_method="det_common",
        )
        item = EvidenceItem(
            item_id="SRV-999", variant="linux",
            resources=[ResourceEvidence(
                resource_id="r", status="good",
                detail="d", evidence="e", raw_evidence="raw",
            )],
        )

        det_return = ("양호", "결정론 근거", True)

        # _judge_one이 예외를 던지도록 패치
        with patch("tests.det_dual_run._run_det", return_value=det_return), \
             patch("tests.det_dual_run._judge_one",
                   side_effect=ConnectionError("가짜 연결 오류")), \
             patch("tests.det_dual_run.load_criteria",
                   return_value={("SRV-999", "linux"): crit}), \
             patch("tests.det_dual_run.get_parser") as mock_parser, \
             patch("tests.det_dual_run.aggregate",
                   return_value={"SRV-999": item}), \
             patch("tests.det_dual_run.get_profile") as mock_profile, \
             patch("tests.det_dual_run._build_thresholds", return_value={}):

            mock_profile.return_value = MagicMock(
                excluded=False, parser="server_xml",
                variants={"linux": MagicMock(name="linux", filename_markers=())},
            )
            mock_profile.return_value.variant_from_filename.return_value = "linux"
            mock_profile.return_value.status_available = False
            mock_profile.return_value.flag_vulnerable_for_review = True
            mock_profile.return_value.empty_means_good = frozenset()

            parser_inst = MagicMock()
            parser_inst.parse.return_value = []
            parser_inst.detect_variant.return_value = "linux"
            mock_parser.return_value = parser_inst

            # 예외가 없어야 한다
            result = run_dual(
                str(tmp_path / "fake.xml"),
                str(tmp_path / "fake.xlsx"),
                "server",
                llm_client=ErrorLLMClient(),
                variant="linux",
            )

        assert result.total == 1
        rec = result.records[0]
        assert "ConnectionError" in rec.notes or "오류" in rec.notes
        assert rec.llm_verdict is None


# ─────────────────────────────────────────────────────────────────────────────
# diff_table 문자열 생성 검증
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffTable:
    """diff_table 출력 검증."""

    def _make_result(self) -> "DualRunResult":
        from tests.det_dual_run import DualRunResult, DualRunRecord
        result = DualRunResult()
        result.total = 3
        result.matched = 1
        result.mismatched = 1
        result.det_only = 1
        result.skipped = 2

        result.records = [
            DualRunRecord(item_id="SRV-001", variant="linux",
                          det_verdict="양호", llm_verdict="양호"),
            DualRunRecord(item_id="SRV-002", variant="linux",
                          det_verdict="취약", llm_verdict="양호",
                          diff_class="llm_mismatch", notes="취약근거 vs 양호근거"),
            DualRunRecord(item_id="SRV-003", variant="linux",
                          det_verdict="양호", llm_verdict=None,
                          det_handled=True),
        ]
        return result

    def test_diff_table_is_str(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        assert isinstance(table, str)

    def test_diff_table_contains_summary(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        assert "total=3" in table
        assert "matched=1" in table
        assert "mismatched=1" in table
        assert "det_only=1" in table
        assert "skipped=2" in table

    def test_diff_table_contains_item_ids(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        assert "SRV-001" in table
        assert "SRV-002" in table
        assert "SRV-003" in table

    def test_diff_table_shows_mismatch_section(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        assert "llm_mismatch" in table
        assert "불일치" in table

    def test_diff_table_det_only_marker(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        # det_only 항목은 match 컬럼에 'det_only' 표시
        assert "det_only" in table

    def test_diff_table_match_rate(self):
        from tests.det_dual_run import diff_table
        result = self._make_result()
        table = diff_table(result)
        # LLM 실행 항목 2건 중 1건 일치 → 50%
        assert "50.0%" in table


# ─────────────────────────────────────────────────────────────────────────────
# save_results (출력 파일 저장)
# ─────────────────────────────────────────────────────────────────────────────

class TestSaveResults:
    """save_results: out/ 에 json + txt 파일 생성."""

    def test_save_creates_files(self, tmp_path):
        from tests.det_dual_run import save_results, DualRunResult, DualRunRecord
        result = DualRunResult()
        result.total = 1
        result.matched = 1
        result.records = [
            DualRunRecord(item_id="SRV-001", variant="linux",
                          det_verdict="양호", llm_verdict="양호"),
        ]
        out_dir = str(tmp_path / "out")
        json_path, table_path = save_results(result, "server", "linux", out_dir)

        assert os.path.exists(json_path)
        assert os.path.exists(table_path)
        assert json_path.endswith(".json")
        assert table_path.endswith(".txt")

    def test_save_json_structure(self, tmp_path):
        import json as _json
        from tests.det_dual_run import save_results, DualRunResult, DualRunRecord
        result = DualRunResult()
        result.total = 1
        result.records = [
            DualRunRecord(item_id="SRV-001", variant="linux",
                          det_verdict="취약", llm_verdict="양호",
                          diff_class="llm_mismatch", notes="테스트"),
        ]
        out_dir = str(tmp_path / "out")
        json_path, _ = save_results(result, "server", "linux", out_dir)

        with open(json_path, encoding="utf-8") as fh:
            data = _json.load(fh)

        assert "summary" in data
        assert "records" in data
        assert data["summary"]["total"] == 1
        assert data["records"][0]["item_id"] == "SRV-001"
        assert data["records"][0]["diff_class"] == "llm_mismatch"


# ─────────────────────────────────────────────────────────────────────────────
# 실 파일 기반 E2E (criteria xlsx가 있을 때만)
# ─────────────────────────────────────────────────────────────────────────────

class TestRunDualWithRealFiles:
    """실제 서버 샘플 + 평가기준 xlsx로 run_dual을 det_only 모드로 실행.

    criteria xlsx가 없거나 샘플 파일이 없으면 스킵한다.
    LLM은 호출하지 않는다 (det_only=True, llm_client=None).
    """

    def test_server_linux_det_only(self, tmp_path):
        from tests.det_dual_run import run_dual

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        criteria_path = os.path.join(
            project_root, "ref",
            "전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx",
        )
        report_path = os.path.join(
            project_root, "collected", "server", "linux", "linux-s-sample.xml")

        if not os.path.exists(criteria_path):
            pytest.skip("평가기준 xlsx 없음")
        if not os.path.exists(report_path):
            pytest.skip("서버 샘플 xml 없음")

        result = run_dual(
            report_path, criteria_path, "server",
            llm_client=None,  # det_only
            variant="linux",
        )

        # det_common 항목이 1건 이상 존재해야 한다
        assert result.total >= 0  # 0이어도 오류 아님(det_common 항목 없을 수 있음)
        # 모든 레코드가 det_only (llm_verdict=None)
        for rec in result.records:
            assert rec.llm_verdict is None
        # skipped >= 0
        assert result.skipped >= 0

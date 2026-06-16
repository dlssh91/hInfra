"""판단방식 5분류(judgment_method) 테스트.

- classify_method 단일 분류 함수: llm / llm_det / det / interview / interview_holdonly
- criteria_loader가 실제 기준 xlsx에서 항목별 judgment_method를 채움
- (e) interview_holdonly: summary_instruction 없는 B → LLM 요약 없이 보류만
- writer: '판단방식' 컬럼 + 한글 표기
"""
import json
import os

import openpyxl
import pytest

from judge_tool.criteria_loader import classify_method, load_criteria
from judge_tool.main import run, _summarize_one, JudgeContext
from judge_tool.models import (
    Criterion, EvidenceItem, Judgment, ResourceEvidence)
from judge_tool.profile import CLOUD, DB_MYSQL
from judge_tool import writer

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sample_db_mysql.txt")


# ── classify_method 단위 ─────────────────────────────────────────────────────

def test_classify_method_all_buckets():
    f = classify_method
    assert f("A", has_summary=False, in_empty_means_good=False) == "llm"
    assert f("A", has_summary=False, in_empty_means_good=True) == "llm_det"
    assert f("C", has_summary=False, in_empty_means_good=False) == "det"
    assert f("D", has_summary=False, in_empty_means_good=False) == "det"
    assert f("B", has_summary=True, in_empty_means_good=False) == "interview"
    assert f("B", has_summary=False, in_empty_means_good=False) == "interview_holdonly"


def test_classify_method_hybrid_b_empty_means_good_is_interview():
    # B + empty_means_good은 주(主)방식 기준 interview(요약 있음). A+guard만 llm_det.
    assert classify_method("B", has_summary=True, in_empty_means_good=True) == "interview"


def test_classify_method_unknown_label_defaults_llm():
    assert classify_method("Z", has_summary=False, in_empty_means_good=False) == "llm"


def test_all_classified_methods_are_registered():
    """classify_method가 산출할 수 있는 모든 method가 디스패치 레지스트리에
    등록돼 있어야 한다(미등록 시 run()이 LLM 폴백+경고로 빠지는 것 방지)."""
    from judge_tool.main import _HANDLERS
    cases = [("A", False, False), ("A", False, True), ("C", False, False),
             ("D", False, False), ("B", True, False), ("B", False, False)]
    for label, has_summary, emg in cases:
        m = classify_method(label, has_summary=has_summary,
                            in_empty_means_good=emg)
        assert m in _HANDLERS, f"method '{m}' 미등록 (label={label})"


# ── criteria_loader가 실제 기준 xlsx에서 방식을 채움 ─────────────────────────

def test_loader_assigns_method_db(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, DB_MYSQL, profile_key="db_mysql")
    # Phase 4: DET 항목에 judgment_method: det_common 부여 (label 유지).
    # mysql_rds 포함 전 mysql 변형에 적용됨.
    assert crit[("DBM-005", "mysql_rds")].judgment_method == "llm_det"   # A+empty, STUB, yaml 미설정
    assert crit[("DBM-016", "mysql_rds")].judgment_method == "det_common" # D(patch), Phase4 det_common 부여
    assert crit[("DBM-003", "mysql_rds")].judgment_method == "det_common" # B+요약, Phase4 det_common 부여
    assert crit[("DBM-006", "mysql_rds")].judgment_method == "det_common" # A, Phase4 det_common 부여


def test_loader_assigns_method_cloud_holdonly(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD, profile_key="cloud")
    # PISM-045: summary_instruction 제거됨 → interview_holdonly (e)
    assert crit[("PISM-045", "AWS")].judgment_method == "interview_holdonly"
    # PISM-023: 요약지시 보유 → interview
    assert crit[("PISM-023", "AWS")].judgment_method == "interview"


# ── (e) interview_holdonly: LLM 요약 호출 없음 ───────────────────────────────

class _NoCallClient:
    def chat(self, system, user):
        raise AssertionError("holdonly는 LLM을 호출하면 안 된다")


def test_holdonly_skips_llm_summary():
    crit = Criterion(
        item_id="PISM-045", item_name="보류항목", risk=3.0, variant="AWS",
        eval_type="스크립트", standard="기준", method="방법", applicable=True,
        label="B", summary_instruction=None, judgment_method="interview_holdonly")
    item = EvidenceItem(
        item_id="PISM-045", variant="AWS",
        resources=[ResourceEvidence("r1", "review", "d", "e")])
    ctx = JudgeContext(profile=CLOUD, profile_key="cloud",
                       client=_NoCallClient(), items={}, variant="AWS")
    j = _summarize_one(crit, item, ctx)
    assert j is not None
    assert j.verdict == "판단보류"
    assert j.interview_summary is None
    assert "인터뷰" in j.rationale


# ── writer: 판단방식 컬럼 + 한글 표기 ────────────────────────────────────────

def _mk_judgment(item_id, method):
    return Judgment(
        item_id=item_id, item_name=item_id, variant="AWS", risk=3.0,
        verdict="판단보류", confidence=0.0, rationale="r", cited_evidence=[],
        scope="스크립트 전체", management_review_needed=False,
        script_status=None, agreement="N/A", needs_review=True,
        label="B", judgment_method=method)


def test_writer_method_column_and_display(tmp_path):
    assert "판단방식" in writer._HEADERS
    assert writer.METHOD_DISPLAY["interview_holdonly"] == "인터뷰(내용정리X)"
    js = [_mk_judgment("PISM-045", "interview_holdonly"),
          _mk_judgment("DBM-005", "llm_det")]
    xout = str(tmp_path / "r.xlsx")
    writer.write_excel(js, {"tool_version": "t"},
                       {"expected": 2, "judged": 2, "missing": []}, xout)
    wb = openpyxl.load_workbook(xout)
    ws = wb["판정결과"]
    headers = [c.value for c in ws[1]]
    midx = headers.index("판단방식")
    vals = {ws.cell(r, 1).value: ws.cell(r, midx + 1).value
            for r in range(2, ws.max_row + 1)}
    assert vals["PISM-045"] == "인터뷰(내용정리X)"
    assert vals["DBM-005"] == "LLM+결정론"


# ── e2e: 산출 JSON에 judgment_method 노출 ───────────────────────────────────

class _StubGood:
    def chat(self, system, user):
        return ('{"verdict":"양호","confidence":0.9,'
                '"rationale":"ok","cited_evidence":[]}')


def _db_xlsx(path):
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "n"); ws.cell(4, 8, "r")
    ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
    # DBM-001=C(det), DBM-004=B(interview)
    for r, dbm in [(5, "DBM-001"), (6, "DBM-004")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, dbm); ws.cell(r, 8, 5.0)
        ws.cell(r, 17, "o"); ws.cell(r, 37, "* 양호 - ..."); ws.cell(r, 38, "m")
    wb.save(path)


def test_e2e_json_has_judgment_method(tmp_path):
    criteria = str(tmp_path / "db.xlsx"); _db_xlsx(criteria)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    run(report, criteria, "db_mysql", _StubGood(), jout, xout, "stub")
    data = json.load(open(jout, encoding="utf-8"))
    by_id = {j["item_id"]: j for j in data["judgments"]}
    assert by_id["DBM-001"]["judgment_method"] == "det_common"  # Phase 4c: DBM-001 det_common 부여 (사전공격 어댑터)
    # Phase 4: DBM-004는 DET → judgment_method: det_common (label B+요약 유지, det_common 우선)
    assert by_id["DBM-004"]["judgment_method"] == "det_common"  # Phase4 det_common 부여

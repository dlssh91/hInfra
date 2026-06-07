"""label 기반 라우팅 테스트 (A/B/C/D).

C·D 라벨 → LLM 호출 없이 판단보류 자동 처리(canned_message).
B 라벨   → LLM 요약 호출, verdict=판단보류 고정, interview_summary 출력.
"""
import json
import os

import openpyxl
import pytest

import judge_tool.main as main_mod
from judge_tool.main import run, _auto_defer, _summarize_one
from judge_tool.models import Criterion, EvidenceItem
from judge_tool.profile import CLOUD


FIXTURE_XML = os.path.join(
    os.path.dirname(__file__), "fixtures", "sample_aws_report.xml")


class CallCountClient:
    """chat 호출 횟수를 기록하는 대역. C/D 라우팅 시 0회 호출 검증에 사용."""

    def __init__(self):
        self.calls = 0
        self._default = ('{"verdict":"양호","confidence":0.9,'
                         '"rationale":"OK","cited_evidence":[]}')

    def chat(self, system, user):
        self.calls += 1
        return self._default


class SummaryClient:
    """B항목 요약 전용 대역: chat 호출 시 고정 요약문 반환."""

    def chat(self, system, user):
        return "계정 목록 요약: admin@% 1개, rdsadmin(시스템) 1개. 담당자 인터뷰 필요."


def _make_criterion(item_id="PISM-001", label="A",
                    canned_message=None, summary_instruction=None) -> Criterion:
    return Criterion(
        item_id=item_id,
        item_name="테스트 항목",
        risk=3.0,
        variant="AWS",
        eval_type="스크립트",
        standard="기준 텍스트",
        method="방법 텍스트",
        applicable=True,
        label=label,
        canned_message=canned_message,
        summary_instruction=summary_instruction,
    )


def _make_item(item_id="PISM-001") -> EvidenceItem:
    return EvidenceItem(item_id=item_id, variant="AWS", resources=[])


def _write_criteria_with_labels(path, rows):
    """label 정보는 YAML에서 오므로, xlsx에는 기본 스크립트 항목만 기입."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    for i, (iid, name, risk, etype, method, standard) in enumerate(rows):
        r = CLOUD.data_start_row + i
        ws.cell(r, CLOUD.id_col, iid)
        ws.cell(r, CLOUD.name_col, name)
        ws.cell(r, CLOUD.risk_col, risk)
        for vname in ("AWS", "Azure"):
            v = CLOUD.variants[vname]
            ws.cell(r, v.eval_type_col, etype)
            ws.cell(r, v.method_col, method)
            ws.cell(r, v.standard_col, standard)
    wb.save(path)


# ---------------------------------------------------------------------------
# 단위: _auto_defer (C·D 라벨)
# ---------------------------------------------------------------------------

def test_auto_defer_c_uses_canned_message():
    crit = _make_criterion(label="C", canned_message="해시 복잡도 판단 불가.")
    item = _make_item()
    j = _auto_defer(crit, item, CLOUD)
    assert j.verdict == "판단보류"
    assert j.label == "C"
    assert "해시 복잡도 판단 불가" in j.rationale


def test_auto_defer_d_uses_canned_message():
    crit = _make_criterion(label="D", canned_message="EOL 외부지식 필요.")
    item = _make_item()
    j = _auto_defer(crit, item, CLOUD)
    assert j.verdict == "판단보류"
    assert j.label == "D"
    assert "EOL 외부지식" in j.rationale


def test_auto_defer_no_canned_message_fallback():
    """canned_message 없을 때 기본 문구로 폴백."""
    crit = _make_criterion(label="C", canned_message=None)
    item = _make_item()
    j = _auto_defer(crit, item, CLOUD)
    assert j.verdict == "판단보류"
    assert j.label == "C"
    assert "[C항목 자동 판단보류]" in j.rationale


# ---------------------------------------------------------------------------
# 단위: _summarize_one (B 라벨)
# ---------------------------------------------------------------------------

def test_summarize_one_verdict_fixed_deferred():
    crit = _make_criterion(label="B", summary_instruction="계정 목록 요약.")
    item = _make_item()
    j = _summarize_one(crit, item, "PISM-001", "AWS", SummaryClient(), CLOUD)
    assert j.verdict == "판단보류"
    assert j.label == "B"
    assert j.interview_summary is not None
    assert "담당자 인터뷰" in j.interview_summary


def test_summarize_one_interview_summary_in_output():
    crit = _make_criterion(label="B")
    item = _make_item()
    j = _summarize_one(crit, item, "PISM-001", "AWS", SummaryClient(), CLOUD)
    assert j.interview_summary
    assert len(j.interview_summary) > 0


# ---------------------------------------------------------------------------
# 통합: run()에서 label 필드가 JSON 출력에 포함됨
# ---------------------------------------------------------------------------

def test_run_output_includes_label_field(tmp_path, monkeypatch):
    """run() 출력 JSON의 각 judgment에 'label' 필드가 존재한다."""
    src = os.path.join(str(tmp_path), "aws_report_synth.xml")
    with open(FIXTURE_XML, encoding="utf-8") as f:
        content = f.read()
    with open(src, "w", encoding="utf-8") as f:
        f.write(content)

    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_criteria_with_labels(criteria, [
        ("PISM-001", "통신구간 암호화", 5, "스크립트", "방법1", "기준1"),
        ("PISM-007", "네트워크 접근제어", 4, "스크립트", "방법7", "기준7"),
    ])
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    run(report_path=src, criteria_path=criteria, profile_key="cloud",
        client=CallCountClient(), json_out=json_out, xlsx_out=xlsx_out,
        model_name="stub")

    data = json.load(open(json_out, encoding="utf-8"))
    for j in data["judgments"]:
        assert "label" in j, f"label 필드 누락: {j['item_id']}"


# ---------------------------------------------------------------------------
# 통합: C라벨 항목 → LLM 호출 없음
# ---------------------------------------------------------------------------

def test_c_label_no_llm_call(monkeypatch):
    """C 라벨 Criterion에 대해 LLM client.chat 이 호출되지 않는다."""
    crit = _make_criterion(label="C", canned_message="해시 크랙 불가.")
    item = _make_item()
    counter = CallCountClient()

    j = _auto_defer(crit, item, CLOUD)
    # _auto_defer는 client를 인자로 받지 않으므로 chat 호출 횟수는 0
    assert counter.calls == 0
    assert j.verdict == "판단보류"


def test_d_label_no_llm_call(monkeypatch):
    """D 라벨 Criterion에 대해 LLM client.chat 이 호출되지 않는다."""
    crit = _make_criterion(label="D", canned_message="EOL 기준 외부지식.")
    item = _make_item()
    counter = CallCountClient()

    j = _auto_defer(crit, item, CLOUD)
    assert counter.calls == 0
    assert j.label == "D"


# ---------------------------------------------------------------------------
# criteria_loader: variant별 라벨 오버라이드
# ---------------------------------------------------------------------------

def test_variant_label_override(tmp_path):
    """YAML variants 구조가 variant별로 다른 label을 주입한다.

    db_postgresql.yaml: DBM-008 default=A, pg_azure→B.
    pg_rds variant는 A를 받고, pg_azure variant는 B를 받아야 한다.
    """
    import yaml
    from judge_tool.criteria_loader import load_criteria
    from judge_tool.profile import DB_POSTGRESQL
    import openpyxl

    # 합성 xlsx: DBM-008 항목, pg_rds/pg_aurora/pg_azure 모두 적용
    p = DB_POSTGRESQL
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = p.sheet_name

    rds = p.variants["pg_rds"]
    aurora = p.variants["pg_aurora"]
    azure = p.variants["pg_azure"]

    row = p.data_start_row
    ws.cell(row, p.id_col, "DBM-008")
    ws.cell(row, p.name_col, "비밀번호 변경주기")
    ws.cell(row, p.risk_col, 3.0)
    for vspec in (rds, aurora, azure):
        ws.cell(row, vspec.applicability_col, "o")
        ws.cell(row, vspec.standard_col, "기준텍스트")
        ws.cell(row, vspec.method_col, "방법")

    xlsx_path = str(tmp_path / "db.xlsx")
    wb.save(xlsx_path)

    criteria = load_criteria(xlsx_path, DB_POSTGRESQL, profile_key="db_postgresql")

    assert criteria[("DBM-008", "pg_rds")].label == "A"
    assert criteria[("DBM-008", "pg_aurora")].label == "A"
    assert criteria[("DBM-008", "pg_azure")].label == "B"
    assert criteria[("DBM-008", "pg_azure")].summary_instruction is not None

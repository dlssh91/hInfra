import json
import os

import openpyxl
import pytest

import judge_tool.main as main_mod
from judge_tool.main import main, run
from judge_tool.profile import CLOUD

FIXTURE_XML = os.path.join(
    os.path.dirname(__file__), "fixtures", "sample_aws_report.xml")


class StubClient:
    """전건 고정 JSON 반환 대역 (Ollama 불필요)."""

    def __init__(self, verdict="양호", confidence=0.9):
        self._verdict = verdict
        self._confidence = confidence

    def chat(self, system, user):
        return (f'{{"verdict":"{self._verdict}","confidence":{self._confidence},'
                f'"rationale":"테스트 판정","cited_evidence":["x"]}}')


class BoomClient:
    """첫 호출만 예외를 던지고 이후는 정상 JSON을 반환하는 대역.

    부분 실패 격리(I-1) 검증용. 항목 단위 예외가 전체 run을 중단시키지
    않고 판단보류+needs_review로 격리되는지 확인한다.
    """

    def __init__(self):
        self.calls = 0

    def chat(self, system, user):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("네트워크 폭발")
        return ('{"verdict":"양호","confidence":0.9,'
                '"rationale":"정상","cited_evidence":["x"]}')


class AllFailClient:
    """모든 chat 호출이 예외를 던지는 대역(전건 LLM 실패 검증용)."""

    def chat(self, system, user):
        raise RuntimeError("전건 네트워크 폭발")


_SECRET_MARKER = "SECRET-EVIDENCE-aws_access_key=AKIA0000"


class LeakyFailClient:
    """예외 메시지에 evidence 원문 같은 민감 문자열을 실어 던지는 대역.

    D-main 검증용: 예외 본문이 rationale/Excel '근거' 로 유출되면 안 된다.
    """

    def chat(self, system, user):
        raise RuntimeError(f"LLM 응답 파싱 실패: {_SECRET_MARKER}")


def _write_synthetic_criteria(path):
    """CLOUD 프로파일 포맷에 맞는 합성 평가기준 xlsx 생성.

    컬럼 레이아웃(CLOUD): id_col=2, name_col=6, risk_col=7,
    AWS variant: eval_type_col=11, standard_col=17, method_col=13.
    데이터 시작행=5. 시트명='클라우드 관리체계'.

    sample_aws_report.xml 의 항목과 매칭되도록 base id 를 직접 기입한다:
      - PISM-001 : 스크립트 (script status=bad)
      - PISM-037 : 스크립트 (split 037_1/037_2 병합)
      - PISM-007 : 스크립트 (script status=review)
      - PISM-099 : N/A      (스킵 대상)
      - PISM-098 : 관리체계 only (비스크립트 → 스킵 대상)
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name

    rows = [
        # (item_id, name, risk, eval_type, method, standard)
        ("PISM-001", "통신구간 암호화", 5, "스크립트", "방법1", "양호 기준 텍스트"),
        ("PISM-037", "비밀번호 정책", 3, "스크립트", "방법37", "양호 기준 텍스트"),
        ("PISM-007", "네트워크 접근제어", 4, "스크립트", "방법7", "양호 기준 텍스트"),
        ("PISM-099", "관리체계 항목", 2, "N/A", "방법99", "기준99"),
        ("PISM-098", "관리체계만", 2, "관리체계", "방법98", "기준98"),
    ]
    for i, (iid, name, risk, etype, method, standard) in enumerate(rows):
        r = CLOUD.data_start_row + i
        ws.cell(r, CLOUD.id_col, iid)
        ws.cell(r, CLOUD.name_col, name)
        ws.cell(r, CLOUD.risk_col, risk)
        aws = CLOUD.variants["AWS"]
        ws.cell(r, aws.eval_type_col, etype)
        ws.cell(r, aws.method_col, method)
        ws.cell(r, aws.standard_col, standard)
        # Azure variant 도 채워 둠(로더가 양 variant 로드)
        az = CLOUD.variants["Azure"]
        ws.cell(r, az.eval_type_col, etype)
        ws.cell(r, az.method_col, method)
        ws.cell(r, az.standard_col, standard)
    wb.save(path)


def _copy_fixture_xml(tmp_path, name="aws_report_synth.xml"):
    """fixture XML 을 variant 식별 가능한 파일명으로 tmp_path 에 복사."""
    dest = os.path.join(str(tmp_path), name)
    with open(FIXTURE_XML, encoding="utf-8") as src:
        content = src.read()
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(content)
    return dest


# --------------------------------------------------------------------------
# I-2: main() CLI 경로
# --------------------------------------------------------------------------

def test_main_cli_writes_outputs(tmp_path, monkeypatch, capsys,
                                 aws_report_path, criteria_xlsx_path):
    if not (os.path.exists(aws_report_path)
            and os.path.exists(criteria_xlsx_path)):
        pytest.skip("실제 보고서/평가기준 파일이 없어 CLI E2E 스킵")

    monkeypatch.setattr(main_mod, "OllamaClient",
                        lambda *a, **k: StubClient(verdict="취약"))

    main(["--report", aws_report_path,
          "--criteria", criteria_xlsx_path,
          "--out-dir", str(tmp_path),
          "--model", "stub"])

    base = os.path.splitext(os.path.basename(aws_report_path))[0]
    json_out = os.path.join(str(tmp_path), f"result_{base}.json")
    xlsx_out = os.path.join(str(tmp_path), f"result_{base}.xlsx")
    assert os.path.exists(json_out)
    assert os.path.exists(xlsx_out)

    out = capsys.readouterr().out
    assert "판정" in out


def test_main_cli_missing_required_arg():
    with pytest.raises(SystemExit):
        main(["--report", "x"])  # --criteria 누락 → argparse SystemExit


# --------------------------------------------------------------------------
# I-3: CI 독립 결정적 run() (합성 입력)
# --------------------------------------------------------------------------

def test_run_synthetic_disagreement_needs_review(tmp_path):
    """StubClient 가 전건 '양호' → script status=bad/review 와 불일치 →
    needs_review True. N/A·관리체계 항목은 judged 에서 제외(스킵)."""
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    cov = run(report_path=report, criteria_path=criteria, profile_key="cloud",
              client=StubClient(verdict="양호", confidence=0.9),
              json_out=json_out, xlsx_out=xlsx_out, model_name="stub")

    data = json.load(open(json_out, encoding="utf-8"))
    by_id = {j["item_id"]: j for j in data["judgments"]}

    # 스크립트 항목만 판정됨
    assert set(by_id) == {"PISM-001", "PISM-037", "PISM-007"}
    # N/A / 관리체계 only 는 스킵
    assert "PISM-099" not in by_id
    assert "PISM-098" not in by_id

    # PISM-001: script bad vs llm 양호 → 불일치 → needs_review
    assert by_id["PISM-001"]["agreement"] == "불일치"
    assert by_id["PISM-001"]["needs_review"] is True

    # 분할항목 PISM-037: 037_1(bad)+037_2(good) overall=bad → 불일치
    assert by_id["PISM-037"]["agreement"] == "불일치"
    assert by_id["PISM-037"]["needs_review"] is True

    # coverage: expected=3(스크립트만), judged=3
    assert cov["expected"] == 3
    assert cov["judged"] == 3


def test_run_variant_identification_failure(tmp_path):
    """파일명에서 variant 를 식별 못 하면 ValueError."""
    bad_name = os.path.join(str(tmp_path), "unknown.xml")
    with open(bad_name, "w", encoding="utf-8") as fh:
        fh.write("<AuditReport/>")
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)

    with pytest.raises(ValueError):
        run(report_path=bad_name, criteria_path=criteria, profile_key="cloud",
            client=StubClient(), json_out=os.path.join(str(tmp_path), "j.json"),
            xlsx_out=os.path.join(str(tmp_path), "x.xlsx"), model_name="stub")


def test_run_isolates_per_item_failure(tmp_path):
    """한 항목 judge 예외가 전체 run 을 중단시키지 않고, 실패 항목은
    판단보류+needs_review 로 격리된 채 출력이 생성된다(I-1)."""
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    cov = run(report_path=report, criteria_path=criteria, profile_key="cloud",
              client=BoomClient(), json_out=json_out, xlsx_out=xlsx_out,
              model_name="stub")

    assert os.path.exists(json_out) and os.path.exists(xlsx_out)
    data = json.load(open(json_out, encoding="utf-8"))
    by_id = {j["item_id"]: j for j in data["judgments"]}

    # 3개 스크립트 항목 모두 결과에 존재(실패 항목도 격리되어 포함)
    assert set(by_id) == {"PISM-001", "PISM-037", "PISM-007"}
    # 정확히 한 항목이 예외로 판단보류 격리됨
    held = [j for j in data["judgments"] if j["verdict"] == "판단보류"]
    assert len(held) == 1
    assert held[0]["needs_review"] is True
    assert cov["judged"] == 3


# --------------------------------------------------------------------------
# I-2 (spec 6.4): 빈 판단기준(standard="") 항목 스킵
# --------------------------------------------------------------------------

def _write_empty_standard_criteria(path):
    """PISM-001 의 standard 를 비워 둔 합성 평가기준 xlsx.

    빈 판단기준은 LLM 호출 없이 스킵되어야 한다(spec 6.4).
    PISM-007 은 정상 기준을 둬 대조군으로 사용.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    rows = [
        # (item_id, name, risk, eval_type, method, standard)
        ("PISM-001", "통신구간 암호화", 5, "스크립트", "방법1", ""),     # 빈 기준 → 스킵
        ("PISM-007", "네트워크 접근제어", 4, "스크립트", "방법7", "양호 기준"),
    ]
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


def test_run_skips_empty_standard_item(tmp_path):
    """standard 가 비어 있는 스크립트 항목은 judged 에서 제외(스킵)된다."""
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_empty_standard_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    cov = run(report_path=report, criteria_path=criteria, profile_key="cloud",
              client=StubClient(verdict="취약"), json_out=json_out,
              xlsx_out=xlsx_out, model_name="stub")

    data = json.load(open(json_out, encoding="utf-8"))
    by_id = {j["item_id"]: j for j in data["judgments"]}
    # 빈 기준 PISM-001 은 스킵, PISM-007 만 판정
    assert "PISM-001" not in by_id
    assert "PISM-007" in by_id
    assert cov["judged"] == 1


# --------------------------------------------------------------------------
# 견고성: 전건 LLM 실패 / 빈 입력
# --------------------------------------------------------------------------

def test_run_all_llm_failures_isolated(tmp_path):
    """모든 chat 호출이 예외여도 run 은 예외 없이 완료되고, 모든 판정이
    판단보류 & needs_review 로 격리된다(부분 실패 격리가 전건에도 동작)."""
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    cov = run(report_path=report, criteria_path=criteria, profile_key="cloud",
              client=AllFailClient(), json_out=json_out, xlsx_out=xlsx_out,
              model_name="stub")

    assert os.path.exists(json_out) and os.path.exists(xlsx_out)
    data = json.load(open(json_out, encoding="utf-8"))
    judgments = data["judgments"]
    assert len(judgments) == 3
    assert cov["judged"] == 3
    for j in judgments:
        assert j["verdict"] == "판단보류"
        assert j["needs_review"] is True


def test_run_redacts_exception_body_from_rationale(tmp_path):
    """judge 예외 메시지(민감 evidence 포함)가 rationale 으로 유출되지 않는다.

    rationale 은 예외 타입명/고정문구만 담아야 한다(D-main).
    """
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    run(report_path=report, criteria_path=criteria, profile_key="cloud",
        client=LeakyFailClient(), json_out=json_out, xlsx_out=xlsx_out,
        model_name="stub")

    data = json.load(open(json_out, encoding="utf-8"))
    for j in data["judgments"]:
        assert j["verdict"] == "판단보류"
        # 예외 raw 본문(민감 문자열)이 rationale 에 새어나오면 안 됨
        assert _SECRET_MARKER not in j["rationale"]
        # 예외 타입명(고정문구)은 허용
        assert "RuntimeError" in j["rationale"]


# --------------------------------------------------------------------------
# E: 출력 디렉터리가 입력 데이터 디렉터리로 가는 것 차단(main CLI 경계)
# --------------------------------------------------------------------------

def test_main_rejects_out_dir_equal_to_report_dir(tmp_path, monkeypatch):
    report = _copy_fixture_xml(tmp_path)
    criteria = os.path.join(str(tmp_path / "crit"), "criteria.xlsx")
    os.makedirs(os.path.dirname(criteria), exist_ok=True)
    _write_synthetic_criteria(criteria)

    monkeypatch.setattr(main_mod, "OllamaClient",
                        lambda *a, **k: StubClient())

    # --out-dir 이 --report 가 위치한 디렉터리(tmp_path)와 동일 → 거부
    with pytest.raises((SystemExit, ValueError)):
        main(["--report", report, "--criteria", criteria,
              "--out-dir", str(tmp_path), "--model", "stub"])


def test_main_rejects_out_dir_equal_to_criteria_dir(tmp_path, monkeypatch):
    rep_dir = tmp_path / "rep"
    crit_dir = tmp_path / "crit"
    os.makedirs(str(rep_dir), exist_ok=True)
    os.makedirs(str(crit_dir), exist_ok=True)
    report = _copy_fixture_xml(rep_dir)
    criteria = os.path.join(str(crit_dir), "criteria.xlsx")
    _write_synthetic_criteria(criteria)

    monkeypatch.setattr(main_mod, "OllamaClient",
                        lambda *a, **k: StubClient())

    # --out-dir 이 --criteria 디렉터리와 동일 → 거부
    with pytest.raises((SystemExit, ValueError)):
        main(["--report", report, "--criteria", criteria,
              "--out-dir", str(crit_dir), "--model", "stub"])


def test_main_rejects_out_dir_under_report_dir(tmp_path, monkeypatch):
    rep_dir = tmp_path / "rep"
    crit_dir = tmp_path / "crit"
    os.makedirs(str(rep_dir), exist_ok=True)
    os.makedirs(str(crit_dir), exist_ok=True)
    report = _copy_fixture_xml(rep_dir)
    criteria = os.path.join(str(crit_dir), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    sub = os.path.join(str(rep_dir), "out")  # 입력 디렉터리 하위

    monkeypatch.setattr(main_mod, "OllamaClient",
                        lambda *a, **k: StubClient())

    with pytest.raises((SystemExit, ValueError)):
        main(["--report", report, "--criteria", criteria,
              "--out-dir", sub, "--model", "stub"])


def test_main_allows_separate_out_dir(tmp_path, monkeypatch, capsys):
    rep_dir = tmp_path / "rep"
    crit_dir = tmp_path / "crit"
    out_dir = tmp_path / "out"
    for d in (rep_dir, crit_dir, out_dir):
        os.makedirs(str(d), exist_ok=True)
    report = _copy_fixture_xml(rep_dir)
    criteria = os.path.join(str(crit_dir), "criteria.xlsx")
    _write_synthetic_criteria(criteria)

    monkeypatch.setattr(main_mod, "OllamaClient",
                        lambda *a, **k: StubClient(verdict="취약"))

    # 입력과 무관한 별도 디렉터리 → 정상 동작
    main(["--report", report, "--criteria", criteria,
          "--out-dir", str(out_dir), "--model", "stub"])

    base = os.path.splitext(os.path.basename(report))[0]
    assert os.path.exists(os.path.join(str(out_dir), f"result_{base}.json"))
    assert os.path.exists(os.path.join(str(out_dir), f"result_{base}.xlsx"))


def test_run_empty_input(tmp_path):
    """스크립트 대상이 0건인 입력 → judged==0, 출력 정상 생성, 예외 없음."""
    report = os.path.join(str(tmp_path), "aws_report_empty.xml")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                 "<AuditReport><CheckList></CheckList></AuditReport>")
    criteria = os.path.join(str(tmp_path), "criteria.xlsx")
    _write_synthetic_criteria(criteria)
    json_out = os.path.join(str(tmp_path), "result.json")
    xlsx_out = os.path.join(str(tmp_path), "result.xlsx")

    cov = run(report_path=report, criteria_path=criteria, profile_key="cloud",
              client=StubClient(), json_out=json_out, xlsx_out=xlsx_out,
              model_name="stub")

    assert os.path.exists(json_out) and os.path.exists(xlsx_out)
    assert cov["judged"] == 0
    data = json.load(open(json_out, encoding="utf-8"))
    assert data["judgments"] == []

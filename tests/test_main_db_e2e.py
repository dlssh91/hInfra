import json
import os
import openpyxl

from judge_tool.main import run, _judge_one
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence
from judge_tool.profile import get_profile

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sample_db_mysql.txt")


class StubVuln:
    def chat(self, system, user):
        return ('{"verdict":"취약","confidence":0.8,'
                '"rationale":"테스트","cited_evidence":["x"]}')


def _db_criteria_xlsx(path):
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "name"); ws.cell(4, 8, "risk")
    ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
    for r, dbm in [(5, "DBM-001"), (6, "DBM-004"), (7, "DBM-017")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, f"{dbm}항목"); ws.cell(r, 8, 5.0)
        ws.cell(r, 17, "o"); ws.cell(r, 37, "* 양호 - ...\n* 취약 - ...")
        ws.cell(r, 38, "방법")
    wb.save(path)


def test_db_run_end_to_end(tmp_path):
    criteria = str(tmp_path / "db.xlsx")
    _db_criteria_xlsx(criteria)
    # 입력 파일을 변형 식별 가능한 이름으로 tmp에 복사(원본 results/ 미사용)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    cov = run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")

    data = json.load(open(jout, encoding="utf-8"))
    ids = {j["item_id"] for j in data["judgments"]}
    assert "DBM-001" in ids and "DBM-004" in ids
    # DB 판정은 script_status None, agreement N/A
    j1 = next(j for j in data["judgments"] if j["item_id"] == "DBM-001")
    assert j1["script_status"] is None and j1["agreement"] == "N/A"
    assert j1["needs_review"] is True            # 취약 → 검토
    # 마스킹: 출력 어디에도 해시 원문 없음
    assert "FAKEFAKE" not in json.dumps(data, ensure_ascii=False)
    assert data["metadata"]["profile"] == "db_mysql"


def test_db_note_forces_judgment_boryu(tmp_path):
    # criteria에 DBM-011/019 추가(평가대상 o, 판단기준 있음) → NOTE면 판단보류
    criteria = str(tmp_path / "db.xlsx")
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "n"); ws.cell(4, 8, "r")
    ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
    for r, dbm in [(5, "DBM-011"), (6, "DBM-019")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, dbm); ws.cell(r, 8, 5.0)
        ws.cell(r, 17, "o"); ws.cell(r, 37, "* 양호 - ..."); ws.cell(r, 38, "m")
    wb.save(criteria)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")
    data = json.load(open(jout, encoding="utf-8"))
    for dbm in ("DBM-011", "DBM-019"):
        j = next(x for x in data["judgments"] if x["item_id"] == dbm)
        assert j["verdict"] == "판단보류"          # NOTE → 강제 판단보류
        assert j["needs_review"] is True
        assert "NOTE" in j["rationale"]


def _db_crit(item_id="DBM-100"):
    return Criterion(
        item_id=item_id, item_name=f"{item_id}항목", risk=5.0,
        variant="MYSQL", eval_type="스크립트",
        standard="* 양호 - ...\n* 취약 - ...", method="방법",
        applicable=True)


def test_judge_one_blank_note_no_indexerror():
    # NOTE 값이 공백뿐이면 과거 .splitlines()[0]에서 IndexError 발생.
    # 줄-시작 정규식으로 교체 후 예외 없이 판단보류를 반환해야 한다.
    crit = _db_crit("DBM-100")
    item = EvidenceItem(item_id="DBM-100", variant="MYSQL",
                        resources=[], context="QUERY: q\nNOTE:   ")
    profile = get_profile("db_mysql")
    j = _judge_one(crit, item, "DBM-100", "MYSQL", StubVuln(), profile)
    assert j is not None
    assert j.verdict == "판단보류"
    assert "NOTE" in j.rationale


def test_judge_one_inline_note_no_false_match():
    # QUERY 줄 중간에 "NOTE:"가 섞여 있고 별도 NOTE 줄은 없는 경우,
    # NOTE 강제 분기에 진입하지 않고 정상 LLM 경로로 가야 한다.
    crit = _db_crit("DBM-101")
    # 증거 1건 부여(무증거 자동 판단보류 가드를 피해 LLM verdict 가 흐르도록).
    item = EvidenceItem(
        item_id="DBM-101", variant="MYSQL",
        resources=[ResourceEvidence(
            resource_id="db1", status="bad", detail="d", evidence="e")],
        context="QUERY: SELECT 'NOTE: inline' FROM dual")
    profile = get_profile("db_mysql")
    j = _judge_one(crit, item, "DBM-101", "MYSQL", StubVuln(), profile)
    assert j is not None
    assert j.verdict == "취약"   # StubVuln → 취약, 판단보류 아님

import json
import os
import openpyxl

from judge_tool.main import run

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

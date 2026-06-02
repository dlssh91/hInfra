import openpyxl
from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import DB_MYSQL


def _make_db_xlsx(path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "데이터베이스"
    ws.cell(4, 2, "평가항목ID"); ws.cell(4, 7, "평가항목"); ws.cell(4, 8, "위험도")
    ws.cell(4, 17, "평가대상(AWS RDS MYSQL)")
    ws.cell(4, 37, "판단기준(RDS)"); ws.cell(4, 38, "판단방법(RDS)")
    # row5: rds 적용(o) + 판단기준 있음 → judgeable
    ws.cell(5, 2, "DBM-001"); ws.cell(5, 7, "비밀번호"); ws.cell(5, 8, 4.0)
    ws.cell(5, 17, "o"); ws.cell(5, 37, "* 양호 - ...\n* 취약 - ..."); ws.cell(5, 38, "확인방법")
    # row6: rds 적용 아님(공란) → not applicable
    ws.cell(6, 2, "DBM-099"); ws.cell(6, 7, "해당없음"); ws.cell(6, 8, 3.0)
    ws.cell(6, 37, "* 양호 - ..."); ws.cell(6, 38, "방법")
    wb.save(path)


def test_db_applicable_from_marker(tmp_path):
    p = str(tmp_path / "db.xlsx")
    _make_db_xlsx(p)
    crit = load_criteria(p, DB_MYSQL)
    c1 = crit[("DBM-001", "mysql_rds")]
    assert c1.applicable is True and c1.is_judgeable is True
    assert "양호" in c1.standard
    c99 = crit[("DBM-099", "mysql_rds")]
    assert c99.applicable is False and c99.is_judgeable is False

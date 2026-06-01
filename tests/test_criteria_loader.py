import openpyxl

from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import CLOUD


def _write_noncanonical_criteria(path):
    """비정규형 item_id(예 'pism_001')가 든 합성 평가기준 xlsx 생성.

    로더가 profile.normalize_id 로 정규화해 'PISM-001' 키로 join 가능하게
    저장하는지 검증하기 위함.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    aws = CLOUD.variants["AWS"]
    r = CLOUD.data_start_row
    ws.cell(r, CLOUD.id_col, "pism_001")        # 비정규형
    ws.cell(r, CLOUD.name_col, "통신구간 암호화")
    ws.cell(r, CLOUD.risk_col, 5)
    ws.cell(r, aws.eval_type_col, "스크립트")
    ws.cell(r, aws.method_col, "방법1")
    ws.cell(r, aws.standard_col, "양호 기준 텍스트")
    wb.save(path)


def test_noncanonical_item_id_is_normalized(tmp_path):
    path = str(tmp_path / "noncanon.xlsx")
    _write_noncanonical_criteria(path)
    crit = load_criteria(path, CLOUD)
    # 비정규형 'pism_001' 이 정규형 'PISM-001' 키로 join 가능해야 함
    assert ("PISM-001", "AWS") in crit
    assert ("pism_001", "AWS") not in crit
    c = crit[("PISM-001", "AWS")]
    # Criterion.item_id 도 정규형으로 저장(reconcile/coverage 일관성)
    assert c.item_id == "PISM-001"


def test_loads_known_item(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    c = crit[("PISM-001", "AWS")]
    assert c.item_name.strip().startswith("통신구간")
    assert c.risk == 5.0
    assert "스크립트" in c.eval_type
    assert "양호" in c.standard          # 판단기준 텍스트 존재
    assert c.variant == "AWS"


def test_mixed_item_flagged(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert crit[("PISM-045", "AWS")].is_mixed is True


def test_both_variants_present(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert ("PISM-001", "AWS") in crit
    assert ("PISM-001", "Azure") in crit
    # 73개 항목 × 2 variant
    item_ids = {k[0] for k in crit}
    assert len(item_ids) == 73

from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import CLOUD


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

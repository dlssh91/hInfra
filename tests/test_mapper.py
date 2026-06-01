from judge_tool.mapper import aggregate
from judge_tool.models import ResourceEvidence
from judge_tool.profile import CLOUD


def test_aggregate_merges_split_items():
    raw = [
        ("pism_037_1", [ResourceEvidence("u1", "bad", "복잡도", "e1")]),
        ("pism_037_2", [ResourceEvidence("u2", "good", "재사용", "e2")]),
        ("pism_001", [ResourceEvidence("b1", "bad", "정책없음", "e3")]),
    ]
    items = aggregate(raw, "AWS", CLOUD)
    assert set(items) == {"PISM-037", "PISM-001"}
    merged = items["PISM-037"]
    assert merged.variant == "AWS"
    assert {r.resource_id for r in merged.resources} == {"u1", "u2"}
    assert merged.overall_status == "bad"

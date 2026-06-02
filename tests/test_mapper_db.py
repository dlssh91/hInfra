from judge_tool.mapper import aggregate
from judge_tool.models import ResourceEvidence
from judge_tool.profile import DB_MYSQL


def test_aggregate_carries_context_and_merges_split():
    raw = [
        ("DBM-017_1", [ResourceEvidence("r0", "", "", "e0")], "QUERY: q1"),
        ("DBM-017_2", [], "QUERY: q2"),
        ("DBM-019", [], "NOTE: 관리형 DB N/A"),
    ]
    items = aggregate(raw, "mysql_rds", DB_MYSQL)
    # 017_1/017_2 → DBM-017 병합
    assert "DBM-017" in items
    assert len(items["DBM-017"].resources) == 1
    assert "q1" in items["DBM-017"].context
    assert items["DBM-019"].context and "N/A" in items["DBM-019"].context


def test_aggregate_backward_compat_2tuple():
    # cloud 파서의 2-tuple도 여전히 동작(context=None)
    raw = [("PISM-001", [ResourceEvidence("r", "good", "d", "e")])]
    from judge_tool.profile import CLOUD
    items = aggregate(raw, "AWS", CLOUD)
    assert items["PISM-001"].context is None

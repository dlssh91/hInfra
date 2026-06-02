from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _crit(applicable, standard="기준", eval_type="스크립트"):
    return Criterion("DBM-001", "암호", 4.0, "mysql_rds",
                     eval_type, standard, "방법", applicable=applicable)


def test_is_judgeable_uses_applicable_and_standard():
    assert _crit(True, "기준").is_judgeable is True
    assert _crit(False, "기준").is_judgeable is False     # 적용대상 아님
    assert _crit(True, "   ").is_judgeable is False        # 빈 판단기준


def test_applicable_defaults_true_for_backward_compat():
    # applicable 미지정 시 기존 cloud 호출 호환(기본 True)
    c = Criterion("PISM-001", "암호", 5.0, "AWS", "스크립트", "기준", "방법")
    assert c.applicable is True
    assert c.is_judgeable is True


def test_evidence_item_context_default_none():
    it = EvidenceItem("DBM-004", "mysql_rds",
                      [ResourceEvidence("r0", "", "d", "e")])
    assert it.context is None
    it.context = "QUERY: SELECT ..."
    assert "SELECT" in it.context

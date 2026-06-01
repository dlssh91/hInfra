from judge_tool.models import (
    Criterion, ResourceEvidence, EvidenceItem, Judgment)


def test_criterion_flags():
    mixed = Criterion("PISM-045", "최소권한", 5.0, "AWS",
                      "관리체계, 스크립트", "기준...", "방법...")
    assert mixed.is_mixed is True
    assert mixed.is_script_based is True

    script_only = Criterion("PISM-001", "암호화", 5.0, "AWS",
                            "스크립트", "기준", "방법")
    assert script_only.is_mixed is False
    assert script_only.is_script_based is True

    na = Criterion("PISM-030", "x", None, "Azure", "N/A", "", "")
    assert na.is_script_based is False


def test_overall_status_priority():
    def item(*statuses):
        res = [ResourceEvidence(f"r{i}", s, "", "") for i, s in enumerate(statuses)]
        return EvidenceItem("PISM-007", "AWS", res)

    assert item("good", "bad", "review").overall_status == "bad"
    assert item("good", "review").overall_status == "review"
    assert item("good", "info").overall_status == "good"
    assert item("info").overall_status == "info"
    # 대문자 status도 정규화
    assert item("Error").overall_status == "error"


def test_overall_status_empty():
    assert EvidenceItem("PISM-001", "AWS", []).overall_status == "info"

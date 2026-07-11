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


def test_judgment_standard_field_default_backward_compat():
    """standard는 기본값("") 있는 optional 필드 — 기존 Judgment(...) 위치/키워드
    생성 호출부(핸들러 등)는 무변경으로 하위호환되어야 한다."""
    j = Judgment(
        item_id="PISM-001", item_name="테스트", variant="AWS", risk=5.0,
        verdict="양호", confidence=0.9, rationale="근거", cited_evidence=["x"],
        scope="스크립트 전체", management_review_needed=False,
        script_status="good", agreement="일치", needs_review=False)
    assert j.standard == ""
    j.standard = "판단기준 텍스트"
    assert j.standard == "판단기준 텍스트"

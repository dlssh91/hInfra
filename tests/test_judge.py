from judge_tool.judge import (
    build_evidence_text, parse_json_lenient, build_prompt, SYSTEM_PROMPT)
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _item(*statuses):
    res = [ResourceEvidence(f"res-{i}", s, f"detail-{i}", f"ev-{i}" * 200)
           for i, s in enumerate(statuses)]
    return EvidenceItem("PISM-001", "AWS", res)


def test_evidence_guard_preserves_non_good():
    # good 다수 + bad 1개. 작은 상한이어도 bad는 보존되어야 한다.
    item = _item("good", "good", "good", "bad")
    text = build_evidence_text(item, max_chars=500)
    assert "res-3" in text          # 유일한 bad 리소스
    assert "축약" in text or "생략" in text  # 축약 표기


def test_parse_json_lenient_strips_fences_and_commas():
    raw = '```json\n{"verdict": "취약", "confidence": 0.9,}\n```'
    data = parse_json_lenient(raw)
    assert data["verdict"] == "취약"
    assert data["confidence"] == 0.9


def test_build_prompt_mixed_item_mentions_script_scope():
    c = Criterion("PISM-045", "최소권한", 5.0, "AWS",
                  "관리체계, 스크립트", "[관리체계]...\n[IAM] 양호-...", "방법")
    prompt = build_prompt(c, _item("bad"))
    assert "스크립트" in prompt
    assert "PISM-045" in prompt
    assert "최소권한" in prompt


def test_system_prompt_demands_json_keys():
    for key in ["verdict", "confidence", "rationale", "cited_evidence"]:
        assert key in SYSTEM_PROMPT

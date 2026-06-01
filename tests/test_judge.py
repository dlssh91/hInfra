import json

import pytest

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


# I-4.1: 증거 없음
def test_evidence_text_no_resources():
    assert build_evidence_text(EvidenceItem("PISM-001", "AWS", [])) == "(증거 없음)"


# I-4.2: 비-혼합 항목은 혼합 scope_note 미포함
def test_build_prompt_non_mixed_no_scope_note():
    c = Criterion("PISM-010", "암호화설정", 3.0, "AWS",
                  "스크립트", "S3 버킷 암호화 옵션 확인", "describe 호출 결과 대조")
    prompt = build_prompt(c, _item("bad"))
    assert "혼합" not in prompt
    assert "관리체계" not in prompt


# I-4.3: 백틱+후행콤마 입력에서 백틱 인용 내용 보존
def test_parse_json_lenient_preserves_backtick_evidence():
    raw = ('{"verdict":"취약","confidence":0.8,'
           '"rationale":"명령 `aws s3 ls` 실행됨",}')
    data = parse_json_lenient(raw)
    assert data["verdict"] == "취약"
    assert "aws s3 ls" in data["rationale"]


# I-4.4: 완전 비-JSON 입력은 JSONDecodeError raise
def test_parse_json_lenient_raises_on_non_json():
    with pytest.raises(json.JSONDecodeError):
        parse_json_lenient("그냥 텍스트")


from judge_tool.judge import judge_item, reconcile


class FakeClient:
    """OllamaClient 대역. 고정 JSON 응답."""
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def chat(self, system, user):
        self.calls.append((system, user))
        return self.payload


def _crit(eval_type="스크립트"):
    return Criterion("PISM-001", "통신구간 암호화", 5.0, "AWS",
                     eval_type, "양호-...취약-...", "방법")


def test_judge_item_returns_validated_dict():
    client = FakeClient('{"verdict":"취약","confidence":0.9,'
                        '"rationale":"정책 없음","cited_evidence":["b1"]}')
    out = judge_item(_crit(), _item("bad"), client)
    assert out["verdict"] == "취약"
    assert client.calls  # 호출됨


def test_reconcile_agreement_high_confidence():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": ["b1"]}
    j = reconcile(llm, _crit(), _item("bad"))   # script overall=bad → 취약
    assert j.script_status == "bad"
    assert j.agreement == "일치"
    assert j.needs_review is False
    assert j.scope == "스크립트 전체"
    assert j.management_review_needed is False


def test_reconcile_disagreement_flags_review():
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("bad"))   # script=취약, llm=양호 → 불일치
    assert j.agreement == "불일치"
    assert j.needs_review is True


def test_reconcile_mixed_item_sets_partial_scope():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit("관리체계, 스크립트"), _item("bad"))
    assert j.scope == "스크립트 부분만"
    assert j.management_review_needed is True
    assert j.needs_review is True   # 혼합 항목은 항상 검토 필요


def test_reconcile_review_status_is_na():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("review"))  # script가 review → 비교 N/A
    assert j.agreement == "N/A"

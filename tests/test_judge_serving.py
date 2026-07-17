"""LLM 서빙 품질 수정(2026-07-17 Opus 리뷰 C-1/H-1/H-2/M-1/M-3) 회귀 테스트.

- C-1: Ollama num_ctx 명시(무음 절단 방지)
- H-1: 요약 경로 format:"json" 해제(chat_text) + 테스트 더블 폴백
- H-2: raw 증거 절단 시 evidence_truncated → needs_review 강제
- M-1: verdict 어휘 보수적 정규화(방향 뒤집힘 절대 흡수 금지)
- M-3: OllamaClient 기본 모델 = production(qwen3-coder:30b)
"""
from unittest import mock

import pytest

from judge_tool.judge import (
    OllamaClient, judge_item, reconcile, summarize_item,
    _normalize_verdict, _NUM_CTX, _RAW_EVIDENCE_CAP)
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _crit(**kw):
    base = dict(item_id="DBM-004", item_name="테스트 항목", risk=5.0,
                variant="mysql_native", eval_type="스크립트",
                standard="양호-기준충족 취약-위반", method="방법")
    base.update(kw)
    return Criterion(**base)


def _raw_item(n_rows: int, row_len: int = 100) -> EvidenceItem:
    rows = [ResourceEvidence(f"r{i}", "review", "d", "x" * row_len)
            for i in range(n_rows)]
    return EvidenceItem(item_id="DBM-004", variant="mysql_native",
                        resources=rows)


# ── C-1 / M-3: OllamaClient 페이로드·기본값 ─────────────────────────────────

def _capture_post(client_call):
    fake_resp = mock.Mock()
    fake_resp.json.return_value = {"message": {"content": "응답"}}
    with mock.patch("judge_tool.judge.requests.post",
                    return_value=fake_resp) as post:
        client_call()
    return post.call_args.kwargs["json"]


def test_chat_payload_sets_num_ctx_and_json_format():
    client = OllamaClient(url="http://x:11434", model="m")
    payload = _capture_post(lambda: client.chat("sys", "usr"))
    assert payload["options"]["num_ctx"] == _NUM_CTX
    assert payload["format"] == "json"


def test_chat_text_payload_has_no_format_key():
    client = OllamaClient(url="http://x:11434", model="m")
    payload = _capture_post(lambda: client.chat_text("sys", "usr"))
    assert "format" not in payload
    assert payload["options"]["num_ctx"] == _NUM_CTX


def test_num_ctx_override():
    client = OllamaClient(url="http://x:11434", model="m", num_ctx=8192)
    payload = _capture_post(lambda: client.chat("sys", "usr"))
    assert payload["options"]["num_ctx"] == 8192


def test_default_model_is_production():
    assert OllamaClient().model == "qwen3-coder:30b"


# ── M-1: verdict 정규화 ─────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("양호", "양호"), ("취약", "취약"), ("판단보류", "판단보류"),
    ("양호함", "양호"), ("취약함", "취약"),
    ("판단 보류", "판단보류"), (" 양호 ", "양호"),
    ("취약.", "취약"), ("양호입니다", "양호"), ("판단보류!", "판단보류"),
])
def test_normalize_verdict_accepts_harmless_variants(raw, expected):
    assert _normalize_verdict(raw) == expected


@pytest.mark.parametrize("raw", [
    "양호하지 않음",      # 방향 뒤집힘 — 절대 흡수 금지
    "취약하지 않다",
    "양호(safe)",         # 미지 꼬리
    "vulnerable", "good", # 영어 어휘
    "양호 또는 취약", "", None, 123, ["양호"],
])
def test_normalize_verdict_rejects_ambiguous(raw):
    assert _normalize_verdict(raw) is None


def test_judge_item_accepts_suffixed_verdict():
    class C:
        def chat(self, system, user):
            return '{"verdict":"양호함","confidence":0.9,"rationale":"r"}'
    out = judge_item(_crit(), _raw_item(2), C(), evidence_mode="raw")
    assert out["verdict"] == "양호"


def test_judge_item_flipped_verdict_falls_back_to_hold():
    class C:
        def chat(self, system, user):
            return '{"verdict":"양호하지 않음","confidence":0.9}'
    out = judge_item(_crit(), _raw_item(2), C(), evidence_mode="raw")
    assert out["verdict"] == "판단보류"


# ── H-2: 증거 절단 → needs_review ──────────────────────────────────────────

def _good_llm_client():
    class C:
        def chat(self, system, user):
            return '{"verdict":"양호","confidence":0.9,"rationale":"r"}'
    return C()


def test_truncated_raw_evidence_sets_flag_and_review():
    # 총량이 _RAW_EVIDENCE_CAP을 확실히 넘도록 구성 → 절단 발생
    rows = _RAW_EVIDENCE_CAP // 100 + 50
    out = judge_item(_crit(), _raw_item(rows), _good_llm_client(),
                     evidence_mode="raw")
    assert out["evidence_truncated"] is True
    j = reconcile(out, _crit(), _raw_item(rows), status_available=False)
    assert j.needs_review is True
    assert "절단" in j.rationale
    assert j.verdict == "양호"  # verdict는 유지, 검토만 강제


def test_untruncated_evidence_no_flag():
    out = judge_item(_crit(), _raw_item(3), _good_llm_client(),
                     evidence_mode="raw")
    assert out["evidence_truncated"] is False
    j = reconcile(out, _crit(), _raw_item(3), status_available=False)
    assert "절단" not in j.rationale


# ── H-1: 요약 경로 chat_text 우선 + chat 폴백 ──────────────────────────────

def test_summarize_prefers_chat_text():
    calls = []

    class C:
        def chat(self, system, user):
            calls.append("chat")
            return "산문 요약입니다."

        def chat_text(self, system, user):
            calls.append("chat_text")
            return "산문 요약입니다."

    crit = _crit(label="B", summary_instruction="계정별로 요약하라")
    out = summarize_item(crit, _raw_item(2), C())
    assert calls == ["chat_text"]
    assert "산문" in out


def test_summarize_falls_back_to_chat_for_test_doubles():
    class C:  # chat_text 없는 기존 인터페이스 더블
        def chat(self, system, user):
            return "산문 요약입니다."

    crit = _crit(label="B", summary_instruction="요약하라")
    out = summarize_item(crit, _raw_item(2), C())
    assert "산문" in out

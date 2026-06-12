import json
from unittest import mock

import pytest

from judge_tool.judge import (
    build_evidence_text, parse_json_lenient, build_prompt, SYSTEM_PROMPT,
    judge_item, reconcile, OllamaClient)
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


# I-4 신규 테스트 -------------------------------------------------------------

def test_judge_item_non_json_falls_back_after_retries():
    # 비-JSON 고정응답 → 매 시도 파싱 실패 → 판단보류 폴백, retries+1회 호출
    client = FakeClient("이건 JSON이 아니다")
    out = judge_item(_crit(), _item("bad"), client)  # retries 기본=2
    assert out["verdict"] == "판단보류"
    assert out["confidence"] == 0.0
    assert len(client.calls) == 3  # retries(2) + 1


def test_judge_item_invalid_verdict_falls_back_after_retries():
    # 파싱은 되지만 verdict가 유효하지 않음 → 재시도 후 판단보류 폴백
    client = FakeClient('{"verdict":"maybe","confidence":0.9}')
    out = judge_item(_crit(), _item("bad"), client)
    assert out["verdict"] == "판단보류"
    assert len(client.calls) == 3


def test_reconcile_low_confidence_alone_triggers_review():
    # 일치 + 비혼합 + verdict≠판단보류 인데 confidence<0.6 → needs_review True
    llm = {"verdict": "양호", "confidence": 0.5,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("good"))  # script=양호, llm=양호 → 일치
    assert j.agreement == "일치"
    assert j.needs_review is True


def test_reconcile_pending_verdict_alone_triggers_review():
    # verdict=="판단보류" 단독 트리거
    llm = {"verdict": "판단보류", "confidence": 0.9,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("review"))  # script review → agreement N/A
    assert j.agreement == "N/A"
    assert j.needs_review is True


def test_reconcile_non_numeric_confidence_no_error():
    # I-1 회귀: confidence가 비숫자여도 ValueError 없이 0.0으로 처리
    llm = {"verdict": "취약", "confidence": "high",
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("bad"))
    assert j.confidence == 0.0


# Pass: 정확성/스펙/보안 이슈 수정 테스트 ------------------------------------

# A: non-dict 유효 JSON에서 judge_item 깨짐
def test_judge_item_non_dict_json_falls_back():
    # ["양호"]는 유효 JSON이지만 dict가 아님 → AttributeError 없이 판단보류 폴백
    client = FakeClient('["양호"]')
    out = judge_item(_crit(), _item("bad"), client)  # retries 기본=2
    assert out["verdict"] == "판단보류"
    assert out["confidence"] == 0.0
    assert len(client.calls) == 3  # retries(2) + 1


def test_judge_item_scalar_json_falls_back():
    client = FakeClient('42')
    out = judge_item(_crit(), _item("bad"), client)
    assert out["verdict"] == "판단보류"
    assert len(client.calls) == 3


# D-judge: 폴백 rationale에 예외 본문(LLM 원문) 비직렬화
def test_judge_item_fallback_rationale_redacts_exception_body():
    # 비-JSON 응답이 rationale에 새지 않아야 한다
    secret = "민감한증거AKIA_SECRET_KEY_XYZ"
    client = FakeClient(secret + " 이건 JSON이 아니다")
    out = judge_item(_crit(), _item("bad"), client)
    assert out["verdict"] == "판단보류"
    assert secret not in out["rationale"]
    # 타입명/고정문구만 (JSONDecodeError 타입명은 허용)
    assert "JSONDecodeError" in out["rationale"] or "파싱 실패" in out["rationale"]


# B+C: error status → 판단보류 강제 + needs_review
def test_reconcile_error_status_forces_pending():
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "정상으로 보임", "cited_evidence": ["e1"]}
    j = reconcile(llm, _crit(), _item("error"))  # script overall=error
    assert j.verdict == "판단보류"
    assert j.needs_review is True
    assert j.cited_evidence == ["e1"]  # cited_evidence 보존


# B+C: 증거 없음(resources=[]) → 판단보류 강제 + needs_review
def test_reconcile_no_evidence_forces_pending():
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "x", "cited_evidence": []}
    item = EvidenceItem("PISM-001", "AWS", [])
    j = reconcile(llm, _crit(), item)
    assert j.verdict == "판단보류"
    assert j.needs_review is True


# B+C: 미지 status("manual")가 overall_status에서 info로 강등되지 않음
def test_overall_status_unknown_not_downgraded_to_info():
    item = _item("manual")
    assert item.overall_status != "info"
    assert item.overall_status == "manual"


# B+C: 미지 status는 증거가드에서 primary로 보존 (good/info만 축약)
def test_evidence_guard_unknown_status_is_primary():
    item = _item("good", "good", "good", "manual")
    text = build_evidence_text(item, max_chars=500)
    assert "res-3" in text  # manual 리소스는 primary로 전량 보존
    assert "축약" in text or "생략" in text


# B+C: 미지/good·bad 아님 status → needs_review True
def test_reconcile_unknown_status_triggers_review():
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("manual"))
    assert j.agreement == "N/A"
    assert j.needs_review is True


def test_ollama_client_chat_payload():
    fake_resp = mock.Mock()
    fake_resp.json.return_value = {"message": {"content": '{"verdict":"양호"}'}}
    with mock.patch("judge_tool.judge.requests.post",
                    return_value=fake_resp) as post:
        client = OllamaClient(url="http://x:11434", model="m", temperature=0.0)
        content = client.chat("sys", "usr")

    assert content == '{"verdict":"양호"}'
    fake_resp.raise_for_status.assert_called_once()
    post.assert_called_once()
    _, kwargs = post.call_args
    # url 위치 인자 확인
    url_arg = post.call_args.args[0]
    assert url_arg.endswith("/api/chat")
    payload = kwargs["json"]
    assert payload["model"] == "m"
    assert payload["stream"] is False
    assert payload["format"] == "json"
    assert payload["options"]["temperature"] == 0.0
    roles = [m["role"] for m in payload["messages"]]
    assert roles == ["system", "user"]
    assert payload["messages"][0]["content"] == "sys"
    assert payload["messages"][1]["content"] == "usr"


from judge_tool.judge import (
    build_evidence_text_raw, reconcile, build_prompt)


def _db_item(rows, context=None):
    from judge_tool.models import EvidenceItem, ResourceEvidence
    res = [ResourceEvidence(f"row{i}", "", "", e) for i, e in enumerate(rows)]
    it = EvidenceItem("DBM-004", "mysql_rds", res)
    it.context = context
    return it


def _db_crit(standard="* 양호 - ...\n* 취약 - ..."):
    from judge_tool.models import Criterion
    return Criterion("DBM-004", "권한", 5.0, "mysql_rds", "", standard,
                     "방법", applicable=True)


def test_raw_evidence_preserves_all_rows_with_cap_note():
    rows = [f'{{"GRANTEE":"u{i}","PRIVILEGE_TYPE":"SELECT"}}' for i in range(5)]
    text = build_evidence_text_raw(_db_item(rows, "QUERY: q"), max_chars=24000)
    assert "QUERY: q" in text
    for i in range(5):
        assert f"u{i}" in text          # 전수 보존


def test_raw_evidence_cap_truncates_with_note():
    rows = [f'{{"GRANTEE":"user{i}","PRIVILEGE_TYPE":"SELECT"}}'
            for i in range(500)]
    text = build_evidence_text_raw(_db_item(rows, None), max_chars=300)
    assert "생략" in text or "표시" in text


def test_db_prompt_uses_raw_mode_and_context():
    p = build_prompt(_db_crit(), _db_item(['{"GRANTEE":"x"}'], "QUERY: select 1"),
                     evidence_mode="raw")
    assert "select 1" in p
    assert "DBM-004" in p


def test_reconcile_db_status_unavailable():
    llm = {"verdict": "취약", "confidence": 0.9, "rationale": "x",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item(['{"GRANTEE":"x"}']),
                  status_available=False, flag_vulnerable_for_review=True)
    assert j.script_status is None
    assert j.agreement == "N/A"
    assert j.needs_review is True          # 취약 → 검토
    assert j.scope == "스크립트 전체"


def test_reconcile_db_empty_means_good_not_forced_boryu():
    # 빈 RESULT지만 empty_means_good 항목이면 판단보류 강제 안 함
    llm = {"verdict": "양호", "confidence": 0.9, "rationale": "위반 0건",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item([], "QUERY: q"),
                  status_available=False, flag_vulnerable_for_review=True,
                  empty_means_good=True)
    assert j.verdict == "양호"             # 강제 보류 아님


def test_reconcile_db_empty_default_forces_boryu():
    llm = {"verdict": "양호", "confidence": 0.9, "rationale": "x",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item([], "QUERY: q"),
                  status_available=False, flag_vulnerable_for_review=True,
                  empty_means_good=False)
    assert j.verdict == "판단보류"         # 무증거 → 보류


# ── network generic variant scope_note 테스트 ─────────────────────────────────

def _net_item():
    from judge_tool.models import EvidenceItem, ResourceEvidence
    res = [ResourceEvidence("NET-001#0", "", "", "show run output")]
    return EvidenceItem("NET-001", "generic", res)


def _net_crit(variant="generic"):
    from judge_tool.models import Criterion
    return Criterion("NET-001", "원격접속 관리", 5.0, variant,
                     "", "* 양호 - SSH만 허용\n* 취약 - telnet 허용", "확인방법")


def test_build_prompt_generic_variant_includes_vendor_neutral_note():
    """variant="generic" → 프롬프트에 '벤더 미식별'/'벤더중립' 문구 포함."""
    c = _net_crit(variant="generic")
    prompt = build_prompt(c, _net_item(), evidence_mode="raw")
    assert "벤더 미식별" in prompt
    assert "벤더중립" in prompt


def test_build_prompt_cisco_variant_excludes_vendor_neutral_note():
    """variant="cisco" → 프롬프트에 '벤더 미식별' 문구 미포함."""
    c = _net_crit(variant="cisco")
    prompt = build_prompt(c, _net_item(), evidence_mode="raw")
    assert "벤더 미식별" not in prompt
    assert "벤더중립" not in prompt


def test_build_prompt_aws_variant_excludes_vendor_neutral_note():
    """variant="AWS"(기존 cloud) → 프롬프트에 '벤더 미식별' 문구 미포함."""
    c = _crit()   # AWS variant
    prompt = build_prompt(c, _item("bad"))
    assert "벤더 미식별" not in prompt
    assert "벤더중립" not in prompt

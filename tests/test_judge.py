import json
from unittest import mock

import pytest

import judge_tool.judge as judge_mod
from judge_tool.judge import (
    build_evidence_text, parse_json_lenient, build_prompt, SYSTEM_PROMPT,
    judge_item, reconcile, OllamaClient)
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


class _FakeTagsResp:
    """requests.get(/api/tags) 응답 대역."""

    def __init__(self, names):
        self._names = names

    def raise_for_status(self):
        pass

    def json(self):
        return {"models": [{"name": n} for n in self._names]}


def _patch_tags(monkeypatch, names):
    monkeypatch.setattr(judge_mod.requests, "get",
                        lambda url, timeout=None: _FakeTagsResp(names))


class TestHealthCheck:
    """OllamaClient.health_check 페일패스트 — 태그 매칭 규율(H-1 회귀 고정)."""

    def test_exact_tag_present_passes(self, monkeypatch):
        _patch_tags(monkeypatch, ["qwen3-coder:30b", "llama3:8b"])
        OllamaClient(url="http://x:11434", model="qwen3-coder:30b").health_check()

    def test_tagged_request_rejects_base_only_match(self, monkeypatch):
        # H-1 핵심: ':30b' 요청인데 ':7b'만 있으면 base('qwen3-coder')가
        # 겹쳐도 통과시키면 안 된다(그러면 chat()이 404→조용히 전부 판단보류).
        _patch_tags(monkeypatch, ["qwen3-coder:7b"])
        with pytest.raises(RuntimeError, match="찾을 수 없습니다"):
            OllamaClient(url="http://x:11434", model="qwen3-coder:30b").health_check()

    def test_tagged_request_rejects_suffix_variant(self, monkeypatch):
        _patch_tags(monkeypatch, ["qwen3-coder:30b-q4"])
        with pytest.raises(RuntimeError, match="찾을 수 없습니다"):
            OllamaClient(url="http://x:11434", model="qwen3-coder:30b").health_check()

    def test_untagged_request_allows_base_match(self, monkeypatch):
        # 태그 미지정 요청은 base 일치 완화 허용('qwen3-coder' → :latest 등).
        _patch_tags(monkeypatch, ["qwen3-coder:latest"])
        OllamaClient(url="http://x:11434", model="qwen3-coder").health_check()

    def test_server_down_raises(self, monkeypatch):
        def _boom(url, timeout=None):
            raise OSError("connection refused")
        monkeypatch.setattr(judge_mod.requests, "get", _boom)
        with pytest.raises(RuntimeError, match="연결할 수 없습니다"):
            OllamaClient(url="http://x:11434", model="qwen3-coder:30b").health_check()


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


def test_system_prompt_has_permission_string_rule():
    """권한 문자열 오독(SRV-096/084 거짓음성) 교정 규칙이 존재해야 한다."""
    # 끝 3자리=others, r-- 도 권한이라는 핵심 지침
    assert "others" in SYSTEM_PROMPT
    assert "-rw-r--r--" in SYSTEM_PROMPT
    assert "-rw-r-----" in SYSTEM_PROMPT
    assert "권한 없음" in SYSTEM_PROMPT  # "'권한 없음'이 절대 아니다"


def test_system_prompt_has_service_block_marker_rule():
    """서비스 상태 블록 [S]..[E] 빈 블록=미실행 규칙(SRV-016 거짓양성) 교정."""
    assert "][S]" in SYSTEM_PROMPT
    assert "][E]" in SYSTEM_PROMPT
    assert "이라는 뜻이 아니다" in SYSTEM_PROMPT
    assert "블록이 비었는데 이름만 보고" in SYSTEM_PROMPT


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


# ── C1 carrier 격리 회귀가드 ───────────────────────────────────────────────────

def _carrier_resource(item_id="DBM-011"):
    """빈 RESULT + raw_data_json이 있을 때 db_json이 생성하는 carrier 더미 리소스."""
    r = ResourceEvidence(
        resource_id=f"{item_id}#raw",
        status="",
        detail="(raw-carrier)",
        evidence="",
        is_raw_carrier=True,
    )
    r.raw_evidence = '{"DBM-011": {"RESULT": []}}'
    return r


def _carrier_item(item_id="DBM-011", variant="mssql_native"):
    """carrier-only EvidenceItem — 빈 RESULT + no_evidence 게이트 확인용."""
    r = _carrier_resource(item_id)
    it = EvidenceItem(item_id, variant, [r])
    return it


def _db_crit_a(item_id="DBM-011", variant="mssql_native"):
    """label A, empty_means_good 아님 기준 — LLM 라우팅 항목 시뮬레이션."""
    return Criterion(item_id, "감사로그", 3.0, variant, "스크립트",
                     "판단기준", "방법", applicable=True, label="A")


# C1-1: carrier-only item → no_evidence=True → LLM 양호여도 강제 판단보류
def test_reconcile_carrier_only_triggers_no_evidence_holdover():
    """빈 RESULT + carrier-only 항목: LLM이 양호를 반환해도 강제 판단보류.

    carrier가 no_evidence 안전망을 무력화하지 않음 — C1 핵심 단언.
    """
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "LLM 양호 응답", "cited_evidence": []}
    item = _carrier_item()
    crit = _db_crit_a()
    j = reconcile(llm, crit, item, status_available=False,
                  empty_means_good=False)
    assert j.verdict == "판단보류", (
        f"carrier-only인데 LLM 양호가 그대로 통과: verdict={j.verdict}")
    assert j.needs_review is True
    assert "증거 없음" in j.rationale


# C1-2: carrier + 실증거 혼합 → no_evidence=False(실증거 있음) → LLM 판정 허용
def test_reconcile_carrier_plus_real_evidence_allows_verdict():
    """carrier + 실증거가 함께 있으면 no_evidence=False → LLM 취약 판정 허용."""
    real_r = ResourceEvidence("DBM-011#row0", "", "실위반", '{"audit_log":"not loaded"}')
    carrier_r = _carrier_resource()
    item = EvidenceItem("DBM-011", "mssql_native", [real_r, carrier_r])
    crit = _db_crit_a()
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "취약 판정", "cited_evidence": []}
    j = reconcile(llm, crit, item, status_available=False,
                  empty_means_good=False)
    # no_evidence 게이트를 통과해 LLM 취약이 유지되어야 한다
    assert j.verdict == "취약"


# C1-3: build_evidence_text — carrier 리소스가 LLM 증거 텍스트에 포함되지 않음
def test_build_evidence_text_excludes_carrier():
    """build_evidence_text: carrier 리소스는 증거 직렬화에서 제외."""
    from judge_tool.judge import build_evidence_text
    carrier_r = _carrier_resource()
    item = EvidenceItem("DBM-011", "mssql_native", [carrier_r])
    text = build_evidence_text(item)
    assert "(증거 없음)" in text, f"carrier-only인데 증거 없음 신호 없음: {text[:200]}"
    assert "raw-carrier" not in text


# C1-4: build_evidence_text_raw — carrier-only → "(점검 결과 0건)" 신호 복원
def test_build_evidence_text_raw_carrier_only_returns_zero_signal():
    """build_evidence_text_raw: carrier-only → '(점검 결과 0건)' 반환(M3 해소)."""
    from judge_tool.judge import build_evidence_text_raw
    carrier_r = _carrier_resource()
    item = EvidenceItem("DBM-011", "mssql_native", [carrier_r])
    text = build_evidence_text_raw(item)
    assert "(점검 결과 0건)" in text, (
        f"carrier-only인데 '0건' 신호 없음: {text[:200]}")
    assert "raw-carrier" not in text


# C1-5: build_evidence_text_raw — carrier + context → context 포함 + 0건 신호
def test_build_evidence_text_raw_carrier_only_with_context():
    """context가 있어도 carrier-only면 '(점검 결과 0건)'을 포함해야 한다."""
    from judge_tool.judge import build_evidence_text_raw
    carrier_r = _carrier_resource()
    item = EvidenceItem("DBM-011", "mssql_native", [carrier_r])
    item.context = "NOTE: PISM-011 참조"
    text = build_evidence_text_raw(item)
    assert "NOTE: PISM-011 참조" in text
    assert "(점검 결과 0건)" in text


# C1-6: is_raw_carrier=False 기본값 → 기존 리소스는 영향 없음 (회귀 불변)
def test_resource_evidence_default_not_carrier():
    """is_raw_carrier 기본값 False — 기존 ResourceEvidence 생성 동작 불변."""
    r = ResourceEvidence("res-0", "bad", "detail", "evidence")
    assert r.is_raw_carrier is False


# C1-7: 실데이터 계열 — db_json.parse() 가 만든 carrier는 is_raw_carrier=True
def test_db_json_parse_carrier_is_flagged():
    """db_json.parse()가 빈 RESULT에 추가하는 더미 리소스는 is_raw_carrier=True."""
    import json
    from judge_tool.parsers.db_json import parse
    import tempfile, os
    # 최소한의 빈 RESULT를 가진 DBM-011 항목
    content = json.dumps([{"DBM-011": {"QUERY": "SELECT ...", "RESULT": []}}])
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write(content)
        tmp = f.name
    try:
        items = parse(tmp)
        by_id = {cid: resources for cid, resources, _ in items}
        assert "DBM-011" in by_id
        carriers = [r for r in by_id["DBM-011"] if r.is_raw_carrier]
        assert carriers, "빈 RESULT에 carrier 더미가 추가되지 않음"
        non_carriers = [r for r in by_id["DBM-011"] if not r.is_raw_carrier]
        assert not non_carriers, "빈 RESULT에 실증거가 잘못 추가됨"
    finally:
        os.unlink(tmp)

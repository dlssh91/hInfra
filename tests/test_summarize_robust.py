"""summarize_item 견고성 테스트 — JSON 재요청/평탄화, 타임아웃 축소 재시도."""
from judge_tool.judge import (
    _json_to_prose, _looks_like_json, summarize_item)
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _crit():
    return Criterion(
        item_id="DBM-003", item_name="테스트", risk=3.0, variant="v",
        eval_type="", standard="기준", method="방법", applicable=True,
        label="B", summary_instruction="계정 요약")


def _item():
    res = ResourceEvidence(resource_id="r", status="info", detail="d",
                           evidence='{"USER": "admin"}')
    return EvidenceItem(item_id="DBM-003", variant="v", resources=[res])


def test_looks_like_json():
    assert _looks_like_json('{"a": 1}')
    assert _looks_like_json('```json\n{"a": 1}\n```')
    assert not _looks_like_json("계정 admin은 활성 상태다.")


def test_json_to_prose_flattens():
    text = '{"활성_계정": [{"USER": "admin"}, {"USER": "test"}], "비고": "없음"}'
    out = _json_to_prose(text)
    assert "{" not in out and "[" not in out
    assert "admin" in out and "비고: 없음" in out


def test_json_to_prose_keeps_unparseable_text():
    assert _json_to_prose("그냥 문장") == "그냥 문장"


class JsonThenProseClient:
    """1차 JSON → 재요청에 산문으로 응답하는 대역."""

    def __init__(self):
        self.calls = 0

    def chat(self, system, user):
        self.calls += 1
        if self.calls == 1:
            return '{"summary": "admin 계정 활성"}'
        return "admin 계정이 활성 상태다. 담당자 확인 필요."


def test_json_output_retried_to_prose():
    client = JsonThenProseClient()
    out = summarize_item(_crit(), _item(), client)
    assert client.calls == 2
    assert out.startswith("admin 계정이 활성")


class AlwaysJsonClient:
    """재요청에도 JSON만 반환하는 대역 → 코드 평탄화 폴백 검증."""

    def chat(self, system, user):
        return '{"summary": ["admin 활성", "test 잠김"]}'


def test_stubborn_json_flattened():
    out = summarize_item(_crit(), _item(), AlwaysJsonClient())
    assert "{" not in out
    assert "admin 활성" in out and "test 잠김" in out


class TimeoutThenOkClient:
    """1차 호출 타임아웃 → 축소 재시도에 성공하는 대역."""

    def __init__(self):
        self.calls = 0

    def chat(self, system, user):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("read timeout")
        return "계정 요약 텍스트."


def test_timeout_retries_with_truncated_evidence():
    client = TimeoutThenOkClient()
    out = summarize_item(_crit(), _item(), client)
    assert client.calls == 2
    assert "계정 요약 텍스트" in out
    assert "일부 행만 요약" in out  # 축소 재시도 표시


class AlwaysFailClient:
    def chat(self, system, user):
        raise TimeoutError("read timeout")


def test_total_failure_returns_marker():
    out = summarize_item(_crit(), _item(), AlwaysFailClient())
    assert out.startswith("[요약 실패:")


# ---------------------------------------------------------------------------
# 요약-증거 커버리지 안전망
# ---------------------------------------------------------------------------

def _multi_row_item(n=5):
    rows = [ResourceEvidence(
        resource_id=f"r{i}", status="info", detail="",
        evidence=f'{{"rolname": "user_{i:02d}_account"}}') for i in range(n)]
    return EvidenceItem(item_id="DBM-003", variant="v", resources=rows)


class FirstRowOnlyClient:
    """첫 행만 언급하는 불충분 요약을 반환 (PG Aurora DBM-003 실패 모드)."""

    def chat(self, system, user):
        return "user_00_account 계정은 활성 상태다. 담당자 확인 필요."


def test_low_coverage_summary_gets_warning():
    out = summarize_item(_crit(), _multi_row_item(5), FirstRowOnlyClient())
    assert "원본 증거 대조 필요" in out
    assert "5행 중 1행" in out


class FullCoverageClient:
    def chat(self, system, user):
        return ("user_00_account, user_01_account, user_02_account, "
                "user_03_account, user_04_account 계정 확인. 인터뷰 필요.")


def test_full_coverage_summary_no_warning():
    out = summarize_item(_crit(), _multi_row_item(5), FullCoverageClient())
    assert "원본 증거 대조 필요" not in out

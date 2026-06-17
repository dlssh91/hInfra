"""로컬 LLM(qwen3-coder:30b) 행동 회귀 가드 (Ollama 통합 테스트).

Codex 리뷰 [medium] 대응: SYSTEM_PROMPT 규칙(권한문자열·서비스블록)이 문자열 존재
검사만으로 보호되던 한계를 보완 — cov 골드라벨로 실제 LLM 판정을 재생 가능하게 검증.

기본 비활성(느린 LLM 호출). 실행하려면:
  RUN_OLLAMA_TESTS=1 python3 -m pytest tests/test_llm_cov_quality.py -q
Ollama 미가동 시 자동 skip. 핵심 단언 = 위험방향 오판 0:
  취약 픽스처가 '양호'로(거짓음성) 또는 양호 픽스처가 '취약'으로(거짓양성) 판정되면 실패.
"""
import os

import pytest

from tests.cov_contract import LLM_PROD_ITEMS, GOOD_FIXTURE, VULN_FIXTURE

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("JUDGE_MODEL", "qwen3-coder:30b")
CRITERIA = "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx"


def _ollama_up():
    try:
        import requests
        requests.get(f"{OLLAMA_URL}/api/tags", timeout=3).raise_for_status()
        return True
    except Exception:  # noqa: BLE001
        return False


_ENABLED = os.environ.get("RUN_OLLAMA_TESTS") == "1"
pytestmark = [
    pytest.mark.skipif(not _ENABLED,
                       reason="RUN_OLLAMA_TESTS=1 설정 시에만 실행(느린 LLM 호출)"),
    pytest.mark.skipif(
        not (os.path.exists(GOOD_FIXTURE) and os.path.exists(VULN_FIXTURE)),
        reason="cov 픽스처 미생성"),
    pytest.mark.skipif(not os.path.exists(CRITERIA), reason="평가기준 xlsx 없음"),
]


@pytest.fixture(scope="module")
def harness():
    if not _ollama_up():
        pytest.skip(f"Ollama 미가동: {OLLAMA_URL}")
    from judge_tool.profile import get_profile
    from judge_tool.criteria_loader import load_criteria
    from judge_tool.parsers import server_xml
    from judge_tool.mapper import aggregate
    from judge_tool.judge import OllamaClient, judge_item

    prof = get_profile("server")
    crit = load_criteria(CRITERIA, prof, profile_key="server")
    client = OllamaClient(url=OLLAMA_URL, model=MODEL)
    ev = {
        "good": aggregate(server_xml.parse(GOOD_FIXTURE), "linux", prof),
        "vuln": aggregate(server_xml.parse(VULN_FIXTURE), "linux", prof),
    }

    def verdict(item_id, sample):
        c = next((v for (k, var), v in crit.items()
                  if k == item_id and var == "linux"), None)
        assert c is not None, f"{item_id} 기준 없음"
        return judge_item(c, ev[sample].get(item_id), client).get("verdict")

    return verdict


@pytest.mark.parametrize("item_id", LLM_PROD_ITEMS)
def test_no_false_negative_on_vuln(harness, item_id):
    """취약 픽스처를 '양호'로 판정하면 거짓음성(위험) — 금지."""
    assert harness(item_id, "vuln") != "양호", f"{item_id}: 거짓음성(취약→양호)"


@pytest.mark.parametrize("item_id", LLM_PROD_ITEMS)
def test_no_false_positive_on_good(harness, item_id):
    """양호 픽스처를 '취약'으로 판정하면 거짓양성 — 금지."""
    assert harness(item_id, "good") != "취약", f"{item_id}: 거짓양성(양호→취약)"

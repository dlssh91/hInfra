"""cov 픽스처 양극성 계약 테스트 (결정론, LLM 불필요).

Codex 리뷰 [high] 대응: 생성기가 편집블록만 검사하던 한계를 보완 —
재생성 시 어떤 LLM-production 항목이 누락/단극성/미변경이면 이 테스트가 실패한다.
"""
import os

import pytest

from judge_tool.profile import get_profile
from judge_tool.parsers import server_xml
from judge_tool.mapper import aggregate
from judge_tool.judge import build_evidence_text

from tests.cov_contract import (
    LLM_PROD_ITEMS, VULN_SIGNALS, GOOD_SIGNALS, GOOD_FIXTURE, VULN_FIXTURE,
)

_HAVE = os.path.exists(GOOD_FIXTURE) and os.path.exists(VULN_FIXTURE)
pytestmark = pytest.mark.skipif(
    not _HAVE, reason="cov 픽스처 미생성 (tests/_build_cov_fixtures.py 실행 필요)")


def _evmap(path):
    profile = get_profile("server")
    return aggregate(server_xml.parse(path), "linux", profile)


def _item_text(evmap, item_id):
    item = evmap.get(item_id)
    if item is None:
        return ""
    # 항목에 귀속된 모든 증거(원문+상세)를 결합해 단서 검색
    parts = []
    for r in item.resources:
        parts.append(getattr(r, "evidence", "") or "")
        parts.append(getattr(r, "detail", "") or "")
    return "\n".join(parts) + "\n" + build_evidence_text(item)


@pytest.fixture(scope="module")
def fixtures():
    return _evmap(GOOD_FIXTURE), _evmap(VULN_FIXTURE)


@pytest.mark.parametrize("item_id", LLM_PROD_ITEMS)
def test_each_item_has_both_polarities(item_id, fixtures):
    """모든 LLM-production 항목은 good/vuln 양쪽에 증거가 있고 서로 달라야 한다."""
    good, vuln = fixtures
    gt = _item_text(good, item_id).strip()
    vt = _item_text(vuln, item_id).strip()
    assert gt and gt != "(증거 없음)", f"{item_id}: cov-good 증거 없음"
    assert vt and vt != "(증거 없음)", f"{item_id}: cov-vuln 증거 없음"
    assert gt != vt, f"{item_id}: good==vuln (단극성 — 극성 손실)"


@pytest.mark.parametrize("item_id", LLM_PROD_ITEMS)
def test_vuln_gold_signal_present(item_id, fixtures):
    """취약 픽스처에 설계된 취약 단서가 존재해야 한다(상속 항목은 None→스킵)."""
    _, vuln = fixtures
    sig = VULN_SIGNALS[item_id]
    if sig is None:
        pytest.skip(f"{item_id}: 취약 극성 원본 상속")
    assert sig in _item_text(vuln, item_id), f"{item_id}: 취약 단서 '{sig}' 누락"


@pytest.mark.parametrize("item_id", LLM_PROD_ITEMS)
def test_good_gold_signal_present(item_id, fixtures):
    """양호 픽스처에 설계된 양호 단서가 존재해야 한다(상속 항목은 None→스킵)."""
    good, _ = fixtures
    sig = GOOD_SIGNALS[item_id]
    if sig is None:
        pytest.skip(f"{item_id}: 양호 극성 원본 상속")
    assert sig in _item_text(good, item_id), f"{item_id}: 양호 단서 '{sig}' 누락"


def test_contract_covers_all_label_a_items():
    """계약 항목 집합이 server.yaml의 LLM-production(label A, det_common 아님)과 일치."""
    import yaml
    y = yaml.safe_load(open("judge_tool/item_configs/server.yaml", encoding="utf-8"))
    items = y.get("items", y)
    pure_llm = {
        k for k, v in items.items()
        if isinstance(v, dict) and v.get("label") == "A"
        and v.get("judgment_method") != "det_common"
    }
    assert set(LLM_PROD_ITEMS) == pure_llm, (
        f"계약-실설정 불일치: 계약에만={set(LLM_PROD_ITEMS)-pure_llm}, "
        f"설정에만={pure_llm-set(LLM_PROD_ITEMS)}")

"""서버(SRV) linux 변형 DET 양극성 계약 테스트 (결정론, LLM 불필요).

목적: linux 변형의 DET/DET-PARTIAL 항목에 대해
  - good 합성 raw → good_verdict(양호) 확인
  - vuln 합성 raw → vuln_verdict(취약) 확인
이로써 전 DET 항목의 양극성이 깨지지 않음을 회귀로 고정한다.

거짓양호(vuln→양호) 0 / 거짓취약(good→취약) 0 이 SHIP 조건.

불변 계약:
  - judge() 직접 호출 (LLM 없음)
  - results/·collected/ 쓰기 금지 (합성 픽스처 인라인)
  - 기존 판정 로직 변경 없음 (검증만)

커버 항목 수(linux variant):
  순수 DET:          36개 (SRV_auto_parse 경로)
  DET-PARTIAL linux: 5개  (SRV_Linux_parse 경로 — SRV-026/069/074/127/131)
  DET-PARTIAL svc:   6개  (서비스 inactive→양호 단방향 — SRV-005/006/007/013/014/064)
  합계:             47개

미커버 이유:
  SRV-074 vuln: epochDays 날짜의존성 — 정적 픽스처로 취약 유발 불가
  SRV-005/006/007/013/014/064 vuln: 서비스 active→(*) 수동경로 — handled=False
"""
from __future__ import annotations

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.server  # noqa: F401 — 등록 부작용
from judge_tool.det_adapters.server import judge
from judge_tool.det_adapters.base import ForcedVerdict

from tests.srv_cov_contract import SRV_COV, MANUAL_HOLD_ITEMS


# ──────────────────────────────────────────────────────────────────────────────
# 파라미터 생성: (item_id, polarity) 쌍
# ──────────────────────────────────────────────────────────────────────────────

def _gen_params():
    """SRV_COV에서 (item_id, polarity) 조합 생성.

    uncovered 항목(또는 극성별 uncovered)은 skip 처리.
    known_bug 항목은 해당 극성만 xfail 처리.
    """
    params = []
    for item_id, spec in SRV_COV.items():
        for polarity in ("good", "vuln"):
            polarity_data = spec.get(polarity)

            # spec 최상위 uncovered (전체 항목이 uncovered) — 웹 cov와 달리
            # srv_cov_contract는 good/vuln 별도로 uncovered 처리 가능
            if isinstance(polarity_data, dict) and polarity_data.get("uncovered"):
                reason = polarity_data.get("uncovered_reason", "미커버")
                params.append(pytest.param(
                    item_id, polarity,
                    marks=pytest.mark.skip(reason=reason),
                ))
                continue

            if spec.get("uncovered"):
                reason = spec.get("uncovered_reason", "미커버")
                params.append(pytest.param(
                    item_id, polarity,
                    marks=pytest.mark.skip(reason=reason),
                ))
                continue

            if spec.get("known_bug"):
                bug_desc = spec["known_bug"]
                bug_polarity = spec.get("known_bug_polarity")
                if polarity == bug_polarity:
                    params.append(pytest.param(
                        item_id, polarity,
                        marks=pytest.mark.xfail(
                            strict=True,
                            reason=f"[발견된 버그] {bug_desc}",
                        ),
                    ))
                else:
                    params.append((item_id, polarity))
            else:
                params.append((item_id, polarity))

    return params


_ALL_PARAMS = _gen_params()


# ──────────────────────────────────────────────────────────────────────────────
# 메인 양극성 테스트
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,polarity", _ALL_PARAMS)
def test_srv_det_polarity(item_id, polarity):
    """SRV DET 항목 양극성(linux): good→expected_verdict, vuln→expected_verdict.

    거짓양호(vuln입력→양호 판정) 및 거짓취약(good입력→취약 판정)이 없음을 확인한다.

    판정 흐름:
      1. gate()가 DET 아니면 handled=False → 결정론 범위 밖(이미 MANUAL 테스트 커버)
      2. handled=True이면 verdict가 기대값과 일치하는지 확인
      3. handled=False이면 verdict != '양호' 임을 확인 (거짓양호 방지)
    """
    spec = SRV_COV[item_id]
    raw = spec[polarity]
    # polarity_data가 dict(uncovered)인 경우는 _gen_params에서 skip 처리됨
    if isinstance(raw, dict):
        pytest.skip(raw.get("uncovered_reason", "미커버"))
    expected_verdict = spec[f"{polarity}_verdict"]

    fv = judge(item_id, raw, "linux", {})

    assert isinstance(fv, ForcedVerdict), (
        f"linux/{item_id}/{polarity}: judge() 반환값이 ForcedVerdict가 아님"
    )

    if not fv.handled:
        # gate 차단(서비스 블록 없음, MANUAL 분류 등) — 거짓양호만 방지하고 skip
        assert fv.verdict != "양호", (
            f"[거짓양호] linux/{item_id}/{polarity}: "
            f"handled=False인데 verdict='양호' — 거짓양호 발생! "
            f"({fv!r})"
        )
        pytest.skip(
            f"linux/{item_id}/{polarity}: handled=False (gate/증거가드). "
            f"verdict={fv.verdict!r} rationale={fv.rationale!r}. "
            f"합성 raw를 확인하거나 DET_SOURCE 분류 재검토 필요."
        )

    # handled=True: verdict 확인
    actual = fv.verdict

    if polarity == "vuln":
        # 거짓양호 검사: vuln 입력인데 양호가 나오면 안 됨
        assert actual != "양호", (
            f"[거짓양호] linux/{item_id}/vuln: "
            f"취약 입력인데 verdict='양호' — 거짓양호 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] linux/{item_id}/vuln: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} citations={fv.citations!r}"
        )

    else:  # polarity == "good"
        # 거짓취약 검사: good 입력인데 취약이 나오면 안 됨
        assert actual != "취약", (
            f"[거짓취약] linux/{item_id}/good: "
            f"양호 입력인데 verdict='취약' — 거짓취약 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] linux/{item_id}/good: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/판단보류 항목 — handled=False + verdict != '양호' 확인
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,variant,note", MANUAL_HOLD_ITEMS)
def test_srv_manual_items_no_false_positive(item_id, variant, note):
    """MANUAL/ABSENT 항목: gate 차단 → handled=False, verdict != '양호' 확인.

    MANUAL = 수동 판단 필요. DET-PARTIAL active = 수동(*) 경로.
    거짓양호(자동 양호 판정) 절대 금지.
    """
    # 서비스 블록이 포함된 dummy raw 제공 (gate 차단이 목적이므로 내용 무관)
    raw = (
        "$ ps -ef\n"
        "root      1234     1  0 00:00 ?        00:00:00 /usr/sbin/sshd\n"
        "dummy line for evidence\n"
    )

    fv = judge(item_id, raw, variant, {})

    assert isinstance(fv, ForcedVerdict)
    assert fv.handled is False, (
        f"MANUAL {variant}/{item_id} ({note}): "
        f"handled=False 기대인데 handled=True. "
        f"DET_SOURCE 분류 확인 필요. verdict={fv.verdict!r}"
    )
    assert fv.verdict != "양호", (
        f"[거짓양호] {variant}/{item_id} ({note}): "
        f"MANUAL인데 양호 판정 발생! verdict={fv.verdict!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# 커버리지 요약 테스트 (계약 완전성 검사)
# ──────────────────────────────────────────────────────────────────────────────

def test_srv_cov_contract_completeness():
    """SRV_COV 계약이 linux 변형 DET 항목을 충분히 커버하는지 확인.

    최소 기대:
      - 전체 항목: 41개 이상 (순수DET 36 + linux-override 5)
      - 서비스inactive 항목: 6개 이상
    """
    total = len(SRV_COV)
    assert total >= 41, (
        f"SRV_COV에 {total}개 항목만 정의됨, 최소 41개 기대. "
        f"DET 항목 커버리지 부족 — 계약 보강 필요."
    )

    # 서비스inactive 항목 (DET-PARTIAL) 최소 커버
    service_inactive_items = {
        "SRV-005", "SRV-006", "SRV-007", "SRV-013", "SRV-014", "SRV-064",
    }
    for item_id in service_inactive_items:
        assert item_id in SRV_COV, (
            f"{item_id}: SRV_COV에 없음 — DET-PARTIAL 서비스inactive 항목 누락"
        )


def test_srv_cov_uncovered_items_documented():
    """미커버(uncovered) 항목이 모두 사유와 함께 문서화됨을 확인.

    uncovered=True 또는 polarity별 {"uncovered": True}인 항목은
    uncovered_reason이 있어야 한다(은폐 금지).
    """
    for item_id, spec in SRV_COV.items():
        # 최상위 uncovered
        if spec.get("uncovered"):
            assert "uncovered_reason" in spec, (
                f"{item_id}: uncovered=True인데 uncovered_reason 없음 — 사유 문서화 필수."
            )
            assert spec["uncovered_reason"].strip(), (
                f"{item_id}: uncovered_reason이 비어있음."
            )
        # polarity별 uncovered (good/vuln이 dict인 경우)
        for polarity in ("good", "vuln"):
            polarity_data = spec.get(polarity)
            if isinstance(polarity_data, dict) and polarity_data.get("uncovered"):
                assert "uncovered_reason" in polarity_data, (
                    f"{item_id}/{polarity}: uncovered=True인데 uncovered_reason 없음."
                )
                assert polarity_data["uncovered_reason"].strip(), (
                    f"{item_id}/{polarity}: uncovered_reason이 비어있음."
                )


def test_srv_cov_covered_items_have_both_polarities():
    """커버된 항목은 good/vuln 양쪽 데이터와 verdict가 모두 있어야 한다.

    uncovered 항목은 제외.
    polarity별 uncovered(dict)가 있는 경우 해당 polarity의 verdict 체크는 skip.
    """
    for item_id, spec in SRV_COV.items():
        if spec.get("uncovered"):
            continue
        for polarity in ("good", "vuln"):
            polarity_data = spec.get(polarity)
            # polarity별 uncovered dict인 경우는 raw 없어도 됨
            if isinstance(polarity_data, dict) and polarity_data.get("uncovered"):
                continue
            assert polarity in spec, f"{item_id}: {polarity} 데이터 없음"
            assert f"{polarity}_verdict" in spec, f"{item_id}: {polarity}_verdict 없음"
            assert spec[f"{polarity}_verdict"] in ("양호", "취약", "판단보류"), (
                f"{item_id}: 알 수 없는 {polarity}_verdict={spec[f'{polarity}_verdict']!r}"
            )


def test_srv_cov_manual_hold_items_documented():
    """MANUAL_HOLD_ITEMS 리스트가 비어있지 않고 각 항목에 note가 있는지 확인."""
    assert MANUAL_HOLD_ITEMS, "MANUAL_HOLD_ITEMS가 비어있음"
    for item_id, variant, note in MANUAL_HOLD_ITEMS:
        assert item_id, "item_id가 비어있음"
        assert variant, "variant가 비어있음"
        assert note, f"{item_id}: note(사유)가 비어있음 — 문서화 필수"

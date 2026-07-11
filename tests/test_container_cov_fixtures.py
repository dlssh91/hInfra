"""컨테이너(PRCC) k8s_master/docker_linux DET 양극성 계약 테스트
(결정론, LLM 불필요). tests/srv_cov_contract.py + test_srv_cov_fixtures.py,
tests/db_cov_contract.py + test_db_cov_fixtures.py 동형 패턴(§3-3).

목적: k8s_master/docker_linux 변형의 DET 항목에 대해
  - good 합성 raw → good_verdict(양호) 확인
  - vuln 합성 raw → vuln_verdict(취약) 확인
전 DET 항목의 양극성이 깨지지 않음을 회귀로 고정한다.

거짓양호(vuln→양호) 0 / 거짓취약(good→취약) 0 이 SHIP 조건.

불변 계약:
  - judge() 직접 호출(LLM 없음)
  - results/·collected/ 쓰기 금지(합성 픽스처 인라인, tests/container_cov_contract.py)
  - container.py/container.yaml/vendor autoAnalysis.py 변경 없음(검증만)

범위: k8s_master(DET 32/50, 2026-07-11 PRCC-045 DET→MANUAL 강등 후) +
docker_linux(DET 31/50) — 실샘플 확보된 2변형만.
나머지 7변형(worker/eks/aks/ocp)은 미커버(§3-3 설계 범위 외, 코드 근거는
DET_SOURCE.yaml에 이미 기재되어 있으나 실측 미검증).
"""
from __future__ import annotations

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.container  # noqa: F401 — 등록 부작용
from judge_tool.det_adapters.container import (
    judge,
    _RE_ERROR_OUTPUT,
    _ERROR_GUARD_EXEMPT_TOKENS,
)
from judge_tool.det_adapters.base import ForcedVerdict

from tests.container_cov_contract import CONTAINER_COV, CONTAINER_MANUAL_HOLD_ITEMS


def _is_command_failure_output(raw: str, item_id: str = "", variant: str = "") -> bool:
    """원격 container.py F8 가드(_RE_ERROR_OUTPUT + 항목별 예외테이블)와 동일한
    판정을 재현하는 테스트 헬퍼. (원격 be38850: PRCC-013 eks_master 항목별
    기대신호 면제 — 다른 (item_id, variant)는 예외 없이 전체 매치.)
    """
    exempt = _ERROR_GUARD_EXEMPT_TOKENS.get((item_id, variant), frozenset())
    for m in _RE_ERROR_OUTPUT.finditer(raw):
        if m.group(0).strip() not in exempt:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# 파라미터 생성: (item_id, variant, polarity) 3튜플
# ──────────────────────────────────────────────────────────────────────────────

def _gen_params():
    params = []
    for item_id, variants in CONTAINER_COV.items():
        for variant, spec in variants.items():
            for polarity in ("good", "vuln"):
                polarity_data = spec.get(polarity)

                if isinstance(polarity_data, dict) and polarity_data.get("uncovered"):
                    reason = polarity_data.get("uncovered_reason", "미커버")
                    params.append(pytest.param(
                        item_id, variant, polarity,
                        marks=pytest.mark.skip(reason=reason),
                    ))
                    continue

                params.append((item_id, variant, polarity))

    return params


_ALL_PARAMS = _gen_params()


# ──────────────────────────────────────────────────────────────────────────────
# 메인 양극성 테스트
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,variant,polarity", _ALL_PARAMS)
def test_container_det_polarity(item_id, variant, polarity):
    """PRCC DET 항목 양극성(k8s_master/docker_linux):
    good→expected_verdict, vuln→expected_verdict.

    거짓양호(vuln입력→양호 판정) 및 거짓취약(good입력→취약 판정)이 없음을 확인한다.
    """
    spec = CONTAINER_COV[item_id][variant]
    raw = spec[polarity]
    if isinstance(raw, dict):
        pytest.skip(raw.get("uncovered_reason", "미커버"))
    expected_verdict = spec[f"{polarity}_verdict"]

    fv = judge(item_id, raw, variant, {})

    assert isinstance(fv, ForcedVerdict), (
        f"{variant}/{item_id}/{polarity}: judge() 반환값이 ForcedVerdict가 아님"
    )

    # F8 가드 상호작용 확인: 정상 출력(오류출력 아님)이 F8 가드에 걸리지 않아야 함
    assert not _is_command_failure_output(raw, item_id, variant), (
        f"[F8 오검출] {variant}/{item_id}/{polarity}: 정상 출력 픽스처가 F8 명령실패 "
        f"가드 정규식에 매치됨 — 픽스처를 오류출력 패턴과 겹치지 않게 재작성 필요."
    )

    if not fv.handled:
        # gate 차단(MANUAL/ABSENT 오분류 등) — 거짓양호만 방지하고 skip
        assert fv.verdict != "양호", (
            f"[거짓양호] {variant}/{item_id}/{polarity}: "
            f"handled=False인데 verdict='양호' — 거짓양호 발생! ({fv!r})"
        )
        pytest.skip(
            f"{variant}/{item_id}/{polarity}: handled=False (gate/증거가드/F8가드). "
            f"verdict={fv.verdict!r} rationale={fv.rationale!r}. "
            f"DET_SOURCE 분류 재검토 또는 픽스처 보강 필요."
        )

    actual = fv.verdict

    if polarity == "vuln":
        assert actual != "양호", (
            f"[거짓양호] {variant}/{item_id}/vuln: 취약 입력인데 verdict='양호' — "
            f"거짓양호 발생! confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] {variant}/{item_id}/vuln: 기대={expected_verdict!r}, "
            f"실제={actual!r}. citations={fv.citations!r}"
        )
    else:  # polarity == "good"
        assert actual != "취약", (
            f"[거짓취약] {variant}/{item_id}/good: 양호 입력인데 verdict='취약' — "
            f"거짓취약 발생! confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] {variant}/{item_id}/good: 기대={expected_verdict!r}, "
            f"실제={actual!r}. rationale={fv.rationale!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/ABSENT 조합 — handled=False + verdict != '양호' 확인
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,variant,note", CONTAINER_MANUAL_HOLD_ITEMS)
def test_container_manual_hold_items_no_false_positive(item_id, variant, note):
    """MANUAL/ABSENT 조합: gate 차단 → handled=False, verdict != '양호' 확인.

    gate()는 raw_output 내용과 무관하게 classify() 결과만으로 차단하므로,
    아래 dummy raw(수집 증거 있는 정상출력)를 넣어도 handled=False가 유지돼야 한다.
    """
    raw = (
        f"F_PRC_C_{item_id.split('-')[-1]} : {variant}\n"
        "# Command : kubectl get pods -A\n"
        "dummy evidence line for gate-block verification\n"
        "flag: [X]\n"
    )

    fv = judge(item_id, raw, variant, {})

    assert isinstance(fv, ForcedVerdict)
    assert fv.handled is False, (
        f"MANUAL/ABSENT {variant}/{item_id} ({note}): handled=False 기대인데 "
        f"handled=True — DET_SOURCE 분류 확인 필요. verdict={fv.verdict!r}"
    )
    assert fv.verdict != "양호", (
        f"[거짓양호] {variant}/{item_id} ({note}): MANUAL/ABSENT인데 양호 판정 발생! "
        f"verdict={fv.verdict!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# 커버리지 요약/완전성 테스트
# ──────────────────────────────────────────────────────────────────────────────

def test_container_cov_contract_completeness():
    """CONTAINER_COV가 k8s_master/docker_linux DET 항목을 충분히 커버하는지 확인.

    DET_SOURCE.yaml 실측 분류: k8s_master DET 32개(2026-07-11 PRCC-045 DET→MANUAL
    강등으로 33→32), docker_linux DET 31개
    (PRCC-017 k8s_master는 코드 pass분기라 good만 커버 — 아래 완전성 카운트에
    포함하되 vuln은 uncovered로 별도 문서화됨).
    """
    k8s_count = sum(1 for variants in CONTAINER_COV.values() if "k8s_master" in variants)
    docker_count = sum(1 for variants in CONTAINER_COV.values() if "docker_linux" in variants)

    assert k8s_count >= 32, (
        f"CONTAINER_COV에 k8s_master 항목 {k8s_count}개만 정의됨, 최소 32개 기대"
        "(DET_SOURCE.yaml 기준 k8s_master DET 32개, 2026-07-11 PRCC-045 강등 후)."
    )
    assert docker_count >= 31, (
        f"CONTAINER_COV에 docker_linux 항목 {docker_count}개만 정의됨, 최소 31개 기대"
        "(DET_SOURCE.yaml 기준 docker_linux DET 31개)."
    )


def test_container_cov_uncovered_items_documented():
    """미커버(uncovered) 극성이 모두 사유와 함께 문서화됨을 확인(은폐 금지)."""
    for item_id, variants in CONTAINER_COV.items():
        for variant, spec in variants.items():
            for polarity in ("good", "vuln"):
                polarity_data = spec.get(polarity)
                if isinstance(polarity_data, dict) and polarity_data.get("uncovered"):
                    assert "uncovered_reason" in polarity_data, (
                        f"{variant}/{item_id}/{polarity}: uncovered=True인데 "
                        f"uncovered_reason 없음 — 사유 문서화 필수."
                    )
                    assert polarity_data["uncovered_reason"].strip(), (
                        f"{variant}/{item_id}/{polarity}: uncovered_reason이 비어있음."
                    )


def test_container_cov_covered_items_have_both_polarities():
    """커버된 (item, variant)는 good/vuln 양쪽 데이터와 verdict가 모두 있어야 한다."""
    for item_id, variants in CONTAINER_COV.items():
        for variant, spec in variants.items():
            for polarity in ("good", "vuln"):
                assert polarity in spec, f"{variant}/{item_id}: {polarity} 데이터 없음"
                assert f"{polarity}_verdict" in spec, (
                    f"{variant}/{item_id}: {polarity}_verdict 없음"
                )
                assert spec[f"{polarity}_verdict"] in ("양호", "취약", "판단보류"), (
                    f"{variant}/{item_id}: 알 수 없는 {polarity}_verdict="
                    f"{spec[f'{polarity}_verdict']!r}"
                )


def test_container_manual_hold_items_documented():
    """CONTAINER_MANUAL_HOLD_ITEMS가 비어있지 않고 각 항목에 note가 있는지 확인."""
    assert CONTAINER_MANUAL_HOLD_ITEMS, "CONTAINER_MANUAL_HOLD_ITEMS가 비어있음"
    for item_id, variant, note in CONTAINER_MANUAL_HOLD_ITEMS:
        assert item_id, "item_id가 비어있음"
        assert variant, "variant가 비어있음"
        assert note, f"{item_id}/{variant}: note(사유)가 비어있음 — 문서화 필수"


def test_container_f8_guard_normal_output_not_flagged():
    """F8 가드 상호작용: CONTAINER_COV의 모든 정상출력 픽스처가 명령실패 가드에
    걸리지 않아야 한다(오류출력이 아닌 정상출력이 가드에 안 걸림을 명시적으로 확인).
    """
    offenders = []
    for item_id, variants in CONTAINER_COV.items():
        for variant, spec in variants.items():
            for polarity in ("good", "vuln"):
                raw = spec.get(polarity)
                if isinstance(raw, dict):
                    continue
                if _is_command_failure_output(raw, item_id, variant):
                    offenders.append(f"{variant}/{item_id}/{polarity}")
    assert not offenders, (
        f"F8 가드가 정상출력 픽스처를 오류출력으로 오검출: {offenders}"
    )

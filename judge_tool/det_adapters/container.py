"""컨테이너(PRCC) 결정론 어댑터 — Phase 2 (§5.2/§18, autoAnalysis 단일함수 브리지).

설계 계약:
  - judge() 시그니처: (item_id, raw_output, variant, thresholds, *, context=None) → ForcedVerdict
  - §18.1 C1: gate() 선확인 — DET/DET-PARTIAL이 아니면 handled=False (거짓양호 구조 차단)
  - 증거 부재 가드: raw_output에 수집 실행 흔적 없으면 handled=False(§3.4 디폴트-N 거짓양호 방지)
  - autoAnalysis(sApp=variant, vulKey=item_id, vulOutput=raw_output) 단일함수 호출
  - 반환 dict 매핑 (§5.4):
      result='M' → handled=False (수동 판단 필요)
      result='Y' → verdict=취약, ev_status=bad, conf=0.9, citations=point 분할
      result='N' → verdict=양호, ev_status=good, conf=0.9, handled=True
      빈/기타 → handled=False (미결정)
  - R1 거짓양호 3중 방어:
      (1) gate: DET_SOURCE 미기재 variant → ABSENT → gate 차단
      (2) 증거 부재 가드: 빈출력·수집실패 → 명령흔적 없음 → handled=False
      (3) result='M' 매핑: autoAnalysis 수동반환 → handled=False
  - raw_output이 citations/rationale로 새지 않도록 경계 유지 (§7)
    citations = autoAnalysis가 만든 point 문자열만 사용 (raw_output 미포함)

레지스트리 등록: 모듈 import 시 _DET_ADAPTERS["container"] = judge 자동 등록.
main.py에서 `import judge_tool.det_adapters.container` 로 부작용 임포트.
"""
import logging
import re
from typing import Optional

from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate

log = logging.getLogger(__name__)

# autoAnalysis.py:32 autoTarget = ["k8s_master","k8s_worker","docker",
#   "ocp_master","ocp_worker","vcenter","esxi","xenserver",
#   "eks_master","eks_worker","aks_master","aks_worker"]
# 외부 게이트 조건: if sApp in autoTarget  (exact list membership, NOT substring)
# → profile 키 "docker_linux"는 autoTarget에 없어서 매칭 실패 → 디폴트 N 거짓양호.
# 내부 분기는 "docker" in sApp (부분문자열)이므로 sApp="docker"를 넘기면 OK.
# ⚠️ 설계서 §2.3 "그대로 전달하면 됨"은 내부 분기만 고려한 착오 —
#    실제 outer gate는 exact membership. 반드시 아래 매핑으로 변환 필요.
_VARIANT_TO_SAPP: dict = {
    "docker_linux": "docker",  # autoTarget에 "docker"가 있음(exact), "docker_linux" 없음
    # 나머지는 profile 키 = autoTarget 토큰으로 1:1 일치
    # k8s_master → "k8s_master", ocp_master → "ocp_master", etc.
}

# 컨테이너 수집 실행 흔적 패턴 (§3.4 증거 부재 가드)
# 컨테이너 샘플 구조 패턴 (k8s_master 실샘플 검증 기반):
#   - F_PRC_C_NNN 헤더, # Command : kubectl... 명령라인
#   - flag: [X] 마커, [not exist] 결과 마커 (PRCC-036 등 존재 확인 결과)
#   - kubectl/docker 토큰, ----- 구분선, ### 구분자
#   - 파일권한 행 패턴: "NNN root:root [...]" (PRCC-007 파일권한 수집 결과)
#   - No result, 취약점 증거 텍스트 패턴 등
# "No result"는 일부 항목에서 취약 증거이므로 증거부재로 보지 않음(과차단 방지).
# 수집 실행 흔적(명령 실행 결과 포함)만 확인한다.
_RE_CONTAINER_CMD = re.compile(
    r"# Command\s*:"
    r"|F_PRC_C_\d+"
    r"|\bkubectl\b"
    r"|\bdocker\b"
    r"|flag:\s*\["
    r"|\[not exist\]"
    r"|\broot:root\b",     # 파일권한 확인 결과(PRCC-007): "600 root:root [...]"
    re.IGNORECASE,
)
# 구분선/구분자 패턴 (-----로 5자 이상 또는 ### 구분자)
_RE_SEPARATOR = re.compile(r"-{5,}|#{3,}")


def _has_collection_evidence(raw_output: str) -> bool:
    """raw_output에 컨테이너 점검 수집이 실제로 이루어진 증거가 있는지 판정.

    True  → F_PRC_C_ 헤더, # Command : kubectl/docker 명령흔적, flag: [ 마커,
             [not exist] 결과 마커, -----구분선, ###구분자,
             root:root 파일권한 행 중 1개 이상 존재.
    False → 빈 출력, 공백뿐, "No result"만 있는 출력.

    주의: "No result" 자체는 일부 항목(PRCC-018 eks/aks)에서 취약 증거이므로
    수집 실행 흔적(명령 있음)과 별도로 본다 — "No result"만 있어도 # Command 등이
    있으면 True (수집 실행됨). "No result" 자체를 증거부재 기준으로 쓰지 않는다.

    [not exist]는 존재 확인 결과 "없음"을 나타내는 마커(PRCC-036 등). 수집이
    실행되었음을 의미하므로 유효 증거로 인정.

    샘플 검증(k8s_master fsec-control-plane-20260615.xml):
      - 전 활성 항목이 # Command / ----- / [not exist] / ### 중 하나를 보유 → True(과트리거 0).
      - 빈 출력 합성 → False(거짓양호 차단).
    """
    if not raw_output or not raw_output.strip():
        return False
    return bool(
        _RE_CONTAINER_CMD.search(raw_output)
        or _RE_SEPARATOR.search(raw_output)
    )


def _citations_from_point(point: str) -> list:
    """autoAnalysis point 문자열에서 citation 리스트 추출 (최대 20개).

    point는 "증거1,증거2,..." 누적 문자열(:1811).
    빈 요소 제거 후 최대 20개. raw_output 미포함 (§7 누출 경계 유지).
    """
    if not point:
        return []
    parts = [p.strip() for p in point.split(",")]
    return [p for p in parts if p][:20]


def judge(
    item_id: str,
    raw_output: str,
    variant: str,
    thresholds: dict,
    *,
    context: Optional[str] = None,
) -> ForcedVerdict:
    """컨테이너(PRCC) 결정론 어댑터 진입점.

    §18.1 C1: gate() 선확인 — DET/DET-PARTIAL이 아니면 즉시 handled=False.
    §3.4: 증거 부재 가드 — 빈출력/수집실패는 디폴트-N 거짓양호 위험 → handled=False.
    §3.1: autoAnalysis 단일함수 호출 → result 매핑.
    §7: raw_output 누출 방지 — point 문자열만 citation으로 사용.
    """
    # ── §18.1 C1: 거짓 양호 게이트 (DET/DET-PARTIAL이 아니면 차단) ─────────────
    gate_result = gate(item_id, variant)
    if gate_result is not None:
        return gate_result

    # ── §3.4 증거 부재 가드 (디폴트-N 거짓양호 방지, autoAnalysis 호출 전) ──────
    # autoAnalysis 디폴트가 {"result":"N","point":""}(:30)이므로
    # 빈 출력/수집실패도 "양호"를 반환한다. gate 통과 후 수집 증거 확인 필수.
    if not _has_collection_evidence(raw_output):
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                "[증거 부재: 컨테이너 수집 출력이 비어있거나 수집 실패 — 자동 양호 불가]"
                f" (item={item_id}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── autoAnalysis 단일함수 호출 (sApp=mapped_variant, vulKey=item_id) ─────────
    # autoAnalysis outer gate: if sApp in autoTarget (exact list membership).
    # autoTarget = ["k8s_master","k8s_worker","docker","ocp_master","ocp_worker",...]
    # "docker_linux" not in autoTarget → _VARIANT_TO_SAPP 변환 필수.
    # 내부 분기는 "docker" in sApp (부분문자열)이므로 sApp="docker"로 변환 후 통과.
    sapp = _VARIANT_TO_SAPP.get(variant, variant)
    from judge_tool.vendor.common.container import autoAnalysis as _mod  # 지연 임포트

    try:
        res = _mod.autoAnalysis(sapp, item_id, raw_output)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "container autoAnalysis 예외 item=%s variant=%s: %s(%s)",
            item_id, variant, type(exc).__name__, exc,
        )
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[결정론 함수 예외] {type(exc).__name__}: {exc!s:.100}",
            citations=[],
            ev_status="review",
            handled=False,
        )

    result = (res or {}).get("result", "")
    point = (res or {}).get("point", "") or ""

    # ── §5.4 판정값 매핑 ─────────────────────────────────────────────────────

    # result="M": 수동 판단 신호 (서버의 (*) 마커 역할)
    if result == "M":
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[수동 판단 필요] {point[:200]}",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # 취약
    if result == "Y":
        return ForcedVerdict(
            verdict="취약",
            confidence=0.9,
            rationale=point[:200] if point else "(-) 취약으로 판단",
            citations=_citations_from_point(point),
            ev_status="bad",
            handled=True,
        )

    # 양호: result="N"
    if result == "N":
        return ForcedVerdict(
            verdict="양호",
            confidence=0.9,
            rationale=point[:200] if point else "(+) 양호로 판단",
            citations=[],
            ev_status="good",
            handled=True,
        )

    # 빈 result / 기타 미결정 — 디폴트 N이 아닌 미결정값은 handled=False
    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=f"[미결정: result={result!r}] {point[:200]}",
        citations=[],
        ev_status="review",
        handled=False,
    )


# ── 레지스트리 등록 (모듈 import 시 자동 실행) ──────────────────────────────
_DET_ADAPTERS["container"] = judge

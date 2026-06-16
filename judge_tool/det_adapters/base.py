"""결정론 어댑터 공통 기반 모듈 (§5.2, §5.3, §18).

주요 역할:
  - ForcedVerdict 데이터클래스: 어댑터 통일 반환 타입(§5.2).
  - DET_SOURCE.yaml 로더 + classify() 조회: 항목×variant별 결정론 분류(§18.0).
  - is_deterministic(): classify 결과가 정확히 'DET'일 때만 True.
  - 어댑터 레지스트리 _DET_ADAPTERS: Phase 0은 빈 dict, 도메인 어댑터는 Phase 1+에서 등록.
  - gate(): STUB/ABSENT/UNREACHABLE/MANUAL 항목에 handled=False ForcedVerdict를 반환해
    거짓 양호를 구조적으로 차단(§18.1 C1). DET-PARTIAL은 통과 허용 —
    common 명확경로는 결정론, (*) 수동경로는 server.py Low-1 가드가 차단(사용자결정 2026-06-16).

DET_SOURCE.yaml 경로: judge_tool/vendor/common/DET_SOURCE.yaml
  파일 없으면 경고 없이 빈 items로 로드(미지 항목=ABSENT=안전).

classify(item_id, variant) 조회 계약:
  1) items에 item_id 없으면 "ABSENT"(미지 항목=비결정론).
  2) entry에 variants 있으면: 실제 variant 문자열 조회 → 없으면
     엔진토큰 variant.split('_')[0] 재조회(예: 'mysql_native'→'mysql') →
     없으면 entry.get('default') → 없으면 "ABSENT".
  3) variants 없으면 entry.get('default', "ABSENT").
"""
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

import yaml

log = logging.getLogger(__name__)

# DET_SOURCE.yaml 경로 (패키지 루트 기준)
_DET_SOURCE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "vendor", "common", "DET_SOURCE.yaml"
)


def _load_det_source() -> Dict:
    """DET_SOURCE.yaml을 1회 로드한다. 파일 없으면 빈 items로 반환(경고 없이)."""
    path = os.path.normpath(_DET_SOURCE_PATH)
    if not os.path.exists(path):
        return {"items": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            log.warning("DET_SOURCE.yaml 최상위가 dict가 아님 — 빈 items로 폴백")
            return {"items": {}}
        if "items" not in data:
            log.warning("DET_SOURCE.yaml에 'items' 키 없음 — 빈 items로 폴백")
            data["items"] = {}
        return data
    except Exception as e:  # noqa: BLE001
        log.warning("DET_SOURCE.yaml 로드 실패(%s) — 빈 items로 폴백", type(e).__name__)
        return {"items": {}}


# 모듈 로드 시 1회 캐시
_DET_SOURCE: Dict = _load_det_source()


def reload_det_source(path: Optional[str] = None) -> None:
    """테스트용: DET_SOURCE를 재로드한다. path를 지정하면 해당 경로에서 로드."""
    global _DET_SOURCE  # noqa: PLW0603
    if path is not None:
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            if not isinstance(data, dict):
                data = {}
            if "items" not in data:
                data["items"] = {}
            _DET_SOURCE = data
        except Exception as e:  # noqa: BLE001
            log.warning("DET_SOURCE 재로드 실패(%s) — 빈 items 유지", type(e).__name__)
            _DET_SOURCE = {"items": {}}
    else:
        _DET_SOURCE = _load_det_source()


def classify(item_id: str, variant: str) -> str:
    """항목×variant별 결정론 분류 문자열을 반환한다.

    반환값: 'DET' | 'STUB' | 'UNREACHABLE' | 'ABSENT' | 'MANUAL' | 'DET-PARTIAL'
    조회 계약(§5 base.py 계약):
      1) items에 item_id 없으면 "ABSENT".
      2) variants 있으면: variant 직접 → 엔진토큰(split('_')[0]) → default → "ABSENT".
      3) variants 없으면 default → "ABSENT".
    """
    items = _DET_SOURCE.get("items", {})
    entry = items.get(item_id)
    if entry is None:
        return "ABSENT"
    if not isinstance(entry, dict):
        return "ABSENT"

    variants_map = entry.get("variants")
    if variants_map and isinstance(variants_map, dict):
        # 1. 실제 variant 문자열 직접 조회
        if variant in variants_map:
            return str(variants_map[variant])
        # 2. 엔진토큰 폴백 (예: 'mysql_native' → 'mysql', 'pg_aurora' → 'pg')
        engine_token = variant.split("_")[0] if "_" in variant else None
        if engine_token and engine_token in variants_map:
            return str(variants_map[engine_token])
        # 3. default
        default = entry.get("default")
        if default is not None:
            return str(default)
        return "ABSENT"
    else:
        # variants 없음: default만
        default = entry.get("default")
        if default is not None:
            return str(default)
        return "ABSENT"


def is_deterministic(item_id: str, variant: str) -> bool:
    """classify 결과가 정확히 'DET'일 때만 True.

    DET-PARTIAL은 variant별로 실제 분류가 달라질 수 있으므로 False.
    (classify가 variants 맵에서 이미 구체값을 반환하므로 'DET-PARTIAL'이
    classify 결과로 나오는 경우는 entry에 variants 없이 default='DET-PARTIAL'인
    케이스뿐이며, 이 경우 어댑터 불가로 False가 안전.)
    """
    return classify(item_id, variant) == "DET"


@dataclass
class ForcedVerdict:
    """어댑터 통일 반환 타입 (§5.2).

    verdict: "양호" | "취약" | "판단보류"
    confidence: 결정론 성공=0.9, 수동/판정불가=0.0
    rationale: 한국어 근거(common reason → 정제)
    citations: 위반 증거 인용(취약 시)
    ev_status: "good" | "bad" | "review"  (합성 ResourceEvidence용)
    handled: False면 이 항목은 결정론 대상 아님 → 호출부에서 LLM 폴백
    """
    verdict: str
    confidence: float
    rationale: str
    citations: list = field(default_factory=list)
    ev_status: str = "review"
    handled: bool = True


# 어댑터 레지스트리: profile_key → adapter callable
# Phase 0은 빈 dict. 도메인 어댑터는 Phase 1+에서 등록.
# 어댑터 시그니처: (item_id: str, raw_output: str, variant: str,
#                   thresholds: dict, *, context: str | None) -> ForcedVerdict
_DET_ADAPTERS: Dict[str, Callable] = {}


def get_adapter(profile_key: str) -> Optional[Callable]:
    """profile_key에 해당하는 어댑터를 반환. 없으면 None (Phase 0에서 항상 None)."""
    return _DET_ADAPTERS.get(profile_key)


def gate(item_id: str, variant: str) -> Optional[ForcedVerdict]:
    """§18.1 C1 거짓 양호 차단 게이트.

    classify 결과가 'DET' 또는 'DET-PARTIAL'이면 None을 반환해 어댑터 진행을 허용한다.
    그 외(STUB/UNREACHABLE/ABSENT/MANUAL)는 handled=False ForcedVerdict를 반환해
    어댑터 진행을 차단한다(C1 불변).

    # 사용자결정(2026-06-16): DET-PARTIAL 패스스루 — common 명확경로는 결정론,
    # (*)수동은 Low-1 가드로 handled=False→LLM. STUB/ABSENT/MANUAL/UNREACHABLE은
    # 계속 차단(C1).
    #
    # DET-PARTIAL 통과의 안전성은 다음 체인에 의존:
    #   common이 애매한 경로를 만나면 반드시 reason에 "(*)" 를 포함해 반환한다.
    #   서버 어댑터(server.py)의 Low-1 가드가 "(*)" in reason and result != "Y" 조건에서
    #   handled=False를 반환해 거짓양호를 차단한다.
    #   따라서 gate가 DET-PARTIAL을 통과시켜도, common이 판정을 보장하지 못한 경우는
    #   Low-1 가드가 handled=False→LLM 폴백으로 처리한다.

    이 함수가 §18.1 C1 가드의 단일 출처다: "아무것도 안 한 N이 양호로 새지 않는다".
    """
    cls = classify(item_id, variant)
    if cls in {"DET", "DET-PARTIAL"}:
        return None
    # STUB/UNREACHABLE/ABSENT/MANUAL: 거짓 양호 차단 — handled=False 반환 (C1 불변)
    rationale = (
        f"[비결정론 소스: {cls}] 이 항목×variant({item_id}, {variant})의 "
        f"결정론 소스가 '{cls}'이므로 결정론 판정을 건너뜁니다. "
        "STUB/ABSENT/MANUAL/UNREACHABLE 항목은 LLM/인터뷰/canned 경로로 라우팅됩니다(§18.1 C1)."
    )
    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=rationale,
        citations=[],
        ev_status="review",
        handled=False,
    )

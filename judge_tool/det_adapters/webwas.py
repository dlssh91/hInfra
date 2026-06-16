"""웹서버-WAS(WST) 결정론 어댑터 — Phase 3 (§5.2/§18, WST 웹특화 check 함수 직접 호출).

설계 계약:
  - judge() 시그니처: (item_id, raw_output, variant, thresholds, *, context=None) → ForcedVerdict
  - SRV-* 항목: server 어댑터에 위임 (§2.1 ID 네임스페이스 라우팅).
  - WST-* 항목: §18.1 C1 gate 선확인 → 웹서버 파서 모듈 선택 → check_WST_NNN 직접 호출.
  - §6.4 config-항목 거짓판정 방어: config 시그니처 부재 시 handled=False (거짓취약/거짓양호 차단).
  - §6.2 웹서버 추론: detect가 linux(OS variant) 반환 시 raw에서 웹서버 종류 추론.
  - §5.3 매핑: result 'N'→양호(증거존재 가드), 'Y'→취약+citations, (*)/수동→handled=False.
  - raw_output이 LLM/citations/산출물로 새지 않도록 경계 유지 (§7).

레지스트리 등록: 모듈 import 시 _DET_ADAPTERS["webwas"] = judge 자동 등록.
main.py에서 `from judge_tool.det_adapters import webwas as _webwas_adapter` 로 부작용 임포트.
"""
import logging
import re
from typing import Optional

from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate
from judge_tool.det_adapters import server as _server

log = logging.getLogger(__name__)

# OS variant 키 (profile.WEBWAS OS 5종, server 어댑터 위임 대상)
_OS_VARIANTS = frozenset({"aix", "hpux", "linux", "solaris", "win"})
# 웹 variant 키 (profile.WEBWAS 웹 6종, WST check 함수 파서로 위임)
_WEB_VARIANTS = frozenset({"webservice", "apache", "webtob", "iis", "tomcat", "jeus"})

# ── §6.4 config-항목 config 시그니처 사전 ─────────────────────────────────────
# config-항목(WST-031/035/036/037/038/039/102)은 raw blob에 config 본문이 없으면
# 거짓취약(035: LimitRequestBody 없음→취약) 또는 거짓양호(038: Directory 정규식 미매치→양호).
# 각 항목별 config 존재 시그니처: 적어도 1개 이상 존재해야 config 수집이 된 것으로 판단.
_WST_CONFIG_SIG: dict = {
    "WST-031": ("<Directory", "Options"),
    "WST-035": ("LimitRequestBody",),
    "WST-036": ("User ", "Group "),
    "WST-037": ("DocumentRoot", "DOCROOT"),
    "WST-038": ("<Directory", "Options"),
    "WST-039": ("LoadModule", "mod_"),
    "WST-102": ("ServerTokens", "removeServerHeader", "httpErrors"),
}

# ── §6.2 raw에서 웹서버 종류 추론 패턴 ──────────────────────────────────────────
# detect가 linux(OS variant)를 반환했을 때 WST 항목 판정을 위해 raw_output 패턴으로 추론.
_INFER_WEB_PATTERNS = (
    (re.compile(r"apache2?|httpd", re.IGNORECASE), "apache"),
    (re.compile(r"IIS|applicationHost|iisadmin", re.IGNORECASE), "iis"),
    (re.compile(r"webtob|wsm\b|htl\b", re.IGNORECASE), "webtob"),
)

# 증거 존재 판정 패턴 (server.py 동형)
_RE_CMD_PROMPT = re.compile(r"^\s*[$#]\s+\S", re.MULTILINE)
_RE_SVC_BLOCK = re.compile(r"\[\s*\S.*?\s*\]\[S\]")


def _has_collection_evidence(raw_output: str) -> bool:
    """raw_output에 점검 수집이 실제로 이루어진 증거가 있는지 판정 (server.py 동형)."""
    if not raw_output or not raw_output.strip():
        return False
    return bool(_RE_CMD_PROMPT.search(raw_output) or _RE_SVC_BLOCK.search(raw_output))


def _citations_from_vul_list(vul_list) -> list:
    """common vul_list에서 citation 문자열 리스트 추출 (최대 20개, server.py 동형)."""
    citations = []
    for item in (vul_list or []):
        if not isinstance(item, dict):
            continue
        text = str(item.get("vulnerabilityConditionOutput", "")).strip()
        if text:
            citations.append(text)
        if len(citations) >= 20:
            break
    return citations


def _absent(reason: str) -> ForcedVerdict:
    """handled=False 반환 헬퍼."""
    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=f"[webwas 어댑터 비결정론: {reason}]",
        citations=[],
        ev_status="review",
        handled=False,
    )


def _infer_web_variant(raw_output: str) -> Optional[str]:
    """raw_output에서 웹서버 종류를 추론한다 (§6.2).

    detect_variant가 linux 등 OS키를 반환했을 때 WST 항목의 웹서버 파서 선택을 위해 사용.
    추론 불가 시 None 반환.
    """
    if not raw_output:
        return None
    for pat, web_key in _INFER_WEB_PATTERNS:
        if pat.search(raw_output):
            return web_key
    return None


def _wst_module(web_variant: str):
    """web_variant에 대응하는 WST 파서 모듈을 반환한다. 파서 없으면 None."""
    if web_variant == "apache":
        from judge_tool.vendor.common.webwas import WST_Apache_parse as m
        return m
    if web_variant == "iis":
        from judge_tool.vendor.common.webwas import WST_IIS_parse as m
        return m
    if web_variant == "webtob":
        from judge_tool.vendor.common.webwas import WST_WebtoB_parse as m
        return m
    # tomcat/jeus/webservice → 파서 없음
    return None


def _has_config_signature(item_id: str, raw_output: str) -> bool:
    """§6.4 config-항목 config 시그니처 존재 확인.

    WST_CONFIG_SIG에 등재된 config-항목은 raw에 해당 시그니처 키워드가 하나도 없으면
    config 미수집으로 판단 → False 반환 (handled=False 처리할 것).
    WST_CONFIG_SIG에 미등재 항목(명령출력 항목)은 항상 True 반환.
    """
    sigs = _WST_CONFIG_SIG.get(item_id)
    if sigs is None:
        # config-항목이 아님 (명령출력 항목) → 시그니처 체크 불필요
        return True
    if not raw_output:
        return False
    return any(sig in raw_output for sig in sigs)


def _map_result(
    item_id: str,
    variant: str,
    result: str,
    reason: str,
    vul_list,
    raw_output: str,
) -> ForcedVerdict:
    """(result, reason, vul_list) → ForcedVerdict 매핑 (server.py §5.4 동형 + §6.4 가드).

    Low-1 가드: (*) in reason and result != 'Y' → handled=False.
    §6.4 config 시그니처 가드: result='N'(양호) + config 시그니처 부재 → handled=False.
    증거존재 가드: result='N'(양호) + 수집 증거 부재 → handled=False.
    """
    # Low-1 가드: (*) 수동 마커 + result != 'Y' → handled=False
    if "(*)" in reason and result != "Y":
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[수동 판단 필요] {reason[:200]}",
            citations=[],
            ev_status="review",
            handled=False,
        )

    if result == "N":
        # 증거존재 가드: 수집 증거 부재 시 handled=False.
        # §6.4 config 시그니처 가드는 check 함수 호출 전 적용 완료 (judge() 내부).
        # config-항목(WST_CONFIG_SIG 등재)은 config 시그니처 가드가 이미 증거 확인 완료.
        # → 명령출력 항목(WST_CONFIG_SIG 미등재)만 추가 증거가드 적용.
        is_config_item = item_id in _WST_CONFIG_SIG
        if not is_config_item and not _has_collection_evidence(raw_output):
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    "[증거 부재: 점검 출력이 비어있거나 수집 실패 — 자동 양호 불가]"
                    f" (item={item_id}, variant={variant})"
                ),
                citations=[],
                ev_status="review",
                handled=False,
            )
        return ForcedVerdict(
            verdict="양호",
            confidence=0.9,
            rationale=reason[:200] if reason else "(+) 양호로 판단",
            citations=[],
            ev_status="good",
            handled=True,
        )

    if result == "Y":
        return ForcedVerdict(
            verdict="취약",
            confidence=0.9,
            rationale=reason[:200] if reason else "(-) 취약으로 판단",
            citations=_citations_from_vul_list(vul_list),
            ev_status="bad",
            handled=True,
        )

    # 빈 결과 / M / NA / 기타
    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=f"[수동/미결정: result={result!r}] {reason[:200]}",
        citations=[],
        ev_status="review",
        handled=False,
    )


def judge(
    item_id: str,
    raw_output: str,
    variant: str,
    thresholds: dict,
    *,
    context: Optional[str] = None,
) -> ForcedVerdict:
    """웹서버-WAS 결정론 어댑터 진입점.

    §2.1 ID 네임스페이스 라우팅:
      SRV-* → server 어댑터 위임 (OS 항목은 SRV ID로 수집됨, §0.1)
      WST-* → WST gate + 파서 모듈 선택 + check_WST_NNN 직접 호출
      기타  → handled=False
    """
    # ── SRV-* 항목: server 어댑터 위임 (§2.1) ────────────────────────────────
    if item_id.startswith("SRV-"):
        # OS variant면 그대로, 웹키면 linux-override 미적용(SRV_auto_parse 경로)
        os_variant = variant if variant in _OS_VARIANTS else "linux"
        return _server.judge(item_id, raw_output, os_variant, thresholds, context=context)

    # ── WST-* 항목 ────────────────────────────────────────────────────────────
    if item_id.startswith("WST-"):
        # §18.1 C1: gate 선확인 (DET/DET-PARTIAL이 아니면 차단)
        gate_result = gate(item_id, variant)
        if gate_result is not None:
            return gate_result

        # 웹서버 파서 모듈 선택
        if variant in _WEB_VARIANTS:
            web_variant = variant
        elif variant in _OS_VARIANTS:
            # OS variant로 detect된 경우 → raw에서 웹서버 추론 (§6.2)
            web_variant = _infer_web_variant(raw_output)
            if web_variant is None:
                return _absent(f"OS variant({variant})에서 웹서버 종류 추론 불가 — WST 항목 판정 불가")
            # Opus M-2: OS-variant gate 통과 후 추론된 web-variant 분류 재확인(DET 아니면 handled=False) — (*)관습 의존 제거
            from judge_tool.det_adapters.base import classify as _classify
            web_cls = _classify(item_id, web_variant)
            if web_cls not in ("DET", "DET-PARTIAL"):
                return _absent(
                    f"OS variant({variant}) 추론 web-variant({web_variant}) 분류={web_cls!r} — "
                    f"DET/DET-PARTIAL 아니므로 WST 판정 불가(M-2)"
                )
        else:
            return _absent(f"미지 variant: {variant!r}")

        mod = _wst_module(web_variant)
        if mod is None:
            return _absent(f"웹서버 변형({web_variant}) 파서 없음 (tomcat/jeus/webservice)")

        fn = getattr(mod, "check_" + item_id.replace("-", "_"), None)
        if fn is None:
            return _absent(f"{item_id} check 함수 없음 (variant={web_variant})")

        # §6.4 config-항목 사전 가드: check 함수 호출 전 config 시그니처 존재 확인.
        # config 시그니처 없음 → 거짓취약(Y 오판) 또는 거짓양호(N 오판) 둘 다 차단.
        if not _has_config_signature(item_id, raw_output):
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[config 미수집: {item_id} config 시그니처 없음 — 자동 판정 불가]"
                    f" (item={item_id}, variant={web_variant})"
                ),
                citations=[],
                ev_status="review",
                handled=False,
            )

        try:
            result, reason, vul_list = fn(raw_output)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "det_adapters.webwas check 함수 예외 item=%s variant=%s web_variant=%s fn=%s: %s",
                item_id, variant, web_variant, fn.__name__, exc,
            )
            return _absent(f"결정론 함수 예외: {type(exc).__name__}")

        return _map_result(item_id, web_variant, result, reason, vul_list, raw_output)

    # ── 미지 접두어 ───────────────────────────────────────────────────────────
    return _absent(f"미지 ID 접두어: {item_id!r}")


# ── 레지스트리 등록 (모듈 import 시 자동 실행) ──────────────────────────────
_DET_ADAPTERS["webwas"] = judge

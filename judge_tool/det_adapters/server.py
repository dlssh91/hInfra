"""서버(OS) 결정론 어댑터 — Phase 1 서버 파일럿 (§5.2/§16.3/§18).

설계 계약:
  - judge() 시그니처: (item_id, raw_output, variant, thresholds, *, context=None) → ForcedVerdict
  - variant=="linux" 이고 item ∈ {SRV-026,069,074,127,131} → SRV_Linux_parse 사용 (§16.3)
  - 그 외 → SRV_auto_parse 사용
  - DET_SOURCE gate: DET가 아니면 handled=False (거짓 양호 차단 §18.1 C1)
  - 판정값 매핑 (§5.4):
      result='N' (양호) AND "(*)" not in reason → 증거존재 확인 후 verdict=양호, ev_status=good, conf=0.9, handled=True
      result='N' (양호) AND 증거부재(빈출력·명령없음·에러만) → handled=False (C-1/C-2 shift-left 가드)
      result='N' (양호) AND 세션/연결 오류출력(_RE_ERROR_OUTPUT) → handled=False (F10 가드, 백로그 처리)
      result='Y' → verdict=취약, ev_status=bad, conf=0.9, citations 추출, handled=True
      "(*)" in reason AND result != 'Y' → handled=False (Low-1 거짓양호 방지 가드, fail-closed)
      result in ('', 'M') → handled=False
      예외 → handled=False (경고 로그)
  - raw_output이 LLM/citations/산출물로 새지 않도록 경계 유지 (§7)

레지스트리 등록: 모듈 import 시 _DET_ADAPTERS["server"] = judge 로 자동 등록.
main.py에서 `from judge_tool.det_adapters import server as _server_adapter` 로 부작용 임포트.
"""
import logging
import re
from typing import Optional

from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate

log = logging.getLogger(__name__)

# linux variant에서 오버라이드되는 5개 항목 (§16.3 SRV_Linux_parse 우선병합)
_LINUX_OVERRIDE_ITEMS = frozenset({"SRV-026", "SRV-069", "SRV-074", "SRV-127", "SRV-131"})

# 증거 존재 판정 패턴: 명령 프롬프트 라인 또는 서비스 블록
# - 명령 프롬프트: 행 시작에 $ 또는 # + 공백 + 비공백(실제 명령어)
# - 서비스 블록: [ name ][S] 형태의 블록 경계 패턴 (get_check_service 포맷)
#   → 단순 부분문자열 "[S]" 매칭은 'garbage [S] more' 같은 우연 포함도 통과시키므로
#     블록 경계 패턴(\[\s*\S.*?\s*\]\[S\])으로 조여 거짓 증거 차단. (Opus Medium 이슈 수정)
_RE_CMD_PROMPT = re.compile(r"^\s*[$#]\s+\S", re.MULTILINE)
_RE_SVC_BLOCK = re.compile(r"\[\s*\S.*?\s*\]\[S\]")


def _has_collection_evidence(raw_output: str) -> bool:
    """raw_output에 점검 수집이 실제로 이루어진 증거가 있는지 판정.

    True  → 명령 프롬프트 라인($ cmd / # cmd) 또는 서비스 블록([ name ][S] 경계 패턴)이
            1개 이상 존재.
    False → 빈 출력, 에러 문구만 있는 출력, garbage. 양호로 신뢰하면 안 됨.

    서비스 블록 패턴은 단순 "[S]" 부분문자열이 아니라 블록 경계형
    패턴 (예: "[ ftp ][S]")만 인정.
    'garbage [S] more' 같은 우연 포함은 통과시키지 않는다. (Opus Medium 이슈 수정)

    샘플 검증(linux-s-sample.xml 기준):
      - 정당 양호: 모든 DET/DET-PARTIAL 항목이 패턴 중 하나를 가짐 → True (과트리거 0).
      - 빈/garbage/에러만: 패턴 없음 → False (거짓양호 차단).
    """
    if not raw_output or not raw_output.strip():
        return False
    return bool(_RE_CMD_PROMPT.search(raw_output) or _RE_SVC_BLOCK.search(raw_output))


# ── F10 오류출력 가드 (백로그, 2026-07-11-falsegood-audit.md F10 처리) ──────────
# 대상: "명령은 찍혔으나(=_has_collection_evidence 통과) 실패한 출력"에서
# check_SRV_*가 기대 취약패턴을 찾지 못해 result='N'(양호)로 떨어지는 거짓양호.
# container.py F8과 동형 문제이나, 실샘플 실증 결과 **F8과 동일한 토큰셋을
# 그대로 쓸 수 없다** — 아래는 그 실증 근거와 최종 축소 설계다.
#
# 실증(collected/server/linux/*, out/srv_lab/*, collected/web/apache_linux/*,
# out/was_lab/* 전 실샘플 + comparison.md 항목별 양호증거표):
#   - "cat: /etc/mail/sendmail.cf: No such file or directory" 류는 SRV-004~009
#     (메일릴레이 점검)의 **정당 양호증거 그 자체**다(메일서버 미설치=양호).
#   - "cat: /etc/motd: No such file or directory"는 SRV-163(로그인 배너)의
#     **정당 양호증거**다(배너 파일 없음=정보노출 없음=양호, comparison.md 참조).
#   - "sendmail: command not found"/"...: not found"는 SRV-006/007의 정당
#     양호증거(메일서버 바이너리 없음=양호) — out/was_lab/tomcat-good.xml(양호
#     라벨 샘플)에도 그대로 등장.
#   - 즉 컨테이너 F8과 달리 서버 도메인은 "명령 결과 없음/파일 없음"이 다수
#     항목에서 이미 의도된 정상 신호이므로, container.py의 무앵커 토큰
#     (`command not found`/`Permission denied`/`No such file or directory`)을
#     그대로 쓰면 **정당 양호가 대량으로 판단보류 강등** → 과트리거 0 실패.
#     (F8이 요구한 "과트리거 0 검증" 원칙을 지키려면 이 토큰들을 넣을 수 없다.)
#
# 따라서 F10은 "개별 명령의 대상 부재/거부"가 아니라 **세션/연결 전체가
# 끊겨 이후 모든 명령 결과를 신뢰할 수 없는** 신호만 좁게 채택한다.
# 이 토큰들은 위 실샘플 전체(양호/취약 라벨 불문) grep 결과 0건이며,
# vendor/common/server, vendor/common/webwas, comparison.md 어디에서도
# "정당 양호증거"로 문서화된 사례가 없다(전수 grep 확인, 면제 테이블 불요).
#   - `-bash:`/`sh:` 로 시작하는 셸 자체의 명령 미발견/권한거부
#     (개별 도구의 "cat:/grep:/ls: 파일없음"과 달리, 셸이 명령 자체를
#     못 찾거나 실행을 거부한 것 — 수집 스크립트 실행 환경이 깨졌다는 신호).
#   - 연결류: Connection refused/timed out, No route to host,
#     Network is unreachable, Unable to connect, Host is down
#     (SSH/원격 연결이 중간에 끊겨 이후 명령 출력이 비정상이라는 신호).
#   - Operation not permitted (capability 수준 거부 — Permission denied와
#     달리 실샘플에서 정상 점검 결과로 쓰인 사례가 전혀 없어 채택).
_RE_ERROR_OUTPUT = re.compile(
    r"(?m)"
    r"^\s*(-bash|sh):.*(command not found|Permission denied)"
    r"|Connection refused"
    r"|Connection timed out"
    r"|No route to host"
    r"|Network is unreachable"
    r"|Unable to connect"
    r"|Host is down"
    r"|Operation not permitted"
)


def _has_error_output(raw_output: str):
    """raw_output에서 F10 오류출력 가드 패턴 매치를 반환(없으면 None).

    webwas.py의 WST-* 명령출력 항목에서도 동일 패턴을 재사용한다(§F10 파급).
    """
    if not raw_output:
        return None
    return _RE_ERROR_OUTPUT.search(raw_output)


def _citations_from_vul_list(vul_list) -> list:
    """common vul_list에서 citation 문자열 리스트 추출 (최대 20개).

    각 원소는 dict({'vulnerabilityConditionOutput': ..., ...}).
    누출 방지: raw_output 전체가 아니라 vul_list의 구조화된 출력만 사용.
    """
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


def judge(
    item_id: str,
    raw_output: str,
    variant: str,
    thresholds: dict,
    *,
    context: Optional[str] = None,
) -> ForcedVerdict:
    """서버 결정론 어댑터 진입점.

    §18.1 C1: gate() 선확인 — DET가 아니면 즉시 handled=False.
    §16.3: linux variant + _LINUX_OVERRIDE_ITEMS → SRV_Linux_parse 사용.
    §5.4: result 매핑 및 수동/(*)분기 처리.
    F10: result='N' 경로에서 세션/연결급 오류출력(_RE_ERROR_OUTPUT) 감지 시
         handled=False로 강등(명령은 찍혔으나 실패한 출력→N→양호 차단, 백로그).
    §7: raw_output 누출 방지 — reason/vul_list 텍스트만 사용.
    """
    # ── §18.1 C1: 거짓 양호 게이트 (DET가 아니면 차단) ──────────────────────
    gate_result = gate(item_id, variant)
    if gate_result is not None:
        # gate()가 None이 아님 = DET가 아님 → handled=False 반환
        return gate_result

    # ── 모듈 선택 (§16.3) ────────────────────────────────────────────────────
    if variant == "linux" and item_id in _LINUX_OVERRIDE_ITEMS:
        from judge_tool.vendor.common.server import SRV_Linux_parse as _mod
    else:
        from judge_tool.vendor.common.server import SRV_auto_parse as _mod

    # ── check 함수 조회 ───────────────────────────────────────────────────────
    fname = "check_" + item_id.replace("-", "_")
    fn = getattr(_mod, fname, None)
    if fn is None:
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[어댑터: {item_id} check 함수 없음 — 방어 폴백]",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── check 함수 호출 ───────────────────────────────────────────────────────
    try:
        result, reason, vul_list = fn(raw_output)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "det_adapters.server check 함수 예외 item=%s variant=%s fn=%s type=%s: %s",
            item_id, variant, fname, type(exc).__name__, exc,
        )
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[결정론 함수 예외] {type(exc).__name__}",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── §5.4 판정값 매핑 ─────────────────────────────────────────────────────

    # Low-1(Opus §Phase1): result=N이라도 (*) 수동마커 동반 시 거짓양호 방지 — fail-closed.
    # (*) 있고 result != 'Y' → handled=False (result='N'+'(*)'+'(-)'도 거짓양호이므로 차단).
    # result='Y'+'(*)'+'(-)' 케이스는 취약(보수적으로 안전)이므로 이 가드를 통과시킨다.
    if "(*)" in reason and result != "Y":
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[수동 판단 필요] {reason[:200]}",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # 기존 수동 분기((*) 있고 (-) 없음)는 위 가드로 완전히 대체됨.
    # result='Y'+'(*)'+'(-)'는 아래 취약 분기에서 처리(handled=True, verdict=취약).

    # 양호
    if result == "N":
        # Opus C-1/C-2 shift-left: result='N'(양호)이라도 raw_output에 점검 증거(명령 실행 흔적)가
        # 없으면 수집실패/빈입력을 양호로 오판하는 거짓양호 → handled=False로 강등.
        # (*) 가드(Low-1)와 별개로 "증거 부재→양호 금지".
        # 증거 존재 판정: raw_output에 명령 프롬프트 라인($ cmd 또는 # cmd) 또는 서비스 블록([S])이
        # 1개 이상 있어야 점검이 실제 실행된 것으로 본다.
        # 정당 양호(서비스 inactive, 파일권한 양호 등)는 모두 이 패턴 중 하나를 가진다.
        # 빈 출력, 에러 문구만 있는 출력, garbage 입력은 어떤 패턴도 없으므로 증거부재로 판정.
        if not _has_collection_evidence(raw_output):
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

        # F10 오류출력 가드: 명령은 찍혔으나(증거존재 통과) 세션/연결이 끊겨
        # 실패한 출력이면 check_SRV_*의 "패턴 부재→N" 판정을 신뢰할 수 없다.
        # _RE_ERROR_OUTPUT 설계근거는 위 정의부 주석 참조(과트리거 0 실증 완료).
        err_match = _has_error_output(raw_output)
        if err_match is not None:
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    "[수집 명령 오류 출력 감지 — 자동판정 불가]"
                    f" (item={item_id}, variant={variant},"
                    f" 매치토큰={err_match.group(0).strip()!r})"
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

    # 취약
    if result == "Y":
        return ForcedVerdict(
            verdict="취약",
            confidence=0.9,
            rationale=reason[:200] if reason else "(-) 취약으로 판단",
            citations=_citations_from_vul_list(vul_list),
            ev_status="bad",
            handled=True,
        )

    # 빈 결과 / M
    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=f"[수동/미결정: result={result!r}] {reason[:200]}",
        citations=[],
        ev_status="review",
        handled=False,
    )


# ── 알려진 한계 (Known Limitations) ──────────────────────────────────────────
# 빈 서비스 블록(예: "[ ftp ][S][ ftp ][E]")은 "서비스 off → 양호"와
# "수집 스크립트 미실행 → 데이터 없음" 두 경우를 구분할 수 없다.
# 실제 fsi_unix.sh는 netstat+ps+inetd+rpcinfo 다중탐지로 블록을 채우므로
# 실데이터에서는 건전하다. 합성 빈블록만 이론적 위험으로 남는다.
# 백로그: 수집 스크립트에 "check-ran 마커" 추가로 근본 해결 가능 (향후 과제).

# ── 레지스트리 등록 (모듈 import 시 자동 실행) ──────────────────────────────
_DET_ADAPTERS["server"] = judge

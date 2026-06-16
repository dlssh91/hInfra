"""Pre-flight 인코딩 교정 + LLM 점검 가능 게이트.

전 도메인 공통 pre-flight: main.run 점검 루프 이전에 실행한다.

Step 1 — 인코딩 자동 교정 (결정론 휴리스틱, LLM 아님)
  charset 판별(strict 프로빙):
    1. bytes.decode('utf-8-sig', errors='strict') 성공 → utf-8-sig(BOM).
    2. bytes.decode('utf-8', errors='strict') 성공 → utf-8
       (utf-8은 자기검증적이라 euc-kr 선언이어도 strict 성공 = utf-8 확정).
    3. bytes.decode('cp949', errors='strict') 성공 → cp949
       (euc-kr 상위호환).
    4. 셋 다 실패 → utf-8 errors='replace' 폴백 + 경고.
  XML 선언(<?xml ... ?>) 제거 후 sanitize 적용.

Step 2 — LLM 점검 가능 상태 게이트 (OllamaClient 재사용)
  교정된 텍스트 샘플로 로컬 LLM에 판독 가능성·데이터 존재 여부 질의.
  - OK → 진행.
  - NG → PreflightError(ReportError 하위) 발생.
  LLM 호출 실패(Ollama 미가동 등) → 휴리스틱 폴백(replacement char 비율·제어문자 비율).

공개 API:
  read_text(path) -> (text: str, meta: dict)
      meta: {declared_encoding, used_encoding, encoding_corrected, sanitized}
  run_llm_gate(text, meta, client, path) -> None   (NG 이면 PreflightError)
"""
import logging
import re
from typing import Dict, Optional, Tuple

from judge_tool.errors import ReportError

log = logging.getLogger(__name__)

# XML 선언(<?xml ... ?>). ET.fromstring(str)은 encoding 선언이 있는 유니코드
# 문자열을 거부하므로 디코딩 후 선언부를 제거한다.
_XML_DECL = re.compile(r"^\s*<\?xml[^>]*\?>")
# 선언부의 encoding 속성(바이트 단계에서 추출 — 디코딩 전)
_ENC_DECL = re.compile(rb"encoding=[\"']([A-Za-z0-9_.\-]+)[\"']")

# UTF-8 replacement character (U+FFFD) 탐지 정규식
_REPLACEMENT_CHAR = re.compile(r"�")
# XML 1.0 불법 제어문자(tab·LF·CR 제외)
_ILLEGAL_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# 게이트 샘플 최대 크기 (문자, 너무 길면 LLM timeout 위험)
_GATE_SAMPLE_CHARS = 2000

# CDATA 내용 추출 패턴 (XML 내 실제 점검 결과 텍스트)
_CDATA_CONTENT = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)


class PreflightError(ReportError):
    """Pre-flight 게이트 실패 — 입력 파일이 판독 불가/손상 상태.

    ReportError 상속으로 main()의 ReportError 핸들러에서 포착된다.
    """


# ---------------------------------------------------------------------------
# Step 1: 인코딩 교정
# ---------------------------------------------------------------------------

_UTF8_BOM = b"\xef\xbb\xbf"


def _detect_encoding(raw: bytes) -> Tuple[str, bool]:
    """strict 프로빙으로 실제 인코딩을 확정한다.

    반환: (used_encoding, is_replacement_fallback)

    판별 순서:
      1. BOM 확인: 파일이 UTF-8 BOM(EF BB BF)으로 시작하면 → utf-8-sig.
         (utf-8-sig는 utf-8을 완전히 포함하므로 BOM이 없어도 strict를 통과한다.
          BOM 유무를 먼저 체크해 오탐(BOM 없는 UTF-8 → utf-8-sig 오선택)을 막는다.)
      2. utf-8 strict: BOM 없음 + UTF-8 self-validating bytes → utf-8.
      3. cp949 strict: UTF-8 실패 + EUC-KR/CP949 합법 바이트 → cp949.
      4. 모두 실패 → utf-8 replace 폴백(is_replacement_fallback=True).
    """
    # 1) BOM이 있으면 utf-8-sig (BOM은 utf-8-sig 고유, strip 포함)
    if raw[:3] == _UTF8_BOM:
        try:
            raw.decode("utf-8-sig", errors="strict")
            return "utf-8-sig", False
        except (UnicodeDecodeError, LookupError):
            pass

    # 2) utf-8 strict (BOM 없음. UTF-8은 self-validating → euc-kr 선언이어도 확정)
    try:
        raw.decode("utf-8", errors="strict")
        return "utf-8", False
    except (UnicodeDecodeError, LookupError):
        pass

    # 3) cp949 (euc-kr 상위호환)
    #    단, cp949 디코딩 결과에 mojibake 시그니처(U+FFFD 또는 깨진 패턴)가
    #    많으면 "우연히 valid cp949"로 통과한 truncated/corrupted UTF-8일 수 있다.
    #    비율이 5%를 초과하면 cp949를 신뢰하지 않고 utf-8 replace 폴백을 사용한다.
    #    (실제 한글 cp949 파일은 replacement char가 0개이므로 오탐 없음.)
    try:
        decoded_cp949 = raw.decode("cp949", errors="strict")
        repl_count = decoded_cp949.count("�")
        if repl_count / max(len(decoded_cp949), 1) <= 0.05:
            return "cp949", False
        # mojibake 비율 초과 → utf-8 replace 폴백으로 낙하
        log.debug(
            "cp949 strict 성공이나 mojibake 비율 %.1f%% > 5%% — "
            "truncated UTF-8 가능성, utf-8 replace 폴백 사용",
            repl_count / max(len(decoded_cp949), 1) * 100)
    except (UnicodeDecodeError, LookupError):
        pass

    return "utf-8", True  # 폴백


def _declared_encoding(raw: bytes) -> Optional[str]:
    """XML 선언에서 encoding 속성을 추출한다. 없으면 None."""
    m = _ENC_DECL.search(raw[:200])
    if m:
        try:
            return m.group(1).decode("ascii", errors="replace").lower()
        except Exception:  # noqa: BLE001
            pass
    return None


def read_text(path: str) -> Tuple[str, Dict]:
    """파일을 읽어 교정된 유니코드 텍스트와 메타데이터를 반환한다.

    반환:
        text: XML 선언 제거 + sanitize 적용된 텍스트.
        meta: {
            "declared_encoding": str | None,  # XML 선언의 인코딩(소문자)
            "used_encoding":     str,          # 실제 사용된 인코딩
            "encoding_corrected": bool,        # 선언 ≠ 실제 → True
            "replace_fallback":   bool,        # strict 실패, replace 폴백
            "sanitized":         bool,         # cloud_xml.sanitize 적용 여부
        }
    """
    from judge_tool.parsers.cloud_xml import sanitize  # 지연 임포트(순환 방지)

    with open(path, "rb") as fh:
        raw = fh.read()

    declared = _declared_encoding(raw)
    used_enc, replace_fallback = _detect_encoding(raw)
    errors_mode = "replace" if replace_fallback else "strict"

    try:
        text = raw.decode(used_enc, errors=errors_mode)
    except (UnicodeDecodeError, LookupError):
        # 안전망: strict 판정이 맞았는데 decode 재호출 실패(거의 불가)
        text = raw.decode("utf-8", errors="replace")
        replace_fallback = True

    # 선언과 다른 경우 경고
    encoding_corrected = False
    if declared is not None:
        # utf-8-sig 는 선언에 "utf-8" 로 적히는 경우도 있으므로 normalise
        used_norm = "utf-8" if used_enc == "utf-8-sig" else used_enc
        if declared not in (used_norm, used_enc):
            encoding_corrected = True
            log.warning(
                "인코딩 교정: %s — declared=%s, used=%s",
                path, declared, used_enc)

    if replace_fallback:
        log.warning(
            "인코딩 폴백(replace): %s — strict 디코딩 모두 실패, "
            "판독 불가 바이트를 치환합니다.",
            path)

    # XML 선언 제거 (ET.fromstring이 encoding 선언 있는 유니코드 문자열을 거부)
    text = _XML_DECL.sub("", text, count=1)
    # well-formed 보정 (불법 제어문자, 단독 &)
    text = sanitize(text)

    meta = {
        "declared_encoding": declared,
        "used_encoding": used_enc,
        "encoding_corrected": encoding_corrected,
        "replace_fallback": replace_fallback,
        "sanitized": True,
    }
    return text, meta


# ---------------------------------------------------------------------------
# Step 2: LLM 점검 가능 상태 게이트
# ---------------------------------------------------------------------------

_GATE_SYSTEM = (
    "당신은 보안 점검 보고서 파일의 인코딩·데이터 손상 여부만 검사하는 도구다. "
    "판단 기준은 단 두 가지뿐이다:\n"
    "  NG 조건 ① — 문자 인코딩 깨짐(mojibake): 한글이 '??' 연속이거나 "
    "U+FFFD(\\uFFFD/\\xef\\xbf\\xbd) 이진 쓰레기가 텍스트 전반에 범람하는 경우.\n"
    "  NG 조건 ② — 전부 손상/빈 데이터: 텍스트가 거의 비어 있거나 판독 불가한 "
    "이진 쓰레기로만 이루어진 경우.\n"
    "이 두 조건에 해당하지 않으면 무조건 OK다. 특히:\n"
    "  - 보안 취약 내용(예: 패스워드 정책 미흡, 불필요 계정 존재 등)은 NG가 아니다 "
    "— 취약 결과도 정상적으로 판독 가능한 데이터다.\n"
    "  - 한글/영문이 정상 읽히면 내용이 '취약'이어도 OK다.\n"
    "  - 쉘 명령어·XML 태그·영문 명령 출력·flag:[X]/[O]·기술 용어(kubectl/grep/awk)는 "
    "정상이므로 깨짐으로 판단하지 말 것.\n"
    "출력: JSON만(설명·마크다운 금지):\n"
    '{"result": "OK" 또는 "NG", "reason": "한 줄 사유"}'
)


def _heuristic_gate(text: str) -> Tuple[str, str]:
    """LLM 없이 텍스트 품질을 간이 판별한다.

    반환: ("OK" | "NG", reason_str)
    기준:
      - replacement char(\\uFFFD) 비율 > 1% → NG
        (1%: 84,000자 파일에서 3% = 2520개 replacement char이면 심각한 mojibake.
         정상 파일은 0개이므로 오탐 위험 낮음. 이진 파일 혼입 등 극단적 경우 보수 처리.)
      - 불법 제어문자 비율 > 2% → NG
      - 텍스트 길이 < 50 → NG (사실상 빈 파일)
    """
    if not text or len(text) < 50:
        return "NG", "텍스트가 너무 짧거나 비어 있음"
    total = len(text)
    repl_count = len(_REPLACEMENT_CHAR.findall(text))
    ctrl_count = len(_ILLEGAL_CTRL.findall(text))
    repl_ratio = repl_count / total
    ctrl_ratio = ctrl_count / total
    if repl_ratio > 0.01:
        return "NG", f"replacement char 비율 {repl_ratio:.1%} > 1% — 인코딩 손상"
    if ctrl_ratio > 0.02:
        return "NG", f"불법 제어문자 비율 {ctrl_ratio:.1%} > 2% — 데이터 손상"
    return "OK", "휴리스틱 통과"


def _build_gate_sample(text: str, max_chars: int = _GATE_SAMPLE_CHARS) -> str:
    """LLM 게이트에 전달할 대표 샘플 텍스트를 구성한다.

    XML 파일의 경우 CDATA 내용(실제 점검 결과 텍스트)을 우선 추출한다.
    CDATA가 없거나 추출 결과가 너무 짧으면 원본 앞부분을 사용한다.
    XML 태그·CDATA 마커는 제거해 LLM이 실제 내용에 집중하게 한다.
    """
    # CDATA 블록 내용 추출 시도 (XML 보안 점검 결과의 실제 내용)
    cdata_matches = _CDATA_CONTENT.findall(text)
    if cdata_matches:
        extracted = "\n".join(m.strip() for m in cdata_matches if m.strip())
        if len(extracted) >= 100:
            return extracted[:max_chars]
    # 폴백: 원본 앞부분
    return text[:max_chars]


def run_llm_gate(text: str, meta: Dict, client, path: str) -> None:
    """LLM 게이트를 실행한다. NG이면 PreflightError를 발생시킨다.

    결정 행렬 (사용자 계약):
      - LLM 호출 성공: LLM 판정이 최종 결정권자.
          LLM OK -> 통과.  LLM NG -> PreflightError(중단).
          휴리스틱 참조 안 함.
      - LLM 호출 실패/미가동(예외) 또는 client=None:
          휴리스틱 폴백(OK/NG). 로그에 "heuristic(fallback)" 명시.

    meta에 "gate_decided_by": "llm" | "heuristic(fallback)" 기록.
    """
    # 대표 샘플: CDATA 내용 우선 추출(XML 점검 결과의 실제 텍스트)
    sample = _build_gate_sample(text)

    result = "OK"
    reason = ""
    gate_decided_by = "heuristic(fallback)"

    if client is not None:
        try:
            raw_resp = client.chat(_GATE_SYSTEM, f"점검 텍스트:\n{sample}")
            # 응답 파싱: JSON 추출
            import json as _json
            s = raw_resp.strip()
            s = re.sub(r"^```(?:json)?", "", s).strip()
            s = re.sub(r"```$", "", s).strip()
            start, end = s.find("{"), s.rfind("}")
            if start != -1 and end != -1:
                s = s[start:end + 1]
            parsed = _json.loads(s)
            result = (parsed.get("result") or "OK").strip().upper()
            reason = parsed.get("reason") or ""
            gate_decided_by = "llm"
            log.info(
                "게이트 결정권자: llm — %s — %s (%s)",
                result, reason, path)
        except Exception as e:  # noqa: BLE001
            log.warning(
                "LLM 게이트 호출 실패(%s) -> 휴리스틱 폴백(heuristic fallback): %s",
                type(e).__name__, path)

    if gate_decided_by == "heuristic(fallback)":
        # LLM 불가/미가동 시에만 휴리스틱을 사용한다
        result, reason = _heuristic_gate(text)
        log.info(
            "게이트 결정권자: heuristic(fallback) — %s — %s (%s)",
            result, reason, path)

    # meta에 결정권자 기록 (호출부에서 dict 참조 가능)
    meta["gate_decided_by"] = gate_decided_by

    if result == "NG":
        raise PreflightError(
            f"[Pre-flight NG] {path}: {reason}. "
            "입력 파일이 판독 불가 또는 손상된 상태입니다. "
            "파일 인코딩/수집 상태를 확인하세요. "
            "--skip-preflight 플래그로 게이트를 우회할 수 있습니다(테스트/오프라인용).")


def run_preflight(path: str, client, skip: bool = False) -> Tuple[str, Dict]:
    """인코딩 교정 후 LLM 게이트를 실행하는 통합 진입점.

    Args:
        path: 보고서 파일 경로.
        client: OllamaClient 인스턴스 (None이면 휴리스틱 폴백).
        skip: True이면 LLM 게이트를 건너뜀(--skip-preflight).

    Returns:
        (corrected_text, meta): 교정된 텍스트와 메타데이터.

    Raises:
        PreflightError: 게이트 NG 시.
        OSError: 파일 읽기 실패 시.
    """
    text, meta = read_text(path)

    if not skip:
        run_llm_gate(text, meta, client, path)
    else:
        log.info("pre-flight 게이트 건너뜀(--skip-preflight): %s", path)

    return text, meta

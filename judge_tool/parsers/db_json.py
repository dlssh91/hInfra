import json
import re
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence

# 민감 키(해시/비번류)
_PASS_KEY = re.compile(
    r"(pass|pwd|pswd|pword|\bpw\b|auth\w*string|hash|secret|credential|token|api[_-]?key)",
    re.I)
# MySQL 해시류 값 패턴: $A$..., *HEX, 긴 hex
_HASH_VAL = re.compile(r"^\*?[0-9A-Fa-f]{16,}$|^\$[A-Za-z0-9]")
# JSON 문자열을 깨뜨리는 raw 제어문자(탭/개행 제외)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _mask_value(key: str, val: str) -> str:
    if _PASS_KEY.search(key) or _HASH_VAL.match(val.strip()):
        return f"<REDACTED len={len(val)}>"
    return val


def _mask_row(row: Dict) -> Dict:
    """행 dict에서 민감값 마스킹. 길이는 노출(존재 인지), 구조 키는 보존.

    - 키가 비번/해시류이거나 값이 해시패턴이면 마스킹.
    - COLUMN_NAME이 비번류인 행(DBM-005)의 RESULT 값(평문)도 마스킹.
    """
    col = str(row.get("COLUMN_NAME", "")).lower()
    pass_col = bool(_PASS_KEY.search(col))
    out = {}
    for k, v in row.items():
        if isinstance(v, dict):
            out[k] = _mask_row(v)
        elif isinstance(v, list):
            out[k] = [_mask_row(x) if isinstance(x, dict)
                      else (f"<REDACTED len={len(x)}>"
                            if isinstance(x, str) and x and _HASH_VAL.match(x.strip())
                            else x)
                      for x in v]
        elif isinstance(v, str) and v:
            if _PASS_KEY.search(k) or _HASH_VAL.match(v.strip()):
                out[k] = _mask_value(k, v)
            elif pass_col and k.upper() == "RESULT":
                out[k] = f"<REDACTED 평문추정 len={len(v)}>"
            else:
                out[k] = v
        else:
            out[k] = v
    return out


def _strip_leading_noise(text: str) -> str:
    i = text.find("[")
    if i == -1:
        raise ReportError("DB 결과 파싱 실패: 최상위 배열('[')을 찾을 수 없습니다.")
    return text[i:]


def _iter_top_objects(arr_text: str):
    """최상위 배열 텍스트에서 {...} 객체를 brace-match로 순서대로 yield.
    콤마 누락/트레일링콤마와 무관하게 중괄호 균형만으로 분리한다."""
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(arr_text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                yield arr_text[start:i + 1]
                start = None


def _sanitize_scalar(s: str) -> str:
    return _CTRL.sub("", s)


def _json_safe(s: str) -> str:
    r"""행 텍스트를 json.loads 가능하게 중화.

    제어문자 제거 + JSON에서 유효하지 않은 백슬래시 이스케이프 제거
    (\" \\ \/ \b \f \n \r \t \uXXXX 만 허용)."""
    s = _CTRL.sub("", s)
    s = re.sub(r'\\(?!["\\/bfnrtu])', "", s)
    return s


def _mask_raw_text(s: str) -> str:
    """파싱 불가 raw 텍스트에서 해시/평문 민감값을 정규식으로 마스킹.

    폴백 경로 전용 방어심화: 해시/평문이 절대 raw로 남지 않게 한다."""
    # 해시류 토큰: $A$..., 긴 hex(16+), *HEX
    s = re.sub(r'\$[A-Za-z0-9][^"\s,}]*', "<REDACTED>", s)
    s = re.sub(r'\*?[0-9A-Fa-f]{16,}', "<REDACTED>", s)
    # 민감 키의 값 마스킹: "...PASS...": "값"
    s = re.sub(
        r'("(?:[^"]*(?:pass|pwd|pswd|auth\w*string|hash|secret|credential|token)'
        r'[^"]*)"\s*:\s*)"[^"]*"',
        r'\1"<REDACTED>"', s, flags=re.I)
    return s


def _extract_check_id(obj_text: str) -> Optional[str]:
    m = re.search(r'"\s*(DBM-[\w]+)\s*"\s*:', obj_text)
    return m.group(1) if m else None


def _extract_query(inner: str) -> str:
    m = re.search(r'"QUERY"\s*:\s*"(.*?)"\s*,\s*"RESULT"', inner, re.S)
    if not m:
        m = re.search(r'"QUERY"\s*:\s*"(.*?)"', inner, re.S)
    return _sanitize_scalar(m.group(1)) if m else ""


def _extract_note(inner: str) -> str:
    m = re.search(r'"NOTE"\s*:\s*"(.*?)"', inner, re.S)
    return _sanitize_scalar(m.group(1)) if m else ""


def _extract_result_block(inner: str) -> str:
    """`"RESULT": [ ... ]` 의 대괄호 내부 텍스트 반환(없으면 "")."""
    m = re.search(r'"RESULT"\s*:\s*\[', inner)
    if not m:
        return ""
    i = m.end() - 1  # '[' 위치
    depth = 0
    in_str = False
    esc = False
    for j in range(i, len(inner)):
        ch = inner[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return inner[i + 1:j]
    return inner[i + 1:]


def _parse_rows(result_block: str) -> List[ResourceEvidence]:
    """RESULT 내부에서 행 dict와 bare 문자열을 추출.
    각 dict는 sanitize 후 개별 json.loads(실패 시 raw 문자열로 보존), 마스킹."""
    rows: List[ResourceEvidence] = []
    # 1) 행 객체 {...}
    idx = 0
    for obj in _iter_top_objects(result_block):
        san = _json_safe(obj)
        san = re.sub(r",\s*([}\]])", r"\1", san)  # 트레일링콤마 제거
        try:
            d = json.loads(san)
            if isinstance(d, dict):
                masked = _mask_row(d)
                rows.append(ResourceEvidence(
                    resource_id=f"row{idx}", status="", detail="",
                    evidence=json.dumps(masked, ensure_ascii=False)))
                idx += 1
                continue
        except json.JSONDecodeError:
            pass
        # 파싱 실패 dict → raw 보존하되 반드시 마스킹(해시/평문 누출 방지)
        rows.append(ResourceEvidence(
            resource_id=f"row{idx}", status="", detail="(파싱불가 행)",
            evidence=_mask_raw_text(_json_safe(obj))[:500]))
        idx += 1
    # 2) bare 문자열 행(객체 밖의 "....") — 객체를 제거한 잔여에서 추출
    residue = re.sub(r"\{.*?\}", "", result_block, flags=re.S)
    for sm in re.finditer(r'"([^"]{3,})"', residue):
        val = _sanitize_scalar(sm.group(1))
        if val and val.upper() != "NOTE":
            rows.append(ResourceEvidence(
                resource_id=f"note{idx}", status="", detail=val, evidence=val))
            idx += 1
    return rows


def parse(txt_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """DB 결과 .txt → [(check_id, [ResourceEvidence], context), ...]."""
    try:
        with open(txt_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        arr = _strip_leading_noise(raw)
        out = []
        for obj_text in _iter_top_objects(arr):
            cid = _extract_check_id(obj_text)
            if not cid:
                continue
            # inner = check_id 값(중첩 객체) 본문. 가장 바깥 {} 내부 사용.
            inner = obj_text
            query = _extract_query(inner)
            note = _extract_note(inner)
            result_block = _extract_result_block(inner)
            resources = _parse_rows(result_block) if result_block.strip() or '"RESULT"' in inner else []
            ctx_parts = []
            if query:
                ctx_parts.append(f"QUERY: {query}")
            if note:
                ctx_parts.append(f"NOTE: {note}")
            context = "\n".join(ctx_parts) if ctx_parts else None
            out.append((cid, resources, context))
        if not out:
            raise ReportError("DB 결과 파싱 실패: 유효한 DBM 항목이 없습니다.")
        return out
    except ReportError:
        raise
    except Exception as e:  # noqa: BLE001 - 손상 파일을 명확한 ReportError로 변환
        raise ReportError(
            f"DB 결과 파싱 실패: {txt_path} ({type(e).__name__}). "
            "결과 파일이 손상되었을 수 있습니다.") from e

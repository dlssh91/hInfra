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


def _sanitize_scalar(s: str) -> str:
    return _CTRL.sub("", s)


def _json_safe(s: str) -> str:
    r"""행 텍스트를 json.loads 가능하게 중화.

    raw 탭(0x09)/개행(0x0a,0x0d)을 \\t/\\n 으로 이스케이프(문자열 값 안의
    raw 제어문자가 json.loads 를 깨뜨리는 것을 방지: rds DBM-001 해시 3행),
    그 외 제어문자 제거 + JSON에서 유효하지 않은 백슬래시 이스케이프 제거
    (\" \\ \/ \b \f \n \r \t \uXXXX 만 허용)."""
    s = s.replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")
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


def _iter_top_result_items(arr_text: str):
    """RESULT 대괄호 내부 텍스트를 brace-aware 단일 패스로 순회하며
    ("obj", 객체텍스트) 또는 ("bare", 문자열값) 을 등장 순서대로 yield.

    depth==0 의 따옴표 문자열은 bare 행, {...} 객체는 행 객체로 수집한다.
    정규식 residue 방식을 폐기해 값에 '}' 가 있어도 유령 추출이 없다."""
    depth = 0
    start = None       # 현재 객체 시작 위치(depth 0→1 진입점)
    str_start = None    # 현재 top-level bare 문자열 시작(여는 따옴표 다음)
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
                if str_start is not None:
                    # depth 0 에서 닫힌 bare 문자열
                    yield ("bare", arr_text[str_start:i])
                    str_start = None
            continue
        if ch == '"':
            in_str = True
            if depth == 0:
                str_start = i + 1
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    yield ("obj", arr_text[start:i + 1])
                    start = None


# 최상위 항목 시작 마커: {"DBM-xxx": ...
_ITEM_START = re.compile(r'\{\s*"(DBM-[\w]+)"\s*:')


def _split_items(arr_text: str):
    """최상위 배열 텍스트를 항목 시작 마커로 경계 분할.

    brace-balance 대신 각 항목 시작부터 다음 시작 직전까지를 한 세그먼트로
    잘라 yield 한다. 한 항목의 중괄호가 손상돼도(예: outer 미닫힘) 다음
    항목 경계에서 복원되어 desync 가 번지지 않는다. 중복키도 각각 잡힌다."""
    starts = [(m.start(), m.group(1)) for m in _ITEM_START.finditer(arr_text)]
    for i, (s, cid) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(arr_text)
        yield cid, arr_text[s:end]


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


def _parse_rows(result_block: str, check_id: str) -> List[ResourceEvidence]:
    """RESULT 내부에서 행 dict와 bare 문자열을 brace-aware 단일 패스로 추출.

    각 dict는 sanitize 후 개별 json.loads(실패 시 raw 문자열로 보존), 마스킹.
    resource_id 는 spec §6.1 대로 f'{check_id}#row{i}'(bare/note 는 #note{i}).
    값에 '}' 가 있어도 유령 행이 생기지 않도록 정규식 residue 방식을 폐기한다."""
    rows: List[ResourceEvidence] = []
    idx = 0
    # 실데이터(DBM-011·DBM-013)는 NOTE가 RESULT 배열 안에 콤마 누락 상태로 들어와
    # bare 문자열 추출 시 phantom 증거 행이 된다. NOTE는 이미 _extract_note 가
    # context 로 가져가므로, 행 추출 전에 stray NOTE 키:값과 단독 토큰을 제거한다.
    # (NOTE 값에 '"' 가 포함되지 않음 — 실데이터 확인.)
    result_block = re.sub(r'"NOTE"\s*:\s*"[^"]*"', "", result_block)
    result_block = re.sub(r'"NOTE"\s*', "", result_block)
    for kind, text in _iter_top_result_items(result_block):
        if kind == "obj":
            san = _json_safe(text)
            san = re.sub(r",\s*([}\]])", r"\1", san)  # 트레일링콤마 제거
            try:
                d = json.loads(san)
                if isinstance(d, dict):
                    masked = _mask_row(d)
                    rows.append(ResourceEvidence(
                        resource_id=f"{check_id}#row{idx}", status="", detail="",
                        evidence=json.dumps(masked, ensure_ascii=False)))
                    idx += 1
                    continue
            except json.JSONDecodeError:
                pass
            # 파싱 실패 dict → raw 보존하되 반드시 마스킹(해시/평문 누출 방지)
            rows.append(ResourceEvidence(
                resource_id=f"{check_id}#row{idx}", status="",
                detail="(파싱불가 행)",
                evidence=_mask_raw_text(_json_safe(text))[:500]))
            idx += 1
        else:  # bare 문자열 행
            val = _sanitize_scalar(text)
            if len(val) >= 3 and val.upper() != "NOTE":
                val = _mask_raw_text(val)
                rows.append(ResourceEvidence(
                    resource_id=f"{check_id}#note{idx}", status="",
                    detail=val, evidence=val))
                idx += 1
    return rows


def parse(txt_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """DB 결과 .txt → [(check_id, [ResourceEvidence], context), ...]."""
    try:
        with open(txt_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        arr = _strip_leading_noise(raw)
        out = []
        # 최상위 항목을 brace-balance 가 아니라 항목 시작 마커로 경계 분할한다.
        # 한 항목이 손상(예: outer 미닫힘)돼도 다음 항목 경계에서 복원되어
        # 무음 손실(desync)이 번지지 않는다.
        for cid, segment in _split_items(arr):
            # inner = 항목 세그먼트(시작 마커부터 다음 항목 직전까지).
            inner = segment
            query = _extract_query(inner)
            note = _extract_note(inner)
            result_block = _extract_result_block(inner)
            resources = _parse_rows(result_block, cid) if result_block.strip() or '"RESULT"' in inner else []
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

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

import re
import xml.etree.ElementTree as ET
from typing import List, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence

# 유효한 엔티티(&amp; &lt; &#39; 등)가 아닌 단독 '&'를 escape
_BARE_AMP = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)")
# CDATA 구간 (내부 '&'는 이미 유효한 리터럴이므로 건드리지 않음)
_CDATA = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
# XML 1.0 불법 C0 제어문자(tab #x09·LF #x0a·CR #x0d 제외). CDATA 안에서도 불법이라
# ElementTree(expat)가 거부한다. 실수집 명령출력의 ANSI escape(\x1b[..m) 등이
# CDATA로 섞여 들어오는 경우를 보정한다(제거). 증거 의미 없는 터미널 제어용 바이트.
_XML_ILLEGAL_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize(raw: str) -> str:
    """well-formed가 아닌 XML을 보정한다.
    1) XML 1.0 불법 제어문자(ANSI escape 등) 제거 — CDATA 포함 전체 선적용.
    2) 스크립트가 이스케이프하지 않은 단독 '&'를 escape (CDATA 내부는 그대로)."""
    # 1) 불법 제어문자는 CDATA 안에서도 금지 → 전체 텍스트에 먼저 적용
    raw = _XML_ILLEGAL_CTRL.sub("", raw)
    # 2) CDATA 밖 단독 '&'만 escape
    parts = []
    last = 0
    for m in _CDATA.finditer(raw):
        parts.append(_BARE_AMP.sub("&amp;", raw[last:m.start()]))
        parts.append(m.group(0))            # CDATA 구간은 원본 유지
        last = m.end()
    parts.append(_BARE_AMP.sub("&amp;", raw[last:]))
    return "".join(parts)


def _text(el, tag) -> str:
    v = el.findtext(tag)
    return "" if v is None else v


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence]]]:
    """XML → [(check_id, [ResourceEvidence, ...]), ...]. CheckResult 순서 유지."""
    with open(xml_path, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        root = ET.fromstring(sanitize(raw))
    except ET.ParseError as e:
        # XML 본문/민감 evidence는 메시지에 싣지 않는다(경로·파서 위치 요약만).
        raise ReportError(
            f"XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그)."
        ) from e

    result: List[Tuple[str, List[ResourceEvidence]]] = []
    for cr in root.findall(".//CheckResult"):
        check_id = (cr.findtext("CheckID") or "").strip()
        resources = [
            ResourceEvidence(
                resource_id=_text(item, "ResourceID").strip(),
                status=(item.get("status") or "").strip().lower(),
                detail=_text(item, "Detail").strip(),
                evidence=_text(item, "Evidence").strip(),
            )
            for item in cr.findall(".//Item")
        ]
        result.append((check_id, resources))
    return result

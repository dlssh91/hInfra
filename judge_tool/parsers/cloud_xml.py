import re
import xml.etree.ElementTree as ET
from typing import List, Tuple

from judge_tool.models import ResourceEvidence

# 유효한 엔티티(&amp; &lt; &#39; 등)가 아닌 단독 '&'를 escape
_BARE_AMP = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)")


def sanitize(raw: str) -> str:
    """스크립트가 이스케이프하지 않은 '&'로 인해 well-formed가 아닌 XML을 보정."""
    return _BARE_AMP.sub("&amp;", raw)


def _text(el, tag) -> str:
    v = el.findtext(tag)
    return "" if v is None else v


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence]]]:
    """XML → [(check_id, [ResourceEvidence, ...]), ...]. CheckResult 순서 유지."""
    with open(xml_path, encoding="utf-8") as fh:
        root = ET.fromstring(sanitize(fh.read()))

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

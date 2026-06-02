from typing import Dict, List, Optional, Tuple

from judge_tool.models import EvidenceItem, ResourceEvidence
from judge_tool.profile import Profile


def aggregate(raw_checks, variant: str,
              profile: Profile) -> Dict[str, EvidenceItem]:
    """원본 CheckID를 base id로 정규화하며 분할항목을 한 EvidenceItem으로 병합.

    raw_checks 원소는 (check_id, resources) 또는 (check_id, resources, context).
    context(QUERY/NOTE 등)는 base별로 합친다(중복 제거, 순서 보존).
    """
    items: Dict[str, EvidenceItem] = {}
    for entry in raw_checks:
        check_id, resources = entry[0], entry[1]
        context = entry[2] if len(entry) > 2 else None
        base = profile.normalize_id(check_id)
        if base not in items:
            items[base] = EvidenceItem(item_id=base, variant=variant,
                                       resources=[])
        items[base].resources.extend(resources)
        if context:
            cur = items[base].context
            if cur is None:
                items[base].context = context
            elif context not in cur:
                items[base].context = f"{cur}\n{context}"
    return items

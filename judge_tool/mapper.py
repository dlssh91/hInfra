from typing import Dict, List, Tuple

from judge_tool.models import EvidenceItem, ResourceEvidence
from judge_tool.profile import Profile


def aggregate(raw_checks: List[Tuple[str, List[ResourceEvidence]]],
              variant: str,
              profile: Profile) -> Dict[str, EvidenceItem]:
    """원본 CheckID를 base id로 정규화하며 분할항목을 한 EvidenceItem으로 병합."""
    items: Dict[str, EvidenceItem] = {}
    for check_id, resources in raw_checks:
        base = profile.normalize_id(check_id)
        if base not in items:
            items[base] = EvidenceItem(item_id=base, variant=variant, resources=[])
        items[base].resources.extend(resources)
    return items

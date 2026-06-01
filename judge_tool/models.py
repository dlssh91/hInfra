from dataclasses import dataclass, field
from typing import List, Optional

# overall_status 우선순위 (앞일수록 우선)
_STATUS_PRIORITY = ["bad", "review", "error", "good", "info"]


@dataclass
class Criterion:
    item_id: str          # "PISM-001"
    item_name: str
    risk: Optional[float]
    variant: str          # "AWS"
    eval_type: str        # "스크립트" | "관리체계, 스크립트" | "N/A" ...
    standard: str         # 판단기준 텍스트
    method: str           # 판단방법 텍스트

    @property
    def is_mixed(self) -> bool:
        return "관리체계" in self.eval_type and "스크립트" in self.eval_type

    @property
    def is_script_based(self) -> bool:
        return "스크립트" in self.eval_type

    @property
    def is_judgeable(self) -> bool:
        """LLM 판정 대상 여부: 스크립트 기반이며 eval_type 이 N/A 가 아니고
        판단기준(standard)이 비어 있지 않아야 한다.

        main.run 의 스킵 조건과 writer.build_coverage 의 expected 조건이
        공유하는 술어. 두 곳의 일관성을 보장하기 위해 한 곳에 둔다.
        """
        return (self.is_script_based and self.eval_type != "N/A"
                and bool((self.standard or "").strip()))


@dataclass
class ResourceEvidence:
    resource_id: str
    status: str           # good | bad | info | error | review
    detail: str
    evidence: str


@dataclass
class EvidenceItem:
    item_id: str          # 정규화된 base id "PISM-045"
    variant: str
    resources: List[ResourceEvidence] = field(default_factory=list)

    @property
    def overall_status(self) -> str:
        statuses = {r.status.lower() for r in self.resources}
        for s in _STATUS_PRIORITY:
            if s in statuses:
                return s
        return "info"


@dataclass
class Judgment:
    item_id: str
    item_name: str
    variant: str
    risk: Optional[float]
    verdict: str          # 양호 | 취약 | 판단보류
    confidence: float
    rationale: str
    cited_evidence: List[str]
    scope: str            # "스크립트 전체" | "스크립트 부분만"
    management_review_needed: bool
    script_status: Optional[str]
    agreement: str        # 일치 | 불일치 | N/A
    needs_review: bool

import json
import re
from typing import Dict, List

import requests

from judge_tool.models import Criterion, EvidenceItem, Judgment

SYSTEM_PROMPT = (
    "당신은 전자금융기반시설 클라우드 보안 취약점 평가자다. "
    "주어진 '판단기준'과 '점검 증거'만 근거로 해당 항목의 취약 여부를 판정한다. "
    "추측하지 말고 증거에 없는 사실을 지어내지 않는다. "
    "증거가 판단기준을 충족하면 '양호', 위배되면 '취약', "
    "근거가 부족하거나 관리체계(문서·인터뷰) 확인이 필요한 부분이면 '판단보류'로 판정한다. "
    "반드시 아래 키를 가진 JSON 하나만 출력한다(설명·마크다운 금지):\n"
    '{"verdict": "양호|취약|판단보류", "confidence": 0.0~1.0, '
    '"rationale": "한국어 근거 2~4문장", '
    '"cited_evidence": ["인용한 리소스ID 또는 핵심 증거 문자열", ...]}'
)

_GOOD = {"good", "info"}


def build_evidence_text(item: EvidenceItem, max_chars: int = 8000) -> str:
    """증거를 텍스트로 직렬화. 취약 후보(good/info 외)는 전량 보존, good/info만 축약."""
    def fmt(r):
        return (f"- [{r.status}] {r.resource_id} :: {r.detail}\n"
                f"  evidence: {r.evidence}")

    primary = [r for r in item.resources if r.status.lower() not in _GOOD]
    secondary = [r for r in item.resources if r.status.lower() in _GOOD]

    lines = [fmt(r) for r in primary]
    used = sum(len(l) for l in lines)
    shown_secondary = 0
    for r in secondary:
        block = fmt(r)
        if used + len(block) > max_chars:
            break
        lines.append(block)
        used += len(block)
        shown_secondary += 1

    omitted = len(secondary) - shown_secondary
    if omitted > 0:
        lines.append(f"... (양호/정보 리소스 {omitted}건 축약·생략됨)")
    if not item.resources:
        return "(증거 없음)"
    return "\n".join(lines)


def build_prompt(criterion: Criterion, item: EvidenceItem,
                 max_chars: int = 8000) -> str:
    scope_note = ""
    if criterion.is_mixed:
        scope_note = (
            "\n[중요] 이 항목은 '관리체계+스크립트' 혼합이다. "
            "판단기준 중 기술/스크립트로 확인 가능한 부분만 대조해 판정하고, "
            "관리체계(문서·정책·인터뷰) 영역은 판정 근거로 삼지 말 것.")
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name} "
        f"(위험도 {criterion.risk})\n"
        f"변형: {criterion.variant}\n"
        f"--- 판단기준 ---\n{criterion.standard}\n"
        f"--- 판단방법 ---\n{criterion.method}\n"
        f"{scope_note}\n"
        f"--- 점검 증거 ---\n{build_evidence_text(item, max_chars)}\n"
        f"--- 위 판단기준에 따라 JSON으로 판정하라. ---"
    )


def parse_json_lenient(text: str) -> Dict:
    """코드펜스/후행콤마/백틱을 허용하는 관대한 JSON 파서."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end != -1:
        t = t[start:end + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        t2 = re.sub(r",\s*([}\]])", r"\1", t)  # 후행 콤마 제거
        t2 = t2.replace("`", '"')              # 백틱 → 따옴표
        return json.loads(t2)

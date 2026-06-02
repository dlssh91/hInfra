import json
import re
from typing import Dict

import requests

from judge_tool.models import (
    Criterion, EvidenceItem, Judgment, GOOD_STATUSES)

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

# status 분류는 models.GOOD_STATUSES 를 단일 출처로 사용한다.
_GOOD = GOOD_STATUSES


def build_evidence_text(item: EvidenceItem, max_chars: int = 8000) -> str:
    """증거를 텍스트로 직렬화.

    증거가드 핵심계약: primary(취약 후보 = status가 good/info가 아닌 리소스)는
    max_chars를 **의도적으로 무시하고 전량 보존**한다. 상한(max_chars)은
    good/info(보조 증거)에만 적용되어 상한 내에서만 추가되고 나머지는 축약·생략된다.
    리소스가 하나도 없으면 "(증거 없음)"을 반환한다.
    """
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


def build_evidence_text_raw(item: EvidenceItem, max_chars: int = 24000) -> str:
    """원시증거(DB) 직렬화: 사전분류 status가 없으므로 전수 보존이 기본.

    context(QUERY/NOTE)를 상단에 두고 모든 행을 직렬화한다. 행이 한 그룹키로
    반복되는 결과(예: GRANTEE)는 그룹별 요약을 병기한다. 총량이 max_chars를
    넘으면 행을 잘라 "M행 중 N행 표시, K행 생략"을 명시한다.
    """
    head = (item.context + "\n") if item.context else ""
    if not item.resources:
        return head + "(점검 결과 0건)"
    lines = [r.evidence if r.evidence else r.detail for r in item.resources]
    summary = _group_summary(item.resources)
    body_head = head + (summary + "\n" if summary else "")
    total = len(lines)
    shown, used = [], len(body_head)
    for ln in lines:
        if used + len(ln) + 1 > max_chars:
            break
        shown.append(ln)
        used += len(ln) + 1
    out = body_head + "\n".join(shown)
    if len(shown) < total:
        out += f"\n... ({total}행 중 {len(shown)}행 표시, {total - len(shown)}행 생략)"
    return out


def _group_summary(resources) -> str:
    """행들이 'GRANTEE' 같은 그룹키 + 값(PRIVILEGE_TYPE)을 가지면 그룹별
    값 집합 요약을 만든다. 해당 구조가 아니면 빈 문자열."""
    groups = {}
    for r in resources:
        try:
            d = json.loads(r.evidence)
        except Exception:  # noqa: BLE001
            return ""
        if not isinstance(d, dict) or "GRANTEE" not in d:
            return ""
        groups.setdefault(d.get("GRANTEE", ""), set()).add(
            d.get("PRIVILEGE_TYPE", ""))
    if not groups:
        return ""
    parts = ["[요약] 계정별 권한집합:"]
    for k, vs in groups.items():
        vlist = sorted(v for v in vs if v)
        shown = ", ".join(vlist[:12])
        if len(vlist) > 12:
            shown += f" ...(+{len(vlist) - 12})"
        line = f"  {k}: [{len(vlist)}]"
        parts.append(f"{line} {shown}" if shown else line)
    return "\n".join(parts)


def build_prompt(criterion: Criterion, item: EvidenceItem,
                 max_chars: int = 8000,
                 evidence_mode: str = "preclassified") -> str:
    scope_note = ""
    if criterion.is_mixed:
        scope_note = (
            "\n[중요] 이 항목은 '관리체계+스크립트' 혼합이다. "
            "판단기준 중 기술/스크립트로 확인 가능한 부분만 대조해 판정하고, "
            "관리체계(문서·정책·인터뷰) 영역은 판정 근거로 삼지 말 것.")
    if evidence_mode == "raw":
        evidence = build_evidence_text_raw(item, max(max_chars, 24000))
    else:
        evidence = build_evidence_text(item, max_chars)
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name} "
        f"(위험도 {criterion.risk})\n"
        f"변형: {criterion.variant}\n"
        f"--- 판단기준 ---\n{criterion.standard}\n"
        f"--- 판단방법 ---\n{criterion.method}\n"
        f"{scope_note}\n"
        f"--- 점검 증거 ---\n{evidence}\n"
        f"--- 위 판단기준에 따라 JSON으로 판정하라. ---"
    )


def parse_json_lenient(text: str) -> Dict:
    """코드펜스/후행콤마/백틱을 허용하는 관대한 JSON 파서.

    복구는 단계적으로 시도한다:
      0) 원문 그대로 파싱.
      1) 후행 콤마만 제거하고 재시도(백틱은 그대로 보존 — 흔한 경우인
         '백틱 인용 + 후행콤마'를 evidence 손상 없이 복구).
      2) 그래도 실패하면 백틱→따옴표 치환까지 적용해 마지막 재시도
         (백틱이 키 구분자로 잘못 쓰인 비정상 출력 대비).

    모든 복구 시도가 실패하면 마지막 단계의 ``json.JSONDecodeError``를
    그대로 raise 한다. 호출부(Task 7)가 이를 잡아 처리할 책임을 진다.
    """
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end != -1:
        t = t[start:end + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    # 1단계: 후행 콤마만 제거 (백틱 보존)
    t1 = re.sub(r",\s*([}\]])", r"\1", t)
    try:
        return json.loads(t1)
    except json.JSONDecodeError:
        pass
    # 2단계: 백틱 → 따옴표 치환까지 적용한 마지막 재시도
    t2 = t1.replace("`", '"')
    return json.loads(t2)


def _to_float(v, default: float = 0.0) -> float:
    """안전 float 캐스팅. 변환 불가 시 default 반환."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


_VALID_VERDICTS = {"양호", "취약", "판단보류"}
# 스크립트 status → 기대 verdict (비교 가능한 것만)
_STATUS_TO_VERDICT = {"good": "양호", "bad": "취약"}
_LOW_CONFIDENCE = 0.6


class OllamaClient:
    def __init__(self, url: str = "http://localhost:11434",
                 model: str = "qwen2.5:14b", temperature: float = 0.0,
                 timeout: int = 120):
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    def chat(self, system: str, user: str) -> str:
        resp = requests.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": self.temperature},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


def judge_item(criterion: Criterion, item: EvidenceItem, client,
               max_chars: int = 8000, retries: int = 2,
               evidence_mode: str = "preclassified") -> Dict:
    """LLM 호출 후 검증된 판정 dict 반환. JSON 실패 시 재시도.

    JSON 파싱 실패만 재시도하며, 네트워크/HTTP 예외(requests 예외) 및
    응답 구조 오류는 호출부(Task 9) 책임으로 전파한다.
    """
    prompt = build_prompt(criterion, item, max_chars, evidence_mode)
    last_err = None
    for _ in range(retries + 1):
        raw = client.chat(SYSTEM_PROMPT, prompt)
        try:
            data = parse_json_lenient(raw)
        except json.JSONDecodeError as e:
            last_err = e
            continue
        # 유효 JSON이지만 객체(dict)가 아닌 경우(예: ["양호"], 스칼라):
        # data.get(...) 이 AttributeError 를 던지므로 가드 후 재시도.
        if not isinstance(data, dict):
            last_err = ValueError("JSON 객체 아님")
            continue
        if data.get("verdict") in _VALID_VERDICTS:
            data["confidence"] = _to_float(data.get("confidence", 0.0))
            data.setdefault("rationale", "")
            data.setdefault("cited_evidence", [])
            return data
        last_err = ValueError(f"잘못된 verdict: {data.get('verdict')}")
    # 모든 시도 실패 → 판단보류로 안전 처리.
    # 보안: 예외 본문에는 LLM 응답 원문(evidence 반향 가능)이 섞일 수 있으므로
    # 예외 타입명/고정문구만 노출하고 raw 응답은 rationale 에 넣지 않는다.
    err_name = type(last_err).__name__ if last_err is not None else "Unknown"
    return {"verdict": "판단보류", "confidence": 0.0,
            "rationale": f"LLM 응답 파싱 실패({err_name})", "cited_evidence": []}


def reconcile(llm: Dict, criterion: Criterion, item: EvidenceItem, *,
              status_available: bool = True,
              flag_vulnerable_for_review: bool = False,
              empty_means_good: bool = False) -> Judgment:
    if status_available:
        script_status = item.overall_status
        expected = _STATUS_TO_VERDICT.get(script_status)
    else:
        script_status = None
        expected = None
    verdict = llm.get("verdict", "판단보류")
    confidence = _to_float(llm.get("confidence", 0.0))
    rationale = llm.get("rationale", "")

    if expected is None:
        agreement = "N/A"
    else:
        agreement = "일치" if verdict == expected else "불일치"

    # spec 6.7: script_status 가 "error" 이거나 증거가 전혀 없으면 신뢰할 수
    # 없으므로 LLM verdict 와 무관하게 판단보류로 강제하고 검토 대상으로 표시.
    # 단 empty_means_good(위반 0건=양호 후보)면 무증거 강제 보류에서 제외.
    # cited_evidence 는 보존한다.
    no_evidence = (not item.resources) and not empty_means_good
    if (script_status == "error" or no_evidence) and verdict != "판단보류":
        verdict = "판단보류"
        reason = "증거 없음" if no_evidence else "스크립트 점검 오류(error)"
        note = f"[자동 판단보류: {reason}]"
        rationale = f"{rationale} {note}".strip()

    needs_review = (
        agreement == "불일치"
        or confidence < _LOW_CONFIDENCE
        or criterion.is_mixed
        or verdict == "판단보류"
        # script_status 가 good/bad 로 매핑되지 않으면(미지/review/error 등)
        # 양호/취약 자동 대조가 불가하므로 사람 검토가 필요하다.
        or expected is None
        or (flag_vulnerable_for_review and verdict == "취약")
    )
    return Judgment(
        item_id=criterion.item_id,
        item_name=criterion.item_name,
        variant=criterion.variant,
        risk=criterion.risk,
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        cited_evidence=list(llm.get("cited_evidence", [])),
        scope="스크립트 부분만" if criterion.is_mixed else "스크립트 전체",
        management_review_needed=criterion.is_mixed,
        script_status=script_status,
        agreement=agreement,
        needs_review=needs_review,
    )

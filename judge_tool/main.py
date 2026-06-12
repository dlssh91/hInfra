import argparse
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

import json as _json

from judge_tool import __version__
from judge_tool.criteria_loader import load_criteria
from judge_tool.errors import ReportError
from judge_tool.judge import OllamaClient, judge_item, reconcile, summarize_item
from judge_tool.eol import judge_eol, judge_patch
from judge_tool.fw_policy import detect_for_iss, policy_from_dict
from judge_tool.mapper import aggregate
from judge_tool.models import EvidenceItem, Judgment, ResourceEvidence
from judge_tool.parsers import get_parser
from judge_tool.profile import get_profile
from judge_tool.writer import build_coverage, write_excel, write_json

log = logging.getLogger(__name__)

# 기준 고시 버전 패턴 "제YYYY-N호" (예: "제2026-1호")
_CRITERIA_VERSION = re.compile(r"제\d{4}-\d+호")
_DEFAULT_CRITERIA_VERSION = "제2026-1호"


def _extract_criteria_version(criteria_path: str) -> str:
    """평가기준 파일명에서 '제YYYY-N호' 버전을 추출. 실패 시 기본값 폴백."""
    m = _CRITERIA_VERSION.search(os.path.basename(criteria_path))
    return m.group(0) if m else _DEFAULT_CRITERIA_VERSION


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class JudgeContext:
    """판정 핸들러 공통 컨텍스트. 핸들러마다 profile 속성을 수동 스레딩하던
    것을 한 객체로 묶어 디스패치 시그니처를 통일한다."""
    profile: object
    profile_key: str
    client: object
    items: Dict
    variant: str


def _auto_defer(crit, item, profile) -> Judgment:
    """C·D 라벨: LLM 호출 없이 판단보류 자동 처리. canned_message를 근거로 기록."""
    def _reconcile(llm):
        return reconcile(
            llm, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=crit.item_id in profile.empty_means_good)

    msg = crit.canned_message or f"[{crit.label}항목 자동 판단보류]"
    forced = {"verdict": "판단보류", "confidence": 0.0,
              "rationale": msg, "cited_evidence": []}
    j = _reconcile(forced)
    j.label = crit.label
    return j


def _defer_or_eol(crit, item, ctx: "JudgeContext") -> Judgment:
    """det(C·D 라벨) 처리: eol_check는 EOL 결정론 판정, patch_check는 패치
    버전 결정론 대조를 먼저 시도하고, 실패(버전 미검출·테이블 미수록)하면
    기존 canned_message 자동보류로 폴백한다."""
    profile, profile_key, items = ctx.profile, ctx.profile_key, ctx.items
    forced = None
    # item.variant를 전달해 네이티브/클라우드 분기 문구가 정확히 선택되도록 한다.
    item_variant = item.variant if item is not None else None
    if crit.eol_check:
        forced = judge_eol(profile_key, items, variant=item_variant)
    elif crit.patch_check:
        forced = judge_patch(profile_key, items, variant=item_variant)
    if forced is None:
        return _auto_defer(crit, item, profile)

    ev_item = item
    if not item.resources:
        # 버전 증거가 타 항목(DBM-016 등)에 있어 자기 섹션이 비어 있는
        # 경우: 인용 버전을 증거로 실어 reconcile의 '증거 없음 → 판단보류
        # 강제' 가드를 통과시킨다.
        cited = (forced.get("cited_evidence") or [""])[0]
        ev_item = EvidenceItem(
            item_id=crit.item_id, variant=item.variant,
            resources=[ResourceEvidence(
                resource_id="eol-version", status="info",
                detail="버전 증거(타 항목 섹션에서 추출)",
                evidence=cited)])
    j = reconcile(
        forced, crit, ev_item,
        status_available=profile.status_available,
        flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
        empty_means_good=False)
    j.label = crit.label
    # 테이블(eol.yaml) 기반 자동판정은 테이블 노후화 위험이 있으므로
    # 항상 사람 검토 대상으로 명시한다. 현재 DB 프로파일에서는 status
    # 미분류 덕에 우연히 needs_review=True가 되지만, 그 우연(파서가
    # status를 채우지 않는 동작)에 의존하지 않는다(Opus 리뷰 반영).
    j.needs_review = True
    return j


_MISSING_EVIDENCE_MSG = (
    "[자동 판단보류: 증거 미수집] 점검 보고서에 해당 항목의 증거 섹션이 없습니다. "
    "점검 스크립트의 수집 범위를 확인하세요.")


def _missing_evidence_defer(crit, variant: str, profile) -> Judgment:
    """판정대상인데 보고서에 증거 섹션 자체가 없는 항목의 자동보류.

    조용한 누락(coverage missing)을 산출물에 보이는 행으로 바꾼다.
    섹션 부재는 '수집 안 됨'이지 '위반 0건'이 아니므로 empty_means_good을
    적용하지 않는다.
    """
    item = EvidenceItem(item_id=crit.item_id, variant=variant, resources=[])
    forced = {"verdict": "판단보류", "confidence": 0.0,
              "rationale": _MISSING_EVIDENCE_MSG, "cited_evidence": []}
    j = reconcile(
        forced, crit, item,
        status_available=profile.status_available,
        flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
        empty_means_good=False)
    j.label = crit.label
    return j


def _summarize_one(crit, item, ctx: "JudgeContext") -> Optional[Judgment]:
    """인터뷰(B 라벨): verdict=판단보류 고정.

    - interview(내용정리): LLM으로 증거 요약 → interview_summary.
    - interview_holdonly(내용정리X): summary_instruction이 없으면 LLM 요약을
      호출하지 않고 보류만 반환(요약 없음).
    - 예외: empty_means_good 항목에서 증거가 0건이면 LLM 없이 양호로 처리
      (예: DBM-024 빈 결과 = GRANT OPTION 없음 = 양호).
    """
    profile, client = ctx.profile, ctx.client
    item_id, variant = crit.item_id, ctx.variant
    is_empty_good = crit.item_id in profile.empty_means_good

    def _reconcile(llm):
        return reconcile(
            llm, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=is_empty_good)

    # 빈 증거 + empty_means_good → A항목처럼 양호로 직결(B 요약 불필요)
    if is_empty_good and not item.resources:
        forced = {"verdict": "양호", "confidence": 1.0,
                  "rationale": "[자동 양호: 빈 결과 = 위반 없음]",
                  "cited_evidence": []}
        try:
            j = _reconcile(forced)
            j.label = crit.label
            return j
        except Exception as e:  # noqa: BLE001
            log.warning("B항목 빈결과 reconcile 실패 item=%s type=%s",
                        item_id, type(e).__name__)
            return None

    # (e) interview_holdonly: 요약 지시가 없으면 LLM 요약을 생략하고 보류만.
    if not crit.summary_instruction:
        forced = {"verdict": "판단보류", "confidence": 0.0,
                  "rationale": "[인터뷰 필요] 기술 증거 요약 대상이 아니며, "
                               "담당자 인터뷰로 확인이 필요한 항목입니다.",
                  "cited_evidence": []}
        try:
            j = _reconcile(forced)
            j.label = crit.label
            return j
        except Exception as e:  # noqa: BLE001
            log.warning("B항목(holdonly) reconcile 실패, 스킵 item=%s type=%s",
                        item_id, type(e).__name__)
            return None

    summary = summarize_item(crit, item, client, evidence_mode=profile.evidence_mode)
    # rationale에 summary_instruction(내부 지시문)을 노출하지 않는다 — 고정 문구만.
    forced = {"verdict": "판단보류", "confidence": 0.0,
              "rationale": "[B항목: 담당자 인터뷰 필요] 기술 증거만으로 판정 불가. "
                           "'인터뷰요약' 컬럼의 증거 요약을 참고하여 담당자 인터뷰로 확인하세요.",
              "cited_evidence": []}
    try:
        j = _reconcile(forced)
        j.label = crit.label
        j.interview_summary = summary
        return j
    except Exception as e:  # noqa: BLE001
        log.warning("B항목 reconcile 실패, 스킵 item=%s variant=%s type=%s",
                    item_id, variant, type(e).__name__)
        return None


def _clean_note(note: str) -> str:
    """수집 단계에서 한글이 소실된 NOTE('?? ?? ???')를 감지해 대체 문구로 교체.

    원본 결과 파일이 비유니코드 인코딩으로 저장되어 한글이 전부 '?'로
    바뀐 경우(예: MariaDB RDS 결과), 깨진 텍스트가 산출물 근거에 그대로
    노출되는 것을 막는다. 실제 손상 NOTE는 '?' 비율이 60%+이므로 임계
    50%로 정상 문장의 물음표 오탐을 피한다(Opus 리뷰 반영).
    """
    if note and note.count("?") > len(note) * 0.5:
        return ("(원본 NOTE 인코딩 손상 — 점검 스크립트 수집 단계의 "
                "한글 인코딩 확인 필요)")
    return note


def _judge_one(crit, item, ctx: "JudgeContext") -> Optional[Judgment]:
    """단일 항목을 LLM으로 판정한다(llm·llm_det). 프로파일 속성으로 evidence/
    판정 모드를 결정하며 부분 실패를 격리하는 견고성 로직:

    - NOTE 보유 항목 → LLM 호출 없이 판단보류 강제(empty_means_good보다 우선)
    - judge 실패 → 판단보류 폴백으로 reconcile (격리, 결과 포함)
    - 폴백 reconcile 마저 실패 → 해당 항목만 스킵(None 반환)
    """
    profile, client = ctx.profile, ctx.client
    item_id, variant = crit.item_id, ctx.variant

    # reconcile은 항상 동일한 프로파일 인자로 호출되므로 지역 헬퍼로 묶는다.
    def _reconcile(llm: Dict) -> Judgment:
        return reconcile(
            llm, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=item_id in profile.empty_means_good)

    # B-2: NOTE 보유 항목은 기술점검 범위 밖(관리체계/외부확인/N-A)이므로
    # LLM 호출 없이 판단보류로 강제하고 NOTE를 사유로 기록(empty_means_good보다 우선).
    # 줄-시작 정규식으로 NOTE 줄만 정확히 매칭한다.
    # (?m)^NOTE:\s*(.*)$ → QUERY 줄 중간의 "NOTE:"는 오탐하지 않고,
    # 값이 공백/빈문자면 group(1).strip()이 ""가 되어 IndexError가 없다.
    note_m = re.search(r"(?m)^NOTE:\s*(.*)$", item.context or "")
    if note_m:
        note = _clean_note(note_m.group(1).strip())
        forced = {"verdict": "판단보류", "confidence": 0.0,
                  "rationale": f"[자동 판단보류: NOTE] {note}".strip(),
                  "cited_evidence": []}
        return _reconcile(forced)
    try:
        llm = judge_item(crit, item, client,
                         evidence_mode=profile.evidence_mode)
        j = _reconcile(llm)
        j.label = crit.label  # 리터럴 "A" 대신 설정값 사용(다른 핸들러와 일관성 유지)
        return j
    except Exception as e:  # noqa: BLE001 - 부분 실패 격리(네트워크/HTTP/KeyError 등)
        # 예외 본문에는 LLM 응답/evidence 원문이 섞일 수 있으므로 산출물·로그에
        # raw 메시지를 직렬화하지 않는다(타입명/item_id 만 남긴다).
        log.warning("judge 실패 item=%s variant=%s type=%s",
                    item_id, variant, type(e).__name__)
        fallback_llm = {"verdict": "판단보류", "confidence": 0.0,
                        "rationale": f"판정 중 오류({type(e).__name__})",
                        "cited_evidence": []}

    try:
        return _reconcile(fallback_llm)
    except Exception as e2:  # noqa: BLE001 - reconcile 자체 실패 시 해당 항목만 스킵
        log.warning("폴백 reconcile 실패, 스킵 item=%s variant=%s type=%s",
                    item_id, variant, type(e2).__name__)
        return None


def _fw_policy_handler(crit, item, ctx: "JudgeContext") -> Optional[Judgment]:
    """방화벽 이상정책 결정론 판정 핸들러 (judgment_method="fw_policy").

    item.context에서 FW_FORMAT과 FW_POLICIES_JSON을 파싱해
    fw_policy.detect_for_iss()를 호출한다.

    context 형식 (fw_policy_xlsx.parse() 생성):
        FW_FORMAT:<fmt>
        FW_SHEETS:<s1,...>
        FW_POLICY_COUNT:<n>
        FW_POLICIES_JSON:<compact_json>

    reconcile의 '빈 증거 → 판단보류 강제' 가드를 통과시키기 위해
    탐지 결과를 ResourceEvidence로 래핑한 EvidenceItem을 생성한다.
    needs_review는 항상 True (탐지=결정론, 정당성=사람).
    """
    profile = ctx.profile
    context = item.context or ""

    def _reconcile(llm_dict: Dict, ev_item: EvidenceItem) -> Judgment:
        return reconcile(
            llm_dict, crit, ev_item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=crit.item_id in profile.empty_means_good,
        )

    # context 파싱
    fmt = "unknown"
    policies_json: Optional[str] = None
    for line in context.splitlines():
        if line.startswith("FW_FORMAT:"):
            fmt = line[len("FW_FORMAT:"):].strip()
        elif line.startswith("FW_POLICIES_JSON:"):
            policies_json = line[len("FW_POLICIES_JSON:"):].strip()

    if not policies_json:
        forced = {
            "verdict": "판단보류", "confidence": 0.0,
            "rationale": "[FW 파서 오류] 정책 데이터가 context에 없습니다. "
                         "파서 동작을 확인하세요.",
            "cited_evidence": [],
        }
        # 빈 resources로 reconcile → 판단보류 강제 (원하는 동작)
        j = _reconcile(forced, item)
        j.label = crit.label
        return j

    try:
        policies_raw = _json.loads(policies_json)
        policies = [policy_from_dict(d) for d in policies_raw]
    except Exception as e:  # noqa: BLE001
        log.warning("FW policy JSON 파싱 실패 item=%s type=%s", crit.item_id, type(e).__name__)
        forced = {
            "verdict": "판단보류", "confidence": 0.0,
            "rationale": f"[FW 정책 파싱 오류] {type(e).__name__}",
            "cited_evidence": [],
        }
        j = _reconcile(forced, item)
        j.label = crit.label
        return j

    result = detect_for_iss(crit.item_id, policies, fmt)

    # 탐지 결과를 ResourceEvidence로 래핑 →
    # reconcile의 '빈 증거 → 판단보류 강제' 가드 우회
    violation_text = (
        "\n".join(result.violations[:20]) if result.violations else "이상 정책 없음"
    )
    ev_status = "bad" if result.violations else "good"
    ev_item = EvidenceItem(
        item_id=crit.item_id,
        variant=ctx.variant,
        resources=[ResourceEvidence(
            resource_id=f"{crit.item_id}-fw-detect",
            status=ev_status,
            detail=result.rationale[:200],
            evidence=violation_text,
        )],
        context=None,
    )

    forced = {
        "verdict": result.verdict,
        "confidence": result.confidence,
        "rationale": result.rationale,
        "cited_evidence": result.violations[:20],
    }
    try:
        j = _reconcile(forced, ev_item)
        j.label = crit.label
        j.needs_review = True  # 탐지=결정론, 정당성=사람 → 항상
        return j
    except Exception as e2:  # noqa: BLE001
        log.warning("FW policy reconcile 실패, 스킵 item=%s type=%s",
                    crit.item_id, type(e2).__name__)
        return None


# 판단방식(judgment_method) → 핸들러 디스패치 레지스트리.
# label if/elif 분기를 대체한다. 새 판정 종류(예: 방화벽 결정론 엔진)는
# 여기에 method→핸들러를 등록하는 것으로 확장한다(elif 증식 없음).
# 모든 핸들러는 (crit, item, ctx) -> Optional[Judgment] 시그니처를 따른다.
_HANDLERS = {
    "llm": _judge_one,
    "llm_det": _judge_one,
    "interview": _summarize_one,
    "interview_holdonly": _summarize_one,
    "det": _defer_or_eol,
    "fw_policy": _fw_policy_handler,
}


def _is_within(child: str, parent: str) -> bool:
    """child(realpath)가 parent(realpath)와 같거나 그 하위면 True.

    경로 문자열 기준으로 정규화해 비교하므로 입력 파일이 실제로
    존재하지 않아도 안전하게 동작한다.
    """
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    if child == parent:
        return True
    return child.startswith(parent + os.sep)


def _guard_out_dir(out_dir: str, report_path: str, criteria_path: str) -> None:
    """출력 디렉터리가 입력 데이터 디렉터리(보고서/평가기준 파일의 디렉터리)와
    같거나 그 하위면 거부한다. 실데이터 디렉터리 오염을 막는 CLI 경계 가드."""
    for input_path in (report_path, criteria_path):
        input_dir = os.path.dirname(os.path.abspath(input_path))
        if _is_within(out_dir, input_dir):
            raise SystemExit(
                "출력 디렉터리가 입력 데이터 디렉터리와 같습니다. "
                "별도 --out-dir을 지정하세요.")


def run(report_path: str, criteria_path: str, profile_key: str, client,
        json_out: str, xlsx_out: str, model_name: str,
        now: Optional[str] = None, variant_override: Optional[str] = None) -> Dict:
    # 잘못된 --profile 입력은 사용자 입력 오류이므로 ReportError로 변환해
    # main()에서 깔끔히 안내한다(raw KeyError 트레이스백 노출 방지).
    try:
        profile = get_profile(profile_key)
    except KeyError as e:
        raise ReportError(str(e)) from e
    # Tibero 등 excluded 프로파일은 구조만 정의돼 있고 판정 대상이 아니다.
    # load_criteria/parse 전에 차단해 의도치 않은 실행을 막는다.
    if profile.excluded:
        raise ReportError(
            f"프로파일 '{profile_key}'은 현재 판정 대상에서 배제됨"
            "(구조만 정의, 후속 과제). 다른 프로파일을 지정하세요.")
    # 변형 식별 전에 파서를 가져온다 — 파일명에 변형 마커가 없는 도메인
    # (서버: 출력 파일명 {hostname}-s-{date}.xml에 OS 정보 없음)은 파서의
    # 내용 기반 식별(detect_variant)로 폴백하기 위함.
    parser = get_parser(profile.parser)
    if variant_override is not None:
        if variant_override not in profile.variants:
            raise ReportError(
                f"알 수 없는 variant: {variant_override} "
                f"(프로파일 '{profile_key}' 사용 가능: {list(profile.variants)})")
        variant = variant_override
    else:
        variant = profile.variant_from_filename(report_path)
        # 내용 기반 폴백 seam: 파서가 detect_variant를 제공하면(서버 XML의
        # <asset><os>) 그것으로 식별한다. cloud/db 파서는 detect_variant가
        # 없으므로 hasattr 가드로 기존 동작 불변.
        if variant is None and hasattr(parser, "detect_variant"):
            variant = parser.detect_variant(report_path)
    if variant is None:
        markers = sorted(
            m for vs in profile.variants.values() for m in vs.filename_markers)
        if markers:
            raise ReportError(
                f"파일명에서 variant를 식별할 수 없음(미식별 또는 모호): {report_path}. "
                f"고유한 마커({markers})를 가진 파일명을 쓰거나 --variant로 직접 "
                f"지정하세요.")
        # 파일명 마커가 없는 도메인(서버) → 내용 기반 식별까지 실패한 경우.
        raise ReportError(
            f"보고서 내용에서 variant를 식별할 수 없음: {report_path}. "
            f"--variant로 직접 지정하세요"
            f"(사용 가능: {list(profile.variants)}).")

    criteria = load_criteria(criteria_path, profile, profile_key=profile_key)
    raw_checks = parser.parse(report_path)
    items = aggregate(raw_checks, variant, profile)

    judgments = []
    judged_ids: set = set()
    ctx = JudgeContext(profile=profile, profile_key=profile_key, client=client,
                       items=items, variant=variant)

    # TODO(네이티브 OS레벨 항목): DBM-012(lsnrctl)/022(파일권한)/026(umask)/
    # 034(구동권한)/021(ODBC) 등은 SQL이 섹션 자체를 출력하지 않아 아래 루프에서
    # items에 없고, 후단의 '증거 미수집' 보충 루프에서 _missing_evidence_defer로
    # 자동 판단보류된다(현행 유지). 실제 수집·판정은 서버 스크립트 연계 후속 과제.
    # 단 MSSQL DBM-031(SA)·MySQL DBM-033(이중화)은 실제 섹션을 내므로 default A로
    # LLM 판정된다 — 라벨 적정성은 실데이터 확보 후 재검토(item_configs TODO 참조).
    for item_id, item in items.items():
        crit = criteria.get((item_id, variant))
        if crit is None or not crit.is_judgeable:
            continue  # 기준에 없거나 스크립트 대상 아님/빈 판단기준 → 스킵
        # 판단방식 → 핸들러 디스패치. 미지 method는 LLM 판정으로 폴백.
        # 미등록 method가 조용히 LLM 판정으로 은폐되지 않도록 경고를 남긴다.
        if crit.judgment_method not in _HANDLERS:
            log.warning("미등록 judgment_method=%s item=%s → LLM 폴백",
                        crit.judgment_method, item_id)
        handler = _HANDLERS.get(crit.judgment_method, _judge_one)
        judgment = handler(crit, item, ctx)
        if judgment is not None:
            judgment.judgment_method = crit.judgment_method  # 정적 전파
            judgments.append(judgment)
            judged_ids.add(item_id)

    # 보고서에 증거 섹션이 없는 판정대상 항목도 빠짐없이 행을 만든다.
    # - det(C/D): canned_message·EOL 결정론 (기존 동작 유지)
    # - 그 외(llm/llm_det/interview*): '증거 미수집' 자동보류 — 고위험 항목이
    #   조용히 누락되는 것을 방지(예: PG 보고서에 DBM-005 섹션 자체가 없는 경우)
    # 단, 증거 섹션이 있었는데 처리 실패(judgment=None)로 빠진 항목은
    # '미수집'이 아니므로 제외한다(coverage missing으로 남아 실패가 보임).
    for (crit_id, crit_variant), crit in criteria.items():
        if crit_variant != variant or not crit.is_judgeable:
            continue
        if crit_id in judged_ids or crit_id in items:
            continue
        if crit.judgment_method == "det":
            dummy_item = EvidenceItem(item_id=crit_id, variant=variant,
                                      resources=[])
            # 버전 증거가 다른 항목(DBM-016 등)에 있을 수 있으므로
            # 자기 섹션이 없어도 EOL 결정론 판정을 시도한다.
            judgment = _defer_or_eol(crit, dummy_item, ctx)
        else:
            judgment = _missing_evidence_defer(crit, variant, profile)
        if judgment is not None:
            judgment.judgment_method = crit.judgment_method  # 정적 전파
            judgments.append(judgment)
            judged_ids.add(crit_id)

    judgments.sort(key=lambda j: j.item_id)
    coverage = build_coverage(criteria, judgments, variant)
    meta = {
        "tool_version": __version__,
        "criteria_version": _extract_criteria_version(criteria_path),
        "model": model_name,
        "generated_at": now or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_file": os.path.basename(report_path),
        "source_sha256": _sha256(report_path),
        "profile": profile_key,
        "variant": variant,
    }
    write_json(judgments, meta, coverage, json_out)
    write_excel(judgments, meta, coverage, xlsx_out)
    return coverage


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="클라우드 점검 결과 LLM 자동 판단 도구")
    ap.add_argument("--report", required=True, help="점검 결과 XML 경로")
    ap.add_argument("--criteria", required=True, help="평가기준 xlsx 경로")
    ap.add_argument("--profile", default="cloud")
    ap.add_argument("--variant", default=None,
                    help="변형 강제 지정(파일명 자동식별을 건너뜀). "
                         "예: oracle_native, mysql_rds")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    args = ap.parse_args(argv)

    _guard_out_dir(args.out_dir, args.report, args.criteria)

    base = os.path.splitext(os.path.basename(args.report))[0]
    json_out = os.path.join(args.out_dir, f"result_{base}.json")
    xlsx_out = os.path.join(args.out_dir, f"result_{base}.xlsx")

    client = OllamaClient(url=args.ollama_url, model=args.model)
    try:
        cov = run(args.report, args.criteria, args.profile, client,
                  json_out, xlsx_out, args.model,
                  variant_override=args.variant)
    except (ReportError, OSError) as e:
        # 사용자 입력 오류(손상 XML/파일 부재 등)만 깔끔히 안내한다.
        # ReportError 는 의도된 입력/보고서 문제, OSError(FileNotFoundError
        # 포함)는 파일 부재/권한 등 파일시스템 오류. 그 외 우발적 ValueError
        # 등 프로그래밍 버그는 잡지 않고 트레이스백으로 노출시켜 디버깅 가능.
        # raw 트레이스백 대신 stderr에 한 줄 명확한 안내 후 비정상 종료.
        print(f"오류: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    print(f"판정 {cov['judged']}/{cov['expected']} 완료. "
          f"미판정: {cov['missing']}")
    print(f"출력: {json_out}\n      {xlsx_out}")


if __name__ == "__main__":
    main()

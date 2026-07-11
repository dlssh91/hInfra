import argparse
import glob
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import json as _json

from judge_tool import __version__
from judge_tool.criteria_loader import load_criteria
from judge_tool.errors import ReportError
from judge_tool.judge import OllamaClient, judge_item, reconcile, summarize_item
from judge_tool.eol import judge_eol, judge_patch
from judge_tool.fw_objects import load_aux_objects
from judge_tool.fw_policy import detect_for_iss, policy_from_dict
from judge_tool.mapper import aggregate
from judge_tool.models import EvidenceItem, Judgment, ResourceEvidence
from judge_tool.parsers import get_parser
from judge_tool.preflight import PreflightError, run_preflight  # noqa: F401
from judge_tool.profile import get_profile, guess_profile, list_profile_keys
from judge_tool.writer import build_coverage, write_excel, write_json

# 결정론 어댑터 등록 — import 시 _DET_ADAPTERS["server"] 등록 부작용 발생
import judge_tool.det_adapters.server as _server_adapter  # noqa: F401,E402
# 컨테이너 어댑터 등록 — import 시 _DET_ADAPTERS["container"] 등록 부작용 발생
import judge_tool.det_adapters.container as _container_adapter  # noqa: F401,E402
# 웹서버-WAS 어댑터 등록 — import 시 _DET_ADAPTERS["webwas"] 등록 부작용 발생 (Phase 3)
import judge_tool.det_adapters.webwas as _webwas_adapter  # noqa: F401,E402
# DB 어댑터 등록 — import 시 _DET_ADAPTERS["db_mysql/oracle/mssql/mariadb/postgresql"] 5개 등록 (Phase 4)
import judge_tool.det_adapters.db as _db_adapter  # noqa: F401,E402

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
    # 항목별 임계값 맵 {item_id: {param: value, ...}}. 기본 빈 dict.
    # run()에서 _build_thresholds(criteria)로 채워짐(§6). 기존 생성 호출 불변.
    thresholds: Dict = field(default_factory=dict)
    # (a) hashcat 연동 옵션. None → hashcat 비활성(graceful skip). Phase 4c-a.
    # HashcatOpts는 db_pwcrack 모듈에서 import; None이면 (b)-only 동작.
    hashcat_opts: Optional[object] = None  # 타입: db_pwcrack.HashcatOpts | None


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
        FW_PARSE_STATS_JSON:<compact_json>
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
    # parse_stats=None은 "통계 소실"(라인 부재/JSON 손상)을 뜻하며 dict와
    # 구분된다 — M-1: 소실 시 fail-open(가드 침묵 해제) 대신 fail-closed
    # (위반 0건 항목을 양호 대신 판단보류)로 처리한다.
    fmt = "unknown"
    policies_json: Optional[str] = None
    parse_stats: Optional[Dict] = None
    for line in context.splitlines():
        if line.startswith("FW_FORMAT:"):
            fmt = line[len("FW_FORMAT:"):].strip()
        elif line.startswith("FW_PARSE_STATS_JSON:"):
            stats_json = line[len("FW_PARSE_STATS_JSON:"):].strip()
            try:
                loaded = _json.loads(stats_json)
                parse_stats = loaded if isinstance(loaded, dict) else None
            except Exception:  # noqa: BLE001 - 손상 = 소실로 취급(None 유지)
                log.warning("FW parse_stats JSON 손상 item=%s — fail-closed 가드 적용",
                            crit.item_id)
                parse_stats = None
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

    result = detect_for_iss(
        crit.item_id, policies, fmt,
        unrecognized_action_count=(parse_stats or {}).get(
            "unrecognized_action_count", 0),
    )

    # M-1 fail-closed: 파싱 통계가 소실된 상태에서는 미인식 액션 존재 여부를
    # 확인할 수 없으므로, 위반 0건의 "양호"를 단정할 수 없다 → 판단보류 강등.
    # (위반 1건 이상 "취약"과 capability 부재 "판단보류"는 그대로 유지 —
    #  FW_POLICIES_JSON 손상 시 판단보류인 것과 대칭.)
    if parse_stats is None and result.verdict == "양호":
        result.verdict = "판단보류"
        result.confidence = 0.0
        result.rationale += (
            " 단, 파싱 통계 소실(FW_PARSE_STATS_JSON 부재/손상) → "
            "미인식 정책 액션 여부 확인 불가 → 양호 단정 불가(판단보류)."
        )

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


def _build_thresholds(criteria: Dict) -> Dict:
    """criteria({(item_id, variant): Criterion}) → {item_id: dict} 임계값 맵.

    Criterion.thresholds가 비어있지 않은 항목만 수록한다.
    같은 item_id가 여러 variant에 걸쳐 있으면 비어있지 않은 것 중 첫 번째를 사용
    (현재 thresholds는 variant 무관 공통값이므로 충돌 없음).
    criteria가 비어있거나 어떤 항목도 thresholds를 가지지 않으면 빈 dict.
    """
    result: Dict = {}
    for crit in criteria.values():
        if getattr(crit, "thresholds", None) and crit.item_id not in result:
            result[crit.item_id] = crit.thresholds
    return result


def _raw_evidence_for_det(item) -> str:
    """det_common 어댑터 공급용: item의 resources에서 raw_evidence를 모아 반환.

    citation/LLM 경로에는 사용하지 않는다(§7 누출 경계).
    raw_evidence가 있는 첫 번째 ResourceEvidence의 raw_evidence를 반환.
    없으면 빈 문자열(어댑터가 빈 입력으로 handled=False 반환 가능).
    """
    for res in (item.resources if item else []):
        raw = getattr(res, "raw_evidence", None)
        if raw:
            return raw
    return ""


def _det_common_label_route(crit, item, ctx: "JudgeContext") -> Optional[Judgment]:
    """§18.3 라벨 라우팅: handled=False 시 crit.label에 따라 분기한다.

    label A → _judge_one(LLM)
    label B → _summarize_one(인터뷰)
    label C / D → _defer_or_eol(canned/EOL)
    기타/미지 → _judge_one(보수적 폴백)

    구현됨(§18.3 라우팅): Phase 1부터 무조건 LLM 폴백 금지.
    """
    label = getattr(crit, "label", None) or "A"
    if label == "B":
        return _summarize_one(crit, item, ctx)
    if label in ("C", "D"):
        return _defer_or_eol(crit, item, ctx)
    # label A 또는 미지 → LLM
    return _judge_one(crit, item, ctx)


def _det_common_handler(crit, item, ctx: "JudgeContext") -> Optional[Judgment]:
    """common 결정론 판정 핸들러 (judgment_method="det_common").

    Phase 0 동작: 어댑터 레지스트리가 비어있으므로 get_adapter()가 항상 None →
    §18.3 라벨 라우팅으로 폴백. 기존 판정 동작 불변(서버 항목에 det_common 미부여 상태).

    Phase 1+ 동작(어댑터 등록 후):
      1) gate(): 비결정론(STUB/ABSENT/UNREACHABLE/MANUAL)이면 handled=False →
         §18.3 라벨 라우팅(A→LLM, B→인터뷰, C/D→canned). 구현됨(§18.3 라우팅).
      2) DET 확인 후 어댑터 호출 → ForcedVerdict.
      3) handled=True면 fw_policy_handler 패턴으로 합성 EvidenceItem 래핑 →
         forced → reconcile → needs_review=True.

    raw 입력은 citation/LLM에 노출되지 않는다(§7 누출 경계: _raw_evidence_for_det 사용).
    """
    from judge_tool.det_adapters import base as det_base  # 지연 임포트(순환 방지)

    profile = ctx.profile
    adapter = det_base.get_adapter(ctx.profile_key)

    # 어댑터 없음 → §18.3 라벨 라우팅(Phase 0: 서버 항목에 det_common 미부여라 실질 불변)
    if adapter is None:
        return _det_common_label_route(crit, item, ctx)

    # Phase 1+: 어댑터 있는 경우 — 거짓 양호 게이트(§18.1 C1)
    gate_result = det_base.gate(crit.item_id, ctx.variant)
    if gate_result is not None and not gate_result.handled:
        # 비-DET(ABSENT/MANUAL/STUB) 항목: §18.3 라벨 라우팅(구현됨)
        return _det_common_label_route(crit, item, ctx)

    # DET 확인: 어댑터 호출
    raw = _raw_evidence_for_det(item)  # §7: raw를 citation/LLM에 넘기지 않는다
    thresholds = ctx.thresholds.get(crit.item_id, {})
    try:
        fv = adapter(crit.item_id, raw, ctx.variant, thresholds,
                     context=item.context if item else None)
    except Exception as e:  # noqa: BLE001
        log.warning("det_common 어댑터 예외 item=%s variant=%s type=%s — §18.3 라벨 라우팅",
                    crit.item_id, ctx.variant, type(e).__name__)
        return _det_common_label_route(crit, item, ctx)

    if not fv.handled:
        # 어댑터가 (*)/M 분기를 만남 → §18.3 라벨 라우팅(구현됨)
        return _det_common_label_route(crit, item, ctx)

    # fw_policy_handler와 동일 패턴: 합성 EvidenceItem 래핑 → reconcile → needs_review
    violation_text = "\n".join(fv.citations[:20]) if fv.citations else "이상 없음"
    ev_item = EvidenceItem(
        item_id=crit.item_id,
        variant=ctx.variant,
        resources=[ResourceEvidence(
            resource_id=f"{crit.item_id}-det",
            status=fv.ev_status,
            detail=fv.rationale[:200],
            evidence=violation_text,
            # raw_evidence는 합성 증거에 넣지 않는다(§7 누출 경계)
        )],
        context=None,
    )
    forced = {
        "verdict": fv.verdict,
        "confidence": fv.confidence,
        "rationale": fv.rationale,
        "cited_evidence": fv.citations[:20],
    }
    try:
        j = reconcile(
            forced, crit, ev_item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=crit.item_id in profile.empty_means_good,
        )
        j.label = crit.label
        j.needs_review = True  # 탐지=결정론, 임계값 정당성=사람
        summary = getattr(fv, "interview_summary", None)
        if summary:
            j.interview_summary = summary
        return j
    except Exception as e2:  # noqa: BLE001
        log.warning("det_common reconcile 실패, §18.3 라벨 라우팅 item=%s type=%s",
                    crit.item_id, type(e2).__name__)
        return _det_common_label_route(crit, item, ctx)


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
    "det_common": _det_common_handler,  # Phase 0: 어댑터 미등록 → LLM 폴백(동작 불변)
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


def _resolve_out_dir(preferred: str, report_path: str, criteria_path: str) -> str:
    """out-dir 후보가 입력 경로와 충돌하면 저장소 루트의 out/으로 자동
    폴백한다.

    대화형/배치 모드는 "결과 파일이 있는 폴더"를 스캔 대상으로 삼는데,
    실사용자가 그 폴더 자체에서(cwd=해당 폴더) judge_tool을 실행하면
    기본 out-dir('out')이 입력 폴더의 하위가 되어 _guard_out_dir가
    거부한다. 이 경우 사람이 --out-dir을 다시 입력하게 만들기보다
    저장소 루트의 out/으로 조용히 대체해 "그냥 동작"하게 한다.
    사용자가 --out-dir을 명시한 경로(단일파일 CLI)는 이 함수를 거치지
    않고 기존 엄격한 _guard_out_dir만 적용된다(하위호환 불변).
    """
    try:
        _guard_out_dir(preferred, report_path, criteria_path)
        return preferred
    except SystemExit:
        fallback = os.path.join(_PKG_ROOT, "out")
        if fallback == os.path.abspath(preferred):
            # 폴백 후보가 방금 거부된 경로와 동일 → 완화할 여지 없음.
            # 가드가 거부한 경로를 무검증 반환하지 않고 원래 거부를 유지한다.
            raise
        _guard_out_dir(fallback, report_path, criteria_path)
        return fallback


# ── 스마트 런처: 자동추정/헬스체크/배치용 헬퍼 ───────────────────────────────

# 이 method들은 client.chat()을 절대 호출하지 않음이 코드로 보장된다:
# det(canned/EOL 결정론), fw_policy(방화벽 결정론 탐지) — _defer_or_eol/
# _fw_policy_handler 참조. 그 외(llm/llm_det/interview*/det_common)는
# 실행 경로에 따라 LLM 호출 가능성이 있으므로 보수적으로 "필요"로 간주한다.
_NEVER_LLM_METHODS = {"det", "fw_policy"}


def _needs_llm(criteria: Dict, variant: str) -> bool:
    """이 variant의 판정대상 항목 중 LLM 호출 가능성이 있는 항목이 있는지 판별.

    Ollama 페일패스트 헬스체크의 게이트로 쓰인다(iss처럼 순수 결정론
    프로파일은 Ollama가 없어도 동작해야 하므로 헬스체크를 건너뛴다).
    interview/interview_holdonly는 classify_method가 summary_instruction
    유무로 정적 분류하지만, 안전을 위해 실제 crit.summary_instruction 값을
    직접 확인한다(§18.3 라벨 라우팅으로 method가 우회되는 경우까지 대비).
    """
    for (_item_id, crit_variant), crit in criteria.items():
        if crit_variant != variant or not crit.is_judgeable:
            continue
        method = crit.judgment_method
        if method in _NEVER_LLM_METHODS:
            continue
        if method in ("interview", "interview_holdonly"):
            if crit.summary_instruction:
                return True
            continue
        # llm / llm_det / det_common(어댑터 미처리 시 라벨 라우팅으로 LLM
        # 폴백 가능) / 미등록 method → 보수적으로 LLM 필요로 간주.
        return True
    return False


# 평가기준 xlsx 자동탐색 시 뒤질 후보 디렉터리(우선순위 순).
# 1) 현재 작업 디렉터리 기준 ref/ — judge.sh가 작업루트로 cd 후 실행하므로
#    일반적인 실사용 경로. 2) 패키지 설치 위치 기준 ref/ — cwd가 다르더라도
#    'python3 -m judge_tool' 을 다른 위치에서 띄운 경우의 안전망.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _discover_criteria_path() -> str:
    """--criteria 미지정 시 ref/ 아래 평가기준 xlsx를 자동탐색한다.

    패턴: '*평가기준*제*호*.xlsx'. 복수 매칭이면 파일명의 '제YYYY-N호'
    버전이 가장 높은 파일을 선택한다(최신 고시 우선). 매칭이 없으면
    ReportError로 명확한 한글 안내를 낸다(추측 대신 사용자에게 --criteria
    직접 지정을 요구 — 오판정보다 명시 요구가 안전).
    """
    pattern = "*평가기준*제*호*.xlsx"
    search_dirs = []
    for base in (os.getcwd(), _PKG_ROOT):
        d = os.path.join(base, "ref")
        if d not in search_dirs:
            search_dirs.append(d)

    matches: List[str] = []
    for d in search_dirs:
        matches.extend(glob.glob(os.path.join(d, pattern)))
    # 중복 제거(realpath 기준), 순서 보존
    seen = set()
    unique: List[str] = []
    for m in matches:
        rp = os.path.realpath(m)
        if rp not in seen:
            seen.add(rp)
            unique.append(m)
    matches = unique

    if not matches:
        raise ReportError(
            "--criteria가 지정되지 않았고, 다음 위치의 'ref/' 아래에서 평가기준 "
            f"xlsx 파일을 자동으로 찾지 못했습니다: {search_dirs}. "
            "--criteria 옵션으로 평가기준 xlsx 경로를 직접 지정하세요.")
    if len(matches) == 1:
        return matches[0]

    def _version_key(path: str) -> Tuple[int, int]:
        m = _CRITERIA_VERSION.search(os.path.basename(path))
        if not m:
            return (0, 0)
        vm = re.search(r"제(\d{4})-(\d+)호", m.group(0))
        return (int(vm.group(1)), int(vm.group(2))) if vm else (0, 0)

    matches.sort(key=_version_key, reverse=True)
    return matches[0]


def _resolve_profile(report_path: str, explicit: Optional[str]) -> str:
    """--profile 미지정 시 파일명/확장자로 자동추정한다.

    명시된 프로파일이 있으면 그대로 사용(기존 동작 불변). 없으면
    profile.guess_profile()로 추정하되, 모호(복수 후보)하거나 추정 불가면
    ReportError로 후보/사용법을 안내하고 종료한다 — cloud 무조건 폴백은
    제거(오판정보다 명시 요구가 안전).
    """
    if explicit:
        return explicit
    guessed, candidates = guess_profile(report_path)
    if guessed:
        return guessed
    if candidates:
        raise ReportError(
            f"--profile을 확정할 수 없습니다(파일명으로 프로파일 후보가 여럿입니다): "
            f"{list(candidates)}. --profile 옵션으로 직접 지정하세요.")
    raise ReportError(
        f"--profile을 추정할 수 없습니다(파일명/확장자로 식별 불가): {report_path}. "
        f"--profile 옵션으로 직접 지정하세요(사용 가능: {list(list_profile_keys())}).")


# 배치/대화형 모드에서 후보로 취급할 결과 파일 확장자.
# .txt = DB 결과 표준 포맷(CLAUDE.md 예시 --report <result.txt>, 픽스처
# sample_db_mysql.txt 등)이므로 반드시 포함 — 누락 시 폴더드롭에서 조용히 제외됨.
_CANDIDATE_EXTS = (".xml", ".json", ".xlsx", ".csv", ".txt")


def _list_candidate_reports(directory: str) -> List[str]:
    """디렉터리 안에서 판정 대상일 법한 결과 파일 목록을 반환(정렬됨).

    평가기준 xlsx('평가기준' 포함 파일명)와 기존 산출물('result_' 접두)은
    후보에서 제외한다.
    """
    out: List[str] = []
    for name in sorted(os.listdir(directory)):
        if name.startswith("."):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext not in _CANDIDATE_EXTS:
            continue
        if "평가기준" in name or name.startswith("result_"):
            continue
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            out.append(full)
    return out


def run(report_path: str, criteria_path: str, profile_key: str, client,
        json_out: str, xlsx_out: str, model_name: str,
        now: Optional[str] = None, variant_override: Optional[str] = None,
        skip_preflight: bool = False,
        hashcat_opts: Optional[object] = None,
        aux_objects_path: Optional[str] = None) -> Dict:
    """판정 실행 함수.

    hashcat_opts: HashcatOpts 또는 None (None → (a) 비활성, (b)-only 동작).
    aux_objects_path: `--aux-objects` 경로(B′-3b, FW 전용). fw_policy_xlsx
        파서에서만 사용 — 그 외 프로파일은 전달돼도 무시된다(no-op).
        None(기본)이면 fw_policy_xlsx.parse()가 aux_table=None으로 호출되어
        기존 B′-3a 동작과 완전 동일(회귀 없음).
    """
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

    # Pre-flight: 인코딩 교정 + LLM 점검 가능 게이트.
    # 교정 결과 텍스트는 preflight 모듈이 파서 내부(_read_text)에 이미 통합돼
    # 있으므로 여기서는 게이트(NG이면 PreflightError)만 실행한다.
    # 게이트 적용 기준: 파일 확장자 하드코딩 대신 profile.parser 종류로 판단.
    # XML 계열 파서(cloud_xml/server_xml/container_xml/network_xml/osvirt_xml/
    # webwas_xml/iss_xml)는 텍스트 XML이므로 인코딩 교정+게이트 적용.
    # db_json/fw_policy_xlsx 등 비XML 파서는 자체 처리라 게이트 생략.
    # 이로써 대문자 .XML·확장자 없는 경로에도 일관 적용된다.
    _XML_PARSERS = {
        "cloud_xml", "server_xml", "container_xml", "network_xml",
        "osvirt_xml", "webwas_xml", "iss_xml",
    }
    if profile.parser in _XML_PARSERS:
        run_preflight(report_path, client if not skip_preflight else None,
                      skip=skip_preflight)
    elif not skip_preflight:
        log.debug(
            "pre-flight 게이트: XML 파서 아님(parser=%s), 게이트 생략 (%s)",
            profile.parser, report_path)

    criteria = load_criteria(criteria_path, profile, profile_key=profile_key)

    # Ollama 페일패스트: LLM이 필요한 판정인데 서버·모델이 없으면 판정 루프를
    # 다 돌기 전에 먼저 알린다. 예외: skip_preflight(테스트/오프라인 모드) 또는
    # 이 variant가 순결정론(det/fw_policy만, 예: iss)이면 건너뛴다. client가
    # health_check를 제공하지 않는 대역(테스트 Stub 등)도 자연히 건너뛴다.
    if not skip_preflight and _needs_llm(criteria, variant):
        health_check = getattr(client, "health_check", None)
        if callable(health_check):
            try:
                health_check()
            except Exception as e:  # noqa: BLE001 - 원인 다양(미가동/모델 없음/네트워크)
                model_name_for_hint = getattr(client, "model", "qwen3-coder:30b")
                raise ReportError(
                    f"[Ollama 확인 실패] {e} "
                    "Ollama가 실행 중인지 확인하세요: `ollama serve`, "
                    f"`ollama pull {model_name_for_hint}`."
                ) from e

    # B′-3b: --aux-objects는 fw_policy_xlsx 파서 전용 확장 인자라 다른
    # 파서의 parse(report_path) 단일인자 계약을 건드리지 않도록 profile.parser
    # 로 분기한다(hasattr 대신 명시 문자열 비교 — fw_policy_xlsx.parse()의
    # 새 aux_table kwarg는 이 파서에만 존재).
    if profile.parser == "fw_policy_xlsx" and aux_objects_path:
        aux_table = load_aux_objects(aux_objects_path)
        raw_checks = parser.parse(report_path, aux_table=aux_table)
    else:
        raw_checks = parser.parse(report_path)
    items = aggregate(raw_checks, variant, profile)

    judgments = []
    judged_ids: set = set()
    ctx = JudgeContext(profile=profile, profile_key=profile_key, client=client,
                       items=items, variant=variant,
                       thresholds=_build_thresholds(criteria),
                       hashcat_opts=hashcat_opts)

    # Phase 4c-a: hashcat 옵션을 db_pwcrack 모듈 세임에 주입.
    # CLI 단일 프로세스이므로 모듈 글로벌 변수가 안전함.
    # M-1: try/finally 로 감싸 예외 발생 시에도 세임이 반드시 클리어됨을 보장.
    from judge_tool.det_adapters import db_pwcrack as _db_pwcrack_seam
    _db_pwcrack_seam.set_hashcat_opts(hashcat_opts)
    try:
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
                judgment.standard = crit.standard  # 판정 근거: xlsx 판단기준 전파
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
                judgment = None
                # det_common 구조적취약(데이터 무관) 항목은 섹션이 없어도 어댑터로 시도한다.
                # (예: pg_native DBM-006/007 — PostgreSQL 코어 기능 부재 = 데이터 없이 취약.)
                # 어댑터가 실판정(취약/양호)을 낸 경우에만 채택하고, 판단보류 폴백이면
                # 아래 '증거 미수집' 경로로 보낸다(비구조적 det_common 동작 불변).
                if crit.judgment_method == "det_common":
                    dummy_item = EvidenceItem(item_id=crit_id, variant=variant,
                                              resources=[])
                    j = _det_common_handler(crit, dummy_item, ctx)
                    if j is not None and j.verdict in ("취약", "양호"):
                        judgment = j
                if judgment is None:
                    judgment = _missing_evidence_defer(crit, variant, profile)
            if judgment is not None:
                judgment.judgment_method = crit.judgment_method  # 정적 전파
                judgment.standard = crit.standard  # 판정 근거: xlsx 판단기준 전파
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
    finally:
        # Phase 4c-a: hashcat 세임 클리어 (모듈 글로벌 초기화)
        # M-1: finally 블록으로 예외 발생 시에도 반드시 클리어.
        _db_pwcrack_seam.clear_hashcat_opts()


def _hashcat_opts_from_args(args):
    """argparse Namespace → HashcatOpts. main()/_run_batch가 공유."""
    from judge_tool.det_adapters.db_pwcrack import HashcatOpts as _HashcatOpts
    return _HashcatOpts(
        hashcat_path=args.hashcat_path,
        wordlist=args.hashcat_wordlist,
        rules=args.hashcat_rules,
        timeout=args.hashcat_timeout,
    )


def _run_batch(args) -> None:
    """--report에 디렉터리가 주어진 경우: 폴더 안 결과파일을 파일별로
    프로파일 자동추정 후 순차 판정한다. 한 파일의 실패가 나머지 파일
    처리를 막지 않도록 격리하고, 끝에 파일별 1행 종합 요약을 출력한다.
    """
    files = _list_candidate_reports(args.report)
    if not files:
        print(f"오류: '{args.report}' 안에서 처리할 결과 파일을 찾지 못했습니다.",
              file=sys.stderr)
        raise SystemExit(2)

    # out-dir이 argparse 기본값('out') 그대로면, 사용자가 결과 폴더 자체에서
    # 실행해도(cwd=args.report) 조용히 동작하도록 충돌 시 저장소 루트
    # out/으로 자동 폴백한다. --out-dir을 명시했다면 기존 엄격한 가드 적용.
    # 스캔 폴더 자체를 가드 기준으로 삼기 위해 프로브 경로(폴더 내 임의 파일)를
    # 넘긴다 — _guard_out_dir는 report_path의 dirname을 입력 디렉터리로 보므로
    # 디렉터리를 그대로 넘기면 그 '부모'가 기준이 되어버린다.
    scan_probe = os.path.join(args.report, "_")
    out_dir = args.out_dir
    if out_dir == "out":
        out_dir = _resolve_out_dir(out_dir, scan_probe, args.criteria)
    else:
        # 명시적 --out-dir: makedirs 전에 선가드 — 실데이터/입력 폴더 안에
        # 디렉터리를 만들고서야 거부하는 것(M-2)을 방지. 실패 시 SystemExit로
        # 배치 시작 전 즉시 중단(파일별 격리 대상이 아닌 설정 오류).
        _guard_out_dir(out_dir, scan_probe, args.criteria)
    os.makedirs(out_dir, exist_ok=True)
    hashcat_opts = _hashcat_opts_from_args(args)

    rows: List[Tuple[str, str, str, str]] = []  # (파일명, 프로파일, 상태, 상세)
    for path in files:
        base = os.path.splitext(os.path.basename(path))[0]
        json_out = os.path.join(out_dir, f"result_{base}.json")
        xlsx_out = os.path.join(out_dir, f"result_{base}.xlsx")
        name = os.path.basename(path)
        try:
            profile_key = _resolve_profile(path, args.profile)
            # out_dir은 루프 진입 전에 스캔 폴더 기준으로 선가드했다(비재귀
            # 목록이라 전 파일이 같은 폴더). 파일별 재가드는 SystemExit로
            # 배치를 중단시키므로 두지 않는다(M-3).
            client = OllamaClient(url=args.ollama_url, model=args.model)
            cov = run(path, args.criteria, profile_key, client,
                     json_out, xlsx_out, args.model,
                     skip_preflight=args.skip_preflight,
                     hashcat_opts=hashcat_opts,
                     aux_objects_path=args.aux_objects)
            rows.append((name, profile_key, "성공",
                        f"{cov['judged']}/{cov['expected']} 판정, "
                        f"미판정 {len(cov['missing'])}"))
        except (ReportError, OSError) as e:
            rows.append((name, "-", "실패", str(e)))
        except Exception as e:  # noqa: BLE001 - 배치 격리: 파일 1건의 우발적
            # 예외도 전체 배치를 중단시키지 않는다(불변 계약: 실패 격리).
            log.warning("배치 처리 중 예외 report=%s type=%s", path, type(e).__name__)
            rows.append((name, "-", "실패", f"{type(e).__name__}: {e}"))

    print(f"\n=== 배치 판정 요약 ({len(rows)}건) ===")
    for name, prof, status, detail in rows:
        print(f"[{status}] {name}  (profile={prof})  {detail}")
    ok = sum(1 for r in rows if r[2] == "성공")
    print(f"\n성공 {ok}/{len(rows)}. 산출물 위치: {out_dir}")


def _interactive_main() -> None:
    """무인자 대화형 모드: 인자 0개 + tty에서 진입(스마트 런처).

    현재 폴더의 후보 결과파일을 나열(추정 프로파일 병기) → 사용자가 번호
    선택 → 추정 프로파일 확인(엔터=수락) → 실행. stdlib input()만 사용.
    """
    print("=== judge_tool 대화형 모드 ===")
    cwd = os.getcwd()
    dir_in = input(f"결과 파일이 있는 폴더 [{cwd}]: ").strip() or cwd
    if not os.path.isdir(dir_in):
        print(f"오류: 폴더를 찾을 수 없습니다: {dir_in}", file=sys.stderr)
        raise SystemExit(2)

    files = _list_candidate_reports(dir_in)
    if not files:
        print(f"오류: '{dir_in}' 안에서 결과 파일을 찾지 못했습니다.", file=sys.stderr)
        raise SystemExit(2)

    print("\n번호  파일명                                      추정 프로파일")
    guesses: List[Optional[str]] = []
    for i, path in enumerate(files, start=1):
        guessed, candidates = guess_profile(path)
        guesses.append(guessed)
        if guessed:
            label = guessed
        elif candidates:
            label = f"모호({','.join(candidates)})"
        else:
            label = "추정 불가"
        print(f"[{i:2d}] {os.path.basename(path):42s} {label}")

    sel = input(f"\n판정할 파일 번호 선택 (1-{len(files)}): ").strip()
    try:
        idx = int(sel) - 1
        if not (0 <= idx < len(files)):
            raise ValueError
    except ValueError:
        print("오류: 올바른 번호를 입력하세요.", file=sys.stderr)
        raise SystemExit(2)

    report_path = files[idx]
    guessed_profile = guesses[idx]
    prompt = (f"추정 프로파일: {guessed_profile} (엔터=수락, 다른 값 입력=변경): "
             if guessed_profile else
             "프로파일을 추정하지 못했습니다. 직접 입력하세요"
             f"(사용 가능: {list(list_profile_keys())}): ")
    prof_in = input(prompt).strip()
    profile_key = prof_in or guessed_profile
    if not profile_key:
        print("오류: 프로파일이 지정되지 않았습니다.", file=sys.stderr)
        raise SystemExit(2)

    model = "qwen3-coder:30b"

    try:
        criteria_path = _discover_criteria_path()
        # 기본 out-dir('out')이 방금 스캔한 폴더(=cwd)와 충돌하면(사용자가
        # 결과 폴더 안에서 바로 실행한 흔한 경우) 저장소 루트 out/으로
        # 조용히 대체한다 — 대화형 모드는 --out-dir을 물어보지 않으므로
        # 여기서 막히면 사용자가 다시 CLI로 돌아가야 해 UX가 깨진다.
        out_dir = _resolve_out_dir("out", report_path, criteria_path)
        base = os.path.splitext(os.path.basename(report_path))[0]
        json_out = os.path.join(out_dir, f"result_{base}.json")
        xlsx_out = os.path.join(out_dir, f"result_{base}.xlsx")
        client = OllamaClient(url="http://localhost:11434", model=model)
        cov = run(report_path, criteria_path, profile_key, client,
                 json_out, xlsx_out, model)
    except (ReportError, OSError) as e:
        print(f"오류: {e}", file=sys.stderr)
        raise SystemExit(2) from e

    print(f"\n판정 {cov['judged']}/{cov['expected']} 완료. 미판정: {cov['missing']}")
    print(f"출력: {json_out}\n      {xlsx_out}")


def main(argv=None):
    # 무인자 대화형 진입: 실제 CLI 인자가 0개이고 표준입력이 tty일 때만
    # (파이프/CI 등 비대화형 환경에서는 기존 argparse 동작을 그대로 유지 —
    # pytest처럼 stdin이 tty가 아닌 환경은 이 분기에 절대 들어오지 않는다).
    resolved_argv = sys.argv[1:] if argv is None else argv
    if not resolved_argv and sys.stdin.isatty():
        return _interactive_main()

    ap = argparse.ArgumentParser(
        description="클라우드 점검 결과 LLM 자동 판단 도구")
    ap.add_argument("report_positional", nargs="?", default=None,
                    metavar="REPORT",
                    help="점검 결과 파일/폴더 경로(위치인자, --report와 동일. "
                         "예: python3 -m judge_tool result.xml)")
    ap.add_argument("--report", default=None,
                    help="점검 결과 파일 경로(디렉터리 지정 시 배치 판정). "
                         "위치인자로도 지정 가능.")
    ap.add_argument("--criteria", default=None,
                    help="평가기준 xlsx 경로. 미지정 시 ref/ 아래 "
                         "'*평가기준*제*호*.xlsx'를 자동탐색(복수면 최신 "
                         "'제N호' 선택).")
    ap.add_argument("--profile", default=None,
                    help="미지정 시 파일명/확장자로 자동추정. 모호하거나 "
                         "추정 불가면 후보를 안내하고 종료.")
    ap.add_argument("--variant", default=None,
                    help="변형 강제 지정(파일명 자동식별을 건너뜀). "
                         "예: oracle_native, mysql_rds")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--model", default="qwen3-coder:30b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--skip-preflight", "--no-llm-gate",
                    action="store_true", default=False,
                    help="pre-flight 인코딩 교정·LLM 게이트 및 Ollama "
                         "헬스체크를 건너뜀(테스트/오프라인 모드용). "
                         "기본은 활성화.")
    # ── Phase 4c-a: hashcat 연동 옵션 ─────────────────────────────────────────
    ap.add_argument(
        "--hashcat-path", default=None, metavar="PATH",
        help="hashcat 바이너리 경로 (미지정 시 PATH 자동탐지; 없으면 (a) 비활성).",
    )
    ap.add_argument(
        "--hashcat-wordlist", default=None, metavar="PATH",
        help="hashcat wordlist 파일 경로 (미지정 시 내장 pwdict 사전 사용).",
    )
    ap.add_argument(
        "--hashcat-rules", default=None, metavar="PATH",
        help="hashcat rules 파일 경로 (선택; 벤더 fsi_custom.rule 등).",
    )
    ap.add_argument(
        "--hashcat-timeout", default=600, type=int, metavar="SEC",
        help="hashcat 단일 모드 실행 timeout(초). 기본 600.",
    )
    # ── B′-3b: FW 그룹객체(named object) 해석 테이블 ──────────────────────────
    ap.add_argument(
        "--aux-objects", default=None, metavar="PATH",
        help="FW 그룹객체(주소/서비스 그룹) 정의 YAML 경로(캐노니컬 포맷은 "
             "judge_tool/fw_objects.py 참조). fw 프로파일에서만 사용 — "
             "미지정 시 기존 동작과 동일(그룹 미해석 정책은 판단보류).",
    )
    args = ap.parse_args(argv)

    # 위치인자와 --report를 동시에, 그것도 서로 다르게 지정하면 어느 하나가
    # 조용히 무시되어 "지정한 파일이 판정 안 됨"이 된다(M-4) — 명시적으로 거부.
    if (args.report_positional and args.report
            and os.path.abspath(args.report_positional) != os.path.abspath(args.report)):
        print("오류: 위치인자와 --report에 서로 다른 경로가 지정되었습니다 "
              f"('{args.report_positional}' vs '{args.report}'). 하나만 지정하세요.",
              file=sys.stderr)
        raise SystemExit(2)
    args.report = args.report or args.report_positional
    if not args.report:
        print("오류: 점검 결과 파일/폴더 경로가 필요합니다 "
              "(위치인자 또는 --report로 지정하세요).", file=sys.stderr)
        raise SystemExit(2)

    try:
        if args.criteria is None:
            args.criteria = _discover_criteria_path()

        # 배치 모드: --report가 디렉터리면 폴더 안 파일들을 순차 판정.
        if os.path.isdir(args.report):
            _run_batch(args)
            return

        args.profile = _resolve_profile(args.report, args.profile)

        _guard_out_dir(args.out_dir, args.report, args.criteria)

        base = os.path.splitext(os.path.basename(args.report))[0]
        json_out = os.path.join(args.out_dir, f"result_{base}.json")
        xlsx_out = os.path.join(args.out_dir, f"result_{base}.xlsx")

        # Phase 4c-a: hashcat 옵션 조립 (바이너리 지정 또는 PATH 자동탐지; 없으면 None)
        hashcat_opts = _hashcat_opts_from_args(args)

        client = OllamaClient(url=args.ollama_url, model=args.model)
        cov = run(args.report, args.criteria, args.profile, client,
                  json_out, xlsx_out, args.model,
                  variant_override=args.variant,
                  skip_preflight=args.skip_preflight,
                  hashcat_opts=hashcat_opts,
                  aux_objects_path=args.aux_objects)
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

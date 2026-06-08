import argparse
import hashlib
import logging
import os
import re
import sys
from datetime import datetime
from typing import Dict, Optional

from judge_tool import __version__
from judge_tool.criteria_loader import load_criteria
from judge_tool.errors import ReportError
from judge_tool.judge import OllamaClient, judge_item, reconcile, summarize_item
from judge_tool.mapper import aggregate
from judge_tool.models import Judgment
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


def _summarize_one(crit, item, item_id: str, variant: str, client,
                   profile) -> Optional[Judgment]:
    """B 라벨: LLM으로 증거 요약. verdict=판단보류 고정.

    예외: empty_means_good 항목에서 증거가 0건이면 LLM 없이 양호로 처리.
    (예: DBM-024 빈 결과 = GRANT OPTION 없음 = 양호)
    """
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
            j.label = "B"
            return j
        except Exception as e:  # noqa: BLE001
            log.warning("B항목 빈결과 reconcile 실패 item=%s type=%s",
                        item_id, type(e).__name__)
            return None

    summary = summarize_item(crit, item, client, evidence_mode=profile.evidence_mode)
    forced = {"verdict": "판단보류", "confidence": 0.0,
              "rationale": "[B항목: 담당자 인터뷰 필요] " + (crit.summary_instruction or ""),
              "cited_evidence": []}
    try:
        j = _reconcile(forced)
        j.label = "B"
        j.interview_summary = summary
        return j
    except Exception as e:  # noqa: BLE001
        log.warning("B항목 reconcile 실패, 스킵 item=%s variant=%s type=%s",
                    item_id, variant, type(e).__name__)
        return None


def _judge_one(crit, item, item_id: str, variant: str, client,
               profile) -> Optional[Judgment]:
    """단일 항목을 판정한다. 프로파일 속성으로 evidence/판정 모드를 결정하며
    부분 실패를 격리하는 견고성 로직:

    - NOTE 보유 항목 → LLM 호출 없이 판단보류 강제(empty_means_good보다 우선)
    - judge 실패 → 판단보류 폴백으로 reconcile (격리, 결과 포함)
    - 폴백 reconcile 마저 실패 → 해당 항목만 스킵(None 반환)
    """
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
        note = note_m.group(1).strip()
        forced = {"verdict": "판단보류", "confidence": 0.0,
                  "rationale": f"[자동 판단보류: NOTE] {note}".strip(),
                  "cited_evidence": []}
        return _reconcile(forced)
    try:
        llm = judge_item(crit, item, client,
                         evidence_mode=profile.evidence_mode)
        j = _reconcile(llm)
        j.label = "A"
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
        now: Optional[str] = None) -> Dict:
    profile = get_profile(profile_key)
    variant = profile.variant_from_filename(report_path)
    if variant is None:
        raise ReportError(f"파일명에서 variant를 식별할 수 없음: {report_path}")

    criteria = load_criteria(criteria_path, profile, profile_key=profile_key)
    parser = get_parser(profile.parser)
    raw_checks = parser.parse(report_path)
    items = aggregate(raw_checks, variant, profile)

    judgments = []
    judged_ids: set = set()

    for item_id, item in items.items():
        crit = criteria.get((item_id, variant))
        if crit is None or not crit.is_judgeable:
            continue  # 기준에 없거나 스크립트 대상 아님/빈 판단기준 → 스킵
        label = crit.label
        if label in ("C", "D"):
            judgment = _auto_defer(crit, item, profile)
        elif label == "B":
            judgment = _summarize_one(crit, item, item_id, variant, client, profile)
        else:  # A (기본)
            judgment = _judge_one(crit, item, item_id, variant, client, profile)
        if judgment is not None:
            judgments.append(judgment)
            judged_ids.add(item_id)

    # C/D 라벨 항목은 보고서에 증거가 없어도 자동보류를 생성한다.
    # (예: DBM-025 버전 섹션이 보고서에 없는 경우에도 canned_message 출력)
    for (crit_id, crit_variant), crit in criteria.items():
        if crit_variant != variant or not crit.is_judgeable:
            continue
        if crit.label not in ("C", "D") or crit_id in judged_ids:
            continue
        # 증거 없는 빈 EvidenceItem 생성
        from judge_tool.models import EvidenceItem as _EI
        dummy_item = _EI(item_id=crit_id, variant=variant, resources=[])
        judgment = _auto_defer(crit, dummy_item, profile)
        if judgment is not None:
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
                  json_out, xlsx_out, args.model)
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

"""듀얼런 하니스 — Phase 1 활성화.

det_common(결정론) verdict vs LLM verdict를 동일 item에 대해 이중 실행하고
불일치를 분류·집계한다.

결과는 results/ 불가침 → out/ 에만 저장.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# CLI 직접 실행 시 프로젝트 루트를 sys.path에 추가 (python3 tests/det_dual_run.py 지원)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

log = logging.getLogger(__name__)

# 어댑터 등록 부작용 — main.py와 동일하게 세 어댑터를 모두 활성화
import judge_tool.det_adapters.server as _server_adapter   # noqa: F401,E402
import judge_tool.det_adapters.container as _container_adapter  # noqa: F401,E402
import judge_tool.det_adapters.webwas as _webwas_adapter   # noqa: F401,E402

# 파이프라인 컴포넌트 — 테스트에서 patch("tests.det_dual_run.X") 로 교체 가능하게
# 모듈 레벨에서 임포트한다.  run_dual()은 이 이름들을 직접 사용한다.
from judge_tool.criteria_loader import load_criteria          # noqa: E402
from judge_tool.mapper import aggregate                        # noqa: E402
from judge_tool.main import (                                  # noqa: E402
    JudgeContext,
    _build_thresholds,
    _judge_one,
    _det_common_handler,
    _raw_evidence_for_det,
)
from judge_tool.parsers import get_parser                      # noqa: E402
from judge_tool.profile import get_profile                     # noqa: E402


@dataclass
class DualRunRecord:
    """단일 항목의 결정론/LLM 이중 판정 결과."""
    item_id: str
    variant: str
    det_verdict: Optional[str] = None       # 결정론 판정 결과
    det_rationale: Optional[str] = None     # 결정론 근거
    det_handled: bool = False               # 어댑터 handled 플래그
    llm_verdict: Optional[str] = None       # LLM 판정 결과
    llm_rationale: Optional[str] = None     # LLM 근거
    diff_class: Optional[str] = None        # 불일치 분류: 'det_bug'|'llm_mismatch'|'threshold'|'review'
    notes: str = ""


@dataclass
class DualRunResult:
    """듀얼런 전체 실행 결과."""
    records: List[DualRunRecord] = field(default_factory=list)
    total: int = 0
    matched: int = 0
    mismatched: int = 0
    det_only: int = 0     # 결정론만 실행된 항목 수(LLM 미실행)
    skipped: int = 0      # det_common 미라벨 → 스킵


def _run_det(crit, item, ctx) -> tuple:
    """결정론 어댑터를 직접 호출해 (verdict, rationale, handled) 를 반환.

    _det_common_handler는 내부에서 어댑터→reconcile→Judgment까지 처리한다.
    handled 플래그를 정확히 얻으려면 어댑터를 한 번 더 직접 호출한다.
    어댑터가 없거나 gate()가 ABSENT면 handled=False.
    """
    from judge_tool.det_adapters import base as det_base

    adapter = det_base.get_adapter(ctx.profile_key)
    handled = False

    if adapter is not None:
        # gate 통과 여부 확인
        gate_result = det_base.gate(crit.item_id, ctx.variant)
        if gate_result is None or gate_result.handled:
            raw = _raw_evidence_for_det(item)
            thresholds = ctx.thresholds.get(crit.item_id, {})
            try:
                fv = adapter(crit.item_id, raw, ctx.variant, thresholds,
                             context=item.context if item else None)
                handled = fv.handled
            except Exception as e:  # noqa: BLE001
                log.warning("det 어댑터 직접 호출 실패 item=%s: %s", crit.item_id, type(e).__name__)

    # _det_common_handler로 Judgment 획득
    try:
        judgment = _det_common_handler(crit, item, ctx)
    except Exception as e:  # noqa: BLE001
        log.warning("_det_common_handler 실패 item=%s: %s", crit.item_id, type(e).__name__)
        return None, None, False

    if judgment is None:
        return None, None, handled

    return judgment.verdict, judgment.rationale, handled


def classify_diff(rec: DualRunRecord) -> str:
    """단일 불일치 레코드의 분류를 반환한다.

    휴리스틱 분류 (자동으로 det_bug를 단정하지 않음):
      - det=양호, llm=취약 → 'review' (결정론이 양호를 냈지만 LLM이 취약 → 검토 필요)
        : det_bug 의심이나 LLM 과탐 가능성도 있어 자동 단정 금지
      - det=취약, llm=양호 → 'llm_mismatch' (검증된 결정론 취약 vs LLM 양호 → LLM 오판 의심)
      - 그 외 조합 → 'review'
    """
    det = rec.det_verdict
    llm = rec.llm_verdict

    if det == "양호" and llm == "취약":
        return "review"  # det_bug 또는 LLM 과탐 — notes에 양측 근거 기록
    if det == "취약" and llm == "양호":
        return "llm_mismatch"  # 결정론이 취약 확정인데 LLM이 양호 → LLM 오판 의심
    if det == "취약" and llm == "판단보류":
        return "llm_mismatch"  # 결정론 취약 vs LLM 보류 → LLM이 결론 내지 못한 경우
    if det == "양호" and llm == "판단보류":
        return "review"  # 결정론 양호 vs LLM 보류 → 임계값 또는 증거 해석 차이
    return "review"


def run_dual(
    report_path: str,
    criteria_path: str,
    profile_key: str,
    *,
    llm_client=None,
    variant: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> DualRunResult:
    """결정론과 LLM을 동일 item에 대해 이중 실행한다.

    Args:
        report_path: 점검 결과 파일 경로
        criteria_path: 평가기준 xlsx 경로
        profile_key: 프로파일 키 (예: 'server', 'db_mysql')
        llm_client: LLM 클라이언트 (OllamaClient 등). None이면 LLM 스킵.
        variant: 변형 강제 지정. None이면 자동 식별.
        item_ids: 특정 항목만 실행. None이면 전체.

    Returns:
        DualRunResult: 이중 판정 결과 집계
    """
    from judge_tool.errors import ReportError

    # 프로파일 로드
    try:
        profile = get_profile(profile_key)
    except KeyError as e:
        raise ReportError(str(e)) from e

    if profile.excluded:
        raise ReportError(
            f"프로파일 '{profile_key}'은 현재 판정 대상에서 배제됨")

    # 파서 로드 + variant 식별
    parser = get_parser(profile.parser)
    if variant is not None:
        if variant not in profile.variants:
            raise ReportError(
                f"알 수 없는 variant: {variant} "
                f"(사용 가능: {list(profile.variants)})")
        resolved_variant = variant
    else:
        resolved_variant = profile.variant_from_filename(report_path)
        if resolved_variant is None and hasattr(parser, "detect_variant"):
            resolved_variant = parser.detect_variant(report_path)
    if resolved_variant is None:
        raise ReportError(
            f"variant 식별 실패: {report_path}. --variant로 직접 지정하세요 "
            f"(사용 가능: {list(profile.variants)}).")

    # criteria + items
    criteria = load_criteria(criteria_path, profile, profile_key=profile_key)
    raw_checks = parser.parse(report_path)
    items = aggregate(raw_checks, resolved_variant, profile)

    ctx_det = JudgeContext(
        profile=profile, profile_key=profile_key,
        client=None,  # 결정론 경로: LLM 클라이언트 불필요 (어댑터 직접 호출)
        items=items, variant=resolved_variant,
        thresholds=_build_thresholds(criteria),
    )
    ctx_llm = JudgeContext(
        profile=profile, profile_key=profile_key,
        client=llm_client,
        items=items, variant=resolved_variant,
        thresholds=_build_thresholds(criteria),
    )

    result = DualRunResult()

    for item_id, item in items.items():
        crit = criteria.get((item_id, resolved_variant))
        if crit is None or not crit.is_judgeable:
            continue
        if crit.judgment_method != "det_common":
            result.skipped += 1
            continue
        if item_ids is not None and item_id not in item_ids:
            result.skipped += 1
            continue

        result.total += 1
        rec = DualRunRecord(item_id=item_id, variant=resolved_variant)

        # ── 결정론 실행 ──────────────────────────────────────────────────────
        det_verdict, det_rationale, det_handled = _run_det(crit, item, ctx_det)
        rec.det_verdict = det_verdict
        rec.det_rationale = det_rationale
        rec.det_handled = det_handled

        # ── LLM 실행 ─────────────────────────────────────────────────────────
        if llm_client is not None:
            try:
                llm_judgment = _judge_one(crit, item, ctx_llm)
                if llm_judgment is not None:
                    rec.llm_verdict = llm_judgment.verdict
                    rec.llm_rationale = llm_judgment.rationale
                else:
                    rec.notes = (rec.notes + " [LLM: _judge_one None 반환]").strip()
            except Exception as e:  # noqa: BLE001
                rec.notes = (rec.notes + f" [LLM 오류: {type(e).__name__}]").strip()
                log.warning("LLM 호출 실패 item=%s type=%s", item_id, type(e).__name__)
        else:
            result.det_only += 1

        # ── diff 분류 ─────────────────────────────────────────────────────────
        if rec.llm_verdict is None:
            # LLM 미실행(det_only) 또는 LLM 실패
            pass
        elif rec.det_verdict == rec.llm_verdict:
            result.matched += 1
        elif (rec.det_verdict == "판단보류" and rec.llm_verdict == "판단보류"):
            result.matched += 1
        else:
            result.mismatched += 1
            rec.diff_class = classify_diff(rec)
            # notes에 양측 근거 기록 (사람 triage용)
            det_short = (rec.det_rationale or "")[:200]
            llm_short = (rec.llm_rationale or "")[:200]
            rec.notes = (
                rec.notes
                + f" [det근거] {det_short} [llm근거] {llm_short}"
            ).strip()

        result.records.append(rec)

    return result


def diff_table(result: DualRunResult) -> str:
    """불일치 항목을 분류해 텍스트 표로 반환한다."""
    lines = []
    lines.append("=" * 90)
    lines.append("듀얼런 결과 표 (결정론 vs LLM)")
    lines.append("=" * 90)

    # 헤더
    col_w = [12, 14, 10, 10, 8, 14, 40]
    header = (
        f"{'item_id':<12} {'variant':<14} {'det':<10} {'llm':<10} "
        f"{'match':<8} {'diff_class':<14} {'notes':<40}"
    )
    lines.append(header)
    lines.append("-" * 90)

    for rec in result.records:
        if rec.llm_verdict is None:
            match_str = "det_only"
        elif rec.det_verdict == rec.llm_verdict:
            match_str = "O"
        else:
            match_str = "X"

        notes_short = (rec.notes or "")[:38]
        row = (
            f"{rec.item_id:<12} {rec.variant:<14} "
            f"{(rec.det_verdict or '-'):<10} {(rec.llm_verdict or '-'):<10} "
            f"{match_str:<8} {(rec.diff_class or '-'):<14} {notes_short:<40}"
        )
        lines.append(row)

    lines.append("=" * 90)
    lines.append(f"합계:   total={result.total}")
    lines.append(f"  matched={result.matched}  mismatched={result.mismatched}  "
                 f"det_only={result.det_only}  skipped={result.skipped}")
    if result.total > 0:
        match_rate = (result.matched / (result.total - result.det_only) * 100
                      if (result.total - result.det_only) > 0 else 0.0)
        lines.append(f"  일치율(LLM 실행 항목): {match_rate:.1f}%")

    # 불일치 상세
    mismatch_recs = [r for r in result.records if r.diff_class is not None]
    if mismatch_recs:
        lines.append("")
        lines.append("── 불일치 상세 ──")
        for rec in mismatch_recs:
            lines.append(
                f"  [{rec.item_id}] det={rec.det_verdict} llm={rec.llm_verdict} "
                f"class={rec.diff_class}"
            )
            if rec.notes:
                for chunk in [rec.notes[i:i+80] for i in range(0, len(rec.notes), 80)]:
                    lines.append(f"    {chunk}")

    return "\n".join(lines)


def save_results(result: DualRunResult, profile_key: str, variant: str,
                 out_dir: str = "out") -> tuple:
    """결과를 out/ 에 저장한다. (json_path, table_path) 반환."""
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"dualrun_{profile_key}_{variant}_{ts}"

    json_path = os.path.join(out_dir, f"{stem}.json")
    table_path = os.path.join(out_dir, f"{stem}_table.txt")

    # JSON 직렬화 (dataclass → dict)
    def _rec_to_dict(r: DualRunRecord) -> dict:
        return {
            "item_id": r.item_id,
            "variant": r.variant,
            "det_verdict": r.det_verdict,
            "det_rationale": r.det_rationale,
            "det_handled": r.det_handled,
            "llm_verdict": r.llm_verdict,
            "llm_rationale": r.llm_rationale,
            "diff_class": r.diff_class,
            "notes": r.notes,
        }

    payload = {
        "summary": {
            "total": result.total,
            "matched": result.matched,
            "mismatched": result.mismatched,
            "det_only": result.det_only,
            "skipped": result.skipped,
        },
        "records": [_rec_to_dict(r) for r in result.records],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    table_text = diff_table(result)
    with open(table_path, "w", encoding="utf-8") as fh:
        fh.write(table_text)

    return json_path, table_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="듀얼런 하니스: 결정론(det_common) vs LLM 대조")
    ap.add_argument("--report", required=True, help="점검 결과 파일 경로")
    ap.add_argument("--criteria", required=True, help="평가기준 xlsx 경로")
    ap.add_argument("--profile", required=True, help="프로파일 키 (예: server)")
    ap.add_argument("--variant", default=None, help="변형 강제 지정")
    ap.add_argument("--model", default="qwen3-coder:30b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--items", default=None,
                    help="쉼표 구분 item_id 리스트 (예: SRV-001,SRV-002). "
                         "미지정 시 전체.")
    ap.add_argument("--no-llm", action="store_true",
                    help="LLM 호출 없이 결정론만 실행 (det_only 모드)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    item_ids_filter = None
    if args.items:
        item_ids_filter = [s.strip() for s in args.items.split(",") if s.strip()]

    llm_client = None
    if not args.no_llm:
        from judge_tool.judge import OllamaClient
        llm_client = OllamaClient(url=args.ollama_url, model=args.model)

    print(f"듀얼런 시작: profile={args.profile} variant={args.variant or '자동'} "
          f"model={args.model if not args.no_llm else 'N/A(det-only)'}")

    dr = run_dual(
        args.report, args.criteria, args.profile,
        llm_client=llm_client,
        variant=args.variant,
        item_ids=item_ids_filter,
    )

    table = diff_table(dr)
    print(table)

    resolved_variant = dr.records[0].variant if dr.records else (args.variant or "unknown")
    json_path, table_path = save_results(dr, args.profile, resolved_variant, args.out_dir)
    print(f"\n출력:")
    print(f"  JSON : {json_path}")
    print(f"  표   : {table_path}")

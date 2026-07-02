#!/usr/bin/env python3
"""방화벽(FW) 정책 파일 일괄 검증 — B'-1 갭메우기 배치 하네스.

ref/FW/보안장비 결과/ 전 파일에 대해 judge_tool.main.run()을 실행하고,
성공여부·sniff 포맷·정책수·ISS-030~037/041 판정 분포·parse_stats만
숫자로 stdout에 요약한다.

🔒 대외비 경계: 이 스크립트는 셀 데이터·IP·정책명을 **절대 출력하지 않는다**.
산출물(out-dir json)은 내부적으로 읽어 verdict 문자열(양호/취약/판단보류)만
집계하고, 실제 rationale/evidence 텍스트는 읽지 않는다.

사용:
    python3 scripts/fw_batch_validate.py
    python3 scripts/fw_batch_validate.py --data-dir "ref/FW/보안장비 결과" \\
        --criteria "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx" \\
        --out-dir out/fw_batch
"""
import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from judge_tool.main import run  # noqa: E402
from judge_tool.parsers import fw_policy_xlsx  # noqa: E402

_DEFAULT_DATA_DIR = "ref/FW/보안장비 결과"
_DEFAULT_CRITERIA = (
    "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx"
)
_DEFAULT_OUT_DIR = "out/fw_batch"

_FW_ISS_IDS = [
    "ISS-030", "ISS-031", "ISS-032", "ISS-033", "ISS-034",
    "ISS-035", "ISS-036", "ISS-037", "ISS-041",
]
_VERDICTS = ["양호", "취약", "판단보류"]


def _file_label(fname: str) -> str:
    """파일명에서 'P02_정책.xlsx' -> 'P02' 같은 짧은 라벨 추출."""
    m = re.match(r"^(P\d+)", fname)
    return m.group(1) if m else os.path.splitext(fname)[0]


def _sniff_stats(report_path: str) -> Tuple[str, int, Dict]:
    """파서를 직접 호출해 (포맷, 정책수, parse_stats)만 추출한다.

    실패해도 배치 전체를 막지 않도록 호출측에서 예외를 잡는다.
    """
    result = fw_policy_xlsx.parse(report_path)
    context = result[0][2] if result else ""
    fmt = "unknown"
    policy_count = 0
    parse_stats: Dict = {}
    for line in context.splitlines():
        if line.startswith("FW_FORMAT:"):
            fmt = line[len("FW_FORMAT:"):].strip()
        elif line.startswith("FW_POLICY_COUNT:"):
            try:
                policy_count = int(line[len("FW_POLICY_COUNT:"):].strip())
            except ValueError:
                policy_count = 0
        elif line.startswith("FW_PARSE_STATS_JSON:"):
            try:
                parse_stats = json.loads(line[len("FW_PARSE_STATS_JSON:"):].strip())
            except Exception:  # noqa: BLE001
                parse_stats = {}
    return fmt, policy_count, parse_stats


def _verdict_distribution(json_out_path: str) -> Dict[str, Dict[str, int]]:
    """산출물 json을 내부적으로 읽어 ISS항목별 verdict 건수만 집계한다.

    rationale/cited_evidence 등 정책 내용이 담긴 필드는 절대 읽지 않는다
    (item_id/verdict 두 필드만 사용).
    """
    with open(json_out_path, encoding="utf-8") as f:
        payload = json.load(f)
    dist: Dict[str, Dict[str, int]] = {
        iss_id: {v: 0 for v in _VERDICTS} for iss_id in _FW_ISS_IDS
    }
    for j in payload.get("judgments", []):
        item_id = j.get("item_id", "")
        verdict = j.get("verdict", "")
        if item_id in dist and verdict in _VERDICTS:
            dist[item_id][verdict] += 1
    return dist


def _run_one(report_path: str, criteria_path: str, out_dir: str) -> Dict:
    """파일 하나를 처리해 숫자 집계 결과 dict를 반환. 예외를 삼키지 않고 기록."""
    label = _file_label(os.path.basename(report_path))
    entry: Dict = {"label": label, "file": os.path.basename(report_path)}

    try:
        fmt, policy_count, parse_stats = _sniff_stats(report_path)
        entry["sniff_fmt"] = fmt
        entry["policy_count"] = policy_count
        entry["parse_stats"] = parse_stats
    except Exception as e:  # noqa: BLE001
        entry["sniff_error"] = type(e).__name__

    os.makedirs(out_dir, exist_ok=True)
    json_out = os.path.join(out_dir, "result.json")
    xlsx_out = os.path.join(out_dir, "result.xlsx")

    try:
        run(
            report_path=report_path,
            criteria_path=criteria_path,
            profile_key="iss",
            client=None,
            json_out=json_out,
            xlsx_out=xlsx_out,
            model_name="n/a",
            skip_preflight=True,
        )
        entry["success"] = True
        entry["verdict_dist"] = _verdict_distribution(json_out)
    except Exception as e:  # noqa: BLE001
        entry["success"] = False
        entry["error_type"] = type(e).__name__
        entry["error_msg"] = str(e)[:200]

    return entry


def _print_table(results: List[Dict]) -> None:
    print(f"\n{'파일':10} {'성공':6} {'포맷':10} {'정책수':8} "
          f"{'행총':6} {'행drop':7} {'미인식act':9}")
    print("-" * 70)
    for r in results:
        ok = "OK" if r.get("success") else "FAIL"
        fmt = r.get("sniff_fmt", "?")
        pc = r.get("policy_count", "?")
        ps = r.get("parse_stats", {}) or {}
        rt = ps.get("rows_total", "-")
        rd = ps.get("rows_dropped", "-")
        ua = ps.get("unrecognized_action_count", "-")
        print(f"{r['label']:10} {ok:6} {fmt:10} {pc!s:8} {rt!s:6} {rd!s:7} {ua!s:9}")
        if not r.get("success"):
            print(f"    └─ error={r.get('error_type')}: {r.get('error_msg')}")

    print(f"\n{'파일':10} " + " ".join(f"{iid:>18}" for iid in _FW_ISS_IDS))
    print("-" * (10 + 19 * len(_FW_ISS_IDS)))
    for r in results:
        dist = r.get("verdict_dist")
        if not dist:
            print(f"{r['label']:10} (판정 분포 없음 — 실행 실패)")
            continue
        cells = []
        for iid in _FW_ISS_IDS:
            d = dist.get(iid, {})
            cells.append(f"양{d.get('양호',0)}/취{d.get('취약',0)}/보{d.get('판단보류',0)}")
        print(f"{r['label']:10} " + " ".join(f"{c:>18}" for c in cells))

    total = len(results)
    succ = sum(1 for r in results if r.get("success"))
    print(f"\n총 {total}개 파일 중 성공 {succ} / 실패 {total - succ}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="FW 정책 파일 일괄 검증(숫자만 출력)")
    ap.add_argument("--data-dir", default=_DEFAULT_DATA_DIR)
    ap.add_argument("--criteria", default=_DEFAULT_CRITERIA)
    ap.add_argument("--out-dir", default=_DEFAULT_OUT_DIR)
    args = ap.parse_args(argv)

    files = sorted(
        f for f in os.listdir(args.data_dir)
        if f.lower().endswith((".xlsx", ".csv")) and not f.startswith("~$")
    )

    results = []
    for fname in files:
        report_path = os.path.join(args.data_dir, fname)
        label = _file_label(fname)
        file_out_dir = os.path.join(args.out_dir, label)
        entry = _run_one(report_path, args.criteria, file_out_dir)
        results.append(entry)

    _print_table(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

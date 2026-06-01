import argparse
import hashlib
import os
from datetime import datetime
from typing import Dict, Optional

from judge_tool import __version__
from judge_tool.criteria_loader import load_criteria
from judge_tool.judge import OllamaClient, judge_item, reconcile
from judge_tool.mapper import aggregate
from judge_tool.parsers import cloud_xml
from judge_tool.profile import get_profile
from judge_tool.writer import build_coverage, write_excel, write_json

_PARSERS = {"cloud_xml": cloud_xml}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run(report_path: str, criteria_path: str, profile_key: str, client,
        json_out: str, xlsx_out: str, model_name: str,
        now: Optional[str] = None) -> Dict:
    profile = get_profile(profile_key)
    variant = profile.variant_from_filename(report_path)
    if variant is None:
        raise ValueError(f"파일명에서 variant를 식별할 수 없음: {report_path}")

    criteria = load_criteria(criteria_path, profile)
    raw_checks = _PARSERS[profile.parser].parse(report_path)
    items = aggregate(raw_checks, variant, profile)

    judgments = []
    for item_id, item in items.items():
        crit = criteria.get((item_id, variant))
        if crit is None or not crit.is_script_based or crit.eval_type == "N/A":
            continue  # 기준에 없거나 스크립트 대상 아님 → 스킵
        llm = judge_item(crit, item, client)
        judgments.append(reconcile(llm, crit, item))

    judgments.sort(key=lambda j: j.item_id)
    coverage = build_coverage(criteria, judgments, variant)
    meta = {
        "tool_version": __version__,
        "criteria_version": "제2026-1호",
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

    base = os.path.splitext(os.path.basename(args.report))[0]
    json_out = os.path.join(args.out_dir, f"result_{base}.json")
    xlsx_out = os.path.join(args.out_dir, f"result_{base}.xlsx")

    client = OllamaClient(url=args.ollama_url, model=args.model)
    cov = run(args.report, args.criteria, args.profile, client,
              json_out, xlsx_out, args.model)
    print(f"판정 {cov['judged']}/{cov['expected']} 완료. "
          f"미판정: {cov['missing']}")
    print(f"출력: {json_out}\n      {xlsx_out}")


if __name__ == "__main__":
    main()

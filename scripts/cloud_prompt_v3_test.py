#!/usr/bin/env python3
"""
프롬프트 v2 효과 검증 — 30b/14b/7b 각 1회
기존 결과(out/model_experiment)와 verdict 비교.
변화 있는 항목(특히 PISM-023/036)에 집중.
"""
import json, os, sys, datetime, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORT   = str(ROOT / "results/Public Cloud/aws_report_20251223_hinno.xml")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "prompt_v3"

MODELS = [
    ("qwen3-coder:30b",    "out/model_experiment/qwen3-coder_30b/run1/result.json"),
    ("qwen2.5-coder:14b",  "out/model_experiment/qwen2.5-coder_14b/run1/result.json"),
    ("qwen2.5-coder:7b",   "out/model_experiment/qwen2.5-coder_7b/run1/result.json"),
]

FOCUS_IDS = {"PISM-023", "PISM-036"}  # 이전에 오류났던 항목

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient
from judge_tool.main import run as tool_run


def run_test():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log_path = OUT_BASE / "test.log"

    with open(log_path, "w") as log:
        def tee(msg):
            print(msg)
            log.write(msg + "\n")
            log.flush()

        tee(f"=== 프롬프트 v2 검증: {datetime.datetime.now().isoformat()} ===\n")

        for model, old_path in MODELS:
            run_dir = OUT_BASE / model.replace(":", "_").replace("/", "_")
            run_dir.mkdir(parents=True, exist_ok=True)
            json_out = str(run_dir / "result.json")
            xlsx_out = str(run_dir / "result.xlsx")

            tee(f"\n--- {model} ---")
            t0 = time.time()
            client = OllamaClient(model=model, temperature=0.0)
            cov = tool_run(
                report_path=REPORT, criteria_path=CRITERIA,
                profile_key="cloud", client=client,
                json_out=json_out, xlsx_out=xlsx_out, model_name=model,
            )
            elapsed = time.time() - t0
            tee(f"  완료: {elapsed:.0f}s, 판정 {cov['judged']}/{cov['expected']}")

            # 이전 결과와 비교
            new  = {j["item_id"]: j for j in json.load(open(json_out))["judgments"]}
            old  = {j["item_id"]: j for j in json.load(open(ROOT / old_path))["judgments"]}
            opus = {j["item_id"]: j for j in
                    json.load(open(ROOT / "out/opus_experiment/run1/result.json"))["judgments"]}

            changed = [i for i in sorted(new) if new[i]["verdict"] != old.get(i, {}).get("verdict")]
            tee(f"  변화 항목 ({len(changed)}건): {changed if changed else '없음'}")

            tee(f"\n  [주요 항목 비교]")
            for iid in sorted(set(new.keys()) | FOCUS_IDS):
                if iid not in new:
                    continue
                nv = new[iid]["verdict"]
                ov = old.get(iid, {}).get("verdict", "—")
                ov2 = opus.get(iid, {}).get("verdict", "—")
                arrow = "→" if nv != ov else "  "
                opus_match = "✅" if nv == ov2 else "❌"
                if iid in FOCUS_IDS or nv != ov:
                    tee(f"  {iid}: v1={ov} {arrow} v2={nv}  Opus={ov2} {opus_match}")

        tee("\n=== 완료 ===")

    return log_path


if __name__ == "__main__":
    log = run_test()
    print(f"\n로그: {log}")

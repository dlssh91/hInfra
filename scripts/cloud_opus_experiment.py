#!/usr/bin/env python3
"""
Claude Opus (Anthropic API via claude -p) ×3회 실험
qwen3-coder:30b 기준선 대비 절대비교.
"""
import json, os, sys, datetime, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORT = str(ROOT / "results/Public Cloud/aws_report_20251223_hinno.xml")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "opus_experiment"
MODEL = "claude-opus-4-8"
RUNS = 3

sys.path.insert(0, str(ROOT))
from judge_tool.judge import ClaudeCliClient
from judge_tool.main import run as tool_run


def run_experiment():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log_path = OUT_BASE / "experiment.log"
    runs_verdicts = []

    with open(log_path, "w") as log:
        def tee(msg):
            print(msg)
            log.write(msg + "\n")
            log.flush()

        tee(f"=== Claude Opus ×{RUNS}회 실험: {datetime.datetime.now().isoformat()} ===")
        tee(f"모델: {MODEL}\n")

        for r in range(1, RUNS + 1):
            run_dir = OUT_BASE / f"run{r}"
            run_dir.mkdir(parents=True, exist_ok=True)
            json_out = str(run_dir / "result.json")
            xlsx_out = str(run_dir / "result.xlsx")

            tee(f"[{r}/{RUNS}] 시작: {datetime.datetime.now().strftime('%H:%M:%S')}")
            t0 = time.time()

            client = ClaudeCliClient(model=MODEL, timeout=180)
            cov = tool_run(
                report_path=REPORT,
                criteria_path=CRITERIA,
                profile_key="cloud",
                client=client,
                json_out=json_out,
                xlsx_out=xlsx_out,
                model_name=MODEL,
            )
            elapsed = time.time() - t0
            tee(f"[{r}/{RUNS}] 완료: {elapsed:.0f}s, 판정 {cov['judged']}/{cov['expected']}")

            with open(json_out) as f:
                data = json.load(f)
            v_map = {j["item_id"]: j["verdict"] for j in data["judgments"]}
            runs_verdicts.append(v_map)

        # 결정성 분석
        tee("\n" + "="*60)
        tee("결과 분석")
        tee("="*60)

        all_ids = sorted(set(runs_verdicts[0].keys()))
        agree = sum(1 for id_ in all_ids if len({r.get(id_) for r in runs_verdicts}) == 1)
        pct = agree / len(all_ids) * 100 if all_ids else 0
        tee(f"\n[결정성] {agree}/{len(all_ids)} ({pct:.1f}%) 3회 일치")
        disagree_ids = [id_ for id_ in all_ids if len({r.get(id_) for r in runs_verdicts}) > 1]
        if disagree_ids:
            for id_ in disagree_ids:
                verdicts = [r.get(id_, "-") for r in runs_verdicts]
                tee(f"  불일치: {id_} → {verdicts}")

        # 30b 기준선 대비 비교
        ref_path = ROOT / "out" / "model_experiment" / "qwen3-coder_30b" / "run1" / "result.json"
        if ref_path.exists():
            with open(ref_path) as f:
                ref_data = json.load(f)
            ref_map = {j["item_id"]: j["verdict"] for j in ref_data["judgments"]}
            opus_map = runs_verdicts[0]
            common = set(ref_map.keys()) & set(opus_map.keys())
            match = sum(1 for id_ in common if ref_map[id_] == opus_map[id_])
            tee(f"\n[30b 대비] {match}/{len(common)} ({match/len(common)*100:.1f}%) 일치")
            diff_ids = [id_ for id_ in sorted(common) if ref_map[id_] != opus_map[id_]]
            if diff_ids:
                for id_ in diff_ids:
                    tee(f"  불일치: {id_} — 30b={ref_map[id_]}, Opus={opus_map[id_]}")
            else:
                tee("  30b와 완전 일치")

        # Opus run1 verdict 요약
        with open(str(OUT_BASE / "run1" / "result.json")) as f:
            d1 = json.load(f)
        vcts = {}
        for j in d1["judgments"]:
            vcts[j["verdict"]] = vcts.get(j["verdict"], 0) + 1
        nr = sum(1 for j in d1["judgments"] if j.get("needs_review"))
        tee(f"\n[Opus run1 verdict] {vcts}, needs_review={nr}")

    return runs_verdicts, log_path


if __name__ == "__main__":
    runs_verdicts, log_path = run_experiment()
    print(f"\n로그: {log_path}")

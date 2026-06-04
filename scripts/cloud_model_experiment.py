#!/usr/bin/env python3
"""
클라우드 모델×3 실험 스크립트
모델별(30b/14b/7b) 각 3회 실행 → 결정성 + 30b 대비 일치율 측정
"""
import json, os, sys, datetime, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORT = str(ROOT / "results/Public Cloud/aws_report_20251223_hinno.xml")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "model_experiment"

MODELS = [
    "qwen3-coder:30b",
    "qwen2.5-coder:14b",
    "qwen2.5-coder:7b",
]
RUNS = 3

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient
from judge_tool.main import run as tool_run


def run_experiment():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log_path = OUT_BASE / "experiment.log"

    all_results = {}  # model -> [run1_judgments, run2_judgments, run3_judgments]

    with open(log_path, "w") as log:
        def tee(msg):
            print(msg)
            log.write(msg + "\n")
            log.flush()

        tee(f"=== 클라우드 모델×3 실험 시작: {datetime.datetime.now().isoformat()} ===")

        for model in MODELS:
            all_results[model] = []
            tee(f"\n--- 모델: {model} ---")

            for r in range(1, RUNS + 1):
                run_dir = OUT_BASE / model.replace(":", "_").replace("/", "_") / f"run{r}"
                run_dir.mkdir(parents=True, exist_ok=True)

                json_out = str(run_dir / "result.json")
                xlsx_out = str(run_dir / "result.xlsx")

                tee(f"  [{r}/3] 시작: {datetime.datetime.now().strftime('%H:%M:%S')}")
                t0 = time.time()

                client = OllamaClient(model=model, temperature=0.0)
                result = tool_run(
                    report_path=REPORT,
                    criteria_path=CRITERIA,
                    profile_key="cloud",
                    client=client,
                    json_out=json_out,
                    xlsx_out=xlsx_out,
                    model_name=model,
                )

                elapsed = time.time() - t0
                tee(f"  [{r}/3] 완료: {elapsed:.0f}s, 판정 {result['judged']}/{result['expected']}")

                with open(json_out) as f:
                    data = json.load(f)
                all_results[model].append({j["item_id"]: j["verdict"] for j in data["judgments"]})

    return all_results, log_path


def analyze(all_results):
    models = list(all_results.keys())
    ref_model = models[0]  # 30b

    lines = []
    lines.append("\n" + "="*60)
    lines.append("결과 분석")
    lines.append("="*60)

    # 모델별 결정성 (3회 일치율)
    lines.append("\n[1] 모델별 결정성 (3회 내 일치율)")
    for model in models:
        runs = all_results[model]
        if len(runs) < 2:
            lines.append(f"  {model}: 런 수 부족")
            continue
        all_ids = set(runs[0].keys())
        agree = sum(1 for id_ in all_ids if len({r.get(id_) for r in runs}) == 1)
        pct = agree / len(all_ids) * 100 if all_ids else 0
        lines.append(f"  {model}: {agree}/{len(all_ids)} ({pct:.1f}%) 일치")
        # 불일치 항목 목록
        disagree_ids = [id_ for id_ in sorted(all_ids) if len({r.get(id_) for r in runs}) > 1]
        if disagree_ids:
            for id_ in disagree_ids:
                verdicts = [r.get(id_, "-") for r in runs]
                lines.append(f"    {id_}: {verdicts}")

    # 30b 대비 일치율
    if len(models) > 1:
        lines.append(f"\n[2] 30b 대비 일치율 (run1 기준)")
        ref_run = all_results[ref_model][0]
        for model in models[1:]:
            if not all_results[model]:
                continue
            cmp_run = all_results[model][0]
            all_ids = set(ref_run.keys()) & set(cmp_run.keys())
            agree = sum(1 for id_ in all_ids if ref_run.get(id_) == cmp_run.get(id_))
            pct = agree / len(all_ids) * 100 if all_ids else 0
            lines.append(f"  {ref_model} vs {model}: {agree}/{len(all_ids)} ({pct:.1f}%) 일치")
            disagree_ids = [id_ for id_ in sorted(all_ids) if ref_run.get(id_) != cmp_run.get(id_)]
            if disagree_ids:
                for id_ in disagree_ids:
                    lines.append(f"    {id_}: 30b={ref_run.get(id_)}, {model}={cmp_run.get(id_)}")

    return "\n".join(lines)


if __name__ == "__main__":
    all_results, log_path = run_experiment()
    summary = analyze(all_results)
    print(summary)
    with open(log_path, "a") as f:
        f.write(summary + "\n")
    print(f"\n로그: {log_path}")

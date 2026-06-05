#!/usr/bin/env python3
"""
MySQL DB — 7b/14b/30b 각 3회 + Opus 기준선 비교
결정성(3회 일치율) + Opus 대비 일치율 + 항목별 근거 전체 출력
"""
import json, sys, time, datetime
from pathlib import Path

ROOT     = Path(__file__).parent.parent
REPORT   = str(ROOT / "results/DB/MySQL/mysql_result_rds.txt")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "db_mysql_experiment"
RUNS     = 3

MODELS = [
    "qwen3-coder:30b",
    "qwen2.5-coder:14b",
    "qwen2.5-coder:7b",
]

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient
from judge_tool.main import run as tool_run


def run_experiment():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log = open(OUT_BASE / "experiment.log", "w", buffering=1)

    def tee(msg):
        print(msg)
        log.write(msg + "\n")

    tee(f"=== MySQL DB 모델×3 실험: {datetime.datetime.now().isoformat()} ===\n")
    all_results = {}  # model -> [run1_map, run2_map, run3_map]

    for model in MODELS:
        all_results[model] = []
        tee(f"\n--- {model} ---")
        for r in range(1, RUNS + 1):
            run_dir = OUT_BASE / model.replace(":", "_").replace("/", "_") / f"run{r}"
            run_dir.mkdir(parents=True, exist_ok=True)
            json_out = str(run_dir / "result.json")
            xlsx_out = str(run_dir / "result.xlsx")

            tee(f"  [{r}/{RUNS}] 시작: {datetime.datetime.now().strftime('%H:%M:%S')}")
            t0 = time.time()
            client = OllamaClient(model=model, temperature=0.0)
            cov = tool_run(
                report_path=REPORT, criteria_path=CRITERIA,
                profile_key="db_mysql", client=client,
                json_out=json_out, xlsx_out=xlsx_out, model_name=model,
            )
            elapsed = time.time() - t0
            tee(f"  [{r}/{RUNS}] 완료: {elapsed:.0f}s, 판정 {cov['judged']}/{cov['expected']}")
            vmap = {j["item_id"]: j for j in json.load(open(json_out))["judgments"]}
            all_results[model].append(vmap)

    log.close()
    return all_results


def analyze(all_results):
    opus_path = ROOT / "out/db_mysql_compare/opus/result.json"
    opus_map = ({j["item_id"]: j for j in json.load(open(opus_path))["judgments"]}
                if opus_path.exists() else {})

    lines = []
    lines.append("\n" + "="*70)
    lines.append("분석 결과")
    lines.append("="*70)

    # 결정성
    lines.append("\n[1] 모델별 결정성 (3회 내 일치율)")
    for model, runs in all_results.items():
        all_ids = sorted(set(runs[0].keys()))
        agree = sum(1 for i in all_ids if len({r.get(i,{}).get("verdict") for r in runs}) == 1)
        pct = agree / len(all_ids) * 100 if all_ids else 0
        lines.append(f"  {model}: {agree}/{len(all_ids)} ({pct:.1f}%)")
        unstable = [i for i in all_ids if len({r.get(i,{}).get("verdict") for r in runs}) > 1]
        for i in unstable:
            vs = [r.get(i,{}).get("verdict","-") for r in runs]
            lines.append(f"    불안정: {i} → {vs}")

    # Opus 대비
    if opus_map:
        lines.append("\n[2] Opus 대비 일치율 (run1 기준)")
        for model, runs in all_results.items():
            run1 = runs[0]
            common = set(run1.keys()) & set(opus_map.keys())
            match = sum(1 for i in common if run1[i]["verdict"] == opus_map[i]["verdict"])
            pct = match / len(common) * 100 if common else 0
            lines.append(f"  {model}: {match}/{len(common)} ({pct:.1f}%)")
            diffs = [i for i in sorted(common) if run1[i]["verdict"] != opus_map[i]["verdict"]]
            for i in diffs:
                lines.append(f"    {i}: {model}={run1[i]['verdict']}, Opus={opus_map[i]['verdict']}")

    # 항목별 전체 비교표
    lines.append("\n[3] 항목별 판정 비교 (run1 / Opus 기준)")
    all_ids = sorted(set().union(*[set(r.keys()) for runs in all_results.values() for r in runs]))
    hdr = f"{'항목':<12}"
    for m in MODELS:
        short = m.split(":")[1] if ":" in m else m
        hdr += f" {short:<8}"
    hdr += f" {'Opus':<8}"
    lines.append(hdr)
    lines.append("-" * 60)

    s = {"양호":"양호","취약":"취약","판단보류":"보류"}
    for iid in all_ids:
        row = f"{iid:<12}"
        verdicts = []
        for model, runs in all_results.items():
            v = runs[0].get(iid, {}).get("verdict", "—")
            row += f" {s.get(v,v):<8}"
            verdicts.append(v)
        ov = opus_map.get(iid, {}).get("verdict", "—") if opus_map else "—"
        all_same = len(set(verdicts + [ov])) == 1
        row += f" {s.get(ov,ov):<8} {'✅' if all_same else '❌'}"
        lines.append(row)

    # 불일치 항목 근거 전체
    lines.append("\n[4] 불일치 항목 상세 근거")
    for iid in all_ids:
        model_verdicts = {m: all_results[m][0].get(iid,{}).get("verdict","—") for m in MODELS}
        ov = opus_map.get(iid,{}).get("verdict","—") if opus_map else "—"
        all_v = list(model_verdicts.values()) + [ov]
        if len(set(all_v)) == 1:
            continue

        lines.append(f"\n  {'='*60}")
        lines.append(f"  {iid}")
        lines.append(f"  {'='*60}")
        for model, runs in all_results.items():
            j = runs[0].get(iid, {})
            # 3회 verdict
            three = [r.get(iid,{}).get("verdict","-") for r in runs]
            lines.append(f"\n  [{model.split(':')[1]}] {j.get('verdict','-')} (conf={j.get('confidence','-')}) 3회={three}")
            lines.append(f"  근거: {j.get('rationale','')}")
            lines.append(f"  cited: {j.get('cited_evidence',[])[:3]}")
        if opus_map and iid in opus_map:
            oj = opus_map[iid]
            lines.append(f"\n  [Opus] {oj.get('verdict','-')} (conf={oj.get('confidence','-')})")
            lines.append(f"  근거: {oj.get('rationale','')}")
            lines.append(f"  cited: {oj.get('cited_evidence',[])[:3]}")

    return "\n".join(lines)


if __name__ == "__main__":
    all_results = run_experiment()
    summary = analyze(all_results)
    print(summary)
    with open(OUT_BASE / "experiment.log", "a") as f:
        f.write(summary + "\n")
    print(f"\n로그: {OUT_BASE / 'experiment.log'}")

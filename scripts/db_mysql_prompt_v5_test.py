#!/usr/bin/env python3
"""프롬프트 v4 — MySQL 30b×3회 재검증. DBM-004·009 중점 확인."""
import json, sys, time, datetime
from pathlib import Path

ROOT     = Path(__file__).parent.parent
REPORT   = str(ROOT / "results/DB/MySQL/mysql_result_rds.txt")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "db_mysql_v5"
RUNS     = 3
MODEL    = "qwen3-coder:30b"
FOCUS    = {"DBM-003", "DBM-004", "DBM-007", "DBM-008", "DBM-009"}

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient
from judge_tool.main import run as tool_run

def main():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    opus = {j["item_id"]: j for j in
            json.load(open(ROOT / "out/db_mysql_compare/opus/result.json"))["judgments"]}
    prev = {j["item_id"]: j for j in
            json.load(open(ROOT / "out/db_mysql_v4/run1/result.json"))["judgments"]}

    runs = []
    for r in range(1, RUNS + 1):
        run_dir = OUT_BASE / f"run{r}"
        run_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        print(f"[{r}/{RUNS}] {datetime.datetime.now().strftime('%H:%M:%S')}", end=" ", flush=True)
        cov = tool_run(
            report_path=REPORT, criteria_path=CRITERIA,
            profile_key="db_mysql",
            client=OllamaClient(model=MODEL, temperature=0.0),
            json_out=str(run_dir / "result.json"),
            xlsx_out=str(run_dir / "result.xlsx"),
            model_name=MODEL,
        )
        print(f"→ {time.time()-t0:.0f}s, {cov['judged']}/{cov['expected']}")
        runs.append({j["item_id"]: j for j in
                     json.load(open(run_dir / "result.json"))["judgments"]})

    all_ids = sorted(runs[0].keys())
    print(f"\n{'항목':<12} {'v4(이전)':<8} {'v5-r1':<8} {'v5-r2':<8} {'v5-r3':<8} {'Opus':<8} 변화")
    print("-" * 72)
    s = {"양호":"양호","취약":"취약","판단보류":"보류"}
    for iid in all_ids:
        pv = s.get(prev.get(iid,{}).get("verdict","—"), "—")
        ov = s.get(opus.get(iid,{}).get("verdict","—"), "—")
        vs = [s.get(r.get(iid,{}).get("verdict","—"), "—") for r in runs]
        changed = "✅" if vs[0] == ov and pv != ov else ("❌" if vs[0] != ov else "  ")
        focus = "★" if iid in FOCUS else " "
        print(f"{focus}{iid:<11} {pv:<8} {vs[0]:<8} {vs[1]:<8} {vs[2]:<8} {ov:<8} {changed}")

    print("\n[불일치 근거]")
    for iid in all_ids:
        v4 = runs[0].get(iid, {}).get("verdict")
        ov = opus.get(iid, {}).get("verdict")
        if v4 != ov:
            j = runs[0][iid]
            print(f"\n  {iid}: v4={j['verdict']}  Opus={ov}")
            print(f"  {j['rationale']}")

main()

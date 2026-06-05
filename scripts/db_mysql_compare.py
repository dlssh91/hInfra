#!/usr/bin/env python3
"""
MySQL DB — 30b(v1/v3) vs Opus 항목별 판정 비교
"""
import json, sys, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORT   = str(ROOT / "results/DB/MySQL/mysql_result_rds.txt")
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "db_mysql_compare"

sys.path.insert(0, str(ROOT))
from judge_tool.judge import ClaudeCliClient
from judge_tool.main import run as tool_run


def run_opus():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    out_dir = OUT_BASE / "opus"
    out_dir.mkdir(exist_ok=True)
    print(f"Opus MySQL 실행 중...")
    t0 = time.time()
    client = ClaudeCliClient(model="claude-opus-4-8", timeout=180)
    cov = tool_run(
        report_path=REPORT, criteria_path=CRITERIA,
        profile_key="db_mysql", client=client,
        json_out=str(out_dir / "result.json"),
        xlsx_out=str(out_dir / "result.xlsx"),
        model_name="claude-opus-4-8",
    )
    print(f"완료: {time.time()-t0:.0f}s, 판정 {cov['judged']}/{cov['expected']}")


def compare():
    paths = {
        "30b v1": ROOT / "out/result_mysql_result_rds.json",
        "Opus":   OUT_BASE / "opus/result.json",
    }
    data = {}
    for label, p in paths.items():
        if p.exists():
            data[label] = {j["item_id"]: j for j in json.load(open(p))["judgments"]}

    if len(data) < 2:
        print("비교할 결과 부족")
        return

    all_ids = sorted(set().union(*[set(v.keys()) for v in data.values()]))
    ref = data["Opus"]

    print(f"\n{'항목':<12} {'30b v1':<8} {'Opus':<8} 일치")
    print("-" * 40)
    for iid in all_ids:
        v30  = data["30b v1"].get(iid, {}).get("verdict", "—")
        vop  = ref.get(iid, {}).get("verdict", "—")
        s = {"양호":"양호","취약":"취약","판단보류":"보류"}
        flag = "✅" if v30 == vop else "❌"
        print(f"{iid:<12} {s.get(v30,v30):<8} {s.get(vop,vop):<8} {flag}")

    # 불일치 근거
    diffs = [i for i in all_ids
             if data["30b v1"].get(i,{}).get("verdict") != ref.get(i,{}).get("verdict")]
    if diffs:
        print(f"\n불일치 {len(diffs)}건 근거:")
        for iid in diffs:
            print(f"\n  [{iid}]")
            for label in ["30b v1", "Opus"]:
                j = data[label].get(iid, {})
                print(f"  {label}: {j.get('verdict')} — {j.get('rationale','')[:150]}")
    else:
        print(f"\n전 항목 일치 ✅")


if __name__ == "__main__":
    run_opus()
    compare()

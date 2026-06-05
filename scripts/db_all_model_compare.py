#!/usr/bin/env python3
"""
나머지 DBMS — Opus 기준선 + 30b×3 비교
Oracle·MS-SQL·MariaDB·PostgreSQL(rds/aurora/azure) 전체
"""
import json, sys, time, datetime
from pathlib import Path

ROOT     = Path(__file__).parent.parent
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "db_all_compare"
RUNS     = 3

CASES = [
    ("db_oracle",     "results/DB/Oracle/oracle_result_rds.txt"),
    ("db_mssql",      "results/DB/MS-SQL/mssql_result_rds.txt"),
    ("db_mariadb",    "results/DB/MariaDB/mariadb_result_rds.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_rds.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_aurora.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_azure.txt"),
]

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient, ClaudeCliClient
from judge_tool.main import run as tool_run

s = {"양호":"양호","취약":"취약","판단보류":"보류"}

def run_one(profile_key, report_path, out_dir, client, model_name):
    out_dir.mkdir(parents=True, exist_ok=True)
    return tool_run(
        report_path=report_path, criteria_path=CRITERIA,
        profile_key=profile_key, client=client,
        json_out=str(out_dir / "result.json"),
        xlsx_out=str(out_dir / "result.xlsx"),
        model_name=model_name,
    )

def load(path):
    return {j["item_id"]: j for j in json.load(open(path))["judgments"]}

def compare_block(label, runs_30b, opus_map, log):
    def tee(msg): print(msg); log.write(msg+"\n"); log.flush()

    all_ids = sorted(set(runs_30b[0].keys()) | set(opus_map.keys()))

    # 결정성
    stable = sum(1 for i in all_ids
                 if len({r.get(i,{}).get("verdict") for r in runs_30b}) == 1)
    tee(f"  결정성: {stable}/{len(all_ids)} ({stable/len(all_ids)*100:.0f}%)")

    # 일치율
    common = set(runs_30b[0].keys()) & set(opus_map.keys())
    match  = sum(1 for i in common if runs_30b[0][i]["verdict"] == opus_map[i]["verdict"])
    tee(f"  Opus 일치: {match}/{len(common)} ({match/len(common)*100:.0f}%)")

    # 비교표
    tee(f"\n  {'항목':<14} {'30b-r1':<8} {'30b-r2':<8} {'30b-r3':<8} {'Opus':<8}")
    tee("  " + "-"*50)
    for iid in all_ids:
        vs = [s.get(r.get(iid,{}).get("verdict","—"),"—") for r in runs_30b]
        ov = s.get(opus_map.get(iid,{}).get("verdict","—"),"—")
        flag = "✅" if vs[0]==ov and len(set(vs))==1 else "❌"
        tee(f"  {iid:<14} {vs[0]:<8} {vs[1]:<8} {vs[2]:<8} {ov:<8} {flag}")

    # 불일치 근거
    diffs = [i for i in all_ids
             if runs_30b[0].get(i,{}).get("verdict") != opus_map.get(i,{}).get("verdict")]
    if diffs:
        tee(f"\n  [불일치 {len(diffs)}건 근거]")
        for iid in diffs:
            j30  = runs_30b[0].get(iid, {})
            jop  = opus_map.get(iid, {})
            three = [r.get(iid,{}).get("verdict","-") for r in runs_30b]
            tee(f"\n  {iid}: 30b={j30.get('verdict')} (3회={three})  Opus={jop.get('verdict')}")
            tee(f"  30b: {j30.get('rationale','')[:200]}")
            tee(f"  Opus: {jop.get('rationale','')[:200]}")
    else:
        tee("  ✅ 전 항목 Opus 일치")


def main():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log = open(OUT_BASE / "compare.log", "w", buffering=1)
    def tee(msg): print(msg); log.write(msg+"\n"); log.flush()

    tee(f"=== DBMS 전체 비교: {datetime.datetime.now().isoformat()} ===\n")

    for profile_key, rel_path in CASES:
        report_path = str(ROOT / rel_path)
        label = Path(rel_path).stem
        tee(f"\n{'='*60}")
        tee(f"{label}  ({profile_key})")
        tee(f"{'='*60}")

        case_dir = OUT_BASE / label

        # Opus
        opus_dir = case_dir / "opus"
        if not (opus_dir / "result.json").exists():
            tee("  Opus 실행 중...")
            t0 = time.time()
            run_one(profile_key, report_path, opus_dir,
                    ClaudeCliClient(model="claude-opus-4-8", timeout=180), "claude-opus-4-8")
            tee(f"  Opus 완료: {time.time()-t0:.0f}s")
        else:
            tee("  Opus: 캐시 사용")

        # 30b ×3
        runs_30b = []
        for r in range(1, RUNS+1):
            run_dir = case_dir / f"30b_run{r}"
            if not (run_dir / "result.json").exists():
                tee(f"  30b run{r} 시작: {datetime.datetime.now().strftime('%H:%M:%S')}", )
                t0 = time.time()
                cov = run_one(profile_key, report_path, run_dir,
                              OllamaClient(model="qwen3-coder:30b", temperature=0.0),
                              "qwen3-coder:30b")
                tee(f"  30b run{r} 완료: {time.time()-t0:.0f}s, {cov['judged']}/{cov['expected']}")
            runs_30b.append(load(run_dir / "result.json"))

        opus_map = load(opus_dir / "result.json")
        compare_block(label, runs_30b, opus_map, log)

    tee(f"\n=== 전체 완료: {datetime.datetime.now().isoformat()} ===")
    log.close()

if __name__ == "__main__":
    main()

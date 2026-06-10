#!/usr/bin/env python3
"""
Phase-3 재실험: A/B/C/D 라벨 라우팅 효과 측정
- C/D: LLM 호출 없음, canned_message 자동 판단보류
- B:   LLM 요약만 (판정 없음)
- A:   LLM 판정 (Opus 대비 일치율)

대상: MySQL RDS + 나머지 DBMS 전체 (30b 모델 × 3회)
"""
import json
import sys
import time
import datetime
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).parent.parent
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "reexperiment_phase3"
# 결정성(temperature=0 → 3회 동일 판정)은 2026-06-08 두 차례 전수 실험으로
# 입증 완료. 기본 1회 실행, 스팟체크 필요 시 `python3 reexperiment_all.py 3`.
RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 1
MODEL_30B = "qwen3-coder:30b"

CASES = [
    ("db_mysql",      ROOT / "results/DB/MySQL/mysql_result_rds.txt"),
    ("db_oracle",     ROOT / "results/DB/Oracle/oracle_result_rds.txt"),
    ("db_mssql",      ROOT / "results/DB/MS-SQL/mssql_result_rds.txt"),
    ("db_mariadb",    ROOT / "results/DB/MariaDB/mariadb_result_rds.txt"),
    ("db_postgresql", ROOT / "results/DB/PostgreSQL/postgresql_result_rds.txt"),
    ("db_postgresql", ROOT / "results/DB/PostgreSQL/postgresql_result_aurora.txt"),
    ("db_postgresql", ROOT / "results/DB/PostgreSQL/postgresql_result_azure.txt"),
]

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient, ClaudeCliClient
from judge_tool.main import run as tool_run


def tee(msg, log=None):
    print(msg, flush=True)
    if log:
        log.write(msg + "\n")
        log.flush()


def run_one(profile_key, report_path, out_dir, client, model_name):
    out_dir.mkdir(parents=True, exist_ok=True)
    return tool_run(
        report_path=str(report_path),
        criteria_path=CRITERIA,
        profile_key=profile_key,
        client=client,
        json_out=str(out_dir / "result.json"),
        xlsx_out=str(out_dir / "result.xlsx"),
        model_name=model_name,
    )


def load_judgments(path):
    data = json.load(open(path))
    return {j["item_id"]: j for j in data["judgments"]}


def label_stats(judgments_map):
    """label별 항목 수 집계."""
    counts = defaultdict(int)
    for j in judgments_map.values():
        counts[j.get("label", "A")] += 1
    return dict(counts)


def analyze_case(label, runs_map_list, log):
    """단일 케이스 분석."""
    all_ids = sorted(set().union(*[set(r.keys()) for r in runs_map_list]))
    n_runs = len(runs_map_list)
    if n_runs > 1:
        tee(f"\n  [결정성]", log)
        stable = sum(
            1 for i in all_ids
            if len({r.get(i, {}).get("verdict") for r in runs_map_list}) == 1
        )
        tee(f"  {stable}/{len(all_ids)} ({stable/len(all_ids)*100:.0f}%) "
            f"항목이 {n_runs}회 동일 판정", log)

    # 라벨별 통계 (run1 기준)
    stats = label_stats(runs_map_list[0])
    tee(f"\n  [라벨별 항목 수] {stats}", log)
    total = sum(stats.values())
    cd_count = stats.get("C", 0) + stats.get("D", 0)
    b_count = stats.get("B", 0)
    a_count = stats.get("A", 0)
    if total > 0:
        tee(f"  → A(판정): {a_count}건 ({a_count/total*100:.0f}%), "
            f"B(요약): {b_count}건 ({b_count/total*100:.0f}%), "
            f"C+D(자동보류): {cd_count}건 ({cd_count/total*100:.0f}%)", log)

    # 불안정 항목
    unstable = [i for i in all_ids
                if len({r.get(i, {}).get("verdict") for r in runs_map_list}) > 1]
    if unstable:
        tee(f"\n  [불안정 항목]", log)
        for i in unstable:
            vs = [r.get(i, {}).get("verdict", "—") for r in runs_map_list]
            tee(f"    {i}: {vs}", log)

    return all_ids, stats


def compare_with_opus(label, run1_map, opus_map, log):
    """Opus와 A항목만 비교."""
    # A항목만 추출 (B/C/D는 판단보류 고정이라 비교 무의미)
    a_ids = [i for i, j in run1_map.items() if j.get("label", "A") == "A"]
    common = [i for i in a_ids if i in opus_map]
    if not common:
        tee(f"  [Opus 비교] 공통 A항목 없음", log)
        return

    match = sum(1 for i in common if run1_map[i]["verdict"] == opus_map[i]["verdict"])
    pct = match / len(common) * 100
    tee(f"\n  [Opus 대비 A항목 일치율] {match}/{len(common)} ({pct:.0f}%)", log)

    diffs = [i for i in sorted(common)
             if run1_map[i]["verdict"] != opus_map[i]["verdict"]]
    for i in diffs:
        tee(f"    불일치 {i}: 30b={run1_map[i]['verdict']}, Opus={opus_map[i]['verdict']}", log)
        tee(f"      30b 근거: {run1_map[i].get('rationale','')[:120]}", log)


def print_b_summaries(run1_map, log):
    """B항목 인터뷰 요약문 출력."""
    b_items = {i: j for i, j in run1_map.items()
               if j.get("label") == "B" and j.get("interview_summary")}
    if not b_items:
        return
    tee(f"\n  [B항목 인터뷰 요약]", log)
    for i, j in sorted(b_items.items()):
        tee(f"    --- {i} ---", log)
        summary = j.get("interview_summary", "")
        tee(f"    {summary[:200]}{'...' if len(summary) > 200 else ''}", log)


def main():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log = open(OUT_BASE / "reexperiment.log", "w", buffering=1)
    now = datetime.datetime.now().isoformat()
    tee(f"=== Phase-3 재실험: {now} ===", log)
    tee(f"=== 모델: {MODEL_30B}, {RUNS}회 반복 ===\n", log)

    client_30b = OllamaClient(model=MODEL_30B, temperature=0.0)

    for profile_key, report_path in CASES:
        if not report_path.exists():
            tee(f"\n[SKIP] 파일 없음: {report_path}", log)
            continue

        case_label = f"{profile_key}/{report_path.stem}"
        tee(f"\n{'='*65}", log)
        tee(f"케이스: {case_label}", log)
        tee(f"{'='*65}", log)

        case_dir = OUT_BASE / case_label.replace("/", "_")
        runs_map = []

        # 30b × RUNS
        for r in range(1, RUNS + 1):
            run_dir = case_dir / f"run{r}"
            t0 = time.time()
            tee(f"  [{r}/{RUNS}] 시작 {datetime.datetime.now().strftime('%H:%M:%S')}", log)
            cov = run_one(profile_key, report_path, run_dir, client_30b, MODEL_30B)
            elapsed = time.time() - t0
            tee(f"  [{r}/{RUNS}] 완료 {elapsed:.0f}s  판정 {cov['judged']}/{cov['expected']}", log)
            runs_map.append(load_judgments(run_dir / "result.json"))

        all_ids, stats = analyze_case(case_label, runs_map, log)
        print_b_summaries(runs_map[0], log)

        # Opus 기준선 (있으면 비교)
        opus_candidates = [
            ROOT / "out" / "db_mysql_compare" / "opus" / "result.json",
            ROOT / "out" / "db_all_compare" / f"{profile_key}_{report_path.stem}" / "opus" / "result.json",
        ]
        for opus_path in opus_candidates:
            if opus_path.exists():
                opus_map = load_judgments(opus_path)
                compare_with_opus(case_label, runs_map[0], opus_map, log)
                break

    tee(f"\n\n{'='*65}", log)
    tee("전체 완료", log)
    tee(f"로그: {OUT_BASE / 'reexperiment.log'}", log)
    log.close()


if __name__ == "__main__":
    main()

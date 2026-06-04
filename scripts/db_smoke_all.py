#!/usr/bin/env python3
"""
나머지 DBMS 스모크 테스트 (Oracle/MS-SQL/MariaDB/PostgreSQL)
실제 Ollama 모델로 parse→aggregate→judge→reconcile 전 파이프라인 검증.
results/ 는 읽기전용 — 절대 쓰지 않음. 출력은 out/db_smoke/ 에 저장.
"""
import json, os, sys, datetime, time
from pathlib import Path

ROOT = Path(__file__).parent.parent
CRITERIA = str(ROOT / "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
OUT_BASE = ROOT / "out" / "db_smoke"
MODEL = "qwen3-coder:30b"

SMOKE_CASES = [
    ("db_oracle",     "results/DB/Oracle/oracle_result_rds.txt"),
    ("db_mssql",      "results/DB/MS-SQL/mssql_result_rds.txt"),
    ("db_mariadb",    "results/DB/MariaDB/mariadb_result_rds.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_rds.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_aurora.txt"),
    ("db_postgresql", "results/DB/PostgreSQL/postgresql_result_azure.txt"),
]

sys.path.insert(0, str(ROOT))
from judge_tool.judge import OllamaClient
from judge_tool.main import run as tool_run


def run_smoke():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    log_path = OUT_BASE / "smoke.log"
    summary = []

    with open(log_path, "w") as log:
        def tee(msg):
            print(msg)
            log.write(msg + "\n")
            log.flush()

        tee(f"=== DB 전DBMS 스모크: {datetime.datetime.now().isoformat()} | 모델: {MODEL} ===\n")

        for profile_key, rel_path in SMOKE_CASES:
            report_path = str(ROOT / rel_path)
            if not os.path.exists(report_path):
                tee(f"[SKIP] {rel_path} (파일 없음)")
                continue

            label = Path(rel_path).stem
            run_dir = OUT_BASE / label
            run_dir.mkdir(parents=True, exist_ok=True)
            json_out = str(run_dir / "result.json")
            xlsx_out = str(run_dir / "result.xlsx")

            tee(f"[{label}] 시작 ({profile_key})")
            t0 = time.time()
            client = OllamaClient(model=MODEL, temperature=0.0)
            cov = tool_run(
                report_path=report_path,
                criteria_path=CRITERIA,
                profile_key=profile_key,
                client=client,
                json_out=json_out,
                xlsx_out=xlsx_out,
                model_name=MODEL,
            )
            elapsed = time.time() - t0

            with open(json_out) as f:
                data = json.load(f)
            verdicts = {}
            for j in data["judgments"]:
                v = j["verdict"]
                verdicts[v] = verdicts.get(v, 0) + 1
            nr = sum(1 for j in data["judgments"] if j.get("needs_review"))
            masking_ok = all(
                "<REDACTED" not in str(j.get("rationale", "")) and
                "<REDACTED" not in str(j.get("cited_evidence", []))
                for j in data["judgments"]
            )

            tee(f"  판정 {cov['judged']}/{cov['expected']}, 미판정: {cov['missing']}")
            tee(f"  verdict: {verdicts}")
            tee(f"  needs_review: {nr}/{cov['judged']}")
            tee(f"  마스킹 누출 없음: {masking_ok}")
            tee(f"  소요: {elapsed:.0f}s\n")

            summary.append({
                "label": label,
                "profile": profile_key,
                "judged": cov["judged"],
                "expected": cov["expected"],
                "missing": cov["missing"],
                "verdicts": verdicts,
                "needs_review": nr,
                "masking_ok": masking_ok,
                "elapsed_s": round(elapsed),
            })

        tee("=== 완료 ===")
        for s in summary:
            tee(f"  {s['label']}: {s['judged']}/{s['expected']} | {s['verdicts']} | nr={s['needs_review']} | mask={s['masking_ok']}")

    return summary, log_path


if __name__ == "__main__":
    summary, log_path = run_smoke()
    print(f"\n로그: {log_path}")

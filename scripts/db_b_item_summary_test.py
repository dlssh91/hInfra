"""B항목 summary_instruction 검증 스크립트.

MySQL RDS 실제 증거로 B항목 LLM 요약을 실행하고 결과를 출력.
평가자 관점에서 인터뷰 보조용으로 충분한지 수동 검토용.

사용법: python3 scripts/db_b_item_summary_test.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import yaml

from judge_tool.judge import OllamaClient, summarize_item
from judge_tool.mapper import aggregate
from judge_tool.models import Criterion
from judge_tool.parsers import get_parser
from judge_tool.profile import DB_MYSQL

REPORT = "results/DB/MySQL/mysql_result_rds.txt"
ITEM_CONFIG_YAML = "judge_tool/item_configs/db_mysql.yaml"
MODEL = "qwen3-coder:30b"
VARIANT = "mysql_rds"

B_ITEMS = ["DBM-003", "DBM-004", "DBM-020", "DBM-024", "DBM-028"]


def main():
    print(f"=== B항목 요약 검증 (model={MODEL}) ===\n")

    # item_configs 로딩
    with open(ITEM_CONFIG_YAML, encoding="utf-8") as fh:
        configs = yaml.safe_load(fh)

    # 증거 파싱
    parser = get_parser("db_json")
    raw_checks = parser.parse(REPORT)
    items = aggregate(raw_checks, VARIANT, DB_MYSQL)

    client = OllamaClient(model=MODEL)

    for item_id in B_ITEMS:
        cfg = configs.get(item_id, {})
        if cfg.get("label") != "B":
            print(f"[SKIP] {item_id}: 라벨={cfg.get('label','없음')}")
            continue

        item = items.get(item_id)
        if item is None:
            print(f"[SKIP] {item_id}: 증거 없음 (empty_means_good 또는 항목 미존재)")
            continue

        # 더미 Criterion (요약용이므로 standard/method는 불필요)
        crit = Criterion(
            item_id=item_id,
            item_name=f"테스트({item_id})",
            risk=None,
            variant=VARIANT,
            eval_type="스크립트",
            standard="",
            method="",
            applicable=True,
            label="B",
            summary_instruction=cfg.get("summary_instruction"),
        )

        print(f"\n{'='*60}")
        print(f"항목: {item_id}")
        print(f"증거 행 수: {len(item.resources)}")
        if item.context:
            print(f"컨텍스트: {item.context[:100]}")
        print(f"요약 지시: {cfg.get('summary_instruction','(없음)')[:80]}...")
        print(f"\n--- LLM 요약 결과 ---")

        summary = summarize_item(crit, item, client, evidence_mode="raw")
        print(summary)
        print()


if __name__ == "__main__":
    main()

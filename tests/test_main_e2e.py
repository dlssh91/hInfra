import json
import os

import pytest

from judge_tool.main import run


class StubClient:
    """모든 항목을 '취약'으로 판정하는 대역 (Ollama 불필요)."""
    def chat(self, system, user):
        return ('{"verdict":"취약","confidence":0.8,'
                '"rationale":"테스트 판정","cited_evidence":["x"]}')


def test_run_end_to_end(tmp_path, aws_report_path, criteria_xlsx_path):
    if not (os.path.exists(aws_report_path) and os.path.exists(criteria_xlsx_path)):
        pytest.skip("실제 보고서/평가기준 파일이 없어 E2E 스킵")

    json_path = os.path.join(tmp_path, "result.json")
    xlsx_path = os.path.join(tmp_path, "result.xlsx")
    summary = run(
        report_path=aws_report_path,
        criteria_path=criteria_xlsx_path,
        profile_key="cloud",
        client=StubClient(),
        json_out=json_path,
        xlsx_out=xlsx_path,
        model_name="stub-model",
    )
    assert os.path.exists(json_path) and os.path.exists(xlsx_path)

    data = json.load(open(json_path, encoding="utf-8"))
    # 실제 보고서의 스크립트 항목만 판정되었는지
    judged_ids = {j["item_id"] for j in data["judgments"]}
    assert "PISM-001" in judged_ids
    # 분할항목이 하나로 합쳐졌는지 (037_1/037_2 → PISM-037 1건)
    assert sum(1 for j in data["judgments"] if j["item_id"] == "PISM-037") == 1
    # 감사 메타데이터
    assert data["metadata"]["model"] == "stub-model"
    assert len(data["metadata"]["source_sha256"]) == 64
    # 커버리지 존재
    assert data["coverage"]["judged"] >= 1
    assert summary["judged"] == data["coverage"]["judged"]

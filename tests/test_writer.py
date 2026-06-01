import json
import os

import openpyxl

from judge_tool.models import Criterion, Judgment
from judge_tool.writer import build_coverage, write_json, write_excel


def _judgment(item_id="PISM-001", needs_review=False):
    return Judgment(item_id, "통신구간 암호화", "AWS", 5.0, "취약", 0.9,
                    "근거", ["b1"], "스크립트 전체", False, "bad", "일치",
                    needs_review)


def _criteria():
    return {
        ("PISM-001", "AWS"): Criterion("PISM-001", "암호화", 5.0, "AWS",
                                       "스크립트", "기준", "방법"),
        ("PISM-005", "AWS"): Criterion("PISM-005", "퍼블릭", 5.0, "AWS",
                                       "스크립트", "기준", "방법"),
        ("PISM-006", "AWS"): Criterion("PISM-006", "분리", 3.0, "AWS",
                                       "관리체계", "기준", "방법"),  # 스크립트 아님
    }


def test_coverage_lists_missing_script_items():
    cov = build_coverage(_criteria(), [_judgment("PISM-001")], "AWS")
    assert cov["expected"] == 2          # PISM-001, 005 (006은 관리체계라 제외)
    assert cov["judged"] == 1
    assert cov["missing"] == ["PISM-005"]


def test_write_json(tmp_path):
    path = os.path.join(tmp_path, "out.json")
    meta = {"model": "test", "criteria_version": "제2026-1호"}
    cov = {"expected": 2, "judged": 1, "missing": ["PISM-005"]}
    write_json([_judgment()], meta, cov, path)
    data = json.load(open(path, encoding="utf-8"))
    assert data["metadata"]["model"] == "test"
    assert data["coverage"]["missing"] == ["PISM-005"]
    assert data["judgments"][0]["item_id"] == "PISM-001"


def test_write_excel(tmp_path):
    path = os.path.join(tmp_path, "out.xlsx")
    meta = {"model": "test", "criteria_version": "제2026-1호",
            "generated_at": "2026-06-01 10:00:00", "source_file": "x.xml",
            "source_sha256": "abc", "tool_version": "0.1.0"}
    cov = {"expected": 2, "judged": 1, "missing": ["PISM-005"]}
    write_excel([_judgment(needs_review=True)], meta, cov, path)
    wb = openpyxl.load_workbook(path)
    assert "판정결과" in wb.sheetnames
    ws = wb["판정결과"]
    header = [c.value for c in ws[1]]
    assert "항목ID" in header and "판정" in header and "재검토" in header

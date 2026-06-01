import os

import pytest

from judge_tool.parsers.cloud_xml import sanitize, parse

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "sample_aws_report.xml")


def test_sanitize_escapes_bare_ampersand():
    raw = "<ResourceID>SD-WAN & Router</ResourceID>"
    assert sanitize(raw) == "<ResourceID>SD-WAN &amp; Router</ResourceID>"


def test_sanitize_keeps_valid_entities():
    raw = "a &amp; b &lt; c &#39;d&#39;"
    assert sanitize(raw) == raw


def test_parse_fixture_structure():
    checks = parse(FIXTURE)
    ids = [cid for cid, _ in checks]
    assert ids == ["pism_001", "pism_037_1", "pism_037_2", "pism_007"]
    by_id = dict(checks)
    # bare '&' 가 정제되어 정상 파싱 (ET가 &amp; 를 & 로 복원)
    assert any("SD-WAN & Router" in r.resource_id for r in by_id["pism_007"])
    # status 소문자화: "Error" -> "error"
    assert any(r.status == "error" for r in by_id["pism_007"])
    assert any(r.status == "review" for r in by_id["pism_007"])
    first = by_id["pism_001"][0]
    assert first.status == "bad"
    assert first.resource_id == "bucket-A"
    assert first.evidence != ""


def test_parse_real_report_if_present(aws_report_path):
    if not os.path.exists(aws_report_path):
        pytest.skip("실제 점검 결과 파일 없음 (평가자 환경에서만 존재)")
    checks = parse(aws_report_path)
    ids = [cid for cid, _ in checks]
    assert len(checks) == 26
    assert "pism_001" in ids
    assert "pism_037_1" in ids and "pism_037_2" in ids

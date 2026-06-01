from judge_tool.parsers.cloud_xml import sanitize, parse


def test_sanitize_escapes_bare_ampersand():
    raw = "<ResourceID>SD-WAN & Router</ResourceID>"
    assert sanitize(raw) == "<ResourceID>SD-WAN &amp; Router</ResourceID>"


def test_sanitize_keeps_valid_entities():
    raw = "a &amp; b &lt; c &#39;d&#39;"
    assert sanitize(raw) == raw


def test_parse_real_report(aws_report_path):
    checks = parse(aws_report_path)
    ids = [cid for cid, _ in checks]
    # 분할항목 원본 CheckID 보존
    assert "pism_001" in ids
    assert "pism_037_1" in ids and "pism_037_2" in ids
    assert len(checks) == 26

    # pism_001 의 첫 리소스 구조
    first = dict(checks)["pism_001"]
    assert first[0].resource_id != ""
    assert first[0].status in {"good", "bad", "info", "error", "review"}

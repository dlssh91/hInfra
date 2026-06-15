import os

import pytest

from judge_tool.parsers.cloud_xml import sanitize, parse

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "sample_aws_report.xml")
MALFORMED_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                                 "malformed_report.xml")


def test_sanitize_escapes_bare_ampersand():
    raw = "<ResourceID>SD-WAN & Router</ResourceID>"
    assert sanitize(raw) == "<ResourceID>SD-WAN &amp; Router</ResourceID>"


def test_sanitize_keeps_valid_entities():
    raw = "a &amp; b &lt; c &#39;d&#39;"
    assert sanitize(raw) == raw


def test_sanitize_leaves_cdata_ampersand_untouched():
    raw = "<E><![CDATA[A & B]]></E><R>C & D</R>"
    out = sanitize(raw)
    assert "<![CDATA[A & B]]>" in out          # CDATA 내부 '&' 보존
    assert "<R>C &amp; D</R>" in out           # 일반 텍스트 '&' 는 escape


def test_sanitize_strips_xml_illegal_control_chars():
    """XML 1.0 불법 C0 제어문자(ANSI escape 등) 제거 — CDATA 안에서도 불법.

    실수집 데이터(예: fsi_unix.sh의 PS1 환경변수 덤프)에 ANSI 컬러 코드
    \\x1b[01;32m 가 CDATA로 들어와 ElementTree 파싱을 깨뜨리던 갭을 보정한다.
    tab/LF/CR(\\x09/\\x0a/\\x0d)는 유효 문자이므로 보존한다.
    """
    raw = "<E><![CDATA[PS1='\x1b[01;32m'\nok\ttab]]></E>"
    out = sanitize(raw)
    assert "\x1b" not in out                    # ESC 제거
    assert "\x00" not in out
    assert "\n" in out and "\t" in out          # 유효 공백류 보존
    # 제거 후 well-formed → ElementTree 파싱 성공
    import xml.etree.ElementTree as ET
    root = ET.fromstring(out)
    assert "ok" in root.text


def test_sanitize_strips_control_chars_outside_cdata():
    """CDATA 밖 일반 텍스트의 불법 제어문자도 제거."""
    raw = "<R>val\x07ue\x1bX</R>"   # BEL, ESC
    out = sanitize(raw)
    assert "\x07" not in out and "\x1b" not in out
    import xml.etree.ElementTree as ET
    assert ET.fromstring(out).text == "valueX"


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
    # CDATA 내부 '&' 는 보존되어야 한다 (over-escape 방지)
    assert "&amp;" not in first.evidence
    assert "A & B" in first.evidence


def test_parse_malformed_xml_raises_clear_value_error():
    """닫히지 않은 <Evidence> 등 손상 XML → 경로/원인을 담은 ValueError.

    raw ParseError 트레이스백 대신 명확한 안내 예외로 변환되어야 한다.
    민감 evidence 본문은 메시지에 포함되면 안 된다(경로·라이브러리 위치만).
    """
    with pytest.raises(ValueError) as ei:
        parse(MALFORMED_FIXTURE)
    msg = str(ei.value)
    assert "파싱 실패" in msg
    assert MALFORMED_FIXTURE in msg
    # XML 본문/evidence 원문이 메시지에 새어나오면 안 됨
    assert "synthetic evidence text" not in msg


def test_parse_malformed_xml_raises_report_error():
    """손상 XML → 전용 ReportError(단, ValueError 하위라 기존 호환 유지)."""
    from judge_tool.errors import ReportError

    with pytest.raises(ReportError) as ei:
        parse(MALFORMED_FIXTURE)
    assert isinstance(ei.value, ValueError)


def test_parse_real_report_if_present(aws_report_path):
    if not os.path.exists(aws_report_path):
        pytest.skip("실제 점검 결과 파일 없음 (평가자 환경에서만 존재)")
    checks = parse(aws_report_path)
    ids = [cid for cid, _ in checks]
    assert len(checks) == 26
    assert "pism_001" in ids
    assert "pism_037_1" in ids and "pism_037_2" in ids

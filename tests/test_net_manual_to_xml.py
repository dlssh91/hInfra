"""net_manual_to_xml.py(수기 템플릿 → network_xml 호환 XML 변환기) 단위 테스트.

DRAFT 검증(§5-2) — scripts/ 는 패키지가 아니므로 파일 경로로 직접 모듈을 로드한다.
network_xml.parse()/detect_variant() 를 통해 실제 파서와의 계약 준수도 함께 검증한다
(파서 무변경 확인용 — judge_tool/parsers/network_xml.py 는 수정하지 않는다).
"""
import importlib.util
import os

import pytest

from judge_tool.parsers import network_xml

_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "scripts")
_MODULE_PATH = os.path.join(_SCRIPTS_DIR, "net_manual_to_xml.py")

_spec = importlib.util.spec_from_file_location("net_manual_to_xml", _MODULE_PATH)
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def _write_xml(tmp_path, name, xml_text):
    p = tmp_path / name
    p.write_text(xml_text, encoding="utf-8")
    return str(p)


# ── parse_template ───────────────────────────────────────────────────────────

def test_parse_template_asset_and_single_section():
    text = (
        "hostname: router1\n"
        "vendor: Cisco Systems\n"
        "model: Catalyst 3750\n"
        "version: IOS 15.2\n"
        "\n"
        "[NET-001]\n"
        "no ip http server\n"
    )
    asset, sections = m.parse_template(text)
    assert asset == {
        "hostname": "router1", "vendor": "Cisco Systems",
        "model": "Catalyst 3750", "version": "IOS 15.2",
    }
    assert sections == [(["NET-001"], "no ip http server")]


def test_parse_template_multi_id_section():
    text = "[NET-003,NET-004, NET-005]\nshared output line\n"
    _, sections = m.parse_template(text)
    ids, body = sections[0]
    assert ids == ["NET-003", "NET-004", "NET-005"]
    assert body == "shared output line"


def test_parse_template_multiple_sections_same_id_allowed():
    text = "[NET-001]\nfrom running-config\n\n[NET-001]\nfrom show version\n"
    _, sections = m.parse_template(text)
    assert [s[0] for s in sections] == [["NET-001"], ["NET-001"]]
    assert sections[0][1] == "from running-config"
    assert sections[1][1] == "from show version"


def test_parse_template_empty_body_preserved():
    text = "[NET-001]\n\n[NET-003]\nsomething\n"
    _, sections = m.parse_template(text)
    assert sections[0] == (["NET-001"], "")


def test_parse_template_no_sections_raises():
    with pytest.raises(m.TemplateError, match=r"섹션 헤더"):
        m.parse_template("hostname: router1\nno bracket headers here\n")


def test_parse_template_no_asset_header_ok():
    """자산 메타데이터 없이 섹션만 있어도 파싱은 성공(파서가 generic 폴백 처리)."""
    asset, sections = m.parse_template("[NET-001]\nshow output\n")
    assert asset == {}
    assert sections == [(["NET-001"], "show output")]


# ── build_xml / convert — 구조 계약 ──────────────────────────────────────────

def test_convert_produces_expected_envelope_shape():
    text = (
        "hostname: router1\nvendor: Cisco Systems\n\n"
        "[NET-001]\nno ip http server\n"
    )
    xml_text = m.convert(text)
    assert "<script>" in xml_text
    assert "<asset>" in xml_text
    assert "<hostname>router1</hostname>" in xml_text
    assert "<vendor>Cisco Systems</vendor>" in xml_text
    assert "<results>" in xml_text
    assert "<dump><items><id>NET-001</id></items>" in xml_text
    assert "<![CDATA[no ip http server]]>" in xml_text


def test_convert_cdata_close_sequence_escaped():
    """출력 본문에 ']]>' 가 있어도 CDATA를 깨지 않고 분할-재시작한다."""
    text = "[NET-001]\nweird ]]> sequence\n"
    xml_text = m.convert(text)
    assert "]]]]><![CDATA[>" in xml_text
    # 분할 후에도 well-formed XML이어야 함 — ET로 직접 파싱 확인
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_text)
    assert root.findtext(".//output") is not None


def test_convert_escapes_asset_special_chars():
    text = "hostname: router & co <1>\n\n[NET-001]\nx\n"
    xml_text = m.convert(text)
    assert "router &amp; co &lt;1&gt;" in xml_text


# ── mask_text 옵션 ────────────────────────────────────────────────────────────

def test_mask_enable_secret():
    ev = m.mask_text("enable secret 5 SuperSecretHash\nno ip http server")
    assert "SuperSecretHash" not in ev
    assert "enable secret" in ev
    assert "no ip http server" in ev


def test_mask_snmp_community_public_preserved():
    ev = m.mask_text("snmp-server community public RO\nsnmp-server community hidden RW")
    assert "snmp-server community public" in ev
    assert "hidden" not in ev


def test_convert_mask_flag_applied_before_output():
    text = "[NET-004]\nenable secret 5 PlainSecretValue\n"
    xml_text = m.convert(text, mask=True)
    assert "PlainSecretValue" not in xml_text
    xml_text_nomask = m.convert(text, mask=False)
    assert "PlainSecretValue" in xml_text_nomask


# ── network_xml 파서와의 실제 계약 검증(e2e) ─────────────────────────────────

def test_convert_output_parses_via_network_xml(tmp_path):
    text = (
        "hostname: router1\nvendor: Cisco Systems\nmodel: Catalyst 3750\n"
        "version: IOS 15.2\n\n"
        "[NET-001]\n\n"
        "[NET-003,NET-004]\n"
        "enable secret 5 $1$mERr$hashhashhashhashhashhash\n"
        "snmp-server community public RO\n"
        "snmp-server community SecretComm RW\n\n"
        "[NET-048,NET-059]\n"
        "Cisco IOS Software, C3750 Software, Version 15.2(4)E10\n"
    )
    xml_text = m.convert(text, mask=True)
    path = _write_xml(tmp_path, "router1.xml", xml_text)

    assert network_xml.detect_variant(path) == "cisco"
    out = network_xml.parse(path)
    by_id = {cid: resources for cid, resources, _ctx in out}

    assert by_id["NET-001"] == []
    assert "<REDACTED 비밀번호#0>" in by_id["NET-003"][0].evidence
    assert "<REDACTED 커뮤니티#0>" in by_id["NET-003"][0].evidence
    assert "snmp-server community public" in by_id["NET-003"][0].evidence
    assert by_id["NET-004"][0].evidence == by_id["NET-003"][0].evidence
    assert "C3750" in by_id["NET-048"][0].evidence
    assert by_id["NET-059"][0].evidence == by_id["NET-048"][0].evidence


def test_convert_generic_vendor_variant(tmp_path):
    text = "hostname: switch2\nvendor: Juniper Networks\nmodel: SRX-320\nversion: JUNOS 22.4\n\n[NET-001]\nx\n"
    path = _write_xml(tmp_path, "switch2.xml", m.convert(text))
    assert network_xml.detect_variant(path) == "generic"


def test_convert_no_asset_still_parses_generic(tmp_path):
    """자산 메타데이터 없이도(§선택) 파서가 크래시 없이 generic으로 폴백."""
    path = _write_xml(tmp_path, "noasset.xml", m.convert("[NET-001]\nsome output\n"))
    assert network_xml.detect_variant(path) == "generic"
    out = network_xml.parse(path)
    assert out[0][0] == "NET-001"


# ── CLI main() ────────────────────────────────────────────────────────────

def test_main_writes_output_file(tmp_path):
    infile = tmp_path / "template.txt"
    infile.write_text("hostname: r1\nvendor: Cisco\n\n[NET-001]\nno ip http server\n",
                       encoding="utf-8")
    outfile = tmp_path / "out.xml"
    rc = m.main(["--in", str(infile), "--out", str(outfile)])
    assert rc == 0
    assert outfile.exists()
    content = outfile.read_text(encoding="utf-8")
    assert "<hostname>r1</hostname>" in content


def test_main_reports_error_on_missing_sections(tmp_path, capsys):
    infile = tmp_path / "bad.txt"
    infile.write_text("hostname: r1\nvendor: Cisco\nno bracket sections\n", encoding="utf-8")
    outfile = tmp_path / "out.xml"
    rc = m.main(["--in", str(infile), "--out", str(outfile)])
    assert rc == 2
    assert not outfile.exists()
    captured = capsys.readouterr()
    assert "오류" in captured.err


def test_main_mask_flag(tmp_path):
    infile = tmp_path / "t.txt"
    infile.write_text("[NET-004]\nenable secret 5 PlainSecretValue\n", encoding="utf-8")
    outfile = tmp_path / "out.xml"
    m.main(["--in", str(infile), "--out", str(outfile), "--mask"])
    content = outfile.read_text(encoding="utf-8")
    assert "PlainSecretValue" not in content

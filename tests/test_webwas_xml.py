"""웹서버-WAS XML 파서 단위 테스트 (webwas_xml).

합성 XML 문자열로 실데이터 없이 실행한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers.webwas_xml import detect_variant, parse


# ─ 합성 XML 헬퍼 ──────────────────────────────────────────────────────────────

def _xml(variant="", os="", webserver="", product="", dumps=None, encoding="UTF-8"):
    asset_extra = ""
    if variant:
        asset_extra += f"<variant>{variant}</variant>\n"
    if os:
        asset_extra += f"<os>{os}</os>\n"
    if webserver:
        asset_extra += f"<webserver>{webserver}</webserver>\n"
    if product:
        asset_extra += f"<product>{product}</product>\n"

    if dumps is None:
        dumps = [("WST-001", "snmp config output")]

    dump_xml = ""
    for ids, output in dumps:
        if isinstance(ids, str):
            ids = [ids]
        id_tags = "".join(f"<id>{i}</id>" for i in ids)
        dump_xml += f"""
<dump>
<items>{id_tags}</items>
<output><![CDATA[{output}]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="{encoding}"?>
<script>
<asset>
<hostname>web-host-01</hostname>
{asset_extra}
</asset>
<results>{dump_xml}</results>
</script>
"""


def _write(tmp_path, content, name="report.xml"):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ─ detect_variant: 직접 키 ────────────────────────────────────────────────────

def test_detect_variant_direct_apache(tmp_path):
    p = _write(tmp_path, _xml(variant="apache"))
    assert detect_variant(p) == "apache"


def test_detect_variant_direct_linux(tmp_path):
    p = _write(tmp_path, _xml(variant="linux"))
    assert detect_variant(p) == "linux"


def test_detect_variant_direct_jeus(tmp_path):
    p = _write(tmp_path, _xml(variant="jeus"))
    assert detect_variant(p) == "jeus"


def test_detect_variant_direct_hpux_alias(tmp_path):
    """직접 키 'hp-ux' → 'hpux'."""
    p = _write(tmp_path, _xml(variant="hp-ux"))
    assert detect_variant(p) == "hpux"


# ─ detect_variant: OS 우선 ────────────────────────────────────────────────────

def test_detect_variant_os_linux(tmp_path):
    p = _write(tmp_path, _xml(os="Linux 5.4"))
    assert detect_variant(p) == "linux"


def test_detect_variant_os_aix(tmp_path):
    p = _write(tmp_path, _xml(os="AIX 7.2"))
    assert detect_variant(p) == "aix"


def test_detect_variant_os_priority_over_webserver(tmp_path):
    """OS 태그가 webserver보다 우선(서버 동형 점검 기반)."""
    p = _write(tmp_path, _xml(os="Linux", webserver="Apache"))
    assert detect_variant(p) == "linux"


# ─ detect_variant: 웹서버 ─────────────────────────────────────────────────────

def test_detect_variant_webserver_apache(tmp_path):
    """OS 없고 webserver=Apache → apache."""
    p = _write(tmp_path, _xml(webserver="Apache HTTP Server 2.4"))
    assert detect_variant(p) == "apache"


def test_detect_variant_webserver_httpd_alias(tmp_path):
    p = _write(tmp_path, _xml(webserver="httpd"))
    assert detect_variant(p) == "apache"


def test_detect_variant_webserver_tomcat(tmp_path):
    """'Apache Tomcat'은 Tomcat(WAS) → tomcat (구체 토큰 우선)."""
    p = _write(tmp_path, _xml(webserver="Apache Tomcat 9"))
    assert detect_variant(p) == "tomcat"


def test_detect_variant_webserver_iis_via_product(tmp_path):
    """webserver 없고 product=IIS → iis."""
    p = _write(tmp_path, _xml(product="Microsoft IIS 10.0"))
    assert detect_variant(p) == "iis"


def test_detect_variant_webserver_jeus(tmp_path):
    p = _write(tmp_path, _xml(webserver="TmaxSoft JEUS 8"))
    assert detect_variant(p) == "jeus"


# ─ detect_variant: 미식별 → None ──────────────────────────────────────────────

def test_detect_variant_no_tags_none(tmp_path):
    p = _write(tmp_path, _xml())
    assert detect_variant(p) is None


def test_detect_variant_unknown_none(tmp_path):
    """미지 OS/웹서버 → None (--variant 유도)."""
    p = _write(tmp_path, _xml(os="FreeBSD", webserver="nginx"))
    assert detect_variant(p) is None


# ─ parse ──────────────────────────────────────────────────────────────────────

def test_parse_basic_tuple_contract(tmp_path):
    p = _write(tmp_path, _xml(dumps=[("WST-001", "config output")]))
    result = parse(p)
    assert len(result) == 1
    cid, resources, ctx = result[0]
    assert cid == "WST-001"
    assert ctx is None
    assert resources[0].resource_id == "WST-001#0"
    assert "config output" in resources[0].evidence


def test_parse_multi_ids_share_output(tmp_path):
    p = _write(tmp_path, _xml(dumps=[
        (["WST-001", "WST-031"], "shared output"),
    ]))
    result = parse(p)
    assert [r[0] for r in result] == ["WST-001", "WST-031"]
    assert result[0][1][0].evidence == result[1][1][0].evidence


def test_parse_empty_output_no_resources(tmp_path):
    p = _write(tmp_path, _xml(dumps=[("WST-007", "   ")]))
    result = parse(p)
    assert result[0][1] == []


def test_parse_duplicate_cid_unique_resource_ids(tmp_path):
    p = _write(tmp_path, _xml(dumps=[
        ("WST-001", "output A"),
        ("WST-001", "output B"),
    ]))
    result = parse(p)
    rids = [r[1][0].resource_id for r in result if r[1]]
    assert rids == ["WST-001#0", "WST-001#1"]


def test_parse_no_dumps_raises(tmp_path):
    content = """<?xml version="1.0"?>
<script><asset><hostname>h</hostname></asset><results></results></script>"""
    p = _write(tmp_path, content)
    with pytest.raises(ReportError):
        parse(p)


def test_parse_malformed_xml_raises(tmp_path):
    p = _write(tmp_path, "not xml <<broken>>")
    with pytest.raises(ReportError):
        parse(p)


def test_parse_euckr_encoding(tmp_path):
    content = (
        b'<?xml version="1.0" encoding="euc-kr"?>\n'
        b'<script>\n'
        b'<asset><hostname>web-01</hostname>'
        b'<variant>apache</variant></asset>\n'
        b'<results>\n'
        b'<dump><items><id>WST-031</id></items>'
        b'<output><![CDATA[httpd.conf Options directive]]></output></dump>\n'
        b'</results>\n</script>\n'
    )
    p = tmp_path / "euckr.xml"
    p.write_bytes(content)
    result = parse(str(p))
    assert result[0][0] == "WST-031"
    assert "httpd.conf" in result[0][1][0].evidence


# ─ 민감 마스킹 ────────────────────────────────────────────────────────────────

def test_parse_masks_crypt_hash(tmp_path):
    crypt = "$6$rounds=5000$salt12345678$" + "A" * 43 + "B" * 43
    p = _write(tmp_path, _xml(dumps=[("WST-044", f"admin:{crypt}:18000:")]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert crypt not in ev
    assert "<REDACTED 해시>" in ev


def test_parse_masks_private_key(tmp_path):
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    p = _write(tmp_path, _xml(dumps=[("WST-120", pem)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MIIEowIBAAKCAQEA" not in ev
    assert "BEGIN RSA PRIVATE KEY" in ev
    assert "<REDACTED>" in ev


# ─ 파서 레지스트리 + 불변식 ───────────────────────────────────────────────────

def test_parser_registry_webwas_xml():
    from judge_tool.parsers import get_parser
    parser = get_parser("webwas_xml")
    assert hasattr(parser, "parse")
    assert hasattr(parser, "detect_variant")


def test_detect_variant_returns_registered_key_or_none():
    """detect_variant 반환값은 WEBWAS.variants 키 또는 None (무증상 스킵 방어)."""
    from judge_tool.parsers.webwas_xml import (
        _DIRECT_VARIANT_MAP, _WEBSERVER_TOKENS)
    from judge_tool.parsers.server_xml import _OS_VARIANTS
    from judge_tool.profile import WEBWAS

    valid = set(WEBWAS.variants.keys())
    mapped = (set(_DIRECT_VARIANT_MAP.values())
              | {v for _, v in _WEBSERVER_TOKENS}
              | {v for _, v in _OS_VARIANTS})
    assert mapped.issubset(valid), (
        f"detect_variant가 반환할 수 있는 미등록 키: {mapped - valid}")


def test_all_variants_reachable_via_detect():
    """역방향: WEBWAS 11변형 전부 어떤 detect 경로로든 도달 가능한지.

    직접키(_DIRECT_VARIANT_MAP)·OS토큰(_OS_VARIANTS)·웹서버토큰(_WEBSERVER_TOKENS)
    중 하나로 반환 가능해야 한다. 도달 불가 변형은 영원히 판정 안 되는 사각지대.
    """
    from judge_tool.parsers.webwas_xml import (
        _DIRECT_VARIANT_MAP, _WEBSERVER_TOKENS)
    from judge_tool.parsers.server_xml import _OS_VARIANTS
    from judge_tool.profile import WEBWAS

    reachable = (set(_DIRECT_VARIANT_MAP.values())
                 | {v for _, v in _WEBSERVER_TOKENS}
                 | {v for _, v in _OS_VARIANTS})
    unreachable = set(WEBWAS.variants.keys()) - reachable
    assert not unreachable, f"detect 경로로 도달 불가한 변형: {unreachable}"

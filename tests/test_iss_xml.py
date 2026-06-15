"""정보보호시스템 장비 XML 파서 단위 테스트 (iss_xml).

합성 XML 문자열로 실데이터 없이 실행한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers.iss_xml import detect_variant, parse


# ─ 합성 XML 헬퍼 ──────────────────────────────────────────────────────────────

def _xml(device_type="", vendor="", model="", dumps=None, encoding="UTF-8"):
    """합성 정보보호시스템 XML 문자열."""
    asset_extra = ""
    if device_type:
        asset_extra += f"<device_type>{device_type}</device_type>\n"
    if vendor:
        asset_extra += f"<vendor>{vendor}</vendor>\n"
    if model:
        asset_extra += f"<model>{model}</model>\n"

    if dumps is None:
        dumps = [("ISS-001", "show running-config output")]

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
<hostname>iss-device-01</hostname>
{asset_extra}
</asset>
<results>{dump_xml}</results>
</script>
"""


def _write(tmp_path, content, name="report.xml"):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ─ detect_variant ─────────────────────────────────────────────────────────────

def test_detect_variant_vpn(tmp_path):
    p = _write(tmp_path, _xml(device_type="VPN"))
    assert detect_variant(p) == "vpn"


def test_detect_variant_ids(tmp_path):
    p = _write(tmp_path, _xml(device_type="IDS"))
    assert detect_variant(p) == "ids"


def test_detect_variant_ips_phrase(tmp_path):
    """'Intrusion Prevention System' 구문 → ips (구문 토큰 우선)."""
    p = _write(tmp_path, _xml(device_type="Intrusion Prevention System"))
    assert detect_variant(p) == "ips"


def test_detect_variant_ids_phrase(tmp_path):
    p = _write(tmp_path, _xml(device_type="intrusion detection"))
    assert detect_variant(p) == "ids"


def test_detect_variant_ddos(tmp_path):
    p = _write(tmp_path, _xml(device_type="Anti-DDoS"))
    assert detect_variant(p) == "ddos"


def test_detect_variant_ddos_antiddos_space(tmp_path):
    p = _write(tmp_path, _xml(device_type="Anti DDoS Appliance"))
    assert detect_variant(p) == "ddos"


def test_detect_variant_waf_phrase(tmp_path):
    """'Web Application Firewall' → waf (firewall 단독보다 구문 우선)."""
    p = _write(tmp_path, _xml(device_type="Web Application Firewall"))
    assert detect_variant(p) == "waf"


def test_detect_variant_waf_short(tmp_path):
    p = _write(tmp_path, _xml(device_type="WAF"))
    assert detect_variant(p) == "waf"


def test_detect_variant_unknown_to_generic(tmp_path):
    """'Firewall NGFW' 등 미지 문자열 → generic (firewall 미매핑 설계)."""
    p = _write(tmp_path, _xml(device_type="Firewall NGFW"))
    assert detect_variant(p) == "generic"


def test_detect_variant_firewall_alone_to_generic(tmp_path):
    """설계 계약: 'Firewall' 단독 → generic.

    FW는 --profile iss(정책 xlsx) 전용이므로 firewall 토큰은 의도적으로 미매핑.
    iss_device.xml에 FW XML이 들어오면 generic 폴백으로 처리된다.
    """
    p = _write(tmp_path, _xml(device_type="Firewall"))
    assert detect_variant(p) == "generic"


def test_detect_variant_next_gen_fw_to_generic(tmp_path):
    """'Next-Generation Firewall' / 'NGFW' → generic (firewall 토큰 포함해도 미매핑)."""
    for dtype in ("Next-Generation Firewall", "NGFW"):
        p = _write(tmp_path, _xml(device_type=dtype))
        assert detect_variant(p) == "generic", f"{dtype!r} should map to generic"


def test_detect_variant_missing_tags_to_generic(tmp_path):
    """asset/device_type 태그 부재 → generic (오류 없이 폴백)."""
    p = _write(tmp_path, _xml())
    assert detect_variant(p) == "generic"


def test_detect_variant_model_fallback(tmp_path):
    """device_type 없고 model에 'SSL-VPN 3000' → vpn."""
    p = _write(tmp_path, _xml(model="SSL-VPN 3000"))
    assert detect_variant(p) == "vpn"


def test_detect_variant_vendor_fallback(tmp_path):
    """device_type/model 없고 vendor에 'IPS-1100' → ips."""
    p = _write(tmp_path, _xml(vendor="IPS-1100 appliance"))
    assert detect_variant(p) == "ips"


def test_detect_variant_word_boundary(tmp_path):
    """'shipside rapids' — ips·ids 내부 매치 배제 → generic."""
    p = _write(tmp_path, _xml(device_type="shipside rapids"))
    assert detect_variant(p) == "generic"


def test_detect_variant_device_type_overrides_model(tmp_path):
    """device_type이 있으면 model보다 우선."""
    p = _write(tmp_path, _xml(device_type="WAF", model="SSL-VPN 3000"))
    assert detect_variant(p) == "waf"


# ─ parse ──────────────────────────────────────────────────────────────────────

def test_parse_basic_tuple_contract(tmp_path):
    p = _write(tmp_path, _xml(dumps=[("ISS-001", "show log output")]))
    result = parse(p)
    assert len(result) == 1
    cid, resources, ctx = result[0]
    assert cid == "ISS-001"
    assert ctx is None
    assert len(resources) == 1
    assert resources[0].resource_id == "ISS-001#0"
    assert "show log output" in resources[0].evidence


def test_parse_multi_ids_share_output(tmp_path):
    """한 dump에 id 2개 → 각 id가 같은 output으로 분리 emit."""
    p = _write(tmp_path, _xml(dumps=[
        (["ISS-001", "ISS-002"], "shared output"),
    ]))
    result = parse(p)
    assert len(result) == 2
    assert result[0][0] == "ISS-001"
    assert result[1][0] == "ISS-002"
    assert result[0][1][0].evidence == result[1][1][0].evidence


def test_parse_empty_output_no_resources(tmp_path):
    """공백 CDATA → resources=[] (증거 없음 → 판단보류 가드)."""
    p = _write(tmp_path, _xml(dumps=[("ISS-007", "   ")]))
    result = parse(p)
    assert result[0][1] == []


def test_parse_duplicate_cid_unique_resource_ids(tmp_path):
    """같은 id가 두 dump에 등장 → resource_id가 #0, #1로 유일."""
    p = _write(tmp_path, _xml(dumps=[
        ("ISS-001", "output A"),
        ("ISS-001", "output B"),
    ]))
    result = parse(p)
    rids = [r[1][0].resource_id for r in result if r[1]]
    assert rids[0] == "ISS-001#0"
    assert rids[1] == "ISS-001#1"


def test_parse_no_dumps_raises(tmp_path):
    """dump 없음 → ReportError."""
    content = """<?xml version="1.0"?>
<script><asset><hostname>h</hostname></asset><results></results></script>"""
    p = _write(tmp_path, content)
    with pytest.raises(ReportError):
        parse(p)


def test_parse_malformed_xml_reporterror(tmp_path):
    """손상 XML → ReportError, 오류 메시지에 '--profile iss' 안내 포함."""
    p = _write(tmp_path, "not xml <<broken>>")
    with pytest.raises(ReportError, match="--profile iss"):
        parse(p)


def test_parse_euckr_encoding(tmp_path):
    """EUC-KR 인코딩 XML 정상 디코딩 (_read_text 체이닝 검증)."""
    content = (
        b'<?xml version="1.0" encoding="euc-kr"?>\n'
        b'<script>\n'
        b'<asset><hostname>vpn-01</hostname>'
        b'<device_type>VPN</device_type></asset>\n'
        b'<results>\n'
        b'<dump><items><id>ISS-001</id></items>'
        b'<output><![CDATA[show crypto isakmp sa output]]></output></dump>\n'
        b'</results>\n</script>\n'
    )
    p = tmp_path / "euckr.xml"
    p.write_bytes(content)
    result = parse(str(p))
    assert result[0][0] == "ISS-001"
    assert "show crypto isakmp sa" in result[0][1][0].evidence


# ─ 민감 마스킹 ────────────────────────────────────────────────────────────────

def test_mask_preshared_key_redacted(tmp_path):
    """pre-shared-key 값 → <REDACTED 비밀번호#N>."""
    output = "  pre-shared-key MySecretKey123\n  lifetime 86400\n"
    p = _write(tmp_path, _xml(dumps=[("ISS-001", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MySecretKey123" not in ev
    assert "<REDACTED 비밀번호#0>" in ev
    assert "lifetime 86400" in ev


def test_mask_equivalence_across_dumps(tmp_path):
    """두 dump의 같은 비밀값 → 같은 <REDACTED #N> 토큰 (파일 전체 동등성 공유)."""
    shared_secret = "S3cr3tP@ssw0rd"
    p = _write(tmp_path, _xml(dumps=[
        ("ISS-001", f"  pre-shared-key {shared_secret}"),
        ("ISS-002", f"  pre-shared-key {shared_secret}"),
    ]))
    result = parse(p)
    ev1 = result[0][1][0].evidence
    ev2 = result[1][1][0].evidence
    assert "<REDACTED 비밀번호#0>" in ev1
    assert "<REDACTED 비밀번호#0>" in ev2
    assert shared_secret not in ev1
    assert shared_secret not in ev2


def test_mask_private_key_block_chained(tmp_path):
    """PEM 블록 본문 치환 (server_xml 체이닝 동작)."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    p = _write(tmp_path, _xml(dumps=[("ISS-021", pem)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MIIEowIBAAKCAQEA" not in ev
    assert "BEGIN RSA PRIVATE KEY" in ev
    assert "<REDACTED>" in ev


def test_mask_crypt_hash_chained(tmp_path):
    """$6$ 해시 → <REDACTED 해시> (server_xml 체이닝 동작)."""
    crypt = "$6$rounds=5000$salt12345678$" + "A" * 43 + "B" * 43
    p = _write(tmp_path, _xml(dumps=[("ISS-017", f"admin:{crypt}:18000:")]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert crypt not in ev
    assert "<REDACTED 해시>" in ev


def test_mask_snmp_public_preserved(tmp_path):
    """snmp-server community public → 원문 보존 (취약 증거 계약)."""
    output = "snmp-server community public RO\nsnmp-server community private RW\n"
    p = _write(tmp_path, _xml(dumps=[("ISS-014", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "community public" in ev
    assert "community private" in ev


# ─ 파서 레지스트리 + 불변식 검증 ──────────────────────────────────────────────

def test_parser_registry_iss_xml():
    from judge_tool.parsers import get_parser
    parser = get_parser("iss_xml")
    assert hasattr(parser, "parse")
    assert hasattr(parser, "detect_variant")


def test_detect_variant_returns_registered_key():
    """detect_variant가 반환할 수 있는 값이 모두 ISS_DEVICE.variants 키 집합에 속함.

    (detect_variant가 미등록 키를 반환하면 전 항목 무증상 스킵 — 불변식 방어.)
    """
    from judge_tool.parsers.iss_xml import _TOKEN_RES
    from judge_tool.profile import ISS_DEVICE

    valid_keys = set(ISS_DEVICE.variants.keys()) | {"generic"}
    returned_variants = {var for _, var in _TOKEN_RES}
    returned_variants.add("generic")  # 폴백 포함
    assert returned_variants.issubset(valid_keys), (
        f"detect_variant가 반환할 수 있는 미등록 키: {returned_variants - valid_keys}"
    )

"""OS 가상화 시스템 XML 파서 단위 테스트 (osvirt_xml).

합성 XML 문자열로 실데이터 없이 실행한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers.osvirt_xml import detect_variant, parse


# ─ 합성 XML 헬퍼 ──────────────────────────────────────────────────────────────

def _xml(variant="", product="", dumps=None, encoding="UTF-8"):
    """합성 OS 가상화 XML 문자열."""
    asset_extra = ""
    if variant:
        asset_extra += f"<variant>{variant}</variant>\n"
    if product:
        asset_extra += f"<product>{product}</product>\n"

    if dumps is None:
        dumps = [("PRCV-001", "esxcli system account list output")]

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
<hostname>esxi-host-01</hostname>
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

def test_detect_variant_direct_vcenter(tmp_path):
    p = _write(tmp_path, _xml(variant="vcenter"))
    assert detect_variant(p) == "vcenter"


def test_detect_variant_direct_esxi(tmp_path):
    p = _write(tmp_path, _xml(variant="esxi"))
    assert detect_variant(p) == "esxi"


def test_detect_variant_direct_xen(tmp_path):
    p = _write(tmp_path, _xml(variant="xen"))
    assert detect_variant(p) == "xen"


def test_detect_variant_direct_xenserver_alias(tmp_path):
    """직접 키 'xenserver' → 'xen' (약식 정규화)."""
    p = _write(tmp_path, _xml(variant="xenserver"))
    assert detect_variant(p) == "xen"


# ─ detect_variant: product 텍스트 ─────────────────────────────────────────────

def test_detect_variant_product_esxi(tmp_path):
    p = _write(tmp_path, _xml(product="VMware ESXi 7.0.3"))
    assert detect_variant(p) == "esxi"


def test_detect_variant_product_vcenter(tmp_path):
    p = _write(tmp_path, _xml(product="VMware vCenter Server 7.0"))
    assert detect_variant(p) == "vcenter"


def test_detect_variant_product_xenserver(tmp_path):
    p = _write(tmp_path, _xml(product="Citrix XenServer 8.2"))
    assert detect_variant(p) == "xen"


def test_detect_variant_product_citrix_hypervisor(tmp_path):
    p = _write(tmp_path, _xml(product="Citrix Hypervisor 8.2 LTSR"))
    assert detect_variant(p) == "xen"


def test_detect_variant_product_vsphere_fallback_esxi(tmp_path):
    """vsphere 단독 제품군명 → esxi 폴백(슈퍼셋)."""
    p = _write(tmp_path, _xml(product="VMware vSphere 7"))
    assert detect_variant(p) == "esxi"


def test_detect_variant_product_vcenter_priority_over_esxi(tmp_path):
    """vcenter·esxi 토큰이 동시 등장 → vcenter 우선(토큰 순서 안전장치).

    vCenter는 ESXi 호스트를 관리하므로 제품 문자열에 둘 다 나올 수 있다.
    _PRODUCT_TOKENS에서 vcenter를 esxi보다 앞에 둔 설계를 직접 검증.
    """
    p = _write(tmp_path, _xml(product="vCenter Server 7.0 managing ESXi hosts"))
    assert detect_variant(p) == "vcenter"


def test_detect_variant_direct_overrides_product(tmp_path):
    """직접 variant 키가 product보다 우선."""
    p = _write(tmp_path, _xml(variant="xen", product="VMware ESXi 7.0"))
    assert detect_variant(p) == "xen"


# ─ detect_variant: 미식별 → None ──────────────────────────────────────────────

def test_detect_variant_no_tags_none(tmp_path):
    """variant/product 태그 없음 → None (--variant 유도)."""
    p = _write(tmp_path, _xml())
    assert detect_variant(p) is None


def test_detect_variant_unknown_product_none(tmp_path):
    """미지 제품 문자열 → None (자동 폴백 안 함, 범주오류 방지)."""
    p = _write(tmp_path, _xml(product="Hyper-V Server 2019"))
    assert detect_variant(p) is None


def test_detect_variant_unknown_direct_falls_to_product(tmp_path):
    """미등록 직접 키는 무시하고 product로 식별."""
    p = _write(tmp_path, _xml(variant="kvm", product="VMware ESXi 7.0"))
    assert detect_variant(p) == "esxi"


# ─ parse ──────────────────────────────────────────────────────────────────────

def test_parse_basic_tuple_contract(tmp_path):
    p = _write(tmp_path, _xml(dumps=[("PRCV-001", "account list output")]))
    result = parse(p)
    assert len(result) == 1
    cid, resources, ctx = result[0]
    assert cid == "PRCV-001"
    assert ctx is None
    assert len(resources) == 1
    assert resources[0].resource_id == "PRCV-001#0"
    assert "account list output" in resources[0].evidence


def test_parse_multi_ids_share_output(tmp_path):
    p = _write(tmp_path, _xml(dumps=[
        (["PRCV-001", "PRCV-002"], "shared output"),
    ]))
    result = parse(p)
    assert len(result) == 2
    assert result[0][0] == "PRCV-001"
    assert result[1][0] == "PRCV-002"
    assert result[0][1][0].evidence == result[1][1][0].evidence


def test_parse_empty_output_no_resources(tmp_path):
    """공백 CDATA → resources=[] (증거 없음 → 판단보류 가드)."""
    p = _write(tmp_path, _xml(dumps=[("PRCV-007", "   ")]))
    result = parse(p)
    assert result[0][1] == []


def test_parse_duplicate_cid_unique_resource_ids(tmp_path):
    p = _write(tmp_path, _xml(dumps=[
        ("PRCV-001", "output A"),
        ("PRCV-001", "output B"),
    ]))
    result = parse(p)
    rids = [r[1][0].resource_id for r in result if r[1]]
    assert rids[0] == "PRCV-001#0"
    assert rids[1] == "PRCV-001#1"


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
    """EUC-KR 인코딩 XML 정상 디코딩."""
    content = (
        b'<?xml version="1.0" encoding="euc-kr"?>\n'
        b'<script>\n'
        b'<asset><hostname>esxi-01</hostname>'
        b'<variant>esxi</variant></asset>\n'
        b'<results>\n'
        b'<dump><items><id>PRCV-001</id></items>'
        b'<output><![CDATA[esxcli system account list]]></output></dump>\n'
        b'</results>\n</script>\n'
    )
    p = tmp_path / "euckr.xml"
    p.write_bytes(content)
    result = parse(str(p))
    assert result[0][0] == "PRCV-001"
    assert "esxcli system account list" in result[0][1][0].evidence


# ─ 민감 마스킹 (server_xml 체이닝) ────────────────────────────────────────────

def test_parse_masks_crypt_hash(tmp_path):
    """ESXi shadow crypt 해시 → <REDACTED 해시>."""
    crypt = "$6$rounds=5000$salt12345678$" + "A" * 43 + "B" * 43
    p = _write(tmp_path, _xml(dumps=[("PRCV-004", f"root:{crypt}:18000:")]))
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
    p = _write(tmp_path, _xml(dumps=[("PRCV-025", pem)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "MIIEowIBAAKCAQEA" not in ev
    assert "BEGIN RSA PRIVATE KEY" in ev
    assert "<REDACTED>" in ev


# ── 하이퍼바이저 특화 마스킹 초안 (§4-2, 2026-07-11 — 공유 마스커 신규 패턴) ────
# 실데이터 없음 — 공개 문서 기반 보수적 초안. 과마스킹 가드(esxcli/vim-cmd 출력
# 보존)를 osvirt parse() 경로로도 재확인한다(server_xml 단위 테스트와 별도로,
# osvirt 실제 소비 지점에서의 회귀 고정).

def test_parse_masks_vpxuser_credential(tmp_path):
    """vpxa 설정 덤프의 `vpxuserPassword="..."` 결합토큰 값만 마스킹된다."""
    p = _write(tmp_path, _xml(dumps=[
        ("PRCV-001",
         '<vpxa><config vpxuserPassword="R4nd0mVpx!Secr3t" '
         'hostname="esxi-01"/></vpxa>'),
    ]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "R4nd0mVpx!Secr3t" not in ev
    assert 'vpxuserPassword="<REDACTED>"' in ev
    assert 'hostname="esxi-01"' in ev


def test_parse_masks_saml_assertion(tmp_path):
    """vCenter SSO SAML 어서션 본문은 치환, 태그 마커는 보존된다."""
    p = _write(tmp_path, _xml(dumps=[
        ("PRCV-001",
         "<saml2:Assertion ID=\"_x1\">"
         "<saml2:Subject>administrator@vsphere.local</saml2:Subject>"
         "</saml2:Assertion>"),
    ]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "administrator@vsphere.local" not in ev
    assert "<saml2:Assertion" in ev
    assert "</saml2:Assertion>" in ev


def test_parse_overmasking_guard_esxi_config_lines_preserved(tmp_path):
    """과마스킹 가드(핵심): PRCV 판정에 실제 쓰이는 vim-cmd/esxcli 라인은
    하이퍼바이저 특화 패턴 추가 후에도 그대로 보존된다(합성 케이스, 실데이터
    없음 — 실수집 확보 시 재검증 필요)."""
    output = (
        "Security.PasswordMaxDays | 90\n"
        "Security.AccountLockFailures | 5\n"
        "UserVars.HostClientSessionTimeout | 900\n"
        "Syslog.global.logHost | udp://loghost.example.com:514\n"
        "esxcli network vswitch standard policy security get "
        "--vswitch-name=vSwitch0\n"
        "   Allow Promiscuous: false\n"
        "   Forged Transmits: false\n"
        "   MAC Address Change: false\n"
        "Name: vpxuser  Description: vSphere Administrator  "
        "Enabled: true  Locked: false\n"
    )
    p = _write(tmp_path, _xml(dumps=[("PRCV-005", output)]))
    result = parse(p)
    ev = result[0][1][0].evidence
    assert "Security.PasswordMaxDays | 90" in ev
    assert "Security.AccountLockFailures | 5" in ev
    assert "UserVars.HostClientSessionTimeout | 900" in ev
    assert "Syslog.global.logHost | udp://loghost.example.com:514" in ev
    assert "Allow Promiscuous: false" in ev
    assert "Forged Transmits: false" in ev
    assert "MAC Address Change: false" in ev
    assert "Description: vSphere Administrator" in ev
    assert "Enabled: true" in ev
    assert "Locked: false" in ev
    assert "<REDACTED>" not in ev


def test_parse_preserves_normal_output(tmp_path):
    normal = "Account  Description\nroot     Administrator\ndcui     DCUI User"
    p = _write(tmp_path, _xml(dumps=[("PRCV-001", normal)]))
    result = parse(p)
    assert normal in result[0][1][0].evidence


# ─ 파서 레지스트리 + 불변식 ───────────────────────────────────────────────────

def test_parser_registry_osvirt_xml():
    from judge_tool.parsers import get_parser
    parser = get_parser("osvirt_xml")
    assert hasattr(parser, "parse")
    assert hasattr(parser, "detect_variant")


def test_detect_variant_returns_registered_key_or_none(tmp_path):
    """detect_variant 반환값은 OS_VIRT.variants 키 또는 None.

    (미등록 키 반환 시 전 항목 무증상 스킵 — 불변식 방어.)
    """
    from judge_tool.parsers.osvirt_xml import (
        _DIRECT_VARIANT_MAP, _PRODUCT_TOKENS)
    from judge_tool.profile import OS_VIRT

    valid = set(OS_VIRT.variants.keys())
    mapped = set(_DIRECT_VARIANT_MAP.values()) | {v for _, v in _PRODUCT_TOKENS}
    assert mapped.issubset(valid), (
        f"detect_variant가 반환할 수 있는 미등록 키: {mapped - valid}")

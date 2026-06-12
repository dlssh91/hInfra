"""network_xml 파서 단위 테스트 (작업④ — 합성 픽스처 기반).

실수집 데이터 대상 e2e는 샘플 미확보로 보류. 수집 포맷 명세(PROVISIONAL XML
엔벨로프)에 따른 합성 XML로 parse/detect_variant/마스킹 계약을 검증한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers import get_parser, network_xml


def _write(tmp_path, name, text, encoding="utf-8"):
    p = tmp_path / name
    p.write_bytes(text.encode(encoding))
    return str(p)


def _net_xml(vendor="Cisco Systems", model="Catalyst 3750",
             version="IOS 15.2", body=None):
    body = body if body is not None else """
<dump>
<items><id>NET-001</id></items>
<output><![CDATA[
enable secret 5 $1$mERr$testhashhashhashhashhashhash
no ip http server
]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<script>
<asset>
<hostname>router1</hostname>
<vendor>{vendor}</vendor>
<model>{model}</model>
<version>{version}</version>
</asset>
<results>{body}</results>
</script>
"""


def _net_xml_os(os_text, body=None):
    """os 태그를 사용하는 변형 (vendor 없음)."""
    body = body if body is not None else """
<dump>
<items><id>NET-001</id></items>
<output><![CDATA[show version output]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<script>
<asset>
<hostname>switch1</hostname>
<os>{os_text}</os>
</asset>
<results>{body}</results>
</script>
"""


# ── 파서 등록 ───────────────────────────────────────────────────────────────────

def test_parser_registered():
    assert get_parser("network_xml") is network_xml
    assert hasattr(network_xml, "detect_variant")  # 내용 기반 폴백 seam 계약
    assert hasattr(network_xml, "parse")


# ── parse 3-튜플 계약 ────────────────────────────────────────────────────────────

def test_parse_basic_3tuple(tmp_path):
    path = _write(tmp_path, "net.xml", _net_xml())
    out = network_xml.parse(path)
    assert len(out) >= 1
    cid, resources, context = out[0]
    assert cid == "NET-001"
    assert context is None
    assert resources[0].resource_id == "NET-001#0"
    assert resources[0].status == ""
    assert resources[0].detail == ""


def test_parse_multi_id_shares_output(tmp_path):
    """한 dump에 <id>가 여러 개 → 각 id로 분리 emit, 같은 output 공유."""
    body = """
<dump>
<items><id>NET-010</id><id>NET-011</id></items>
<output><![CDATA[shared config line]]></output>
</dump>
"""
    path = _write(tmp_path, "multi.xml", _net_xml(body=body))
    out = network_xml.parse(path)
    assert [e[0] for e in out] == ["NET-010", "NET-011"]
    for cid, resources, _ in out:
        assert resources[0].resource_id == f"{cid}#0"
        assert resources[0].evidence == "shared config line"


def test_parse_empty_output_no_resources(tmp_path):
    """공백뿐인 output → ResourceEvidence 없음(빈 리스트)."""
    body = """
<dump><items><id>NET-020</id></items><output><![CDATA[   ]]></output></dump>
"""
    path = _write(tmp_path, "empty.xml", _net_xml(body=body))
    out = network_xml.parse(path)
    assert out == [("NET-020", [], None)]


def test_parse_malformed_raises_reporterror(tmp_path):
    path = _write(tmp_path, "broken.xml", "<script><results><dump>")
    with pytest.raises(ReportError, match="네트워크 XML 파싱 실패"):
        network_xml.parse(path)


def test_parse_no_dumps_raises_reporterror(tmp_path):
    path = _write(tmp_path, "nodumps.xml", _net_xml(body=""))
    with pytest.raises(ReportError, match="네트워크 결과 파싱 실패"):
        network_xml.parse(path)


def test_parse_euckr_encoding(tmp_path):
    """encoding="euc-kr" 선언 파일도 디코딩·파싱된다."""
    xml = _net_xml().replace('encoding="UTF-8"', 'encoding="euc-kr"').replace(
        "<hostname>router1</hostname>", "<hostname>라우터일호</hostname>")
    path = _write(tmp_path, "euckr.xml", xml, encoding="euc-kr")
    out = network_xml.parse(path)
    assert out[0][0] == "NET-001"


def test_resource_id_unique_across_dumps(tmp_path):
    """같은 cid가 여러 dump에 등장하면 resource_id가 #0, #1, ... 로 유일."""
    body = """
<dump>
<items><id>NET-001</id></items>
<output><![CDATA[first dump]]></output>
</dump>
<dump>
<items><id>NET-001</id></items>
<output><![CDATA[second dump]]></output>
</dump>
"""
    path = _write(tmp_path, "dup.xml", _net_xml(body=body))
    out = network_xml.parse(path)
    assert len(out) == 2
    assert out[0][1][0].resource_id == "NET-001#0"
    assert out[1][1][0].resource_id == "NET-001#1"


# ── detect_variant ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vendor,expected", [
    ("Cisco Systems", "cisco"),
    ("CISCO Systems", "cisco"),         # 대소문자 무관
    ("Cisco", "cisco"),
    ("cisco systems", "cisco"),
])
def test_detect_variant_cisco_vendor(tmp_path, vendor, expected):
    path = _write(tmp_path, "v.xml", _net_xml(vendor=vendor))
    assert network_xml.detect_variant(path) == expected


@pytest.mark.parametrize("version_str,expected", [
    ("IOS-XE 17.3.1", "cisco"),
    ("NX-OS 9.3", "cisco"),
    ("Catalyst 9000", "cisco"),
    ("IOS 15.2(4)M7", "cisco"),
])
def test_detect_variant_cisco_tokens_in_version(tmp_path, version_str, expected):
    path = _write(tmp_path, "v2.xml", _net_xml(version=version_str))
    assert network_xml.detect_variant(path) == expected


def test_detect_variant_ios_xe_os_tag(tmp_path):
    """os 태그에 IOS-XE가 있으면 cisco."""
    path = _write(tmp_path, "v3.xml", _net_xml_os("IOS-XE"))
    assert network_xml.detect_variant(path) == "cisco"


@pytest.mark.parametrize("vendor,expected", [
    ("Juniper Networks", "generic"),
    ("A10 Networks", "generic"),
    ("Brocade", "generic"),
    ("F5 Networks", "generic"),
    ("Unknown", "generic"),
    ("", "generic"),
])
def test_detect_variant_other_vendor_returns_generic(tmp_path, vendor, expected):
    # version과 model을 비-Cisco 값으로 설정 — 기본값은 cisco 토큰을 포함
    path = _write(tmp_path, "v4.xml",
                  _net_xml(vendor=vendor, model="SRX-320", version="JUNOS 22.4"))
    assert network_xml.detect_variant(path) == expected


def test_detect_variant_no_asset_tag_returns_generic(tmp_path):
    """asset 태그 없음 → generic."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<script>
<results>
<dump><items><id>NET-001</id></items><output><![CDATA[x]]></output></dump>
</results>
</script>
"""
    path = _write(tmp_path, "no_asset.xml", xml)
    assert network_xml.detect_variant(path) == "generic"


def test_detect_variant_bare_bios_word_not_cisco(tmp_path):
    """'bios' 단어는 Cisco 토큰이 아니므로 generic. version/model도 비-Cisco 값 사용."""
    path = _write(tmp_path, "bios.xml",
                  _net_xml(vendor="bios firmware vendor",
                           model="Generic-HW-1", version="BIOS 2.4.1"))
    assert network_xml.detect_variant(path) == "generic"


# ── 마스킹 테스트 ────────────────────────────────────────────────────────────────

def _parse_evidence(tmp_path, name, config_text):
    """config_text를 CDATA output에 넣고 parse 후 evidence 반환."""
    body = f"""
<dump>
<items><id>NET-001</id></items>
<output><![CDATA[{config_text}]]></output>
</dump>
"""
    path = _write(tmp_path, name, _net_xml(body=body))
    out = network_xml.parse(path)
    return out[0][1][0].evidence


def test_mask_enable_secret_body_masked_prefix_preserved(tmp_path):
    """enable secret 5 <hash> → 비밀값 마스킹, 'enable secret 5' 접두 보존."""
    config = "enable secret 5 $1$mERr$hashhashhashhashhashhashhash\nno ip http server"
    ev = _parse_evidence(tmp_path, "en_secret.xml", config)
    # 비밀값(해시) 마스킹
    assert "$1$mERr$" not in ev or "<REDACTED" in ev
    # 접두 키워드 보존
    assert "enable secret" in ev
    # 비민감 줄 보존
    assert "no ip http server" in ev
    # 마스킹 마커 존재
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_type7_short_hex_masked(tmp_path):
    """Type-7 짧은 hex(14~30자) — 키워드 앵커가 길이무관으로 포착 (under-mask 경계)."""
    # Type-7 예시: 14자 hex (서버 _LONG_HEX 32+ 기준 미달이므로 키워드앵커 필수)
    config = "enable password 7 0822455D0A16\nno service password-encryption"
    ev = _parse_evidence(tmp_path, "type7.xml", config)
    # 패스워드 값은 마스킹
    assert "0822455D0A16" not in ev
    assert "<REDACTED 비밀번호#0>" in ev
    # 비민감 줄 보존
    assert "no service password-encryption" in ev


def test_mask_equivalence_same_value_same_token(tmp_path):
    """동일 Type-7 값 두 줄 → 같은 <REDACTED 비밀번호#N> (NET-009 동등성)."""
    config = (
        "username admin password 7 0822455D0A16\n"
        "enable password 7 0822455D0A16\n"
        "username guest password 7 AABBCCDDEE1122\n"
    )
    ev = _parse_evidence(tmp_path, "equiv.xml", config)
    # 같은 값은 같은 번호 (#0)
    assert ev.count("<REDACTED 비밀번호#0>") == 2
    # 다른 값은 다른 번호 (#1)
    assert "<REDACTED 비밀번호#1>" in ev
    # 원문 비밀값 없음
    assert "0822455D0A16" not in ev
    assert "AABBCCDDEE1122" not in ev


def test_mask_snmp_community_secret_masked_ro_preserved(tmp_path):
    """snmp community 비밀명 마스킹, RO/ACL 후행 보존."""
    config = "snmp-server community SecretComm RO 10\nsnmp-server location DataCenter"
    ev = _parse_evidence(tmp_path, "snmp.xml", config)
    assert "SecretComm" not in ev
    assert "<REDACTED 커뮤니티#0>" in ev
    # 비민감 줄 보존
    assert "snmp-server location DataCenter" in ev


def test_mask_snmp_community_public_preserved(tmp_path):
    """snmp community public → 원문 보존 (취약 증거)."""
    config = "snmp-server community public RO\nsnmp-server community private RW"
    ev = _parse_evidence(tmp_path, "snmp_pub.xml", config)
    assert "snmp-server community public" in ev
    assert "snmp-server community private" in ev
    # public/private는 마스킹 마커로 치환되지 않아야 함
    assert "<REDACTED 커뮤니티" not in ev


def test_mask_key_chain_key_number_preserved(tmp_path):
    """key chain `key 1` 숫자 보존, key-string 값 마스킹 (over-mask 경계)."""
    config = (
        "key chain MYCHAIN\n"
        " key 1\n"
        "  key-string MySecretKey\n"
        " key 2\n"
        "  key-string AnotherSecret\n"
    )
    ev = _parse_evidence(tmp_path, "keychain.xml", config)
    # key 번호 보존 (over-mask 방지)
    assert "key 1" in ev
    assert "key 2" in ev
    assert "key chain MYCHAIN" in ev
    # key-string 값 마스킹
    assert "MySecretKey" not in ev
    assert "AnotherSecret" not in ev
    assert "<REDACTED 비밀번호#" in ev


def test_mask_tacacs_key_masked_host_preserved(tmp_path):
    """tacacs-server key 마스킹, host 주소 보존."""
    config = (
        "tacacs-server host 192.168.1.10 key 7 TACACSSECRET\n"
        "radius-server host 10.0.0.1 key MyRadiusKey\n"
    )
    ev = _parse_evidence(tmp_path, "tacacs.xml", config)
    assert "TACACSSECRET" not in ev
    assert "MyRadiusKey" not in ev
    # host 주소 보존 (키워드 밖이므로)
    assert "192.168.1.10" in ev
    assert "10.0.0.1" in ev
    assert "<REDACTED 비밀번호#" in ev


def test_mask_non_secret_config_lines_preserved(tmp_path):
    """인터페이스/description/service password-encryption 등 비밀 아닌 줄 원문 보존."""
    config = (
        "interface GigabitEthernet0/0\n"
        " description WAN uplink to ISP\n"
        "service password-encryption\n"
        "ip route 0.0.0.0 0.0.0.0 192.168.1.1\n"
    )
    ev = _parse_evidence(tmp_path, "nonsecret.xml", config)
    assert "interface GigabitEthernet0/0" in ev
    assert "description WAN uplink to ISP" in ev
    assert "service password-encryption" in ev
    assert "ip route 0.0.0.0 0.0.0.0 192.168.1.1" in ev
    # 마스킹 마커 없음
    assert "<REDACTED" not in ev


def test_mask_pem_key_chained_from_server(tmp_path):
    """PEM 개인키 블록 — server_xml 체이닝으로 마스킹."""
    config = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA2a2rwplBQLkeydata...\n"
        "-----END RSA PRIVATE KEY-----\n"
        "no ip telnet\n"
    )
    ev = _parse_evidence(tmp_path, "pem.xml", config)
    assert "MIIEowIBAAKCAQEA2a2rwplBQLkeydata" not in ev
    assert "<REDACTED>" in ev
    assert "no ip telnet" in ev


def test_mask_long_hex_chained_from_server(tmp_path):
    """32+ hex — server_xml 체이닝으로 마스킹."""
    short_hex = "deadbeef"       # 8자 보존
    long_hex = "a" * 32          # 32자 마스킹
    config = f"short={short_hex}\nmd5={long_hex}\nno ip http server"
    ev = _parse_evidence(tmp_path, "hex.xml", config)
    assert short_hex in ev
    assert long_hex not in ev
    assert "<REDACTED>" in ev


def test_mask_juniper_dollar9_masked(tmp_path):
    """Juniper $9$ 난독화 → <REDACTED 비밀번호#N>."""
    config = (
        "set system root-authentication encrypted-password \"$9$secrethash123\"\n"
        "set interfaces ge-0/0/0 description uplink\n"
    )
    ev = _parse_evidence(tmp_path, "juniper.xml", config)
    assert "$9$secrethash123" not in ev
    assert "<REDACTED 비밀번호#" in ev
    assert "set interfaces ge-0/0/0 description uplink" in ev


def test_mask_equivalence_across_dumps(tmp_path):
    """동일 비밀값이 여러 dump에 걸쳐 등장해도 같은 <REDACTED #N> (파일 단위 공유)."""
    body = """
<dump>
<items><id>NET-009</id></items>
<output><![CDATA[enable secret 5 SameSecret123]]></output>
</dump>
<dump>
<items><id>NET-010</id></items>
<output><![CDATA[enable password 7 SameSecret123]]></output>
</dump>
"""
    path = _write(tmp_path, "cross_dump.xml", _net_xml(body=body))
    out = network_xml.parse(path)
    ev0 = out[0][1][0].evidence
    ev1 = out[1][1][0].evidence
    # 두 dump 모두 같은 번호 #0
    assert "<REDACTED 비밀번호#0>" in ev0
    assert "<REDACTED 비밀번호#0>" in ev1
    # 원문 없음
    assert "SameSecret123" not in ev0
    assert "SameSecret123" not in ev1


# ── H1 회귀 테스트: ppp chap/pap / SNMPv3 auth+priv ──────────────────────────

def test_mask_h1_ppp_chap_password_type0(tmp_path):
    """H1: ppp chap password 0 <KEY> — 키값 마스킹, 명령/타입 보존."""
    config = "ppp chap password 0 MyChapSecret"
    ev = _parse_evidence(tmp_path, "ppp_chap0.xml", config)
    assert "MyChapSecret" not in ev
    assert "ppp chap password 0" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_h1_ppp_chap_password_type7(tmp_path):
    """H1: ppp chap password 7 <KEY> — Type-7 변형도 마스킹."""
    config = "ppp chap password 7 0822455D0A16"
    ev = _parse_evidence(tmp_path, "ppp_chap7.xml", config)
    assert "0822455D0A16" not in ev
    assert "ppp chap password 7" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_h1_ppp_chap_no_type(tmp_path):
    """H1: ppp chap password (타입 없음) <KEY> — 타입 생략 변형."""
    config = "ppp chap password NoTypeSecret"
    ev = _parse_evidence(tmp_path, "ppp_chapnt.xml", config)
    assert "NoTypeSecret" not in ev
    assert "ppp chap password" in ev


def test_mask_h1_ppp_pap_sent_username(tmp_path):
    """H1: ppp pap sent-username bob password 0 <KEY> — username 보존, 키 마스킹."""
    config = "ppp pap sent-username bob password 0 MyPapSecret"
    ev = _parse_evidence(tmp_path, "ppp_pap.xml", config)
    assert "MyPapSecret" not in ev
    assert "ppp pap sent-username bob password 0" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_h1_snmpv3_auth_and_priv_both_masked(tmp_path):
    """H1: snmp-server user v3 auth md5 <AUTHKEY> priv des <PRIVKEY> — 두 키 모두 마스킹."""
    config = (
        "snmp-server user admin GROUP v3 auth md5 MyAuthPass priv des MyPrivPass"
    )
    ev = _parse_evidence(tmp_path, "snmpv3.xml", config)
    assert "MyAuthPass" not in ev
    assert "MyPrivPass" not in ev
    # 알고리즘 토큰·username·group 보존
    assert "auth md5" in ev
    assert "priv des" in ev
    assert "admin" in ev
    assert "GROUP" in ev
    assert "<REDACTED 비밀번호#" in ev


def test_mask_h1_snmpv3_sha_aes(tmp_path):
    """H1: snmp-server user v3 auth sha <KEY> priv aes <KEY> — sha/aes 변형."""
    config = (
        "snmp-server user secuser SECGROUP v3 auth sha ShaAuthKey priv aes AesPrivKey"
    )
    ev = _parse_evidence(tmp_path, "snmpv3_sha_aes.xml", config)
    assert "ShaAuthKey" not in ev
    assert "AesPrivKey" not in ev
    assert "auth sha" in ev
    assert "priv aes" in ev


# ── H2 회귀 테스트: generic(비-Cisco) 벤더 평문 비밀 ──────────────────────────

def test_mask_h2_plain_text_password(tmp_path):
    """H2: Juniper plain-text-password <VALUE> — 키값 마스킹."""
    config = (
        "set system login user admin authentication plain-text-password MyPlainPass123"
    )
    ev = _parse_evidence(tmp_path, "jnpr_plain.xml", config)
    assert "MyPlainPass123" not in ev
    assert "plain-text-password" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_h2_encrypted_password(tmp_path):
    """H2: encrypted-password <VALUE> — 키값 마스킹."""
    config = "set system login user admin authentication encrypted-password $ABC123"
    ev = _parse_evidence(tmp_path, "jnpr_enc.xml", config)
    assert "$ABC123" not in ev
    assert "encrypted-password" in ev


def test_mask_h2_set_snmp_community_non_public(tmp_path):
    """H2: set snmp community <비공개명> — 마스킹. public은 원문 보존."""
    config = (
        "set snmp community PrivateCommunityStr\n"
        "set snmp community public\n"
    )
    ev = _parse_evidence(tmp_path, "jnpr_snmp.xml", config)
    assert "PrivateCommunityStr" not in ev
    assert "<REDACTED 커뮤니티#0>" in ev
    # public은 보존
    assert "set snmp community public" in ev


def test_mask_h2_preshared_key_ascii_text(tmp_path):
    """H2: pre-shared-key ascii-text <VALUE> — Juniper IKE PSK 마스킹."""
    config = "set security ike policy MyPolicy pre-shared-key ascii-text MyJuniperPSK"
    ev = _parse_evidence(tmp_path, "jnpr_psk.xml", config)
    assert "MyJuniperPSK" not in ev
    assert "pre-shared-key ascii-text" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_h2_preshared_key_hexadecimal(tmp_path):
    """H2: pre-shared-key hexadecimal <VALUE> — hex PSK 마스킹."""
    config = "set security ike policy HexPolicy pre-shared-key hexadecimal AABBCCDD1122"
    ev = _parse_evidence(tmp_path, "jnpr_hex_psk.xml", config)
    assert "AABBCCDD1122" not in ev
    assert "pre-shared-key hexadecimal" in ev


def test_mask_h2_f5_secret(tmp_path):
    """H2: F5 auth ... { secret <VALUE> } — secret 값 마스킹."""
    config = "auth radius { secret MyF5Secret }"
    ev = _parse_evidence(tmp_path, "f5_secret.xml", config)
    assert "MyF5Secret" not in ev
    assert "secret" in ev
    assert "<REDACTED 비밀번호#0>" in ev


# ── M1 회귀 테스트: community_index 분리 / 동등성 ────────────────────────────

def test_mask_m1_community_value_equals_dunder_community(tmp_path):
    """M1 엣지: community 값이 '__community__' 문자열이어도 타입 혼용 없음."""
    # 수정 전이라면 secret_index["__community__"] = <dict>가 되어
    # 비밀값 "__community__"와 충돌했을 케이스.
    config = 'snmp-server community __community__ RO'
    ev = _parse_evidence(tmp_path, "m1_edge.xml", config)
    assert "__community__" not in ev or "<REDACTED" in ev
    # 커뮤니티 마스킹 마커 존재
    assert "<REDACTED 커뮤니티#0>" in ev


def test_mask_m1_community_and_password_counter_separate(tmp_path):
    """M1: community 카운터와 password 카운터가 독립적 #N을 갖는다."""
    config = (
        "snmp-server community SecretComm RO\n"
        "enable secret 5 EnableHash\n"
        "snmp-server community AnotherComm RW\n"
    )
    ev = _parse_evidence(tmp_path, "m1_counter.xml", config)
    # community: #0, #1 (커뮤니티 네임스페이스)
    assert "<REDACTED 커뮤니티#0>" in ev
    assert "<REDACTED 커뮤니티#1>" in ev
    # password: #0 (비밀번호 네임스페이스 — community와 별개로 시작)
    assert "<REDACTED 비밀번호#0>" in ev
    # 원문 없음
    assert "SecretComm" not in ev
    assert "EnableHash" not in ev
    assert "AnotherComm" not in ev


def test_mask_m1_same_community_same_token(tmp_path):
    """M1: 동일 community 값 두 줄 → 같은 <REDACTED 커뮤니티#N> (동등성 보존)."""
    config = (
        "snmp-server community SharedComm RO\n"
        "snmp-server community SharedComm RW\n"
    )
    ev = _parse_evidence(tmp_path, "m1_equiv.xml", config)
    assert ev.count("<REDACTED 커뮤니티#0>") == 2
    assert "SharedComm" not in ev


# ── M2 회귀 테스트: AAA key 후행 토큰 보존 ──────────────────────────────────

def test_mask_m2_tacacs_key_timeout_preserved(tmp_path):
    """M2: tacacs-server key 7 <KEY> timeout 5 — timeout 후행 토큰 보존."""
    config = "tacacs-server host 1.2.3.4 key 7 0822455D0A16 timeout 5"
    ev = _parse_evidence(tmp_path, "m2_tacacs.xml", config)
    assert "0822455D0A16" not in ev
    assert "timeout 5" in ev
    assert "1.2.3.4" in ev
    assert "<REDACTED 비밀번호#0>" in ev


def test_mask_m2_radius_key_retransmit_preserved(tmp_path):
    """M2: radius-server key <KEY> retransmit 3 — retransmit 후행 보존."""
    config = "radius-server host 10.0.0.1 key RadiusKey retransmit 3"
    ev = _parse_evidence(tmp_path, "m2_radius.xml", config)
    assert "RadiusKey" not in ev
    assert "retransmit 3" in ev
    assert "10.0.0.1" in ev


# ── over-mask 회귀 재확인 ─────────────────────────────────────────────────────

def test_overmask_description_not_touched(tmp_path):
    """over-mask 회귀: description 줄은 새 패턴으로도 건드리지 않는다."""
    config = (
        "interface GigabitEthernet0/1\n"
        " description secret uplink to ISP\n"
        " ip address 192.168.1.1 255.255.255.0\n"
    )
    ev = _parse_evidence(tmp_path, "desc_intact.xml", config)
    assert "description secret uplink to ISP" in ev
    # 마스킹 마커 없음
    assert "<REDACTED" not in ev


def test_overmask_service_password_encryption_preserved(tmp_path):
    """over-mask 회귀: service password-encryption 줄 원문 보존."""
    config = "service password-encryption\nno ip http server"
    ev = _parse_evidence(tmp_path, "svc_pe.xml", config)
    assert "service password-encryption" in ev
    assert "no ip http server" in ev
    assert "<REDACTED" not in ev


def test_overmask_key_chain_number_preserved(tmp_path):
    """over-mask 회귀: key chain 'key 1' 숫자 보존 (bare key 번호는 마스킹 금지)."""
    config = (
        "key chain MYCHAIN\n"
        " key 1\n"
        "  key-string MySecret\n"
    )
    ev = _parse_evidence(tmp_path, "keychain2.xml", config)
    assert "key 1" in ev
    assert "MySecret" not in ev


def test_overmask_set_snmp_community_public_preserved(tmp_path):
    """over-mask 회귀: set snmp community public — generic 경로에서도 원문 보존."""
    config = "set snmp community public"
    ev = _parse_evidence(tmp_path, "jnpr_pub.xml", config)
    assert "set snmp community public" in ev
    assert "<REDACTED" not in ev


def test_overmask_snmp_location_not_touched(tmp_path):
    """over-mask 회귀: snmp-server location 줄 원문 보존."""
    config = (
        "snmp-server community SecretComm RO\n"
        "snmp-server location DataCenter Seoul\n"
    )
    ev = _parse_evidence(tmp_path, "snmp_loc.xml", config)
    assert "snmp-server location DataCenter Seoul" in ev
    assert "SecretComm" not in ev

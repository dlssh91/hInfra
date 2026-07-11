"""server_xml 파서 단위 테스트 (작업③ — 합성 픽스처 기반).

실수집 데이터 대상 e2e는 샘플 미확보로 보류. fsi_unix.sh/fsi_win.bat 출력
포맷 명세에 따른 합성 XML로 parse/detect_variant 계약을 검증한다.
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers import get_parser, server_xml


def _write(tmp_path, name, text, encoding="utf-8"):
    p = tmp_path / name
    p.write_bytes(text.encode(encoding))
    return str(p)


def _server_xml(os_text="Linux", body=None):
    body = body if body is not None else """
<dump>
<items><id>SRV-001</id></items>
<output><![CDATA[
root:x:0:0:root:/root:/bin/bash
PermitRootLogin no
]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="isac.xsl"?>
<script>
<asset>
<hostname>testhost</hostname>
<os>{os_text}</os>
<uname>uname-str</uname>
<whoami>root</whoami>
<version>2026.1</version>
</asset>
<results>{body}</results>
</script>
"""


def test_parser_registered():
    assert get_parser("server_xml") is server_xml
    assert hasattr(server_xml, "detect_variant")  # 내용 기반 폴백 seam 계약


def test_parse_basic_raw_evidence(tmp_path):
    path = _write(tmp_path, "h-s-20260612.xml", _server_xml())
    out = server_xml.parse(path)
    # 3-튜플 계약(db_json.parse와 동일): (id, [ResourceEvidence], context)
    assert len(out) == 1
    cid, resources, context = out[0]
    assert cid == "SRV-001"
    assert context is None
    assert len(resources) == 1
    r = resources[0]
    assert r.resource_id == "SRV-001#0"
    assert r.status == "" and r.detail == ""
    assert "PermitRootLogin no" in r.evidence
    assert r.evidence == r.evidence.strip()  # CDATA strip


def test_parse_multi_id_dump_shares_output(tmp_path):
    """한 dump에 <id>가 여러 개(fDumpS 루프) → 각 id로 분리 emit,
    같은 output 증거 공유."""
    body = """
<dump>
<items><id>SRV-002</id><id>SRV-003</id></items>
<output><![CDATA[shared evidence line]]></output>
</dump>
"""
    path = _write(tmp_path, "h-s-1.xml", _server_xml(body=body))
    out = server_xml.parse(path)
    assert [e[0] for e in out] == ["SRV-002", "SRV-003"]
    for cid, resources, _ in out:
        assert resources[0].resource_id == f"{cid}#0"
        assert resources[0].evidence == "shared evidence line"


def test_parse_non_srv_ids_also_emitted(tmp_path):
    """비-SRV 덤프(Internet, date 등)도 파싱은 된다 — 기준 매칭 실패로
    main.run에서 자연 스킵되는 것이 계약."""
    body = """
<dump><items><id>Internet</id></items><output><![CDATA[ping ok]]></output></dump>
<dump><items><id>SRV-010</id></items><output><![CDATA[x]]></output></dump>
"""
    path = _write(tmp_path, "h-s-2.xml", _server_xml(body=body))
    ids = [e[0] for e in server_xml.parse(path)]
    assert ids == ["Internet", "SRV-010"]


def test_parse_empty_output_no_resources(tmp_path):
    """공백뿐인 output → ResourceEvidence 없음(빈 리스트).
    reconcile의 '증거 없음 → 판단보류' 가드가 동작하는 보수적 선택."""
    body = """
<dump><items><id>SRV-004</id></items><output><![CDATA[   ]]></output></dump>
"""
    path = _write(tmp_path, "h-s-3.xml", _server_xml(body=body))
    out = server_xml.parse(path)
    assert out == [("SRV-004", [], None)]


def test_parse_bare_ampersand_sanitized(tmp_path):
    """CDATA 밖 bare '&'(well-formed 위반)는 sanitize로 보정되어 파싱 성공.
    CDATA 안 '&'는 원본 보존."""
    xml = _server_xml(os_text="Linux").replace(
        "<hostname>testhost</hostname>", "<hostname>a&b</hostname>").replace(
        "PermitRootLogin no", "AT&T literal")
    path = _write(tmp_path, "h-s-4.xml", xml)
    out = server_xml.parse(path)
    assert "AT&T literal" in out[0][1][0].evidence


def test_parse_euckr_declared_encoding(tmp_path):
    """encoding="euc-kr" 선언 파일도 디코딩·파싱된다(한글 포함)."""
    xml = _server_xml().replace('encoding="UTF-8"', 'encoding="euc-kr"').replace(
        "<hostname>testhost</hostname>", "<hostname>서버일호</hostname>")
    path = _write(tmp_path, "h-s-5.xml", xml, encoding="euc-kr")
    out = server_xml.parse(path)
    assert out[0][0] == "SRV-001"
    assert server_xml.detect_variant(path) == "linux"


def test_parse_malformed_raises_reporterror(tmp_path):
    path = _write(tmp_path, "broken.xml", "<script><results><dump>")
    with pytest.raises(ReportError, match="서버 XML 파싱 실패"):
        server_xml.parse(path)


def test_parse_no_dumps_raises_reporterror(tmp_path):
    path = _write(tmp_path, "empty.xml", _server_xml(body=""))
    with pytest.raises(ReportError, match="dump 항목이 없습니다"):
        server_xml.parse(path)


# ── detect_variant: OS 문자열 → 변형 키 ─────────────────────────────────────

@pytest.mark.parametrize("os_text,expected", [
    ("Linux", "linux"),
    ("linux", "linux"),
    ("AIX", "aix"),
    ("HP-UX", "hpux"),
    ("HPUX", "hpux"),
    ("SunOS", "solaris"),
    ("Solaris 11", "solaris"),
    ("Microsoft Windows Server 2019 Standard", "win"),
])
def test_detect_variant_mapping(tmp_path, os_text, expected):
    path = _write(tmp_path, "v.xml", _server_xml(os_text=os_text))
    assert server_xml.detect_variant(path) == expected


def test_detect_variant_unknown_os_returns_none(tmp_path):
    path = _write(tmp_path, "v2.xml", _server_xml(os_text="FreeBSD"))
    assert server_xml.detect_variant(path) is None


def test_detect_variant_missing_os_tag_returns_none(tmp_path):
    xml = _server_xml().replace("<os>Linux</os>", "")
    path = _write(tmp_path, "v3.xml", xml)
    assert server_xml.detect_variant(path) is None


# ── M3: 민감정보 마스킹 테스트 ──────────────────────────────────────────────────

def test_mask_shadow_hash_redacted(tmp_path):
    """shadow 파일의 Unix crypt 해시($6$ 등)는 evidence에서 원문이 사라지고
    <REDACTED 해시>로 치환된다. 비민감 텍스트(PermitRootLogin 등)는 보존."""
    body = """
<dump>
<items><id>SRV-010</id></items>
<output><![CDATA[
root:$6$rounds=5000$saltsalt$hashhashhashhashhashhashhashhash1234:19000:0:99999:7:::
daemon:*:18375:0:99999:7:::
PermitRootLogin no
]]></output>
</dump>
"""
    path = _write(tmp_path, "shadow.xml", _server_xml(body=body))
    out = server_xml.parse(path)
    evidence = out[0][1][0].evidence
    # 원래 해시 토큰이 없어야 한다
    assert "$6$" not in evidence
    assert "hashhashhashhash" not in evidence
    # 마스킹 마커가 있어야 한다
    assert "<REDACTED 해시>" in evidence
    # 비민감 텍스트는 보존된다
    assert "PermitRootLogin no" in evidence
    assert "daemon:*:" in evidence


def test_mask_other_crypt_schemes_redacted(tmp_path):
    """$5$(SHA-256) 등 다른 crypt 형식도 마스킹된다."""
    body = """
<dump>
<items><id>SRV-011</id></items>
<output><![CDATA[
user1:$5$saltsalts$hashhashhashhashhashhashhashh:19000:0:99999:7:::
user2:$1$saltsalt$hashhashhashhash1234:19000:0:99999:7:::
]]></output>
</dump>
"""
    path = _write(tmp_path, "crypt.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "$5$" not in evidence
    assert "$1$" not in evidence
    assert "<REDACTED 해시>" in evidence


def test_mask_private_key_block_redacted(tmp_path):
    """PEM/OpenSSH 개인키 블록은 BEGIN/END 마커를 남기고 본문만 마스킹된다."""
    body = """
<dump>
<items><id>SRV-012</id></items>
<output><![CDATA[
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29Ba9DYY2NKGK
4rIBPtFSBNBjLJKMExKYCuauRDhNkBUDpQnbJlqPCpXDpYQv9sHNf+2w==
-----END RSA PRIVATE KEY-----
PasswordAuthentication no
]]></output>
</dump>
"""
    path = _write(tmp_path, "privkey.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    # 키 본문이 없어야 한다
    assert "MIIEowIBAAKCAQEA" not in evidence
    # 마스킹 마커가 있어야 한다
    assert "<REDACTED>" in evidence
    # BEGIN/END 마커는 남아도 무방(명세 상 "무방")
    # 비민감 텍스트는 보존
    assert "PasswordAuthentication no" in evidence


def test_mask_openssh_private_key_redacted(tmp_path):
    """OPENSSH 형식 개인키도 마스킹된다."""
    body = """
<dump>
<items><id>SRV-013</id></items>
<output><![CDATA[
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...secret_key_data...AAAA
-----END OPENSSH PRIVATE KEY-----
]]></output>
</dump>
"""
    path = _write(tmp_path, "openssh.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "b3BlbnNzaC1rZXktdjEAAAAA" not in evidence
    assert "secret_key_data" not in evidence
    assert "<REDACTED>" in evidence


def test_mask_long_hex_redacted_short_hex_preserved(tmp_path):
    """32+ 연속 hex는 마스킹되고, 8자 이하 짧은 hex는 보존된다."""
    short_hex = "deadbeef"          # 8자 — 보존
    long_hex = "a" * 32             # 32자 MD5 길이 — 마스킹
    very_long_hex = "b" * 64        # 64자 SHA256 길이 — 마스킹
    body = f"""
<dump>
<items><id>SRV-014</id></items>
<output><![CDATA[
short={short_hex}
md5sum={long_hex}
sha256sum={very_long_hex}
normal_text=ok
]]></output>
</dump>
"""
    path = _write(tmp_path, "hex.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    # 짧은 hex는 보존
    assert short_hex in evidence
    # 32+ hex는 마스킹
    assert long_hex not in evidence
    assert very_long_hex not in evidence
    assert "<REDACTED>" in evidence
    # 일반 텍스트 보존
    assert "normal_text=ok" in evidence


# ── M1: resource_id 유일성 테스트 ────────────────────────────────────────────────

def test_resource_id_unique_across_dumps(tmp_path):
    """같은 cid가 여러 dump에 등장하면 resource_id가 #0, #1, ... 로 유일하게 부여된다."""
    body = """
<dump>
<items><id>SRV-001</id></items>
<output><![CDATA[first dump output]]></output>
</dump>
<dump>
<items><id>SRV-001</id></items>
<output><![CDATA[second dump output]]></output>
</dump>
"""
    path = _write(tmp_path, "dup.xml", _server_xml(body=body))
    out = server_xml.parse(path)
    assert len(out) == 2
    # 두 항목 모두 SRV-001이지만 resource_id가 달라야 한다
    rid0 = out[0][1][0].resource_id
    rid1 = out[1][1][0].resource_id
    assert rid0 == "SRV-001#0"
    assert rid1 == "SRV-001#1"
    # 증거 내용은 각 dump의 것이어야 한다
    assert "first dump output" in out[0][1][0].evidence
    assert "second dump output" in out[1][1][0].evidence


def test_resource_id_unique_different_cids_start_at_zero(tmp_path):
    """서로 다른 cid는 각자 #0부터 시작한다."""
    body = """
<dump>
<items><id>SRV-001</id></items>
<output><![CDATA[output A]]></output>
</dump>
<dump>
<items><id>SRV-002</id></items>
<output><![CDATA[output B]]></output>
</dump>
<dump>
<items><id>SRV-001</id></items>
<output><![CDATA[output C]]></output>
</dump>
"""
    path = _write(tmp_path, "mixed.xml", _server_xml(body=body))
    out = server_xml.parse(path)
    assert len(out) == 3
    rids = [e[1][0].resource_id for e in out]
    assert rids == ["SRV-001#0", "SRV-002#0", "SRV-001#1"]


def test_resource_id_single_occurrence_is_zero(tmp_path):
    """단일 출현 cid는 #0이 유지된다(기존 계약 보존)."""
    path = _write(tmp_path, "single.xml", _server_xml())
    out = server_xml.parse(path)
    assert out[0][1][0].resource_id == "SRV-001#0"


# ── H1 회귀방지 + M-b 과마스킹 해소 + M-a ENCRYPTED 개인키 ─────────────────────


def test_h1_bcrypt_full_body_masked(tmp_path):
    """H1 회귀방지(최우선): bcrypt 해시($2b$12$<53자 본문>)는 본문 전체가
    마스킹되어야 한다. 수정 전 패턴({1,30} 상한)은 30자 이후를 평문 노출했음.

    사용 샘플:
      $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    bcrypt 해시 구조: $2b$ (알고리즘ID) + 12$ (cost) + 22자 salt + 31자 hash.
    본문 뒷부분('kqquzi.Ss7KIUgO2t0jWMUW')이 evidence에 남아있으면 H1 재발."""
    bcrypt_hash = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    body = f"""
<dump>
<items><id>SRV-020</id></items>
<output><![CDATA[
testuser:{bcrypt_hash}:19000:0:99999:7:::
PermitRootLogin no
]]></output>
</dump>
"""
    path = _write(tmp_path, "bcrypt.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    # 해시 본문이 조금이라도 남아있으면 H1 재발 — 대표적 꼬리 부분으로 검증
    assert "kqquzi.Ss7KIUgO2t0jWMUW" not in evidence, (
        "H1 재발: bcrypt 해시 꼬리가 평문 노출됨"
    )
    assert "R9h/cIPz0gi.URNNX3kh2" not in evidence, (
        "H1 재발: bcrypt 해시 앞 본문이 평문 노출됨"
    )
    # 마스킹 마커 존재
    assert "<REDACTED 해시>" in evidence
    # 비민감 컨텍스트 보존
    assert "PermitRootLogin no" in evidence
    assert "testuser:" in evidence


def test_m_b_env_var_chain_not_masked(tmp_path):
    """M-b 과마스킹 해소: $PATH$HOME$USER 같은 환경변수 연쇄는 알고리즘 ID가
    아니므로 마스킹되지 않고 원문이 보존되어야 한다."""
    body = """
<dump>
<items><id>SRV-021</id></items>
<output><![CDATA[
echo $PATH$HOME$USER
awk '{print $1$2$3}'
PATH=/usr/bin:/bin
]]></output>
</dump>
"""
    path = _write(tmp_path, "envvar.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    # 환경변수 참조 라인이 원문 그대로 보존되어야 한다
    assert "echo $PATH$HOME$USER" in evidence, (
        "M-b 과마스킹: 환경변수 연쇄가 오마스킹됨"
    )
    assert "awk '{print $1$2$3}'" in evidence, (
        "M-b 과마스킹: awk 필드참조가 오마스킹됨"
    )
    assert "PATH=/usr/bin:/bin" in evidence


def test_m_a_encrypted_private_key_masked(tmp_path):
    """M-a: ENCRYPTED PRIVATE KEY(PKCS#8 암호화 형식) 블록 본문이 마스킹된다.
    기존 패턴(RSA|OPENSSH|EC|DSA 만 열거)은 이 형식을 누락했음."""
    body = """
<dump>
<items><id>SRV-022</id></items>
<output><![CDATA[
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAIISecretBodyHere
AAICBAA...more_secret_data...AAAA==
-----END ENCRYPTED PRIVATE KEY-----
AuthorizedKeysFile .ssh/authorized_keys
]]></output>
</dump>
"""
    path = _write(tmp_path, "enc_privkey.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    # 키 본문이 없어야 한다
    assert "MIIFHDBOBgkqhkiG9w0BBQ0" not in evidence, (
        "M-a: ENCRYPTED PRIVATE KEY 본문이 평문 노출됨"
    )
    assert "more_secret_data" not in evidence
    # 마스킹 마커 존재
    assert "<REDACTED>" in evidence
    # 비민감 텍스트 보존
    assert "AuthorizedKeysFile .ssh/authorized_keys" in evidence


def test_m_a_pkcs8_bare_private_key_masked(tmp_path):
    """M-a: 접두어 없는 'PRIVATE KEY'(PKCS#8 비암호화) 블록도 마스킹된다."""
    body = """
<dump>
<items><id>SRV-023</id></items>
<output><![CDATA[
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...pkcs8_secret...AAAA==
-----END PRIVATE KEY-----
]]></output>
</dump>
"""
    path = _write(tmp_path, "pkcs8.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "pkcs8_secret" not in evidence, (
        "M-a: 접두어 없는 PRIVATE KEY 본문이 평문 노출됨"
    )
    assert "<REDACTED>" in evidence


# ── L2 마스킹 확장 (2026-07-11, §1/§2 도커 자가수집 실증 결함 수정) ──────────
# 실증(out/srv_lab/*.xml, out/was_lab/*.xml)에서 기존 3패턴을 통과한 평문 4종
# + 과마스킹 가드(login.defs/PAM/sshd 판정 라인 보존)를 고정한다.
# 패턴 A(XML/속성형)·B(셸 KEY=VALUE형)는 서버·웹WAS 파서가 공유하는
# server_xml._mask_server_evidence 한 곳에서 구현된다.

def test_l2_shell_kv_db_password_masked(tmp_path):
    """서버 /etc/profile류 `DB_PASSWORD=...` 평문이 마스킹된다(실증 §1)."""
    body = """
<dump>
<items><id>/etc/profile</id></items>
<output><![CDATA[
# app secret (test) DB_PASSWORD=SuperSecretPassw0rd! api_key=sk-live-ABCDEF1234567890
]]></output>
</dump>
"""
    path = _write(tmp_path, "profile.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "SuperSecretPassw0rd!" not in evidence
    assert "sk-live-ABCDEF1234567890" not in evidence
    assert "DB_PASSWORD=<REDACTED>" in evidence
    assert "api_key=<REDACTED>" in evidence


def test_l2_xml_attr_password_masked(tmp_path):
    """웹WAS tomcat-users.xml류 `password="..."` 속성값만 마스킹, 속성명·따옴표는
    보존된다(실증 §2)."""
    body = """
<dump>
<items><id>wasconf</id></items>
<output><![CDATA[
<user username="admin" password="Sup3rSecretPW!23" roles="manager-gui"/>
]]></output>
</dump>
"""
    path = _write(tmp_path, "tomcatusers.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "Sup3rSecretPW!23" not in evidence
    assert 'password="<REDACTED>"' in evidence
    assert 'username="admin"' in evidence


def test_l2_xml_attr_keystore_pass_masked(tmp_path):
    """웹WAS server.xml류 `keystorePass="..."`/`certificateKeystorePassword="..."`
    속성값만 마스킹된다(실증 §2)."""
    body = """
<dump>
<items><id>WST-102</id></items>
<output><![CDATA[
<SSLHostConfig keystorePass="KeyStoreSecr3t99" keystoreFile="conf/keystore.jks">
<Certificate certificateKeystorePassword="KeyStoreSecr3t99" type="RSA" />
</SSLHostConfig>
]]></output>
</dump>
"""
    path = _write(tmp_path, "serverxml.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "KeyStoreSecr3t99" not in evidence
    assert 'keystorePass="<REDACTED>"' in evidence
    assert 'certificateKeystorePassword="<REDACTED>"' in evidence


def test_l2_overmasking_guard_login_defs_pam_sshd_preserved(tmp_path):
    """과마스킹 가드: `=` 가 없는 login.defs/PAM/sshd 판정 라인은 그대로 보존된다.

    이 라인들은 결정론 판정이 참조하는 문자열(예: PermitRootLogin 값,
    PAM 스택 구성)이므로 한 글자도 손상되면 안 된다.
    """
    body = """
<dump>
<items><id>SRV-030</id></items>
<output><![CDATA[
PASS_MAX_DAYS   99999
PASS_MIN_LEN    8
password        requisite               pam_pwquality.so
PermitRootLogin yes
]]></output>
</dump>
"""
    path = _write(tmp_path, "guard.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "PASS_MAX_DAYS   99999" in evidence
    assert "PASS_MIN_LEN    8" in evidence
    assert "password        requisite               pam_pwquality.so" in evidence
    assert "PermitRootLogin yes" in evidence
    assert "<REDACTED>" not in evidence


# ── 하이퍼바이저 특화 마스킹 초안 (§4-2, 2026-07-11 — 실데이터 없음, 공개문서 기반) ──
# osvirt_xml이 이 마스커를 그대로 체이닝하므로 여기서 회귀 고정한다.
# vpxuser 자격증명(quoted/unquoted, 결합토큰만) + SAML 어서션 + Bearer/
# vmware-api-session-id 세션 토큰. 과마스킹 가드(ESXi 설정 판정 라인 보존)가
# 핵심 — 실데이터 확보 전이므로 최대한 보수적으로 검증한다.

def test_vpxuser_quoted_password_masked(tmp_path):
    """`vpxuserPassword="..."` 같은 결합토큰 속성값만 마스킹된다."""
    body = """
<dump>
<items><id>PRCV-000</id></items>
<output><![CDATA[
<vpxa><config vpxuserPassword="R4nd0mVpx!Secr3t" hostname="esxi-01"/></vpxa>
]]></output>
</dump>
"""
    path = _write(tmp_path, "vpxa.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "R4nd0mVpx!Secr3t" not in evidence
    assert 'vpxuserPassword="<REDACTED>"' in evidence
    assert 'hostname="esxi-01"' in evidence


def test_vpxuser_unquoted_kv_masked(tmp_path):
    """`vpxuser_pwd=...` 비따옴표 셸 KV 형태도 마스킹된다."""
    body = """
<dump>
<items><id>PRCV-000</id></items>
<output><![CDATA[
vpxuser_pwd=Sup3rRand0mVpx99
]]></output>
</dump>
"""
    path = _write(tmp_path, "vpxkv.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "Sup3rRand0mVpx99" not in evidence
    assert "vpxuser_pwd=<REDACTED>" in evidence


def test_vpxuser_overmasking_guard_passwd_line_preserved(tmp_path):
    """과마스킹 가드: /etc/passwd류 `vpxuser:x:1000:...` 콜론 라인은 UID/GID/셸
    필드가 보존된다 — "vpxuser"만으로는 매치하지 않고 password 키워드가
    결합된 토큰만 매치 대상이다."""
    body = """
<dump>
<items><id>PRCV-001</id></items>
<output><![CDATA[
vpxuser:x:1000:1000::/home/vpxuser:/bin/false
Name: vpxuser  Description: vSphere Administrator  Enabled: true  Locked: false
]]></output>
</dump>
"""
    path = _write(tmp_path, "vpxguard.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "vpxuser:x:1000:1000::/home/vpxuser:/bin/false" in evidence
    assert "Description: vSphere Administrator" in evidence
    assert "Enabled: true" in evidence
    assert "<REDACTED>" not in evidence


def test_saml_assertion_block_masked(tmp_path):
    """vCenter SSO(STS) SAML 어서션 본문은 치환, 태그 마커는 보존된다."""
    body = """
<dump>
<items><id>PRCV-000</id></items>
<output><![CDATA[
<saml2:Assertion ID="_abc123" IssueInstant="2026-07-11T00:00:00Z">
<saml2:Subject>administrator@vsphere.local</saml2:Subject>
<saml2:Signature>MIIB...secretsig...</saml2:Signature>
</saml2:Assertion>
]]></output>
</dump>
"""
    path = _write(tmp_path, "saml.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "administrator@vsphere.local" not in evidence
    assert "secretsig" not in evidence
    assert "<saml2:Assertion" in evidence
    assert "</saml2:Assertion>" in evidence
    assert "<REDACTED>" in evidence


def test_sso_bearer_token_masked(tmp_path):
    """`Authorization: Bearer <token>` 헤더의 토큰 값만 마스킹된다."""
    body = """
<dump>
<items><id>PRCV-000</id></items>
<output><![CDATA[
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.superlongtoken.sig
]]></output>
</dump>
"""
    path = _write(tmp_path, "bearer.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "eyJhbGciOiJSUzI1NiJ9.superlongtoken.sig" not in evidence
    assert "Authorization: Bearer <REDACTED>" in evidence


def test_vmware_api_session_id_masked(tmp_path):
    """`vmware-api-session-id: <token>` 세션 헤더 값만 마스킹된다."""
    body = """
<dump>
<items><id>PRCV-000</id></items>
<output><![CDATA[
vmware-api-session-id: 52a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
]]></output>
</dump>
"""
    path = _write(tmp_path, "sessid.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "52a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5" not in evidence
    # 32자 hex이므로 _LONG_HEX가 먼저 처리할 수 있으나 어느 경로든 평문 노출 없이
    # REDACTED로 치환되면 된다.
    assert "vmware-api-session-id: <REDACTED" in evidence


def test_hypervisor_masking_overmasking_guard_esxcli_lines_preserved(tmp_path):
    """과마스킹 가드(핵심): 판정에 쓰이는 vim-cmd/esxcli 실제 출력 라인은
    새 하이퍼바이저 패턴으로 인해 전혀 손상되지 않는다."""
    body = """
<dump>
<items><id>PRCV-005</id></items>
<output><![CDATA[
Security.PasswordMaxDays | 90
Security.AccountLockFailures | 5
Security.AccountUnlockTime | 900
UserVars.HostClientSessionTimeout | 900
Syslog.global.logHost | udp://loghost.example.com:514
esxcli network vswitch standard policy security get --vswitch-name=vSwitch0
   Allow Promiscuous: false
   Forged Transmits: false
   MAC Address Change: false
vim-cmd hostsvc/auth/permissions
Enabled: true
Locked: false
]]></output>
</dump>
"""
    path = _write(tmp_path, "guard2.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert "Security.PasswordMaxDays | 90" in evidence
    assert "Security.AccountLockFailures | 5" in evidence
    assert "UserVars.HostClientSessionTimeout | 900" in evidence
    assert "Syslog.global.logHost | udp://loghost.example.com:514" in evidence
    assert "Allow Promiscuous: false" in evidence
    assert "Forged Transmits: false" in evidence
    assert "MAC Address Change: false" in evidence
    assert "Enabled: true" in evidence
    assert "Locked: false" in evidence
    assert "<REDACTED>" not in evidence


def test_l2_double_masking_no_broken_quotes(tmp_path):
    """패턴 A(따옴표 값)와 패턴 B(셸 KEY=VALUE)가 같은 라인에서 중복 치환되어
    따옴표가 깨지지 않는다 — 패턴 B는 (?!["']) 가드로 이미 마스킹된 따옴표 값을
    재매치하지 않는다."""
    body = """
<dump>
<items><id>wasconf</id></items>
<output><![CDATA[
<user password="Sup3rSecretPW!23"/>
]]></output>
</dump>
"""
    path = _write(tmp_path, "doublemask.xml", _server_xml(body=body))
    evidence = server_xml.parse(path)[0][1][0].evidence
    assert 'password="<REDACTED>"' in evidence
    assert "Sup3rSecretPW!23" not in evidence

"""네트워크 장비 점검 결과 XML 파서.

[PROVISIONAL] 수집 포맷: 서버 동일 XML 엔벨로프 가정.

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset>
        <hostname>..</hostname>
        <vendor>Cisco Systems</vendor>
        <model>Catalyst 3750</model>
        <version>IOS 15.2</version>
      </asset>
      <results>
        <dump>
          <items><id>NET-001</id>[<id>NET-002</id>..]</items>
          <output><![CDATA[ raw config/show 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

parse() 3-튜플 계약:
  [(id, [ResourceEvidence], context=None), ...]. mapper.aggregate가 그대로 소비.

detect_variant() 의미:
  <asset> 의 vendor→os→model 텍스트에서 Cisco 토큰을 찾으면 "cisco" 반환.
  어느 것도 매칭 안 되면(타 벤더/미식별/태그 없음) "generic" 반환.
  None을 반환하지 않는다(server_xml과 차이). 단 손상 XML에는 ReportError.

마스킹 계약:
  CISCO config 키워드 앵커 패턴들을 먼저 적용한 뒤 server_xml._mask_server_evidence
  를 체이닝한다. 동등성 보존(NET-009 중복탐지): 같은 비밀값은 같은 <REDACTED 비밀번호#N>
  으로, 다른 비밀값은 다른 번호로 치환한다. secret_index dict를 parse 레벨에서 1개
  생성해 전 dump 공유 — 파일 내 모든 dump에 걸친 중복을 인식한다.
  community 인덱스는 secret_index와 별도 지역 dict(community_index)로 분리하여
  타입 혼용·카운터 오염을 방지한다. 커뮤니티 동등성은 community_index 내에서 유지.

  Cisco: enable/username/line password, snmp community, tacacs/radius key,
    isakmp key, pre-shared-key, ntp auth-key, key-string, ppp chap/pap password,
    snmp-server user v3 auth/priv 키 마스킹.
  Generic(비-Cisco): Juniper $9$/$8$ 가역 난독화 + plain-text-password/
    encrypted-password, pre-shared-key ascii-text/hexadecimal, set snmp community
    (public/private 제외), F5 secret 값 마스킹.

④ 활성화 게이트 — 나머지 9개 벤더(A10/BROCADE/ALTEON/NOTEL/BIGIP/CITRIX/
PIOLINK/3COM/JUNIPER)는 detect_variant 토큰 확장 + VariantSpec 등록 후 활성화.
현재 generic 폴백이 비-Cisco 장비의 Juniper 가역 난독화·평문 비밀까지 마스킹한다.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.parsers.server_xml import _mask_server_evidence, _read_text

# ── Cisco 변형 식별 정규식 ────────────────────────────────────────────────────
# vendor/os/model 텍스트(lower)에서 Cisco 제품을 식별하는 토큰들.
# 단어 경계(소문자 영숫자 비인접)로 검사해 오탐 방지.
_CISCO_TOKEN_RE = re.compile(
    r"(?<![a-z0-9])(cisco|ios[- ]?xe|nx[- ]?os|catalyst|ios)(?![a-z0-9])"
)

# ── 네트워크 장비 마스킹 패턴 (CISCO config 키워드 앵커) ──────────────────────
# 모두 (?mi) 줄앵커 — 줄머리 공백 허용, 키워드·타입숫자·후행토큰 보존, 비밀값만 치환.
# 동등성 dict: {원본_비밀값: 번호} — parse 레벨에서 생성·전달.

# 1. enable secret/password (level 포함, type 0/5/7/8/9)
_ENABLE_SECRET = re.compile(
    r"(?mi)^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+[05789])?)\s+(\S+)\s*$"
)

# 2. username ... password/secret (type 포함)
_USERNAME_SECRET = re.compile(
    r"(?mi)^(\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:password|secret)(?:\s+[05789])?)\s+(\S+)"
)

# 3. line 블록 password (type 0/7 포함)
_LINE_PASSWORD = re.compile(
    r"(?mi)^(\s*password(?:\s+[07])?)\s+(\S+)\s*$"
)

# 4. snmp-server community (public/private는 원문 보존 — 취약 증거)
_SNMP_COMMUNITY = re.compile(
    r"(?mi)^(\s*snmp-server\s+community)\s+(\S+)"
)
_SNMP_PUBLIC_PRIVATE = re.compile(r"^(?:public|private)$", re.IGNORECASE)

# 5. tacacs-server / radius-server key
# M2 수정: 그룹2를 (.+)$→(\S+) 으로 변경 — 후행 timeout 등 보존
_AAA_KEY = re.compile(
    r"(?mi)^(\s*(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key(?:\s+[07])?)\s+(\S+)"
)

# 6a. crypto isakmp key
_ISAKMP_KEY = re.compile(
    r"(?mi)^(\s*crypto\s+isakmp\s+key)\s+(\S+)"
)

# 6b. pre-shared-key (local/remote 포함)
_PRESHARED_KEY = re.compile(
    r"(?mi)^(\s*pre-shared-key(?:\s+(?:local|remote))?)\s+(\S+)"
)

# 7. ntp authentication-key
_NTP_AUTH_KEY = re.compile(
    r"(?mi)^(\s*ntp\s+authentication-key\s+\d+\s+\S+)\s+(\S+)"
)

# 8. key-string (type 0/7 포함). bare 'key \d+' (key chain 키번호)는 매칭 금지.
_KEY_STRING = re.compile(
    r"(?mi)^(\s*key-string(?:\s+[07])?)\s+(\S+)"
)

# 9. Juniper 가역 난독화 ($9$ / $8$)
_JUNIPER_SECRET = re.compile(r"\$9\$[^\s;\"']+|\$8\$[^\s;\"']+")

# H1 — 줄 중간 비밀 명령 (Cisco 활성 변형 추가)
# 10. ppp chap password (type 0/7 포함)
_PPP_CHAP = re.compile(
    r"(?mi)^(\s*ppp\s+chap\s+password(?:\s+[07])?)\s+(\S+)"
)
# 11. ppp pap sent-username ... password (type 0/7 포함)
_PPP_PAP = re.compile(
    r"(?mi)^(\s*ppp\s+pap\s+sent-username\s+\S+\s+password(?:\s+[07])?)\s+(\S+)"
)
# 12. snmp-server user ... v3 auth {md5|sha|sha256|sha384|sha512} <AUTHKEY>
#     [priv {des|3des|aes ...} <PRIVKEY>]
#     auth 키와 priv 키를 순서대로 각각 치환 (한 줄에 2개)
#     알고리즘 토큰·username·group 보존, 키값만 치환
_SNMP_V3_AUTH = re.compile(
    r"(?mi)((?:\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+.*?)"
    r"auth\s+(?:md5|sha(?:256|384|512)?)\s+)(\S+)"
)
_SNMP_V3_PRIV = re.compile(
    r"(?mi)((?:\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\s+.*?)"
    r"priv\s+(?:des|3des|aes(?:128|192|256)?)\s+)(\S+)"
)

# H2 — generic(비-Cisco) 벤더 평문 비밀
# 13. plain-text-password / encrypted-password (Juniper set style)
_SET_PLAIN_PASSWORD = re.compile(
    r"(?mi)((?:plain-text-password|encrypted-password)\s+)(\S+)"
)
# 14. pre-shared-key ascii-text / hexadecimal (Juniper set style, Cisco 줄앵커와 별도)
_SET_PRESHARED_KEY = re.compile(
    r"(?mi)(pre-shared-key\s+(?:ascii-text|hexadecimal)\s+)(\S+)"
)
# 15. set snmp community <VALUE> (Juniper) — public/private는 원문 보존
_SET_SNMP_COMMUNITY = re.compile(
    r"(?mi)^(\s*set\s+snmp\s+community\s+)(\S+)"
)
# 16. F5 iRules/config: secret <VALUE> (중괄호 블록 내)
#     줄머리에서 "auth ... { secret VALUE }" 또는 들여쓴 "secret VALUE" 형태.
#     Cisco enable secret / username ... secret 은 패턴 1·2가 먼저 처리하므로
#     여기서는 "secret"이 줄의 유일 키워드(들여쓰기 허용)인 경우만 포착.
#     over-mask 방지: 줄 앞에 enable/username이 있으면 이미 처리됨(패턴 1·2 선행).
_F5_SECRET = re.compile(
    r"(?mi)^(\s*(?:auth\s+\S+\s+\{\s+)?secret\s+)(\S+)"
)


def _redact_secret(value: str, secret_index: Dict[str, str],
                   prefix: str = "비밀번호") -> str:
    """동등성 보존 치환: 같은 값은 같은 <REDACTED prefix#N>을 반환."""
    if value not in secret_index:
        secret_index[value] = f"<REDACTED {prefix}#{len(secret_index)}>"
    return secret_index[value]


def _mask_network_evidence(text: str,
                           secret_index: Optional[Dict[str, str]] = None,
                           community_index: Optional[Dict[str, str]] = None,
                           ) -> str:
    """CISCO config 키워드 앵커 마스킹 후 server_xml._mask_server_evidence 체이닝.

    secret_index: 동등성 보존 dict (parse 레벨에서 파일 전체 공유).
                  None이면 이 호출 단독 dict를 사용(단독 호출/테스트 용도).
    community_index: community 전용 동등성 dict (M1: secret_index와 완전 분리).
                     None이면 이 호출 단독으로 생성.
    """
    if secret_index is None:
        secret_index = {}
    # M1 수정: community 카운터를 secret_index와 완전 분리한 별도 dict로 관리.
    # parse() 레벨에서 두 dict를 함께 생성·공유하여 dump 간 동등성도 유지.
    if community_index is None:
        community_index = {}

    def redact(m, val_group=2):
        prefix = m.group(1)
        val = m.group(val_group)
        return f"{prefix} {_redact_secret(val, secret_index)}"

    # 1. enable secret/password
    text = _ENABLE_SECRET.sub(redact, text)

    # 2. username ... password/secret
    text = _USERNAME_SECRET.sub(redact, text)

    # 3. line 블록 password
    text = _LINE_PASSWORD.sub(redact, text)

    # 4. snmp-server community: public/private는 원문 보존(취약 증거)
    def _snmp_sub(m):
        prefix = m.group(1)
        val = m.group(2)
        if _SNMP_PUBLIC_PRIVATE.match(val):
            return m.group(0)   # 원문 보존
        return f"{prefix} {_redact_secret(val, community_index, prefix='커뮤니티')}"

    text = _SNMP_COMMUNITY.sub(_snmp_sub, text)

    # 5. tacacs-server / radius-server key (M2 수정: (\S+) 으로 그리디 제거)
    text = _AAA_KEY.sub(redact, text)

    # 6a. crypto isakmp key
    text = _ISAKMP_KEY.sub(redact, text)

    # 6b. pre-shared-key (Cisco 줄앵커 형태)
    text = _PRESHARED_KEY.sub(redact, text)

    # 7. ntp authentication-key
    text = _NTP_AUTH_KEY.sub(redact, text)

    # 8. key-string
    text = _KEY_STRING.sub(redact, text)

    # 9. Juniper 가역 난독화
    def _juniper_sub(m):
        return _redact_secret(m.group(0), secret_index)

    text = _JUNIPER_SECRET.sub(_juniper_sub, text)

    # H1 추가: ppp chap password
    text = _PPP_CHAP.sub(redact, text)

    # H1 추가: ppp pap sent-username ... password
    text = _PPP_PAP.sub(redact, text)

    # H1 추가: snmp-server user v3 auth/priv 키
    # 그룹1 끝에 공백이 포함되므로 prefix에 추가 공백 없이 연결
    def redact_no_space(m):
        prefix = m.group(1)
        val = m.group(2)
        return f"{prefix}{_redact_secret(val, secret_index)}"

    text = _SNMP_V3_AUTH.sub(redact_no_space, text)
    text = _SNMP_V3_PRIV.sub(redact_no_space, text)

    # H2 추가: generic(비-Cisco) 벤더 set-style 평문 비밀
    # 그룹1 끝에 공백 포함 — redact_no_space 사용
    # 13. plain-text-password / encrypted-password
    text = _SET_PLAIN_PASSWORD.sub(redact_no_space, text)

    # 14. pre-shared-key ascii-text / hexadecimal (set style)
    text = _SET_PRESHARED_KEY.sub(redact_no_space, text)

    # 15. set snmp community (Juniper) — public/private 제외
    def _set_snmp_sub(m):
        prefix = m.group(1)
        val = m.group(2)
        if _SNMP_PUBLIC_PRIVATE.match(val):
            return m.group(0)
        return f"{prefix}{_redact_secret(val, community_index, prefix='커뮤니티')}"

    text = _SET_SNMP_COMMUNITY.sub(_set_snmp_sub, text)

    # 16. F5 secret <VALUE>
    def _f5_secret_sub(m):
        kw = m.group(1)
        val = m.group(2)
        return f"{kw}{_redact_secret(val, secret_index)}"

    text = _F5_SECRET.sub(_f5_secret_sub, text)

    # 체이닝: server_xml 패턴(PEM 개인키, crypt 해시, 긴 hex)
    return _mask_server_evidence(text)


def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"네트워크 XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그)."
        ) from e


def detect_variant(xml_path: str) -> str:
    """<asset> 의 vendor→os→model 텍스트로 변형 키를 반환.

    Cisco 토큰(_CISCO_TOKEN_RE)이 vendor/os/model 중 하나에서 매칭되면 "cisco".
    어느 것도 매칭 안 되면(타 벤더/미식별/태그 없음) "generic".
    None을 반환하지 않는다 — 단 손상 XML에는 ReportError(via _parse_root).
    """
    root = _parse_root(xml_path)
    asset = root.find("./asset")
    if asset is not None:
        for tag in ("vendor", "os", "model"):
            text = (asset.findtext(tag) or "").strip().lower()
            if text and _CISCO_TOKEN_RE.search(text):
                return "cisco"
    return "generic"


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """네트워크 XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    같은 cid가 여러 dump에 걸쳐 등장해도 resource_id 중복이 발생하지 않는다.
    evidence: _mask_network_evidence()로 민감정보 마스킹.
    동등성 dict는 parse 레벨에서 1개 생성해 전 dump 공유(NET-009 중복탐지).
    """
    root = _parse_root(xml_path)
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    cid_counter: Dict[str, int] = {}
    # 파일 전체 동등성 dict: 같은 비밀값 → 같은 <REDACTED #N>
    secret_index: Dict[str, str] = {}
    # M1 수정: community 전용 동등성 dict — secret_index와 분리하여 타입 혼용·카운터 오염 방지
    community_index: Dict[str, str] = {}

    for dump in root.findall(".//dump"):
        ids = [(i.text or "").strip() for i in dump.findall("./items/id")]
        ids = [i for i in ids if i]
        raw_output = (dump.findtext("./output") or "").strip()
        masked_output = (
            _mask_network_evidence(raw_output, secret_index, community_index)
            if raw_output else raw_output
        )
        for cid in ids:
            n = cid_counter.get(cid, 0)
            cid_counter[cid] = n + 1
            resources = []
            if masked_output:
                resources.append(ResourceEvidence(
                    resource_id=f"{cid}#{n}", status="", detail="",
                    evidence=masked_output))
            out.append((cid, resources, None))

    if not out:
        raise ReportError(
            f"네트워크 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

"""서버(OS) 점검 결과 XML 파서.

fsi_unix.sh / fsi_win.bat 가 출력하는 동일 포맷을 처리한다:

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset><hostname>..</hostname><os>Linux|AIX|HP-UX|SunOS|Windows..</os>..</asset>
      <results>
        <dump>
          <items><id>SRV-001</id>[<id>SRV-002</id>..]</items>
          <output><![CDATA[ raw 명령 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

특징/계약:
- 출력 파일명({hostname}-s-{date}.xml)에 OS 변형 마커가 없으므로
  detect_variant()가 <asset><os> 텍스트로 변형을 식별한다(내용 기반 폴백,
  main.run의 hasattr(parser, "detect_variant") seam에서 호출).
- parse()는 db_json.parse와 동일한 3-튜플 계약:
  [(id, [ResourceEvidence], context=None), ...]. mapper.aggregate가 그대로 소비.
- <dump> 하나에 <id>가 여러 개면(fDumpS 의 `for ID in $1` 루프) 각 id가
  같은 output 증거를 공유하도록 id별로 분리 emit 한다.
- SRV-* 외의 비-SRV id(Internet, date, WST-* 등)도 그대로 emit 한다 —
  main.run에서 기준(서버 시트) 매칭 실패로 자연 스킵된다.
- CDATA output이 공백뿐이면 ResourceEvidence를 만들지 않는다(빈 리스트).
  reconcile의 '증거 없음 → 판단보류 강제' 가드가 동작하는 보수적 선택
  (서버는 empty_means_good 분석 자료가 없어 빈 출력=양호로 단정 불가).
- XML 파싱 실패는 ReportError로 변환(경로/위치만 노출, 본문 비노출).
- parse()는 evidence(공개 필드)에 마스킹된 출력을, raw_evidence(비공개)에
  마스킹 전 원문을 각각 싣는다(§7 raw_evidence 분리 계약):
    - evidence: _mask_server_evidence()로 shadow 해시·SSH 개인키·긴 hex 마스킹.
      산출물·LLM 프롬프트·citation에 이 필드만 사용한다(누출 경계).
    - raw_evidence: 마스킹 전 원문. det_common 핸들러만 읽는다.
      빈 출력(raw_output이 빈 문자열)이면 raw_evidence=None.
- resource_id는 cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
  같은 cid가 여러 dump에 걸쳐 등장해도 중복 resource_id가 발생하지 않는다.
"""
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from judge_tool.models import ResourceEvidence
from judge_tool.parsers import _common

# <asset><os> 텍스트(lower) → 변형 키. 구체 토큰을 먼저 검사한다.
# 변형 키는 profile.SERVER.variants 키와 일치해야 한다.
# ⚠️ 재사용 주의: webwas_xml.detect_variant가 이 테이블을 OS 식별에 그대로
#   재사용한다(profile.WEBWAS도 동일 OS 변형 키 보유). 토큰/키 변경 시
#   webwas의 detect_variant·불변식 테스트에 동기 영향이 있으므로 함께 점검할 것.
_OS_VARIANTS: Tuple[Tuple[str, str], ...] = (
    ("hp-ux", "hpux"),
    ("hpux", "hpux"),
    ("aix", "aix"),
    ("sunos", "solaris"),
    ("solaris", "solaris"),
    ("windows", "win"),
    ("linux", "linux"),
)

# XML 선언(<?xml ... ?>). ET.fromstring(str)은 encoding 선언이 있는 유니코드
# 문자열을 거부(ValueError)하므로 디코딩 후 선언부를 제거한다.
_XML_DECL = re.compile(r"^\s*<\?xml[^>]*\?>")
# 선언부의 encoding 속성(바이트 단계에서 추출 — 디코딩 전이므로 bytes 패턴)
_ENC_DECL = re.compile(rb"encoding=[\"']([A-Za-z0-9_.\-]+)[\"']")

# ── 민감정보 마스킹 패턴 (서버 raw 명령출력 대상) ───────────────────────────────
# Unix crypt 해시 토큰: $id$[param$]salt$hash 형식.
# 지원 알고리즘: $1$(MD5), $2/$2a/$2b/$2x/$2y$(bcrypt), $5$(SHA-256),
# $6$(SHA-512), $7$(scrypt), $y$(yescrypt), $gy$(gost-yescrypt).
# rounds= 옵션 포함 형식($6$rounds=5000$salt$hash)도 처리한다.
#
# 설계 계약 (H1·M-b 수정):
#   - H1(누출 방지): 알고리즘 ID로 앵커링 + [^\s:]+ 로 공백/콜론까지 전부
#     포착 → bcrypt 53자 본문 등 길이 제한 없이 완전 마스킹.
#   - M-b(과마스킹 해소):
#       (a) 첫 $-세그먼트가 알고리즘 ID 목록에 없으면 미매칭
#           → $PATH$HOME$USER 오탐 배제.
#       (b) $id$ 이후 전체 길이(최소 8자)를 요구해 awk '$1$2$3' 같은 단편
#           연쇄(id 이후 몇 자 뿐)를 배제한다. 실제 shadow/crypt 해시는
#           $id$ 이후 salt+hash 조합이 항상 16자 이상이므로 안전.
#           최솟값 8: md5($1$) salt=8chars + "$" + 22chars hash = 31자 이상;
#           bcrypt cost=2 + "$" + 53자 body = 56자 이상 — 충분히 보수적.
#   - 치환 결과: <REDACTED 해시>.
_CRYPT_HASH = re.compile(
    r"\$(?:1|2[abxy]?|5|6|7|y|gy)\$[^\s:]{8,}"
)
# SSH/PEM 개인키 블록: BEGIN ... PRIVATE KEY ~ END ... PRIVATE KEY 사이 전체.
# DOTALL로 멀티라인 매칭. 마커는 유지, 본문만 <REDACTED>로.
#
# 설계 계약 (M-a 수정): 헤더를 [A-Z0-9 ]*? 와일드카드로 일반화해
# RSA/OPENSSH/EC/DSA 외에 ENCRYPTED(PKCS#8 암호화), PRIVATE KEY(무접두어)
# 등 모든 "... PRIVATE KEY" 변형을 커버한다. BEGIN/END 타입이 달라도
# 마스킹 목적상 허용(보안 보수).
_PRIVATE_KEY_BLOCK = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*?PRIVATE KEY-----)"
    r".*?"
    r"(-----END [A-Z0-9 ]*?PRIVATE KEY-----)",
    re.DOTALL,
)
# 32+ 연속 hex 문자(해시/다이제스트류 — 일반 메모리 주소/짧은 값은 보존).
# 트레이드오프: 임계를 16+로 낮추면 MD5(32자)·SHA1(40자) 모두 잡히지만
# 짧은 hex 토큰(MAC 주소 구성요소, /proc 경로 등)을 과마스킹할 수 있어
# 32+로 보수적 적용(MD5 32자·SHA1/256/512 이상 해시류만, 짧은 값 보존).
_LONG_HEX = re.compile(r"[0-9A-Fa-f]{32,}")

# ── L2 마스킹 확장 (2026-07-11, §1/§2 도커 자가수집 실증 결함 수정) ──────────
# 실증(out/srv_lab, out/was_lab)에서 기존 3패턴이 놓친 평문 토큰:
#   - 서버 /etc/profile류 셸 KEY=VALUE: `DB_PASSWORD=SuperSecretPassw0rd!`,
#     `api_key=sk-live-...`
#   - 웹WAS XML/속성형(같은 마스커를 webwas_xml.py가 체이닝):
#     tomcat-users.xml `password="Sup3rSecretPW!23"`,
#     server.xml `keystorePass="..."` / `certificateKeystorePassword="..."`
#
# 패턴 A(XML/속성형, 따옴표 값): 지정 속성명 + `=` + 따옴표로 감싼 값만 치환,
# 속성명·따옴표는 보존한다. 대소문자 무시.
_ATTR_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|keystorePass|certificateKeystorePassword|"
    r"truststorePass|secret|token)(\s*=\s*)([\"'])(.*?)\3"
)
# 패턴 B(셸 KEY=VALUE, 따옴표 없는 값): 임의 접두/접미 단어문자를 허용하는
# 키워드 앵커(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|CREDENTIAL) + `=` + 값(비공백
# 연속) 을 매치, 값만 치환한다. 대소문자 무시.
#
# 과마스킹 가드: 값 앞에 부정형 전방탐색 `(?!["'])` 를 둬 패턴 A가 이미 처리한
# 따옴표 값(예: `password="<REDACTED>"`)을 다시 건드리지 않는다(중복치환으로
# 따옴표가 깨지는 것 방지) — 패턴 A를 먼저 적용한 뒤 패턴 B를 적용해야 한다.
# `=` 가 없는 라인(예: `PASS_MAX_DAYS 99999`, `password requisite pam_unix.so`,
# `PermitRootLogin yes`)은 애초에 `\s*=\s*` 요구조건에서 매치되지 않아
# 판정에 필요한 login.defs/PAM/sshd 설정 라인이 보존된다(회귀테스트로 고정).
_SHELL_KV_SECRET = re.compile(
    r"(?i)\b(\w*(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|CREDENTIAL)\w*)"
    r"(\s*=\s*)(?![\"'])(\S+)"
)

# ── 하이퍼바이저 특화 마스킹 (§4-2, 2026-07-11 초안 — 실수집 데이터 없음) ──────
# osvirt_xml은 자체 마스커가 없고 이 함수를 그대로 체이닝한다(웹WAS와 동일 구조
# — commit 0cc3239 선례 계승: 도메인 특화 패턴도 공유 마스커에 추가). ESXi
# shell/vCenter 로그에서 나타날 수 있는 두 가지 공개문서 기반 토큰 형태를
# 보수적으로 추가한다(실데이터 확보 전이므로 과탐 최소화 우선):
#   1. vpxuser 자격증명: vCenter가 각 ESXi 호스트에 생성하는 내부 관리계정
#      (VMware 문서상 자동 생성·주기 로테이션되는 임의 비밀번호). vpxa.cfg류
#      설정 덤프나 계정 관리 스크립트 출력에 "vpxuser...password" 형태의
#      키=값으로 노출될 수 있음.
#   2. vCenter SSO(STS) SAML 토큰 / vSphere REST API 세션 토큰: vSphere
#      Authentication Guide 기준 STS는 WS-Trust 기반 SAML 2.0 어서션
#      (<saml2:Assertion>...</saml2:Assertion>)을 발급하고, REST/vSAN API는
#      `vmware-api-session-id` 헤더 또는 `Authorization: Bearer <token>` 로
#      세션 토큰을 전달(공식 API 문서).
#
# 과마스킹 가드(핵심 — 실데이터 부재 시 가장 중요한 안전장치):
#   - vpxuser 패턴은 "vpxuser"와 password/secret 계열 키워드가 **하나의
#     식별자 토큰**으로 결합된 경우에만 매치한다(예: vpxuserPassword,
#     vpxuser_pwd, vpxuser.secret). "vpxuser" 단독 언급(계정명 표시,
#     `Name: vpxuser` 등)이나 /etc/passwd류 콜론 구분 라인(`vpxuser:x:...`)은
#     매치하지 않는다 — 후자는 판정에 필요한 UID/GID/셸 정보를 보존해야 하며
#     이미 크랙된 shadow 해시는 기존 _CRYPT_HASH 패턴이 별도 처리한다.
#   - SAML 어서션 블록은 `<Assertion>`/`<saml2:Assertion>` 같은 SAML 전용
#     태그명만 앵커로 삼아 esxcli/vim-cmd 설정 판정용 일반 XML 출력과
#     혼동되지 않는다(해당 태그명은 SAML/WS-Trust 맥락 외 등장 가능성 낮음).
#   - 세션 토큰 패턴은 `Authorization: Bearer` / `vmware-api-session-id`
#     헤더 키워드 자체를 앵커로 사용 — ESXi/vCenter 설정값 판정 라인
#     (Enabled/Locked/lockdown mode 등)과 겹치지 않는다.
_VPXUSER_SECRET = re.compile(
    r"(?i)(\bvpxuser\w*(?:password|passwd|pwd|secret)\w*"
    r"|\b\w*(?:password|passwd|pwd|secret)\w*vpxuser\w*)"
    r"(\s*=\s*)([\"'])(.*?)\3"
)
_VPXUSER_KV_SECRET = re.compile(
    r"(?i)(\bvpxuser\w*(?:password|passwd|pwd|secret)\w*"
    r"|\b\w*(?:password|passwd|pwd|secret)\w*vpxuser\w*)"
    r"(\s*[:=]\s*)(?![\"'])(\S+)"
)
_SAML_ASSERTION_BLOCK = re.compile(
    r"(<(?:\w+:)?Assertion\b[^>]*>)"
    r".*?"
    r"(</(?:\w+:)?Assertion>)",
    re.DOTALL,
)
_SSO_BEARER_TOKEN = re.compile(
    r"(?i)\b(Authorization\s*:\s*Bearer\s+|vmware-api-session-id\s*:\s*)(\S+)"
)


def _mask_server_evidence(text: str) -> str:
    """서버 raw 명령출력에서 명백한 민감 토큰을 마스킹한다.

    원본 라인 구조·명령출력 맥락은 보존하고 민감 토큰만 치환한다.
    적용 순서:
      1. SSH/PEM 개인키 블록 (DOTALL, 마커 보존·본문 치환) — ENCRYPTED 포함 M-a
      2. Unix crypt 해시 토큰 (알고리즘 ID 앵커, 길이 제한 없음 — H1·M-b 수정)
      3. 32+ 연속 hex (MD5·SHA1·SHA256 이상 해시류; 짧은 hex 주소 등은 보존)
      4. XML/속성형 시크릿(password=".."/keystorePass=".." 등, 값만 치환) — L2 확장
      5. 셸 KEY=VALUE형 시크릿(DB_PASSWORD=.. 등, 값만 치환) — L2 확장
      6. SAML 어서션 블록(<Assertion>~</Assertion>, 마커 보존·본문 치환) — §4-2 초안
      7. vpxuser 자격증명(quoted/unquoted, vpxuser+password류 결합 토큰만) — §4-2 초안
      8. SSO/API 세션 토큰(Authorization: Bearer / vmware-api-session-id) — §4-2 초안
    """
    # 1) 개인키 블록: 마커는 유지, 사이 내용만 <REDACTED>로
    text = _PRIVATE_KEY_BLOCK.sub(
        r"\1<REDACTED>\2", text
    )
    # 2) Unix crypt 해시 토큰
    text = _CRYPT_HASH.sub("<REDACTED 해시>", text)
    # 3) 긴 hex (32+)
    text = _LONG_HEX.sub("<REDACTED>", text)
    # 4) XML/속성형 시크릿 (password="..", keystorePass="..", token='..' 등)
    text = _ATTR_SECRET.sub(r"\1\2\3<REDACTED>\3", text)
    # 5) 셸 KEY=VALUE형 시크릿 (DB_PASSWORD=.., api_key=.. 등) — 패턴 A가 이미
    #    치환한 따옴표 값은 (?!["']) 가드로 재매치하지 않는다.
    text = _SHELL_KV_SECRET.sub(r"\1\2<REDACTED>", text)
    # 6) SAML 어서션 블록: 마커는 유지, 사이 내용만 <REDACTED>로 (vCenter SSO/STS)
    text = _SAML_ASSERTION_BLOCK.sub(r"\1<REDACTED>\2", text)
    # 7) vpxuser 자격증명: 따옴표 값 패턴을 먼저 적용해야 비따옴표 KV 패턴이
    #    이미 치환된 값(`<REDACTED>`, 따옴표 보존)을 재매치하지 않는다.
    text = _VPXUSER_SECRET.sub(r"\1\2\3<REDACTED>\3", text)
    text = _VPXUSER_KV_SECRET.sub(r"\1\2<REDACTED>", text)
    # 8) SSO/API 세션 토큰 (Authorization: Bearer .., vmware-api-session-id: ..)
    text = _SSO_BEARER_TOKEN.sub(r"\1<REDACTED>", text)
    return text


# _read_text: 다른 파서(network/osvirt/webwas/iss/container)가 이 이름으로
# import 하므로 그대로 유지(공용 구현은 _common.read_text에 위임).
_read_text = _common.read_text


def _parse_root(xml_path: str) -> ET.Element:
    # XML 본문/민감 evidence는 메시지에 싣지 않는다(경로·위치 요약만).
    return _common.parse_root(
        xml_path, "서버 XML",
        "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그).")


def detect_variant(xml_path: str) -> Optional[str]:
    """<asset><os> 텍스트로 OS 변형 키(aix|hpux|linux|solaris|win)를 반환.

    식별 불가(os 태그 없음/미지 OS 문자열)면 None — 호출부(main.run)에서
    --variant 유도 ReportError로 처리된다.
    """
    root = _parse_root(xml_path)
    os_text = (root.findtext("./asset/os") or "").strip().lower()
    if not os_text:
        return None
    for token, variant in _OS_VARIANTS:
        if token in os_text:
            return variant
    return None


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """서버 XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    같은 cid가 여러 dump에 걸쳐 등장해도 resource_id 중복이 발생하지 않는다.
    evidence: _mask_server_evidence()로 shadow 해시·SSH 개인키·긴 hex를 마스킹.
    """
    root = _parse_root(xml_path)
    # §7 raw_evidence 분리: attach_raw_evidence=True로 마스킹 전 원문을 실음.
    out = _common.parse_dumps(root, _mask_server_evidence, attach_raw_evidence=True)
    _common.require_nonempty(out, xml_path, "서버")
    return out

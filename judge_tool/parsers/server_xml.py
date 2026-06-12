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
- parse()는 evidence 적재 전 _mask_server_evidence()로 민감정보를 마스킹한다.
  shadow 해시·SSH 개인키·32+ 연속 hex가 대상(db_json.py 마스킹과 보안 일관성).
- resource_id는 cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
  같은 cid가 여러 dump에 걸쳐 등장해도 중복 resource_id가 발생하지 않는다.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize

# <asset><os> 텍스트(lower) → 변형 키. 구체 토큰을 먼저 검사한다.
# 변형 키는 profile.SERVER.variants 키와 일치해야 한다.
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


def _mask_server_evidence(text: str) -> str:
    """서버 raw 명령출력에서 명백한 민감 토큰을 마스킹한다.

    원본 라인 구조·명령출력 맥락은 보존하고 민감 토큰만 치환한다.
    적용 순서:
      1. SSH/PEM 개인키 블록 (DOTALL, 마커 보존·본문 치환) — ENCRYPTED 포함 M-a
      2. Unix crypt 해시 토큰 (알고리즘 ID 앵커, 길이 제한 없음 — H1·M-b 수정)
      3. 32+ 연속 hex (MD5·SHA1·SHA256 이상 해시류; 짧은 hex 주소 등은 보존)
    """
    # 1) 개인키 블록: 마커는 유지, 사이 내용만 <REDACTED>로
    text = _PRIVATE_KEY_BLOCK.sub(
        r"\1<REDACTED>\2", text
    )
    # 2) Unix crypt 해시 토큰
    text = _CRYPT_HASH.sub("<REDACTED 해시>", text)
    # 3) 긴 hex (32+)
    text = _LONG_HEX.sub("<REDACTED>", text)
    return text


def _read_text(xml_path: str) -> str:
    """선언된 인코딩(UTF-8/euc-kr 등)으로 디코딩하고 XML 선언을 제거해 반환.

    미지/오기 인코딩 선언은 utf-8 폴백, 디코딩 불가 바이트는 치환(errors=
    replace)해 구조 파싱이 깨지지 않게 한다(태그/id는 ASCII).
    """
    with open(xml_path, "rb") as fh:
        raw = fh.read()
    m = _ENC_DECL.search(raw[:200])
    enc = m.group(1).decode("ascii", errors="replace") if m else "utf-8"
    try:
        text = raw.decode(enc, errors="replace")
    except LookupError:  # 알 수 없는 인코딩 이름 → utf-8 폴백
        text = raw.decode("utf-8", errors="replace")
    return _XML_DECL.sub("", text, count=1)


def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        # XML 본문/민감 evidence는 메시지에 싣지 않는다(경로·위치 요약만).
        raise ReportError(
            f"서버 XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그)."
        ) from e


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
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    # cid별 출현 횟수 카운터 — 전역(파일 전체) 기준으로 #0, #1, ... 부여
    cid_counter: Dict[str, int] = {}
    for dump in root.findall(".//dump"):
        ids = [(i.text or "").strip() for i in dump.findall("./items/id")]
        ids = [i for i in ids if i]
        raw_output = (dump.findtext("./output") or "").strip()
        masked_output = _mask_server_evidence(raw_output) if raw_output else raw_output
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
            f"서버 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

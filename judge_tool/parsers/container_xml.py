"""컨테이너 가상화 시스템 점검 결과 XML 파서.

kubectl/docker 수집 스크립트가 출력하는 PROVISIONAL XML 엔벨로프를 처리한다.
엔벨로프는 server_xml/network_xml 와 동일한 구조를 PROVISIONAL 가정:

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset>
        <hostname>...</hostname>
        <variant>k8s_master</variant>          <!-- 직접 지정(우선) -->
        <!-- 또는: <platform>k8s</platform><role>master</role> -->
      </asset>
      <results>
        <dump>
          <items><id>PRCC-001</id>[<id>PRCC-002</id>...]</items>
          <output><![CDATA[ raw kubectl/docker 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

계약:
- detect_variant(): <asset><variant> 직접 키 우선, 없으면 <platform>+<role> 조합.
  식별 불가면 None → main.run에서 --variant 유도 ReportError.
- parse(): 3-튜플 [(id, [ResourceEvidence], None), ...] — server_xml과 동일 계약.
- 민감 마스킹: 컨테이너 전용 패턴(JWT·base64 YAML) 선적용 후
  server_xml._mask_server_evidence(crypt해시·PEM개인키·32+hex) 체이닝.
  network_xml과 동일한 체이닝 선례를 따른다.
- resource_id: cid별 전역 카운터({cid}#0, ...)로 유일성 보장.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.parsers.server_xml import _mask_server_evidence, _read_text

# ─ 변형 식별 매핑 ─────────────────────────────────────────────────────────────

# <asset><platform>(lower) → 정규화 플랫폼 키
_PLATFORM_MAP: Tuple[Tuple[str, str], ...] = (
    ("kubernetes", "k8s"),
    ("k8s",        "k8s"),
    ("eks",        "eks"),
    ("aks",        "aks"),
    ("openshift",  "ocp"),
    ("ocp",        "ocp"),
    ("docker",     "docker"),
)

# <asset><role>(lower) → 정규화 역할 키
_ROLE_MAP: Tuple[Tuple[str, str], ...] = (
    ("control-plane", "master"),
    ("controlplane",  "master"),
    ("control",       "master"),
    ("master",        "master"),
    ("worker",        "worker"),
    ("node",          "worker"),
)

# 직접 variant 텍스트(lower) → profile.CONTAINER.variants 키 (collect 스크립트 명시)
_DIRECT_VARIANT_MAP: Dict[str, str] = {
    "k8s_master":    "k8s_master",
    "k8s_worker":    "k8s_worker",
    "eks_master":    "eks_master",
    "eks_worker":    "eks_worker",
    "aks_master":    "aks_master",
    "aks_worker":    "aks_worker",
    "ocp_master":    "ocp_master",
    "ocp_worker":    "ocp_worker",
    "docker_linux":  "docker_linux",
    "docker":        "docker_linux",  # 약식 허용
}

# ─ 컨테이너 전용 민감 마스킹 패턴 ────────────────────────────────────────────
#
# kubectl secret/serviceaccount 토큰은 server_xml 패턴(crypt·PEM·hex)에
# 매칭되지 않는 별도 형식이므로 선적용 후 server 패턴을 체이닝한다.

# JWT(ServiceAccount/Bearer 토큰): base64url 3파트 점 구분자.
# eyJ 로 시작하는 header(≥10자).payload(≥10자).signature(≥10자) 구조.
_JWT_TOKEN = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)

# kubectl Secret YAML의 data: 블록 base64 값.
# YAML 인덴트 + 키: 뒤에 오는 base64 값(20자 이상, 패딩 = 포함 가능).
# 예: "  tls.crt: MIIFwDCCA6ugAwIBAgI...=="
# 보수적 임계(20자): 짧은 ID/이름 오마스킹 방지.
# 오탐 방지: _is_base64_like 로 2차 필터링.
_K8S_SECRET_BASE64 = re.compile(
    r"(?m)^(\s+[\w.\-/]+:\s+)([A-Za-z0-9+/]{20,}={0,2})\s*$"
)


def _is_base64_like(value: str) -> bool:
    """base64 인코딩 가능성 확인: 패딩 존재 또는 대소문자 혼합.

    순수 숫자(resourceVersion 등)·순수 소문자(hex digest·URL 경로) 오탐을 차단.
    """
    if value.endswith("="):
        return True
    return any(c.isupper() for c in value) and any(c.islower() for c in value)


def _mask_container_evidence(text: str) -> str:
    """컨테이너 전용 패턴(JWT·base64 YAML) 선적용 후 server_xml 패턴 체이닝.

    적용 순서:
      1. JWT 토큰 (ServiceAccount/Bearer)
      2. kubectl Secret YAML data 블록 base64 값 (_is_base64_like 필터 적용)
      3. server_xml._mask_server_evidence (crypt해시·PEM개인키·32+hex)
    """
    text = _JWT_TOKEN.sub("<REDACTED JWT>", text)
    text = _K8S_SECRET_BASE64.sub(
        lambda m: m.group(1) + "<REDACTED base64>" if _is_base64_like(m.group(2)) else m.group(0),
        text,
    )
    return _mask_server_evidence(text)


# ─ XML 파싱 헬퍼 ──────────────────────────────────────────────────────────────

def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"컨테이너 XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다."
        ) from e


# ─ 변형 식별 ──────────────────────────────────────────────────────────────────

def detect_variant(xml_path: str) -> Optional[str]:
    """<asset><variant> 직접 키 우선, 없으면 <platform>+<role> 조합으로 변형 식별.

    반환값: profile.CONTAINER.variants 키 중 하나.
    식별 불가 → None (main.run이 --variant 유도 ReportError).
    """
    root = _parse_root(xml_path)

    # 1) <asset><variant> 직접 지정
    direct = (root.findtext("./asset/variant") or "").strip().lower()
    if direct and direct in _DIRECT_VARIANT_MAP:
        return _DIRECT_VARIANT_MAP[direct]

    # 2) <platform> + <role> 조합
    platform_raw = (root.findtext("./asset/platform") or "").strip().lower()
    role_raw     = (root.findtext("./asset/role")     or "").strip().lower()

    platform = None
    for token, key in _PLATFORM_MAP:
        if token in platform_raw:
            platform = key
            break

    # Docker는 master/worker 구분 없음 (swarm 등 추가 시 재검토)
    if platform == "docker":
        return "docker_linux"

    role = None
    for token, key in _ROLE_MAP:
        if token in role_raw:
            role = key
            break

    if platform and role:
        return f"{platform}_{role}"

    return None


# ─ 파싱 ───────────────────────────────────────────────────────────────────────

def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """컨테이너 XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    output이 공백뿐이면 ResourceEvidence를 만들지 않는다(빈 리스트).
    """
    root = _parse_root(xml_path)
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    cid_counter: Dict[str, int] = {}

    for dump in root.findall(".//dump"):
        ids = [(i.text or "").strip() for i in dump.findall("./items/id")]
        ids = [i for i in ids if i]
        raw_output = (dump.findtext("./output") or "").strip()
        masked = _mask_container_evidence(raw_output) if raw_output else raw_output

        for cid in ids:
            n = cid_counter.get(cid, 0)
            cid_counter[cid] = n + 1
            resources = []
            if masked:
                resources.append(ResourceEvidence(
                    resource_id=f"{cid}#{n}", status="", detail="",
                    evidence=masked))
            out.append((cid, resources, None))

    if not out:
        raise ReportError(
            f"컨테이너 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

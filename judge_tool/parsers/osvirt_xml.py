"""OS 가상화 시스템(하이퍼바이저) 점검 결과 XML 파서.

[PROVISIONAL] 수집 포맷: 서버 동일 XML 엔벨로프 가정.

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset>
        <hostname>esxi-01</hostname>
        <variant>esxi</variant>            <!-- 직접 지정(우선) -->
        <!-- 또는: <product>VMware ESXi 7.0</product> -->
      </asset>
      <results>
        <dump>
          <items><id>PRCV-001</id>[<id>PRCV-002</id>...]</items>
          <output><![CDATA[ raw esxcli/PowerCLI/xe 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

3변형: vcenter(VMware vCenter) / esxi(VMware ESXi) / xen(XenServer).
ESXi가 평가항목 슈퍼셋(35항목 전부 'o'), vCenter·Xen은 부분집합.

계약:
- detect_variant(): <asset><variant> 직접 키 우선, 없으면 <asset><product>
  텍스트로 토큰 식별. 식별 불가면 None → main.run에서 --variant 유도 ReportError.
  None 반환(network/container의 generic 폴백과 다름): 3변형 항목 적용이 크게
  달라(vCenter ⊂ ESXi) 변형 오판 시 범주 오류가 발생하므로, 미식별 시 자동
  폴백 대신 명시적 --variant 지정을 유도하는 보수 선택(server_xml 선례).
- parse(): 3-튜플 [(id, [ResourceEvidence], None), ...] — server_xml과 동일 계약.
- 민감 마스킹: server_xml._mask_server_evidence(crypt해시·PEM개인키·32+hex) 체이닝.
  ESXi shell은 리눅스 기반이라 crypt 해시 동형. §4-2(2026-07-11) 초안으로
  하이퍼바이저 특화 패턴(vpxuser 자격증명 결합토큰, SAML 어서션, Bearer/
  vmware-api-session-id 세션 토큰)도 공유 마스커에 추가됨(공개 문서 기반
  보수적 작성 — 실수집 데이터 확보 시 재검증 필요, docs/superpowers/specs/
  2026-07-02-remaining-domains-design.md §4 참조).
- resource_id: cid별 전역 카운터({cid}#0, ...)로 유일성 보장.
- 빈 output → resources=[] (증거 없음 → 판단보류 가드).
"""
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.parsers.server_xml import _mask_server_evidence, _read_text

# ─ 변형 식별 매핑 ─────────────────────────────────────────────────────────────

# <asset><variant> 직접 키(lower) → profile.OS_VIRT.variants 키 (collect 스크립트 명시)
_DIRECT_VARIANT_MAP: Dict[str, str] = {
    "vcenter":   "vcenter",
    "esxi":      "esxi",
    "xen":       "xen",
    "xenserver": "xen",
}

# <asset><product> 텍스트(lower) → 변형 키. 구체 토큰을 먼저 검사한다.
# "vmware esxi" 에는 "esxi"가, "vmware vcenter" 에는 "vcenter"가 포함되므로
# 두 토큰을 모두 두고 더 구체적인 esxi/vcenter를 vsphere보다 앞에 둔다.
# vsphere 단독(제품군명만)은 ESXi 호스트 점검으로 보아 esxi 폴백(슈퍼셋).
_PRODUCT_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("vcenter",            "vcenter"),
    ("esxi",               "esxi"),
    ("xenserver",          "xen"),
    ("citrix hypervisor",  "xen"),
    ("xen",                "xen"),
    ("vsphere",            "esxi"),
)


def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"OS 가상화 XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그)."
        ) from e


def detect_variant(xml_path: str) -> Optional[str]:
    """<asset><variant> 직접 키 우선, 없으면 <asset><product> 텍스트로 식별.

    식별 불가(태그 없음/미지 제품 문자열)면 None — 호출부(main.run)에서
    --variant 유도 ReportError로 처리된다.
    """
    root = _parse_root(xml_path)
    asset = root.find("./asset")
    if asset is None:
        return None
    # 1) 직접 variant 키 우선
    variant_text = (asset.findtext("variant") or "").strip().lower()
    if variant_text in _DIRECT_VARIANT_MAP:
        return _DIRECT_VARIANT_MAP[variant_text]
    # 2) product 텍스트 토큰 식별
    product_text = (asset.findtext("product") or "").strip().lower()
    if product_text:
        for token, variant in _PRODUCT_TOKENS:
            if token in product_text:
                return variant
    return None


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """OS 가상화 XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    evidence: _mask_server_evidence()로 crypt 해시·PEM 개인키·긴 hex 마스킹.
    """
    root = _parse_root(xml_path)
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    cid_counter: Dict[str, int] = {}
    for dump in root.findall(".//dump"):
        ids = [(i.text or "").strip() for i in dump.findall("./items/id")]
        ids = [i for i in ids if i]
        raw_output = (dump.findtext("./output") or "").strip()
        masked_output = (
            _mask_server_evidence(raw_output) if raw_output else raw_output)
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
            f"OS 가상화 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

"""정보보호시스템 장비(VPN/IDS/IPS/DDoS/WAF) 점검 결과 XML 파서.

[PROVISIONAL] 수집 포맷: 서버 동일 XML 엔벨로프 가정 (server_xml docstring 참조).

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset>
        <hostname>vpn-01</hostname>
        <device_type>VPN</device_type>   ← 1차 식별 키
        <vendor>...</vendor>
        <model>...</model>
      </asset>
      <results>
        <dump>
          <items><id>ISS-001</id>[<id>ISS-002</id>...]</items>
          <output><![CDATA[ raw 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

detect_variant() 의미:
  <asset>의 device_type→model→vendor 순으로 토큰 검사.
  vpn|ids|ips|ddos|waf 매칭 시 해당 키, 미매칭 시 "generic"(network_xml 동일 —
  None을 반환하지 않음). 손상 XML만 ReportError.
  주의: firewall 토큰은 의도적으로 매핑하지 않음 — FW는 --profile iss(정책 xlsx) 전용.
  FW XML이 들어오면 generic 폴백으로 판정(판단기준 col18은 전 장비 공유라 안전).

parse() 3-튜플 계약:
  [(id, [ResourceEvidence], context=None), ...]. mapper.aggregate가 그대로 소비.

마스킹 계약:
  network_xml._mask_network_evidence 체이닝(보안장비 config는 Cisco ASA·
  Juniper set-style·F5 secret 등 네트워크 패턴과 동일 계열). 신규 패턴 없음.
  동등성 보존 dict(secret_index, community_index)는 parse 레벨에서 파일 전체 공유.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.parsers.network_xml import _mask_network_evidence
from judge_tool.parsers.server_xml import _read_text

# ── 장비 타입 토큰 (검사 순서 = 첫 매칭 승리) ────────────────────────────────
# 다단어 구문을 단일 토큰보다 앞에 배치 — "intrusion"끼리 충돌 방지.
# firewall 토큰은 의도적으로 미포함 — FW는 --profile iss 전용.
_DEVICE_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("intrusion prevention", "ips"),
    ("intrusion detection",  "ids"),
    ("web application firewall", "waf"),
    ("anti-ddos", "ddos"),
    ("anti ddos", "ddos"),
    ("ddos", "ddos"),
    ("waf",  "waf"),
    ("ips",  "ips"),
    ("ids",  "ids"),
    ("vpn",  "vpn"),
)

# 단어 경계 검사 — 'ships'의 ips, 'rapids'의 ids 같은 단어 내부 우연 매치 배제.
_TOKEN_RES: Tuple[Tuple, ...] = tuple(
    (re.compile(r"(?<![a-z0-9])" + re.escape(tok) + r"(?![a-z0-9])"), var)
    for tok, var in _DEVICE_TOKENS
)


def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"정보보호시스템 XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다. "
            "FW 정책 xlsx는 --profile iss 를 사용하세요."
        ) from e


def detect_variant(xml_path: str) -> str:
    """device_type→model→vendor 텍스트로 변형 키 반환. 미식별 시 'generic'.

    None을 반환하지 않는다 — 단 손상 XML에는 ReportError(via _parse_root).
    """
    root = _parse_root(xml_path)
    asset = root.find("./asset")
    if asset is not None:
        for tag in ("device_type", "model", "vendor"):
            text = (asset.findtext(tag) or "").strip().lower()
            if not text:
                continue
            for token_re, variant in _TOKEN_RES:
                if token_re.search(text):
                    return variant
    return "generic"


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """정보보호시스템 XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    evidence: _mask_network_evidence()로 민감정보 마스킹.
    동등성 dict는 parse 레벨에서 1개 생성해 전 dump 공유.
    """
    root = _parse_root(xml_path)
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    cid_counter: Dict[str, int] = {}
    secret_index: Dict[str, str] = {}
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
            f"정보보호시스템 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

"""웹서버-WAS 점검 결과 XML 파서.

[PROVISIONAL] 수집 포맷: 서버 동일 XML 엔벨로프 가정.

    <?xml version="1.0" encoding="UTF-8|euc-kr"?>
    <script>
      <asset>
        <hostname>web-01</hostname>
        <os>Linux</os>                  <!-- OS 변형 식별 -->
        <webserver>Apache</webserver>   <!-- 웹서버 변형 식별(선택) -->
        <!-- 또는: <variant>apache</variant> 직접 지정 -->
      </asset>
      <results>
        <dump>
          <items><id>WST-001</id>[<id>WST-031</id>...]</items>
          <output><![CDATA[ raw 명령/config 출력 ]]></output>
        </dump>
        ...
      </results>
    </script>

11변형: OS 5종(aix/hpux/linux/solaris/win) + 웹서버 6종(webservice/apache/
webtob/iis/tomcat/jeus). 웹서버-WAS 시트는 총 126항목(WST-001~126)으로,
서버(SRV)와 항목명 동일한 106개(OS 점검) + 웹서버 특화 20개로 구성된다.
웹 특화 항목은 WST-031~044처럼 ID 구간에 산재한다(연속 구간 아님).

⚠️ 변형별 판단 컬럼 구조가 비대칭(profile.WEBWAS 참조):
- OS 5종: 전용 판단기준/판단방법 컬럼(col23~32).
- 웹서버 6종: 전용 컬럼 없이 공통 판단기준(col37)/판단방법(col38) 공유.
  applicability_col만 col17~22로 갈린다.

OS/웹 이중성(활성화 게이트): 한 호스트가 OS 변형 1개 + 웹서버 변형 1개를 동시에
가질 수 있으나(예: Linux+Apache), 현재 단일 variant 구조는 한 변형만 선택한다.
웹 특화 항목의 판단기준은 OS 변형 컬럼(col23~32)에도 복제돼 있어 OS 변형 선택
시에도 웹 항목이 판정되나, 웹서버 종류별 세분 점검은 --variant로 명시 선택.
상세는 PROGRESS.md ⑦ 웹서버-WAS 활성화 게이트 참조.

계약:
- detect_variant(): <asset><variant> 직접 키 우선 > <asset><os> OS 식별 >
  <asset><webserver>/<product> 웹서버 식별. 미식별 시 None(server_xml 선례).
- parse(): 3-튜플 [(id, [ResourceEvidence], None), ...] — server_xml과 동일 계약.
- 마스킹: server_xml._mask_server_evidence(crypt해시·PEM개인키·32+hex) 체이닝.
- resource_id: cid별 전역 카운터({cid}#0, ...)로 유일성 보장.
- 빈 output → resources=[] (증거 없음 → 판단보류 가드).
"""
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.parsers.server_xml import (
    _OS_VARIANTS, _mask_server_evidence, _read_text)

# ─ 변형 식별 매핑 ─────────────────────────────────────────────────────────────

# <asset><variant> 직접 키(lower) → profile.WEBWAS.variants 키 (collect 스크립트 명시)
_DIRECT_VARIANT_MAP: Dict[str, str] = {
    "aix":        "aix",
    "hpux":       "hpux",
    "hp-ux":      "hpux",
    "linux":      "linux",
    "solaris":    "solaris",
    "win":        "win",
    "windows":    "win",
    "webservice": "webservice",
    "apache":     "apache",
    "webtob":     "webtob",
    "iis":        "iis",
    "tomcat":     "tomcat",
    "jeus":       "jeus",
}

# <asset><webserver>/<product> 텍스트(lower) → 웹서버 변형 키.
# 구체적 WAS 토큰을 먼저 검사한다 — "Apache Tomcat"은 Tomcat(WAS)이므로
# tomcat을 apache보다 앞에 둬 "apache http server"만 apache로 분류.
_WEBSERVER_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("tomcat",  "tomcat"),
    ("jeus",    "jeus"),
    ("webtob",  "webtob"),
    ("internet information services", "iis"),
    ("iis",     "iis"),
    ("httpd",   "apache"),
    ("apache",  "apache"),
)


def _parse_root(xml_path: str) -> ET.Element:
    try:
        return ET.fromstring(sanitize(_read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"웹서버-WAS XML 파싱 실패: {xml_path} ({e}). "
            "보고서가 손상되었을 수 있습니다(예: 닫히지 않은 태그)."
        ) from e


def detect_variant(xml_path: str) -> Optional[str]:
    """<asset><variant> 직접 키 > <os> OS 식별 > <webserver>/<product> 웹서버.

    식별 불가면 None — 호출부(main.run)에서 --variant 유도 ReportError로 처리.
    우선순위: 직접 variant 키 > OS(서버와 동형 점검 기반) > 웹서버 토큰.
    """
    root = _parse_root(xml_path)
    asset = root.find("./asset")
    if asset is None:
        return None
    # 1) 직접 variant 키 우선
    variant_text = (asset.findtext("variant") or "").strip().lower()
    if variant_text in _DIRECT_VARIANT_MAP:
        return _DIRECT_VARIANT_MAP[variant_text]
    # 2) OS 식별 (server_xml._OS_VARIANTS 재사용 — aix/hpux/linux/solaris/win)
    os_text = (asset.findtext("os") or "").strip().lower()
    if os_text:
        for token, variant in _OS_VARIANTS:
            if token in os_text:
                return variant
    # 3) 웹서버 식별 (webserver → product 순)
    for tag in ("webserver", "product"):
        web_text = (asset.findtext(tag) or "").strip().lower()
        if not web_text:
            continue
        for token, variant in _WEBSERVER_TOKENS:
            if token in web_text:
                return variant
    return None


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """웹서버-WAS XML → [(id, [ResourceEvidence], None), ...]. dump 순서 유지.

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
                    evidence=masked_output,
                    raw_evidence=raw_output or None,  # §6.1 Phase3: 결정론 전용 비마스킹
                ))
            out.append((cid, resources, None))
    if not out:
        raise ReportError(
            f"웹서버-WAS 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")
    return out

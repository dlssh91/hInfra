"""파서 6종(server/network/osvirt/webwas/iss/container) 공용 헬퍼.

각 도메인 파서의 parse()/_parse_root()가 반복하던 두 가지 패턴을 추출한다:
  1. parse_root(): ET.fromstring(sanitize(read_text)) + ParseError→ReportError.
  2. parse_dumps(): <dump> 순회 → id 추출 → output 마스킹 →
     cid 전역 카운터 채번 → ResourceEvidence emit.

⚠️ 순수 리팩터(동작 보존) 목적 모듈이다. 마스킹 함수(mask_fn)와 에러 메시지
문구(error_label/error_suffix)는 도메인별로 반드시 다르므로 호출부가
파라미터로 정확히 주입한다 — 이 모듈 자체는 도메인 지식을 갖지 않는다.
"""
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence
from judge_tool.parsers.cloud_xml import sanitize
from judge_tool.preflight import read_text as _preflight_read_text


def read_text(xml_path: str) -> str:
    """인코딩 자동 교정 후 텍스트를 반환한다(preflight.read_text 위임)."""
    text, _meta = _preflight_read_text(xml_path)
    return text


def parse_root(xml_path: str, error_label: str, error_suffix: str) -> ET.Element:
    """ET.fromstring(sanitize(read_text(xml_path))). 실패 시 ReportError.

    error_label: "{error_label} 파싱 실패: ..." 형태 메시지 앞부분(도메인별 상이,
      예: "서버 XML", "네트워크 XML").
    error_suffix: 메시지 뒷부분 안내 문구(도메인별 상이, 원문 그대로 전달).
    """
    try:
        return ET.fromstring(sanitize(read_text(xml_path)))
    except ET.ParseError as e:
        raise ReportError(
            f"{error_label} 파싱 실패: {xml_path} ({e}). {error_suffix}"
        ) from e


def parse_dumps(
    root: ET.Element,
    mask_fn: Callable[[str], str],
    *,
    attach_raw_evidence: bool = False,
) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """<dump> 순회 → id 추출 → output 마스킹 → cid 전역 카운터 채번 → emit.

    mask_fn: raw_output(str) → 마스킹된 str. 도메인별 마스킹 함수를 그대로
      전달한다(부가 상태가 필요하면 호출부에서 클로저로 캡처 — 예: network/iss
      의 secret_index/community_index 동등성 dict를 parse() 레벨에서 생성해
      파일 전체 공유하는 패턴).
    attach_raw_evidence: True면 §7 raw_evidence 분리 계약대로 마스킹 전 원문을
      ResourceEvidence.raw_evidence에 싣는다(server/webwas/container).
      False(기본)면 raw_evidence를 세팅하지 않는다(기본값 None 유지 —
      network/osvirt/iss).

    resource_id: cid별 전역 카운터({cid}#0, {cid}#1, ...)로 유일성 보장.
    같은 cid가 여러 dump에 걸쳐 등장해도 resource_id 중복이 발생하지 않는다.
    """
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]] = []
    cid_counter: Dict[str, int] = {}
    for dump in root.findall(".//dump"):
        ids = [(i.text or "").strip() for i in dump.findall("./items/id")]
        ids = [i for i in ids if i]
        raw_output = (dump.findtext("./output") or "").strip()
        masked_output = mask_fn(raw_output) if raw_output else raw_output
        for cid in ids:
            n = cid_counter.get(cid, 0)
            cid_counter[cid] = n + 1
            resources: List[ResourceEvidence] = []
            if masked_output:
                kwargs = dict(
                    resource_id=f"{cid}#{n}", status="", detail="",
                    evidence=masked_output,
                )
                if attach_raw_evidence:
                    kwargs["raw_evidence"] = raw_output or None
                resources.append(ResourceEvidence(**kwargs))
            out.append((cid, resources, None))
    return out


def require_nonempty(
    out: List[Tuple[str, List[ResourceEvidence], Optional[str]]],
    xml_path: str,
    error_label: str,
) -> None:
    """out이 비어 있으면 도메인별 라벨의 ReportError를 던진다.

    error_label: "{error_label} 결과 파싱 실패: ..." 형태 메시지 앞부분
      (도메인별 상이, 예: "서버", "네트워크").
    """
    if not out:
        raise ReportError(
            f"{error_label} 결과 파싱 실패: {xml_path} 에 유효한 dump 항목이 없습니다.")

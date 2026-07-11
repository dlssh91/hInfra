#!/usr/bin/env python3
"""net_manual_to_xml.py — 수기 템플릿 → network_xml 파서 호환 XML 변환기. DRAFT.

⚠️ 현장 협의 전 초안. 배포용 아님.

설계: docs/superpowers/specs/2026-07-02-remaining-domains-design.md §5-2
(수집기 배포 불가 현장의 폴백 경로 — 운영자가 show 출력을 항목별로 붙여넣는
수기 텍스트 템플릿 → fsec_network_collect.sh와 동일한 XML 엔벨로프로 변환).

파서 계약(무변경): judge_tool/parsers/network_xml.py 가 실제로 기대하는 스키마는
    <script><asset>..</asset><results>
      <dump><items><id>NET-001</id></items><output><![CDATA[..]]></output></dump>
      ...
    </results></script>
이며, 본 변환기의 출력은 이 스키마를 그대로 따른다(파서 무변경 원칙).

stdlib만 사용(외부 의존성 없음).

── 템플릿 형식 ──────────────────────────────────────────────────────────────
파일 앞부분은 "key: value" 자산 메타데이터(선택, 인식 키: hostname/vendor/model/
version), 그 뒤로 "[NET-xxx]" 또는 "[NET-xxx,NET-yyy,...]" 헤더로 시작하는
섹션이 이어진다. 각 섹션의 본문(다음 헤더 또는 EOF까지)이 해당 id(들)의
<output> 원문이 된다. 같은 id가 여러 섹션에 나와도 된다(파서가 dump별로
{cid}#0, {cid}#1 ... 유일 resource_id를 부여).

    hostname: router1
    vendor: Cisco Systems
    model: Catalyst 3750
    version: IOS 15.2

    [NET-001]
    (인터뷰 전용 — 보통 비워둠)

    [NET-003,NET-004,NET-005,NET-006]
    Building configuration...
    ... show running-config 발췌 ...

    [NET-048,NET-059]
    Cisco IOS Software, C3750 Software ...

사용:
    python3 scripts/net_manual_to_xml.py --in template.txt --out router1.xml [--mask]
"""
import argparse
import re
import sys
from xml.sax.saxutils import escape

_SECTION_HEADER_RE = re.compile(r"^\[\s*([A-Za-z0-9,\-\s]+?)\s*\]\s*$")
_ASSET_KEYS = ("hostname", "vendor", "model", "version")

# ── 1차 마스킹(참고용, --mask) — 파서 2차 마스킹(network_xml.py 16패턴)이
# 최종 권위. bash 수집기(fsec_network_collect.sh)의 mask_text()와 동일한
# 대표 패턴 부분집합만 구현 — 완전성 보장 안 함(§5-4).
_MASK_PATTERNS = [
    # (전체매치 정규식, 보존할 접두 그룹 인덱스) — 접두 뒤 값만 치환.
    (re.compile(r"(?mi)^(\s*enable (?:secret|password)(?: level \d+)?(?: [0-9])?)"
                r"\s+(\S+)\s*$"), 1),
    (re.compile(r"(?mi)^(\s*username \S+(?: privilege \d+)? "
                r"(?:password|secret)(?: [0-9])?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*password(?: [07])?)\s+(\S+)\s*$"), 1),
    (re.compile(r"(?mi)^(\s*(?:tacacs-server|radius-server)"
                r"(?: host \S+)? key(?: [07])?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*crypto isakmp key)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*pre-shared-key(?: (?:local|remote))?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)(pre-shared-key (?:ascii-text|hexadecimal))\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*ntp authentication-key \d+ \S+)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*key-string(?: [07])?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*ppp chap password(?: [07])?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)^(\s*ppp pap sent-username \S+ password(?: [07])?)\s+(\S+)"), 1),
    (re.compile(r"(?mi)((?:plain-text-password|encrypted-password)\s+)(\S+)"), 1),
]
_SNMP_COMMUNITY_RE = re.compile(r"(?mi)^(\s*(?:snmp-server|set) (?:community|snmp community))"
                                 r"\s+(\S+)")
_SNMP_PUBLIC_PRIVATE = re.compile(r"^(?:public|private)$", re.IGNORECASE)
_JUNIPER_SECRET_RE = re.compile(r"\$[89]\$[^\s;\"']+")

_MASK_TOKEN = "<MASKED_BY_COLLECTOR>"


def mask_text(text: str) -> str:
    """참고용 1차 마스킹. 파서(network_xml.py)의 16패턴이 최종 권위."""
    for pattern, _ in _MASK_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1).rstrip()} {_MASK_TOKEN}", text)

    def _snmp_sub(m):
        val = m.group(2)
        if _SNMP_PUBLIC_PRIVATE.match(val):
            return m.group(0)
        return f"{m.group(1)} {_MASK_TOKEN}"

    text = _SNMP_COMMUNITY_RE.sub(_snmp_sub, text)
    text = _JUNIPER_SECRET_RE.sub(_MASK_TOKEN, text)
    return text


class TemplateError(ValueError):
    """수기 템플릿 파싱 실패(구조 오류)."""


def parse_template(text: str):
    """수기 템플릿 텍스트 → (asset_dict, [(ids: List[str], body: str), ...]).

    섹션이 하나도 없으면 TemplateError.
    """
    lines = text.splitlines()
    asset: dict = {}
    sections = []
    current_ids = None
    current_body: list = []
    in_header = True

    def _flush():
        if current_ids is not None:
            sections.append((current_ids, "\n".join(current_body).strip("\n")))

    for line in lines:
        m = _SECTION_HEADER_RE.match(line.strip())
        if m:
            _flush()
            current_ids = [i.strip() for i in m.group(1).split(",") if i.strip()]
            current_body = []
            in_header = False
            continue
        if in_header:
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                if key in _ASSET_KEYS:
                    asset[key] = val.strip()
            continue
        current_body.append(line)
    _flush()

    if not sections:
        raise TemplateError(
            "템플릿에 '[NET-xxx]' 형식의 섹션 헤더가 하나도 없습니다. "
            "형식: scripts/net_manual_to_xml.py 모듈 docstring 참조.")
    return asset, sections


def _cdata(text: str) -> str:
    # "]]>"는 CDATA 내부에 그대로 둘 수 없으므로 분할-재시작한다.
    return "<![CDATA[" + text.replace("]]>", "]]]]><![CDATA[>") + "]]>"


def build_xml(asset: dict, sections, mask: bool = False) -> str:
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<script>", "<asset>"]
    for key in _ASSET_KEYS:
        if asset.get(key):
            parts.append(f"<{key}>{escape(asset[key])}</{key}>")
    parts.append("</asset>")
    parts.append("<results>")
    for ids, body in sections:
        items = "".join(f"<id>{escape(i)}</id>" for i in ids)
        output = mask_text(body) if mask else body
        parts.append(f"<dump><items>{items}</items><output>{_cdata(output)}</output></dump>")
    parts.append("</results>")
    parts.append("</script>")
    return "\n".join(parts) + "\n"


def convert(text: str, mask: bool = False) -> str:
    """템플릿 텍스트 전체 → network_xml 호환 XML 문자열. 진입점(테스트용)."""
    asset, sections = parse_template(text)
    return build_xml(asset, sections, mask=mask)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--in", dest="infile", required=True, help="수기 템플릿 txt 경로")
    ap.add_argument("--out", dest="outfile", required=True, help="출력 XML 경로")
    ap.add_argument("--mask", action="store_true",
                     help="1차 마스킹 적용(참고용, 파서 2차 마스킹이 최종 권위)")
    args = ap.parse_args(argv)

    with open(args.infile, "r", encoding="utf-8") as fh:
        text = fh.read()

    try:
        xml_text = convert(text, mask=args.mask)
    except TemplateError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2

    with open(args.outfile, "w", encoding="utf-8") as fh:
        fh.write(xml_text)
    print(f"완료: {args.outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

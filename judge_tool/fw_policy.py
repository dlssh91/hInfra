"""방화벽 이상정책 결정론 탐지 엔진 (eol.py 선례).

ISS-030~041 항목별 탐지 함수 + 단일 진입점 detect_for_iss().
LLM 없이 ipaddress(stdlib) + 집합연산으로 정확·전수 탐지.
탐지=결정론, 정당성=사람 (모든 결과 needs_review=True).

포맷별 capability:
  SECUI: ISS-030~036, 041 (hit-count 없어 ISS-037 불가)
  ID70 : ISS-030~037, 041 (DAILY/WEEKLY HIT COUNT 컬럼)
  PaloAlto: ISS-030~037, 041 (Hit Count 컬럼)
  krfw (한글 13열, P13/P14/P24/P25 실증): ISS-030~032/034/036/041
        (Two-way/출발지포트/hit-count 컬럼 없어 033/035/037 불가)
  unknown: 전 항목 판정불가 → 판단보류

ISS-038/039는 --aux 자산목록/토폴로지 필요 → 전 포맷 판정불가.
ISS-040은 비정책 항목(계정/로깅 등) → 별도 처리.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Set, Tuple

from judge_tool.fw_objects import UnresolvableError, resolve_name

# ─ 정규화 Policy 모델 ──────────────────────────────────────────────────────────

@dataclass
class Policy:
    """포맷 독립 정규화 방화벽 정책 레코드."""
    seq: Optional[int]                          # 순서 번호 (정렬·그림자 분석용)
    rule_id: Optional[str]                      # 규칙 ID / 이름 (증거 인용용)
    enabled: bool = True
    action: str = ""                            # "allow"|"permit"|"accept"|"deny"|"drop"
    two_way: bool = False                       # SECUI Two-way 컬럼
    src_ips: List[str] = field(default_factory=list)    # CIDR/IP 목록
    dst_ips: List[str] = field(default_factory=list)
    src_ports: List[str] = field(default_factory=list)  # "any"|"22"|"1-65535"
    dst_ports: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)  # "tcp"|"udp"|"icmp"|"any"
    hit_count: Optional[int] = None             # Palo Alto / ID70 전용
    description: str = ""
    # 미해석(named 객체/그룹 후보) 토큰 보존 (B′-3a).
    # resolve_policies()가 src_ips/dst_ips/dst_ports/protocols에서 IP/포트로
    # 파싱 불가한 토큰을 제거해 여기로 옮긴다. 후속 B′-3b에서 ObjectTable로
    # 실치환 시도 대상이 되며, 그 전까지는 detect_for_iss의 거짓양호 봉쇄
    # 가드(양호→판단보류 강등)의 근거로 쓰인다.
    unresolved_src: List[str] = field(default_factory=list)
    unresolved_dst: List[str] = field(default_factory=list)
    unresolved_svc: List[str] = field(default_factory=list)


# ─ 포맷 탐지 ──────────────────────────────────────────────────────────────────

_FORMAT_SECUI    = "secui"
_FORMAT_ID70     = "id70"
_FORMAT_PALOALTO = "paloalto"
_FORMAT_KRFW     = "krfw"
_FORMAT_UNKNOWN  = "unknown"


def sniff_format(
    headers: List[str],
) -> Literal["secui", "id70", "paloalto", "krfw", "unknown"]:
    """첫 헤더 행 리스트로 포맷 식별.

    SECUI: 'Font Color:' 범례 행이거나 ('Seq' + 'Two-way' + 'Action') 조합.
    ID70 : 'PRIORITY' + 'SVC SPEC' (또는 SRC TYPE) 존재.
    PaloAlto: 'Hit Count' 또는 ('Zone' + 'Application') 존재.
    krfw : 한글 13열 포맷 — '출발지' + '목적지' + ('정책' 또는 '룰'*) 조합
           (P13/P14/P24/P25 실증, 기존 3포맷 오식별 방지 위해 마지막에 검사).
    미지: unknown.

    대소문자·공백 정규화 후 부분 문자열 매칭.
    """
    flat = {str(h).strip().lower() for h in headers if h}

    # Font Color 범례 행이 직접 헤더로 오는 경우
    if any("font color" in tok for tok in flat):
        return _FORMAT_SECUI
    # SECUI 정책 헤더행: Seq + Action + (Two-way 또는 From/To)
    has_seq = any("seq" == tok or tok.startswith("seq") for tok in flat)
    has_action = "action" in flat
    has_twoway = any("two-way" in tok or "twoway" in tok or "two way" in tok
                     for tok in flat)
    if has_seq and has_action and has_twoway:
        return _FORMAT_SECUI
    # ID70: PRIORITY + SVC SPEC
    has_priority = "priority" in flat
    has_svcspec = any("svc spec" in tok or "svcspec" in tok for tok in flat)
    if has_priority and has_svcspec:
        return _FORMAT_ID70
    # ID70 추가 식별: SRC TYPE
    has_src_type = any("src type" in tok for tok in flat)
    if has_priority and has_src_type:
        return _FORMAT_ID70
    # Palo Alto: Hit Count
    has_hitcount = any("hit count" in tok for tok in flat)
    if has_hitcount:
        return _FORMAT_PALOALTO
    # Palo Alto: Zone + Application 조합
    has_zone = any(tok == "zone" or tok.endswith("zone") for tok in flat)
    has_app = any("application" in tok for tok in flat)
    if has_zone and has_app:
        return _FORMAT_PALOALTO
    # krfw: 한글 13열 포맷 — 출발지 + 목적지 + (정책 또는 룰*) 조합.
    # 기존 3포맷 검사 뒤에 배치해 오식별 방지(영문 헤더와 겹칠 여지 없음).
    has_src_kr = "출발지" in flat
    has_dst_kr = "목적지" in flat
    has_policy_or_rule_kr = ("정책" in flat) or any("룰" in tok for tok in flat)
    if has_src_kr and has_dst_kr and has_policy_or_rule_kr:
        return _FORMAT_KRFW
    return _FORMAT_UNKNOWN


# ─ 포트/CIDR 유틸 ─────────────────────────────────────────────────────────────

# 광역 CIDR 임계: prefix_len <= 이 값 (≤ /8 = 16M+ 호스트)
_BROAD_CIDR_PREFIX_LEN = 8

# 관리 포트 집합 (ISS-031)
ADMIN_PORTS: FrozenSet[int] = frozenset({
    22,    # SSH
    23,    # Telnet
    80,    # HTTP 관리
    443,   # HTTPS 관리
    3389,  # RDP
    8080, 8443,  # 대체 관리 포트
})

# 취약 포트 집합 (ISS-041)
VULN_PORTS: FrozenSet[int] = frozenset({
    137, 138, 139,   # NetBIOS
    445,              # SMB
    1433,             # MSSQL
    1521,             # Oracle
    3306,             # MySQL
    5432,             # PostgreSQL
    6379,             # Redis
    27017,            # MongoDB
})

# 취약 원격 서비스 포트 (ISS-036)
VULN_REMOTE_PORTS: FrozenSet[int] = frozenset({
    512, 513, 514,   # r-services (rexec, rlogin, rsh)
    69,              # TFTP
})


def _is_any(ip_str: str) -> bool:
    """any/0.0.0.0/0.0.0.0/0 등 '전체' IP 표현 인식."""
    s = ip_str.strip().lower()
    return s in ("any", "*", "all", "0.0.0.0", "0.0.0.0/0", "::/0", "")


def _is_broad_cidr(ip_str: str) -> bool:
    """광역 CIDR 여부: any이거나 prefix_len <= _BROAD_CIDR_PREFIX_LEN."""
    if _is_any(ip_str):
        return True
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        return net.prefixlen <= _BROAD_CIDR_PREFIX_LEN
    except ValueError:
        return False


# sentinel: 1024개 초과 포트 범위를 표현하는 특수값
_SENTINEL_WIDE_RANGE = -1


def _parse_port_range(port_str: str) -> Set[int]:
    """포트 문자열 → 정수 집합.

    'any'/'*' → empty set (is_any_port로 별도 체크).
    '22' → {22}.
    '22-23' → {22, 23}.
    '1024-65535' → {-1} (sentinel: 광범위 포트).
    'tcp 1-65535 443-443' (ID70) → 마지막 토큰 파싱.
    """
    s = port_str.strip().lower()
    if not s or s in ("any", "*", "all"):
        return set()
    # ID70 포맷: 'tcp 1-65535 443-443' → 마지막 토큰
    tokens = s.split()
    s = tokens[-1] if tokens else s
    # 범위
    m = re.match(r"^(\d+)-(\d+)$", s)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if hi - lo > 1023:
            return {_SENTINEL_WIDE_RANGE}
        return set(range(lo, hi + 1))
    # 단일 포트
    if re.match(r"^\d+$", s):
        return {int(s)}
    return set()


def _is_any_port(port_str: str) -> bool:
    """포트 문자열이 '전체 허용'이면 True."""
    s = port_str.strip().lower()
    if not s or s in ("any", "*", "all"):
        return True
    tokens = s.split()
    s = tokens[-1] if tokens else s
    m = re.match(r"^(\d+)-(\d+)$", s)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return (lo == 0 or lo == 1) and hi >= 65535
    return False


def _ports_intersect(policy_ports: List[str], target: FrozenSet[int]) -> bool:
    """정책 포트 목록이 target 포트 집합과 교집합이 있으면 True."""
    for ps in policy_ports:
        if _is_any_port(ps):
            return True
        parsed = _parse_port_range(ps)
        if _SENTINEL_WIDE_RANGE in parsed:
            return True  # 광범위 범위는 모든 포트를 포함
        if parsed & target:
            return True
    return False


def _has_broad_ip(ip_list: List[str]) -> bool:
    return bool(ip_list) and any(_is_broad_cidr(ip) for ip in ip_list)


def _is_allow_action(action: str) -> bool:
    return action.strip().lower() in ("allow", "permit", "accept", "pass")


# ─ 미해석 토큰 분류 + 해석 패스 (named 객체/그룹 후보 — B′-3a) ────────────────
#
# "미해석" 판정 기준(설계문서 2026-07-02-fw-implementation-design.md A-2 정의와
# 동일): IP측 = `_is_any()` 아님 ∧ `ipaddress.ip_network()` 실패. 포트측 =
# `_is_any_port()` 아님 ∧ `_parse_port_range()` 빈집합. 둘 다 아니면(=IP/CIDR/
# any 또는 숫자/범위/any로 파싱 가능) 해석됨으로 간주해 원 필드에 유지한다.
# IP 대시범위(`a-b`) 해석은 별도 과제(B′-4)로 아직 unparseable — 이번 태스크는
# 그룹객체 후보를 "제거하지 않고 보존"하는 것이 목적이므로 대시범위도 일단
# unresolved로 분류해도 안전(후속 과제가 좁혀줌).
_KNOWN_PROTOCOL_TOKENS: FrozenSet[str] = frozenset({
    "tcp", "udp", "icmp", "ip", "gre", "esp", "ah",
    "any", "all", "*", "",
})


def _is_resolvable_ip_token(token: str) -> bool:
    """src_ips/dst_ips 토큰이 IP/CIDR/any 계열로 파싱 가능하면 True."""
    if _is_any(token):
        return True
    try:
        ipaddress.ip_network(token.strip(), strict=False)
        return True
    except (ValueError, AttributeError):
        return False


def _is_resolvable_port_token(token: str) -> bool:
    """dst_ports 토큰이 숫자/범위/any로 파싱 가능하면 True."""
    if _is_any_port(token):
        return True
    return bool(_parse_port_range(token))


def _is_resolvable_protocol_token(token: str) -> bool:
    """protocols 토큰이 알려진 프로토콜명이거나 포트형으로 파싱 가능하면 True.

    ID70 SVC SPEC 단일토큰(`_parse_svc_spec`)처럼 숫자가 아닌 값이 protocols에
    떨어지는 경로가 있어(named 서비스객체 후보), tcp/udp/icmp 등 알려진
    프로토콜명은 유지하고 그 외 미지 토큰만 unresolved_svc 후보로 취급한다.
    """
    if token.strip().lower() in _KNOWN_PROTOCOL_TOKENS:
        return True
    return _is_resolvable_port_token(token)


def _resolve_unresolved_tokens(
    tokens: List[str],
    section: Dict[str, List[str]],
    table: Any,
    kind: str,
    is_resolvable_fn: Any,
) -> Tuple[List[str], List[str]]:
    """unresolved_* 리스트의 각 토큰을 table의 kind 섹션으로 실해석 시도.

    토큰이 section에 없으면(테이블에 정의되지 않음) 원 토큰 그대로 보존.
    있으면 fw_objects.resolve_name으로 재귀 해석(중첩까지 leaf로 펼침) —
    순환/깊이초과(UnresolvableError)면 역시 원 토큰 그대로 보존(부분 결과
    반환 금지, 전체를 미해석으로). 해석된 leaf 중 IP/포트로 파싱 가능한
    것은 resolved_out으로, 파싱 불가능한 것(leaf 자체가 또 다른 미지 토큰)은
    new_unresolved로 분류한다.

    반환: (resolved_out, new_unresolved).
    """
    resolved_out: List[str] = []
    new_unresolved: List[str] = []
    for tok in tokens:
        if tok not in section:
            new_unresolved.append(tok)
            continue
        try:
            leaves = resolve_name(table, kind, tok)
        except UnresolvableError:
            new_unresolved.append(tok)
            continue
        for leaf in leaves:
            if is_resolvable_fn(leaf):
                resolved_out.append(leaf)
            else:
                new_unresolved.append(leaf)
    return resolved_out, new_unresolved


def _resolve_src_ports_inplace(p: "Policy", table: Any) -> None:
    """src_ports의 named(파싱불가) 토큰을 table.service로 **제자리 치환**.

    src_ports는 unresolved_* 필드로 옮기지 않는다(B′-3a-fix의 "빈 리스트
    함정" — src_ips/dst_ips/dst_ports가 미해석 토큰만 있어 빈 리스트가 되면
    각 detect_* 함수가 "전체(any)"로 오분류하던 버그의 회피책 — 같은 함정을
    src_ports에도 만들지 않기 위해 리스트에서 아예 제거하지 않고 그 자리에서
    치환한다). 해석 성공 시 원 토큰 위치에 확장된 leaf들을 삽입하고, 테이블에
    없거나 순환/깊이초과로 실패하면 원 토큰을 그대로 둔다(=여전히 미해석 —
    ISS-035 갭 가드가 이를 감지해 판단보류로 강등한다).
    """
    new_src_ports: List[str] = []
    for tok in p.src_ports:
        if not tok or _is_any_port(tok) or _parse_port_range(tok):
            new_src_ports.append(tok)
            continue
        if tok not in table.service:
            new_src_ports.append(tok)  # 테이블에 없음 — 그대로 미해석 유지
            continue
        try:
            leaves = resolve_name(table, "service", tok)
        except UnresolvableError:
            new_src_ports.append(tok)  # 순환/깊이초과 — 원 토큰 그대로(미해석)
            continue
        new_src_ports.extend(leaves)  # 제자리 치환(파싱가능 여부 무관하게 삽입)
    p.src_ports = new_src_ports


def resolve_policies(
    policies: List[Policy],
    table: Any = None,
) -> List[Policy]:
    """정책 목록의 IP/포트 토큰을 해석하고(1회 분류 패스 + table 주입 시 실치환).

    1단계(분류, table 무관): 파싱 가능한 토큰은 원래 필드(src_ips/dst_ips/
    dst_ports/protocols)에 그대로 유지하고, 불가능한 토큰(=named 객체/그룹
    후보)은 해당 필드에서 제거해 unresolved_src/unresolved_dst/unresolved_svc로
    옮긴다(dst_ports·protocols의 미해석 토큰은 모두 unresolved_svc로 합류).

    2단계(실치환, table 주입 시만 — B′-3b): unresolved_src/dst 토큰이
    table.address에 있으면 fw_objects.resolve_name으로 재귀 해석해 leaf 중
    IP파싱 가능한 것을 src_ips/dst_ips로 복귀시키고, 파싱불가 leaf는
    unresolved_*에 잔존시킨다. unresolved_svc는 table.service로 해석해
    dst_ports로 복귀. src_ports는 named 토큰이 table.service에 있으면
    제자리 치환(unresolved_* 필드로 옮기지 않음).

    table=None(기본)이면 1단계 분류만 수행(B′-3a와 완전 동일 — 회귀 0).
    """
    for p in policies:
        resolved_src: List[str] = []
        for tok in p.src_ips:
            if _is_resolvable_ip_token(tok):
                resolved_src.append(tok)
            else:
                p.unresolved_src.append(tok)
        p.src_ips = resolved_src

        resolved_dst: List[str] = []
        for tok in p.dst_ips:
            if _is_resolvable_ip_token(tok):
                resolved_dst.append(tok)
            else:
                p.unresolved_dst.append(tok)
        p.dst_ips = resolved_dst

        resolved_dport: List[str] = []
        for tok in p.dst_ports:
            if _is_resolvable_port_token(tok):
                resolved_dport.append(tok)
            else:
                p.unresolved_svc.append(tok)
        p.dst_ports = resolved_dport

        resolved_proto: List[str] = []
        for tok in p.protocols:
            if _is_resolvable_protocol_token(tok):
                resolved_proto.append(tok)
            else:
                p.unresolved_svc.append(tok)
        p.protocols = resolved_proto

    if table is not None:
        for p in policies:
            add_src, p.unresolved_src = _resolve_unresolved_tokens(
                p.unresolved_src, table.address, table, "address",
                _is_resolvable_ip_token,
            )
            p.src_ips = p.src_ips + add_src

            add_dst, p.unresolved_dst = _resolve_unresolved_tokens(
                p.unresolved_dst, table.address, table, "address",
                _is_resolvable_ip_token,
            )
            p.dst_ips = p.dst_ips + add_dst

            add_svc, p.unresolved_svc = _resolve_unresolved_tokens(
                p.unresolved_svc, table.service, table, "service",
                _is_resolvable_port_token,
            )
            p.dst_ports = p.dst_ports + add_svc

            _resolve_src_ports_inplace(p, table)

    return policies


# ─ 포맷별 capability 맵 ───────────────────────────────────────────────────────

# {iss_id: {format: can_judge}}
# krfw(한글 13열, P13/P14/P24/P25 실증): Two-way/출발지포트/hit-count 컬럼이
# 없어 ISS-033/035/037은 False(사유는 _NO_CAPABILITY_REASON_BY_FORMAT).
# ISS-035(B'-2, 2026-07-10 Fable 설계 확정): SECUI 실파일 15/15 헤더 스캔 결과
# 출발지 포트 컬럼 부재 확정(포트 컬럼은 'Service Port'(목적지) 뿐) → False.
# PaloAlto도 파서가 src_ports=[](미수집)인데 True였던 영구양호 벡터 → False.
# ID70만 SVC SPEC(`tcp <src> <dst>`)에서 실수집되어 True 유지.
_CAPABILITY: Dict[str, Dict[str, bool]] = {
    "ISS-030": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
    "ISS-031": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
    "ISS-032": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
    "ISS-033": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: False},
    "ISS-034": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
    "ISS-035": {_FORMAT_SECUI: False, _FORMAT_ID70: True,  _FORMAT_PALOALTO: False, _FORMAT_KRFW: False},
    "ISS-036": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
    "ISS-037": {_FORMAT_SECUI: False, _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: False},
    "ISS-038": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False, _FORMAT_KRFW: False},
    "ISS-039": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False, _FORMAT_KRFW: False},
    "ISS-040": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False, _FORMAT_KRFW: False},
    "ISS-041": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True,  _FORMAT_KRFW: True},
}

_NO_CAPABILITY_REASON: Dict[str, str] = {
    "ISS-037": (
        "SECUI 포맷은 hit-count 컬럼이 없어 미사용 정책 자동 탐지가 불가능합니다. "
        "담당자 인터뷰로 확인하세요."
    ),
    "ISS-038": (
        "서버 IP 접근 정책 확인은 자산목록(--aux) 연계가 필요합니다. "
        "현재 구현 범위 외 항목으로 담당자 인터뷰로 확인하세요."
    ),
    "ISS-039": (
        "접근통제시스템 IP 정책은 네트워크 토폴로지 정보가 필요합니다. "
        "현재 구현 범위 외 항목으로 담당자 인터뷰로 확인하세요."
    ),
    "ISS-040": (
        "ISS-040은 방화벽 정책이 아닌 계정·로깅 설정 항목으로, "
        "현재 자동판정 범위 외입니다. 담당자 인터뷰로 확인하세요."
    ),
}

# 포맷 조건부 사유(동일 iss_id라도 포맷별로 부재 이유가 다른 경우).
# detect_for_iss가 (iss_id, fmt) 우선 조회 → 없으면 _NO_CAPABILITY_REASON 폴백.
_NO_CAPABILITY_REASON_BY_FORMAT: Dict[Tuple[str, str], str] = {
    ("ISS-033", _FORMAT_KRFW): (
        "krfw(한글 13열) 포맷은 Two-way(양방향) 상당 컬럼이 없어 "
        "자동 탐지가 불가능합니다. 담당자 인터뷰로 확인하세요."
    ),
    ("ISS-035", _FORMAT_SECUI): (
        "SECUI 포맷은 출발지 포트 컬럼이 정책 export에 없어(실파일 15종 확인, "
        "포트 컬럼은 Service Port(목적지) 뿐) 자동 탐지가 불가능합니다. "
        "담당자 인터뷰로 확인하세요."
    ),
    ("ISS-035", _FORMAT_PALOALTO): (
        "PaloAlto 포맷은 export에 출발지 포트 컬럼이 없어(수집 불가) "
        "자동 탐지가 불가능합니다. 담당자 인터뷰로 확인하세요."
    ),
    ("ISS-035", _FORMAT_KRFW): (
        "krfw(한글 13열) 포맷은 출발지 포트 컬럼이 없어 "
        "자동 탐지가 불가능합니다. 담당자 인터뷰로 확인하세요."
    ),
    ("ISS-037", _FORMAT_KRFW): (
        "krfw(한글 13열) 포맷은 hit-count(세션/사용이력) 컬럼이 없어 "
        "미사용 정책 자동 탐지가 불가능합니다. 담당자 인터뷰로 확인하세요."
    ),
}

# 항목별 미해석 토큰 가드 관련 필드(B′-3a §B-1 규칙3).
# 030/031/034/041 = src+dst 미해석, 032/036 = svc(dst_ports/protocols) 미해석.
# 033/035/037/038~040은 이 가드의 대상이 아니다(무영향).
_UNRESOLVED_GUARD_FIELDS: Dict[str, Tuple[str, ...]] = {
    "ISS-030": ("unresolved_src", "unresolved_dst"),
    "ISS-031": ("unresolved_src", "unresolved_dst"),
    "ISS-034": ("unresolved_src", "unresolved_dst"),
    "ISS-041": ("unresolved_src", "unresolved_dst"),
    "ISS-032": ("unresolved_svc",),
    "ISS-036": ("unresolved_svc",),
}


def _count_unresolved_policies(iss_id: str, policies: List[Policy]) -> int:
    """iss_id 관련 필드에 미해석 토큰을 가진 **enabled** 정책 수.

    disabled 정책은 애초에 탐지 대상이 아니므로(각 detect_* 함수가 이미
    enabled 필터링) 가드도 disabled 정책의 미해석은 무시한다.
    """
    fields = _UNRESOLVED_GUARD_FIELDS.get(iss_id)
    if not fields:
        return 0
    count = 0
    for p in policies:
        if not p.enabled:
            continue
        if any(getattr(p, f) for f in fields):
            count += 1
    return count


# ISS-035 전용 미해석 출발지포트 갭 가드(B′-3b, 최종 브랜치리뷰 Low-2).
#
# src_ports는 unresolved_* 인프라를 타지 않으므로(B′-3a-fix "빈 리스트 함정"
# 회피 — 위 _resolve_src_ports_inplace 참조) _UNRESOLVED_GUARD_FIELDS/
# _count_unresolved_policies 메커니즘이 감지하지 못한다. named 출발지포트
# 토큰(_is_any_port도 아니고 _parse_port_range도 실패하는 토큰)이 --aux-objects
# 없이(또는 테이블에 없어) 그대로 남아 있으면 detect_source_port_usage의
# 파싱 실패 루프가 조용히 스킵해 위반 0건 = "양호"로 나가는 거짓양호 벡터가
# 있었다 — 이 함수가 그 갭을 별도로 카운트해 detect_for_iss의 ISS-035
# 분기에서 양호→판단보류 강등 근거로 쓰인다.
def _count_unresolved_src_port_policies(policies: List[Policy]) -> int:
    """enabled+allow 정책 중 src_ports에 미해석(named) 토큰을 가진 정책 수."""
    count = 0
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        if any(
            ps for ps in p.src_ports
            if ps and not _is_any_port(ps) and not _parse_port_range(ps)
        ):
            count += 1
    return count


# ─ 탐지 함수들 ────────────────────────────────────────────────────────────────

def detect_any_any_allow(policies: List[Policy]) -> List[Policy]:
    """ISS-030: action=allow + src=any + dst=any인 정책."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        # 미해석(named 객체) 토큰이 유일한 값이라 빈 리스트가 된 경우는
        # "전체(any)"가 아니라 불확정 — any-any 위반으로 오분류하지 않는다
        # (B′-3a-fix Opus 리뷰 High: 위반0→판단보류 가드 우회 버그 수정).
        src_any = (
            (not p.src_ips and not p.unresolved_src)
            or (bool(p.src_ips) and all(_is_any(ip) for ip in p.src_ips))
        )
        dst_any = (
            (not p.dst_ips and not p.unresolved_dst)
            or (bool(p.dst_ips) and all(_is_any(ip) for ip in p.dst_ips))
        )
        if src_any and dst_any:
            result.append(p)
    return result


def detect_broad_cidr_port(
    policies: List[Policy],
    target_ports: FrozenSet[int],
) -> List[Policy]:
    """ISS-031/041: 광역 CIDR(src 또는 dst) + 대상 포트 허용."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        has_broad = _has_broad_ip(p.src_ips) or _has_broad_ip(p.dst_ips)
        if not has_broad:
            continue
        # dst_ports가 비어있으면 전포트 허용으로 간주
        if not p.dst_ports or _ports_intersect(p.dst_ports, target_ports):
            result.append(p)
    return result


def detect_all_port_allow(policies: List[Policy]) -> List[Policy]:
    """ISS-032: ALL 서비스 또는 전체 포트(1~65535) 허용 정책."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        # dst_ports 없음 = 전포트, 또는 any 표현. 단 미해석(named 서비스객체)
        # 토큰이 유일한 값이라 비었을 뿐이면 불확정 — 전포트 위반으로
        # 오분류하지 않는다(B′-3a-fix).
        all_ports = (
            (not p.dst_ports and not p.unresolved_svc)
            or (bool(p.dst_ports) and all(_is_any_port(ps) for ps in p.dst_ports))
        )
        if all_ports:
            result.append(p)
    return result


def detect_two_way(policies: List[Policy]) -> List[Policy]:
    """ISS-033: Two-way=True 허용 정책.

    역방향 페어 탐지(별도 두 규칙)는 O(n²) + 그룹객체 확장 없이
    오탐 위험이 높아 1차 구현에서는 제외. TODO: 후속 과제.
    """
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        if p.two_way:
            result.append(p)
    return result


def detect_source_port_usage(policies: List[Policy]) -> List[Policy]:
    """ISS-035: 출발지 포트를 구체적으로 지정한 허용 정책.

    src_ports가 'any'/'1-65535'(전체 허용 표기)가 아니면 위반.
    [M-3] 기준 원문 "출발지 포트 기반의 정책이 존재할 경우 취약"에는 범위
    조건이 없으므로, 1024-65535처럼 any는 아니지만 넓은 특정범위 지정도
    위반으로 간주(과거엔 _SENTINEL_WIDE_RANGE로 제외해 미탐이었음).
    """
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        for ps in p.src_ports:
            if ps and not _is_any_port(ps):
                parsed = _parse_port_range(ps)
                if parsed:
                    result.append(p)
                    break
    return result


def detect_vuln_remote_service(policies: List[Policy]) -> List[Policy]:
    """ISS-036: r-services(512-514) / TFTP(69) 허용 정책."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        # 미해석(named 서비스객체) 토큰이 유일한 값이라 dst_ports가 비었을
        # 뿐이면 불확정 — 취약 원격포트 위반으로 오분류하지 않는다(B′-3a-fix).
        if not p.dst_ports and p.unresolved_svc:
            continue
        # dst 포트가 취약 원격 포트와 교집합
        if not p.dst_ports or _ports_intersect(p.dst_ports, VULN_REMOTE_PORTS):
            # dst_ports 없으면 전포트 허용이므로 취약 포트 포함
            result.append(p)
    return result


def detect_unused_policies(policies: List[Policy]) -> List[Policy]:
    """ISS-037: hit_count=0인 허용 정책 (ID70/Palo Alto 전용)."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        if p.hit_count is not None and p.hit_count == 0:
            result.append(p)
    return result


def detect_shadow_policies(
    policies: List[Policy],
) -> List[Tuple[Policy, Policy]]:
    """ISS-034: 그림자(shadow) 정책 — 상위 규칙이 하위를 IP+포트 범위 면에서
    완전 포함하면서 action이 다른 쌍.

    1차 구현: IP 포함은 ipaddress.subnet_of, 포트는 집합 포함으로 검사.
    그룹 객체 미확장 → 보수 처리(단일 IP/CIDR 문자열만 파싱, 파싱 실패 시 스킵).
    반환: [(상위_정책, 하위_정책)] 쌍 목록.
    """
    active = [p for p in policies if p.enabled]
    result: List[Tuple[Policy, Policy]] = []
    for i, upper in enumerate(active):
        for lower in active[i + 1:]:
            if upper.action.strip().lower() == lower.action.strip().lower():
                continue  # action 동일 → 그림자 아님
            if _policy_covers(upper, lower):
                result.append((upper, lower))
    return result


def _policy_covers(upper: Policy, lower: Policy) -> bool:
    """upper가 lower를 IP+포트 면에서 완전 포함하는지."""
    # upper의 src/dst가 named 객체(미해석 토큰)만 있어 빈 리스트가 됐을
    # 뿐이면 "전체 포함"이 아니라 불확정 — 그림자 페어 후보에서 제외한다
    # (B′-3a-fix: 기존 _ips_cover의 "빈 리스트=any" 관례가 upper 커버리지를
    # 오분류하던 버그 수정).
    if (not upper.src_ips and upper.unresolved_src) or (
        not upper.dst_ips and upper.unresolved_dst
    ):
        return False
    if not _ips_cover(upper.src_ips, lower.src_ips):
        return False
    if not _ips_cover(upper.dst_ips, lower.dst_ips):
        return False
    # 포트 포함 검사
    if upper.dst_ports and lower.dst_ports:
        upper_ports: Set[int] = set()
        for ps in upper.dst_ports:
            if _is_any_port(ps):
                upper_ports = {_SENTINEL_WIDE_RANGE}
                break
            upper_ports |= _parse_port_range(ps)
        lower_ports: Set[int] = set()
        for ps in lower.dst_ports:
            lower_ports |= _parse_port_range(ps)
        # sentinel: upper가 전포트 → 항상 포함
        if _SENTINEL_WIDE_RANGE not in upper_ports and lower_ports:
            if not lower_ports.issubset(upper_ports):
                return False
    return True


def _ips_cover(upper_list: List[str], lower_list: List[str]) -> bool:
    """upper_list의 CIDR들이 lower_list의 모든 IP를 포함하면 True."""
    if not upper_list or all(_is_any(ip) for ip in upper_list):
        return True
    if not lower_list or all(_is_any(ip) for ip in lower_list):
        # lower가 any인데 upper가 특정 범위 → 포함 못 함
        return False
    for lower_ip in lower_list:
        if _is_any(lower_ip):
            return False  # lower가 any인데 upper가 한정 → 불포함
        try:
            lower_net = ipaddress.ip_network(lower_ip, strict=False)
        except ValueError:
            return False
        covered = False
        for upper_ip in upper_list:
            if _is_any(upper_ip):
                covered = True
                break
            try:
                upper_net = ipaddress.ip_network(upper_ip, strict=False)
                if lower_net.subnet_of(upper_net):  # type: ignore[attr-defined]
                    covered = True
                    break
            except (ValueError, TypeError):
                pass
        if not covered:
            return False
    return True


# ─ DetectResult 및 단일 진입점 ───────────────────────────────────────────────

@dataclass
class DetectResult:
    can_judge: bool         # 포맷 capability 있으면 True
    violations: List[str]   # 위반 규칙 요약 텍스트 목록
    needs_review: bool      # 탐지=결정론, 정당성=사람 → 항상 True
    verdict: str            # "양호"|"취약"|"판단보류"
    confidence: float       # 결정론=0.9, capability 없음=0.0
    rationale: str          # 판정 근거


def _summarize_policy(p: Policy) -> str:
    """정책 하나를 증거 인용용 텍스트로 직렬화."""
    seq = f"seq={p.seq}" if p.seq is not None else ""
    rid = f"id={p.rule_id}" if p.rule_id else ""
    label = seq or rid or "?"
    src = ",".join(p.src_ips) if p.src_ips else "any"
    dst = ",".join(p.dst_ips) if p.dst_ips else "any"
    dports = ",".join(p.dst_ports) if p.dst_ports else "any"
    return f"[{label}] {p.action.upper()} src={src} dst={dst} dport={dports}"


def detect_for_iss(
    iss_id: str,
    policies: List[Policy],
    fmt: str,
    unrecognized_action_count: int = 0,
) -> DetectResult:
    """ISS 항목 ID별 탐지 결과 반환. 항상 needs_review=True.

    Args:
        iss_id: "ISS-030" 등 정규화된 항목 ID.
        policies: 정규화된 Policy 리스트.
        fmt: 포맷 키("secui"/"id70"/"paloalto"/"krfw"/"unknown").
        unrecognized_action_count: 파일 전체에서 관대매핑으로도 인식 못한
            action 값 건수(기본 0, 기존 호출부 하위호환). krfw 등에서
            parse_stats로 계측됨. >0이면 거짓양호 봉쇄 가드가 발동해
            위반 0건인 항목의 "양호"를 "판단보류"로 강등한다(위반 1건 이상은
            그대로 취약 유지 — 미인식은 추가 미탐 가능성만 부기).
    """
    cap_map = _CAPABILITY.get(iss_id, {})
    can_judge = cap_map.get(fmt, False)
    if fmt == _FORMAT_UNKNOWN:
        can_judge = False

    if not can_judge:
        reason = _NO_CAPABILITY_REASON_BY_FORMAT.get(
            (iss_id, fmt),
            _NO_CAPABILITY_REASON.get(
                iss_id,
                f"포맷={fmt} 에서 항목 {iss_id} 탐지에 필요한 정보가 없거나 미지원 포맷입니다.",
            ),
        )
        return DetectResult(
            can_judge=False, violations=[], needs_review=True,
            verdict="판단보류", confidence=0.0,
            rationale=f"[FW 자동판정 불가] {reason}",
        )

    viol_policies: List[Policy] = []
    viol_pairs: List[Tuple[Policy, Policy]] = []
    detect_label = ""

    if iss_id == "ISS-030":
        viol_policies = detect_any_any_allow(policies)
        detect_label = "any-any allow 정책"
    elif iss_id == "ISS-031":
        viol_policies = detect_broad_cidr_port(policies, ADMIN_PORTS)
        detect_label = "광역CIDR + 관리포트(SSH/Telnet/RDP 등) 허용"
    elif iss_id == "ISS-032":
        viol_policies = detect_all_port_allow(policies)
        detect_label = "전체포트(ALL/1~65535) 허용"
    elif iss_id == "ISS-033":
        viol_policies = detect_two_way(policies)
        detect_label = "양방향(Two-way) 허용 정책"
    elif iss_id == "ISS-034":
        viol_pairs = detect_shadow_policies(policies)
        detect_label = "그림자(shadow) 정책 (상위가 하위 포함 + action 상이)"
    elif iss_id == "ISS-035":
        viol_policies = detect_source_port_usage(policies)
        detect_label = "출발지포트 지정 허용 정책"
    elif iss_id == "ISS-036":
        viol_policies = detect_vuln_remote_service(policies)
        detect_label = "취약 원격서비스 허용 (r-services 512-514 / TFTP 69)"
    elif iss_id == "ISS-037":
        viol_policies = detect_unused_policies(policies)
        detect_label = "미사용 정책 (hit-count=0)"
    elif iss_id == "ISS-041":
        viol_policies = detect_broad_cidr_port(policies, VULN_PORTS)
        detect_label = "광역CIDR + 취약포트(NetBIOS/SMB/DB 등) 허용"
    else:
        # ISS-038/039/040: capability=False → 위에서 이미 처리됨 (도달 불가)
        return DetectResult(
            can_judge=False, violations=[], needs_review=True,
            verdict="판단보류", confidence=0.0,
            rationale=f"[FW 자동판정 불가] {iss_id} 탐지 미구현.",
        )

    if iss_id == "ISS-034":
        violations = [
            f"[그림자] 상위: {_summarize_policy(u)} → 하위: {_summarize_policy(l)}"
            for u, l in viol_pairs
        ]
        count = len(viol_pairs)
    else:
        violations = [_summarize_policy(p) for p in viol_policies]
        count = len(viol_policies)

    active_total = len([p for p in policies if p.enabled])
    # 거짓양호 봉쇄 가드 ② (B′-3a §B-1 규칙3): 항목 관련 필드에 미해석
    # (named 객체/그룹 후보) 토큰을 가진 enabled 정책 수. 기존 가드
    # (unrecognized_action_count, 위 docstring)와 독립적으로 판정한다 —
    # 서로 다른 근거(액션 미인식 vs. 토큰 미해석)라 순서 간섭 없이 병기 가능.
    unresolved_count = _count_unresolved_policies(iss_id, policies)
    # ISS-035 전용 갭 가드(B′-3b): src_ports는 unresolved_* 인프라 밖이라
    # 위 unresolved_count로는 잡히지 않는다. 다른 항목에는 무영향.
    src_port_unresolved_count = (
        _count_unresolved_src_port_policies(policies)
        if iss_id == "ISS-035" else 0
    )

    if count > 0:
        rationale = (
            f"[FW 결정론 탐지] {detect_label} — "
            f"활성 정책 {active_total}개 중 {count}개 위반 탐지. "
            "정책 정당성(업무 필요성)은 담당자 확인 필요."
        )
        if unrecognized_action_count > 0:
            rationale += (
                f" (참고: 미인식 정책 액션 {unrecognized_action_count}건 존재 — "
                "추가 미탐 가능성 있으나 이미 탐지된 위반은 유효.)"
            )
        if unresolved_count > 0:
            rationale += (
                f" (참고: 미해석 객체 토큰 보유 정책 {unresolved_count}건 존재 — "
                "추가 미탐 가능성 있으나 이미 탐지된 위반은 유효.)"
            )
        verdict = "취약"
        confidence = 0.9
    elif (unresolved_count > 0 or unrecognized_action_count > 0
          or src_port_unresolved_count > 0):
        # 거짓양호 봉쇄 가드(핵심 계약): 위반 0건이라도 (a) 파일 내 미인식
        # action이 있거나 (b) 판정 관련 필드에 미해석 객체 토큰을 가진
        # enabled 정책이 있거나 (c, ISS-035 전용) 미해석 출발지포트 토큰을
        # 가진 정책이 있으면 "양호"를 단정할 수 없다 — 어느 쪽이든 탐지
        # 로직이 실제 위반을 놓쳤을 가능성이 있으므로 판단보류로 강등한다.
        hold_reasons: List[str] = []
        if unresolved_count > 0:
            hold_reasons.append(
                f"미해석 객체 토큰 보유 정책 {unresolved_count}건 → 양호 단정 불가"
            )
        if unrecognized_action_count > 0:
            hold_reasons.append(
                f"미인식 정책 액션 {unrecognized_action_count}건 → 양호 단정 불가"
            )
        if src_port_unresolved_count > 0:
            hold_reasons.append(
                f"미해석 출발지포트 토큰 보유 정책 {src_port_unresolved_count}건 "
                "→ 양호 단정 불가"
            )
        rationale = (
            f"[FW 결정론 탐지] {detect_label} — "
            f"활성 정책 {active_total}개 전수 검사, 해당 이상 없음. "
            f"단, {' / '.join(hold_reasons)}(판단보류)."
        )
        verdict = "판단보류"
        confidence = 0.0
    else:
        rationale = (
            f"[FW 결정론 탐지] {detect_label} — "
            f"활성 정책 {active_total}개 전수 검사, 해당 이상 없음."
        )
        verdict = "양호"
        confidence = 0.9

    return DetectResult(
        can_judge=True,
        violations=violations,
        needs_review=True,
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
    )


# ─ 직렬화/역직렬화 (파서 ↔ 핸들러 간 context 경유) ────────────────────────────

def policy_to_dict(p: Policy) -> Dict[str, Any]:
    """Policy → JSON 직렬화 가능 dict."""
    return {
        "seq": p.seq, "rule_id": p.rule_id, "enabled": p.enabled,
        "action": p.action, "two_way": p.two_way,
        "src_ips": p.src_ips, "dst_ips": p.dst_ips,
        "src_ports": p.src_ports, "dst_ports": p.dst_ports,
        "protocols": p.protocols, "hit_count": p.hit_count,
        "description": p.description,
        "unresolved_src": p.unresolved_src,
        "unresolved_dst": p.unresolved_dst,
        "unresolved_svc": p.unresolved_svc,
    }


def policy_from_dict(d: Dict[str, Any]) -> Policy:
    """dict → Policy 역직렬화 (핸들러에서 context JSON 파싱 시 사용).

    unresolved_src/dst/svc(B′-3a 신규 필드)는 `.get(..., []) or []` 패턴으로
    하위호환 처리 — 신규 필드 도입 이전에 직렬화된 데이터를 로드해도 빈
    리스트로 채워져 KeyError 없이 동작한다.
    """
    return Policy(
        seq=d.get("seq"),
        rule_id=d.get("rule_id"),
        enabled=d.get("enabled", True),
        action=d.get("action", ""),
        two_way=d.get("two_way", False),
        src_ips=d.get("src_ips") or [],
        dst_ips=d.get("dst_ips") or [],
        src_ports=d.get("src_ports") or [],
        dst_ports=d.get("dst_ports") or [],
        protocols=d.get("protocols") or [],
        hit_count=d.get("hit_count"),
        description=d.get("description") or "",
        unresolved_src=d.get("unresolved_src", []) or [],
        unresolved_dst=d.get("unresolved_dst", []) or [],
        unresolved_svc=d.get("unresolved_svc", []) or [],
    )

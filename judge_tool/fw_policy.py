"""방화벽 이상정책 결정론 탐지 엔진 (eol.py 선례).

ISS-030~041 항목별 탐지 함수 + 단일 진입점 detect_for_iss().
LLM 없이 ipaddress(stdlib) + 집합연산으로 정확·전수 탐지.
탐지=결정론, 정당성=사람 (모든 결과 needs_review=True).

포맷별 capability:
  SECUI: ISS-030~036, 041 (hit-count 없어 ISS-037 불가)
  ID70 : ISS-030~037, 041 (DAILY/WEEKLY HIT COUNT 컬럼)
  PaloAlto: ISS-030~037, 041 (Hit Count 컬럼)
  unknown: 전 항목 판정불가 → 판단보류

ISS-038/039는 --aux 자산목록/토폴로지 필요 → 전 포맷 판정불가.
ISS-040은 비정책 항목(계정/로깅 등) → 별도 처리.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Set, Tuple

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


# ─ 포맷 탐지 ──────────────────────────────────────────────────────────────────

_FORMAT_SECUI    = "secui"
_FORMAT_ID70     = "id70"
_FORMAT_PALOALTO = "paloalto"
_FORMAT_UNKNOWN  = "unknown"


def sniff_format(
    headers: List[str],
) -> Literal["secui", "id70", "paloalto", "unknown"]:
    """첫 헤더 행 리스트로 포맷 식별.

    SECUI: 'Font Color:' 범례 행이거나 ('Seq' + 'Two-way' + 'Action') 조합.
    ID70 : 'PRIORITY' + 'SVC SPEC' (또는 SRC TYPE) 존재.
    PaloAlto: 'Hit Count' 또는 ('Zone' + 'Application') 존재.
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


# ─ 포맷별 capability 맵 ───────────────────────────────────────────────────────

# {iss_id: {format: can_judge}}
_CAPABILITY: Dict[str, Dict[str, bool]] = {
    "ISS-030": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-031": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-032": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-033": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-034": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-035": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-036": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-037": {_FORMAT_SECUI: False, _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
    "ISS-038": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False},
    "ISS-039": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False},
    "ISS-040": {_FORMAT_SECUI: False, _FORMAT_ID70: False, _FORMAT_PALOALTO: False},
    "ISS-041": {_FORMAT_SECUI: True,  _FORMAT_ID70: True,  _FORMAT_PALOALTO: True},
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


# ─ 탐지 함수들 ────────────────────────────────────────────────────────────────

def detect_any_any_allow(policies: List[Policy]) -> List[Policy]:
    """ISS-030: action=allow + src=any + dst=any인 정책."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        src_any = (not p.src_ips) or all(_is_any(ip) for ip in p.src_ips)
        dst_any = (not p.dst_ips) or all(_is_any(ip) for ip in p.dst_ips)
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
        # dst_ports 없음 = 전포트, 또는 any 표현
        all_ports = (
            not p.dst_ports
            or all(_is_any_port(ps) for ps in p.dst_ports)
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

    src_ports가 'any'/'1-65535'가 아닌 구체적 포트 범위면 이상.
    """
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
            continue
        for ps in p.src_ports:
            if ps and not _is_any_port(ps):
                parsed = _parse_port_range(ps)
                if parsed and _SENTINEL_WIDE_RANGE not in parsed:
                    result.append(p)
                    break
    return result


def detect_vuln_remote_service(policies: List[Policy]) -> List[Policy]:
    """ISS-036: r-services(512-514) / TFTP(69) 허용 정책."""
    result = []
    for p in policies:
        if not p.enabled or not _is_allow_action(p.action):
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
) -> DetectResult:
    """ISS 항목 ID별 탐지 결과 반환. 항상 needs_review=True.

    Args:
        iss_id: "ISS-030" 등 정규화된 항목 ID.
        policies: 정규화된 Policy 리스트.
        fmt: 포맷 키("secui"/"id70"/"paloalto"/"unknown").
    """
    cap_map = _CAPABILITY.get(iss_id, {})
    can_judge = cap_map.get(fmt, False)
    if fmt == _FORMAT_UNKNOWN:
        can_judge = False

    if not can_judge:
        reason = _NO_CAPABILITY_REASON.get(
            iss_id,
            f"포맷={fmt} 에서 항목 {iss_id} 탐지에 필요한 정보가 없거나 미지원 포맷입니다.",
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

    if count > 0:
        rationale = (
            f"[FW 결정론 탐지] {detect_label} — "
            f"활성 정책 {active_total}개 중 {count}개 위반 탐지. "
            "정책 정당성(업무 필요성)은 담당자 확인 필요."
        )
        verdict = "취약"
        confidence = 0.9
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
    }


def policy_from_dict(d: Dict[str, Any]) -> Policy:
    """dict → Policy 역직렬화 (핸들러에서 context JSON 파싱 시 사용)."""
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
    )

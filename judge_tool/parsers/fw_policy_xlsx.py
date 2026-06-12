"""방화벽 정책 XLSX 파서.

지원 포맷:
  1. SECUI류: 'Font Color:' 범례 + Seq/Two-way/Action/From/To/Service 헤더
  2. ID70: 'PRIORITY/SVC SPEC/SRC TYPE' 70열
  3. PaloAlto: 'Hit Count' 컬럼 포함

parse() 계약:
  [(iss_id, [], context_str), ...] — ISS-030~041 12개 3-튜플.
  resources=[] (탐지는 핸들러에서). context에 직렬화된 정책 데이터.

context 형식:
  FW_FORMAT:<fmt>\\n
  FW_SHEETS:<s1,s2,...>\\n
  FW_POLICY_COUNT:<n>\\n
  FW_POLICIES_JSON:<compact_json>

detect_variant():
  ISS 프로파일은 FW 변형만 구현 → 항상 "fw" 반환.
  main.run의 hasattr(parser, 'detect_variant') seam에서 호출됨.
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple

import openpyxl

from judge_tool.errors import ReportError
from judge_tool.fw_policy import Policy, policy_to_dict, sniff_format
from judge_tool.models import ResourceEvidence

# ISS-030~041 대상 ID 목록 (파서가 emit할 ID 집합)
_ISS_FW_IDS: List[str] = [
    "ISS-030", "ISS-031", "ISS-032", "ISS-033", "ISS-034",
    "ISS-035", "ISS-036", "ISS-037", "ISS-038", "ISS-039",
    "ISS-040", "ISS-041",
]

# 건너뛸 메타 시트 이름 (점검대상, 요약 등)
_SKIP_SHEETS = frozenset({"점검대상", "sheet1", "요약", "summary", "index"})


def detect_variant(xlsx_path: str) -> str:
    """ISS 프로파일은 FW 변형 단일이므로 항상 "fw" 반환.

    파일 접근 없이 고정 반환. main.run의 hasattr(parser, 'detect_variant') seam.
    """
    return "fw"


def parse(
    xlsx_path: str,
) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """방화벽 정책 XLSX → ISS-030~041 12개 3-튜플 emit.

    모든 정책 시트를 순회해 Policy 리스트를 합산하고,
    compact JSON으로 직렬화해 context에 담는다.
    resources는 빈 리스트 — 탐지/판정은 _fw_policy_handler에서.
    """
    try:
        wb = openpyxl.load_workbook(xlsx_path, data_only=True, read_only=True)
    except Exception as e:
        raise ReportError(
            f"방화벽 정책 파일 열기 실패: {xlsx_path} ({type(e).__name__}). "
            "Excel 파일이 손상되었거나 접근 권한이 없습니다."
        ) from e

    all_policies: List[Policy] = []
    detected_fmt: str = "unknown"
    sheet_names: List[str] = []

    try:
        for sname in wb.sheetnames:
            if sname.strip().lower() in _SKIP_SHEETS:
                continue
            ws = wb[sname]
            rows = list(ws.iter_rows(values_only=True))
            if not rows:
                continue
            # 비어있는 시트 스킵
            if all(all(c is None for c in row) for row in rows[:3]):
                continue

            # 포맷 탐지: 헤더 행 후보를 순서대로 시도
            fmt = _detect_format_from_rows(rows)
            if detected_fmt == "unknown" and fmt != "unknown":
                detected_fmt = fmt

            policies = _parse_sheet(rows, fmt, sname)
            if policies:
                all_policies.extend(policies)
                sheet_names.append(sname)

    finally:
        wb.close()

    if not sheet_names and not all_policies:
        raise ReportError(
            f"방화벽 정책 파싱 실패: {xlsx_path} — 유효한 정책 시트가 없습니다."
        )

    # compact JSON 직렬화 (단일 행 보장)
    policies_json = json.dumps(
        [policy_to_dict(p) for p in all_policies],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    context_str = (
        f"FW_FORMAT:{detected_fmt}\n"
        f"FW_SHEETS:{','.join(sheet_names)}\n"
        f"FW_POLICY_COUNT:{len(all_policies)}\n"
        f"FW_POLICIES_JSON:{policies_json}"
    )

    # ISS-030~041 각각에 대해 3-튜플 emit (resources=[] 빈 리스트)
    return [(iss_id, [], context_str) for iss_id in _ISS_FW_IDS]


# ─ 포맷 탐지 ──────────────────────────────────────────────────────────────────

def _detect_format_from_rows(rows: List[Tuple]) -> str:
    """시트 상단 몇 행을 스캔해 포맷 결정. 첫 매칭 행에서 반환."""
    for row in rows[:10]:
        headers = [str(v).strip() if v is not None else "" for v in row]
        if any(headers):
            fmt = sniff_format(headers)
            if fmt != "unknown":
                return fmt
    return "unknown"


# ─ 포맷별 시트 파싱 ───────────────────────────────────────────────────────────

def _cell(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _parse_sheet(
    rows: List[Tuple],
    fmt: str,
    sheet_name: str,
) -> List[Policy]:
    if fmt == "secui":
        return _parse_secui(rows, sheet_name)
    if fmt == "id70":
        return _parse_id70(rows, sheet_name)
    if fmt == "paloalto":
        return _parse_paloalto(rows, sheet_name)
    return []  # unknown: 핸들러에서 판단보류 처리


# ─ SECUI 어댑터 ───────────────────────────────────────────────────────────────

def _find_secui_header_row(rows: List[Tuple]) -> Tuple[int, Dict[str, int]]:
    """SECUI 주요 헤더 행을 동적으로 찾고 컬럼 인덱스 맵을 반환.

    'Seq'와 'Action'이 모두 있는 행이 주요 헤더 행.
    반환: (data_start_row_index, {컬럼명: 인덱스})
    컬럼명 키: seq/enable/two_way/rule_id/action/src_ip/dst_ip/proto/dst_port
    """
    for row_idx, row in enumerate(rows[:15]):
        cells = [_cell(v).lower() for v in row]
        if "seq" not in cells and not any("seq" == c for c in cells):
            continue
        if "action" not in cells:
            continue
        # 이 행이 주요 헤더 행
        col_map: Dict[str, int] = {}
        for i, c in enumerate(cells):
            if c == "seq":
                col_map.setdefault("seq", i)
            elif c in ("enable", "enabled"):
                col_map.setdefault("enable", i)
            elif "two" in c and "way" in c:
                col_map.setdefault("two_way", i)
            elif c == "id":
                col_map.setdefault("rule_id", i)
            elif c == "action":
                col_map.setdefault("action", i)
        # From/To/Service 는 헤더가 여러 열에 걸쳐 있어 서브헤더 행에서 IP 추출
        # 기본 인덱스 설정 (SECUI 표준 레이아웃)
        col_map.setdefault("seq", 0)
        col_map.setdefault("enable", 1)
        col_map.setdefault("two_way", 2)
        col_map.setdefault("rule_id", 3)
        col_map.setdefault("action", 4)
        return row_idx + 1, col_map
    # 헤더 행 미발견 → 기본값 사용 (SECUI 표준 레이아웃)
    return 6, {
        "seq": 0, "enable": 1, "two_way": 2,
        "rule_id": 3, "action": 4,
    }


def _find_secui_ip_cols(rows: List[Tuple], header_row: int) -> Tuple[int, int, int, int]:
    """SECUI 서브헤더에서 src_ip/dst_ip/proto/dst_port 컬럼 인덱스 추정.

    표준 SECUI 레이아웃에서 IP 컬럼은 From 그룹(col~8)과 To 그룹(col~15)에 위치.
    서브헤더 행에서 'ip' 키워드를 포함하는 컬럼 두 개를 순서대로 src/dst로 삼음.
    """
    # 서브헤더 행들(header_row ~ header_row+4) 스캔
    src_ip_col, dst_ip_col = 8, 15  # SECUI 기본값
    proto_col, port_col = 20, 21

    for row in rows[header_row: header_row + 5]:
        cells = [_cell(v).lower() for v in row]
        ip_cols = [i for i, c in enumerate(cells) if c == "ip" or "ip" == c]
        if len(ip_cols) >= 2:
            src_ip_col, dst_ip_col = ip_cols[0], ip_cols[1]
        # 프로토콜/포트 컬럼 탐색
        for i, c in enumerate(cells):
            if c in ("protocol", "proto"):
                proto_col = i
            if c in ("service port", "port", "dport", "dst port"):
                port_col = i
    return src_ip_col, dst_ip_col, proto_col, port_col


def _parse_secui(rows: List[Tuple], sheet_name: str) -> List[Policy]:
    """SECUI 포맷 파싱.

    특징:
    - 상단 몇 행은 색 범례/서브헤더 (Font Color, 색 표, 헤더, 서브헤더들)
    - Seq 컬럼에 숫자가 있는 행이 새 정책의 시작
    - 연속 행(Seq 빈칸)은 현재 정책의 IP/포트 추가 행
    """
    data_start, col_map = _find_secui_header_row(rows)
    src_ip_col, dst_ip_col, proto_col, port_col = _find_secui_ip_cols(
        rows, data_start
    )

    seq_col    = col_map.get("seq", 0)
    enable_col = col_map.get("enable", 1)
    tw_col     = col_map.get("two_way", 2)
    rid_col    = col_map.get("rule_id", 3)
    act_col    = col_map.get("action", 4)

    policies: List[Policy] = []
    current: Optional[Policy] = None

    for row in rows[data_start:]:
        if len(row) == 0:
            continue
        seq_val = _cell(row[seq_col] if len(row) > seq_col else None)

        if seq_val and re.match(r"^\d+$", seq_val):
            # 새 정책 시작 — 이전 정책 저장
            if current is not None:
                policies.append(current)
            enabled_str = _cell(row[enable_col] if len(row) > enable_col else None)
            enabled = enabled_str.upper() not in ("N", "NO", "FALSE", "0", "X")
            two_way = _cell(row[tw_col] if len(row) > tw_col else None).upper() == "Y"
            rule_id = _cell(row[rid_col] if len(row) > rid_col else None)
            action  = _cell(row[act_col] if len(row) > act_col else None)
            current = Policy(
                seq=int(seq_val),
                rule_id=rule_id or None,
                enabled=enabled,
                action=action,
                two_way=two_way,
                src_ips=[], dst_ips=[],
                src_ports=["any"], dst_ports=[],
                protocols=[],
            )

        if current is None:
            continue

        # IP/프로토콜/포트 수집 (새 정책 행 + 연속 행 모두)
        src_ip = _cell(row[src_ip_col] if len(row) > src_ip_col else None)
        dst_ip = _cell(row[dst_ip_col] if len(row) > dst_ip_col else None)
        proto  = _cell(row[proto_col]  if len(row) > proto_col  else None)
        dport  = _cell(row[port_col]   if len(row) > port_col   else None)

        if src_ip and src_ip not in current.src_ips:
            current.src_ips.append(src_ip)
        if dst_ip and dst_ip not in current.dst_ips:
            current.dst_ips.append(dst_ip)
        if proto and proto.lower() not in ("protocol", "") and proto not in current.protocols:
            current.protocols.append(proto)
        if dport and dport.lower() not in ("port", "service port", "") and dport not in current.dst_ports:
            current.dst_ports.append(dport)

    if current is not None:
        policies.append(current)

    return policies


# ─ ID70 어댑터 ────────────────────────────────────────────────────────────────

# ID70 헤더 키워드 → 정규화 필드명 맵핑
_ID70_HEADER_MAP: Dict[str, str] = {
    "priority": "rule_id",
    "enabled":  "enable",
    "enable":   "enable",
    "src addr": "src",
    "source":   "src",
    "dst addr": "dst",
    "destination": "dst",
    "svc spec": "svc_spec",
    "service":  "svc_spec",
    "action":   "action",
    "allow":    "action",
    "daliy hit count":   "hit",
    "daily hit count":   "hit",
    "weekly hit count":  "hit",
    "monthly hit count": "hit",
    "hit count": "hit",
}


def _build_id70_col_map(header_row: List[str]) -> Dict[str, int]:
    """ID70 헤더 행에서 필드→컬럼 인덱스 맵 생성."""
    col_map: Dict[str, int] = {}
    for i, h in enumerate(header_row):
        key = h.strip().lower()
        for pattern, field_name in _ID70_HEADER_MAP.items():
            if pattern in key and field_name not in col_map:
                col_map[field_name] = i
                break
    return col_map


def _parse_svc_spec(svc: str, policy: Policy) -> None:
    """ID70 SVC SPEC 파싱: 'tcp 1-65535 443-443' → protocol/src_port/dst_port."""
    parts = svc.strip().split()
    if len(parts) >= 3:
        proto, src_port, dst_port = parts[0], parts[1], parts[2]
        if proto not in policy.protocols:
            policy.protocols.append(proto)
        if src_port not in policy.src_ports:
            policy.src_ports.append(src_port)
        if dst_port not in policy.dst_ports:
            policy.dst_ports.append(dst_port)
    elif len(parts) == 2:
        proto, dport = parts[0], parts[1]
        if proto not in policy.protocols:
            policy.protocols.append(proto)
        if dport not in policy.dst_ports:
            policy.dst_ports.append(dport)
    elif len(parts) == 1:
        s = parts[0]
        if re.match(r"\d", s):  # 포트처럼 보이면 dst_port로
            if s not in policy.dst_ports:
                policy.dst_ports.append(s)
        elif s not in policy.protocols:
            policy.protocols.append(s)


def _parse_id70(rows: List[Tuple], sheet_name: str) -> List[Policy]:
    """ID70 포맷 파싱 (단일 헤더행, 최대 70열).

    PRIORITY 컬럼 값이 있는 행이 새 정책 시작.
    연속 행에서 SRC/DST/SVC 추가.
    """
    if not rows:
        return []

    header = [_cell(v).lower() for v in rows[0]]
    col_map = _build_id70_col_map(header)

    if "rule_id" not in col_map:
        return []  # PRIORITY 컬럼 없으면 ID70 아님

    rid_col    = col_map.get("rule_id", 0)
    enable_col = col_map.get("enable", -1)
    src_col    = col_map.get("src", -1)
    dst_col    = col_map.get("dst", -1)
    svc_col    = col_map.get("svc_spec", -1)
    act_col    = col_map.get("action", -1)
    hit_col    = col_map.get("hit", -1)

    policies: List[Policy] = []
    current: Optional[Policy] = None

    for row in rows[1:]:
        if not any(row):
            continue
        priority_val = row[rid_col] if len(row) > rid_col else None

        if priority_val is not None and str(priority_val).strip():
            if current is not None:
                policies.append(current)
            enabled_str = _cell(row[enable_col] if enable_col >= 0 and len(row) > enable_col else None)
            enabled = enabled_str.lower() not in ("no", "false", "n", "0", "x", "disabled")
            action = _cell(row[act_col] if act_col >= 0 and len(row) > act_col else None)
            hit_count: Optional[int] = None
            if hit_col >= 0 and len(row) > hit_col and row[hit_col] is not None:
                try:
                    hit_count = int(row[hit_col])
                except (TypeError, ValueError):
                    pass
            current = Policy(
                seq=None,
                rule_id=str(priority_val).strip(),
                enabled=enabled,
                action=action,
                two_way=False,
                src_ips=[], dst_ips=[],
                src_ports=[], dst_ports=[],
                protocols=[],
                hit_count=hit_count,
            )

        if current is None:
            continue

        src = _cell(row[src_col] if src_col >= 0 and len(row) > src_col else None)
        dst = _cell(row[dst_col] if dst_col >= 0 and len(row) > dst_col else None)
        svc = _cell(row[svc_col] if svc_col >= 0 and len(row) > svc_col else None)

        if src and src not in current.src_ips:
            current.src_ips.append(src)
        if dst and dst not in current.dst_ips:
            current.dst_ips.append(dst)
        if svc:
            _parse_svc_spec(svc, current)

    if current is not None:
        policies.append(current)

    return policies


# ─ Palo Alto 어댑터 ───────────────────────────────────────────────────────────

_PALOALTO_HEADER_KEYWORDS: Dict[str, List[str]] = {
    "action":    ["action"],
    "src":       ["source address", "source", "src"],
    "dst":       ["destination address", "destination", "dst"],
    "dport":     ["destination port", "service", "port"],
    "proto":     ["application", "protocol"],
    "hit":       ["hit count", "hitcount"],
    "enable":    ["enable", "enabled", "status"],
    "rule_name": ["name", "rule name", "rulename"],
}


def _build_paloalto_col_map(header: List[str]) -> Dict[str, int]:
    """Palo Alto 헤더에서 필드→컬럼 인덱스 맵 (동적)."""
    col_map: Dict[str, int] = {}
    lower_header = [h.strip().lower() for h in header]
    for field_name, keywords in _PALOALTO_HEADER_KEYWORDS.items():
        for kw in keywords:
            for i, h in enumerate(lower_header):
                if kw in h and field_name not in col_map:
                    col_map[field_name] = i
    return col_map


def _parse_paloalto(rows: List[Tuple], sheet_name: str) -> List[Policy]:
    """Palo Alto 18열 포맷 파싱 (동적 헤더 탐색)."""
    if not rows:
        return []

    header = [_cell(v) for v in rows[0]]
    col_map = _build_paloalto_col_map(header)

    act_col    = col_map.get("action", -1)
    src_col    = col_map.get("src", -1)
    dst_col    = col_map.get("dst", -1)
    dport_col  = col_map.get("dport", -1)
    proto_col  = col_map.get("proto", -1)
    hit_col    = col_map.get("hit", -1)
    enable_col = col_map.get("enable", -1)

    policies: List[Policy] = []
    for row in rows[1:]:
        if not any(row):
            continue
        action = _cell(row[act_col] if act_col >= 0 and len(row) > act_col else None)
        if not action:
            continue

        src   = _cell(row[src_col]    if src_col    >= 0 and len(row) > src_col    else None)
        dst   = _cell(row[dst_col]    if dst_col    >= 0 and len(row) > dst_col    else None)
        dport = _cell(row[dport_col]  if dport_col  >= 0 and len(row) > dport_col  else None)
        proto = _cell(row[proto_col]  if proto_col  >= 0 and len(row) > proto_col  else None)
        ena_s = _cell(row[enable_col] if enable_col >= 0 and len(row) > enable_col else None)
        enabled = ena_s.lower() not in ("no", "false", "n", "0", "disabled")

        hit_count: Optional[int] = None
        if hit_col >= 0 and len(row) > hit_col and row[hit_col] is not None:
            try:
                hit_count = int(row[hit_col])
            except (TypeError, ValueError):
                pass

        policies.append(Policy(
            seq=None,
            rule_id=None,
            enabled=enabled,
            action=action,
            two_way=False,
            src_ips=[src] if src else [],
            dst_ips=[dst] if dst else [],
            src_ports=[],
            dst_ports=[dport] if dport else [],
            protocols=[proto] if proto else [],
            hit_count=hit_count,
        ))

    return policies

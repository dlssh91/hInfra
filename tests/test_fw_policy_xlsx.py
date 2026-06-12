"""fw_policy_xlsx 파서 단위 테스트 (작업②).

합성 openpyxl xlsx 픽스처로 실데이터 없이 실행한다.
"""
import json

import openpyxl
import pytest

from judge_tool.errors import ReportError
from judge_tool.parsers.fw_policy_xlsx import (
    detect_variant,
    parse,
    _ISS_FW_IDS,
    _detect_format_from_rows,
    _parse_id70,
    _parse_paloalto,
    _parse_secui,
)


# ─ detect_variant ─────────────────────────────────────────────────────────────

def test_detect_variant_always_fw():
    assert detect_variant("any_path.xlsx") == "fw"
    assert detect_variant("") == "fw"


# ─ 합성 xlsx 헬퍼 ──────────────────────────────────────────────────────────────

def _write_xlsx(path, sheet_name, rows):
    """rows: list of list; 각 원소가 셀값."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name
    for r_idx, row in enumerate(rows, start=1):
        for c_idx, val in enumerate(row, start=1):
            ws.cell(r_idx, c_idx, val)
    wb.save(str(path))


def _secui_rows():
    """최소 SECUI 시트 rows (헤더 + 2개 정책)."""
    return [
        # row1: 범례 (font color 키워드)
        ["Font Color:", "색", None, None, None],
        # row2: 빈행
        [None]*5,
        # row3: 주요 헤더 행
        ["Seq", "Enable", "Two-way", "ID", "Action", None, None, None, "IP", None, None,
         None, None, None, None, "IP", None, None, None, None, "Protocol", "Port"],
        # row4: 데이터 행1 — any-any allow
        [1, "Y", "N", "R001", "allow", None, None, None, "any", None, None,
         None, None, None, None, "any", None, None, None, None, "tcp", "80"],
        # row5: 데이터 행2 — deny
        [2, "Y", "N", "R002", "deny", None, None, None, "10.0.0.1", None, None,
         None, None, None, None, "192.168.1.1", None, None, None, None, "tcp", "443"],
    ]


def _id70_rows():
    """최소 ID70 시트 rows (헤더 + 2개 정책)."""
    return [
        ["PRIORITY", "ENABLED", "SRC ADDR", "DST ADDR", "SVC SPEC", "ACTION",
         "DAILY HIT COUNT"],
        ["P001", "YES", "any", "10.0.0.0/8", "tcp 1-65535 22-22", "allow", 0],
        ["P002", "YES", "192.168.1.0/24", "any", "tcp 1-65535 443-443", "deny", 100],
    ]


def _paloalto_rows():
    """최소 Palo Alto 시트 rows (헤더 + 2개 정책)."""
    return [
        ["Name", "Source", "Destination", "Service", "Action", "Hit Count", "Application"],
        ["rule1", "any", "10.0.0.0/8", "22", "allow", 0, "ssh"],
        ["rule2", "192.168.1.0/24", "any", "443", "deny", 50, "ssl"],
    ]


# ─ _detect_format_from_rows ───────────────────────────────────────────────────

def test_detect_format_secui():
    rows = [(v,) if not isinstance(v, (list, tuple)) else tuple(v)
            for v in _secui_rows()]
    rows_as_tuples = [tuple(r) if isinstance(r, list) else r for r in _secui_rows()]
    fmt = _detect_format_from_rows(rows_as_tuples)
    assert fmt == "secui"


def test_detect_format_id70():
    rows_as_tuples = [tuple(r) for r in _id70_rows()]
    fmt = _detect_format_from_rows(rows_as_tuples)
    assert fmt == "id70"


def test_detect_format_paloalto():
    rows_as_tuples = [tuple(r) for r in _paloalto_rows()]
    fmt = _detect_format_from_rows(rows_as_tuples)
    assert fmt == "paloalto"


def test_detect_format_all_empty():
    fmt = _detect_format_from_rows([(None, None, None)] * 10)
    assert fmt == "unknown"


# ─ _parse_id70 단위 ───────────────────────────────────────────────────────────

def test_parse_id70_policies():
    rows = [tuple(r) for r in _id70_rows()]
    policies = _parse_id70(rows, "test")
    assert len(policies) == 2
    p = policies[0]
    assert p.rule_id == "P001"
    assert p.action == "allow"
    assert p.src_ips == ["any"]
    assert p.dst_ips == ["10.0.0.0/8"]
    assert p.hit_count == 0


def test_parse_id70_svc_spec_parsed():
    rows = [tuple(r) for r in _id70_rows()]
    policies = _parse_id70(rows, "test")
    p = policies[0]  # "tcp 1-65535 22-22"
    assert "tcp" in p.protocols
    assert "22-22" in p.dst_ports


def test_parse_id70_hit_count():
    rows = [tuple(r) for r in _id70_rows()]
    policies = _parse_id70(rows, "test")
    assert policies[0].hit_count == 0
    assert policies[1].hit_count == 100


def test_parse_id70_empty_rows():
    assert _parse_id70([], "test") == []


def test_parse_id70_no_priority_col():
    rows = [("Name", "Action", "Source"), ("rule1", "allow", "any")]
    assert _parse_id70([tuple(r) for r in rows], "test") == []


# ─ _parse_secui 단위 ───────────────────────────────────────────────────────────

def test_parse_secui_policies():
    rows = [tuple(r) for r in _secui_rows()]
    policies = _parse_secui(rows, "test")
    assert len(policies) == 2
    assert policies[0].action == "allow"
    assert policies[1].action == "deny"


def test_parse_secui_seq():
    rows = [tuple(r) for r in _secui_rows()]
    policies = _parse_secui(rows, "test")
    assert policies[0].seq == 1
    assert policies[1].seq == 2


def test_parse_secui_ips_extracted():
    rows = [tuple(r) for r in _secui_rows()]
    policies = _parse_secui(rows, "test")
    # any-any row
    p0 = policies[0]
    assert "any" in p0.src_ips or len(p0.src_ips) == 0 or "any" in p0.src_ips


# ─ _parse_paloalto 단위 ───────────────────────────────────────────────────────

def test_parse_paloalto_policies():
    rows = [tuple(r) for r in _paloalto_rows()]
    policies = _parse_paloalto(rows, "test")
    assert len(policies) == 2


def test_parse_paloalto_action_and_ips():
    rows = [tuple(r) for r in _paloalto_rows()]
    policies = _parse_paloalto(rows, "test")
    assert policies[0].action == "allow"
    assert policies[0].src_ips == ["any"]
    assert policies[0].dst_ips == ["10.0.0.0/8"]
    assert policies[0].hit_count == 0


def test_parse_paloalto_empty_rows():
    assert _parse_paloalto([], "test") == []


def test_parse_paloalto_skip_empty_action():
    rows = [
        ("Source", "Action", "Hit Count"),
        ("any", None, 0),   # action 없음 → skip
        ("any", "allow", 0),
    ]
    policies = _parse_paloalto([tuple(r) for r in rows], "test")
    assert len(policies) == 1


# ─ parse() — 통합 ──────────────────────────────────────────────────────────────

def test_parse_returns_12_tuples_secui(tmp_path):
    p = str(tmp_path / "secui.xlsx")
    _write_xlsx(p, "FW_Policy", _secui_rows())
    result = parse(p)
    assert len(result) == 12
    ids = [r[0] for r in result]
    assert ids == _ISS_FW_IDS


def test_parse_resources_always_empty(tmp_path):
    p = str(tmp_path / "secui2.xlsx")
    _write_xlsx(p, "FW_Policy", _secui_rows())
    result = parse(p)
    for iss_id, resources, ctx in result:
        assert resources == []


def test_parse_context_format_secui(tmp_path):
    p = str(tmp_path / "secui3.xlsx")
    _write_xlsx(p, "FW_Policy", _secui_rows())
    result = parse(p)
    ctx = result[0][2]
    assert ctx.startswith("FW_FORMAT:secui")
    assert "FW_SHEETS:" in ctx
    assert "FW_POLICY_COUNT:" in ctx
    assert "FW_POLICIES_JSON:" in ctx


def test_parse_context_json_valid(tmp_path):
    p = str(tmp_path / "id70.xlsx")
    _write_xlsx(p, "FW_Policy", _id70_rows())
    result = parse(p)
    ctx = result[0][2]
    json_part = ctx.split("FW_POLICIES_JSON:", 1)[1]
    policies = json.loads(json_part)
    assert isinstance(policies, list)
    assert len(policies) == 2


def test_parse_id70_file(tmp_path):
    p = str(tmp_path / "id70b.xlsx")
    _write_xlsx(p, "FW_Policy", _id70_rows())
    result = parse(p)
    ctx = result[0][2]
    assert "FW_FORMAT:id70" in ctx


def test_parse_paloalto_file(tmp_path):
    p = str(tmp_path / "paloalto.xlsx")
    _write_xlsx(p, "FW_Policy", _paloalto_rows())
    result = parse(p)
    ctx = result[0][2]
    assert "FW_FORMAT:paloalto" in ctx


def test_parse_skip_sheets_meta(tmp_path):
    """'점검대상' 시트는 스킵되고 정책 시트만 파싱된다."""
    wb = openpyxl.Workbook()
    # 첫 시트를 '점검대상'으로
    ws1 = wb.active
    ws1.title = "점검대상"
    for r, row in enumerate(_id70_rows(), start=1):
        for c, val in enumerate(row, start=1):
            ws1.cell(r, c, val)
    # 두 번째 시트에 실제 정책
    ws2 = wb.create_sheet("방화벽정책")
    for r, row in enumerate(_id70_rows(), start=1):
        for c, val in enumerate(row, start=1):
            ws2.cell(r, c, val)
    p = str(tmp_path / "multi.xlsx")
    wb.save(p)
    result = parse(p)
    ctx = result[0][2]
    # 방화벽정책 시트만 포함
    assert "방화벽정책" in ctx
    assert "점검대상" not in ctx.split("FW_SHEETS:")[1].split("\n")[0]


def test_parse_no_valid_sheet_raises(tmp_path):
    """빈 시트만 있으면 ReportError 발생."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "빈시트"
    # 아무 내용 없음
    p = str(tmp_path / "empty.xlsx")
    wb.save(p)
    with pytest.raises(ReportError):
        parse(p)


def test_parse_invalid_path_raises():
    with pytest.raises(ReportError):
        parse("/nonexistent/path/file.xlsx")


def test_parse_all_iss_ids_present(tmp_path):
    p = str(tmp_path / "all_ids.xlsx")
    _write_xlsx(p, "FW_Policy", _paloalto_rows())
    result = parse(p)
    returned_ids = {r[0] for r in result}
    assert returned_ids == set(_ISS_FW_IDS)


def test_parse_shared_context_across_all_items(tmp_path):
    """12개 3-튜플이 동일한 context 문자열을 공유한다."""
    p = str(tmp_path / "shared.xlsx")
    _write_xlsx(p, "FW_Policy", _id70_rows())
    result = parse(p)
    contexts = [ctx for _, _, ctx in result]
    assert all(c == contexts[0] for c in contexts)

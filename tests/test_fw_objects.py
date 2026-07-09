"""fw_objects 단위 테스트 (B′-3b) — ObjectTable/load_aux_objects/resolve_name.

합성 픽스처(더미 YAML) 사용 — 실 객체 export 데이터 불필요(현 데이터셋에
객체정의 시트 자체가 없음, 2026-07-10 Fable 실사).
"""
import pytest

from judge_tool.errors import ReportError
from judge_tool.fw_objects import (
    ObjectTable,
    UnresolvableError,
    load_aux_objects,
    resolve_name,
)


# ─ ObjectTable / load_aux_objects ────────────────────────────────────────────

def test_object_table_defaults_empty():
    t = ObjectTable()
    assert t.address == {}
    assert t.service == {}


def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "objects.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_load_aux_objects_simple(tmp_path):
    path = _write_yaml(tmp_path, """
address:
  WEB_GRP: ["10.0.1.0/24", "10.0.2.0/24"]
service:
  WEB_SVC: ["80", "443"]
""")
    table = load_aux_objects(path)
    assert table.address == {"WEB_GRP": ["10.0.1.0/24", "10.0.2.0/24"]}
    assert table.service == {"WEB_SVC": ["80", "443"]}


def test_load_aux_objects_nested_reference(tmp_path):
    path = _write_yaml(tmp_path, """
address:
  WEB_GRP: ["10.0.1.0/24", "DMZ_GRP"]
  DMZ_GRP: ["172.16.0.0/16"]
""")
    table = load_aux_objects(path)
    assert table.address["WEB_GRP"] == ["10.0.1.0/24", "DMZ_GRP"]


def test_load_aux_objects_missing_section_defaults_empty(tmp_path):
    path = _write_yaml(tmp_path, "address:\n  A: [\"1.2.3.4\"]\n")
    table = load_aux_objects(path)
    assert table.service == {}


def test_load_aux_objects_empty_sections_ok(tmp_path):
    path = _write_yaml(tmp_path, "address: {}\nservice: {}\n")
    table = load_aux_objects(path)
    assert table.address == {}
    assert table.service == {}


# ─ load_aux_objects — fail-closed 오류 케이스 (g) ────────────────────────────

def test_load_aux_objects_missing_file_raises():
    with pytest.raises(ReportError, match="찾을 수 없습니다"):
        load_aux_objects("/no/such/path/objects.yaml")


def test_load_aux_objects_broken_yaml_raises(tmp_path):
    path = _write_yaml(tmp_path, "address: [broken: yaml: syntax\n")
    with pytest.raises(ReportError, match="YAML 파싱 오류"):
        load_aux_objects(path)


def test_load_aux_objects_empty_file_raises(tmp_path):
    path = _write_yaml(tmp_path, "")
    with pytest.raises(ReportError, match="비어 있습니다"):
        load_aux_objects(path)


def test_load_aux_objects_top_level_not_mapping_raises(tmp_path):
    path = _write_yaml(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ReportError, match="최상위는 매핑"):
        load_aux_objects(path)


def test_load_aux_objects_section_not_mapping_raises(tmp_path):
    path = _write_yaml(tmp_path, "address:\n  - not\n  - a\n  - mapping\n")
    with pytest.raises(ReportError, match="'address' 섹션은 매핑"):
        load_aux_objects(path)


def test_load_aux_objects_value_not_string_list_raises(tmp_path):
    path = _write_yaml(tmp_path, "address:\n  WEB_GRP: \"not a list\"\n")
    with pytest.raises(ReportError, match="문자열 리스트"):
        load_aux_objects(path)


def test_load_aux_objects_value_list_with_non_string_raises(tmp_path):
    path = _write_yaml(tmp_path, "address:\n  WEB_GRP: [1, 2, 3]\n")
    with pytest.raises(ReportError, match="문자열 리스트"):
        load_aux_objects(path)


# ─ resolve_name — 단순/중첩/순환/깊이초과 ────────────────────────────────────

def test_resolve_name_simple_no_nesting():
    table = ObjectTable(address={"WEB_GRP": ["10.0.1.0/24", "10.0.2.0/24"]})
    assert resolve_name(table, "address", "WEB_GRP") == [
        "10.0.1.0/24", "10.0.2.0/24"
    ]


def test_resolve_name_two_level_nesting():
    table = ObjectTable(address={
        "WEB_GRP": ["10.0.1.0/24", "DMZ_GRP"],
        "DMZ_GRP": ["172.16.0.0/16"],
    })
    assert resolve_name(table, "address", "WEB_GRP") == [
        "10.0.1.0/24", "172.16.0.0/16"
    ]


def test_resolve_name_service_section():
    table = ObjectTable(service={"WEB_SVC": ["80", "443", "ALT_SVC"],
                                  "ALT_SVC": ["8080"]})
    assert resolve_name(table, "service", "WEB_SVC") == ["80", "443", "8080"]


def test_resolve_name_depth_boundary_8_ok():
    """8단 중첩(G0→G1→...→G7→leaf)은 경계 내 — 정상 해석."""
    address = {}
    for i in range(7):
        address[f"G{i}"] = [f"G{i+1}"]
    address["G7"] = ["1.2.3.4"]
    table = ObjectTable(address=address)
    assert resolve_name(table, "address", "G0") == ["1.2.3.4"]


def test_resolve_name_depth_9_exceeds_raises():
    """9단 중첩(G0→...→G8→leaf)은 깊이상한 초과 — UnresolvableError."""
    address = {}
    for i in range(8):
        address[f"G{i}"] = [f"G{i+1}"]
    address["G8"] = ["1.2.3.4"]
    table = ObjectTable(address=address)
    with pytest.raises(UnresolvableError):
        resolve_name(table, "address", "G0")


def test_resolve_name_cycle_raises():
    """A→B→A 순환 — 무한루프 없이 UnresolvableError."""
    table = ObjectTable(address={"A": ["B"], "B": ["A"]})
    with pytest.raises(UnresolvableError):
        resolve_name(table, "address", "A")


def test_resolve_name_self_cycle_raises():
    table = ObjectTable(address={"A": ["A"]})
    with pytest.raises(UnresolvableError):
        resolve_name(table, "address", "A")


def test_resolve_name_partial_leaf_and_unknown_token():
    """멤버 중 일부만 leaf가 IP파싱 불가한 미지 토큰이어도 resolve_name 자체는
    (그 값이 섹션의 키가 아닌 한) 그대로 leaf로 반환 — IP/포트 파싱 가능여부
    판단은 resolve_name의 책임이 아니라 호출측(fw_policy)의 책임이다."""
    table = ObjectTable(address={"MIXED_GRP": ["10.0.1.0/24", "UNKNOWN_TOKEN"]})
    assert resolve_name(table, "address", "MIXED_GRP") == [
        "10.0.1.0/24", "UNKNOWN_TOKEN"
    ]


def test_resolve_name_unknown_top_level_returns_as_leaf():
    """name 자체가 섹션에 없으면(호출측이 사전확인 없이 부른 경우) leaf로 반환."""
    table = ObjectTable(address={})
    assert resolve_name(table, "address", "NOT_IN_TABLE") == ["NOT_IN_TABLE"]

import openpyxl

from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import CLOUD


def _write_noncanonical_criteria(path):
    """비정규형 item_id(예 'pism_001')가 든 합성 평가기준 xlsx 생성.

    로더가 profile.normalize_id 로 정규화해 'PISM-001' 키로 join 가능하게
    저장하는지 검증하기 위함.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    aws = CLOUD.variants["AWS"]
    r = CLOUD.data_start_row
    ws.cell(r, CLOUD.id_col, "pism_001")        # 비정규형
    ws.cell(r, CLOUD.name_col, "통신구간 암호화")
    ws.cell(r, CLOUD.risk_col, 5)
    ws.cell(r, aws.eval_type_col, "스크립트")
    ws.cell(r, aws.method_col, "방법1")
    ws.cell(r, aws.standard_col, "양호 기준 텍스트")
    wb.save(path)


def test_noncanonical_item_id_is_normalized(tmp_path):
    path = str(tmp_path / "noncanon.xlsx")
    _write_noncanonical_criteria(path)
    crit = load_criteria(path, CLOUD)
    # 비정규형 'pism_001' 이 정규형 'PISM-001' 키로 join 가능해야 함
    assert ("PISM-001", "AWS") in crit
    assert ("pism_001", "AWS") not in crit
    c = crit[("PISM-001", "AWS")]
    # Criterion.item_id 도 정규형으로 저장(reconcile/coverage 일관성)
    assert c.item_id == "PISM-001"


def _write_full_mapping_criteria(path):
    """CLOUD 포맷의 모든 컬럼 인덱스를 변별 가능한 값으로 채운 합성 xlsx.

    AWS/Azure 의 eval_type/standard/method 컬럼을 서로 다른 텍스트로 두어
    load_criteria 의 컬럼 인덱스 매핑이 정확한지 결정적으로 검증한다.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    aws = CLOUD.variants["AWS"]
    az = CLOUD.variants["Azure"]
    r = CLOUD.data_start_row
    ws.cell(r, CLOUD.id_col, "pism_042")        # 비정규형 → 정규화 검증
    ws.cell(r, CLOUD.name_col, "  접근통제  ")  # 공백 trim 검증
    ws.cell(r, CLOUD.risk_col, 3)
    # AWS 컬럼
    ws.cell(r, aws.eval_type_col, "스크립트")
    ws.cell(r, aws.standard_col, "AWS 판단기준")
    ws.cell(r, aws.method_col, "AWS 판단방법")
    # Azure 컬럼(AWS 와 구분되는 값)
    ws.cell(r, az.eval_type_col, "관리체계, 스크립트")
    ws.cell(r, az.standard_col, "Azure 판단기준")
    ws.cell(r, az.method_col, "Azure 판단방법")
    wb.save(path)


def test_full_column_mapping_is_exact(tmp_path):
    """각 variant 의 eval_type/standard/method 가 올바른 컬럼에서 읽혀야 한다."""
    path = str(tmp_path / "fullmap.xlsx")
    _write_full_mapping_criteria(path)
    crit = load_criteria(path, CLOUD)

    aws = crit[("PISM-042", "AWS")]
    assert aws.item_id == "PISM-042"          # 정규화
    assert aws.item_name == "접근통제"        # trim
    assert aws.risk == 3.0
    assert aws.variant == "AWS"
    assert aws.eval_type == "스크립트"
    assert aws.standard == "AWS 판단기준"
    assert aws.method == "AWS 판단방법"

    az = crit[("PISM-042", "Azure")]
    assert az.variant == "Azure"
    assert az.eval_type == "관리체계, 스크립트"
    assert az.standard == "Azure 판단기준"
    assert az.method == "Azure 판단방법"
    # 컬럼이 섞이지 않았는지(교차 오염 방지)
    assert az.standard != aws.standard
    assert az.method != aws.method
    assert az.is_mixed is True and aws.is_mixed is False


def test_blank_id_rows_are_skipped(tmp_path):
    """item_id 가 빈 행은 건너뛴다(data_start_row 이후 빈 행 안전)."""
    path = str(tmp_path / "blank.xlsx")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = CLOUD.sheet_name
    aws = CLOUD.variants["AWS"]
    # data_start_row 는 비워 두고 그 다음 행에 데이터
    r = CLOUD.data_start_row + 1
    ws.cell(r, CLOUD.id_col, "pism_005")
    ws.cell(r, CLOUD.name_col, "로그관리")
    ws.cell(r, CLOUD.risk_col, 2)
    ws.cell(r, aws.eval_type_col, "스크립트")
    ws.cell(r, aws.standard_col, "기준")
    ws.cell(r, aws.method_col, "방법")
    wb.save(path)

    crit = load_criteria(path, CLOUD)
    assert ("PISM-005", "AWS") in crit
    # 빈 첫 데이터행으로 생긴 가짜 키가 없어야 함
    assert all(k[0] for k in crit)


def test_loads_known_item(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    c = crit[("PISM-001", "AWS")]
    assert c.item_name.strip().startswith("통신구간")
    assert c.risk == 5.0
    assert "스크립트" in c.eval_type
    assert "양호" in c.standard          # 판단기준 텍스트 존재
    assert c.variant == "AWS"


def test_mixed_item_flagged(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert crit[("PISM-045", "AWS")].is_mixed is True


def test_both_variants_present(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert ("PISM-001", "AWS") in crit
    assert ("PISM-001", "Azure") in crit
    # 73개 항목 × 2 variant
    item_ids = {k[0] for k in crit}
    assert len(item_ids) == 73

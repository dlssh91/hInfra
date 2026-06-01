from typing import Dict, Tuple

import openpyxl

from judge_tool.models import Criterion
from judge_tool.profile import Profile


def _cell(ws, row, col) -> str:
    v = ws.cell(row=row, column=col).value
    return "" if v is None else str(v).strip()


def load_criteria(xlsx_path: str,
                  profile: Profile) -> Dict[Tuple[str, str], Criterion]:
    """xlsx → {(item_id, variant): Criterion}. 모든 변형을 로드한다."""
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    try:
        ws = wb[profile.sheet_name]
        out: Dict[Tuple[str, str], Criterion] = {}

        for row in range(profile.data_start_row, ws.max_row + 1):
            item_id = _cell(ws, row, profile.id_col)
            if not item_id:
                continue
            name = _cell(ws, row, profile.name_col)
            # risk는 숫자 원본이 필요하므로 _cell(str 변환) 대신 .value를 직접 사용
            risk_raw = ws.cell(row=row, column=profile.risk_col).value
            try:
                risk = float(risk_raw)
            except (TypeError, ValueError):
                risk = None

            for vname, vspec in profile.variants.items():
                out[(item_id, vname)] = Criterion(
                    item_id=item_id,
                    item_name=name,
                    risk=risk,
                    variant=vname,
                    eval_type=_cell(ws, row, vspec.eval_type_col),
                    standard=_cell(ws, row, vspec.standard_col),
                    method=_cell(ws, row, vspec.method_col),
                )
        return out
    finally:
        wb.close()

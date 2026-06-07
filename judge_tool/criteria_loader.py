import os
from typing import Dict, Tuple

import openpyxl
import yaml

from judge_tool.models import Criterion
from judge_tool.profile import Profile

_ITEM_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "item_configs")


def _load_item_configs(profile_key: str) -> Dict:
    """item_configs/{profile_key}.yaml 로딩. 파일 없으면 빈 dict 반환."""
    path = os.path.join(_ITEM_CONFIG_DIR, f"{profile_key}.yaml")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def _cell(ws, row, col) -> str:
    v = ws.cell(row=row, column=col).value
    return "" if v is None else str(v).strip()


def load_criteria(xlsx_path: str,
                  profile: Profile,
                  profile_key: str = "") -> Dict[Tuple[str, str], Criterion]:
    """xlsx → {(item_id, variant): Criterion}. 모든 변형을 로드한다."""
    item_configs = _load_item_configs(profile_key) if profile_key else {}
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    try:
        ws = wb[profile.sheet_name]
        out: Dict[Tuple[str, str], Criterion] = {}

        for row in range(profile.data_start_row, ws.max_row + 1):
            item_id = _cell(ws, row, profile.id_col)
            if not item_id:
                continue
            # mapper.aggregate 가 증거 측 CheckID 를 normalize_id 로 정규화하므로
            # 기준 키도 동일 정규형으로 맞춰 join 비대칭을 제거한다.
            item_id = profile.normalize_id(item_id)
            name = _cell(ws, row, profile.name_col)
            # risk는 숫자 원본이 필요하므로 _cell(str 변환) 대신 .value를 직접 사용
            risk_raw = ws.cell(row=row, column=profile.risk_col).value
            try:
                risk = float(risk_raw)
            except (TypeError, ValueError):
                risk = None

            for vname, vspec in profile.variants.items():
                eval_type = (_cell(ws, row, vspec.eval_type_col)
                             if vspec.eval_type_col is not None else "")
                standard = _cell(ws, row, vspec.standard_col)
                method = _cell(ws, row, vspec.method_col)
                if vspec.applicability_col is not None:
                    # DB: 평가대상 컬럼 'o'
                    marker = _cell(ws, row, vspec.applicability_col).strip().lower()
                    applicable = (marker == "o")
                else:
                    # cloud: 기존 is_judgeable 동치(스크립트 기반 & N/A 아님)
                    applicable = ("스크립트" in eval_type) and eval_type != "N/A"
                cfg = item_configs.get(item_id, {})
                # variant별 오버라이드: cfg["variants"][vname]이 있으면 해당 값 우선
                vcfg = cfg.get("variants", {}).get(vname, {})
                out[(item_id, vname)] = Criterion(
                    item_id=item_id,
                    item_name=name,
                    risk=risk,
                    variant=vname,
                    eval_type=eval_type,
                    standard=standard,
                    method=method,
                    applicable=applicable,
                    label=vcfg.get("label", cfg.get("label", "A")),
                    canned_message=vcfg.get("canned_message",
                                            cfg.get("canned_message")),
                    summary_instruction=vcfg.get("summary_instruction",
                                                 cfg.get("summary_instruction")),
                )
        return out
    finally:
        wb.close()

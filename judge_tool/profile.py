import os
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class VariantSpec:
    name: str
    eval_type_col: int
    standard_col: int
    method_col: int
    filename_markers: Tuple[str, ...]


@dataclass(frozen=True)
class Profile:
    key: str
    sheet_name: str
    header_row: int
    data_start_row: int
    id_col: int
    name_col: int
    risk_col: int
    variants: Dict[str, VariantSpec]
    parser: str

    def normalize_id(self, raw: str) -> str:
        """'pism_037_1' -> 'PISM-037'. 접두어+첫 숫자만 사용, 하위 인덱스 제거."""
        m = re.match(r"\s*([A-Za-z]+)[_-](\d+)", raw)
        if not m:
            return raw.strip().upper()
        return f"{m.group(1).upper()}-{int(m.group(2)):03d}"

    def variant_from_filename(self, filename: str) -> Optional[str]:
        low = os.path.basename(filename).lower()
        for vspec in self.variants.values():
            if any(marker in low for marker in vspec.filename_markers):
                return vspec.name
        return None


CLOUD = Profile(
    key="cloud",
    sheet_name="클라우드 관리체계",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=6,
    risk_col=7,
    parser="cloud_xml",
    variants={
        "AWS": VariantSpec("AWS", eval_type_col=11, standard_col=17,
                           method_col=13, filename_markers=("aws_report",)),
        "Azure": VariantSpec("Azure", eval_type_col=12, standard_col=18,
                             method_col=14, filename_markers=("azure_report",)),
    },
)

_PROFILES = {CLOUD.key: CLOUD}


def get_profile(key: str) -> Profile:
    if key not in _PROFILES:
        raise KeyError(f"알 수 없는 프로파일: {key} (사용 가능: {list(_PROFILES)})")
    return _PROFILES[key]

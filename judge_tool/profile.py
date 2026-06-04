import os
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple


@dataclass(frozen=True)
class VariantSpec:
    name: str
    standard_col: int
    method_col: int
    filename_markers: Tuple[str, ...]
    eval_type_col: Optional[int] = None      # cloud: 적용여부 판정용. DB: 없음.
    applicability_col: Optional[int] = None  # DB: 평가대상 'o' 컬럼. cloud: 없음.


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
    evidence_mode: str = "preclassified"           # "preclassified"|"raw"
    status_available: bool = True                  # False면 LLM 단독(교차비교 없음)
    flag_vulnerable_for_review: bool = False        # True면 verdict=취약도 needs_review
    empty_means_good: FrozenSet[str] = frozenset()  # 빈 RESULT=양호신호인 base id

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

# DB(MySQL) — 원시증거. 평가대상 'o' 컬럼으로 적용여부 판정(eval_type 컬럼 없음).
# 컬럼(열 인덱스): 적용 rds=17/aurora=18/azure=19, 판단기준 37/39/41, 판단방법 38/40/42.
DB_MYSQL = Profile(
    key="db_mysql",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    # 위반필터형 쿼리(빈 결과=위반 0건=양호 신호). 스크립트 분석 기준.
    # DBM-024는 모든 하위쿼리가 WHERE IS_GRANTABLE='YES' 필터라 빈 결과=GRANT
    # OPTION 없음=양호 (스모크에서 확인, 초기 분류가 IS_GRANTABLE 패턴 누락).
    empty_means_good=frozenset(
        {"DBM-005", "DBM-017", "DBM-019", "DBM-024", "DBM-028"}),
    variants={
        "mysql_rds": VariantSpec(
            "mysql_rds", standard_col=37, method_col=38,
            applicability_col=17, filename_markers=("mysql_result_rds",)),
        "mysql_aurora": VariantSpec(
            "mysql_aurora", standard_col=39, method_col=40,
            applicability_col=18, filename_markers=("mysql_result_aurora",)),
        "mysql_azure": VariantSpec(
            "mysql_azure", standard_col=41, method_col=42,
            applicability_col=19, filename_markers=("mysql_result_azure",)),
    },
)

# DB(Oracle RDS) — 원시증거. 스크립트 분석 기준 empty_means_good:
# DBM-005(평문컬럼), DBM-015(PUBLIC 권한), DBM-017(SYS/DBA_ 비인가 접근), DBM-024(ADMIN_OPTION/grantable).
DB_ORACLE = Profile(
    key="db_oracle",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset({"DBM-005", "DBM-015", "DBM-017", "DBM-024"}),
    variants={
        "oracle_rds": VariantSpec(
            "oracle_rds", standard_col=29, method_col=30,
            applicability_col=13, filename_markers=("oracle_result_rds",)),
    },
)

# DB(MS-SQL RDS) — 원시증거. 스크립트 분석 기준 empty_means_good:
# DBM-005(평문컬럼), DBM-015(public 권한), DBM-024(GRANT_WITH_GRANT_OPTION).
DB_MSSQL = Profile(
    key="db_mssql",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset({"DBM-005", "DBM-015", "DBM-024"}),
    variants={
        "mssql_rds": VariantSpec(
            "mssql_rds", standard_col=33, method_col=34,
            applicability_col=15, filename_markers=("mssql_result_rds",)),
    },
)

# DB(MariaDB RDS) — 원시증거. 스크립트 분석 기준 empty_means_good:
# DBM-005(평문컬럼), DBM-024(IS_GRANTABLE=YES 전 레벨).
# DBM-017/DBM-028은 MariaDB에서 권한 목록 조회(정보성)로 위반필터형이 아님.
DB_MARIADB = Profile(
    key="db_mariadb",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset({"DBM-005", "DBM-024"}),
    variants={
        "mariadb_rds": VariantSpec(
            "mariadb_rds", standard_col=45, method_col=46,
            applicability_col=21, filename_markers=("mariadb_result_rds",)),
    },
)

# DB(PostgreSQL) — 원시증거. 스크립트 분석 기준 empty_means_good:
# DBM-005(평문컬럼), DBM-015(PUBLIC 권한), DBM-017(pg_catalog 비인가 접근),
# DBM-024(is_grantable=YES 전 레벨).
DB_POSTGRESQL = Profile(
    key="db_postgresql",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset({"DBM-005", "DBM-015", "DBM-017", "DBM-024"}),
    variants={
        "pg_rds": VariantSpec(
            "pg_rds", standard_col=49, method_col=50,
            applicability_col=23, filename_markers=("postgresql_result_rds",)),
        "pg_aurora": VariantSpec(
            "pg_aurora", standard_col=51, method_col=52,
            applicability_col=24, filename_markers=("postgresql_result_aurora",)),
        "pg_azure": VariantSpec(
            "pg_azure", standard_col=53, method_col=54,
            applicability_col=25, filename_markers=("postgresql_result_azure",)),
    },
)

_PROFILES = {
    CLOUD.key: CLOUD,
    DB_MYSQL.key: DB_MYSQL,
    DB_ORACLE.key: DB_ORACLE,
    DB_MSSQL.key: DB_MSSQL,
    DB_MARIADB.key: DB_MARIADB,
    DB_POSTGRESQL.key: DB_POSTGRESQL,
}


def get_profile(key: str) -> Profile:
    if key not in _PROFILES:
        raise KeyError(f"알 수 없는 프로파일: {key} (사용 가능: {list(_PROFILES)})")
    return _PROFILES[key]

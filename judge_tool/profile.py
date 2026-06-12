import os
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple

# 네이티브 제네릭 마커 모호성 가드용 클라우드 토큰. 알파벳 경계로 검사해
# 'passwords'·'standards'의 'rds'처럼 단어 내부 우연 매치를 배제한다.
_CLOUD_TOKEN_RE = re.compile(r"(?<![a-z])(rds|aurora|azure)(?![a-z])")


@dataclass(frozen=True)
class VariantSpec:
    name: str
    standard_col: int
    method_col: int
    filename_markers: Tuple[str, ...]
    eval_type_col: Optional[int] = None      # cloud: 적용여부 판정용. DB: 없음.
    applicability_col: Optional[int] = None  # DB: 평가대상 'o' 컬럼. cloud: 없음.
    applies_when_standard: bool = False      # network generic: 판단기준(C18) 비공백=적용


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
    excluded: bool = False                          # True면 구조만 정의·판정 배제(Tibero)

    def normalize_id(self, raw: str) -> str:
        """'pism_037_1' -> 'PISM-037'. 접두어+첫 숫자만 사용, 하위 인덱스 제거."""
        m = re.match(r"\s*([A-Za-z]+)[_-](\d+)", raw)
        if not m:
            return raw.strip().upper()
        return f"{m.group(1).upper()}-{int(m.group(2)):03d}"

    def variant_from_filename(self, filename: str) -> Optional[str]:
        """파일명에서 변형을 식별한다. 여러 변형의 마커가 동시에 매칭되면
        **가장 긴(=가장 구체적인) 마커**를 가진 변형을 선택한다.

        예: 'oracle_result.txt'는 'oracle_result'(oracle_native)만,
        'oracle_result_rds.txt'는 'oracle_result'와 'oracle_result_rds' 둘 다
        매칭하지만 더 긴 'oracle_result_rds'(oracle_rds)가 이긴다. 이로써
        네이티브('{engine}_result')와 클라우드('..._rds/_aurora/_azure')가
        substring 포함관계여도 정확히 갈린다. 동률(같은 길이) 마커는 변형
        삽입순으로 먼저 선언된 쪽이 우선한다.

        모호성 가드: 최장 매치 변형이 네이티브 제네릭(_native로 끝남)인데
        파일명에 클라우드 토큰(rds/aurora/azure)이 독립 단어로 포함돼 있으면
        None을 반환한다. 호출부에서 --variant 유도 오류로 처리된다. 토큰은
        단어경계로 검사하므로 'passwords'·'standards'의 'rds'처럼 다른 단어에
        우연히 묻힌 경우는 오발동하지 않는다."""
        low = os.path.basename(filename).lower()
        best_name: Optional[str] = None
        best_len = -1
        for vspec in self.variants.values():
            for marker in vspec.filename_markers:
                if marker in low and len(marker) > best_len:
                    best_name, best_len = vspec.name, len(marker)
        # 최장 매치가 네이티브 변형인데 클라우드 토큰이 독립 단어로 있으면 모호 → None
        if (best_name is not None and best_name.endswith("_native")
                and _CLOUD_TOKEN_RE.search(low)):
            return None
        return best_name


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
    # 네이티브(mysql_native)는 동일 set 상속: 네이티브/RDS는 같은 스크립트의
    # db_environment_state 분기로, 위반필터 커서가 동일하고 차이는 RDSADMIN 등
    # 계정 제외 한 줄뿐이므로 empty_means_good 의미가 같다(per-variant 불필요).
    empty_means_good=frozenset(
        {"DBM-005", "DBM-017", "DBM-019", "DBM-024", "DBM-028"}),
    variants={
        "mysql_native": VariantSpec(
            "mysql_native", standard_col=35, method_col=36,
            applicability_col=16, filename_markers=("mysql_result",)),
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
        "oracle_native": VariantSpec(
            "oracle_native", standard_col=27, method_col=28,
            applicability_col=12, filename_markers=("oracle_result",)),
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
        "mssql_native": VariantSpec(
            "mssql_native", standard_col=31, method_col=32,
            applicability_col=14, filename_markers=("mssql_result",)),
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
        "mariadb_native": VariantSpec(
            "mariadb_native", standard_col=43, method_col=44,
            applicability_col=20, filename_markers=("mariadb_result",)),
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
        "pg_native": VariantSpec(
            "pg_native", standard_col=47, method_col=48,
            applicability_col=22, filename_markers=("postgresql_result",)),
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

# DB(Tibero) — 구조만 정의하고 판정에서 배제(excluded=True). 기준표에 평가대상
# (col26)·판단기준(col55)·판단방법(col56) 컬럼이 존재하나 점검 스크립트·파서가
# 아직 없어 현재는 판정하지 않는다. 활성화는 후속 과제.
DB_TIBERO = Profile(
    key="db_tibero",
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
    excluded=True,
    empty_means_good=frozenset(),
    variants={
        "tibero": VariantSpec(
            "tibero", standard_col=55, method_col=56,
            applicability_col=26, filename_markers=("tibero_result",)),
    },
)

# 서버(OS) — 원시증거(셸/배치 명령 raw 출력). 수집 스크립트(fsi_unix.sh /
# fsi_win.bat)의 출력 파일명({hostname}-s-{date}.xml)에 OS 변형 마커가 없어
# filename_markers는 빈 튜플이고, server_xml.detect_variant가 <asset><os>
# 텍스트로 변형을 식별한다(main.run의 내용 기반 폴백 seam).
# empty_means_good: 서버용 위반필터형 분석 자료가 아직 없어 빈 집합으로 시작
# (빈 출력은 보수적으로 '증거 없음 → 판단보류'). 실수집 데이터 확보 후 보강.
SERVER = Profile(
    key="server",
    sheet_name="서버",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="server_xml",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "aix": VariantSpec(
            "aix", standard_col=17, method_col=18,
            applicability_col=12, filename_markers=()),
        "hpux": VariantSpec(
            "hpux", standard_col=19, method_col=20,
            applicability_col=13, filename_markers=()),
        "linux": VariantSpec(
            "linux", standard_col=21, method_col=22,
            applicability_col=14, filename_markers=()),
        "solaris": VariantSpec(
            "solaris", standard_col=23, method_col=24,
            applicability_col=15, filename_markers=()),
        "win": VariantSpec(
            "win", standard_col=25, method_col=26,
            applicability_col=16, filename_markers=()),
    },
)

# 네트워크 장비 — 원시증거(config/show raw). 판단기준(col18)·판단방법(col19)을
# 전 벤더가 공유하고 벤더별로는 평가대상 'o' 컬럼만 갈린다(col33~42). 현재
# CISCO 단일 벤더 + generic(미해당) 폴백만 구현. CISCO는 45항목 전부 'o'.
# generic은 벤더 미식별 장비를 벤더중립 판단기준(C18)으로 LLM 판정하는 폴백.
#
# TODO(나머지 9개 벤더 — ④ 활성화 게이트): applicability_col A10=34,BROCADE=35,
#   ALTEON=36,NOTEL=37,BIGIP=38,CITRIX=39,PIOLINK=40,3COM=41,JUNIPER=42
#   (standard/method는 18/19 공유). VariantSpec 등록 + detect_variant 토큰 확장.
# TODO(적용성 보조축 미사용): col12 스위치/col13 라우터/col14~17 A~D그룹.
# 수집 포맷 미확정(셸 없음→on-host 수집 불가). 파서는 서버 동일 XML 엔벨로프를
# PROVISIONAL 가정 — network_xml docstring·④ 게이트 참조. empty_means_good 빈 집합.
NETWORK = Profile(
    key="network", sheet_name="네트워크 장비",
    header_row=4, data_start_row=5,
    id_col=2, name_col=7, risk_col=8,
    parser="network_xml", evidence_mode="raw",
    status_available=False, flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "cisco": VariantSpec(
            "cisco", standard_col=18, method_col=19,
            applicability_col=33, filename_markers=()),
        "generic": VariantSpec(
            "generic", standard_col=18, method_col=19,
            applicability_col=None, applies_when_standard=True,
            filename_markers=()),
    },
)

# 정보보호시스템 장비 (ISS) — FW 변형 1개 + 나머지 5개 TODO.
# 이번 구현 범위: FW 변형 + ISS-030~041 정책-이상 항목.
# 파일명에 변형 마커 없음 → detect_variant 폴백("fw" 고정 반환, fw_policy_xlsx 참조).
# status_available=False → 전 판정 script_status=None → needs_review=True(자동).
ISS = Profile(
    key="iss",
    sheet_name="정보보호시스템 장비",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="fw_policy_xlsx",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "fw": VariantSpec(
            "fw", standard_col=18, method_col=19,
            applicability_col=12, filename_markers=()),
        # VPN/IDS/IPS/DDoS/WAF/generic은 iss_device 프로파일 참조(XML 입력).
    },
)

# 정보보호시스템 장비 — 비-FW 5종(VPN/IDS/IPS/DDoS/WAF) + generic 폴백.
# 같은 시트("정보보호시스템 장비")를 iss(FW 정책 xlsx)와 분할 사용.
# DB 도메인이 한 시트를 엔진별 프로파일로 나누는 선례와 동일.
# 판단기준(col18)·판단방법(col19)은 전 장비 공유, 장비별로는 applicability_col만 갈린다.
# generic: 장비 미식별 시 폴백 — network generic 패턴(applies_when_standard=True).
# 파일명 마커 없음 → iss_xml.detect_variant(<asset><device_type>)로 식별.
# ISS-030~041(FW 정책 항목): vpn~waf는 해당 열이 None → applicable=False 자동 제외.
#   generic은 col18 비공백이면 applicable=True가 되나 iss_device.yaml label C로 자동보류.
ISS_DEVICE = Profile(
    key="iss_device",
    sheet_name="정보보호시스템 장비",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="iss_xml",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "vpn":  VariantSpec("vpn",  standard_col=18, method_col=19,
                            applicability_col=13, filename_markers=()),
        "ids":  VariantSpec("ids",  standard_col=18, method_col=19,
                            applicability_col=14, filename_markers=()),
        "ips":  VariantSpec("ips",  standard_col=18, method_col=19,
                            applicability_col=15, filename_markers=()),
        "ddos": VariantSpec("ddos", standard_col=18, method_col=19,
                            applicability_col=16, filename_markers=()),
        "waf":  VariantSpec("waf",  standard_col=18, method_col=19,
                            applicability_col=17, filename_markers=()),
        "generic": VariantSpec("generic", standard_col=18, method_col=19,
                               applicability_col=None,
                               applies_when_standard=True,
                               filename_markers=()),
    },
)

# 컨테이너 가상화 시스템 — 9변형(k8s/EKS/AKS/OCP master·worker + Docker-Linux).
# 파일명 마커로 1차 변형 식별(DB와 동일 패턴). 마커 미매칭 시 detect_variant 폴백
# (<asset><variant> 직접 키 또는 <platform>+<role> 조합 — container_xml 참조).
# status_available=False → 전 판정 script_status=None → needs_review=True 자동.
# 판단기준(standard_col)/판단방법(method_col)은 변형별 전용 컬럼(C21~C38).
# 평가대상 'o' 컬럼은 변형별(C12~C20).
CONTAINER = Profile(
    key="container",
    sheet_name="컨테이너 가상화 시스템",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="container_xml",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "k8s_master": VariantSpec(
            "k8s_master", standard_col=22, method_col=21,
            applicability_col=12, filename_markers=("k8s_master",)),
        "k8s_worker": VariantSpec(
            "k8s_worker", standard_col=24, method_col=23,
            applicability_col=13, filename_markers=("k8s_worker",)),
        "eks_master": VariantSpec(
            "eks_master", standard_col=26, method_col=25,
            applicability_col=14, filename_markers=("eks_master",)),
        "eks_worker": VariantSpec(
            "eks_worker", standard_col=28, method_col=27,
            applicability_col=15, filename_markers=("eks_worker",)),
        "aks_master": VariantSpec(
            "aks_master", standard_col=30, method_col=29,
            applicability_col=16, filename_markers=("aks_master",)),
        "aks_worker": VariantSpec(
            "aks_worker", standard_col=32, method_col=31,
            applicability_col=17, filename_markers=("aks_worker",)),
        "ocp_master": VariantSpec(
            "ocp_master", standard_col=34, method_col=33,
            applicability_col=18, filename_markers=("ocp_master",)),
        "ocp_worker": VariantSpec(
            "ocp_worker", standard_col=36, method_col=35,
            applicability_col=19, filename_markers=("ocp_worker",)),
        "docker_linux": VariantSpec(
            "docker_linux", standard_col=38, method_col=37,
            applicability_col=20, filename_markers=("docker_linux",)),
    },
)

_PROFILES = {
    CLOUD.key: CLOUD,
    DB_MYSQL.key: DB_MYSQL,
    DB_ORACLE.key: DB_ORACLE,
    DB_MSSQL.key: DB_MSSQL,
    DB_MARIADB.key: DB_MARIADB,
    DB_POSTGRESQL.key: DB_POSTGRESQL,
    DB_TIBERO.key: DB_TIBERO,
    SERVER.key: SERVER,
    NETWORK.key: NETWORK,
    ISS.key: ISS,
    ISS_DEVICE.key: ISS_DEVICE,
    CONTAINER.key: CONTAINER,
}


def get_profile(key: str) -> Profile:
    if key not in _PROFILES:
        # 배제(excluded) 프로파일은 '(배제)'로 표기해 판정 가능 목록과 구분한다.
        avail = [f"{k}(배제)" if p.excluded else k
                 for k, p in _PROFILES.items()]
        raise KeyError(f"알 수 없는 프로파일: {key} (사용 가능: {avail})")
    return _PROFILES[key]

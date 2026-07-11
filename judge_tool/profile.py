import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Set, Tuple

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
    # 파일명 플랫폼 별칭(§1 _PLATFORM_ALIASES)에서 유추 가능한 변형 폴백.
    # (환경토큰, variant명) 쌍. detect_variant가 없는 파서 프로파일(cloud/db_*)만
    # 부여한다 — 내용식별 도메인(server 등)은 파일명 힌트가 약해 오추정 위험이 큼
    # (SERVER.variant_from_filename("linux.xml") is None 계약 유지).
    alias_variant_tokens: Tuple[Tuple[str, str], ...] = ()

    def normalize_id(self, raw: str) -> str:
        """'pism_037_1' -> 'PISM-037'. 접두어+첫 숫자만 사용, 하위 인덱스 제거.

        접두어가 글자그룹 사이에 구분자를 갖는 형태('PRC-C-001')도 흡수해
        구분자를 제거하고 합친다('PRCC-001'). 실수집 컨테이너 스크립트
        (fsec_container_script.sh) 출력이 'PRC-C-NNN' 표기이기 때문.
        단일 글자그룹(SRV/DBM/PISM/PRCV 등)은 동작 불변.
        """
        m = re.match(r"\s*([A-Za-z]+(?:[_-][A-Za-z]+)*)[_-](\d+)", raw)
        if not m:
            return raw.strip().upper()
        prefix = re.sub(r"[_-]", "", m.group(1)).upper()
        return f"{prefix}-{int(m.group(2)):03d}"

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
        우연히 묻힌 경우는 오발동하지 않는다.

        구체마커가 전혀 매칭되지 않으면 alias_variant_tokens(플랫폼 별칭표에서
        유추 가능한 환경토큰 → variant명)로 폴백한다. 정확히 하나의 variant만
        가리키면 그 variant, 2개 이상이면 모호로 간주해 None(오추정 방지)."""
        # guess_profile과 동일하게 NFC 정규화 — _alias_hit는 NFC 입력을 전제
        # 하므로(한글 토큰 substring), 향후 한글 variant 별칭이 추가돼도
        # macOS NFD 파일명에서 조용히 실패하지 않는다(Fable 리뷰 L-1).
        low = unicodedata.normalize("NFC", os.path.basename(filename)).lower()
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
        if best_name is not None:
            return best_name
        found = {v for tok, v in self.alias_variant_tokens if _alias_hit(tok, low)}
        return next(iter(found)) if len(found) == 1 else None


CLOUD = Profile(
    key="cloud",
    sheet_name="클라우드 관리체계",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=6,
    risk_col=7,
    parser="cloud_xml",
    # detect_variant 없는 파서(cloud_xml) → 플랫폼 별칭 variant 폴백 부여.
    alias_variant_tokens=(("aws", "AWS"), ("azure", "Azure")),
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
    # detect_variant 없는 파서(db_json) → 플랫폼 별칭 variant 폴백 부여.
    alias_variant_tokens=(
        ("rds", "mysql_rds"), ("aurora", "mysql_aurora"), ("azure", "mysql_azure")),
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
    alias_variant_tokens=(("rds", "oracle_rds"),),
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
    alias_variant_tokens=(("rds", "mssql_rds"),),
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
    alias_variant_tokens=(("rds", "mariadb_rds"),),
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
    alias_variant_tokens=(
        ("rds", "pg_rds"), ("aurora", "pg_aurora"), ("azure", "pg_azure")),
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

# 정보보호시스템 장비(FW) — FW 변형 단일, fw_policy_xlsx 파서(정책 xlsx 입력).
# 비-FW 5종(VPN/IDS/IPS/DDoS/WAF/generic)은 iss_device 프로파일 참조(XML 입력).
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

# OS 가상화 시스템 — 하이퍼바이저 3변형(vcenter/esxi/xen).
# 원시증거(esxcli/PowerCLI/xe raw 출력). 파일명 마커 없음 →
# osvirt_xml.detect_variant(<asset><variant> 또는 <product>)로 식별.
# ⚠️ 컬럼 순서 주의: 다른 도메인과 달리 '판단방법'이 '판단기준'보다 앞에 온다
#   (1-indexed, openpyxl ws.cell 기준):
#   col12=평가대상(vCenter) col13=평가대상(ESXi)   col14=평가대상(Xen)
#   col15=판단방법(vCenter) col16=판단기준(vCenter)
#   col17=판단방법(ESXi)    col18=판단기준(ESXi)
#   col19=판단방법(Xen)     col20=판단기준(Xen)
# → standard_col(판단기준)=16/18/20, method_col(판단방법)=15/17/19.
# 변형별 적용 차이 큼: ESXi 35항목 전부 'o'(슈퍼셋), vCenter·Xen은 부분집합
# (PRCV-008 등 21개 항목이 변형마다 다름) → 변형별 applicability_col 분리 필수.
# status_available=False → 전 판정 needs_review=True 자동.
OS_VIRT = Profile(
    key="osvirt",
    sheet_name="OS 가상화 시스템",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="osvirt_xml",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        "vcenter": VariantSpec("vcenter", standard_col=16, method_col=15,
                               applicability_col=12, filename_markers=()),
        "esxi":    VariantSpec("esxi", standard_col=18, method_col=17,
                               applicability_col=13, filename_markers=()),
        "xen":     VariantSpec("xen", standard_col=20, method_col=19,
                               applicability_col=14, filename_markers=()),
    },
)

# 웹서버-WAS — 11변형(OS 5종 + 웹서버 6종). 원시증거(명령/config raw 출력).
# 시트는 서버(SRV) 106항목을 항목명 동일하게 포함(WST-001~120 OS 점검) +
# 웹서버 특화 20항목(WST-031~044 등). 총 126항목(WST-001~126).
# ⚠️ 변형별 판단 컬럼 비대칭(1-indexed, openpyxl ws.cell 기준):
#   적용:   AIX=12 HPUX=13 LINUX=14 SOL=15 WIN=16
#           웹서비스=17 Apache=18 WebtoB=19 IIS=20 Tomcat=21 JEUS=22
#   OS 5종:  판단기준 col23/25/27/29/31, 판단방법 col24/26/28/30/32 (기준 먼저).
#   웹서버 6종: 전용 컬럼 없음 → 공통 판단기준(col37)/판단방법(col38) 공유.
# 웹 특화 항목의 판단기준은 OS 변형 컬럼(col23~32)에도 복제돼 있어 OS 변형 선택
# 시에도 웹 항목이 판정됨. OS/웹 이중성은 활성화 게이트(PROGRESS.md ⑦) 참조.
# status_available=False → 전 판정 needs_review=True 자동.
WEBWAS = Profile(
    key="webwas",
    sheet_name="웹서버-WAS",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="webwas_xml",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    empty_means_good=frozenset(),
    variants={
        # OS 5종 — 전용 판단기준/판단방법 컬럼
        "aix":        VariantSpec("aix", standard_col=23, method_col=24,
                                  applicability_col=12, filename_markers=()),
        "hpux":       VariantSpec("hpux", standard_col=25, method_col=26,
                                  applicability_col=13, filename_markers=()),
        "linux":      VariantSpec("linux", standard_col=27, method_col=28,
                                  applicability_col=14, filename_markers=()),
        "solaris":    VariantSpec("solaris", standard_col=29, method_col=30,
                                  applicability_col=15, filename_markers=()),
        "win":        VariantSpec("win", standard_col=31, method_col=32,
                                  applicability_col=16, filename_markers=()),
        # 웹서버 6종 — 공통 판단기준(37)/판단방법(38) 공유, applicability만 갈림
        "webservice": VariantSpec("webservice", standard_col=37, method_col=38,
                                  applicability_col=17, filename_markers=()),
        "apache":     VariantSpec("apache", standard_col=37, method_col=38,
                                  applicability_col=18, filename_markers=()),
        "webtob":     VariantSpec("webtob", standard_col=37, method_col=38,
                                  applicability_col=19, filename_markers=()),
        "iis":        VariantSpec("iis", standard_col=37, method_col=38,
                                  applicability_col=20, filename_markers=()),
        "tomcat":     VariantSpec("tomcat", standard_col=37, method_col=38,
                                  applicability_col=21, filename_markers=()),
        "jeus":       VariantSpec("jeus", standard_col=37, method_col=38,
                                  applicability_col=22, filename_markers=()),
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
    OS_VIRT.key: OS_VIRT,
    WEBWAS.key: WEBWAS,
}


def get_profile(key: str) -> Profile:
    if key not in _PROFILES:
        # 배제(excluded) 프로파일은 '(배제)'로 표기해 판정 가능 목록과 구분한다.
        avail = [f"{k}(배제)" if p.excluded else k
                 for k, p in _PROFILES.items()]
        raise KeyError(f"알 수 없는 프로파일: {key} (사용 가능: {avail})")
    return _PROFILES[key]


def list_profile_keys() -> Tuple[str, ...]:
    """판정 가능(배제 아님) 프로파일 키 목록. --profile 자동추정 실패 안내용."""
    return tuple(k for k, p in _PROFILES.items() if not p.excluded)


def _marker_profile_index() -> Dict[str, str]:
    """filename_markers(variant 식별용) → profile_key 역인덱스.

    variant 식별에 이미 쓰이는 마커 정보를 재사용해 --profile 자동추정으로
    확장한다(새 마커 목록을 따로 유지하지 않음). 배제(excluded) 프로파일은
    자동추정 후보에서 제외한다.
    """
    index: Dict[str, str] = {}
    for profile in _PROFILES.values():
        if profile.excluded:
            continue
        for vspec in profile.variants.values():
            for marker in vspec.filename_markers:
                index[marker] = profile.key
    return index


# 확장자만으로 유일하게 결정되는 프로파일(마커 매칭 실패 시 폴백).
# iss(방화벽 정책) 프로파일만 xlsx 결과파일을 받는 유일한 프로파일이다.
_EXT_UNIQUE_PROFILE: Dict[str, str] = {".xlsx": "iss"}

# 확장자로 후보군만 좁혀지는(그러나 유일하지 않은) 그룹. 파일명 마커가 없는
# 도메인(server/network/iss_device/osvirt/webwas)은 XML 확장자 하나를 공유해
# 확장자만으로는 유일 식별이 불가하다 — 후보 나열 후 --profile 명시 유도.
_EXT_CANDIDATE_GROUPS: Dict[str, Tuple[str, ...]] = {
    ".json": ("db_mysql", "db_oracle", "db_mssql", "db_mariadb",
             "db_postgresql"),  # db_tibero는 배제(excluded) → 후보 제외
    ".xml": ("cloud", "container", "server", "network", "iss_device",
             "osvirt", "webwas"),
}

# ---------------------------------------------------------------------------
# 플랫폼 별칭 표 (파일명 → 프로파일 인지, Stage B). 설계서
# docs/superpowers/specs/2026-07-03-filename-recognition-design.md §1 계약.
#
# 매칭규약: ASCII 토큰 = 알파벳 경계 정규식 `(?<![a-z])tok(?![a-z])`(숫자 인접은
# 허용 — win2019는 매치, winter/darwin은 경계에서 차단). 한글 토큰(2자 이상) =
# NFC 정규화 후 단순 substring. 전부 소문자로만 등록한다.
#
# 금지 토큰(오탐/충돌 위험으로 등록하지 않음): server/서버, sql, db/dbms/web/net/host,
# pg/my/ora/maria(엔진 접두 단독), ids/ips(user_ids/server_ips 오탐), checkpoint,
# 가상화, hyperv/kvm/tibero(미지원 도메인).
#
# 위험 토큰(등록은 하되 경계검사로 방어): "was"(webwas) — 영어 단어 "was"와
# 겹치는 최고위험 토큰이다. 오탐이 실측된다면 아래 tuple에서 "was" 한 줄만
# 삭제하면 즉시 비활성화된다.
_PLATFORM_ALIASES: Dict[str, Tuple[str, ...]] = {
    "cloud": ("aws", "azure", "cloud", "클라우드"),
    "db_mysql": ("mysql",),
    "db_oracle": ("oracle", "오라클"),
    "db_mssql": ("mssql", "ms-sql", "ms_sql", "sqlserver", "sql-server", "sql_server"),
    "db_mariadb": ("mariadb",),
    "db_postgresql": ("postgresql", "postgres", "pgsql"),
    "server": (
        "linux", "unix", "aix", "hpux", "hp-ux", "hp_ux", "solaris", "sunos",
        "redhat", "rhel", "centos", "rocky", "ubuntu", "debian", "suse",
        "windows", "win", "리눅스", "유닉스", "솔라리스", "윈도우",
    ),
    "webwas": (
        "apache", "nginx", "tomcat", "webtob", "jeus", "iis", "weblogic",
        "was",  # ⚠️ 최고위험 토큰(주석 참조) — 오탐 시 이 줄만 삭제.
        "웹서버", "톰캣", "아파치",
    ),
    "container": (
        "docker", "kubernetes", "k8s", "openshift", "container",
        "eks", "aks", "ocp", "쿠버네티스", "도커", "컨테이너",
    ),
    "network": ("cisco", "juniper", "switch", "router", "네트워크", "스위치", "라우터"),
    "iss": (
        "firewall", "fw", "방화벽", "secui", "paloalto", "palo-alto",
        "palo_alto", "fortigate", "fortinet",
    ),
    "iss_device": ("vpn", "ddos", "waf"),
    "osvirt": ("vmware", "esxi", "vcenter", "xen"),
}

# ASCII 별칭 토큰의 경계 정규식을 모듈 로드 시 1회 프리컴파일해 재사용한다.
# _alias_hit()는 Stage B(_PLATFORM_ALIASES, 프로파일 단위)와
# Profile.variant_from_filename의 alias_variant_tokens 폴백(variant 단위) 양쪽에서
# 재사용되므로, 두 출처의 ASCII 토큰을 모두 모아 캐시를 채운다(KeyError 방지).
_ALIAS_TOKEN_RE: Dict[str, "re.Pattern[str]"] = {
    tok: re.compile(r"(?<![a-z])" + re.escape(tok) + r"(?![a-z])")
    for tok in {
        *(tok for _tokens in _PLATFORM_ALIASES.values() for tok in _tokens),
        *(tok for _profile in _PROFILES.values()
          for tok, _variant in _profile.alias_variant_tokens),
    }
    if tok.isascii()
}


def _alias_hit(token: str, low: str) -> bool:
    """별칭 토큰 하나가 (이미 소문자·NFC 정규화된) 파일명에 매칭되는지 검사.

    ASCII 토큰은 프리컴파일된 알파벳 경계 정규식으로, 한글 토큰(2자 이상)은
    단순 substring으로 검사한다."""
    if token.isascii():
        return _ALIAS_TOKEN_RE[token].search(low) is not None
    return token in low


def _match_platform_aliases(low: str) -> Dict[str, Set[str]]:
    """플랫폼 별칭표 전체를 스캔해 {profile_key: {매칭된 토큰...}}을 반환한다."""
    hits: Dict[str, Set[str]] = {}
    for profile_key, tokens in _PLATFORM_ALIASES.items():
        matched = {tok for tok in tokens if _alias_hit(tok, low)}
        if matched:
            hits[profile_key] = matched
    return hits


def _refine_alias_hits(hits: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """DB-클라우드 정제(설계서 §2/§4): DB 엔진 별칭 1개 + cloud 별칭이 동시에
    매칭되고 cloud쪽 매칭 토큰이 aws/azure(환경 힌트)만으로 구성되면 cloud를
    제거해 DB 프로파일 단일 확정으로 정리한다.

    예: 'mysql_azure점검.txt' → {db_mysql:{mysql}, cloud:{azure}} → cloud 토큰이
    {aws,azure} 부분집합이므로 cloud 제거 → db_mysql 확정(variant는
    Profile.variant_from_filename의 alias_variant_tokens 폴백이 별도 처리).
    진짜 클라우드 보고서(aws_report/azure_report)는 구체마커라 Stage A에서
    이미 확정되므로 이 단계에 도달하지 않는다. cloud 매칭이 aws/azure 외
    토큰(cloud/클라우드 등)을 포함하면 정제하지 않는다(진짜 클라우드 보고서일
    가능성을 보존)."""
    db_keys = [key for key in hits if key.startswith("db_")]
    if len(db_keys) == 1 and set(hits) == {db_keys[0], "cloud"}:
        if hits["cloud"] <= {"aws", "azure"}:
            refined = dict(hits)
            del refined["cloud"]
            return refined
    return hits


def guess_profile(report_path: str) -> Tuple[Optional[str], Tuple[str, ...]]:
    """보고서 파일명에서 --profile 을 추정한다.

    3단계로 추정한다(Stage A → Stage B → Stage C, 앞 단계가 0매칭일 때만 다음
    단계로 넘어간다):
      Stage A: 구체 filename_markers(variant 식별용 마커) 역인덱스 substring.
      Stage B: 플랫폼 별칭표(_PLATFORM_ALIASES) 스캔. Stage A가 0매칭일 때만
        수행한다 — 마커는 수집기가 생성한 정밀한 이름이라 항상 우선한다.
        DB 엔진 별칭 + aws/azure 별칭이 동시 매칭되면 DB-클라우드 정제
        (_refine_alias_hits)로 cloud 쪽을 제거해 단일 확정을 시도한다.
      Stage C: 확장자 폴백(.xlsx→iss 유일, .json/.xml→후보군).

    반환: (guessed_key 또는 None, candidates)
      - 마커/별칭으로 유일 식별                    → (key, (key,))
      - 마커·별칭 모두 미매칭 + 확장자로 유일 식별 → (key, (key,))
      - 마커 여럿·별칭 여럿·확장자 후보군(복수)    → (None, candidates)  # 모호
      - 전혀 추정 불가                              → (None, ())
    호출부(main.py)는 guessed가 None이면 candidates 유무로 "모호" vs
    "추정 불가"를 구분해 안내한다(오판정보다 명시 요구가 안전 — 별칭 2개
    이상이 동시 매칭돼도 거짓 라우팅하지 않고 모호로 fail-safe한다).

    macOS 드래그앤드롭 등으로 들어온 한글 파일명은 NFD(자모 분해형)일 수 있어
    소스 코드의 NFC 한글 별칭 토큰과 substring 매칭이 실패한다 — 반드시
    unicodedata.normalize("NFC", ...)로 정규화한 뒤 비교한다.
    """
    low = unicodedata.normalize("NFC", os.path.basename(report_path)).lower()
    ext = os.path.splitext(low)[1]
    index = _marker_profile_index()
    matched = {key for marker, key in index.items() if marker in low}
    if len(matched) == 1:
        key = next(iter(matched))
        return key, (key,)
    if len(matched) > 1:
        return None, tuple(sorted(matched))
    # Stage B: 구체마커 0매칭일 때만 플랫폼 별칭 스캔(오라클_result.xlsx 같은
    # 자연 파일명 인지 — 확장자 폴백보다 먼저 시도해 별칭이 우선한다).
    alias_hits = _refine_alias_hits(_match_platform_aliases(low))
    if len(alias_hits) == 1:
        key = next(iter(alias_hits))
        return key, (key,)
    if len(alias_hits) > 1:
        return None, tuple(sorted(alias_hits))
    # Stage C: 마커·별칭 모두 미매칭 → 확장자 폴백
    if ext in _EXT_UNIQUE_PROFILE:
        key = _EXT_UNIQUE_PROFILE[ext]
        return key, (key,)
    if ext in _EXT_CANDIDATE_GROUPS:
        return None, _EXT_CANDIDATE_GROUPS[ext]
    return None, ()

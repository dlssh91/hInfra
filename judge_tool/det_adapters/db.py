"""DB(DBM) 결정론 어댑터 — Phase 4 / Phase 4b / Phase 4c / Phase 4d (§3/§18, class-based analysis 브리지).

설계 계약:
  - judge() 시그니처: (item_id, raw_output, variant, thresholds, *, context=None) → ForcedVerdict
  - §18.1 C1: gate() 선확인 — DET가 아니면 handled=False (거짓양호 구조 차단)
  - 결정1(R1 해소): raw_output = 전체 비마스킹 data dict JSON (db_json.parse()가 주입)
  - 결정2: engine Analysis(config, data).run 1회 + 모듈 캐시 (키=engine+is_cloud+data지문)
  - 결정3: _DET_ADAPTERS에 db_mysql/db_oracle/db_mssql/db_mariadb/db_postgresql 5개 동시 등록
  - 결정4(Phase 4b): variant suffix로 클래스 선택 — _native→{Engine}Analysis, _rds/_aurora/_azure→{Engine}CloudAnalysis
  - 결정5(Phase 4c): base=="DBM-001"이면 db_pwcrack.crack_judge로 라우팅 (사전공격 어댑터)
  - 결정6(Phase 4d/4e): _DETECT_VULN_ELSE_HOLD 모드(DBM-011) — 취약 탐지 → 취약 확정,
    위반0(수집됨) → 판단보류 강제(양호 자동판정 절대 금지). 적용: mysql/oracle/mariadb/pg/mssql.
    Phase 4e 추가: pg(pgaudit 신규 포맷 탐지), mssql(활성 감사 탐지). 보류 rationale에 확인내용 명시.
  - 증거존재 가드(D3): base의 data_key 없으면 handled=False (거짓양호 구조 차단)
  - 예외내성(R3): vendor dbm_process_data 예외 삼킴 감지 — stdout "[!] Exception Occurred" 캡처 후
    exc_keys 추출, 빈 위반이면서 exc_keys에 포함된 base → handled=False (거짓양호 방지)
  - §7 누출경계: citation = _mask_row 처리된 위반행만, raw data dict 미포함

레지스트리 등록: 모듈 import 시 db_mysql/db_oracle/db_mssql/db_mariadb/db_postgresql 5개 자동 등록.
main.py에서 `import judge_tool.det_adapters.db` 로 부작용 임포트.
"""
import contextlib
import hashlib
import io
import json
import logging
import os
import re
from typing import Optional

from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate
from judge_tool.det_adapters import db_pwcrack as _db_pwcrack
from judge_tool.parsers.db_json import _mask_row

log = logging.getLogger(__name__)

# ── engine 매핑 (variant.split('_')[0] → 실제 engine 이름) ─────────────────
# 'pg' → 'postgresql' 주의 (§3)
_ENGINE_MAP: dict = {
    "mysql":      "mysql",
    "oracle":     "oracle",
    "mssql":      "mssql",
    "mariadb":    "mariadb",
    "pg":         "postgresql",
    "postgresql": "postgresql",   # full name도 수용
}

# ── 엔진별 Analysis class 이름 (native) ─────────────────────────────────────
_ENGINE_CLASS: dict = {
    "mysql":      "MySQLAnalysis",
    "oracle":     "OracleAnalysis",
    "mssql":      "MssqlAnalysis",
    "mariadb":    "MariaDBAnalysis",
    "postgresql": "PostgreSQLAnalysis",
}

# ── 엔진별 CloudAnalysis class 이름 (Phase 4b — rds/aurora/azure 변형) ──────
# variant suffix가 _rds/_aurora/_azure인 경우 cloud 클래스를 사용.
# config는 native와 공유({engine}-config.json 동일).
_ENGINE_CLOUD_CLASS: dict = {
    "mysql":      "MySQLCloudAnalysis",
    "oracle":     "OracleCloudAnalysis",
    "mssql":      "MSSQLCloudAnalysis",
    "mariadb":    "MariaDBCloudAnalysis",
    "postgresql": "PostgreSQLCloudAnalysis",
}

# cloud variant suffix set
_CLOUD_SUFFIXES = frozenset({"rds", "aurora", "azure"})

# ── vendor db config 위치 ───────────────────────────────────────────────────
_VENDOR_DB_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "common", "db")
)

# ── config 캐시 (engine → {exception, rules}) ───────────────────────────────
_CONFIG_CACHE: dict = {}


def _load_config(engine: str) -> dict:
    """vendor config/{engine}-config.json을 1회 로드. 없으면 빈 dict, 경고(fail-soft)."""
    if engine in _CONFIG_CACHE:
        return _CONFIG_CACHE[engine]
    path = os.path.join(_VENDOR_DB_DIR, "config", f"{engine}-config.json")
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        if not isinstance(cfg, dict):
            raise ValueError(f"config JSON 최상위가 dict가 아님: {path}")
        _CONFIG_CACHE[engine] = cfg
    except Exception as exc:  # noqa: BLE001
        log.warning("DB config 로드 실패 engine=%s path=%s: %s", engine, path, exc)
        _CONFIG_CACHE[engine] = {"exception": {}, "rules": {}}
    return _CONFIG_CACHE[engine]


# ── .run 결과 캐시 (키: (engine, is_cloud, data_fingerprint)) ──────────────
# 같은 변형의 여러 base id item이 호출돼도 .run 1회만 실행.
# 캐시 키에 is_cloud 포함(결정4): 같은 data를 native/cloud로 오판 방지.
# 캐시 값: (dbm_result: dict, exc_keys: frozenset) 튜플 (R3 거짓양호 방지용)
_RUN_CACHE: dict = {}

# ── 예외 print 메시지에서 result_key 추출 정규식 (R3) ──────────────────────
# 벤더 포맷 예:
#   "[!] Exception Occurred MySQL DBM-007: KeyError('VARIABLE_NAME')"
#   "[!] Exception Occurred oracle DBM-001: ..."
#   "[!] Exception Occurred MariaDB DBM-022: ..."
# 공통 패턴: "[!] Exception Occurred" 뒤에 DBM-\d+ 가 항상 존재.
_EXC_KEY_RE = re.compile(r"Exception Occurred[^\n]*(DBM-\d+)", re.IGNORECASE)


def _parse_exc_keys(captured_stdout: str) -> frozenset:
    """캡처된 stdout에서 예외 발생한 result_key 집합을 추출한다 (R3).

    "[!] Exception Occurred" 패턴이 있으면 DBM-NNN 패턴을 추출.
    추출 실패(엔진 포맷이 달라 파싱 불가)해도 Exception Occurred 자체를 탐지하면
    보수적으로 _AMBIGUOUS_EXC sentinel을 포함해 호출자가 확인할 수 있게 한다.
    """
    if "[!] Exception Occurred" not in captured_stdout:
        return frozenset()
    keys = frozenset(m.group(1) for m in _EXC_KEY_RE.finditer(captured_stdout))
    if not keys:
        # 예외는 분명히 발생했으나 result_key를 파싱 못한 경우 → 보수적 sentinel
        keys = frozenset(["__AMBIGUOUS__"])
    return keys


def _fingerprint(data: dict) -> str:
    """data dict의 SHA1 지문(캐시 키용)."""
    try:
        return hashlib.sha1(
            json.dumps(data, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()
    except Exception:  # noqa: BLE001
        return str(id(data))


def _is_cloud_variant(variant: str) -> bool:
    """variant suffix가 _rds/_aurora/_azure이면 True (결정4 Phase 4b).

    'mysql_rds' → suffix='rds' → True
    'mysql_native' → suffix='native' → False
    'pg_aurora' → True
    """
    parts = variant.split("_")
    if len(parts) < 2:
        return False
    return parts[-1] in _CLOUD_SUFFIXES


def _run_analysis(engine: str, data: dict, is_cloud: bool = False) -> tuple:
    """engine Analysis(config, data).run 1회 실행 (모듈 캐시).

    Phase 4b: is_cloud=True → {Engine}CloudAnalysis(cloud_analysis.py) 사용.
    is_cloud=False → {Engine}Analysis(analysis.py) 사용 (기존 native).
    캐시 키에 is_cloud 포함 — 같은 data를 native/cloud로 오판 방지(결정4).

    반환: (dbm_result: dict, exc_keys: frozenset)
      - dbm_result: {result_key: [위반행]} (성공) 또는 {} (치명 예외)
      - exc_keys: 벤더가 stdout에 print한 예외의 result_key 집합 (R3).
        빈 frozenset = 예외 없음.

    R3: vendor dbm_process_data는 메서드별 try/except로 예외를 print만 하고 삼킨다.
    stdout을 redirect_stdout으로 캡처해 exc_keys를 파싱, 어댑터가 거짓양호를 차단한다.
    """
    fp = _fingerprint(data)
    cache_key = (engine, is_cloud, fp)
    if cache_key in _RUN_CACHE:
        return _RUN_CACHE[cache_key]

    config = _load_config(engine)

    if is_cloud:
        class_name = _ENGINE_CLOUD_CLASS.get(engine)
        mod_suffix = "cloud_analysis"
    else:
        class_name = _ENGINE_CLASS.get(engine)
        mod_suffix = "analysis"

    if not class_name:
        log.warning("DB 어댑터: 미지원 engine=%s is_cloud=%s", engine, is_cloud)
        _RUN_CACHE[cache_key] = ({}, frozenset())
        return ({}, frozenset())

    captured = io.StringIO()
    try:
        mod_path = f"judge_tool.vendor.common.db.{engine}.{mod_suffix}"
        import importlib
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, class_name)
        with contextlib.redirect_stdout(captured):
            result = cls(config, data).run
        if not isinstance(result, dict):
            result = {}
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "DB analysis.run 예외 engine=%s is_cloud=%s: %s(%s)",
            engine, is_cloud, type(exc).__name__, exc,
        )
        result = {}

    exc_keys = _parse_exc_keys(captured.getvalue())
    if exc_keys:
        log.warning(
            "DB analysis.run 내부 예외(벤더 삼킴) engine=%s is_cloud=%s exc_keys=%s",
            engine, is_cloud, exc_keys,
        )

    value = (result, exc_keys)
    _RUN_CACHE[cache_key] = value
    return value


def _normalize_base(item_id: str) -> str:
    """'DBM-017_1' → 'DBM-017'. 정규화 실패 시 원본 반환."""
    m = re.match(r"(DBM)-(\d+)", item_id)
    if m:
        return f"DBM-{int(m.group(2)):03d}"
    return item_id


def _engine_of(variant: str) -> Optional[str]:
    """variant 문자열 → engine 이름. 미지원이면 None."""
    token = variant.split("_")[0] if "_" in variant else variant
    return _ENGINE_MAP.get(token)


def _has_data_key_for(base: str, data: dict) -> bool:
    """data 키 중 base 또는 'base_' prefix 항목이 1개 이상 있는지 확인(증거존재 가드).

    DBM-017의 경우 data에 DBM-017_1, DBM-017_2, ... 키가 있어야 True.
    """
    for k in data:
        if k == base or k.startswith(base + "_"):
            return True
    return False


def _filter_noise(rows: list) -> list:
    """noise 행 제거: @@@(NOTE), ***(config Note) 단일키 항목 제거.

    {"*": datum}(문자열 위반행 래핑), alert 항목, 일반 위반행은 유지.

    ⚠️ bare 문자열 행(str)은 드롭하지 말고 {"*": row}로 래핑해 유지한다.
    DBM-022 file_entry, oracle DBM-001 hashcat 결과 등 진짜 위반이 bare str로
    도착하므로 드롭하면 거짓양호가 발생한다 (CRITICAL, 2026-06-18 수정).
    Note/alert/notice는 모두 dict({@@@}/{***}/{DBM-xxx})로 도착하므로
    래핑 유지가 거짓취약을 일으키지 않는다.
    """
    filtered = []
    for row in rows:
        if not isinstance(row, dict):
            # bare 문자열(또는 기타 non-dict) → {"*": row}로 래핑해 위반행 보존
            filtered.append({"*": row})
            continue
        keys = set(row.keys())
        # 단일 "@@@" 키 = NOTE 행 → 제거
        if keys == {"@@@"}:
            continue
        # 단일 "***" 키 = config Note 행 → 제거
        if keys == {"***"}:
            continue
        filtered.append(row)
    return filtered


def _mask_violations(rows: list) -> list:
    """위반행을 마스킹해 citations에 사용 (§7 비마스킹 raw 미노출).

    최대 20행. 각 행은 _mask_row 처리.
    문자열 위반행 {"*": datum}은 값이 해시/민감 패턴이면 마스킹.
    """
    result = []
    for row in rows[:20]:
        if not isinstance(row, dict):
            continue
        try:
            masked = _mask_row(row)
            result.append(json.dumps(masked, ensure_ascii=False))
        except Exception:  # noqa: BLE001
            result.append(str(row)[:200])
    return result


# ── 모드 A: detect-then-hold (DBM 분류 검토 Batch1) ────────────────────────
# 결정론이 "후보"를 탐지하되 업무 필요성은 사람이 판단하는 항목(label B 의도).
# 위반(후보) ≥1 → 판단보류 + 후보목록 citations, 위반0 → 양호.
_DETECT_THEN_HOLD: frozenset = frozenset({"DBM-004"})

# ── 모드 D: empty-RESULT / 기대변수-부재 거짓양호 가드 (DBM-019 — 비밀번호 재사용 방지)
# 재사용 방지 설정값이 '없음/비활성(UNLIMITED·0·미로드)'이면 위반 탐지 → 취약.
# RESULT가 완전히 빈 경우(설정 미수집): 위반0이지만 설정이 적절한 건지 알 수 없음
# → 양호 자동판정 금지, 판단보류(증거미수집).
# 대상: mysql(password_history/reuse_interval), oracle(PASSWORD_REUSE_TIME/MAX),
#       mssql(is_policy_checked), mariadb(PASSWORD_REUSE_CHECK_INTERVAL).
# 판단: RESULT가 완전 비어있음(0행) → 판단보류(증거 미수집).
#       RESULT에 행은 있지만 기대 변수가 하나도 없음 → 판단보류(변수 미수집).
#       기대 변수가 존재하고 위반 없음 → 양호(현행 유지).
_EMPTY_RESULT_HOLD: frozenset = frozenset({"DBM-019"})

# 엔진별 "기대 변수 존재 여부" 검사 함수.
# 각 함수는 RESULT 행(list) 전체를 받아, 기대 변수가 **하나라도** 존재하면 True 반환.
# 매핑 없는 엔진은 기존 0행-only 가드만 동작(None 처리).
def _dbm019_mysql_has_expected(rows: list) -> bool:
    """mysql: password_history 또는 password_reuse_interval 행이 1개 이상 있어야 양호 가능."""
    expected_names = {"password_history", "password_reuse_interval"}
    return any(
        isinstance(row, dict) and row.get("VARIABLE_NAME") in expected_names
        for row in rows
    )

def _dbm019_mariadb_has_expected(rows: list) -> bool:
    """mariadb: PASSWORD_REUSE_CHECK_INTERVAL dict행 또는 'not loaded' 문자열 신호가 있어야 함.

    'not loaded' 문자열은 플러그인 미로드 → 취약 신호이지만, 최소한 수집은 된 것이므로
    기대변수 '존재' 확인에 포함한다(이 경우 위반 탐지 → 취약으로 이미 처리됨).
    """
    for row in rows:
        if isinstance(row, str) and "not loaded" in row:
            return True
        if isinstance(row, dict) and row.get("VARIABLE_NAME") == "PASSWORD_REUSE_CHECK_INTERVAL":
            return True
    return False

# engine → 기대변수 존재 검사 함수 매핑 (없으면 None — 0행-only 가드)
_DBM019_EXPECTED_CHECKER: dict = {
    "mysql":   _dbm019_mysql_has_expected,
    "mariadb": _dbm019_mariadb_has_expected,
}

# ── 모드 E: 파일권한 미수집 거짓양호 가드 (DBM-022 — 파일 접근권한) ──────────
# DBM-022 위반행은 벤더 analysis.py가 bare 문자열(file_entry)로 생성한다.
# _filter_noise 수정(2026-06-18)으로 bare str → {"*": row} 래핑 유지 → 위반 탐지 복원.
# 추가 가드: RESULT에 행은 있지만 권한패턴(`^[drwxstl-]{10}`) 매칭이 0건인 경우
# (예: "No such file or directory", 빈 출력) → 파일 미수집/접근실패 → 거짓양호 방지.
# 보수 원칙: 파일 부존재를 "정상 양호"로 볼 수도 있지만, 불확실성 > 거짓양호 위험
# → 판단보류 채택. 적용: mysql/oracle/mariadb/pg/tibero 전 엔진.
_PERM_GUARD: frozenset = frozenset({"DBM-022"})

# 권한 패턴: 유닉스 10자리 권한 문자열 시작. 벤더 analysis.py와 동일한 패턴 기준.
# re.MULTILINE 필수: `ls -al` 출력이 "total N\n-rw-------..." 처럼 헤더로 시작하면
# MULTILINE 없이는 ^ 가 첫 줄(헤더)만 매칭 → 권한라인 미탐 → 거짓보류 발생.
_PERM_LINE_RE = re.compile(r"^[drwxstDRWXSTlL\-]{10}", re.IGNORECASE | re.MULTILINE)


def _dbm022_has_perm_line(result_rows: list) -> bool:
    """DBM-022 RESULT에서 유닉스 권한 패턴이 매칭되는 행이 1개 이상 있는지 확인.

    result_rows는 data['DBM-022']['RESULT'] — 원본 수집 행들(dict, output 키 포함).
    각 행의 'output' 값에서 권한 패턴을 탐색한다.
    """
    for row in result_rows:
        if not isinstance(row, dict):
            continue
        output = row.get("output", "")
        if not isinstance(output, str):
            continue
        if _PERM_LINE_RE.search(output):
            return True
    return False


# ── 모드 B: 구조적 취약 (DBM 분류 검토 Batch1) ─────────────────────────────
# PostgreSQL 코어에 네이티브 기능(실패잠금/복잡도강제)이 없어 데이터 없이도 구조적 취약.
# (base, variant) 키. pg_native만 — 클라우드(rds/aurora/azure)는 관리형 별도 처리(제외).
_STRUCTURAL_VULN: dict = {
    ("DBM-006", "pg_native"): "네이티브 로그인 실패잠금",
    ("DBM-007", "pg_native"): "네이티브 비밀번호 복잡도 강제",
}

# ── 모드 C: detect-vuln-else-hold (DBM-011 — 감사로그 수집 및 백업 여부) ───
# 판단기준 양호 = "감사로그 수집 중 AND 주기적 백업". 벤더 로직은 수집(플러그인 로드) 여부만
# 판정하고 백업 주기는 점검 안 함(인터뷰 영역).
# 동작: 벤더 결정론 취약 탐지(violations 비어있지 않음) → 취약 확정.
#       위반0(수집됨)이면 양호 주지 말고 판단보류.
#       사유: "감사로그 수집 확인됨 [확인내용], 주기적 백업 여부는 인터뷰/증적 확인 필요"
# Phase 4d: mysql/oracle/mariadb 적용.
# Phase 4e: pg(pgaudit 신규 포맷)/mssql(활성 감사 탐지) 추가.
#            보류 rationale에 엔진별 확인내용 명시 (_extract_audit_detail).
# 적용 엔진: mysql/oracle/mariadb/pg/mssql.
_DETECT_VULN_ELSE_HOLD: frozenset = frozenset({"DBM-011"})


def _extract_audit_detail(engine: str, data: dict) -> str:
    """모드C 판단보류 rationale용 — 수집된 감사/플러그인 내용 요약 문자열 반환.

    검토자가 "무엇이 수집 확인됐는지" 보고 백업만 인터뷰하면 되도록.
    §7 마스킹 경계: 경로/플러그인명/감사명 등 식별자는 노출 OK, 민감 자격증명은 미포함.
    data dict에서 해당 DBM-011 RESULT를 직접 읽어 엔진별 키를 추출한다.
    M1: 각 행은 _mask_row 처리 후 값을 읽어 citation 마스킹 규율을 준수한다.
    """
    try:
        result_rows = data.get("DBM-011", {}).get("RESULT", [])
        if not result_rows:
            return ""
        if engine == "mysql":
            # RESULT에 {"VARIABLE_NAME":"audit_log_file","VARIABLE_VALUE":"..."} 등
            for row in result_rows:
                if isinstance(row, dict):
                    masked = _mask_row(row)  # M1: citation 마스킹 경유
                    if masked.get("VARIABLE_NAME") == "audit_log_file":
                        val = masked.get("VARIABLE_VALUE", "")
                        return f"audit_log 플러그인 로드됨 (audit_log_file={val})"
            # not loaded 문자열이 없으면 수집됨(file 경로 정보 없어도 로드 상태)
            return "audit_log 플러그인 로드됨"
        if engine == "mariadb":
            for row in result_rows:
                if isinstance(row, dict):
                    masked = _mask_row(row)  # M1: citation 마스킹 경유
                    if masked.get("VARIABLE_NAME", "").upper() == "SERVER_AUDIT_FILE_PATH":
                        path = masked.get("VARIABLE_VALUE", "")
                        return f"server_audit 플러그인 로드됨 (SERVER_AUDIT_FILE_PATH={path})"
            return "server_audit 플러그인 로드됨"
        if engine == "oracle":
            for row in result_rows:
                if isinstance(row, dict):
                    masked = _mask_row(row)  # M1: citation 마스킹 경유
                    if masked.get("name") == "audit_trail":
                        val = masked.get("value", "")
                        return f"audit_trail={val} (감사 활성)"
            return "audit_trail 감사 활성"
        if engine == "postgresql":
            for row in result_rows:
                if isinstance(row, dict):
                    masked = _mask_row(row)  # M1: citation 마스킹 경유
                    if masked.get("pgaudit_status") == "Loaded":
                        settings = masked.get("pgaudit_settings", [])
                        return f"pgaudit 로드됨 (pgaudit_settings={settings!r})"
                    if masked.get("setting_name") == "shared_preload_libraries":
                        value = masked.get("value", "")
                        settings = masked.get("pgaudit_settings", [])
                        if "pgaudit" in str(value).lower() or settings:
                            return f"pgaudit 로드됨 (shared_preload_libraries={value!r}, pgaudit_settings={settings!r})"
            return "pgaudit 로드됨"
        if engine == "mssql":
            audits = [
                r for r in result_rows
                if isinstance(r, dict) and r.get("audit_name")
            ]
            if audits:
                first = _mask_row(audits[0])  # M1: citation 마스킹 경유
                name = first.get("audit_name", "")
                action = first.get("audit_action", "")
                extra = f" (+{len(audits)-1}건)" if len(audits) > 1 else ""
                note = data.get("DBM-011", {}).get("NOTE", "")
                pism_hint = " — 업로드 설정은 PISM-011 결과 참조" if "PISM-011" in note else ""
                return f"활성 서버감사: {name} (action={action}){extra}{pism_hint}"
            return "활성 서버감사 확인됨"
    except Exception:  # noqa: BLE001
        pass
    return ""


def judge(
    item_id: str,
    raw_output: str,
    variant: str,
    thresholds: dict,
    *,
    context: Optional[str] = None,
) -> ForcedVerdict:
    """DB(DBM) 결정론 어댑터 진입점.

    §18.1 C1: gate() 선확인 — DET가 아니면 즉시 handled=False.
    결정1: raw_output = db_json.parse()가 주입한 전체 비마스킹 data dict JSON.
    결정2: engine Analysis(config, data).run 1회 + 모듈 캐시.
    결정3: 5개 profile_key 공유 (engine_of로 분기).
    D3: 증거존재 가드 — base의 data_key 없으면 handled=False.
    §7: raw data dict를 citation/LLM에 노출하지 않는다.
    """
    # ── §18.1 C1: 거짓 양호 게이트 ─────────────────────────────────────────
    gate_result = gate(item_id, variant)
    if gate_result is not None:
        return gate_result

    # ── base 정규화, engine 추출, cloud 여부 판별 ────────────────────────────
    base = _normalize_base(item_id)
    engine = _engine_of(variant)
    is_cloud = _is_cloud_variant(variant)   # 결정4: _rds/_aurora/_azure → cloud 클래스
    if not engine:
        log.warning("DB 어댑터: 미지원 variant=%s item=%s", variant, item_id)
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[미지원 variant: {variant}] DB 엔진 매핑 실패",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 모드 B: 구조적 취약 (pg_native DBM-006/007 — 네이티브 기능 부재) ──────
    # gate를 이미 통과(DET). 데이터 불필요 — 구조적 사실이 곧 증거.
    _sv_reason = _STRUCTURAL_VULN.get((base, variant))
    if _sv_reason is not None:
        return ForcedVerdict(
            verdict="취약",
            confidence=0.9,
            rationale=(
                f"PostgreSQL 코어에 {_sv_reason} 기능 없음 — "
                "외부모듈(passwordcheck 등)/RDS 파라미터로 보완 시 담당자 확인 필요"
            ),
            citations=["PostgreSQL 네이티브 미지원"],
            ev_status="bad",
            handled=True,
        )

    # ── 결정1: raw_output → 전체 비마스킹 data dict 파싱 ────────────────────
    if not raw_output:
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[증거 부재: raw_output 없음] (item={item_id}, variant={variant})",
            citations=[],
            ev_status="review",
            handled=False,
        )

    try:
        data: dict = json.loads(raw_output)
        if not isinstance(data, dict):
            raise ValueError("data dict가 dict 타입이 아님")
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "DB 어댑터: raw_output JSON 파싱 실패 item=%s variant=%s: %s",
            item_id, variant, exc,
        )
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[raw_output 파싱 실패: {type(exc).__name__}]",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 증거 부재 가드 (D3): data dict 자체가 비어있음 ───────────────────────
    if not data:
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[증거 부재: data dict 비어있음] "
                f"(item={item_id}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 증거존재 가드 (D3): base의 data_key 1개 이상 필요 ───────────────────
    if not _has_data_key_for(base, data):
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[증거 부재: {base}의 data_key 없음 → 미수집 또는 해당 엔진 미대상] "
                f"(item={item_id}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 결정5 (Phase 4c): DBM-001 → 사전공격 어댑터 (db_pwcrack) ────────────
    # gate()를 이미 통과한 상태 (DET이므로 crack_judge 호출).
    # crack_judge 내부에서도 증거가드를 수행하므로 이중 가드 구조.
    if base == "DBM-001":
        return _db_pwcrack.crack_judge(engine, data, variant)

    # ── 결정2: engine Analysis.run 1회 (모듈 캐시, 예외내성) ────────────────
    # 결정4: is_cloud에 따라 native/cloud 클래스 분기, 캐시 키에 is_cloud 포함
    cache_result, exc_keys = _run_analysis(engine, data, is_cloud)
    if not cache_result:
        # .run이 {} 반환 = 예외 발생 or 완전 빈 결과
        # 증거 존재 확인했음에도 {} → R3 위험: handled=False로 LLM 폴백
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[결정론 분석 실패 또는 빈 결과: engine={engine}] "
                f"(item={item_id}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── base result_key로 위반 목록 조회 ────────────────────────────────────
    # analysis.run이 DBM-017을 result_key로 반환하므로 base(= DBM-017)로 조회.
    raw_rows = cache_result.get(base, None)
    if raw_rows is None:
        # run 결과에 base가 없는 엔진 = 이 엔진에서 해당 검사 미수행
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[결정론 결과에 {base} 없음: engine={engine}가 해당 검사 미수행] "
                f"(item={item_id}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── noise 필터(@@@/*** 단일키 행 제거) ──────────────────────────────────
    violations = _filter_noise(raw_rows)

    # ── R3 거짓양호 차단: 벤더 예외 삼킴으로 빈 위반 → 양호 매핑 방지 ────────
    # 조건: len(violations)==0 AND (base가 exc_keys에 있거나 __AMBIGUOUS__ sentinel)
    # 위반이 1건이라도 있으면 다른 sub-call이 정상 작동한 것 → 취약 판정 유지(과차단 방지).
    if not violations and exc_keys:
        should_block = (
            base in exc_keys          # 해당 result_key에서 예외 확인됨
            or "__AMBIGUOUS__" in exc_keys  # 예외 있으나 result_key 파싱 불가 → 보수적 차단
        )
        if should_block:
            log.warning(
                "R3 차단: base=%s engine=%s exc_keys=%s → handled=False (거짓양호 방지)",
                base, engine, exc_keys,
            )
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[결정론 내부 예외 — 양호 판정 불가, LLM 폴백] "
                    f"(base={base}, engine={engine}, exc_keys={sorted(exc_keys)})"
                ),
                citations=[],
                ev_status="review",
                handled=False,
            )

    # ── 모드 A: detect-then-hold (DBM-004 — 후보 나열, 판정은 사람) ──────────
    # 위반(후보)≥1 → 판단보류 + 후보목록, 위반0 → 양호. (R3 차단은 위에서 선적용)
    if base in _DETECT_THEN_HOLD:
        if not violations:
            return ForcedVerdict(
                verdict="양호",
                confidence=0.9,
                rationale=f"(+) 결정론 탐지: 해당 후보 없음 (engine={engine})",
                citations=[],
                ev_status="good",
                handled=True,
            )
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"결정론 탐지: 후보 {len(violations)}건 — "
                "업무상 필요성 담당자 확인 필요 (자동 취약 판정 보류)"
            ),
            citations=_mask_violations(violations),
            ev_status="review",
            handled=True,
        )

    # ── 모드 C: detect-vuln-else-hold (DBM-011 — 감사로그 수집 및 백업) ──────
    # 벤더 로직은 수집(플러그인 로드) 여부만 판정. 백업 주기는 인터뷰 영역.
    # 취약(미수집) 탐지 → 취약 확정, 위반0(수집됨) → 판단보류(양호 자동판정 절대 금지).
    # Phase 4e: 보류 rationale에 확인된 감사/플러그인 내용 명시 (§7 경계 준수).
    if base in _DETECT_VULN_ELSE_HOLD:
        if violations:
            citations = _mask_violations(violations)
            return ForcedVerdict(
                verdict="취약",
                confidence=0.9,
                rationale=(
                    f"(-) 결정론 판정: 감사로그 미수집 {len(violations)}건 (engine={engine})"
                ),
                citations=citations,
                ev_status="bad",
                handled=True,
            )
        # 위반0: 수집은 확인됐으나 백업 주기 미검증 → 판단보류 강제
        audit_detail = _extract_audit_detail(engine, data)
        detail_suffix = f" [{audit_detail}]" if audit_detail else ""
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"감사로그 수집 확인됨 (engine={engine}){detail_suffix}, "
                "주기적 백업 여부는 인터뷰/증적 확인 필요 — 자동 양호 판정 불가"
            ),
            citations=[audit_detail] if audit_detail else [],
            ev_status="review",
            handled=True,
        )

    # ── 모드 D: empty-RESULT / 기대변수-부재 거짓양호 가드 (DBM-019) ────────────
    # 위반0인 경우:
    #   (1) RESULT 0행 → 설정 미수집 → 판단보류.
    #   (2) RESULT에 행은 있지만 엔진별 기대 변수가 하나도 없음 → 변수 미수집 → 판단보류.
    #   (3) 기대 변수가 존재하고 위반 없음 → 정상 양호.
    # 매핑 없는 엔진은 (1)만 동작 (oracle/mssql은 직접 인덱싱→KeyError로 이미 안전).
    if base in _EMPTY_RESULT_HOLD and not violations:
        raw_result_rows = data.get(base, {}).get("RESULT", [])
        if not raw_result_rows:
            log.warning(
                "모드D 가드: base=%s engine=%s RESULT 완전 비어있음 → 판단보류(설정 미수집)",
                base, engine,
            )
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[재사용방지 설정 미수집: RESULT 0행] "
                    f"비밀번호 재사용 방지 설정 데이터를 수집하지 못함 — "
                    f"자동 양호 판정 불가 (engine={engine}, item={base})"
                ),
                citations=[],
                ev_status="review",
                handled=True,
            )
        # (2) 행은 있지만 기대 변수 부재 → 판단보류
        expected_checker = _DBM019_EXPECTED_CHECKER.get(engine)
        if expected_checker is not None and not expected_checker(raw_result_rows):
            log.warning(
                "모드D 가드(확장): base=%s engine=%s RESULT %d행 존재하나 기대변수 미수집 → 판단보류",
                base, engine, len(raw_result_rows),
            )
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[재사용방지 설정 변수 미수집 → 판단보류] "
                    f"RESULT에 {len(raw_result_rows)}행이 있으나 "
                    f"재사용 방지 기대 변수가 포함되지 않음 — "
                    f"자동 양호 판정 불가 (engine={engine}, item={base})"
                ),
                citations=[],
                ev_status="review",
                handled=True,
            )

    # ── 모드 E: DBM-022 파일권한 미수집 거짓양호 가드 ────────────────────────
    # 위반0인 경우 두 가지 케이스를 판단보류로 처리:
    #   (1) RESULT 0행(빈 배열) → 파일권한 미수집(모드D DBM-019와 일관성)
    #   (2) RESULT 행 있으나 권한 패턴 0건 → "No such file" 등 접근 실패
    # 보수 원칙: 불확실한 경우 판단보류 채택(거짓양호 회피 우선).
    if base in _PERM_GUARD and not violations:
        raw_result_rows = data.get(base, {}).get("RESULT", [])
        # (1) RESULT 빈배열 → 파일권한 미수집
        if not raw_result_rows:
            log.warning(
                "모드E 가드: base=%s engine=%s RESULT 0행(빈배열) → 판단보류(파일권한 미수집)",
                base, engine,
            )
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[파일권한 미수집 → 판단보류] "
                    f"RESULT가 빈 배열(0행) — "
                    f"파일 권한 수집 자체가 이루어지지 않아 자동 양호 판정 불가 "
                    f"(engine={engine}, item={base})"
                ),
                citations=[],
                ev_status="review",
                handled=True,
            )
        # (2) RESULT 행 있으나 권한 패턴 0건 → 접근 실패 또는 수집 오류
        if not _dbm022_has_perm_line(raw_result_rows):
            log.warning(
                "모드E 가드: base=%s engine=%s RESULT %d행 존재하나 권한라인 0건 → 판단보류(파일권한 미수집)",
                base, engine, len(raw_result_rows),
            )
            return ForcedVerdict(
                verdict="판단보류",
                confidence=0.0,
                rationale=(
                    f"[파일권한 미수집 → 판단보류] "
                    f"RESULT에 {len(raw_result_rows)}행이 있으나 "
                    f"권한 문자열(drwxrwxrwx 형식)이 포함되지 않음 — "
                    f"파일 접근 실패 또는 수집 오류 가능성, 자동 양호 판정 불가 "
                    f"(engine={engine}, item={base})"
                ),
                citations=[],
                ev_status="review",
                handled=True,
            )

    # ── 결과 매핑: 빈 위반 = 양호, 비어있지 않음 = 취약 ─────────────────────
    if not violations:
        return ForcedVerdict(
            verdict="양호",
            confidence=0.9,
            rationale=f"(+) 결정론 판정: 위반 없음 (engine={engine})",
            citations=[],
            ev_status="good",
            handled=True,
        )

    # 취약: 위반행 마스킹 후 citations
    citations = _mask_violations(violations)
    return ForcedVerdict(
        verdict="취약",
        confidence=0.9,
        rationale=f"(-) 결정론 판정: 위반 {len(violations)}건 (engine={engine})",
        citations=citations,
        ev_status="bad",
        handled=True,
    )


# ── 레지스트리 등록 (모듈 import 시 자동 실행) ──────────────────────────────
# 결정3: 5개 profile_key 동시 등록 (db_tibero excluded)
for _k in ("db_mysql", "db_oracle", "db_mssql", "db_mariadb", "db_postgresql"):
    _DET_ADAPTERS[_k] = judge

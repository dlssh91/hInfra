"""DB(DBM) 엔진별 DET 양극성 커버리지 픽스처 계약 (단일 진실원천).

각 DET 항목에 대해 good(위반없음→양호) / vuln(위반→취약 또는 탐지→판단보류) 합성 RESULT를 정의.

구조:
  DB_COV[engine][item_id] = {
      "good": {"<data_key>": {"RESULT": [...]}},   # 빈 위반 → 양호 기대
      "vuln": {"<data_key>": {"RESULT": [...]}},   # 위반 → 취약(또는 detect-then-hold=판단보류) 기대
      "good_verdict": "양호",                       # 기대 verdict (good 입력 기준)
      "vuln_verdict": "취약",                       # 기대 verdict (vuln 입력 기준)
      "note": "...",                                # 선택적 설명
  }

특수 verdict:
  - "양호"      : 위반 없음
  - "취약"      : 위반 확정
  - "판단보류"  : 모드A(detect-then-hold), 모드C(detect-vuln-else-hold), 모드D/E/F/G/H 가드 등

미커버(UNCOVERED) 표시:
  항목에 "uncovered": True 가 있으면 skip 사유가 "uncovered_reason" 에 명시됨.
"""
from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────────
# mysql native DET 항목
# ──────────────────────────────────────────────────────────────────────────────
_MYSQL = {
    # DBM-001: crack_judge — 양호 판정 없음(설계 계약). 빈 RESULT → D3 증거가드 handled=False.
    "DBM-001": {
        "uncovered": True,
        "uncovered_reason": "crack_judge 설계 계약: 양호 판정 없음(crack하거나 보류). 양극성 불가.",
    },

    # DBM-003: 업무상 불필요한 계정 존재 — 모드A2(classify-then-hold)
    # good/vuln 모두 현실적 계정목록(활성/잠김/시스템내장 혼합) → 항상 판단보류.
    "DBM-003": {
        "good": {"DBM-003": {"RESULT": [
            {"USER": "root", "HOST": "localhost", "ACCOUNT_LOCKED": "N"},
            {"USER": "mysql.sys", "HOST": "localhost", "ACCOUNT_LOCKED": "Y"},
            {"USER": "app_svc", "HOST": "%", "ACCOUNT_LOCKED": "N"},
        ]}},
        "vuln": {"DBM-003": {"RESULT": [
            {"USER": "root", "HOST": "localhost", "ACCOUNT_LOCKED": "N"},
            {"USER": "mysql.sys", "HOST": "localhost", "ACCOUNT_LOCKED": "Y"},
            {"USER": "test_api", "HOST": "%", "ACCOUNT_LOCKED": "N"},
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "판단보류",
        "note": "label B → 모드A2(classify-then-hold): 항상 판단보류+분류정보. "
                "good은 거짓취약 부재만 고정(계정분류 정리정보 동반).",
    },

    # DBM-004: 관리자 권한 — 모드A(detect-then-hold)
    # good: RESULT 존재 + 무해행(SELECT는 관리자 권한 아님) → 후보0 → 양호.
    # vuln: SUPER 권한 존재 → 판단보류(모드A 후보 탐지)
    "DBM-004": {
        "good": {"DBM-004": {"RESULT": [
            {"GRANTEE": "'app'@'%'", "PRIVILEGE_TYPE": "SELECT"}
        ]}},
        "vuln": {"DBM-004": {"RESULT": [
            {"GRANTEE": "hacker@%", "PRIVILEGE_TYPE": "SUPER", "IS_GRANTABLE": "NO"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "판단보류",
        "note": "모드A: 후보 탐지 → 판단보류(자동 취약 아님). good은 RESULT 비어있지 않은 "
                "무해행(신규 수집실패 가드 회피)으로 진짜 양호를 고정.",
    },

    # DBM-006: 로그인 실패 제한 — USER_ATTRIBUTES 필드
    # good: 빈 RESULT → 양호(실패잠금 설정 OK 또는 계정 없음)
    # vuln: USER_ATTRIBUTES=="" → 잠금 미설정 계정 존재 → 취약
    "DBM-006": {
        "good": {"DBM-006": {"RESULT": []}},
        "vuln": {"DBM-006": {"RESULT": [
            {"USER": "app_user", "HOST": "localhost", "USER_ATTRIBUTES": ""}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-007: 비밀번호 복잡도 — validate_password_policy
    # good: 빈 RESULT → 양호(플러그인 로드됨+정책 OK)
    # vuln: "not loaded" → 취약
    "DBM-007": {
        "good": {"DBM-007": {"RESULT": [
            {"VARIABLE_NAME": "validate_password.policy", "VARIABLE_VALUE": "STRONG"}
        ]}},
        "vuln": {"DBM-007": {"RESULT": ["validate_password.so plugin is not loaded!"]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-008: 비밀번호 주기변경 90일
    # good: 오늘 날짜 (최근 변경) → 위반 없음
    # vuln: 오래된 날짜 (2000-01-01) → 90일 초과 → 취약
    "DBM-008": {
        "good": {"DBM-008": {"RESULT": [
            {"USER": "app_user", "HOST": "localhost", "PASSWORD_LAST_CHANGED": "2099-01-01"}
        ]}},
        "vuln": {"DBM-008": {"RESULT": [
            {"USER": "old_user", "HOST": "localhost", "PASSWORD_LAST_CHANGED": "2000-01-01"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-009: 세션 종료 — wait_timeout/interactive_timeout (MySQL 소문자)
    # mysql config rules: VARIABLE_NAME=['wait_timeout'], TIME=['900']
    # good: wait_timeout=900 → 900 > 900 False → 위반 없음 → 양호
    # vuln: wait_timeout=9999 → 9999 > 900 True → 취약
    "DBM-009": {
        "good": {"DBM-009": {"RESULT": [
            {"VARIABLE_NAME": "wait_timeout", "VARIABLE_VALUE": "900"}
        ]}},
        "vuln": {"DBM-009": {"RESULT": [
            {"VARIABLE_NAME": "wait_timeout", "VARIABLE_VALUE": "9999"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "mysql: 소문자 wait_timeout. mariadb: 대문자 WAIT_TIMEOUT",
    },

    # DBM-011: 감사로그 — 모드C(detect-vuln-else-hold)
    # good: 수집됨(위반0) → 판단보류(양호 자동판정 금지)
    # vuln: "not loaded" → 취약
    "DBM-011": {
        "good": {"DBM-011": {"RESULT": [
            {"VARIABLE_NAME": "audit_log_file", "VARIABLE_VALUE": "/var/log/audit.log"}
        ]}},
        "vuln": {"DBM-011": {"RESULT": ["audit_log.so plugin is not loaded!"]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "취약",
        "note": "모드C: good입력=수집됨→판단보류(양호 아님), vuln=미수집→취약",
    },

    # DBM-013: 원격접근통제 — HOST에 % 포함
    # good: localhost만 → 위반 없음
    # vuln: HOST='%' 와일드카드 → 취약
    "DBM-013": {
        "good": {"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "localhost"}
        ]}},
        "vuln": {"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "%"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-019: 비밀번호 재사용 — password_history/password_reuse_interval
    # good: password_history=5(기준 이상) → 위반 없음
    # vuln: password_history=0(재사용 허용) → 취약
    "DBM-019": {
        "good": {"DBM-019": {"RESULT": [
            {"VARIABLE_NAME": "password_history", "VARIABLE_VALUE": "5"},
            {"VARIABLE_NAME": "password_reuse_interval", "VARIABLE_VALUE": "365"},
        ]}},
        "vuln": {"DBM-019": {"RESULT": [
            {"VARIABLE_NAME": "password_history", "VARIABLE_VALUE": "0"},
            {"VARIABLE_NAME": "password_reuse_interval", "VARIABLE_VALUE": "0"},
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-022: 파일 권한 — output 필드에 ls -al 출력
    # good: -rw------- → owner read/write만, group/other 권한 없음 → 위반 없음
    # vuln: -rw-rw-rw- → other write 있음 → 취약
    "DBM-022": {
        "good": {"DBM-022": {"RESULT": [
            {"output": "-rw-------  1 mysql mysql 1234 Jun 1 2024 /etc/mysql/my.cnf"}
        ]}},
        "vuln": {"DBM-022": {"RESULT": [
            {"output": "-rw-rw-rw-  1 mysql mysql 1234 Jun 1 2024 /etc/mysql/my.cnf"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-025: EOL — label D. F2(2026-07): item_configs에 judgment_method가
    # 없으므로 classify_method가 'det'를 도출 → main._defer_or_eol → judge_eol
    # (eol.yaml as_of/staleness 권위경로)로 라우팅되며, 이 det_adapters/db.py
    # judge() 테스트 하네스(DET_SOURCE 기반)는 우회한다. DET_SOURCE도 이중방어로
    # STUB 처리되어 gate()가 항상 handled=False+판단보류를 반환 — RESULT
    # 내용과 무관해 결정론 양극성(양호/취약) 자체가 성립하지 않는다.
    "DBM-025": {
        "uncovered": True,
        "uncovered_reason": "label D EOL: judgment_method='det'로 judge_eol(eol.yaml) "
                             "권위경로 라우팅 — det_adapters STUB(이중방어)이라 이 "
                             "하네스에서는 판단보류 고정, 결정론 양극성(양호/취약) 없음.",
    },

    # DBM-026: umask — output 필드
    # good: umask 022 → group=2, other=2 → 위반 없음
    # vuln: umask 000 → group=0, other=0 → 취약
    "DBM-026": {
        "good": {"DBM-026": {"RESULT": [
            {"output": "0022"}
        ]}},
        "vuln": {"DBM-026": {"RESULT": [
            {"output": "0000"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-033: 이중화 평문비번 — PASSWORD 필드
    # good: PASSWORD="" → 노출 없음 → 양호
    # vuln: PASSWORD="secret123" → 평문 노출 → 취약
    "DBM-033": {
        "good": {"DBM-033": {"RESULT": [
            {"PASSWORD": ""}
        ]}},
        "vuln": {"DBM-033": {"RESULT": [
            {"PASSWORD": "secret123", "MASTER_HOST": "192.168.1.1"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-034: 서비스 구동 권한 — output 필드에 ps 출력
    # good: mysql 계정으로 mysqld 구동 → 위반 없음
    # vuln: root 계정으로 mysqld 구동 → 취약
    "DBM-034": {
        "good": {"DBM-034": {"RESULT": [
            {"output": "mysql     1234     1  0 Jun01 ?        00:00:00 /usr/sbin/mysqld"}
        ]}},
        "vuln": {"DBM-034": {"RESULT": [
            {"output": "root      1234     1  0 Jun01 ?        00:00:00 /usr/sbin/mysqld"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# mariadb native DET 항목
# ──────────────────────────────────────────────────────────────────────────────
_MARIADB = {
    "DBM-001": {
        "uncovered": True,
        "uncovered_reason": "crack_judge 설계 계약: 양호 판정 없음. 양극성 불가.",
    },

    # DBM-003: 업무상 불필요한 계정 존재 — 모드A2(classify-then-hold)
    # mariadb는 ACCOUNT_LOCKED 필드 대신 PASSWORD_EXPIRED 사용. good/vuln 모두 판단보류.
    "DBM-003": {
        "good": {"DBM-003": {"RESULT": [
            {"USER": "root", "HOST": "localhost", "PASSWORD_EXPIRED": "N"},
            {"USER": "mariadb.sys", "HOST": "localhost", "PASSWORD_EXPIRED": "Y"},
        ]}},
        "vuln": {"DBM-003": {"RESULT": [
            {"USER": "root", "HOST": "localhost", "PASSWORD_EXPIRED": "N"},
            {"USER": "old_user", "HOST": "localhost", "PASSWORD_EXPIRED": "N"},
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "판단보류",
        "note": "label B → 모드A2(classify-then-hold): 항상 판단보류+분류정보. "
                "good은 거짓취약 부재만 고정(계정분류 정리정보 동반).",
    },

    "DBM-004": {
        "good": {"DBM-004": {"RESULT": [
            {"GRANTEE": "'app'@'%'", "PRIVILEGE_TYPE": "USAGE"}
        ]}},
        "vuln": {"DBM-004": {"RESULT": [
            {"GRANTEE": "bad@%", "PRIVILEGE_TYPE": "SUPER", "IS_GRANTABLE": "NO"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "판단보류",
        "note": "모드A",
    },

    # DBM-005: mariadb는 STUB → gate 차단 → label A LLM. 양극성 커버 불가.
    "DBM-005": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE mariadb=STUB. gate 차단 → LLM 경로. 결정론 양극성 없음.",
    },

    # DBM-006: mariadb는 MAX_PASSWORD_ERRORS 변수로 실패잠금 판정
    # config rules: VARIABLE_NAME=['MAX_PASSWORD_ERRORS'], VARIABLE_VALUE=['5']
    # vuln: MAX_PASSWORD_ERRORS=10 (5 초과) → 취약
    # good: 빈 RESULT 또는 MAX_PASSWORD_ERRORS <= 5 → 위반 없음 → 양호
    "DBM-006": {
        "good": {"DBM-006": {"RESULT": []}},
        "vuln": {"DBM-006": {"RESULT": [
            {"VARIABLE_NAME": "MAX_PASSWORD_ERRORS", "VARIABLE_VALUE": "10"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "mariadb: VARIABLE_NAME=MAX_PASSWORD_ERRORS, VARIABLE_VALUE>5 → 취약",
    },

    # DBM-008: mariadb는 DEFAULT_PASSWORD_LIFETIME 변수로 판정 (>90일 또는 0=영구)
    # good: DEFAULT_PASSWORD_LIFETIME=90 → 정확히 90일 → 위반 아님
    # vuln: DEFAULT_PASSWORD_LIFETIME=0 → 영구(비활성) → 취약
    "DBM-008": {
        "good": {"DBM-008": {"RESULT": [
            {"VARIABLE_NAME": "DEFAULT_PASSWORD_LIFETIME", "VARIABLE_VALUE": "90"}
        ]}},
        "vuln": {"DBM-008": {"RESULT": [
            {"VARIABLE_NAME": "DEFAULT_PASSWORD_LIFETIME", "VARIABLE_VALUE": "0"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "mariadb: DEFAULT_PASSWORD_LIFETIME>90 or ==0 → 취약",
    },

    # DBM-009: mariadb config rules['VARIABLE_NAME']=['WAIT_TIMEOUT','INTERACTIVE_TIMEOUT'] (대문자)
    "DBM-009": {
        "good": {"DBM-009": {"RESULT": [
            {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "900"}
        ]}},
        "vuln": {"DBM-009": {"RESULT": [
            {"VARIABLE_NAME": "WAIT_TIMEOUT", "VARIABLE_VALUE": "9999"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-011: mariadb DET 복원 — "not loaded" 탐지
    "DBM-011": {
        "good": {"DBM-011": {"RESULT": [
            {"VARIABLE_NAME": "SERVER_AUDIT_FILE_PATH", "VARIABLE_VALUE": "/var/log/mariadb-audit.log"}
        ]}},
        "vuln": {"DBM-011": {"RESULT": ["server_audit.so plugin is not loaded!"]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "취약",
        "note": "모드C: good=수집됨→판단보류",
    },

    "DBM-013": {
        "good": {"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "localhost"}
        ]}},
        "vuln": {"DBM-013": {"RESULT": [
            {"USER": "app_user", "HOST": "%"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    "DBM-019": {
        "good": {"DBM-019": {"RESULT": [
            {"VARIABLE_NAME": "PASSWORD_REUSE_CHECK_INTERVAL", "VARIABLE_VALUE": "365"}
        ]}},
        "vuln": {"DBM-019": {"RESULT": ["plugin is not loaded!"]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "mariadb: not loaded 문자열 → 취약",
    },

    "DBM-022": {
        "good": {"DBM-022": {"RESULT": [
            {"output": "-rw-------  1 mysql mysql 1234 Jun 1 2024 /etc/mysql/my.cnf"}
        ]}},
        "vuln": {"DBM-022": {"RESULT": [
            {"output": "-rw-rw-rw-  1 mysql mysql 1234 Jun 1 2024 /etc/mysql/my.cnf"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    "DBM-026": {
        "good": {"DBM-026": {"RESULT": [{"output": "0022"}]}},
        "vuln": {"DBM-026": {"RESULT": [{"output": "0000"}]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    "DBM-034": {
        "good": {"DBM-034": {"RESULT": [
            {"output": "mysql     1234     1  0 Jun01 ?        00:00:00 /usr/sbin/mariadbd"}
        ]}},
        "vuln": {"DBM-034": {"RESULT": [
            {"output": "root      1234     1  0 Jun01 ?        00:00:00 /usr/sbin/mariadbd"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# oracle native DET 항목
# ──────────────────────────────────────────────────────────────────────────────
_ORACLE = {
    "DBM-001": {
        "uncovered": True,
        "uncovered_reason": "crack_judge 설계 계약: 양호 판정 없음. 양극성 불가.",
    },

    # DBM-003: 업무상 불필요한 계정 존재 — 모드A2(classify-then-hold)
    # oracle은 expiry_date/last_login/account_status/username 필드. good/vuln 모두 판단보류.
    "DBM-003": {
        "good": {"DBM-003": {"RESULT": [
            {
                "username": "SYSTEM",
                "account_status": "OPEN",
                "last_login": "15-JUN-26 09.45.17.000000",
                "expiry_date": "",
            }
        ]}},
        "vuln": {"DBM-003": {"RESULT": [
            {
                "username": "OLD_USER",
                "account_status": "OPEN",
                "last_login": "",
                "expiry_date": "19-DEC-25",
            }
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "판단보류",
        "note": "label B → 모드A2(classify-then-hold): 항상 판단보류+분류정보. "
                "good은 거짓취약 부재만 고정(계정분류 정리정보 동반).",
    },

    # DBM-004: grantee/username exception 기반
    # good: RESULT 0행(exception 공백) → 위반0이지만 신규 수집실패 가드에 걸려 판단보류.
    "DBM-004": {
        "good": {"DBM-004_1": {"RESULT": []}},
        "vuln": {"DBM-004_1": {"RESULT": [
            {"grantee": "BAD_USER"}
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "판단보류",
        "note": "모드A: RESULT 0행 → 신규 수집실패 가드(_base_result_rows_exist)에 걸려 "
                "판단보류(권한목록 미수집). 후보 탐지 시에도 판단보류(자동 취약 아님).",
    },

    # DBM-006: FAILED_LOGIN_ATTEMPTS/IDLE_TIME
    "DBM-006": {
        "good": {"DBM-006": {"RESULT": []}},
        "vuln": {"DBM-006": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "UNLIMITED"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-007: 비밀번호 복잡도 — profile/limit
    "DBM-007": {
        "good": {"DBM-007_1": {"RESULT": []}},
        "vuln": {"DBM-007_1": {"RESULT": [
            {"profile": "DEFAULT", "limit": "UNLIMITED"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-008: 비밀번호 주기변경 — ptime 필드 (oracle '%d-%b-%y' 포맷)
    # good: 1개월 이내 변경 (19-May-26 = 오늘 기준 1개월 이내) → 위반 없음
    # vuln: 12개월 이전 변경 (19-Jun-25 = 2025-06-19) → 6개월 초과 → 취약
    "DBM-008": {
        "good": {"DBM-008_1": {"RESULT": [
            {"name": "oracle_user", "ptime": "19-May-26"}
        ]}},
        "vuln": {"DBM-008_1": {"RESULT": [
            {"name": "oracle_user", "ptime": "19-Jun-25"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "oracle ptime 포맷: '%d-%b-%y'. 6개월(relativedelta) 기준. good=1개월 전, vuln=12개월 전.",
    },

    # DBM-009: 세션 종료 — IDLE_TIME
    # 모드J(F3, 2026-07-10): good을 빈RESULT(거짓양호 실인코딩)에서 IDLE_TIME 유효행
    # (limit=UNLIMITED 아님 → 위반0)으로 교체. resource_name=IDLE_TIME 행 존재 →
    # 모드J checker 통과 → 위반0 그대로 양호(회귀 없음).
    "DBM-009": {
        "good": {"DBM-009": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "IDLE_TIME", "limit": "900"}
        ]}},
        "vuln": {"DBM-009": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "IDLE_TIME", "limit": "UNLIMITED"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-011: oracle audit_trail — 모드C
    "DBM-011": {
        "good": {"DBM-011": {"RESULT": [
            {"name": "audit_trail", "value": "DB"}
        ]}},
        "vuln": {"DBM-011": {"RESULT": [
            {"name": "audit_trail", "value": "NONE"}
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "취약",
        "note": "모드C. dateutil 필요(importorskip으로 처리).",
    },

    # DBM-014: oracle 전용 파라미터
    # 모드J(F4, 2026-07-10): good을 빈RESULT(거짓양호 실인코딩)에서
    # os_roles/remote_os_roles FALSE 행(위반0 유지)으로 교체.
    "DBM-014": {
        "good": {"DBM-014": {"RESULT": [
            {"name": "os_roles", "value": "FALSE"},
            {"name": "remote_os_roles", "value": "FALSE"},
        ]}},
        "vuln": {"DBM-014": {"RESULT": [
            {"name": "some_param", "value": "TRUE"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "oracle 전용. config rules에 따라 판정. 모드J: os_roles/remote_os_roles FALSE 행 필요.",
    },

    # DBM-019: 비밀번호 재사용 — PASSWORD_REUSE_TIME/MAX
    "DBM-019": {
        "good": {"DBM-019": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_TIME", "limit": "365"}
        ]}},
        "vuln": {"DBM-019": {"RESULT": [
            {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_TIME", "limit": "UNLIMITED"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-022: 파일 권한
    "DBM-022": {
        "good": {"DBM-022": {"RESULT": [
            {"output": "-rw-------  1 oracle dba 1234 Jun 1 2024 /u01/app/oracle/product/19c/dbhome_1/dbs/init.ora"}
        ]}},
        "vuln": {"DBM-022": {"RESULT": [
            {"output": "-rw-rw-rw-  1 oracle dba 1234 Jun 1 2024 /u01/app/oracle/product/19c/dbhome_1/dbs/init.ora"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-025: EOL — label D. F2(2026-07): judgment_method 미지정 →
    # classify_method='det' → judge_eol(eol.yaml) 권위경로. 이 하네스는
    # det_adapters STUB(이중방어)로 gate 차단 — 양극성 성립 안 함.
    "DBM-025": {
        "uncovered": True,
        "uncovered_reason": "label D EOL: judgment_method='det'로 judge_eol(eol.yaml) "
                             "권위경로 라우팅 — det_adapters STUB(이중방어)이라 이 "
                             "하네스에서는 판단보류 고정, 결정론 양극성 없음.",
    },

    "DBM-026": {
        "good": {"DBM-026": {"RESULT": [{"output": "0022"}]}},
        "vuln": {"DBM-026": {"RESULT": [{"output": "0000"}]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-029: oracle RESOURCE_LIMIT — 모드D(빈 RESULT → 판단보류)
    # good: RESOURCE_LIMIT=TRUE → 위반 없음
    # vuln: 빈 RESULT → 모드D → 판단보류 (취약 확정이 아님)
    "DBM-029": {
        "good": {"DBM-029": {"RESULT": [
            {"name": "RESOURCE_LIMIT", "value": "TRUE"}
        ]}},
        "vuln": {"DBM-029": {"RESULT": [
            {"name": "RESOURCE_LIMIT", "value": "FALSE"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
        "note": "DBM-029 oracle: RESOURCE_LIMIT=FALSE → 취약. 빈 RESULT는 모드D → 판단보류.",
    },

    "DBM-034": {
        "good": {"DBM-034": {"RESULT": [
            {"output": "oracle    1234     1  0 Jun01 ?        00:00:00 ora_pmon_ORCL"}
        ]}},
        "vuln": {"DBM-034": {"RESULT": [
            {"output": "root      1234     1  0 Jun01 ?        00:00:00 ora_pmon_ORCL"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# mssql native DET 항목
# ──────────────────────────────────────────────────────────────────────────────
_MSSQL = {
    "DBM-001": {
        "uncovered": True,
        "uncovered_reason": "crack_judge 설계 계약: 양호 판정 없음. 양극성 불가.",
    },

    # DBM-003: 업무상 불필요한 계정 존재 — 모드A2(classify-then-hold)
    # is_disabled=0/1 기준 활성/잠김. good/vuln 모두 판단보류.
    "DBM-003": {
        "good": {"DBM-003_1": {"RESULT": [
            {"name": "sa", "is_disabled": "0", "modify_date": "Jun 15 2026  9:41AM"}
        ]}},
        "vuln": {"DBM-003_1": {"RESULT": [
            {"is_disabled": "0", "name": "old_user", "modify_date": "Jan-01-2020 00:00:00"}
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "판단보류",
        "note": "label B → 모드A2(classify-then-hold): 항상 판단보류+분류정보. "
                "good은 거짓취약 부재만 고정(계정분류 정리정보 동반).",
    },

    # DBM-004: sysadmin/serveradmin/securityadmin != '0'
    # good: RESULT 존재 + 무해행(권한 전부 0) → 후보0 → 양호.
    "DBM-004": {
        "good": {"DBM-004": {"RESULT": [
            {"name": "app", "sysadmin": "0", "serveradmin": "0", "securityadmin": "0"}
        ]}},
        "vuln": {"DBM-004": {"RESULT": [
            {"name": "bad_user", "sysadmin": "1", "serveradmin": "0", "securityadmin": "0"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "판단보류",
        "note": "모드A",
    },

    # DBM-005: mssql native는 label A + det_common, DET_SOURCE=DET(sample is not None)
    # good: sample=null → 위반 없음
    # vuln: sample='some_data' → 취약
    # NOTE: mssql native dbm_005: datum['sample'] is not None → 위반. sample=null/None → 양호.
    "DBM-005": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE mssql native=DET지만 config rules['DBM-005']['permission_name']=[] "
                            "구조 불명확. 수집 포맷 미확인. 빈 RESULT → 양호 확인에 충분.",
    },

    # DBM-006: is_policy_checked=0 → 취약
    "DBM-006": {
        "good": {"DBM-006": {"RESULT": []}},
        "vuln": {"DBM-006": {"RESULT": [
            {"is_policy_checked": "0", "name": "sa"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-007: is_policy_checked=0 → 취약
    "DBM-007": {
        "good": {"DBM-007": {"RESULT": []}},
        "vuln": {"DBM-007": {"RESULT": [
            {"is_policy_checked": "0", "name": "sa"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-008: days_after_changed > 90
    "DBM-008": {
        "good": {"DBM-008": {"RESULT": [
            {"name": "sa", "days_after_changed": "0"}
        ]}},
        "vuln": {"DBM-008": {"RESULT": [
            {"name": "old_user", "days_after_changed": "180"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-009: mssql native=STUB → gate 차단 → 미커버
    "DBM-009": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE mssql native=STUB(lambda True). gate 차단 → 결정론 불가.",
    },

    # DBM-011: 활성 서버감사 탐지 — 모드C
    "DBM-011": {
        "good": {"DBM-011": {"RESULT": [
            {"audit_name": "ServerAudit1", "audit_action": "DATABASE_OBJECT_ACCESS_GROUP",
             "create_date": "2024-01-01", "modify_date": "2024-01-01"}
        ]}},
        "vuln": {"DBM-011": {"RESULT": []}},
        "good_verdict": "판단보류",
        "vuln_verdict": "취약",
        "note": "모드C: good=감사활성→판단보류, vuln=미수집→취약",
    },

    # DBM-013: mssql native=STUB → 미커버
    "DBM-013": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE mssql native=STUB(빈본문). gate 차단 → 결정론 불가.",
    },

    # DBM-019: is_policy_checked=0 → 취약
    "DBM-019": {
        "good": {"DBM-019": {"RESULT": [
            {"is_policy_checked": "1", "name": "sa"}
        ]}},
        "vuln": {"DBM-019": {"RESULT": [
            {"is_policy_checked": "0", "name": "sa"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-025: EOL — label D. F2(2026-07): judgment_method 미지정 →
    # classify_method='det' → judge_eol(eol.yaml) 권위경로. 이 하네스는
    # det_adapters STUB(이중방어)로 gate 차단 — 양극성 성립 안 함.
    "DBM-025": {
        "uncovered": True,
        "uncovered_reason": "label D EOL: judgment_method='det'로 judge_eol(eol.yaml) "
                             "권위경로 라우팅 — det_adapters STUB(이중방어)이라 이 "
                             "하네스에서는 판단보류 고정, 결정론 양극성 없음.",
    },

    # DBM-031: SA 계정 정책 — is_disabled=0 AND is_policy_checked=0 → 취약
    "DBM-031": {
        "good": {"DBM-031": {"RESULT": [
            {"is_disabled": "1", "is_policy_checked": "1"}
        ]}},
        "vuln": {"DBM-031": {"RESULT": [
            {"is_disabled": "0", "is_policy_checked": "0"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-035: xp_cmdshell 비활성 — value_in_use
    "DBM-035": {
        "good": {"DBM-035": {"RESULT": [
            {"name": "xp_cmdshell", "value_in_use": "0"}
        ]}},
        "vuln": {"DBM-035": {"RESULT": [
            {"name": "xp_cmdshell", "value_in_use": "1"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-036: Registry 확장프로시저 접근권한 — public EXECUTE
    "DBM-036": {
        "good": {"DBM-036": {"RESULT": [
            {"object": "xp_regread", "permission": "EXECUTE", "grantee": "sysadmin"}
        ]}},
        "vuln": {"DBM-036": {"RESULT": [
            {"object": "xp_regread", "permission": "EXECUTE", "grantee": "public"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# postgresql native DET 항목
# ──────────────────────────────────────────────────────────────────────────────
_POSTGRESQL = {
    "DBM-001": {
        "uncovered": True,
        "uncovered_reason": "crack_judge 설계 계약: 양호 판정 없음. 양극성 불가.",
    },

    # DBM-005: pg native=STUB → 미커버
    "DBM-005": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE pg native=STUB. gate 차단 → 결정론 불가.",
    },

    # DBM-006: pg native — 모드B(구조적취약): 코어 실패잠금 부재. 데이터 무관 취약.
    # good 입력: 어떤 데이터를 넣어도 취약(구조적). "good 없음" 특수 케이스.
    "DBM-006": {
        "uncovered": True,
        "uncovered_reason": (
            "모드B(구조적취약): pg native 코어 실패잠금 부재 → 항상 취약. "
            "good 입력 없음(구조적 취약 = 양호 불가능). "
            "vuln_only=True: 어떤 입력에서도 취약."
        ),
        "vuln_only": True,
        "vuln": {"DBM-006_dummy": {"RESULT": []}},
        "vuln_verdict": "취약",
    },

    # DBM-008: rolvaliduntil — None이면 취약
    "DBM-008": {
        "good": {"DBM-008": {"RESULT": [
            {"rolvaliduntil": "2099-01-01 00:00:00+09", "rolcanlogin": "t", "rolname": "app_user"}
        ]}},
        "vuln": {"DBM-008": {"RESULT": [
            {"rolvaliduntil": None, "rolcanlogin": "t", "rolname": "app_user"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-009: idle_in_transaction_session_timeout — 0 또는 >900 → 취약
    "DBM-009": {
        "good": {"DBM-009": {"RESULT": [
            {"setting_name": "idle_in_transaction_session_timeout", "value": "900"}
        ]}},
        "vuln": {"DBM-009": {"RESULT": [
            {"setting_name": "idle_in_transaction_session_timeout", "value": "0"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-011: pgaudit 미로드 탐지 — 모드C
    "DBM-011": {
        "good": {"DBM-011": {"RESULT": [
            {"pgaudit_status": "Loaded", "pgaudit_settings": ["DDL", "WRITE"]}
        ]}},
        "vuln": {"DBM-011": {"RESULT": [
            {"pgaudit_status": "Not Loaded", "pgaudit_settings": []}
        ]}},
        "good_verdict": "판단보류",
        "vuln_verdict": "취약",
        "note": "모드C: good=로드됨→판단보류, vuln=미로드→취약",
    },

    # DBM-013: pg native=STUB → 미커버
    "DBM-013": {
        "uncovered": True,
        "uncovered_reason": "DET_SOURCE pg native=STUB(빈본문). gate 차단 → 결정론 불가.",
    },

    # DBM-022: 파일 권한
    "DBM-022": {
        "good": {"DBM-022": {"RESULT": [
            {"output": "-rw-------  1 postgres postgres 1234 Jun 1 2024 /etc/postgresql/pg_hba.conf"}
        ]}},
        "vuln": {"DBM-022": {"RESULT": [
            {"output": "-rw-rw-rw-  1 postgres postgres 1234 Jun 1 2024 /etc/postgresql/pg_hba.conf"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-025: EOL — label D. F2(2026-07): judgment_method 미지정 →
    # classify_method='det' → judge_eol(eol.yaml) 권위경로. 이 하네스는
    # det_adapters STUB(이중방어)로 gate 차단 — 양극성 성립 안 함.
    "DBM-025": {
        "uncovered": True,
        "uncovered_reason": "label D EOL: judgment_method='det'로 judge_eol(eol.yaml) "
                             "권위경로 라우팅 — det_adapters STUB(이중방어)이라 이 "
                             "하네스에서는 판단보류 고정, 결정론 양극성 없음.",
    },

    "DBM-026": {
        "good": {"DBM-026": {"RESULT": [{"output": "0022"}]}},
        "vuln": {"DBM-026": {"RESULT": [{"output": "0000"}]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    # DBM-032: pg_hba.conf 평문비번 — host/hostnossl+password
    "DBM-032": {
        "good": {"DBM-032": {"RESULT": [
            {"output": "hostssl all all 0.0.0.0/0 scram-sha-256"}
        ]}},
        "vuln": {"DBM-032": {"RESULT": [
            {"output": "host all all 0.0.0.0/0 password"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },

    "DBM-034": {
        "good": {"DBM-034": {"RESULT": [
            {"output": "postgres  1234     1  0 Jun01 ?        00:00:00 /usr/lib/postgresql/14/bin/postgres"}
        ]}},
        "vuln": {"DBM-034": {"RESULT": [
            {"output": "root      1234     1  0 Jun01 ?        00:00:00 /usr/lib/postgresql/14/bin/postgres"}
        ]}},
        "good_verdict": "양호",
        "vuln_verdict": "취약",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# 통합 딕셔너리
# ──────────────────────────────────────────────────────────────────────────────
DB_COV: dict[str, dict] = {
    "mysql":      _MYSQL,
    "mariadb":    _MARIADB,
    "oracle":     _ORACLE,
    "mssql":      _MSSQL,
    "postgresql": _POSTGRESQL,
}

# 엔진 → variant(native) 매핑
ENGINE_TO_VARIANT: dict[str, str] = {
    "mysql":      "mysql_native",
    "mariadb":    "mariadb_native",
    "oracle":     "oracle_native",
    "mssql":      "mssql_native",
    "postgresql": "pg_native",
}

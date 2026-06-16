"""정적 비밀번호 사전 — Phase 4c DBM-001 사전공격 (b 레이어).

내용:
  - DBMS 기본계정 비번 매핑 (계정명 → 후보 비번 리스트)
  - 공통 약한 비번 top-N (≈200)
  - 빈 해시 처리 규칙은 db_pwcrack.py 참고 (별도 분기)

§7 보안: 이 모듈은 후보 평문을 상수로 갖는다. 매치 결과 평문을 외부에 노출하는
것은 db_pwcrack.py에서 엄격히 금지된다.
"""
from __future__ import annotations

# ── DBMS 기본계정 비번 (계정명 → 후보 리스트) ─────────────────────────────────
# 키: 소문자 계정명, 값: 고정 후보 리스트 (중복 허용 — 중복은 crack 시 첫 매치 stop)
ACCOUNT_DEFAULT_PASSWORDS: dict[str, list[str]] = {
    # Oracle
    "oracle":            ["oracle", "oracle123", "oracle1"],
    "system":            ["manager", "oracle", "oracle123", "password", "change_on_install", "system"],
    "sys":               ["change_on_install", "oracle", "password", "oracle123"],
    "dbsnmp":            ["dbsnmp", "oracle", "password"],
    "scott":             ["tiger", "scott", "password"],
    "hr":                ["hr", "oracle", "password"],
    "sh":                ["sh", "oracle"],
    "outln":             ["outln", "oracle"],
    "mdsys":             ["mdsys", "oracle"],
    "ctxsys":            ["ctxsys", "oracle"],
    "wmsys":             ["wmsys", "oracle"],
    "xdb":               ["xdb", "oracle"],
    # MSSQL
    "sa":                ["sa", "", "password", "Password123", "sa@123", "Admin@123", "Password1", "1234"],
    # PostgreSQL
    "postgres":          ["postgres", "", "password", "postgresql", "admin", "12345"],
    # MySQL / MariaDB
    "root":              ["root", "", "password", "mysql", "toor", "root123", "admin", "mariadb", "12345"],
    "mysql":             ["mysql", "password", ""],
    "admin":             ["admin", "admin123", "password", "12345", ""],
    "test":              ["test", "test123", "password", ""],
    "user":              ["user", "user123", "password", ""],
    "guest":             ["guest", "guest123", "password", ""],
    "backup":            ["backup", "backup123", "password", ""],
    "replication":       ["replication", "replication123", "password", ""],
    "replica":           ["replica", "replica123", "password", ""],
    "monitoring":        ["monitoring", "monitor123", "password", ""],
    "monitor":           ["monitor", "monitor123", "password", ""],
    "deploy":            ["deploy", "deploy123", "password", ""],
    "app":               ["app", "app123", "password", ""],
    "webapp":            ["webapp", "webapp123", "password", ""],
    "developer":         ["developer", "developer123", "password", ""],
    "dev":               ["dev", "dev123", "password", ""],
    "dba":               ["dba", "dba123", "password", ""],
    "dbadmin":           ["dbadmin", "dbadmin123", "password", ""],
    "sysadmin":          ["sysadmin", "sysadmin123", "password", ""],
}

# ── 공통 약한 비번 top-N (≈200 정적 목록) ─────────────────────────────────────
# 출처: 공개 약한 비번 목록 + DBMS 기본값 + 단순 패턴
# 순서: 가장 흔한 것부터 (첫 매치 stop이므로 순서 중요)
COMMON_WEAK_PASSWORDS: list[str] = [
    # 완전 공백/단순
    "",
    " ",
    "password",
    "password1",
    "password123",
    "Password",
    "Password1",
    "Password123",
    "PASSWORD",
    "PASSWORD1",
    "PASSWORD123",
    # 숫자만
    "1",
    "12",
    "123",
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "0",
    "00",
    "000",
    "0000",
    "00000",
    "000000",
    "111",
    "1111",
    "11111",
    "111111",
    "1111111",
    "11111111",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999",
    # 간단한 단어
    "admin",
    "administrator",
    "root",
    "toor",
    "admin123",
    "admin1234",
    "Admin",
    "Admin1",
    "Admin123",
    "Admin@123",
    "admin@123",
    "root123",
    "root1234",
    "test",
    "test123",
    "Test123",
    "guest",
    "guest123",
    "user",
    "user123",
    "login",
    "pass",
    "pass123",
    "changeme",
    "change_me",
    "temp",
    "temp123",
    "oracle",
    "oracle123",
    "oracle1",
    "Oracle123",
    "mysql",
    "mysql123",
    "postgres",
    "postgres123",
    "mariadb",
    "mssql",
    "sqlserver",
    "database",
    "db123",
    "dba",
    "dba123",
    # 조합 패턴
    "abc",
    "abc123",
    "Abc123",
    "qwerty",
    "qwerty123",
    "Qwerty123",
    "asdf",
    "asdf1234",
    "zxcv",
    "qazwsx",
    "qazwsxedc",
    "letmein",
    "letmein1",
    "iloveyou",
    "sunshine",
    "monkey",
    "master",
    "master123",
    "dragon",
    "shadow",
    "baseball",
    "football",
    "superman",
    "batman",
    "access",
    "login123",
    "welcome",
    "welcome1",
    "Welcome1",
    "Welcome123",
    "secret",
    "secret123",
    "manage",
    "manager",
    "Manager123",
    # DBMS 특정 기본값
    "change_on_install",
    "tiger",
    "dbsnmp",
    "scott",
    "mariadba",
    "sa",
    "sa@123",
    "Sa@12345",
    # 패턴 기반
    "P@ssw0rd",
    "P@ssword",
    "P@ss123",
    "Passw0rd",
    "Passw0rd1",
    "Pa$$w0rd",
    "Pass@123",
    "pass@123",
    "@dmin123",
    "Admin@1234",
    "A@123456",
    "Test@123",
    "test@123",
    "System@1",
    "Oracle@1",
    "Oracle@123",
    "Mysql@123",
    "Postgres@1",
    # 날짜 패턴
    "2023",
    "2024",
    "2025",
    "2026",
    "20230101",
    "20240101",
    "Jan@2024",
    # 한국어 로마자
    "hanaro",
    "hanamoney",
    "kbstar",
    "shinhan",
    "woori",
    "nonghyup",
    "ibk",
    "korea",
    "korea123",
    "seoul",
    "seoul123",
    # 반복/키보드
    "aaaaaa",
    "aaa111",
    "aaaa1111",
    "abcd1234",
    "abcd@1234",
    "1q2w3e4r",
    "1Q2W3E4R",
    "q1w2e3r4",
    "qwer1234",
    "!@#$%^",
    "!@#$%^&*",
    "!QAZ2wsx",
    "1qaz2wsx",
]

# 계산 캐시: 사전 lookup 최적화
_ACCOUNT_SET: dict[str, frozenset[str]] = {
    name: frozenset(pw_list)
    for name, pw_list in ACCOUNT_DEFAULT_PASSWORDS.items()
}
_COMMON_SET: frozenset[str] = frozenset(COMMON_WEAK_PASSWORDS)

# 전체 후보 리스트(순서 보존, 중복 제거) — 사전 전체 순회 시 사용
_ALL_CANDIDATES: list[str] = []
_seen: set[str] = set()
for _pw in COMMON_WEAK_PASSWORDS:
    if _pw not in _seen:
        _ALL_CANDIDATES.append(_pw)
        _seen.add(_pw)
for _pw_list in ACCOUNT_DEFAULT_PASSWORDS.values():
    for _pw in _pw_list:
        if _pw not in _seen:
            _ALL_CANDIDATES.append(_pw)
            _seen.add(_pw)
del _seen, _pw_list, _pw  # type: ignore[name-defined]

# 성능 상한
MAX_CANDIDATES: int = 400
MAX_ACCOUNTS: int = 200

# 상한 적용
_ALL_CANDIDATES = _ALL_CANDIDATES[:MAX_CANDIDATES]


def candidates_for_account(account_name: str) -> list[str]:
    """계정명에 최적화된 후보 리스트 반환 (계정 기본비번 우선 + 공통 목록).

    순서: 계정 기본비번(계정명 소문자 exact + 전체 ACCOUNT_DEFAULT_PASSWORDS) 먼저,
    이후 공통 목록. 중복 제거 + MAX_CANDIDATES 상한.
    """
    seen: set[str] = set()
    result: list[str] = []

    def _add(pw: str) -> None:
        if pw not in seen and len(result) < MAX_CANDIDATES:
            seen.add(pw)
            result.append(pw)

    # 1. 계정명 자체 소문자 → 기본비번 후보
    lower_name = account_name.lower()
    for pw in ACCOUNT_DEFAULT_PASSWORDS.get(lower_name, []):
        _add(pw)

    # 2. 공통 약한 비번
    for pw in COMMON_WEAK_PASSWORDS:
        if len(result) >= MAX_CANDIDATES:
            break
        _add(pw)

    # 3. 나머지 ACCOUNT_DEFAULT_PASSWORDS 전체 (다른 계정의 기본비번도 공통 사전에 포함)
    for pw_list in ACCOUNT_DEFAULT_PASSWORDS.values():
        if len(result) >= MAX_CANDIDATES:
            break
        for pw in pw_list:
            if len(result) >= MAX_CANDIDATES:
                break
            _add(pw)

    return result

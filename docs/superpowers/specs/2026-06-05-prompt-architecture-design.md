# LLM 판정 프롬프트 아키텍처 설계

> 작성일: 2026-06-05  
> 근거: 클라우드 AWS + DB(MySQL·Oracle·MS-SQL·MariaDB·PostgreSQL) 실험 결과

---

## 1. 현황 및 문제 진단

### 1-1. 현재 구조

```
SYSTEM_PROMPT (단일 전역)
  ├─ 기본 판정 원칙
  ├─ 태그 무시 지시
  ├─ few-shot: 환경변수 (클라우드 특화)
  ├─ few-shot: 계정 이름 (MySQL 형식 기준)
  └─ few-shot: 숫자 설정값 (MySQL 형식 기준)
```

### 1-2. 실험 결과 요약

| DBMS | 30b Opus 일치율 | 상태 |
|------|----------------|------|
| MySQL RDS | **100%** (16/16) | 프롬프트 튜닝 완료 |
| PostgreSQL RDS | 86% (12/14) | |
| PostgreSQL Aurora | 79% (11/14) | |
| MariaDB RDS | 76% (13/17) | |
| MS-SQL RDS | 71% (10/14) | |
| Oracle RDS | 63% (12/19) | |
| PostgreSQL Azure | 64% (9/14) | |
| 클라우드 AWS | 83% (15/18, Opus 기준) | |

결정성: **전 모델·전 DBMS 100%** (temperature=0 효과)

### 1-3. 불일치 항목 분류

전체 25건 불일치를 원인별로 분류:

#### [A] 인터뷰 확인 항목 과단정 — 18건 (72%)
> MySQL few-shot 반영 후에도 다른 DBMS에서 재발

| 항목 | 발생 DBMS | 30b 오류 방향 | 근거 |
|------|---------|-------------|------|
| DBM-004 | Oracle·MS-SQL·MariaDB·PG | 취약/양호 → 보류 | 관리자 권한 존재 자체를 취약 단정. 판단기준: "인터뷰로 업무 필요성 확인" |
| DBM-024 | MariaDB·MS-SQL·PG | 취약/양호 → 보류 | GRANT OPTION 존재를 불필요하다고 단정. 판단기준: "운영상 불필요한지 인터뷰 확인" |
| DBM-028 | Oracle·PG×2 | 취약/양호 → 보류 | 오브젝트 존재를 불필요하다고 단정 |
| DBM-017 | Oracle | 취약 → 보류 | 동일 패턴 |
| DBM-015 | MS-SQL | 취약 → 보류 | PUBLIC 기본 권한을 불필요한 권한으로 단정 |
| DBM-003 | PG Aurora | 양호 → 보류 | 불필요 계정 없다고 단정, 인터뷰 확인 필요 |
| DBM-020 | MariaDB | 양호 → 보류 | 계정 분리 됐다고 단정 |
| DBM-001 | MariaDB | 취약 → 보류 | 빈 AUTHENTICATION_STRING을 취약으로 단정(rdsadmin 내장계정) |

**원인: MySQL 형식(`GRANTEE`, `PRIVILEGE_TYPE`)에 맞춰 쓰인 few-shot이 Oracle(`grantee`, `granted_role`), PG(`rolsuper`, `rolcreatedb`) 등 다른 증거 형식에서 패턴 매칭 실패**

#### [B] 단위/해석 오류 — 3건 (12%)

| 항목 | DBMS | 오류 내용 |
|------|------|---------|
| DBM-009 | PG RDS | `idle_in_transaction_session_timeout=100` → 100초로 오해(실제 단위: ms) |
| DBM-006 | Oracle | `PASSWORD_LOCK_TIME=UNLIMITED` → 취약 오판(실제: 무기한 잠금 = 더 강한 보안) |
| DBM-030 | Oracle | RDSADMIN의 AUD$ DELETE 권한 → 일반 사용자 권한으로 오판 |

**원인: 스크립트 출력에 단위·맥락 정보 없음. 모델이 DBMS별 파라미터 의미를 모름**

#### [C] PUBLIC 권한 세부 검토 오류 — 2건 (8%)

| 항목 | DBMS | 오류 |
|------|------|------|
| DBM-015 | PG Aurora·Azure | `pg_settings`에 UPDATE 권한 존재 놓침(30b=양호, Opus=취약) |

**원인: SELECT가 아닌 UPDATE 권한을 구분 못함. 권한 세부 내용을 깊이 읽지 않음**

#### [D] 외부 지식 필요 — 2건 (8%)

| 항목 | DBMS | 내용 |
|------|------|------|
| DBM-016 | Oracle·MS-SQL | 패치 날짜가 몇 달 지났는지 판단 (EOL/최신 여부) |

**원인: 벤더별 패치 릴리즈 사이클 지식 필요. 로컬 LLM 한계, 해결 불가**

---

## 1-4. 추가 통찰 — "사람이 개입해야 하는 항목"

**판단기준 자체가 "업무상 불필요 여부"를 핵심 조건으로 두는 항목은
어떤 기술 증거가 와도 LLM이 판단할 수 없다.**

### 자동 판단보류 대상 항목 (전 DBMS 공통)

| 항목 | 내용 | 자동보류 이유 |
|------|------|-------------|
| **DBM-003** | 불필요 계정 존재 | "업무상 불필요한 계정인지" = 담당자만 앎 |
| **DBM-004** | 불필요 관리자 권한 | "업무상 불필요하게 부여됐는지" = 담당자만 앎 |
| **DBM-017** | 불필요 시스템 테이블 권한 | "업무상 불필요한 접근 권한인지" = 담당자만 앎 |
| **DBM-024** | WITH GRANT OPTION | "운영상 불필요한지" = 담당자만 앎 |
| **DBM-028** | 불필요 DB Object | "업무상 불필요한지" = 담당자만 앎 |
| DBM-015 | PUBLIC 불필요 권한 (Oracle·MS-SQL·PG) | "업무상 불필요한 권한인지" = 담당자만 앎 |
| PISM-023 | 불필요 가상자원 (클라우드) | "업무상 불필요한 자원인지" = 담당자만 앎 |

### LLM 호출 절감 효과

| DBMS | 자동보류/전체 | 절감율 |
|------|------------|--------|
| MySQL | 5/16 | **31%** |
| Oracle | 6/19 | **32%** |
| MS-SQL | 6/14 | **43%** |
| MariaDB | 5/17 | **29%** |
| PostgreSQL | 6/14 | **43%** |
| 클라우드 | 3/22 | **14%** |

### 구현 방법

`Criterion` 모델에 `auto_deferred: bool` 필드 추가.  
판단기준(standard) 텍스트에 "업무상 불필요"/"운영상 불필요"/"인터뷰하여" 포함 시 `True`.

```python
# judge_tool/models.py
@dataclass
class Criterion:
    ...
    auto_deferred: bool = False  # True면 LLM 호출 없이 자동 판단보류

# judge_tool/criteria_loader.py — 로딩 시 자동 감지
AUTO_DEFERRED_KW = ["업무상 불필요", "업무상 필요", "운영상 불필요", "인터뷰하여"]

def _is_auto_deferred(standard: str) -> bool:
    return any(kw in standard for kw in AUTO_DEFERRED_KW)
```

```python
# judge_tool/main.py — _judge_one 호출 전 체크
if crit.auto_deferred:
    judgments.append(Judgment(
        item_id=item_id, verdict="판단보류", confidence=1.0,
        rationale="판단기준이 담당자 인터뷰를 통한 업무 필요성 확인을 요구합니다. 기술 증거만으로 판정 불가.",
        cited_evidence=[], needs_review=True, ...
    ))
    continue  # LLM 호출 건너뜀
```

**이 변경으로:**
- LLM 호출 29~43% 절감
- 30b의 잘못된 취약/양호 판정 원천 차단
- 평가자가 인터뷰로 확인해야 할 항목 명확히 표시

---

## 2. 설계 방향

### 2-1. 핵심 원칙

> **문제 유형에 따라 해결 레이어를 분리한다.**  
> 프롬프트(LLM)로 해결할 것과 코드로 해결할 것을 명확히 구분.

```
[A] 인터뷰 확인 항목    → 프롬프트: DBMS별 SYSTEM_PROMPT 분리
[B] 단위/맥락 오류      → 코드: Profile.known_units + evidence 주석
[C] PUBLIC 권한 오류    → 프롬프트: DBMS별 예시 (PG 전용)
[D] 외부 지식           → 수용(한계로 문서화, 해결 불가)
```

### 2-2. 원칙 추상화 vs DBMS별 예시

**DBMS별 예시가 더 맞다.** 근거:

- [A] 유형 불일치 18건 중 13건은 "원칙은 맞는데 증거 형식이 달라 적용 실패"
- 추상 원칙("관리자 권한 → 인터뷰 확인")은 이미 있음에도 재발
- 모델이 `PRIVILEGE_TYPE=ALTER` (MySQL)과 `rolsuper=t` (PG)를 동일 패턴으로 연결 못함
- **DBMS별 증거 형식에 맞는 구체적 예시가 필요**

단, 모든 것을 단일 SYSTEM_PROMPT에 넣으면:
- 토큰 낭비 (관계없는 DBMS 예시 포함)
- 예시 간 충돌·혼동 가능성
- 관리 복잡도 증가

→ **Profile별로 다른 SYSTEM_PROMPT를 사용하는 구조**

---

## 3. 구체적 설계

### 3-1. Profile별 SYSTEM_PROMPT 분리

```python
# judge_tool/prompts.py (신규)

BASE_PROMPT = """
당신은 전자금융기반시설 보안 취약점 평가자다.
[공통 원칙]
- 판단기준과 증거만 근거로 판정
- 추측 금지, 증거에 없는 사실 지어내기 금지
- '[bad]/[good]/[info]' 태그는 예비 분류, 실제 값을 직접 대조
- '[info]' + '인터뷰 확인' 지시 → 판단보류
- 관리자 권한/불필요 계정/오브젝트 존재 여부는 '업무 필요성 판단 = 인터뷰 확인' → 판단보류
- 숫자 설정값은 값의 존재가 아닌 크기를 기준과 대조
[출력] JSON만: {"verdict":..., "confidence":..., "rationale":..., "cited_evidence":...}
"""

CLOUD_PROMPT = BASE_PROMPT + """
[클라우드 환경변수 예시]
• PASSWORD_LENGTH=32 → 설정값, 민감정보 아님
• enc=AQICAH... → KMS 암호문, 이미 암호화
• DB_PASSWORD=MyP@ssw0rd! → 평문 비밀번호, 민감정보
"""

DB_MYSQL_PROMPT = BASE_PROMPT + """
[MySQL/MariaDB 판단 예시]
• PRIVILEGE_TYPE=ALTER 등 Global 권한 보유 → 업무상 필요 여부 인터뷰 확인 → 판단보류
• IS_GRANTABLE=YES 권한 존재 → 운영상 불필요한지 인터뷰 확인 → 판단보류
• wait_timeout=28800(s) > 900s(기준 15분) → 설정 존재≠기준 충족 → 취약
• default_password_lifetime=90 → 분기(90일) 1회 강제 설정 = 기준 충족 → 양호
• AUTHENTICATION_STRING이 비어있어도 auth_socket/unix_socket 인증 계정은 취약 아님
"""

DB_ORACLE_PROMPT = BASE_PROMPT + """
[Oracle 판단 예시]
• dba_role_privs에 DBA role 부여 계정 존재 → 업무상 필요 여부 인터뷰 확인 → 판단보류
• dba_tab_privs에 DBA_* 시스템 테이블 접근 권한 → 인터뷰 확인 → 판단보류
• dba_objects에 알 수 없는 계정 오브젝트 존재 → 인터뷰 확인 → 판단보류
• PASSWORD_LOCK_TIME=UNLIMITED → 무기한 잠금(더 강한 보안), 취약 아님
• AUD$ 소유자=SYS + DELETE 권한자=RDSADMIN/관리자 → 관리자 계정만 보유 → 양호
• ADMIN_OPTION=YES → 인터뷰 확인 → 판단보류
"""

DB_MSSQL_PROMPT = BASE_PROMPT + """
[MS-SQL 판단 예시]
• sysadmin=1인 계정: rdsa/NT AUTHORITY\\SYSTEM/NT SERVICE\\* → RDS/OS 내장 시스템 계정, 업무 필요 여부 인터뷰 확인 → 판단보류
• PUBLIC에 VIEW ANY DATABASE + 기본 엔드포인트 CONNECT → SQL Server 기본 부여 표준 권한 → 판단보류(업무 필요성 확인 필요)
• msdb의 rds_backup/restore_database 등 WITH GRANT OPTION → RDS 마스터 기본 제공 → 판단보류
"""

DB_POSTGRESQL_PROMPT = BASE_PROMPT + """
[PostgreSQL 판단 예시]
• rolsuper/rolcreatedb/rolcreaterole=t 계정 존재 → 업무상 필요 여부 인터뷰 확인 → 판단보류
• passwordcheck.so 미로드 → PostgreSQL 전용 방법 외 Azure Entra/써드파티로도 복잡도 강제 가능, 확인 필요 → 판단보류
• shared_preload_libraries에 pgaudit 없음 → RDS/Azure 파라미터 그룹 별도 확인 필요 → 판단보류
• PUBLIC에 pg_catalog SELECT 외 UPDATE 등 쓰기 권한 → 과도한 권한 → 취약
• idle_in_transaction_session_timeout 단위=ms. 예: 100=100ms=0.1초 < 900,000ms(기준 15분) → 양호
• is_grantable=YES 권한: 운영상 불필요한지 인터뷰 확인 → 판단보류
"""
```

**Profile 매핑:**

```python
# judge_tool/profile.py
@dataclass(frozen=True)
class Profile:
    ...
    prompt_key: str = "base"  # "cloud" | "db_mysql" | "db_oracle" | "db_mssql" | "db_postgresql"
```

**OllamaClient/ClaudeCliClient 호출 시 profile.prompt_key로 SYSTEM_PROMPT 선택.**

### 3-2. Profile.known_units — 단위 자동 주석

```python
# judge_tool/profile.py
@dataclass(frozen=True)
class Profile:
    ...
    known_units: Dict[str, str] = field(default_factory=dict)
    # 예: {"idle_in_transaction_session_timeout": "ms", "connect_timeout": "s"}
```

```python
# judge_tool/judge.py — build_evidence_text 수정
def _annotate_units(evidence_dict: dict, known_units: dict) -> dict:
    """알려진 파라미터에 단위 주석 추가."""
    result = dict(evidence_dict)
    for k, v in result.items():
        param_name = (evidence_dict.get("VARIABLE_NAME") or
                      evidence_dict.get("name") or "").lower()
        if param_name in known_units:
            result["_unit"] = known_units[param_name]
    return result
```

**각 Profile 정의:**

```python
DB_POSTGRESQL = Profile(
    ...
    prompt_key="db_postgresql",
    known_units={
        "idle_in_transaction_session_timeout": "ms",
        "lock_timeout": "ms",
        "statement_timeout": "ms",
        "deadlock_timeout": "ms",
    },
)

DB_ORACLE = Profile(
    ...
    prompt_key="db_oracle",
    known_units={},  # Oracle은 단위가 파라미터별로 다르고 DBA_PROFILES에서 명시됨
)
```

### 3-3. DBMS별 기준선 문서

```
docs/superpowers/specs/
  ├─ 2026-06-05-model-baseline.md          # 클라우드(기존) + 개요
  ├─ 2026-06-05-model-baseline-db.md       # DB 분야 통합 (신규)
  └─ ...
```

DB 기준선 문서 구조:
- 전체 DBMS별 Opus 일치율 표
- 해결 불가 항목(외부지식 필요 — DBM-016)
- 프롬프트 개선 후 예상 일치율
- 분야별 권장 모델

---

## 4. 예상 효과

### 현재 vs 개선 후 예상 일치율

| DBMS | 현재 | 예상(개선 후) | 해결 불가 |
|------|------|------------|---------|
| MySQL | 100% | 100% | — |
| Oracle | 63% (12/19) | ~84% (16/19) | DBM-016(외부지식) |
| MS-SQL | 71% (10/14) | ~86% (12/14) | DBM-016(외부지식) |
| MariaDB | 76% (13/17) | ~94% (16/17) | — |
| PG RDS | 86% (12/14) | ~93% (13/14) | — |
| PG Aurora | 79% (11/14) | ~93% (13/14) | — |
| PG Azure | 64% (9/14) | ~86% (12/14) | — |

예상 근거:
- [A] 인터뷰 확인 항목(18건): DBMS별 예시로 ~80% 해결 가능 (MySQL 선례)
- [B] 단위 오류(3건): known_units로 100% 해결
- [C] PUBLIC 권한(2건): PG 예시(`pg_settings UPDATE`)로 해결
- [D] 외부 지식(2건): 해결 불가(문서화)

---

## 5. 구현 우선순위

| 단계 | 내용 | 난이도 | 예상 효과 |
|------|------|--------|---------|
| **1** | `prompts.py` 신규 — DBMS별 SYSTEM_PROMPT 5종 | 低 | 가장 큼(18건) |
| **2** | `Profile.prompt_key` 추가 + `judge.py` 연결 | 低 | — |
| **3** | `Profile.known_units` + `build_evidence_text` 단위 주석 | 中 | 3건 |
| **4** | PG PUBLIC 권한 예시 (prompts.py 내 포함) | 低 | 2건 |
| **5** | DBMS별 기준선 문서 작성 | 低 | 문서화 |

단계 1·2가 가장 크고 쉬움. 단계 3은 Profile API 변경 필요.

---

## 6. 한계 — 변경해도 해결 안 되는 것

| 항목 | 이유 | 대응 |
|------|------|------|
| DBM-016 (Oracle/MS-SQL 패치 최신 여부) | 벤더 릴리즈 사이클 외부 지식 | 보류로 문서화 — 평가자 직접 판단 |
| 클라우드 PISM-025 (Lambda 런타임 EOL) | AWS EOL 날짜 외부 지식 | 동일 |
| 클라우드 방화벽 복합 정책 | 실험 데이터 없음 | 별도 테스트 필요 |
| 14b·7b DBMS별 예시 적용 | 모델 크기 한계(in-context reasoning) | 30b 이상 권장 |

---

## 7. 검토 필요 사항

구현 전 결정이 필요한 항목:

1. **prompts.py 위치**: `judge_tool/prompts.py` 신규 vs `judge_tool/judge.py` 내부 상수로 유지
2. **Profile.known_units 범위**: PostgreSQL만 우선? 전 DBMS 동시?
3. **ClaudeCliClient prompt 전달 방식**: `--system-prompt` 플래그가 있는지 확인 필요
   - 없으면 현재처럼 `<system>...</system>` 태그로 user 메시지에 포함

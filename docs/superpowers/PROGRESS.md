# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-08. 다음 세션에서 이 파일부터 읽고 이어서 진행할 것.

## 무엇을 만들고 있나
클라우드(AWS/Azure) + DB(MySQL·Oracle·MS-SQL·MariaDB·PostgreSQL) 점검 결과를
로컬 LLM(Ollama)이 PISM 항목별로 자동 판정하는 CLI 도구 `judge_tool`.

- 설계(spec): `docs/superpowers/specs/2026-06-01-llm-judgment-tool-design.md`
- 프롬프트 아키텍처 설계: `docs/superpowers/specs/2026-06-05-prompt-architecture-design.md`
- 항목별 라벨 YAML: `judge_tool/item_configs/` (6개 프로파일)
- 모델 기준선: `docs/superpowers/specs/2026-06-05-model-baseline.md`

---

## 2026-06-08 현재 상태

### 완료된 것

| 항목 | 내용 |
|------|------|
| 클라우드 AWS 구현 | Task 0~10 완료, 스모크 통과 |
| DB MySQL 구현 | Phase-2 완료, 스모크 통과 |
| DB 나머지 프로파일 | Oracle·MS-SQL·MariaDB·PostgreSQL 프로파일 추가 |
| 모델 실험 | 30b/14b/7b ×3회 결정성 100%, Opus 절대비교 완료 |
| 프롬프트 개선 | few-shot v4 — MySQL 기준 30b Opus 완전 일치(16/16) |
| DBMS 전체 스모크 | Oracle·MS-SQL·MariaDB·PostgreSQL×3환경 통과 |
| 모델 기준선 문서 | `2026-06-05-model-baseline.md` — 방화벽 정책 한계 명시 |
| 아키텍처 설계 | `2026-06-05-prompt-architecture-design.md` |
| A/B/C/D 라벨 체계 구현 | Phase-3 Step 1~3 완료 (136 tests, 3 commits) |

### Phase-3 Step 1~3 완료 내용 (2026-06-08)

| Step | 내용 |
|------|------|
| Step 1 | YAML A/B → A/B/C/D 확장. DBM-001→C, DBM-016/025→D, DBM-020→B, DBM-008 PG→variants |
| Step 2 | criteria_loader variants 오버라이드. db_postgresql DBM-008: default=A, pg_azure=B |
| Step 3 | B항목 summary 품질 개선. SUMMARY_SYSTEM_PROMPT 텍스트 강제. empty_means_good+B 충돌 해결 |

**라벨별 항목 수 (전 DBMS 합계 기준):**
- A: 기술 판정 — 대부분
- B: 인터뷰 필요 — DBM-003·004·017·020·024·028 (전 DBMS), DBM-015(Oracle/MSSQL/PG), PISM-023·045
- C: 기술 한계 — DBM-001(MySQL/Oracle/MariaDB)
- D: 외부지식 — DBM-016·025(전 DBMS)

### 현재 실험 결과 요약

**모델별 권장:**
- 최종 산출물: `claude-opus-4-8` (Anthropic API, ClaudeCliClient)
- 로컬 운영: `qwen3-coder:30b` (MySQL 100% Opus 일치, 외부지식 제외)
- 로컬 확인용: `qwen2.5-coder:7b` (클라우드 30b 100% 일치, 빠름)

**DBMS별 30b Opus 일치율 (프롬프트 v4, 외부지식 제외):**
- MySQL: 100% ✅
- PostgreSQL RDS: 86%, Aurora: 79%, Azure: 64%
- MariaDB: 76%
- MS-SQL: 71%
- Oracle: 63%

---

## 다음에 할 일 (정확한 재개 지점)

### Phase-3: Step 4~5 (Step 1~3 완료)

#### Step 1~3. ✅ 완료 (2026-06-08)

#### Step 4. (구현 완료) 재실험 — 개선 효과 검증

Step 1~3 코드가 이미 구현됨. 남은 것은:
- 전 DBMS × 3회 재실험 → C/D항목 LLM 절약 확인, B항목 요약 품질 확인
- 특히 30b 모델 기준으로 기존 오류 항목(DBM-009 단위, DBM-001 해시 등) 개선 여부

#### Step 4-실험. 전 DBMS 재실험 (다음 세션 시작 시 진행)

현재 `A/B` 2가지 라벨의 문제점이 발견됨:

```
현재: A(기술판정) / B(인터뷰필요)
필요: A(기술판정) / B(인터뷰필요) / C(기술한계) / D(외부지식필요)
```

| 새 라벨 | 해당 항목 | 처리 방법 |
|--------|---------|---------|
| A | DBM-006·007·009 등 | LLM 판정 (현행) |
| B | DBM-003·004·017·020·024·028 | LLM 증거 요약 + verdict=판단보류 고정 |
| C | DBM-001 (해시크랙 불가) | 자동 판단보류 + "비밀번호 해시 확인됨" 메시지 |
| D | DBM-016·025 (EOL/패치 외부지식) | 자동 판단보류 + 버전 정보만 출력 |

**수정 필요 항목:**
- DBM-020: 전 DBMS → A→B (인터뷰 필요인데 A로 잘못 분류됨)
- DBM-001: 전 DBMS → A→C (해시 복잡도 판단 불가)
- DBM-008 PostgreSQL: A→B (마스킹된 날짜값, 판단 불가)
- DBM-016: 전 DBMS → A→D (외부지식 필요)
- DBM-025: 전 DBMS → A→D (외부지식 필요)
- empty_means_good 항목(DBM-017·024 MySQL 등): B→A 분기 필요 (빈결과=양호)

#### Step 2. Variant별 세분화 (설계 필요)

현재 YAML은 프로파일 단위(db_mysql 전체). 실제로는 variant별 차이 있음:
- DBM-008: MySQL=A / PostgreSQL=B
- DBM-011: RDS variant → NOTE 자동보류 / 온프렘 → 기술판정

YAML 구조 변경안:
```yaml
DBM-008:
  default: A
  variants:
    pg_azure: B
```

#### Step 3. B항목 summary_instruction 검증 (가장 중요)

각 B 항목의 실제 증거를 보고 LLM 요약 지시 품질 검증:
- 항목별 실제 증거 샘플 → LLM 요약 테스트
- 평가자가 인터뷰에서 쓸 수 있는 수준인지 확인
- 필요시 summary_instruction 수정

현재 summary_instruction 검토 필요 항목:
- DBM-028 (Oracle/PG): 증거 형식이 다름
- PISM-045: 클라우드 관리체계 항목, 스크립트 증거 없을 수 있음
- DBM-017, DBM-024 MySQL: 빈 결과 케이스 미처리

#### Step 4-실험. 전 DBMS 재실험 스크립트
```bash
# MySQL 기준 재실험 (3회, 30b 모델)
python3 scripts/db_mysql_model_experiment.py

# 이후 Oracle·MS-SQL·MariaDB·PostgreSQL 순서로
python3 scripts/db_all_model_compare.py
```

#### Step 5. Azure 클라우드 (별도)

- `results/Public Cloud/azure_report_20251121.xml` 손상(894행, `<Evidence>` 미닫힘)
- 손상 범위 파악 후 관대파서 개발 필요

---

## 핵심 설계 계약 (재개 시 확인)

- **auto_deferred 판별**: `standard`에 "업무상 불필요"/"운영상 불필요"/"인터뷰하여" 포함 시
- **empty_means_good 우선**: 빈 증거=양호 항목(DBM-017·024·028 등)은 B 라벨보다 empty_means_good이 우선
- **B항목 처리**: verdict=판단보류 고정, LLM은 summary_instruction으로 증거 요약만
- **results/ 쓰기 금지**: 실데이터 디렉터리, 절대 쓰기/삭제 금지
- **pip install 금지**: 시스템 python3 사용

## 실행 명령 (참고)
```bash
# 클라우드 AWS 판정
python3 -m judge_tool.main --report "results/Public Cloud/aws_report_20251223_hinno.xml" \
  --criteria "ref/...xlsx" --out-dir out --model "qwen3-coder:30b"

# DB MySQL 판정
python3 -m judge_tool.main --report "results/DB/MySQL/mysql_result_rds.txt" \
  --criteria "ref/...xlsx" --profile db_mysql --out-dir out --model "qwen3-coder:30b"

# 테스트
python3 -m pytest -q
```

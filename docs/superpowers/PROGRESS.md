# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-11. 다음 세션에서 이 파일부터 읽고 이어서 진행할 것.
> (한 작업단위 종료 시마다 이 파일 갱신 + 커밋/푸시. 토큰 중단돼도 pull 후 이어서 진행.)

## ▶ 다음 세션 즉시 시작점 (TL;DR)
- **로드맵 실행순서: ① → ③ → ④ → ② → ⑤ → ⑥** (아래 "도메인 로드맵" 참조)
- **완료**: 네이티브 DB 5종 변형 + Tibero 스텁 / **① 판단방식 5분류 정교화 + 디스패치 seam**
  (2026-06-11, 205 tests, Opus 리뷰 "병합 가능")
- **다음 착수 = ③ 서버(OS) 자동판정.** 첫 단계: 평가기준 "서버" 시트(106항목/5-OS변형
  AIX·HP-UX·LINUX·SOLARIS·WIN) 컬럼 매핑 조사 → 수집 결과 포맷 확보(현재 샘플 없음)
  → `server` Profile + 파서 + item_configs 라벨. evidence_mode="raw" 재사용.
- 작업 브랜치: `feat/native-db-variants` (네이티브 DB + 판단방식 정교화 누적 커밋).
- **검토/계획 에이전트는 Opus 사용** (사용자 지정).

## 도메인 로드맵 (6개 + 실행순서, Fable 우선순위/아키텍처 리뷰 반영)
평가기준 xlsx에 6개 도메인 시트 모두 존재(기존 Profile/VariantSpec 패턴과 동형).
신규 도메인 추가 실비용 = 파서 1 + Profile 1 + item_configs 라벨. 병목은 코드가 아니라
**도메인별 수집 스크립트·골드라벨 데이터 확보**.

| 순 | 도메인 | 상태 | 데이터 | 비고 |
|---|---|---|---|---|
| ① | 판단방식 5분류 정교화(cloud/DB) | **완료** | - | 코어 분류체계, 후속 도메인 라벨 기반 |
| ③ | 서버(OS) 106항목/5변형 | 다음 | 기준O/샘플X | 최대 도메인. DB 네이티브 OS레벨 갭도 해소 |
| ④ | 네트워크 장비 45항목 | 대기 | 기준O/샘플X | config 텍스트 raw 판정(서버 패턴 이식) |
| ② | 방화벽 이상정책 탐지(정보보호시스템) | 대기 | **샘플O**(정책 20건) | 별도 결정론 엔진 + method 핸들러 등록(seam 위) |
| ⑤ | 컨테이너 가상화 50항목/10변형 | 대기 | 기준O/샘플X | kubectl/API 수집 |
| ⑥ | OS 가상화 35항목/3변형 | 대기 | 기준O/샘플X | ESXi 수집 폐쇄적 |

### ② 방화벽 설계 메모(착수 시)
- 정책테이블 집합연산·순서분석(그림자/중복·any-any·광역CIDR·미사용) = **별도 결정론 엔진**
  (`fw_policy.py`류, eol.py가 선례). LLM 대조 아님.
- 출력은 기존 harness 재사용: 탐지결과→`EvidenceItem.resources`→Judgment/writer.
- main.py `_HANDLERS`에 신규 method 핸들러 **등록만**(① seam 활용, elif 증식 없음).
- 자산목록 보조입력은 프로파일 한정 `--aux` 인자로 시작(일반화 금지/YAGNI).

## 판단방식 5분류 (① 결과, 정적 — judge_tool 코어 계약)
`classify_method()`(criteria_loader.py) 단일 출처. Excel '판단방식' 컬럼 + 요약시트 분포.
| method | 표기 | 규칙 |
|---|---|---|
| llm | LLM | label A, empty_means_good 아님 |
| llm_det | LLM+결정론 | label A ∩ empty_means_good (빈결과=양호 가드) |
| det | 결정론 | label C/D (canned·EOL/패치) |
| interview | 인터뷰(내용정리) | label B + summary_instruction |
| interview_holdonly | 인터뷰(내용정리X) | label B + summary_instruction 없음 (신규) |
- 정적 표기: 런타임 결정론 override(NOTE보류·빈결과양호·EOL폴백) 발동해도 설정값 유지
  → 실제 적용은 '판정'/'근거' 참조(요약시트 '판단방식 주석'에 명시).
- 디스패치: main.py `_HANDLERS`(method→핸들러), `JudgeContext`로 인자 통일.
- (e) interview_holdonly 현재 멤버: cloud PISM-045. 추가 지정은 도메인 판단으로 후속.

## 무엇을 만들고 있나
클라우드(AWS/Azure) + DB(MySQL·Oracle·MS-SQL·MariaDB·PostgreSQL) 점검 결과를
로컬 LLM(Ollama)이 PISM 항목별로 자동 판정하는 CLI 도구 `judge_tool`.

- 설계(spec): `docs/superpowers/specs/2026-06-01-llm-judgment-tool-design.md`
- 프롬프트 아키텍처 설계: `docs/superpowers/specs/2026-06-05-prompt-architecture-design.md`
- 항목별 라벨 YAML: `judge_tool/item_configs/` (6개 프로파일)
- 모델 기준선: `docs/superpowers/specs/2026-06-05-model-baseline.md`

---

## 2026-06-10 현재 상태

### 완료된 것 (누적)

| 항목 | 내용 |
|------|------|
| 클라우드 AWS 구현 | Task 0~10 완료, 스모크 통과 |
| DB 5종 프로파일 | MySQL·Oracle·MS-SQL·MariaDB·PostgreSQL(RDS/Aurora/Azure) |
| A/B/C/D 라벨 체계 | Phase-3 Step 1~3 + variant 오버라이드 + C/D 미증거 자동보류 |
| 결정성 검증 | temperature=0 → 3회 동일 판정 100% (2회 전수 실험으로 입증 종결) |
| 재실험 2회 (06-08) | 30b 전 DBMS. Opus A-일치: MySQL 100%, PG Azure 100%, 그 외 50~75% |
| 증거 미수집 가시화 | 보고서에 섹션 없는 판정대상 → '증거 미수집' 자동보류 행 출력 (06-10) |
| DBM-025 EOL 결정론화 | eol.yaml(endoflife.date 검증) + eol.py — LLM 없이 양호/취약 확정 (06-10) |
| B요약 견고성 | JSON 감지→산문 재요청→코드 평탄화 폴백, 타임아웃 축소 재시도 (06-10) |
| 설정 정리 | verdict_fixed 죽은 키 제거, 깨진 NOTE 방어, rationale 지시문 누출 제거 (06-10) |
| 네이티브 DB 5종 + Tibero 스텁 | oracle/mssql/mysql/mariadb/pg _native 변형, longest-match+모호성 가드, DB_TIBERO(excluded), --variant, DBM-001 라벨버그 수정 (06-11, Fable리뷰 반영) |
| ① 판단방식 5분류 정교화 | judgment_method(llm/llm_det/det/interview/interview_holdonly), classify_method 단일출처, main.py 디스패치 레지스트리+JudgeContext seam, (e) holdonly(PISM-045), writer 판단방식 컬럼/분포 (06-11, Opus리뷰 "병합가능") |
| 테스트 | 205 passed (+판단방식/네이티브/eol 네이티브분기 등 신규) |

### 2026-06-10 비판적 리뷰에서 확정된 사실 (재개 시 꼭 알아야 함)

1. **Opus 일치율 지표는 순환 구조** — 불일치 항목을 B/C로 빼면 분모가 줄어
   일치율이 기계적으로 오름(PG Azure 100% = 3/3). Opus 자체도 미검증 기준선
   (MSSQL DBM-007은 30b=취약이 맞아 보임). **골드라벨 확보 전까지 이 지표로
   라벨 변경을 정당화하지 말 것.**
2. **점검 스크립트 수집 갭 (도구 밖 문제)**: 평가기준 'o' 대상인데 증거 미수집 —
   PG: DBM-005(암호화)·006·019 / MSSQL: DBM-013·019·035(xp_cmdshell)·036 /
   Oracle: DBM-013. 이제 산출물에 '증거 미수집' 행으로 보임.
3. **MariaDB 원본 결과 파일의 NOTE 한글이 수집 단계에서 소실**('??') —
   도구는 대체 문구로 방어, 근본 해결은 수집 스크립트 인코딩 수정 + 재수집.

---

## 세부 백로그 (도메인 작업과 병행 가능 — 위 "도메인 로드맵"이 최상위 순서)

> 아래는 cloud/DB 품질 심화 과제. 도메인 확장(③~⑥)과 별개로 골드라벨이 확보되면 진행.

### 1. 골드라벨 어드주디케이션 (사용자 입력 필요)
2026-06-10 세션에서 22개 항목 × 7케이스 전체 표(판단기준+증거요약+판정근거)를
사용자에게 제공함. 사용자가 항목별 정답(양호/취약/판단보류/라벨적정성)을 주면:
- `docs/superpowers/specs/gold_labels.yaml` 로 저장
- 재실험 스크립트의 비교 기준을 Opus → 골드라벨로 전환 (분모 고정)
- 남은 불일치(DBM-006/007/008 MSSQL, DBM-009 Oracle/MariaDB 등) 라벨 확정

### 2. known_units 구현 (DBM-009 불일치의 직접 원인)
- Oracle IDLE_TIME=15(분), MariaDB wait_timeout=900(초) 등 파라미터 단위 주석
- Profile.known_units + build_evidence_text_raw에 단위 표기 주입
- DBM-009 기준의 임계값 해석(이하/미만)도 기준 xlsx 원문으로 확정할 것

### 3. B요약 품질 측정 (재실험 결과 확인)
- 06-10 재실험에서 JSON 평탄화/재요청 효과 확인 (요약이 산문이 됐는지)
- 요약이 증거 전체를 커버하는지 검증 로직(행 수 대비) — 미구현 과제
- PG Aurora DBM-003류 "첫 행만 요약" 문제 원인 추적

### 4. DBMS별 SYSTEM_PROMPT 분리 (judge_tool/prompts.py)
- MSSQL is_policy_checked 의미(복잡도+잠금 동시 제어) 등 DBMS 지식 주입
- 설계 문서: 2026-06-05-prompt-architecture-design.md

### 5. 수집 스크립트 보완 요청 (도구 외부 — 담당자 전달)
- PG: DBM-005/006/019 수집 추가, MSSQL: DBM-013/019/035/036 추가, Oracle: DBM-013
- MariaDB 결과 저장 인코딩 UTF-8로 수정 + 재수집 (NOTE 한글 소실)
- MySQL NOTE 오타("퍼블랙 액세스 허") 수정

### 6. DBM-016 보안패치 절반 자동화 (eol.yaml 패턴 확장)
- 각 시리즈의 최신 마이너 버전 테이블 추가 → "현재 버전 < 최신" 비교로
  '패치 누락 후보' 표시 (완전 판정은 불가, 후보 표시까지만)

### 7. Azure 클라우드 손상 XML 관대파서 (기존 보류 과제)
- `results/Public Cloud/azure_report_20251121.xml` 894행 `<Evidence>` 미닫힘

### 8. 방화벽 정책 재검증 (기존 보류 과제)

---

## 핵심 설계 계약 (재개 시 확인)

- **판단방식 라우팅(①이후)**: main.py `_HANDLERS`(judgment_method→핸들러) 디스패치.
  llm/llm_det→_judge_one, interview/interview_holdonly→_summarize_one, det→_defer_or_eol.
  (구 라벨 A/B/C/D는 유지되나 라우팅 키는 judgment_method. 신규 엔진은 _HANDLERS 등록.)
- **eol_check (D확장)**: DBM-025는 eol.yaml 대조 결정론 판정 먼저, 실패 시 자동보류
- **증거 미수집**: 판정대상인데 보고서에 섹션 없음 → '증거 미수집' 자동보류 행
  (empty_means_good 미적용 — 섹션 부재는 위반 0건이 아님)
- **empty_means_good 우선**: 빈 증거=양호 항목(DBM-017·024·028 등)은 B라벨보다 우선
- **eol.yaml 갱신 규칙**: as_of 명시, 분기 1회 endoflife.date 대조 (현재 2026-06-10)
- **results/ 쓰기 금지**: 실데이터 디렉터리, 절대 쓰기/삭제 금지
- **pip install 금지**: 시스템 python3 사용

## 실행 명령 (참고)
```bash
# 전 DBMS 재실험 (기본 1회, 결정성 스팟체크는 `... 3`)
python3 scripts/reexperiment_all.py

# DB MySQL 단건 판정
python3 -m judge_tool.main --report "results/DB/MySQL/mysql_result_rds.txt" \
  --criteria "ref/...xlsx" --profile db_mysql --out-dir out --model "qwen3-coder:30b"

# 테스트
python3 -m pytest -q
```

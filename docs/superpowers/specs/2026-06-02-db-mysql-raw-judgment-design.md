# 설계: Phase-2 DB(MySQL) 원시증거 LLM 판정

> 작성: 2026-06-02. brainstorming + 적대적 자기검토 1회 반영본.
> 1단계(클라우드 AWS) 설계: `2026-06-01-llm-judgment-tool-design.md` 의 후속.

## 1. 목표/맥락
`judge_tool`을 **데이터베이스(MySQL) 분야**로 확장한다. 클라우드(사전분류 XML)와 달리 DB 점검 결과는
**원시증거(raw)** — SQL 쿼리와 그 결과 행(row)뿐, good/bad status 사전분류가 없다. 따라서 스크립트 status와의
교차비교(reconcile)가 불가능하고 **LLM 단독 판정**이 된다. 본 확장은 spec §6.3의 "원시증거" 케이스를 실제 구현한다.

- 입력 예: `results/DB/MySQL/mysql_result_{rds,aurora,azure}.txt`
- 평가기준: 기존 xlsx의 **"데이터베이스" 시트**
- 1단계 코어(`models/profile/criteria_loader/judge/writer/main`)를 **최대 재사용**하고, DB 고유부분만 추가/일반화한다.

## 2. 범위 (YAGNI)
- **이번 구현: MySQL 3개 변형만** — `mysql_rds`, `mysql_aurora`, `mysql_azure` (실 샘플 보유).
- 제외(구조만 확장 가능하게 두되 미구현·미테스트): 일반 MYSQL(온프렘), PostgreSQL/Oracle/MS-SQL/MariaDB/Tibero, 조치방법(C59+) 컬럼.

## 3. 입력 파일 실태 (실측 기반 — 파서 설계의 근거)
`.txt` 3개를 직접 검증한 결과 **표준 JSON이 아니다.** 파서는 아래를 모두 견뎌야 한다:
- **최상위가 배열**: `[ {"DBM-001":{...}}, {"DBM-003":{...}}, ... ]` (단일키 객체들의 리스트). dict 아님.
- **트레일링 콤마** 다수(`,]`, `,}`).
- **문자열 값 내 raw 제어문자**(`\x01`,`\x07`,`\x11`,`\x15` 등)와 **불법 백슬래시 이스케이프** — 주로 비밀번호 해시 값.
- **선행 로그 라인**(azure): `[INFO] 탐지된 환경: Azure MySQL Flexible Server (State=3)` 가 배열 앞에 1줄.
- **항목 구조 불균질**:
  - 정상: `{"QUERY": "...", "RESULT": [ {row}, ... ]}`
  - **빈 RESULT**: `"RESULT": []` (DBM-016 등) — "증거 없음"이 아니라 "해당 결과 0건"이라는 의미일 수 있음.
  - **NOTE-only**: QUERY/RESULT 없이 `"NOTE": "..."` 만(DBM-019). NOTE 예: "관리형 DB면 N/A", "클라우드 관리체계 스크립트 참고", "써드파티 솔루션 확인 필요".
  - **RESULT 배열에 NOTE 혼입**: 행 dict들 사이에 `{"NOTE":"..."}` 또는 `"NOTE":"..."` 가 섞임.
  - **QUERY 플레이스홀더**: `"QUERY": "----"`.
- check_id 형식: `DBM-001`(하이픈·3자리). criteria 시트 id와 동일, `normalize_id` 통과.

## 4. "데이터베이스" 시트 컬럼맵 (열 번호; 실측)
- 공통: data_start_row=**5**, id=**2**, 평가항목명=**7**, 위험도=**8**, 상세설명=9.
- 평가대상(적용여부, 값은 소문자 `o` 또는 공란): MYSQL=16, **AWS RDS MYSQL=17**, **AWS Aurora MYSQL=18**, **Azure MYSQL=19**.
- 판단기준/판단방법: RDS=**37/38**, Aurora=**39/40**, Azure=**41/42** (MYSQL 일반=35/36).
- 판단기준 형식은 클라우드와 동일하게 `* 양호 - ... * 취약 - ...` 텍스트 → LLM 판정 근거로 사용.
- (주의: 본 문서의 숫자는 **열 인덱스**다. 스프레드시트 열문자로는 16=P,17=Q,18=R,19=S / 37=AK…42=AP.)

## 5. 핵심 설계 결정 (brainstorming 확정)
1. **LLM 단독 판정**: DB는 교차비교 대상(status)이 없다. `needs_review = verdict∈{취약,판단보류} OR confidence<0.6`.
   (클라우드와 달리 '취약'도 검토 트리거 — 교차검증이 없으므로 감사자 확인 필요.)
2. **변형=환경별**: rds/aurora/azure 각각 별도 variant, 각자 평가대상 컬럼의 `o`로 적용여부 결정.
3. **민감 해시 마스킹(존재 인지형)**: 해시류 값(AUTHENTICATION_STRING 등)은 **원문이 있었다는 사실을 인지할 수 있게** 마스킹한다.
   예: `"AUTHENTICATION_STRING": "<해시 존재: 마스킹됨, len=NN>"`. 구조 필드(plugin/account_locked/host/user/권한/존재여부)는 보존.
   해시 원문은 판정 이득이 없고(해시 크랙 전제) 유출 위험만 있으므로 프롬프트·출력 어디에도 원문을 넣지 않는다.
4. **raw 증거 전수 보존 + 높은 상한**: 행별 good/bad 분류가 없어 임의 절단 시 유일 위반행을 놓친다.
   기본 전수 보존, 아주 큰 경우(수백 행 초과)만 높은 문자 상한으로 잘라 `"M행 중 N행 표시, K행 생략"` 명시.
5. **QUERY·NOTE 보존**: `EvidenceItem`에 항목단위 `context` 필드(선택)를 추가해 QUERY와 NOTE를 담고, 프롬프트에 포함한다.
   NOTE의 "관리형DB N/A"/"외부솔루션 확인"은 판단보류 근거가 되므로 버리지 않는다.
6. **판정모드는 reconcile 재사용(플래그)**: judge_raw 신설 대신 `reconcile`에 정책 흡수.
   - `status_available=False`(DB): script_status=None, agreement="N/A", scope="전체", management_review_needed=False.
   - `flag_vulnerable_for_review=True`(DB): verdict==취약도 needs_review.
   - 기존 "무증거→판단보류", "expected None→needs_review" 동작은 그대로 유효.
7. **적용여부 일반화**: cloud는 eval_type(is_script_based), DB는 평가대상 `o`. 프로파일이 적용 판정 방식을 주입.
   **cloud 동작은 기존과 동치**임을 회귀 테스트로 못박는다(자동 보장 아님).
8. **직렬화 모드와 판정 모드 분리**: 한 플래그로 겸하지 않는다. `Profile.evidence_mode`("preclassified"|"raw")는 증거 직렬화만,
   판정모드(status_available 등)는 별개 프로파일 속성/플래그.

## 6. 컴포넌트
1. **`parsers/db_json.py`** (신규): 관대 DB 파서.
   - 선행 비-`[` 라인 스킵 → 배열 로드.
   - 살균: 트레일링콤마 제거, 문자열 값 내 raw 제어문자/불법 이스케이프 정규화(또는 안전 디코드).
   - 항목 5종 처리: 정상/빈RESULT/NOTE-only/QUERY="----"/RESULT내 NOTE혼입.
   - 출력: `[(check_id, [ResourceEvidence], context)]` 또는 EvidenceItem 직접 구성에 맞는 형태.
     각 RESULT 행 → `ResourceEvidence(resource_id=f"{check_id}#row{i}", status="", detail="", evidence=<마스킹된 행 JSON>)`.
   - QUERY·NOTE → 항목 `context`.
   - 손상 복구 불가 시 `ReportError`(기존 패턴, 민감값 미포함 메시지).
   - `parsers/__init__.py` 레지스트리에 `"db_json"` 등록.
2. **`profile.py`**: `DB_MYSQL` 프로파일.
   - sheet_name="데이터베이스", parser="db_json", data_start_row=5, id_col=2, name_col=7, risk_col=8.
   - `evidence_mode="raw"`, 판정모드 플래그(status_available=False 등) — 신규 필드는 **기본값**을 줘서 cloud Profile/VariantSpec 불변.
   - variants: mysql_rds(적용17·기준37·방법38), mysql_aurora(18/39/40), mysql_azure(19/41/42).
   - `variant_from_filename`: `mysql_result_rds.txt`→mysql_rds, `_aurora`→mysql_aurora, `_azure`→mysql_azure.
3. **`models.py`**: `EvidenceItem.context: Optional[str]=None`(QUERY/NOTE). `ResourceEvidence.status=""` 허용(이미 가능).
   적용여부 일반화를 위한 `Criterion.applicable`(loader가 계산) 또는 동등 메커니즘. is_judgeable=applicable AND standard.strip().
4. **`criteria_loader.py`**: 이미 profile/VariantSpec 기반. DB는 적용여부를 평가대상 `o`로 계산하도록 분기(프로파일 주입).
   cloud applicable=is_script_based(동치 유지).
5. **`judge.py`**:
   - `build_evidence_text` raw 모드: QUERY(context)+RESULT 전수(높은 상한)+필요시 생략표시. 마스킹은 파서 단계에서 이미 적용.
   - `build_prompt`: context(QUERY/NOTE) 포함. is_mixed=False라 scope_note 없음. standard/method 사용.
   - `reconcile`: 위 §5-6 플래그 흡수.
6. **`writer.py`**: 재사용. DB 판정행은 스크립트status/일치여부 컬럼이 공란/N/A(script_status=None 출력).
7. **`main.py`**: 재사용. run이 프로파일 속성에 따라 reconcile 인자(status_available 등) 결정. 흐름 동일.

## 7. 데이터 흐름
`db_json.parse(.txt)` → `aggregate`(DBM 정규화, 분할 없어 1:1 ≈ no-op) → 변형별 criteria join(평가대상 o & 판단기준 채워진 항목) →
`build_prompt`(QUERY/NOTE+raw행, 해시 마스킹) → `judge_item`(LLM 1회) → `reconcile`(status_available=False) → coverage → JSON/Excel.

## 8. 에러/안전
- 손상/비표준 `.txt` → `ReportError`로 명확 안내(민감값 미포함).
- `results/` 실데이터 읽기전용. 출력은 `out/`(gitignore).
- 민감 해시는 §5-3대로 마스킹 — 프롬프트·출력·로그·예외 어디에도 원문 미포함.
- 예외 메시지 비직렬화(기존 정책).

## 9. 테스트
- 합성 픽스처(민감정보 없음): `tests/fixtures/sample_db_mysql.txt` — 배열형, 트레일링콤마, 제어문자, 선행로그라인, 항목 5종(정상/빈RESULT/NOTE-only/QUERY=----/NOTE혼입), 가짜 해시.
- 합성 criteria xlsx(데이터베이스 시트 레이아웃, MySQL 변형 컬럼).
- 단위: db_json 파싱·살균·항목5종, 해시 마스킹(원문 부재+존재인지 마커), 적용여부 o 스킵, raw 전수보존/상한 생략표시, variant_from_filename, reconcile(status_available=False, 취약→needs_review), context 프롬프트 포함, ReportError(손상).
- **cloud 회귀**: 적용여부 일반화 후 cloud 판정/커버리지 동치 회귀 테스트.
- E2E(합성): db_json+합성criteria+StubClient → judged/needs_review/마스킹 검증, CI 독립.
- 실데이터 스모크(수동·선택): `results/DB/MySQL/*.txt` + `qwen3-coder:30b`, `--out-dir out`.

## 10. 알려진 한계(의도적)
- DB 항목 상당수는 원시증거만으로 판정 불가(해시 크랙 전제, "관리형DB N/A", "외부솔루션 확인") → **판단보류 다수 예상**. 도구가 사람 검토로 넘기는 정상 동작.
- mysql 일반/타 DBMS/Tibero는 컬럼맵만 추가하면 되나 이번 미구현.
- 빈 RESULT의 의미(0건=양호 vs 미수집)는 LLM+판단기준에 위임. 모호하면 판단보류.

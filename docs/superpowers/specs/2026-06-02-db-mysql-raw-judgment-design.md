# 설계: Phase-2 DB(MySQL) 원시증거 LLM 판정

> 작성 2026-06-02. brainstorming + opus 적대적 재검토 2회 + 사용자 결정(B-1~B-4) 반영본.
> 1단계(클라우드 AWS) 설계: `2026-06-01-llm-judgment-tool-design.md` 의 후속.

## 1. 목표/맥락
`judge_tool`을 **데이터베이스(MySQL) 분야**로 확장한다. 클라우드(사전분류 XML)와 달리 DB 점검 결과는
**원시증거(raw)** — SQL 쿼리와 결과 행(row)뿐, good/bad status 사전분류가 없다. 스크립트 status와의 교차비교가
불가능하므로 **LLM 단독 판정**이다(spec §6.3 원시증거 케이스의 실제 구현). 1단계 코어를 최대 재사용한다.

- 입력: `results/DB/MySQL/mysql_result_{rds,aurora,azure}.txt`
- 평가기준: 기존 xlsx의 **"데이터베이스" 시트**

## 2. 범위 (YAGNI)
- **이번 구현: MySQL 3개 변형만** — `mysql_rds`, `mysql_aurora`, `mysql_azure` (실 샘플 보유).
- 제외(구조만 확장 가능): 온프렘 일반 MYSQL(샘플 없음), PostgreSQL/Oracle/MS-SQL/MariaDB/Tibero, 조치방법(C59+) 컬럼.
  - **[B-6]** 온프렘 일반 MYSQL은 미포함. `mysql_result.txt`(환경접미사 없음)는 variant 미식별 → `ReportError`.

## 3. 입력 파일 실태 (실측 — 파서는 이 전부를 견뎌야 함)
3개 파일 직접 검증 결과 **표준 JSON 아님.** `json.load` 3개 전부 실패. **원소 단위 토큰 파싱**이 필수(표준 dict 로드 금지):
- 최상위 = **단일키 객체들의 배열** `[ {"DBM-001":{...}}, {"DBM-003":{...}}, ... ]`.
- **배열 원소 간 콤마 누락**(rds DBM-011 등): 배열 안에 bare 문자열과 `"키":"값"`이 콤마 없이 연달아 옴.
- **트레일링 콤마**(`,]`, `,}`).
- **문자열 값 내 raw 제어문자(`\x01` 등)·불법 백슬래시 이스케이프** — rds 한정, 전량 해시 값 내부.
- **선행 로그 라인**(azure만): 배열 앞 `[INFO] 탐지된 환경: ...` 1줄.
- **중복 JSON 키**: `DBM-028_3`이 한 파일에 2회(쿼리 항목 + `{"NOTE":"관리형DB N/A"}`). dict로 합치면 앞 값 유실 → **원소 순회로 둘 다 보존** 후 normalize.
- **항목 구조 6종**:
  1. 정상: `{"QUERY":"...","RESULT":[{row},...]}`
  2. 빈 RESULT: `"RESULT":[]`
  3. NOTE-only: `{"NOTE":"..."}` (QUERY/RESULT 없음)
  4. QUERY 플레이스홀더: `"QUERY":"----"`
  5. RESULT 내 혼입: 행 dict들 사이에 bare 문자열 / `"NOTE":"..."`
  6. **키만 있는 dict**: `{"DBM-022":{"설치형DB: ... , 그 외: ..."}}` (값 없는 단일 문자열 키)
- check_id: `DBM-001`(하이픈·3자리). **분할 인덱스 존재**(`DBM-008_1/_2`, `DBM-017_1~4`, `DBM-024_1~4`, `DBM-028_1~4`) → `normalize_id`로 base(DBM-008 등) 병합.

## 4. "데이터베이스" 시트 컬럼맵 (열 인덱스; 실측 확인)
- 공통: data_start_row=5, id=2, 평가항목명=7, 위험도=8, 상세설명=9.
- **DB 시트엔 cloud식 eval_type(스크립트/관리체계) 컬럼이 없다.** 평가기반(전자금융)=10, (주요정보)=11뿐.
  → 적용여부는 **평가대상 컬럼의 소문자 `o`** 로 판정(값은 `o`/공란 둘뿐, 실측).
- 평가대상(적용): MYSQL=16, **AWS RDS MYSQL=17, AWS Aurora MYSQL=18, Azure MYSQL=19**.
- 판단기준/판단방법: RDS=37/38, Aurora=39/40, Azure=41/42 (MYSQL일반=35/36). 형식 `* 양호 - ... * 취약 - ...`.

## 5. 핵심 설계 결정 (사용자 확정 포함)
1. **LLM 단독 판정**: 교차비교 없음. **needs_review = verdict∈{취약,판단보류} OR confidence<0.6.**
2. **변형=환경별**: rds/aurora/azure 별도 variant, 각자 평가대상 컬럼 `o`로 적용여부.
3. **[B-3] 민감값 마스킹 = 값 제거 + 길이/plugin 노출**:
   - 해시(AUTHENTICATION_STRING 등): `<REDACTED len=NN plugin=X>` 형태. 원문 미포함.
   - **평문 비밀번호(DBM-005 RESULT, COLUMN_NAME=password류)도 반드시 마스킹** — 키명이 아닌 **값/컬럼 휴리스틱**으로 탐지(예: COLUMN_NAME∈{password,passwd}의 값, 해시패턴). `<REDACTED 평문추정 len=NN>` + "평문 저장됨" 사실은 보존(DBM-005 판정에 필수).
   - 원문 해시·평문은 **프롬프트·출력 JSON/Excel·로그·예외 어디에도** 넣지 않는다.
4. **[B-4] 대용량 RESULT = 요약 + 원행**: 그룹 가능한 결과(예: GRANTEE/PRIVILEGE_TYPE)는 **계정별 권한집합 요약(무손실 재구성)** 을 context 상단에 병기하고, 그 뒤 **원행을 상한 내 전수**. `max_chars` 기본을 24000으로 상향(30B 32K 안전선). 그래도 초과 시 "M행 중 N행, K행 생략" 명시. 요약은 "행이 한 그룹키로 반복되는" 결과형에만 적용.
5. **[B-2] NOTE = 자동 판단보류 강제 + 사유기록**: 항목에 NOTE 존재 시 verdict=판단보류 강제, NOTE 원문을 rationale에 보존, needs_review=True. (실 NOTE 5종 전부 "기술점검 범위 밖/외부확인/N/A"로 확인됨.)
6. **[B-1] 빈 RESULT = 점검 스크립트 기반 항목별 정책** *(스크립트 `scripts/DB/MySQL/mysql_v251017.sql` 분석 완료)*:
   스크립트의 쿼리 의미를 분석해 항목별 empty-정책 테이블을 만든다. 세 부류:
   - **위반필터형**(위반행만 반환 — `WHERE ... NOT IN/NOT LIKE` 또는 `WHERE IS_GRANTABLE='YES'`): DBM-005, 017_1~4, 019, **024_1~4(IS_GRANTABLE 필터)**, 028_1~4. → empty_means_good base = {005,017,019,024,028}.
     → 빈 RESULT = **위반 0건 = 양호 신호.** 프롬프트에 "이 점검은 위반 0건"임을 명시, LLM이 판단기준으로 해석(이 항목엔 무증거→판단보류 강제를 적용하지 않음).
   - **상태/설정 조회형**: DBM-003,004,006,008_1/2,009,016,020,024_2~4,025,033. 빈 결과가 드물며, 값 자체를 LLM이 판정. 빈이면 판단보류.
   - **NOTE/명시메시지형**: 011·013(cloud 환경)은 NOTE 보유 → 판단보류(§5-5). 007·011은 빈 대신 `"...plugin is not loaded!"` bare 문자열을 RESULT에 넣음(= 취약 후보, 정상 증거로 취급).
   - 전체 DBM↔부류 매핑은 plan에서 스크립트 기준으로 확정(약 16개 판정대상).
7. **적용여부 일반화(기술)**: `VariantSpec`에 `applicability_col`(평가대상 열) 추가. DB applicable = `cell.strip().lower()=="o"`. cloud는 기존대로 eval_type/is_script_based에서 도출(applicable 동치). `Criterion.applicable` 필드를 loader가 채움. **is_judgeable = applicable AND standard.strip().** cloud 동치 회귀 테스트 필수.
8. **reconcile 시그니처 변경(기술, "플래그 흡수" 아님)**: `reconcile(llm, criterion, item, *, status_available=True, flag_vulnerable_for_review=False)`.
   - DB: status_available=False → script_status=None, agreement="N/A", scope="전체", management_review_needed=False.
   - flag_vulnerable_for_review=True → verdict==취약도 needs_review.
   - 기존 무증거→판단보류 강제는 §5-6의 empty-정책으로 항목별 제어(전역 강제 아님).
9. **증거직렬화 모드와 판정모드 분리**: `Profile.evidence_mode`("preclassified"|"raw")는 직렬화만. 판정모드(status_available 등)는 별개 프로파일 속성.

## 6. 컴포넌트
1. **`parsers/db_json.py`**(신규): §3 관대 파서. 선행 비-`[` 라인 스킵 → 배열을 **원소 단위로** 안전 파싱(콤마누락 분리, 트레일링콤마/제어문자/불법이스케이프 살균, 중복키·키only·NOTE혼입·bare문자열 처리). 출력: 항목별 `(check_id, [ResourceEvidence], context)`. 행→`ResourceEvidence(resource_id=f"{check_id}#row{i}", status="", detail="", evidence=<마스킹된 행>)`. bare 문자열 행→`detail`에. QUERY+NOTE→context. 복구불가→`ReportError`(민감값 미포함). `parsers/__init__.py`에 `"db_json"` 등록. **마스킹은 파서 단계에서 적용**(이후 단계로 원문 미유출).
2. **`profile.py`**: `DB_MYSQL` 프로파일. sheet="데이터베이스", parser="db_json", data_start=5,id=2,name=7,risk=8, evidence_mode="raw", status_available=False, flag_vulnerable_for_review=True(신규 필드 기본값으로 cloud 불변). variants: mysql_rds(적용17·기준37·방법38), mysql_aurora(18/39/40), mysql_azure(19/41/42). `variant_from_filename`: `_rds/_aurora/_azure`.
3. **`models.py`**: `EvidenceItem.context: Optional[str]=None`. `Criterion.applicable: bool`(loader 계산). is_judgeable=applicable AND standard.strip(). ResourceEvidence.status="" 허용(기존).
4. **`criteria_loader.py`**: 이미 profile/VariantSpec 기반. applicable 계산을 프로파일 방식대로 분기(DB=평가대상 o, cloud=is_script_based 동치).
5. **`mapper.py`**: `aggregate`가 파서의 context를 EvidenceItem.context로 전달(분할항목 context는 합치되 QUERY 우선·NOTE 보존). cloud 호출부 호환 유지(context 없으면 None).
6. **`judge.py`**: build_evidence_text raw 모드(§5-4 요약+원행, 마스킹은 파서가 이미 적용), build_prompt가 context 포함(is_mixed=False), reconcile 시그니처(§5-8). NOTE/empty 정책(§5-5/§5-6) 반영.
7. **`writer.py`**: 재사용. DB행은 스크립트status/일치 컬럼 공란(script_status=None).
8. **`main.py`**: run이 프로파일 속성으로 reconcile 인자 결정. 흐름 동일.

## 7. 데이터 흐름
`db_json.parse`(원소순회·살균·마스킹) → `aggregate`(분할 normalize, context 전달) → 변형별 criteria join(평가대상 o & 판단기준 채워짐) → build_prompt(context+요약/원행) → judge_item(LLM 1회) → reconcile(status_available=False, NOTE/empty 정책) → coverage → JSON/Excel.

## 8. 에러/안전·거버넌스
- 손상 `.txt` → `ReportError`(민감값 미포함).
- **[B-7]** 출력은 `out/`(gitignore). **DBM-005 평문·해시 원문은 출력에도 절대 미포함**(마스킹 후만). 산출물에 계정/내부IP 등 식별정보가 남으므로 **보관/삭제 책임 문서화**(README/PROGRESS에 명시). results/ 읽기전용.
- 예외 메시지 비직렬화(기존 정책).

## 9. 테스트
- 합성 픽스처(민감정보 없음) `tests/fixtures/sample_db_mysql.txt`: 배열형·콤마누락·트레일링콤마·제어문자·선행로그라인·중복키·항목6종·가짜해시/가짜평문.
- 합성 criteria xlsx(데이터베이스 레이아웃, MySQL 변형 컬럼, eval_type 컬럼 없음).
- 단위: 파서(원소순회·살균·6종·중복키), 마스킹(원문 부재 + 길이/plugin 노출 + 평문 휴리스틱), 적용여부 o 스킵, raw 요약+원행/상한 생략, NOTE 자동 판단보류+사유, empty 정책(테이블), reconcile(status_available=False·취약→needs_review), context 프롬프트 포함, ReportError(손상6종).
- **cloud 회귀**: 적용여부/ reconcile 시그니처 변경 후 cloud 판정·커버리지 동치.
- E2E(합성, CI독립): db_json+합성criteria+StubClient → judged/needs_review/마스킹 검증.
- **[B-5] 실데이터 스모크(수동)**: `results/DB/MySQL/*.txt`+`qwen3-coder:30b`, `--out-dir out`. **골든셋 사람 확인**: 알려진 취약(DBM-005 평문, 원격 %호스트 고권한 계정 DBM-004/013류, EOL DBM-025)을 최소 정성 검증.

## 10. coverage 실측 / 알려진 한계
- 변형별 판정대상(평가대상 o & 판단기준) 17개, 그중 증거 보유 join = **16개**. DBM-025(EOL)는 증거 없어 항상 missing. DBM-022는 not-judgeable(스킵).
- DB 항목 상당수는 원시증거만으로 판정 불가(해시 크랙 전제 DBM-001, NOTE류) → **판단보류 다수 예상**(정상 동작, 사람 검토로).
- 빈 RESULT 의미는 §5-6 스크립트 기반 테이블로 항목별 처리.

## 11. 입력 자료 (확보됨)
- **[B-1] 점검 스크립트 확보**: `scripts/DB/MySQL/mysql_v251017.sql`. §5-6 empty-정책을 이 스크립트의 쿼리 의미에서 도출(위반필터/상태조회/NOTE 3부류 분류 완료). plan에서 DBM별 매핑 테이블을 확정한다.
  - 참고: 스크립트는 환경(state 0~3: self/Aurora/RDS/Azure)을 자동탐지해 환경별 쿼리를 분기하고, 분할항목(017_1~4 등)을 별도 출력한다. 변형별 적용 차이가 여기서 비롯됨.
- 다른 DBMS 스크립트도 `scripts/DB/{PostgreSQL,Oracle,MS-SQL,MariaDB}/`에 존재(이번 범위 외).

# IMPL 스펙: DBM 분류 검토 Batch 1 (DBM-003~009 결정 반영)

작성: 2026-06-17. 사용자와 항목별 1:1 검토로 확정한 DBM-003~009 결정을 구현. **native 변형 한정**(클라우드 rds/aurora/azure는 기존 처리 유지 — 추후 재감사). 거짓판정 0·§7 불변.

## 확정 결정 요약
| 항목 | mysql | oracle | mssql | mariadb | pg(native) |
|---|---|---|---|---|---|
| 003 | DET(현행) | DET | DET | DET | STUB→LLM(현행) |
| 004 | **detect-then-hold** | hold | hold | hold | LLM(현행) |
| 005 | LLM | LLM | **DET→STUB(LLM)** | LLM | LLM |
| 006 | DET | DET | DET | DET | **구조적취약** |
| 007 | DET | DET | DET | **STUB→DET(복원)** | **구조적취약** |
| 008 | DET | DET | DET | DET | **STUB→DET(파서수정후)** |
| 009 | DET | DET | LLM(현행 STUB) | DET | **극성수정→DET** |

## 새 동작 모드 2개 (db.py)

### 모드 A — detect-then-hold (`_DETECT_THEN_HOLD = {"DBM-004"}`)
DBM-004는 결정론이 "관리자권한 보유 계정"을 탐지하되 업무필요성은 사람이 판단(label B 의도). 매핑 교체:
- `_filter_noise` 후 실위반(rows) ≥1 → **verdict="판단보류"**, ev_status="review", confidence=0.0(또는 0.5), handled=True, needs_review=True, **citations=후보 계정 목록**(rows 마스킹), rationale="결정론 탐지: 관리자권한 보유 계정 N건 — 업무상 필요성 사람 확인 필요".
- rows 0 → **verdict="양호"**(예외 외 관리자권한 계정 없음), handled=True.
- 증거가드/gate/R3는 기존대로 선적용. (base=="DBM-004"이고 위 분기.)

### 모드 B — 구조적 취약 (`_STRUCTURAL_VULN = {("DBM-006","pg_native"), ("DBM-007","pg_native")}`)
PostgreSQL 코어에 실패잠금/복잡도 네이티브 기능 부재 → 데이터 없이도 구조적 취약. gate 통과 후(아래 DET_SOURCE 변경) base/variant가 이 집합이면 **벤더 분석 호출 전** 반환:
- verdict="취약", ev_status="bad", confidence=0.9, handled=True, **needs_review=True**, rationale="PostgreSQL 코어에 네이티브 {실패잠금|복잡도강제} 기능 없음 — 외부모듈(passwordcheck 등)/RDS 파라미터로 보완 시 담당자 확인", citations=["PostgreSQL 네이티브 미지원"].
- (variant는 db.py가 받는 `variant` 인자로 판정 — 'pg_native'만. cloud는 이 집합에 없으므로 기존 경로.)

## DET_SOURCE.yaml 변경 (native 한정 — engine 토큰 'pg'는 pg_native에 적용, 클라우드 explicit 키는 유지)
- **DBM-005**: `mssql: DET` → `mssql: STUB` (전 엔진 STUB → 효과적 LLM).
- **DBM-007**: `mariadb: STUB` → `mariadb: DET`. `pg: STUB` → `pg: DET`(모드 B 라우팅용; 클라우드 pg_rds/aurora/azure 키는 기존 유지).
- **DBM-006**: `pg: STUB` → `pg: DET`(모드 B 라우팅용; 클라우드 키 유지).
- **DBM-008**: `pg: STUB` → `pg: DET`(파서수정 후 실로직 동작).
- **DBM-009**: `pg: STUB` → `pg: DET`(극성수정 후). `mssql`은 STUB 유지(LLM).
※ 클라우드 변형(pg_rds/aurora/azure 등) 분류는 이 배치에서 **변경 금지**(추후 재감사). 변경 후 Phase 4b 전수불변 검증(classify DET/STUB인데 cloud run() 미계산=0) 재실행해 깨지지 않음 확인.

## VENDOR-EDIT (bug) — pg dbm_009 극성 수정
`judge_tool/vendor/common/db/postgresql/analysis.py` `dbm_009`:
- 현재: `int(datum['value']) <= 900` → 취약 (거꾸로 — 300초=양호인데 취약 오판).
- 수정: `int(datum['value']) == 0 or int(datum['value']) > 900` → 취약 (비활성=0 또는 너무 김>900).
- `# VENDOR-EDIT(bug): DBM-009 극성 — KNOWN_BUGS §R-PG009` 주석. `KNOWN_BUGS.md`에 항목 추가(증상/수정/한계: idle_in_transaction_session_timeout만 커버, 일반 유휴세션은 PG14+ idle_session_timeout 별도).
- 단위검증: value=0→취약, value=300→양호, value=1000→취약, value=900→양호.

## db_json.py — pg 비표준 JSON 정규화 (고가치 레버)
pg 수집 행이 `{"rolname": 'x', "rolcanlogin": 'f', "rolvaliduntil": NULL}` (값 작은따옴표 + NULL 베어워드 = 비표준 JSON)이라 파서가 `{"*": "원문문자열"}`로 폴백 → 벤더 KeyError. 정규화 추가:
- pg RESULT 행 파싱 시: **작은따옴표 값 → 큰따옴표**, **`NULL`(베어워드) → `null`**, 그 후 json 파싱 시도. 성공 시 클린 dict로.
- **기존 동작 핀고정**: 정규화는 pg 형식(키는 큰따옴표인데 값만 작은따옴표/NULL)에만 적용. 정상 JSON·다른 엔진은 불변. 기존 db_json 테스트 전부 통과 + 마스킹 불변.
- 효과: pg DBM-008(rolvaliduntil) 등 dict-기반 pg 항목이 클린 dict로 파싱 → DET 동작.
- ⚠️ 부분 따옴표가 값 안에 등장하는 엣지(값에 `'` 포함)는 보수적으로(정규화 실패 시 기존 `{"*":}` 폴백 유지). 과도 정규화로 데이터 깨짐 금지.

## item_configs/db_*.yaml
- **db_mssql DBM-005**: det_common 유지해도 무방(DET_SOURCE STUB라 gate 차단→label A LLM). 명확성 위해 주석.
- **db_mariadb DBM-007**: `judgment_method: det_common` + `needs_review: true` 추가(현재 label A only).
- **db_postgresql**: DBM-006 `judgment_method: det_common` 추가(현재 label A). DBM-007 pg_native variant에 `judgment_method: det_common`(현재 native label A) — 단 클라우드 canned C 유지. DBM-008 pg_native `judgment_method: det_common`. DBM-009 이미 det_common.
- DBM-004: det_common+label B 유지(모드 A는 adapter에서).

## TODO 기록 (PROGRESS)
- **DBM-005 LLM 암호화 판정 품질 검증**(사용자 지정 "나중에 검증"): 골드라벨/실판정 대조.
- pg/mariadb 나머지 R3-STUB 항목(011/015/017/019/020/028 등)은 **항목별 검토 때 각각 재감사**(이 배치 미포함).

## 테스트
- 모드 A(DBM-004): 위반≥1→판단보류+citations(계정목록), 위반0→양호. mysql/oracle/mssql/mariadb.
- 모드 B(pg_native DBM-006/007): →취약+needs_review, rationale 구조적. pg cloud는 모드 B 아님(기존).
- pg dbm_009 극성: 0/300/900/1000 케이스.
- db_json pg 정규화: 작은따옴표/NULL 행 → 클린 dict; pg DBM-008 실데이터 → DET verdict(rolvaliduntil NULL+login → 취약). 정상JSON/타엔진 불변.
- mariadb DBM-007 실데이터 → DET(취약, not loaded).
- DBM-005 mssql → 더이상 자동취약 아님(LLM 경로).
- Phase 4b 전수불변 검증 재실행(클라우드 폴백 거짓양호 0).
- 회귀: 전체 pytest 통과.

## 검증
`python3 -m pytest tests/ -q` 전체 통과 + 5엔진 실데이터: DBM-004 판단보류+목록, pg DBM-006/007 취약(구조적), pg DBM-008 DET, mariadb DBM-007 DET, DBM-005 LLM경로, 거짓판정0, §7 평문비노출.

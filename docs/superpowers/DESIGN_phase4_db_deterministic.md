# DESIGN: Phase 4 DB(DBM) 결정론 통합

작성: Opus(Fable 불가 대체, PROGRESS 계약) / 2026-06-16
대상 코드(미작성): `judge_tool/det_adapters/db.py`, `judge_tool/vendor/common/db/*`, `DET_SOURCE.yaml` 확장, `judge_tool/parsers/db_json.py` 확장, `item_configs/db_*.yaml`

## 0. 요약

DB 도메인(엔진 5종 mysql/oracle/mssql/mariadb/postgresql, tibero excluded)을 Phase 1~3 검증
패턴으로 결정론 통합한다. 단 DB는 **클래스 기반·구조화 입력**이라 server/container의
"raw_output 문자열 → 단일 함수" 브리지와 근본적으로 다르다. 핵심 차이 4가지:

- (D1) 입력이 `raw_output:str`이 아니라 `data: {DBM-NNN(_suffix): {RESULT:[...], NOTE:..}}` dict.
- (D2) 판정 신호가 result='Y'/'N'/'M'이 아니라 **위반 리스트(빈=양호 / 비어있지않음=취약)**.
- (D3) "빈 리스트=양호"가 데이터 미수집·내부예외삼킴과 구분 불가 → **증거존재 가드가 server보다 치명적**.
- (D4) 같은 DBM-NNN이라도 엔진마다 DET/STUB/MANUAL/ABSENT가 산재(§B 표).

## 1. 벤더 소스 사실 (조사 완료)

- 소스 위치(이 머신): `/Users/hinno/Downloads/common/DatabaseConfigLoader/modules/`
  (PROGRESS의 `../flus-main/`은 다른 머신 기준 — 이 머신은 Downloads 경로가 진짜 소스.)
  - `database/{engine}/analysis.py` 6개: 각 `class {Engine}Analysis(config, data={})`.
    - `__init__`: `self.exception=config['exception']`, `self.rules=config['rules']`, `self.data=data`, `self.dbm_result={}`.
    - `@property run`: 항목 메서드(dbm_001..)를 순차 호출 → `self.dbm_result`({result_key:[위반]}) 반환.
    - `dbm_process_data(result_key, data_key, conditions)`: `data_key in self.data`이면 NOTE를
      `{"@@@":..}`, config Note를 추가, RESULT 각 datum에 conditions 전부 통과 시 위반 추가.
      mysql/mssql은 `'alert' in rules` 시 alert 단일 추가 후 break. 문자열 datum은 `{"*":datum}` 래핑. dedup.
    - 예외는 메서드별 try/except로 print만 → **예외 시 result_key=[]로 남아 거짓양호 위험(R3)**.
  - `config/{engine}-config.json` 6개: `{exception, rules}`. **임계값 단일출처**(mysql DBM-008.DAY=["90"], DBM-009.TIME=["900"]).
  - 의존성: `datetime`, `re`, `dateutil.relativedelta`, `packaging.version`만. **Django/lxml 없음** → 벤더링 깨끗. dateutil 2.9 / packaging 설치 확인됨.

- 데이터 키 사실(실샘플 5엔진 native): 수집 JSON 최상위 키는 result_key가 아니라 **data_key**(sub-suffix).
  예 mysql: `DBM-008_1, DBM-017_1.._4, DBM-024_1.._4, DBM-028_1.._4`. analysis가 sub-suffix data_key를
  소비해 base result_key(DBM-017)로 집계한다. **각 dbm_NNN 메서드는 자기 base id의 data_key만 읽는다.**

- 파이프라인 사실(검증):
  - `db_json._split_items` → `_parse_rows(block, check_id)`가 data_key별 행을 `ResourceEvidence(resource_id=f"{check_id}#row{i}")`로 생성. 현재 **raw_evidence 미설정**(마스킹 evidence만).
  - `mapper.aggregate`가 `profile.normalize_id`로 그룹핑: `DBM-017_1#row0`..`DBM-017_4#rowN` → normalize → 모두 `DBM-017` → **한 EvidenceItem DBM-017에 전 resource 합침**.
  - `main._det_common_handler`는 crit(DBM-017) 단위로 어댑터 호출, `_raw_evidence_for_det(item)`가 **첫 resource의 raw_evidence만** 반환.
  - §7 안전: raw_evidence는 LLM/citation 경로 미사용(`_judge_one`/합성 ev_item은 마스킹 evidence 사용).

## 2. 아키텍처 결정 (핵심)

### 결정 1 — R1 해소: db_json이 변형 전체 비마스킹 data dict를 raw_evidence에 적재 (설계안 A)

문제(R1): 핸들러는 crit(item) 단위 호출 + `_raw_evidence_for_det`는 첫 resource raw만 반환.
그러나 analysis는 변형 전체 data dict 필요(메서드는 자기 base id 키만 읽지만, 한 base에 여러
sub-suffix 존재).

해소: `db_json.parse()`가 파싱 중 수집된 **변형 전체 비마스킹 data dict**
(`{data_key: {RESULT:[원행dict..], NOTE:..}}`)를 1회 조립해, **모든 ResourceEvidence의
raw_evidence에 동일 JSON 문자열로 적재**한다. `_raw_evidence_for_det`가 첫 resource raw를
반환하면 어댑터는 전체 data dict를 얻는다.
- 공유 핸들러/`_raw_evidence_for_det` **변경 없음** = 최소 blast radius.
- 중복 적재 비용은 샘플 크기(KB~MB)에서 수용 가능. (원하면 첫 resource에만 적재 최적화 가능하나 aggregate.extend 순서 비보장이라 전 resource 적재가 안전.)
- §7: raw_evidence는 LLM/citation에 안 가므로 비마스킹 적재 안전. **재확인 필수**(어댑터 citation은 마스킹 행만).

### 결정 2 — 전체 `.run` 1회 + 모듈 캐시 + base result_key 룩업

- 어댑터는 raw_evidence(전체 data dict)를 파싱 → engine Analysis(config, data) 생성 → `.run` 1회 → `{result_key:[위반]}`.
- 모듈 캐시: 키 = (engine, data dict 지문[json sha1 또는 id]) → 같은 변형의 여러 base id item이 와도 .run 1회만.
- base id 룩업: `item_id`를 base 정규화(`DBM-017_1`→`DBM-017`) 후 캐시에서 추출.
- 개별 `dbm_NNN()` 직접호출 금지 — 원본 비트호환은 `.run` 전체 실행이 유일 보장.

### 결정 3 — 5개 DB 프로파일이 1개 어댑터 공유 (레지스트리 다중 키)

`_DET_ADAPTERS`는 profile_key로 키잉. import 시 루프 등록:
```python
for _k in ("db_mysql","db_oracle","db_mssql","db_mariadb","db_postgresql"):
    _DET_ADAPTERS[_k] = judge
```
어댑터 내부에서 variant→engine 매핑(`pg`→postgresql 주의). db_tibero는 excluded(미등록).

## 3. 어댑터 설계 (`det_adapters/db.py`)

시그니처(공통 계약): `judge(item_id, raw_output, variant, thresholds, *, context=None) -> ForcedVerdict`

흐름:
```
base   = normalize_base(item_id)        # 'DBM-017_1' → 'DBM-017'
engine = engine_of(variant)             # 'pg_native'→postgresql, 'mysql_native'→mysql ...
fv = gate(base, variant); if fv is not None: return fv   # §18.1 C1 (STUB/ABSENT/MANUAL 차단)
data = parse_data_dict(raw_output)       # 전체 비마스킹 data dict (결정1)
if not data: return handled=False        # 컬렉션 비었음 = 증거부재
if not has_data_key_for(base, data): return handled=False  # ★ 증거존재 가드(D3): base의 data_key 부재→양호 금지
cache = run_analysis(engine, data)       # 모듈 캐시 1회 (결정2). 예외→handled=False(R3)
rows  = filter_noise(cache.get(base, []))
if len(rows)==0: return 양호(good, 0.9)
else:            return 취약(bad, 0.9, citations=mask(rows)[:20])
```

- `engine_of`: 매핑 dict `{mysql,oracle,mssql,mariadb,pg(→postgresql)}`. variant.split('_')[0] 토큰.
- `normalize_base`: `re.match(r'(DBM)-(\d+)', item_id)` → `DBM-{int:03d}`. (profile.normalize_id 재사용 가능.)
- `has_data_key_for(base, data)`: data 키 중 `base` 또는 `base + '_'` prefix가 1개 이상 존재해야 True. 없으면 미수집→handled=False.
- `run_analysis`: `from judge_tool.vendor.common.db.{engine} import analysis as m; m.{Engine}Analysis(config, data).run`. config는 §3.2 로더. try/except → 예외 시 handled=False(R3 방어).
- `filter_noise(rows)`: dict 유일 키가 `'@@@'`(NOTE) 또는 `'***'`(config Note) 또는 tibero default 마커인 항목 제거. **`{"*":datum}`(문자열 위반행 래핑)은 위반이므로 유지.** alert 항목(mysql/mssql)은 위반이므로 유지.
- citations: `db_json._mask_row`/`_mask_raw_text` 재사용으로 위반행 마스킹 직렬화(최대 20). raw/data 원문 미노출(§7).

### 3.2 config 로딩
- vendor `judge_tool/vendor/common/db/config/{engine}-config.json` import 시 1회 로드, engine별 캐시. base.py DET_SOURCE 로더와 동일 fail-soft(없으면 빈 dict, 경고).
- thresholds(main의 xlsx 유래)와의 관계: **config rules가 권위 단일출처**. DB thresholds는 현재 거의 비어있어 어댑터는 config rules 사용, thresholds 무시(향후 교차검증 로그 가능).

### 3.3 증거존재 가드 (D3, 최우선)
"빈 위반=양호"가 미수집·내부예외삼킴(R3)과 구분 불가. 따라서 base의 data_key가 1개도 없으면
handled=False로 거짓양호 구조 차단(container `_has_collection_evidence`의 DB판).

## 4. 벤더링 계획 (§D)

복사(원본 비트동일, VENDOR-EDIT 불필요 — 외부 import 없음 확인):
- `database/{engine}/analysis.py` (6: mysql/oracle/mssql/mariadb/postgresql/tibero) → `judge_tool/vendor/common/db/{engine}/analysis.py`
- `config/{engine}-config.json` (6) → `judge_tool/vendor/common/db/config/{engine}-config.json`
- `judge_tool/vendor/common/db/__init__.py`, `db/{engine}/__init__.py` 신규(빈).
- cloud_analysis.py는 Phase 4 범위 밖 — 복사 생략.
- PROVENANCE.md Phase 4 행 추가(VENDOR-EDIT 없음). 로직/임계값/버그 수정 금지 — 발견 버그는 KNOWN_BUGS.md 등재 후 사용자 승인.

## 5. yaml 라벨 5-way 방침 (§E)
- DET 항목(§B): `judgment_method: det_common`으로 전환(label 유지). needs_review=True.
- STUB/ABSENT: gate가 handled=False → §18.3 라벨 라우팅. **기존 label 유지**(method를 det_common으로 바꾸면 STUB은 자동 LLM/canned 폴백). 보수적으로 STUB/MANUAL/ABSENT는 det_common으로 바꾸지 않아도 동작 동일(gate 차단)하나, 일관성 위해 전 DBM에 det_common 부여 가능 — 단 거짓양호 0 확인 필수.
- MANUAL(dbm_001): label C 유지. DBM-005: mssql=DET, 나머지 STUB(label A LLM 폴백).

## 6. raw_evidence 분리 (§6 / 결정1)
db_json.parse() 확장: evidence=마스킹(현행 불변), raw_evidence=변형 전체 비마스킹 data dict JSON.
빈 컬렉션→raw_evidence=None. 기존 마스킹/파싱 동작 핀고정(회귀 금지).

## 7. 듀얼런 불변 확인 (§F)
DB는 검증된 LLM 산출물 존재 → 회귀 위험. 계획:
1. Phase 4 전(LLM)/후(det_common) 동일 collected 5엔진 native 판정.
2. DET 전환 항목만 verdict 변화 허용, 그 외 불변 단언.
3. DET 항목 양호→취약 신규/취약→양호 약화는 적대리뷰 필수.
4. handled=False 항목이 기존 LLM 라벨 경로로 빠지는지 확인.
5. 핀고정 회귀: 각 DET 항목×엔진 known 위반/무위반 입력 → 기대 verdict 고정.

## 8. 리스크 / 미해결 질문 (§F)
- **R1**: 해소됨(결정1 — db_json raw_evidence 전체 적재).
- **R3**: analysis 메서드 예외 삼킴 → data_key 존재+내부예외 시 []→양호 오판. int변환/strptime 항목은 보수 STUB 또는 듀얼런 식별. 어댑터 .run try/except로 1차 방어.
- **R2**: oracle 실샘플 비정규 키(`DBM-16_12c` 오타) → base 정규화/data_key 매칭 누락 가능 → 증거부재 가드로 안전 폴백.
- **mssql DBM-009(s:136) / pg DBM-028(p:279)**: `lambda datum: True` = 수집행 무조건 위반(거짓취약 위험). 실검사 아님 → **보수적으로 STUB 분류**(pg-028은 §B에서 이미 STUB. mssql-009도 STUB로 확정).
- **R5**: dateutil/packaging 설치 확인됨(2.9 / ok).
- **R6**: tibero excluded — 분류만 기록, 판정 비활성. default-injection(011/028) 활성화 시 STUB 필수.
- **R7**: DBM-009 임계 900초는 xlsx상 "내부규정 미명시 시 15분 가정" — 결정론 비교가 실제 규정과 다를 수 있어 needs_review 필수.

## 9. 임계값 정합성 (§A, 스폿체크 완료)
xlsx '데이터베이스' 시트(header_row=4, id_col=2). DBM-008 "분기별 1회 이상" = config DAY=["90"] 일치.
DBM-009 "15분" = config TIME=["900"] 일치. 평가대상('o') 컬럼은 엔진별, 판단기준/방법 분리 — profile.py 매핑 정합.

## 10. 구현 단계 순서 (§G — Sonnet 체크리스트)
1. [ ] vendor 복사: db/{6engine}/analysis.py + db/config/{6}.json + __init__. import 검증.
2. [ ] PROVENANCE.md Phase 4 행 추가(VENDOR-EDIT 없음 확인).
3. [ ] db_json.parse() 확장: raw_evidence에 변형 전체 비마스킹 data dict JSON 적재(결정1). 기존 마스킹/파싱 핀고정.
4. [ ] det_adapters/db.py: engine 매핑, config 로더(fail-soft), base 정규화, 증거존재 가드, .run 모듈 캐시, noise 필터, result 매핑, 예외내성, §7 누출경계. _DET_ADAPTERS 5키 등록.
5. [ ] main.py: `import judge_tool.det_adapters.db`(부작용 등록) 1줄.
6. [ ] DET_SOURCE.yaml에 §B YAML 블록 병합(DBM-005 시드 확장 포함).
7. [ ] db_*.yaml 5개: DET 항목 judgment_method=det_common(label 유지).
8. [ ] 실데이터 검증: collected/db/{5}_native. 증거존재 가드/noise 필터 스폿체크. 거짓양호 0.
9. [ ] 듀얼런 불변 확인(§7). 회귀 핀고정.
10. [ ] Opus 적대 리뷰: STUB→DET 오분류, 증거부재→양호, 예외삼킴→양호 3중 점검.

---

## §B. DET_SOURCE.yaml DBM 엔진별 분류 (복붙 블록)

> 기존 DBM-005 시드를 이 블록으로 **대체**. variant 키 = engine 토큰(mysql/oracle/mssql/mariadb/pg).
> 근거 약칭: m=mysql, o=oracle, s=mssql, ma=mariadb, p=postgresql analysis.py.
> ★ STUB을 DET로 오분류하면 거짓양호 → 애매하면 STUB. lambda True(무조건 위반)는 거짓취약 위험 → STUB.

```yaml
  DBM-001:                          # 비밀번호 크랙 필요 — 전 엔진 수동
    variants: {mysql: MANUAL, oracle: MANUAL, mssql: MANUAL, mariadb: MANUAL, pg: MANUAL}

  DBM-003:                          # 불필요 계정
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: DET}

  DBM-004:                          # 불필요 관리자권한
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: DET}

  DBM-005:                          # 중요정보 암호화 — mssql만 실검사, 나머지 placeholder
    variants: {mssql: DET, mysql: STUB, oracle: STUB, mariadb: STUB, pg: STUB}

  DBM-006:                          # 로그인 실패 제한
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: STUB}

  DBM-007:                          # 비밀번호 복잡도
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: STUB}

  DBM-008:                          # 비밀번호 주기변경(90일)
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: DET}

  DBM-009:                          # 세션 종료(900초) — mssql은 lambda True=STUB(거짓취약 위험)
    variants: {mysql: DET, oracle: DET, mssql: STUB, mariadb: DET, pg: DET}

  DBM-011:                          # 감사로그
    variants: {mysql: DET, oracle: DET, mssql: STUB, mariadb: DET, pg: DET}

  DBM-013:                          # 원격접근통제
    variants: {mysql: DET, oracle: ABSENT, mssql: MANUAL, mariadb: DET, pg: STUB}

  DBM-014:                          # oracle 전용 파라미터
    variants: {oracle: DET}
    default: ABSENT

  DBM-015:                          # 권한/PUBLIC (oracle 015_1/2 lambda True 혼재 → 듀얼런 검증 필요)
    variants: {oracle: DET, mssql: DET, pg: DET}
    default: ABSENT

  DBM-016:                          # 보안패치 버전
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: STUB, pg: DET}

  DBM-017:                          # 시스템테이블 접근권한
    variants: {mysql: DET, oracle: DET, mssql: MANUAL, mariadb: DET, pg: DET}

  DBM-019:                          # 비밀번호 재사용
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: STUB}

  DBM-020:                          # 계정 분리/공유 (needs_review 필수)
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: DET}

  DBM-021:                          # mssql ODBC — 콘솔 확인
    variants: {mssql: MANUAL}
    default: ABSENT

  DBM-022:                          # 파일 권한 (mssql 빈본문=STUB)
    variants: {mysql: DET, oracle: DET, mssql: STUB, mariadb: DET, pg: DET}

  DBM-024:                          # WITH GRANT OPTION
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: DET}

  DBM-025:                          # EOL (mariadb 빈본문=STUB)
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: STUB, pg: DET}

  DBM-026:                          # umask
    variants: {mysql: DET, oracle: DET, mariadb: DET, pg: DET}
    default: ABSENT

  DBM-028:                          # 불필요 Object (pg lambda True=STUB)
    variants: {mysql: DET, oracle: DET, mssql: DET, mariadb: DET, pg: STUB}

  DBM-029:                          # oracle 전용
    variants: {oracle: DET}
    default: ABSENT

  DBM-030:                          # oracle 감사테이블 소유 (mssql run 미호출=ABSENT)
    variants: {oracle: DET}
    default: ABSENT

  DBM-031:                          # mssql 비활성계정 정책
    variants: {mssql: DET}
    default: ABSENT

  DBM-032:                          # pg 수동대체
    variants: {pg: STUB}
    default: ABSENT

  DBM-033:                          # mysql 이중화 평문비번
    variants: {mysql: DET}
    default: ABSENT

  # DBM-002/010/012/018/023/027: 전 엔진 run() 미호출 → 미기재(classify=ABSENT 자동)
  # DBM-034/035/036: 기존 시드 유지(전 엔진 ABSENT/로직없음).
```

---

## Phase 4b: 클라우드 변형(RDS/Aurora/Azure) 결정론 통합 (2026-06-16 추가)

Phase 4(native)는 `*_native` 변형만 실데이터 검증했다. DB 변형은 native 외 클라우드가 많다:
- mysql/postgresql: native + rds + aurora + azure (각 4)
- oracle/mssql/mariadb: native + rds (각 2)
- tibero: excluded. **총 비-tibero 14변형.**

### 현재 갭 (Phase 4 직후 상태)
- `db.py _ENGINE_CLASS`는 native `{Engine}Analysis`만 매핑. `_engine_of('mysql_rds')`=`mysql` → **클라우드 변형이 native 클래스로 라우팅**.
- 벤더에 엔진별 `cloud_analysis.py`(`{Engine}CloudAnalysis`)가 따로 있고 **메서드셋·데이터 스키마가 native와 다름**(예: mysql cloud DBM-006은 `FAILED_LOGIN_ATTEMPTS`/`PASSWORD_LOCK_TIME_DAYS` 컬럼, native는 `USER_ATTRIBUTES`; mysql cloud run()은 DBM-025/026/033 미수행).
- 현재는 R3 가드로 KeyError→handled=False = **fail-safe(거짓양호 0)이나 클라우드 결정론 커버리지 0** = 미완성.
- ⚠️ **거짓양호 위험**: native=DET인데 cloud run()이 미수행(ABSENT)하는 항목(mysql 025/026/033 등)은, classify()의 engine-token 폴백(`mysql_rds`→`mysql`=DET)이 gate를 통과시키고, CloudAnalysis가 해당 result_key를 채우지 않아 `cache.get(base,[])=[]`→양호로 샐 수 있다(증거가드는 data_key 존재만 보고 분석 수행 여부는 모름). **→ 클라우드 변형 DET_SOURCE를 cloud_analysis.py 기준으로 명시 분류해야 한다.**

### 결정 4 — 클라우드 변형 라우팅: variant suffix로 클래스 선택
- `_native` → `{Engine}Analysis`(analysis.py). `_rds`/`_aurora`/`_azure` → `{Engine}CloudAnalysis`(cloud_analysis.py).
- 모듈 경로: `judge_tool.vendor.common.db.{engine}.cloud_analysis`. 클래스명 맵 `_ENGINE_CLOUD_CLASS`(MySQLCloudAnalysis/OracleCloudAnalysis/MSSQLCloudAnalysis/MariaDBCloudAnalysis/PostgreSQLCloudAnalysis) 추가.
- **config는 native와 공유**(`{engine}-config.json`의 exception/rules 동일) — cloud 전용 config 불필요(`__init__`이 같은 config 키 사용 확인).
- 캐시 키에 native/cloud 구분 포함(예 `(engine, is_cloud, fingerprint)`) — 같은 데이터를 native/cloud로 오판 방지.
- 엔진별 CloudAnalysis 1클래스가 rds/aurora/azure 전부 처리(pg는 내부 데이터분기 azure/rds). → **rds/aurora/azure는 동일 DET/STUB 분류**(한 engine 기준).

### 결정 5 — DET_SOURCE 클라우드 변형 명시 분류 (거짓양호 차단 핵심)
- classify()의 exact-variant 매칭이 engine-token 폴백보다 우선하므로, **각 클라우드 변형 키(mysql_rds/mysql_aurora/mysql_azure 등)를 variants 맵에 명시**한다. base.py 변경 불필요.
- cloud_analysis.py를 메서드 단위로 읽어 DET/STUB/MANUAL/**ABSENT(cloud run() 미호출)** 분류. native와 다른 셀이 핵심:
  - native run()엔 있으나 cloud run()엔 없는 항목 → 클라우드 변형 **ABSENT**.
  - cloud의 lambda True / 빈본문 → STUB.
- 한 엔진의 rds/aurora/azure는 동일 분류(같은 CloudAnalysis) — 3키에 같은 값.

### 결정 6 — 실데이터 부재 → 활성화 게이트
이 머신에 클라우드 변형 실데이터 없음(results/DB 비어있음, collected/db=native만). 따라서 클라우드 변형은
**구조 구현 + 합성 픽스처 단위테스트 + DET_SOURCE 분류**까지만. 실데이터 거짓양호 검증·듀얼런은
클라우드 수집 샘플 확보 후(활성화 게이트). 단 **R3 fail-safe + DET_SOURCE ABSENT 명시**로 거짓양호는
샘플 없이도 구조 차단. db_*.yaml det_common은 per-item이라 이미 클라우드 변형에도 적용됨 —
gate가 cloud ABSENT/STUB를 차단하는지 합성 테스트로 확인.

### Phase 4b 구현 순서 (Sonnet)
1. [ ] cloud_analysis.py 5엔진 벤더 복사(`vendor/common/db/{engine}/cloud_analysis.py`, 비트동일). PROVENANCE Phase 4b 행.
2. [ ] **cloud_analysis.py 5엔진 메서드 단위 정독 → 클라우드 변형 DET_SOURCE 분류**(native와 다른 셀 명시, run() 미호출=ABSENT, lambda True/빈본문=STUB). 애매하면 STUB/ABSENT.
3. [ ] DET_SOURCE.yaml 각 DBM item variants 맵에 클라우드 변형 키 추가(mysql_rds/aurora/azure, oracle_rds, mssql_rds, mariadb_rds, pg_rds/aurora/azure).
4. [ ] db.py: `_ENGINE_CLOUD_CLASS` 맵 + variant suffix로 native/cloud 클래스 선택 + 캐시 키에 is_cloud 포함. `_run_analysis(engine, data, is_cloud)`.
5. [ ] 테스트: native/cloud 라우팅 분기, cloud ABSENT 항목 gate 차단(거짓양호 0), cloud DET 항목 합성 위반→취약/무위반→양호, R3 가드 cloud에도 적용.
6. [ ] `pytest tests/ -q` 전체 통과. PROGRESS 갱신(클라우드=활성화 게이트: 실데이터 검증·듀얼런 대기).

### 분류 요약 (tibero 제외)
- DBM-005 = mssql만 DET, 나머지 4엔진 STUB (기존 시드 정확).
- DBM-001 = 전 엔진 MANUAL(해시크랙).
- pg = STUB 최다(005/006/007/013/019/028/032 빈본문·lambda True).
- mssql = MANUAL 최다(001/013/017/021 인터뷰·콘솔) + STUB(005→DET예외, 009/011/022).
- **lambda True(무조건 위반) = STUB로 분류**: pg-028, mssql-009. (거짓취약 방지.)

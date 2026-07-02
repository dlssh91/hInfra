# 결정론 거짓양호/오라우팅 감사 + 수정 설계 (2026-07-03, Fable)

DBM-003 모드A2 이후, 같은 부류(거짓양호=위험한데 '양호') 결함 전수 감사. 코드로 확인된 것만.

## 0. 이미 가드됨(재지적 제외)
db.py 기존 가드: gate/§18.1 C1, D3 증거가드, R3 예외삼킴 차단, 모드A(DBM-004)/A2(DBM-003)/B(pg006/007)/C(DBM-011)/D(019/029/031)/E(022)/F(026)/G(032)/H(034)/I(035)/I2(036), db_pwcrack(001). DBM-032 pg canned, DBM-016 gate차단, SRV-074(사용자결정) 제외.
핵심 구조: `_det_common_handler`(main.py:467-548)는 어댑터 handled=True면 **label 무관 verdict 확정** → label D/C 의도도 우회(DBM-003 동형). 미가드 항목은 최종 `위반0→양호`(db.py:1545)로 떨어지고, vendor `dbm_process_data`는 (a)RESULT 빈배열 조용히 위반0, (b)**data_key 없으면 조용히 skip**(analysis.py `if data_key in self.data`) — 거짓양호 공통 뿌리.

## 1. 우선순위표
| # | 항목 | 엔진/variant | label·jm | 결함 | 근거 | 재현 | 위험 |
|---|---|---|---|---|---|---|---|
| F1 | DBM-008 주기적 비번변경 | mysql·oracle·mariadb·mssql | A·det_common | data_key 불일치 | mysql analysis:170-181은 'DBM-008'만, 실수집=**'DBM-008_1'**→조용히 skip→양호. oracle:230-240은 '_1'만, 실수집=**'_2'(PASSWORD_LIFE_TIME=UNLIMITED 실취약)**→**양호 실증** | 수집키 불일치/0행→검사0건→양호 | **상(실증)** |
| F2 | DBM-025 EoS DB | mysql·oracle·mssql·pg native | **D**·det_common | D의도 vs det자동판정 + 노후지식 | yaml label D+canned인데 DET_SOURCE=DET→자동판정. oracle-config rules='12'(2023.06)→**12.1/12.2/18c(EoS) 양호**. eol.py 권위경로(as_of+staleness) 우회. cov contract uncovered_reason도 실제 라우팅과 불일치 | 노후 테이블 내 EoS버전/version행 미수집→양호 | **상** |
| F3 | DBM-009 유휴세션 종료 | mysql·mariadb·oracle·pg | A·det_common | 미수집→양호 | analysis 기대변수행(wait_timeout/IDLE_TIME/idle_in_transaction…) 부재→위반0→양호. oracle cov 픽스처가 빈RESULT→양호로 거짓양호 실인코딩(db_cov_contract:461-467) | timeout변수 미수집→양호 | **상** |
| F4 | DBM-014 원격 OS 인증 | oracle native+rds | A·det_common | 미수집→양호 | analysis:270-274 value!='FALSE'만 취약. gv$parameter 전버전 존재→0행=수집실패인데 양호. cov 픽스처 빈RESULT→양호(484-490) | 파라미터 쿼리실패→0행→양호 | **상** |
| F5 | DBM-013 원격접속 접근제어 | mysql·mariadb native+**cloud** | A·det_common | native 미수집→양호 + **cloud capability parity** | native는 VENDOR-EDIT로 `'%'/'_' in HOST` 포함매칭 수정됐으나 **cloud(cloud_analysis) 미반영** — `HOST in ['%']` 정확일치만 → `'10.%'`,`'%.corp.com'` 광역허용이 rds/aurora/azure에서 양호 | cloud 부분 와일드카드 Host→양호 | **상/중** |
| F6 | DBM-006/007 실패잠금·복잡도 | mysql·mariadb·oracle·mssql | A·det_common | 0행→양호 | 계정/프로파일 0행 불가능인데 0행→양호. cov 픽스처 4곳 empty→양호 인코딩. mysql006은 int()ValueError→R3 부분차단 | RESULT 0행→양호 | 중 |
| F7 | DBM-005 암호화 | mssql_rds | A·det_common | 0행→양호 | cloud_analysis:101-106 sample is not None — 0행vs샘플없음 구분불가 | 샘플쿼리 실패→양호 | 중 |
| F8 | container 오류출력→N | container 전 variant | autoAnalysis | 오류출력→N→양호 | container.py:130 가드는 수집흔적만; autoAnalysis 디폴트 {"result":"N"}+"문자열부재=N" | raw=`kubectl…\nerror: Unauthorized`→가드통과→패턴부재→N→양호 | 중 |
| F9 | DBM-033 이중화 평문 | mysql native | A·det_common | (기록) 0행=복제미구성=양호는 문서화된 결정, 수집실패 구분불가 한계 | — | 하 |
| F10 | server 명령실패 출력 | server/webwas | — | (백로그) 명령 찍혔으나 실패한 출력에서 미탐→N→양호 가능 | — | 하 |
부차 미탐(백로그): oracle DBM-009 숫자 IDLE_TIME>15 미탐, pg idle_session_timeout 미커버.

## 2. 수정 설계
### 공통 신규: 모드 J — 테이블 주도 fail-closed 미수집 가드 (db.py, 모드I2 끝 1543 뒤 / 최종 위반0→양호 1545 앞)
```python
def _base_result_rows(base, data):  # base 및 base_* 의 RESULT 전부 concat
    rows=[]
    for k,v in data.items():
        if (k==base or k.startswith(base+"_")) and isinstance(v,dict) and isinstance(v.get("RESULT"),list):
            rows.extend(v["RESULT"])
    return rows
_MODE_J_ITEMS = {
  "DBM-008": None,
  "DBM-009": {"mysql": lambda r: any(str(x.get("VARIABLE_NAME","")).lower()=="wait_timeout" for x in r if isinstance(x,dict)),
              "mariadb": lambda r: any(str(x.get("VARIABLE_NAME","")).upper() in ("WAIT_TIMEOUT","INTERACTIVE_TIMEOUT") for x in r if isinstance(x,dict)),
              "oracle": lambda r: any(x.get("resource_name")=="IDLE_TIME" for x in r if isinstance(x,dict)),
              "postgresql": lambda r: any(x.get("setting_name")=="idle_in_transaction_session_timeout" for x in r if isinstance(x,dict))},
  "DBM-013": None,
  "DBM-014": {"oracle": lambda r: any(x.get("name") in ("os_roles","remote_os_roles","remote_os_authent") for x in r if isinstance(x,dict))},
}
# 가드(위반0일 때만): 0행→판단보류. checker 있고 기대행 없음→판단보류. handled=True(needs_review). interview_summary 불요.
```
과교정 검토: 정상양호는 RESULT행+기대행 보유(실수집 5종 확인). key자체 없는 케이스는 D3에서 이미 handled=False.

### F1 DBM-008 — vendor data_key 정합(VENDOR-EDIT) + 모드J
- mysql/analysis.py:170-181: `'DBM-008'` 유지 + 동일조건 `'DBM-008_1'` 처리 추가. 주석 R-MY008 + KNOWN_BUGS 등재.
- oracle/analysis.py:230-240: `'DBM-008_1'` 유지 + `'DBM-008_2'` 복원(resource_name=='PASSWORD_LIFE_TIME', profile not in exception, limit in ['UNLIMITED']). PASSWORD_GRACE_TIME은 첫조건 배제.
- db.py 모드J 등록. 테스트: _1 취약/_2 UNLIMITED 취약/0행 판단보류/최근변경 양호 회귀. ⚠️mysql collector 컬럼스왑(USER/HOST) 있으니 키만 추가(스왑 정규화 금지).

### F2 DBM-025 — det 자동판정 제거, eol.py 권위 복원
- item_configs 4파일 DBM-025 `judgment_method: det_common` 줄 삭제 → classify_method가 `det`→_defer_or_eol→judge_eol(eol.yaml as_of staleness). mariadb와 동일형태(5엔진 일관).
- DET_SOURCE.yaml DBM-025 native DET→STUB(이중방어) + 주석.
- db_cov_contract 4곳 uncovered_reason 정정. 테스트: db_* DBM-025 jm=='det' assert.
- 과교정: judge_eol은 in-support+fresh면 양호 반환 → 정상양호 보존.

### F3 DBM-009 — 모드J(0행+4엔진 checker). db_cov_contract:461-467 oracle good을 IDLE_TIME 유효행으로 교체(양호 유지). 신규 test_mode_j_hold.
### F4 DBM-014 — 모드J(oracle checker). db_cov_contract:484-490 oracle good을 os_roles/remote_os_roles FALSE행으로 교체.
### F5 DBM-013 — 모드J(0행) + mysql/mariadb cloud_analysis 와일드카드 parity(`'%' in HOST or '_' in HOST`) VENDOR-EDIT + KNOWN_BUGS. 과탐(HOST='%' 관리계정→취약검토)은 안전방향, 테스트로 의도 고정.
### F8 container(2차) — 오류출력 정규식 가드, 매치시 handled=False. 실샘플 과트리거0 검증 필수.

### 구현 순서(커밋 단위, 각 후 pytest 전체)
1. F2(yaml/DET_SOURCE/contract 문서 — 코드무변경 최소리스크) 2. 모드J+F3/F4(db.py+cov 2건+테스트) 3. F1(vendor 2파일+모드J+KNOWN_BUGS) 4. F5(cloud vendor 2파일+모드J) 5. F8 / F6·F7 별도배치(픽스처 empty→양호 재설계)

## 3. 불변계약 준수
results/ 무접근(collected/만 읽기), _HANDLERS 라우팅 유지(F2=기존 det 재사용, 모드J=어댑터내부 테이블), 회귀=cov 픽스처 2건(oracle 009/014 good 유효행)+DBM-025 문서정정뿐, 실수집5종 정당양호→보류강등 0, 합성픽스처로 검증가능.

## 4. 범위밖/보류
FW(ISS-035 capability, 실데이터 필요), LLM label A 품질(모델 필요). 백로그: oracle009 숫자임계 미탐, pg idle_session_timeout, mysql006 int()벤더버그(R3 흡수), server 명령실패출력, DBM-033·005(mssql_rds) 0행 의미.

# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-19 (**상태저장. SRV 최종검증 완료 — linux 변형 DET 양극성 cov 픽스처(tests/srv_cov_contract.py) + 계약 테스트(tests/test_srv_cov_fixtures.py) 생성·전통과. 1847 passed. ★다음 착수=다음 도메인(네트워크/방화벽/가상화 등) 또는 서버 LLM 품질 검토.**). **"다음에 진행해줘"/"개발진행해" → 아래 ★다음 착수부터.**
> (한 작업단위 종료 시마다 이 파일을 갱신해 인계. 이 파일이 단일 진실원천.
>  재개 트리거: "개발진행해"/"개발해줘"/"이어서 진행"/"다음 작업"/**"다음에 진행해"** → 아래 TL;DR ★다음 착수부터.)

## ▶ 다음 세션 즉시 시작점 (TL;DR)

### ★★ 운영 컨셉 (2026-06-17 전환 — 사용자 확정) ★★
검토가 "det 깊이감사"로 번지는 것을 막기 위해 **라우팅 우선 + 픽스처/듀얼런 안전망** 컨셉으로 전환.
1. **빠른 라우팅 triage**: 항목마다 먼저 "깔끔한 이진/기계적 점검인가?"
   - **예** → det 유지. **전수 재유도 금지**, polarity·"미설정→양호 거짓양호" **한 줄 스팟체크만**.
   - **아니오**(적절성/업무상 필요 등 맥락 판단) → LLM(A)/인터뷰(B)로 라우팅, **det 안 건드림**.
2. **common 기존 분류를 기본으로 따라간다**(맹목적 추종은 아님 — 거짓양호 안전망 필수).
3. **거짓양호 안전망 = "모두양호/모두취약 픽스처 + 듀얼런"**(수동 전수감사 대체). good픽스처→취약 / vuln픽스처→양호 / det↔LLM 불일치 **나는 항목만** 파고든다.
4. **LLM은 "맥락 판단 필요 항목"에만** 투입(production=로컬 qwen3-coder:30b 전용, [[local-llm-only]]).
5. **향후 도메인(네트워크/방화벽/가상화)**: 기존분류 따라가기 + 픽스처/듀얼런으로 틀린방향 잡힐 때만 수정.
> ⚠️ **보류한 deep-audit 백로그**: 아래 "deep-audit 백로그(보류)" 섹션 참조. 필요시 나중에 항목별 정밀감사 적용 가능하도록 상태 보존.

- **★다음 착수 = 다음 도메인(네트워크/방화벽/가상화) 또는 별도 작업** — 서버·웹-WAS·DBM 3도메인 모두 DET 양극성 cov 완료. 서버 재확인=DET 36항목 양극성 깨짐 0(거짓양호/거짓취약 발견 0, 깨끗). 웹-WAS=버그4건 수정, DBM=Docker실증.

  **✅ SRV 최종검증 — linux 변형 DET 양극성 cov 픽스처 + 계약 테스트 SHIP (2026-06-19, 1847 passed)**:
  - `tests/srv_cov_contract.py` 신규: linux variant × DET/DET-PARTIAL 항목 양극성 픽스처 단일 진실원천.
    - 순수 DET 36항목(SRV_auto_parse): 전수 양극성 커버.
    - DET-PARTIAL linux-override 5항목(SRV_Linux_parse — SRV-026/069/127/131 양극성, SRV-074 vuln=날짜의존 uncovered).
    - DET-PARTIAL 서비스inactive 8항목(SRV-005/006/007/013/014/021/064/073): good→양호, vuln=수동경로 uncovered.
    - 총 49항목 정의, 양극성 커버 41항목, uncovered 13극성(사유 명시).
  - `tests/test_srv_cov_fixtures.py` 신규: parametrized 계약 테스트 119케이스 (109 passed, 12 skipped-uncovered).
    - `test_srv_det_polarity[item_id-polarity]`: good→good_verdict, vuln→vuln_verdict 전수 확인.
    - `test_srv_manual_items_no_false_positive`: MANUAL/DET-PARTIAL-active 19항목 handled=False 확인.
    - 완전성 테스트(최소항목수/미커버 사유 문서화/양극성 데이터 완전성) 포함.
  - **픽스처 디버깅 중 발견·수정된 설계 이슈**:
    - SRV-081 good: `/etc/crontab -rw-r--r--`(others read=644) → SRV-081은 others r|w 탐지 → 거짓취약. 정정: 640(-rw-r-----).
    - SRV-121/122 good: result='N'이라도 '(*) 다른 프로파일 수동 확인 필요' 부기 → Low-1 가드 → handled=False. good 경로는 uncovered(항상 (*)), vuln 단방향만.
    - SRV-028 good: split_output(4) 요구(4섹션) — good fixture에 3섹션 → 분리 실패 → handled=False. 정정: 4섹션 구조.
    - SRV-021/073: DET-PARTIAL(inactive→양호 DET 경로 존재) — MANUAL_HOLD_ITEMS에서 제거 후 SRV_COV에 추가.
  - 전체 1847 passed, 95 skipped, 0 failed (이전 1738 + 신규 109). 기존 회귀 없음.

  **✅ DBM 최종검증 — 엔진별 양극성 cov 픽스처 + 계약 테스트 SHIP (2026-06-19, 1682 passed)**:
  - `tests/db_cov_contract.py` 신규: 5엔진(mysql/mariadb/oracle/mssql/pg) × DET 항목 양극성 픽스처 단일 진실원천.
    - mysql: 13항목 커버(DBM-003/004/006/007/008/009/011/013/019/022/026/033/034), 2항목 미커버(DBM-001 crack_judge 설계계약, DBM-025 EOL).
    - mariadb: 13항목 커버(DBM-003/004/006/008/009/011/013/019/022/026/034), 2항목 미커버, DBM-005 STUB.
    - oracle: 11항목 커버(DBM-003/004/006/007/008/009/011/013/019/022/026), 2항목 미커버(DBM-001/025).
    - mssql: 10항목 커버(DBM-006/007/008/009/011/013/019/022/031/033/034/035/036 중 DET만), 미커버 명시.
    - pg: 9항목 커버(DBM-008/009/011/013/019/022/026/032/035/036 중 DET만), DBM-006/007 모드B(구조적취약) 포함.
  - `tests/test_db_cov_fixtures.py` 신규: parametrized 계약 테스트 183케이스 + 모드별 가드 테스트.
    - `test_db_det_polarity[engine-item_id-polarity]`: good→good_verdict, vuln→vuln_verdict 전수 확인.
    - 모드B(pg 구조적취약), 모드D(빈RESULT), 모드E(perm가드), 모드F(umask가드), 모드G(pg_hba가드), 모드H(데몬가드), 모드I/I2(xcmdshell/xreg가드) 별도 검증.
    - label B/C/D gate 차단, 미커버 항목 명시 계약 테스트 포함.
  - **발견·수정된 픽스처 불일치**:
    - mysql DBM-009: 소문자 `wait_timeout`(mysql) vs 대문자 `WAIT_TIMEOUT`(mariadb) 대소문자 차이.
    - mariadb DBM-006: `USER_ATTRIBUTES`(MySQL) → `MAX_PASSWORD_ERRORS VARIABLE_NAME/VALUE`(mariadb config).
    - mariadb DBM-008: `PASSWORD_LAST_CHANGED`(MySQL) → `DEFAULT_PASSWORD_LIFETIME VARIABLE_NAME/VALUE`(mariadb).
    - oracle DBM-003: `last_login`은 `rules['last_login']=['']` 매칭(빈 문자열) 조건.
    - oracle DBM-008: `relativedelta(months=6)` 6개월 임계값 — good 날짜를 1개월 이내로 조정.
  - 전체 1682 passed, 63 skipped, 0 failed (기존 1531 + 신규 151).

  **✅ DBM-035/036 mssql 결정론 SHIP (2026-06-19, 1531 passed, Opus SHIP)**: 둘 다 mssql 전용·실 docker(mssql_dbm) 검증.
  - DBM-035(xp_cmdshell): `sys.configurations value_in_use==1→취약/0→양호`. DET. 모드I 가드(xp_cmdshell 행 없음→판단보류).
  - DBM-036(registry proc): `xp_reg* + EXECUTE + 비관리자 grantee→취약`(public 항상취약). **R-036d**: DENY(public 명시차단=안전)는 취약 아님(Opus 발견 거짓취약→state_desc=DENY 스킵). DET. 모드I2 가드.
  - DET_SOURCE DBM-035/036 mssql=DET, mssql_rds=ABSENT. db_mssql.yaml det_common.

  **⚠️ 백로그(034/035/036 수집 — assessment_scripts gitignore)**: judge_tool det 로직은 커밋됐으나 **수집 스크립트는 gitignore라 미커밋**. 필드 수집기에 추가 필요한 계약:
  - DBM-034: `ps -ef` → `{"output":"<ps>"}`. DBM-035: `SELECT name,value_in_use FROM sys.configurations WHERE name='xp_cmdshell'` → `{"name","value_in_use"}`. DBM-036: xp_reg* 권한 → `{"object","permission","state_desc","grantee"}`(컬럼 별칭: object_name→object, permission_name→permission). state_desc 포함 필수.
  - (Low) DBM-036 CONTROL 등 EXECUTE-내포 권한 미탐(public CONTROL 비현실적). DBM-026 다중토큰, DBM-033 FILE-repo, DBM-030 DET승격, 모드H oracle키워드 과매칭 — 기존 백로그 유지.

  **🚨 중대정정 — DBM-020/024/028/030 자동판정 버그 → interview 전환 SHIP (2026-06-19, 전체파이프라인 ground-truth)**:
  - **발견**: criteria_loader.py:98이 yaml `judgment_method: det_common`을 label B보다 우선 → 이 4항목이 label B(인터뷰) 의도인데 **det adapter로 자동판정**(DBM-020 계정있으면 자동취약=거짓취약, DBM-030 AUD$ 빈예외 자동취약). label B·summary_instruction이 죽은코드였음. (앞서 "이미 label B 정답"이라던 내 결론이 틀렸음 — 파이프라인 실행으로 확인.)
  - **수정**: db_{5엔진}.yaml DBM-020/024/028/030에서 `judgment_method: det_common` 제거(14건) → classify_method(B)=interview → _summarize_one → 판단보류. DBM-015/017과 동일 패턴. e2e 검증: DBM-020/024/028 = 판단보류+interview 확인.
  - **교훈**: label B(인터뷰) 항목은 yaml에 det_common 두면 안 됨(자동판정으로 우회됨). 향후 항목도 동일 주의.

  **✅ DBM-035/036 xp_cmdshell 비활성 + Registry Procedure 접근권한 — DET 결정론 SHIP (2026-06-19, 1529 passed)**:
  mssql 전용 2항목. DBM-027 결번, DBM-002/010/012/018/023/027 ABSENT. **DB 도메인 전 항목 완료.**
  - **DBM-035 xp_cmdshell 비활성**: `sys.configurations` xp_cmdshell value_in_use 이진판정. value=0→양호/1→취약. **모드I 가드**: RESULT 빈배열 또는 xp_cmdshell 행 없음 → 판단보류(SQL Server Express는 값 변경 불가이므로 항상 0 = docker 실증). 구현: mssql/analysis.py `dbm_035()` 신규(value_in_use/value 키 지원, int/str 모두 처리). DET_SOURCE mssql=DET, mssql_rds=ABSENT. db_mssql.yaml det_common+needs_review. 어댑터 `_XCMDSHELL_GUARD` + 모드I 가드 블록.
  - **DBM-036 Registry Procedure 접근권한**: `xp_reg*/EXECUTE/public(비관리자)` 탐지. public은 항상 취약(config 예외 무시), config 예외 목록(sysadmin/dbo/db_owner/db_securityadmin)은 양호. **모드I2 가드**: RESULT 빈배열 → 판단보류(거짓양호 최악 원칙). 구현: mssql/analysis.py `dbm_036()` 신규(config exception 읽기, public 하드코딩 예외불가). DET_SOURCE mssql=DET, mssql_rds=ABSENT. db_mssql.yaml det_common+needs_review. 어댑터 `_XREG_GUARD` + 모드I2 가드 블록. mssql-config.json DBM-035/036 exception/rules 추가.
  - **실 docker 검증**: DBM-035 value=0→양호(Express 고정값), DBM-036 public EXECUTE 부여→취약/REVOKE→원복. 수집 포맷 확인.
  - **테스트**: +21 (TestDBM035 10 + TestDBM036 11케이스. polarity/미수집/cloud ABSENT/다른엔진 ABSENT/docker 1케이스 포함).

  **✅ DBM-034 DBMS 서비스 구동 권한 적절성 — DET 결정론 SHIP (2026-06-19, 1506 passed)**:
  판단기준: DBMS 데몬이 root 계정으로 구동되면 취약, 전용계정(mysql/postgres/oracle 등)이면 양호.
  평가대상: mysql/oracle/pg/mariadb(native). mssql은 평가대상 아님. cloud(rds/aurora/azure) = OS접근불가 → ABSENT.
  구현: 4개 엔진 `dbm_034` 메서드 신규(각각 mysqld/mariadbd-mysqld/postgres/ora_-tnslsnr-oracle 키워드로 데몬 라인 식별, 첫필드==root → 위반). DET_SOURCE.yaml DBM-034(native DET, cloud ABSENT, default ABSENT). item_configs 4개 yaml DBM-034(det_common, needs_review, label B). 수집스크립트(MySQL/PostgreSQL/Oracle DBM-034 블록 추가, MariaDB unix_mariadb.sh 신규 생성). 모드H 가드(DAEMON_GUARD): RESULT 빈배열 또는 데몬 키워드 라인 0건 → 판단보류(거짓양호 봉쇄). **가드 설계 포인트**: oracle 데몬 키워드 탐색 시 첫 필드(username) 제외 후 cmd 부분에서만 탐색(username=oracle인 bash 프로세스 오탐 방지). 실 docker 검증: my_dbm→mysql/pg_dbm032→postgres/maria_dbm→mysql/ora_dbm→oracle (전부 양호). root시뮬(합성) 취약 확인. 빈RESULT/데몬없음 판단보류 확인. 테스트 +41(1465→1506).

  **✅ DBM-033 이중화 평문비번(mysql) — DET 유지 확인 (2026-06-19)**: mysql.slave_master_info `User_password != "" → 취약`, polarity 정확. 빈배열(replication 미구성)→양호 정당. **SCOPE 명시**(코드 주석): TABLE repository 전제(8.0+ 기본, 8.0.23+ FILE 제거). 구버전 FILE-repo(master.info 파일)는 미수집이라 범위 밖(현실 영향 미미). oracle DBM-022/026도 docker 실증 완료(파일카테고리 로직 정확). ※ 앞서 보고한 'oracle dbm_022 중복블록'은 sed 겹침 착시 — 실제 없음(정정).
  **🐳 Docker 실데이터 재검토 트랙(진행 중)**: 데이터 없던 OS셸 항목을 실 컨테이너로 검증. 완료: pg/mysql/mariadb의 DBM-022(파일권한)·026(umask)·032(pg_hba) 실데이터 검증 — 내 수정들이 실포맷에서 정확 동작(거짓양호 0) 확인 + 신규 거짓취약 2건 잡아 수정(R-022L 심링크, R-032b 인라인주석). 남음: **oracle 실데이터(022/026 검증)** + **DBM-033(mysql 이중화 평문비번) 검토**. docker 컨테이너 기동 중: pg_dbm032/my_dbm/maria_dbm/ora_dbm.

  **✅ DBM-032 pg_hba 평문비번 → ① 결정론 파서 SHIP (2026-06-19, 1465 passed, Opus SHIP)**: 사용자가 label B 대신 **결정론 파서(auto-verdict)** 선택(도커 실데이터로 검증가능해짐). pg dbm_032 빈STUB→파서: `host/hostnossl + method=password → 취약`, hostssl/local/md5/scram/주석 제외. **R-032b**: 인라인주석(`# legacy`) 선제거(Opus가 거짓양호 발견→수정). DET_SOURCE pg DBM-032 STUB→DET, cloud(rds/aurora/azure)는 label C(pg_hba 직접점검 불가→rds.force_ssl 안내). 모드G 가드(빈/미수집→판단보류). docker pg_dbm032 실증.

  **✅ DBM-022 심링크 거짓취약 수정(R-022L) (2026-06-19)**: `get_check_file_perm` 디렉터리(d)만 제외→심링크(l)도 제외(5엔진). 심링크 `lrwxrwxrwx`(항상777) 항상취약 오플래그(mariadb my.cnf 기본 심링크) → docker maria_dbm 실증(심링크→양호, 실644→취약 유지).
  **검토 방식(빠른 triage)**: 항목마다 [항목명/판단기준(xlsx)/엔진 기준(벤더 로직) **별도 표기**/이진?맥락? 라우팅 권고] 간결 제시 → 사용자 결정. det 유지면 polarity·미설정→양호만 스팟체크.

  **✅ DBM-031 SA 계정 보안설정 — DET 유지 + 빈RESULT 가드 SHIP (2026-06-18, 1432 passed)**: mssql 전용(타엔진 N/A, mssql_rds ABSENT). 엔진 로직 `is_disabled=='0' AND is_policy_checked=='0'` → 취약(로직 자체완결, polarity 정확). 스팟체크로 **빈배열(미수집)→양호 거짓양호** 발견 → `_EMPTY_RESULT_HOLD`에 DBM-031 추가(모드D)→판단보류. "적절한 보안정책"=is_policy_checked(CHECK_POLICY) 좁은 해석. 회귀핀 +4(비활성→양호/정책적용→양호/정책미적용→취약/빈배열→판단보류). 키부재는 R3 차단.

  **✅ DBM-030 AUD$ 접근제어 → label B 전환 SHIP (2026-06-18, 1428 passed)**: oracle 전용. **스팟체크로 거짓취약+거짓양호 동시 발견**: `exception.DBM-030.owner=[]`(빈 예외) → `owner not in []` 항상True → **SYS(관리자)까지 전부 취약(거짓취약)**, 빈 RESULT → 양호(거짓양호). "일반 사용자 vs 관리자" 구분은 사이트별 맥락(커스텀 DBA) → 결정론 신뢰불가. → `db_oracle.yaml` DBM-030 label A→**B**(det_common 후보수집 + LLM "관리자/일반 구분 집계요약" + 판단보류). DBM-015/017/020/024/028(권한 적절성=맥락) 동형. 거짓취약·거짓양호 양쪽 회피.

  **✅ DBM-028 불필요 DB Object — 변경 불필요 (2026-06-18)**: "업무상 불필요" 맥락항목. 이미 전 엔진 label B(native det_common 후보수집+LLM 집계요약, pg STUB[lambda True 거짓취약 차단]). verdict 판단보류 fail-safe. 손댈 것 없음.

  **✅ DBM-029 RESOURCE_LIMIT(oracle 전용) — 빈RESULT 가드 SHIP (2026-06-18, 1428 passed)**: oracle만 평가대상(나머지 N/A). 이진설정(RESOURCE_LIMIT TRUE/FALSE), polarity 정확(value∈['FALSE']→취약). **스팟체크로 거짓양호 1건 발견·수정**: RESULT 빈배열(RESOURCE_LIMIT 미수집)→양호였음 → `_EMPTY_RESULT_HOLD`에 DBM-029 추가(모드D 재사용)→판단보류. value 키 부재는 R3가 별도 차단. 회귀핀 +3. TRUE→양호/FALSE→취약/빈배열→판단보류 확인.

  **✅ DBM-026 umask 거짓양호 버그픽스(R-026) SHIP (2026-06-18, 1425 passed, Opus SHIP)**: 평가대상 mysql/oracle/mariadb/pg(mssql N/A, cloud ABSENT). xlsx=umask 022 이상 양호. **벤더 버그**: `int(output)%100 + "3/4/5" 휴리스틱`(10진 파싱+엉뚱조건) → umask 020/002/000/070/007 전부 거짓양호(000 최악도 양호). **수정**: 5엔진 `_umask_is_violation` 헬퍼(8진 토큰 last3자리, **group≥2 AND other≥2면 양호, 아니면 취약, 파싱불가→None**) + 어댑터 모드F 가드(RESULT 빈배열/8진토큰0 → 판단보류). KNOWN_BUGS R-026, 테스트 +44. 합성: 020/002/000/070/007→취약, 022/027/077→양호, 미수집/심볼릭→판단보류.

  **✅ DBM-024 불필요 WITH GRANT OPTION — 변경 불필요 (2026-06-18, 빠른 triage)**: "운영상 불필요" 맥락항목. 이미 전 엔진 **label B**(det_common 후보수집 IS_GRANTABLE=YES + LLM 계정별 집계요약 + 판단보류). fail-safe. 손댈 것 없음.

  **✅ DBM-025 EoS/EOL — judge_eol 신선도 강등(옵션C) SHIP (2026-06-18, 1381 passed)**: 이미 전 엔진 label D + eol_check + eol.yaml(as_of 2026-06-17, 5 DB엔진). patch-eol-baseline-policy 적용 상태. **정책 불일치 수정**: judge_eol 지원중 분기가 자동 양호였는데 → `(today-as_of).days > _STALE_DAYS(180)` 또는 as_of None이면 **양호→판단보류 강등**(stale 거짓양호 차단, 경고와 verdict 일치). 신선(≤180일)이면 양호 유지. EOL경과→판단보류 불변. eol.py·test_eol.py(+5). 실데이터(1일 경과)→양호 불변. ⚠️ 이 변경은 judge_eol 전 호출자(타 도메인 EOL 포함)에 적용 — EOL 신선도 안전망 일관 강화. **+ 문구 보강(사용자 재논의)**: EOL경과 분기 rationale = verdict 판단보류 유지하되 "서비스 지원 종료(EoS) 확인. 사후관리 절차(교체계획 수립·보고/위험수용 관리)가 확인되지 않으면 취약." 명시(xlsx "EoS+사후관리없음=취약" 정합, stale 거짓취약은 회피). [[patch-eol-baseline-policy]]
  - DBM-022 CRITICAL 버그픽스 완료(2026-06-18): 파일접근권한 거짓양호(전 엔진) 수정. DET 유지(수집판단 정확). 판단보류(모드E) 추가로 파일미수집 케이스도 가드.

  **✅ DBM-022 파일접근권한 CRITICAL 버그픽스 SHIP (2026-06-18, 1367 passed, 거짓양호 0건)**:
  - **CRITICAL 버그**: `det_adapters/db.py` `_filter_noise` — `not isinstance(row, dict): continue` → bare str 위반행 전부 드롭 → violations=0 → 무조건 양호(거짓양호). 벤더 `dbm_022`가 file_entry를 bare str로 직접 append해 발생(mysql/oracle/mariadb/pg/tibero 전 엔진).
  - **수정 1 (핵심)**: `_filter_noise` — bare str → `{"*": row}` 래핑 보존으로 변경. docstring에 근거("Note/alert는 모두 dict로 도착 → 래핑이 거짓취약 유발 없음") 추가.
  - **수정 2 (2차 가드, 모드E)**: `_PERM_GUARD = frozenset({"DBM-022"})` + `_dbm022_has_perm_line()` + `_PERM_LINE_RE` 추가. RESULT에 행은 있으나 권한패턴(`[drwxstl-]{10}`) 0건이면 판단보류(파일미수집/접근실패). 보수 원칙: 불확실 → 거짓양호 회피 우선.
  - **판정 검증**: -rw-r--r--(other=r) → **취약**, -rw-rw----(group=w) → **취약**, -rwxrwxrwx → **취약**, -rw------- → **양호**, -r-------- → **양호**, No-such-file 출력 → **판단보류**.
  - **회귀 확인**: Note/alert dict 행은 래핑 안 되고 기존대로 제거. oracle DBM-001 hashcat → crack_judge 경로(filter_noise 미경유). 다른 항목 거짓취약 0건. 1367 passed.
  - **신규 테스트(21건)**: `TestFilterNoiseBareStringPreservation`(5건), `TestDBM022PermGuardUnit`(6건), `TestDBM022FalsePositiveBugFix`(10건).
  - **수정 파일**: `det_adapters/db.py`, `tests/test_det_adapters_db.py`(+21건).

  **✅ DBM-020 사용자별 계정 분리 — 변경 불필요 (2026-06-17, 빠른 triage)**: 맥락·인터뷰 항목(xlsx "인터뷰로 확인", "적절히 분리"). 이미 5엔진 모두 **label B(인터뷰+LLM 계정목록 요약, verdict 판단보류)** 로 정확히 분류돼 있음. verdict 항상 판단보류 → 거짓양호 불가(fail-safe). 손댈 것 없음.

  **✅ DBM-021 ODBC/OLE-DB 데이터소스·드라이버 제거 → label C SHIP (2026-06-17, 1346 passed)**: **mssql만 평가대상**(나머지 N/A 스킵). **SQL 자동점검 불가**(3중 일치: 점검스크립트 mssql.sql:525 "Self-Managed:콘솔에서 확인, CSP-Managed:N/A" / 수집샘플 증거없음 / 벤더 analysis.py:34 "쿼리로 확인 불가"). → `db_mssql.yaml` DBM-021 **label C + canned_message**("ODBC/OLE-DB는 SQL 점검 불가 → 관리콘솔에서 업무상 불필요 항목 제거 여부 확인 필요(판단보류)"). 실검증: mssql_native DBM-021 verdict=판단보류+사유 출력 확인. mssql_rds=ABSENT(스킵) 유지(=CSP-Managed N/A). [[dbms-feature-absent-policy]] 동류(평가대상이나 자동점검 불가→판단보류+안내).

### deep-audit 백로그 (보류 — 필요시 정밀감사 적용)
빠른 triage로 넘어가며 **전수 deep-audit를 보류한 항목군**. 픽스처/듀얼런이 이상 신호를 주거나 사용자 요청 시 재개.
- **DB det_common 항목 전반(020~036 중 det 유지분)**: 모드D식 "미설정→양호 거짓양호" 가드, polarity 정밀 재검은 **스팟체크로 대체**. 픽스처 결과가 깨끗하지 않으면 해당 항목만 정밀감사.
- **서버 도메인(완료분)**: 기존 분류 유지, 추가 정밀 det-audit 보류(픽스처/듀얼런 안전망에 위임).
- **패치/EOL 항목**: [[patch-eol-baseline-policy]] D+힌트로 처리(자동verdict 금지) — 별도 deep-audit 불필요.
- **(Low) DBM-026 umask 다중토큰 휴리스틱**: 벤더 `_umask_is_violation`가 `tokens[-1]`(마지막 8진토큰) 채택 → `umask` 출력에 후행 숫자(pid/uid/타임스탬프) 섞이면 거짓취약 가능. 거짓양호 방향 아님(안전). native umask 실수집 샘플 확보 시 출력포맷 재확인 + 정규식 단독토큰 강화 고려(Opus 권고, 비차단).
- **(재검토 후보) DBM-030 AUD$ DET 승격**: 현재 label B(맥락). oracle 점검 SQL이 admin 계정을 **선필터링**해 "진짜 의심 계정만" 반환함이 **실 AUD$ 샘플로 확인되면** DET(결과 있으면 취약) 승격 재검토 가능. 현재는 실샘플 없고 Python 예외층 비어 신뢰근거 없어 label B 유지.

  **✅ DBM-019 mariadb polarity 버그픽스 (R-MA019) SHIP (2026-06-17, 1346 passed)**:
  - **버그**: `mariadb/analysis.py dbm_019` — `INTERVAL > DAY[0](30) or INTERVAL == 0 → 취약`. INTERVAL=60(강한 설정) → 거짓취약.
  - **xlsx 판단기준**: "설정 여부"(이진). `INTERVAL > 0 → 양호`, `INTERVAL == 0 / not-loaded → 취약`. DAY 임계값 개념 없음(사용자 확정 'B').
  - **수정**: `dbm_019` dict 분기 → `int(datum['VARIABLE_VALUE']) == 0` 만 위반조건. `DAY[0]` 임계값 비교 제거.
  - **config**: `mariadb-config.json rules.DBM-019.DAY["30"]` 제거 → `{}` (미사용, 근거 KNOWN_BUGS.md R-MA019).
  - **KNOWN_BUGS.md**: `R-MA019` 항목 신규 등록(위치·증상·corrected 동작·회귀테스트 핀).
  - **신규 테스트(+2건)**: `test_mariadb_interval_60_is_good`(핵심 거짓취약 케이스), `test_mariadb_interval_1_is_good`.
  - **실데이터 불변**: mariadb_native DBM-019=취약(plugin not loaded). 변경 없음.
  - **수정 파일**: `vendor/common/db/mariadb/analysis.py`(이미 수정됨), `vendor/common/db/config/mariadb-config.json`, `vendor/common/KNOWN_BUGS.md`, `tests/test_det_adapters_db.py`(+2건).

  **✅ DBM-019 모드D 확장(Opus Critical 갭 수정) SHIP (2026-06-17, 1344 passed, 거짓양호 0건)**:
  - **Critical 수정**: `det_adapters/db.py` 모드D를 "기대변수 부재 → 판단보류"로 확장.
    - `_dbm019_mysql_has_expected()`: RESULT 행 중 `VARIABLE_NAME ∈ {password_history, password_reuse_interval}` 존재해야 양호 가능. 없으면 판단보류.
    - `_dbm019_mariadb_has_expected()`: RESULT 행 중 dict `VARIABLE_NAME == PASSWORD_REUSE_CHECK_INTERVAL` 또는 str `"not loaded"` 신호 있어야 양호 가능. 없으면 판단보류.
    - `_DBM019_EXPECTED_CHECKER` dict에 `{"mysql": ..., "mariadb": ...}` 등록. 매핑 없는 엔진(oracle/mssql)은 기존 0행-only 유지(직접 인덱싱→KeyError로 이미 안전).
    - 판단보류 사유: `"[재사용방지 설정 변수 미수집 → 판단보류] RESULT에 N행이 있으나 재사용 방지 기대 변수가 포함되지 않음 — 자동 양호 판정 불가"`.
  - **신규 테스트(+7건)**: `TestDBM019PasswordReuse` §8 — mysql Critical재현(→판단보류), mysql 다수행 기대변수 부재(→판단보류), mysql 기대변수+기타행 혼재(→양호 불변), mariadb Critical재현(→판단보류), mariadb 다수행 기대신호 부재(→판단보류), mariadb 기대변수+기타행(→양호 불변), mariadb not-loaded+기타행(→취약 불변).
  - **실데이터 불변 확인**: mysql_native DBM-019=취약(history=0,reuse_interval=0), mariadb_native DBM-019=취약(plugin not loaded). 변경 없음.
  - **Medium 해결(R-MA019)**: mariadb `INTERVAL > 30 → 취약` polarity 버그 → 이번 세션 수정 완료. `analysis.py dbm_019` + `config DAY 제거` + `KNOWN_BUGS.md R-MA019` + 테스트 +2건.
  - **수정 파일**: `det_adapters/db.py`, `tests/test_det_adapters_db.py`(+7건).

  **✅ DBM-019 비밀번호 재사용 방지 SHIP (2026-06-17, 1337 passed, 거짓양호 0건)**:
  - **판단기준**: 양호=이전 비밀번호 재사용 불가 설정 / 취약=재사용 가능(미설정 포함).
  - **mariadb DET 복원**: `DET_SOURCE.yaml` mariadb: STUB→DET. `db_mariadb.yaml` DBM-019에 `judgment_method: det_common` 복원. analysis.py `PASSWORD_REUSE_CHECK_INTERVAL/"not loaded"` 탐지 정상 확인(실데이터: "PASSWORD_REUSE_CHECK plugin is not loaded!" → 취약 ✓).
  - **거짓양호 가드(모드D)**: `det_adapters/db.py` `_EMPTY_RESULT_HOLD = frozenset({"DBM-019"})` 신규 추가. RESULT 완전 비어있음(0행) → `모드D 가드` → 판단보류(설정 미수집). RESULT에 데이터행 있으나 위반 없음 → 양호(현행 유지). 적용: mysql/oracle/mssql/mariadb native+cloud.
  - **pg label C 기능부재 안내**: `db_postgresql.yaml` DBM-019 `label: A→C` + `canned_message: "PostgreSQL은 비밀번호 재사용 방지를 native 지원하지 않음(passwordcheck 등 확장/외부 정책 필요) → 자동 점검 불가, 추가 확인 필요(판단보류)."`. `classify_method(C)='det'` → `_defer_or_eol` → `_auto_defer(canned_message)`. DET_SOURCE pg STUB 유지(주석: label C 기능부재).
  - **실데이터 5엔진 검증**: mysql=취약(history=0, reuse_interval=0), mariadb=취약(plugin not loaded), oracle=취약(8건 UNLIMITED), mssql=양호(all policy_checked=1), pg=판단보류+기능부재안내. 거짓양호 0건.
  - **신규 테스트(21건)**: `TestDBM019PasswordReuse` — mariadb DET 복원(2종), 적절설정→양호(4종), 부적절설정→취약(4종), 빈RESULT→판단보류(4종), "not loaded"→취약(1종), pg label C+canned(2종), 실데이터 거짓양호0(4종).
  - **수정 파일**: `vendor/common/DET_SOURCE.yaml`, `item_configs/db_mariadb.yaml`, `item_configs/db_postgresql.yaml`, `det_adapters/db.py`, `tests/test_det_adapters_db.py`(+21건).

  **✅ DBM-016 D+판단보류+힌트 정책 전환 SHIP (2026-06-17, 1299 passed, 자동verdict 0건)**:
  - **정책**: 패치/EOL/버전-최신성 항목 verdict=판단보류 고정, 자동 양호/취약 금지. 버전 기준선은 eol.yaml(as_of 스탬프), 힌트만 제공.
  - **문제**: DET_SOURCE DBM-016 mysql/oracle/mssql/pg+cloud variant = DET → gate() 통과 → `analysis.dbm_016()` 하드코딩 `rules['version']`과 비교 → 자동 취약/양호 (stale 기준, 정책 위반).
  - **해결A (DET_SOURCE.yaml)**: DBM-016 전 variant STUB 전환 (mysql/oracle/mssql/pg + 클라우드 _rds/_aurora/_azure). gate() → handled=False → `_det_common_label_route` → label D → `_defer_or_eol` → `judge_patch` → 판단보류 + 힌트.
  - **해결B (eol.yaml)**: `as_of: 2026-06-17` 갱신. Oracle 19c `latest: "19.28.0.0.250715"` 신규 등재(oracle-config.json 2025.09 기준). mssql 2017 `latest: "14.0.3490.10"` 신규. MySQL 9.0 시리즈 추가. 구 MySQL 9.6/9.7 제거(PostgreSQL 시리즈와 혼동 방지). 기존 더 높은 버전 유지(8.4.9, 8.0.46, 15.0.4470.1, 16.0.4255.1, 13.23~17.10 등).
  - **서버 B (server.yaml SRV-007/064/179)**: eol.yaml 베이스라인 없음 → canned 판단보류 유지. canned 문구에 "버전 기준선(as_of) 확보 시 힌트 제공 예정 — 현재 담당자 확인" 추가.
  - **서버 audit**: 서버 det_common 항목(SRV-001/004/008 등) 전수 확인 → 버전/패치 자동 verdict 항목 없음. SRV-007/064/179 = label D + "det" 핸들러 → _defer_or_eol → canned 판단보류(정책 일치).
  - **검증**: 5엔진 전부 `judge_patch` 반환 판단보류 + 힌트("현재vX vs 기준일 최신vY → 미적용 후보"). oracle 19.26 < 19.28 힌트 생성. 온라인 호출 없음(eol.yaml 로컬 정적). 거짓양호 0, 거짓취약 0.
  - **신규 테스트(8건)**: DBM-016 gate STUB 전 variant(14개 variant), mysql/mssql/oracle/pg native 판단보류+힌트, mariadb canned 폴백, 5엔진 포괄 자동verdict 0 단언.
  - **수정 파일**: `vendor/common/DET_SOURCE.yaml`, `judge_tool/eol.yaml`, `item_configs/server.yaml`, `tests/test_eol.py`(oracle latest 테스트 갱신), `tests/test_main_db_e2e.py`(+8건).

  **✅ DBM-017 label B(인터뷰)+LLM요약 구현 SHIP (2026-06-17, 1316 passed, 양호자동판정 0건)**:
  - **판단기준**: 양호=업무상 필요한 시스템테이블 접근권한만 / 취약=업무상 불필요한 권한 존재. "업무상 불필요"=맥락 판단 → 결정론 부적합.
  - **문제**: mysql/mariadb/oracle = DET(exception-기반 비교) → 과탐/미탐 위험. mssql = STUB(빈 본문), pg = STUB(수집형식 불일치·PUBLIC 과탐). 전부 결정론으로 "업무상 불필요" 판단 불가.
  - **해결: label B(인터뷰)로 전 native 5종 이관** — `judgment_method: det_common` 제거(mysql/mariadb/oracle), label B + 상세 `summary_instruction` → `classify_method=interview` → `_summarize_one` 라우팅(det_common 어댑터 미호출).
  - **db_{mysql,mariadb}.yaml DBM-017**: `judgment_method: det_common` + `needs_review: true` 제거. `label: B` + 상세 `summary_instruction`(information_schema 구분·업무상 불필요 의심 DML·판정 금지). 라우팅 주석 추가.
  - **db_oracle.yaml DBM-017**: `judgment_method: det_common` + `needs_review: true` 제거. `label: B` + 상세 `summary_instruction`(SYS·DBA_*·딕셔너리 구분·업무상 불필요 의심·판정 금지).
  - **db_mssql.yaml DBM-017**: 기존 label B 유지. `summary_instruction` 상세화(sys·INFORMATION_SCHEMA 구분·업무상 불필요 의심·판정 금지).
  - **db_postgresql.yaml DBM-017**: 기존 label B 유지. `needs_review: true` 제거. `summary_instruction` 상세화(pg_catalog·information_schema 구분·PUBLIC 기본권한 설명·업무상 불필요 의심·판정 금지).
  - **DET_SOURCE.yaml DBM-017**: mysql/oracle/mariadb native `DET→STUB` + 주석 "label B 이관(exception-기반 과탐/미탐 회피)". mssql/pg STUB 유지(기존). 클라우드 변형(mysql_rds/oracle_rds/mariadb_rds/pg_rds 등)은 DET 유지.
  - **라우팅 확인**: label B + summary_instruction → `classify_method(B, has_summary=True)='interview'` → `_summarize_one` → `verdict=판단보류`, `interview_summary` 채움. det_common 어댑터(exception-기반 오판 경로) 완전 우회. pg PUBLIC 과탐 해소.
  - **기존 테스트 갱신**: `test_det_dbm017_handled`(DET/handled=True 단언) → `test_det_dbm017_gate_blocked`(STUB/handled=False + 거짓양호 없음 단언).
  - **신규 테스트(17건)**: `TestDBM017LabelBRouting` — classify=STUB(5엔진), gate 차단(5엔진), pg PUBLIC 과탐 차단, judgment_method 없음 yaml 검증, summary_instruction 키워드(5엔진), 클라우드 DET 유지(4변형), fake LLM summary 생성경로.
  - **수정 파일**: `item_configs/db_mysql.yaml`, `item_configs/db_mariadb.yaml`, `item_configs/db_oracle.yaml`, `item_configs/db_mssql.yaml`, `item_configs/db_postgresql.yaml`, `vendor/common/DET_SOURCE.yaml`, `tests/test_det_adapters_db.py`(+17건, docstring 갱신).

  **✅ DBM-015 label B(인터뷰)+LLM요약 구현 SHIP (2026-06-17, 1291 passed, 양호자동판정 0건)**:
  - **문제**: mssql DET였으나 `rules['permission_name']=[]`(빈) → `datum in []` 항상 False → 위반 0 → handled=True+양호(거짓양호). pg STUB이나 `privilege_type` KeyError → pg_catalog 기본 PUBLIC SELECT 과탐(거짓취약). oracle 015_1/2 `lambda:True` 과탐.
  - **해결: label B(인터뷰)로 이관** — `judgment_method: det_common` 제거(mssql), label B + summary_instruction → `classify_method=interview` → `_summarize_one` 라우팅(det_common 어댑터 미호출).
  - **db_mssql.yaml DBM-015**: `judgment_method: det_common` + `needs_review: true` 제거. `label: B` + 상세 `summary_instruction` 추가. 코멘트: "label B이관, rules['permission_name']=[] 거짓양호 회피".
  - **db_oracle.yaml DBM-015**: `label: B` 유지(기존). `summary_instruction` 상세화(SYS·시스템권한 구분, 업무상 불필요 의심 DML 우선, 판정 금지).
  - **db_postgresql.yaml DBM-015**: `label: B` 유지(기존). `summary_instruction` 상세화(pg_catalog·information_schema 구분, 업무 객체 DML 우선, 판정 금지).
  - **DET_SOURCE.yaml DBM-015 mssql**: `DET → STUB` + 주석 "label B 이관(빈 rules 거짓양호 회피)". cloud mssql_rds/pg_rds/pg_aurora/pg_azure는 DET 유지.
  - **라우팅 확인**: label B + summary_instruction → `classify_method(B, has_summary=True)='interview'` → `_summarize_one` → `verdict=판단보류`, `interview_summary` 채움. det_common 어댑터(mssql 거짓양호 경로) 완전 우회.
  - **실데이터 3엔진 검증**: oracle/mssql/pg native → `verdict=판단보류`, `judgment_method=interview`, `interview_summary` 생성, 양호 자동판정 0건.
  - **mysql/mariadb N/A 유지**: applicable=False → 스킵 정상.
  - **실LLM 품질(qwen3-coder:30b)**: mssql DBM-015 `verdict=판단보류` + `interview_summary`에 PUBLIC 권한 목록 생성 확인.
  - **신규 테스트(14건)**: `TestDBM015LabelBRouting` — classify=STUB(oracle/mssql/pg), gate 차단(3엔진), label B→interview 라우팅, mssql 거짓양호 경로 미호출, yaml 키워드 확인, DET_SOURCE mssql=STUB, cloud mssql_rds/pg_rds DET 유지, fake LLM summary 생성경로.
  - **수정 파일**: `item_configs/db_mssql.yaml`, `item_configs/db_oracle.yaml`, `item_configs/db_postgresql.yaml`, `vendor/common/DET_SOURCE.yaml`, `tests/test_det_adapters_db.py`(+14건, docstring 갱신).

  **✅ DBM-013 확정 분류 구현 SHIP (2026-06-17, 1270 passed, 양호자동판정 0건)**:
  - **mysql/mariadb DET + HOST 와일드카드 보강(R-MY013/R-MA013)**: `vendor/common/db/{mysql,mariadb}/analysis.py dbm_013` 기존 `datum['HOST'] in rules['HOST']`(정확매칭) → `'%' in datum['HOST']`(포함 매칭)으로 변경. `'%'`(전체), `'10.%'`(서브넷), `'%.dom'`(도메인) 등 부분 와일드카드 미탐 거짓양호 갭 차단. localhost/특정IP/특정호스트 → 양호 유지. exception USER 제외 보존. VENDOR-EDIT(c) 등재.
  - **oracle STUB 명확화**: `vendor/common/db/oracle/analysis.py dbm_013` — lambda:True(무조건 취약=과탐)에 주석 "미사용(STUB, gate 차단)" 명기. DET_SOURCE oracle=STUB → gate 차단(handled=False) → LLM 라우팅. db_oracle.yaml DBM-013에 라우팅 주석 추가.
  - **mssql/pg 증거미수집 보류**: 빈본문(STUB) → gate 차단 → 양호 자동판정 금지. db_mssql.yaml·db_postgresql.yaml DBM-013에 보류 경로 주석 추가.
  - **KNOWN_BUGS.md**: R-MY013, R-MA013 신규 등재(위치/증상/수정/회귀핀).
  - **실데이터 검증**: mysql 실데이터(root@% → exception 제외 → 양호), 합성 와일드카드 3종(전체/서브넷/도메인) → 취약, 특정호스트/localhost → 양호. oracle/mssql/pg → gate 차단(양호 자동판정 0).
  - **신규 테스트**: `TestDBM013HostWildcard` 19종(mysql/mariadb 와일드카드·양호·예외, oracle/mssql/pg gate차단, judge() 통합). 1270 passed.
  - **수정 파일**: `vendor/common/db/mysql/analysis.py`, `vendor/common/db/mariadb/analysis.py`, `vendor/common/db/oracle/analysis.py`, `vendor/common/KNOWN_BUGS.md`, `item_configs/db_oracle.yaml`, `item_configs/db_mssql.yaml`, `item_configs/db_postgresql.yaml`, `tests/test_det_adapters_db.py`.

  **✅ DBM-011 pg/mssql DET 승격 + rationale 확인내용 강화 SHIP (2026-06-17, 1210 passed)**:
  - **pg STUB→DET 승격**: `vendor/common/db/postgresql/analysis.py dbm_011` 신규 포맷(pgaudit_settings) 탐지 추가. VENDOR-EDIT(c) §R-PG011. pgaudit 미로드(value에 pgaudit 없음 OR pgaudit_status≠Loaded OR pgaudit_settings==[]) → 위반 → 취약. 로드됨 → 위반0 → 모드C 보류. 옛 한글 문자열 하위호환 유지. `DET_SOURCE.yaml` pg: STUB→DET. `db_postgresql.yaml` DBM-011에 `judgment_method: det_common` 추가.
  - **mssql STUB→DET 승격**: `vendor/common/db/mssql/analysis.py dbm_011` 활성 감사 탐지 로직 추가. VENDOR-EDIT §R-MS011. 활성 감사 0행 → 위반(취약). ≥1행 → 위반0(보류). ⚠️ NOTE 우선순위 함정 해소: `db_mssql.yaml`에 `judgment_method: det_common` 부여 → `_det_common_handler` 경로(NOTE 강제보류 없음) → 미수집→취약이 NOTE에 안 가려짐. `DET_SOURCE.yaml` mssql: STUB→DET.
  - **파서 Phase 4e**: `parsers/db_json.py` parse()에 빈 RESULT 항목용 raw-carrier 더미 리소스 추가(mssql DBM-011 RESULT=[] + NOTE = resources[] → raw_evidence 미전달 → _judge_one 경로로 빠지는 문제 해소).
  - **보류 rationale 확인내용 강화**: `det_adapters/db.py` `_extract_audit_detail()` 신규. 모드C 보류 시 엔진별 확인내용 rationale+citations에 추가 — mysql:"audit_log 플러그인 로드됨 (audit_log_file=...)", mariadb:"server_audit 플러그인 로드됨", oracle:"audit_trail=<값> (감사 활성)", pg:"pgaudit 로드됨 (settings=...)", mssql:"활성 서버감사: <name> (action=...) — PISM-011 참조".
  - **실데이터 5엔진 DBM-011 verdict**: pg=취약(det_common, pgaudit Not Loaded), mssql=취약(det_common, No Active Server Audit), mysql/mariadb/oracle=취약(det_common, not loaded/NONE). 양호 자동판정 0건.
  - **신규 테스트**: pg DET 승격(6종), mssql DET 승격(5종), 보류 rationale 확인내용(3종), 전수 거짓양호 확장(pg/mssql 추가). 기존 STUB 테스트 4종 교체.
  - **수정 파일**: `det_adapters/db.py`, `vendor/common/db/postgresql/analysis.py`, `vendor/common/db/mssql/analysis.py`, `vendor/common/DET_SOURCE.yaml`, `item_configs/db_postgresql.yaml`, `item_configs/db_mssql.yaml`, `parsers/db_json.py`, `tests/test_det_adapters_db.py`, `tests/test_db_json.py`.
  - **★Opus 적대리뷰 C1/M1/M2/M3 shift-left 해소(2026-06-17, 1222 passed)**:
    - **C1(Critical)**: raw-carrier가 무조건 추가돼 `reconcile`의 `no_evidence` 안전게이트를 **DB 파서 전역에서 무력화**(빈RESULT+LLM항목이 양호 무검증 통과 지뢰). → **carrier 격리**: `models.ResourceEvidence.is_raw_carrier` 필드 신설, `judge.py reconcile` no_evidence·`build_evidence_text(_raw)` LLM증거에서 carrier 제외(실증거만 카운트). `_raw_evidence_for_det`는 carrier raw 계속 읽음 → det_common(mssql 0행→취약) 보존. **검증: carrier-only+LLM양호→판단보류 복원, build_evidence_raw→"(점검 결과 0건)", mssql DBM-011→취약 유지.**
    - **M1**: `_extract_audit_detail` citation을 `_mask_row` 경유(raw config 비마스킹 노출 차단).
    - **M2**: `KNOWN_BUGS.md`에 §R-PG011·§R-MS011 신규 등재(코드 주석이 인용하나 누락됐던 것).
    - **M3**: C1로 동시 해소(carrier가 LLM 증거텍스트에서 제외 → "(점검 결과 0건)" 복원).
    - 회귀가드 테스트 12종(carrier no_evidence 복원·LLM증거 제외·det_common 보존·citation 마스킹). **1222 passed, 4 skipped.**

  **✅ DBM-011 detect-vuln-else-hold (모드C) 구현 SHIP (2026-06-17, 1197 passed, 양호자동판정 0건)**:
  - **새 모드 `_DETECT_VULN_ELSE_HOLD`**: `db.py`에 모드C 추가. DBM-011 등록. 취약(violations>0) → 취약 확정, 위반0(수집됨) → 판단보류 강제(양호 자동판정 절대 금지).
  - **mariadb DET 복원**: `DET_SOURCE.yaml` mariadb=STUB→DET. analysis에 "not loaded" 탐지 확인(실데이터 `"server_audit.so plugin is not loaded!"` 일치). `db_mariadb.yaml`에 `judgment_method: det_common` 추가.
  - **pg STUB 유지**: 벤더 탐지조건(`'로드된 라이브러리가 없습니다.' in str(datum)`)이 실수집 데이터(`pgaudit_settings:[] dict`) 와 불일치 → 보수적 STUB 유지. LLM이 취약 탐지.
  - **mssql STUB 유지**: 빈 본문(dbm_result=[]만) → 결정론 불가 → LLM(label A) 경로.
  - **실데이터 5엔진 검증 결과**:
    - mysql: 취약(det_common, conf=0.90) — "audit_log.so plugin is not loaded!" 탐지
    - mariadb: 취약(det_common, conf=0.90) — "server_audit.so plugin is not loaded!" 탐지
    - oracle: 취약(**det_common, conf=0.9** — "결정론 판정: 감사로그 미수집") audit_trail=NONE. **(dateutil 설치 후 실제 DET 작동)**
    - mssql: 판단보류(llm) — NOTE 인터뷰 필요
    - postgresql: 취약(llm) — pgaudit 미로드 LLM 탐지
    - **양호 자동판정 0건 확인**
  - **★Opus 적대리뷰 High 해소(2026-06-17): oracle/mssql 벤더 의존성**: `vendor/common/db/{oracle,mssql}/analysis.py·cloud_analysis.py`가 `dateutil.relativedelta`·`packaging.version`(비표준, DBM-008 날짜·DBM-016/025 버전비교 실사용) import → **미설치 시 모듈 import 실패 → oracle/mssql 전 DBM 항목 무징후 LLM 폴백**(classify=DET/runtime=LLM 모순). **사용자 결정=requirements.txt 선언+설치**(`python-dateutil>=2.8`, `packaging>=21.0` 추가, `--break-system-packages` 설치). → oracle/mssql DET 복구 실증(oracle DBM-011 취약 det_common 0.9). **타위치 pull 시 `pip install -r requirements.txt` 필수.**
  - **테스트 마스킹 제거(Opus)**: oracle DBM-011 테스트가 "취약/판단보류 양분 수용"으로 DET 미검증 → **미수집→취약(DET)·수집됨→판단보류 분리 단정**(`pytest.importorskip("dateutil")` 가드).
  - **단위테스트**: `TestDBM011DetectVulnElseHold` 신규 (mysql/mariadb/oracle/mssql/pg/cloud/전수거짓양호) — **1197 passed, 4 skipped**.
  - **수정 파일**: `det_adapters/db.py`, `vendor/common/DET_SOURCE.yaml`, `item_configs/db_mariadb.yaml`, `tests/test_det_adapters_db.py`, **`requirements.txt`(dateutil/packaging 선언)**

  **✅ DBM 분류검토 Batch1 (003~009) 구현 SHIP (2026-06-17, 1176 passed, Opus 적대리뷰 SHIP·Critical0)**:
  - **DBM-003**: 현행 DET 자동판정 유지.
  - **DBM-004**: 모드A detect-then-hold — 위반(후보)≥1→판단보류+후보목록, 0→양호. `db.py _DETECT_THEN_HOLD`(전 변형).
  - **DBM-005**: 전엔진 LLM(mssql DET→STUB, 자동취약 해제). **⚠️나중에 검증 필요(LLM 암호화 판정 품질)**.
  - **DBM-006**: mysql/oracle/mssql/mariadb DET / pg_native=모드B 구조적취약(코어 실패잠금 부재, needs_review).
  - **DBM-007**: mysql/oracle/mssql DET / mariadb DET복원(STUB 오분류 정정·실증) / pg_native=모드B 구조적취약.
  - **DBM-008**: 4엔진 DET / pg_native DET(db_json pg 정규화 후).
  - **DBM-009**: mysql/oracle/mariadb DET / mssql LLM / pg=극성수정(VENDOR-EDIT, `==0 or >900`, KNOWN_BUGS R-PG009).
  - **공통 인프라**: ① `db.py` 모드A(`_DETECT_THEN_HOLD`)·모드B(`_STRUCTURAL_VULN`={pg_native 006/007}) ② `db_json.py` pg 비표준JSON 정규화(`_pg_normalize`) + bare문자열 raw 보존(벤더 type(datum)==str 검사용) ③ `main.py` 미수집 det_common→어댑터 시도(실판정 취약/양호만 채택, 모드B가 무데이터 항목에도 fire) ④ 신규 테스트 `TestBatch1Classification` 9건.
  - **미해결/이월**: pg/mariadb 나머지 R3-STUB(011/015/017/019/020/028 등)는 **항목 검토 때 각각 재감사**(mariadb는 대체로 과보수 오분류→DET복원 가능, pg는 정규화로 복원). DBM-005 LLM 품질 검증 TODO.

  Phase 4c (b+a) hashcat 연동 SHIP.

  **Phase 4c (b+a) 완료 상태**:
  - (b) 레이어: 5엔진 정적 사전공격 (mysql_native/mariadb/mssql/pg/oracle-11g 포맷 지원)
  - **(a) 레이어 SHIP**: `export_for_external` + `run_hashcat` + `crack_judge` hashcat 통합
  - **graceful skip**: hashcat 미설치 → (b)-only 정상 동작, `pwcrack_a=skipped(no hashcat)` 표시
  - **§7 보안**: potfile 평문 즉시 폐기, citation 고정문구 "사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)", 임시파일 0600+finally 삭제
  - **CLI 확장**: `--hashcat-path/--hashcat-wordlist/--hashcat-rules/--hashcat-timeout`
  - **모듈 세임**: `set_hashcat_opts/clear_hashcat_opts` (단일프로세스 CLI 안전)
  - **5엔진 실데이터 graceful skip 실증**: 전부 판단보류(거짓판정 0), oracle handled=False 유지

  **잔여 미해결**:
  - caching_sha2 (a) 모드 미확정 (hashcat 버전별 모드 번호 검증 필요 — 현재 주석처리)
  - oracle DBM-001 실데이터 미수집 (SYSDBA spare4 접근 선결)
  - 벤더 룰/keywords.txt 대용량 자산 경로 설정형(운영자 제공)

  설계서: `docs/superpowers/DESIGN_phase4c_dbm001_pwcrack.md §A2`. 수정 파일: `det_adapters/db_pwcrack.py`, `main.py`, `tests/test_det_adapters_db_pwcrack.py`.
  Opus 리뷰 집중 의심지점: subprocess 인자 주입 방지(리스트형), potfile 파싱 hash:plain 분리(rfind), 세임 단일프로세스 안전성.

- **✅ Phase 4c-a 완료 = Phase 4c-a: DBM-001 hashcat 연동 (a 레이어) (Sonnet구현, 2026-06-16)**
  - **신규/수정 파일**:
    - `judge_tool/det_adapters/db_pwcrack.py`: `HashcatOpts` dataclass, `export_for_external`, `run_hashcat`, `_detect_hashcat`, `_map_cracked_to_accounts`, `set/clear/get_hashcat_opts` 세임 추가. `crack_judge`에 (a) 통합(b-only 폴백, graceful skip).
    - `judge_tool/main.py`: `--hashcat-path/--hashcat-wordlist/--hashcat-rules/--hashcat-timeout` CLI 인자, `JudgeContext.hashcat_opts`, `run()` hashcat_opts 파라미터, 세임 주입/클리어.
    - `tests/test_det_adapters_db_pwcrack.py`: 31건 신규 (§J Phase 4c-a 테스트 — HashcatOpts구조/detect/export/mock-run/통합/§7/graceful/실데이터)
  - **(a) 오케스트레이션**: (b) 먼저 실행 → (b) 취약이면 early-return → (b) 미스 계정만 export_for_external → run_hashcat(potfile 파싱, hash만 추출) → _map_cracked_to_accounts → citations 합산
  - **graceful skip**: `_detect_hashcat(None)` → PATH 자동탐지 → 부재 시 None → (a) 스킵, `pwcrack_a=skipped(no hashcat)` rationale 표시
  - **§7 보안**: potfile `hash:plaintext`에서 `rfind(":")` 기준으로 hash만 추출·폐기, citation="사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)", 임시파일 0600+finally 삭제, subprocess 인자 리스트형
  - **pytest**: 1164 passed(+31), 9 skipped. (b) 회귀 0. 5엔진 실데이터 graceful skip 실증.

  **⚠️ Opus 리뷰 집중 의심지점**:
  1. **subprocess 인자 리스트형**: `cmd=[hashcat_path, "-m", str(mode), ...]` — 셸 인젝션 차단 확인. 경로 문자열에 공백·특수문자 포함 가능성.
  2. **potfile hash:plain 분리**: `rfind(":")` — hash 자체에 `:` 포함(postgres md5=없음, SCRAM=없음, mssql=없음, mysql=없음). 올바른 분리 확인.
  3. **세임 단일프로세스 안전성**: `_current_hashcat_opts` 모듈 글로벌 — CLI 단일프로세스라 안전. 다중스레드/병렬 실행 환경이면 threading.local() 필요.
  4. **wordlist 폴백**: wordlist=None 또는 파일 없으면 pwdict 내장 사전을 임시파일로 기록. `os.fdopen(fd, "w")` 후 fd 이중닫기 방지(`os.fdopen`이 fd 소유권 이전).
  5. **finally 삭제 안전성**: `os.unlink(tmp_path)` — 파일이 이미 없으면 OSError 무시(코드에 except OSError: pass 있음). 확인.

- **✅ Phase 4c 완료 = Phase 4c: DBM-001 비밀번호 사전공격 결정론화 (사용자 지정, 2026-06-16)**
  분류 검토 중 사용자 결정: DBM-001(취약 비밀번호)을 현행 MANUAL/canned에서 **자족 사전공격(b)**으로 전환.
  - **벤더 구조 확인**: common의 dbm_001은 판정 안 함 — oracle만 해시를 hashcat 모드별(11g=112/12c=12300/10g=3100) 정리, 나머지 빈본문. 실제 크랙=외부 hashcat(common 스냅샷 밖, keywords.txt 은행키워드+25MB 변형룰). 
  - **사용자 결정(계층형)**: **(b) 파이썬 자족 사전공격 먼저 전 엔진 완성·검증 SHIP → 이후 (a) 외부 hashcat 연동 별도 증분.** (a)=벤더 원래 방식.
  - **(b) 설계**: 기본/공통 비번 사전 → 계정별 salt로 해싱·비교. 매치=취약(평문 마스킹·§7), 미스=판단보류(복잡도 입증불가, 자동양호 없음). hashcat 불필요·stdlib만.
  - **실 해시 포맷(collected native 확인)**: mariadb=mysql_native_password(`*`+SHA1²40hex 쉬움) / mssql=`0x0200`+salt+SHA512 쉬움 / mysql=caching_sha2 `$A$005$` 중간 / pg=SCRAM-SHA-256 PBKDF2 중간 / oracle 11g SHA1+salt·12c PBKDF2-SHA512(spare4 확인).
  - **라우팅**: DBM-001 DET_SOURCE MANUAL→DET 승격 + db.py 어댑터가 base=='DBM-001'이면 벤더 대신 신규 크랙 모듈 호출. needs_review=True.
  - **리스크**: 크립토 정확성(틀리면 조용한 false-negative) → 포맷별 KAT 테스트벡터 필수. 평문 비번 §7 마스킹 필수.

  **✅ Phase 4c Sonnet 구현 완료 (2026-06-16)**:
  - **신규 파일**: `judge_tool/det_adapters/pwdict.py`(정적 사전 ~250항목), `judge_tool/det_adapters/db_pwcrack.py`(엔진별 verifier + crack_judge), `tests/test_det_adapters_db_pwcrack.py`(59건)
  - **수정 파일**: `judge_tool/det_adapters/db.py`(라우팅 주석 현행화, 이미 결정5 구현됨), `judge_tool/vendor/common/DET_SOURCE.yaml`(DBM-001 DET 승격, 이미 적용됨), `judge_tool/item_configs/db_{mariadb,mysql,mssql,postgresql,oracle}.yaml`(judgment_method: det_common + needs_review: true 추가)
  - **테스트 수정**: `tests/test_det_adapters_db.py`(MANUAL→DET 반영 3건), `tests/test_judgment_method.py`(DBM-001 det→det_common)
  - **포맷별 (b) 활성화 상태**: mysql_native=DET / mariadb=DET / mssql=DET / postgres=DET / oracle=DET(코드준비, 현 native 무데이터→handled=False→canned) / caching_sha2=**비활성**(외부KAT미확보)
  - **KAT 통과**: mysql_native 외부KAT 통과(`*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19`), mssql/postgres/oracle 라운드트립 통과, RFC5802 SCRAM-SHA-256 ServerKey 알고리즘 직접 검증 통과
  - **postgres 혼합포맷 버그 수정**: `_parse_postgres_row`에 혼합형식(이중따옴표키+단따옴표값) 정규식 추가 — 실데이터 postgresql_native 파싱 복구
  - **5엔진 실데이터 스모크**: mariadb/mysql/mssql/pg=판단보류(handled=True, 거짓취약 0), oracle=handled=False(DBM-001 부재, 정상), §7 평문비노출 확인
  - **1130 passed, 9 skipped** (신규 59건 포함)

  **⚠️ Phase 4c Opus 리뷰 집중 의심지점**:
  1. **mssql 0x0200 salt 레이아웃**: `len(hx)==70` → `salt=hx[2:6]`, `hash=hx[6:70]`. 실데이터 확인(70bytes=version2+salt4+sha512_64). len!=70/72 폴백(`pre[-4:]`)이 엣지케이스에서 올바른가.
  2. **oracle 11g S: 형식**: `body[40:60]` = 20 hex chars = 10 bytes salt. `len < 62` 가드. 실데이터 spare4 없어 실증 미완 — 11g S: 표준 레퍼런스 확인 권장.
  3. **postgres 혼합포맷 파서**: `_PG_ROLNAME_MIX_RE = r'"rolname"\s*:\s*\'([^\']+)\''` — 실데이터에만 존재하는 비표준 형식. 파서 3종 시도 순서(JSON→혼합→Python_repr)가 올바른가.
  4. **빈 해시 잠금 스킵**: mariadb `PASSWORD_EXPIRED=Y` → is_expired=True → 스킵. mysql `ACCOUNT_LOCKED=Y` → is_locked=True → 스킵. 설계의도대로 구현됐는가.
  5. **판단보류 handled=True**: 사전 미매치 케이스에서 handled=True, verdict=판단보류, ev=review 반환. label C → det_common_handler → 라벨라우팅 없이 판단보류 verdict가 reconcile 경로로 가는가. `_det_common_handler` 코드(main.py ~line 478)의 handled=True 판단보류 처리 경로 확인.

  **✅ Phase 4b Opus Medium 수정 완료 (2026-06-16)**:
  - **M-1**: DET_SOURCE.yaml 클라우드 ABSENT 명시 — engine-token 폴백이 native값(DET/STUB/MANUAL)을 반환하는 버그 수정.
    - DBM-026(전 엔진 cloud 9셀): mysql_rds/aurora/azure, oracle_rds, mssql_rds, mariadb_rds, pg_rds/aurora/azure → ABSENT
    - DBM-033(mysql cloud 3셀): mysql_rds/aurora/azure → ABSENT
    - DBM-031(mssql cloud 1셀): mssql_rds → ABSENT (폴백=DET였음)
    - DBM-013(oracle cloud 1셀): oracle_rds: STUB→ABSENT (native=STUB이나 cloud run()에 없음)
    - DBM-021(mssql cloud 1셀): mssql_rds → ABSENT (폴백=STUB였음)
    - **전수 재확인 추가 4셀**: DBM-001 mssql_rds, pg_rds/aurora/azure → ABSENT (폴백=MANUAL였음)
    - 합계: Opus 8셀 + 전수재확인 추가 4셀 = **총 19셀** 명시 ABSENT 추가
  - **M-2**: tests/test_det_adapters_db.py — classify(item, variant)=='ABSENT' 직접 단언 추가.
    - 기존 테스트 강화: DBM-026/mysql_rds, DBM-033/mysql_rds, DBM-031/mssql_rds
    - 신규 테스트: DBM-013/oracle_rds, DBM-021/mssql_rds classify=ABSENT + gate 차단
    - 종합 단언 2개: test_m1_classify_absent_all_opus_items, test_m1_classify_absent_additional_items
    - 테스트 93→97건(+4), 전체 1067→1071 passed

  **⚠️ Phase 4b 핵심 결정/주의사항 (Opus 리뷰 집중 의심지점)**:
  1. **거짓양호 차단 구조**: `DET_SOURCE.yaml` variants에 각 클라우드 변형 키 명시 → exact-variant 매칭이 engine-token 폴백보다 우선 → ABSENT 명시 항목은 gate 차단 확인(합성테스트).
  2. **native↔cloud 분류 차이 핵심**:
     - mysql cloud: 025/026/033 = **ABSENT**(native=DET, cloud run() 미호출) → 거짓양호 구조 차단
     - mysql cloud DBM-022: **STUB**(lambda True, native=DET) → gate 차단
     - oracle cloud DBM-016: **STUB**(전체 주석처리, native=DET)
     - pg cloud DBM-003/004/008/011/015/016/017/020/024: **DET**(native=STUB, cloud 다른 스키마로 직접비교)
     - pg cloud DBM-006/019: **ABSENT**(native=STUB, cloud run() 미호출) 
     - pg cloud DBM-009: **STUB**(polarity 의심 버그: <=900을 위반으로 판정)
     - mssql cloud: 019/031 = **ABSENT**(native=DET/ABSENT, cloud run() 미호출)
     - mariadb cloud DBM-019: **DET**(native=STUB, PASSWORD_REUSE_CHECK_INTERVAL 직접비교)
     - mariadb cloud DBM-022/026: **ABSENT**(native=DET, cloud run() 미호출)
  3. **캐시 키 분리**: `(engine, is_cloud, fingerprint)` — native/cloud가 같은 data를 공유 시 오판 방지 확인.
  4. **pg cloud DBM-009 STUB 사유**: `int(datum['value']) <= 900` 조건이 "timeout <= 900초"를 위반으로 판정 — 실제론 900초 이하면 양호(설정 적절)이므로 polarity 의심 → 거짓취약 방지를 위해 STUB. KNOWN_BUGS.md 등재 필요(사용자 확인 대기).
  5. **oracle cloud dbm_008 중복 호출**: cloud oracle run()에 `self.dbm_008()` 2회 호출됨(원본 버그). 결과는 무해(덮어쓰기 패턴). 벤더 원본 비트동일 복사이므로 수정 금지.
  6. **mariadb cloud dbm_008 중복 호출**: 동일 패턴. 원본 그대로.
  7. **클라우드 실데이터 검증 미완료**: results/DB 비어있음 → 구조 확인(합성)만. 실데이터 확보 후:
     - pg_rds DBM-003/004/008 DET 경로 실증(native와 다른 데이터 스키마 확인)
     - pg_rds DBM-011 pgaudit 복합 로직(AWS/Azure 분기) 실증
     - mysql_rds DBM-006 FAILED_LOGIN_ATTEMPTS/PASSWORD_LOCK_TIME_DAYS 스키마 확인
  8. **Opus 리뷰 우선순위**: (a) pg cloud DET 항목(003/004 등) native=STUB이 cloud=DET로 분류 타당성, (b) mysql_rds 025/026/033 ABSENT 차단 실증, (c) oracle_rds 016 STUB(주석) 타당성.

  **⚠️ Phase 4 핵심 결정/주의사항 (다음 세션 인계)**:
  1. **R3 거짓양호 보수처리**: pg 수집형식 `{"*": python_repr_str}` — analysis.py가 column key(`rolvaliduntil` 등) KeyError 삼킴 → `[]` → 거짓양호. pg DBM-003/004/008/011/015/017/020 = STUB(DET_SOURCE 정정). mariadb DBM-007/011/019 동일 패턴 → STUB. **수집형식 수정(flat dict rows) 후 DET 복원 가능 — TODO 잔존.**
  2. **실데이터 검증 결과 요약**: mysql(21판정 det_common=18, 거짓양호 0), oracle(25/19), mssql(23/14), mariadb(20/12), postgresql(22/6). 전 엔진 거짓양호 = 0 확인.
  3. **테스트**: `tests/test_det_adapters_db.py` 신규 64건(engine매핑·base정규화·gate차단·증거가드·noise필터·result매핑·예외내성·§7경계·raw_evidence·캐시·실파일E2E + R3차단 6건).
  4. **설계서**: `docs/superpowers/DESIGN_phase4_db_deterministic.md`(아키텍처·DET_SOURCE 분류표·R1~R7). 어댑터 `det_adapters/db.py`(5 profile_key 공유), db_json raw_evidence 적재(결정1), `.run` 모듈캐시(결정2), KNOWN_BUGS R3 등재.
  5. **⚠️벤더 소스 위치(이 머신)**: `/Users/hinno/Downloads/common/DatabaseConfigLoader/modules/`(database/{engine}/analysis.py + config/{engine}-config.json). PROGRESS의 `../flus-main/`은 이전 머신(fsat) 기준 — 향후 벤더링 시 이 Downloads 경로 사용. 런타임은 `judge_tool/vendor/common/db/`(비트동일 복사본)만 사용.
  6. **Opus 재리뷰 SHIP 근거**: R3 13개 vendor print 전수 base 매칭, stderr/logging/whole-raise/캐시 경로 전부 fail-safe, 5엔진 실데이터 양호/취약 약화 0(과차단 가드 `violations>=1` 실증). 잔여 Low/dormant(`__AMBIGUOUS__` 발동불가·fail-safe 방향).

  **(병행 가능, 비차단) LLM 품질 트랙**: 인코딩 교정·프롬프트 튜닝(빈출력클래스) 안전레버 **소진 완료**. 남은 레버=**골드라벨 확보**(사용자 정답 → 30b/결정론 진짜 측정, 현재 Opus 대용 N=10). 30b는 label-A에 보수적 충분(거짓양호 0) 확인됨.

  - **★서버 로컬LLM 품질 검토(2026-06-17, det_common 50항목 듀얼런 × 2샘플)**: `tests/det_dual_run.py` server/linux, qwen3-coder:30b vs det(검증된 정답프록시). 산출물 `out/srv_llm_review/dualrun_server_linux_*`.
    - **일치율**: 취약샘플(linux-s-vuln) 21/50=42%, 양호샘플(linux-s-sample) 19/50=38%. (production은 det이라 영향 없음 — LLM은 대조용. label-A 56항목이 실제 LLM production.)
    - **취약 탐지력(취약샘플 det=취약 12건)**: 정확탐지 9(75%, root login·UID0중복·telnet/FTP·passwd777 등 명확건 근거까지 정확) / 안전측 보류 2(SRV-028·127) / **거짓음성 1(SRV-096)**.
    - **★새 발견 = 권한 비트 오독 거짓음성(체계적·재현)**: 30b가 symbolic 권한문자열의 group/others triad를 "권한 없음"으로 과소판독. **SRV-096** `-rw-r--r--`(others read=취약 기준) → "others 권한 없음" 양호(양·취약 샘플 **둘 다 재현**). **SRV-084** `/etc/shadow -rw-r-----`(640) → "권한 600" 오독 → 양호. → **권한 점검 항목에서 dangerous 거짓음성.**
    - **★production 직접 리스크**: 순수-LLM(label A, det_common 아님) 10항목 중 권한항목 = **SRV-081(Crontab 권한)** 단 1개인데, 하필 Phase 1에서 det_common 제외돼 LLM polled로 넘어간 항목 → 위 오독 클래스 정통으로 맞음. **권고: SRV-081 권한검사 어댑터 보강(det 재승격) 또는 프롬프트에 "symbolic 권한 끝 3자리=others, 가운데 3자리=group, `r--`도 권한 있음" 명시 + 권한 항목 거짓음성 가드.**
    - **거짓양성(안전측, 검토부담↑)**: SRV-016(미실행 RPC `[S][E]` 빈블록을 "활성"으로 환각, **양·취 샘플 재현**)·SRV-092·011·074.
    - **지배적 패턴**: 양호→판단보류 19~22건(빈출력/미실행/파일부재를 "양호신호" 아닌 "증거부족"으로 과보수 처리 — 이전 37.5~44% 동일 약점, 검토량 폭증·안전측). 메모리 [[llm-perm-string-misread]].

  - **★위 검토 인지사항 개선 SHIP(2026-06-17, 1199 passed, 4 skipped)**: `judge.py SYSTEM_PROMPT`에 결정론 무관 LLM 교정 규칙 2종 추가(label-A 전 항목 적용).
    - **① 파일 권한 문자열(symbolic mode) 판독 규칙**: 끝3=others·가운데3=group, `r--`도 권한임(읽기 무시 금지), 8진수 환산(rwx=7 r--=4 ---=0), "others 권한 없어야 양호"면 끝3=`---`만 양호. **★흔한오판 경고**: "`-rw-r--r--`(644)는 others 읽기권한 있음→취약, '실행만 없으면 양호'는 틀림"을 명시(2차 강화로 SRV-096 완고한 prior 돌파).
    - **② 서비스 상태 블록 `[ 이름 ][S]…[E]` 마커 규칙**: [S]~[E] 사이 빈 블록=미실행, [S] 줄의 이름은 점검대상 목록일 뿐 '실행중' 아님(SRV-016 환각 차단).
    - **실LLM 재검증(qwen3-coder:30b, 양·취 샘플 전수 50항목 듀얼런 before/after)**:
      - 취약샘플 일치율 42%→**48%**, 위험불일치 3→**1**. 양호샘플 38%→**50%**, 위험불일치 5→**2**.
      - **★거짓음성(취약→양호) 양 샘플 모두 0건**(SRV-096 양·취 / SRV-084 해소). 위험방향 교정: SRV-016(거짓양성)·SRV-084·SRV-096(거짓음성) 전부 해소.
      - **부수효과**: 과보수 판단보류→양호 다수 개선(SRV-013/034/158/174, det와 일치).
      - **잔존 위험불일치(전부 거짓양성=안전측)**: SRV-092(취약샘플)·SRV-011·SRV-074(양호샘플) — det=양호/llm=취약. 환각·기준해석차 클래스(30b 추론한계, 이전세션 diminishing returns 판정). 거짓양호 아님→검토부담만. 추가 프롬프트 튜닝은 두더지잡기·회귀위험이라 보류(사용자 판단 대기).
      - 경미회귀(안전측): SRV-074 취약샘플 취약→판단보류, SRV-084 양호샘플 양호(거짓음성)→판단보류(거짓음성 해소·확정엔 미달). 둘 다 거짓양호 방향 아님.
    - **수정 파일**: `judge_tool/judge.py`(SYSTEM_PROMPT +2블록), `tests/test_judge.py`(규칙 존재단언 2건). 산출물 `out/srv_llm_after/`·`out/srv_llm_fix/`.

  - **★LLM-production 항목 과최적화 가드 + 양극성 커버리지 감사(2026-06-17)** — CLAUDE.md "LLM 판정 품질 검토 프로토콜" 신설(모든 도메인 공통). 서버 linux 적용 결과:
    - **분류**: linux judgeable 70항목 = label{A:59,C:4,D:3,B:4}, method{det_common:50, det:7, llm:10, interview:3}. **LLM이 production 1차 판정자(det_common 아님) = 20항목**, 그중 순수 LLM(label A) = 10(SRV-006/027/081/091/112/144/163/165/166/175).
    - **★과최적화 무해 확인**: 위 10개 label-A를 수정전(git HEAD)/수정후 SYSTEM_PROMPT × 양·취 샘플 실판정 → **10개 verdict 전부 전후 동일, 위험방향 회귀 0건.** 즉 권한·서비스블록 규칙은 production-LLM 판정을 바꾸지 않음(개선은 det_common 대조항목에서만 발생, production 무해). 과최적화로 망친 항목 없음.
    - **★양극성 커버리지 심각 부족(샘플 한계 — 측정 불가)**: label-A 10개 중 양호↔취약 대조가 성립하는 건 **SRV-165(양호/취약) 단 1개.** 5개(SRV-006/027/081/144/175)는 **양·취 샘플 모두 판단보류** → LLM 판별력 측정 자체가 불가. SRV-091/166=양쪽 양호, SRV-163=양쪽 취약(단극성). **특히 SRV-081(권한항목, 이번 수정대상)은 양쪽 증거 동일+양쪽 판단보류 → 권한 수정 효과를 production 항목에서 검증 불가.** SRV-003/177/179는 양쪽 증거 자체 없음.
    - **결론**: 현 양호/취약 샘플 2개로는 **LLM-production 품질을 제대로 측정 불가**(10개 중 1개만 양극성). **선결과제 = 취약주입 샘플 보강 또는 골드라벨** — det_common 일치율(42→48%)은 LLM 품질 지표가 아님(거기선 결정론이 production). 타 도메인도 동일 프로토콜로 커버리지부터 점검.

  - **★취약주입 양극성 커버리지 픽스처 SHIP(2026-06-17, 1222 passed)**: 위 미커버 해소 — label-A 10개 전부 양/취 양극성 확보.
    - **신규 픽스처(원본 보존)**: `collected/server/linux/linux-s-cov-good.xml`(전항목 명확한 양호)·`linux-s-cov-vuln.xml`(전항목 명확한 취약). 원본 `linux-s-{sample,vuln}.xml`은 불변(백업 `out/srv_cov_backup/`). 생성기 `tests/_build_cov_fixtures.py`(결정론, provenance 유지).
    - **항목별 주입**: SRV-006(LogLevel 9↔0), SRV-027(tcp-wrapper deny-all↔접근통제 전무), SRV-081(crontab 750·cron파일 640↔crontab 4777·cron파일 666), SRV-091(표준 SUID만↔/usr/bin/find·/tmp bash·home nc SUID 주입), SRV-112(rsyslog cron.* 기록↔미기록), SRV-144(/dev 빈출력+완료마커↔/dev/backdoor 일반파일), SRV-163(경고배너↔기본 issue), SRV-166(정상 dotfile만↔.bd.sh·.hidden·/tmp/.x 의심숨김), SRV-175(timedatectl NTP active↔전 NTP서비스 inactive). SRV-165는 기존 양극성 유지.
    - **★실LLM 검증(qwen3-coder:30b, 10항목×2파일)**: **완전 양극성(good=양호 & vuln=취약) 10/10** (주입 전 1/10). 결과 `out/srv_cov_backup/cov_polarity_final.txt`. SRV-144/175는 1차 보수(빈출력/도구없음 노이즈)→마커 추가·노이즈 제거로 교정 확인.
    - **함의**: 이제 서버 label-A LLM 품질을 양/취 대조로 실측 가능(이전엔 측정 불가). DB/컨테이너/웹 등 타 도메인도 동일하게 cov 픽스처 구축 필요(CLAUDE.md 프로토콜 §2).

  - **★서버 label-A LLM 품질 측정 완료(2026-06-17, cov 골드라벨 대조)**: 10항목 × 양/취 = 20판정, qwen3-coder:30b. 결과 `out/srv_cov_backup/labelA_quality.json`.
    - **verdict 정확도 20/20=100%** (양호 10/10·취약 10/10). **거짓음성 0·거짓양성 0·판단보류 0.** 신뢰도 0.90~1.00.
    - **근거 타당성 10/10**: 취약 판정 근거가 주입한 실제 단서를 정확히 인용 — SRV-091=`/tmp/.cache/rootbash`·`nc`·`/usr/bin/find` SUID 명시, SRV-081=crontab>750·cron파일>640 others권한(권한규칙 정확 적용), SRV-144=`/dev/backdoor`+mqueue/shm 예외까지 적용, SRV-027=iptables ACCEPT+hosts.allow/deny 부재, SRV-166=`.bd.sh` 실행권한. **"맞는 이유로 맞춤" 확인**(우연 일치 아님).
    - **★측정 해석(과대해석 금지)**: 100%는 **설계상 명확한(unambiguous) 케이스** 점수 — 30b가 깨끗한 증거에서 양/취 판별·타당추론에 우수함을 입증(원본 샘플은 5/10 판단보류로 측정조차 불가했음). cov 항목(091/027/144 등)은 프롬프트 튜닝 대상이 아닌 신규 증거 → **과최적화 아닌 일반화 확인**. **단 borderline/희소 증거(빈출력·파일부재·환각)에서의 약점은 별개**(앞서 SRV-092/011/074 거짓양성·과보수 잔존). 즉 "명확건=우수, 애매건=과보수/환각"이 30b 특성. 애매건 측정엔 borderline cov 또는 실골드라벨 필요.

  - **★Codex 적대리뷰 지적 2건 해소 SHIP(2026-06-17, 1246 passed/31 skipped + Ollama가드 20 passed)**: 리뷰 전문 `out/srv_cov_backup/codex_review.txt`.
    - **[high] cov 픽스처 양극성 계약 미강제**: 생성기가 편집블록만 검사 → 재생성 시 단극성 손실 가능했음. **해소**: ① 계약 단일출처 `tests/cov_contract.py`(LLM_PROD_ITEMS 10 + VULN/GOOD 골드신호) ② 결정론 커밋 테스트 `tests/test_cov_fixtures.py`(LLM 없이 항목별 양극성·good≠vuln·골드신호 강제 + **계약집합 == server.yaml 순수LLM label-A 동일성** 단언) ③ 생성기 `_build_cov_fixtures.py`에 post-build 자가검증. 어느 항목이 누락/단극성/신호부재면 테스트·생성 둘 다 실패.
    - **[medium] 프롬프트 행동 회귀 가드 부재**: 기존 test_judge는 문자열 존재만 검사. **해소**: `tests/test_llm_cov_quality.py` — cov 골드라벨로 실LLM 판정 검증(취약→양호 거짓음성 금지·양호→취약 거짓양성 금지), `RUN_OLLAMA_TESTS=1` + Ollama 가동 시에만 실행(기본 skip, 느린 호출). **재생 검증: 20 passed(69초)** — 위험방향 오판 0 재확인.
    - **[medium] PostgreSQL DBM-011 거짓음성**: 제 작업 아님 — **병행 DB 세션 변경분**(`vendor/common/db/postgresql/analysis.py` dbm_011, pgaudit_settings==[] 미탐지). DB 트랙에 전달 필요(미수정).
    - **수정/신규 파일**: `tests/cov_contract.py`(신규), `tests/test_cov_fixtures.py`(신규), `tests/test_llm_cov_quality.py`(신규), `tests/_build_cov_fixtures.py`(자가검증 추가).

  - **Pre-flight 인코딩 교정 + LLM 점검가능 게이트(2026-06-16, 980 passed)**: `judge_tool/preflight.py`.
    - **인코딩 자동교정(결정론)**: utf-8 strict 프로빙→cp949(단 mojibake>5%면 utf-8 replace 폴백)→replace. 선언 인코딩 불신(EUC-KR 선언+UTF-8 바이트 mojibake 버그 수정). server_xml `_read_text`→`preflight.read_text` 위임, container/webwas 자동적용. **실증: 컨테이너 mojibake 812→0(한글 정상).**
    - **점검가능 게이트(사용자계약: 항상 LLM 판정)**: `run_llm_gate` LLM 권위화 — LLM 성공시 LLM 최종(OK→통과/NG→`PreflightError` 중단, 휴리스틱 미참조), **LLM 불가시에만 휴리스틱 폴백**(meta `gate_decided_by`). 모델 기본 `--model qwen3-coder:30b`(production, 사용자확정 [[local-llm-only]]). 게이트 프롬프트: 인코딩깨짐/전손상/빈데이터만 NG(취약내용은 OK). 게이트 적용=profile.parser(XML계열) 기준. `--skip-preflight` 제공.
    - **실LLM 30b 검증**: 정상파일→OK(false NG 없음)·손상→NG(중단)·미가동→폴백. det verdict 불변(ASCII 마커). 목표=LLM 입력 텍스트 정상화 달성.
    - 함의: 이제 LLM-assist(label A) 평가가 공정해짐(깨끗한 한글 입력). 듀얼런 LLM 거짓양성(`[not exist]` 오독류) 일부는 깨끗한 입력 + 마커설명 프롬프트로 개선 여지.
    - **★인코딩 효과 실증(2026-06-16)**: 컨테이너 듀얼런 재실행(동일 30b, 인코딩만 차이) → **일치율 44.4%→72.2%**(matched 16→26, +10항목). mojibake가 LLM 주된 실패원인이었음 확정. PRCC-029/033/035/036/037/047 = 깨진한글→정상으로 LLM 일치. PRCC-028/030 = 취약(거짓)→판단보류(안전)로 개선. 남은 불일치 10건은 전부 det 오류 아님(det=취약·LLM누락 3 / det=양호·LLM보수보류 3 / det=보류·LLM committed 4).

  - **B: 30b label-A 실판정 품질 평가(2026-06-16, vs Opus 레퍼런스)**: 서버/linux label-A 10항목(SRV-006/027/081/091/112/144/163/165/166/175, 증거有)을 30b 실판정 vs Opus 블라인드 레퍼런스 대조(out/eval_labelA_compare.json). **일치 7/10(70%)**. **★위험방향(양호↔취약) 불일치 0** — 거짓양호·거짓취약 전무. 불일치 3건 전부 "30b=판단보류 vs Opus=확정"(30b가 더 보수적): SRV-112/175는 Opus도 journald/timesyncd 미확인 단서 달아 30b 보류가 더 안전, SRV-144만 30b 과보수(Opus 양호 정확). **결론: 30b는 label-A에 보수적으로 충분 — 명확건 일치, 애매건 안전하게 판단보류(전건 needs_review라 사람이 처리), 위험 오판 0.** 개선레버=과보수 축소(프롬프트 "에러없는 빈출력=위반없음=양호" 지침). 캐비엇: N=10·Opus는 골드라벨 대용.
  - **C: 30b label-A 프롬프트 튜닝 + 재평가(2026-06-16, 980 passed, 3 skipped)**: `judge_tool/judge.py SYSTEM_PROMPT` 빈출력·수집마커 판단 블록 추가.
    - **프롬프트 추가 내용**: `[빈 출력·수집 마커 판단 — '위반 없음(양호)'과 '데이터 없음(판단보류)'을 구별]` 블록(SYSTEM_PROMPT 36행 직전, "반드시 아래 키" 앞). ①빈출력=양호 ②[not exist]마커=양호 ③측정도구/설정파일 부재=판단보류 ④보안기능 자체 부재=취약가능 4-point. `find /dev -type f` 명령줄만 있고 출력 없음=양호 예시 추가. 첫줄 "클라우드 보안 취약점 평가자"→"보안 취약점 평가자"(도메인 일반화).
    - **재평가 결과(3열 표)** — 튜닝전 30b / 튜닝후 30b / Opus ref:
      | SRV-006 | 판단보류✓ | 판단보류✓ | 판단보류 | (동일) |
      | SRV-027 | 취약✓ | 판단보류✗ | 취약 | 취약→판단보류(30b 과보수, 거짓양호 아님) |
      | SRV-081 | 판단보류✓ | 판단보류✓ | 판단보류 | (동일) |
      | SRV-091 | 양호✓ | 양호✓ | 양호 | (동일) |
      | SRV-112 | 판단보류✗ | 판단보류✗ | 취약 | (동일) |
      | SRV-144 | 판단보류✗ | **양호✓** | 양호 | **판단보류→양호 (목표 달성)** |
      | SRV-163 | 취약✓ | 취약✓ | 취약 | (동일) |
      | SRV-165 | 양호✓ | 양호✓ | 양호 | (동일) |
      | SRV-166 | 양호✓ | 양호✓ | 양호 | (동일) |
      | SRV-175 | 판단보류✗ | 판단보류✗ | 취약 | (동일) |
    - **일치율**: 튜닝전 7/10=70% → 튜닝후 7/10=70% (SRV-144 개선, SRV-027 상쇄, 유지).
    - **거짓양호**: 0건 — SRV-144 양호 플립은 "명령 정상실행+빈출력=불필요파일없음=양호" (정당). SRV-006/081/112/175는 여전히 판단보류(실패항목 오판 0).
    - **SRV-027 회귀 분석**: 새 "보안기능 부재=취약 가능" 지침 추가했으나 30b가 "3rd-party 제품 미확인" 로직으로 여전히 판단보류 고집. 취약→판단보류는 안전측 회귀(거짓양호 아님), R3+R4 안정 확인. 현재 30b 한계.
    - **pytest**: 980 passed, 3 skipped — 그린 확인.
    - **결정성 재확인(temp=0, 3/3 동일)**: 30b는 이 항목들에서 결정적(비결정 아님). 튜닝은 "빈출력·`[not exist]` 오독 클래스"(듀얼런이 짚은 LLM 최대약점)를 폭넓게 개선해 **유지**. 단 net-flat이 보여주듯 남은 과보수는 "데이터없음(보류) vs 보안통제부재(취약)" 구별의 **30b 추론 한계** — 프롬프트 두더지잡기(수익체감)라 추가 반복 비권장. **다음 LLM 품질 레버 = 골드라벨**(인코딩·프롬프트 안전레버는 소진).

  - **Opus pre-flight C1/H1/M2 shift-left(2026-06-16, 980 passed, 3 skipped)**: `judge_tool/preflight.py` + `judge_tool/main.py` 수정.
    - **점1(Critical) — 게이트 결정권 LLM 우선**: `run_llm_gate` 결정 행렬 교체. LLM 성공 시 LLM이 최종 결정권자(OK→통과, NG→PreflightError). 휴리스틱 참조 안 함. LLM 불가(예외)/client=None 시에만 휴리스틱 폴백. meta에 `gate_decided_by: "llm" | "heuristic(fallback)"` 기록. 이전 "LLM NG + 휴리스틱 OK → 오탐 무효화" 합의로직 제거.
    - **점2(High) — 게이트 모델 30b + 엄격프롬프트**: `main.py --model` 기본값 `qwen2.5:14b` → `qwen3-coder:30b`. `_GATE_SYSTEM` 프롬프트를 "오직 ① 인코딩 깨짐·② 전부 손상/빈 데이터일 때만 NG" 엄격 한정(취약 내용이어도 한글/영문 정상이면 OK 명시).
    - **점3(Medium) — truncated UTF-8 silent cp949 mojibake 방지**: `_detect_encoding` cp949 분기에 mojibake 비율 가드 추가. cp949 strict 성공 후 decode 결과에 U+FFFD 비율 > 5% → utf-8 replace 폴백. 진짜 한글 cp949는 0% → 과트리거 없음.
    - **점4(Medium) — 게이트 적용 기준 profile.parser 기반**: `main.py run()` 내 게이트 적용 조건을 `_ext in (".xml",)` 하드코딩 → `profile.parser in _XML_PARSERS` 집합으로 교체. 대문자 .XML·확장자 없는 경로도 일관 적용. db_json/fw_policy_xlsx 자동 제외.
    - **테스트**: `tests/test_preflight.py` 25건(+4건 신규). LLM NG + 휴리스틱 OK 조합 → 이제 PreflightError(기존 "통과" 계약 역전). gate_decided_by meta 검증 2건 추가. genuine cp949 과트리거 부재 테스트 추가. 기존 테스트 docstring/계약 갱신.
    - **실LLM 30b 검증(qwen3-coder:30b, Ollama 실가동)**:
      - 정상 파일(linux-s-sample.xml) → LLM OK → 통과, 70/70 판정 완료, false NG 없음.
      - 손상 파일(30% U+FFFD) → 실LLM NG → PreflightError 정상(사유: "한글이 깨져 있어 문자 인코딩 깨짐").
      - LLM 미가동(port 99999) → "heuristic fallback" 로그, 크래시 없음.
      - --skip-preflight → gate_decided_by 미설정, NG 클라이언트여도 통과.
    - **Pre-flight 원래 기록**: `judge_tool/preflight.py` 신규.
      - **인코딩 교정**: strict 프로빙(utf-8-sig BOM → utf-8 → cp949 → replace 폴백). 선언 인코딩 신뢰 안 함.
      - **버그 수정**: `server_xml._read_text`가 선언 인코딩(EUC-KR)을 신뢰하던 것 → `preflight.read_text` 위임으로 교체.
      - **실증**: `fsec-control-plane-k8s_master-20260615.xml` — BEFORE: mojibake → AFTER: '관리자 역할이 부여된 롤 바인딩:'. mojibake 0, Korean 585단어.
      - **휴리스틱**: replacement char >1% → NG. 불법 제어문자 >2% → NG. 텍스트 < 50자 → NG.

  - **듀얼런 하니스 실LLM 대조 결과(2026-06-16)**: det_common 항목에 결정론 + LLM(qwen3-coder:30b) 동시판정 diff(out/dualrun_*).
    서버/linux 8항목 일치율 37.5%, 컨테이너/k8s_master 36항목 44.4%(matched 16/mismatch 20).
    **★핵심(ground-truth 검증): 불일치는 거의 전부 LLM 약점, 결정론 버그 0.**
    (1) 서버 불일치=빈 서비스블록(`[ snmp ][S][E]`) — LLM이 블록포맷 해석 못 해 보수적 보류, det "서비스 미실행→양호" 정확.
    (2) 컨테이너 det=양호/LLM=취약(PRCC-028/030)=**LLM 거짓양성** — 수집스크립트 `F_PRC_C_028`이 위반 컨테이너 없으면 `[not exist]`(=양호) 출력, LLM이 이 한글마커를 "필드없음→취약"으로 오독. det 정답(스크립트 로직 확정).
    (3) 컨테이너 det=취약/LLM=양호 12건=**LLM 거짓음성**(k8s 지식부족; det 취약은 Phase2 Opus 참양성 검증).
    **함의: 듀얼런이 결정론 통합 정당성 실증 — common 결정론이 LLM(30b)보다 이 도메인서 유의 정확.** 전 불일치 needs_review=True(triage 표 out/dualrun_*_table.txt). 잔존: LLM 프롬프트에 수집마커(`[not exist]`=양호) 설명 보강 선택(det 무관), worker/eks/aks/ocp·타OS 미확보.

  - **듀얼런 하니스 활성화(2026-06-16, 955 passed, 3 skipped)**: `tests/det_dual_run.py` 스켈레톤 → 완전 구현.
    - **`run_dual()`**: 프로파일 로드 → 파서 → aggregate → det_common 항목 필터 → 결정론+LLM 이중실행 → diff 분류(llm_mismatch/review). `llm_client=None`이면 det_only 모드. LLM 예외 → 크래시 없이 notes 기록.
    - **`diff_table()`**: 텍스트 표(item_id/variant/det/llm/match/diff_class/notes요약) + 요약통계 + 불일치 상세. 일치율% 계산.
    - **`save_results()`**: `out/dualrun_{profile}_{variant}_{ts}.json` + `_table.txt` 저장.
    - **CLI**: `if __name__ == "__main__"` argparse. --report/--criteria/--profile/--variant/--model/--ollama-url/--out-dir/--items/--no-llm. `sys.path` 자동 추가(직접 실행 지원).
    - **분류 계약**: det=취약+llm=양호 → `llm_mismatch`(결정론 취약 vs LLM 오판 의심). det=양호+llm=취약 → `review`(det_bug 의심이나 자동 단정 금지). 양측 근거 notes 기록.
    - **단위테스트** `tests/test_det_dual_run.py` 22건: dataclass 필드 불변 / classify_diff 4케이스 / run_dual mock(matched/mismatched/skipped/det_only) / LLM예외 내성 / diff_table 문자열 / save_results 파일생성·JSON구조 / 실파일 det_only E2E.
    - **실LLM 듀얼런 결과(server/linux, 8항목)**: total=8, matched=3, mismatched=5, det_only=0. 일치율 37.5%.
      - **일치(O)**: SRV-069(취약/취약), SRV-082(양호/양호), SRV-131(취약/취약) — 결정론·LLM 완전 합의.
      - **불일치 5건(전부 class=review)**: SRV-001/004/010/026 det=양호 llm=판단보류, SRV-008 det=양호 llm=취약.
      - **불일치 원인 분석**: det=양호 근거는 "서비스 비활성(service [S][E] 블록 패턴)". LLM은 설정파일 내용 부재(구성 확인 불가) → 판단보류 또는 취약. **결정론 버그 아님**: 서비스 미설치→비활성=양호는 판단기준 정합. LLM이 "설정파일 없음→판단 못 함"으로 보수적 처리. → 판단기준 해석 차이(class=review 적절).
      - **결정론 버그 시사 없음**: 불일치 5건 모두 det_good+llm_defer 패턴 — common이 wrong verdict를 냈다는 증거 없음.

  - **Opus Phase 3 리뷰 H-1/M-1/M-2/L-1 shift-left 완료(2026-06-16, 933 passed, 3 skipped)**:
    - **H-1(WST-038-apache-dotall)**: `check_WST_038` 정규식에 `re.DOTALL` 추가 + `[^\n]*`로 Options 줄만 매치(over-match 방지). 멀티라인 Directory 블록 취약 설정 → 거짓양호 → 취약으로 수정. `KNOWN_BUGS.md §2` 신규 등재, `DET_SOURCE.yaml WST-038 bug:` 추가. `TestWST038DotallRegression`(6건) 신규.
      **Opus 재검증(적대입력 6종)**: 멀티라인 취약(별도줄 FollowSymLinks)→취약 / 2블록 중 1취약→취약 / clean(granted)·no-Options→양호 / over-match(`granted`의 'all', FollowSymLinks無)→양호. 거짓양호 닫힘 + 과/오매치 0 확인 → **H-1 닫힘 SHIP**.
    - **M-1(WST-102 skip 해제)**: `test_known_bugs_regression.py:test_wst102_iis_polarity_corrected` skip 제거, 벤더 함수 직접 단언 구현(위반0건→N, 위반존재→Y). skip 4→3 감소.
    - **M-2(OS-variant web-variant gate 재확인)**: `det_adapters/webwas.py` OS-variant에서 web-variant 추론 후 `classify(item_id, web_variant)` 재확인. DET/DET-PARTIAL 아니면 handled=False(MANUAL/ABSENT 관습 의존 제거).
    - **L-1(WST-040 라벨 정직화)**: `item_configs/webwas.yaml` WST-040에서 `judgment_method: det_common` 제거(DET_SOURCE iis=MANUAL로 gate 항상 차단 → 무의미). `label: A` + 주석(xlsx 역전 의심) 유지.
    - **실데이터 검증**: web_apache-s-sample.xml 재실행 — WST-033=양호 불변, 거짓양호 0, 과트리거 0.
    - **잔존 스킵 3건**: WST-040 IIS polarity(xlsx 역전 미해결), PRCV-027~036(도달불가 버그), NET-051(오타).

  - **Phase 3 완료(2026-06-16, 926 passed, 4 skipped)**: 웹서버-WAS(WST) common 결정론 통합.
    - **범위**: 웹 특화 WST 항목만(실수집 WST-NNN ID — WST-031~044, WST-080, WST-102, WST-121~126). OS-동형 WST(실수집 SRV-NNN ID)는 server 어댑터 위임(§2.1 ID 네임스페이스 라우팅).
    - **벤더링**: `judge_tool/vendor/common/webwas/` — wslib.py(Django 제거), WST_Apache_parse.py, WST_WebtoB_parse.py, WST_IIS_parse.py(VENDOR-EDIT(a) import 경로 + VENDOR-EDIT(bug) WST-102 IIS 극성 양쪽 분기 수정). PROVENANCE.md 갱신.
    - **WST-102 IIS 2부분 버그(VENDOR-EDIT(bug))**: 원본은 `if not vul_list:` 분기에 `result="Y"`(오설정) AND `else:` 분기에 `result="Y"` 줄 누락. 양쪽 모두 수정.
    - **WST-040 xlsx 역전 미해결**: DET_SOURCE iis=MANUAL → gate 차단 → LLM 폴백. xlsx 기준 셀 확인 후 DET 승격 예정.
    - **DET_SOURCE WST 전수 분류(22항목)**: OS 5종(linux/aix/hpux/solaris/win) = DET-PARTIAL(게이트 패스스루용) + 웹서버 3종(apache/iis/webtob) = DET. WST-040 iis/win=MANUAL. WST-044/080/121~126=ABSENT.
    - **§6.4 config-항목 거짓판정 방어**: `_WST_CONFIG_SIG` dict(7항목) + check 함수 호출 **전** 시그니처 검사. 부재 시 handled=False(거짓취약 WST-035 + 거짓양호 WST-038 둘 다 차단).
    - **§6.2 OS/웹 이중성 해결**: detect_variant가 linux 반환 → 어댑터가 raw에서 웹서버 추론(`_infer_web_variant`). OS 변형을 DET-PARTIAL로 분류해 gate 통과 가능.
    - **webwas.yaml 루트레벨 필수**: `items:` 래퍼 없이 WST-NNN 키를 직접 루트에 배치(server.yaml/container.yaml 동형). `items:` 래퍼 시 전항목 LLM 폴백됨.
    - **실데이터 검증(web_apache-s-sample.xml)**: WST-033=양호(det_common, Apache 2.4.52) ✅. WST-044=판단보류(det, label C) ✅. WST-035/038/102=handled=False → LLM 시도(API 키 없음=정상) ✅. **거짓양호 0 확인**.
    - **테스트**: `tests/test_det_adapters_webwas.py` 57건 신규. 총 926 passed, 4 skipped.
    - **잔존 스킵 4건**: WST-040 IIS polarity(xlsx 역전 미해결), WST-102 IIS polarity(vendored 버그수정 완료 → 스킵 조건 재검토 가능), PRCV-027~036(도달불가 버그), NET-051(오타). 도메인 벤더링 순서에 따라 활성화.

  - **Phase 4b 완료(2026-06-16, 1067 passed, 9 skipped)**: DB(DBM) 클라우드 변형(RDS/Aurora/Azure) 결정론 통합.
    - **범위**: 5엔진 클라우드 변형 14개(mysql×3/oracle×1/mssql×1/mariadb×1/pg×3). tibero 제외.
    - **벤더링**: `judge_tool/vendor/common/db/{mysql,oracle,mssql,mariadb,postgresql}/cloud_analysis.py` 원본 비트동일 복사(VENDOR-EDIT 없음). PROVENANCE.md Phase 4b 행 추가.
    - **DET_SOURCE 클라우드 변형 명시 분류**: 각 DBM 항목의 variants에 cloud 키(mysql_rds/aurora/azure 등) 추가. native와 다른 셀 핵심:
      - mysql cloud ABSENT: DBM-025/026/033(run() 미호출)
      - mysql cloud STUB: DBM-005/022(lambda True)
      - oracle cloud STUB: DBM-005/015(lambda True), DBM-016(전체주석)
      - mssql cloud ABSENT: DBM-019/031, STUB: DBM-009(lambda True)/011/013/017/022(빈본문)
      - mariadb cloud ABSENT: DBM-022/026, STUB: DBM-005(lambda True)/016/025(빈본문)
      - pg cloud ABSENT: DBM-005/006/019(run() 미호출), STUB: DBM-007/009(polarity)/013/022/028/032(빈본문/lambda True)
      - pg cloud DET 신규: DBM-003/004/008/011/015/016/017/020/024(native=STUB이나 cloud 다른 스키마로 DET)
    - **db.py 확장(Phase 4b)**:
      - `_ENGINE_CLOUD_CLASS`: 엔진별 CloudAnalysis 클래스 이름 맵
      - `_CLOUD_SUFFIXES`: rds/aurora/azure
      - `_is_cloud_variant(variant)`: suffix 판별
      - `_run_analysis(engine, data, is_cloud)`: is_cloud에 따라 모듈 경로 분기, 캐시 키에 is_cloud 포함
      - `judge()`: is_cloud 결정 + _run_analysis 전달
    - **테스트 신규 29건(Phase 4b)**: TestCloudVariantRouting(6) + TestCloudAbsentGateBlock(6) + TestCloudStubGateBlock(6) + TestCloudDetDetermination(6) + TestCloudCacheSeparation(2) + TestCloudR3Guard(2).
    - **활성화 게이트**: 실데이터 없음 → 합성 픽스처 단위테스트만. 거짓양호는 ABSENT/STUB 명시로 구조 차단. 실데이터 검증·듀얼런은 클라우드 수집 샘플 확보 후.
    - **native 회귀**: 0 (기존 1038→1038 통과, 신규 29건 추가).

  - **Phase 4 완료(2026-06-16, 1032 passed, 9 skipped)**: DB(DBM) common 결정론 통합.
    - **범위**: 5엔진 네이티브(mysql/oracle/mssql/mariadb/postgresql) + RDS/Aurora/Azure 변형 전체.
    - **벤더링**: `judge_tool/vendor/common/db/{mysql,oracle,mssql,mariadb,postgresql,tibero}/` — analysis.py + config/*.json 비트동일 복사(VENDOR-EDIT 없음, stdlib+dateutil+packaging만 사용). PROVENANCE.md 갱신.
    - **DET_SOURCE DBM 전수 분류**: 7단계 분류(DET/STUB/ABSENT/MANUAL) 완료. 주요 정정:
      - mysql/oracle/mariadb/pg DBM-005 = STUB(lambda datum: True)
      - oracle DBM-013 = STUB(§B=ABSENT 오기재, 코드 확인 후 정정)
      - oracle DBM-015_1/_2 = STUB(§B=DET 오기재, lambda True 확인)
      - mssql DBM-011/013/017/021/022 = STUB(빈 본문)
      - pg DBM-006/007/013/019/028/032 = STUB(빈 본문 또는 lambda True)
      - **⚠️R3 보수처리**: pg DBM-003/004/008/011/015/017/020 = STUB(수집형식 `{"*": python_repr}` → analysis KeyError → 거짓양호)
      - **⚠️R3 보수처리**: mariadb DBM-007/011/019 = STUB(동일 수집형식 패턴)
    - **db_json.parse() 확장**: `_build_raw_data_dict()` 신규 — 비마스킹 data dict를 JSON으로 직렬화 → 모든 resource의 `raw_evidence`에 적재(결정1: 단일 빌드·전 resource 공유).
    - **어댑터**: `det_adapters/db.py` — gate → _normalize_base → _engine_of → json.loads → _has_data_key_for(D3) → _run_analysis(캐시·예외내성) → _filter_noise → 결과매핑. 5개 profile_key 레지스트리 등록(`db_mysql/oracle/mssql/mariadb/postgresql`).
    - **item_configs**: `db_{mysql,oracle,mssql,mariadb,postgresql}.yaml` DET 항목에 `judgment_method: det_common` + `needs_review: true` 부여. R3 보수처리 항목(pg 7개+mariadb 3개)은 `det_common` 제거(주석으로 사유 기록).
    - **main.py**: `import judge_tool.det_adapters.db` 1줄 추가 → 5개 키 등록 부작용.
    - **실데이터 검증(거짓양호 0 확인)**:
      - mysql: 21판정, det_common=18, 양호6/취약7/보류8 — DBM-005(STUB) gate 차단 확인
      - oracle: 25판정, det_common=19, 양호6/취약10/보류9
      - mssql: 23판정, det_common=14, 양호11/취약1/보류11
      - mariadb: 20판정, det_common=12, 양호5/취약4/보류11 — DBM-007/011/019 STUB gate 차단
      - postgresql: 22판정, det_common=6, 양호2/취약1/보류19 — R3 보수처리 7항목 gate 차단
      - **전 엔진 거짓양호 = 0 ✅**
    - **noise 필터**: `@@@`/`***` 단일키 행 제거, `{"*": datum}` 위반행 유지 — mysql DBM-011(audit_log.so) 취약 정상 판정 확인.
    - **테스트**: `tests/test_det_adapters_db.py` 신규 58건(engine매핑·base정규화·gate차단·증거가드·noise필터·result매핑·예외내성·§7경계·raw_evidence·캐시·실파일E2E-mysql/pg).
    - **잔존 TODO**:
      1. Opus 적대리뷰 미완료 — 리뷰 후 미듐이상 shift-left 필요.
      2. R3 pg/mariadb 수집형식 수정 후 DET 복원: `{"*": python_repr_str}` → `{"col": val}` flat dict 형식으로 수집 스크립트 수정하면 7+3 항목 det_common 재승격 가능.
      3. 듀얼런 하니스 DB 미실행(LLM API 미연결로 보류).

  - **Phase 2 완료(2026-06-16, Opus 적대리뷰 SHIP, 869 passed, 4 skipped)**: 컨테이너(PRCC) common 결정론 통합.
    - **Opus 리뷰 결과**: Critical/High/Medium 0, Low 3(프롬프트 수치오기·PRCC-011 과보수MANUAL·mojibake 안전측 — 거짓양호 무관). R1 디폴트-N 거짓양호 3경로 실호출 차단 확인. 벤더 diff 0. 실데이터 취약 7건(PRCC-001/002/006/009/010/013/025) 전수 참취약, 양호 표본 참양호(디폴트N 아님). PRCC-031 빈출력→증거가드로 LLM 라우팅(거짓양호 차단 정상). ★Sonnet이 설계 §2.3 오류(docker_linux outer-gate substring 오인) 적발→`_VARIANT_TO_SAPP` 변환으로 docker_linux 거짓양호 봉쇄.
    - **벤더링**: `judge_tool/vendor/common/container/autoAnalysis.py` 원본 비트동일 복사 (stdlib=re/json/traceback만, VENDOR-EDIT 없음). PRCV 포함·미수정. PROVENANCE 갱신.
    - **detect_variant `<app>` 폴백(R6)**: `container_xml.py detect_variant`에 `<asset><app>` 폴백 추가(실수집 샘플은 `<variant>` 대신 `<app>k8s_master` 사용). `_DIRECT_VARIANT_MAP` 재사용. 검증: detect_variant('k8s_master 샘플') = 'k8s_master' ✅.
    - **raw_evidence 분리(§7)**: `container_xml.parse()`에 `raw_evidence=raw_ev` 추가(server_xml 동형). evidence=마스킹본, raw_evidence=원문, 빈출력→None.
    - **DET_SOURCE PRCC 전수 분류(50건)**: autoAnalysis.py 코드 분기 1순위. 분류: 순수 DET 39건 + DET-PARTIAL 8건(004/010/017/018/022/024/036/039) + MANUAL 1건(011). ABSENT=0/UNREACHABLE=0/STUB=0.
    - **⚠️ 설계서 §2.3 착오 발견**: "docker_linux를 그대로 sApp로 전달" — 실제 outer gate(`if sApp in autoTarget`)는 exact list membership. autoTarget에 "docker"가 있고 "docker_linux"는 없음. 어댑터에 `_VARIANT_TO_SAPP = {"docker_linux": "docker"}` 매핑 추가.
    - **어댑터**: `det_adapters/container.py` — autoAnalysis 단일함수 호출, result M/Y/N 매핑, R1 거짓양호 3중 방어(gate+증거가드+M매핑), `_DET_ADAPTERS["container"]` 등록. main.py에 import 부작용 추가.
    - **container.yaml**: 50항목 전수 `det_common` + `label: A`. D/B 강등 금지(§5.1 코드 우선).
    - **증거 가드 패턴**: `# Command:`, `F_PRC_C_NNN`, `kubectl`, `docker`, `flag:[`, `[not exist]`, `root:root`, `-----`, `###` — k8s_master 실샘플 검증(과트리거 0).
    - **실데이터 검증(k8s_master 샘플)**: 36/36 det_common 판정. 취약 7건(001/002/006/009/010/013/025) + 양호 24건 + 판단보류 5건(MANUAL 4 + 빈출력 1). **거짓양호 0 확인**.
    - **잔존 게이트**: worker/eks/aks/ocp/docker variant 실데이터 미검증(k8s_master 한정). 타 variant DET_SOURCE는 코드리뷰 근거 분류(§6.3).
    - **테스트**: `tests/test_det_adapters_container.py` 36건 신규. `tests/test_criteria_loader_container.py` 2건 갱신(Phase2 반영).



  - **Opus 재리뷰 잔존 3건 shift-left(2026-06-16, 832 passed, 4 skipped)**: SRV-073 거짓양호 근본수정 + [S]가드 강화 + 음성테스트 실질화.
    - **Critical(SRV-073-no-group-data)**: `/etc/group` 데이터 부재(권한거부·빈출력·무관 텍스트) 시 `check_SRV_073`이 `(*) 수동` 반환하도록 수정. 파싱 그룹 라인 0건 → Low-1 가드 → handled=False → LLM 폴백. 위치: `SRV_auto_parse.py check_SRV_073`, `KNOWN_BUGS.md §6`, `DET_SOURCE.yaml SRV-073 bug:` 필드.
    - **Medium([S] 가드 강화)**: `_RE_SVC_BLOCK` 패턴을 단순 `[S]` 부분문자열에서 블록 경계 패턴 `\[\s*\S.*?\s*\]\[S\]`으로 강화. 'garbage [S] more' 같은 우연 포함은 증거 불인정. 위치: `det_adapters/server.py`.
    - **Medium(음성 테스트 실질화)**: `TestSRV073NoGroupDataFalsePositiveFix`(5건) + `TestSvcBlockBoundaryGuard`(3건) 신규. `$` 프롬프트 있지만 유효 데이터 없는 입력으로 실제 거짓양호 경로 커버. 빈블록 한계 문서화: `det_adapters/server.py` 말미 "알려진 한계" 주석.
    - **sample 검증**: linux-s-sample.xml SRV-073 verdict=양호(유효 데이터 있는 실데이터 불변). 39 DET 양호 항목 과트리거 0.
  - **Opus C-1/C-2/M-1/M-2/L-1 shift-left(2026-06-16, 824 passed, 4 skipped)**: DET-PARTIAL 거짓양호 근본원인 차단.
    - **C-1(SRV-073)/C-2(SRV-021) 핵심 버그**: 수집 실패(빈출력/에러/garbage) → common이 (*) 없이 result='N' 반환 → Low-1 가드 통과 → 거짓양호 0.9. `_has_collection_evidence()` 가드로 차단.
    - **증거존재 가드(`_has_collection_evidence`)**: `result='N'`(양호) 반환 시 raw_output에 명령 프롬프트 라인(`^\s*[$#]\s+\S`) 또는 서비스 블록(`[S]`)이 없으면 `handled=False`. 위치: Low-1 가드 통과 직후, 양호 반환 직전.
    - **휴리스틱 검증**: linux-s-sample.xml 전 DET/DET-PARTIAL 항목 → 패턴 1개 이상(과트리거 0). 빈/garbage/에러만 → 패턴 0(거짓양호 차단).
    - **M-1(SRV-074) 검증 결과**: `SRV_Linux_parse.check_SRV_074`가 실데이터에서 `(*) 없이 N/Y`를 반환함 확인. `det_common + label B` 설계가 올바름 — Opus의 "자기모순" 지적은 auto_parse 스텁만 봤기 때문이었음. server.yaml 주석 업데이트.
    - **M-2(needs_review 전건 True)**: 증거부재 가드가 근본원인("수집실패→양호") 차단 → M-2 해소.
    - **L-1 음성 테스트**: `TestEvidenceGuardNegative`(70건, 10항목×7가비지) + `TestEvidenceGuardPositive`(10건) + `TestSRV074DeterministicVerification`(2건) 신규. 기존 테스트 fixture 수정(SRV-082 `_output_good()` 등에 `$ cmd` 프롬프트 추가).
    - **실데이터 검증(sample+vuln)**: 과트리거 0(정당 양호 불변). SRV-021 garbage/빈 → handled=False 확인. SRV-074 linux sample→양호, vuln→취약 (결정론 정상).
    - 최종: 824 passed, 4 skipped(도메인 미벤더링 스켈레톤).
  - **DET-PARTIAL 패스스루(2026-06-16, 742 passed, 4 skipped)**: 카테고리4 10항목 `label:A` → `det_common+label:A` 전환.
    - `det_adapters/base.py gate()` 완화: `classify in {DET, DET-PARTIAL}` → 통과(None). STUB/ABSENT/MANUAL/UNREACHABLE → C1 차단 유지.
    - 전환 10항목: SRV-005/009/013/014/021/063/066/073/171/173.
    - **SRV-006 제외**(§13.2 postfix debug_peer_level 누락, LLM 유지).
    - SRV-007/064 불변(label D EOL/패치).
    - 실데이터(sample+vuln): 10항목 모두 거짓양호 0. common 명확경로(서비스 inactive)→결정론 양호(conf=0.9). active(FTP/DNS) → (*) → Low-1 가드 → handled=False → LLM 폴백(HTTPError=정상, LLM 미연결).
    - 신규 테스트: `TestDetPartialPassthrough`(8건) + `TestC1NegativeRegression`(3건) in `test_det_adapters_server.py`; `TestGate.test_det_partial_*` + C1 음성 4건 in `test_det_adapters_base.py`.


  - **Phase 1 완성(2026-06-16, Opus 리뷰 C-1/H-1 수정 후 SHIP, 725 passed, 4 skipped)**: server.yaml 전 SRV 106개 5-way 라벨링.
    - judgment_method det_common: **39개** (linux=DET 항목; SRV-074 인터뷰제외, **SRV-081 거짓양호로 제외**).
    - label 분포: A 59(=det_common 폴백 39 + 순수 LLM 20) / B 4(SRV-074/109/115/118) / C 40(크랙 2 + ABSENT 38) / D 3(SRV-007/064/179).
    - **Opus C-1(Critical) 수정 = SRV-081**: classify=DET이나 common이 xlsx 요구 'crontab 750' 검사 누락 →
      det_common이면 거짓양호(실데이터 0.9 양호 실증). **§13.2 권위원칙대로 det_common 제거 → label A(LLM 폴백)**. SRV-006과 동형.
      ★교훈(사용자 확인): "결정론 분류(DET/MANUAL/ABSENT)는 common 소스를 따르나, **판정 정오 권위는 xlsx**.
      common이 xlsx와 divergence(SRV-081/006/127·5버그)면 '검증·수정 후' 계약대로 xlsx가 이김(어댑터 보강/LLM폴백/버그수정).
    - **Opus H-1 수정**: server.yaml 말미의 잘못 들여쓰기된 타도메인 시드블록(DBM/WST/PRCV/NET) 제거 — YAML 파싱서 소실돼
      무효였고 내용은 DET_SOURCE.yaml에 존재. 제거 후 누출 키 0, 106 SRV 정합.
    - 실데이터 검증(Opus 정오): 파일럿 8개 verdict 불변(001/004/008/010/028/082/083=양호, 069=취약). 신규 det_common 양호항목 참양호.
  - **잔존 미완료(다음 증분 후보)**:
    - **SRV-081 어댑터 보강**(선택): crontab 750 검사 추가 시 det_common 재승격 가능(단 수집 스크립트가 해당 데이터 미수집 — 수집 연계 선행). 현재는 LLM 폴백(안전).
    - **듀얼런 하니스 활성화**(현재 스켈레톤 `tests/det_dual_run.py`만): collected 실데이터에 LLM vs 결정론 diff.
    - SRV-010 외 4개 KNOWN_BUGS 회귀(WST-102/040·PRCV-027~036·NET-051)는 해당 도메인 벤더링 후 활성(현재 4 skip).
  - 롤아웃 순서(§9): 서버(파일럿✅) → 전 항목 라벨링 → 컨테이너(41/50) → 웹 → DB(STUB주의) → 네트워크/PRCV, 클라우드 제외.

  **Phase 1 완료 내역(725 passed, 4 skipped)**:
  ① §18.3 라벨 라우팅 구현: `_det_common_label_route()` + `_det_common_handler()` 교체. 비-DET(ABSENT/MANUAL/STUB)는
     crit.label로 라우팅(A→LLM, B→인터뷰, C/D→canned). 무조건 LLM 폴백 금지(WARNING 주석 제거, 구현됨).
  ② 서버 모듈 벤더링: `judge_tool/vendor/common/server/`(sclib.py 순수헬퍼만 Django/lxml 제거, SRV_auto_parse.py,
     SRV_Linux_parse.py). VENDOR-EDIT(a) import 경로 3파일 + VENDOR-EDIT(bug) SRV-010-polarity(reason만 수정·result 불변).
     **Opus 대조: 벤더본=원본 비트동일(SRV-010 reason 2줄 외), Django/lxml 실import 0건.**
  ③ 서버 어댑터 `det_adapters/server.py`: DET_SOURCE gate → linux 오버라이드(SRV-026/069/074/127/131 → SRV_Linux_parse)
     → check 함수 호출 → ForcedVerdict 매핑(§5.4). `_DET_ADAPTERS["server"]` import 부작용 등록(main 상단).
     **Low-1 fail-closed 가드(Opus): `(*)` 수동마커 + result≠'Y' → handled=False(거짓양호 차단). result='Y'+(*)는 취약 통과.**
  ④ `server.yaml` 8개 파일럿 항목 `det_common` 부여(SRV-001/004/008/010/028/069/082/083, 폴백 label A).
  ⑤ SRV-010 (d)회귀 활성화 + Low-1 음성 테스트 4건.
  ⑥ **실데이터 검증(Opus 정오 확인)**: linux-s-{sample,vuln}.xml. 활성 8항목 verdict 전부 **참**(거짓양호 0).
     SRV-069 양호샘플 취약 = **참양성**(`chage -l root`=99999일 > xlsx 90일 + 복잡도 미설정). SRV-028 vuln=취약(TMOUT 미설정).
     나머지(001/004/008/010 SMTP·SNMP 미실행→양호, 082/083 others-write 0건→양호). needs_review=True 정상(정당성=사람).
  ⑦ 새 테스트: `tests/test_det_adapters_server.py`(21 tests) + SRV-010 회귀 + Low-1 가드.

  **Phase 0 완료 내역(703 passed, 5 skipped=（d）스켈레톤)**:
  - 데이터 아티팩트: `judge_tool/vendor/common/DET_SOURCE.yaml`(items 119: 서버 ~106 전수 + 교차도메인
    버그/회귀 시드 DBM-005·WST-102·WST-040·PRCV-027~036·NET-051. 값분포 DET44/DET-PARTIAL13/MANUAL13/
    ABSENT39/STUB5/UNREACHABLE9. 서버 §17.5와 실질 정합), `KNOWN_BUGS.md`(5버그 file:line 확정),
    `PROVENANCE.md`. **타 도메인(DB/네트워크/PRCC/PRCV/웹) DET_SOURCE 전수는 각 롤아웃 Phase에서 추가**(현재 시드만).
  - `det_adapters/base.py`: `ForcedVerdict`, DET_SOURCE 로더·캐시, `classify(item,variant)`(미지항목→ABSENT
    fail-closed; variants→엔진토큰폴백), `gate()`(DET 외 전부 handled=False = §18.1 C1 거짓양호 차단 단일출처),
    `_DET_ADAPTERS={}`(Phase 0 빈 레지스트리). `judge_tool/vendor/{,common/}__init__.py`.
  - `main.py`: `JudgeContext.thresholds`(trailing default), `_build_thresholds()`, `_raw_evidence_for_det()`,
    `_det_common_handler()`(어댑터 None→`_judge_one` 즉시반환=동작불변), `_HANDLERS["det_common"]` 등록.
  - `models.py`: `ResourceEvidence.raw_evidence`(비마스킹·결정론전용), `Criterion.thresholds/thresholds_source`.
  - `parsers/server_xml.py`: `raw_evidence` 분리(§7) — evidence=마스킹본, raw_evidence=원문, 빈출력→None.
  - `criteria_loader.py`: `thresholds`/`thresholds_source` yaml 로딩(미보유 시 빈/None — 기존 불변).
  - 테스트 신규: test_det_adapters_base(classify·gate·(e)STUB비양호 spy)·test_server_xml_raw_evidence(누출경계
    8건)·test_det_common_handler(등록·Phase0폴백·thresholds기본)·test_known_bugs_regression(5 SKIP)·det_dual_run(스켈레톤).
  **Opus 적대리뷰 결과**: **SHIP**. Critical/High 0. 계약 전부 충족 — §18.1 C1(gate fail-closed·미지입력ABSENT),
    §7(raw_evidence writer/judge/citation/LLM 미참조 grep확증), M1(DBM-005 mysql=STUB가 reconcile前 차단 → empty_means_good
    개입불가, Phase0 코드에 실재), 동작불변(어댑터0개·det_common yaml미지정). Medium 2건 → Sonnet 개선 → Opus 재리뷰 SHIP:
    M-1=KNOWN_BUGS SRV-010 증상서술 정정(**실버그=reason 문자열만 역전, result 값은 정확** — 소스 SRV_auto_parse.py:935-946
    직접 확인), M-2=§18.3 폴백 경고 격상. Low 2건(L-1 핸들러레벨 spy테스트·L-2 SRV-081)은 Phase 1 ④⑤로 이월.

- **(보류) 획득 결과파일 local LLM 판정 유효성 검토**: Docker/제공 결과를 Ollama가 얼마나 잘
  판단하는지 평가(`collected/INDEX.md`). common 통합과 별개 트랙 — Phase 1과 병행 가능.
- **★Docker 실수집 완료(2026-06-15, 8건)**: 서버Linux + DB 5종 네이티브(MySQL/MariaDB/
  PostgreSQL/MS-SQL/Oracle) + 웹Apache + 컨테이너 k8s_master(kind). 전부 파서 검증 통과.
  `collected/{server,db,web,container}/`에 저장. 폴더 재배치: 제공 점검스크립트→`scripts/check_scripts/`,
  신규수집→`collected/`, 기존실샘플→`results/`·`ref/FW/`(불변). 분류표 `collected/INDEX.md`.
  수집 갭(처리): 제어문자 sanitize(수정), **컨테이너 PRC-C↔PRCC normalize_id(수정, 매칭 0→36/39)**,
  MySQL/MariaDB 환경변수 주입, MS-SQL sqlcmd prefix 정제, Oracle 23c 권한차. (661 tests)
- **다음 후보**: ①획득 결과의 local LLM 판정 유효성 검토(아래 ★), ②취약 환경 구성으로
  취약 판정 샘플 다양화(점검 기준의 취약조건 역주입 — 사용자 요청, 미착수).
- **★common 결정론 통합 설계 완료(2026-06-16)** — 설계서
  `docs/superpowers/DESIGN_common_deterministic_integration.md`. `../common`(Django앱)의
  검증된 결정론 판정(check_SRV_*/*Analysis/NET*/autoAnalysis)을 vendor 복사 → `det_common`
  핸들러 1개 + 도메인 어댑터 레지스트리로 통합. "common이 수동/인터뷰로 둔 항목만 LLM,
  나머지는 결정론"을 `handled` 플래그로 구현(fw_policy 선례 패턴). 두 프로젝트 **항목체계 일치**
  (SRV/DBM/WST/NET/PRCC) → common이 서버 라벨분류 TODO의 근거.
  **확정 결정**: 벤더링=vendor/common 복사 / 임계값권위=xlsx(yaml thresholds 단일출처) /
  마스킹=결정론에 비마스킹 raw 공급 허용(raw_evidence 분리, 누출 경계테스트) / DB도 동일정책.
  **착수 순서**: Phase0 공통레이어(동작불변) → 1 서버(파일럿, Q3 임계값 xlsx대조 선행) →
  2 웹 → 3 DB(듀얼런 불변확인) → 4 네트워크 → 5 클라우드(PublicCloud=PISM재인코딩 보류검토).
  **Q3 해결(2026-06-16, 서버 임계값 xlsx 대조 완료, 설계서 §13)**: 핵심 수치임계 9/9 일치
  (TMOUT900·PW90일·복잡도10/8·주요파일권한·umask022·로그권한 등) → "그대로 가져가기" 안전.
  divergence 3건(SRV-127 deny 느슨·SRV-081 crontab750 누락·SRV-006 postfix 누락)은 xlsx 권위로
  어댑터 보강/폴백. SRV-127 판단기준 잠금횟수 컷 셀 재확인 1건 잔존. 미해결: Q5(PublicCloud 보류).
  **결정론불가 항목 LLM대체 분류(2026-06-16, 설계서 §14)**: LLM가능→A(SRV-027/091/144/163/165/166),
  인터뷰→B(SRV-109/115/118/074부분), 크랙기술한계→C(SRV-022/075,DBM-001 canned·LLM호출X),
  **EOL/패치→D 고정(SRV-007/064/179; 사용자지정: LLM·자동확정 금지, 판단보류+needs_review)**.
  데이터갭→증거미수집보류(DB OS레벨 DBM-012/021/022/026/034, ISS-037/038/039).
  **전 8도메인 전수 분류 완료(2026-06-16, 설계서 §15)**: 집계표·도메인별 A/B/C/D/GAP.
  정정① **OS가상화(PRCV)는 common 결정론 소스 존재**(autoAnalysis.py vcenter/esxi/xen, LLM전용 아님).
  정정② **클라우드(PISM)는 외부 PISM 스캐너가 결정론 판정** → LLM은 교차검증(중복), 실질기여는
  PISM-036뿐, 47개 관리체계는 미판정 → **클라우드는 결정론 통합 대상 제외, 현행 유지**.
  핵심: C(크랙류 4~5건뿐)·D(EOL 전도메인 판단보류)·최대레버리지=GAP(수집 연계, DB OS레벨은
  결정론 로직 기구현). 네트워크 12건·ISS 19건은 common 판정 미구현이라 LLM즉효+결정론 후속보강.
  **Opus 적대리뷰 완료(2026-06-16, 설계서 §16)**: 설계 근간 전부 검증(마스킹→raw 실증, 네트워크
  미구현-not-impossible, PISM 제외). 정정5: ①DBM-034 로직없음=순수GAP ②PRCV-027~036 elif버그
  도달불가(커버손실9) ③컨테이너 9건은 주플랫폼 결정론(LLM대상 축소) ④DBM-019 MariaDB결정론(PG만stub)
  ⑤SRV-127 divergence아님(col21 숫자컷 없음). 포팅위험: SRV-069/074/127 로직은 SRV_Linux_parse.py에만.
  **전수 재검증(2차, 2026-06-16, 설계서 §17 — §15 카운트 대체)**: 스폿체크가 놓친 신규문제 다수 적발.
  ①common 실버그(벤더링시 이식): SRV-010 판정역전, PRCV-027~036 도달불가(중첩버그·9항목), WST-102 IIS역전,
  WST-040 polarity, NET-051 오타. ②대규모 ABSENT: 서버 105중 38, 웹 22중 7, DBM-034/035/036 전엔진.
  ③DB는 placeholder STUB 산재(DBM-005 4엔진 lambda:True 등) — "깨끗한 결정론" 아님. ④xlsx 자체오류(WST-040).
  **계약변경: "그대로 가져가기"→"검증·수정 후"**. 결정론가용 도메인편차 큼(컨테이너41/50>네트워크26/45>서버38/105
  >PRCV18/35버그9>DB엔진별STUB). xlsx 항목수정정: 서버105·DB31·네트워크45·PRCC50·PRCV35.
  **Opus 최종리뷰+개선+재리뷰 완료(2026-06-16, 설계서 §18)**: 미듐이상 9건(C1·H1·H2·H3·M1~M5) 전부 해소.
  중심해법=**`DET_SOURCE.yaml`(항목×variant: DET/STUB/UNREACHABLE/ABSENT/MANUAL) + `KNOWN_BUGS.md`**
  (Phase0 1번 산출). C1=STUB/도달불가 N이 거짓양호로 새지 않게 §5.4 매핑 전 DET_SOURCE 게이트(표 인라인 수정).
  H1=VENDOR-EDIT(c) 버그수정 허용+벤더코드내. H2=ABSENT는 handled=False+§14라우팅(LLM폴백금지),
  Phase1 5-way라벨. H3=롤아웃 재배열(서버→컨테이너41/50→웹→DB주의→네트워크/PRCV, 클라우드제외).
  M1=DET_SOURCE>empty_means_good(DBM-005). M5=회귀(d)버그polarity(e)STUB비양호. 재리뷰 SHIP.
  **설계 확정 — 다음=Phase0 구현(§12 순서: DET_SOURCE/KNOWN_BUGS→base.py→핸들러→thresholds/raw_evidence→듀얼런).**
- **로드맵 실행순서: ① → ③ → ④ → ② → ⑤ → ⑥** (아래 "도메인 로드맵" 참조)
- **★실데이터 검증 시작(2026-06-15)**: fsi_unix.sh(서버 스크립트)를 Docker(ubuntu:22.04)에서
  실제 실행 → 출력 XML이 server_xml/webwas_xml 파서 가정과 **구조 완전 일치** 확인
  (한 실행에 SRV 67종+WST 7종 동시 점검, detect_variant=linux). **어댑터 불필요.**
  단 실데이터 갭 1종 발견·수정: CDATA 본문의 ANSI escape(\x1b 등 XML 1.0 불법 C0 제어문자)가
  ElementTree 파싱을 깨뜨림 → `cloud_xml.sanitize`에 불법 제어문자 제거 추가(tab/LF/CR 보존).
  **전 XML 파서(cloud/server/webwas/osvirt/network/iss/container) 공통 적용** = 모든 도메인
  실데이터 활성화의 공통 선결조건 해결. 660 tests. 메모리 [[domain-script-sample-status]].
- **완료**: 네이티브 DB 5종 + Tibero 스텁 / **① 판단방식 5분류 + 디스패치 seam** /
  **③ 서버(OS) 자동판정 구조 + 단위테스트**(2026-06-12, 244 tests) /
  **④ 네트워크 장비 자동판정 구조 + 단위테스트**(2026-06-12, 348 tests, CISCO+generic) /
  **② 방화벽 이상정책 탐지(ISS-030~041)**(2026-06-12, 486 tests, SECUI+ID70+PaloAlto+결정론) /
  **⑤ 컨테이너 가상화 구조 + 단위테스트 + Opus 재리뷰 완료**(2026-06-12, 557 tests) /
  **② ISS_DEVICE VPN/IDS/IPS/DDoS/WAF+generic 구조**(2026-06-12, **591 tests**,
  iss_xml 파서+ISS_DEVICE Profile+iss_device.yaml. 프로파일 분리 설계(Fable):
  iss(FW fw_policy_xlsx)·iss_device(비FW iss_xml). detect_variant: device_type→model→vendor
  토큰매핑(10토큰, firewall 의도적 미매핑). generic: applies_when_standard=True 폴백.
  ISS-030~041: vpn~waf는 applicability_col None→자동제외, generic은 yaml label C 자동보류.
  M3 firewall 미매핑 테스트 2개 추가, Opus 재리뷰 병합가능 통과.
  잔존: M1 이중XML파싱(성능 선례일치), M2 F5 secret 과마스킹(실데이터후 확인)) /
  **⑥ OS 가상화 구조 + Opus 리뷰 완료**(2026-06-15, **626 tests**, 3변형 vcenter/esxi/xen,
  osvirt_xml 파서+OS_VIRT Profile+osvirt.yaml. ⚠️컬럼 역전(판단방법<판단기준) 정확 반영.
  detect_variant: <asset><variant>직접키 > <product>토큰, 미식별 None(범주오류 방지).
  vcenter>esxi 토큰순서로 동시등장 우선순위. 마스킹: server체이닝. Opus [H]없음 통과) /
  **⑦ 웹서버-WAS 구조 + Opus 리뷰 완료**(2026-06-15, **658 tests**, 11변형 OS5종+웹서버6종,
  webwas_xml 파서+WEBWAS Profile+webwas.yaml. 시트=서버 동형 106 + 웹특화 20 = 126항목.
  ⚠️컬럼 비대칭: OS는 전용컬럼(col23~32 기준먼저), 웹서버는 공통컬럼(col37/38) 공유.
  detect_variant: 직접키 > <os>(server _OS_VARIANTS 재사용) > <webserver>/<product>, 미식별 None.
  OS/웹 이중성은 활성화게이트. Opus [H]없음 통과)
- **다음 착수 = 활성화 게이트** 중 실수집 데이터 확보 시 진행 (7개 도메인 구조 전부 완료).
- **단, ③서버·④네트워크·②방화벽·⑤컨테이너·⑥OS가상화·⑦웹서버-WAS는 "실수집 데이터 판정 활성화" 전 게이트 미해결** —
  아래 각 도메인 "활성화 게이트" 참조.
- 작업 브랜치: `feat/native-db-variants`.
- **에이전트 규칙(정정)**: 계획·설계=Fable, **구현=Sonnet**, 검토=Opus (CLAUDE.md 참조).

## 자동판정 대상 = 8개 도메인 확정 (2026-06-15)
관리체계 계열(정보보호 관리체계·가상화 시스템 관리체계)·네트워크 인프라·웹_모바일_HTS
시트는 **범위 외**. 아래 8개만 자동판정 대상으로 확정. 메모리 [[domain-script-sample-status]].

### 점검 스크립트·실수집 샘플 제공 현황 (활성화 게이트 진행 순서 기준)
| 도메인 | 점검 스크립트 | 실수집 샘플 | 위치 |
|---|---|---|---|
| 클라우드 | ✅ | ✅ | scripts/fsi_pism_tools(script)/fsec_aws·azure_script.sh / results/Public Cloud/ |
| 데이터베이스 | ✅ | ✅ | scripts/DB/*.sql+unix_*.sh / results/DB/ |
| 방화벽(ISS FW) | ※정책export | ✅ | ref/FW/보안장비 결과/ P02~P34_정책(20+건) |
| 서버 | ✅ | ❌ | scripts/서버/ fsi_unix.sh+fsi_win.bat |
| 웹서버-WAS | ✅(서버스크립트 공유) | ❌ | **fsi_unix.sh가 SRV+WST 둘 다 점검** |
| OS 가상화 | ✅ | ❌ | scripts/가상화시스템/ fsec_vmware_script.ps1+fsec_xen_script.sh |
| 컨테이너 | ✅ | ❌ | scripts/가상화시스템/ fsec_container_script.sh |
| 네트워크 장비 | ❌ | ❌ | 미제공 |
| 정보보호시스템(VPN/IDS/IPS/DDoS/WAF) | ❌ | ❌ | 미제공(방화벽 정책 샘플만 존재) |
- 스크립트+샘플 모두 있는 것: **클라우드·DB·방화벽 3개** → 활성화 우선.
- 스크립트만 있고 샘플 없는 것: 서버·웹서버-WAS·OS가상화·컨테이너 → 샘플 수집 후.
- 둘 다 없는 것: 네트워크·정보보호시스템(비FW) → 수집 방식 확정부터.

## 도메인 로드맵 (실행순서, Fable 우선순위/아키텍처 리뷰 반영)
평가기준 xlsx에 6개 도메인 시트 모두 존재(기존 Profile/VariantSpec 패턴과 동형).
신규 도메인 추가 실비용 = 파서 1 + Profile 1 + item_configs 라벨. 병목은 코드가 아니라
**도메인별 수집 스크립트·골드라벨 데이터 확보**.

| 순 | 도메인 | 상태 | 데이터 | 비고 |
|---|---|---|---|---|
| ① | 판단방식 5분류 정교화(cloud/DB) | **완료** | - | 코어 분류체계, 후속 도메인 라벨 기반 |
| ③ | 서버(OS) 106항목/5변형 | **완료(구조)** | 기준O/샘플X | server_xml 파서+detect_variant seam. 활성화 게이트 미해결(아래) |
| ④ | 네트워크 장비 45항목 | **완료(구조·CISCO+generic)** | 기준O/샘플X | network_xml 파서, cisco+generic(미해당) 변형, applies_when_standard. 활성화 게이트 미해결(아래) |
| ② | 방화벽 이상정책 탐지(정보보호시스템) | **완료(구조·SECUI+ID70+PaloAlto+ISS_DEVICE·Opus재리뷰)** | **샘플O**(정책 20건+, ≥3포맷) | fw_policy.py 결정론 엔진+3종 어댑터+ISS Profile+ISS_DEVICE(VPN/IDS/IPS/DDoS/WAF/generic). 활성화 게이트 미해결(아래) |
| ⑤ | 컨테이너 가상화 50항목/9변형 | **완료(구조·9변형·Opus재리뷰)** | 기준O/샘플X | container_xml PROVISIONAL. 마스킹 정밀화(_is_base64_like). 활성화 게이트 미해결(아래) |
| ⑥ | OS 가상화 35항목/3변형 | **완료(구조·vcenter/esxi/xen·Opus리뷰)** | 기준O/샘플X | osvirt_xml 파서. 컬럼 역전 주의. 활성화 게이트 미해결(아래) |
| ⑦ | 웹서버-WAS 126항목/11변형 | **완료(구조·OS5+웹서버6·Opus리뷰) + Phase 3 결정론 SHIP** | 기준O/샘플O(apache_linux) | webwas_xml 파서. 서버동형106+웹특화20. OS전용/웹공통 컬럼 비대칭. WST 웹특화 결정론 활성 — apache 실데이터 WST-033 양호 확인. WST-040 xlsx 역전 미해결(MANUAL 유지). |
| DB | 데이터베이스 DBM 31항목/5엔진 | **완료(구조+결정론 SHIP) — Phase 4** | 기준O/샘플O(5엔진 네이티브) | db_json 파서+raw_evidence 확장+det_adapters/db.py. DET_SOURCE DBM 전수 분류. 거짓양호 0 확인. R3 pg/mariadb 보수처리 잔존(10항목 STUB — 수집형식 수정 후 복원 예정). Opus 리뷰 미완료. |

### ⑦ 웹서버-WAS 활성화 게이트 — **Phase 3 SHIP(2026-06-16, 926 passed, 4 skipped)**
웹 특화 WST 결정론 통합 완료. 실데이터(web_apache-s-sample.xml) 검증: WST-033 양호(det_common) 확인.
거짓양호 0. 아래는 잔존 과제.

1. **✅ OS/웹 이중성 처리** — DET_SOURCE OS 변형 = DET-PARTIAL + `_infer_web_variant()` raw 추론으로 해결.
   linux detect → raw에서 apache 추론 → WST-033 apache check 함수 호출 정상.
2. **✅ webwas.yaml 전수 라벨분류** — 웹 특화 WST 항목 등재 완료. WST-126=D, WST-080=D.
   OS-동형 WST는 server 어댑터 위임(ID 라우팅으로 자동).
3. **✅ detect_variant 실데이터 검증** — web_apache-s-sample.xml에서 linux 반환 + raw 추론 apache 정상.
4. **WST-040 xlsx 역전 미해결** — DET_SOURCE iis=MANUAL 유지. xlsx 기준 셀(판단기준/판단방법 역전 여부) 사용자 확인 후 DET 승격 예정.
5. **IIS/WebtoB/Tomcat/JEUS 실수집 샘플 미확보** — 합성 픽스처 기반 테스트만(57건). 실데이터로 업그레이드 필요.
6. **server.yaml OS 항목 라벨 → WST 동기화** — 현재 OS-동형 WST는 server 어댑터가 SRV-NNN으로 처리. webwas.yaml에는 WST-NNN OS 항목 미등재(범위 밖). 필요 시 평가항목명 기준 대조 후 webwas.yaml에 추가.

### ⑥ OS 가상화 활성화 게이트 (실수집 데이터 판정 활성화 전 필수)
구조/단위테스트+Opus리뷰 완료(626 tests, osvirt 33). 3변형 vcenter/esxi/xen.
**⚠️ 컬럼 역전**: 다른 도메인과 달리 판단방법(col15/17/19)이 판단기준(col16/18/20)보다 앞.
profile.OS_VIRT에 반영됨(standard_col=16/18/20, method_col=15/17/19, app_col=12/13/14).
초기 0-indexed/1-indexed 혼동으로 -1 오프셋 버그 → 실데이터 스모크로 발견·수정(현재 일치).
아래는 **실제 하이퍼바이저 결과로 판정을 켜기 전** 처리.
1. **수집 포맷 확정(선행조건)** — esxcli/PowerCLI/xe 결과 수집 스크립트 없음. 현재
   파서(osvirt_xml)는 server_xml과 동일 PROVISIONAL XML 엔벨로프 가정. 실수집 방식
   확정 후 포맷 변경 시 Profile.parser 1줄 교체.
2. **하이퍼바이저 특화 마스킹(Opus [L1] 최우선)** — vpxuser 비밀번호·vCenter SSO/API 세션
   토큰은 `$`-앵커 crypt 해시와 형태가 달라 현재 server_xml 체이닝(crypt/PEM/hex)으로 미포착.
   실데이터 1차 확보 시 osvirt_xml에 패턴 추가(최우선 보강 대상).
3. **item_configs/osvirt.yaml 전수 라벨분류** — 35항목 전부 기본 A(LLM). 샘플 확보 후
   C(기술한계)/D(EOL·패치)/B(인터뷰) 분류. 후보: PRCV-003/022(B 인터뷰), 패치성(D).
4. **detect_variant 실데이터 검증** — 수집 스크립트가 `<asset><variant>`(vcenter/esxi/xen) 또는
   `<asset><product>`(VMware ESXi/vCenter, Citrix XenServer) 어느 방식인지 확인. 미식별 시
   None 반환→--variant 유도(vCenter ⊂ ESXi 범주오류 방지). vsphere 단독은 esxi 폴백.
5. **empty_means_good 식별** — esxcli 위반필터형 명령 분석. 현재 frozenset().

### ⑤ 컨테이너 가상화 활성화 게이트 (실수집 데이터 판정 활성화 전 필수)
구조/단위테스트+Opus재리뷰 완료(557 tests). [L]잔존: JWT alg:none 미탐(k8s SA토큰 실영향 없음),
EUC-KR 테스트 마스킹검증 보강(기능결함 없음). 아래는 **실제 컨테이너 결과로 판정을 켜기 전** 처리.

0. **★ID 표기 정규화 갭(2026-06-15 발견)** — 제공 스크립트(fsec_container_script.sh)는
   항목을 `PRC-C-001` 표기, 기준/파서는 `PRCC-001`. profile.normalize_id가 `PRC-C-001`을
   정규화 못 해(`([A-Za-z]+)[_-](\d+)` 패턴 불일치) 매칭 실패→전건 누락. 컨테이너 활성화
   전 normalize_id에 `PRC-C-NNN`→`PRCC-NNN` 변환 보강 필수. (단 스크립트 출력 XML의
   실제 <id> 표기는 미확인 — fsec_container_script.sh는 docker+kubectl 의존이라 kind 클러스터
   구축 후 실행 필요. 스크립트 체크리스트 표기 기준 추정.)
1. **수집 포맷 확정(선행조건)** — fsec_container_script.sh 존재(scripts/check_scripts/
   virtualization/). docker+kubectl 의존 → kind/minikube로 k8s 클러스터 구축 후 실행 가능.
   현재 파서(container_xml)는 server_xml과 동일 PROVISIONAL XML 엔벨로프 가정.
2. **item_configs/container.yaml 전수 라벨분류** — 50항목 전부 기본 A(LLM). 샘플 확보
   + 판단기준 정독 후 C(기술한계)/D(버전·패치)/B(인터뷰) 분류.
3. **detect_variant 실데이터 검증** — 수집 스크립트가 `<asset><variant>` 또는
   `<asset><platform>+<role>` 어느 방식으로 기록하는지 확인 후 파서 조정.
4. **empty_means_good 식별** — kubectl 위반필터형 명령 분석. 현재 frozenset().
5. **민감 마스킹 실데이터 검증** — kubectl secret/configmap 값 포함 여부 확인.

### ② 방화벽 활성화 게이트 (실수집 데이터 판정 활성화 전 필수)
구조/단위테스트 완료(486 tests). 아래는 **실제 ISS 결과로 판정을 켜기 전** 처리할 것.
합성 픽스처 기반 테스트는 통과됐으나 실수집 xlsx 파일로 스모크 실행 필요.

1. **실수집 스모크 실행** — `python3 -m judge_tool.main --report <fw_policy.xlsx> --criteria
   <기준.xlsx> --profile iss --out-dir out` 으로 context 직렬화·역직렬화·탐지 결과 확인.
   12개 ISS 3-튜플 emit + FW_POLICIES_JSON 왕복 + verdict 확인.
2. **item_configs/iss.yaml 전수 라벨분류** — ISS-001~029, ISS-042~043 현재 기본 A(LLM).
   실수집 데이터 + 판단기준 원문으로 C(기술한계)/D(패치)/B(인터뷰) 분류.
3. **그룹객체 미확장** — 현재 단일 IP/CIDR 문자열만 파싱(보수처리). 실제 규칙셋에서
   그룹객체명(예: "INTERNAL_HOSTS")이 IP 대신 오면 `_is_any`, `_is_broad_cidr` 미인식.
   실수집 샘플 확인 후 그룹→IP 확장 테이블 연계 여부 결정.
4. **VPN·IDS·IPS·DDoS·WAF 5변형 활성화** — `iss.yaml` 주석 처리된 변형 등록 + 각 장비별
   파서·탐지 엔진 구현. 현재 FW 단일 변형만 완성.
5. **ISS-034 블랙리스트 식별 한계** — "블랙리스트 정책 상위 부재" 탐지는 블랙리스트
   대상 IP 목록이 없으면 불가. 현재 그림자(cover+action상이) 탐지로 부분 대체.
6. **ISS-036 Xmanager 버전 판정 불가** — 현재 원격서비스 포트 탐지(512-514/69)로 대체.
   Xmanager 버전 정보는 별도 자산 데이터 없으면 판정 불가 → needs_review 자동.
7. **미지 포맷 로컬LLM 헤더매핑 폴백** — 현재 unknown 포맷 → 판단보류. 사용자 결정:
   "로컬 LLM 헤더매핑 폴백 (헤더만 LLM에 줘 컬럼→정규화 필드 매핑)". v2 구현 대기.

### ② 방화벽 설계 현황 (2026-06-12 조사 완료, 데이터 민감경계 준수=헤더만 열람)
**도메인 = 정보보호시스템 장비 시트**(header_row=4, data_start_row=5, id=2/name=7/risk=8, 43항목
ISS-001~043, 6변형 FW/VPN/IDS/IPS/DDoS/WAF=평가대상 C12~17 'o', 판단기준 C18/판단방법 C19 공유
=네트워크 시트와 동형). 이번 범위 = **FW 변형 + 정책-이상 항목 ISS-030~041**.

**아키텍처 확정**: 정책테이블 집합연산(any-any·광역CIDR·과도서비스·양방향·출발지포트·취약원격)
+순서분석(그림자=cover관계+action상이) = **별도 결정론 엔진 `fw_policy.py`**(LLM·RAG 아님, eol.py 선례).
`ipaddress`(stdlib)로 CIDR/포트 집합연산 정확·전수. **정규화 Policy 모델 1개 + 포맷별 얇은 어댑터 +
포맷 sniff + capability 플래그**(포맷마다 답 가능한 ISS 다름). 탐지=결정론, 정당성=사람
(status_available=False로 전건 needs_review). 출력은 기존 harness 재사용(EvidenceItem→Judgment/writer).
`_HANDLERS`에 신규 method(예 "fw_policy") **등록만**(① seam, elif 증식 없음) + classify_method/item_configs 라우팅.

**ISS-030~041 판정 분류**(판단기준 원문은 기준 xlsx C18, 메모리 [[fw-policy-export-schema]]):
- 완전 결정론: 030(any-any allow)·031/041(광역대역+관리/취약포트)·032(ALL/1024-65535)·033(Two-way
  컬럼/역방향페어)·035(출발지포트)·036(r-svc512-514·TFTP69 포트; 단 "취약 Xmanager 버전"은 판정불가→게이트).
- 결정론(주의): 034(그림자=cover+action상이; "블랙리스트 상위부재"는 블랙리스트 식별 한계→부분).
- 보조정보(--aux/자산): 038(서버IP)·039(접근통제시스템 IP·토폴로지). 없으면 needs_review 보류.
- 인터뷰/포맷의존: 037(미사용=hit-count 필요 — SECUI엔 없음→인터뷰, **Palo Alto엔 Hit Count 있어 결정론 가능**).

**포맷 다양성(확증, 헤더만)**: 메모리 [[fw-policy-export-schema]]에 상세. 요약 — ①점검대상 시트=
자산목록(→`--aux` 대체), ②SECUI류(우세 ~40시트, "Font Color:"범례+Seq/Two-way/Action/From/To/Service),
③식별기반 70열(PRIORITY/SRC TYPE/USER NAME/DEPARTMENT…), ④Palo Alto 18열(Zone/Application/Hit Count).
별도 P02_정책.xlsx도 SECUI류. CLI config형(ASA/FortiGate)은 표 아님→무거운 파서 별도 게이트.

**② 활성화 게이트(안 되는 부분, 명확히)**: 포맷 다양성 전략 미정(위 ⚠️) / 그룹객체 멤버 IP 미확장
시 보수처리 / VPN·IDS·IPS·DDoS·WAF 5변형 / 비-정책이상 ISS(001~029,040,042,043 계정·로깅·패치 등)
/ 034 블랙리스트 식별 한계 / 036 Xmanager 버전판정 불가 / 037 SECUI hit-count 부재 / 실데이터는
사용자 로컬 검증(민감). 합성 픽스처(더미IP)로만 단위테스트.

### ③ 서버 활성화 게이트 (실수집 데이터 판정 활성화 전 필수 — Opus 리뷰 도출)
구조/단위테스트는 완료(244 tests). 아래는 **실제 서버 결과로 판정을 켜기 전** 처리할 것.
샘플 데이터(`{hostname}-s-{date}.xml`) 확보가 1~5의 선행조건.
1. **item_configs/server.yaml 전수 라벨분류** — 현재 106항목 전부 기본 A(LLM). 샘플로
   판단기준/판단방법 정독해 C(기술한계)/D(EOL·패치)/B(인터뷰) 분류. 커널·패치 버전성
   항목은 eol_check/patch_check 연계(현재 eol.yaml에 OS 테이블 없음 → 추가 필요).
2. **empty_means_good 식별** — `fsi_unix.sh` 위반필터형 명령 분석으로 빈출력=양호 항목 도출
   (현재 frozenset() 비어있음 → 빈출력은 전부 판단보류).
3. **M2: detect_variant OS 오식별 검증** — `<asset><os>` 실제 포맷 확인. 현재 substring
   매칭(`server_xml._OS_VARIANTS`)이라 부가텍스트가 토큰 포함 시 오식별→틀린 기준컬럼으로
   *무음* 판정 위험. 산출물 `metadata.variant` 확인 안내 또는 단어경계 매칭 강화.
4. **M-c: 개인키 마스킹 백트래킹** — `_PRIVATE_KEY_BLOCK`의 `.*?`(DOTALL)가 END없는 다중
   BEGIN 손상덤프에서 O(n²)(10k블록≈14s). 대용량/손상 입력 안전성. 일반케이스는 무해.
5. **L2: 평문 시크릿 마스킹 확장** — 현재 마스킹은 crypt해시/PEM개인키/32+hex만. 평문
   `password=`, AWS키(`AKIA…`), base64 키블록 등은 미처리(서버 출력 구조 불규칙해 db_json식
   키기반 마스킹 어려움). 명백 패턴 선제 추가 검토.
- 해결됨(이번 반영): H1 bcrypt 본문 부분누출(알고리즘ID 앵커 `\$(?:1|2[abxy]?|5|6|7|y|gy)\$`),
  M-b crypt 과마스킹($PATH$HOME류), M-a 개인키 헤더 일반화(ENCRYPTED/PKCS#8), M1 resource_id
  유일성(cid별 전역카운터). 6게이트 중 H1·M-a·M-b·M1 완료, M2·M-c·L2 + 라벨/emg 잔존.

### ④ 네트워크 활성화 게이트 (실수집 데이터 판정 활성화 전 필수 — Opus 리뷰 도출)
구조/단위테스트 완료(348 tests, CISCO + generic 변형). 변형 모델: 평가기준 "네트워크 장비"
시트는 판단기준(C18)·판단방법(C19)을 **전 벤더 공유**, 벤더는 평가대상 'o' 컬럼만 갈림
(C33~42). 현재 **cisco**(C33 적용, 45항목 전부 'o')와 **generic(미해당)** 두 변형만 구현.
generic = 벤더 미식별 장비를 벤더중립 판단기준(C18)으로 LLM 판정하는 폴백(applies_when_standard
=True → C18 비공백 전항목 적용). detect_variant: CISCO 토큰→"cisco", 그 외/미식별→"generic"
(에러로 안 끊음). network는 status_available=False라 **전 판정 자동 needs_review**(generic 신뢰도
낮음이 이미 플래그됨). 아래는 **실제 네트워크 결과로 판정을 켜기 전** 처리할 것.
1. **수집 포맷 확정(선행조건)** — 네트워크 장비는 셸 없음 → on-host 수집 불가. 수집 스크립트·
   샘플 모두 없음. 현재 파서(network_xml)는 서버 동일 XML 엔벨로프(`<asset><vendor>`, `<dump>
   <id>NET-xxx</id><output>CDATA</output>`)를 **PROVISIONAL 가정**. 실수집 방식(SSH 관리호스트
   스크립트/수기 템플릿/raw config 덤프) 확정 후: raw config로 확정되면 raw→엔벨로프 변환기
   또는 network_config 파서 추가 등록(Profile.parser 1줄 교체).
2. **나머지 9개 벤더 구현(TODO)** — A10(col34)/BROCADE(35)/ALTEON(36)/NOTEL(37)/BIGIP(38)/
   CITRIX(39)/PIOLINK(40)/3COM(41)/JUNIPER(42). std/method는 18/19 공유. VariantSpec 등록 +
   detect_variant 벤더 토큰 확장 + 벤더별 마스킹 패턴. generic은 영구 최후 폴백으로 유지.
3. **item_configs/network.yaml 전수 라벨분류** — 현재 45항목 전부 기본 A(LLM). 후보 메모:
   NET-001(설정백업, B 인터뷰), NET-048(보안패치, D patch_check), NET-059(EOS 장비교체,
   D eol_check — eol.yaml에 CISCO IOS/NX-OS Lifecycle 테이블 추가 선행), NET-056(비밀번호 주기변경, B).
4. **detect_variant 오식별 검증** — 실수집 `<asset>` 태그 포맷 확인. 타 벤더→generic 폴백은
   안전(벤더중립 C18 적용·범주오류 없음)하나, --variant cisco 강제 오용은 운영 경계.
5. **empty_means_good 식별** — 수집 포맷 확정 후. 네트워크는 config 존재여부형이라 빈출력=양호
   거의 없을 것(현재 frozenset() — 빈 출력 전부 판단보류).
6. **민감마스킹 실데이터 검증** — CISCO 키워드 앵커 16패턴(enable/username/line password,
   ppp chap/pap, snmp community, SNMPv3 user auth/priv, tacacs/radius key, isakmp/pre-shared,
   ntp key, key-string) + Juniper $9$/$8$·set-style 평문 + server crypt/PEM/32+hex 체이닝.
   비밀번호 동등성 보존(<REDACTED 비밀번호#N>, NET-009 중복탐지). **잔존 누출 갭(Low, Opus
   재리뷰)**: (a) F5 단일행 2토큰 `auth ldap x { secret Y }`(다행 tmsh 출력은 정상 마스킹),
   (b) `router bgp ... neighbor X password Y` 인라인 password(줄앵커 범위 밖, 선재 갭).
   실 config로 과/미마스킹 점검 시 보강. Type-7 동등성은 오프셋차로 best-effort.
7. **스위치/라우터(col12/13)·A~D그룹(col14~17) 적용성 축** — 현재 미사용. 장비 역할별 적용
   필터(라우터 전용 필터를 스위치에 적용 등 부정합)는 generic에서 LLM 판단+프롬프트 "역할
   불일치 시 판단보류" 지시에 의존. 필요 시 별도 설계(VariantSpec에 욱여넣지 않음).

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
| ③ 서버(OS) 구조 | SERVER Profile(5변형 aix/hpux/linux/solaris/win, 컬럼 12~26), `server_xml` 파서(XML `<dump><id>/<output>CDATA`), **내용기반 변형식별 `detect_variant`**(파일명 OS마커 없음→`<asset><os>` 매핑), main.run에 `hasattr(parser,'detect_variant')` 폴백 seam(cloud/DB 불변), 민감마스킹(shadow crypt/PEM개인키/32+hex), item_configs/server.yaml 스캐폴드(전수 A). e2e 보류(샘플X). (06-12, Fable설계+Sonnet구현, Opus 2회리뷰 H1 bcrypt누출 수정 후 병합) |
| ④ 네트워크 장비 구조 | NETWORK Profile(변형 cisco[applicability_col=33]+generic[applies_when_standard=True, 벤더중립 C18 폴백]), VariantSpec에 `applies_when_standard` 필드 가산, criteria_loader elif 분기, `network_xml` 파서(server_xml 미러: parse 3-튜플·detect_variant cisco/generic 폴백·민감마스킹 16패턴+Juniper+동등성보존), judge.py generic 벤더중립 scope_note, writer 요약시트 프로파일/변형 행, item_configs/network.yaml 스캐폴드(전수 A). e2e 보류(샘플X). (06-12, Fable설계+델타설계, Sonnet구현, Opus 2회리뷰 마스킹누출 H1[ppp/SNMPv3]·H2[비-Cisco set평문]·M1[community_index 분리]·M2 수정 후 병합) |
| ② 방화벽 이상정책 탐지(ISS) | ISS Profile(fw 변형, applicability_col=12, standard/method 18/19), `fw_policy_xlsx` 파서(detect_variant="fw" 고정, 12개 ISS-030~041 3-튜플 emit, SECUI/ID70/PaloAlto 3종 어댑터, compact JSON 직렬화), `fw_policy.py` 결정론 탐지 엔진(Policy dataclass, sniff_format, ADMIN/VULN/VULN_REMOTE 포트셋, detect_any_any/broad_cidr/all_port/two_way/src_port/vuln_remote/unused/shadow 8개 함수, _CAPABILITY 포맷×항목 맵, detect_for_iss 진입점, 직렬화 왕복), criteria_loader.py yaml judgment_method 오버라이드 seam, main.py `_fw_policy_handler` + `_HANDLERS["fw_policy"]` 등록, item_configs/iss.yaml(ISS-030~037/041: fw_policy, ISS-038/039/040: label C). 포맷전략 = 수요기반 3종+로컬LLM 헤더매핑 폴백(v2). 합성 픽스처 단위테스트 4파일. (06-12, Plan설계, Sonnet구현) |
| ⑤ 컨테이너 가상화 구조 | CONTAINER Profile(9변형: k8s_master/k8s_worker/eks_master/eks_worker/aks_master/aks_worker/ocp_master/ocp_worker/docker_linux, applicability_col C12~20, std/method 쌍 C21~38), `container_xml` 파서(server_xml 미러, detect_variant: <asset><variant> 직접 키 > <platform>+<role> 조합, 마스킹 동일), parsers/__init__.py 등록, item_configs/container.yaml 스캐폴드(전 50항목 기본 A). e2e 보류(샘플X). (06-12, Sonnet) |
| Phase 3 웹서버-WAS(WST) 결정론 | `judge_tool/vendor/common/webwas/`(wslib.py/WST_Apache_parse.py/WST_WebtoB_parse.py/WST_IIS_parse.py — VENDOR-EDIT(a)+(bug) WST-102 IIS 2부분 극성 수정), `det_adapters/webwas.py`(SRV-* → server 위임 / WST-* gate+파서+§6.4 config 시그니처 가드+§6.2 raw 추론+_map_result), `parsers/webwas_xml.py` raw_evidence 분리, `judge_tool/vendor/common/DET_SOURCE.yaml` WST 22항목 전수 분류(OS 5종=DET-PARTIAL, 웹 3종=DET, WST-040=MANUAL, WST-044/080/121~126=ABSENT), `item_configs/webwas.yaml` 루트레벨 전수 등재(WST-031~044/080/102/121~126), `tests/test_det_adapters_webwas.py`(57건). 실데이터 WST-033=양호(det_common, Apache 2.4.52) 거짓양호 0. (2026-06-16, Sonnet) |
| 테스트 | **926 passed, 4 skipped** (+Phase3 webwas 57: test_det_adapters_webwas.py) |

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
- **변형 식별 seam(③이후)**: main.run은 `--variant` > `variant_from_filename` >
  (파일명 마커 없을 때) `parser.detect_variant(report)` 내용기반 폴백 순. 파서가
  `detect_variant`를 노출할 때만 `hasattr` 가드로 발동 → cloud/DB(미보유) 경로 불변.
  서버처럼 출력 파일명에 변형 마커가 없는 도메인은 파서에 `detect_variant` 구현.
- **applies_when_standard 적용성(④이후)**: VariantSpec 새 불리언(기본 False, 순수 가산).
  loader applicable 분기 우선순위 = applicability_col('o') > applies_when_standard(bool(standard))
  > eval_type(cloud). 네트워크 generic(미해당) 변형이 이걸 써서 벤더중립 판단기준(C18) 비공백
  전항목을 적용대상으로 삼는다. is_judgeable=applicable∧standard비공백이므로 generic은
  "C18 비공백 전항목 판정"과 동치. 기존 8개 프로파일은 전부 False라 동작 불변.
- **generic(미해당) 폴백 패턴(④이후)**: 내용기반 detect_variant가 벤더 미식별 시 None(→오류)이
  아니라 "generic" 변형으로 폴백해 항상 판정 가능하게 한다. 안전성: 판정기준이 벤더특화가 아닌
  공유 컬럼(C18/C19)이라 "타벤더를 cisco기준으로 오판정"하는 범주오류가 없고, 산출물
  metadata.variant·판정행·요약시트에 "generic"이 노출돼 운영자가 인지. status_available=False
  도메인은 전 판정 needs_review=True라 신뢰도 낮음이 자동 플래그됨. 다른 도메인이 동일 폴백을
  원하면 (a) VariantSpec에 generic+applies_when_standard, (b) 파서 detect_variant가 미식별 시
  generic 반환, (c) 손상 입력은 generic 폴백 말고 ReportError 유지(유효 출력에만 폴백).
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

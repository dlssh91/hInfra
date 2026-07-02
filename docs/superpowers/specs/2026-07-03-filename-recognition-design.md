# 설계서: 파일명 플랫폼 별칭 기반 프로파일 자동인지 확장 (2026-07-03, Fable)

목표: 업로드/입력 파일명을 보고 플랫폼(프로파일) 자동인지율↑. 현재 variant 단위 `filename_markers`가
`mysql_result`/`aws_report` 등 구체 토큰이라 `MySQL점검.txt`·`오라클_result.xlsx`·`방화벽정책.xlsx` 같은
자연 이름은 인식 실패. **거짓 라우팅 절대금지 > 인지율** — 애매하면 (None, 후보)로 사용자 선택 요청.

## 확정된 미결(사용자/오케스트레이터 결정)
1. 별칭↔확장자 상충 시 **별칭 승리**(예: 오라클_result.xlsx→db_oracle. 현행 iss 오탐보다 나음).
2. `was` 토큰 **포함**(경계검사 필수 + 별칭표에 "위험/제거가능" 주석).
3. 합리적 한글 별칭 포함.

## 0. 현행 계약 (탐색 결과)
- `guess_profile(path)->(Optional[str],Tuple[str,...])` (profile.py:603-629): Stage A 구체마커 역인덱스(`_marker_profile_index`:571) substring→유일1개 확정/2개↑ (None,sorted)/0개 Stage C 확장자폴백(.xlsx→iss 유일, .json·.xml→후보군, 그외 (None,())).
- `variant_from_filename` (:53-80): 최장마커 우선 + 네이티브×클라우드토큰 모호가드(`_CLOUD_TOKEN_RE`:8 = `(?<![a-z])(rds|aurora|azure)(?![a-z])`)→가드 발동 시 None. 계약: `rds_mysql_result.txt`→None(test_profile_db.py:182), `SERVER.variant_from_filename("linux.xml")`→None(test_profile_server.py:49).
- `main._resolve_profile`(:703-722): explicit 우선, guess 실패→ReportError. `run()`(:777-802): variant_override→variant_from_filename→parser.detect_variant seam(hasattr)→실패 시 --variant 유도 ReportError.
- detect_variant 보유 파서: server/network/iss/iss_device/container/osvirt/webwas. 미보유: cloud_xml, db_json.
- webui store.add_asset(:221)=guess_profile 결과 저장, set_asset_profile(:263) 정정, jobs.py variant_override로 run().

핵심 발견: (a) **오라클_result.xlsx가 현재 .xlsx→iss 거짓라우팅** → 별칭 스캔을 확장자폴백 앞에 넣으면 해소. (b) **macOS NFD 함정**: 드래그앤드롭 한글명은 NFD 분해형 → 소스의 NFC 토큰과 substring 실패 → `unicodedata.normalize("NFC",...)` 필수(stdlib).

## 1. 플랫폼 별칭 표 (토큰→프로파일)
매칭규약: ASCII 토큰=알파벳경계 `(?<![a-z])tok(?![a-z])`(숫자인접 허용: win2019 매치, winter/darwin 차단). 한글 토큰=NFC 후 substring(2자↑). 전부 소문자.

| 프로파일 | 토큰 | 비고 |
|---|---|---|
| cloud | aws, azure, cloud, 클라우드 | 경계로 flaws/soundcloud/cloudwatch 차단. aws/azure는 §2 DB정제 이중역할 |
| db_mysql | mysql | 경계검사 안전 |
| db_oracle | oracle, 오라클 | oraclelinux 경계차단; oracle_linux_x.xml은 linux와 동시매칭→모호(정답) |
| db_mssql | mssql, ms-sql, ms_sql, sqlserver, sql-server, sql_server | sql 단독 금지 |
| db_mariadb | mariadb | maria 단독 금지 |
| db_postgresql | postgresql, postgres, pgsql | pg 단독 금지 |
| server | linux, unix, aix, hpux, hp-ux, hp_ux, solaris, sunos, redhat, rhel, centos, rocky, ubuntu, debian, suse, windows, win, 리눅스, 유닉스, 솔라리스, 윈도우 | win 경계필수. server/서버 금지(웹서버·DB서버·sql_server 충돌) |
| webwas | apache, nginx, tomcat, webtob, jeus, iis, weblogic, was, 웹서버, 톰캣, 아파치 | **was=최고위험(경계필수, 주석표기·1줄삭제 가능하게)** |
| container | docker, kubernetes, k8s, openshift, container, eks, aks, ocp, 쿠버네티스, 도커, 컨테이너 | eks/aks/ocp 경계(weeks/leaks 차단) |
| network | cisco, juniper, switch, router, 네트워크, 스위치, 라우터 | 변형은 detect_variant 위임 |
| iss | firewall, fw, 방화벽, secui, paloalto, palo-alto, palo_alto, fortigate, fortinet | fw 경계. checkpoint 금지. variant는 fw_policy_xlsx.detect_variant "fw" 고정 |
| iss_device | vpn, ddos, waf | ids/ips **금지**(user_ids/server_ips). wafer 경계차단 |
| osvirt | vmware, esxi, vcenter, xen | xenon 경계차단. 가상화 금지(container 충돌). hyperv/kvm 미등록(dead-end) |

미등록: db_tibero(excluded — test_guess_profile_excludes_tibero 유지).

## 2. 매칭 알고리즘 (3단계, 반환계약 불변)
```
Stage A(기존): _marker_profile_index substring → 유일→(key,(key,)) / 2개↑→(None,sorted)  ← 구체마커 우선
Stage B(신규, A가 0매칭일 때만): 별칭 스캔
   hits: Dict[profile, Set[token]]
   [DB-클라우드 정제] hits=={db_* 1개, "cloud"}이고 cloud토큰⊆{"aws","azure"} → cloud 제거
       (mysql_azure점검.txt→db_mysql. 진짜 클라우드 보고서는 aws_report/azure_report로 Stage A에서 잡힘)
   len==1→(key,(key,)) / len>=2→(None,tuple(sorted(hits)))   ← 다중=모호 fail-safe
Stage C(기존): 확장자 폴백
```
- Stage B가 Stage C 앞: 오라클_result.xlsx→db_oracle 교정. 별칭↔확장자 상충 시 별칭 승리.
- Stage A 우선 귀결: linux_mysql_result.json→db_mysql(마커 확정, 별칭 미스캔). 마커=수집기 생성명이라 정밀.
- 검증예: MySQL점검.txt→db_mysql / linux_web1.xml→server / 방화벽정책.xlsx→iss / mysql_on_linux.json→(None,(db_mysql,server)) / 리눅스_아파치.xml→(None,(server,webwas)).

## 3. 코드 변경 위치 (profile.py 단일 파일)
1. import(:1-4): `import unicodedata`.
2. Profile dataclass(:37 excluded 다음): `alias_variant_tokens: Tuple[Tuple[str,str],...] = ()`.
3. variant_from_filename(:76-80) 재구조화 — 기존 가드·마커 불변, 마커 0매칭일 때만 별칭 변형 폴백:
```python
if (best_name is not None and best_name.endswith("_native") and _CLOUD_TOKEN_RE.search(low)):
    return None                       # 기존 가드(rds_mysql_result.txt→None)
if best_name is not None:
    return best_name                  # 기존 마커
found = {v for tok, v in self.alias_variant_tokens if _alias_hit(tok, low)}
return next(iter(found)) if len(found) == 1 else None   # 2개↑=모호→None
```
4. alias_variant_tokens 부여 — **detect_variant 없는 파서 프로파일만**(내용식별 도메인은 파일명힌트 약함 → SERVER.variant_from_filename("linux.xml") is None 유지):
   - CLOUD: `(("aws","AWS"),("azure","Azure"))`
   - DB_MYSQL: `(("rds","mysql_rds"),("aurora","mysql_aurora"),("azure","mysql_azure"))`
   - DB_ORACLE: `(("rds","oracle_rds"),)` / DB_MSSQL: `(("rds","mssql_rds"),)` / DB_MARIADB: `(("rds","mariadb_rds"),)`
   - DB_POSTGRESQL: `(("rds","pg_rds"),("aurora","pg_aurora"),("azure","pg_azure"))`
   ※ variant명은 실제 정의된 variant 키와 일치하는지 반드시 확인 후 사용.
5. 모듈 레벨(:600 `_EXT_CANDIDATE_GROUPS` 뒤): `_PLATFORM_ALIASES`(§1, ascii는 import 시 경계regex 프리컴파일 캐시), `_alias_hit(token,low)`(ascii→경계regex/한글→substring), `_match_platform_aliases(low)->Dict[str,Set[str]]`, `_refine_alias_hits(hits)`(§2 DB-클라우드 정제).
6. guess_profile(:614): `low = unicodedata.normalize("NFC", os.path.basename(report_path)).lower()`. :622(2개↑ 블록)와 :623(확장자폴백) 사이 Stage B 삽입. docstring 갱신.
7. 시그니처/반환계약 불변. _marker_profile_index/list_profile_keys/get_profile 무변경. 판정엔진 무변경, stdlib(re,unicodedata)만.

## 4. DB 클라우드 variant
- 엔진 별칭만(MySQL점검.txt) → **variant=None**(native 기본 금지 — variant가 applicability/standard 컬럼 가름, native 오추정=조용한 오판정). None이면 run()이 --variant 유도(CLI)/webui set_asset_profile로 지정.
- 엔진+환경토큰 정확히1개(rds/aurora/azure, variant 존재 시) → 그 variant(mysql_rds_점검.txt→mysql_rds). 2개↑→None.
- 기존 마커 매칭 시 폴백 미발동: rds_mysql_result.txt→None(가드), mysql_result_rds.txt→mysql_rds(최장마커) 불변.

## 5. 웹UI/CLI — 추가 배선 불필요
_resolve_profile/배치/대화형/store.add_asset 모두 guess_profile 직접 호출→자동반영. profile_candidates에 별칭 모호후보 저장→기존 UI 후보표시/set_asset_profile 정정 재사용. (선택 UX: DB 별칭인지 자산은 판정 전 variant 지정 안내 — 현행 에러가 안내하므로 필수 아님.)

## 6. 테스트 (tests/test_profile.py 확장)
1. 별칭 성공(영문+한글): MySQL점검.txt→db_mysql, 오라클_result.xlsx→db_oracle(확장자 iss폴백보다 별칭우선=회귀방지 핵심), linux_web1.xml→server, 방화벽정책.xlsx→iss, cisco_backbone.xml→network, docker_host01.xml→container, vmware_esxi01.xml→osvirt, tomcat_was01.xml→webwas, AWS점검결과.xml→cloud. NFD: normalize("NFD","오라클점검.txt")→db_oracle.
2. 모호 fail-safe: mysql_on_linux.json→(None,("db_mysql","server")), 리눅스_아파치.xml→(None,(server,webwas)), oracle_linux.xml→모호.
3. 오탐 배제: winter_report.txt/darwin_notes.txt→(None,()), user_ids.xml·server_ips.xml→.xml 후보군(iss_device 아님), checkpoint_dump.json→.json 후보군, weeks_summary.xml(eks 미발동), wafer_data.xml(waf 미발동).
4. 구체마커 우선 회귀: linux_mysql_result.json→db_mysql, 기존 test_guess_profile_* 통과.
5. DB-클라우드 정제: mysql_azure_점검.txt→db_mysql / azure_점검.xml→cloud / azure_linux.xml→모호.
6. variant 별칭 폴백: CLOUD.variant_from_filename("AWS점검.xml")=="AWS", ("aws_azure.xml")→None, DB_MYSQL("mysql_rds_점검.txt")=="mysql_rds", ("MySQL점검.txt")→None, 가드회귀 rds_mysql_result.txt→None, SERVER("linux.xml") is None.
7. 별칭표 불변식: (a) excluded 키 미포함, (b) 모든 키 _PROFILES 존재, (c) 서로 다른 프로파일 ascii 토큰이 경계규칙상 상호 미매칭(페어와이즈 자동검사).
8. webui 회귀: 기존 mysql_result_rds.json/foo.xml/한글결과파일.xml 무변경 통과. (선택: MySQL점검.txt 업로드 profile 자동채움 1건.)
9. 게이트: pytest 전체 통과 + PROGRESS.md 갱신.

## 7. 금지 토큰(등록 금지) 및 위험 토큰
금지: server/서버, sql, db/dbms/web/net/host, pg/my/ora/maria, ids/ips(user_ids/server_ips), checkpoint, 가상화, hyperv/kvm/tibero(미지원/배제). 위험(등록하되 경계·감시): was(최고위험, 주석+삭제가능), win, rocky, cloud/container, fw(2글자).
과교정 검토: 별칭이 정상 판정을 뭉개지 않는지 — 별칭은 프로파일만 인지(variant 미특정), 판정로직 무관, 모호는 fail-safe.

# DESIGN: Phase 4c — DBM-001 비밀번호 사전공격 결정론화 (b 레이어)

작성: Opus(Fable 불가 대체) / 2026-06-16
대상(미작성): `judge_tool/det_adapters/db_pwcrack.py`(신규), `judge_tool/det_adapters/pwdict.py`(신규 정적 사전), `judge_tool/det_adapters/db.py`(라우팅 1지점), `judge_tool/vendor/common/DET_SOURCE.yaml`(DBM-001 승격), `tests/test_det_adapters_db_pwcrack.py`(신규)
범위: **(b) 파이썬 자족 사전공격 전 엔진.** (a) hashcat 연동은 다음 증분(본 설계는 §G 확장지점만).

## 보안 맥락 (정당성)
전자금융기반시설 **자체** 보안취약점 평가 CLI. DBM-001="취약하게 설정된 비밀번호" — 인가된 방어적 점검에서 수집된 자기 시스템 계정 해시에 기본/공통 비번 사전을 대조해 약한 비번 탐지(정당). 평문은 산출물 비노출·마스킹.

## 0. 핵심 설계결정
- **매치=취약, 미스=판단보류(needs_review, handled=True)**. 복잡도는 해시로 입증 불가 → 미스를 양호로 단정 금지. 기존 db.py(빈위반=양호)와 충돌 → **DBM-001 전용 어댑터 `db_pwcrack.py` 분리 필수.**
- **§7 절대 불변**: 크랙 평문은 citations/rationale/log 어디에도 노출 금지. "계정 X: 기본/사전 비밀번호 사용(평문 비공개)"만.
- **stdlib만**: hashlib/hmac/binascii/base64. 외부 의존 0. 미검증 포맷은 비활성·(a) 위임(거짓판정 차단).

## 1. 실데이터 접지 (collected/db/{engine}_native 직접 확인)
| 엔진 | DBM-001 | 포맷 | (b) 가능 |
|---|---|---|---|
| mariadb | O | `mysql_native_password` `*40HEX`, 빈="" | O 정확 |
| mysql | O | `caching_sha2_password` `$A$005$<salt><hash>`; native `*HEX`도 | △ caching_sha2 정확성 리스크 |
| mssql | O | `0x0200<salt16HEX><sha512 128HEX>`; 구 `0x0100`=SHA1 | O 정확 |
| postgres | O | `SCRAM-SHA-256$4096:<b64salt>$<b64StoredKey>:<b64ServerKey>`; 구 `md5<hex>` | O 정확 |
| **oracle** | **X (native 샘플에 DBM-001 부재, spare4 미수집)** | 11g `S:`/12c `T:`/10g | 현 데이터 무의미→판단보류 |

## 2. 입력/파이프라인 (db.py 계약 재사용)
db_json.parse가 전체 비마스킹 data dict를 raw_evidence에 적재 → `_raw_evidence_for_det` → 어댑터 json.loads. postgres `DBM-001_1/_2`, 나머지 `DBM-001`. `_has_data_key_for("DBM-001",data)`(prefix 매칭) 재사용.

## 3. §A 포맷별 검증 알고리즘 (stdlib, 의사코드)
**mysql_native/mariadb** (`*40HEX`): `"*"+SHA1(SHA1(pw)).hex().upper()` 비교. salt/반복 없음.
**mssql 0x0200**: `hx[4:20]`=8byte salt(raw), `hx[20:]`=sha512 hex. `SHA512(pw.encode('utf-16-le')+salt).hex()` 비교. 구 0x0100=SHA1 폴백. ★UTF-16LE.
**postgres SCRAM**: `SCRAM-SHA-256$<it>:<b64salt>$<b64StoredKey>:<b64ServerKey>`. `salted=pbkdf2_hmac('sha256',pw,salt,it)`; `ServerKey=HMAC(salted,b"Server Key")` == 저장 ServerKey. (또는 StoredKey=SHA256(HMAC(salted,b"Client Key")) 비교.) 구 md5: `"md5"+md5(pw+rolname).hex()`.
**mysql caching_sha2** (`$A$<it3>$<salt20><hash>`): iter=code*1000. MySQL 전용 sha256 stretch + 비표준 base64 → **KAT 핀 고정 전 신뢰 불가. 외부 KAT 미확보 시 이 포맷 비활성·(a) 위임.** placeholder salt(`THISISACOMBINATION...`)·잠금계정 빠른 스킵.
**oracle 11g S:**: salt=`S[40:60]`→raw, `SHA1(pw+salt).hex().upper()`==`S[0:40]`. 12c T(PBKDF2-SHA512)/10g DES=(b) 미커버→(a). 입력파싱은 벤더 `parse_spare4` 차용. **단 현 native 데이터에 spare4 없음.**

## 4. §B KAT 테스트벡터
- mysql_native `password` → `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` (조사 확인).
- mssql/postgres-md5/oracle-11g/postgres-SCRAM: self verify∘generate 라운드트립 + 공개벡터(RFC5802 SCRAM) 1개.
- caching_sha2: **MySQL 서버 생성 공개 검증벡터 확보 필수 — 미확보 시 비활성.**
원칙: 외부 표준값 최소 1 + 라운드트립 보강.

## 5. §C 사전 (`pwdict.py` 정적 상수)
1. DBMS 기본계정: oracle(oracle/system→manager/scott→tiger/sys→change_on_install/dbsnmp), mssql(sa→공백/sa/Password123), postgres(공백/postgres), mysql·mariadb(root→공백/root/password/mysql).
2. 공통 약한 비번 top-N(≈100~300) 정적 발췌.
3. **빈 해시=비번 미설정 → 명백 취약(NO PASSWORD)**, 단 account_locked/password_expired='Y'면 스킵(예 mariadb.sys). 사전 매치 아닌 별도 분기.
- vendor keywords.txt(은행 키워드)와 분리 — 본 증분 정적 사전만. 키워드 주입=(a)/옵션.

## 6. §D 어댑터 통합·라우팅
1. **DET_SOURCE**: DBM-001 전 엔진(native+해당 cloud) MANUAL→**DET** 승격 → gate 통과.
2. **db.py 분기 1지점**: `judge()`에서 `base=="DBM-001"`이면 벤더 `_run_analysis` 대신 `db_pwcrack.crack_judge(engine,data,variant)`. 그 외 불변. registry 변경 불필요.
3. **db_pwcrack.crack_judge**: data에서 DBM-001(_n) RESULT 정규화(계정명/해시/메타). 엔진별 verifier+사전. 매핑:
   - 사전매치 또는 (미잠금)빈해시 ≥1 → **취약** conf0.9 citations=["계정 root: 기본/약한 비밀번호 사용(평문 비공개)"] ev=bad handled=True.
   - 매치0 → **판단보류** conf0.0 ev=review handled=True needs_review.
   - 증거가드: DBM-001 data_key 없음/RESULT빔/해시전무 → handled=False(폴백). oracle native 현 상태.
   - 미구현 포맷(oracle12c/10g, caching_sha2 비활성)만 있는 계정 → 사유에 "(a) 위임".

## 7. §E 마스킹/보안 (§7)
매치 평문은 즉시 폐기·계정명만 기록, log에도 평문 금지. 고정문구만. 해시 마스킹 `_mask_row` 재사용. raw data dict는 citation/LLM 미전달(db.py 경계 유지).

## 8. §F 성능
비용=계정×사전×KDF. native/mssql 경량, SCRAM(4096)/caching_sha2/oracle-12c 무거움. 상한: 계정당 후보 ≤MAX_CANDIDATES(~400), 계정 ≤MAX_ACCOUNTS(~200) 초과시 절단+needs_review. 빈해시·placeholder·잠금·미지원포맷 KDF 스킵. 첫 매치 stop. pbkdf2_hmac C구현.

## 9. §G (a) 확장지점 (미구현)
"전부 미스" 계정을 hashcat 모드별 라인(11g=112/10g=3100/12c=12300, mysql=7401, mssql=1731, scram 등)으로 직렬화하는 `export_for_external(engine,accounts)->dict[mode]->lines` 예약. 벤더 oracle cloud_analysis.dbm_001 분류가 참조. (a)가 이 출력+키워드 wordlist를 hashcat에 투입.

## 10. §H 테스트
KAT단위(포맷별 라운드트립+외부표준) / 사전매치→취약 / 미스→판단보류(handled=True needs_review) / 빈해시→취약·잠금빈해시→스킵 / **§7 평문 비노출 substring 단언** / 증거가드(data_key 없음→handled=False) / 실데이터 native 5엔진 스모크(에러없음·거짓취약 없음·oracle handled=False) / 성능 cap.

## §A2. Phase 4c-a: 외부 hashcat 연동 (2026-06-16 추가 — 사용자 결정)

(b) 자족 사전공격 SHIP 후 다음 증분. 결정: **찾으면 취약, 못 찾으면 판단보류**(크랙은 양호 증명 불가 — (a)도 동일). (a)+(b) 커버리지는 **(a) ⊇ (b)**: hashcat이 caching_sha2/oracle-12c 등 (b) 미커버 포맷까지 모드로 지원 + 키워드 변형룰로 더 깊게.

### 환경 사실
- 이 머신에 **hashcat 미설치** → (a)는 **graceful skip + 활성화 게이트**(없으면 (b)-only). 실데이터 크랙 e2e 불가 → **mock 기반 테스트** + 부재시 스킵 테스트.
- 벤더 룰 자산(`fsi_custom.rule` 13MB + `fsi_custom_base.rule` 12MB + `keywords.txt` 은행키워드 32B)은 **대용량·민감 → git 번들 금지**. **경로 설정형**(운영자/점검건이 제공). 미제공시 (b) 내장 사전을 hashcat wordlist로 폴백 가능.

### §A2.1 설정/CLI 표면 (main.py argparse 확장)
- `--hashcat-path PATH`(기본=PATH에서 자동탐지, 없으면 (a) 비활성)
- `--hashcat-wordlist PATH`(선택; 미지정시 pwdict를 임시 wordlist로 사용)
- `--hashcat-rules PATH`(선택; 벤더 fsi_custom.rule 등)
- `--hashcat-timeout SEC`(기본 예: 600; 초과시 부분결과+판단보류)
- 모두 미설정/바이너리 부재 → (a) 스킵, 로그 `gate_decided_by` 유사하게 `pwcrack_a=skipped(no hashcat)` 메타 기록.

### §A2.2 export + hashcat 모드 매핑 (db_pwcrack 확장)
`export_for_external(engine, accounts) -> dict[mode]->list[hashline]`: (b) 미스 계정만, 포맷별 hashcat 모드 라인으로 직렬화. 모드는 **코드 내 dict 상수**(버전별 상이 → 활성화 시 `hashcat --help`로 검증·교정. 아래는 참조 best-known):
| 포맷 | hashcat mode(참조) | 비고 |
|---|---|---|
| mysql_native (`*SHA1²`) | 300 | |
| mysql caching_sha2 (`$A$`) | **확인 필요**(7401 sha256crypt 계열 추정) | (b) 미커버분 여기서 커버 |
| mssql 0x0100 | 131 (또는 132 case-sensitive) | (b) 미지원분 |
| mssql 0x0200 (SHA512) | 1731 | |
| postgres md5 | 12 | |
| postgres SCRAM-SHA-256 | 28600 | |
| oracle 11g `S:` | 112 | 벤더 oracle dbm_001 확인 |
| oracle 12c `T:` | 12300 | (b) 미구현분 |
| oracle 10g (password DES) | 3100 | |
**주의**: 모드 번호는 hashcat 버전별 상이 가능 → 상수 dict + 활성화시 검증. 잘못된 모드는 hashcat이 거부(조용한 false-neg 아님 — 에러로 드러남).

### §A2.3 오케스트레이션
1. (b) 먼저 실행(즉시 디폴트 탐지). (b)가 취약 판정한 계정은 (a) 제외.
2. (a) 활성(바이너리 존재)시: 미스 계정을 mode별 임시 hash 파일에 기록(`tempfile`, 0600 권한, finally 삭제) → `subprocess.run(["hashcat","-m",mode,"-a",0,hashfile,wordlist,"-r",rules,"--potfile-path",tmp_pot,"--quiet", ...], timeout=...)`.
3. **potfile 파싱**: hashcat 결과(`hash:plaintext`)에서 **크랙된 hash만 식별** → 해당 계정 = 취약. **평문은 읽되 즉시 폐기, citation엔 계정명만**(§A2.4).
4. 매핑: (b) 또는 (a) 크랙 ≥1 → 취약(handled=True, ev=bad) / 둘 다 0 → 판단보류(handled=True, needs_review) / DBM-001 무데이터 → handled=False.
5. timeout/에러 → 부분결과 반영 + needs_review, 크래시 없이 (b) 결과로 폴백.

### §A2.4 보안 (§7 강화)
- **potfile은 크랙 평문을 담는다** → 임시경로(0600), 파싱 후 즉시 삭제(finally), 평문을 변수 밖/로그/citation에 절대 노출 금지. log.debug에도 hash:plain 금지.
- 임시 hash 입력 파일도 해시(민감) → 0600 + 삭제.
- subprocess 인자는 리스트형(셸 인젝션 차단), 사용자 제공 경로는 존재·실행권한 검증.
- citation 고정문구: "계정 X: 사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)".

### §A2.5 graceful degradation / 활성화 게이트
- hashcat 바이너리 부재 → (a) 전체 스킵, (b)-only, 정상 동작(에러 아님).
- 실데이터 크랙 e2e는 hashcat 설치 + 룰/wordlist 확보 환경에서만(활성화 게이트). 본 증분은 구조+mock 테스트.

### §A2.6 테스트
- **mock hashcat**: 가짜 potfile 생성하는 스텁(subprocess monkeypatch 또는 fake 스크립트) → 크랙 시뮬레이션 → 취약 매핑 검증.
- 바이너리 부재 → (a) 스킵, (b) 결과만 반환 단언.
- export_for_external 모드별 직렬화 포맷 단언.
- **§7**: mock potfile의 평문이 verdict/citation/rationale/log에 substring으로 없음 단언.
- timeout/비정상 종료 → 크래시 없이 (b) 폴백 단언.
- 임시파일 cleanup(potfile/hashfile 삭제) 단언.

## 11. §I 리스크/미해결
1. **oracle native spare4 부재** → (b) 무의미, 수집 수정 선결.
2. **caching_sha2 정확성** → 외부 KAT 미확보 시 비활성·(a) 위임.
3. **빈해시=미설정** 취약(본 설계) — 잠금/만료 제외 규칙 의존. 사용자 확정 여지.
4. SASLprep 미완전 → 비-ASCII 비번 SCRAM 거짓미스(은행 ASCII 가정 낮음).
5. 사전 커버리지(은행 키워드 미포함) → (a)/옵션 보완.
6. 거짓취약 회피: 실 root 해시 우연충돌 무시가능, 스모크로 가드.

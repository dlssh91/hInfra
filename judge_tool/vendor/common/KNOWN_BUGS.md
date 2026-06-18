# KNOWN_BUGS.md — common 실버그 목록

> 상태: **확정(2026-06-16)** · 전수검증(§17.2) + Opus 리뷰(§16) 반영.  
> 규칙: 벤더링(Phase 1~) 시 이 파일의 버그만 `# VENDOR-EDIT(bug):` 주석과 함께 수정.  
> 수정 시 반드시 corrected 동작을 단언하는 핀고정 회귀테스트 동반(§18.2/§18.6-d).  
> `DET_SOURCE.yaml`의 `bug:` 필드 id와 1:1 매핑.

---

## 1. `SRV-010-polarity`

**id**: `SRV-010-polarity`  
**위치**: `flus-main/app/common/ServerConfigLoader/SRV_auto_parse.py` lines **942–946**  
**함수**: `check_SRV_010(output)` — sendmail 분기

### 증상
sendmail `PrivacyOptions restrictqrun` 체크에서 **result 값(Y/N)은 올바르나, reason 문자열(양호/취약 문구)만 역전**되어 있다.

실제 소스(SRV_auto_parse.py:935-946):

```python
# 현재 버그 코드 (SRV_auto_parse.py:935-946)
if not restrictq:   # restrictqrun 부재 = 취약 상황
    result = 'Y'    # ← Y=취약 마킹 (정확)
    auto_result_reason = "(+) sendmail.cf :: PrivacyOptions필드에 "
        "restrictqrun값이 존재하는 것으로 탐지되어 양호로 판단\n"
    # ↑ reason만 역전: "존재"·"(+)"·"양호" → 사실은 "부재=취약"이어야 함
else:               # restrictqrun 존재 = 양호 상황
    result = 'N'    # ← N=양호 마킹 (정확)
    auto_result_reason = "(-) sendmail.cf :: PrivacyOptions필드에 "
        "restrictqrun값이 존재하지 않는 것으로 탐지되어 취약으로 판단\n"
    # ↑ reason만 역전: "존재하지 않는"·"(-)"·"취약" → 사실은 "존재=양호"이어야 함
```

**result 값(Y/N)은 각 분기에서 올바르게 설정**된다.  
버그는 **reason 문자열만**: `if not restrictq`(취약 분기)에 양호 문구가, `else`(양호 분기)에 취약 문구가 붙는다.

> 참고: postfix 분기(lines 913–918)는 result와 reason 모두 올바르게 구현되어 있다.  
> exim 분기(line 921)는 `(*) 수동` — 버그 해당 없음.

### Corrected 동작 명세
수정: **result 값은 변경하지 않고** reason 문자열만 각 분기에 맞게 교체.  
수정 후: `restrictqrun` **부재**(`not restrictq`) → `result='Y'`(취약), `"(-) ... 존재하지 않아 취약으로 판단"`.  
수정 후: `restrictqrun` **존재**(`else`) → `result='N'`(양호), `"(+) ... 존재하여 양호로 판단"`.

```python
# 수정 후 (VENDOR-EDIT(bug): SRV-010-polarity)
if not restrictq:
    result = 'Y'                                                # ← 변경 없음(취약)
    auto_result_reason = "(-) sendmail.cf :: PrivacyOptions필드에 "
        "restrictqrun값이 존재하지 않는 것으로 탐지되어 취약으로 판단\n" + reason_str.strip()
    # ↑ reason만 교체: (-) + 취약 문구
else:
    result = 'N'                                                # ← 변경 없음(양호)
    auto_result_reason = "(+) sendmail.cf :: PrivacyOptions필드에 "
        "restrictqrun값이 존재하는 것으로 탐지되어 양호로 판단\n" + reason_str.strip()
    # ↑ reason만 교체: (+) + 양호 문구
```

### 회귀테스트 핀
- **입력**: `restrictqrun`이 포함된 sendmail.cf 출력 → **기대 result='N'(양호), reason에 "(+)"·"양호" 포함**
- **입력**: `restrictqrun`이 없는 sendmail.cf 출력 → **기대 result='Y'(취약), reason에 "(-)"·"취약" 포함**
- `vulnerability_condition_result_model_list`가 비어있으면 result='N', 있으면 result='Y'임을 단언.
- result 값 자체는 수정 전후 동일(수정 대상은 reason 문자열만).

---

## 2. `WST-038-apache-dotall`

**id**: `WST-038-apache-dotall`  
**위치**: `judge_tool/vendor/common/webwas/WST_Apache_parse.py` line **314** 부근  
**함수**: `check_WST_038(configData)` — Apache FollowSymLinks 심볼릭링크 설정 점검

### 증상
`vuln_pattern` 정규식이 `re.IGNORECASE`만 사용하고 `re.DOTALL`을 누락했다.  
`.`이 개행 문자를 넘지 못해, **표준 멀티라인 httpd.conf** 형식의 `<Directory>` 블록
(`<Directory /var/www>\nOptions Indexes FollowSymLinks\n</Directory>`)에서
취약 설정이 있어도 정규식이 매치하지 못해 `result='N'`(양호) = **거짓 양호** 반환.

같은 파일 WST-031은 `re.DOTALL | re.IGNORECASE`로 올바르게 구현되어 있음.

```python
# 현재 버그 코드 (WST_Apache_parse.py:314)
vuln_pattern = re.compile(
    r"<Directory((?!<\/Directory>)[\s\S])*?Options.*\b(?:\+FollowSymLinks|FollowSymLinks|all)\b.*?<\/Directory>",
    re.IGNORECASE   # ← re.DOTALL 누락
)
```

재현:
```python
check_WST_038("<Directory /var/www>\nOptions Indexes FollowSymLinks\nAllowOverride None\n</Directory>")
# → result='N'(양호)  (버그: 취약이어야 함)
```

### Corrected 동작 명세
수정: `re.IGNORECASE` → `re.DOTALL | re.IGNORECASE` (WST-031과 동형).  
수정 후:
- 멀티라인 `<Directory>` 블록에서 `FollowSymLinks` 발견 → `result='Y'`(취약)
- 단일라인 `<Directory ...>Options ... FollowSymLinks ...</Directory>` → `result='Y'`(취약)
- `FollowSymLinks` 없는 clean 블록 → `result='N'`(양호)

```python
# 수정 후 (VENDOR-EDIT(c): WST-038-apache-dotall)
vuln_pattern = re.compile(
    # [^\n]* 로 Options 줄만 검색(over-match 방지) + re.DOTALL로 블록 경계 매치
    r"<Directory((?!<\/Directory>)[\s\S])*?Options[^\n]*\b(?:\+FollowSymLinks|FollowSymLinks|all)\b[^\n]*.*?<\/Directory>",
    re.DOTALL | re.IGNORECASE
)
```

> 주의: 단순히 `re.DOTALL` 추가 시 `Options` 뒤 `.*`가 다른 줄의 `Require all granted`를
> 매치하는 over-match 발생. `[^\n]*`로 Options 키워드 매치를 해당 줄로 제한함.

### 회귀테스트 핀
- **입력**: 멀티라인 `<Directory>` + `Options Indexes FollowSymLinks` → **기대 result='Y'(취약)**
- **입력**: 단일라인 `<Directory...>Options ... FollowSymLinks...</Directory>` → **기대 result='Y'(취약)**
- **입력**: `FollowSymLinks` 없는 clean `<Directory>` 블록 → **기대 result='N'(양호)**
- 어댑터 경유 `judge('WST-038', <멀티라인 취약 raw>, 'apache', {})` → `verdict='취약'`, `handled=True`

---

## 3. `WST-102-iis-polarity`

**id**: `WST-102-iis-polarity`  
**위치**: `flus-main/app/common/WebServerConfigLoader/WST_IIS_parse.py` lines **688–689**  
**함수**: `check_WST_102(configData)` — IIS 서버 정보 노출 헤더 설정

### 증상
위반 항목(`vulnerability_condition_result_model_list`)이 **비어있을 때** `result = "Y"`(취약)로 설정된다.

```python
# 현재 버그 코드 (WST_IIS_parse.py:688-693)
if not vulnerability_condition_result_model_list:
    result = "Y"  # 양호 상태 ← 주석은 "양호"이나 "Y"는 common 인코딩상 취약
    auto_result_reason = "(+) requestFiltering removeServerHeader값이 true 거나 ..."
```

common 인코딩: `Y`=취약, `N`=양호 (`sclib.py:344-346` 확인). 위반 0건이 양호인데 `result="Y"`(취약)로 역전.

### Corrected 동작 명세
수정 후: 위반 항목 없음(`not vulnerability_condition_result_model_list`) → `result = "N"` (양호).  
수정 후: 위반 항목 있음 → `result = "Y"` 유지(취약 — 올바름).

```python
# 수정 후 (VENDOR-EDIT(bug): WST-102-iis-polarity)
if not vulnerability_condition_result_model_list:
    result = "N"  # 위반 없음 = 양호
    auto_result_reason = "(+) ..."
else:
    # result 기본값 "N", 위반 종류별로 "Y" 설정 (기존 else 블록 유지)
```

### 회귀테스트 핀
- **입력**: `removeServerHeader="true"` + `errorMode` 없음 → **기대 result='N'(양호)**
- **입력**: removeServerHeader 없음 + `errorMode="detailed"` → **기대 result='Y'(취약)**
- 위반 0건 → N, 위반 1건 이상 → Y를 단언.

---

## 4. `WST-040-polarity`

**id**: `WST-040-polarity`  
**위치**: `flus-main/app/common/WebServerConfigLoader/WST_IIS_parse.py` lines **524–580**  
**함수**: `check_WST_040(configData)` — IIS `.asa`/`.asax` 파일 매핑 허용 설정

### 증상
복합 polarity 의심:
1. **코드 polarity**: `requestFiltering` 섹션 없음(`not has_match`) → `result='N'`(기본, 양호)로 처리하는데, 섹션 부재가 `.asa`/`.asax` 차단인지 허용인지 판단 방법과 불일치 가능성 있음 (lines 571–572).
2. **xlsx 판단기준 역전 의심**: xlsx 웹 시트 WST-040 row의 양호/취약 판단기준 문구가 코드 판단방법과 역전되어 있을 수 있음 (§17.6 지적, 사용자 확인 필요).

> ⚠️ **xlsx 정정 미확인**: 코드 로직은 "`.asa`/`.asax` 매핑 `true` 존재 → 취약(Y)", "없거나 섹션 부재 → 양호(N)"이나,  
> xlsx 판단기준 셀의 양호/취약 문구가 이와 역전되어 있다는 지적(§17.6). **Phase 3 착수 전 xlsx 셀 재확인 필수**.

### Corrected 동작 명세(잠정)
코드 기준 올바른 로직:
- `.asa` 또는 `.asax` 매핑이 `true`로 설정됨 → `result="Y"` (취약)
- 매핑 없거나 `requestFiltering` 섹션 없음 → `result="N"` (양호)

xlsx 판단기준 문구가 위와 역전되어 있다면 → **xlsx 정정이 우선** (xlsx 권위 원칙). 사용자 확인 후 `# VENDOR-EDIT(bug): WST-040-polarity` 처리.

### 회귀테스트 핀
- **입력**: `.asa` true 포함 → **기대 result='Y'(취약)** (코드 현행 동작)
- **입력**: `requestFiltering` 없음 → **기대 result='N'(양호)** (코드 현행 동작)
- xlsx 확인 후 corrected 방향이 확정되면 핀 갱신 필요.

---

## 5. `PRCV-027-036-unreachable`

**id**: `PRCV-027-036-unreachable`  
**위치**: `flus-main/app/common/PrivatecloudConfigLoader/autoAnalysis.py` lines **1678–1804**  
**함수**: OS가상화 판정 분기 (autoAnalysis 메인 루프 내)

### 증상
`PRCV-027`~`PRCV-036`(결번 `PRCV-032` 제외) 9개 항목의 판정 분기가 **`PRCV-026` 블록 안에 잘못 들여쓰기**되어 있어 **도달 불가**하다.

```python
# 현재 버그 코드 (autoAnalysis.py:1649~1678~)
elif "PRCV-026" in vulKey:          # line 1649
    if "esxi" in sApp:              # line 1650
        ...                         # PRCV-026 logic (lines 1651-1676)

        elif "PRCV-027" in vulKey:  # line 1678 ← 들여쓰기 오류!
            if "esxi" in sApp:      # PRCV-026의 if-esxi 블록 안의 elif
                ...
        elif "PRCV-028" in vulKey:  # line 1691
            ...
        # ... PRCV-029~036 동일 패턴
```

`elif "PRCV-027" in vulKey`는 `elif "PRCV-026" in vulKey` 블록 내부의 `if "esxi" in sApp:` 절의 `elif`로 처리되어, `vulKey`에 `PRCV-026`이 있을 때만 도달 가능하다. 실제로는 `PRCV-027`이 `vulKey`인 경우 `elif "PRCV-026"` 블록 자체에 진입하지 않으므로 **영구 미발동**.

영향: xlsx 실존 9개 항목(PRCV-027~031, PRCV-033~036)이 항상 기본값 `result='N'`(양호) 반환 — **거짓 양호**.

### Corrected 동작 명세
수정: `PRCV-027`~`PRCV-036` 분기를 `PRCV-026` 블록 **바깥**으로 들여쓰기 교정.  
수정 후: 각 항목이 독립적으로 진입 가능, esxi 조건 하에서 결정론 판정 동작.

```python
# 수정 후 구조 (VENDOR-EDIT(bug): PRCV-027-036-unreachable)
elif "PRCV-026" in vulKey:          # 독립 elif
    if "esxi" in sApp:
        ...                         # PRCV-026 로직

elif "PRCV-027" in vulKey:          # ← 들여쓰기 교정: 동위 elif
    if "esxi" in sApp:
        ...
elif "PRCV-028" in vulKey:          # ← 동위 elif
    ...
# ... PRCV-029~036 동일
```

### 회귀테스트 핀
- `vulKey="PRCV-027"`, `sApp="esxi"`, 취약 입력 → **기대: result='Y'(취약)** (현재는 'N' = 거짓 양호)
- `vulKey="PRCV-026"`, `sApp="esxi"` → 기존 PRCV-026 로직 불변 확인
- 9개 항목(027~031, 033~036) 각각 취약/양호 입력 단언 필요.

---

## 6. `SRV-073-no-group-data`

**id**: `SRV-073-no-group-data`
**위치**: `judge_tool/vendor/common/server/SRV_auto_parse.py` 함수 `check_SRV_073`
**함수**: `check_SRV_073(output)` — 관리자 그룹 멤버 점검

### 증상
`/etc/group` 수집 결과가 없는 경우 — 권한거부(`cat: /etc/group: Permission denied`),
빈 cat 결과(`$ cat /etc/group\n`), 무관 텍스트 등 — `commands` 리스트에서 파싱 가능한
그룹 라인이 0건이어도 `man_inspect=False`로 떨어져 **`result='N'`(양호)**를 반환한다.

어댑터의 증거부재 가드(`_has_collection_evidence`)는 `$ cat /etc/group` 프롬프트 라인을
"증거"로 인식하여 통과시키므로 **거짓 양호 0.9**가 최종 판정으로 나온다.

재현:
```python
judge('SRV-073', '$ cat /etc/group\ncat: /etc/group: Permission denied\n', 'linux', {})
# → verdict='양호', handled=True  (버그)
```

### Corrected 동작 명세
수정: `check_SRV_073` 내부에서 `commands`가 비었거나 파싱된 그룹 라인이 0건이면
`result='N'` 양호로 반환하지 않고 `(*) 수동 판단 필요: /etc/group 수집 결과 없음...`을 반환.
어댑터 Low-1 가드(`(*) and result!='Y'` → handled=False)가 잡아 LLM 폴백으로 라우팅.

수정 후 동작:
- `/etc/group` 데이터 있음 → 결정론 판정 유지 (기존 동작 불변)
- `/etc/group` 데이터 없음(권한거부/빈/무관) → `(*) 수동` → handled=False → LLM 폴백

### 회귀테스트 핀
- `'$ cat /etc/group\ncat: /etc/group: Permission denied\n'` → handled=False, verdict≠양호
- `'$ cat /etc/group\n'` (빈 결과) → handled=False, verdict≠양호
- `'$ cat /etc/group\nunrelated text\n'` → handled=False, verdict≠양호
- `'$ cat /etc/group\nroot:x:0:\n'` (유효 데이터) → handled=True, verdict=양호 (회귀 불변)

---

## 5. `NET-051-typo`

**id**: `NET-051-typo`  
**위치(v202101R1)**: `flus-main/app/common/NetworkConfigAnalysis/v202101R1/NetworkConfig.py` line **2592**  
**위치(v202001R1)**: `flus-main/app/common/NetworkConfigAnalysis/v202001R1/NetworkConfig.py` line **3106**  
**함수**: `NET051(...)` — Cisco tcp keepalives 설정 점검

### 증상
`line 2592`에서 검색 문자열에 오타가 있다:

```python
# 현재 버그 코드 (NetworkConfig.py:2592)
if "service tcp-kepalives-in" in line:   # ← "keepalives" → "kepalives" (e 누락)
```

실제 Cisco IOS 설정 문자열은 `"service tcp-keepalives-in"`. 오타로 인해 검색 조건이 **영구 미발동** → 취약 판정 분기 미진입 → 항상 기본 결과(양호) 반환. 사실상 `STUB`과 동일.

### Corrected 동작 명세
수정: `"tcp-kepalives-in"` → `"tcp-keepalives-in"` (e 추가).  
수정 후: Cisco IOS에서 `service tcp-keepalives-in`이 없거나 `no`인 경우 `result="Y"` (취약) 판정.

```python
# 수정 후 (VENDOR-EDIT(bug): NET-051-typo)
if "service tcp-keepalives-in" in line:   # ← 오타 수정
```

> 두 버전(v202001R1, v202101R1) 모두 동일 오타 존재. 벤더링 시 채용 버전을 PROVENANCE.md에 명기하고 양쪽 모두 수정 또는 채용 버전만 수정.

### 회귀테스트 핀
- **입력**: `"service tcp-keepalives-in"` 포함 Cisco raw → **기대: result='N'(양호)**
- **입력**: `"no service tcp-keepalives-in"` 포함 → **기대: result='Y'(취약)**
- 오타 문자열(`tcp-kepalives-in`) 검색은 위 두 입력 어디서도 매치하지 않음을 단언.

---

## R3. `dbm-process-data-exc-swallow`

**id**: `dbm-process-data-exc-swallow`  
**위치**: `judge_tool/vendor/common/db/{mysql,oracle,mssql,mariadb,postgresql}/analysis.py` — `dbm_process_data` 메서드 및 일부 개별 메서드  
**엔진별 print 포맷**:
- mysql/mssql: `f"[!] Exception Occurred MySQL {result_key}: {str(e)}"`  
- oracle(generic): `f"[!] Exception Occurred Oracle {result_key}: {str(e)}"`  
- oracle(DBM-001): `"[!] Exception Occurred oracle DBM-001: " + str(e)` (소문자, 하드코딩)  
- oracle(DBM-022): `"[!] Exception Occurred Oracle DBM-022: " + str(e)` (하드코딩)  
- mariadb: `f"[!] Exception Occurred MariaDB {result_key}: {str(e)}"`  
- postgresql: `f"[!] Exception Occurred PostgreSQL {result_key}: {str(e)}"` 및 `"[!] Exception Occurred PostgreSQL DBM-022: " + str(e)` (하드코딩)

### 증상
`dbm_process_data`(및 일부 전용 메서드)의 `try/except` 블록이 예외(KeyError, ValueError, strptime 등)를 `print("[!] Exception Occurred ...")` 만 하고 삼킨다. `dbm_result[result_key]` 리스트는 빈 채로 남는다.

어댑터(`db.py`)는 `.run` 반환 dict의 빈 result_key 값을 **위반 없음 → 양호(conf 0.9)**로 매핑하므로, `data_key`가 존재해 D3 증거가드도 통과한 상태에서 **구조적 거짓양호**가 발생한다.

재현(수정 전):
```python
data = {"DBM-007": {"RESULT": [{"SOME_OTHER_KEY":"x","X":"LOW"}]}}
judge("DBM-007", json.dumps(data), "mysql_native", {})
# → verdict='양호' handled=True conf=0.9  ← 거짓양호 (KeyError('VARIABLE_NAME') 삼킴)
```

### 어댑터 수정 (벤더 비트동일 유지)
`judge_tool/det_adapters/db.py` `_run_analysis()` 에서 `contextlib.redirect_stdout`으로 `.run` 실행 중 stdout을 캡처한다. 캡처 텍스트에서 `DBM-NNN` 패턴을 정규식으로 추출해 `exc_keys: frozenset`를 구성하고, `(dbm_result, exc_keys)` 튜플로 `_RUN_CACHE`에 저장한다.

result 매핑 직전에 **`len(violations)==0 and base in exc_keys`** 이면 `handled=False`(rationale: `"[결정론 내부 예외 — 양호 판정 불가, LLM 폴백]"`)를 반환한다. `__AMBIGUOUS__` sentinel: DBM 패턴 파싱 불가 시 보수적 차단.

**과차단 방지**: `violations >= 1`이면 exc_keys 무관하게 취약 판정 유지 (다른 sub-call이 정상 위반 탐지한 경우).

### Corrected 동작 명세
- `len(violations)==0 and (base in exc_keys or '__AMBIGUOUS__' in exc_keys)` → `handled=False`, `conf=0.0`, `ev_status='review'`
- `len(violations) >= 1` → 취약 판정 유지 (exc_keys 무관)
- `exc_keys` 비어있고 `violations==0` → 양호 판정 불변 (R3 무간섭)

### 회귀테스트 핀 (tests/test_det_adapters_db.py::TestR3FalsePositiveBlock)
- `{"DBM-007": {"RESULT": [{"SOME_OTHER_KEY": "x"}]}}` → `handled=False`, `verdict != "양호"` (거짓양호 차단)
- 실위반 있는 항목(예: DBM-004 SUPER 권한) → `verdict='취약'` 유지 (과차단 없음)
- 정상 빈 RESULT(`{"DBM-003": {"RESULT": []}}`) → `verdict='양호'` 불변
- `_parse_exc_keys`: MySQL/Oracle/MariaDB/PostgreSQL/oracle소문자 5포맷 키 추출 단언
- `_parse_exc_keys`: 예외 없는 stdout → `frozenset()`, DBM 미포함 예외 → `__AMBIGUOUS__` sentinel

---

## R-PG009. pg dbm_009 idle_in_transaction_session_timeout 극성 버그 (Batch1, VENDOR-EDIT(bug))

**파일**: `judge_tool/vendor/common/db/postgresql/analysis.py` `dbm_009`

**증상**: 원본은 `int(value) <= 900` 이면 취약으로 판정 — 극성이 거꾸로다. timeout=300(5분 종료=양호)도 `300<=900`이라 취약으로 오판(거짓취약). timeout=0(비활성=진짜 취약)은 우연히 잡히나 양호 케이스를 전부 취약으로 본다.

**판단기준(xlsx)**: 일정시간(미명시 시 15분=900초) 미사용 세션 자동종료 → 양호 / 미설정 → 취약.

**수정(VENDOR-EDIT(bug))**: `int(value) == 0 (비활성) 또는 int(value) > 900 (너무 김)` → 취약. 정상 범위(0 < value <= 900)는 양호.

**한계**: pg `idle_in_transaction_session_timeout`은 트랜잭션 유휴만 커버. 일반 유휴세션 타임아웃은 PG14+ `idle_session_timeout` 별도(미수집 시 needs_review). DBM-009 pg는 needs_review로 사람 재확인.

**회귀 핀**: value=0→취약, value=300→양호, value=900→양호, value=1000→취약.

---

## R-PG011. pg dbm_011 옛 한글포맷 → 신규 포맷 미대응 + 빈 pgaudit_settings 거짓음성 (VENDOR-EDIT)

**id**: `R-PG011`
**위치**: `judge_tool/vendor/common/db/postgresql/analysis.py` `dbm_011`
**상태**: VENDOR-EDIT 완료 (2026-06-17, 2차 보강 포함)

### 증상 (1차: 포맷-lag)
pg 수집 스크립트는 초기(옛) 포맷에서 pgaudit 상태를 한글 문자열(예: `"로드됨"`, `"미설치"`) 또는 bare 텍스트로 출력했다. 신규 수집 포맷은 `{"pgaudit_status": "Loaded", "pgaudit_settings": [...]}` 구조체로 변경되었으나, `dbm_011` 메서드는 신규 구조를 인식하지 못한다.

결과: 신규 포맷 데이터가 들어오면 `dbm_011`이 위반0으로 반환 → `_DETECT_VULN_ELSE_HOLD` 모드에서 판단보류(양호 자동판정 없음)로 처리 — 즉시 거짓양호는 없으나, 활성 pgaudit 설치가 확인됐음에도 위반0=취약 경로를 타지 않아 rationale 문구가 엔진 내부 기본값("로드됨")으로 빠질 수 있다.

### 증상 (2차: 빈 pgaudit_settings 거짓음성, 2026-06-17 Codex 발견)
신규 포맷 대응 후에도 추가 거짓음성이 잔존했다:

- **Case A** (`pgaudit_status` 필드): `pgaudit_status == 'Loaded'`이면 `pgaudit_settings` 여부에 상관없이 위반0으로 처리.  
  → `{"pgaudit_status": "Loaded", "pgaudit_settings": []}` 입력 시 취약 탐지 못함(거짓음성).
- **Case B** (`shared_preload_libraries` value 필드): `'pgaudit' in value AND pgaudit_settings=[]` 조합을 위반으로 처리하지 않음.  
  → `{"value": "pgaudit", "pgaudit_settings": []}` 입력 시 취약 탐지 못함(거짓음성).

실제 의미: pgaudit 확장은 로드됐으나 `pgaudit.log` 등 감사 클래스가 미설정 = 실질적으로 감사 미수행 = **취약(미수집)**.  
기존 로직은 이를 "수집됨(로드됨)" 상태로 오인해 판단보류로 빠뜨렸다.

재현(수정 전):
```python
# Case A
data = {"DBM-011": {"RESULT": [{"pgaudit_status": "Loaded", "pgaudit_settings": []}]}}
# → dbm_011 위반0 → 어댑터 판단보류  (버그: 취약이어야 함)

# Case B
data = {"DBM-011": {"RESULT": [{"setting_name": "shared_preload_libraries",
                                 "value": "pgaudit", "pgaudit_settings": []}]}}
# → dbm_011 위반0 → 어댑터 판단보류  (버그: 취약이어야 함)
```

### Corrected 동작 (VENDOR-EDIT, 2차 보강 포함)
`dbm_011` 내부 수정 — 빈 `pgaudit_settings`는 단독으로 위반:

- **Case A**: `pgaudit_status == 'Loaded'` + `pgaudit_settings == []` → **위반 추가** (`violation_reason: "pgaudit 로드됨 but 감사 클래스 미설정(pgaudit_settings 비어있음)"`)
- **Case A-OK**: `pgaudit_status == 'Loaded'` + `pgaudit_settings` 비어있지 않음 → 위반0(판단보류 경로, 과탐 아님)
- **Case B**: `'pgaudit' in value` + `pgaudit_settings == []` → **위반 추가** (동일 `violation_reason`)
- **Case B-OK**: `'pgaudit' in value` + `pgaudit_settings` 비어있지 않음 → 위반0(판단보류 경로)
- **Case B-미로드**: `'pgaudit' not in value` → 기존 "Not Loaded" 위반 경로 유지(settings 무관)
- 옛 한글 문자열 하위호환 불변.

### 회귀테스트 핀 (tests/test_det_adapters_db.py::TestDBM011DetectVulnElseHold)
- `{"pgaudit_status":"Loaded","pgaudit_settings":["log"]}` → 위반0 → 어댑터 판단보류 (회귀 불변)
- `{"pgaudit_status":"Not Loaded"}` → 위반≥1 → 어댑터 취약 (회귀 불변)
- **신규** `{"pgaudit_status":"Loaded","pgaudit_settings":[]}` → **위반≥1** → 어댑터 **취약** (§R-PG011 2차 보강)
- **신규** `{"setting_name":"shared_preload_libraries","value":"pgaudit","pgaudit_settings":[]}` → **위반≥1** → 어댑터 **취약**
- **신규** `{"value":"pgaudit,pg_stat_statements","pgaudit_settings":[{"pgaudit.log":"ddl,write,role"}]}` → 위반0 → 판단보류 (과탐 없음)
- 옛 bare 텍스트 포맷 — `"로드된 라이브러리가 없습니다."` — 기존 동작 불변

---

## R-MY013. mysql dbm_013 복합 수정 (VENDOR-EDIT(b)+(c))

**id**: `R-MY013`
**위치**: `judge_tool/vendor/common/db/mysql/analysis.py` `dbm_013` +
         `judge_tool/vendor/common/db/config/mysql-config.json` `exception.DBM-013.USER`
**상태**: VENDOR-EDIT(c) 완료 (2026-06-17) + VENDOR-EDIT(b) 추가 완료 (2026-06-17)

### 증상-1 (Critical: root@% 거짓양호 — VENDOR-EDIT(b))
`mysql-config.json` `exception.DBM-013.USER`에 `["root", "mysql.infoschema", "mysql.session", "mysql.sys"]`가 포함되어 있었다 — DBM-003(불필요계정) 리스트를 그대로 복붙한 것.

DBM-013(원격접근통제) 검사 조건 `datum['USER'] not in exception['USER']`에서 root가 예외 처리되어 `root@%` 입력 시 위반0 → verdict=양호 0.9 = **거짓양호(Critical)**.

재현(수정 전):
```python
# mysql-config.json DBM-013 exception USER = ["root", ...]
rows = [{"USER": "root", "HOST": "%"}]
# root in exception → 조건 탈락 → 위반0 → 거짓양호
```

수정(VENDOR-EDIT(b)): `exception.DBM-013.USER = []` (빈 배열).  
근거: 원격접근통제 항목에선 어떤 계정도 와일드카드-Host 검사에서 면제하면 안 됨.  
시스템계정은 보통 `@localhost`(와일드카드 없음)라 exception 비워도 영향 없음.

### 증상-2 (거짓양호 갭: 부분 와일드카드 미탐 — VENDOR-EDIT(c))
기존 코드는 `datum['HOST'] in self.rules['DBM-013']['HOST']` — 즉 `rules['HOST'] == ['%']` 와 정확매칭하여 HOST가 정확히 `'%'`인 경우만 취약으로 잡는다.

`'10.%'`(서브넷 와일드카드), `'%.domain.com'`(도메인 와일드카드), `'10.0.0._'`(`_` 단일문자 와일드카드) 등 부분 와일드카드가 포함된 HOST는 정확매칭에서 탈락하여 양호로 오판 — **거짓양호 갭**.

재현(수정 전):
```python
datum = {"USER": "app_user", "HOST": "10.%"}
# datum['HOST'] in ['%'] → False → 위반 미포함 → 거짓양호
datum = {"USER": "app_user", "HOST": "10.0.0._"}
# '_' 와일드카드 → '%' in HOST → False → 위반 미포함 → 거짓양호
```

### 증상-3 (High: _ 단일문자 와일드카드 미탐 — VENDOR-EDIT(b))
VENDOR-EDIT(c) 이후에도 `'%' in datum['HOST']` 검사만으로는 MySQL `_`(임의 1문자) 와일드카드 미탐.
`'10.0.0._'`, `'host_db'` 등 `_`만 포함된 HOST가 광역 원격허용임에도 양호로 오판.

### Corrected 동작 (VENDOR-EDIT(b)+(c) 통합)
수정-1: `mysql-config.json` `exception.DBM-013.USER = []`  
수정-2: 와일드카드 매칭 `'%' in HOST` → `'%' in HOST or '_' in HOST`

수정 후:
- `HOST = '%'` (전체 와일드카드) → 취약 ✓
- `HOST = '10.%'` (서브넷 와일드카드) → 취약 ✓
- `HOST = '%.domain.com'` (도메인 와일드카드) → 취약 ✓
- `HOST = '10.0.0._'` (`_` 단일문자 와일드카드) → 취약 ✓
- `HOST = 'localhost'` → 양호 ✓ (과탐 아님)
- `HOST = '192.168.1.100'` (특정IP) → 양호 ✓ (과탐 아님)
- `HOST = 'root@localhost'` → 양호 ✓ (와일드카드 없음)
- `USER = 'root', HOST = '%'` → **취약** ✓ (Critical-1 거짓양호 차단)

### 회귀테스트 핀
- `{"USER": "app_user", "HOST": "%"}` → 위반 포함 → 취약
- `{"USER": "app_user", "HOST": "10.%"}` → 위반 포함 → 취약
- `{"USER": "app_user", "HOST": "%.dom"}` → 위반 포함 → 취약
- `{"USER": "app_user", "HOST": "10.0.0._"}` → 위반 포함 → 취약 (High-2)
- `{"USER": "app_user", "HOST": "host_db"}` → 위반 포함 → 취약 (High-2)
- `{"USER": "root", "HOST": "%"}` → 위반 포함 → **취약** (Critical-1)
- `{"USER": "root", "HOST": "localhost"}` → 위반 미포함 → 양호
- `{"USER": "appuser", "HOST": "%"}` → 위반 포함 → 취약 (비root 와일드카드)
- `{"USER": "app_user", "HOST": "localhost"}` → 위반 미포함 → 양호
- `{"USER": "app_user", "HOST": "192.168.1.1"}` → 위반 미포함 → 양호

---

## R-MA013. mariadb dbm_013 복합 수정 (VENDOR-EDIT(b)+(c))

**id**: `R-MA013`
**위치**: `judge_tool/vendor/common/db/mariadb/analysis.py` `dbm_013` +
         `judge_tool/vendor/common/db/config/mariadb-config.json` `exception.DBM-013.USER`
**상태**: VENDOR-EDIT(c) 완료 (2026-06-17) + VENDOR-EDIT(b) 추가 완료 (2026-06-17)

### 증상
R-MY013과 동일.
- `mariadb-config.json` `exception.DBM-013.USER`에 `["root", "mariadb.sys", "healthcheck"]` 포함 → `root@%` 거짓양호(Critical).
- `'%' in HOST`만으로는 `_` 와일드카드 미탐(High).

### Corrected 동작 (VENDOR-EDIT(b)+(c) 통합)
R-MY013과 동일.
- `mariadb-config.json` `exception.DBM-013.USER = []`
- 와일드카드 매칭: `'%' in HOST or '_' in HOST`

### 회귀테스트 핀
R-MY013과 동일 (mariadb engine 대상).

---

## R-MA019. mariadb dbm_019 polarity 역전 — INTERVAL 임계값 오판 (VENDOR-EDIT(c) 완료)

**id**: `R-MA019`
**위치**: `judge_tool/vendor/common/db/mariadb/analysis.py` `dbm_019` +
         `judge_tool/vendor/common/db/config/mariadb-config.json` `rules.DBM-019`
**상태**: VENDOR-EDIT(c) 완료 (2026-06-17)

### 증상
기존 코드: `PASSWORD_REUSE_CHECK_INTERVAL > DAY[0](30) or INTERVAL == 0` → 취약.
60일처럼 강한 재사용방지 설정(INTERVAL=60)도 `60 > 30`이라 취약으로 오판 — 거짓취약(Critical).

xlsx 판단기준(제2026-1호) = **"이전 비밀번호 재사용 방지 설정 여부"(이진)**: 설정됨(켜짐)→양호 / 미설정(꺼짐)→취약.
INTERVAL 일(day) 값의 크기로 판단하는 것이 아니라 켜짐/꺼짐만 본다.

```python
# 버그 코드 (수정 전)
lambda datum: int(datum['VARIABLE_VALUE']) > int(self.rules[result_key]['DAY'][0]) or int(datum['VARIABLE_VALUE']) == 0
# → INTERVAL=60 → 60 > 30 → True → 취약 (거짓취약!)
```

### Corrected 동작 (VENDOR-EDIT(c))
- `str` 분기 `"not loaded"` 포함 → 취약 (플러그인 미설치=꺼짐)
- `INTERVAL == 0` → 취약 (무제한=꺼짐)
- `INTERVAL > 0` → 양호 (며칠이든 재사용방지 켜짐)

```python
# 수정 후 (VENDOR-EDIT(c): R-MA019)
self.dbm_process_data(result_key, 'DBM-019', [
    lambda datum: type(datum) == str,
    lambda datum: "not loaded" in datum
])
self.dbm_process_data(result_key, 'DBM-019', [
    lambda datum: type(datum) == dict,
    lambda datum: datum['VARIABLE_NAME'] == "PASSWORD_REUSE_CHECK_INTERVAL",
    lambda datum: int(datum['VARIABLE_VALUE']) == 0   # ← DAY[0] 임계값 비교 제거
])
```

config `rules.DBM-019.DAY` 미사용 → `Note`로 교체: `"미사용: 설정여부 이진 판정(INTERVAL>0=양호, 0/not-loaded=취약). DAY 임계값 개념 없음(R-MA019)."`.

### 회귀테스트 핀 (tests/test_det_adapters_db.py::TestDBM019PasswordReuse)
- `INTERVAL=60` → **양호** (핵심: 수정 전 거짓취약 케이스)
- `INTERVAL=1` → 양호
- `INTERVAL=30` → 양호 (기존 테스트 불변)
- `INTERVAL=0` → 취약
- `"not loaded"` 포함 str → 취약
- 실데이터(mariadb_native): 플러그인 미로드 → **취약 불변**

---

## R-MS011. mssql dbm_011 빈 RESULT(0 audit행) → 활성 감사 행 판단 (VENDOR-EDIT)

**id**: `R-MS011`
**위치**: `judge_tool/vendor/common/db/mssql/analysis.py` `dbm_011` (또는 동등 메서드)
**상태**: VENDOR-EDIT 필요

### 증상
mssql DBM-011 활성 감사 점검에서 수집 스크립트가 `sys.server_audits`/`sys.server_audit_specifications` 쿼리를 실행하나, 감사정책이 없거나 비활성인 경우 RESULT 행이 0건으로 비어 있다.

현재 `dbm_011` 메서드는 빈 RESULT를 위반0(양호)로 취급한다. 그러나 RESULT=0은 "활성 감사 없음 = 취약"이어야 한다. `_DETECT_VULN_ELSE_HOLD` 모드에서 어댑터가 위반0을 받으면 판단보류로 처리하는 안전망이 있으나, 그 전에 벤더 로직이 잘못된 방향으로 판정을 내리면 거짓양호 위험이 있다.

현재 어댑터 계층 보호(`_DETECT_VULN_ELSE_HOLD`): 위반0이어도 자동 양호 판정을 하지 않고 판단보류를 강제한다. 따라서 현재는 즉각적인 거짓양호는 없지만 올바른 취약 판정을 내리지 못하는 상태.

RESULT=0행(활성 감사 없음)은 `dbm_011`이 위반1건 이상(취약 경로)을 반환해야 한다. 어댑터(`_DETECT_VULN_ELSE_HOLD`)가 취약 탐지 → 취약 확정 경로를 탈 수 있도록 벤더 로직 수정이 필요.

### Corrected 동작 (VENDOR-EDIT)
- `sys.server_audits` 결과가 비어있음(0행) → `dbm_011` 위반1건 반환(취약 신호)
- `sys.server_audits` 결과에 활성 감사 행이 있음 → 위반0(수집됨) 반환
- 어댑터(`_DETECT_VULN_ELSE_HOLD`): 위반≥1 → 취약 확정, 위반0 → 판단보류

### 회귀테스트 핀
- `{"DBM-011": {"RESULT": []}}` → `dbm_011` 위반≥1 → 어댑터 취약 판정
- `{"DBM-011": {"RESULT": [{"audit_name":"FSI_Audit","audit_action":"..."}]}}` → `dbm_011` 위반0 → 어댑터 판단보류
- raw-carrier 더미 리소스를 통한 `_raw_evidence_for_det` 동작 불변 확인

---

## R-026. DBM-026 umask 판정 로직 오류 — 10진 파싱 + 잘못된 휴리스틱 거짓양호 (VENDOR-EDIT(c) 완료)

**id**: `R-026`
**위치**: `judge_tool/vendor/common/db/{mysql,oracle,mariadb,postgresql,tibero}/analysis.py` `dbm_026`
         `judge_tool/det_adapters/db.py` 모드F 가드 (_UMASK_GUARD)
**상태**: VENDOR-EDIT(c) 완료 (2026-06-18)

### 증상 (Critical 거짓양호)
기존 코드:
```python
lambda datum: any(sub in str(int(datum['output'])%100) for sub in ["3", "4", "5"])
```

이중 버그:
1. **10진 파싱**: `int(datum['output'])` — umask는 8진수인데 10진으로 파싱. `"022"` → `int("022")=22`, `"020"` → `int("020")=20`.
2. **잘못된 휴리스틱**: `%100` 결과에 문자 "3"/"4"/"5" 포함 여부 — xlsx "022 이상" 기준이 전혀 아님.

결과: umask **020/002/000/070/007**(모두 < 022, 취약이어야 함)이 **양호로 빠짐(거짓양호 Critical)**.
- 000(가장 위험한 umask)조차 양호로 판정. 

재현(수정 전):
```python
# umask 020 → int("020")=20 → 20%100=20 → str="20" → "3"/"4"/"5" 미포함 → 위반 아님 → 양호(거짓양호!)
# umask 000 → 0%100=0 → "0" → "3"/"4"/"5" 미포함 → 양호(최악)
```

### Corrected 동작 (VENDOR-EDIT(c))
벤더 5엔진(mysql/oracle/mariadb/postgresql/tibero) 모두에 `_umask_is_violation(output)` 헬퍼 추가:
- 8진수 토큰 추출 (마지막 3자리 = owner/group/other)
- **group 자리 ≥ 2 AND other 자리 ≥ 2 → 양호(위반 아님, False)**
- 아니면 취약(위반, True)
- 파싱 불가(8진 토큰 없음) → None — 어댑터 모드F가 판단보류로 처리

어댑터 모드F 가드(`_UMASK_GUARD`, `_dbm026_has_umask_token`):
- RESULT 0행(빈배열) → 판단보류(umask 미수집)
- RESULT 행 있으나 8진 토큰 없음 → 판단보류(umask 미파싱/command not found 등)

수정 후 판정:
- umask **022** → group=2, other=2 → **양호** ✓
- umask **027/077** → **양호** ✓
- umask **020** → other=0 < 2 → **취약** ✓ (수정 전 거짓양호)
- umask **002** → group=0 < 2 → **취약** ✓ (수정 전 거짓양호)
- umask **000** → group=0, other=0 → **취약** ✓ (수정 전 최악 거짓양호)
- umask **070/007** → **취약** ✓
- "umask: command not found" → **판단보류** ✓
- RESULT 빈배열 → **판단보류** ✓

### 회귀테스트 핀 (tests/test_det_adapters_db.py::TestDBM026*)
- `TestDBM026UmaskHelperUnit`: 헬퍼 단위테스트 (양호/취약/파싱불가, 5엔진 횡단)
- `TestDBM026UmaskGuardUnit`: `_dbm026_has_umask_token` 및 `_UMASK_GUARD` 검증
- `TestDBM026FalsePositiveBugFix.test_mysql_020_is_vuln` → **취약** (CRITICAL 핵심)
- `TestDBM026FalsePositiveBugFix.test_mysql_000_is_vuln` → **취약** (최악 케이스)
- `TestDBM026FalsePositiveBugFix.test_mysql_022_is_good` → **양호** (회귀 없음)
- `TestDBM026FalsePositiveBugFix.test_mysql_empty_result_is_hold` → **판단보류**
- `TestDBM026FalsePositiveBugFix.test_mysql_command_not_found_is_hold` → **판단보류**
- 전 엔진(oracle/mariadb/pg) 020→취약, 022→양호, 빈배열→판단보류

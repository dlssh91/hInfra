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

## R-MY013-CLOUD / R-MA013-CLOUD. mysql/mariadb cloud_analysis dbm_013 와일드카드 parity 누락 (VENDOR-EDIT, 2026-07-10, §F5)

**id**: `R-MY013-CLOUD`(mysql), `R-MA013-CLOUD`(mariadb)
**위치**: `judge_tool/vendor/common/db/mysql/cloud_analysis.py` `dbm_013` +
         `judge_tool/vendor/common/db/mariadb/cloud_analysis.py` `dbm_013`
**상태**: VENDOR-EDIT 완료 (2026-07-10)

### 증상 (cloud capability parity 누락 — 거짓양호)
R-MY013/R-MA013은 **native**(`mysql/analysis.py`, `mariadb/analysis.py`)의 `dbm_013`만
`'%' in HOST or '_' in HOST` 포함매칭으로 수정했다. rds/aurora/azure variant가 사용하는
**cloud_analysis.py**의 `dbm_013`은 수정 전 그대로 `datum['HOST'] in self.rules['DBM-013']['HOST']`
(= `['%']`)로 **정확일치만** 검사했다 — `'10.%'`(서브넷 와일드카드), `'%.corp.com'`(도메인
부분 와일드카드), `'10.0.0._'`(`_` 단일문자 와일드카드) 같은 광역 원격허용 Host가 정확일치에서
탈락하여 rds/aurora/azure에서 **양호로 오판(거짓양호)**.

재현(수정 전):
```python
datum = {"USER": "app_user", "HOST": "10.%"}
# datum['HOST'] in ['%'] → False → 위반 미포함 → 거짓양호(cloud만 발생, native는 이미 수정됨)
```

### Corrected 동작 (VENDOR-EDIT)
mysql/mariadb cloud_analysis 모두 native와 동일하게 변경:
`datum['HOST'] in self.rules['DBM-013']['HOST']` → `'%' in datum['HOST'] or '_' in datum['HOST']`.
`exception.DBM-013.USER`는 mysql-config.json/mariadb-config.json 양쪽 다 이미 `[]`(빈 배열)이라
네이티브의 VENDOR-EDIT(b)(root 등 예외 제거)가 cloud에도 그대로 적용된다 — 별도 config 수정 불필요.

수정 후:
- `HOST = '%'` → 취약 ✓ (기존에도 잡던 케이스, 회귀 확인)
- `HOST = '10.%'` → 취약 ✓ (F5 거짓양호 차단)
- `HOST = '%.corp.com'` → 취약 ✓ (F5 거짓양호 차단)
- `HOST = '10.0.0._'` → 취약 ✓ (F5 거짓양호 차단)
- `HOST = '192.168.1.100'` (구체 지정) → 양호 ✓ (과탐 아님, 회귀 유지)
- `USER = 'root', HOST = '%'` → **취약** ✓ (설계서 §F5 명시 — 관리계정도 취약 검토 대상에
  포함하는 것은 과탐이 아니라 안전방향 계약. 오탐이 아님을 테스트로 고정)

### 모드J(0행 가드)
`judge_tool/det_adapters/db.py` `_MODE_J_ITEMS["DBM-013"] = None`(T2에서 이미 등록) —
RESULT 0행(수집실패) → 판단보류. 엔진별 "기대 변수 존재" checker는 두지 않는다(HOST 컬럼은
행이 수집되면 항상 존재하므로 0행-only 가드로 충분).

### 회귀테스트 핀
`tests/test_det_adapters_db.py::TestDBM013CloudHostWildcard`
- mysql/mariadb cloud_analysis 단위: `HOST='%'/'10.%'/'%.corp.com'/'10.0.0._'` → 위반 포함(취약),
  `HOST='192.168.1.100'` → 위반 미포함(양호)
- `root@%`(cloud) → 위반 포함(취약) — 안전방향 계약 고정
- `judge("DBM-013", ..., "mysql_rds"/"mariadb_rds", {})`: `HOST='10.%'` → handled 시 취약,
  구체 Host만 → handled 시 양호, RESULT 0행 → 판단보류(모드J)
- native mysql/mariadb DBM-013 기존 테스트(`TestDBM013HostWildcard`) 회귀 무변

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


## R-022L — DBM-022 심볼릭 링크 거짓취약 (2026-06-19)
- 증상: `get_check_file_perm`이 디렉터리(`d`)만 제외, 심링크(`l`)는 검사 → `lrwxrwxrwx`(항상 777)가 owner 'x'로 항상 취약 오플래그. mariadb my.cnf 등 심링크 설정파일에서 체계적 거짓취약.
- 수정: `startswith("d")` → `startswith(("d","l"))` (5엔진 mysql/oracle/mariadb/postgresql/tibero).
- 회귀핀: 심링크→양호, 실 644 일반파일→취약 유지 (docker maria_dbm 실증).

## R-032 / R-032b — DBM-032 pg_hba 평문비번 결정론 파서 (2026-06-19)
- R-032: pg dbm_032 빈 STUB → pg_hba.conf 파서 구현. host/hostnossl + method=password → 취약. hostssl/local/md5/scram 제외. cloud(rds/aurora/azure)는 label C(파라미터 기반, 직접점검 불가).
- R-032b: 인라인 주석(`host ... password # legacy`) 미제거 시 마지막토큰이 주석어가 되어 평문 라인 누락(거짓양호) → `line.split('#',1)[0]` 으로 인라인 주석 선제거. docker pg_dbm032 pg_hba_file_rules 뷰로 ground-truth 검증.


## R-034 / R-034u — DBM-034 DBMS 구동권한(root) 결정론 (2026-06-19)
- R-034: 신규 — ps output에서 DB 데몬(mysqld/mariadbd/postgres/ora_/tnslsnr) 소유자==root → 취약. 수집(unix_*.sh ps -ef) + 벤더 dbm_034 + DET_SOURCE native DET/cloud ABSENT + 모드H 가드(데몬라인0→판단보류).
- R-034u: ps가 소유자를 숫자 UID 0으로 출력(이름 미해석)하면 root 미탐 거짓양호 → owner in (root,0) 비교(4벤더). docker 포맷 검증.
- 백로그(Low): 모드H _DAEMON_KEYWORDS oracle 'oracle'가 경로문자열 과매칭 가능(안전방향, oracle ps 실데이터 확보 시 narrowing).


## R-035 / R-036 / R-036d — DBM-035/036 mssql 결정론 (2026-06-19)
- R-035: 신규 xp_cmdshell — sys.configurations value_in_use==1→취약/0→양호. 모드I 가드(행없음→판단보류).
- R-036: 신규 registry proc — xp_reg*+EXECUTE+비관리자 grantee→취약(public 항상취약). 모드I2 가드.
- R-036d: DENY(public 명시차단=안전)를 취약 오판(거짓취약, Opus docker 재현) → state_desc==DENY 스킵. GRANT만 위반.

---

## BUG-WST102-webtob — ServerTokens "full" 거짓양호 (2026-06-19, VENDOR-EDIT(bug) 완료)

**id**: `BUG-WST102-webtob`
**위치**: `judge_tool/vendor/common/webwas/WST_WebtoB_parse.py` 함수 `check_WST_102`
**분류**: 거짓양호 (vuln→양호) — 최우선

### 증상
기존 조건 `"min" not in tokens_val and tokens_val not in ["os","full","prod"]`에서
`"full"`이 `["os","full","prod"]` 리스트에 포함되어 두 번째 조건이 False → 취약 미탐지 → 거짓양호.

```python
# 버그 코드 (수정 전)
if "min" not in tokens_val and tokens_val not in ["os", "full", "prod"]:
    # → tokens_val="full" → "full" in list → False → 취약 미탐지 (거짓양호!)
```

`ServerTokens="full"`(버전 전체 노출)이 양호로 판정됨.

### Corrected 동작 (VENDOR-EDIT(bug))
판단기준: `os`/`full` → 버전/OS 노출 → **취약**, `prod`/`min` → 최소 노출 → **양호**.

```python
# 수정 후 (VENDOR-EDIT(bug): BUG-WST102-webtob)
if tokens_val in ("os", "full"):
    # 취약 (버전/OS 노출)
elif "min" in tokens_val or tokens_val == "prod":
    # 양호 (prod/min)
else:
    # 알 수 없는 값 → 보수적 취약 처리
```

### 회귀 핀
- `ServerTokens="full"` → **취약** (핵심: 수정 전 거짓양호 케이스)
- `ServerTokens="os"` → **취약**
- `ServerTokens="prod"` → **양호**
- `ServerTokens="min"` → **양호**
- ServerTokens 없음(기본값 Off) → **양호**
- 테스트: `tests/test_web_cov_fixtures.py::test_web_det_polarity[webtob-WST-102-vuln]` PASS (구 xfail→pass)

---

## BUG-WST031-apache — `-Indexes` 거짓취약 (2026-06-19, VENDOR-EDIT(bug) 완료)

**id**: `BUG-WST031-apache`
**위치**: `judge_tool/vendor/common/webwas/WST_Apache_parse.py` 함수 `check_WST_031`
**분류**: 거짓취약 (good→취약)

### 증상
기존 정규식 `Options.*([^-]Indexes|all)`: `[^-]Indexes`는 `-` 이외의 단일 문자 뒤의 `Indexes`에 매치하는데, `Options -Indexes`에서 공백(` `) + `Indexes`가 `[^-]Indexes`에 매치된다. 즉 `-Indexes`(비활성=양호)를 취약으로 오판.

```python
# 버그 코드 (수정 전)
r"<Directory((?!<\/Directory>)[\s\S])*?Options.*([^-]Indexes|all).*?<\/Directory>"
# → "Options -Indexes MultiViews" → ' Indexes' 부분에 [^-]Indexes 매치 → 거짓취약!
```

### Corrected 동작 (VENDOR-EDIT(bug))
음수 룩비하인드로 `-` 직전 Indexes를 제외. `+Indexes` 또는 단독 `Indexes`(비활성 제외)만 취약으로 매치.

```python
# 수정 후 (VENDOR-EDIT(bug): BUG-WST031-apache)
r"<Directory((?!<\/Directory>)[\s\S])*?Options[^\n]*(?:(?<!\-)\bIndexes\b|\ball\b)[^\n]*.*?<\/Directory>"
```

### 회귀 핀
- `Options -Indexes MultiViews` → **양호** (핵심: 수정 전 거짓취약 케이스)
- `Options Indexes MultiViews` → **취약**
- `Options +Indexes MultiViews` → **취약**
- `Options all` → **취약**
- `Options MultiViews` → **양호**
- 테스트: `tests/test_web_cov_fixtures.py::test_web_det_polarity[apache-WST-031-good]` PASS (구 xfail→pass)

---

## BUG-WST031-webtob — `NOINDEX` 서브스트링 거짓취약 (2026-06-19, VENDOR-EDIT(bug) 완료)

**id**: `BUG-WST031-webtob`
**위치**: `judge_tool/vendor/common/webwas/WST_WebtoB_parse.py` 함수 `check_WST_031`
**분류**: 거짓취약 (good→취약)

### 증상
기존 정규식 `Options.*?INDEX`(IGNORECASE)가 `NOINDEX`의 `INDEX` 서브스트링에도 매치된다.
`Options = NOINDEX NOLIST`(양호 설정)가 취약으로 오판됨.

```python
# 버그 코드 (수정 전)
vuln_pattern = re.compile(r"(.*)?Options.*?INDEX.*", re.IGNORECASE)
# → "Options = NOINDEX" → 'NOINDEX'의 'INDEX' 서브스트링 매치 → 거짓취약!
```

### Corrected 동작 (VENDOR-EDIT(bug))
음수 룩비하인드(`(?<!NO)`)와 단어경계(`\b`)로 `NO` 접두 제외.

```python
# 수정 후 (VENDOR-EDIT(bug): BUG-WST031-webtob)
vuln_pattern = re.compile(r"(.*)?Options.*?(?<!NO)\bINDEX\b.*", re.IGNORECASE)
```

### 회귀 핀
- `Options = NOINDEX NOLIST` → **양호** (핵심: 수정 전 거짓취약 케이스)
- `Options = INDEX LIST` → **취약**
- `Options = INDEX` → **취약**
- `Options = NOINDEX` → **양호** (NOINDEX 단독도 양호)
- 테스트: `tests/test_web_cov_fixtures.py::test_web_det_polarity[webtob-WST-031-good]` PASS (구 xfail→pass)


## R-MY008. mysql dbm_008 data_key 불일치 — 'DBM-008_1' 조용히 skip (VENDOR-EDIT(bug) 완료, 2026-07-03)

**id**: `R-MY008`
**위치**: `judge_tool/vendor/common/db/mysql/analysis.py` `dbm_008`
**상태**: VENDOR-EDIT(bug) 완료 (2026-07-03, F1)

### 증상
`dbm_008`은 `dbm_process_data(result_key, 'DBM-008', [...])`만 호출한다. 그런데 실수집
데이터의 data_key가 `'DBM-008'`이 아니라 **`'DBM-008_1'`**로 오는 경우가 있다(수집
스크립트/버전 편차). `dbm_process_data`는 `data_key in self.data`가 False면 조용히
skip하므로 위반0(빈 리스트) 반환 → 어댑터가 위반0=양호로 매핑 → **거짓양호**.

재현(수정 전):
```python
data = {"DBM-008_1": {"RESULT": [
    {"HOST": "%", "USER": "app", "PASSWORD_LAST_CHANGED": "2020-01-01"}  # 5년 전, 실제 취약
]}}
# dbm_008(): 'DBM-008' data_key 없음 → dbm_process_data skip → dbm_result['DBM-008']=[] → 양호(거짓양호!)
```

### Corrected 동작 (VENDOR-EDIT(bug))
기존 `'DBM-008'` 처리는 유지하고, 동일 조건으로 `'DBM-008_1'` data_key도 처리한다.

```python
# 수정 후 (VENDOR-EDIT(bug): R-MY008)
self.dbm_process_data(result_key, 'DBM-008_1', [
    lambda datum: datum['HOST'] not in self.exception[result_key]['HOST'],
    lambda datum: datum['USER'] not in self.exception[result_key]['USER'],
    lambda datum: current_date > datetime.strptime(datum['PASSWORD_LAST_CHANGED'], '%Y-%m-%d') + timedelta(days=int(self.rules[result_key]['DAY'][0]))
])
```

⚠️ mysql collector에 별도의 USER/HOST 컬럼스왑 이슈가 있는 것으로 알려져 있으나, 이번
수정 범위는 **data_key 추가만**이며 컬럼 스왑 정규화는 시도하지 않는다(설계서 §F1 명시
— 별도 트랙에서 다룰 문제).

### 회귀테스트 핀
- `{"DBM-008_1": {"RESULT": [{"HOST":"%","USER":"app","PASSWORD_LAST_CHANGED":"<90일 초과 과거>"}]}}` → **취약** (핵심: 수정 전 거짓양호 케이스)
- `{"DBM-008": {"RESULT": [{"HOST":"%","USER":"app","PASSWORD_LAST_CHANGED":"<최근>"}]}}` → 양호 (회귀 불변, 기존 data_key)
- `{"DBM-008_1": {"RESULT": [{"HOST":"%","USER":"app","PASSWORD_LAST_CHANGED":"<최근>"}]}}` → 양호 (신규 data_key, 최근 변경은 양호)
- 0행/data_key 부재 → 판단보류(모드J, checker=None)

---

## R-OR008. oracle dbm_008 'DBM-008_2'(PASSWORD_LIFE_TIME) 블록 주석처리 — 거짓양호 (VENDOR-EDIT(bug) 완료, 2026-07-03)

**id**: `R-OR008`
**위치**: `judge_tool/vendor/common/db/oracle/analysis.py` `dbm_008`
**상태**: VENDOR-EDIT(bug) 완료 (2026-07-03, F1)

### 증상
`dbm_008`은 `'DBM-008_1'`(ptime 기반) 처리만 활성화돼 있고, `'DBM-008_2'` 처리 블록은
통째로 주석처리(dead code)돼 있었다. 실수집 데이터가 `'DBM-008_2'`
(`profile`/`resource_name`/`limit` 형태, 예: `resource_name=PASSWORD_LIFE_TIME`,
`limit=UNLIMITED` — 실제 취약)로 오면 `dbm_process_data`가 data_key 자체를 찾지 못해
조용히 skip → 위반0 → **거짓양호**(2026-07-03 감사 §F1 실증).

재현(수정 전):
```python
data = {"DBM-008_2": {"RESULT": [
    {"profile": "DEFAULT", "resource_name": "PASSWORD_LIFE_TIME", "limit": "UNLIMITED"}  # 실제 취약(무기한)
]}}
# dbm_008(): 'DBM-008_2' 처리 블록 주석처리 → 조용히 skip → dbm_result['DBM-008']=[] → 양호(거짓양호!)
```

### Corrected 동작 (VENDOR-EDIT(bug))
`'DBM-008_2'` 처리를 복원하되, 기존 주석 코드에 없던 `resource_name` 조건을 추가한다
(원본은 `resource_name` 비교 없이 `profile`/`limit`만 봐서 `PASSWORD_GRACE_TIME` 등
다른 resource_name 행까지 오탐할 위험이 있었다):

```python
# 수정 후 (VENDOR-EDIT(bug): R-OR008)
self.dbm_process_data(result_key, 'DBM-008_2', [
    lambda datum: datum['resource_name'] == 'PASSWORD_LIFE_TIME',
    lambda datum: datum['profile'] not in self.exception[result_key]['profile'],
    lambda datum: datum['limit'] in self.rules[result_key]['limit']
])
```

`self.rules['DBM-008']['limit'] == ['UNLIMITED']`(oracle-config.json), `exception.profile`은
기본 빈 배열이므로 별도 프로파일 예외가 설정되지 않는 한 모든 profile이 대상이 된다.

### 회귀테스트 핀
- `{"DBM-008_2": {"RESULT": [{"profile":"DEFAULT","resource_name":"PASSWORD_LIFE_TIME","limit":"UNLIMITED"}]}}` → **취약** (핵심: 수정 전 거짓양호 케이스)
- `{"DBM-008_2": {"RESULT": [{"profile":"DEFAULT","resource_name":"PASSWORD_GRACE_TIME","limit":"UNLIMITED"}]}}` → 위반 아님(첫 조건 `resource_name` 비교에서 자연 배제, 오탐 방지 고정)
- `{"DBM-008_1": {"RESULT": [...]}}` (ptime 기반) → 기존 동작 불변 (회귀)
- 0행/data_key 부재 → 판단보류(모드J, checker=None)

---

## WST-102-webtob-min (Opus 재리뷰 추가 정정, 2026-06-19)
- 1차 수정이 `"min" in tokens_val → 양호`로 두어 Min/Minimal/Minor(전체버전 Apache/2.4.x 노출)를 거짓양호로 신규 유입.
- 정정: ServerTokens 안전값은 **Prod(ProductOnly)뿐** → `tokens_val == "prod"`만 양호, os/full/min/minimal/minor/major 전부 취약(Apache WST-102 및 함수 자기 메시지와 정합).
- 회귀핀: test_wst102_webtob_min_is_vuln.

## OBS-MY006 / OBS-OR007. 벤더 로직 관찰 사항(수정 없음) — F6/F7 배치 중 발견 (2026-07-11, §F6 falsegood-audit)

본 배치의 실제 수정은 db.py 모드J(DBM-005/006/007 0행 fail-closed 가드) 등록뿐이다.
아래 두 건은 조사 중 발견된 **별도** vendor 로직 결함으로, spec(§F6) 지시에 따라
"관찰만 보고, 벤더 코드 수정은 범위 밖"으로 남긴다.

### OBS-MY006. mysql `dbm_006` USER_ATTRIBUTES `int()` 변환 실패 시 R3가 조용히 흡수(부분 차단)

`judge_tool/vendor/common/db/mysql/analysis.py:138-153`:
```python
self.dbm_process_data(result_key, 'DBM-006', [
    lambda datum: datum['USER_ATTRIBUTES'] == "",
    ...
])
self.dbm_process_data(result_key, 'DBM-006', [
    lambda datum: datum['USER_ATTRIBUTES'] != "",
    ...,
    lambda datum: int(datum['USER_ATTRIBUTES']) > int(self.rules['DBM-006']['USER_ATTRIBUTES'][0])
])
```
실제 MySQL 8의 `User_attributes`는 계정 잠금이 설정된 경우 순수 정수 문자열이 아니라
JSON(`{"Password_locking": {"failed_login_attempts": N, ...}}`)이다. 이 경우 두 번째
`dbm_process_data` 호출의 `int(datum['USER_ATTRIBUTES'])`가 `ValueError`를 던지고,
`dbm_process_data`의 try/except(R3)가 예외를 print만 하고 삼켜 해당 행은 위반으로
집계되지 않는다 — **계정 잠금이 실제로 설정돼 있어도(비어있지 않은 값) 그 값이 순수
정수가 아니면 조용히 통과**하는 부분 차단 상태다. db.py의 R3 exc_keys 메커니즘은 이
예외를 탐지해 `handled=False`로 폴백시키므로 거짓양호(verdict=양호)로 이어지지는
않지만(LLM 경로로 위임됨), 결정론 판정 자체가 무력화된다.
**docker 실증(mysql:8, 2026-07-11)**: 기본 설치에서 `User_attributes`는 전 계정 NULL(빈
값)이라 이 경로 자체가 트리거되지 않음을 확인 — 실제 트리거는 관리자가 계정별
`FAILED_LOGIN_ATTEMPTS`/`PASSWORD_LOCK_TIME`을 명시적으로 설정한 서버에서만 발생.
**수정 여부**: 벤더 코드 미수정(§F6 spec 명시: "벤더버그는 R3가 부분 차단 — 벤더 코드
수정 금지, 관찰 결과만 보고"). db.py 모드J DBM-006 등록과는 독립적인 문제(모드J는
0행/기대필드부재만 다루고, 이 건은 필드가 존재하되 파싱 실패하는 경우).

### OBS-OR007. oracle `dbm_007` exception 설정이 빈 리스트라 값과 무관하게 상시 위반(거짓취약 위험)

`judge_tool/vendor/common/db/config/oracle-config.json`의 `DBM-007` 항목:
```json
"exception": {"username": [], "profile": [], "resource_name": [], "limit": []},
"rules":     {"username": [], "profile": [], "resource_name": [], "limit": []}
```
`judge_tool/vendor/common/db/oracle/analysis.py:223-228`(native)과
`cloud_analysis.py:201-206`(cloud) 동일:
```python
def dbm_007(self, result_key='DBM-007'):
    self.dbm_result[result_key] = []
    self.dbm_process_data(result_key, 'DBM-007_1', [
        lambda datum: datum['limit'] not in self.exception[result_key]['limit'],
        lambda datum: datum['profile'] not in self.exception[result_key]['profile']
    ])
```
`exception['limit']`/`exception['profile']`가 둘 다 빈 리스트이므로 `not in []`는 항상
`True`다 — 즉 `DBM-007_1`에 `profile`/`limit` 필드를 가진 행이 하나라도 있으면 **그
값(실제로 PASSWORD_VERIFY_FUNCTION이 설정돼 있든 아니든)과 무관하게 무조건 위반으로
집계**된다. 실수집(`collected/db/oracle_native/oracle_native_result.json`)에서는
`DBM-007_1` 4행 모두 `limit="NULL"`(미설정, 실제로도 취약)이라 이 버그가 결과를
왜곡하지 않았지만, 만약 DBA가 `PASSWORD_VERIFY_FUNCTION`을 실제로 설정한 서버라면
`limit`에 함수명이 채워져도 여전히 위반으로 집계돼 **거짓취약**이 발생한다.
**db.py 모드J와의 상호작용**: 이 버그 때문에 oracle DBM-007은 "행이 있고 위반이 0"인
진짜 양호 상태를 결정론적으로 재현할 방법이 없다 — 도달 가능한 결과는 0행(모드J →
판단보류) 또는 행 존재(항상 취약) 둘뿐이다. `tests/db_cov_contract.py`의 oracle
`DBM-007` good_verdict를 양호→판단보류로 정정한 근거이자(§F6 배치),
`tests/test_mode_j_hold.py::TestModeJDbm007OracleAlwaysHoldOrVuln`이 이 상한 동작을
회귀 고정한다.
**수정 여부**: 벤더 config/코드 미수정(§F6 spec 범위 밖 — exception 설정을 채우려면
"Oracle 12c+ 기본 제공 `ORA12C_VERIFY_FUNCTION` 계열을 exception으로 인정할지" 등
정책 판단이 필요해 별도 배치로 분리 권고).
- 최근 비밀번호 변경(정상) → 양호 회귀 (과탐 방지)

## R-PRCC-NOTEXIST. 컨테이너 PRCC-023/035/036/037/038 docker_linux "미존재" 마커
불일치 — 거짓취약 (2026-07-11, VENDOR-EDIT(bug) 완료, §3-3 항목1)

**id**: `R-PRCC-NOTEXIST`
**위치**: `judge_tool/vendor/common/container/autoAnalysis.py`
`PRCC-023`(:777), `PRCC-035`(:980), `PRCC-036`(:1015), `PRCC-037`(:1037),
`PRCC-038`(:1056) — 각 `elif "docker" in sApp:` 분기.
**상태**: VENDOR-EDIT(bug) 완료 (2026-07-11)
**관련**: `tests/container_cov_contract.py`, `tests/test_container_cov_fixtures.py`

### 증상 (마커 리터럴 불일치 → "미존재" 판정 영구 미매치 → 거짓취약)

autoAnalysis.py는 컨테이너 목록이 비어있음(위반 없음)을 나타내는 마커로
`"[does not exist]"`(PRCC-035/036/037/038) 또는 `"does not exist"`(PRCC-023,
대괄호 없음)만 인식했다:
```python
# 버그 코드 (수정 전, 5곳 공통 패턴)
elif "docker" in sApp:
    if "[does not exist]" not in vulOutput:      # PRCC-035/036/037/038
        autoResult["result"] = "Y"
        ...
```
그러나 실 수집 스크립트(`out/kind_lab/829d2152a3d6-docker-*.xml` 실측, kind 클러스터
docker_linux 실수집)가 실제로 방출하는 마커는 `"[not exist]"`("does" 없음)이며, 해당
XML 7곳(PRC-C-023/035/036/037/038 각 출력 블록)에서 확인된다. 즉 **실 데이터에서는
"[does not exist]"/"does not exist"가 절대 매치되지 않아, docker_linux는 이 5항목에서
실제 상태(위반 컨테이너 존재 여부)와 무관하게 항상 `result='Y'`(취약)로 판정**되었다
(방향=과판정/거짓취약 — 안전 방향이지만 정확도 붕괴, real 도커 환경 5항목 전수 오탐).

### Corrected 동작 (VENDOR-EDIT(bug))

기존 리터럴은 회귀 보존을 위해 유지하고, 실 마커 `"[not exist]"`를 OR로 추가 인식:
```python
# 수정 후 (VENDOR-EDIT(bug): R-PRCC-NOTEXIST) — 5곳 동일 패턴
elif "docker" in sApp:
    if "[does not exist]" not in vulOutput and "[not exist]" not in vulOutput:
        autoResult["result"] = "Y"
        ...
```
PRCC-023만 대괄호 없는 `"does not exist"` 리터럴이라 동일하게
`if "does not exist" not in vulOutput and "[not exist]" not in vulOutput:`로 수정.

각 항목의 판단기준(criteria xlsx '컨테이너 가상화 시스템' 시트, PRCC-023/035/036/
037/038 Docker-Linux 판단기준)을 개별 확인한 결과, 5항목 모두 동일 극성이다 —
**해당 위반 컨테이너 목록이 비어있음(마커 존재) = 양호, 목록에 항목 존재(마커 부재)
= 취약**. 즉 `"[not exist]"`는 5항목 전부에서 **양호 신호**이며 일괄 OR 추가가
안전하다(항목별 정독 완료, 일괄 처리가 아닌 개별 판단기준 확인 후 동일 결론).

실측 검증(`out/kind_lab/829d2152a3d6-docker-*.xml` 실데이터로 autoAnalysis 직접 호출):
- PRCC-035/036/037/038: 수정 전 전부 `result='Y'`(거짓취약) → 수정 후 전부
  `result='N'`(양호, 실환경에 위반 컨테이너 없음 — 정답).
- PRCC-023: 수정 후에도 `result='Y'` 유지 — 단 이는 마커 버그가 아닌 **별개의
  독립 조건**(`"default_bridge:true" in vulOutput`, 이 클러스터의 docker 기본
  브릿지가 실제로 `default_bridge:true`로 설정되어 있음)에 의한 것으로, 참 양성이다.
  마커 관련 두 번째 조건("브릿지 사용 컨테이너 목록" 부재 확인)은 정정 후 정상적으로
  거짓(→미기여)으로 평가됨(수정 전에는 이 조건도 상시 참이라 point 문구에 부정확한
  이유가 덧붙었으나 판정 자체는 이미 Y였음 — 수정으로 근거 문구 정확도 개선).

### 회귀테스트 핀 (tests/container_cov_contract.py + test_container_cov_fixtures.py)

- PRCC-023/035/036/037/038 docker_linux `good` 픽스처를 실 마커 `"[not exist]"`로
  재작성 — 실 데이터 기준 양호 경로 도달 확인(수정 전에는 도달 불가능했음).
  `vuln` 픽스처(마커 완전 부재)는 기존 그대로 유지 — 취약 경로 회귀 보존.

## PRCC-045-k8s-hostuts. 컨테이너 PRCC-045 k8s_master 수집 jsonpath 불일치 —
거짓양호, DET→MANUAL 강등 (2026-07-11, 라우팅 조정 완료, §3-3 항목2)

**id**: `PRCC-045-k8s-hostuts`
**위치**:
- 코드: `judge_tool/vendor/common/container/autoAnalysis.py:1136` (`elif "PRCC-045" in vulKey:` → `if "k8s_master" in sApp ...`)
- 조치: `judge_tool/vendor/common/DET_SOURCE.yaml` `PRCC-045.variants.k8s_master`
**상태**: 강등 완료 (2026-07-11) — **코드 자체는 수정하지 않음**(아래 "수정하지 않은
이유" 참조), DET_SOURCE.yaml 분류 변경으로 gate 차단만 적용.
**관련**: `tests/container_cov_contract.py`, `tests/test_container_cov_fixtures.py`

### 증상 (수집 jsonpath와 코드 마커 문자열 불일치 → 마커 영구 부재 → 항상 양호)

`autoAnalysis.py:1136`:
```python
elif "PRCC-045" in vulKey:
    if "k8s_master" in sApp or "k8s_master" in sApp:   # (중복조건, 별개 관찰사항 — 무해)
        if "spec.hostUTS:'true'" in vulOutput:
            autoResult["result"] = "Y"
            ...
```
코드는 `"spec.hostUTS:'true'"` 문자열을 검사하지만, 실 수집 스크립트(out/kind_lab/
prcc-lab-control-plane-k8s_master-*.xml 실측, PRC-C-045 output)의 실제 jsonpath는
```
$ kubectl get pod [POD] -n [namespaces] -o jsonpath=" -securityContext.hostUTS:'{.securityContext.hostUTS}'"
```
로 **`securityContext.hostUTS`** 접두를 사용한다(`spec.hostUTS`가 아니다).
PRCC-042/043/044(hostPID/hostIPC/hostNetwork)는 실 스크립트가 `spec.xxx` 접두를
정확히 쓰는 반면(코드와 일치, 정상 동작), PRCC-045만 접두가 달라 코드 문자열이 실
데이터에서 **절대 매치되지 않는다** → k8s_master는 실제 hostUTS 공유 여부와 무관하게
항상 `result='N'`(양호)로 고정된다(**거짓양호, High** — DET 항목이 실제로는 아무
것도 검증하지 못하면서 매번 "양호"를 반환).

추가로, hostUTS는 vanilla Kubernetes Pod API의 표준 필드가 아니다 —
`kubectl explain pod.spec` / `pod.spec.securityContext` 어디에도 `hostUTS`가 없으며,
호스트 네임스페이스 공유 관련 표준 필드는 `hostPID`/`hostIPC`/`hostNetwork` 3종뿐이다.
즉 수집 스크립트 자체가 애초 존재하지 않는 필드를 조회하고 있어, jsonpath를 code와
일치시켜도(`securityContext.hostUTS`로 코드를 고쳐도) 실 데이터에서 항상 빈 값만
나올 것으로 예상된다 — **이 항목은 k8s_master에서 결정론 검증이 구조적으로 불가능**.

### 수정하지 않은 이유 (마커 문자열만 맞추지 않은 이유)

R-PRCC-NOTEXIST(위 항목)처럼 코드의 마커 문자열을 실 데이터에 맞춰 고치는 방식은
여기서는 **채택하지 않았다** — jsonpath가 조회하는 필드 자체가 vanilla Kubernetes에
존재하지 않으므로, 문자열만 맞춰도 수집값이 항상 비어 있어 실질적으로 여전히
"검증 불가능한 결정론"이 된다(문자열 수정은 겉보기 정합성만 회복하고 실제 판정
능력은 회복하지 못함). 따라서 fail-closed 원칙에 따라 **DET_SOURCE.yaml에서
k8s_master 분류를 DET→MANUAL로 강등**해 gate가 이 조합을 결정론 경로에서 완전히
차단하도록 했다.

### Corrected 라우팅 (DET_SOURCE.yaml 변경)

```yaml
PRCC-045:
  variants:
    k8s_master: MANUAL   # 2026-07-11 DET→MANUAL 강등 — gate 차단→LLM(label A)
    docker_linux: DET    # 변경 없음(docker --uts=host 실재, 마커 정상 일치)
    ocp_master: DET       # 변경 없음
```

실 라우팅 확인(코드 경로 추적, `judge_tool/det_adapters/base.py::classify/gate`,
`judge_tool/main.py::_det_common_handler/_det_common_label_route`):
1. `classify("PRCC-045", "k8s_master")` → `"MANUAL"`.
2. `gate()`가 `handled=False` ForcedVerdict(verdict="판단보류") 반환 —
   raw_output 내용과 무관(§18.1 C1).
3. `main.py::_det_common_handler`가 `gate_result.handled is False`를 보고
   `_det_common_label_route()`로 위임 → `container.yaml` PRCC-045 `label: A`이므로
   `_judge_one`(LLM 판정) 경로로 폴백.
4. 즉 k8s_master PRCC-045는 더 이상 "항상 양호"가 아니라 LLM이 실제 raw_output
   (예: `"[not exist]"` 마커 포함 출력)을 보고 판단한다. PROGRESS.md 문서화된
   LLM 프롬프트 가드(`[not exist]`=양호 신호로 해석)에 따라 결과적으로 "양호"에
   도달할 수 있으나, 이는 **결정론 마커 매칭이 아닌 LLM의 근거 있는 판단**이며
   증거 부재/모호 시에는 판단보류로 흡수된다 — 항상-양호 거짓양호 구조가 제거됨.
   (⚠️ 로컬 LLM을 실제로 기동해 end-to-end 실행 검증은 이 배치 범위에서 수행하지
   않았다 — 위 4단계는 코드 경로 추적으로 확인.)

### 회귀테스트 핀 (tests/container_cov_contract.py + test_container_cov_fixtures.py)

- `CONTAINER_COV["PRCC-045"]`에서 `"k8s_master"` 키 제거(DET 양극성 대상 아님).
- `CONTAINER_MANUAL_HOLD_ITEMS`에 `("PRCC-045", "k8s_master", ...)` 추가 —
  `test_container_manual_hold_items_no_false_positive`가 dummy 증거 raw로도
  `handled=False` + `verdict != '양호'`를 회귀 고정.
- `test_container_cov_contract_completeness`의 k8s_master 최소 개수를 33→32로 조정
  (DET_SOURCE.yaml 실제 분류 변경 반영).
- docker_linux PRCC-045(good/vuln)는 변경 없이 유지 — 회귀 보존.

## R-WST033. 웹서버-WAS WST-033 Apache 서비스 조기반환 죽은 코드 → 허위근거 거짓양호
(2026-07-11, VENDOR-EDIT(bug) 완료, §1/§2 도커 자가수집 실증)

**id**: `BUG-WST033-apache`
**위치**: `judge_tool/vendor/common/webwas/WST_Apache_parse.py` `check_WST_033()`
(서비스 조기반환부 원래 line 19-22, 버전 미검출 폴백부 원래 line 60-61)
**상태**: 수정 완료 (2026-07-11)
**관련**: `tests/web_cov_contract.py`, `tests/test_web_cov_fixtures.py`

### 증상 (헤더가 패턴과 항상 매치 → 조기반환 도달불가 → 허위근거 양호)

`out/was_lab/tomcat-good.xml`(Apache 미설치 호스트) 실측 WST-033 raw:

```
[ http|https|http-alt|www|www-http|apache|apache2 ][S]
[ http|https|http-alt|www|www-http|apache|apache2 ][E]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ rpm -qa httpd
/tmp/fsi_unix.sh: line 2670: rpm: command not found
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ dpkg -l | grep apache
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$ apache2 -v
/tmp/fsi_unix.sh: line 2678: apache2: command not found
```

수정 전 코드:

```python
# 현재 버그 코드 (WST_Apache_parse.py:19-22, 원본)
service_pattern = "http\\|https\\|http-alt\\|www\\|www-http\\|apache\\|apache2"
if not re.search(service_pattern, output_arr[0], re.IGNORECASE):
    auto_result_reason = "(+) Apache 서비스가 실행 중이지 않은 것으로 탐지되어 양호로 판단\n" + output_arr[0]
    return result, auto_result_reason, vulnerability_condition_result_model_list
```

`output_arr[0]`은 fDumpS 진단 헤더(`[ http|https|http-alt|www|www-http|apache|
apache2 ][S]` ~ `[E]`)를 **항상** 포함하며, 이 헤더 문자열 자체가 점검 대상
서비스 토큰을 그대로 echo한다. 게다가 `service_pattern`은 `\|`(이스케이프된
리터럴 파이프)로 토큰을 이었기 때문에 정규식 교대(alternation)가 아니라
`"http|https|http-alt|www|www-http|apache|apache2"` 라는 **하나의 긴 리터럴
문자열**을 찾는 패턴이었다 — 이 리터럴은 헤더 자체에만 등장한다(우연히도
헤더 포맷과 100% 일치). 결과적으로 `re.search(service_pattern, output_arr[0])`
는 Apache 설치/실행 여부와 **무관하게 항상 매치** → 이 조기반환은 도달
불가능한 죽은 코드였다.

조기반환이 죽었으므로 처리는 계속 진행되어 `httpd_pattern`(output_arr[1] =
rpm 출력)·`apache_pattern`(output_arr[2] = dpkg 출력) 모두 미매치 →
`vulnerability_condition_result_model_list`가 비고 `apache_version`도 빈
문자열(`""`)로 남는데, 다음 폴백이 무조건 실행된다:

```python
# 현재 버그 코드 (WST_Apache_parse.py:60-61, 원본)
if not vulnerability_condition_result_model_list:
    auto_result_reason = "(+) Apache 버전이 2.1 이상인 것으로 탐지되어 양호로 판단\n" + apache_version + "\n"
```

즉 Apache가 아예 설치되지 않아 버전을 전혀 탐지하지 못했는데도
**"버전이 2.1 이상인 것으로 탐지되어"라는 허위 근거**로 `result='N'`(양호)를
반환한다(`tomcat-good.xml`로 재현 확인, High — 근거 없는 자동 양호).

### Corrected 동작 명세

1. **서비스 조기반환 복구**: `output_arr[0]`에서 fDumpS 헤더 라인
   (`^(?:-e\s+)?\[.*?\]\[[SE]\]\s*$`, MULTILINE)만 제거한 나머지(`$ ps -ef |
   egrep apache` 등 실제 명령 출력)에서 서비스 존재를 판정한다. 이와 함께
   `service_pattern`의 이스케이프도 진짜 교대(`|`)로 고쳐, 헤더를 제외한
   뒤에도 실제 프로세스 라인(`apache2` 등)과 정상적으로 매치되도록 한다.
   Apache 부재 시(헤더만 남고 실 데이터가 비거나 토큰 미포함) 조기반환이
   실제로 발동해 "(+) Apache 서비스가 실행 중이지 않은 것으로 탐지되어
   양호로 판단"이라는 **정직한 사유**로 양호를 반환한다.
2. **허위근거 폴백 제거**: 취약 조건 미발견 + `apache_version` 실제 탐지 시
   → 기존과 동일하게 "(+) Apache 버전이 2.1 이상인 것으로 탐지되어 양호로
   판단" 유지(참 근거). 취약 조건 미발견 + `apache_version`이 끝내 빈 문자열
   (서비스는 확인됐지만 rpm/dpkg/apache2 -v 어디서도 버전을 못 뽑은 경우) →
   `"(*) Apache 서비스는 확인되었으나 버전 문자열이 탐지되지 않아 수동 확인
   필요"`로 **판단보류**시킨다. `"(*)"` 마커 + `result != "Y"` 조합은
   `judge_tool/det_adapters/webwas.py::_map_result`의 Low-1 가드가
   `handled=False`(판단보류)로 흡수한다 — 버전 미검출을 "2.1 이상"으로
   추정하는 거짓양호 경로를 제거.
3. `output_arr` 길이 방어(`len(output_arr) > 1`/`> 2` 가드)도 함께 추가해
   구분자 수가 기대(4섹션)보다 적은 비정상 캡처에서 IndexError 없이
   안전하게 미검출로 처리되도록 했다(동작 변경 없음, 방어적 보강).

### 형제 체크 점검 결과 (같은 파일)

같은 파일의 `check_WST_034`/`check_WST_044`는 순수 MANUAL 스텁(항상 `(*)
수동 분석/점검 필요` 반환)이라 `output_arr[0]`/`service_pattern` 헤더매칭
로직 자체가 없다. config-항목 체크(`check_WST_031/035/036/037/038/039/102`)는
`outputData`가 아니라 `configData`(설정파일 본문)를 직접 검사하며 구분자/헤더
분할이 없다. 따라서 **이 파일 안에서는 WST-033 외 동일 결함이 없음**을
확인했다(사실 보고, 수정 없음).

### 회귀테스트 핀 (tests/test_wst033_apache_service_detection.py)

- **헤더-only(Apache 부재, tomcat-good.xml 실측 형상)** → `result='N'`,
  reason에 "실행 중이지 않은" 문구(정직한 조기반환 사유) — 종전엔 죽은 코드라
  도달 불가능했던 경로가 실제로 발동함을 고정.
- **실제 Apache 구버전(rpm httpd-1.3.42)** → `result='Y'`(취약) 회귀.
- **실제 Apache 신버전(dpkg apache2 2.4.52 / apache2 -v Apache/2.4.52)** →
  `result='N'`(양호), reason에 실제 탐지된 버전 문자열 포함 회귀.
- **서비스 존재 + 버전 미검출**(rpm/dpkg/apache2 -v 모두 실패) →
  `result='N'` + reason에 `"(*)"` 마커 포함 → 어댑터 경유 시 `handled=False`
  (판단보류) 확인.
- `tests/web_cov_contract.py` `_APACHE["WST-033"]`(good/vuln) 기존 픽스처가
  새 헤더-스트립 게이트에서도 그대로 통과하는지 재확인(회귀 없음).


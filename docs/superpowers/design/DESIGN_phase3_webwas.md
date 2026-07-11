# 설계: common 결정론 통합 Phase 3 — 웹서버-WAS (WST)

> 작성: 2026-06-16 · 상태: **구현 계획(미구현)** · 작성자: Opus(설계 대행, Fable 미접근)
> 전제 계약: "검증·수정 후 가져간다"(DESIGN_common_deterministic_integration.md §17.6/§18).
> 재사용 패턴: Phase 1 서버(SHIP)·Phase 2 컨테이너(SHIP). 본 문서는 Sonnet이 그대로
> 구현 가능한 수준의 작업 지시서다. 코드라인 인용으로 추측을 배제했다.

---

## 0. ★핵심 발견 — 설계 예상과 다른 점 (먼저 읽을 것)

전수 코드/실데이터 확인 결과, **PROGRESS ⑦ 게이트의 "OS/웹 이중성" 난점은 실데이터에서
이미 해소되어 있다.** 추측이 아니라 다음 근거에 기반한다:

### 0.1 실데이터의 ID 체계 (검증된 사실)
`collected/web/apache_linux/web_apache-s-sample.xml`(fsi_unix.sh 산출)의 `<dump>/<items>/<id>`:
- **OS 점검 항목은 `SRV-NNN` ID로 emit**(67건: SRV-001/004/.../175). `web_apache-s-sample.xml:1913`
  부근부터 SRV 블록, `<id>SRV-001</id>` 등.
- **웹 특화 항목만 `WST-NNN` ID로 emit**(6건: WST-033/034/035/038/044/102).
  `web_apache-s-sample.xml:1911,1955,2014,2050,2102,2120`.
- `<asset>`에는 `<os>Linux</os>`만 있고 `<webserver>`/`<variant>`/`<app>` 태그는 **없다**
  (`web_apache-s-sample.xml:4-10`).

→ **즉, 하나의 호스트 파일에 SRV(OS) + WST(웹) 항목이 섞여 들어온다.** 한 variant로
  OS와 웹 항목을 모두 판정해야 하는 "이중성"이 실재한다. 그러나 ID 충돌은 없다
  (SRV 네임스페이스 vs WST 네임스페이스 분리).

### 0.2 common 웹 모듈의 실제 구조 (검증된 사실)
`flus-main/app/common/WebServerConfigLoader/`에는 **웹서버 3종 파서만** 존재:
- `WST_Apache_parse.py` / `WST_IIS_parse.py` / `WST_WebtoB_parse.py` / `wslib.py`.
- **Tomcat/JEUS 파서 없음**(§17.3 ABSENT 확정 — `ls`로 확인).
- 각 파서는 **웹 특화 항목만** 구현: `check_WST_031`~`check_WST_044` + `check_WST_102`
  (전 3파서 union 15함수, `grep check_WST_ *.py`로 확인).
- **OS 항목(WST-001~120 영역)에 대응하는 common 함수는 웹 모듈에 전혀 없다.**
  웹 모듈의 주석이 `# 기존 SRV-040`(WST-031), `# 기존 SRV-148`(WST-102) 식으로
  "이 WST 항목은 과거 SRV 항목과 동일 점검"임을 명시(`WST_Apache_parse.py:417-429`).

→ **결론: "WST의 OS항목 106은 서버 SRV 로직과 동형"의 의미는 = 그 항목들이 실제로는
  SRV ID로 수집되어 SERVER 프로파일로 판정된다는 것.** common 웹 모듈은 OS 항목을
  중복 구현하지 않았다. 따라서 **WST↔SRV ID 매핑 테이블은 불필요**(아래 §2 전략 A 근거).

### 0.3 common 웹 판정 함수의 형태 (검증된 사실)
각 `check_WST_NNN(data) -> (result, auto_result_reason, vul_list)` — **서버 동형 시그니처**
(`WST_Apache_parse.py:7,83` 등). `Y`=취약/`N`=양호/`(*)`=수동, server와 동일 인코딩.
- 단 입력 분기 2종: **명령출력 항목**(WST-033/034/044 — `function_dispatcher`)과
  **config-파일 항목**(WST-031/035/036/037/038/039/102 — `config_function_dispatcher`,
  `WST_Apache_parse.py:416-430`). config 항목은 `main()`에서 `data_dict['apache']`
  (별도 config 블록)을 받도록 설계됨(`WST_Apache_parse.py:450-453`).
- **그러나 개별 `check_WST_NNN`는 단일 문자열 인자만 받는 순수함수** — server.py 어댑터처럼
  직접 호출 가능. `main()` 디스패처는 우회한다(아래 §5).

### 0.4 실데이터 입력 형태의 함정 (검증된 사실, 정확도에 직접 영향)
실데이터 WST 블록은 **flat raw 명령출력**이지, common `main()`이 기대하는
`{WST-NNN: out, 'apache': config}` dict가 **아니다**. 또한:
- WST-035(LimitRequestBody) 출력에 **apache2.conf 본문 dump가 없다** — 프로세스 탐지 +
  "JEUS NOT installed"만(`web_apache-s-sample.xml:2016-2045`). config-항목 check 함수는
  config 본문을 못 받으면 "구문 없음→취약" 또는 "섹션 없음→양호" 분기로 빠진다
  (예: `check_WST_035` LimitRequestBody 미존재→**취약 Y**, `WST_Apache_parse.py:162-169`).
- WST-038(`ls /etc/apache2/` + `ls /var/www/html/`)은 `<Directory>` 블록 config가 아니라
  디렉터리 리스팅 → `check_WST_038`의 `<Directory>` 정규식 미매치 → "양호" 오판 위험.

→ **함정**: config-항목을 raw blob에 그대로 먹이면 **거짓취약(035) 또는 거짓양호(038)**.
  이것이 본 Phase의 최대 정확도 리스크다(§4·§6·§9에서 처리).

---

## 1. 벤더링 범위

### 1.1 새로 벤더링할 것 → `judge_tool/vendor/common/webwas/`
| 원본 | 벤더 경로 | stdlib 의존 | VENDOR-EDIT |
|---|---|---|---|
| `WebServerConfigLoader/wslib.py` | `vendor/common/webwas/wslib.py` | (a) Django import 제거 | (a) |
| `WebServerConfigLoader/WST_Apache_parse.py` | `vendor/common/webwas/WST_Apache_parse.py` | re, json | (a) wslib import 경로 |
| `WebServerConfigLoader/WST_IIS_parse.py` | `vendor/common/webwas/WST_IIS_parse.py` | re, json | (a) + (c) WST-102/040 버그수정 |
| `WebServerConfigLoader/WST_WebtoB_parse.py` | `vendor/common/webwas/WST_WebtoB_parse.py` | re, json | (a) wslib import 경로 |

- **VENDOR-EDIT(a)**: `wslib.py:1-7`이 Django(`apps.proofs.models`/`django.core.files`/
  `django.db.models`)와 `datetime`을 import. 우리는 `parseAnalysisResult`(Django ORM 의존,
  `wslib.py:14-94`)를 **사용하지 않으므로** 벤더 시 그 함수와 Django import를 **제거**하고
  `get_remove_line`(`wslib.py:9-12`, 순수 stdlib)만 남긴다. Apache/IIS/WebtoB는
  `from common.WebServerConfigLoader.wslib import get_remove_line`(`WST_Apache_parse.py:2`)을
  `from judge_tool.vendor.common.webwas.wslib import get_remove_line`로 1줄 교체.
- **VENDOR-EDIT(c)**: WST-102(IIS)/WST-040(IIS) 버그수정 — §4 상세.
- **제외**: `parseAnalysisResult`(ORM), `main()` 디스패처는 **벤더에 남겨두되 호출 안 함**
  (어댑터가 개별 check 함수 직접 호출). `main()`은 `data_dict['apache']` 등 dict 형태
  입력을 요구하므로 우리 입력과 불일치 — 우회가 정답(§5). main()을 지워도 무방하나,
  원본 보존 원칙상 **남겨두고 호출하지 않음**(diff 최소화).

### 1.2 OS 항목 — 서버 벤더 재사용 (신규 벤더링 없음)
§0.2/§2 근거: WST OS 항목은 실데이터에서 **SRV ID로 수집** → SERVER 프로파일이 판정.
webwas 프로파일에는 OS 항목 결정론이 **불필요**. 이미 벤더링된
`vendor/common/server/{SRV_auto_parse,SRV_Linux_parse,sclib}.py`를 webwas 어댑터가
**그대로 재사용**한다(§5.2 — OS variant일 때 server 어댑터에 위임). 추가 벤더링 0.

---

## 2. ★OS/웹 이중성 처리 (핵심 난점) — 전략 A 채택

PROGRESS ⑦ 게이트의 (a)/(b)/(c) 중 **(a) "OS variant 단일 판정 + 웹항목 자동포함"의
변형**을 채택한다. 단 실데이터 ID 체계(§0.1)에 맞춰 정밀화한다.

### 2.1 채택 전략 A — "ID 네임스페이스로 항목별 위임"
한 호스트 파일에 SRV(OS) 항목 + WST(웹) 항목이 섞여 들어오고, variant는 하나
(예: `apache`로 detect 또는 `linux`로 detect — §6.2). webwas 어댑터는 **item_id 접두어로
판정 경로를 가른다**:

```
webwas_adapter.judge(item_id, raw, variant, thresholds, *, context):
    if item_id.startswith("SRV-"):
        # OS 항목 → server 어댑터에 위임 (OS variant로 변환)
        os_variant = _resolve_os_variant(variant)   # §2.3
        return server_adapter.judge(item_id, raw, os_variant, thresholds, context=context)
    if item_id.startswith("WST-"):
        # 웹 특화 항목 → WST common check 함수 (web variant로)
        web_variant = _resolve_web_variant(variant)  # §2.3
        return _judge_wst(item_id, raw, web_variant, thresholds, context=context)
    return _absent_forced(item_id)   # 미지 접두어 → handled=False
```

근거:
- WST OS 항목은 common 웹 모듈에 함수가 없다(§0.2) → 별도 구현은 ABSENT 차단만 양산.
  실데이터는 OS를 SRV로 emit(§0.1) → **server 어댑터(검증된 SHIP)에 그대로 위임**이 정답.
- 웹 특화 항목만 WST common(15함수)로 판정.
- ID 충돌 없음(SRV vs WST 네임스페이스) → 라우팅이 결정론적·단순.

### 2.2 왜 (b)(2회 판정)·(c)(복합 variant) 아닌가
- (b) "OS+웹 2회 판정"은 같은 호스트를 server 프로파일 + webwas 프로파일로 2번 돌리는 것.
  실데이터가 단일 파일에 SRV+WST 혼재(§0.1)라 **1회 실행으로 충분** — 2회는 중복.
- (c) "복합 variant"(예: `apache_linux` 단일 키)는 profile.WEBWAS 컬럼 구조(OS 5 + 웹 6
  독립 variant, `profile.py:511-536`)와 충돌. detect_variant도 단일 키 반환 계약
  (`webwas_xml.py:98-126`). 복합키는 컬럼 매핑(standard_col/method_col)을 깨뜨린다.

### 2.3 variant 정규화 헬퍼 (webwas 어댑터 내부)
detect_variant(§6.2)가 반환하는 단일 variant는 OS키(linux 등) 또는 웹키(apache 등) 중 하나.
- `_resolve_os_variant(variant)`: variant가 OS키({aix,hpux,linux,solaris,win})면 그대로;
  웹키(apache 등)면 **OS 정보 부족** → SRV 항목 위임 시 server 어댑터의 linux-override가
  안 걸리므로 SRV_auto_parse 경로 사용(대부분 항목 정상; SRV-026/069/074/127/131만 linux
  전용 — §16.3). 실데이터는 `<os>Linux</os>`라 detect가 `linux` 반환(§6.2) → OS 위임 정상.
  **웹키로 detect된 경우의 SRV 항목은 OS 정보가 없으므로 보수적으로 SRV_auto_parse**
  (linux-override 미적용). 이 경계는 §9 리스크에 명시.
- `_resolve_web_variant(variant)`: variant가 웹키({webservice,apache,webtob,iis,tomcat,
  jeus})면 그대로; OS키면 **웹서버 종류 미상** → WST 판정에 어느 파서를 쓸지 모름
  → WST 항목은 `handled=False`(ABSENT 유사) 또는 raw blob에서 웹서버 추론(§5.3).

### 2.4 webwas.yaml 라벨 동기화 (OS 항목)
webwas.yaml의 SRV-* 항목(OS) 라벨은 **server.yaml을 그대로 복사**한다(§7). 위임 대상이
server 어댑터이므로 라벨도 동일해야 일관. WST-* 항목만 본 Phase에서 새로 분류.

> ⚠️ **검증 한계**: 실데이터(`web_apache-s-sample.xml`)의 OS 항목은 SRV ID라
> SERVER 프로파일로도 이미 판정 가능. webwas 프로파일에서 SRV 항목을 받으려면
> **criteria 시트(웹서버-WAS)에 SRV ID 행이 있어야 한다**. 시트는 WST ID만 가질 가능성이
> 높다(profile.WEBWAS id_col=2가 WST 기대). → **이것이 본 설계 최대 불확실성**(§9 R-DUAL).
> 두 가지 가능성:
>   (1) 시트가 WST ID만 보유 + OS 항목도 WST ID로 매핑되어 있다면 → §0.1 실데이터(SRV emit)와
>       **ID 불일치** → webwas 프로파일은 WST 항목만 매칭, SRV 항목은 criteria에 없어 누락.
>   (2) 사용자 지시("server와 별도 프로파일, OS항목 중복 허용", PROGRESS ⑦)대로 시트가
>       OS항목을 WST ID로 복제 보유.
> **구현 착수 전 1번 액션(§8.0): criteria 웹 시트의 실제 ID 목록을 dump해 SRV/WST 혼재
> 여부 확정.** 결과에 따라 §2.5 분기.

### 2.5 criteria ID 확정 후 분기 (착수 전 결정)
- **케이스 (1) 시트=WST ID만(OS항목도 WST ID)**: webwas 어댑터가 **WST OS항목 ID를 SRV로
  역매핑**해야 함 → §0.2가 "common 웹 모듈에 SRV-NNN 주석"을 남겼으므로, 그 주석에서
  WST→SRV 매핑 테이블(`WST-031→SRV-040` 등)을 **웹 특화 14항목만** 추출 가능. 그러나
  OS 항목 100여개의 WST↔SRV 매핑은 주석에 없음 → **항목명(name_col) 기준 대조 필요**
  (PROGRESS ⑦ 3번 지시: "ID 직접 매핑 금지, 평가항목명 기준"). 이 경우 OS 항목은
  **수작업 name 매핑 테이블**(WST↔SRV) 1개를 산출물로 추가.
- **케이스 (2) 시트=SRV+WST 혼재**: §2.1 전략 그대로(ID 접두어 라우팅) — 추가 작업 0.
- **권장**: 케이스 (1)이면 **본 Phase는 웹 특화 항목(WST 15)만 결정론화**하고 OS 항목은
  server 프로파일로 별도 점검하도록 문서화(이중성 단순화). 사용자 확인 항목.

---

## 3. DET_SOURCE WST 분류 방법론

### 3.1 분류 대상 = 웹 특화 항목만 (OS 항목은 SRV 분류 준용)
DET_SOURCE.yaml에 **WST-031~044 + WST-080 + WST-102 + WST-121~126**(웹 특화 22항목)을
등재. OS 항목(WST-001~120 중 SRV 동형)은 **서버 분류를 준용** → 위임 대상이 server
어댑터이므로 DET_SOURCE의 SRV 엔트리가 그대로 적용된다(webwas 어댑터가 SRV-* 항목에서
server.gate를 통과). **케이스(1)이면 WST OS-ID도 SRV 분류로 미러링 필요**(§2.5).

### 3.2 코드 근거 분류 (웹 특화 22항목)
variant키 = profile.WEBWAS 웹키({webservice,apache,webtob,iis,tomcat,jeus}). 분류 근거 =
3파서의 dispatcher 등재 여부 + 함수 본문 `(*)` 마커.

| WST | Apache | IIS | WebtoB | 분류(DET_SOURCE) | 근거 |
|---|---|---|---|---|---|
| WST-031 | DET | DET | DET | DET-PARTIAL(variants) | 3파서 config_dispatcher 등재 |
| WST-032 | — | DET | — | DET-PARTIAL{iis:DET} | IIS only(`WST_IIS_parse.py:716`) |
| WST-033 | DET | DET | NA→MANUAL | DET-PARTIAL | WebtoB는 NA 처리(`WST_WebtoB_parse.py:314`) |
| WST-034 | **MANUAL** | DET | MANUAL | DET-PARTIAL | Apache/WebtoB `(*)`(`WST_Apache_parse.py:69`) |
| WST-035 | DET | DET | DET | DET-PARTIAL | 3파서 등재 |
| WST-036 | DET(+(*)분기) | DET | DET | DET-PARTIAL | Apache `$`환경변수→(*)(`:207`) |
| WST-037 | DET | DET | DET | DET-PARTIAL | 3파서 등재 |
| WST-038 | DET | DET | NA→MANUAL | DET-PARTIAL | WebtoB NA(`:316`) |
| WST-039 | **MANUAL** | DET | DET | DET-PARTIAL | Apache `(*)`(`WST_Apache_parse.py:357`) |
| WST-040 | — | DET(버그) | — | DET-PARTIAL{iis:DET} | IIS only, §4 버그 |
| WST-041 | — | DET | — | DET-PARTIAL{iis:DET} | IIS only(`:720`) |
| WST-042 | — | DET | — | DET-PARTIAL{iis:DET} | IIS only(`:733`) |
| WST-043 | — | DET | — | DET-PARTIAL{iis:DET} | IIS only(`:721`) |
| WST-044 | **MANUAL** | **MANUAL** | **MANUAL** | MANUAL | 전 파서 `(*)`(`WST_Apache_parse.py:77`) — §15.1 C |
| WST-102 | DET | DET(버그) | DET | DET-PARTIAL | 3파서 등재, IIS 버그 §4 |
| WST-080 | — | — | — | ABSENT | 함수 없음(§17.3) — 패치성, label D |
| WST-121 | — | — | — | ABSENT | 함수 없음(§17.3) |
| WST-122 | — | — | — | ABSENT | 함수 없음 |
| WST-123 | — | — | — | ABSENT | 함수 없음 |
| WST-124 | — | — | — | ABSENT | 함수 없음 |
| WST-125 | — | — | — | ABSENT | 함수 없음 |
| WST-126 | — | — | — | ABSENT | 함수 없음 — EOL, label D |

> **결번 확인**: criteria 웹 시트 실제 ID로 결번/항목수 확정은 §8.0 dump 후. 위 표는
> 코드(파서 함수) 기준. WST-040/041/042/043은 IIS 전용(Apache/WebtoB 미구현).

### 3.3 variants 맵 스키마 (DET-PARTIAL 펼침)
PRCC 선례(`DET_SOURCE.yaml` 컨테이너 블록)와 동형. 예:
```yaml
  WST-040:
    default: ABSENT          # apache/webtob/tomcat/jeus/webservice엔 함수 없음
    variants:
      iis: DET               # IIS만 구현(버그수정 후 DET)
    bug: WST-040-polarity    # 이미 등재(DET_SOURCE.yaml:286-288)
  WST-034:
    default: ABSENT
    variants:
      apache: MANUAL         # (*) 수동
      iis: DET
      webtob: MANUAL
  WST-102:
    default: ABSENT
    variants:
      apache: DET
      iis: DET               # 버그수정 후 DET
      webtob: DET
    bug: WST-102-iis-polarity  # 이미 등재(DET_SOURCE.yaml:282-284)
```
- **default=ABSENT** 원칙: 함수 없는 variant(tomcat/jeus 전부, webservice 대부분)는
  variants에 미등재 → classify가 default(ABSENT) 반환 → gate 차단. tomcat/jeus는 전 WST에서
  ABSENT(파서 없음).
- variant키는 **반드시 profile.WEBWAS.variants 키와 일치**(apache/iis/webtob/tomcat/jeus/
  webservice). base.classify의 엔진토큰 폴백(`base.py:101-104`)은 `_`가 없으면 미발동 —
  웹키엔 `_` 없으므로 직접 매칭만 사용. ✅

---

## 4. 버그수정 계획 (VENDOR-EDIT(c), KNOWN_BUGS 이미 등재)

### 4.1 WST-102 IIS 역전 — 확정 버그, 코드만으로 수정 가능
**위치**: `WST_IIS_parse.py:688-689`(벤더본 동일 라인).
```python
# 버그(원본):
if not vulnerability_condition_result_model_list:
    result = "Y"   # ← 위반 0건인데 취약으로 역전! (양호여야 함)
```
**수정**(VENDOR-EDIT(bug): WST-102-iis-polarity):
```python
if not vulnerability_condition_result_model_list:
    result = "N"   # 위반 0건 → 양호 (KNOWN_BUGS §2 corrected)
```
- **Apache/WebtoB의 WST-102는 정상**(검증: `WST_Apache_parse.py:395-407` 정상 polarity,
  `WST_WebtoB_parse.py:292-307` 정상). → IIS만 수정.
- KNOWN_BUGS.md §2(`:68-104`)에 corrected-동작 명세 이미 존재. (d)회귀테스트 핀 추가.

### 4.2 WST-040 IIS — 코드 polarity + xlsx 기준역전 (이중 문제)
**위치**: `WST_IIS_parse.py:524-580`.
- **코드 polarity 검토 결과**: `has_match and count>0`(`.asa/.asax` 매핑 존재) → 취약 Y
  (`:572-575`), `not has_match`(섹션 없음) → 양호(`:569-571`). 코드 자체는
  **판단방법(requestFiltering에서 .asa/.asax 허용=취약)과 일관** — polarity 명백 오류 아님.
  단 `has_match and count==0`(섹션 있고 매핑 없음)에서 vul_list에 항목을 추가(`:560-566`)한 뒤
  `else`(`:576-578`)에서 양호 처리 — **vul_list 비어있지 않은데 result=N** 모순 가능.
  실해(實害)는 낮으나 KNOWN_BUGS §3 등재대로 `# VENDOR-EDIT(bug)` 주석 + (d)테스트로 핀.
- **xlsx 기준역전(§17.6.4)**: xlsx 웹 시트 WST-040 row의 양호/취약 판단기준 문구가 코드
  판단방법과 역전 의심. **코드만으로 못 고친다** → 아래 처리.

**WST-040 xlsx 역전 처리방안 (코드로 수정 불가)**:
1. webwas.yaml WST-040에 `label: A`(LLM 폴백 보류) 또는 **`label: C`(canned 판단보류)**로
   두고, DET_SOURCE는 `iis: MANUAL`로 **강등**(결정론 비활성). 이유: xlsx 기준이 역전이면
   결정론 verdict가 어느 방향이든 xlsx와 충돌 → 거짓판정. **사용자 확인 전까지 결정론 금지.**
2. webwas.yaml에 **`needs_user_confirmation: "WST-040 xlsx 판단기준 양호/취약 역전 의심 —
   기준셀 정정 필요(§17.6.4)"`** 주석 명시(추적). KNOWN_BUGS.md §3에 사용자확인 대기 표시.
3. xlsx 정정 확인 후에만 `iis: DET`로 승격 + 코드 polarity 최종 확정.

> ⚠️ **권장**: WST-040은 본 Phase에서 **결정론 비활성(MANUAL→LLM/canned)**. 단일샘플이
> apache_linux라 IIS WST-040은 어차피 검증 불가(§8). 안전측.

### 4.3 검증된 무버그 항목
- Apache WST-102/WebtoB WST-102: 정상(수정 불필요).
- WST-040은 IIS 전용 → apache_linux 검증타깃에서 미발동(영향 0).

---

## 5. 어댑터 설계 — `det_adapters/webwas.py`

### 5.1 형태 선택: **server.py 재사용형 + 디스패처 가미**
server.py(per-item check 함수 직접 호출)와 container.py(단일 main 함수) 중 **server형**.
근거: WST check 함수가 개별 호출 가능한 순수함수(§0.3)이고, OS 항목은 server 어댑터에
직접 위임(§2.1)하므로 server 패턴이 자연스럽다. container의 단일-main형은 dict 입력을
요구해 부적합(§0.4).

### 5.2 어댑터 골격
```python
# det_adapters/webwas.py
from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate
from judge_tool.det_adapters import server as _server  # OS 항목 위임

_OS_VARIANTS = frozenset({"aix","hpux","linux","solaris","win"})
_WEB_VARIANTS = frozenset({"webservice","apache","webtob","iis","tomcat","jeus"})

# 웹 특화 항목별 파서 모듈 라우팅 (variant → vendor 모듈)
def _wst_module(web_variant):
    if web_variant == "apache":  from ...webwas import WST_Apache_parse as m; return m
    if web_variant == "iis":     from ...webwas import WST_IIS_parse as m;    return m
    if web_variant == "webtob":  from ...webwas import WST_WebtoB_parse as m; return m
    return None   # tomcat/jeus/webservice → 파서 없음 → ABSENT

def judge(item_id, raw_output, variant, thresholds, *, context=None):
    # ── OS 항목: server 어댑터 위임 (§2.1) ──
    if item_id.startswith("SRV-"):
        os_variant = variant if variant in _OS_VARIANTS else "linux_unknown"
        # server.gate가 SRV DET_SOURCE로 판정 — 그대로 위임
        return _server.judge(item_id, raw_output, _normalize_os(variant), thresholds, context=context)

    # ── 웹 특화: gate(WST DET_SOURCE) 선확인 (§18.1 C1) ──
    gate_result = gate(item_id, variant)          # base.gate: WST DET_SOURCE 조회
    if gate_result is not None:
        return gate_result                        # 비-DET → handled=False

    # DET 확인됨. 파서 모듈 선택
    web_variant = variant if variant in _WEB_VARIANTS else None
    mod = _wst_module(web_variant)
    if mod is None:
        return _absent("웹서버 종류 미상 또는 파서 없음")   # handled=False

    fn = getattr(mod, "check_" + item_id.replace("-", "_"), None)
    if fn is None:
        return _absent("check 함수 없음")          # handled=False

    try:
        result, reason, vul_list = fn(raw_output)
    except Exception:
        return _absent("결정론 함수 예외")          # handled=False, 경고로그

    return _map_result(item_id, variant, result, reason, vul_list, raw_output)
```

### 5.3 `_map_result` = server.py §5.4 매핑 + 가드 재사용
server.py의 매핑 로직을 **그대로 복제**(또는 base로 추출 후 공유 — §5.5):
- `(*)` in reason and result != 'Y' → handled=False (Low-1 가드, `server.py:140-148`).
- result=='N' → **증거존재 가드**(`_has_collection_evidence`, `server.py:40-57`) 적용 후
  양호. 단 웹용 증거 패턴 보강 필요(§6.3).
- result=='Y' → 취약 + citations(`_citations_from_vul_list`, `server.py:60-75`).
- result in ('','M') → handled=False.

### 5.4 OS 항목 위임의 증거가드
server 어댑터에 위임하면 server의 증거가드가 자동 적용(SRV 항목엔 `$ cmd`/`[S]` 블록
패턴이 실데이터에 존재 — §0.1 검증). 추가 작업 0.

### 5.5 리팩터링 권고 (선택, simplify 단계)
server.py의 `_has_collection_evidence`/`_citations_from_vul_list`/`_map_result` 로직을
`det_adapters/_common_mapping.py`로 추출해 server·webwas 공유. **단 Phase 3 핵심 아님** —
먼저 복제로 동작 확보 후 simplify에서 통합(회귀위험 최소화).

---

## 6. 입력 브리지

### 6.1 raw_evidence 분리 (§7) — **webwas_xml.py 수정 필요(현재 미적용)**
`webwas_xml.py:142-151`은 `evidence=masked_output`만 설정, **`raw_evidence` 미설정**.
server_xml/container_xml 선례대로 추가:
```python
masked_output = _mask_server_evidence(raw_output) if raw_output else raw_output
resources.append(ResourceEvidence(
    resource_id=f"{cid}#{n}", status="", detail="",
    evidence=masked_output,
    raw_evidence=raw_output or None,   # ← §7 신규: 결정론 전용 비마스킹
))
```
`_raw_evidence_for_det`(`main.py:395-406`)가 이를 읽어 어댑터에 공급. evidence(마스킹)는
LLM/citation 경로 유지. 누출 경계테스트(server 선례 `test_server_xml_raw_evidence`) 동형 추가.

### 6.2 detect_variant 실데이터 정합 (검증됨)
`web_apache-s-sample.xml`은 `<os>Linux</os>`만 보유, `<webserver>`/`<variant>`/`<app>` 없음
(§0.1). `webwas_xml.detect_variant`(`:98-126`)는:
- `<variant>` 없음 → 스킵.
- `<os>Linux</os>` → `_OS_VARIANTS` 매칭 → **`linux` 반환**(`:113-117`).
→ **즉 실데이터는 `linux`(OS variant)로 detect된다.** 웹 항목(WST)도 이 linux variant로
  들어온다 → §2.3 `_resolve_web_variant("linux")` = OS키 → 웹서버 미상 문제.

**처리**: detect_variant에 **웹서버 추론 폴백** 추가 — `<os>`만 있고 raw에 apache/httpd/
nginx 프로세스 흔적이 있으면 웹키 우선. 그러나 단일샘플 검증 범위에선:
- **권장**: WST 항목 판정 시 raw_output에서 웹서버 종류를 추론(`_infer_web_from_raw`):
  raw에 `apache2`/`httpd` → apache, `IIS`/`applicationHost` → iis, `webtob`/`wsm` → webtob.
  실데이터 WST-033 raw에 `apache2`/`dpkg ... apache`(`:1941-1948`) 존재 → apache 추론 가능.
- 또는 사용자가 `--variant apache` 명시. detect가 linux만 잡으므로 **WST 항목엔 raw 추론
  폴백이 실용적**. §9 R-INFER 리스크.

### 6.3 증거존재 가드 — 웹 패턴 보강
server의 `_RE_CMD_PROMPT`(`^\s*[$#]\s+\S`)는 WST raw에도 적용됨(WST-038 raw에 `$ ls`
존재, `:2077`). 단 config-항목(WST-035 등)은 config 본문 부재 시 "구문 없음→취약"으로
빠지므로(§0.4), 증거가드가 양호 거짓을 막아도 **취약 거짓은 못 막는다**. → §6.4.

### 6.4 ★config-항목 거짓판정 방어 (§0.4 함정 — 최우선)
config-항목(WST-031/035/036/037/038/039/102)은 raw blob에 **config 본문이 없으면**
거짓취약(035: LimitRequestBody 없음→취약) 또는 거짓양호(038: Directory 정규식 미매치→양호).
방어 설계:
- **(권장) config 본문 존재 휴리스틱 가드**: WST config-항목은 raw에 해당 config 시그니처
  (`ServerTokens`/`<Directory`/`LimitRequestBody`/`DocumentRoot`/`User `/`Group ` 등 항목별
  키워드)가 1개도 없으면 → **handled=False**(수집 미흡 → LLM/수동). server의
  `_has_collection_evidence`와 동형이되 **항목별 config 시그니처 사전**을 둔다.
  ```python
  _WST_CONFIG_SIG = {
    "WST-031": ("<Directory", "Options"),
    "WST-035": ("LimitRequestBody",),
    "WST-036": ("User ", "Group "),
    "WST-037": ("DocumentRoot",),
    "WST-038": ("<Directory", "Options"),
    "WST-102": ("ServerTokens", "removeServerHeader", "httpErrors"),
    ...
  }
  ```
  raw에 시그니처 토큰이 하나도 없으면 "config 미수집"으로 보고 handled=False.
- 이로써 실데이터 WST-035(LimitRequestBody 미존재 + config 본문 없음)가 **거짓취약 대신
  handled=False→LLM 폴백** 된다(거짓취약 차단). WST-038도 동일.
- **이 가드가 Phase 3의 거짓판정 0 핵심**(Phase 1/2의 증거가드에 대응).

---

## 7. 5-way 라벨 — `item_configs/webwas.yaml`

### 7.1 OS 항목 (SRV-*) — server.yaml 복사
케이스(2)(시트 SRV+WST 혼재)면 server.yaml의 SRV-* 블록 전체를 webwas.yaml에 복사
(label + judgment_method:det_common 포함). 위임 대상이 server 어댑터라 동일 라벨이어야 함.
케이스(1)이면 §2.5대로 WST OS-ID로 name 매핑 후 동일 라벨 부여.

### 7.2 웹 특화 항목 라벨
| WST | judgment_method | label | 근거 |
|---|---|---|---|
| WST-031/032/033/035/037/038/041/042/043 | det_common | A | DET-PARTIAL, handled=False시 LLM |
| WST-034/039 | det_common | A | apache/webtob MANUAL→LLM, iis DET |
| WST-036 | det_common | A | `$`환경변수→(*)→LLM |
| WST-040 | (det 비활성) | **C 또는 A** | §4.2 xlsx역전 — canned 보류 또는 LLM, **결정론 금지** |
| WST-044 | (없음) | **C** | 전파서 MANUAL, §15.1 기본계정 크랙류 → canned(LLM 호출X) |
| WST-102 | det_common | A | DET-PARTIAL(IIS 버그수정 후) |
| WST-080 | (없음) | **D** | 보안패치 ABSENT → canned(eol/patch) |
| WST-121~125 | (없음) | A | ABSENT(파서 없음) → §15.4 일부 LLM 가능(WST-125 등) |
| WST-126 | (없음) | **D** | EOL → canned |

- **WST-044=C**(§16.1 검증됨): tomcat/JEUS 기본계정 PW — 크랙류, LLM도 불가.
- **WST-080/126=D**: 패치/EOL, 사용자지정 판단보류 고정.
- **WST-121~126 GAP**(§15.5): 파서 미구현. WST-125는 §15.4 LLM 가능(label A),
  WST-121~124는 수집/파서 부재 → 기본 A(LLM)로 두되 증거 없으면 LLM이 판단보류.
- label A 기본 = handled=False/ABSENT 시 `_det_common_label_route`가 LLM 폴백.

### 7.3 라벨 원칙 (container.yaml 선례)
DET_SOURCE(코드 근거)가 결정론 권위. label은 폴백 경로. D/B 강등 금지(§5.1 코드 우선) —
단 WST-040은 xlsx오류라 예외적으로 결정론 비활성(사용자확인 대기).

---

## 8. 검증계획

### 8.0 ★착수 전 필수 (criteria ID dump)
`read_xlsx.py` 패턴으로 웹서버-WAS 시트의 실제 ID 목록(SRV/WST 혼재 여부)을 dump.
→ §2.5 케이스(1)/(2) 확정. **이게 0번 액션**(나머지 설계가 여기 의존). criteria xlsx는
현재 ref/에 부재(gitignore 대용량) → 사용자에게 경로 요청 또는 기존 위치 확인.

### 8.1 실데이터 결정론 판정 (apache_linux 단일샘플)
`collected/web/apache_linux/web_apache-s-sample.xml`:
- **OS 항목(SRV 67건)**: server 어댑터 위임 → Phase 1 SHIP과 동일 결과 기대(이미 검증된
  로직). linux variant로 SRV-001/004/.../082/083 등 양호, SRV-069 등 취약(실데이터 정오).
- **웹 항목(WST 6건: 033/034/035/038/044/102)**:
  - WST-033(apache 버전 2.4.52): `check_WST_033` → 2.1 이상 → **양호** 기대.
  - WST-034: apache MANUAL `(*)` → handled=False → LLM.
  - WST-035: config 본문 없음 → §6.4 가드 → **handled=False**(거짓취약 차단) ✅.
  - WST-038: config 본문 없음(디렉터리 리스팅만) → §6.4 가드 → handled=False ✅.
  - WST-044: MANUAL(C) → canned 판단보류.
  - WST-102: apache, config 본문 없음 → §6.4 가드 → handled=False.
- **거짓양호/거짓취약 0** 확인이 SHIP 기준(Phase 1/2 동일).

### 8.2 단위테스트 (신규 `tests/test_det_adapters_webwas.py`)
- 어댑터 등록 확인(`_DET_ADAPTERS["webwas"]` callable).
- SRV-* 위임 경로(server 어댑터 호출 spy).
- WST DET-PARTIAL variant 분기(apache/iis/webtob).
- §6.4 config 시그니처 가드(양성/음성).
- WST-102 IIS 버그수정 회귀((d), KNOWN_BUGS §2 corrected) — IIS 위반0건→양호.
- WST-040 결정론 비활성 확인((e) STUB/MANUAL 비양호).
- 증거가드/Low-1 가드(server 동형).
- raw_evidence 누출 경계(`test_webwas_xml` 확장).

### 8.3 단일샘플 한계 명시
- **apache+linux만** 보유. iis/tomcat/jeus/webtob·타OS(aix/hpux/solaris/win) 샘플 **없음**.
- IIS 버그수정(WST-102/040)은 **실데이터 검증 불가** — 합성 픽스처(IIS config 문자열)로만
  단위테스트. WST-040 xlsx역전은 사용자 확인 전까지 미해결.
- DET-PARTIAL의 iis/webtob 경로는 합성 픽스처 검증, apache만 실데이터.

---

## 9. 리스크

| ID | 리스크 | 영향 | 완화 |
|---|---|---|---|
| **R-DUAL** | criteria 웹 시트 ID 체계 미확정(SRV+WST? WST만?) | OS 항목 매칭 전부 좌우 | §8.0 착수 전 dump 필수. 케이스별 §2.5 분기 |
| **R-CONFIG** | config-항목에 config 본문 부재 → 거짓취약(035)/거짓양호(038) | 보안도구 최악(거짓판정) | §6.4 config 시그니처 가드(최우선 구현) |
| **R-INFER** | detect가 linux만 잡음 → WST 웹서버 종류 미상 | WST 항목 ABSENT 강등 | §6.2 raw 웹서버 추론 폴백 or --variant |
| **R-040** | WST-040 xlsx 판단기준 역전(코드로 수정 불가) | IIS WST-040 거짓판정 | §4.2 결정론 비활성 + 사용자확인 대기 |
| **R-7ABSENT** | WST-080/121~126 미커버(파서 없음) | 7항목 결정론 불가 | DET_SOURCE=ABSENT + §7.2 라벨(D/A)로 안전 폴백 |
| **R-SAMPLE** | 단일샘플(apache+linux) | iis/webtob/tomcat/jeus·타OS 미검증 | 합성 픽스처 + 한계 문서화(§8.3) |
| **R-MAP** | WST↔SRV name 매핑 오류(케이스1) | OS 항목 오라벨 | name_col 기준 대조, 자동 ID매핑 금지(PROGRESS ⑦) |
| **R-IISBUG** | IIS 버그수정 실데이터 검증 불가 | 회귀 미탐 | (d)회귀 픽스처 핀 + KNOWN_BUGS corrected 단언 |
| **R-DELEG** | 웹키 detect 시 SRV 항목 linux-override 미적용 | SRV-026/069/074/127/131 수동 강등 | §2.3 명시. 실데이터는 linux detect라 무해 |

---

## 10. 구현 순서 (Sonnet 착수 체크리스트)

0. **(필수 선행)** §8.0 criteria 웹 시트 ID dump → §2.5 케이스 확정. **막히면 사용자 확인.**
1. 벤더링 `vendor/common/webwas/`(wslib+3파서, VENDOR-EDIT(a) import). PROVENANCE 갱신.
2. WST-102 IIS 버그수정(VENDOR-EDIT(c), §4.1). WST-040은 결정론 비활성(§4.2).
3. DET_SOURCE.yaml에 WST 웹특화 22항목 등재(§3, variants 맵). 케이스(1)이면 OS-ID 미러링.
4. `webwas_xml.py`에 raw_evidence 분리(§6.1).
5. `det_adapters/webwas.py`(§5): SRV 위임 + WST 디스패처 + §5.3 매핑 + §6.4 config 가드 +
   §6.2 웹서버 추론. `_DET_ADAPTERS["webwas"]=judge` 등록. main.py import 부작용 추가.
6. `webwas.yaml` 5-way 라벨(§7): OS=server 복사, 웹특화=§7.2 표.
7. 테스트(§8.2) + 실데이터 검증(§8.1, 거짓판정 0).
8. `pytest tests/ -q` 전체 그린. PROGRESS.md 갱신.

**불변계약 준수**: results/ 쓰기금지(검증은 collected/ 읽기만), 시스템 python3, det_common은
`_HANDLERS` 기등록(신규 method 추가 없음 — webwas는 어댑터 등록만).

---

## 부록 A — 코드라인 근거 색인 (추측 배제)
- WST 파서 3종만 존재(Tomcat/JEUS 없음): `WebServerConfigLoader/` ls.
- check 함수 시그니처(서버동형): `WST_Apache_parse.py:7,67,83`.
- 2-bucket dispatcher(main): `WST_Apache_parse.py:416-468`, `WST_IIS_parse.py:715-773`,
  `WST_WebtoB_parse.py:313-355`.
- main 입력 dict 키: apache=`data_dict['apache']`(`:450`), iis=`IIS_CONFIG`(`:755`),
  webtob=`webtob`(`:347`).
- (*) 수동 마커: WST-034(`Apache:69`), WST-039(`Apache:357`), WST-044(`Apache:77`),
  WST-036 `$`환경변수(`Apache:207,228`).
- WST-102 IIS 역전버그: `WST_IIS_parse.py:688-689`. Apache 정상: `:395-407`.
  WebtoB 정상: `WST_WebtoB_parse.py:292-307`.
- WST-040 IIS: `WST_IIS_parse.py:524-580`. IIS 전용(Apache/WebtoB 미구현).
- 실데이터 ID 체계(SRV emit + WST 6건): `web_apache-s-sample.xml:1913`(SRV),
  `:1911/1955/2014/2050/2102/2120`(WST). asset=`<os>Linux</os>`만(`:4-10`).
- 실데이터 config 본문 부재: WST-035(`:2016-2045`), WST-038(`:2077-2096` 디렉터리 리스팅).
- webwas_xml raw_evidence 미적용: `webwas_xml.py:142-151`.
- profile.WEBWAS variants/컬럼: `profile.py:498-537`.
- DET_SOURCE 기존 WST 시드: `DET_SOURCE.yaml:282-288`(WST-102/040 bug 필드).
- KNOWN_BUGS WST: `KNOWN_BUGS.md:68-104`(§2 WST-102), `:106-125`(§3 WST-040).
- server 어댑터 매핑/가드(재사용원): `det_adapters/server.py:40-57,60-75,140-202`.
- det_common 핸들러(프로파일 무관 일반): `main.py:428-506`, gate `base.py:160-196`.

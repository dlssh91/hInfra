# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-12 (② ISS_DEVICE VPN/IDS/IPS/DDoS/WAF+generic 구조 완료, 591 tests). 다음 세션에서 이 파일부터 읽고 이어서 진행할 것.
> (한 작업단위 종료 시마다 이 파일을 갱신해 인계. commit/push 안 함 — 문서로만 이어받음.
>  "개발진행해" 트리거는 CLAUDE.md 참조. 이 파일이 단일 진실원천.)

## ▶ 다음 세션 즉시 시작점 (TL;DR)
- **로드맵 실행순서: ① → ③ → ④ → ② → ⑤ → ⑥** (아래 "도메인 로드맵" 참조)
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
  Opus 리뷰 미실시 — 다음 세션에서 진행)
- **다음 착수 = ② ISS_DEVICE Opus 리뷰** → 이후 ⑥ OS 가상화 35항목/3변형 (ESXi) 또는
  **③·④·②·⑤ 활성화 게이트** 중 실수집 데이터 확보 시 먼저 진행.
- **단, ③ 서버·④ 네트워크·② 방화벽은 "실수집 데이터 판정 활성화" 전 게이트 미해결** —
  아래 "③ 서버 활성화 게이트"·"④ 네트워크 활성화 게이트"·"② 방화벽 활성화 게이트" 참조.
- 작업 브랜치: `feat/native-db-variants`.
- **에이전트 규칙(정정)**: 계획·설계=Fable, **구현=Sonnet**, 검토=Opus (CLAUDE.md 참조).

## 도메인 로드맵 (6개 + 실행순서, Fable 우선순위/아키텍처 리뷰 반영)
평가기준 xlsx에 6개 도메인 시트 모두 존재(기존 Profile/VariantSpec 패턴과 동형).
신규 도메인 추가 실비용 = 파서 1 + Profile 1 + item_configs 라벨. 병목은 코드가 아니라
**도메인별 수집 스크립트·골드라벨 데이터 확보**.

| 순 | 도메인 | 상태 | 데이터 | 비고 |
|---|---|---|---|---|
| ① | 판단방식 5분류 정교화(cloud/DB) | **완료** | - | 코어 분류체계, 후속 도메인 라벨 기반 |
| ③ | 서버(OS) 106항목/5변형 | **완료(구조)** | 기준O/샘플X | server_xml 파서+detect_variant seam. 활성화 게이트 미해결(아래) |
| ④ | 네트워크 장비 45항목 | **완료(구조·CISCO+generic)** | 기준O/샘플X | network_xml 파서, cisco+generic(미해당) 변형, applies_when_standard. 활성화 게이트 미해결(아래) |
| ② | 방화벽 이상정책 탐지(정보보호시스템) | **완료(구조·SECUI+ID70+PaloAlto+ISS_DEVICE)** | **샘플O**(정책 20건+, ≥3포맷) | fw_policy.py 결정론 엔진+3종 어댑터+ISS Profile+ISS_DEVICE(VPN/IDS/IPS/DDoS/WAF/generic). Opus리뷰 미실시. 활성화 게이트 미해결(아래) |
| ⑤ | 컨테이너 가상화 50항목/9변형 | **완료(구조·9변형·Opus재리뷰)** | 기준O/샘플X | container_xml PROVISIONAL. 마스킹 정밀화(_is_base64_like). 활성화 게이트 미해결(아래) |
| ⑥ | OS 가상화 35항목/3변형 | 대기 | 기준O/샘플X | ESXi 수집 폐쇄적 |

### ⑤ 컨테이너 가상화 활성화 게이트 (실수집 데이터 판정 활성화 전 필수)
구조/단위테스트+Opus재리뷰 완료(557 tests). [L]잔존: JWT alg:none 미탐(k8s SA토큰 실영향 없음),
EUC-KR 테스트 마스킹검증 보강(기능결함 없음). 아래는 **실제 컨테이너 결과로 판정을 켜기 전** 처리.

1. **수집 포맷 확정(선행조건)** — kubectl 결과를 수집·저장하는 스크립트가 없음. 현재
   파서(container_xml)는 server_xml과 동일 PROVISIONAL XML 엔벨로프 가정. 실수집 방식
   확정 후 포맷 변경 시 Profile.parser 1줄 교체.
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
| 테스트 | **551 passed** (+⑤ 컨테이너 ~65: test_profile_container.py/test_container_xml.py/test_criteria_loader_container.py) |

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

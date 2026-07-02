# 방화벽(FW) 구현설계 — 실검증(Phase A) + 갭메우기(Phase B)

> 작성: 2026-07-02 (Fable 설계). 기준: PROGRESS.md "방화벽 즉시 시작점" + fw_policy.py/fw_policy_xlsx.py 코드 실사.
> 원칙: 순수 결정론(LLM 무관여) 유지 · 탐지=결정론/정당성=사람(needs_review=True) · **거짓양호 봉쇄 최우선** · ref/FW 읽기전용.
>
> **🔒 대외비 경계(2026-07-02 사용자 지시, 절대 준수)**: ref/FW 실데이터는 **헤더 1행(필요시 2행 양식확인)까지만** 사람/LLM 열람 가능. 데이터 행 내용은 Claude·에이전트 컨텍스트로 읽지 않는다(읽었다면 즉시 휘발, 재인용 금지). 파이프라인의 로컬 실행은 허용하되, **산출물(out-dir)도 정책 내용이 담기므로 직접 열람 금지** — 모든 검증·정량화는 "스크립트 내부 계산 → 건수·비율 숫자만 출력" 패턴으로. 보고서·문서·커밋에 실 IP/호스트명/정책명/객체명 금지. (메모리 [[fw-data-confidential-header-only]])

## 0. 현재 상태 (설계 전제)

- `judge_tool/fw_policy.py`(588줄): ISS-030~041 결정론 엔진. Policy 정규화 모델 + sniff_format(SECUI/ID70/PaloAlto/unknown) + `_CAPABILITY` 포맷×항목 맵 + 8개 탐지함수 + `detect_for_iss()` 진입점 + dict 직렬화 왕복.
- `judge_tool/parsers/fw_policy_xlsx.py`(504줄): 포맷별 어댑터(_parse_secui/_parse_id70/_parse_paloalto).
- 실데이터: `ref/FW/보안장비 결과/` P02~P34 정책 export 20건(P15만 csv). P02 실행검증 완료(37/37 판정).
- 알려진 갭: 그룹객체(named object) 미확장→보수 스킵(미탐 방향), ISS-034 완전포함+action상이만, ISS-038/039 aux 필요, ISS-037 SECUI hit-count 부재, unknown 포맷→보류.

## ✅ Phase A 실검증 결과 (2026-07-02 Opus 검토 완료 — 대외비 경계 준수, 숫자만 집계)

- **기준 파일 정정(중요)**: `ref/FW/22년_...방화벽 정책_....xlsx`는 평가기준이 아니라 **정책 데이터 성격 파일**(P001~P219 시트, 대외비). 실제 기준 = `ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx`(정보보호시스템 장비 시트). 이후 모든 실행은 이 경로 사용.
- **일괄 실행**: 20파일 중 **성공 15 / 실패 5**. 성공분은 **전부 SECUI**(37/37 판정, ISS-037만 보류=설계대로). 실패 = 한글 13컬럼 포맷 4건(P13/P14/P24/P25 — sniff 미인식→파서 ReportError **크래시**) + P15 CSV(openpyxl 전용이라 미지원).
- **ID70/PaloAlto 어댑터는 실데이터에서 한 번도 실행 안 됨**(합성 픽스처만 = 실증 공백).
- **그룹객체 미파싱 정량화**: src 2.8%, **dst 35.5%**(파일 편차 큼 — 최대 96.9%), svc 0.0%. → 일부 사이트는 목적지를 거의 전부 named object로 운용 = 해당 파일에서 ISS-030/031/032/034/041 사실상 탐지 불능. **확장 우선순위: dst 주소객체 > src ≫ 서비스객체(불필요)**.
- **Opus 코드리뷰 발견**: [H-1] SECUI 파서가 src_ports를 항상 "any"로 고정(수집 코드 부재) → **ISS-035 전면 거짓양호**. [H-2] 미지원 포맷 = 판단보류가 아니라 파서 크래시(전체 실행 실패). [H-4] IP 대시범위(`a-b`) 미파싱 → 광역/그림자 미탐. [M-1] 광역 임계 /8 과관대(/12~/16 미탐). [M-2] `_policy_covers` 포트 비대칭(lower 전포트+upper 제한 → 거짓 그림자, 오탐 방향). [M-3] src 넓은범위(1024-65535) 지정 미탐. [L] sniff 부분매칭 여지. 직렬화 왕복은 무결.
- **결론**: 현 상태 = "탐지된 취약은 신뢰, 미탐(양호)은 신뢰 불가". 아래 Phase A 하네스는 재실행 가능한 스크립트로 존치시키되, 착수 우선순위는 Phase B'(아래)로 재편.

## Phase B′ — 갭메우기 재우선순위 (Opus 실검증 반영, 이 순서로 구현)

1. **B′-1 [H-2] 미지원 포맷 방어적 강등 + 한글 13열 어댑터 + CSV 분기** ★최우선
   - (즉시) 파서: 전 시트 정책 0건 시 raise 대신 unknown-context emit → 전 항목 판단보류(거짓양호 아님, 침묵 크래시 제거).
   - (이어서) 한글 13열 포맷(`룰 NUM/출발지/목적지/서비스/Protocol/inbound/시간/정책/로그/session-limit/tcp/활성화/설명`) sniff 토큰 + 4번째 어댑터 `_parse_krfw` 추가. capability 맵에 포맷 추가(ISS-033 Two-way 상당 컬럼 유무는 헤더로 확인).
   - CSV: A-3 설계대로 csv.reader 분기.
2. **B′-2 [H-1] SECUI src_port** — 서브헤더에서 출발지 포트 컬럼 매핑 시도, 컬럼 부재가 확인되면 ISS-035 SECUI capability=False(판단보류) 강등. **어느 쪽이든 현 "영구 양호"는 제거**. [M-3]도 같이(넓은 특정범위도 지정으로 간주할지 기준 xlsx 원문 재확인).
3. **B′-3 [H-3] 그룹객체 확장** — 아래 B-1 설계대로. 선행조건: 객체정의 매핑 소스(원본 xlsx 내 객체 시트 존재 여부, **헤더만 열람**으로 확인). dst 주소객체 우선.
4. **B′-4 [H-4]+[M-1]+[M-2] 정밀도 보정** — IP 대시범위 파싱(`ip_range→CIDR 목록` 유틸), 광역 임계 /8→/16 상향(항목별 분리 검토, 기준 xlsx 원문 근거로 확정), `_policy_covers` 포트 비대칭 수정(lower 전포트 ∧ upper 제한 → covers=False).
5. 이후 기존 B-2(aux)~B-5(cov 계약) 순.

## Phase A — 실데이터 전수 검증 (P02~P34)

### A-1. 배치 검증 하네스
- 스크립트: `scripts/fw_batch_validate.py` (신규, judge_tool 코어 무변경).
  - `ref/FW/보안장비 결과/P*.xlsx|csv` 전수 순회 → `judge_tool.main` 호출(out-dir는 `out/fw_batch/PXX`, ref/FW 밖).
  - 파일별 수집 지표: (a) 실행 성공/예외, (b) sniff 포맷, (c) ISS 항목별 verdict 분포, (d) 파싱 행수/드롭 행수, (e) **named-object 추정 토큰 비율**(아래 A-2).
  - 산출: `out/fw_batch/summary.md` 집계표(민감 IP 미포함 — 건수·비율만).
- 통과 기준: 20/20 파일 무예외 실행, 포맷 오식별 0(unknown은 허용하되 사유 기록), verdict 분포가 포맷별로 설명 가능.

### A-2. 파서 계측(instrumentation) — 그룹확장 우선순위의 정량 근거
- `fw_policy_xlsx.parse()`에 `parse_stats` 추가(가산적, 기존 반환계약 유지):
  `{rows_total, rows_parsed, rows_dropped, ip_tokens_total, ip_tokens_unparsed, port_tokens_total, port_tokens_unparsed}`.
- "unparsed" 판정 = `_is_any()` 아님 ∧ `ipaddress.ip_network()` 실패 (IP측) / `_parse_port_range()` 빈집합 ∧ any 아님 (포트측) → named object 후보.
- 이 통계를 metadata로 요약시트에 노출 → 운영자가 "이 파일은 그룹객체 비율 n%라 미탐 위험" 인지 가능.

### A-3. P15_정책.csv 지원
- 파서가 xlsx 전용이면: csv 분기 추가(`csv.reader` → rows 튜플화 후 기존 `_detect_format_from_rows` 재사용). openpyxl 경로와 동일 파이프라인. 의존성 추가 없음(stdlib csv).

## Phase B — 갭메우기 (우선순위순)

### B-1. 그룹객체(named object) 확장 ★최우선
**문제**: 실 정책은 주소/서비스 그룹을 다용 → 현재 파싱 실패 시 스킵(보수) → ISS-030/031/032/034/036/041 **미탐** + 위반 0건이면 "양호" 표기 = **사실상 거짓양호**.

**설계**:
1. **ObjectTable 모듈** (`judge_tool/fw_objects.py` 신규):
   - `AddressObjects: Dict[name, List[cidr_str]]`, `ServiceObjects: Dict[name, List[port_spec]]`.
   - 소스 2계층: ① 정책 export xlsx 내 객체/그룹 시트 자동 발견(시트 헤더 sniff — SECUI export는 주소객체·서비스객체·그룹 시트 동반이 일반적, Phase A에서 실파일 시트명 확정), ② `--aux-objects <파일>` CLI 명시 지정(①이 없을 때).
   - 중첩 그룹: 재귀 해석 + visited-set 순환가드 + 깊이 상한(예 8).
2. **해석 패스**: 파서가 Policy 생성 후 `resolve_policies(policies, table)` 1회 호출.
   - 각 IP/서비스 토큰: 파싱 가능 → 그대로 / 테이블 매칭 → 멤버 CIDR·포트로 **치환(확장)** / 둘 다 실패 → `Policy.unresolved_src/dst/svc` 목록에 보존(신규 필드, 기본 빈 리스트 — `policy_from_dict` `.get()` 패턴으로 하위호환).
3. **거짓양호 봉쇄 규칙(핵심 계약)**: `detect_for_iss()`에서 해당 항목의 판정 관련 필드에 unresolved 토큰이 있는 정책이 존재하고 **위반 0건**이면 verdict를 `양호`가 아니라 **`판단보류`**로 강등 + rationale에 "미해석 객체 n건 → 양호 단정 불가" 명시. 위반이 이미 1건 이상이면 취약 유지(미해석은 추가 미탐 가능성만 부기).
   - 항목별 관련 필드: 030/031/041/034=src+dst(+svc), 032/036=svc(dst_ports), 033/035/037=해당 없음(그대로).
4. **테스트**: 합성 픽스처(더미IP)로 (a) 그룹→확장→탐지 성공, (b) 중첩그룹, (c) 순환그룹 안전, (d) 미해석→양호 강등, (e) 직렬화 왕복(신규 필드 포함) — polarity 계약 테스트는 B-5와 통합.

### B-2. ISS-038/039 --aux 연계
- `--aux-assets <자산목록.xlsx>`: ref/FW의 "점검대상" 시트가 자산목록 역할(PROGRESS 확증) → 서버IP/접근통제시스템IP 목록 추출 스키마 확정(Phase A에서 실파일 헤더 확인).
- ISS-038(서버 IP 접근정책): aux 제공 시 capability True로 승격 — 탐지 = dst∈서버IP ∧ (src 광역 ∨ dst_ports 과다/any) 허용정책. 미제공 시 현행 판단보류 유지.
- ISS-039(접근통제시스템 경유): 토폴로지 판단은 자동화 신뢰 불가 → aux 있어도 **후보 나열 + 판단보류**(인터뷰 요약형, 자동 취약/양호 금지). label C 유지.

### B-3. unknown 포맷 → 로컬 LLM 헤더매핑 폴백 (v2, 사용자 기승인 컨셉)
- 흐름: sniff=unknown → **헤더 행만**(데이터 비전송) qwen3-coder:30b에 제시 → `{원본헤더→정규화필드}` JSON 매핑 수신 → 필수필드(action, src_ips, dst_ips, dst_ports) 충족 시 generic 어댑터로 파싱.
- 가드: (a) 매핑은 산출물 metadata에 기록(감사가능), (b) capability는 매핑된 필드로 답 가능한 항목만 True, (c) 전 판정 needs_review + rationale에 "LLM 헤더매핑 기반" 명시, (d) LLM 실패/불충분 → 현행 판단보류 폴백. 판정 로직 자체는 여전히 결정론.

### B-4. iss.yaml 비정책 항목(ISS-001~029, 040, 042~043) 라벨분류
- 정책 export에는 계정·로깅·패치 증거가 없음 → 현행 "증거 미수집 자동보류"가 정답 동작. 기준 xlsx C18/C19 원문 정독 후 B(인터뷰)/C(기술한계)/D(패치·EOL, [[patch-eol-baseline-policy]]) 전수 라벨링. ISS-043=label A 유지(증거 미수집→보류).
- 주의: label B 항목에 `judgment_method` 잔존 금지(DBM-020 사고 패턴).

### B-5. FW 양극성 커버리지 계약 테스트 (도메인 공통 프로토콜 준수)
- `tests/fw_cov_contract.py` + `tests/test_fw_cov_fixtures.py` (srv/db cov 패턴 동형): ISS-030~037/041 × good/vuln 합성 픽스처 쌍(더미IP), 포맷 3종 각각. 038/039/040은 판단보류 고정 계약. 미커버 극성은 사유 명시.

### B-6. 후순위(백로그 유지)
- ISS-034 부분겹침 correlation(현재 완전포함+action상이만) — 오탐 위험 대비 가치 낮음, 그룹확장 후 재평가.
- ISS-037 SECUI 대체판정 — hit-count 원천 부재, 인터뷰 유지.
- ISS-036 Xmanager 버전 — 자산 데이터 없이는 불가, 포트 대체탐지 유지.
- VPN/IDS/IPS/DDoS/WAF 5변형 — 샘플 부재, 잔여도메인 설계문서(2026-07-02-remaining-domains-design.md) §4 참조.

## 실행 순서 및 SHIP 조건
1. A-1~A-3(배치 하네스+계측+csv) → Sonnet 구현 → Opus 리뷰.
2. B-1 그룹확장(계측 수치로 시급성 확정 후) → Sonnet 구현 → Opus 리뷰 → 재검증(A 배치 재실행, 판정 변화 diff).
3. B-5 계약 테스트 → B-2 → B-4 → B-3.
- SHIP 조건: 전체 pytest 통과 + P02~P34 재배치에서 예외 0 + 그룹확장 전후 diff가 "미탐→탐지/보류" 방향만(양호→취약 뒤집힘은 전건 수동확인) + 거짓양호 방향 회귀 0.

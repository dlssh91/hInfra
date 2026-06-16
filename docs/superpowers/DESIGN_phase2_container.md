# 설계: Phase 2 — 컨테이너(PRCC) common 결정론 통합

> 작성: 2026-06-16 · 상태: **설계(미구현)** · 설계자: Opus(Fable 대체) · 구현자: Sonnet
> 상위 계약: `DESIGN_common_deterministic_integration.md` §5/§9/§17.5/§18 + Phase 1(서버) SHIP 패턴.
> 트리거: PROGRESS.md TL;DR "★다음 착수 = Phase 2 컨테이너(PRCC)".
> **이 문서는 Sonnet이 그대로 구현 가능한 구체 계획서다.** 코드라인 인용으로 추측을 배제했다.

---

## 0. Phase 1과의 핵심 구조 차이 (반드시 먼저 이해)

서버 패턴을 "그대로 재사용"하되, **autoAnalysis.py의 구조가 서버와 근본적으로 다르다**.
이 차이가 어댑터 설계의 거의 전부를 결정한다.

| 측면 | 서버(Phase 1) | 컨테이너(PRCC, Phase 2) |
|---|---|---|
| 함수 형태 | 항목별 `check_SRV_NNN(output)` 개별 함수 | **단일 거대 함수** `autoAnalysis(sApp, vulKey, vulOutput)` (1812줄, PRCC+PRCV 공용) |
| 분기 방식 | 함수명으로 항목 선택 | 함수 **내부** `if/elif "PRCC-NNN" in vulKey` 체인 + **그 안에서 다시** `if "<variant>" in sApp` 분기 |
| 변형 처리 | linux 5항목만 별도 모듈(`SRV_Linux_parse`) | **모든 항목이 variant별 분기를 내장** → 본질적으로 전 항목이 DET-PARTIAL 후보 |
| 반환 타입 | `(result, reason, vul_list)` 튜플 | **`{"result": "N"|"Y"|"M", "point": str}` dict** (`autoAnalysis.py:30,1812`) |
| 수동 표기 | `reason`에 `(*)` 마커 (`(-)` 없음) | **`result="M"`** 직접 반환. `(*)` 마커 관습 **없음** |
| 미분기 기본값 | 함수가 명시 반환 | **`{"result":"N","point":""}` 디폴트**(`:30`) → 분기 미스 시 조용히 "N=양호" (★거짓양호 핵심 위험) |
| vul_list | 구조화 dict 리스트 | **없음** — `point`는 단일 누적 문자열(`",".join`식, `:1811`서 trailing `,` 제거) |

→ **결론**: 서버 어댑터의 `_LINUX_OVERRIDE_ITEMS` 모듈선택·`vul_list` citation 추출·`(*)` 가드는
컨테이너에 **그대로 못 쓴다**. 컨테이너 어댑터는 (a) 단일 함수 1회 호출, (b) `result=="M"`을
수동 신호로, (c) **`point` 문자열을 citation으로**, (d) **디폴트-N 거짓양호를 DET_SOURCE 게이트로 차단**한다.

---

## 1. 벤더링 범위/방안

### 1.1 결정: autoAnalysis.py **파일 전체** 벤더링 (PRCV 포함, 미사용)

근거(코드 확인):
- PRCC(`autoAnalysis.py:37~1212`)와 PRCV(`:1215~1804`)는 **같은 `autoAnalysis` 함수 본문**에 산다.
  함수를 쪼개 PRCC만 추출하면 원본과 diff가 커져 스냅샷 동기화 추적(PROVENANCE)이 어렵고,
  `parseOutput`(`:8-24`)·`autoTarget`(`:32`)·try/except 래퍼(`:35,1807`)를 재구성해야 한다.
- **전체 벤더링이 원본 비트 보존에 유리**(Phase 1 sclib와 동일 원칙). PRCV 분기는 컨테이너 variant로는
  도달 불가(`vcenter/esxi/xenserver` 토큰)하므로 PRCC 호출 시 **부작용 없음**.

**방안**: `judge_tool/vendor/common/container/autoAnalysis.py`에 원본 복사.
- 의존성: 표준 라이브러리만 — `import re, json, traceback`(`:1-3`). **Django/lxml 의존 0건.** import 경로 수정 불필요.
  → VENDOR-EDIT(a)(import 경로) **불필요**. 원본 비트동일 복사 가능.
- `parseOutput`은 PRCC에서 실사용되지 않으나(대부분 `in vulOutput` 문자열매칭) 함께 복사(원본 보존).

### 1.2 PRCV elif 버그는 **절대 건드리지 말 것**

- `PRCV-027~036` 도달불가 버그(`autoAnalysis.py:1678` indent16, PRCV-026 esxi블록 내 중첩)는
  **PRCV 영역**이며 이미 `KNOWN_BUGS.md §4 PRCV-027-036-unreachable` + `DET_SOURCE.yaml`(PRCV-027~036
  = UNREACHABLE)에 등재됨(`KNOWN_BUGS.md:134-157`, `DET_SOURCE.yaml:283-310` 확인).
- **Phase 2 범위 아님.** 벤더링 시 버그를 포함한 채 그대로 복사하고, 수정/회귀테스트 추가도 하지 않는다.
  (PRCV 결정론 복구는 Phase 5의 별도 작업. 여기서 손대면 회귀 위험 + 범위 침범.)

### 1.3 VENDOR-EDIT 계획

| 편집 | 적용 여부 | 사유 |
|---|---|---|
| (a) import 경로 | **불필요** | stdlib만 의존(`:1-3`) |
| (b) 임계값 상수화 | **불필요(Phase 2)** | §4 참조 — PRCC 임계값은 권한 정수컷(PRCC-007 `>600` 등)으로 xlsx와 별도 대조 전까지 하드코딩 유지. divergence 미발견 시 편집 없음 |
| (c) 버그수정 | **없음** | PRCC에 KNOWN_BUGS 등재 버그 없음(아래 1.4). PRCV 버그는 범위 밖·미수정 |

→ **벤더 코드는 원본 비트동일 복사가 목표.** `PROVENANCE.md`에 원본 경로
(`flus-main/app/common/PrivatecloudConfigLoader/autoAnalysis.py`)·날짜·"편집 없음(비트동일)" 기록.

### 1.4 PRCC 영역 버그 점검 결과 (벤더링 전 확인됨)

전수 리뷰(설계서 §17.2)가 PRCC에서 식별한 것은 **PRCC-024 ocp_master leaf 그림자(무해)** 1건뿐:
- `autoAnalysis.py:795-797` `elif "ocp_master"` 블록은 `:782`의 `if "k8s_master" or "ocp_master"...`에서
  **선매칭**되어 도달 불가하나, 항목 분류·verdict에 **영향 없음**(§17.2 "무해"). 수정 불필요, 그대로 복사.
- 그 외 PRCC 분기에 polarity 역전·오타 버그 **없음**(서버 SRV-010 같은 Critical 부재).

---

## 2. DET_SOURCE PRCC 분류 방법론

> 방법론·스키마·함정은 본 절(설계)이 확정한다. **50항목 전수 값 작성은 Sonnet**이 코드 근거로 수행한다.

### 2.1 분모 확정 (결번 확인)

- xlsx 컨테이너 항목 = **PRCC-001~050, 50개**(설계서 §17.1 "PRCC 50개", 결번 없음).
- common `autoAnalysis.py`에 PRCC-001~050 **전 항목 elif 분기 존재**(`:37~1212`, grep로 050까지 확인).
  → **ABSENT(함수없음)는 PRCC에 0건**(서버와 달리 전 항목 분기 존재).

### 2.2 분류 라벨 = §18.0 5종 (+DET-PARTIAL)

`DET` / `STUB` / `UNREACHABLE` / `ABSENT` / `MANUAL` / `DET-PARTIAL`. PRCC 실제 분포 예상:
- **ABSENT=0, UNREACHABLE=0, STUB=0**(PRCC 분기에 lambda:True·빈본문·도달불가 없음 — 1.4 확인).
- **MANUAL**: 항목의 **모든 활성 variant가 `result="M"`** 인 경우(예: PRCC-039는 k8s/ocp/eks/aks_master 전부 M,
  docker만 DET → 따라서 MANUAL이 아니라 DET-PARTIAL).
- **DET-PARTIAL(핵심, §17.5 "DET-PARTIAL 9")**: variant에 따라 일부는 DET·일부는 `M` 반환.
- **DET**: 활성 variant 전부가 결정론 N/Y 반환(M 분기 없음).

### 2.3 ★variant 키 정확 일치 + sApp 토큰 함정 (Critical)

**common `sApp`(`autoAnalysis.py:32` autoTarget)와 profile.CONTAINER.variants 키가 다르다.**

| profile.CONTAINER 키(`profile.py:421-447`) | common `in sApp` 토큰(`:32`) | 매칭 |
|---|---|---|
| k8s_master / k8s_worker | `"k8s_master"` / `"k8s_worker"` | ✅ 정확 |
| eks_master / eks_worker | `"eks_master"` / `"eks_worker"` | ✅ |
| aks_master / aks_worker | `"aks_master"` / `"aks_worker"` | ✅ |
| ocp_master / ocp_worker | `"ocp_master"` / `"ocp_worker"` | ✅ |
| **docker_linux** | **`"docker"`** (`if "docker" in sApp`) | ⚠️ **부분일치로 통과**(`"docker" in "docker_linux"`=True) |

→ **함정**: common은 `in sApp` 부분문자열 매칭. profile 키 `docker_linux`를 sApp로 그대로 넘기면
`"docker" in "docker_linux"`=True라 **정상 동작한다**(어댑터는 ctx.variant를 그대로 sApp로 전달하면 됨).
단 DET_SOURCE.yaml `variants:` 맵의 **키는 profile 키(`docker_linux`)**여야 base.py `classify()`가 조회한다
(`base.py:99` `if variant in variants_map`). **common 토큰(`docker`)을 DET_SOURCE 키로 쓰면 안 됨.**

### 2.4 variants 맵 스키마 (Sonnet이 채울 틀)

각 PRCC 항목을 variant별로 분류. base.py `classify()`는 `variants[variant]` 직접조회(`:99`) →
엔진토큰폴백(`:102`, `_`split) → `default`(`:106`) 순. 컨테이너는 variant가 완전키이므로 **default 불필요**(생략 시 미지variant→ABSENT=안전).

```yaml
# DET_SOURCE.yaml — 컨테이너(PRCC) 섹션 (Sonnet 작성, 본 스키마 준수)
  PRCC-001:
    variants:
      k8s_master: DET        # :38 "ROLE: cluster-admin" 매칭 → N/Y
      eks_master: DET        # :38 동일 분기(or조건)
      aks_master: DET
      ocp_master: DET
      # worker/docker_linux 미기재 → classify=ABSENT → gate 차단(평가대상 아님, 안전)
  PRCC-004:
    variants:
      k8s_master: MANUAL     # :83-85 result="M"
      ocp_master: DET        # :87-94 token-auth-file 매칭 → Y
    # → 항목 전체 분류는 DET-PARTIAL이나, DET_SOURCE는 variant별 값으로 표현
    #   (base.py classify가 variant별로 DET/MANUAL을 정확 반환 → gate가 variant별 처리)
  PRCC-039:
    variants:
      k8s_master: MANUAL     # :1054-1056 M
      ocp_master: MANUAL
      eks_master: MANUAL
      aks_master: MANUAL
      docker_linux: DET      # :1058-1063 HostConfig.Devices 매칭 → Y
```

**핵심 설계 결정**: DET-PARTIAL을 **항목 단위가 아니라 variant 단위 값**으로 인코딩한다.
- base.py `classify(item, variant)`는 이미 variant별 값을 반환(`:99`)하므로, 활성 variant가
  `DET`면 gate 통과(`base.py:181`), `MANUAL`이면 gate가 handled=False 차단(`:183-196`).
- 이렇게 하면 §18.5(DET-PARTIAL→variant 분기)가 **gate 레벨에서 자동 처리**되어, 어댑터가 별도
  DET-PARTIAL 분기 로직을 둘 필요가 없다. (서버 DET-PARTIAL은 entry default='DET-PARTIAL'로 두고
  Low-1 `(*)` 가드에 의존했으나, **컨테이너는 `(*)` 관습이 없으므로 variant별 명시값이 정답**.)

### 2.5 §16.2 정정3 반영 — GAP 과장 금지 (Sonnet 필수 준수)

설계서 §16.2 정정3: "컨테이너 9건은 주플랫폼 결정론 Y·보조플랫폼만 M". 분류 시:
- **PRCC-010**: k8s_master=DET(`:482-492` audit-log-path), k8s_worker=DET(`:494-505`),
  ocp_master=DET(`:507-517`), **ocp_worker=MANUAL**(`:519-521` M). → 주플랫폼 DET, ocp_worker만 M.
- **PRCC-011**: docker_linux만 분기(`:524-531`). docker는 `not matches or json-file`→Y, else→**M**.
  → docker_linux는 **DET-PARTIAL의 변종**(같은 variant 안에서 Y 또는 M). 보수적으로 **MANUAL 분류 권장**
  (M 경로 존재 → gate 차단 → LLM 폴백이 안전). ⚠️ "주플랫폼 DET" 단정 금지 — docker가 유일 활성이고 M 경로 있음.
- **PRCC-018**: k8s_worker=**MANUAL**(`:713-715` M, §16.2 "k8s_worker 분기 존재" 확인),
  ocp_worker=DET(`:717-720`), eks_worker=DET(`:722-728`), aks_worker=DET(`:730-733`). → worker 도메인 항목.
- **PRCC-024**: master 4종 = "No resources"→Y else→**M**(`:782-788`) → **DET-PARTIAL/MANUAL 혼합**.
  docker_linux=DET(`:790-793` enable_icc). ⚠️ §15.4는 PRCC-024=A(LLM)로 분류 → **master는 M 경로가
  지배적이므로 MANUAL**, docker만 DET. (No resources일 때만 Y라 부분결정론이나, else=M이 흔함 → MANUAL 보수분류.)
- **PRCC-036**: k8s_master=DET(`:1000-1006` sock 매칭), docker_linux=DET(`:1008-1011`),
  **ocp_master=MANUAL**(`:1013-1015`). → 주플랫폼 DET, ocp만 M. §15.4 PRCC-036=A는 **과대** — k8s/docker는 DET.

→ **Sonnet 지침**: §15.4의 A 분류(PRCC-024/036)를 맹신하지 말고 **코드 분기를 1순위 근거**로 삼아라.
master/docker가 DET면 DET로 분류(GAP 축소). M 경로만 있는 variant만 MANUAL.

### 2.6 예상 분포 (Sonnet 검산용, 코드 근거)

- ABSENT 0 / UNREACHABLE 0 / STUB 0.
- 순수 DET(전 활성 variant N/Y): ~35~40항목.
- DET-PARTIAL(variant 맵에 DET+MANUAL 혼재): ~9항목(§17.5 "DET-PARTIAL 9" 정합 — PRCC-004/010/011/018/024/036/039 등).
- 전 활성 variant MANUAL: §17.5 "MANUAL-ALL 0" → **0항목 예상**.
- **D(EOL/버전)**: PRCC-004는 §15.4서 "버전조건부 D" 언급되나 **코드는 k8s=M/ocp=DET**(버전판정 아님).
  → DET_SOURCE는 코드대로(k8s=MANUAL, ocp=DET), **D 라벨은 container.yaml에서 별도 판단**(§5).

---

## 3. 어댑터 설계 — `det_adapters/container.py`

### 3.1 전체 구조 (서버 어댑터 골격 재사용, 호출부만 교체)

```python
"""컨테이너(PRCC) 결정론 어댑터 — Phase 2 (§5.2/§18, autoAnalysis 단일함수 브리지)."""
import logging, re
from typing import Optional
from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS, gate

log = logging.getLogger(__name__)

def judge(item_id, raw_output, variant, thresholds, *, context=None) -> ForcedVerdict:
    # ── §18.1 C1 게이트 (DET/DET-PARTIAL만 통과; MANUAL/ABSENT/STUB 차단) ──
    gate_result = gate(item_id, variant)
    if gate_result is not None:
        return gate_result

    # ── 증거 부재 가드 (디폴트-N 거짓양호 차단, §3.4) ──
    if not _has_collection_evidence(raw_output):
        return _review("[증거 부재: 수집 출력 없음 — 자동 양호 불가]", item_id, variant)

    # ── 단일 함수 호출 (sApp=variant, vulKey=item_id, vulOutput=raw) ──
    from judge_tool.vendor.common.container import autoAnalysis as _mod
    try:
        res = _mod.autoAnalysis(variant, item_id, raw_output)   # dict 반환
    except Exception as exc:
        log.warning("container autoAnalysis 예외 item=%s variant=%s: %s", item_id, variant, exc)
        return _review(f"[결정론 함수 예외] {type(exc).__name__}", item_id, variant)

    result = (res or {}).get("result", "")
    point  = (res or {}).get("point", "") or ""

    # ── §5.4 매핑 (M=수동, Y=취약, N=양호) ──
    if result == "M":
        return ForcedVerdict("판단보류", 0.0, f"[수동 판단 필요] {point[:200]}", [], "review", False)
    if result == "Y":
        return ForcedVerdict("취약", 0.9, point[:200] or "(-) 취약으로 판단",
                             _citations_from_point(point), "bad", True)
    if result == "N":
        return ForcedVerdict("양호", 0.9, point[:200] or "(+) 양호로 판단", [], "good", True)
    # 빈/기타
    return ForcedVerdict("판단보류", 0.0, f"[미결정: result={result!r}] {point[:200]}", [], "review", False)

_DET_ADAPTERS["container"] = judge   # profile.CONTAINER.key == "container"
```

### 3.2 item_id → 함수 매핑 (서버와 다름)

- 서버: `getattr(_mod, "check_"+id)`. **컨테이너: getattr 없음** — `autoAnalysis(variant, item_id, raw)`
  한 함수가 `if "PRCC-NNN" in vulKey`로 내부 분기(`:37~`). 어댑터는 **item_id를 vulKey로 그대로 전달**.
- ⚠️ `in vulKey` 부분문자열 매칭이므로 item_id는 정규화된 `"PRCC-001"` 형태여야 한다
  (normalize_id가 PRC-C-001→PRCC-001 변환 완료 — `profile.py:39-45` 확인). crit.item_id는 이미 정규화됨.

### 3.3 9변형 DET-PARTIAL 처리 = **gate에 위임**(§2.4 설계 결정)

- 어댑터는 DET-PARTIAL 분기 로직을 **두지 않는다**. base.py `gate(item, variant)`가 variant별
  DET_SOURCE 값을 보고: DET→통과, MANUAL→차단(handled=False)을 이미 수행(`base.py:160-196`).
- 활성 variant가 MANUAL인 항목(예: PRCC-039 k8s_master)은 gate가 호출 전 차단 → autoAnalysis 미호출.
- 활성 variant가 DET인 항목(예: PRCC-039 docker_linux)은 gate 통과 → autoAnalysis가 Y/N 반환.
- **이중 안전망**: 설령 DET_SOURCE 분류가 느슨해 MANUAL variant가 gate를 통과해도, autoAnalysis가
  `result="M"`을 반환하면 §3.1 매핑이 handled=False로 차단(M→판단보류). → 거짓양호 2중 방어.

### 3.4 증거 부재 가드 (★컨테이너 최우선 — 디폴트-N 거짓양호)

**서버보다 위험이 크다**: autoAnalysis 디폴트가 `{"result":"N"}`(`:30`)이고, 대부분의 PRCC 분기는
"위반 발견 시 Y, 아니면 디폴트 N 유지" 구조다. 즉 **수집 실패(빈출력)·미매칭 variant도 N(양호)으로 떨어진다**.
- gate가 1차 방어(미지 variant→ABSENT→차단)이나, 활성 variant라도 **빈 출력이면 N=양호 거짓판정** 가능.
- **`_has_collection_evidence(raw_output)` 가드 필수**(autoAnalysis 호출 **전** 차단):
  - 컨테이너 출력 증거 패턴(샘플 `fsec-control-plane-...xml` 기준): `# Command :` 라인,
    `F_PRC_C_NNN` 헤더, `[X]`/`flag:` 마커, `kubectl`/`docker` 토큰, `-----` 구분선 중 1개 이상.
  - 빈 출력·공백뿐·`No result`만 있는 경우 → handled=False(LLM 폴백). ⚠️ 단 `No result`는 일부 항목
    (PRCC-018 eks/aks)에서 **취약 증거**이므로, "증거 패턴"은 명령흔적(`# Command`/`F_PRC_C`)으로 판정하고
    `No result` 자체를 증거부재로 보지 말 것(과차단 방지). → 패턴은 **수집 실행 흔적**만 본다.
- Sonnet: 서버의 `_has_collection_evidence`(`server.py:40-57`)를 컨테이너 패턴으로 재작성.
  실데이터(k8s_master 샘플)로 전 활성 항목이 패턴 1개 이상 보유함을 검증(과트리거 0).

### 3.5 호출 시그니처 브리지

- common `autoAnalysis(sApp, vulKey, vulOutput)`. 어댑터는 `autoAnalysis(variant, item_id, raw_output)`.
  - `sApp = ctx.variant`(profile 키, 예 `"k8s_master"`/`"docker_linux"` — §2.3 docker 부분일치 OK).
  - `vulKey = item_id`(정규화 `"PRCC-001"`).
  - `vulOutput = raw_output`(비마스킹 raw_evidence, §4).
- common이 `vulOutput.split('######')[0]`로 설명부 제거(`:31`) — 샘플에 `######` 존재(12건 확인)하므로
  **어댑터는 raw를 그대로 넘기고 분할은 common에 맡긴다**(원본 동작 보존).
- `thresholds`·`context`는 PRCC에서 **미사용**(common이 임계값을 코드 하드코딩, §4) → 시그니처 통일성
  위해 받되 전달 안 함. (향후 임계값 divergence 발견 시 §4 워크플로로 주입.)

### 3.6 citation 추출 = `point` 문자열 분할 (vul_list 없음)

- 서버는 `vul_list` dict에서 추출(`server.py:60-75`). **컨테이너는 vul_list 없음** —
  `point`이 `"증거1,증거2,..."` 누적 문자열(`:125,1811`). `_citations_from_point(point)`:
  `point.split(",")` → strip → 빈문자 제거 → 최대 20개. raw_output 누출 아님(common이 가공한 point만 사용).

### 3.7 마스킹 경계 (§7, kubectl secret)

- 결정론은 **비마스킹 raw_evidence**를 받는다(§4). citation은 common이 만든 `point`만(secret값 미포함 —
  point는 "sock이 마운트된 컨테이너 존재" 식 서술). raw_output 원문은 ForcedVerdict로 **나가지 않음**.
- container_xml은 이미 JWT·k8s Secret base64를 마스킹(`container_xml.py:84-121`). 산출물/LLM/citation
  경로는 마스킹본(`evidence`)만 사용. 어댑터는 `raw_evidence`(비마스킹)를 받아 판정 후 **메모리에서 폐기**.
- 누출 경계 테스트(서버 선례): raw_evidence가 ForcedVerdict.citations/rationale로 새지 않음을 단언.

---

## 4. 입력 브리지 — raw_evidence + ★variant 식별 갭

### 4.1 raw_evidence 분리 필요 여부 → **필요**

- container_xml.parse()는 현재 `_mask_container_evidence`로 **마스킹본만** 싣는다(`:193,200`).
  ResourceEvidence에 `raw_evidence`(비마스킹) 필드 분리 안 됨(server_xml은 Phase 0서 분리 완료).
- **작업**: container_xml.parse()를 server_xml 패턴(PROGRESS Phase 0 ⑤)대로 수정 —
  `evidence=마스킹본`, `raw_evidence=원문`, 빈출력→None. `main._raw_evidence_for_det`가 이를 읽음.
- ⚠️ Sonnet: server_xml의 raw_evidence 분리 구현(`parsers/server_xml.py`)을 참조해 동형 적용.
  비마스킹 raw가 산출물/LLM로 새지 않는 경계 유지(서버 테스트 동형).

### 4.2 ★variant 식별 갭 (실데이터 발견 — Critical 블로커)

**실수집 샘플은 `<asset><app>k8s_master</app>`를 쓴다**(`fsec-control-plane-...xml:10` 확인).
그러나 `container_xml.detect_variant`는 `<asset><variant>`·`<platform>`·`<role>`만 읽고
**`<app>`을 읽지 않는다**(`container_xml.py:147,152-153`). → 샘플에서 detect_variant=**None** →
`--variant k8s_master` 강제 없이는 ReportError.

**조치(택1, Sonnet 구현)**:
- **(권장) detect_variant에 `<asset><app>` 폴백 추가**: `<variant>` 직접키 → **`<app>` (`_DIRECT_VARIANT_MAP` 재사용)**
  → `<platform>+<role>` 순. `<app>` 값(`k8s_master`)이 `_DIRECT_VARIANT_MAP` 키와 일치하므로 1줄 추가로 해결.
  PROGRESS ⑤ 활성화게이트 3번("detect_variant 실데이터 검증") 충족.
- (대안) 검증은 `--variant k8s_master` 명시로 진행하고, `<app>` 폴백은 별도 증분. → 검증이 막히므로 비권장.

→ **이 갭은 Phase 2 검증의 선결조건.** 미해결 시 §6 검증 불가.

### 4.3 출력 정합 확인

- common 입력 = raw 문자열(`vulOutput`). container_xml 출력 = ResourceEvidence.evidence/raw_evidence(문자열).
  → 자연 일치(§8 "컨테이너 raw str = 낮음" 난이도). 단 한 항목에 ResourceEvidence 여러 개일 수 있음
  (cid별 카운터 `:195-197`) — 어댑터는 main이 합친 raw_evidence를 받는다(`_raw_evidence_for_det` 계약).

---

## 5. 5-way 라벨 계획 — `item_configs/container.yaml`

Phase 1 server.yaml 규칙(`server.yaml:11-18`) 준용. 50항목 전수 라벨링(현재 전부 암묵 A):

| 규칙 | 처리 | PRCC 적용 |
|---|---|---|
| classify==DET(전 활성 variant) | `judgment_method: det_common` + `label: A`(폴백) | 순수 DET ~35~40항목 |
| DET-PARTIAL(variant 맵 DET+MANUAL 혼재) | `judgment_method: det_common` + `label: A` | DET variant는 결정론, MANUAL variant는 gate차단→LLM(§3.3). ~9항목 |
| MANUAL(전 활성 variant M) | label A/B/C(§14 라우팅) | PRCC엔 0 예상(§2.6) |
| EOL/버전 | `label: D` | **PRCC-004**(§15.4 "버전조건부") — ⚠️아래 주의 |
| 인터뷰 | `label: B` | **PRCC-039**(§15.4 B 후보 — 단 docker는 DET) |
| 기술한계 | `label: C` | PRCC엔 없음(§15.1 크랙류 부재) |

### 5.1 PRCC 특화 주의 (Sonnet 필수)

- **D = PRCC-004**: §15.4는 "버전조건부 D". 그러나 코드는 k8s_master=M·ocp_master=DET(`:82-94`),
  **버전 판정 아님**. → **충돌**. 권장: DET_SOURCE는 코드대로(k8s=MANUAL/ocp=DET), container.yaml은
  `det_common`+label A로 두되 주석에 "§15.4 D언급 vs 코드 M/DET 불일치 — 코드 우선" 명기.
  (D 고정은 "EOL/패치 자동확정 금지"용인데 PRCC-004는 EOL이 아니므로 D 부적합.)
- **B = PRCC-039**: §15.4 B(인터뷰). 코드는 master=M·docker_linux=DET(`:1053-1063`). →
  `det_common`+label A. docker_linux는 결정론 Y, master는 gate(MANUAL)차단→label A폴백(LLM). B 고정은
  docker 결정론을 버리므로 부적합 → **A 폴백 권장**.
- **A = PRCC-024/036**: §15.4 A. 코드상 §2.5대로 master/docker DET 다수 → `det_common`+label A.
  DET variant는 결정론, M variant는 LLM 폴백.

→ **원칙(설계서 §13.2 권위원칙 재확인)**: 결정론 분류는 **코드(DET_SOURCE)**가, 폴백 라벨은 §14/§15가
정한다. 둘이 충돌하면(PRCC-004) **코드 결정론을 살리고 label은 A 폴백**(D 강등은 결정론 손실).

### 5.2 yaml 스키마 (server.yaml 동형)

```yaml
PRCC-001:
  judgment_method: det_common
  label: A                  # DET(master 4종); 비활성 variant는 gate→LLM
PRCC-004:
  judgment_method: det_common
  label: A                  # DET-PARTIAL(k8s_master=M→gate차단→LLM / ocp_master=DET). §15.4 D는 코드불일치
PRCC-039:
  judgment_method: det_common
  label: A                  # DET-PARTIAL(master 4종=M→LLM / docker_linux=DET)
# thresholds: PRCC는 코드 하드코딩(§4) — 현재 미주입. divergence 발견 시 추가.
```

---

## 6. 검증 계획

### 6.1 단일 샘플(k8s_master)로 검증 가능한 것

샘플 `collected/container/k8s_master/fsec-control-plane-k8s_master-20260615.xml`
(IDs: PRC-C-001~047 중 36건 수집, 파서검증 통과). 검증 항목:
1. **변수 식별(4.2 선결)**: detect_variant가 `<app>k8s_master`로 `k8s_master` 반환(폴백 추가 후).
2. **k8s_master DET 항목 결정론 판정**: PRCC-001(cluster-admin 존재→**취약** 예상, 샘플에 "ROLE: cluster-admin" 有),
   PRCC-010(audit-log-path), PRCC-012(tls), PRCC-036(sock) 등 → verdict가 코드 분기대로 나오는지.
3. **증거존재 가드**: 전 활성 항목이 `# Command`/`F_PRC_C` 흔적 보유 → 과트리거 0. 빈입력 합성→handled=False.
4. **gate**: k8s_worker/docker 전용 항목(예: PRCC-011 docker, PRCC-018 worker)을 k8s_master로 조회 시
   DET_SOURCE에 해당 variant 미기재→ABSENT→gate 차단(평가대상 아님, 정상).
5. **거짓양호 0**: result=N으로 나온 항목이 **실제 양호 증거 보유**함을 사람이 정오 확인(서버 Phase 1 방식).

### 6.2 pytest 그린 + 신규 테스트

- `tests/test_det_adapters_container.py`(서버 test 동형): autoAnalysis 매핑(N/Y/M)·gate·증거가드·
  citation분할·누출경계. DET_SOURCE 음성테스트(MANUAL variant→handled=False, §18.6 e).
- `python3 -m pytest tests/ -q` 전체 그린(어댑터 미등록 항목 불변 + 신규 그린).

### 6.3 단일 샘플 한계 (명시)

- **worker/eks/aks/ocp/docker 샘플 없음**. → 이 variant의 DET-PARTIAL 분기는 **코드리뷰로만 분류**,
  실데이터 검증 불가. container.yaml/DET_SOURCE는 코드근거로 작성하되 "k8s_master 외 미검증" 명기.
- PROGRESS 활성화게이트 ⑤의 1(수집포맷)·4(detect_variant)는 k8s_master 한정 충족. 타 variant는 게이트 잔존.

---

## 7. 리스크

| # | 리스크 | 완화 |
|---|---|---|
| R1 | **디폴트-N 거짓양호**(autoAnalysis `:30`) | gate(미지variant→ABSENT 차단) + `_has_collection_evidence`(빈출력 차단) + result="M"매핑. 3중 방어. ★최우선 |
| R2 | **GAP 과장**(§16.2) | DET_SOURCE를 §15.4 분류가 아니라 **코드 분기 1순위**로 작성. master/docker DET면 DET(§2.5) |
| R3 | **PRCV 혼입** | autoAnalysis 전체 벤더링하되 PRCV 분기 미수정·미호출. PRCV 버그(KNOWN_BUGS §4)는 범위 밖, 건드리지 않음 |
| R4 | **단일 샘플** | k8s_master만 실검증. 타 variant는 코드리뷰 분류 + 게이트 잔존 명시(§6.3) |
| R5 | **variant 키 불일치**(§2.3) | DET_SOURCE 키=profile키(`docker_linux`), sApp 전달=profile키(common `in` 부분일치로 OK). 혼동 금지 |
| R6 | **variant 식별 갭**(§4.2) | `<app>` 폴백 detect_variant 추가(선결). 미해결 시 검증 불가 |
| R7 | 마스킹(kubectl secret) | raw_evidence 비마스킹 판정·즉시폐기, citation=point만, 누출 경계 테스트(§3.7) |

---

## 8. Sonnet 구현 순서 (TL;DR)

1. **벤더링**: `vendor/common/container/autoAnalysis.py` 원본 복사(비트동일, stdlib만) + `__init__.py` +
   PROVENANCE 기록. PRCV 미수정.
2. **DET_SOURCE.yaml**: PRCC-001~050 variants맵 작성 — **코드 분기 1순위**(§2.4 스키마, §2.5 GAP금지, §2.6 분포).
3. **container_xml**: raw_evidence 분리(§4.1) + detect_variant `<app>` 폴백(§4.2).
4. **det_adapters/container.py**: §3 골격(단일함수 호출·M매핑·point citation·증거가드) + `_DET_ADAPTERS["container"]` 등록.
   main.py 상단에 부작용 import 추가(서버 선례).
5. **container.yaml**: 50항목 5-way 라벨(§5, 코드 우선·D/B 강등 금지).
6. **테스트**: `test_det_adapters_container.py` + k8s_master 샘플 실검증(거짓양호 0) + `pytest -q` 전체 그린.
7. **PROGRESS.md 갱신**: 완료내역·다음착수·잔존게이트(타 variant 미검증).

> 검토 사이클: Sonnet 구현 → Opus 리뷰(특히 R1 거짓양호·R2 GAP·R3 PRCV혼입·R7 마스킹) → 개선 → 재리뷰.

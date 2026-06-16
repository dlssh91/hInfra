# 설계: common 결정론 판정 로직 통합 (결정론 우선 + LLM 폴백)

> 작성: 2026-06-16 · 상태: **설계(미구현, Opus 최종리뷰 반영)** · 트리거: 사용자 "common의 결정론
> 소스를 가져가고, 결정론으로 안 되는 것만 LLM" 방향 검토 요청.
> ⚠️ **확정 계약(§17.6/§18): "그대로 가져간다"가 아니라 "검증·수정 후 가져간다"** — common은 실버그
> 보유(§17.2). 결정론 가용도는 도메인별 편차 큼(§17.5). 정규 설계는 §18이 §5/§9/§10/§12를 갱신.
> 설계 에이전트 규칙상 Fable이어야 하나 `claude-fable-5` 미접근 → 메인 루프(Opus)가 작성.

## 0. 사용자 고정 결정 (이 설계의 제약)
1. **전 도메인 공통 레이어를 먼저 설계**하고, 도메인은 그 위에 순차 적용한다.
   (도메인별 개별 설계 금지 — 공통 어댑터 프레임 + `det_common` 핸들러가 1순위 산출물)
2. **임계값/판정값의 권위 = 평가기준 xlsx**("xlsx 기준 우선"). common이 코드에
   하드코딩한 임계값(서버 90일/900초 등)을 암묵 상속하지 않는다.
3. **벤더링 = `judge_tool/vendor/common/` 복사**(§5.1 확정).
4. **마스킹 = 결정론에 비마스킹 raw 공급 허용**(§7 옵션 1 확정). 속도 차이 없음 —
   마스킹본은 길이/내용 기반 check(SRV-070 등)에서 오판하므로 raw가 정확도상 필수.
   산출물·LLM·citation에는 마스킹본만 나간다(누출 경계 테스트 필수).
5. **DB도 타 도메인과 동일 정책**(§9 Phase 3 정정): "common이 수동/인터뷰로 둔 항목만
   LLM, 나머지는 결정론"은 전 도메인 균일. DB만 이미 검증된 LLM 산출물(661 테스트)이
   있을 뿐 → 듀얼런은 *별도 정책이 아니라* 전환 시 기존 결과/테스트 불변 확인용 안전장치.

## 1. 한 줄 결론
방향이 맞고, judge_tool의 `_HANDLERS`(judgment_method→핸들러) + label 라우팅이 정확히
이걸 위한 구조다. `fw_policy`가 동일 패턴의 선례다. common의 핵심 판정 함수는 Django-free라
재사용 가능하다. 두 프로젝트는 **같은 점검항목 표준**을 공유한다(아래 §2). 따라서 통합은
"신규 엔진 추가" 패턴(`_HANDLERS` 등록 + `classify_method`/yaml 라벨)으로 깔끔히 들어간다.

핵심 제약 3가지: **(A) 마스킹 순서**, **(B) 임계값 권위=xlsx와 common 하드코딩의 충돌**,
**(C) 도메인별 입력 형태 차이**. 모두 §5~§8에서 다룬다.

## 2. 결정적 근거 — 항목 체계 일치
| 도메인 | common | judge_tool |
|---|---|---|
| 서버 | `check_SRV_001~` 103개 | `server.yaml` "106 SRV" / profile.SERVER |
| DB | `dbm_001,003,004,005,...` | `DBM-001,003,004,005,...` (정확 일치) |
| 웹 | `check_WST_NNN` | webwas (WST-001~126) |
| 네트워크 | `NETNNN` | network (NET, col18/19 공유) |
| 컨테이너 | `PRCC-NNN`(autoAnalysis) | container (PRCC, normalize PRC-C→PRCC) |

→ common은 "어떤 항목이 결정론 가능 / 어떤 항목이 수동인가"의 **사실상의 정답지**다.
`server.yaml`의 TODO("실수집 후 C/D/B 분류")를 common이 추정이 아닌 근거로 채워준다.

## 3. judge_tool 측 통합 지점 (확인된 사실, file:line)
- `_HANDLERS` 디스패치: `main.py:376-383`, 호출 `main.py:480-481`. 미등록 method는
  경고 후 `_judge_one`(LLM) 폴백(`main.py:477-480`).
- `classify_method`: `criteria_loader.py:23-41`. label C/D→`det`, B→`interview(_holdonly)`,
  A→`llm`/`llm_det`. **yaml `judgment_method:`가 classify_method를 우회**(`criteria_loader.py:96-99`).
  → 신규 method는 이 우회 밸브로 항목에 부여한다(fw_policy=ISS-030 선례).
- 결정론 핸들러 참조 구현: `_fw_policy_handler`(`main.py:273-369`). 패턴:
  1) 결정론 엔진 호출(`fw_policy.detect_for_iss`),
  2) 탐지결과를 합성 `ResourceEvidence`(status good/bad)로 래핑 →
     reconcile의 "증거 없음 → 판단보류 강제" 가드(`judge.py:473-478`) 통과,
  3) `forced={verdict,confidence,rationale,cited_evidence}`로 `reconcile()` 호출,
  4) `j.needs_review=True` 고정("탐지=결정론, 정당성=사람").
- `reconcile`(`judge.py:450-504`): forced dict + item → `Judgment`. 비-cloud/DB 프로파일은
  **`status_available=False`**(profile.py)이므로 `expected is None` → `needs_review=True`가
  **자동**(judge.py:487). 즉 서버/네트워크/웹/컨테이너/가상화/ISS는 결정론이든 LLM이든
  모든 판정이 이미 사람 검토 대상이다. 결정론의 가치는 "LLM 추측" 대신 **신뢰 가능한
  시작 verdict(양호/취약)** 를 검토자에게 제공하는 것.
- 입력 브리지의 사실:
  - `server_xml.parse()`(`parsers/server_xml.py:170-198`)는
    `ResourceEvidence(evidence=masked_output)`로 항목별 **raw 명령출력**을 보존한다.
    common의 `check_SRV_NNN(output:str)`이 원하는 바로 그 형태 → 브리지가 자연스럽다.
  - 단 `parse()`가 `_mask_server_evidence()`로 **마스킹을 선적용**한다
    (`server_xml.py:185`). → §5 제약 A.

## 4. common 측 재사용 대상 (확인된 사실)
- 판정값 인코딩: `Y`=취약, `N`=양호, `M`/`수동`/`(*)`(단 `(-)` 없음)=수동필요(verdict 클리어).
  근거: `sclib.parseAnalysisResult`의 `if "(*)" in reason and not "(-)" in reason: result=''`
  (`ServerConfigLoader/sclib.py:344-346`).
- Django-free 핵심:
  - 서버: `check_SRV_NNN(output)->(result,reason,vul_list)` + `sclib` 순수 헬퍼
    (`get_check_service`/`get_check_file_perm`/`get_remove_line`/`split_output`,
    `sclib.py:17-35`). stdlib(re/json/datetime)만 의존.
  - DB: `MySQLAnalysis` 등 — 순수, 임계값을 `modules/config/*-config.json`의
    `rules`/`exception`에서 로드. `Config` 클래스가 경로 prefix를 하드코딩(추출 시 수정).
    DBM-001은 빈 결과(수동 해시크랙).
  - 네트워크: `NetworkConfig.py:NETNNN(ldRaw, Raw, optional_info)` — 순수지만
    **벤더 파서(`ml_Cisco.py` 등)로 사전 파싱된 dict가 선행 필요**.
  - 컨테이너/사설클라우드: `PrivatecloudConfigLoader/autoAnalysis.py` — 순수
    문자열매칭/임계값, 20개 `"M"`(수동) 분기.
  - 퍼블릭클라우드: `PublicCloudConfigLoader/autoAnalysis.py`는 **상위 PISM 스캐너가
    이미 정한 status(bad/good)를 재인코딩**할 뿐 — 독립 판정 아님.
- 재사용 불가: `*lib.parseAnalysisResult`/`util.py`의 Django ORM·settings 의존 부분
  (`sclib.py:6-12` import 참조) → judge_tool writer로 대체.

---

## 5. 공통 레이어 설계 (1순위 산출물)

### 5.1 벤더링 (import 경로 vs 복사)
**결정: 벤더링(복사)**, `judge_tool/vendor/common/` 아래에 Django-free 모듈만.
- 이유: `../common`은 레포 **밖** 형제 디렉터리(.gitignore 대용량 자산, 항시 존재 보장 X).
  CLI가 상대경로 sibling에 의존하면 깨지기 쉽다. common은 frozen 스냅샷(4월)이라 churn 낮음.
- 포함: `vendor/common/server/`(SRV check 함수 + sclib 순수 헬퍼),
  `vendor/common/db/`(*Analysis + config json), 이후 도메인별 추가.
- 제외: 모든 `parseAnalysisResult`, `util.py`의 Django 부분, `flus.settings` 참조.
- 수정 최소화 원칙: 벤더 코드는 **원본 보존**. 허용되는 편집은 2종뿐 —
  (a) `Config` 하드코딩 경로 prefix 제거/주입, (b) **임계값 상수화**(§6).
  각 편집은 파일 상단 `# VENDOR-EDIT:` 주석 + `vendor/common/PROVENANCE.md`에
  원본 경로·날짜·편집 사유를 기록(스냅샷 동기화 추적).

### 5.2 도메인 어댑터 인터페이스 (통일 계약)
벤더 코드의 도메인별 형태 차이를 흡수하는 얇은 어댑터를 도메인마다 둔다.
`judge_tool/det_adapters/<domain>.py`. 통일 시그니처:

```python
# det_adapters/base.py
@dataclass
class ForcedVerdict:
    verdict: str          # "양호"|"취약"|"판단보류"
    confidence: float     # 결정론 성공=0.9, 수동/판정불가=0.0
    rationale: str        # 한국어 근거(common reason → 정제)
    citations: list[str]  # 위반 증거 인용(취약 시)
    ev_status: str        # "good"|"bad"|"review"  (합성 ResourceEvidence용)
    handled: bool         # False면 이 항목은 결정론 대상 아님 → 호출부에서 LLM 폴백

def judge(item_id: str, raw_output: str, variant: str,
          thresholds: dict, *, context: str | None = None) -> ForcedVerdict: ...
```
- 어댑터가 common 함수를 호출하고, common의 `(Y/N/M/(*))`을 `ForcedVerdict`로 매핑.
- `handled=False`는 "이 항목은 common이 수동으로 둠" 신호 → §5.4에서 LLM/인터뷰로 보냄.

### 5.3 단일 핸들러 `det_common`
`_HANDLERS["det_common"] = _det_common_handler` 하나만 추가(메서드 폭증 없음).
도메인 분기는 핸들러가 아니라 **어댑터 레지스트리**가 한다.

```python
_DET_ADAPTERS = {            # profile_key → adapter.judge
    "server": server_adapter.judge,
    "webwas": webwas_adapter.judge,
    "db_mysql": db_adapter.make("mysql"), ...
}

def _det_common_handler(crit, item, ctx):
    adapter = _DET_ADAPTERS.get(ctx.profile_key)
    if adapter is None:
        return _judge_one(crit, item, ctx)          # 안전 폴백
    raw = _raw_evidence_for_det(item)                # §5 제약 A: 비마스킹 원문
    thresholds = ctx.thresholds.get(crit.item_id, {})# §6: xlsx 권위
    # adapter는 호출 전 DET_SOURCE[item,variant] 확인(§18.1): DET가 아니면
    # (STUB/UNREACHABLE/ABSENT/MANUAL) common 미호출 + handled=False 반환.
    fv = adapter(crit.item_id, raw, ctx.variant, thresholds, context=item.context)
    if not fv.handled:
        # det_common 라벨 = 본래 DET 항목(§18.3 5-way). 여기 도달 = DET+MANUAL의
        # (*) 경로 등 → label A 의도면 LLM, 아니면 §14 라우팅. ABSENT/STUB은 애초에
        # det_common으로 라벨되지 않음(§18.3) → 거짓양호 불가(C1).
        return _judge_one(crit, item, ctx)           # (label A 항목의 (*)→LLM)
    # fw_policy와 동일: 합성 evidence 래핑 → forced → reconcile → needs_review
    ev = EvidenceItem(item_id=crit.item_id, variant=ctx.variant,
        resources=[ResourceEvidence(f"{crit.item_id}-det", fv.ev_status,
                                    fv.rationale[:200], "\n".join(fv.citations[:20]) or "이상 없음")])
    forced = {"verdict": fv.verdict, "confidence": fv.confidence,
              "rationale": fv.rationale, "cited_evidence": fv.citations[:20]}
    j = reconcile(forced, crit, ev, status_available=ctx.profile.status_available,
                  flag_vulnerable_for_review=ctx.profile.flag_vulnerable_for_review,
                  empty_means_good=crit.item_id in ctx.profile.empty_means_good)
    j.label = crit.label
    j.needs_review = True       # 탐지=결정론, 임계값정당성=사람
    return j
```
> `JudgeContext`에 `thresholds`(§6 로딩 결과)를 추가 필드로 싣는다(현재 profile/client/items/
> variant만 있음 — `main.py:46-54`). 기존 핸들러 시그니처 불변.

### 5.4 판정값 매핑 (common → judge_tool)
> ⚠️ **전제(§18.1, Critical)**: 아래 매핑은 `DET_SOURCE[item,variant]==DET`일 때만 적용한다.
> 어댑터는 common 호출 **전에** DET_SOURCE를 확인하고, DET가 아니면(STUB/UNREACHABLE/ABSENT/
> MANUAL) common을 **호출하지 않고 즉시 `handled=False`**. 즉 "아무것도 안 한 N"이 양호로 새지 않는다.

| common (DET_SOURCE=DET 전제) | 조건 | judge_tool ForcedVerdict |
|---|---|---|
| `N` | 양호(실판정) | verdict=양호, ev_status=good, conf=0.9, handled=True |
| `Y` | 취약 | verdict=취약, ev_status=bad, conf=0.9, citations=vul_list, handled=True |
| `M`/`수동` | 수동 | **handled=False** (→ §14 라벨 라우팅) |
| reason에 `(*)` 있고 `(-)` 없음 | 수동 우선 | **handled=False** |
| reason에 `(*)`와 `(-)` 둘 다 | 취약(부분수동) | verdict=취약 + needs_review(이미 True) |
| 빈 결과 + empty_means_good **(소스=DET일 때만)** | 양호 | verdict=양호 (DET_SOURCE>empty_means_good, §18.4) |
| **STUB / UNREACHABLE / ABSENT** | 비결정론 | **handled=False (절대 양호 매핑 안 함, §18.1)** — 호출 전 차단 |
| **DET-PARTIAL** | variant 의존 | 활성 플랫폼 경로 DET면 N/Y 매핑, M-분기면 **handled=False** (§18.5) |
| 함수 예외 | — | handled=False (§14 라우팅, 경고 로그) |

→ "결정론으로 되면(DET) 결정론, 아니면 LLM/인터뷰/canned"이 `DET_SOURCE` + `handled` 플래그로 구현됨.
**핵심**: `N→양호`는 소스가 DET일 때만 — placeholder/도달불가/부재의 N은 매핑 전에 차단(§18.1).

---

## 6. 제약 B — 임계값 권위 = xlsx (가장 어려운 부분)
**문제**: xlsx의 판단기준/판단방법은 **자유서술 한국어 산문**이지 구조화 수치가 아니다.
런타임 산문 파싱은 비신뢰적. common은 서버 임계값을 코드에 하드코딩, DB는 JSON에 둔다.

**설계(현실적 해석)**: "xlsx 권위"는 *런타임 산문 파싱*이 아니라 **사람이 xlsx 산문을 읽고
구조화 임계값으로 옮겨 적은 단일 출처를 judge_tool이 보유**한다는 의미로 구현한다.
- 임계값 저장소: `item_configs/<profile>.yaml`에 항목별 `thresholds:` 블록 신설.
  ```yaml
  SRV-069:
    judgment_method: det_common
    thresholds: { password_max_age_days: 90, complexity_min_classes: 2 }   # ← xlsx 산문 근거
    thresholds_source: "서버 시트 SRV-069 판단기준 셀(2026-1호)"             # 추적용
  ```
- 로딩: `criteria_loader.load_criteria`가 yaml `thresholds`를 `Criterion`(또는 별도 맵)에
  실어 `JudgeContext.thresholds`로 전달.
- 주입: 어댑터가 `thresholds`를 common 함수에 넘긴다.
  - **DB**: 이미 JSON config(`rules`)에서 읽으므로, 우리 yaml→config dict로 매핑해 주입(깨끗).
  - **서버/웹**: common 함수가 임계값을 **하드코딩** → 허용 편집 (b)로 그 리터럴을 모듈
    상수로 끌어올리고(`_TH = {...}`) 어댑터가 호출 전 override. 편집 항목은 `# VENDOR-EDIT`.
- 정합 워크플로:
  1) 도메인 활성화 시 common 하드코딩값을 **초기 default로 시드**(빠른 출발),
  2) 사람이 xlsx 산문과 1:1 대조해 `thresholds` 확정(차이가 있으면 xlsx가 이김),
  3) common값≠xlsx값인 항목은 `thresholds_source`에 명기 + 활성화 게이트 체크.
- **플래그 필요**: common 서버 임계값(90일/900초 등)이 현행 고시(2026-1호) xlsx와
  실제로 다른 항목이 있는지 1차 대조가 선행되어야 함(미확인 — 오픈 질문 Q3).

---

## 7. 제약 A — 마스킹 순서 (신규 발견, 반드시 반영)
`server_xml.parse()`는 핸들러 도달 **전에** `_mask_server_evidence()`로 shadow 해시→
`<REDACTED 해시>`, 32+ hex→`<REDACTED>`로 치환한다(`server_xml.py:106-123,185`).
그런데 common `check_SRV_070`은 `/etc/passwd` **해시 필드 길이(`len>15`)** 로 판정,
다른 check는 키/해시 **존재**로 판정한다. 마스킹된 텍스트를 먹이면 **결정론 판정이 오염**된다.

**설계**: 결정론 핸들러는 **마스킹 전 raw**를 받아야 한다.
- 옵션 1(권장): 파서가 `ResourceEvidence`에 `raw_evidence`(비마스킹) 필드를 **추가**하되,
  산출물/citation/LLM 경로는 기존 `evidence`(마스킹)만 사용. `det_common`만 `raw_evidence`를
  읽는다. 비마스킹 원문이 산출물 xlsx/json·LLM 프롬프트로 **새지 않도록** 경계 테스트 필수.
- 옵션 2: 결정론은 마스킹 토큰을 인지하도록 어댑터에서 보정(취약 — 길이 기반 판정엔 무력).
- **옵션 1 확정**(사용자 결정 #4). 속도 차이 없음 — 정확도 문제. 단 "민감정보를 비마스킹으로
  메모리 보유"가 새 위험 → 결정론 판정 후 즉시 폐기, 산출물엔 마스킹본만. 보안 리뷰(Opus)
  항목으로 명시. raw_evidence가 산출물 xlsx/json·LLM 프롬프트·citation로 새지 않음을
  단위테스트로 강제(누출 경계 테스트).

---

## 8. 제약 C — 도메인별 입력 형태 차이
| 도메인 | common 입력 | judge_tool 공급원 | 브리지 난이도 |
|---|---|---|---|
| 서버/웹 | raw 명령출력 str | `ResourceEvidence.raw_evidence` 연결 | 낮음(자연 일치) |
| DB | 정규화 SQL 행 | `db_json` 파서 출력(evidence_mode=raw) | 중(행 구조 매핑) |
| 네트워크 | 벤더 파서 dict | **벤더 파서도 함께 벤더링 필요** | 높음 |
| 컨테이너/사설클라우드 | raw str | container_xml evidence | 낮음 |
| 퍼블릭클라우드 | PISM status | (해당 없음) | — 포팅 가치 의문 |

---

## 9. 도메인 롤아웃 순서 (결정 #1: 공통 먼저)
> ⚠️ **§18(H3) 정정**: 순서를 §17.5 *결정론 가용도*에 맞춰 재배열. "DB가 가장 깨끗"은 폐기
> (§17.4 STUB 산재). 컨테이너가 가장 깨끗(41/50). 모든 Phase는 §18의 DET_SOURCE 분류 선행.
- **Phase 0 — 공통 레이어**: §5 어댑터 프레임 + `det_common` 핸들러 + 매핑 + `thresholds` 로딩 +
  raw_evidence 분리(§7) + 듀얼런 하니스(§10) + **§18의 `DET_SOURCE.yaml`·`KNOWN_BUGS.md` 선행
  산출**. 어댑터 0개라 **동작 불변**(yaml에 det_common 미부여 → 기존 테스트 그대로 통과).
- **Phase 1 — 서버(파일럿)**: 가치 최대(미활성=전부 LLM). common `check_SRV_*`(+SRV_Linux_parse)
  벤더링 → 어댑터 → `server.yaml` **5-way 라벨링**(§18 H2: DET→det_common / MANUAL·(*)·ABSENT→
  §14 A/B/C/D). SRV-010 버그수정(§18 H1) 포함. 활성화 게이트(PROGRESS ⑤) 동시 충족.
- **Phase 2 — 컨테이너(PRCC)**: **결정론 가장 깨끗(41/50)**, 입력 브리지 낮음(§8). DET-PARTIAL 9건은
  variant 선택(§18 M2)으로 주 플랫폼 결정론 보존. (PRCV 아님 주의 — PRCV는 §18 버그수정 선행.)
- **Phase 3 — 웹(WST)**: 서버와 동일 형태 → 어댑터 재사용. WST-102/040 버그수정(§18 H1) + 미커버 7건 라벨.
- **Phase 4 — DB**: ⚠️ **결정론 패치 많음**(§17.4 STUB 산재) → 엔진별 `DET_SOURCE` 확인 후 **DET 항목만**
  활성. DBM-005 등 STUB은 handled=False(§18 M1). 이미 검증된 LLM 산출물 존재 → **듀얼런으로 전환 후
  불변 확인 필수**. DBM-034/035/036은 소스 없음.
- **Phase 5 — 네트워크 / OS가상화**: 네트워크는 벤더 파서 벤더링 필요(최중량)+EMPTY/COMMENTED 다수.
  OS가상화는 **PRCV-027~036 도달불가 버그(§18 H1) 수정해야 9항목 복구**. 둘 다 후순위.
- **대상 제외**: 클라우드(PISM)는 스캐너 결정론(§17.6.5) → 통합 안 함, 현행 LLM 교차검증 유지.

## 10. 회귀·검증 전략 (불변계약: 전 테스트 통과)
- **격리**: `det_common`은 yaml이 명시한 항목에서만 활성. 미부여 시 경로 미진입 →
  기존 동작/테스트 불변. Phase 0 머지 시점에 661 그린 유지가 수용 기준.
- **듀얼런 하니스**(`scripts/` 신규, `results/` 불가침): 수집 실데이터(`collected/`, `out/`)에
  대해 LLM·결정론 동시 판정 → verdict diff 표 생성. 불일치는 (a)결정론 버그, (b)LLM 오판,
  (c)임계값 불일치(§6)로 분류해 triage. **결정론 전환은 도메인별 게이트 통과 후**.
- **신규 단위테스트**: 어댑터별로 common 로직의 대표 입력→verdict 픽스처 테스트.
  마스킹 비누출 경계 테스트(§7). 매핑 테이블(§5.4) 테스트.
- **CLAUDE.md 준수**: Sonnet 구현 → Opus 리뷰(특히 §7 보안, §6 임계값) → 개선 → 재리뷰.

## 11. 오픈 질문 — 결정 현황
- **Q1 (벤더링)**: ✅ 해결 — `vendor/common/` 복사 채택(결정 #3).
- **Q2 (마스킹 §7)**: ✅ 해결 — 비마스킹 raw 공급 허용(결정 #4). 속도 무관·정확도 필수.
- **Q3 (임계값 §6)**: 🔲 미해결(권장 선행) — common 서버 하드코딩 임계값(90일/900초 등)이
  현행 고시 xlsx와 일치하는지 1차 대조를 Phase 1 착수 전에 수행. Phase 1 첫 작업으로 포함.
- **Q4 (DB §9 Phase 3)**: ✅ 해결 — 전 도메인 동일 정책(결정 #5). DB도 결정론 적용,
  듀얼런은 전환 후 불변 확인용.
- **Q5 (PublicCloud)**: 🔲 미해결 — PISM 재인코딩 포팅 보류(현행 유지) 제안. Phase 5에서 재확인.

## 13. 부록 — 서버 임계값 xlsx 대조 결과 (Q3, 2026-06-16)
대상: common `SRV_auto_parse.py`/`SRV_Linux_parse.py` 하드코딩값 vs 평가기준
`(제2026-1호)` "서버" 시트 linux 판단기준(col21)/판단방법(col22) 산문.

### 13.1 일치 — 그대로 채택 가능 (xlsx=common)
| SRV-ID | 항목 | common 코드 | xlsx(2026-1호) | 판정 |
|---|---|---|---|---|
| SRV-028 | 세션 타임아웃 | TMOUT>900 취약(부재=취약) | 900초 이하 양호 | ✅ 일치 |
| SRV-069 | PW 변경주기 | >90일 취약 | 90일 이하 | ✅ 일치 |
| SRV-069 | PW 복잡도/길이 | 2조합 minlen<10 / 3조합<8 취약 | 2조합 10자·3조합 8자 | ✅ 일치 |
| SRV-074 | 휴면계정 | 로그인/변경 >90일 취약 | 분기(=90일) 1회 | ✅ 일치 |
| SRV-084 | 주요파일 권한 | passwd644/shadow600/inetd600/hosts.lpd640/그외644 | 동일 | ✅ 일치 |
| SRV-108 | 로그 권한 | btmp660/wtmp·lastlog664/그외644 | 동일 | ✅ 일치 |
| SRV-122 | umask | <022 취약 | 022 이상 양호 | ✅ 일치 |
| SRV-014 | NFS 설정파일 권한 | ≤644 | 644 초과 취약 | ✅ 일치 |
| SRV-161 | ftpusers 권한 | ≤640 | 640 이하 양호 | ✅ 일치 |

→ 위 9개 임계값은 `thresholds:` yaml에 common값=xlsx값으로 시드(추가 대조 불필요).

### 13.2 불일치/갭 — xlsx가 이김, Phase 1 처리 필요
| SRV-ID | 항목 | common | xlsx(2026-1호) | 조치 |
|---|---|---|---|---|
| ~~SRV-127~~ | 로그인 실패 잠금 | `deny<1`/미설정만 취약 | col21 판단기준=설정 **존재 여부**(숫자 컷 없음); deny=3/5는 col22 *예시*일 뿐 | ✅ **리뷰 정정(§16)**: 분기 컷은 col21에 없음 → common(존재=양호)이 binding 기준과 **일치**. divergence 아님 |
| **SRV-081** | crontab 권한 | at/cron.allow·deny 640 검사 | crontab 명령어 **750 이하** + at/cron 640 | ⚠️ crontab 바이너리 750 검사 **누락 의심** — 어댑터에서 보강 또는 LLM 폴백 |
| **SRV-006** | SMTP 로그수준 | sendmail≥9·exim<5 검사 | + postfix `debug_peer_level≥2` | ⚠️ postfix 분기 **누락 의심** — 보강 또는 폴백 |
| **SRV-075** | PW 복잡도 | 수동 stub(auto-Y 없음) | 2조합10자·3조합8자 임계 존재 | ℹ️ 임계충돌 아님 — common은 동일 로직을 SRV-069에 둠. 라벨링 시 075→det_common(069 로직 재사용) 또는 A 검토 |
| SRV-064 | DNS 패치시기 | 수동 stub | 1개월 이내 | ℹ️ 패치/시기성 → eol/patch_check(D라벨) 영역, 결정론 임계 아님. 별도 |
| SRV-007 | SMTP 패치버전 | 수동/부분 | 버전 최솟값 다수 | ℹ️ 위와 동일 — patch_check 영역 |

### 13.3 수동/인터뷰 확정 (common·xlsx 합치 — det_common이 handled=False로 LLM/인터뷰)
- **확정 수동**: SRV-022/027/075(stub)/091/109/112/115/118/144/163/165/166/175 + SRV-074·115(xlsx도 인터뷰 명시).
- xlsx 정책검토 경계: SRV-109/118/179(절차·내부정책 확인) → label B(인터뷰) 후보.

### 13.4 대조 결론
> ⚠️ **§17.6/§18 정정**: "그대로 가져간다"는 **폐기**. 서버에도 실버그(SRV-010 판정역전)가
> 있으므로 **"검증·수정 후 가져간다"가 확정 계약.** 아래 "안전"은 *임계값 일치*에 한정된 의미다.
- 핵심 수치 임계 **9/9 일치** → common 결정론의 *임계값*은 서버에서 신뢰 가능(코드 버그는 별개).
- divergence는 **3건(SRV-127/081/006)**, 모두 common이 xlsx보다 **느슨/누락**(거짓 양호 위험).
  → 어댑터에서 xlsx 임계 주입(127) 또는 보강/LLM폴백(081/006). **xlsx 권위 원칙대로 처리.**
- SRV-127 판단기준(col21)의 정확한 잠금횟수 컷은 미확인 → Phase 1 라벨링 시 셀 재확인 1건.

## 14. 부록 — 결정론 불가 항목의 LLM 대체 가능성 분류 (2026-06-16)
"결정론으로 안 되는 것만 LLM"의 *그 LLM 대상*을 확정. judge_tool 라벨로 직매핑.
**사용자 지정: EOL/패치는 LLM으로도 자동 verdict로도 가지 않고 판단보류(label D) 고정.**

| 분류 | 처리(label/method) | 서버 항목 | 비고 |
|---|---|---|---|
| LLM 대체 가능(증거 有·의미판단) | **A (llm)** | SRV-027,091,144,163,165,166 | common `(*)`수동을 LLM으로 승격, 커버리지↑ |
| 부분(기술은 LLM·최종 인터뷰) | **B (interview)** | SRV-074 | ISS-040(수집 시) |
| 인터뷰 필수(기술증거 없음) | **B (interview)** | SRV-109,115,118 | 내부정책/운영행위 — LLM 불가 |
| 기술한계(LLM도 불가) | **C (canned 판단보류, LLM 호출 X)** | SRV-022,075 | 해시 크랙 필요 + 해시 마스킹. DBM-001 동일 |
| **EOL/패치(LLM 금지)** | **D (eol/patch→판단보류, needs_review)** | SRV-007,064,179 | ⛔ 자동 verdict 금지. eol.py 테이블은 보조참고만, 확정은 사람 |
| 데이터 갭(수집되면 LLM) | 증거 미수집 판단보류 | (DB OS레벨 DBM-012/021/022/026/034) | ISS-037(SECUI hit-count 부재)·038/039(--aux) |

핵심: 결정론 핸들러가 common의 수동표기로 `handled=False`를 내면 → 위 라벨에 따라
A(LLM)/B(인터뷰)/C(canned)/D(EOL)로 분기. **A만 실제 LLM 판정**, B는 보류+요약,
C·D는 LLM 호출 없는 자동 판단보류. EOL이 LLM/자동확정으로 새지 않도록 D 고정이 계약.

## 15. 부록 — 전 8개 도메인 결정론 불가 항목 전수 + LLM 대체 분류 (2026-06-16)
분류: **A**=LLM 가능 / **B**=인터뷰·관리체계 / **C**=기술한계(LLM도 불가) /
**D**=EOL·패치(LLM 금지, 판단보류 고정) / **GAP**=데이터 갭(수집되면 대개 A).

### 15.0 도메인별 집계
| 도메인 | 결정론 불가 | A(LLM) | B(인터뷰) | C(기술한계) | D(EOL) | GAP(수집) |
|---|---|---|---|---|---|---|
| 서버(SRV) | ~17 | 6 | 4 | 2 | 3 | (DB로) |
| DB(DBM) | ~15+ | (GAP다수) | 7 | 1(DBM-001) | 2 | 9+ (엔진별) |
| 네트워크(NET) | 20 | 12 | 3 | 0 | 2 | 1(NET-054) |
| ISS(정보보호) | 35 | 19 | 8 | 1(ISS-018) | 2 | 5 |
| 컨테이너(PRCC) | ⚠️정정 | 2 | 1 | 0 | 1 | ~~5~~ | 9개는 **주 플랫폼 결정론+보조 플랫폼만 M**(§16). 비결정론 아님 |
| OS가상화(PRCV) | 8(M)+⚠️ | 1 | 4 | 0 | 0 | 3 | **PRCV-027~036 elif버그로 도달불가**(§16). 결정론 커버 손실 9건 |
| 클라우드(PISM) | 49 | (스캐너판정) | 2+47 | 0 | 0 | 0 |
| 웹(WST 특화) | ~16 | 6 | 2 | 1(WST-044) | 3 | 4 |

### 15.1 C — 기술한계 (LLM으로도 대체 불가, label C canned)
극소수. **패스워드/비밀번호 크랙류**가 전부:
- SRV-022, SRV-075 (서버 PW 크랙), DBM-001 (DB 해시 크랙), WST-044 (웹 기본계정 PW),
  ISS-018 (보안장비 암호화 PW — 평문 추출 불가).
→ 해시가 마스킹되고 LLM도 못 깬다. canned 판단보류.

### 15.2 D — EOL/패치 (사용자 지정: LLM·자동확정 금지, 판단보류 고정)
- 서버 SRV-007/064/179, DB DBM-016/025, 네트워크 NET-048/059, ISS-005/043,
  컨테이너 PRCC-004(버전조건부), 웹 WST-080/033/126.
→ eol.py 테이블은 보조참고만, 자동 verdict 금지. **eol.yaml에 네트워크/ISS/웹 장비 테이블이
  아직 없음** → 현재 전부 canned 판단보류로 떨어짐(정상 동작).

### 15.3 B — 인터뷰/관리체계 (기술증거 없음·정책 의존, label B)
가장 큰 비중. 대표:
- 서버: SRV-074(업무사용)/109(내부정책)/115·118(운영행위)
- DB: DBM-003/004/015/017/024/028(업무상 불필요 여부), 엔진별 DBM-019/020
- 네트워크: NET-001/056(백업·변경주기 운영), NET-047(상단 DDoS장비 존재)
- ISS: 8건(ISS-001/006/008/019/026/028/029/040 — 보고절차·변경통제·감사증적)
- 컨테이너 PRCC-039, OS가상화 PRCV-001/002/003/008(계정 분리·역할 적정성)
- **클라우드 PISM: 47개가 순수 관리체계** → 현재 judge_tool이 `applicable=False`로
  **아예 미판정**(설계상 정확). + PISM-023/045 인터뷰 2건.

### 15.4 A — LLM 대체 가능 (증거 있음·의미판단, label A)
common이 수동(`(*)`)으로 뒀거나 *판정 미구현*이지만 config 증거가 있어 LLM이 판정 가능:
- 서버: SRV-027/091/144/163/165/166
- 네트워크: **12건**(NET-005/006/007/009/012/013/022/038/039/040/041/050/058) —
  ⚠️ common이 정보수집은 하나 **판정 섹션이 공백/주석처리**. "결정론 불가"가 아니라
  *common 미구현*. 결정론화 or LLM 둘 다 가능 — 우선 LLM(A), 후속 결정론 보강 여지.
- ISS: 19건(ISS-007/009/010~017/020~025/027/042 등 — 패턴·설정 존재여부 해석)
- 컨테이너 PRCC-024(NetworkPolicy 내용)/036(시스템 네임스페이스 예외)
- OS가상화 PRCV-011(배너 버전노출), 웹 WST-034/036/041/042/125

### 15.5 GAP — 데이터 갭 (지금은 불가, 수집되면 대부분 A; 결정론 로직 일부 기구현)
**가장 레버리지 큰 범주** — 수집만 되면 풀림:
- DB OS레벨: **DBM-022/026만** analysis.py에 결정론 로직 존재(SQL 섹션 미출력이 유일 장애 →
  연계 시 즉시 결정론). **DBM-034는 어느 엔진에도 메서드 없음 = 순수 GAP**(리뷰 정정 §16 —
  "로직 이미 존재"는 오류). DBM-011/012/013/021/032/006(엔진별)도 수집·로직 없음.
- 네트워크 NET-054(포트보안/SPAN 수집 미구현), 컨테이너 PRCC-010/011/017/018/022(config.toml·
  로그경로 미수집), OS가상화 PRCV-004/013(AD·SNMP 수집), 웹 WST-121~126(파서 미구현).
- ISS-003/004/037/038/039(자산목록·토폴로지·hit-count 등 외부데이터 필요).

### 15.6 도메인 특이사항 (정정 포함)
- **OS가상화(PRCV)**: ✅ common에 **결정론 소스 존재**(autoAnalysis.py vcenter/esxi/xen). "LLM 전용"
  아님. ⚠️ **리뷰 정정(§16)**: elif 중첩버그(autoAnalysis.py:1678, PRCV-027~036이 PRCV-026의
  `if "esxi"` 블록 안에 잘못 들여쓰기)로 **PRCV-027~036 전부 도달불가** — xlsx 실존 9항목
  (027~031,033~036)의 결정론 커버 손실. PRCV-032만 무해(xlsx 결번). 벤더링 시 이 버그 수정 필요.
- **클라우드(PISM)**: PISM 스캐너가 `<Item status=good/bad>`를 **이미 결정론 판정** →
  judge_tool cloud는 `status_available=True`로 이를 교차검증. **LLM은 대체가 아닌 2차의견**,
  플래그성 항목은 사실상 중복. **LLM 실질 기여는 PISM-036(환경변수 비밀 평문 식별) 정도.**
  47개 관리체계는 미판정(범위 외). → 클라우드는 결정론 통합 대상이 아니라 *현행 유지* 타당.
- **웹(WST)**: OS공유 106항목은 서버와 동일(서버 분류 준용). 웹특화 신규 WST-121~126은
  common 파서 미구현(전부 GAP). WST-040은 xlsx 판단기준 양호/취약 **역전 오기** 발견.

### 15.7 종합 결론
- **진짜 LLM이 유일 수단인 곳(A)**: 네트워크·ISS·서버 일부 — config 증거를 의미 해석.
  네트워크 12건·ISS 19건은 common이 미구현이라 *LLM이 즉효, 결정론은 후속 보강* 전략이 맞다.
- **LLM으로도 불가(C)**: 크랙류 4~5건뿐 → canned.
- **EOL(D)**: 전 도메인 판단보류 고정(사용자 지정), eol.yaml 장비테이블 확충이 후속.
- **최대 레버리지(GAP)**: 수집 연계가 핵심 — 특히 DB OS레벨은 로직이 이미 있어 수집만 붙이면 됨.
- **클라우드(PISM)는 예외** — 스캐너가 결정론 엔진. 결정론 통합 대상에서 제외, 현행 LLM 교차검증 유지.

## 17. 전수 재검증 (2차, 2026-06-16) — §15 카운트는 본 절로 대체
사용자 지적("스폿체크로 또 있을지 어떻게 아나")에 따라 **샘플 아닌 전수**로 재검증
(매 항목 코드라인 인용 + xlsx 항목수 100% 정합). **§15보다 정확하며, 충돌 시 본 절 우선.**
1차 리뷰가 못 본 신규 문제가 다수 발견됨 — 아래.

### 17.1 검증된 xlsx 항목 수 (정정 — 이전 추정 오류)
- 서버 **105**개(106 아님). DB **31**개 DBM(002/010/018/023/027 결번). 네트워크 **45**개.
  컨테이너(PRCC) **50**개. OS가상화(PRCV) **35**개(PRCV-032 결번). 웹 **125**개(웹특화 22).

### 17.2 신규 발견 ① — **common 코드 자체의 버그**(벤더링 시 그대로 옮겨짐 → 반드시 수정)
| 버그 | 위치 | 영향 |
|---|---|---|
| **SRV-010 판정 역전** | SRV_auto_parse.py:942/945 | result 'Y'에 "양호", 'N'에 "취약" 출력 — 양호/취약 뒤바뀜 |
| **PRCV-027~036 도달불가** | autoAnalysis.py:1678~1804 (indent16, PRCV-026 esxi블록 내 중첩) | xlsx 실존 **9항목**이 항상 기본값 'N' 반환(결정론 커버 상실) |
| **WST-102 IIS 역전** | WST_IIS_parse.py:688-689 | 위반 0건일 때 result='Y'(취약)로 뒤집힘 |
| **WST-040 IIS+xlsx 둘 다 의심** | WST_IIS_parse.py:524-580 + xlsx 웹 row44 col31 | xlsx 판단기준 양호/취약 문구 역전 + 코드 polarity도 판단방법과 불일치 |
| **NET-051 오타** | NetworkConfig.py:2592 `tcp-kepalives-in`(e 누락) | 실제 수집 문자열과 불일치 → 판정 분기 영구 미발동(사실상 EMPTY) |
| SRV-147 사유코드 오기 | SRV_auto_parse.py:2781 "SRV-142"로 라벨 | 경미(사유코드만) |
| NET-046 acl_flag 미사용 | NetworkConfig.py:2401~ | 경미(Y/N은 나옴) |
| PRCC-024 ocp_master leaf 그림자 | autoAnalysis.py:795-797 | 무해(L782서 선매칭, 항목 분류 불변) |
→ **"그대로 가져간다"는 위험. "가져오되 검증·수정 후"로 계약 변경 필요(§17.5).**

### 17.3 신규 발견 ② — **대규모 미커버(ABSENT)**, common에 함수 자체가 없음
- **서버: 105개 중 38개 ABSENT**(common에 check 함수 없음) — 대부분 Windows 전용
  (SRV-072/078/079/080/090/103~105/116/128/135~140/149~152 등) + 인터뷰/인벤토리. 
  common 함수는 67(auto)+5(Linux)뿐. → 이 38개는 결정론 소스 자체가 없음(LLM/신규 필요).
- **DB: DBM-034/035/036은 전 엔진 ABSENT**(§16은 034만 지적, 035/036도 없음). 추가로 DBM-012(oracle만 stub)/021(mssql만 stub) 등 단일 엔진 한정.
- **웹: 웹특화 22개 중 7개 ABSENT**(WST-080/121/122/123/124/125/126). Tomcat/JEUS 파서 없음(전부 수동 punt).

### 17.4 신규 발견 ③ — **DB 결정론은 생각보다 패치 많음**(placeholder STUB 다수)
common DB는 "깨끗한 결정론"이 아니라 **엔진별 STUB(lambda datum:True=전행 덤프, 빈 본문) 산재**:
- **DBM-005**: mssql만 DET, **mysql/oracle/mariadb/postgres는 `lambda:True` placeholder**.
  ⚠️ judge_tool DB_MYSQL.empty_means_good에 DBM-005 포함 — common 로직 이식 시 충돌 검토 필요.
- DBM-028: postgres STUB(전 분기 lambda:True). DBM-013: mysql/mariadb만 DET, oracle/mssql/pg STUB.
- 엔진 비대칭 확정(WHICH 정확): DBM-006/007/019/028 → **PG만 STUB**; DBM-009/011/017/022 → **MSSQL만 STUB**;
  DBM-016/025 → **MariaDB만 STUB**; DBM-001 → **Oracle만 DET**(나머지 manual/stub).
  → **DBM-019 정정 재확인**: MariaDB DET, PG만 STUB(§16 정정과 일치, 전수로 확정).

### 17.5 도메인별 검증된 카운트 (§15 대체)
| 도메인 | 분모 | 결정론 가용 | 부분(일부 플랫폼/경로 M·미구현) | 미판정/불가 |
|---|---|---|---|---|
| 서버 | 105 | DET 38(+5 Linux전용) | DET+MANUAL 16 | MANUAL 13 / **ABSENT 38** |
| 네트워크 | 45 | DET-FULL 26 | DET-PARTIAL 6(외부필터족 등) | EMPTY 9 / COMMENTED 2 / ABSENT 2 |
| 컨테이너 PRCC | 50 | **DET-ALL 41** | DET-PARTIAL 9(보조플랫폼만 M) | MANUAL-ALL 0 |
| OS가상화 PRCV | 35 | DET-ALL 18 | DET-PARTIAL 5 | MANUAL-ALL 3 / **UNREACHABLE 9(버그)** |
| DB | 31×5엔진 | (엔진별 DET) | STUB 다수(§17.4) | DBM-034/035/036 전엔진 ABSENT |
- 네트워크 "미구현이라 LLM 후속결정론" 주장은 유지되나(EMPTY/COMMENTED=common이 끔, NET-022/041은 `'''`주석),
  NET-001/056은 **인터뷰 metadata 기반**(config 아님), NET-035는 trivial, 외부필터족(006/038/039/040/042)은
  **양호 short-circuit만** 있고 핵심 verdict 미구현.

### 17.6 전략적 함의 (계약 갱신)
1. **"common 그대로 가져가기" → "검증·수정 후 가져가기"로 변경.** common은 실버그 보유
   (SRV-010 역전, WST-102/040, NET-051, PRCV 9항목 dead). 벤더링 = 버그까지 이식 → 포팅 시
   **고정 회귀테스트로 polarity·도달성 가드** 필수. (PRCV 중첩버그는 수정해야 9항목 결정론 복구.)
2. **결정론 가용도 = 도메인별 천차만별**: 컨테이너(41/50) > 네트워크(26/45) > 서버(38/105, +ABSENT38)
   > PRCV(18/35, 버그9) > DB(엔진별 STUB 산재). "균일 결정론"이라는 전제는 틀림.
3. **ABSENT/미커버가 큼**(서버38·웹7·DB3) — 결정론 소스가 아예 없어 LLM 또는 신규로직 불가피.
4. **xlsx 자체 오류 존재**(WST-040 양호/취약 역전) — 어느 방식이든 영향. 기준셀 정정 사용자 확인 필요.
5. **클라우드(PISM) 결론은 불변** — 스캐너 결정론, 통합 대상 제외.

### 17.7 신뢰성 메모
본 절은 8개 도메인 전 항목을 코드라인 인용+xlsx 정합으로 전수 확인했고, 1차 스폿체크가 놓친
신규 버그 5건·대규모 ABSENT·DB STUB 산재를 추가 적발했다. 단 STUB/DET 경계 일부(예: "조건이
사실상 항상 참"인 보수적 default)는 판단 여지가 있어, 포팅 착수 시 항목별 1건씩 실데이터로
재확인하는 절차를 Phase 0에 포함한다(듀얼런 하니스와 연계).

## 16. Opus 적대적 리뷰 결과 및 정정 (2026-06-16)
3개 Opus 에이전트가 원본 소스 대조로 검증. **핵심 설계 가정은 모두 검증됨**, 분류 세부 5건 정정.

### 16.1 검증됨 (CONFIRMED) — 설계 근간 유지
- **§7 마스킹 가정(최중요)**: 서버 파서가 핸들러 前 마스킹 + `check_SRV_070`이 해시 **길이>15**로
  판정 → 마스킹 시 verdict가 취약→양호로 **실제 뒤집힘(거짓음성)**을 실증 확인. `_CRYPT_HASH`가
  /etc/passwd 2번째 필드를 매칭. **"결정론엔 비마스킹 raw 공급" 결정은 옳음.**
- §3/§5 통합 라우팅: `_HANDLERS`(376-383)·디스패치(480-481)·yaml 우회(96-99) 라인 정확.
  `det_common` 등록+yaml 부여 라우팅 성립. `_fw_policy_handler` 패턴 정확.
- §13.1 서버 임계값 9/9 매치(8건 직접 확인). §13.2 SRV-081(750 미완)·SRV-006(postfix 누락) 실재.
- **네트워크 "12 A = 미구현/비활성"(최중요 전략 주장) 검증**: NET022·NET041은 Y/N 로직이
  `'''...'''`로 **주석처리**돼 있음(직접 증거). "결정론 불가"가 아니라 "common이 끔" → LLM 즉효 +
  결정론 후속보강 전략 타당.
- ISS capability(fw_policy 214-246), ISS-018=C, 클라우드 PISM 스캐너 재인코딩 + 47개 미판정(정확히
  47 수치 일치) + status_available=True. DBM-001=C, DBM-022/026 로직존재, DBM-006 PG단독갭,
  DBM-009 MSSQL placeholder. 웹 Tomcat/JEUS 파서 부재·WST-121~126 GAP·WST-040 기준역전·WST-044=C.

### 16.2 정정 (수정 반영 완료)
| # | 항목 | 오류 | 정정 | 심각도 |
|---|---|---|---|---|
| 1 | **DBM-034** | "결정론 로직 이미 존재" | 어느 엔진에도 메서드 없음 = **순수 GAP**(로직 없음) | High |
| 2 | **PRCV 버그 범위** | "PRCV-032만 도달불가" | elif 중첩으로 **PRCV-027~036 전부 도달불가**, 실존 9항목 커버 손실 | High |
| 3 | **컨테이너 PRCC 프레이밍** | "9개 항목 비결정론(M)" | 9개 모두 **주 플랫폼은 결정론 Y**, 보조 플랫폼만 M. PRCC-010/011은 주플랫폼 판정함(GAP 과장). PRCC-018 k8s_worker 분기 **존재(M반환)**, 부재 아님 | Med-High(전략) |
| 4 | **DBM-019** | "MariaDB/PG = B" | MariaDB는 **결정론 로직 있음**. 빈 stub은 **PG만** | Med |
| 5 | **SRV-127** | "common 느슨, divergence" | col21 판단기준에 숫자 컷 없음(deny=3/5는 col22 예시) → common(존재=양호) **일치**, divergence 아님 | Med |

### 16.3 신규 발견 — 벤더링 포팅 위험 (Med, §5.1 보강 필요)
**SRV-069/074/127의 실제 결정론 로직은 `SRV_Linux_parse.py`(5함수 Linux 오버라이드)에만 있고,
`SRV_auto_parse.py`의 동명 함수는 `(*)` 수동 stub**이다. 벤더링 시 Linux 모듈을 포팅하지 않으면
이 항목들이 **조용히 수동으로 강등**된다. → vendor 시 SRV_Linux_parse 우선 병합 + 단위테스트로 가드.

### 16.4 저심각 메모
- 클라우드 status_available=True는 dataclass 기본값(암묵). PISM-036 "유일 LLM 기여"는 분석가
  주장(구조검증 밖, 미확정). NET006/038/039/040은 "판정 공백"이 아니라 양호 short-circuit만 있음(부분).
  SRV-074는 "기술=LLM"이 아니라 기술부분 결정론+인터뷰 확정(B with prefill). DBM-015는 B가 아니라
  yaml 미등재·common 미구현(unhandled).

### 16.5 종합 판정
**설계의 전략적 근간(마스킹→raw, 네트워크 미구현-not-impossible, 핸들러 패턴, PISM 제외)은 검증됨.**
정정은 전부 *분류 세부 정확도* 문제로, 착수 전 수정으로 흡수됨. 단 **컨테이너는 결정론 커버가
생각보다 넓고**(LLM 대상 축소), **OS가상화는 elif 버그로 결정론 커버가 좁다**(수정 필요) — 이 둘은
Phase 적용 시 재산정 대상.

## 18. 최종 리뷰 반영 — 정규 설계 보정 (2026-06-16, Opus 리뷰 C1/H1/H2/M1/M2/M5)
§17 전수검증을 정규 설계(§5/§9/§10/§12)에 스레딩. **충돌 시 본 절이 §5 핸들러 계약을 갱신한다.**
9건 중 H3(§9)·M3(§13.4/헤더)는 인라인 수정 완료. 나머지를 아래에 확정한다.

### 18.0 중심 아티팩트 (Phase 0 최우선 산출 — C1/H1/H2/M1/M2가 전부 여기 의존)
두 파일을 `vendor/common/`에 둔다. §17.5/§17.2에서 기계적으로 도출 가능.
- **`DET_SOURCE.yaml`** — 항목×variant별 소스 분류:
  `DET`(실결정론) / `STUB`(placeholder·lambda:True·빈본문) / `UNREACHABLE`(도달불가 dead) /
  `ABSENT`(함수없음) / `MANUAL`(`(*)`/M). 어댑터는 common 호출 **전에** 이 표를 본다.
- **`KNOWN_BUGS.md`** — common 실버그 5건(SRV-010 역전, WST-102 역전, WST-040 polarity,
  PRCV-027~036 도달불가, NET-051 오타) + 각 corrected-동작 명세 + 회귀테스트 핀.

### 18.1 [C1, Critical] STUB/도달불가-N → 거짓 양호 차단 (§5.4 갱신)
common은 STUB·unreachable·NET-051오타에서 **위반 없음 → N/빈결과**를 낸다. §5.4의 `N→양호@0.9`를
무조건 적용하면 **"판정한 적 없는데 confident 양호"**(보안도구 최악 실패, 무징후)가 된다.
- **어댑터 계약**: `judge()`는 호출 전 `DET_SOURCE[item,variant]` 확인 →
  `DET`만 common 호출 후 매핑. `STUB|UNREACHABLE|ABSENT|MANUAL`은 **즉시 `handled=False`**(호출 안 함).
- **§5.4 신규 행**: `STUB/placeholder/unreachable/absent 소스 → handled=False (절대 양호로 매핑 안 함)`.
- 이로써 "진짜 결정론-양호의 N" vs "아무것도 안 한 N"을 *런타임 추측이 아니라 구조적으로* 구분.

### 18.2 [H1, High] 벤더 버그 수정 메커니즘 (§5.1 갱신)
§5.1 허용 편집에 **(c) 검증된 정확성 수정**을 추가한다 — `KNOWN_BUGS.md` 등재 버그에 한정,
`# VENDOR-EDIT(bug):` 주석 + PROVENANCE + corrected 동작을 단언하는 핀고정 회귀테스트 동반.
- **결정: 버그 수정은 벤더 코드 안에서**(어댑터에서 verdict를 사후 뒤집지 않는다 →
  어댑터의 `N→양호` 매핑을 정직하게 유지, "common이 무엇을 판정했나"의 단일 출처 보존).
- PRCV 중첩버그는 들여쓰기 수정으로 9항목 결정론 복구(수정 없으면 그 9항목은 `DET_SOURCE=UNREACHABLE`).

### 18.3 [H2, High] ABSENT 항목 처리 + Phase 1 라벨링 5-way (§5.3/§9 갱신)
- 서버 38·웹 7·DBM-034/035/036은 common에 **함수 자체가 없음**. 어댑터는 이를 **`handled=False`
  + reason=`ABSENT`**로 반환(존재하지 않는 함수 호출 시도 금지). 핸들러는 **§14 라벨로 라우팅**
  하며 **무조건 LLM 폴백 금지**(LLM 부적합이면 C/D로).
- **Phase 1 `server.yaml` 라벨링은 2-way가 아니라 5-way**: `DET→det_common` /
  `MANUAL·(*)→§14 A/B/C` / `ABSENT→§14`(LLM 적합 §15.4 명시분만 A, 기본 C 판단보류) /
  `EOL→D`. 입력은 손으로 재유도하지 말고 **`DET_SOURCE.yaml`을 권위 입력**으로 쓴다.

### 18.4 [M1, Med] DBM-005 충돌 해소: DET_SOURCE > empty_means_good
common `dbm_005`가 STUB(mysql 등 4엔진)인데 profile.empty_means_good에 DBM-005 포함 →
STUB의 빈결과를 empty_means_good이 양호로 *이중 정당화*하는 거짓양호. **해소: DET_SOURCE 우선** —
소스가 STUB/ABSENT면 어댑터가 reconcile *전에* `handled=False` → empty_means_good이 개입 못 함.
empty_means_good은 **소스가 진짜 DET이고 정당하게 0행**일 때만 적용. (회귀테스트: DBM-005 mysql
은 STUB에서 양호로 나오면 안 됨 — §18.6 (e).)

### 18.5 [M2, Med] handled 플래그가 placeholder-N·DET-PARTIAL 미포함 (§5.4 갱신)
§5.4에 두 행 추가:
- `placeholder-N / unreachable-N → handled=False`(C1과 동일).
- `DET-PARTIAL → variant로 분기`: 활성 플랫폼 경로가 DET면 N/Y 매핑, 활성 경로가 M-분기면
  `handled=False`. 이미 `judge(...variant...)`에 넘기는 variant가 선택자. (컨테이너 9·서버 16·
  네트워크 6·PRCV 5의 부분결정론을 코드에서 정확히 처리 — §16.2 "GAP 과장" 재발 방지.)

### 18.6 [M5, Med] 회귀 테스트 보강 (§10 갱신)
§10 (a)~(c)에 추가:
- **(d) 고정 버그 회귀테스트**: KNOWN_BUGS 각 항목당 corrected-polarity/도달성 단언 →
  재벤더링이 버그 재유입 시 CI 실패.
- **(e) STUB/ABSENT 비-양호 단언**: DET_SOURCE非DET 항목은 `handled=False`이며 verdict가
  양호로 안 나옴(DBM-005 mysql 포함). **듀얼런 diff만으론 거짓양호 못 잡음**(LLM과 우연히
  일치 가능) → 이 음성 테스트가 별도 필요.

## 12. 다음 착수 (이 설계 승인 시)
> **구현자 TL;DR**(부록 다 안 읽어도 착수 가능): 읽을 것 = §17.5(카운트·소스품질) · §18(정규 보정,
> 특히 18.0 아티팩트) · §14(handled=False 라벨 라우팅) · §16.1(검증된 불변 패턴) · §7(마스킹).
> 계약: "검증·수정 후 가져간다". 클라우드(PISM) 제외.

Phase 0 구체 순서 (M4 반영 — DET_SOURCE/KNOWN_BUGS가 1번):
1. **`vendor/common/DET_SOURCE.yaml` + `KNOWN_BUGS.md`** 작성(§18.0 — 이후 모든 가드가 의존).
2. `det_adapters/base.py`(ForcedVerdict + DET_SOURCE 조회 + 레지스트리).
3. `main.py`에 `_det_common_handler` + `_HANDLERS["det_common"]` 등록(동작 불변 확인).
4. `JudgeContext.thresholds` 배선 + `server_xml` `raw_evidence` 분리(§7).
5. 듀얼런 하니스 + 회귀테스트 (d)(e)(§18.6) 스켈레톤.
→ 전 단계 후 `pytest -q` 그린(어댑터 0개라 기존 동작 불변).

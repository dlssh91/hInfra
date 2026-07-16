# 설계: 웹UI 계층 워크스페이스 (점검분야 → 대상 → 파일)

작성 2026-07-16 · 상태 **확정(구현 대기)** · 브레인스토밍+Fable 비판검토 완료(High3/Medium7 반영) · 사용자 목업 승인
기존 webui **확장**(재설계 아님). 참고 목업: `docs/superpowers/specs/2026-07-16-webui-hierarchy-mockup.html`
(Artifact: https://claude.ai/code/artifact/0a3462a2-73e5-4314-92eb-ad72eb383bb6)

## 1. 목표 / 확정 요구사항
사용자가 **프로젝트**를 만들고, 그 안에서 **점검분야 → 대상(시스템) → 파일** 계층으로 조직화하며,
판정결과가 **색으로 구분**되고 **인터뷰 참고사항**이 보기 좋게 나오는 워크스페이스.

- **확장 대상**: `judge_tool/webui/`(server.py, store.py, jobs.py, static/index.html). 판정엔진 `main.run`·대외비 `results/` **무접촉**(기존 store 격리원칙 유지).
- **계층**: 프로젝트 → 점검분야(도메인) → 대상 → 파일. **한 대상 = 한 분야 고정**(DBMS는 소프트웨어라 같은 물리서버라도 OS점검=서버분야, DB점검=DBMS분야로 대상 별개).
- **조직화 = 수동**(자동 도메인분류 없음). 사용자가 분야에 파일 드롭 or 빈 대상 생성.
- **스케일: 분야당 수십 개 대상**(예: 서버 40대 = 대상 40개, 각 파일 1개). → 검색/정렬/상태필터/분야 롤업/일괄판정 필수.
- **올리는 파일 = "점검 결과 파일"**(점검·수집 스크립트를 대상에 돌려 나온 산출물 = `--report`). 원시 설정파일 아님. **FW만 예외**(정책 export 자체가 입력).
- **파일 드롭 시 대상 생성**: 파일 1개 = 대상 1개, **대상명 = 파일명(확장자·result/점검/결과 접미사 제거), 수정 가능**. 여러 파일 드롭 = 대상 여러 개 일괄 생성.
- **결과 화면**: 요약바(양호/취약/보류 색 카운트 + 혼합상태 "M/N 판정완료") + 항목표(**ID 번호순**, 판정열 색배경) + 인터뷰 참고 패널.
- 색 팔레트(`--good/--bad/--hold`)·인터뷰 패널은 **기존 index.html에 이미 존재** — 재사용.

## 2. 데이터 모델 (접근 B-lite — 경량 target 레코드)
`project.json` 확장(하위호환, `schema_version` 유지=1):
```jsonc
{
  "id":"p-xxxxxxxx", "name":"...", "created":"...",
  "targets":[                                  // ★신설
    { "id":"t-xxxxxxxx", "domain":"dbms", "name":"PROD-DB-01", "created":"..." }
  ],
  "assets":[ { "id":"a-xxxxxxxx", ..., "target_id":"t-xxxxxxxx" } ]  // ★신설 참조
}
```
- **target = 가벼운 레코드**(디스크 디렉터리 없음). 자산 물리저장은 기존 `assets/a-xxx/` 유지.
- **domain = 점검분야 enum 키**(프로파일 아님 — H-2). asset의 프로파일은 기존대로 자산별 유지.
- 모든 접근은 `.get("targets", [])` / `asset.get("target_id")` 방어적(구스키마=키 부재 안전 폴백). `order` 필드 **없음**(YAGNI, 정렬=created+name).

### 점검분야 enum ↔ 프로파일 매핑 (H-2, M-6) — 신규 상수(위치: store.py 또는 profile.py)
표시순 = 기준서 표준순. 매핑에 없는 프로파일은 목록 뒤 알파벳순 폴백.
| domain 키 | 표시명 | 프로파일 |
|---|---|---|
| `server` | 서버 | server |
| `dbms` | DBMS | db_mysql, db_oracle, db_mssql, db_mariadb, db_postgresql, db_tibero |
| `webwas` | WEB·WAS | webwas |
| `network` | 네트워크 | network |
| `security` | 정보보호시스템 | iss, iss_device |
| `cloud` | 클라우드 | cloud |
| `container` | 컨테이너 | container |
| `osvirt` | OS가상화 | osvirt |

## 3. 백엔드 — store.py (기존 함수 무수정, 추가만)
- `validate_target_id()` + `_TARGET_ID_RE=^t-[0-9a-f]{8}$` **신설**(기존 `_ID_RE` 무수정 — H-1).
- `create_target(pid, domain, name)`: lock 하 load-modify-save. domain enum 검증, name 검증(strip·비어있음거부·길이≤120·제어문자거부 — M-5).
- `rename_target(pid, tid, name)`: 이름만 변경 → judging 중에도 안전(참조는 id, ConflictError 불요 — L-3).
- `delete_target(pid, tid, cascade=False)`: **단일 lock+원자쓰기**로 처리(H-3).
  - `cascade=False`(기본): 해당 tid 참조 자산의 `target_id`를 None으로 → "미분류" 이동(비파괴). 부분상태 없음.
  - `cascade=True`: 삭제 전 대상 내 judging 자산 전수검사 → 있으면 `ConflictError`. 없으면 자산+결과 함께 삭제(`delete_project` 패턴).
- `assign_asset_target(pid, aid, tid|None)`: 자산을 대상에 배치/이동(lock 하, tid 존재검증).
- `list_targets(pid)`: created→name 정렬 반환.
- `target_summary(pid, tid)`: **읽기시점 파생**(M-1). 결과 JSON 재파싱 없이 `asset["summary"]["verdict_counts"]`(jobs.py `_summarize` 기록분)만 합산. 반환 `{verdict_counts, judged_assets, total_assets, failed, judging}`(혼합상태).
- `add_asset(...)`에 `target_id` 옵션 인자 추가(동일 lock 내 target 존재검증). 프로파일: `guess_profile` 결과가 대상 domain의 프로파일 집합에 속하면 유지(`guessed`), 아니면 domain 기본 프로파일 or 미지정+경고. `profile_source`에 `"target"` 값 추가(M-3).
- **`list_projects` 응답 무변경**(기존 키집합 단언 테스트 test_webui_store.py:46 보호 — M-7).

## 4. 백엔드 — server.py 라우트 (기존 무수정, 추가만; `/api/` 인증게이트 자동 커버)
| 메서드 | 경로 | 동작 |
|---|---|---|
| POST | `/api/projects/{pid}/targets` | 대상 생성 (JSON body: domain, name) |
| POST | `/api/projects/{pid}/targets/{tid}/rename` | 이름변경 (body: name) |
| POST | `/api/projects/{pid}/targets/{tid}/delete` | 삭제 (body: cascade=bool) |
| GET | `/api/projects/{pid}/targets/{tid}/summary` | 대상 롤업 요약(파생) |
| POST | `/api/projects/{pid}/assets/{aid}/target` | 자산 배치/이동 (body: target_id\|null) |
- 업로드 시 대상 지정: 기존 `POST .../assets`에 **`X-Target-Id` 헤더** 추가(기존 X-Filename 관행 — M-2). 서버는 add_asset 동일 lock 내 target 검증(없으면 400).
- `judge_all`에 선택적 `target` 필터 파라미터 추가(대상/분야 단위 판정 — L-4).

## 5. 프런트엔드 — static/index.html (확장)
### 레이아웃
좌측 사이드바=프로젝트 목록(기존). 우측 워크스페이스=**8분야 트리**(기준서 표준순, 빈 분야 흐리게).
### 분야(도메인) 그룹
- 헤더: 분야명 · `대상 N · 판정 M/N` · **롤업 미니바**(분야 전체 양호/취약/보류 합산) · 프로파일 힌트.
- 펼치면 상단 **드롭존** + **툴바**(검색 / 상태필터[전체·취약있음·미판정] / 정렬[이름순·취약많은순·미판정먼저] / **분야 전체 판정**).
### 대상 추가 (드롭존)
- **결과 파일 드래그드롭** → 파일당 대상 1개 일괄 생성(이름=`nameFromFile`=확장자+result/점검/결과 접미사 제거). 실제 DnD(dragover/drop) 처리.
- **＋ 빈 대상** 버튼(이름만 입력, 결과 파일 나중에 드롭).
- 프로파일=대상 domain으로 필터·기본값(M-3).
### 대상 목록 (수십 개 스케일)
- **조밀한 행**: 이름 · 파일명(mono) · 미니 판정바 · 상태배지(판정완료/부분/미판정). `max-height + overflow-y`로 스크롤.
- 행 클릭 → **인라인 확장**: 자산별 결과(기존 `renderResultPanel` 재사용):
  - **항목표**: ID 번호순(정렬은 이미 판정엔진 저장시점 `main.py:934`에서 완료 — 프런트는 순서대로 렌더), **판정열 색배경**(취약=`--bad-weak`/보류=`--hold-weak`/양호=`--good-weak` + 아이콘).
  - **💬 인터뷰 참고 패널**: 자산 결과의 `interview_summary`(DBM-003 classify-then-hold 등) 카드. 기존 `#interview-panel`/`.interview-card` 재사용.
- **대상당 다중파일**: v1 **항목표 병합 금지**(M-4) — 요약바만 대상합산, 항목표는 자산별 아코디언.
### 렌더 규칙
- target name 삽입 시 기존 `escapeHtml` 준수(M-5, XSS 방지).
- 신규 함수: `renderDomainTree(project)`(8분야 고정순), `renderTargetRow/summary`, 드롭존 핸들러. 기존 결과렌더 재사용.

## 6. 대상 삭제 UX
기본 confirm = **자산 미분류 이동(비파괴)** — LLM 판정결과 재작업(Ollama 재실행) 비용 보호. "자산·판정결과 함께 삭제"는 체크박스+명시문구 **이중확인** 시에만 cascade(H-3의 judging 전수검사 적용).

## 7. 테스트 계획 (M-7 — 기존 무수정, 추가만)
신규 `tests/test_webui_targets.py`(또는 기존 webui 테스트 파일에 추가):
- store: create/rename/delete_target(cascade=T/F), assign_asset_target, list_targets 정렬, target_summary 혼합상태 집계.
- 하위호환: `targets` 키 부재 구스키마 project.json 로드.
- 방어: 댕글링 tid(삭제된 대상 참조 자산) → 미분류 폴백.
- 동시성/충돌: judging 중 cascade 삭제 → 409(ConflictError).
- API: 없는 tid로 업로드(X-Target-Id) → 400. 신규 라우트 인증게이트 커버.
- domain enum/name 입력검증(잘못된 domain·초장문 name 거부).
- **회귀**: `list_projects` 응답 무변경 확인(기존 키집합 단언 통과). `python3 -m pytest tests/ -q` 전체 통과가 SHIP 조건.

## 8. v1 비범위 (YAGNI)
- 대상 order 수동 재정렬(정렬은 created+name 자동).
- 대상당 다중파일 항목표 병합 판정(자산별 표시 유지).
- 도메인 자동분류(수동 조직화 확정).

## 9. 리스크 / 주의
- 프로파일 상속 vs guess 충돌: domain 집합 우선(M-3) — 잘못 드롭 시 경고만, 자산별 재지정 가능.
- 대외비: webui는 판정엔진 산출물만 표시. `check_project_root_safe`로 project_root가 `results/` 하위이면 거부(기존 가드 유지).
- 기존 `_secui_rows` 등과 무관(webui 계층 한정). 판정 로직 무변경.

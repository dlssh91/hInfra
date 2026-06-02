# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-01. 다음 세션에서 이 파일부터 읽고 이어서 진행할 것.

## 무엇을 만들고 있나
클라우드(AWS) 점검 결과 XML + 평가기준 xlsx를 입력받아, **로컬 LLM(Ollama)** 이 PISM 항목별로
양호/취약/판단보류를 독립 판단하고 스크립트 status와 교차 비교하는 CLI 도구 `judge_tool`.

- 설계(spec): `docs/superpowers/specs/2026-06-01-llm-judgment-tool-design.md`
- 구현계획(plan): `docs/superpowers/plans/2026-06-01-cloud-aws-llm-judgment.md` ← **태스크 전체 텍스트·코드가 여기 있음**
- 실행 방식: **superpowers:subagent-driven-development** (태스크마다 새 구현 서브에이전트 → 스펙 리뷰 → 코드품질 리뷰 → 다음)

## Git 상태
- 브랜치: `main` (feature/cloud-aws-llm-judgment에서 이름변경)
- 마지막 커밋: DB Phase-2(MySQL) T1~T8 완료 — 각 태스크 구현→리뷰(미듐+ 수정 반복)→simplify.
- 테스트: `python3 -m pytest -q` → **125 passed** (openpyxl UserWarning 5건은 무해)
- **1단계(클라우드 AWS) Task 0~10 전부 완료.** Phase-2 DB(MySQL) T1~T8 완료(아래 별도 표). 남은 것: DB T10(실제 Ollama 스모크, 수동·선택).

## Phase-2 DB(MySQL) 진행 (plan: docs/superpowers/plans/2026-06-02-db-mysql-raw-judgment.md)
| T | 내용 | 상태 |
|---|---|---|
| 1~3 | models.applicable/context, profile.DB_MYSQL, criteria_loader applicable | ✅ (결합, cloud 동치 회귀) |
| 4 | db_json 마스킹(해시/평문 휴리스틱, 방어심화) | ✅ |
| 5 | db_json 파서 본체(경계분할·살균·NOTE/빈/중복키) | ✅ (보안누출·무음손실·NOTE phantom 3차 수정, 실데이터 손실0/누출0) |
| 6 | mapper context(2/3-tuple) | ✅ |
| 7 | judge raw 증거가드 + reconcile 확장(status_available 등) | ✅ |
| 8 | main.run DB 연결 + NOTE→판단보류 | ✅ (실데이터 E2E: coverage 16/17, DBM-025 missing — spec §10 일치) |
| 9 | 거버넌스+회귀 | ✅ |
| 10 | 실제 Ollama 스모크(수동·선택) | ✅ (qwen3-coder:30b, rds, 2026-06-02) |

DB 스모크 결과(rds, qwen3-coder:30b): 판정 16/17(미판정 DBM-025), 양호5/취약4/판단보류7, needs_review 16/16, 마스킹 누출 0.
설계 검증: DBM-005 평문→취약(마스킹+사실보존), DBM-004 관리자권한→취약(권한요약), DBM-001 해시→판단보류, DBM-011/013 NOTE→판단보류, DBM-017 빈RESULT→양호(empty_means_good). B-1~B-4 전부 실모델 작동.

### ⚠️ DB 산출물 거버넌스 (민감정보)
- DB 결과(.txt)엔 **비밀번호 해시·평문**이 포함됨. db_json 파서가 **마스킹**(값 제거+길이/plugin 노출)하나, `out/` 산출물(JSON/Excel)엔 여전히 **계정명/호스트/내부IP 등 식별정보**가 남는다.
- `out/`은 gitignore됨. **해시/평문 원문은 마스킹되어 산출물에 미포함**(실데이터 3파일 누출 0건 회귀 테스트로 고정).
- 산출물 보관/삭제 책임은 평가자에게 있으며 **민감 디렉터리(results/ 등)에 출력 금지**(도구가 `--out-dir`=입력 디렉터리면 거부).
- 2차 리뷰 보강(커밋 f5155ed/fc8eb4d/3c2bf5e): non-dict JSON 가드, status 분류 일원화(GOOD_STATUSES 단일출처), **error/증거없음→판단보류 강제**(spec 6.7), needs_review에 `expected is None` 추가(info-only 등 미대조 항목 보수적 검토), 예외 본문 비직렬화(evidence 유출 차단), 파서 레지스트리 `parsers/__init__.py`로 이전, `--out-dir`이 입력 데이터 디렉터리면 거부, criteria 컬럼매핑 합성 테스트.
- 패키지(openpyxl/requests/pytest)는 시스템에 이미 설치됨. **PEP668로 pip install 차단됨 → venv 불필요, 그대로 시스템 python3 사용.**

## 진행 현황 (10개 태스크 중)
| Task | 내용 | 상태 |
|---|---|---|
| 0 | 스캐폴딩(git init, requirements, conftest) | ✅ 완료 |
| 1 | models.py (Criterion/ResourceEvidence/EvidenceItem/Judgment) | ✅ 완료·리뷰 |
| 2 | profile.py (Profile/VariantSpec/CLOUD, normalize_id, variant) | ✅ 완료·리뷰 |
| 3 | criteria_loader.py (xlsx→Criterion dict, 73항목) | ✅ 완료·리뷰 |
| 4 | parsers/cloud_xml.py (정제+파싱, CDATA-aware) | ✅ 완료·리뷰 |
| 5 | mapper.py (분할항목 집계) | ✅ 완료(인라인확인) |
| 6 | judge.py 1부 (SYSTEM_PROMPT/build_evidence_text/build_prompt/parse_json_lenient) | ✅ 완료·리뷰 (스펙✅+품질✅, I-1 백틱복구 수정 `ad3f63c`) |
| 7 | judge.py 2부 (OllamaClient/judge_item/reconcile) | ✅ 완료·리뷰 (스펙✅+품질✅, confidence안전캐스팅 등 `64f77e1`) |
| 8 | writer.py (JSON/Excel/커버리지) | ✅ 완료·리뷰 (스펙✅+품질✅, None방어/auto-mkdir `08faf49`) |
| 9 | main.py (CLI run() + 골든 E2E, LLM 모킹) | ✅ 완료·리뷰 (스펙✅+품질✅, 부분실패격리/CLI·결정성테스트 `07952cd`) |
| 10 | 실제 Ollama 스모크(수동, 선택) | ✅ 완료 (qwen3-coder:30b, 2026-06-02) |

## 다음에 할 일 (정확한 재개 지점)
1. **1단계(클라우드 AWS) 완전 종료** — 구현+2차 전체리뷰+Task 10 실제 Ollama 스모크까지 완료.
   - Task 10 결과(2026-06-02, `qwen3-coder:30b`): 판정 18/22(미판정 4건은 보고서에 증거 없는 항목 PISM-041/045/060/064), verdict 취약13·양호3·판단보류2, 일치14·N/A3·불일치1(PISM-043), 재검토 7건. 근거가 실제 증거(S3/보안그룹/RDS) 인용해 구체적. 출력은 `out/`(gitignore, 민감데이터).
   - 실행 예: `python3 -m judge_tool.main --report "results/Public Cloud/aws_report_20251223_hinno.xml" --criteria "ref/...xlsx" --out-dir out --model "qwen3-coder:30b"`
   - ⚠️ `--out-dir`을 results/·ref/(입력 데이터 디렉터리)로 주면 **도구가 거부**(안전가드). `out/`도 gitignore됨.
2. 다음 작업은 **Phase-2**(서버/DB/네트워크 등 분야 확장) 또는 아래 연기항목 처리.

## ⏭️ Phase-2 연기 항목
### ✅ 처리 완료 (2026-06-02)
- **[②] 손상 XML 견고성**: `cloud_xml.parse`가 ParseError를 `ReportError`(judge_tool/errors.py, ValueError 하위)로 변환해 파일경로+line/col 명확 안내(evidence 미유출). `main()`은 `except (ReportError, OSError)`로 입력오류만 깔끔히 안내·종료하고 우발적 버그(ValueError)는 트레이스백 전파. 실 azure 파일(894행 미닫힘 `<Evidence>`)이 이제 명확한 메시지로 처리됨. 단 **Azure 실파일은 소스 XML 자체가 손상**(스캐너 빈 Evidence 버그)이라 파싱하려면 별도 데이터 수정 필요 — 도구 책임 아님.
- **[③] criteria_version 하드코딩 제거**: `_extract_criteria_version`이 criteria 파일명에서 `제\d{4}-\d+호` 추출, 실패 시 "제2026-1호" 폴백.

### ⬜ 미구현 (실 Phase-2 데이터 생길 때까지 정직하게 연기)
- **[①] 증거가드 원시증거(raw) 모드**: `build_evidence_text`는 status 사전분류(good/info) 전제. DB/서버 등 status 없는 원시증거용 "행 상한+일부표시" 모드(`profile.evidence_mode` 등) 필요. **`results/DB/`는 .DS_Store뿐 — 실제 DB 보고서 샘플·포맷 전무**하여 지금 구현하면 추측 코드. 실 데이터 확보 후 brainstorming→plan부터.
- **[④] normalize_id 분야별 오버라이드**: 분할 구분자/ID 체계 다른 분야가 아직 없음. 투기적 → 해당 분야 등장 시.

## ▶ 개발 재개 루틴 (트리거: 사용자가 "개발해줘" 라고 하면)

사용자가 "개발해줘"(또는 동의어: "이어서 개발", "다음 진행")라고 하면, **확인 질문 없이** 아래
루틴을 태스크 단위로 반복 실행한다. (superpowers:subagent-driven-development 기반)

각 태스크마다:
1. **다음 태스크 선정** — 이 PROGRESS.md의 진행 표에서 가장 위의 미완료(⬜/⏳) 태스크를 고른다.
   해당 태스크의 전체 텍스트·코드는 plan(`docs/superpowers/plans/2026-06-01-cloud-aws-llm-judgment.md`)에 있다.
2. **구현** — 구현 서브에이전트(general-purpose, sonnet)에 plan의 태스크 텍스트를 그대로 전달.
   프롬프트에 **반드시** "results/ 는 읽기전용·쓰기금지" 안전규칙과 "pip install 금지(시스템 패키지 사용)"를 포함. TDD로 진행.
3. **스펙 리뷰** — 별도 리뷰 서브에이전트로 spec 준수 검증(코드 직접 읽기, 보고 신뢰 금지). 이슈 있으면 구현자가 수정 → 재리뷰.
4. **코드 품질 리뷰** — spec ✅ 후 품질 리뷰 서브에이전트. Critical/Important는 수정 → 재리뷰. Minor는 판단껏(가치 있으면 반영).
5. **simplify** — 변경된 코드에 대해 `simplify` 스킬(또는 code-simplifier 에이전트)로 정리(중복/복잡도/가독성). 동작 보존 확인(테스트 재실행).
6. **검증·커밋** — `python3 -m pytest -q` 전체 통과 확인 후 커밋(이미 태스크 안에서 커밋했으면 추가 변경분만).
7. **PROGRESS.md 갱신** — 진행 표 상태 업데이트 + 커밋. 다음 태스크로 계속(연속 실행, 태스크 사이에 멈추지 않음).

- 멈추는 경우만: BLOCKED(해결 불가), 스펙 모호로 진행 불가, 또는 모든 태스크 완료.
- 전 태스크 완료 시: 전체 코드 최종 리뷰 → `superpowers:finishing-a-development-branch`로 마무리.
- "한 태스크만" 같은 요청이 있으면 그 범위만 수행. 기본은 연속 실행.

## ⚠️ 반드시 지킬 안전 규칙 (사고 발생 이력)
- **모든 서브에이전트 프롬프트에 "results/ 디렉터리는 읽기전용, 절대 쓰기/삭제 금지"를 명시할 것.**
  - Task 4 때 한 서브에이전트가 실제 업로드 데이터(`results/Public Cloud/aws_report_20251223_hinno.xml` 323KB, `azure_report_20251121.xml` 88KB)를 합성 파일로 덮어쓰고 삭제함. → 커밋 `544f292`에서 복구 완료(`git show 544f292:"경로" > 경로`). 현재 정상.
- `results/`는 **gitignore**됨 (민감정보 — DB 결과에 비밀번호 해시 포함). 절대 커밋하지 말 것. 실파일은 디스크에 존재.
- 테스트는 committed 합성 픽스처 `tests/fixtures/sample_aws_report.xml` 사용. 실파일 테스트는 `os.path.exists` 가드로 평가자 환경에서만 실행.

## 핵심 설계 계약 (리뷰/구현 시 확인)
- **항목별 1회 LLM 호출(A안).** 클라우드도 LLM 독립판단 후 스크립트 status와 교차비교(일치→확신도↑, 불일치→needs_review).
- **증거가드**: status가 good/info가 아닌 리소스(취약후보)는 max_chars 무시하고 전량 보존; good/info만 축약("축약·생략" 표기).
- **혼합항목**(eval_type에 "관리체계"+"스크립트"): 프롬프트가 기술/스크립트 부분만 판정하도록 지시, 출력 scope="스크립트 부분만", management_review_needed=True, needs_review=True.
- **분할항목**(pism_037_1/2, pism_046_1/2/3 → PISM-037/046): mapper가 한 EvidenceItem으로 병합, 단일 판단기준으로 holistic 판정.
- **reconcile(Task 7)**: script_status good→양호/bad→취약 매핑, review/info/error는 비교 N/A. needs_review = 불일치 OR confidence<0.6 OR is_mixed OR verdict==판단보류.
- **감사 메타데이터(Task 9)**: model, criteria_version(제2026-1호), generated_at, source_file, source_sha256(64자), tool_version.
- **모델 기본값** `qwen2.5:14b`은 잠정값. 추후 "최저사양 대비 결과 일관성" 실측 후 결정.

## 실제 데이터 사실 (참고)
- AWS 실파일: CheckResult 26개, CheckID 예 pism_001/pism_037_1/pism_037_2, status에 good/bad/info/review/Error 존재, Evidence는 CDATA, ResourceID에 이스케이프 안 된 `&` 존재(→정제 필요).
- 클라우드 시트 "클라우드 관리체계": PISM-001~073 (73항목), 스크립트 기반 AWS 22 / Azure 18.
- 최종 목표: 같은 xlsx의 서버/DB/네트워크/정보보호/OS가상화/컨테이너로 확장(프로파일+증거파서 플러그인 추가). 1단계는 클라우드 AWS만.

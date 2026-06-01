# 작업 재개 노트 (RESUME)

> 마지막 업데이트: 2026-06-01. 다음 세션에서 이 파일부터 읽고 이어서 진행할 것.

## 무엇을 만들고 있나
클라우드(AWS) 점검 결과 XML + 평가기준 xlsx를 입력받아, **로컬 LLM(Ollama)** 이 PISM 항목별로
양호/취약/판단보류를 독립 판단하고 스크립트 status와 교차 비교하는 CLI 도구 `judge_tool`.

- 설계(spec): `docs/superpowers/specs/2026-06-01-llm-judgment-tool-design.md`
- 구현계획(plan): `docs/superpowers/plans/2026-06-01-cloud-aws-llm-judgment.md` ← **태스크 전체 텍스트·코드가 여기 있음**
- 실행 방식: **superpowers:subagent-driven-development** (태스크마다 새 구현 서브에이전트 → 스펙 리뷰 → 코드품질 리뷰 → 다음)

## Git 상태
- 브랜치: `feature/cloud-aws-llm-judgment`
- 마지막 커밋: `5b42c45` (Task 6 구현)
- 테스트: `python3 -m pytest -q` → **22 passed** (openpyxl UserWarning 3건은 무해)
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
| 6 | judge.py 1부 (SYSTEM_PROMPT/build_evidence_text/build_prompt/parse_json_lenient) | ⏳ **구현완료, 리뷰 미완** |
| 7 | judge.py 2부 (OllamaClient/judge_item/reconcile) | ⬜ 미착수 |
| 8 | writer.py (JSON/Excel/커버리지) | ⬜ 미착수 |
| 9 | main.py (CLI run() + 골든 E2E, LLM 모킹) | ⬜ 미착수 |
| 10 | 실제 Ollama 스모크(수동, 선택) | ⬜ 미착수 |

## 다음에 할 일 (정확한 재개 지점)
1. **Task 6 리뷰 마저 실행** — 스펙+품질 리뷰 서브에이전트 디스패치 (대상: commit `5b42c45`, 부모 `1e31ee5`, 파일 judge_tool/judge.py·tests/test_judge.py). 리뷰 기준은 plan의 Task 6 + 아래 핵심계약.
2. Task 7 → 8 → 9 순서로 plan의 태스크 텍스트/코드를 그대로 구현 서브에이전트에 전달. 각 태스크 후 두 단계 리뷰.
3. 모든 태스크 후 전체 코드 최종 리뷰 → `superpowers:finishing-a-development-branch`.

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

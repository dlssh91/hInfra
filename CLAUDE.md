# judge_tool — 전자금융 보안 취약점 자동판정 도구

전자금융기반시설 보안 점검 결과를 평가기준(xlsx)에 따라 LLM/결정론/인터뷰로
자동 판정하는 CLI. 현재 cloud(AWS/Azure) + DB 6종(네이티브+RDS/Aurora/Azure) 지원.
로드맵: 서버·네트워크·방화벽·가상화 도메인까지 확장 예정.

## ▶▶ 트리거: "개발진행해" / "개발해줘" (또는 "이어서 진행", "다음 작업", "다음에 진행해")
이 말이 나오면 **반드시 먼저** `docs/superpowers/PROGRESS.md`(작업 재개 노트)를
읽고, 맨 위 "다음 세션 즉시 시작점(TL;DR)"의 **다음 착수** 항목부터 이어서 진행한다.
- PROGRESS.md가 단일 진실원천(현재 상태·로드맵 실행순서·다음 착수·설계 계약).
- 추측하지 말고 PROGRESS.md → 관련 spec/코드 순으로 파악 후 착수.

## 작업단위 종료 시 의무 (commit/push 대신)
한 작업단위가 끝날 때마다:
1. `docs/superpowers/PROGRESS.md`를 갱신한다 — TL;DR "다음 착수", 완료 표,
   판단방식/도메인 계약, 새로 생긴 설계 결정/주의사항을 반영.
2. **git commit/push는 하지 않는다**(원격 미설정, 사용자 지정). 진행상황은 오직
   PROGRESS.md 문서로만 인계한다. 토큰이 끊겨도 다음 세션이 이 문서로 이어받는다.

## 에이전트 사용 규칙 (사용자 지정)
- **계획(plan)·설계 에이전트 = Fable.**
- **구현 에이전트 = Sonnet.**
- **검토(리뷰) 에이전트 = Opus.**
- 검토 사이클 기본형: Fable 설계 → Sonnet 구현 → Opus 리뷰 → (미듐 이상) Sonnet 개선 → Opus 재리뷰.

## 불변 계약 (절대 위반 금지)
- `results/` 는 실데이터 디렉터리 — **쓰기/삭제 금지**. 산출물은 `out/` 등 별도 경로.
- 시스템 `python3` 사용. 의존성 추가가 필요하면 사용자에게 알린다(임의 pip 설치 지양).
- 판정 동작 변경은 회귀 위험 — 변경 후 `python3 -m pytest tests/ -q` 전체 통과 확인.
- 판단방식 라우팅은 `main.py _HANDLERS`(judgment_method→핸들러). 새 판정 엔진은
  if/elif 추가가 아니라 `_HANDLERS` 등록 + `classify_method` 분류로 확장.

## LLM 판정 품질 검토 프로토콜 (모든 도메인 공통 — 필수)
도메인 결정론 통합 후 "로컬 LLM이 얼마나 제대로 판단하나"를 검토할 때 **반드시 아래 순서**로 한다.
이 프로토콜은 서버 도메인에서 확립됨(2026-06-17, PROGRESS.md LLM 품질 트랙 참조).
1. **분류 전수 파악**: 해당 variant의 모든 judgeable 항목을 `(label, judgment_method)`로 분류하고,
   **LLM이 production 1차 판정자인 항목**(`judgment_method != det_common`, 보통 label A 순수LLM)을 식별한다.
   ⚠️ **det_common 항목의 LLM 일치율로 LLM 품질을 단정 금지** — 거기선 결정론이 production이고
   LLM은 대조용(듀얼런 `det_dual_run.py`도 det_common만 보고 LLM-production 항목은 `skipped` 처리).
2. **양극성 커버리지 확인**: 양호/취약 샘플 쌍이 **LLM-production 항목 각각에 대해
   양호 결과와 취약 결과를 모두** 제공하는지 확인. 두 샘플 증거가 동일한 항목(=한 극성만)·
   증거 없는 항목은 **"미커버"로 명시**하고 품질 측정 불가 → 샘플 보강 필요로 기록(추측 금지).
3. **과최적화(overfitting) 가드**: 프롬프트/LLM 튜닝이 det_common(결정론=정답) 항목에서 검증되더라도,
   **실제 LLM-production(label A 등) 항목을 수정 전/후로 재판정**해 회귀·과적합이 없는지 별도 확인.
   위험방향(양호↔취약) 회귀 **0** 확인을 SHIP 조건으로 한다.
4. 결과(커버리지 표·미커버 항목·전후 비교)는 **PROGRESS.md LLM 품질 트랙**에 기록.

## 자주 쓰는 명령
```bash
python3 -m pytest tests/ -q                      # 전체 테스트
python3 -m judge_tool.main --report <result.txt> \
  --criteria <기준.xlsx> --profile <db_mysql|cloud|...> --out-dir out
```

# 설계서: judge_tool 로컬 웹 UI — "프로젝트/자산" 워크스페이스 (2026-07-03, Fable)

로컬 브라우저 도구. 결과파일 드래그앤드롭 → 각 파일=자산(asset), 점검 건=프로젝트(project),
자산별 판정 결과를 보기 쉽게. 확정 결정: ①디스크 저장(재오픈), ②웹에서 판정 실행.
추가 확정(2026-07-03): 프로젝트 삭제 기능 포함, 저장 위치 기본 repo 하위 `judge_projects/`(--project-root 변경 가능).

## 0. 근거 코드 사실관계 (그대로 믿어도 되는 계약)

| 재사용 대상 | 위치 | 정확한 계약 |
|---|---|---|
| `run()` | judge_tool/main.py | `run(report_path, criteria_path, profile_key, client, json_out, xlsx_out, model_name, now=None, variant_override=None, skip_preflight=False, hashcat_opts=None) -> Dict`. 반환=coverage `{"expected":int,"judged":int,"missing":[str]}`. json/xlsx 지정 경로 기록. `ReportError`(사용자 오류 한글)·기타 예외 가능. **run() 내부에 _guard_out_dir 없음** — out 가드는 CLI 계층 책임. |
| Ollama 페일패스트 | main.py run() 내부 | LLM 필요 시(`_needs_llm`) `client.health_check()` 자동 호출, 실패 시 `ReportError("[Ollama 확인 실패] ... ollama serve ...")`. **웹이 중복 구현 불필요.** iss 등 순결정론은 Ollama 없이 동작. |
| `OllamaClient` | judge_tool/judge.py | `OllamaClient(url="http://localhost:11434", model=..., temperature=0.0, timeout=120)`. `.health_check()` = `GET {url}/api/tags`, 실패 시 `RuntimeError`(한글). |
| `guess_profile` | judge_tool/profile.py | `guess_profile(report_path)->(Optional[str],Tuple[str,...])`. `(key,(key,))`=유일 / `(None,(후보들))`=모호 / `(None,())`=추정불가. |
| `list_profile_keys` | profile.py | 배제 아닌 프로파일 키 튜플. |
| `get_profile(key).variants` | profile.py | variant 목록. |
| `_discover_criteria_path` | main.py | 인자 없음. ref/에서 `*평가기준*제*호*.xlsx` 자동탐색, 실패 시 ReportError. |
| `_CANDIDATE_EXTS` | main.py | `(".xml",".json",".xlsx",".csv",".txt")` — 업로드 허용 확장자. |
| 결과 JSON 스키마 | judge_tool/writer.py | `{"metadata":{...},"coverage":{...},"judgments":[asdict(Judgment)]}`. Judgment: `item_id,item_name,variant,risk,verdict("양호"|"취약"|"판단보류"),confidence,rationale,cited_evidence[],scope,management_review_needed,script_status,agreement,needs_review,label("A"~"D"),interview_summary,judgment_method`. metadata: `tool_version,criteria_version,model,generated_at,source_file,source_sha256,profile,variant`. |
| 테스트 대역 | tests/test_main_unit.py | `StubClient`, `_write_synthetic_criteria(path)`, fixtures `sample_aws_report.xml`/`sample_db_mysql.txt`. |
| 대외비 | results/ (repo 루트) | 읽기/쓰기 금지. 프로젝트 저장 루트가 이 안이면 기동 거부. |

핵심 제약: **파일명이 프로파일/variant 식별 입력**(basename substring 마커) → 업로드 자산은 **원본 파일명 그대로 보존 저장**. **Python 3.13에서 `cgi` 제거 → multipart 직접 파싱 금지**, 업로드는 `application/octet-stream` + `X-Filename` 헤더 방식.

## 1. 디렉터리·진입점

신규 파일:
```
judge_tool/webui/
  __init__.py          # 빈 파일
  __main__.py          # python3 -m judge_tool.webui 진입점(argparse)
  server.py            # ThreadingHTTPServer + 라우팅
  store.py             # 프로젝트/자산 디스크 영속화 + 검증
  jobs.py              # 백그라운드 판정 작업 큐(워커 1개)
  static/index.html    # self-contained 단일 HTML(인라인 CSS/JS, 외부 리소스 0)
tests/
  test_webui_store.py
  test_webui_jobs.py
  test_webui_api.py
```
수정 파일: `judge.sh`(--web 분기 3줄), `docs/USAGE.md`(웹 모드 섹션). **main.py/`__main__.py`는 한 줄도 수정 안 함**.

진입: `python3 -m judge_tool.webui [--port 8765] [--host 127.0.0.1] [--project-root PATH] [--ollama-url URL] [--model NAME] [--criteria PATH] [--token TOKEN] [--max-upload-mb 50]`
judge.sh 최상단(`exec python3 -m judge_tool "$@"` 위):
```bash
if [[ "${1:-}" == "--web" ]]; then
  shift
  exec python3 -m judge_tool.webui "$@"
fi
```

`__main__.py` 기본값: host="127.0.0.1"(다른 값 → SystemExit 한글), port=8765, project-root=None(→ `<repo루트>/judge_projects`, repo루트=`judge_tool.main._PKG_ROOT`), ollama-url="http://localhost:11434", model="qwen3-coder:30b", criteria=None(→판정 시점 `_discover_criteria_path()`), token=None, max-upload-mb=50.
기동 시퀀스: (1) project_root 검증(§6: results/ 내부·동일경로 거부)+makedirs, (2) `store.sweep_stale_judging()`(judging 멈춘 자산→failed, error="서버 재시작으로 판정이 중단되었습니다. 다시 실행하세요."), (3) 기동, (4) stdout 한글 배너(접속 URL, 저장위치+대외비 안내, Ctrl+C 종료).

## 2. 데이터 모델 (store.py)

레이아웃:
```
judge_projects/
  p-3f9a2c1e/
    project.json              # 원자적 쓰기(.tmp→os.replace)
    assets/a-7b2d90aa/mysql_result_rds.json   # 원본명 그대로
    results/result_a-7b2d90aa.json / .xlsx
```
asset을 asset_id 하위 디렉터리+원본명 저장: (a)마커 매칭 계약, (b)중복명 허용, (c)traversal 방어 단순화. results/ 하위폴더는 repo 실데이터 results/와 경로 다름(run()은 out 가드 안 함).

project.json(schema_version=1): `{schema_version, project_id("p-"+uuid4().hex[:8]), name, created_at, updated_at, assets:[...]}`.
asset: `{asset_id("a-"+...), original_filename, stored_relpath, size_bytes, sha256, uploaded_at, profile, profile_source("guessed"|"user"|null), profile_candidates:[], variant(기본 null=자동식별), status("pending"|"judging"|"judged"|"failed"), error, result_json_relpath, result_xlsx_relpath, summary, judged_at}`.
status 전이: pending→judging→(judged|failed), failed→judging(재실행), judged→judging(재판정).
summary(judged): `{expected,judged,missing:[],verdict_counts:{"양호":n,"취약":n,"판단보류":n},needs_review:n}` — jobs가 결과JSON 집계.
시각 포맷 `"%Y-%m-%d %H:%M:%S"`(main.py meta 동일). ID는 `_new_id(prefix)` 함수 분리(테스트 monkeypatch).

`ProjectStore(root)` 공개 API(모든 쓰기 self._lock=RLock + 원자적 저장):
`create_project(name)->dict`, `list_projects()->list[dict]`(요약: id/name/created_at/asset_count/status_counts), `get_project(pid)->dict`(없으면 KeyError→404), `add_asset(pid,filename,data:bytes)->dict`(검증: ①basename 강제+금지패턴(빈문자,"..","/","\\",NUL)→ValueError ②확장자∈_CANDIDATE_EXTS→ValueError ③크기≤상한→ValueError; 저장 후 guess_profile로 profile/candidates 채움), `set_asset_profile(pid,aid,profile,variant)->dict`(profile은 list_profile_keys 검증, variant는 get_profile(profile).variants 검증, judging중이면 ValueError), `update_asset(pid,aid,**fields)->dict`, `asset_abspath(pid,aid)->str`(traversal 재검증), `result_paths(pid,aid)->(json,xlsx)`, `sweep_stale_judging()->int`, `get_asset(pid,aid)`, `delete_asset(pid,aid)`(judging이면 ValueError), `delete_project(pid)`.
ID 검증 정규식(경로 파라미터 공통): `^[ap]-[0-9a-f]{8}$` 불일치→400. `asset_abspath`는 이중방어로 `os.path.realpath`가 `realpath(root)+os.sep` 하위인지 재확인(_is_within 5줄 로직 store.py에 사설 복사).

## 3. HTTP API (server.py)

`http.server.ThreadingHTTPServer`+`BaseHTTPRequestHandler`, `daemon_threads=True`. 바인딩 리터럴 "127.0.0.1". 핸들러에 store/job_manager/config 주입. 테스트용 `make_server(store, jobs, config, port=0)->ThreadingHTTPServer` 팩토리(포트0 기동).
공통: 응답 `application/json; charset=utf-8`, `{"ok":true,...}`/오류 `{"ok":false,"error":"<한글>"}`. body는 Content-Length 필수(없으면 411), max_upload 초과 선언→413(읽기 전 거부). `ReportError/ValueError→400`, `KeyError→404`, 예상밖→500 `{"error":"서버 내부 오류(<타입명>)"}`(증거 유출 방지).

| 메서드·경로 | 요청 | 응답 | 동작 |
|---|---|---|---|
| GET / | — | text/html | static/index.html 반환 |
| GET /api/health | — | `{ok,ollama:{ok,error},model,ollama_url,project_root}` | health_check 호출, RuntimeError→ollama.ok=false. HTTP 항상 200 |
| GET /api/profiles | — | `{ok,profiles:[{key,variants:[]}]}` | list_profile_keys + variants |
| GET /api/projects | — | `{ok,projects:[요약]}` | list_projects |
| POST /api/projects | `{name}` | `{ok,project}` 201 | create_project (빈 name→400) |
| GET /api/projects/{pid} | — | `{ok,project}` | 폴링 겸용 |
| POST /api/projects/{pid}/delete | `{}` | `{ok}` | delete_project |
| POST /api/projects/{pid}/assets | octet-stream + `X-Filename:encodeURIComponent(원본명)` | `{ok,asset}` 201 | unquote→add_asset. 파일당 1요청 |
| POST /api/projects/{pid}/assets/{aid}/profile | `{profile,variant}` | `{ok,asset}` | set_asset_profile |
| POST /api/projects/{pid}/assets/{aid}/judge | `{}` | `{ok,asset}` 202 | profile null→400; judging→409; enqueue후 status=judging 즉시전이·영속 |
| POST /api/projects/{pid}/judge_all | `{}` | `{ok,enqueued:[],skipped:[{asset_id,reason}]}` | profile 있는 pending/failed 전부 enqueue |
| GET /api/projects/{pid}/assets/{aid} | — | `{ok,asset}` | 단건 폴링 |
| GET /api/projects/{pid}/assets/{aid}/result | — | `{ok,result:<result json 전체>}` | judged 아니면 409 |
| GET /api/projects/{pid}/assets/{aid}/result.xlsx | — | xlsx 바이트 | Content-Disposition attachment, RFC5987 한글 파일명 |
| POST /api/projects/{pid}/assets/{aid}/delete | `{}` | `{ok}` | judging→409; 자산디렉터리+결과 삭제(root 하위 재검증) |

라우팅: `urlparse(path).path`를 정규식 테이블 매칭(`re.fullmatch`). DELETE/PATCH 안 씀, POST 통일.

## 4. 판정 연동 (jobs.py)

`JobManager(store, config)`: `queue.Queue`, `_active`(set, Lock), 워커 스레드 1개 daemon. `start()`, `enqueue(pid,aid)`(_active에 있으면 RuntimeError), `_loop`(queue.get→_run_one→task_done). **워커 1개 순차**(Ollama 단일 서버). 자산 단위 coarse 상태만(run()에 콜백 훅 없음, 엔진 수정 금지). UI는 judging에 스피너+경과시간(클라이언트 계산).

`_run_one(pid,aid)`:
```python
from judge_tool import main as _main       # 모듈참조(테스트 monkeypatch)
from judge_tool.judge import OllamaClient
try:
    asset = self.store.get_asset(pid, aid)
    report = self.store.asset_abspath(pid, aid)
    criteria = self.config.criteria or _main._discover_criteria_path()
    json_out, xlsx_out = self.store.result_paths(pid, aid)
    client = OllamaClient(url=self.config.ollama_url, model=self.config.model)
    cov = _main.run(report, criteria, asset["profile"], client, json_out, xlsx_out,
                    self.config.model, variant_override=asset["variant"])
    summary = _summarize(json_out, cov)
    self.store.update_asset(pid, aid, status="judged", error=None, summary=summary,
        judged_at=_now(), result_json_relpath=..., result_xlsx_relpath=...)
except (ReportError, OSError) as e:
    self.store.update_asset(pid, aid, status="failed", error=str(e))
except Exception as e:
    log.warning("웹 판정 실패 pid=%s aid=%s type=%s", pid, aid, type(e).__name__)
    self.store.update_asset(pid, aid, status="failed",
        error=f"판정 중 오류가 발생했습니다({type(e).__name__}). 파일과 프로파일을 확인하세요.")
finally:
    self._active.discard((pid, aid))
```
`_summarize(json_out,cov)`: 결과JSON 로드→`verdict_counts=Counter(...)`(3키 0기본)+`needs_review` 합+cov 병합. Ollama 미가동은 run() 페일패스트가 ReportError 던짐→그대로 asset.error. enqueue 시점 사전 헬스체크 **안 함**(순결정론 프로파일 배려, _needs_llm이 이미 정확). skip_preflight 기본 False.

## 5. 프론트엔드 (static/index.html 단일)

외부 리소스 0(`<link>`/`<script src>`/webfont/CDN 금지). 시스템 폰트 스택. 바닐라 JS(ES2017), fetch.
2단 레이아웃: 사이드바(프로젝트 목록+새 프로젝트) / 메인(헤더=프로젝트명·Ollama 상태점 → 드래그앤드롭 존 → 자산 테이블 → 결과 패널).
동작: (1)초기화 GET /api/health(끊김이면 노랑 경고)+profiles+projects. (2)드롭존 dragover/drop+숨김 input file multiple, 순차 POST assets(octet-stream+X-Filename). (3)자산 행: profile null이면 빨간 select+후보표시, 변경 시 POST profile, variant 보조 select(기본"자동식별"); 상태배지 대기(회색)/판정중(파랑+CSS스피너)/완료(초록)/실패(빨강+error툴팁); 요약셀 `양호 12·취약 3·판단보류 8·재검토 5`(양호#2e7d32 취약#c62828 판단보류#f9a825). (4)판정 폴링 setInterval(2000) GET project, judging 0되면 clear, 경과시간 mm:ss. (5)결과 패널: 요약카드 3+1(클릭 필터), **인터뷰 패널**(연노랑#FFF2CC, label==="B"||interview_summary truthy 항목의 item_id/name/interview_summary 카드, 제목"담당자 인터뷰 필요 항목"), 항목테이블(ID/명/라벨/판단방식/판정 배지/재검토●/근거 2줄 말줄임→클릭 확장 rationale+cited_evidence, needs_review 행 연노랑), metadata 푸터. (6)새 프로젝트 인라인 입력. (7)토큰 모드: URL ?token= 있으면 모든 fetch에 X-Auth-Token.

## 6. 보안/대외비

1. 바인딩 "127.0.0.1" 리터럴, --host 다른값→SystemExit("대외비 보호를 위해 127.0.0.1만 허용됩니다"). 2. project_root 가드: realpath가 realpath(repo/results)와 같거나 하위면 SystemExit. 3. traversal: pid/aid 정규식 강제(400)+업로드명 basename 강제+".."/"/"/"\\"/NUL→400+디스크 접근 직전 realpath 하위 재검증. 4. 업로드 검증: 확장자 화이트리스트, 크기 상한(Content-Length 선검사), 0바이트→400. 5. 선택 토큰 --token(모든 /api/*에 X-Auth-Token hmac.compare_digest, 불일치 401; GET / 는 허용). 6. 외부접점 0(OllamaClient localhost만), index.html에 외부 http 참조 부재를 테스트로 grep. 7. 오류 응답 스택/증거 미포함.

## 7. 테스트 (Ollama·실데이터 불필요, 합성)

fixture: ProjectStore(tmp)+JobManager+make_server(port=0)+스레드, requests로 접속.
T-1 store CRUD+원자적저장+_new_id monkeypatch. T-2 add_asset(mysql_result_rds.json→db_mysql, foo.xml→None+후보, .exe→ValueError, 크기초과). T-3 traversal(../../evil.xml 거부, NUL). T-4 set_asset_profile 검증+sweep_stale_judging. T-5 jobs: main.run monkeypatch(가짜 result json 기록+cov)→judged+summary verdict_counts. T-6 run이 ReportError("[Ollama 확인 실패]")→failed+한글 보존. T-7 run이 RuntimeError("SECRET")→error에 원문 미포함(타입명만). T-8 프로젝트 CRUD+404/400+pid 정규식 위반. T-9 octet-stream 업로드 e2e(X-Filename 한글)→201+guessed; Content-Length 초과→413. T-10 judge: profile null→400, 정상→202+judging, 폴링 judged(run stub), 중복→409, result/result.xlsx. T-11 /api/health(health_check monkeypatch 양쪽)+index.html 200+본문 `src="http`/`href="http` 부재.
jobs 대기는 queue.join() 또는 타임아웃 폴링(≤5초). 신규 파일만 추가 → 기존 pytest 전체 통과가 SHIP 조건.

## 8. 구현 순서 + 리스크

순서(각 단계 끝 pytest): 1.__init__+store+test_webui_store 2.jobs+test_webui_jobs(run은 _main.run 모듈참조) 3.server+test_webui_api 4.static/index.html 5.__main__+judge.sh --web 3줄+USAGE.md 웹섹션 6.전체 pytest+수동 스모크(./judge.sh --web→mysql_result.txt 드롭).
리스크: 항목단위 진행률 없음(자산단위만); 서버 1개 가정(project.json 락은 프로세스내 RLock, 다중서버 경합 시 .lock pid 경고는 선택); 판정중 종료→sweep failed; .xml 단독은 항상 모호(후보 강제 정상). 
확정(구현 포함): 프로젝트 삭제 O, judge_projects 기본 repo 하위(--project-root 변경).

# judge_tool — 전자금융기반시설 보안 취약점 자동판정 도구

전자금융기반시설 보안 점검 결과 파일을 평가기준(xlsx)에 따라 자동 판정하는 CLI/웹 도구.
항목 성격에 따라 **결정론 엔진**(감사가능·환각 0), **로컬 LLM**(Ollama, 폐쇄망 동작),
**인터뷰 요약**(자동판정 불가 항목은 판단보류 + 점검자용 참고정보)을 조합해 판정하며,
불확실하면 양호가 아니라 **판단보류**로 귀결시키는 fail-closed(거짓양호 최소화) 원칙을 따른다.

## 지원 도메인

| 점검분야 | 프로파일 | 입력 형식 |
|---|---|---|
| 서버 (Linux) | `server` | 점검 스크립트 결과 XML |
| DBMS | `db_mysql` `db_oracle` `db_mssql` `db_mariadb` `db_postgresql` (`db_tibero`는 실샘플 검증 전 배제) | 수집 스크립트 결과 JSON — native/RDS/Aurora/Azure 변형 자동식별 |
| WEB·WAS | `webwas` | 점검 결과 XML (Apache/IIS/WebtoB) |
| 네트워크 | `network` | 점검 결과 XML |
| 정보보호시스템 | `iss`(방화벽 정책), `iss_device`(장비) | FW 정책 export xlsx/csv (SECUI·PaloAlto·한글13열 등) / XML |
| 클라우드 | `cloud` | AWS/Azure 점검 결과 XML |
| 컨테이너 | `container` | k8s/docker 점검 결과 XML |
| OS가상화 | `osvirt` | 점검 결과 XML |

프로파일·변형은 파일명/확장자로 자동추정된다(`--profile`/`--variant`로 강제 지정 가능).

## 설치

요구사항: **Python 3.10+**, (LLM 판정 항목용) **Ollama + qwen3-coder:30b**.

```bash
# 1) 파이썬 의존성
python3 -m pip install -r requirements.txt
# 폐쇄망: python3 -m pip install --no-index --find-links=wheelhouse -r requirements.txt

# 2) 로컬 LLM (판정에 LLM이 필요한 항목용 — 결정론 전용 프로파일은 --skip-preflight로 생략 가능)
ollama serve            # 서버 기동
ollama pull qwen3-coder:30b
```

평가기준 xlsx는 `ref/` 아래에 두면 자동탐색된다(`*평가기준*제N호*.xlsx`, 복수면 최신 호 선택).
비개발자용 단계별 안내(폐쇄망 설치·트러블슈팅 포함)는 **[docs/USAGE.md](docs/USAGE.md)** 참조.

## 사용법

```bash
./judge.sh                          # ① 무인자 → 대화형 모드 (파일 경로만 입력하면 됨)
./judge.sh result.xml               # ② 단일 파일 — 프로파일/평가기준 자동추정 후 판정
./judge.sh 점검결과폴더/             # ③ 폴더 배치 — 폴더 안 파일들을 순차 판정
./judge.sh --web                    # ④ 로컬 웹 UI (127.0.0.1:8765)
```

동일 명령의 모듈 형태: `python3 -m judge_tool <파일> [옵션]`, `python3 -m judge_tool.webui`.

### 주요 옵션

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--report <경로>` | (위치인자와 동일) | 점검 결과 파일/폴더 |
| `--criteria <xlsx>` | `ref/` 자동탐색 | 평가기준 엑셀 |
| `--profile <키>` | 파일명 자동추정 | 지원 목록은 위 표 |
| `--variant <키>` | 파일명 자동식별 | 예: `oracle_native`, `mysql_rds` |
| `--out-dir <경로>` | `out` | 산출물 디렉터리 |
| `--model` / `--ollama-url` | `qwen3-coder:30b` / `localhost:11434` | 로컬 LLM 설정 |
| `--skip-preflight` | 꺼짐 | Ollama 헬스체크·LLM 게이트 생략 (오프라인/결정론 전용) |
| `--aux-objects <yaml>` | 없음 | FW 그룹객체 정의 (미지정 시 미해석 정책=판단보류) |
| `--hashcat-*` | 자동탐지 | 패스워드 크랙 검증 연동 (DBM-001) |

### 산출물

`out/` 아래 `result_<파일명>.json`(전체 판정 상세) + `result_<파일명>.xlsx`(항목별 판정·근거·
인터뷰 참고사항). 판정값은 **양호 / 취약 / 판단보류** 3종.

### 웹 UI

`./judge.sh --web` → 프로젝트 생성 → **점검분야(8분야) → 대상(시스템) → 결과 파일** 계층으로
드래그앤드롭 조직화 → 대상/분야 단위 일괄 판정 → 색 구분 항목표·인터뷰 참고 패널.
데이터는 `judge_projects/`(git 미추적)에 로컬 저장된다.

## 판정 방식

평가기준의 각 항목은 성격에 따라 라우팅된다:

- **결정론(det)** — 이진/기계적 점검(설정값·권한·포트 등). LLM 무관여, 근거 인용 포함.
  방화벽(ISS-030~041)은 순수 결정론(ipaddress+집합연산).
- **LLM(label A)** — 맥락 판단이 필요한 항목. 로컬 qwen3-coder만 사용(외부 API 없음).
- **인터뷰(label B/C)** — 업무상 필요성 등 사람 확인이 필요한 항목. 판단보류 + 수집증거
  요약을 인터뷰 참고정보로 제공.
- 수집 실패·0행·미해석 데이터는 어느 경로든 **판단보류**로 귀결(거짓양호 봉쇄 가드).

## 프로젝트 구조

```
judge_tool/
├── main.py            # CLI 진입점·판정 오케스트레이션 (_HANDLERS 라우팅)
├── judge.py           # LLM(Ollama) 판정 클라이언트
├── criteria_loader.py # 평가기준 xlsx 로더 (항목 라벨 분류)
├── profile.py         # 프로파일 레지스트리·파일명 자동추정
├── parsers/           # 도메인별 결과 파일 파서 (XML/JSON/xlsx)
├── det_adapters/      # 결정론 판정 어댑터 (거짓양호 가드 포함)
├── fw_policy.py       # 방화벽 이상정책 결정론 탐지 (ISS-030~041)
├── item_configs/      # 프로파일별 항목 설정 yaml
├── vendor/            # 점검 스크립트 벤더 분석 로직 (외부 코드 스냅샷)
├── eol.py / eol.yaml  # EoS/EOL 기준선 (출처 URL·as_of 신선도 관리)
└── webui/             # 로컬 웹 UI (stdlib http.server, 127.0.0.1 전용)
tests/                 # pytest 회귀 스위트 (판정 동작 변경 시 전체 통과 필수)
docs/USAGE.md          # 비개발자용 운영 매뉴얼
docs/superpowers/      # 설계 문서·작업 인계 노트 (PROGRESS.md = 단일 진실원천)
```

## 테스트

```bash
python3 -m pytest tests/ -q
```

판정 동작 변경은 회귀 위험이 있으므로 변경 후 전체 통과를 확인한다.
양호/취약 양극성 커버리지 픽스처(`tests/*_cov_contract.py`)가 거짓양호 회귀를 상시 감시한다.

## 주의

- `results/`(실데이터, 대외비)는 읽기 전용 — 산출물은 `out/` 등 별도 경로만 사용.
- 판정은 전부 로컬에서 수행된다(외부 API 전송 없음) — 폐쇄망 운용 전제.

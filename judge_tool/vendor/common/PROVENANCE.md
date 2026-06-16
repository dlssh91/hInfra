# PROVENANCE.md — vendor/common 스냅샷 추적

> 목적: common 원본과 이 벤더 디렉터리의 관계를 추적. 실제 common 모듈은 아직 복사되지 않음.

---

## 현재 상태 (2026-06-16)

**Phase 0 완료**: 데이터 아티팩트(`DET_SOURCE.yaml`, `KNOWN_BUGS.md`) 작성.  
**Phase 1 완료**: 서버 모듈 벤더링 완료. `judge_tool/vendor/common/server/` 아래 3개 파일 존재.
**Phase 2 완료**: 컨테이너 모듈 벤더링 완료. `judge_tool/vendor/common/container/` 아래 `autoAnalysis.py` 존재.
**Phase 3 완료**: 웹서버-WAS 모듈 벤더링 완료. `judge_tool/vendor/common/webwas/` 아래 4개 파일 존재.
**Phase 4 완료**: DB 모듈 벤더링 완료. `judge_tool/vendor/common/db/` 아래 5엔진 analysis.py + config/*.json 존재.

```
judge_tool/vendor/common/
├── __init__.py
├── DET_SOURCE.yaml          ← Phase 0 산출 (§18.0), Phase 3/4에서 WST/DBM 항목 추가
├── KNOWN_BUGS.md            ← Phase 0 산출 (§18.0)
├── PROVENANCE.md            ← 본 파일
├── server/
│   ├── __init__.py
│   ├── sclib.py             ← Phase 1: 순수 헬퍼 추출 (Django 의존 제거)
│   ├── SRV_auto_parse.py    ← Phase 1: 원본 복사 + VENDOR-EDIT(a) + VENDOR-EDIT(bug)
│   └── SRV_Linux_parse.py   ← Phase 1: 원본 복사 + VENDOR-EDIT(a)
├── container/
│   ├── __init__.py
│   └── autoAnalysis.py      ← Phase 2: 원본 비트동일 복사 (VENDOR-EDIT 없음)
├── webwas/
│   ├── __init__.py
│   ├── wslib.py             ← Phase 3: Django 의존 제거, get_remove_line 순수함수만 추출
│   ├── WST_Apache_parse.py  ← Phase 3: 원본 복사 + VENDOR-EDIT(a) import 경로 수정
│   ├── WST_IIS_parse.py     ← Phase 3: 원본 복사 + VENDOR-EDIT(a) + VENDOR-EDIT(bug) WST-102
│   └── WST_WebtoB_parse.py  ← Phase 3: 원본 복사 + VENDOR-EDIT(a) import 경로 수정
└── db/
    ├── __init__.py
    ├── config/
    │   ├── mysql-config.json     ← Phase 4: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    │   ├── oracle-config.json    ← Phase 4: 원본 비트동일 복사
    │   ├── mssql-config.json     ← Phase 4: 원본 비트동일 복사
    │   ├── mariadb-config.json   ← Phase 4: 원본 비트동일 복사
    │   ├── postgresql-config.json← Phase 4: 원본 비트동일 복사
    │   └── tibero-config.json    ← Phase 4: 원본 비트동일 복사
    ├── mysql/
    │   ├── __init__.py
    │   ├── analysis.py          ← Phase 4: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    │   └── cloud_analysis.py    ← Phase 4b: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    ├── oracle/
    │   ├── __init__.py
    │   ├── analysis.py          ← Phase 4: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    │   └── cloud_analysis.py    ← Phase 4b: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    ├── mssql/
    │   ├── __init__.py
    │   ├── analysis.py          ← Phase 4: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    │   └── cloud_analysis.py    ← Phase 4b: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    ├── mariadb/
    │   ├── __init__.py
    │   ├── analysis.py          ← Phase 4: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    │   └── cloud_analysis.py    ← Phase 4b: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    ├── postgresql/
    │   ├── __init__.py
    │   ├── analysis.py          ← Phase 4: 복사 + VENDOR-EDIT(bug) dbm_009 극성 수정 (Batch1, KNOWN_BUGS R-PG009)
    │   └── cloud_analysis.py    ← Phase 4b: 원본 비트동일 복사 (VENDOR-EDIT 없음)
    └── tibero/
        ├── __init__.py
        └── analysis.py          ← Phase 4: 원본 비트동일 복사 (tibero excluded, 미등록)
```

### Phase 1 벤더링 상세

**원본**: `flus-main/app/common/ServerConfigLoader/` (스냅샷 2026-04, frozen)

**서버 모듈 VENDOR-EDIT 목록**:
| 파일 | 종류 | 내용 |
|------|------|------|
| `sclib.py` | (a) 신규 작성 | Django/lxml/openpyxl 의존 제거. `DELIMITER`, `get_check_service`, `get_check_service_escape_ver`, `get_remove_line`, `split_output` 순수 헬퍼만 추출. `robust_parse_xml`은 NotImplementedError 스텁(어댑터 미사용 경로). |
| `SRV_auto_parse.py` | (a) import 경로 | `from common.ServerConfigLoader.sclib` → `from judge_tool.vendor.common.server.sclib` |
| `SRV_auto_parse.py` | (bug) SRV-010-polarity | `check_SRV_010` sendmail 분기 (lines 945-946) reason 문자열 역전 수정. result(Y/N)은 원본 그대로, reason 마커만 교정: `if not restrictq`→`(-)취약`, `else`→`(+)양호`. |
| `SRV_Linux_parse.py` | (a) import 경로 | `from common.ServerConfigLoader.sclib` → `from judge_tool.vendor.common.server.sclib` |

**미벤더링**: AIX/HPUX/Solaris/Win 파서 — Phase 1은 linux 파일럿만. 향후 OS별 파서는 각 Phase에서 추가.

**어댑터**: `judge_tool/det_adapters/server.py` — Phase 1 서버 결정론 어댑터.
  - DET_SOURCE gate 통과(DET) 항목만 결정론 판정
  - linux variant + {SRV-026,069,074,127,131} → SRV_Linux_parse 오버라이드 (§16.3)
  - 레지스트리 `_DET_ADAPTERS["server"]` 자동 등록 (import 부작용)

---

## common 원본 경로

```
flus-main/app/common/
├── ServerConfigLoader/
│   ├── SRV_auto_parse.py
│   ├── SRV_Linux_parse.py
│   ├── SRV_AIX_parse.py
│   ├── SRV_HPUX_parse.py
│   ├── SRV_Solaris_parse.py
│   ├── SRV_auto_parse_win.py
│   └── sclib.py
├── WebServerConfigLoader/
│   └── WST_IIS_parse.py
├── PrivatecloudConfigLoader/
│   └── autoAnalysis.py
├── NetworkConfigAnalysis/
│   ├── v202001R1/NetworkConfig.py
│   └── v202101R1/NetworkConfig.py
└── ...
```

**스냅샷 기준일**: 2026-04 (frozen, churn 낮음)  
**레포 위치**: `flus-main/` (레포 내 형제 디렉터리, 항시 존재 보장 없음 → 벤더링 결정 이유)

---

## VENDOR-EDIT 규칙 (§5.1/§18.2)

벤더 코드에 허용되는 편집은 **3종뿐**. 각 편집은 파일 상단 `# VENDOR-EDIT:` 주석을 달고 이 파일에 기록.

### (a) 경로 prefix 제거/주입
**대상**: `Config` 클래스, DB config JSON 경로 하드코딩 등.  
**규칙**: `# VENDOR-EDIT(path): 원본경로 → 인수 주입 or vendor_root 기준 상대경로`

### (b) 임계값 상수화
**대상**: 서버 하드코딩 임계값(90일, 900초, 파일권한 비트 등).  
**규칙**: 리터럴을 모듈 상수(`_TH = {...}`)로 끌어올리고 어댑터가 호출 전 override 가능하게.  
`# VENDOR-EDIT(threshold): 원본값 → _TH 키 명시`

### (c) KNOWN_BUGS 등재 버그 수정 (§18.2 추가)
**대상**: `KNOWN_BUGS.md`에 등재된 5건 버그(SRV-010-polarity, WST-102-iis-polarity, WST-040-polarity, PRCV-027-036-unreachable, NET-051-typo)에 한정.  
**규칙**: `# VENDOR-EDIT(bug): <bug-id> — <1줄 수정 요약>`  
각 수정은 corrected 동작을 단언하는 핀고정 회귀테스트와 함께 도입.

> ⚠️ **금지**: 위 3종 외 변경(로직 추가, 임계값 재정의, 새 버그 수정 등)은 이 규칙 밖. 발견 시 KNOWN_BUGS.md에 신규 등재 후 사용자 승인 절차.

---

## 벤더 편집 이력

| Phase | 파일 | VENDOR-EDIT 종류 | 내용 | 날짜 |
|-------|------|-----------------|------|------|
| Phase 1 | `server/sclib.py` | (a) 신규 작성 | Django/lxml 의존 제거, 순수 헬퍼만 추출 | 2026-06-16 |
| Phase 1 | `server/SRV_auto_parse.py` | (a) import 경로 | `from common.ServerConfigLoader.sclib` → 벤더 경로 | 2026-06-16 |
| Phase 1 | `server/SRV_auto_parse.py` | (bug) SRV-010-polarity | `check_SRV_010` sendmail 분기 reason 역전 수정 | 2026-06-16 |
| Phase 1 | `server/SRV_Linux_parse.py` | (a) import 경로 | `from common.ServerConfigLoader.sclib` → 벤더 경로 | 2026-06-16 |
| Phase 2 | `container/autoAnalysis.py` | **없음** | 원본 비트동일 복사. stdlib(`re`, `json`, `traceback`) 의존, Django/lxml 없음. PRCV 포함·미수정. | 2026-06-16 |
| Phase 3 | `webwas/wslib.py` | (a) 신규 작성 | Django/ORM 의존 제거. `get_remove_line` 순수함수만 추출. `parseAnalysisResult` 제거. | 2026-06-16 |
| Phase 3 | `webwas/WST_Apache_parse.py` | (a) import 경로 | `from common.WebServerConfigLoader.wslib` → 벤더 경로 | 2026-06-16 |
| Phase 3 | `webwas/WST_WebtoB_parse.py` | (a) import 경로 | `from common.WebServerConfigLoader.wslib` → 벤더 경로 | 2026-06-16 |
| Phase 3 | `webwas/WST_IIS_parse.py` | (a) import 없음 (IIS는 원본에 wslib import 없음) | 경로 수정 불필요 | 2026-06-16 |
| Phase 3 | `webwas/WST_IIS_parse.py` | (bug) WST-102-iis-polarity | `check_WST_102` line 688: `result = "Y"` → `result = "N"` (위반0건→양호) | 2026-06-16 |
| Phase 3 | `webwas/WST_IIS_parse.py` | (bug) WST-040-polarity 주석 | `check_WST_040` 함수에 VENDOR-EDIT(bug) 주석 추가. xlsx 역전 미해결, 결정론 비활성. | 2026-06-16 |
| Phase 4 | `db/{5엔진}/analysis.py` | **없음** | 원본 비트동일 복사. stdlib(`re`, `datetime`) + dateutil + packaging 의존, Django/lxml 없음. | 2026-06-16 |
| Phase 4 | `db/config/{6엔진}-config.json` | **없음** | 원본 비트동일 복사. 임계값 단일출처. | 2026-06-16 |
| Phase 4b | `db/{5엔진}/cloud_analysis.py` | **없음** | 원본 비트동일 복사 (mysql/oracle/mssql/mariadb/postgresql). VENDOR-EDIT 없음 확인: 외부 import 없음(stdlib+dateutil+packaging만), 로직/임계값 수정 없음. pg DBM-009 polarity 의심 버그(KNOWN_BUGS.md 등재 대상) 는 수정 금지. | 2026-06-16 |

---

## 채용 버전 결정 (미확정, Phase 1~5에서 도메인별 결정)

| 도메인 | common 원본 파일 | 채용 버전 후보 | 결정 |
|--------|----------------|---------------|------|
| 서버   | SRV_auto_parse.py, SRV_Linux_parse.py | — | Phase 1 결정 |
| 네트워크 | NetworkConfig.py | v202001R1 or v202101R1 | Phase 5 결정 (둘 다 NET-051 오타 존재) |
| OS가상화 | PrivatecloudConfigLoader/autoAnalysis.py | — | Phase 5 결정 |
| 웹(IIS) | WebServerConfigLoader/WST_IIS_parse.py | — | Phase 3 결정 |

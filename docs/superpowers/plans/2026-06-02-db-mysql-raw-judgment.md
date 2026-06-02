# DB(MySQL) 원시증거 LLM 판정 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** judge_tool을 DB(MySQL: rds/aurora/azure) 원시증거(.txt JSON) 분야로 확장 — 새 파서·DB 프로파일·raw 증거가드·민감값 마스킹·LLM 단독 판정.

**Architecture:** 1단계 코어(models/profile/criteria_loader/judge/writer/main) 재사용 + 일반화. DB는 status 사전분류가 없어 reconcile을 status_available=False로 호출(LLM 단독). 손상된 .txt는 원소 단위 토큰 파싱으로 견디고, 민감 해시/평문은 파서 단계에서 마스킹.

**Tech Stack:** Python 3.14(시스템), openpyxl, requests, pytest. **pip install 금지(시스템 패키지)**. 로컬 Ollama.

**스펙:** `docs/superpowers/specs/2026-06-02-db-mysql-raw-judgment-design.md`

## ⚠️ 모든 태스크 공통 안전 규칙 (구현 서브에이전트에 반드시 전달)
- `results/`·`ref/`는 **읽기전용 실데이터. 절대 쓰기/삭제/덮어쓰기 금지.** 테스트 출력은 pytest `tmp_path` 또는 committed `tests/fixtures/`에만.
- **pip install 금지.** 시스템 `python3` 사용.
- 기존 테스트(현재 84 passed)를 깨지 마라. 특히 **cloud 동작 동치**를 보장하라.
- 민감값(해시/평문 비번)은 프롬프트·출력·로그·예외 어디에도 원문을 넣지 마라.

## 파일 구조
- Modify: `judge_tool/models.py` — `Criterion.applicable`, `EvidenceItem.context`.
- Modify: `judge_tool/profile.py` — VariantSpec/Profile 필드 추가, `DB_MYSQL` 등록.
- Modify: `judge_tool/criteria_loader.py` — applicable 계산(마커/eval_type).
- Create: `judge_tool/parsers/db_json.py` — 관대 DB 파서 + 마스킹.
- Modify: `judge_tool/parsers/__init__.py` — `db_json` 등록.
- Modify: `judge_tool/mapper.py` — context 전달(3-tuple 허용).
- Modify: `judge_tool/judge.py` — raw 증거가드, build_prompt(context/mode), reconcile(status_available/flag_vulnerable/empty_means_good).
- Modify: `judge_tool/main.py` — run이 프로파일 속성으로 reconcile/evidence 모드 전달.
- Test: `tests/test_models.py`(가능 시), `tests/test_profile.py`, `tests/test_criteria_loader.py`, `tests/test_db_json.py`(신규), `tests/test_judge.py`, `tests/test_main_db_e2e.py`(신규), `tests/fixtures/sample_db_mysql.txt`(신규).

---

## Task 1: models — Criterion.applicable + EvidenceItem.context

**Files:**
- Modify: `judge_tool/models.py`
- Test: `tests/test_models_db.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_models_db.py`

```python
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _crit(applicable, standard="기준", eval_type="스크립트"):
    return Criterion("DBM-001", "암호", 4.0, "mysql_rds",
                     eval_type, standard, "방법", applicable=applicable)


def test_is_judgeable_uses_applicable_and_standard():
    assert _crit(True, "기준").is_judgeable is True
    assert _crit(False, "기준").is_judgeable is False     # 적용대상 아님
    assert _crit(True, "   ").is_judgeable is False        # 빈 판단기준


def test_applicable_defaults_true_for_backward_compat():
    # applicable 미지정 시 기존 cloud 호출 호환(기본 True)
    c = Criterion("PISM-001", "암호", 5.0, "AWS", "스크립트", "기준", "방법")
    assert c.applicable is True
    assert c.is_judgeable is True


def test_evidence_item_context_default_none():
    it = EvidenceItem("DBM-004", "mysql_rds",
                      [ResourceEvidence("r0", "", "d", "e")])
    assert it.context is None
    it.context = "QUERY: SELECT ..."
    assert "SELECT" in it.context
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_models_db.py -q` → FAIL (`applicable` 인자/`context` 속성 없음)

- [ ] **Step 3: models.py 수정**

`Criterion`에 `applicable: bool = True` 필드 추가(기존 7개 필드 뒤, 기본값으로 backward-compat). `is_judgeable`를 applicable 기반으로 교체:

```python
@dataclass
class Criterion:
    item_id: str
    item_name: str
    risk: Optional[float]
    variant: str
    eval_type: str
    standard: str
    method: str
    applicable: bool = True   # 해당 variant 평가대상 여부(loader가 계산)

    @property
    def is_mixed(self) -> bool:
        return "관리체계" in self.eval_type and "스크립트" in self.eval_type

    @property
    def is_script_based(self) -> bool:
        return "스크립트" in self.eval_type

    @property
    def is_judgeable(self) -> bool:
        """LLM 판정 대상: 해당 variant에 적용되며 판단기준이 비어있지 않음.

        cloud는 loader가 applicable=(is_script_based and eval_type!='N/A')로
        계산해 기존 동작과 동치. DB는 applicable=(평가대상 'o').
        main.run 스킵 조건과 writer.build_coverage expected가 공유한다.
        """
        return self.applicable and bool((self.standard or "").strip())
```

`EvidenceItem`에 `context: Optional[str] = None` 추가:

```python
@dataclass
class EvidenceItem:
    item_id: str
    variant: str
    resources: List[ResourceEvidence] = field(default_factory=list)
    context: Optional[str] = None   # 항목단위 맥락(QUERY/NOTE 등; DB용)
```

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_models_db.py -q` → PASS

- [ ] **Step 5: cloud 회귀 확인** — Run: `python3 -m pytest -q` → 기존 전부 통과(+신규 3). cloud criteria 테스트가 applicable 기본 True로 여전히 통과해야 함.

- [ ] **Step 6: Commit**

```bash
git add judge_tool/models.py tests/test_models_db.py
git commit -m "feat(models): Criterion.applicable + EvidenceItem.context for raw domains"
```

---

## Task 2: profile — VariantSpec/Profile 필드 + DB_MYSQL

**Files:**
- Modify: `judge_tool/profile.py`
- Test: `tests/test_profile_db.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_profile_db.py`

```python
from judge_tool.profile import get_profile, CLOUD, DB_MYSQL


def test_db_mysql_registered():
    p = get_profile("db_mysql")
    assert p is DB_MYSQL
    assert p.sheet_name == "데이터베이스"
    assert p.parser == "db_json"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True


def test_db_variants_columns():
    v = DB_MYSQL.variants
    assert v["mysql_rds"].applicability_col == 17
    assert v["mysql_rds"].standard_col == 37
    assert v["mysql_rds"].method_col == 38
    assert v["mysql_aurora"].applicability_col == 18
    assert v["mysql_azure"].applicability_col == 19
    # DB는 eval_type 컬럼 없음
    assert v["mysql_rds"].eval_type_col is None


def test_db_variant_from_filename():
    assert DB_MYSQL.variant_from_filename("mysql_result_rds.txt") == "mysql_rds"
    assert DB_MYSQL.variant_from_filename("mysql_result_aurora.txt") == "mysql_aurora"
    assert DB_MYSQL.variant_from_filename("mysql_result_azure.txt") == "mysql_azure"
    assert DB_MYSQL.variant_from_filename("mysql_result.txt") is None  # 온프렘 미지원


def test_cloud_profile_defaults_unchanged():
    assert CLOUD.evidence_mode == "preclassified"
    assert CLOUD.status_available is True
    assert CLOUD.flag_vulnerable_for_review is False
    # cloud VariantSpec은 eval_type_col 보유, applicability_col 없음
    assert CLOUD.variants["AWS"].eval_type_col == 11
    assert CLOUD.variants["AWS"].applicability_col is None


def test_empty_means_good_set():
    assert "DBM-017" in DB_MYSQL.empty_means_good
    assert "DBM-028" in DB_MYSQL.empty_means_good
    assert "DBM-004" not in DB_MYSQL.empty_means_good
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_profile_db.py -q` → FAIL

- [ ] **Step 3: profile.py 수정**

`VariantSpec`: `eval_type_col`을 Optional로 바꾸고 `applicability_col` 추가. `Profile`: 신규 필드(기본값으로 cloud 불변) 추가. `DB_MYSQL` 정의·등록.

```python
import os
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple


@dataclass(frozen=True)
class VariantSpec:
    name: str
    standard_col: int
    method_col: int
    filename_markers: Tuple[str, ...]
    eval_type_col: Optional[int] = None      # cloud: 적용여부 판정용. DB: 없음.
    applicability_col: Optional[int] = None  # DB: 평가대상 'o' 컬럼. cloud: 없음.


@dataclass(frozen=True)
class Profile:
    key: str
    sheet_name: str
    header_row: int
    data_start_row: int
    id_col: int
    name_col: int
    risk_col: int
    variants: Dict[str, VariantSpec]
    parser: str
    evidence_mode: str = "preclassified"          # "preclassified"|"raw"
    status_available: bool = True                 # False면 LLM 단독(교차비교 없음)
    flag_vulnerable_for_review: bool = False       # True면 verdict=취약도 needs_review
    empty_means_good: FrozenSet[str] = frozenset() # 빈 RESULT=양호신호인 base id

    def normalize_id(self, raw: str) -> str:
        m = re.match(r"\s*([A-Za-z]+)[_-](\d+)", raw)
        if not m:
            return raw.strip().upper()
        return f"{m.group(1).upper()}-{int(m.group(2)):03d}"

    def variant_from_filename(self, filename: str) -> Optional[str]:
        low = os.path.basename(filename).lower()
        for vspec in self.variants.values():
            if any(marker in low for marker in vspec.filename_markers):
                return vspec.name
        return None
```

기존 CLOUD 정의에서 VariantSpec 인자는 키워드라 그대로 동작(eval_type_col=11 등). CLOUD 뒤에 추가:

```python
# DB(MySQL) — 원시증거. 평가대상 'o' 컬럼으로 적용여부 판정(eval_type 컬럼 없음).
# 컬럼(열 인덱스): 적용 rds=17/aurora=18/azure=19, 판단기준 37/39/41, 판단방법 38/40/42.
DB_MYSQL = Profile(
    key="db_mysql",
    sheet_name="데이터베이스",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=7,
    risk_col=8,
    parser="db_json",
    evidence_mode="raw",
    status_available=False,
    flag_vulnerable_for_review=True,
    # 위반필터형 쿼리(빈 결과=위반 0건=양호 신호). 스크립트 분석 기준.
    empty_means_good=frozenset({"DBM-005", "DBM-017", "DBM-019", "DBM-028"}),
    variants={
        "mysql_rds": VariantSpec(
            "mysql_rds", standard_col=37, method_col=38,
            applicability_col=17, filename_markers=("mysql_result_rds",)),
        "mysql_aurora": VariantSpec(
            "mysql_aurora", standard_col=39, method_col=40,
            applicability_col=18, filename_markers=("mysql_result_aurora",)),
        "mysql_azure": VariantSpec(
            "mysql_azure", standard_col=41, method_col=42,
            applicability_col=19, filename_markers=("mysql_result_azure",)),
    },
)

_PROFILES = {CLOUD.key: CLOUD, DB_MYSQL.key: DB_MYSQL}
```

(주의: `field` import는 미사용이면 넣지 말 것. frozenset 기본값은 immutable이라 dataclass field 직접 기본값으로 안전.)

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_profile_db.py -q` → PASS

- [ ] **Step 5: cloud 회귀** — Run: `python3 -m pytest -q` → 전부 통과

- [ ] **Step 6: Commit**

```bash
git add judge_tool/profile.py tests/test_profile_db.py
git commit -m "feat(profile): DB_MYSQL profile + raw/status flags + applicability_col"
```

---

## Task 3: criteria_loader — applicable 계산(마커 vs eval_type)

**Files:**
- Modify: `judge_tool/criteria_loader.py`
- Test: `tests/test_criteria_loader_db.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_criteria_loader_db.py`

```python
import openpyxl
from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import DB_MYSQL


def _make_db_xlsx(path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "데이터베이스"
    ws.cell(4, 2, "평가항목ID"); ws.cell(4, 7, "평가항목"); ws.cell(4, 8, "위험도")
    ws.cell(4, 17, "평가대상(AWS RDS MYSQL)")
    ws.cell(4, 37, "판단기준(RDS)"); ws.cell(4, 38, "판단방법(RDS)")
    # row5: rds 적용(o) + 판단기준 있음 → judgeable
    ws.cell(5, 2, "DBM-001"); ws.cell(5, 7, "비밀번호"); ws.cell(5, 8, 4.0)
    ws.cell(5, 17, "o"); ws.cell(5, 37, "* 양호 - ...\n* 취약 - ..."); ws.cell(5, 38, "확인방법")
    # row6: rds 적용 아님(공란) → not applicable
    ws.cell(6, 2, "DBM-099"); ws.cell(6, 7, "해당없음"); ws.cell(6, 8, 3.0)
    ws.cell(6, 37, "* 양호 - ..."); ws.cell(6, 38, "방법")
    wb.save(path)


def test_db_applicable_from_marker(tmp_path):
    p = str(tmp_path / "db.xlsx")
    _make_db_xlsx(p)
    crit = load_criteria(p, DB_MYSQL)
    c1 = crit[("DBM-001", "mysql_rds")]
    assert c1.applicable is True and c1.is_judgeable is True
    assert "양호" in c1.standard
    c99 = crit[("DBM-099", "mysql_rds")]
    assert c99.applicable is False and c99.is_judgeable is False
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_criteria_loader_db.py -q` → FAIL (applicable이 항상 True 기본값이라 DBM-099도 True)

- [ ] **Step 3: criteria_loader.py 수정**

variant별 Criterion 생성 시 applicable을 프로파일 방식대로 계산. `vspec.applicability_col`이 있으면 마커('o') 모드, 없으면 eval_type 모드(cloud 동치). `eval_type`은 컬럼 없으면 "".

기존 루프(`for vname, vspec in profile.variants.items():`) 내부를 아래로 교체:

```python
            for vname, vspec in profile.variants.items():
                eval_type = (_cell(ws, row, vspec.eval_type_col)
                             if vspec.eval_type_col else "")
                standard = _cell(ws, row, vspec.standard_col)
                method = _cell(ws, row, vspec.method_col)
                if vspec.applicability_col is not None:
                    # DB: 평가대상 컬럼 'o'
                    marker = _cell(ws, row, vspec.applicability_col).strip().lower()
                    applicable = (marker == "o")
                else:
                    # cloud: 기존 is_judgeable 동치(스크립트 기반 & N/A 아님)
                    applicable = ("스크립트" in eval_type) and eval_type != "N/A"
                out[(item_id, vname)] = Criterion(
                    item_id=item_id,
                    item_name=name,
                    risk=risk,
                    variant=vname,
                    eval_type=eval_type,
                    standard=standard,
                    method=method,
                    applicable=applicable,
                )
```

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_criteria_loader_db.py -q` → PASS

- [ ] **Step 5: cloud 동치 회귀 (중요)** — Run: `python3 -m pytest tests/test_criteria_loader.py -q` 및 `python3 -m pytest -q` → cloud criteria 로딩/coverage가 기존과 동일하게 통과. (cloud applicable = 스크립트&≠N/A = 기존 is_judgeable 술어와 동치)

- [ ] **Step 6: Commit**

```bash
git add judge_tool/criteria_loader.py tests/test_criteria_loader_db.py
git commit -m "feat(criteria_loader): compute applicable per profile (marker vs eval_type)"
```

---

## Task 4: parsers/db_json.py — 관대 파서 + 마스킹 (1부: 마스킹 + 행 파싱)

**Files:**
- Create: `judge_tool/parsers/db_json.py`
- Test: `tests/test_db_json.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_db_json.py`

```python
from judge_tool.parsers import db_json


def test_mask_row_hash_and_plaintext():
    row = {"USER": "u1", "AUTHENTICATION_STRING": "$A$005$ABCDEF0123456789hash",
           "PLUGIN": "caching_sha2_password", "ACCOUNT_LOCKED": "N"}
    m = db_json._mask_row(row)
    assert "ABCDEF0123456789" not in m["AUTHENTICATION_STRING"]
    assert "REDACTED" in m["AUTHENTICATION_STRING"]
    assert "len=" in m["AUTHENTICATION_STRING"]
    assert m["PLUGIN"] == "caching_sha2_password"   # 비민감 보존
    assert m["ACCOUNT_LOCKED"] == "N"


def test_mask_row_plaintext_password_column():
    # DBM-005류: COLUMN_NAME이 비번류면 RESULT 값(평문)을 마스킹
    row = {"TABLE_SCHEMA": "app", "TABLE_NAME": "users",
           "COLUMN_NAME": "user_password", "RESULT": "PlainText123!,secret9"}
    m = db_json._mask_row(row)
    assert "PlainText123" not in m["RESULT"]
    assert "REDACTED" in m["RESULT"]
    assert m["TABLE_NAME"] == "users"   # 비민감 보존
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_db_json.py -q` → FAIL (모듈 없음)

- [ ] **Step 3: db_json.py 1부 구현(마스킹)**

```python
import json
import re
from typing import Dict, List, Optional, Tuple

from judge_tool.errors import ReportError
from judge_tool.models import ResourceEvidence

# 민감 키(해시/비번류)
_PASS_KEY = re.compile(r"(pass|pwd|pswd|auth\w*string|hash|secret)", re.I)
# MySQL 해시류 값 패턴: $A$..., *HEX, 긴 hex
_HASH_VAL = re.compile(r"^\*?[0-9A-Fa-f]{16,}$|^\$[A-Za-z0-9]")
# JSON 문자열을 깨뜨리는 raw 제어문자(탭/개행 제외)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _mask_value(key: str, val: str) -> str:
    if _PASS_KEY.search(key) or _HASH_VAL.match(val.strip()):
        return f"<REDACTED len={len(val)}>"
    return val


def _mask_row(row: Dict) -> Dict:
    """행 dict에서 민감값 마스킹. 길이는 노출(존재 인지), 구조 키는 보존.

    - 키가 비번/해시류이거나 값이 해시패턴이면 마스킹.
    - COLUMN_NAME이 비번류인 행(DBM-005)의 RESULT 값(평문)도 마스킹.
    """
    col = str(row.get("COLUMN_NAME", "")).lower()
    pass_col = bool(_PASS_KEY.search(col))
    out = {}
    for k, v in row.items():
        if isinstance(v, str) and v:
            if _PASS_KEY.search(k) or _HASH_VAL.match(v.strip()):
                out[k] = _mask_value(k, v)
            elif pass_col and k.upper() == "RESULT":
                out[k] = f"<REDACTED 평문추정 len={len(v)}>"
            else:
                out[k] = v
        else:
            out[k] = v
    return out
```

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_db_json.py -q` → PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/parsers/db_json.py tests/test_db_json.py
git commit -m "feat(db_json): sensitive value masking (hash + plaintext heuristic)"
```

---

## Task 5: parsers/db_json.py — 2부: 관대 파서 본체 + 레지스트리

**Files:**
- Modify: `judge_tool/parsers/db_json.py`
- Modify: `judge_tool/parsers/__init__.py`
- Test: `tests/test_db_json.py`, `tests/fixtures/sample_db_mysql.txt` (신규)

- [ ] **Step 1: 합성 픽스처 작성** `tests/fixtures/sample_db_mysql.txt` (민감정보 없음; 손상 양상 재현)

```
[INFO] 탐지된 환경: AWS RDS MySQL (State=2)
[
{"DBM-001":{
"QUERY": "SELECT Host, User, password, plugin, account_locked FROM mysql.user",
"RESULT": [
{"HOST": "%","USER": "app","AUTHENTICATION_STRING": "$A$005$FAKEFAKEFAKE0123456789","PLUGIN": "caching_sha2_password","ACCOUNT_LOCKED": "N"},
{"HOST": "localhost","USER": "root","AUTHENTICATION_STRING": "$A$005$ZZZZ1111","PLUGIN": "caching_sha2_password","ACCOUNT_LOCKED": "N"},
]}},
{"DBM-004":{
"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES",
"RESULT": [
{"GRANTEE": "'app'@'%'","PRIVILEGE_TYPE": "SELECT"},
{"GRANTEE": "'app'@'%'","PRIVILEGE_TYPE": "SUPER"},
]}},
{"DBM-017":{
"QUERY": "SELECT GRANTEE, PRIVILEGE_TYPE ... WHERE ... NOT IN ('USAGE')",
"RESULT": [
]}},
{"DBM-011":{
"QUERY": "SELECT VARIABLE_NAME, VARIABLE_VALUE ... LIKE audit_log",
"RESULT": [
"audit_log.so plugin is not loaded!"
],
"NOTE": "For audit log upload settings, refer to the PISM-011 script results."
}},
{"DBM-019":{
"NOTE": "관리형 DB를 사용하는 환경일 경우 N/A"
}},
{"DBM-022":{"설치형DB: 서버 스크립트 참고, 그 외: 해당없음"}}
]
```

- [ ] **Step 2: 실패 테스트 추가** `tests/test_db_json.py` 끝에

```python
import os

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sample_db_mysql.txt")


def test_parse_returns_items_with_context():
    out = db_json.parse(FIX)
    by_id = {cid: (res, ctx) for cid, res, ctx in out}
    assert "DBM-001" in by_id and "DBM-004" in by_id
    # DBM-001: 2행, 해시 마스킹됨
    res001, _ = by_id["DBM-001"]
    assert len(res001) == 2
    assert all("FAKEFAKE" not in r.evidence for r in res001)
    assert any("REDACTED" in r.evidence for r in res001)
    # DBM-017: 빈 RESULT → resources 0건
    res017, _ = by_id["DBM-017"]
    assert res017 == []
    # DBM-011: bare 문자열 행 + NOTE(context)
    res011, ctx011 = by_id["DBM-011"]
    assert any("not loaded" in r.evidence or "not loaded" in r.detail
               for r in res011)
    assert ctx011 and "PISM-011" in ctx011
    # DBM-019: NOTE-only → resources 0건, context에 N/A
    res019, ctx019 = by_id["DBM-019"]
    assert res019 == []
    assert ctx019 and "N/A" in ctx019
    # DBM-022: 키only dict → 죽지 않고 처리(빈 resources 또는 context)
    assert "DBM-022" in by_id


def test_parse_includes_query_in_context():
    out = db_json.parse(FIX)
    by_id = {cid: ctx for cid, res, ctx in out}
    assert "USER_PRIVILEGES" in (by_id["DBM-004"] or "")


def test_parse_malformed_raises_reporterror(tmp_path):
    import pytest
    p = tmp_path / "bad.txt"
    p.write_text("this is not json at all {{{", encoding="utf-8")
    with pytest.raises(Exception) as ei:
        db_json.parse(str(p))
    from judge_tool.errors import ReportError
    assert isinstance(ei.value, ReportError)
```

- [ ] **Step 3: 실패 확인** — Run: `python3 -m pytest tests/test_db_json.py -q` → FAIL (`parse` 없음)

- [ ] **Step 4: db_json.py 2부 구현(파서 본체)**

`_mask_row` 아래에 추가. 전략: 선행 비-`[`라인 스킵 → 최상위 배열에서 `{"DBM-...":` 단위로 brace-match 추출 → 각 항목 본문에서 QUERY/RESULT/NOTE 추출 → RESULT는 행 단위로 brace-match·bare문자열 추출 후 개별 sanitize+json.loads(실패 시 raw 보존) → 마스킹.

```python
def _strip_leading_noise(text: str) -> str:
    i = text.find("[")
    if i == -1:
        raise ReportError("DB 결과 파싱 실패: 최상위 배열('[')을 찾을 수 없습니다.")
    return text[i:]


def _iter_top_objects(arr_text: str):
    """최상위 배열 텍스트에서 {...} 객체를 brace-match로 순서대로 yield.
    콤마 누락/트레일링콤마와 무관하게 중괄호 균형만으로 분리한다."""
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(arr_text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                yield arr_text[start:i + 1]
                start = None


def _sanitize_scalar(s: str) -> str:
    return _CTRL.sub("", s)


def _extract_check_id(obj_text: str) -> Optional[str]:
    m = re.search(r'"\s*(DBM-[\w]+)\s*"\s*:', obj_text)
    return m.group(1) if m else None


def _extract_query(inner: str) -> str:
    m = re.search(r'"QUERY"\s*:\s*"(.*?)"\s*,\s*"RESULT"', inner, re.S)
    if not m:
        m = re.search(r'"QUERY"\s*:\s*"(.*?)"', inner, re.S)
    return _sanitize_scalar(m.group(1)) if m else ""


def _extract_note(inner: str) -> str:
    m = re.search(r'"NOTE"\s*:\s*"(.*?)"', inner, re.S)
    return _sanitize_scalar(m.group(1)) if m else ""


def _extract_result_block(inner: str) -> str:
    """`"RESULT": [ ... ]` 의 대괄호 내부 텍스트 반환(없으면 "")."""
    m = re.search(r'"RESULT"\s*:\s*\[', inner)
    if not m:
        return ""
    i = m.end() - 1  # '[' 위치
    depth = 0
    in_str = False
    esc = False
    for j in range(i, len(inner)):
        ch = inner[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return inner[i + 1:j]
    return inner[i + 1:]


def _parse_rows(result_block: str) -> List[ResourceEvidence]:
    """RESULT 내부에서 행 dict와 bare 문자열을 추출.
    각 dict는 sanitize 후 개별 json.loads(실패 시 raw 문자열로 보존), 마스킹."""
    rows: List[ResourceEvidence] = []
    # 1) 행 객체 {...}
    idx = 0
    for obj in _iter_top_objects(result_block):
        san = _sanitize_scalar(obj)
        san = re.sub(r",\s*([}\]])", r"\1", san)  # 트레일링콤마 제거
        try:
            d = json.loads(san)
            if isinstance(d, dict):
                masked = _mask_row(d)
                rows.append(ResourceEvidence(
                    resource_id=f"row{idx}", status="", detail="",
                    evidence=json.dumps(masked, ensure_ascii=False)))
                idx += 1
                continue
        except json.JSONDecodeError:
            pass
        # 파싱 실패 dict → raw 보존(마스킹 불가 시 통째 마스킹 회피 위해 길이만)
        rows.append(ResourceEvidence(
            resource_id=f"row{idx}", status="", detail="(파싱불가 행)",
            evidence=_sanitize_scalar(obj)[:500]))
        idx += 1
    # 2) bare 문자열 행(객체 밖의 "....") — 객체를 제거한 잔여에서 추출
    residue = re.sub(r"\{.*?\}", "", result_block, flags=re.S)
    for sm in re.finditer(r'"([^"]{3,})"', residue):
        val = _sanitize_scalar(sm.group(1))
        if val and val.upper() != "NOTE":
            rows.append(ResourceEvidence(
                resource_id=f"note{idx}", status="", detail=val, evidence=val))
            idx += 1
    return rows


def parse(txt_path: str) -> List[Tuple[str, List[ResourceEvidence], Optional[str]]]:
    """DB 결과 .txt → [(check_id, [ResourceEvidence], context), ...]."""
    try:
        with open(txt_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        arr = _strip_leading_noise(raw)
        out = []
        for obj_text in _iter_top_objects(arr):
            cid = _extract_check_id(obj_text)
            if not cid:
                continue
            # inner = check_id 값(중첩 객체) 본문. 가장 바깥 {} 내부 사용.
            inner = obj_text
            query = _extract_query(inner)
            note = _extract_note(inner)
            result_block = _extract_result_block(inner)
            resources = _parse_rows(result_block) if result_block.strip() or '"RESULT"' in inner else []
            ctx_parts = []
            if query:
                ctx_parts.append(f"QUERY: {query}")
            if note:
                ctx_parts.append(f"NOTE: {note}")
            context = "\n".join(ctx_parts) if ctx_parts else None
            out.append((cid, resources, context))
        if not out:
            raise ReportError("DB 결과 파싱 실패: 유효한 DBM 항목이 없습니다.")
        return out
    except ReportError:
        raise
    except Exception as e:  # noqa: BLE001 - 손상 파일을 명확한 ReportError로 변환
        raise ReportError(
            f"DB 결과 파싱 실패: {txt_path} ({type(e).__name__}). "
            "결과 파일이 손상되었을 수 있습니다.") from e
```

- [ ] **Step 5: parsers/__init__.py에 등록** — `cloud_xml` 옆에 `db_json` 추가:

```python
from judge_tool.parsers import cloud_xml, db_json

_PARSERS = {"cloud_xml": cloud_xml, "db_json": db_json}
```

(기존 `get_parser`는 그대로.)

- [ ] **Step 6: 통과 확인** — Run: `python3 -m pytest tests/test_db_json.py -q` → PASS. 이어 `python3 -m pytest -q` 전체 통과.

- [ ] **Step 7: Commit**

```bash
git add judge_tool/parsers/db_json.py judge_tool/parsers/__init__.py tests/test_db_json.py tests/fixtures/sample_db_mysql.txt
git commit -m "feat(db_json): lenient element-wise parser for DB raw results"
```

---

## Task 6: mapper.aggregate — context 전달(3-tuple 허용)

**Files:**
- Modify: `judge_tool/mapper.py`
- Test: `tests/test_mapper_db.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_mapper_db.py`

```python
from judge_tool.mapper import aggregate
from judge_tool.models import ResourceEvidence
from judge_tool.profile import DB_MYSQL


def test_aggregate_carries_context_and_merges_split():
    raw = [
        ("DBM-017_1", [ResourceEvidence("r0", "", "", "e0")], "QUERY: q1"),
        ("DBM-017_2", [], "QUERY: q2"),
        ("DBM-019", [], "NOTE: 관리형 DB N/A"),
    ]
    items = aggregate(raw, "mysql_rds", DB_MYSQL)
    # 017_1/017_2 → DBM-017 병합
    assert "DBM-017" in items
    assert len(items["DBM-017"].resources) == 1
    assert "q1" in items["DBM-017"].context
    assert items["DBM-019"].context and "N/A" in items["DBM-019"].context


def test_aggregate_backward_compat_2tuple():
    # cloud 파서의 2-tuple도 여전히 동작(context=None)
    raw = [("PISM-001", [ResourceEvidence("r", "good", "d", "e")])]
    from judge_tool.profile import CLOUD
    items = aggregate(raw, "AWS", CLOUD)
    assert items["PISM-001"].context is None
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_mapper_db.py -q` → FAIL

- [ ] **Step 3: mapper.py 수정** — 2/3-tuple 모두 허용, context 병합:

```python
from typing import Dict, List, Optional, Tuple

from judge_tool.models import EvidenceItem, ResourceEvidence
from judge_tool.profile import Profile


def aggregate(raw_checks, variant: str,
              profile: Profile) -> Dict[str, EvidenceItem]:
    """원본 CheckID를 base id로 정규화하며 분할항목을 한 EvidenceItem으로 병합.

    raw_checks 원소는 (check_id, resources) 또는 (check_id, resources, context).
    context(QUERY/NOTE 등)는 base별로 합친다(중복 제거, 순서 보존).
    """
    items: Dict[str, EvidenceItem] = {}
    for entry in raw_checks:
        check_id, resources = entry[0], entry[1]
        context = entry[2] if len(entry) > 2 else None
        base = profile.normalize_id(check_id)
        if base not in items:
            items[base] = EvidenceItem(item_id=base, variant=variant,
                                       resources=[])
        items[base].resources.extend(resources)
        if context:
            cur = items[base].context
            if cur is None:
                items[base].context = context
            elif context not in cur:
                items[base].context = f"{cur}\n{context}"
    return items
```

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_mapper_db.py -q` → PASS

- [ ] **Step 5: cloud 회귀** — Run: `python3 -m pytest -q` → 전부 통과(기존 cloud aggregate 테스트 포함)

- [ ] **Step 6: Commit**

```bash
git add judge_tool/mapper.py tests/test_mapper_db.py
git commit -m "feat(mapper): thread item context, accept 2/3-tuple raw checks"
```

---

## Task 7: judge — raw 증거가드 + build_prompt(context) + reconcile 확장

**Files:**
- Modify: `judge_tool/judge.py`
- Test: `tests/test_judge.py` (테스트 추가)

- [ ] **Step 1: 실패 테스트 추가** `tests/test_judge.py` 끝에

```python
from judge_tool.judge import (
    build_evidence_text_raw, reconcile, build_prompt)


def _db_item(rows, context=None):
    from judge_tool.models import EvidenceItem, ResourceEvidence
    res = [ResourceEvidence(f"row{i}", "", "", e) for i, e in enumerate(rows)]
    it = EvidenceItem("DBM-004", "mysql_rds", res)
    it.context = context
    return it


def _db_crit(standard="* 양호 - ...\n* 취약 - ..."):
    from judge_tool.models import Criterion
    return Criterion("DBM-004", "권한", 5.0, "mysql_rds", "", standard,
                     "방법", applicable=True)


def test_raw_evidence_preserves_all_rows_with_cap_note():
    rows = [f'{{"GRANTEE":"u{i}","PRIVILEGE_TYPE":"SELECT"}}' for i in range(5)]
    text = build_evidence_text_raw(_db_item(rows, "QUERY: q"), max_chars=24000)
    assert "QUERY: q" in text
    for i in range(5):
        assert f"u{i}" in text          # 전수 보존


def test_raw_evidence_cap_truncates_with_note():
    rows = [f'{{"GRANTEE":"user{i}","PRIVILEGE_TYPE":"SELECT"}}'
            for i in range(500)]
    text = build_evidence_text_raw(_db_item(rows, None), max_chars=300)
    assert "생략" in text or "표시" in text


def test_db_prompt_uses_raw_mode_and_context():
    p = build_prompt(_db_crit(), _db_item(['{"GRANTEE":"x"}'], "QUERY: select 1"),
                     evidence_mode="raw")
    assert "select 1" in p
    assert "DBM-004" in p


def test_reconcile_db_status_unavailable():
    llm = {"verdict": "취약", "confidence": 0.9, "rationale": "x",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item(['{"GRANTEE":"x"}']),
                  status_available=False, flag_vulnerable_for_review=True)
    assert j.script_status is None
    assert j.agreement == "N/A"
    assert j.needs_review is True          # 취약 → 검토
    assert j.scope == "스크립트 전체"


def test_reconcile_db_empty_means_good_not_forced_boryu():
    # 빈 RESULT지만 empty_means_good 항목이면 판단보류 강제 안 함
    llm = {"verdict": "양호", "confidence": 0.9, "rationale": "위반 0건",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item([], "QUERY: q"),
                  status_available=False, flag_vulnerable_for_review=True,
                  empty_means_good=True)
    assert j.verdict == "양호"             # 강제 보류 아님


def test_reconcile_db_empty_default_forces_boryu():
    llm = {"verdict": "양호", "confidence": 0.9, "rationale": "x",
           "cited_evidence": []}
    j = reconcile(llm, _db_crit(), _db_item([], "QUERY: q"),
                  status_available=False, flag_vulnerable_for_review=True,
                  empty_means_good=False)
    assert j.verdict == "판단보류"         # 무증거 → 보류
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_judge.py -q` → FAIL

- [ ] **Step 3: judge.py 수정**

(a) raw 증거가드 추가(`build_evidence_text` 아래):

```python
def build_evidence_text_raw(item: EvidenceItem, max_chars: int = 24000) -> str:
    """원시증거(DB) 직렬화: 사전분류 status가 없으므로 전수 보존이 기본.

    context(QUERY/NOTE)를 상단에 두고 모든 행을 직렬화한다. 행이 한 그룹키로
    반복되는 결과(예: GRANTEE)는 그룹별 요약을 병기한다. 총량이 max_chars를
    넘으면 행을 잘라 "M행 중 N행 표시, K행 생략"을 명시한다.
    """
    head = (item.context + "\n") if item.context else ""
    if not item.resources:
        return head + "(점검 결과 0건)"
    lines = [r.evidence if r.evidence else r.detail for r in item.resources]
    summary = _group_summary(item.resources)
    body_head = head + (summary + "\n" if summary else "")
    total = len(lines)
    shown, used = [], len(body_head)
    for ln in lines:
        if used + len(ln) + 1 > max_chars:
            break
        shown.append(ln)
        used += len(ln) + 1
    out = body_head + "\n".join(shown)
    if len(shown) < total:
        out += f"\n... ({total}행 중 {len(shown)}행 표시, {total - len(shown)}행 생략)"
    return out


def _group_summary(resources) -> str:
    """행들이 'GRANTEE' 같은 그룹키 + 값(PRIVILEGE_TYPE)을 가지면 그룹별
    값 집합 요약을 만든다. 해당 구조가 아니면 빈 문자열."""
    import json as _json
    groups = {}
    ok = 0
    for r in resources:
        try:
            d = _json.loads(r.evidence)
        except Exception:  # noqa: BLE001
            return ""
        if not isinstance(d, dict) or "GRANTEE" not in d:
            return ""
        key = d.get("GRANTEE", "")
        val = d.get("PRIVILEGE_TYPE", "")
        groups.setdefault(key, set()).add(val)
        ok += 1
    if ok == 0:
        return ""
    parts = ["[요약] 계정별 권한집합:"]
    for k, vs in groups.items():
        vlist = sorted(v for v in vs if v)
        parts.append(f"  {k}: [{len(vlist)}] " + ", ".join(vlist[:12])
                     + (f" ...(+{len(vlist) - 12})" if len(vlist) > 12 else ""))
    return "\n".join(parts)
```

(b) `build_prompt`에 `evidence_mode` 파라미터 추가 — raw면 raw 직렬화 사용, context 포함:

```python
def build_prompt(criterion: Criterion, item: EvidenceItem,
                 max_chars: int = 8000, evidence_mode: str = "preclassified") -> str:
    scope_note = ""
    if criterion.is_mixed:
        scope_note = (
            "\n[중요] 이 항목은 '관리체계+스크립트' 혼합이다. "
            "판단기준 중 기술/스크립트로 확인 가능한 부분만 대조해 판정하고, "
            "관리체계(문서·정책·인터뷰) 영역은 판정 근거로 삼지 말 것.")
    if evidence_mode == "raw":
        evidence = build_evidence_text_raw(item, max(max_chars, 24000))
    else:
        evidence = build_evidence_text(item, max_chars)
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name} "
        f"(위험도 {criterion.risk})\n"
        f"변형: {criterion.variant}\n"
        f"--- 판단기준 ---\n{criterion.standard}\n"
        f"--- 판단방법 ---\n{criterion.method}\n"
        f"{scope_note}\n"
        f"--- 점검 증거 ---\n{evidence}\n"
        f"--- 위 판단기준에 따라 JSON으로 판정하라. ---"
    )
```

(c) `judge_item`에 `evidence_mode` 파라미터 전달:

```python
def judge_item(criterion: Criterion, item: EvidenceItem, client,
               max_chars: int = 8000, retries: int = 2,
               evidence_mode: str = "preclassified") -> Dict:
    prompt = build_prompt(criterion, item, max_chars, evidence_mode)
    last_err = None
    for _ in range(retries + 1):
        raw = client.chat(SYSTEM_PROMPT, prompt)
        ...   # 이하 기존 로직 동일
```

(d) `reconcile` 시그니처 확장(키워드 전용 인자, 기본값으로 cloud 불변):

```python
def reconcile(llm: Dict, criterion: Criterion, item: EvidenceItem, *,
              status_available: bool = True,
              flag_vulnerable_for_review: bool = False,
              empty_means_good: bool = False) -> Judgment:
    if status_available:
        script_status = item.overall_status
        expected = _STATUS_TO_VERDICT.get(script_status)
    else:
        script_status = None
        expected = None
    verdict = llm.get("verdict", "판단보류")
    confidence = _to_float(llm.get("confidence", 0.0))
    rationale = llm.get("rationale", "")

    if expected is None:
        agreement = "N/A"
    else:
        agreement = "일치" if verdict == expected else "불일치"

    # 무증거/error 시 판단보류 강제 — 단 empty_means_good(위반 0건=양호 후보)면 제외.
    no_evidence = (not item.resources) and not empty_means_good
    if (script_status == "error" or no_evidence) and verdict != "판단보류":
        verdict = "판단보류"
        reason = "증거 없음" if no_evidence else "스크립트 점검 오류(error)"
        rationale = f"{rationale} [자동 판단보류: {reason}]".strip()

    needs_review = (
        agreement == "불일치"
        or confidence < _LOW_CONFIDENCE
        or criterion.is_mixed
        or verdict == "판단보류"
        or expected is None
        or (flag_vulnerable_for_review and verdict == "취약")
    )
    return Judgment(
        item_id=criterion.item_id,
        item_name=criterion.item_name,
        variant=criterion.variant,
        risk=criterion.risk,
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        cited_evidence=list(llm.get("cited_evidence", [])),
        scope="스크립트 부분만" if criterion.is_mixed else "스크립트 전체",
        management_review_needed=criterion.is_mixed,
        script_status=script_status,
        agreement=agreement,
        needs_review=needs_review,
    )
```

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_judge.py -q` → PASS

- [ ] **Step 5: cloud 회귀** — Run: `python3 -m pytest -q` → 전부 통과(기존 reconcile/judge 테스트는 status_available 기본 True라 동작 동일)

- [ ] **Step 6: Commit**

```bash
git add judge_tool/judge.py tests/test_judge.py
git commit -m "feat(judge): raw evidence guard + context prompt + reconcile flags"
```

---

## Task 8: main.run — 프로파일 속성으로 DB 경로 연결

**Files:**
- Modify: `judge_tool/main.py`
- Test: `tests/test_main_db_e2e.py` (신규)

- [ ] **Step 1: 실패 테스트 작성** `tests/test_main_db_e2e.py`

```python
import json
import os
import openpyxl

from judge_tool.main import run

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sample_db_mysql.txt")


class StubVuln:
    def chat(self, system, user):
        return ('{"verdict":"취약","confidence":0.8,'
                '"rationale":"테스트","cited_evidence":["x"]}')


def _db_criteria_xlsx(path):
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "name"); ws.cell(4, 8, "risk")
    ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
    for r, dbm in [(5, "DBM-001"), (6, "DBM-004"), (7, "DBM-017")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, f"{dbm}항목"); ws.cell(r, 8, 5.0)
        ws.cell(r, 17, "o"); ws.cell(r, 37, "* 양호 - ...\n* 취약 - ...")
        ws.cell(r, 38, "방법")
    wb.save(path)


def test_db_run_end_to_end(tmp_path):
    criteria = str(tmp_path / "db.xlsx")
    _db_criteria_xlsx(criteria)
    # 입력 파일을 변형 식별 가능한 이름으로 tmp에 복사(원본 results/ 미사용)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    cov = run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")

    data = json.load(open(jout, encoding="utf-8"))
    ids = {j["item_id"] for j in data["judgments"]}
    assert "DBM-001" in ids and "DBM-004" in ids
    # DB 판정은 script_status None, agreement N/A
    j1 = next(j for j in data["judgments"] if j["item_id"] == "DBM-001")
    assert j1["script_status"] is None and j1["agreement"] == "N/A"
    assert j1["needs_review"] is True            # 취약 → 검토
    # 마스킹: 출력 어디에도 해시 원문 없음
    assert "FAKEFAKE" not in json.dumps(data, ensure_ascii=False)
    assert data["metadata"]["profile"] == "db_mysql"


def test_db_note_forces_judgment_boryu(tmp_path):
    # criteria에 DBM-011/019 추가(평가대상 o, 판단기준 있음) → NOTE면 판단보류
    criteria = str(tmp_path / "db.xlsx")
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "n"); ws.cell(4, 8, "r")
    ws.cell(4, 17, "대상"); ws.cell(4, 37, "기준"); ws.cell(4, 38, "방법")
    for r, dbm in [(5, "DBM-011"), (6, "DBM-019")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, dbm); ws.cell(r, 8, 5.0)
        ws.cell(r, 17, "o"); ws.cell(r, 37, "* 양호 - ..."); ws.cell(r, 38, "m")
    wb.save(criteria)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")
    data = json.load(open(jout, encoding="utf-8"))
    for dbm in ("DBM-011", "DBM-019"):
        j = next(x for x in data["judgments"] if x["item_id"] == dbm)
        assert j["verdict"] == "판단보류"          # NOTE → 강제 판단보류
        assert j["needs_review"] is True
        assert "NOTE" in j["rationale"]
```

- [ ] **Step 2: 실패 확인** — Run: `python3 -m pytest tests/test_main_db_e2e.py -q` → FAIL (run이 evidence_mode/flags 미전달 → DB 경로 동작 안 함)

- [ ] **Step 3: main.py `run` 수정** — 프로파일 속성으로 judge/reconcile 인자 결정. `_judge_one`에 프로파일·empty_means_good 전달.

`run`의 판정 루프와 `_judge_one`을 아래로 교체:

```python
def _judge_one(crit, item, item_id: str, variant: str, client,
               profile) -> Optional[Judgment]:
    """단일 항목 판정 + 부분 실패 격리. 프로파일로 evidence/판정 모드 결정."""
    empty_ok = item_id in profile.empty_means_good
    # B-2: NOTE 보유 항목은 기술점검 범위 밖(관리체계/외부확인/N-A)이므로
    # LLM 호출 없이 판단보류로 강제하고 NOTE를 사유로 기록(empty_means_good보다 우선).
    if item.context and "NOTE:" in item.context:
        note = item.context.split("NOTE:", 1)[1].strip().splitlines()[0]
        forced = {"verdict": "판단보류", "confidence": 0.0,
                  "rationale": f"[자동 판단보류: NOTE] {note}",
                  "cited_evidence": []}
        return reconcile(
            forced, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=empty_ok)
    try:
        llm = judge_item(crit, item, client,
                         evidence_mode=profile.evidence_mode)
        return reconcile(
            llm, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=empty_ok)
    except Exception as e:  # noqa: BLE001 - 부분 실패 격리
        log.warning("judge 실패 item=%s variant=%s type=%s",
                    item_id, variant, type(e).__name__)
        fallback_llm = {"verdict": "판단보류", "confidence": 0.0,
                        "rationale": f"판정 중 오류({type(e).__name__})",
                        "cited_evidence": []}
    try:
        return reconcile(
            fallback_llm, crit, item,
            status_available=profile.status_available,
            flag_vulnerable_for_review=profile.flag_vulnerable_for_review,
            empty_means_good=empty_ok)
    except Exception as e2:  # noqa: BLE001
        log.warning("폴백 reconcile 실패, 스킵 item=%s type=%s",
                    item_id, type(e2).__name__)
        return None
```

`run` 내 호출부 수정(profile 전달):

```python
        judgment = _judge_one(crit, item, item_id, variant, client, profile)
```

(`run`은 이미 `profile = get_profile(profile_key)`를 갖고 있으므로 그대로 전달.)

- [ ] **Step 4: 통과 확인** — Run: `python3 -m pytest tests/test_main_db_e2e.py -q` → PASS

- [ ] **Step 5: 전체 회귀** — Run: `python3 -m pytest -q` → 전부 통과(cloud E2E 포함; cloud는 profile.evidence_mode="preclassified", status_available=True라 기존 동작)

- [ ] **Step 6: Commit**

```bash
git add judge_tool/main.py tests/test_main_db_e2e.py
git commit -m "feat(main): wire DB profile (raw evidence, status-unavailable reconcile)"
```

---

## Task 9: 거버넌스 문서 + 전체 회귀 점검

**Files:**
- Modify: `docs/superpowers/PROGRESS.md` (또는 README 보안 노트)

- [ ] **Step 1: 거버넌스 노트 추가** — PROGRESS.md(또는 README)에 DB 산출물 취급 규칙 명시:
  - `out/` 산출물엔 마스킹된 증거(계정/내부IP 식별정보 포함)가 남는다. **gitignore 유지, 평문/해시 원문은 절대 미포함.** 보관/삭제 책임은 평가자에게 있으며 민감 디렉터리에 두지 말 것.

- [ ] **Step 2: 전체 테스트** — Run: `python3 -m pytest -q` → 전부 통과. `git status --porcelain -- results/ ref/` 공백 확인.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/PROGRESS.md
git commit -m "docs: DB output governance note (masked evidence handling)"
```

---

## Task 10: 실제 Ollama 스모크 (수동, 선택)

**Files:** 없음(실행만)

- [ ] **Step 1: 실행** (출력은 results/ 밖 `out/`로)

```bash
cd "/Users/fsat/Documents/saptweb/04.Script_judgement_automation"
python3 -m judge_tool.main \
  --report "results/DB/MySQL/mysql_result_rds.txt" \
  --criteria "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx" \
  --profile db_mysql --out-dir out --model "qwen3-coder:30b"
```
Expected: `판정 N/M 완료 ...` + `out/result_mysql_result_rds.{json,xlsx}` 생성, 트레이스백 없음.

- [ ] **Step 2: 골든셋 육안 확인 (B-5)**
  - DBM-005(평문 비번 존재 → 취약), 원격 `%` 호스트 고권한 계정(DBM-004/017), audit_log not loaded(DBM-011) 등이 합리적으로 취약/판단보류로 잡혔는지.
  - **출력물에 해시/평문 원문이 없는지**(마스킹 검증) 확인.
  - aurora/azure도 동일 실행해 환경별 차이 확인(선택).

---

## Self-Review (작성자 점검)

- **스펙 커버리지:** §2 범위(MySQL 3변형)→T2. §3 파서 손상6종→T4/T5(원소순회·살균·중복키·bare·NOTE·키only). §4 컬럼맵→T2/T3. §5-1 needs_review→T7. §5-2 NOTE 판단보류→파서가 NOTE를 context로 보존, T8의 _judge_one이 context에 "NOTE:" 있으면 LLM 없이 판단보류 강제(empty_means_good보다 우선)+사유기록. T8 테스트로 검증. §5-3 마스킹→T4. §5-4 요약+원행/상한→T7. §5-5/§5-6 NOTE/empty 정책→T2(empty_means_good)/T7/T8. §5-7 applicable→T1/T3. §5-8 reconcile 시그니처→T7. §5-9 모드분리→T2/T7. §6 컴포넌트→T1~T8. §8 거버넌스→T9. §9 테스트→각 T. §10 스모크→T10.
- **placeholder 스캔:** 모든 코드 step에 실제 코드 포함. TBD 없음.
- **타입 일관성:** `parse()`는 3-tuple 반환↔`aggregate`가 2/3-tuple 허용. `reconcile(*, status_available, flag_vulnerable_for_review, empty_means_good)`↔`_judge_one`/T7 테스트 호출 일치. `build_prompt(..., evidence_mode)`↔`judge_item(..., evidence_mode)`↔run 전달 일치. `Criterion(..., applicable=)`↔loader/T1 일치. `EvidenceItem.context`↔parser/mapper/judge 일치. `Profile.empty_means_good/evidence_mode/status_available/flag_vulnerable_for_review`↔T2/T8 일치.
- **알려진 한계:** NOTE-only/빈(비-위반필터) 항목은 판단보류로 수렴(정상). DBM-024는 혼합이라 empty_means_good 제외(보수적). 실데이터 검증은 T10(수동).

# 클라우드(AWS) LLM 자동 판단 도구 — 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 클라우드 AWS 점검 결과 XML과 평가기준 xlsx를 입력받아, 로컬 LLM(Ollama)이 PISM 항목별로 양호/취약/판단보류를 독립 판단하고 스크립트 status와 교차 비교한 결과를 JSON·Excel 보고서로 출력하는 CLI 도구.

**Architecture:** 도메인 무관 코어(criteria_loader / judge / writer)와 분야별 경량 프로파일(컬럼맵·파서·variant 규칙)을 분리한다. 항목별로 1회 LLM 호출(A안)하며, 스크립트의 good/bad는 정답이 아니라 LLM 판정과의 교차 비교 신호로만 쓴다. 실제 결과 XML은 이스케이프되지 않은 `&` 때문에 well-formed가 아니므로 파서가 사전 정제(sanitize) 후 파싱한다.

**Tech Stack:** Python 3, `openpyxl`(xlsx), 표준 `xml.etree`(정제 후), `requests`(Ollama HTTP), `pytest`(테스트). 출력 한국어.

설계 문서: `docs/superpowers/specs/2026-06-01-llm-judgment-tool-design.md`

---

## File Structure

```
judge_tool/
  __init__.py          # 버전 상수
  models.py            # 데이터클래스 (Criterion/ResourceEvidence/EvidenceItem/Judgment)
  profile.py           # Profile/VariantSpec + CLOUD 프로파일, ID 정규화·variant 규칙
  criteria_loader.py   # xlsx → {(item_id,variant): Criterion}
  parsers/
    __init__.py
    cloud_xml.py       # XML 정제 + 파싱 → [(check_id, [ResourceEvidence])]
  mapper.py            # 분할항목 집계 → {base_id: EvidenceItem}
  judge.py             # 프롬프트·증거가드·Ollama 호출·관대한 JSON 파싱·reconcile
  writer.py            # JSON + Excel + 커버리지 요약
  main.py              # CLI 오케스트레이션 + 감사 메타데이터
tests/
  conftest.py          # 공용 픽스처
  test_models.py
  test_profile.py
  test_criteria_loader.py
  test_cloud_xml.py
  test_mapper.py
  test_judge.py
  test_writer.py
  test_main_e2e.py     # 실제 AWS 샘플로 골든 테스트(LLM 모킹)
requirements.txt
```

각 파일은 단일 책임을 가진다. `comparator`는 별도 모듈이 아니라 `judge.reconcile()` 함수로 둔다.

---

## Task 0: 프로젝트 스캐폴딩

**Files:**
- Create: `requirements.txt`, `judge_tool/__init__.py`, `judge_tool/parsers/__init__.py`, `tests/conftest.py`

- [ ] **Step 1: git 저장소 초기화 (현재 비저장소)**

Run:
```bash
cd "/Users/fsat/Documents/saptweb/04.Script_judgement_automation"
git init && printf '__pycache__/\n*.pyc\n.pytest_cache/\nresult_*.json\nresult_*.xlsx\n' > .gitignore
```
Expected: `Initialized empty Git repository ...`

- [ ] **Step 2: requirements.txt 작성**

```
openpyxl>=3.1
requests>=2.31
pytest>=8.0
```

- [ ] **Step 3: 패키지 init 작성**

`judge_tool/__init__.py`:
```python
__version__ = "0.1.0"
```

`judge_tool/parsers/__init__.py`:
```python
```
(빈 파일)

- [ ] **Step 4: 공용 픽스처 작성**

`tests/conftest.py`:
```python
import os
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def project_root():
    return PROJECT_ROOT


@pytest.fixture
def aws_report_path(project_root):
    """업로드된 실제 AWS 점검 결과 샘플."""
    return os.path.join(project_root, "results", "Public Cloud",
                        "aws_report_20251223_hinno.xml")


@pytest.fixture
def criteria_xlsx_path(project_root):
    return os.path.join(
        project_root, "ref",
        "전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")
```

- [ ] **Step 5: 의존성 설치 후 빈 테스트 수집 확인**

Run:
```bash
cd "/Users/fsat/Documents/saptweb/04.Script_judgement_automation"
python3 -m pip install -r requirements.txt && python3 -m pytest -q
```
Expected: `no tests ran` (수집 에러 없음)

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "chore: scaffold judge_tool project"
```

---

## Task 1: 데이터 모델 (models.py)

**Files:**
- Create: `judge_tool/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_models.py`:
```python
from judge_tool.models import (
    Criterion, ResourceEvidence, EvidenceItem, Judgment)


def test_criterion_flags():
    mixed = Criterion("PISM-045", "최소권한", 5.0, "AWS",
                      "관리체계, 스크립트", "기준...", "방법...")
    assert mixed.is_mixed is True
    assert mixed.is_script_based is True

    script_only = Criterion("PISM-001", "암호화", 5.0, "AWS",
                            "스크립트", "기준", "방법")
    assert script_only.is_mixed is False
    assert script_only.is_script_based is True

    na = Criterion("PISM-030", "x", None, "Azure", "N/A", "", "")
    assert na.is_script_based is False


def test_overall_status_priority():
    def item(*statuses):
        res = [ResourceEvidence(f"r{i}", s, "", "") for i, s in enumerate(statuses)]
        return EvidenceItem("PISM-007", "AWS", res)

    assert item("good", "bad", "review").overall_status == "bad"
    assert item("good", "review").overall_status == "review"
    assert item("good", "info").overall_status == "good"
    assert item("info").overall_status == "info"
    # 대문자 status도 정규화
    assert item("Error").overall_status == "error"


def test_overall_status_empty():
    assert EvidenceItem("PISM-001", "AWS", []).overall_status == "info"
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_models.py -q`
Expected: FAIL (`ModuleNotFoundError: judge_tool.models`)

- [ ] **Step 3: models.py 구현**

`judge_tool/models.py`:
```python
from dataclasses import dataclass, field
from typing import List, Optional

# overall_status 우선순위 (앞일수록 우선)
_STATUS_PRIORITY = ["bad", "review", "error", "good", "info"]


@dataclass
class Criterion:
    item_id: str          # "PISM-001"
    item_name: str
    risk: Optional[float]
    variant: str          # "AWS"
    eval_type: str        # "스크립트" | "관리체계, 스크립트" | "N/A" ...
    standard: str         # 판단기준 텍스트
    method: str           # 판단방법 텍스트

    @property
    def is_mixed(self) -> bool:
        return "관리체계" in self.eval_type and "스크립트" in self.eval_type

    @property
    def is_script_based(self) -> bool:
        return "스크립트" in self.eval_type


@dataclass
class ResourceEvidence:
    resource_id: str
    status: str           # good | bad | info | error | review
    detail: str
    evidence: str


@dataclass
class EvidenceItem:
    item_id: str          # 정규화된 base id "PISM-045"
    variant: str
    resources: List[ResourceEvidence] = field(default_factory=list)

    @property
    def overall_status(self) -> str:
        statuses = {r.status.lower() for r in self.resources}
        for s in _STATUS_PRIORITY:
            if s in statuses:
                return s
        return "info"


@dataclass
class Judgment:
    item_id: str
    item_name: str
    variant: str
    risk: Optional[float]
    verdict: str          # 양호 | 취약 | 판단보류
    confidence: float
    rationale: str
    cited_evidence: List[str]
    scope: str            # "스크립트 전체" | "스크립트 부분만"
    management_review_needed: bool
    script_status: Optional[str]
    agreement: str        # 일치 | 불일치 | N/A
    needs_review: bool
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_models.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/models.py tests/test_models.py && git commit -m "feat: add core data models"
```

---

## Task 2: 프로파일 (profile.py)

**Files:**
- Create: `judge_tool/profile.py`
- Test: `tests/test_profile.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_profile.py`:
```python
from judge_tool.profile import CLOUD, get_profile


def test_normalize_id_strips_subindex():
    assert CLOUD.normalize_id("pism_001") == "PISM-001"
    assert CLOUD.normalize_id("pism_037_1") == "PISM-037"
    assert CLOUD.normalize_id("pism_046_3") == "PISM-046"


def test_variant_from_filename():
    assert CLOUD.variant_from_filename("aws_report_20251223_hinno.xml") == "AWS"
    assert CLOUD.variant_from_filename("azure_report_20251121.xml") == "Azure"
    assert CLOUD.variant_from_filename("random.xml") is None


def test_profile_columns():
    assert CLOUD.sheet_name == "클라우드 관리체계"
    aws = CLOUD.variants["AWS"]
    assert (aws.eval_type_col, aws.standard_col, aws.method_col) == (11, 17, 13)


def test_get_profile():
    assert get_profile("cloud") is CLOUD
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_profile.py -q`
Expected: FAIL (`ModuleNotFoundError: judge_tool.profile`)

- [ ] **Step 3: profile.py 구현**

`judge_tool/profile.py`:
```python
import os
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class VariantSpec:
    name: str
    eval_type_col: int
    standard_col: int
    method_col: int
    filename_markers: Tuple[str, ...]


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

    def normalize_id(self, raw: str) -> str:
        """'pism_037_1' -> 'PISM-037'. 접두어+첫 숫자만 사용, 하위 인덱스 제거."""
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


CLOUD = Profile(
    key="cloud",
    sheet_name="클라우드 관리체계",
    header_row=4,
    data_start_row=5,
    id_col=2,
    name_col=6,
    risk_col=7,
    parser="cloud_xml",
    variants={
        "AWS": VariantSpec("AWS", eval_type_col=11, standard_col=17,
                           method_col=13, filename_markers=("aws_report",)),
        "Azure": VariantSpec("Azure", eval_type_col=12, standard_col=18,
                             method_col=14, filename_markers=("azure_report",)),
    },
)

_PROFILES = {CLOUD.key: CLOUD}


def get_profile(key: str) -> Profile:
    if key not in _PROFILES:
        raise KeyError(f"알 수 없는 프로파일: {key} (사용 가능: {list(_PROFILES)})")
    return _PROFILES[key]
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_profile.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/profile.py tests/test_profile.py && git commit -m "feat: add domain profile with cloud config"
```

---

## Task 3: 평가기준 로더 (criteria_loader.py)

**Files:**
- Create: `judge_tool/criteria_loader.py`
- Test: `tests/test_criteria_loader.py`

- [ ] **Step 1: 실패 테스트 작성** (실제 xlsx 사용)

`tests/test_criteria_loader.py`:
```python
from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import CLOUD


def test_loads_known_item(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    c = crit[("PISM-001", "AWS")]
    assert c.item_name.strip().startswith("통신구간")
    assert c.risk == 5.0
    assert "스크립트" in c.eval_type
    assert "양호" in c.standard          # 판단기준 텍스트 존재
    assert c.variant == "AWS"


def test_mixed_item_flagged(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert crit[("PISM-045", "AWS")].is_mixed is True


def test_both_variants_present(criteria_xlsx_path):
    crit = load_criteria(criteria_xlsx_path, CLOUD)
    assert ("PISM-001", "AWS") in crit
    assert ("PISM-001", "Azure") in crit
    # 73개 항목 × 2 variant
    item_ids = {k[0] for k in crit}
    assert len(item_ids) == 73
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_criteria_loader.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: criteria_loader.py 구현**

`judge_tool/criteria_loader.py`:
```python
from typing import Dict, Tuple

import openpyxl

from judge_tool.models import Criterion
from judge_tool.profile import Profile


def _cell(ws, row, col) -> str:
    v = ws.cell(row=row, column=col).value
    return "" if v is None else str(v).strip()


def load_criteria(xlsx_path: str,
                  profile: Profile) -> Dict[Tuple[str, str], Criterion]:
    """xlsx → {(item_id, variant): Criterion}. 모든 변형을 로드한다."""
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb[profile.sheet_name]
    out: Dict[Tuple[str, str], Criterion] = {}

    for row in range(profile.data_start_row, ws.max_row + 1):
        item_id = _cell(ws, row, profile.id_col)
        if not item_id:
            continue
        name = _cell(ws, row, profile.name_col)
        risk_raw = ws.cell(row=row, column=profile.risk_col).value
        try:
            risk = float(risk_raw)
        except (TypeError, ValueError):
            risk = None

        for vname, vspec in profile.variants.items():
            out[(item_id, vname)] = Criterion(
                item_id=item_id,
                item_name=name,
                risk=risk,
                variant=vname,
                eval_type=_cell(ws, row, vspec.eval_type_col),
                standard=_cell(ws, row, vspec.standard_col),
                method=_cell(ws, row, vspec.method_col),
            )
    return out
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_criteria_loader.py -q`
Expected: PASS (3 passed). 경고(openpyxl UserWarning)는 무시.

- [ ] **Step 5: Commit**

```bash
git add judge_tool/criteria_loader.py tests/test_criteria_loader.py && git commit -m "feat: load criteria from xlsx"
```

---

## Task 4: 클라우드 XML 파서 (parsers/cloud_xml.py)

**Files:**
- Create: `judge_tool/parsers/cloud_xml.py`
- Test: `tests/test_cloud_xml.py`

- [ ] **Step 1: 실패 테스트 작성** (정제 + 실제 샘플)

`tests/test_cloud_xml.py`:
```python
from judge_tool.parsers.cloud_xml import sanitize, parse


def test_sanitize_escapes_bare_ampersand():
    raw = "<ResourceID>SD-WAN & Router</ResourceID>"
    assert sanitize(raw) == "<ResourceID>SD-WAN &amp; Router</ResourceID>"


def test_sanitize_keeps_valid_entities():
    raw = "a &amp; b &lt; c &#39;d&#39;"
    assert sanitize(raw) == raw


def test_parse_real_report(aws_report_path):
    checks = parse(aws_report_path)
    ids = [cid for cid, _ in checks]
    # 분할항목 원본 CheckID 보존
    assert "pism_001" in ids
    assert "pism_037_1" in ids and "pism_037_2" in ids
    assert len(checks) == 26

    # pism_001 의 첫 리소스 구조
    first = dict(checks)["pism_001"]
    assert first[0].resource_id != ""
    assert first[0].status in {"good", "bad", "info", "error", "review"}
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_cloud_xml.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: cloud_xml.py 구현**

`judge_tool/parsers/cloud_xml.py`:
```python
import re
import xml.etree.ElementTree as ET
from typing import List, Tuple

from judge_tool.models import ResourceEvidence

# 유효한 엔티티(&amp; &lt; &#39; 등)가 아닌 단독 '&'를 escape
_BARE_AMP = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)")


def sanitize(raw: str) -> str:
    """스크립트가 이스케이프하지 않은 '&'로 인해 well-formed가 아닌 XML을 보정."""
    return _BARE_AMP.sub("&amp;", raw)


def _text(el, tag) -> str:
    v = el.findtext(tag)
    return "" if v is None else v


def parse(xml_path: str) -> List[Tuple[str, List[ResourceEvidence]]]:
    """XML → [(check_id, [ResourceEvidence, ...]), ...]. CheckResult 순서 유지."""
    with open(xml_path, encoding="utf-8") as fh:
        root = ET.fromstring(sanitize(fh.read()))

    result: List[Tuple[str, List[ResourceEvidence]]] = []
    for cr in root.findall(".//CheckResult"):
        check_id = (cr.findtext("CheckID") or "").strip()
        resources = [
            ResourceEvidence(
                resource_id=_text(item, "ResourceID").strip(),
                status=(item.get("status") or "").strip(),
                detail=_text(item, "Detail").strip(),
                evidence=_text(item, "Evidence").strip(),
            )
            for item in cr.findall(".//Item")
        ]
        result.append((check_id, resources))
    return result
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_cloud_xml.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/parsers/cloud_xml.py tests/test_cloud_xml.py && git commit -m "feat: parse cloud XML with sanitization"
```

---

## Task 5: 분할항목 집계 (mapper.py)

**Files:**
- Create: `judge_tool/mapper.py`
- Test: `tests/test_mapper.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_mapper.py`:
```python
from judge_tool.mapper import aggregate
from judge_tool.models import ResourceEvidence
from judge_tool.profile import CLOUD


def test_aggregate_merges_split_items():
    raw = [
        ("pism_037_1", [ResourceEvidence("u1", "bad", "복잡도", "e1")]),
        ("pism_037_2", [ResourceEvidence("u2", "good", "재사용", "e2")]),
        ("pism_001", [ResourceEvidence("b1", "bad", "정책없음", "e3")]),
    ]
    items = aggregate(raw, "AWS", CLOUD)
    assert set(items) == {"PISM-037", "PISM-001"}
    merged = items["PISM-037"]
    assert merged.variant == "AWS"
    assert {r.resource_id for r in merged.resources} == {"u1", "u2"}
    assert merged.overall_status == "bad"
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_mapper.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: mapper.py 구현**

`judge_tool/mapper.py`:
```python
from typing import Dict, List, Tuple

from judge_tool.models import EvidenceItem, ResourceEvidence
from judge_tool.profile import Profile


def aggregate(raw_checks: List[Tuple[str, List[ResourceEvidence]]],
              variant: str,
              profile: Profile) -> Dict[str, EvidenceItem]:
    """원본 CheckID를 base id로 정규화하며 분할항목을 한 EvidenceItem으로 병합."""
    items: Dict[str, EvidenceItem] = {}
    for check_id, resources in raw_checks:
        base = profile.normalize_id(check_id)
        if base not in items:
            items[base] = EvidenceItem(item_id=base, variant=variant, resources=[])
        items[base].resources.extend(resources)
    return items
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_mapper.py -q`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/mapper.py tests/test_mapper.py && git commit -m "feat: aggregate split check items"
```

---

## Task 6: 판단 엔진 — 프롬프트·증거가드·파싱 (judge.py 1부)

**Files:**
- Create: `judge_tool/judge.py`
- Test: `tests/test_judge.py`

- [ ] **Step 1: 실패 테스트 작성** (LLM 무관 순수 함수)

`tests/test_judge.py`:
```python
from judge_tool.judge import (
    build_evidence_text, parse_json_lenient, build_prompt, SYSTEM_PROMPT)
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence


def _item(*statuses):
    res = [ResourceEvidence(f"res-{i}", s, f"detail-{i}", f"ev-{i}" * 200)
           for i, s in enumerate(statuses)]
    return EvidenceItem("PISM-001", "AWS", res)


def test_evidence_guard_preserves_non_good():
    # good 다수 + bad 1개. 작은 상한이어도 bad는 보존되어야 한다.
    item = _item("good", "good", "good", "bad")
    text = build_evidence_text(item, max_chars=500)
    assert "res-3" in text          # 유일한 bad 리소스
    assert "축약" in text or "생략" in text  # 축약 표기


def test_parse_json_lenient_strips_fences_and_commas():
    raw = '```json\n{"verdict": "취약", "confidence": 0.9,}\n```'
    data = parse_json_lenient(raw)
    assert data["verdict"] == "취약"
    assert data["confidence"] == 0.9


def test_build_prompt_mixed_item_mentions_script_scope():
    c = Criterion("PISM-045", "최소권한", 5.0, "AWS",
                  "관리체계, 스크립트", "[관리체계]...\n[IAM] 양호-...", "방법")
    prompt = build_prompt(c, _item("bad"))
    assert "스크립트" in prompt
    assert "PISM-045" in prompt
    assert "최소권한" in prompt


def test_system_prompt_demands_json_keys():
    for key in ["verdict", "confidence", "rationale", "cited_evidence"]:
        assert key in SYSTEM_PROMPT
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_judge.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: judge.py 1부 구현** (프롬프트/가드/파싱)

`judge_tool/judge.py`:
```python
import json
import re
from typing import Dict, List

import requests

from judge_tool.models import Criterion, EvidenceItem, Judgment

SYSTEM_PROMPT = (
    "당신은 전자금융기반시설 클라우드 보안 취약점 평가자다. "
    "주어진 '판단기준'과 '점검 증거'만 근거로 해당 항목의 취약 여부를 판정한다. "
    "추측하지 말고 증거에 없는 사실을 지어내지 않는다. "
    "증거가 판단기준을 충족하면 '양호', 위배되면 '취약', "
    "근거가 부족하거나 관리체계(문서·인터뷰) 확인이 필요한 부분이면 '판단보류'로 판정한다. "
    "반드시 아래 키를 가진 JSON 하나만 출력한다(설명·마크다운 금지):\n"
    '{"verdict": "양호|취약|판단보류", "confidence": 0.0~1.0, '
    '"rationale": "한국어 근거 2~4문장", '
    '"cited_evidence": ["인용한 리소스ID 또는 핵심 증거 문자열", ...]}'
)

_GOOD = {"good", "info"}


def build_evidence_text(item: EvidenceItem, max_chars: int = 8000) -> str:
    """증거를 텍스트로 직렬화. 취약 후보(good/info 외)는 전량 보존, good/info만 축약."""
    def fmt(r):
        return (f"- [{r.status}] {r.resource_id} :: {r.detail}\n"
                f"  evidence: {r.evidence}")

    primary = [r for r in item.resources if r.status.lower() not in _GOOD]
    secondary = [r for r in item.resources if r.status.lower() in _GOOD]

    lines = [fmt(r) for r in primary]
    used = sum(len(l) for l in lines)
    shown_secondary = 0
    for r in secondary:
        block = fmt(r)
        if used + len(block) > max_chars:
            break
        lines.append(block)
        used += len(block)
        shown_secondary += 1

    omitted = len(secondary) - shown_secondary
    if omitted > 0:
        lines.append(f"... (양호/정보 리소스 {omitted}건 축약·생략됨)")
    if not item.resources:
        return "(증거 없음)"
    return "\n".join(lines)


def build_prompt(criterion: Criterion, item: EvidenceItem,
                 max_chars: int = 8000) -> str:
    scope_note = ""
    if criterion.is_mixed:
        scope_note = (
            "\n[중요] 이 항목은 '관리체계+스크립트' 혼합이다. "
            "판단기준 중 기술/스크립트로 확인 가능한 부분만 대조해 판정하고, "
            "관리체계(문서·정책·인터뷰) 영역은 판정 근거로 삼지 말 것.")
    return (
        f"평가항목: {criterion.item_id} {criterion.item_name} "
        f"(위험도 {criterion.risk})\n"
        f"변형: {criterion.variant}\n"
        f"--- 판단기준 ---\n{criterion.standard}\n"
        f"--- 판단방법 ---\n{criterion.method}\n"
        f"{scope_note}\n"
        f"--- 점검 증거 ---\n{build_evidence_text(item, max_chars)}\n"
        f"--- 위 판단기준에 따라 JSON으로 판정하라. ---"
    )


def parse_json_lenient(text: str) -> Dict:
    """코드펜스/후행콤마/백틱을 허용하는 관대한 JSON 파서."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end != -1:
        t = t[start:end + 1]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        t2 = re.sub(r",\s*([}\]])", r"\1", t)  # 후행 콤마 제거
        t2 = t2.replace("`", '"')              # 백틱 → 따옴표
        return json.loads(t2)
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_judge.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/judge.py tests/test_judge.py && git commit -m "feat: judge prompt building, evidence guard, lenient json"
```

---

## Task 7: 판단 엔진 — Ollama 호출 + reconcile (judge.py 2부)

**Files:**
- Modify: `judge_tool/judge.py` (함수 추가)
- Test: `tests/test_judge.py` (테스트 추가)

- [ ] **Step 1: 실패 테스트 추가**

`tests/test_judge.py` 끝에 추가:
```python
from judge_tool.judge import judge_item, reconcile


class FakeClient:
    """OllamaClient 대역. 고정 JSON 응답."""
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def chat(self, system, user):
        self.calls.append((system, user))
        return self.payload


def _crit(eval_type="스크립트"):
    return Criterion("PISM-001", "통신구간 암호화", 5.0, "AWS",
                     eval_type, "양호-...취약-...", "방법")


def test_judge_item_returns_validated_dict():
    client = FakeClient('{"verdict":"취약","confidence":0.9,'
                        '"rationale":"정책 없음","cited_evidence":["b1"]}')
    out = judge_item(_crit(), _item("bad"), client)
    assert out["verdict"] == "취약"
    assert client.calls  # 호출됨


def test_reconcile_agreement_high_confidence():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": ["b1"]}
    j = reconcile(llm, _crit(), _item("bad"))   # script overall=bad → 취약
    assert j.script_status == "bad"
    assert j.agreement == "일치"
    assert j.needs_review is False
    assert j.scope == "스크립트 전체"
    assert j.management_review_needed is False


def test_reconcile_disagreement_flags_review():
    llm = {"verdict": "양호", "confidence": 0.95,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("bad"))   # script=취약, llm=양호 → 불일치
    assert j.agreement == "불일치"
    assert j.needs_review is True


def test_reconcile_mixed_item_sets_partial_scope():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit("관리체계, 스크립트"), _item("bad"))
    assert j.scope == "스크립트 부분만"
    assert j.management_review_needed is True
    assert j.needs_review is True   # 혼합 항목은 항상 검토 필요


def test_reconcile_review_status_is_na():
    llm = {"verdict": "취약", "confidence": 0.9,
           "rationale": "x", "cited_evidence": []}
    j = reconcile(llm, _crit(), _item("review"))  # script가 review → 비교 N/A
    assert j.agreement == "N/A"
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_judge.py -q`
Expected: FAIL (`ImportError: cannot import name 'judge_item'`)

- [ ] **Step 3: judge.py 2부 추가** (파일 끝에 append)

`judge_tool/judge.py` 끝에 추가:
```python
_VALID_VERDICTS = {"양호", "취약", "판단보류"}
# 스크립트 status → 기대 verdict (비교 가능한 것만)
_STATUS_TO_VERDICT = {"good": "양호", "bad": "취약"}
_LOW_CONFIDENCE = 0.6


class OllamaClient:
    def __init__(self, url: str = "http://localhost:11434",
                 model: str = "qwen2.5:14b", temperature: float = 0.0,
                 timeout: int = 120):
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    def chat(self, system: str, user: str) -> str:
        resp = requests.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": self.temperature},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


def judge_item(criterion: Criterion, item: EvidenceItem, client,
               max_chars: int = 8000, retries: int = 2) -> Dict:
    """LLM 호출 후 검증된 판정 dict 반환. JSON 실패 시 재시도."""
    prompt = build_prompt(criterion, item, max_chars)
    last_err = None
    for _ in range(retries + 1):
        raw = client.chat(SYSTEM_PROMPT, prompt)
        try:
            data = parse_json_lenient(raw)
        except json.JSONDecodeError as e:
            last_err = e
            continue
        if data.get("verdict") in _VALID_VERDICTS:
            data.setdefault("confidence", 0.0)
            data.setdefault("rationale", "")
            data.setdefault("cited_evidence", [])
            return data
        last_err = ValueError(f"잘못된 verdict: {data.get('verdict')}")
    # 모든 시도 실패 → 판단보류로 안전 처리
    return {"verdict": "판단보류", "confidence": 0.0,
            "rationale": f"LLM 응답 파싱 실패: {last_err}", "cited_evidence": []}


def reconcile(llm: Dict, criterion: Criterion, item: EvidenceItem) -> Judgment:
    script_status = item.overall_status
    expected = _STATUS_TO_VERDICT.get(script_status)
    verdict = llm["verdict"]
    confidence = float(llm.get("confidence", 0.0))

    if expected is None:
        agreement = "N/A"
    else:
        agreement = "일치" if verdict == expected else "불일치"

    needs_review = (
        agreement == "불일치"
        or confidence < _LOW_CONFIDENCE
        or criterion.is_mixed
        or verdict == "판단보류"
    )
    return Judgment(
        item_id=criterion.item_id,
        item_name=criterion.item_name,
        variant=criterion.variant,
        risk=criterion.risk,
        verdict=verdict,
        confidence=confidence,
        rationale=llm.get("rationale", ""),
        cited_evidence=list(llm.get("cited_evidence", [])),
        scope="스크립트 부분만" if criterion.is_mixed else "스크립트 전체",
        management_review_needed=criterion.is_mixed,
        script_status=script_status,
        agreement=agreement,
        needs_review=needs_review,
    )
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_judge.py -q`
Expected: PASS (9 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/judge.py tests/test_judge.py && git commit -m "feat: ollama client, judge_item, reconcile"
```

---

## Task 8: 출력기 — JSON·Excel·커버리지 (writer.py)

**Files:**
- Create: `judge_tool/writer.py`
- Test: `tests/test_writer.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_writer.py`:
```python
import json
import os

import openpyxl

from judge_tool.models import Criterion, Judgment
from judge_tool.writer import build_coverage, write_json, write_excel


def _judgment(item_id="PISM-001", needs_review=False):
    return Judgment(item_id, "통신구간 암호화", "AWS", 5.0, "취약", 0.9,
                    "근거", ["b1"], "스크립트 전체", False, "bad", "일치",
                    needs_review)


def _criteria():
    return {
        ("PISM-001", "AWS"): Criterion("PISM-001", "암호화", 5.0, "AWS",
                                       "스크립트", "기준", "방법"),
        ("PISM-005", "AWS"): Criterion("PISM-005", "퍼블릭", 5.0, "AWS",
                                       "스크립트", "기준", "방법"),
        ("PISM-006", "AWS"): Criterion("PISM-006", "분리", 3.0, "AWS",
                                       "관리체계", "기준", "방법"),  # 스크립트 아님
    }


def test_coverage_lists_missing_script_items():
    cov = build_coverage(_criteria(), [_judgment("PISM-001")], "AWS")
    assert cov["expected"] == 2          # PISM-001, 005 (006은 관리체계라 제외)
    assert cov["judged"] == 1
    assert cov["missing"] == ["PISM-005"]


def test_write_json(tmp_path):
    path = os.path.join(tmp_path, "out.json")
    meta = {"model": "test", "criteria_version": "제2026-1호"}
    cov = {"expected": 2, "judged": 1, "missing": ["PISM-005"]}
    write_json([_judgment()], meta, cov, path)
    data = json.load(open(path, encoding="utf-8"))
    assert data["metadata"]["model"] == "test"
    assert data["coverage"]["missing"] == ["PISM-005"]
    assert data["judgments"][0]["item_id"] == "PISM-001"


def test_write_excel(tmp_path):
    path = os.path.join(tmp_path, "out.xlsx")
    meta = {"model": "test", "criteria_version": "제2026-1호",
            "generated_at": "2026-06-01 10:00:00", "source_file": "x.xml",
            "source_sha256": "abc", "tool_version": "0.1.0"}
    cov = {"expected": 2, "judged": 1, "missing": ["PISM-005"]}
    write_excel([_judgment(needs_review=True)], meta, cov, path)
    wb = openpyxl.load_workbook(path)
    assert "판정결과" in wb.sheetnames
    ws = wb["판정결과"]
    header = [c.value for c in ws[1]]
    assert "항목ID" in header and "판정" in header and "재검토" in header
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_writer.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: writer.py 구현**

`judge_tool/writer.py`:
```python
import json
from dataclasses import asdict
from typing import Dict, List, Tuple

import openpyxl
from openpyxl.styles import Font, PatternFill

from judge_tool.models import Criterion, Judgment


def build_coverage(criteria: Dict[Tuple[str, str], Criterion],
                   judgments: List[Judgment], variant: str) -> Dict:
    """스크립트 기반·해당 variant 항목 중 미판정 목록 산출."""
    expected_ids = {
        c.item_id for (iid, v), c in criteria.items()
        if v == variant and c.is_script_based and c.eval_type != "N/A"
    }
    judged_ids = {j.item_id for j in judgments}
    missing = sorted(expected_ids - judged_ids)
    return {"expected": len(expected_ids), "judged": len(judged_ids),
            "missing": missing}


def write_json(judgments: List[Judgment], meta: Dict, coverage: Dict,
               path: str) -> None:
    payload = {
        "metadata": meta,
        "coverage": coverage,
        "judgments": [asdict(j) for j in judgments],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


_HEADERS = ["항목ID", "항목명", "위험도", "변형", "판정", "확신도",
            "스크립트status", "일치여부", "재검토", "범위", "관리체계검토",
            "근거", "인용증거"]
_REVIEW_FILL = PatternFill("solid", fgColor="FFF2CC")  # 연노랑


def write_excel(judgments: List[Judgment], meta: Dict, coverage: Dict,
                path: str) -> None:
    wb = openpyxl.Workbook()

    # 요약 시트
    summary = wb.active
    summary.title = "요약"
    rows = [
        ("도구 버전", meta.get("tool_version", "")),
        ("기준 버전", meta.get("criteria_version", "")),
        ("사용 모델", meta.get("model", "")),
        ("생성 시각", meta.get("generated_at", "")),
        ("입력 파일", meta.get("source_file", "")),
        ("입력 SHA256", meta.get("source_sha256", "")),
        ("대상 항목수", coverage.get("expected", "")),
        ("판정 항목수", coverage.get("judged", "")),
        ("미판정 항목", ", ".join(coverage.get("missing", []))),
        ("재검토 필요수", sum(1 for j in judgments if j.needs_review)),
    ]
    for r, (k, v) in enumerate(rows, start=1):
        summary.cell(r, 1, k).font = Font(bold=True)
        summary.cell(r, 2, v)

    # 판정결과 시트
    ws = wb.create_sheet("판정결과")
    ws.append(_HEADERS)
    for c in ws[1]:
        c.font = Font(bold=True)
    for j in judgments:
        ws.append([
            j.item_id, j.item_name, j.risk, j.variant, j.verdict,
            round(j.confidence, 2), j.script_status, j.agreement,
            "예" if j.needs_review else "", j.scope,
            "예" if j.management_review_needed else "",
            j.rationale, " | ".join(j.cited_evidence),
        ])
        if j.needs_review:
            for c in ws[ws.max_row]:
                c.fill = _REVIEW_FILL
    wb.save(path)
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_writer.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add judge_tool/writer.py tests/test_writer.py && git commit -m "feat: JSON/Excel writer with coverage"
```

---

## Task 9: CLI 오케스트레이션 + 골든 E2E (main.py)

**Files:**
- Create: `judge_tool/main.py`
- Test: `tests/test_main_e2e.py`

- [ ] **Step 1: 실패 테스트 작성** (실제 XML+xlsx, LLM만 모킹)

`tests/test_main_e2e.py`:
```python
import json
import os

from judge_tool.main import run


class StubClient:
    """모든 항목을 '취약'으로 판정하는 대역 (Ollama 불필요)."""
    def chat(self, system, user):
        return ('{"verdict":"취약","confidence":0.8,'
                '"rationale":"테스트 판정","cited_evidence":["x"]}')


def test_run_end_to_end(tmp_path, aws_report_path, criteria_xlsx_path):
    json_path = os.path.join(tmp_path, "result.json")
    xlsx_path = os.path.join(tmp_path, "result.xlsx")
    summary = run(
        report_path=aws_report_path,
        criteria_path=criteria_xlsx_path,
        profile_key="cloud",
        client=StubClient(),
        json_out=json_path,
        xlsx_out=xlsx_path,
        model_name="stub-model",
    )
    assert os.path.exists(json_path) and os.path.exists(xlsx_path)

    data = json.load(open(json_path, encoding="utf-8"))
    # 실제 보고서의 스크립트 항목만 판정되었는지
    judged_ids = {j["item_id"] for j in data["judgments"]}
    assert "PISM-001" in judged_ids
    # 분할항목이 하나로 합쳐졌는지 (037_1/037_2 → PISM-037 1건)
    assert sum(1 for j in data["judgments"] if j["item_id"] == "PISM-037") == 1
    # 감사 메타데이터
    assert data["metadata"]["model"] == "stub-model"
    assert len(data["metadata"]["source_sha256"]) == 64
    # 커버리지 존재
    assert data["coverage"]["judged"] >= 1
    assert summary["judged"] == data["coverage"]["judged"]
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_main_e2e.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: main.py 구현**

`judge_tool/main.py`:
```python
import argparse
import hashlib
import os
from datetime import datetime
from typing import Dict, Optional

from judge_tool import __version__
from judge_tool.criteria_loader import load_criteria
from judge_tool.judge import OllamaClient, judge_item, reconcile
from judge_tool.mapper import aggregate
from judge_tool.parsers import cloud_xml
from judge_tool.profile import get_profile
from judge_tool.writer import build_coverage, write_excel, write_json

_PARSERS = {"cloud_xml": cloud_xml}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run(report_path: str, criteria_path: str, profile_key: str, client,
        json_out: str, xlsx_out: str, model_name: str,
        now: Optional[str] = None) -> Dict:
    profile = get_profile(profile_key)
    variant = profile.variant_from_filename(report_path)
    if variant is None:
        raise ValueError(f"파일명에서 variant를 식별할 수 없음: {report_path}")

    criteria = load_criteria(criteria_path, profile)
    raw_checks = _PARSERS[profile.parser].parse(report_path)
    items = aggregate(raw_checks, variant, profile)

    judgments = []
    for item_id, item in items.items():
        crit = criteria.get((item_id, variant))
        if crit is None or not crit.is_script_based or crit.eval_type == "N/A":
            continue  # 기준에 없거나 스크립트 대상 아님 → 스킵
        llm = judge_item(crit, item, client)
        judgments.append(reconcile(llm, crit, item))

    judgments.sort(key=lambda j: j.item_id)
    coverage = build_coverage(criteria, judgments, variant)
    meta = {
        "tool_version": __version__,
        "criteria_version": "제2026-1호",
        "model": model_name,
        "generated_at": now or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_file": os.path.basename(report_path),
        "source_sha256": _sha256(report_path),
        "profile": profile_key,
        "variant": variant,
    }
    write_json(judgments, meta, coverage, json_out)
    write_excel(judgments, meta, coverage, xlsx_out)
    return coverage


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="클라우드 점검 결과 LLM 자동 판단 도구")
    ap.add_argument("--report", required=True, help="점검 결과 XML 경로")
    ap.add_argument("--criteria", required=True, help="평가기준 xlsx 경로")
    ap.add_argument("--profile", default="cloud")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    args = ap.parse_args(argv)

    base = os.path.splitext(os.path.basename(args.report))[0]
    json_out = os.path.join(args.out_dir, f"result_{base}.json")
    xlsx_out = os.path.join(args.out_dir, f"result_{base}.xlsx")

    client = OllamaClient(url=args.ollama_url, model=args.model)
    cov = run(args.report, args.criteria, args.profile, client,
              json_out, xlsx_out, args.model)
    print(f"판정 {cov['judged']}/{cov['expected']} 완료. "
          f"미판정: {cov['missing']}")
    print(f"출력: {json_out}\n      {xlsx_out}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_main_e2e.py -q`
Expected: PASS (1 passed)

- [ ] **Step 5: 전체 테스트 통과 확인**

Run: `python3 -m pytest -q`
Expected: PASS (전부)

- [ ] **Step 6: Commit**

```bash
git add judge_tool/main.py tests/test_main_e2e.py && git commit -m "feat: CLI orchestration with golden e2e test"
```

---

## Task 10: 실제 Ollama 연동 스모크 테스트 (수동, 선택)

**Files:** 없음 (실행만)

- [ ] **Step 1: Ollama·모델 준비**

Run:
```bash
ollama pull qwen2.5:14b   # 또는 보유 모델
```

- [ ] **Step 2: 실제 실행**

Run:
```bash
cd "/Users/fsat/Documents/saptweb/04.Script_judgement_automation"
python3 -m judge_tool.main \
  --report "results/Public Cloud/aws_report_20251223_hinno.xml" \
  --criteria "ref/전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx" \
  --out-dir results
```
Expected: `판정 N/M 완료 ...` + `result_aws_report_20251223_hinno.json/.xlsx` 생성

- [ ] **Step 3: 결과 육안 확인**

`result_*.xlsx`의 "판정결과" 시트에서 양호/취약 판정·근거·재검토(노랑) 표시 확인.
스크립트 status와 LLM 판정이 다른 행(불일치)이 재검토로 잡혔는지 확인.

---

## Self-Review (작성자 점검 결과)

- **스펙 커버리지:** §3 결정(A안/독립판단+비교/경량분리/런타임추출/JSON+Excel/모델교체) → Task 2·6·7·8·9. §6.1 분할집계 → Task 5. §6.2 혼합=부분판정 → Task 6·7. §6.3 증거가드 → Task 6. §6.4 N/A 스킵 → Task 9. §6.5 커버리지 → Task 8. §6.6 일관성(온도0/JSON강제/재시도) → Task 7. §6.7 에러처리(판단보류/연결실패/관대파싱) → Task 6·7. 감사 메타데이터 → Task 9. 정제(malformed XML) → Task 4. 모두 매핑됨.
- **플레이스홀더:** 없음(모든 step에 실제 코드/명령/기대출력 포함).
- **타입 일관성:** `Criterion/ResourceEvidence/EvidenceItem/Judgment` 시그니처가 Task 1 정의와 이후 모든 사용처 일치. `chat(system,user)->str`, `parse()`, `aggregate()`, `judge_item()`, `reconcile()`, `build_coverage()`, `run()` 시그니처 교차 확인 완료.
- **알려진 한계(의도적):** 모델 기본값 `qwen2.5:14b`은 placeholder가 아니라 잠정 기본값(스펙대로 추후 실측 교체). Task 10은 수동/선택.

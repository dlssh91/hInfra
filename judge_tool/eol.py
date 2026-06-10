"""DBM-025(서비스 지원종료) 결정론 판정.

eol.yaml의 벤더별 지원종료일 테이블과 보고서 증거에서 추출한 버전을
대조해 LLM 없이 양호/취약을 판정한다. D라벨의 "로컬 LLM이 EOL 기준을
모름" 문제를 정적 데이터로 해결하는 모듈.

폴백 계약: 버전 추출 실패·테이블 미수록·테이블 부재 시 None을 반환하고,
호출부(main)는 기존 D라벨 canned_message 자동보류로 처리한다.
테이블 날짜는 사람이 갱신하므로(eol.yaml as_of) rationale에 기준일을
명시해 평가자가 정책 변동을 재확인할 수 있게 한다.
"""
import datetime
import os
import re
from typing import Dict, Optional

import yaml

_EOL_PATH = os.path.join(os.path.dirname(__file__), "eol.yaml")

# profile_key → (제품 키, 버전 추출 패턴 목록 — 첫 매치 사용)
# 패턴은 보고서 증거(JSON 행 직렬화 텍스트)에서 제품 버전 문자열을 찾는다.
# "VARIABLE_NAME": "version" 은 따옴표로 앵커되어 admin_tls_version 등
# 유사 변수명을 오탐하지 않는다.
_PATTERNS = {
    "db_mysql": ("mysql", [
        re.compile(r'"VARIABLE_NAME":\s*"version"\s*,\s*'
                   r'"VARIABLE_VALUE":\s*"(\d[\d.]*)', re.IGNORECASE),
    ]),
    "db_mariadb": ("mariadb", [
        re.compile(r'"VARIABLE_NAME":\s*"version"\s*,\s*'
                   r'"VARIABLE_VALUE":\s*"(\d[\d.]*)', re.IGNORECASE),
    ]),
    "db_mssql": ("mssql", [
        re.compile(r"Microsoft SQL Server (\d{4})"),
    ]),
    "db_postgresql": ("postgresql", [
        re.compile(r"PostgreSQL (\d[\d.]*)"),
    ]),
    "db_oracle": ("oracle", [
        re.compile(r"Database Release Update\s*:\s*(\d[\d.]*)"),
        re.compile(r"Oracle Database (\d{2})c?"),
    ]),
}

_table_cache: Optional[Dict] = None


def _load_table() -> Dict:
    global _table_cache
    if _table_cache is None:
        if not os.path.exists(_EOL_PATH):
            _table_cache = {}
        else:
            with open(_EOL_PATH, encoding="utf-8") as fh:
                _table_cache = yaml.safe_load(fh) or {}
    return _table_cache


def _series(product: str, version: str) -> str:
    """버전 문자열 → eol.yaml 시리즈 키.

    mysql/mariadb는 마이너까지(8.4), postgresql/oracle은 주버전(17/19),
    mssql은 연도(2019)가 시리즈 단위다.
    """
    parts = version.split(".")
    if product in ("mysql", "mariadb"):
        return ".".join(parts[:2])
    return parts[0]


def _extract_version(items: Dict, patterns) -> Optional[str]:
    """증거에서 버전 추출. 버전이 사는 DBM-016/025 항목을 우선 탐색."""
    ordered = [items[k] for k in ("DBM-016", "DBM-025") if k in items]
    ordered.extend(v for k, v in items.items()
                   if k not in ("DBM-016", "DBM-025"))
    for item in ordered:
        text = (item.context or "") + "\n" + "\n".join(
            (r.evidence or r.detail or "") for r in item.resources)
        for pat in patterns:
            m = pat.search(text)
            if m:
                return m.group(1)
    return None


def judge_eol(profile_key: str, items: Dict,
              today: Optional[datetime.date] = None) -> Optional[Dict]:
    """EOL 결정론 판정. 성공 시 reconcile에 넣을 판정 dict, 실패 시 None."""
    spec = _PATTERNS.get(profile_key)
    if spec is None:
        return None
    product, patterns = spec
    table = _load_table()
    series_map = (table.get("products") or {}).get(product) or {}
    if not series_map:
        return None
    version = _extract_version(items, patterns)
    if version is None:
        return None
    eol_date = series_map.get(_series(product, version))
    if not isinstance(eol_date, datetime.date):
        return None
    if today is None:
        today = datetime.date.today()
    as_of = table.get("as_of")
    suffix = (f" (EOL 테이블 기준일 {as_of} — 벤더 정책 변동·Extended Support "
              f"계약 여부는 평가자 확인 필요)" if as_of else "")
    series = _series(product, version)
    if eol_date < today:
        return {"verdict": "취약", "confidence": 0.9,
                "rationale": f"[EOL 자동판정] {product} {version} (시리즈 "
                             f"{series})의 벤더 지원 종료일 {eol_date}이 "
                             f"경과함.{suffix}",
                "cited_evidence": [f"version={version}"]}
    return {"verdict": "양호", "confidence": 0.9,
            "rationale": f"[EOL 자동판정] {product} {version} (시리즈 {series})"
                         f"은 {eol_date}까지 벤더 지원 대상.{suffix}",
            "cited_evidence": [f"version={version}"]}

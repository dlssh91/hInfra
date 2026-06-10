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


def _lookup(profile_key: str, items: Dict):
    """공통 조회: (product, version, series, entry, as_of) 또는 None."""
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
    series = _series(product, version)
    entry = series_map.get(series)
    if not isinstance(entry, dict):
        return None
    return product, version, series, entry, table.get("as_of")


def judge_eol(profile_key: str, items: Dict,
              today: Optional[datetime.date] = None) -> Optional[Dict]:
    """EOL 결정론 판정. 성공 시 reconcile에 넣을 판정 dict, 실패 시 None."""
    found = _lookup(profile_key, items)
    if found is None:
        return None
    product, version, series, entry, as_of = found
    eol_date = entry.get("eol")
    if not isinstance(eol_date, datetime.date):
        return None
    if today is None:
        today = datetime.date.today()
    suffix = (f" (EOL 테이블 기준일 {as_of} — 벤더 정책 변동·Extended Support "
              f"계약 여부는 평가자 확인 필요)" if as_of else "")
    suffix += _staleness_warning(as_of, today)
    if eol_date < today:
        # 커뮤니티 EOL 경과를 '취약'으로 단정하지 않는다:
        # (1) 관리형 서비스(RDS/Aurora/Azure)는 Extended Support 등 별도
        #     lifecycle을 가지며, (2) 판단기준 자체가 "별도 사후 관리 절차
        #     없이 사용하는 경우"를 취약 조건으로 둬 인터뷰 확인이 필요하다.
        return {"verdict": "판단보류", "confidence": 0.5,
                "rationale": f"[EOL 자동판정] {product} {version} (시리즈 "
                             f"{series})의 커뮤니티 지원 종료일 {eol_date}이 "
                             f"경과함 — EOL 후보. 관리형 서비스 Extended "
                             f"Support 계약·사후 관리 절차 여부를 담당자에게 "
                             f"확인 필요.{suffix}",
                "cited_evidence": [f"version={version}"]}
    return {"verdict": "양호", "confidence": 0.9,
            "rationale": f"[EOL 자동판정] {product} {version} (시리즈 {series})"
                         f"은 {eol_date}까지 벤더 지원 대상.{suffix}",
            "cited_evidence": [f"version={version}"]}


_STALE_DAYS = 180


def _staleness_warning(as_of, today) -> str:
    """테이블이 오래되면 '양호' 판정이 false-good이 될 수 있으므로 경고.

    사람의 갱신 규율에만 의존하지 않는 코드 차원 방어(Opus 리뷰 반영).
    """
    if isinstance(as_of, datetime.date) and (today - as_of).days > _STALE_DAYS:
        return (f" [경고: EOL 테이블이 {(today - as_of).days}일 경과 — "
                f"eol.yaml 갱신 필요, 판정 신뢰 불가]")
    return ""


# MSSQL은 연도(2019)가 시리즈 키이므로 패치 대조는 빌드 번호로 한다.
# 빌드 문자열이 연도와 다른 증거 행에 분리되어 있으면 추출 실패 →
# canned_message 폴백(조용한 폴백이지만 안전한 방향).
_MSSQL_BUILD = re.compile(r"(\d{2}\.\d+\.\d+\.\d+)")


def _ver_tuple(v: str):
    return tuple(int(p) for p in re.findall(r"\d+", v))


def judge_patch(profile_key: str, items: Dict,
                today: Optional[datetime.date] = None) -> Optional[Dict]:
    """DBM-016 패치 결정론 대조. 현재 버전 vs 시리즈 최신(latest)을 비교해
    사실만 제공한다. verdict는 판단보류 고정 — 관리형 서비스(RDS/Aurora/
    Azure)는 커뮤니티 최신과 패치 채널이 달라 단정할 수 없기 때문.
    latest 미수록(예: Oracle)이면 None → canned_message 폴백."""
    found = _lookup(profile_key, items)
    if found is None:
        return None
    product, version, series, entry, as_of = found
    latest = entry.get("latest")
    if not latest:
        return None
    current = version
    if product == "mssql":
        current = _extract_version(items, [_MSSQL_BUILD])
        if current is None:
            return None
    if today is None:
        today = datetime.date.today()
    suffix = f" (패치 테이블 기준일 {as_of})" if as_of else ""
    suffix += _staleness_warning(as_of, today)
    if _ver_tuple(current) < _ver_tuple(str(latest)):
        msg = (f"[패치 자동대조] 현재 {current}, 시리즈({series}) 최신 "
               f"{latest} — 최신 패치 미적용 후보.{suffix} 관리형 서비스의 "
               f"패치 채널 차이가 있으므로 담당자 확인 필요.")
    else:
        msg = (f"[패치 자동대조] 현재 {current}는 시리즈({series}) 최신 "
               f"{latest} 이상 — 커뮤니티 기준 최신 패치 수준.{suffix} "
               f"벤더 권고사항 적용 여부는 담당자 확인 필요.")
    return {"verdict": "판단보류", "confidence": 0.5,
            "rationale": msg, "cited_evidence": [f"version={current}"]}

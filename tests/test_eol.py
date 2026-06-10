"""eol.py — DBM-025 EOL 결정론 판정 테스트."""
import datetime

from judge_tool.eol import judge_eol, _series
from judge_tool.models import EvidenceItem, ResourceEvidence

TODAY = datetime.date(2026, 6, 10)


def _items(item_id, evidence):
    res = ResourceEvidence(resource_id="r1", status="info",
                           detail="", evidence=evidence)
    return {item_id: EvidenceItem(item_id=item_id, variant="v",
                                  resources=[res])}


def test_series_mapping():
    assert _series("mysql", "8.4.4") == "8.4"
    assert _series("mariadb", "11.4.4") == "11.4"
    assert _series("postgresql", "17.4") == "17"
    assert _series("oracle", "19.26.0.0.250121") == "19"
    assert _series("mssql", "2019") == "2019"


def test_mysql_supported_version_good():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "양호"
    assert "8.4.4" in r["rationale"]


def test_mysql_eol_version_vulnerable():
    """MySQL 8.0은 2026-04-30 지원 종료 → 2026-06-10 기준 취약."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "취약"


def test_postgresql_version_good():
    items = _items("DBM-016",
                   '{"version": "PostgreSQL 17.4 on aarch64-unknown-linux-gnu"}')
    r = judge_eol("db_postgresql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "양호"


def test_mssql_version_good():
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2019 (RTM-CU32)"}')
    r = judge_eol("db_mssql", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_oracle_version_good():
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 19.26.0.0.250121"}')
    r = judge_eol("db_oracle", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_mariadb_version_good():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "VERSION","VARIABLE_VALUE": "11.4.4-MariaDB-log"}')
    r = judge_eol("db_mariadb", items, today=TODAY)
    assert r["verdict"] == "양호"


def test_version_in_other_item_found():
    """버전이 DBM-025가 아닌 임의 항목에 있어도 전수 탐색으로 발견."""
    items = _items("DBM-099",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None and r["verdict"] == "양호"


def test_admin_tls_version_not_false_positive():
    """admin_tls_version 같은 유사 변수명은 버전으로 오인하지 않는다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "admin_tls_version",'
                   '"VARIABLE_VALUE": "TLSv1.2,TLSv1.3"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_unknown_series_returns_none():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "5.7.44"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_unknown_profile_returns_none():
    assert judge_eol("cloud", {}, today=TODAY) is None


def test_no_version_evidence_returns_none():
    items = _items("DBM-016", '{"no": "version here"}')
    assert judge_eol("db_mysql", items, today=TODAY) is None


def test_rationale_cites_as_of_date():
    """rationale에 테이블 기준일이 포함되어 평가자가 갱신 여부를 알 수 있다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert "EOL 테이블 기준일" in r["rationale"]


def test_defer_or_eol_preserves_verdict_with_empty_own_section():
    """DBM-025 자기 섹션이 비어 있고 버전이 타 항목에 있어도 EOL 판정의
    verdict(양호)가 reconcile '증거 없음' 가드에 덮어써지지 않는다.

    회귀: 2026-06-10 실데이터 검증에서 EOL 양호 판정이 빈 더미 item 때문에
    판단보류로 강제되는 버그 발견.
    """
    from judge_tool.main import _defer_or_eol
    from judge_tool.models import Criterion
    from judge_tool.profile import DB_MYSQL

    crit = Criterion(
        item_id="DBM-025", item_name="EOL", risk=3.0, variant="mysql_rds",
        eval_type="", standard="기준", method="방법", applicable=True,
        label="D", eol_check=True, canned_message="폴백 메시지")
    empty_item = EvidenceItem(item_id="DBM-025", variant="mysql_rds",
                              resources=[])
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')

    j = _defer_or_eol(crit, empty_item, items, DB_MYSQL, "db_mysql")
    assert j.verdict == "양호", "EOL 양호 판정이 보존되어야 함"
    assert "[EOL 자동판정]" in j.rationale
    assert "[자동 판단보류" not in j.rationale

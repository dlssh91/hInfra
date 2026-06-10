"""eol.py — DBM-025 EOL / DBM-016 패치 결정론 판정 테스트."""
import datetime

from judge_tool.eol import judge_eol, judge_patch, _series, _ver_tuple
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


def test_mysql_eol_passed_defers_not_vulnerable():
    """커뮤니티 EOL 경과(MySQL 8.0, 2026-04-30)는 '취약' 단정이 아니라
    'EOL 후보' 판단보류 — 관리형 서비스는 Extended Support 등 별도
    lifecycle이 있고, 판단기준도 '사후 관리 절차 없이'를 조건으로 둠."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.0.32"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "EOL 후보" in r["rationale"]
    assert "경과" in r["rationale"]


def test_stale_table_warning_attached():
    """as_of가 180일 넘게 경과하면 판정 신뢰 불가 경고가 붙는다."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    far_future = datetime.date(2027, 6, 10)
    r = judge_eol("db_mysql", items, today=far_future)
    assert r is not None
    assert "갱신 필요" in r["rationale"]


def test_fresh_table_no_staleness_warning():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_eol("db_mysql", items, today=TODAY)
    assert "갱신 필요" not in r["rationale"]


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


# ---------------------------------------------------------------------------
# judge_patch — DBM-016 패치 대조
# ---------------------------------------------------------------------------

def test_ver_tuple_numeric_compare():
    assert _ver_tuple("17.4") < _ver_tuple("17.10")   # 문자열 비교였다면 반대
    assert _ver_tuple("8.4.9") > _ver_tuple("8.4.4")


def test_patch_behind_flagged():
    """현재 8.4.4 < 시리즈 최신 8.4.9 → 미적용 후보, verdict는 판단보류."""
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.4"}')
    r = judge_patch("db_mysql", items)
    assert r is not None
    assert r["verdict"] == "판단보류"
    assert "미적용 후보" in r["rationale"]
    assert "8.4.9" in r["rationale"]


def test_patch_current_is_latest():
    items = _items("DBM-016",
                   '{"VARIABLE_NAME": "version","VARIABLE_VALUE": "8.4.9"}')
    r = judge_patch("db_mysql", items)
    assert r["verdict"] == "판단보류"
    assert "최신 패치 수준" in r["rationale"]


def test_patch_mssql_compares_build_number():
    """MSSQL은 연도(2019)가 아닌 빌드 번호(15.0.x)로 대조한다."""
    items = _items("DBM-016",
                   '{"version_info": "Microsoft SQL Server 2019 (RTM-CU32) '
                   '(KB5054833) - 15.0.4430.1 (X64)"}')
    r = judge_patch("db_mssql", items)
    assert r is not None
    assert "15.0.4430.1" in r["rationale"]
    assert "15.0.4470.1" in r["rationale"]
    assert "미적용 후보" in r["rationale"]


def test_patch_oracle_no_latest_falls_back():
    """Oracle은 latest 미수록 → None 폴백(canned_message 사용)."""
    items = _items("DBM-016",
                   '{"description":"Database Release Update : 19.26.0.0.250121"}')
    assert judge_patch("db_oracle", items) is None


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
    # 테이블 기반 자동판정은 파서 status 동작과 무관하게 항상 검토 대상
    assert j.needs_review is True

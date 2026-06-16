import json
import os
import openpyxl
import pytest

from judge_tool.errors import ReportError
from judge_tool.main import run, _judge_one, JudgeContext
from judge_tool.models import Criterion, EvidenceItem, ResourceEvidence
from judge_tool.profile import get_profile

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


def _db_native_criteria_xlsx(path):
    """mysql_native 컬럼(평가대상16/판단기준35/판단방법36)으로 합성 기준."""
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "데이터베이스"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "name"); ws.cell(4, 8, "risk")
    ws.cell(4, 16, "대상"); ws.cell(4, 35, "기준"); ws.cell(4, 36, "방법")
    for r, dbm in [(5, "DBM-001"), (6, "DBM-004"), (7, "DBM-017")]:
        ws.cell(r, 2, dbm); ws.cell(r, 7, f"{dbm}항목"); ws.cell(r, 8, 5.0)
        ws.cell(r, 16, "o"); ws.cell(r, 35, "* 양호 - ...\n* 취약 - ...")
        ws.cell(r, 36, "방법")
    wb.save(path)


def test_db_run_native_variant_e2e(tmp_path):
    """파일명→native variant→네이티브 컬럼 로딩→판정→writer 전 배선을
    LLM 없이(StubVuln) 검증. 실데이터 e2e는 데이터 확보 후 별도 진행."""
    criteria = str(tmp_path / "db_native.xlsx")
    _db_native_criteria_xlsx(criteria)
    # 접미사 없는 파일명 → mysql_native 로 식별되어야 한다.
    report = str(tmp_path / "mysql_result.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")

    data = json.load(open(jout, encoding="utf-8"))
    assert data["metadata"]["variant"] == "mysql_native"
    by_id = {j["item_id"]: j for j in data["judgments"]}
    assert "DBM-001" in by_id
    # DBM-001은 db_mysql.yaml에서 label C → LLM 없이 canned 자동 판단보류.
    assert by_id["DBM-001"]["label"] == "C"
    assert by_id["DBM-001"]["verdict"] == "판단보류"


def test_tibero_profile_excluded(tmp_path):
    """Tibero 프로파일은 구조만 정의·판정 배제 → 즉시 ReportError."""
    with pytest.raises(ReportError, match="배제"):
        run(str(tmp_path / "tibero_result.txt"), str(tmp_path / "c.xlsx"),
            "db_tibero", StubVuln(),
            str(tmp_path / "j.json"), str(tmp_path / "r.xlsx"), "stub")


def test_unknown_profile_raises_reporterror(tmp_path):
    """잘못된 --profile은 raw KeyError 대신 ReportError로 변환되어야 한다."""
    with pytest.raises(ReportError, match="알 수 없는 프로파일"):
        run(str(tmp_path / "mysql_result_rds.txt"), str(tmp_path / "c.xlsx"),
            "db_bogus", StubVuln(),
            str(tmp_path / "j.json"), str(tmp_path / "r.xlsx"), "stub")


def test_db_note_forces_judgment_boryu(tmp_path):
    # Phase 4 이전: NOTE 보유 → 강제 판단보류(pre-det_common 동작).
    # Phase 4 이후: DBM-011/019는 mysql에서 DET이므로 det_common 어댑터가 먼저 실행.
    #   - DBM-011: audit_log.so not loaded = 실제 위반 → 취약 (NOTE 우회, 올바른 동작)
    #   - DBM-019: @@@/*** noise만 → filter_noise 후 빈 위반 → 양호
    # 이 테스트는 Phase 4 이후 동작(det_common 우선)을 검증한다.
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
    # DBM-011: audit_log.so not loaded → 실제 위반 → 취약 (det_common 우선)
    j_011 = next(x for x in data["judgments"] if x["item_id"] == "DBM-011")
    assert j_011["verdict"] == "취약", f"DBM-011은 audit_log 미로드 → 취약 기대: {j_011}"
    assert j_011["needs_review"] is True
    # DBM-019: @@@/*** noise만 → filter_noise 후 빈 위반 → 양호
    j_019 = next(x for x in data["judgments"] if x["item_id"] == "DBM-019")
    assert j_019["verdict"] in ("양호", "취약", "판단보류"), f"DBM-019 verdict unexpected: {j_019}"
    # needs_review는 det_common 결과에도 설정됨
    assert j_011["needs_review"] is True


def _db_crit(item_id="DBM-100"):
    return Criterion(
        item_id=item_id, item_name=f"{item_id}항목", risk=5.0,
        variant="MYSQL", eval_type="스크립트",
        standard="* 양호 - ...\n* 취약 - ...", method="방법",
        applicable=True)


def test_judge_one_blank_note_no_indexerror():
    # NOTE 값이 공백뿐이면 과거 .splitlines()[0]에서 IndexError 발생.
    # 줄-시작 정규식으로 교체 후 예외 없이 판단보류를 반환해야 한다.
    crit = _db_crit("DBM-100")
    item = EvidenceItem(item_id="DBM-100", variant="MYSQL",
                        resources=[], context="QUERY: q\nNOTE:   ")
    profile = get_profile("db_mysql")
    ctx = JudgeContext(profile=profile, profile_key="db_mysql",
                       client=StubVuln(), items={}, variant="MYSQL")
    j = _judge_one(crit, item, ctx)
    assert j is not None
    assert j.verdict == "판단보류"
    assert "NOTE" in j.rationale


def test_judge_one_inline_note_no_false_match():
    # QUERY 줄 중간에 "NOTE:"가 섞여 있고 별도 NOTE 줄은 없는 경우,
    # NOTE 강제 분기에 진입하지 않고 정상 LLM 경로로 가야 한다.
    crit = _db_crit("DBM-101")
    # 증거 1건 부여(무증거 자동 판단보류 가드를 피해 LLM verdict 가 흐르도록).
    item = EvidenceItem(
        item_id="DBM-101", variant="MYSQL",
        resources=[ResourceEvidence(
            resource_id="db1", status="bad", detail="d", evidence="e")],
        context="QUERY: SELECT 'NOTE: inline' FROM dual")
    profile = get_profile("db_mysql")
    ctx = JudgeContext(profile=profile, profile_key="db_mysql",
                       client=StubVuln(), items={}, variant="MYSQL")
    j = _judge_one(crit, item, ctx)
    assert j is not None
    assert j.verdict == "취약"   # StubVuln → 취약, 판단보류 아님


# ── M3. --variant 오버라이드 테스트 ─────────────────────────────────────────

def test_variant_override_success(tmp_path):
    """(a) 마커 없는 파일명 + variant_override → metadata에 지정 variant 기록."""
    criteria = str(tmp_path / "db_native.xlsx")
    _db_native_criteria_xlsx(criteria)
    # 파일명은 마커 없는 임의 이름 — variant_override로 강제 지정
    report = str(tmp_path / "unknown.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub",
        variant_override="mysql_native")

    data = json.load(open(jout, encoding="utf-8"))
    assert data["metadata"]["variant"] == "mysql_native"


def test_variant_override_invalid_raises(tmp_path):
    """(b) 유효하지 않은 variant_override → '알 수 없는 variant' ReportError."""
    criteria = str(tmp_path / "db.xlsx")
    _db_criteria_xlsx(criteria)
    report = str(tmp_path / "mysql_result_rds.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    with pytest.raises(ReportError, match="알 수 없는 variant"):
        run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub",
            variant_override="nope")


def test_no_override_unknown_filename_raises(tmp_path):
    """(c) 오버라이드 없이 마커 없는 파일명 → '--variant' 안내 ReportError."""
    criteria = str(tmp_path / "db.xlsx")
    _db_criteria_xlsx(criteria)
    # 파일명에 어떤 마커도 없는 임의 이름
    report = str(tmp_path / "unknown.txt")
    with open(FIX, encoding="utf-8") as s, open(report, "w", encoding="utf-8") as d:
        d.write(s.read())
    jout = str(tmp_path / "r.json"); xout = str(tmp_path / "r.xlsx")
    with pytest.raises(ReportError, match="--variant"):
        run(report, criteria, "db_mysql", StubVuln(), jout, xout, "stub")

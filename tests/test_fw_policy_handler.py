"""_fw_policy_handler 통합 배선 테스트 (B'-1).

parse()가 만든 context를 그대로 핸들러에 넘겨 detect_for_iss까지 이어지는
경로(특히 FW_PARSE_STATS_JSON → unrecognized_action_count 가드)를 검증한다.
실데이터 불필요 — 합성 openpyxl 픽스처만 사용.
"""
import openpyxl
import pytest

from judge_tool.main import JudgeContext, _fw_policy_handler
from judge_tool.models import Criterion, EvidenceItem
from judge_tool.parsers.fw_policy_xlsx import parse
from judge_tool.profile import get_profile


def _write_xlsx(path, sheet_name, rows):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name
    for r_idx, row in enumerate(rows, start=1):
        for c_idx, val in enumerate(row, start=1):
            ws.cell(r_idx, c_idx, val)
    wb.save(str(path))


_KRFW_HEADER = ["룰 NUM", "출발지", "목적지", "서비스", "Protocol", "inbound",
                "시간", "정책", "로그", "session-limit", "tcp", "활성화", "설명"]


def _make_crit(item_id: str) -> Criterion:
    return Criterion(
        item_id=item_id, item_name="테스트 항목", risk=None, variant="fw",
        eval_type="스크립트", standard="", method="",
        judgment_method="fw_policy", label="A",
    )


def _make_ctx() -> JudgeContext:
    profile = get_profile("iss")
    return JudgeContext(profile=profile, profile_key="iss", client=None,
                         items={}, variant="fw")


def test_handler_downgrades_to_hold_when_unrecognized_actions(tmp_path):
    """위반 0건 + 미인식 action 존재 → 핸들러 최종 verdict도 판단보류."""
    rows = [
        _KRFW_HEADER,
        ["1", "192.168.1.1", "10.0.0.1", "443", "tcp", None, None,
         "차단", "Enable", None, None, "Enable", None],
        ["2", "192.168.1.2", "10.0.0.2", "80", "tcp", None, None,
         "이상한값", "Enable", None, None, "Enable", None],
    ]
    p = str(tmp_path / "krfw_hold.xlsx")
    _write_xlsx(p, "Detail", rows)
    result = parse(p)
    context = dict((iss_id, ctx) for iss_id, _, ctx in result)["ISS-030"]

    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "판단보류"
    assert j.needs_review is True


def test_handler_stays_good_when_no_unrecognized_actions(tmp_path):
    """미인식 action이 없으면 위반 0건 시 기존처럼 양호(회귀 없음)."""
    rows = [
        _KRFW_HEADER,
        ["1", "192.168.1.1", "10.0.0.1", "443", "tcp", None, None,
         "차단", "Enable", None, None, "Enable", None],
    ]
    p = str(tmp_path / "krfw_good.xlsx")
    _write_xlsx(p, "Detail", rows)
    result = parse(p)
    context = dict((iss_id, ctx) for iss_id, _, ctx in result)["ISS-030"]

    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "양호"


def test_handler_unknown_format_no_crash_all_hold(tmp_path):
    """미지원 포맷 파일 → 크래시 없이 판단보류 (B'-1 핵심 계약)."""
    rows = [
        ["PolicyName", "Status", "Port"],
        ["r1", "active", "80"],
    ]
    p = str(tmp_path / "unknown.xlsx")
    _write_xlsx(p, "정책", rows)
    result = parse(p)
    ctx_obj = _make_ctx()
    for iss_id, _, context in result:
        crit = _make_crit(iss_id)
        item = EvidenceItem(item_id=iss_id, variant="fw", context=context)
        j = _fw_policy_handler(crit, item, ctx_obj)
        assert j is not None
        assert j.verdict == "판단보류"


# ─ C-1: sniff 인식 + 정책 0건 → 전 항목 판단보류(양호 0건) ────────────────────

def test_handler_sniffed_format_zero_policies_all_hold_no_good(tmp_path):
    """(C-1①) krfw 헤더는 인식됐지만 정책 0건 → 전 항목 판단보류, 양호 0건.

    침묵 거짓양호 봉쇄 극성 고정 테스트: fmt가 유지된 채 emit되면 capability
    있는 항목이 '위반 0건=양호'로 나가던 결함의 회귀 방지.
    """
    rows = [_KRFW_HEADER]  # 헤더만, 데이터 행 없음
    p = str(tmp_path / "krfw_headeronly.xlsx")
    _write_xlsx(p, "Detail", rows)
    result = parse(p)
    ctx_obj = _make_ctx()
    for iss_id, _, context in result:
        crit = _make_crit(iss_id)
        item = EvidenceItem(item_id=iss_id, variant="fw", context=context)
        j = _fw_policy_handler(crit, item, ctx_obj)
        assert j is not None
        assert j.verdict == "판단보류", f"{iss_id}: 양호 유출 금지"


def test_handler_title_row_krfw_detects_violation(tmp_path):
    """(C-1②) 제목행+2행 헤더 krfw 파일 → 정상 파싱·탐지(any-any → 취약)."""
    title = ["방화벽 정책 현황"] + [None] * 12
    rows = [
        title,
        _KRFW_HEADER,
        ["1", "any", "any", None, "tcp", None, None,
         "허용", "Enable", None, None, "Enable", None],
    ]
    p = str(tmp_path / "krfw_title.xlsx")
    _write_xlsx(p, "Detail", rows)
    result = parse(p)
    context = dict((iss_id, ctx) for iss_id, _, ctx in result)["ISS-030"]

    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "취약"


# ─ M-1: parse_stats 부재/손상 → fail-closed(양호 대신 판단보류) ───────────────

_POLICIES_JSON_DENY_ONLY = (
    '[{"seq":1,"rule_id":null,"enabled":true,"action":"deny","two_way":false,'
    '"src_ips":["192.168.1.1"],"dst_ips":["10.0.0.1"],"src_ports":["any"],'
    '"dst_ports":["443"],"protocols":["tcp"],"hit_count":null,"description":""}]'
)

_POLICIES_JSON_ANYANY_ALLOW = (
    '[{"seq":1,"rule_id":null,"enabled":true,"action":"allow","two_way":false,'
    '"src_ips":["any"],"dst_ips":["any"],"src_ports":["any"],'
    '"dst_ports":[],"protocols":["tcp"],"hit_count":null,"description":""}]'
)


def _context_without_stats(policies_json: str) -> str:
    return (
        "FW_FORMAT:krfw\n"
        "FW_SHEETS:Detail\n"
        "FW_POLICY_COUNT:1\n"
        f"FW_POLICIES_JSON:{policies_json}"
    )


def _context_with_corrupt_stats(policies_json: str) -> str:
    return (
        "FW_FORMAT:krfw\n"
        "FW_SHEETS:Detail\n"
        "FW_POLICY_COUNT:1\n"
        "FW_PARSE_STATS_JSON:{broken json!!\n"
        f"FW_POLICIES_JSON:{policies_json}"
    )


def test_handler_stats_line_missing_downgrades_good_to_hold():
    """(M-1) stats 라인 부재 + 위반 0건 → 양호 대신 판단보류(fail-closed)."""
    context = _context_without_stats(_POLICIES_JSON_DENY_ONLY)
    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "판단보류"
    assert "통계" in j.rationale


def test_handler_stats_line_corrupt_downgrades_good_to_hold():
    """(M-1) stats 라인 손상 + 위반 0건 → 양호 대신 판단보류(fail-closed)."""
    context = _context_with_corrupt_stats(_POLICIES_JSON_DENY_ONLY)
    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "판단보류"
    assert "통계" in j.rationale


def test_handler_stats_missing_does_not_override_violation():
    """(M-1) stats 부재라도 위반 1건 이상이면 취약 유지(가드는 양호만 강등)."""
    context = _context_without_stats(_POLICIES_JSON_ANYANY_ALLOW)
    crit = _make_crit("ISS-030")
    item = EvidenceItem(item_id="ISS-030", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "취약"


def test_handler_stats_missing_capability_hold_stays_hold():
    """(M-1) stats 부재 + capability 없는 항목(판단보류)은 그대로 판단보류."""
    context = _context_without_stats(_POLICIES_JSON_DENY_ONLY)
    crit = _make_crit("ISS-037")  # krfw는 hit-count 없음 → 원래 판단보류
    item = EvidenceItem(item_id="ISS-037", variant="fw", context=context)
    j = _fw_policy_handler(crit, item, _make_ctx())

    assert j is not None
    assert j.verdict == "판단보류"

"""fw_policy 결정론 탐지 엔진 단위 테스트 (작업②).

합성 Policy 객체 사용 — 실데이터 불필요.
탐지 함수별 양성/음성 케이스 + detect_for_iss capability 검사.
"""
import pytest

from judge_tool.fw_policy import (
    ADMIN_PORTS,
    VULN_PORTS,
    VULN_REMOTE_PORTS,
    DetectResult,
    Policy,
    _CAPABILITY,
    _FORMAT_ID70,
    _FORMAT_KRFW,
    _FORMAT_PALOALTO,
    _FORMAT_SECUI,
    _FORMAT_UNKNOWN,
    _is_any,
    _is_any_port,
    _is_broad_cidr,
    _ips_cover,
    _parse_port_range,
    _ports_intersect,
    _SENTINEL_WIDE_RANGE,
    detect_all_port_allow,
    detect_any_any_allow,
    detect_broad_cidr_port,
    detect_for_iss,
    detect_shadow_policies,
    detect_source_port_usage,
    detect_two_way,
    detect_unused_policies,
    detect_vuln_remote_service,
    policy_from_dict,
    policy_to_dict,
    resolve_policies,
    sniff_format,
)


# ─ 헬퍼 ───────────────────────────────────────────────────────────────────────

def _make(action="allow", src_ips=None, dst_ips=None, dst_ports=None,
          src_ports=None, two_way=False, hit_count=None, enabled=True,
          seq=None, rule_id=None):
    return Policy(
        seq=seq, rule_id=rule_id, enabled=enabled, action=action,
        two_way=two_way,
        src_ips=src_ips or [], dst_ips=dst_ips or [],
        src_ports=src_ports or [], dst_ports=dst_ports or [],
        protocols=[], hit_count=hit_count,
    )


# ─ sniff_format ────────────────────────────────────────────────────────────────

def test_sniff_secui_font_color():
    assert sniff_format(["Font Color:", "색", "Seq"]) == "secui"


def test_sniff_secui_seq_twoway_action():
    assert sniff_format(["Seq", "Enable", "Two-way", "ID", "Action"]) == "secui"


def test_sniff_secui_case_insensitive():
    assert sniff_format(["seq", "enable", "two-way", "action"]) == "secui"


def test_sniff_id70_priority_svcspec():
    assert sniff_format(["PRIORITY", "ENABLED", "SVC SPEC", "ACTION"]) == "id70"


def test_sniff_id70_priority_src_type():
    assert sniff_format(["PRIORITY", "SRC TYPE", "DST ADDR"]) == "id70"


def test_sniff_paloalto_hit_count():
    assert sniff_format(["Name", "Action", "Hit Count", "Zone"]) == "paloalto"


def test_sniff_paloalto_zone_application():
    assert sniff_format(["Zone", "Application", "Source"]) == "paloalto"


def test_sniff_krfw_full_headers():
    headers = ["룰 NUM", "출발지", "목적지", "서비스", "Protocol", "inbound",
               "시간", "정책", "로그", "session-limit", "tcp", "활성화", "설명"]
    assert sniff_format(headers) == "krfw"


def test_sniff_krfw_rul_token_without_policy():
    # "정책" 컬럼명이 없어도 "룰"+출발지+목적지면 krfw로 인식
    assert sniff_format(["룰 NUM", "출발지", "목적지", "기타"]) == "krfw"


def test_sniff_krfw_no_false_positive_on_secui():
    # 기존 SECUI/ID70/PaloAlto 오식별 없어야 함(회귀 방지)
    assert sniff_format(["Seq", "Enable", "Two-way", "ID", "Action"]) == "secui"
    assert sniff_format(["PRIORITY", "ENABLED", "SVC SPEC", "ACTION"]) == "id70"
    assert sniff_format(["Name", "Action", "Hit Count", "Zone"]) == "paloalto"


def test_sniff_unknown():
    assert sniff_format(["PolicyName", "Status", "Port"]) == "unknown"


def test_sniff_empty_headers():
    assert sniff_format([]) == "unknown"
    assert sniff_format([None, None]) == "unknown"


# ─ _is_any ─────────────────────────────────────────────────────────────────────

def test_is_any_variants():
    for v in ("any", "ANY", "*", "all", "0.0.0.0", "0.0.0.0/0", "::/0", ""):
        assert _is_any(v), v


def test_is_any_specific_ip_false():
    assert not _is_any("192.168.1.1")
    assert not _is_any("10.0.0.0/8")


# ─ _is_broad_cidr ──────────────────────────────────────────────────────────────

def test_is_broad_cidr_any():
    assert _is_broad_cidr("any")
    assert _is_broad_cidr("0.0.0.0/0")


def test_is_broad_cidr_slash8_boundary():
    assert _is_broad_cidr("10.0.0.0/8")   # /8 → broad
    assert not _is_broad_cidr("10.0.0.0/9")  # /9 → not broad


def test_is_broad_cidr_slash24_false():
    assert not _is_broad_cidr("192.168.1.0/24")


def test_is_broad_cidr_host_false():
    assert not _is_broad_cidr("10.1.2.3")


def test_is_broad_cidr_invalid_false():
    assert not _is_broad_cidr("not-an-ip")


# ─ _parse_port_range / _is_any_port ────────────────────────────────────────────

def test_parse_port_single():
    assert _parse_port_range("22") == {22}


def test_parse_port_range():
    assert _parse_port_range("22-23") == {22, 23}


def test_parse_port_any():
    assert _parse_port_range("any") == set()
    assert _parse_port_range("") == set()
    assert _parse_port_range("*") == set()


def test_parse_port_wide_sentinel():
    result = _parse_port_range("1-65535")
    assert _SENTINEL_WIDE_RANGE in result


def test_parse_port_id70_format():
    # "tcp 1-65535 443-443" → 마지막 토큰 "443-443" → {443}
    assert _parse_port_range("tcp 1-65535 443-443") == {443}


def test_is_any_port():
    assert _is_any_port("any")
    assert _is_any_port("")
    assert _is_any_port("1-65535")
    assert not _is_any_port("22")
    assert not _is_any_port("22-23")


# ─ _ports_intersect ───────────────────────────────────────────────────────────

def test_ports_intersect_any_vs_target():
    assert _ports_intersect(["any"], ADMIN_PORTS)


def test_ports_intersect_ssh():
    assert _ports_intersect(["22"], ADMIN_PORTS)


def test_ports_intersect_no_match():
    assert not _ports_intersect(["8888"], ADMIN_PORTS)


def test_ports_intersect_range():
    assert _ports_intersect(["20-25"], ADMIN_PORTS)  # 22 포함


def test_ports_intersect_empty():
    # dst_ports 없으면 caller가 empty 체크 후 직접 처리
    assert _ports_intersect([], ADMIN_PORTS) is False


# ─ detect_any_any_allow (ISS-030) ─────────────────────────────────────────────

def test_detect_any_any_allow_positive():
    p = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    assert detect_any_any_allow([p]) == [p]


def test_detect_any_any_allow_empty_ips():
    # src_ips/dst_ips 모두 빈 리스트도 any로 간주
    p = _make(action="allow")
    assert detect_any_any_allow([p]) == [p]


def test_detect_any_any_allow_deny():
    p = _make(action="deny", src_ips=["any"], dst_ips=["any"])
    assert detect_any_any_allow([p]) == []


def test_detect_any_any_allow_specific_dst():
    p = _make(action="allow", src_ips=["any"], dst_ips=["192.168.1.0/24"])
    assert detect_any_any_allow([p]) == []


def test_detect_any_any_allow_disabled():
    p = _make(action="allow", enabled=False)
    assert detect_any_any_allow([p]) == []


def test_detect_any_any_allow_permit():
    p = _make(action="permit")
    assert detect_any_any_allow([p]) == [p]


# ─ detect_broad_cidr_port (ISS-031, ISS-041) ──────────────────────────────────

def test_detect_broad_cidr_admin_positive():
    p = _make(action="allow", src_ips=["10.0.0.0/8"], dst_ips=["any"],
              dst_ports=["22"])
    assert detect_broad_cidr_port([p], ADMIN_PORTS) == [p]


def test_detect_broad_cidr_any_src():
    p = _make(action="allow", src_ips=["any"], dst_ports=["443"])
    assert detect_broad_cidr_port([p], ADMIN_PORTS) == [p]


def test_detect_broad_cidr_specific_ip_negative():
    p = _make(action="allow", src_ips=["192.168.1.1"], dst_ports=["22"])
    assert detect_broad_cidr_port([p], ADMIN_PORTS) == []


def test_detect_broad_cidr_non_admin_port():
    p = _make(action="allow", src_ips=["10.0.0.0/8"], dst_ports=["9999"])
    assert detect_broad_cidr_port([p], ADMIN_PORTS) == []


def test_detect_broad_cidr_vuln_ports():
    p = _make(action="allow", src_ips=["any"], dst_ports=["445"])
    assert detect_broad_cidr_port([p], VULN_PORTS) == [p]


def test_detect_broad_cidr_no_dst_ports_is_all():
    # dst_ports 없으면 전포트 허용 → ADMIN_PORTS 포함
    p = _make(action="allow", src_ips=["10.0.0.0/8"])
    assert detect_broad_cidr_port([p], ADMIN_PORTS) == [p]


# ─ detect_all_port_allow (ISS-032) ────────────────────────────────────────────

def test_detect_all_port_no_dst_ports():
    p = _make(action="allow")
    assert detect_all_port_allow([p]) == [p]


def test_detect_all_port_any_service():
    p = _make(action="allow", dst_ports=["any"])
    assert detect_all_port_allow([p]) == [p]


def test_detect_all_port_specific_port():
    p = _make(action="allow", dst_ports=["443"])
    assert detect_all_port_allow([p]) == []


def test_detect_all_port_deny():
    p = _make(action="deny")
    assert detect_all_port_allow([p]) == []


# ─ detect_two_way (ISS-033) ───────────────────────────────────────────────────

def test_detect_two_way_positive():
    p = _make(action="allow", two_way=True)
    assert detect_two_way([p]) == [p]


def test_detect_two_way_false():
    p = _make(action="allow", two_way=False)
    assert detect_two_way([p]) == []


def test_detect_two_way_deny():
    p = _make(action="deny", two_way=True)
    assert detect_two_way([p]) == []


# ─ detect_source_port_usage (ISS-035) ─────────────────────────────────────────

def test_detect_src_port_specific():
    p = _make(action="allow", src_ports=["22"])
    assert detect_source_port_usage([p]) == [p]


def test_detect_src_port_any():
    p = _make(action="allow", src_ports=["any"])
    assert detect_source_port_usage([p]) == []


def test_detect_src_port_wide_range():
    # 1-65535는 any 표기(_is_any_port) → 탐지 안 됨(ID70 SVC SPEC 관례)
    p = _make(action="allow", src_ports=["1-65535"])
    assert detect_source_port_usage([p]) == []


def test_detect_src_port_no_src_ports():
    p = _make(action="allow")
    assert detect_source_port_usage([p]) == []


def test_detect_src_port_wide_specific_range_is_violation_m3():
    """[M-3] 1024-65535처럼 any가 아닌 넓은 특정범위도 이제 위반.

    기준 원문 "출발지 포트 기반의 정책이 존재할 경우 취약"(범위 조건 없음) →
    _SENTINEL_WIDE_RANGE 제외 분기 삭제 이후 회귀 확인.
    """
    p = _make(action="allow", src_ports=["1024-65535"])
    assert detect_source_port_usage([p]) == [p]


# ─ detect_vuln_remote_service (ISS-036) ───────────────────────────────────────

def test_detect_vuln_remote_rsh():
    p = _make(action="allow", dst_ports=["514"])
    assert detect_vuln_remote_service([p]) == [p]


def test_detect_vuln_remote_tftp():
    p = _make(action="allow", dst_ports=["69"])
    assert detect_vuln_remote_service([p]) == [p]


def test_detect_vuln_remote_negative():
    p = _make(action="allow", dst_ports=["80"])
    assert detect_vuln_remote_service([p]) == []


def test_detect_vuln_remote_no_dst():
    # dst_ports 없으면 전포트 → VULN_REMOTE_PORTS 포함
    p = _make(action="allow")
    assert detect_vuln_remote_service([p]) == [p]


# ─ detect_unused_policies (ISS-037) ───────────────────────────────────────────

def test_detect_unused_hit_zero():
    p = _make(action="allow", hit_count=0)
    assert detect_unused_policies([p]) == [p]


def test_detect_unused_hit_nonzero():
    p = _make(action="allow", hit_count=100)
    assert detect_unused_policies([p]) == []


def test_detect_unused_hit_none():
    # None은 hit-count 정보 없음 → 탐지 안 됨
    p = _make(action="allow", hit_count=None)
    assert detect_unused_policies([p]) == []


def test_detect_unused_deny():
    p = _make(action="deny", hit_count=0)
    assert detect_unused_policies([p]) == []


# ─ detect_shadow_policies (ISS-034) ───────────────────────────────────────────

def test_detect_shadow_same_action_no_shadow():
    p1 = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    p2 = _make(action="allow", src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    assert detect_shadow_policies([p1, p2]) == []


def test_detect_shadow_different_action():
    # p1(allow, any→any)이 p2(deny, 10.x→192.x)를 포함 + action 다름 → 그림자
    p1 = _make(action="allow", seq=1, src_ips=["any"], dst_ips=["any"])
    p2 = _make(action="deny",  seq=2, src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    result = detect_shadow_policies([p1, p2])
    assert len(result) == 1
    assert result[0] == (p1, p2)


def test_detect_shadow_no_cover():
    # 두 정책이 서로 다른 대역 → 포함 관계 없음
    p1 = _make(action="allow", src_ips=["10.0.0.0/24"])
    p2 = _make(action="deny",  src_ips=["192.168.0.0/24"])
    assert detect_shadow_policies([p1, p2]) == []


def test_detect_shadow_disabled_excluded():
    p1 = _make(action="allow", enabled=False, src_ips=["any"], dst_ips=["any"])
    p2 = _make(action="deny",  src_ips=["10.0.0.1"])
    assert detect_shadow_policies([p1, p2]) == []


# ─ detect_for_iss — capability & 탐지 ────────────────────────────────────────

def test_detect_for_iss_030_positive():
    p = _make(action="allow")
    r = detect_for_iss("ISS-030", [p], _FORMAT_SECUI)
    assert r.can_judge is True
    assert r.verdict == "취약"
    assert r.needs_review is True
    assert len(r.violations) == 1


def test_detect_for_iss_030_negative():
    p = _make(action="deny")
    r = detect_for_iss("ISS-030", [p], _FORMAT_SECUI)
    assert r.can_judge is True
    assert r.verdict == "양호"
    assert r.violations == []
    assert r.needs_review is True


def test_detect_for_iss_037_secui_no_capability():
    p = _make(action="allow", hit_count=0)
    r = detect_for_iss("ISS-037", [p], _FORMAT_SECUI)
    assert r.can_judge is False
    assert r.verdict == "판단보류"
    assert r.violations == []
    assert r.needs_review is True


def test_detect_for_iss_037_id70_capability():
    p = _make(action="allow", hit_count=0)
    r = detect_for_iss("ISS-037", [p], _FORMAT_ID70)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_037_paloalto_capability():
    p = _make(action="allow", hit_count=0)
    r = detect_for_iss("ISS-037", [p], _FORMAT_PALOALTO)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_038_no_capability():
    r = detect_for_iss("ISS-038", [], _FORMAT_SECUI)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_039_no_capability():
    r = detect_for_iss("ISS-039", [], _FORMAT_PALOALTO)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_040_no_capability():
    r = detect_for_iss("ISS-040", [], _FORMAT_ID70)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_unknown_format():
    p = _make(action="allow")
    r = detect_for_iss("ISS-030", [p], _FORMAT_UNKNOWN)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_041_vuln_ports():
    p = _make(action="allow", src_ips=["any"], dst_ports=["445"])
    r = detect_for_iss("ISS-041", [p], _FORMAT_SECUI)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_needs_review_always():
    """verdict 무관하게 needs_review는 항상 True."""
    for iss_id in ["ISS-030", "ISS-031", "ISS-032", "ISS-033",
                   "ISS-034", "ISS-035", "ISS-036", "ISS-037",
                   "ISS-038", "ISS-039", "ISS-040", "ISS-041"]:
        r = detect_for_iss(iss_id, [], _FORMAT_PALOALTO)
        assert r.needs_review is True, f"{iss_id} needs_review should be True"


def test_detect_for_iss_empty_policies_all_good():
    """정책이 없으면 탐지 대상이 없어 양호.

    ISS-035는 B'-2로 SECUI capability=False(판단보류 강등)가 되어 이 목록에서
    제외 — 아래 test_detect_for_iss_035_secui_no_capability에서 별도 검증.
    """
    for iss_id in ["ISS-030", "ISS-031", "ISS-032", "ISS-033",
                   "ISS-036", "ISS-041"]:
        r = detect_for_iss(iss_id, [], _FORMAT_SECUI)
        assert r.verdict == "양호", f"{iss_id} with no policies should be 양호"


# ─ detect_for_iss — ISS-035 SECUI/PaloAlto capability 강등 (B'-2) ────────────
#
# SECUI 실파일 15/15에 출발지 포트 컬럼이 없음(포트 컬럼은 목적지 Service Port
# 뿐)이 확정됨 → 파서가 만들어낼 수 없는 위반을 영구 '양호'로 표기하던 거짓양호를
# 판단보류로 강등. PaloAlto도 파서가 src_ports=[](미수집)인데 capability=True라
# 동일한 영구양호 벡터였으므로 동일 강등. ID70만 SVC SPEC에서 실수집되어 True 유지.

def test_detect_for_iss_035_secui_no_capability():
    p = _make(action="allow", src_ports=["22"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_SECUI)
    assert r.can_judge is False
    assert r.verdict == "판단보류"
    assert r.violations == []
    assert "출발지 포트" in r.rationale


def test_detect_for_iss_035_secui_no_capability_even_empty_policies():
    """정책이 0건이어도(과거엔 '양호') SECUI는 capability=False라 판단보류."""
    r = detect_for_iss("ISS-035", [], _FORMAT_SECUI)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_035_paloalto_no_capability():
    p = _make(action="allow", src_ports=["22"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_PALOALTO)
    assert r.can_judge is False
    assert r.verdict == "판단보류"
    assert r.violations == []


def test_detect_for_iss_035_id70_capability_retained():
    """ID70은 SVC SPEC에서 출발지 포트가 실수집되므로 capability=True 유지."""
    p = _make(action="allow", src_ports=["22"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_ID70)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_035_id70_any_notation_not_violation():
    """ID70: src spec 1-65535(=any 표기)는 위반 아님."""
    p = _make(action="allow", src_ports=["1-65535"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_ID70)
    assert r.can_judge is True
    assert r.verdict == "양호"


def test_detect_for_iss_035_id70_wide_specific_range_violation_m3():
    """[M-3] ID70: 1024-65535(any 아닌 넓은 특정범위)는 이제 위반."""
    p = _make(action="allow", src_ports=["1024-65535"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_ID70)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_035_id70_specific_port_violation():
    """ID70: 5000 등 구체 포트 지정은 위반."""
    p = _make(action="allow", src_ports=["5000"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_ID70)
    assert r.can_judge is True
    assert r.verdict == "취약"


# ─ detect_for_iss — krfw capability (B′-1) ───────────────────────────────────

def test_detect_for_iss_033_krfw_no_capability():
    p = _make(action="allow", two_way=True)
    r = detect_for_iss("ISS-033", [p], _FORMAT_KRFW)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_035_krfw_no_capability():
    p = _make(action="allow", src_ports=["22"])
    r = detect_for_iss("ISS-035", [p], _FORMAT_KRFW)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


def test_detect_for_iss_037_krfw_no_capability():
    p = _make(action="allow", hit_count=0)
    r = detect_for_iss("ISS-037", [p], _FORMAT_KRFW)
    assert r.can_judge is False
    assert r.verdict == "판단보류"


@pytest.mark.parametrize("iss_id", ["ISS-030", "ISS-031", "ISS-032", "ISS-034",
                                     "ISS-036", "ISS-041"])
def test_detect_for_iss_krfw_capability_good(iss_id):
    """krfw 포맷에서 양호 샘플 → 양호(극성 커버리지: good)."""
    p = _make(action="deny", src_ips=["192.168.1.1"], dst_ips=["10.0.0.1"],
              dst_ports=["443"])
    r = detect_for_iss(iss_id, [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "양호"


def test_detect_for_iss_030_krfw_vuln():
    p = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_031_krfw_vuln():
    p = _make(action="allow", src_ips=["any"], dst_ports=["22"])
    r = detect_for_iss("ISS-031", [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_032_krfw_vuln():
    p = _make(action="allow")
    r = detect_for_iss("ISS-032", [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_036_krfw_vuln():
    p = _make(action="allow", dst_ports=["69"])
    r = detect_for_iss("ISS-036", [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_041_krfw_vuln():
    p = _make(action="allow", src_ips=["any"], dst_ports=["445"])
    r = detect_for_iss("ISS-041", [p], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


def test_detect_for_iss_034_krfw_vuln():
    p1 = _make(action="allow", seq=1, src_ips=["any"], dst_ips=["any"])
    p2 = _make(action="deny", seq=2, src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    r = detect_for_iss("ISS-034", [p1, p2], _FORMAT_KRFW)
    assert r.can_judge is True
    assert r.verdict == "취약"


# ─ detect_for_iss — 미인식 action 거짓양호 봉쇄 가드 ─────────────────────────

def test_detect_for_iss_guard_downgrades_good_to_hold_when_unrecognized_actions():
    """위반 0건인데 파일 내 미인식 action이 있으면 양호가 아니라 판단보류."""
    p = _make(action="deny")  # 위반 0건 → 원래는 양호
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW, unrecognized_action_count=3)
    assert r.can_judge is True
    assert r.verdict == "판단보류"
    assert "미인식" in r.rationale


def test_detect_for_iss_guard_no_effect_when_no_unrecognized_actions():
    """미인식 action이 0건이면 기존처럼 양호 유지(회귀 없음)."""
    p = _make(action="deny")
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW, unrecognized_action_count=0)
    assert r.verdict == "양호"


def test_detect_for_iss_guard_does_not_override_violation():
    """위반이 이미 1건 이상이면 미인식 action이 있어도 취약 유지."""
    p = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW, unrecognized_action_count=5)
    assert r.verdict == "취약"


def test_detect_for_iss_guard_default_param_backward_compatible():
    """unrecognized_action_count 인자를 넘기지 않는 기존 호출부는 그대로 동작."""
    p = _make(action="deny")
    r = detect_for_iss("ISS-030", [p], _FORMAT_SECUI)
    assert r.verdict == "양호"


# ─ policy_to_dict / policy_from_dict 왕복 직렬화 ─────────────────────────────

def test_policy_roundtrip():
    p = Policy(
        seq=1, rule_id="R001", enabled=True, action="allow", two_way=True,
        src_ips=["any"], dst_ips=["10.0.0.0/8"],
        src_ports=["any"], dst_ports=["22", "443"],
        protocols=["tcp"], hit_count=42, description="test",
    )
    d = policy_to_dict(p)
    p2 = policy_from_dict(d)
    assert p2.seq == p.seq
    assert p2.rule_id == p.rule_id
    assert p2.enabled == p.enabled
    assert p2.action == p.action
    assert p2.two_way == p.two_way
    assert p2.src_ips == p.src_ips
    assert p2.dst_ips == p.dst_ips
    assert p2.src_ports == p.src_ports
    assert p2.dst_ports == p.dst_ports
    assert p2.protocols == p.protocols
    assert p2.hit_count == p.hit_count


def test_policy_from_dict_defaults():
    p = policy_from_dict({})
    assert p.seq is None
    assert p.enabled is True
    assert p.action == ""
    assert p.src_ips == []
    assert p.hit_count is None


def test_policy_unresolved_fields_default_empty():
    p = _make(action="allow")
    assert p.unresolved_src == []
    assert p.unresolved_dst == []
    assert p.unresolved_svc == []


# ─ resolve_policies (B′-3a) — named 객체 토큰 분류 ────────────────────────────

def test_resolve_policies_named_dst_moves_to_unresolved():
    """(a) named 객체 토큰(그룹명) dst → unresolved_dst로 분류, dst_ips에서 제거."""
    p = _make(action="allow", src_ips=["10.0.0.1"], dst_ips=["WEB_SERVERS_GRP"])
    result = resolve_policies([p])
    assert result[0].dst_ips == []
    assert result[0].unresolved_dst == ["WEB_SERVERS_GRP"]


def test_resolve_policies_named_src_moves_to_unresolved():
    p = _make(action="allow", src_ips=["ADMIN_GRP"], dst_ips=["any"])
    resolve_policies([p])
    assert p.src_ips == []
    assert p.unresolved_src == ["ADMIN_GRP"]


def test_resolve_policies_ip_and_cidr_kept():
    p = _make(action="allow", src_ips=["10.0.0.1", "192.168.1.0/24", "any"],
               dst_ips=["0.0.0.0/0"])
    resolve_policies([p])
    assert p.src_ips == ["10.0.0.1", "192.168.1.0/24", "any"]
    assert p.unresolved_src == []
    assert p.dst_ips == ["0.0.0.0/0"]
    assert p.unresolved_dst == []


def test_resolve_policies_named_svc_from_dst_ports():
    p = _make(action="allow", dst_ports=["HTTP_SVC_GRP"])
    resolve_policies([p])
    assert p.dst_ports == []
    assert p.unresolved_svc == ["HTTP_SVC_GRP"]


def test_resolve_policies_numeric_port_kept():
    p = _make(action="allow", dst_ports=["22", "1-65535", "any"])
    resolve_policies([p])
    assert p.dst_ports == ["22", "1-65535", "any"]
    assert p.unresolved_svc == []


def test_resolve_policies_known_protocol_kept():
    p = Policy(seq=1, rule_id=None, action="allow", protocols=["tcp", "udp", "ANY"])
    resolve_policies([p])
    assert p.protocols == ["tcp", "udp", "ANY"]
    assert p.unresolved_svc == []


def test_resolve_policies_unknown_protocol_token_moves_to_unresolved_svc():
    p = Policy(seq=1, rule_id=None, action="allow", protocols=["CUSTOM_SVC_OBJ"])
    resolve_policies([p])
    assert p.protocols == []
    assert p.unresolved_svc == ["CUSTOM_SVC_OBJ"]


def test_resolve_policies_table_none_only_classifies():
    """table=None(현재 유일 지원)이면 치환 없이 분류만 수행."""
    p = _make(action="allow", dst_ips=["DB_GRP"])
    resolve_policies([p], table=None)
    assert p.dst_ips == []
    assert p.unresolved_dst == ["DB_GRP"]


def test_resolve_policies_returns_same_list():
    p = _make(action="allow")
    result = resolve_policies([p])
    assert result == [p]


# ─ detect_for_iss — 미해석 객체 토큰 거짓양호 봉쇄 가드 (B′-3a §B-1 규칙3) ────

def test_detect_for_iss_030_unresolved_and_no_violation_downgrades_to_hold():
    """(b) 030: unresolved 존재 + 위반 0 → 판단보류, rationale에 명시 문구."""
    p = _make(action="deny", src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    p.unresolved_dst = ["WEB_GRP"]
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale


def test_detect_for_iss_032_unresolved_svc_and_no_violation_downgrades_to_hold():
    """(b) 032: unresolved_svc 존재 + 위반 0 → 판단보류."""
    p = _make(action="allow", dst_ports=["443"])
    p.unresolved_svc = ["HTTP_SVC_GRP"]
    r = detect_for_iss("ISS-032", [p], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale


def test_detect_for_iss_030_unresolved_but_violation_exists_stays_vulnerable():
    """(c) 위반≥1 + unresolved → 취약 유지 + rationale에 미해석 건수 부기."""
    p = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    p.unresolved_dst = ["WEB_GRP"]
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.verdict == "취약"
    assert "미해석 객체 토큰 보유 정책 1건 존재" in r.rationale


def test_detect_for_iss_036_unresolved_but_violation_exists_stays_vulnerable():
    p = _make(action="allow", dst_ports=["69"])
    p.unresolved_svc = ["SVC_GRP"]
    r = detect_for_iss("ISS-036", [p], _FORMAT_KRFW)
    assert r.verdict == "취약"
    assert "미해석 객체 토큰 보유 정책 1건 존재" in r.rationale


def test_detect_for_iss_no_unresolved_verdict_unchanged_positive():
    """(d) unresolved 없음 → 기존 판정 불변(양극성 회귀: 취약 유지)."""
    p = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.verdict == "취약"
    assert "미해석" not in r.rationale


def test_detect_for_iss_no_unresolved_verdict_unchanged_negative():
    """(d) unresolved 없음 → 기존 판정 불변(양극성 회귀: 양호 유지)."""
    p = _make(action="deny", src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.verdict == "양호"
    assert "미해석" not in r.rationale


@pytest.mark.parametrize("iss_id,field", [
    ("ISS-033", "unresolved_src"),
    ("ISS-035", "unresolved_src"),
    ("ISS-037", "unresolved_svc"),
])
def test_detect_for_iss_guard_no_effect_on_unrelated_items(iss_id, field):
    """(e) 033/035/037은 unresolved 토큰이 있어도 가드 무영향(capability로만 결정)."""
    p = _make(action="allow", hit_count=100)
    setattr(p, field, ["SOME_GRP"])
    r = detect_for_iss(iss_id, [p], _FORMAT_ID70)
    assert r.verdict == "양호"
    assert "미해석" not in r.rationale


def test_detect_for_iss_guard_disabled_policy_unresolved_no_effect():
    """(g) disabled 정책의 unresolved는 가드 미발동(위반도 없으니 양호 유지)."""
    p_disabled = _make(action="deny", enabled=False)
    p_disabled.unresolved_dst = ["WEB_GRP"]
    p_active = _make(action="deny", src_ips=["10.0.0.1"], dst_ips=["192.168.1.1"])
    r = detect_for_iss("ISS-030", [p_disabled, p_active], _FORMAT_KRFW)
    assert r.verdict == "양호"
    assert "미해석" not in r.rationale


def test_detect_for_iss_unresolved_guard_independent_of_unrecognized_action_guard():
    """두 가드가 각각 독립적으로 판단보류를 만들고 함께 있으면 둘 다 명시."""
    p = _make(action="deny")
    p.unresolved_dst = ["WEB_GRP"]
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW, unrecognized_action_count=2)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale
    assert "미인식 정책 액션 2건 → 양호 단정 불가" in r.rationale


# ─ Opus 리뷰 재현 4케이스 (B′-3a-fix): 빈 리스트=any 오분류 → 판단보류 귀속 ───
#
# resolve_policies가 named 토큰을 빼내 src_ips/dst_ips/dst_ports가 비면, 기존
# 탐지함수의 "빈 리스트=전체(any/all)" 관례가 그 정책을 가짜 위반(취약)으로
# 집계해버려 "위반0→판단보류" 가드를 건너뛰던 버그. 미해석 유래 빈 필드는
# any가 아니라 불확정이므로 위반판정에서 제외되고 판단보류 가드로 귀속돼야 한다.

def test_detect_for_iss_030_both_sides_named_only_not_any_any_violation():
    """재현①: src/dst 모두 named 객체만 있어 빈 리스트가 됐을 뿐인데 기존
    관례가 '전체(any-any)' 위반으로 오탐지 → 판단보류가 되어야 한다."""
    p = _make(action="allow")
    p.unresolved_src = ["SRC_GRP"]
    p.unresolved_dst = ["DST_GRP"]
    r = detect_for_iss("ISS-030", [p], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale
    # 진짜 any-any(반대극)는 여전히 취약 유지 — 양극성 회귀 가드.
    p_real_any = _make(action="allow", src_ips=["any"], dst_ips=["any"])
    r_real = detect_for_iss("ISS-030", [p_real_any], _FORMAT_KRFW)
    assert r_real.verdict == "취약"


def test_detect_for_iss_032_named_svc_only_not_all_port_violation():
    """재현②: dst_ports가 named 서비스객체만 있어 비었을 뿐인데 '전포트 허용'
    으로 오탐지 → 판단보류가 되어야 한다."""
    p = _make(action="allow")
    p.unresolved_svc = ["SVC_GRP"]
    r = detect_for_iss("ISS-032", [p], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale
    # 반대극(진짜 ALL 포트)은 여전히 취약 유지.
    p_real_all = _make(action="allow", dst_ports=["any"])
    r_real = detect_for_iss("ISS-032", [p_real_all], _FORMAT_KRFW)
    assert r_real.verdict == "취약"


def test_detect_for_iss_036_named_svc_only_not_vuln_remote_violation():
    """재현③: dst_ports가 named 서비스객체만 있어 비었을 뿐인데 취약 원격
    서비스(r-services/TFTP) 허용으로 오탐지 → 판단보류가 되어야 한다."""
    p = _make(action="allow")
    p.unresolved_svc = ["SVC_GRP"]
    r = detect_for_iss("ISS-036", [p], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale
    # 반대극(진짜 취약 원격포트 허용)은 여전히 취약 유지.
    p_real_vuln = _make(action="allow", dst_ports=["69"])
    r_real = detect_for_iss("ISS-036", [p_real_vuln], _FORMAT_KRFW)
    assert r_real.verdict == "취약"


def test_detect_for_iss_034_upper_named_src_only_not_shadow_violation():
    """재현④: 상위 정책의 src가 named 객체만 있어 빈 리스트가 됐을 뿐인데
    '상위가 전체를 포함'으로 오탐지 → 그림자쌍 제외 + 판단보류가 되어야 한다."""
    upper = _make(action="allow", dst_ips=["0.0.0.0/0"], seq=1)
    upper.unresolved_src = ["SRC_GRP"]
    lower = _make(action="deny", src_ips=["10.0.0.5"], dst_ips=["10.0.0.5"], seq=2)
    r = detect_for_iss("ISS-034", [upper, lower], _FORMAT_KRFW)
    assert r.verdict == "판단보류"
    assert "미해석 객체 토큰 보유 정책 1건 → 양호 단정 불가" in r.rationale
    # 반대극(진짜 상위가 전체 포함 + action 상이)은 여전히 그림자 취약 유지.
    upper_real = _make(action="allow", src_ips=["any"], dst_ips=["any"], seq=1)
    lower_real = _make(
        action="deny", src_ips=["10.0.0.5"], dst_ips=["10.0.0.5"], seq=2
    )
    r_real = detect_for_iss("ISS-034", [upper_real, lower_real], _FORMAT_KRFW)
    assert r_real.verdict == "취약"


# ─ policy_to_dict / policy_from_dict — unresolved 필드 왕복 (B′-3a) ──────────

def test_policy_roundtrip_unresolved_fields():
    """(f) 직렬화 왕복: unresolved_src/dst/svc 보존."""
    p = Policy(
        seq=1, rule_id="R001", enabled=True, action="allow",
        src_ips=["10.0.0.1"], dst_ips=["any"],
        unresolved_src=["ADMIN_GRP"], unresolved_dst=["WEB_GRP"],
        unresolved_svc=["HTTP_SVC_GRP"],
    )
    d = policy_to_dict(p)
    p2 = policy_from_dict(d)
    assert p2.unresolved_src == p.unresolved_src
    assert p2.unresolved_dst == p.unresolved_dst
    assert p2.unresolved_svc == p.unresolved_svc


def test_policy_from_dict_unresolved_fields_backward_compatible():
    """기존(신규 필드 도입 이전) 직렬 데이터 로드 시 KeyError 없이 빈 리스트."""
    legacy_dict = {
        "seq": 1, "rule_id": "R001", "enabled": True, "action": "allow",
        "two_way": False, "src_ips": ["any"], "dst_ips": ["any"],
        "src_ports": [], "dst_ports": [], "protocols": [],
        "hit_count": None, "description": "",
    }
    p = policy_from_dict(legacy_dict)
    assert p.unresolved_src == []
    assert p.unresolved_dst == []
    assert p.unresolved_svc == []

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
    # 1-65535는 광범위 → sentinel → 탐지 안 됨
    p = _make(action="allow", src_ports=["1-65535"])
    assert detect_source_port_usage([p]) == []


def test_detect_src_port_no_src_ports():
    p = _make(action="allow")
    assert detect_source_port_usage([p]) == []


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
    """정책이 없으면 탐지 대상이 없어 양호."""
    for iss_id in ["ISS-030", "ISS-031", "ISS-032", "ISS-033",
                   "ISS-035", "ISS-036", "ISS-041"]:
        r = detect_for_iss(iss_id, [], _FORMAT_SECUI)
        assert r.verdict == "양호", f"{iss_id} with no policies should be 양호"


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

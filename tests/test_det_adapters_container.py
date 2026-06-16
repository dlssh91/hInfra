"""컨테이너(PRCC) 결정론 어댑터 단위 테스트 (Phase 2).

검증 항목:
  (a) 어댑터 기본 매핑: result 'N'→양호, 'Y'→취약+citations, 'M'→handled=False
  (b) R1 디폴트-N 거짓양호 방어: 빈 출력 → 증거 부재 → handled=False
  (c) 증거 부재 가드: 수집 흔적 없는 출력 → handled=False
  (d) DET_SOURCE gate: MANUAL/ABSENT variant → handled=False (C1 불변)
  (e) citation: point 문자열 분할 확인, raw_output 누출 없음 (§7)
  (f) 실 PRCC-001 취약/양호 매핑
  (g) DET-PARTIAL(PRCC-039): docker_linux=DET 통과, k8s_master=MANUAL gate차단
"""
import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.container  # noqa: F401,E402 — 등록 부작용
from judge_tool.det_adapters.container import judge, _has_collection_evidence  # noqa: E402
from judge_tool.det_adapters.base import ForcedVerdict  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# 수집 증거 패턴 헬퍼 테스트
# ─────────────────────────────────────────────────────────────────────────────

class TestHasCollectionEvidence:
    """_has_collection_evidence 패턴 검증."""

    def test_empty_is_no_evidence(self):
        assert _has_collection_evidence("") is False
        assert _has_collection_evidence("   ") is False
        assert _has_collection_evidence("\n\n") is False

    def test_f_prc_c_header(self):
        raw = "F_PRC_C_001 : k8s_master\n---\n"
        assert _has_collection_evidence(raw) is True

    def test_command_token(self):
        raw = "# Command : kubectl get clusterrolebindings\nsome output"
        assert _has_collection_evidence(raw) is True

    def test_kubectl_token(self):
        raw = "kubectl get nodes\nsome output"
        assert _has_collection_evidence(raw) is True

    def test_docker_token(self):
        raw = "docker inspect container1\nsome output"
        assert _has_collection_evidence(raw) is True

    def test_flag_marker(self):
        raw = "flag: [X]\nsome data"
        assert _has_collection_evidence(raw) is True

    def test_separator_line(self):
        raw = "some content\n-------------------------\nmore"
        assert _has_collection_evidence(raw) is True

    def test_no_result_alone_is_not_evidence(self):
        """No result만 있는 출력은 증거 흔적 없음 → False."""
        raw = "No result\n"
        assert _has_collection_evidence(raw) is False

    def test_no_result_with_command_is_evidence(self):
        """No result이 있어도 # Command 흔적 있으면 수집 실행됨 → True."""
        raw = "# Command : kubectl get ...\nNo result\n"
        assert _has_collection_evidence(raw) is True

    def test_not_exist_marker(self):
        """[not exist] 마커 있으면 증거 있음(PRCC-036 등 존재확인 결과)."""
        raw = "CRI Socket 확인:\n[not exist]\n"
        assert _has_collection_evidence(raw) is True

    def test_hash_separator(self):
        """### 구분자 있으면 증거 있음."""
        raw = "some output\n###결과###\n"
        assert _has_collection_evidence(raw) is True


# ─────────────────────────────────────────────────────────────────────────────
# C1: gate 차단 — DET_SOURCE 미등재 또는 MANUAL variant
# ─────────────────────────────────────────────────────────────────────────────

class TestGateBlock:
    """C1 불변: MANUAL/ABSENT variant → handled=False."""

    def test_absent_item_handled_false(self):
        """DET_SOURCE에 없는 항목 → ABSENT → gate 차단."""
        raw = "# Command : kubectl get something\nsome output\n"
        fv = judge("PRCC-999", raw, "k8s_master", {})
        assert fv.handled is False, f"ABSENT 항목이 handled=True: {fv}"
        assert fv.verdict != "양호", f"ABSENT 항목이 양호로 판정: {fv}"

    def test_manual_variant_handled_false(self):
        """PRCC-039 k8s_master=MANUAL → gate 차단."""
        raw = "# Command : kubectl get pods\nHostConfig.Devices: [/dev/sda]\n"
        fv = judge("PRCC-039", raw, "k8s_master", {})
        assert fv.handled is False, (
            f"PRCC-039 k8s_master(MANUAL)이 handled=True — gate 미작동: {fv}"
        )

    def test_det_partial_manual_variant_blocked(self):
        """PRCC-004 k8s_master=MANUAL → gate 차단."""
        raw = "# Command : kubectl get apiserver\nsome output\n"
        fv = judge("PRCC-004", raw, "k8s_master", {})
        assert fv.handled is False

    def test_worker_not_in_det_source_blocked(self):
        """PRCC-001 k8s_worker는 DET_SOURCE 미기재 → ABSENT → gate 차단."""
        raw = "# Command : kubectl ...\nROLE: cluster-admin\n"
        fv = judge("PRCC-001", raw, "k8s_worker", {})
        assert fv.handled is False

    def test_det_variant_passes_gate(self):
        """PRCC-001 k8s_master=DET → gate 통과(증거 있으면 결정론 진행)."""
        raw = "# Command : kubectl get clusterrolebindings\nROLE: cluster-admin\n"
        fv = judge("PRCC-001", raw, "k8s_master", {})
        # gate 통과 확인: handled는 True(취약) 또는 True(양호) 여야 함
        assert fv.handled is True, f"DET 항목 gate가 차단됨: {fv}"


# ─────────────────────────────────────────────────────────────────────────────
# R1 거짓양호 방어 — 빈 출력/증거 부재
# ─────────────────────────────────────────────────────────────────────────────

class TestR1FalseNegativeGuard:
    """R1: 디폴트-N 거짓양호 방어."""

    def test_empty_output_handled_false(self):
        """빈 출력 → 증거 부재 → handled=False (autoAnalysis 디폴트 N 차단)."""
        fv = judge("PRCC-001", "", "k8s_master", {})
        assert fv.handled is False, (
            f"빈 출력이 양호로 판정됨 — R1 거짓양호 (디폴트-N): {fv}"
        )
        assert fv.verdict != "양호"

    def test_whitespace_only_handled_false(self):
        """공백만 있는 출력 → 증거 부재 → handled=False."""
        fv = judge("PRCC-001", "   \n\n  ", "k8s_master", {})
        assert fv.handled is False

    def test_no_collection_pattern_handled_false(self):
        """수집 흔적 없는 출력(No result만) → 증거 부재 → handled=False."""
        fv = judge("PRCC-001", "No result\n", "k8s_master", {})
        assert fv.handled is False

    def test_det_item_with_evidence_not_blocked(self):
        """수집 흔적 있는 출력 → 증거 있음 → 결정론 진행(handled=True 가능)."""
        raw = "# Command : kubectl ...\nROLE: cluster-admin\n"
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert fv.handled is True


# ─────────────────────────────────────────────────────────────────────────────
# (a) 기본 매핑: PRCC-001 N→양호, Y→취약
# ─────────────────────────────────────────────────────────────────────────────

class TestPRCC001Mapping:
    """PRCC-001: cluster-admin 역할 — 결정론 매핑."""

    def _raw_good(self):
        """cluster-admin 없음 → N(양호)."""
        return (
            "F_PRC_C_001 : k8s_master\n"
            "# Command : kubectl get clusterrolebindings\n"
            "관리자 역할이 부여된 롤 바인딩:\n"
            "Cluster Role Name: some-other-role\n"
            "ROLE: view\n"
        )

    def _raw_vuln(self):
        """cluster-admin 있음 → Y(취약)."""
        return (
            "F_PRC_C_001 : k8s_master\n"
            "# Command : kubectl get clusterrolebindings\n"
            "관리자 역할이 부여된 롤 바인딩:\n"
            "Cluster Role Name: cluster-admin\n"
            "ROLE: cluster-admin\n"
            "Kind: Group\n"
        )

    def test_good_verdict(self):
        fv = judge("PRCC-001", self._raw_good(), "k8s_master", {})
        assert fv.handled is True
        assert fv.verdict == "양호"
        assert fv.ev_status == "good"
        assert fv.confidence == 0.9

    def test_vuln_verdict(self):
        fv = judge("PRCC-001", self._raw_vuln(), "k8s_master", {})
        assert fv.handled is True
        assert fv.verdict == "취약"
        assert fv.ev_status == "bad"
        assert fv.confidence == 0.9

    def test_vuln_has_citations(self):
        fv = judge("PRCC-001", self._raw_vuln(), "k8s_master", {})
        # citations는 point 문자열에서 추출 — "cluster-admin이 부여된 role 존재"
        assert len(fv.citations) >= 1
        assert any("cluster-admin" in c for c in fv.citations)

    def test_citations_no_raw_leak(self):
        """§7 누출 경계: raw_output 전문이 citations/rationale에 포함되지 않음."""
        raw = self._raw_vuln()
        fv = judge("PRCC-001", raw, "k8s_master", {})
        # citations는 point 문자열(짧음)이어야 함, raw 전체 아님
        for c in fv.citations:
            assert len(c) < 500, f"citation이 지나치게 길다(raw 누출 의심): {c!r:.100}"
        # rationale도 raw 전체 아님
        assert raw not in fv.rationale, "raw_output 전문이 rationale에 포함됨 — §7 위반"


# ─────────────────────────────────────────────────────────────────────────────
# (a) result='M' → handled=False
# ─────────────────────────────────────────────────────────────────────────────

class TestManualResult:
    """result='M' 반환 → handled=False."""

    def test_prcc004_ocp_no_token_file_returns_n(self):
        """PRCC-004 ocp_master: --token-auth-file 없음 → N(양호) → handled=True."""
        raw = (
            "F_PRC_C_004 : ocp_master\n"
            "# Command : ...\n"
            "some output without token-auth-file\n"
        )
        fv = judge("PRCC-004", raw, "ocp_master", {})
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_prcc039_docker_no_devices_returns_n(self):
        """PRCC-039 docker_linux: HostConfig.Devices 없음 → N → handled=True."""
        raw = (
            "F_PRC_C_039 : docker\n"
            "# Command : docker inspect ...\n"
            " .HostConfig.Devices: []\n"
        )
        fv = judge("PRCC-039", raw, "docker_linux", {})
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_prcc039_docker_with_devices_returns_y(self):
        """PRCC-039 docker_linux: HostConfig.Devices 있음 → Y → handled=True."""
        raw = (
            "F_PRC_C_039 : docker\n"
            "# Command : docker inspect ...\n"
            " .HostConfig.Devices: [/dev/sda]\n"
        )
        fv = judge("PRCC-039", raw, "docker_linux", {})
        assert fv.handled is True
        assert fv.verdict == "취약"


# ─────────────────────────────────────────────────────────────────────────────
# (g) DET-PARTIAL: PRCC-039 gate 분기
# ─────────────────────────────────────────────────────────────────────────────

class TestDETPartialGate:
    """DET-PARTIAL 항목의 variant별 gate 자동 분기."""

    def test_prcc039_k8s_master_blocked(self):
        """PRCC-039 k8s_master=MANUAL → gate 차단."""
        raw = "# Command : kubectl ...\n.HostConfig.Devices: [/dev/sda]\n"
        fv = judge("PRCC-039", raw, "k8s_master", {})
        assert fv.handled is False

    def test_prcc039_docker_linux_passes(self):
        """PRCC-039 docker_linux=DET → gate 통과."""
        raw = (
            "F_PRC_C_039 : docker\n"
            "# Command : docker inspect ...\n"
            " .HostConfig.Devices: [/dev/sda]\n"
        )
        fv = judge("PRCC-039", raw, "docker_linux", {})
        assert fv.handled is True

    def test_prcc036_k8s_master_passes(self):
        """PRCC-036 k8s_master=DET → gate 통과."""
        raw = (
            "F_PRC_C_036 : k8s_master\n"
            "# Command : kubectl ...\n"
            "docker.sock이 마운트된 컨테이너\n"
        )
        fv = judge("PRCC-036", raw, "k8s_master", {})
        assert fv.handled is True

    def test_prcc036_ocp_master_blocked(self):
        """PRCC-036 ocp_master=MANUAL → gate 차단."""
        raw = "# Command : kubectl ...\nsome sock output\n"
        fv = judge("PRCC-036", raw, "ocp_master", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (e) citation 분할 + 누출 경계
# ─────────────────────────────────────────────────────────────────────────────

class TestCitationsFromPoint:
    """point 문자열 분할 및 §7 누출 경계."""

    def test_citations_split_from_comma(self):
        """point = 'a,b,c' → citations = ['a','b','c']."""
        from judge_tool.det_adapters.container import _citations_from_point
        assert _citations_from_point("a,b,c") == ["a", "b", "c"]

    def test_citations_empty_strip(self):
        """빈 요소 제거."""
        from judge_tool.det_adapters.container import _citations_from_point
        assert _citations_from_point("a,,b,") == ["a", "b"]

    def test_citations_max_20(self):
        """최대 20개 제한."""
        from judge_tool.det_adapters.container import _citations_from_point
        long_point = ",".join(f"item{i}" for i in range(30))
        assert len(_citations_from_point(long_point)) == 20

    def test_citations_empty_point(self):
        from judge_tool.det_adapters.container import _citations_from_point
        assert _citations_from_point("") == []
        assert _citations_from_point(None) == []


# ─────────────────────────────────────────────────────────────────────────────
# 레지스트리 등록 확인
# ─────────────────────────────────────────────────────────────────────────────

def test_registry_container_registered():
    """_DET_ADAPTERS["container"] 가 등록되어 있음."""
    from judge_tool.det_adapters.base import _DET_ADAPTERS
    assert "container" in _DET_ADAPTERS
    assert callable(_DET_ADAPTERS["container"])

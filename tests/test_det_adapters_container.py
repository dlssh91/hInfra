"""컨테이너(PRCC) 결정론 어댑터 단위 테스트 (Phase 2).

검증 항목:
  (a) 어댑터 기본 매핑: result 'N'→양호, 'Y'→취약+citations, 'M'→handled=False
  (b) R1 디폴트-N 거짓양호 방어: 빈 출력 → 증거 부재 → handled=False
  (c) 증거 부재 가드: 수집 흔적 없는 출력 → handled=False
  (d) DET_SOURCE gate: MANUAL/ABSENT variant → handled=False (C1 불변)
  (e) citation: point 문자열 분할 확인, raw_output 누출 없음 (§7)
  (f) 실 PRCC-001 취약/양호 매핑
  (g) DET-PARTIAL(PRCC-039): docker_linux=DET 통과, k8s_master=MANUAL gate차단
  (h) F8 오류출력 가드: 명령은 찍혔지만 실패한 출력 → handled=False(거짓양호 차단)
      + 과트리거 0 검증(collected/container 실샘플 corpus)
"""
from pathlib import Path

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


# ─────────────────────────────────────────────────────────────────────────────
# (h) F8 오류출력 가드 — 명령은 찍혔지만 실패한 출력 → handled=False
#     (2026-07-03-falsegood-audit.md §1 F8 + §2 F8)
# ─────────────────────────────────────────────────────────────────────────────

# 실제 kubectl/docker/셸 오류 출력 대표 케이스 (토큰별 1개 이상)
_ERROR_OUTPUT_CASES = [
    # (case_id, 오류 라인)
    ("error_anchor",
     "error: You must be logged in to the server (Unauthorized)"),
    ("error_from_server",
     'Error from server (Forbidden): pods is forbidden: '
     'User "system:anonymous" cannot list resource "pods"'),
    ("unable_to_connect",
     "Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout"),
    ("command_not_found",
     "bash: kubectl: command not found"),
    ("permission_denied_upper",
     "cat: /etc/kubernetes/manifests/kube-apiserver.yaml: Permission denied"),
    ("permission_denied_lower",
     "docker: permission denied while trying to connect to the Docker daemon socket"),
    ("unauthorized",
     "The server returned: Unauthorized"),
    ("forbidden",
     "response status: Forbidden"),
    ("connection_refused",
     "dial tcp 127.0.0.1:6443: connect: connection refused"),
    ("no_such_file",
     "ls: cannot access '/etc/kubernetes/pki': No such file or directory"),
]


def _raw_with_error(error_line):
    """수집 명령 흔적(# Command)은 있으나 실행이 실패한 출력."""
    return (
        "F_PRC_C_001 : k8s_master\n"
        "# Command : kubectl get clusterrolebindings -o json\n"
        f"{error_line}\n"
    )


class TestErrorOutputGuard:
    """F8: 오류출력 정규식 가드 — 매치 시 handled=False(판단보류 폴백)."""

    def test_brief_case_error_unauthorized(self):
        """브리프 (a): # Command + error: Unauthorized → handled=False."""
        raw = _raw_with_error("error: Unauthorized")
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert fv.handled is False, (
            f"오류출력이 autoAnalysis로 내려가 판정됨 — F8 거짓양호: {fv}"
        )
        assert fv.verdict == "판단보류"
        assert fv.ev_status == "review"
        assert "오류 출력" in fv.rationale
        assert "PRCC-001" in fv.rationale and "k8s_master" in fv.rationale

    @pytest.mark.parametrize(
        "case_id,error_line",
        _ERROR_OUTPUT_CASES,
        ids=[c[0] for c in _ERROR_OUTPUT_CASES],
    )
    def test_error_tokens_handled_false(self, case_id, error_line):
        """브리프 (b): 토큰별 대표 오류 출력 → handled=False."""
        fv = judge("PRCC-001", _raw_with_error(error_line), "k8s_master", {})
        assert fv.handled is False, (
            f"[{case_id}] 오류출력 가드 미발동 — F8 거짓양호: {fv}"
        )
        assert fv.verdict == "판단보류"

    def test_error_guard_no_raw_leak(self):
        """§7: rationale에 매치토큰(짧음)만 — raw 전문 미포함."""
        raw = _raw_with_error("error: Unauthorized")
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert raw not in fv.rationale
        assert fv.citations == []

    def test_normal_good_output_unaffected(self):
        """브리프 (c): 정상 수집 출력 → 가드 미발동, 기존 양호 판정 불변."""
        raw = (
            "F_PRC_C_001 : k8s_master\n"
            "# Command : kubectl get clusterrolebindings\n"
            "관리자 역할이 부여된 롤 바인딩:\n"
            "Cluster Role Name: some-other-role\n"
            "ROLE: view\n"
        )
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_normal_vuln_output_unaffected(self):
        """브리프 (c): 정상 취약 출력 → 가드 미발동, 기존 취약 판정 불변."""
        raw = (
            "F_PRC_C_001 : k8s_master\n"
            "# Command : kubectl get clusterrolebindings\n"
            "Cluster Role Name: cluster-admin\n"
            "ROLE: cluster-admin\n"
            "Kind: Group\n"
        )
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert fv.handled is True
        assert fv.verdict == "취약"

    def test_no_result_is_not_error(self):
        """브리프 (d): 'No result'는 오류가 아님(PRCC-018 취약 증거 의미 유지).

        # Command + No result 출력은 오류 가드에 매치되지 않고
        기존 autoAnalysis 경로로 내려가야 한다.
        """
        from judge_tool.det_adapters.container import _RE_ERROR_OUTPUT
        raw = "# Command : kubectl get ...\nNo result\n"
        assert _RE_ERROR_OUTPUT.search(raw) is None, (
            "'No result'가 오류 토큰에 매치됨 — PRCC-018 취약 증거 의미 훼손"
        )
        fv = judge("PRCC-001", raw, "k8s_master", {})
        # 오류 가드 rationale이 아니어야 함 (기존 의미 유지)
        assert "오류 출력" not in fv.rationale

    def test_case_sensitivity_no_blind_ignorecase(self):
        """무차별 IGNORECASE 금지 — 설정 덤프 내 일반 단어 오매치 방지.

        예: 'errors:' 필드명, 소문자 'forbidden'/'unauthorized'(RBAC 설정값·
        정책 이름 등 설정 덤프 어휘)는 매치되면 안 된다.
        """
        from judge_tool.det_adapters.container import _RE_ERROR_OUTPUT
        benign = (
            "# Command : kubectl get cm -o yaml\n"
            "  errors: 0\n"
            "  policy: deny-unauthorized-traffic\n"
            "  annotation: forbidden-sysctls=none\n"
            "  message: ERROR COUNT ZERO\n"
        )
        assert _RE_ERROR_OUTPUT.search(benign) is None

    def test_error_anchor_requires_line_start(self):
        """'error:'는 행 시작 앵커형 — 행 중간의 'error:' 문구는 미매치."""
        from judge_tool.det_adapters.container import _RE_ERROR_OUTPUT
        benign = "# Command : kubectl logs\nlog-level=error: false 설정 확인\n"
        # 행 중간 'error:'(앞에 비공백 문자) → 미매치
        assert _RE_ERROR_OUTPUT.search(benign) is None


# ─────────────────────────────────────────────────────────────────────────────
# (T8 리뷰 Medium 수정) F8 가드 항목별 기대신호 면제
#   autoAnalysis.py:595-598 PRCC-013 eks_master —
#   "forbidden" in vulOutput 은 anonymous API 접속이 차단됨을 뜻하는 **양호 신호**.
#   F8 가드가 이를 오류로 오인해 판단보류로 강등하면 결정론 자동판정 손실.
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorGuardExemptTokens:
    """PRCC-013 eks_master: Forbidden/Error from server는 기대 신호 — 가드 면제."""

    def _raw_forbidden_only(self):
        """eks_master의 정상(양호) 출력 — anonymous API 접속이 Forbidden으로 차단됨."""
        return (
            "F_PRC_C_013 : eks_master\n"
            "# Command : kubectl get --raw /api\n"
            'Error from server (Forbidden): pods is forbidden: '
            'User "system:anonymous" cannot list resource "pods"\n'
        )

    def test_prcc013_eks_master_forbidden_guard_not_triggered(self):
        """(a) 브리프: PRCC-013 eks_master의 Forbidden 출력 → 가드 미발동
        → autoAnalysis 양호(N) 판정 복원(handled=True, verdict=양호)."""
        fv = judge("PRCC-013", self._raw_forbidden_only(), "eks_master", {})
        assert fv.handled is True, (
            f"면제 미적용 — F8 가드가 PRCC-013 eks_master 정상 출력을 오류로 오인: {fv}"
        )
        assert fv.verdict == "양호"
        assert fv.ev_status == "good"

    def test_prcc013_eks_master_real_error_still_guarded(self):
        """(b) 같은 출력에 진짜(비면제) 오류 토큰이 섞이면 → 가드는 여전히 발동."""
        raw = self._raw_forbidden_only() + "bash: kubectl: command not found\n"
        fv = judge("PRCC-013", raw, "eks_master", {})
        assert fv.handled is False, (
            "비면제 오류 토큰(command not found)이 섞였는데 가드가 발동하지 않음"
        )
        assert fv.verdict == "판단보류"

    def test_other_item_forbidden_still_guarded(self):
        """(c) 다른 항목(PRCC-001)의 Forbidden → 면제는 (item,variant) 한정 —
        여전히 가드 발동(기존 TestErrorOutputGuard 케이스와 동일 취지 재확인)."""
        raw = _raw_with_error(
            'Error from server (Forbidden): pods is forbidden: '
            'User "system:anonymous" cannot list resource "pods"'
        )
        fv = judge("PRCC-001", raw, "k8s_master", {})
        assert fv.handled is False
        assert fv.verdict == "판단보류"

    def test_other_variant_same_item_still_guarded(self):
        """(c) 확장: 같은 항목이라도 variant가 다르면(eks_master가 아니면) 면제 미적용."""
        raw = (
            "F_PRC_C_013 : k8s_master\n"
            "# Command : kubectl get --raw /api\n"
            'Error from server (Forbidden): pods is forbidden: '
            'User "system:anonymous" cannot list resource "pods"\n'
        )
        fv = judge("PRCC-013", raw, "k8s_master", {})
        assert fv.handled is False, (
            "eks_master 전용 면제가 다른 variant(k8s_master)에도 잘못 적용됨"
        )
        assert fv.verdict == "판단보류"


class TestErrorGuardNoOvertrigger:
    """F8 SHIP 조건: 리포지토리 내 컨테이너 실샘플 corpus 과트리거 0 검증."""

    def _corpus_outputs(self):
        """collected/container 하위 전체 xml의 (파일, 항목id, raw_output) 순회."""
        from judge_tool.parsers.container_xml import parse
        base = Path(__file__).resolve().parents[1] / "collected" / "container"
        xmls = sorted(base.rglob("*.xml")) if base.exists() else []
        outputs = []
        for x in xmls:
            for cid, resources, _ in parse(str(x)):
                for r in resources:
                    raw = r.raw_evidence or r.evidence or ""
                    outputs.append((x.name, cid, raw))
        return outputs

    def test_collected_corpus_zero_false_matches(self):
        """실수집 컨테이너 xml 전 항목 raw_output에 오류 가드 오매치 0건."""
        from judge_tool.det_adapters.container import _RE_ERROR_OUTPUT
        outputs = self._corpus_outputs()
        assert outputs, (
            "collected/container corpus가 비어 있음 — 과트리거 검증 불가"
        )
        false_matches = [
            (fname, cid, m.group(0))
            for fname, cid, raw in outputs
            if (m := _RE_ERROR_OUTPUT.search(raw))
        ]
        assert false_matches == [], (
            f"실샘플 과트리거 {len(false_matches)}건 — 토큰 앵커 강화 필요: "
            f"{false_matches[:10]}"
        )

    def test_synthetic_good_fixtures_zero_false_matches(self):
        """본 테스트 파일의 정상(양호/취약) 합성 픽스처에도 오매치 0건."""
        from judge_tool.det_adapters.container import _RE_ERROR_OUTPUT
        fixtures = [
            TestPRCC001Mapping()._raw_good(),
            TestPRCC001Mapping()._raw_vuln(),
            "F_PRC_C_004 : ocp_master\n# Command : ...\nsome output without token-auth-file\n",
            "F_PRC_C_039 : docker\n# Command : docker inspect ...\n .HostConfig.Devices: []\n",
            "F_PRC_C_036 : k8s_master\n# Command : kubectl ...\ndocker.sock이 마운트된 컨테이너\n",
            "CRI Socket 확인:\n[not exist]\n",
            "# Command : kubectl get ...\nNo result\n",
            "600 root:root /etc/kubernetes/manifests/kube-apiserver.yaml\n",
        ]
        for raw in fixtures:
            m = _RE_ERROR_OUTPUT.search(raw)
            assert m is None, f"합성 정상 픽스처 오매치: {m.group(0)!r} in {raw!r:.80}"

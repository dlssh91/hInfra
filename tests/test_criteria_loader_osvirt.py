"""OS 가상화(osvirt 프로파일) 기준 로더 단위 테스트.

합성 xlsx 픽스처 기반 — 실수집 데이터 없이 실행한다.
핵심 검증: (1) 컬럼 역전(판단방법이 판단기준보다 앞) 정확 매핑,
           (2) 변형별 적용 차이(ESXi 슈퍼셋, vCenter·Xen 부분집합).
"""
import openpyxl
import pytest

from judge_tool.criteria_loader import load_criteria
from judge_tool.profile import OS_VIRT

# 컬럼 배치 (1-indexed, openpyxl ws.cell 기준 — ⚠️ 방법이 기준보다 앞!)
_ID_COL   = 2
_NAME_COL = 7
_RISK_COL = 8
_VC_APP   = 12  # 평가대상(vCenter)
_ESXI_APP = 13  # 평가대상(ESXi)
_XEN_APP  = 14  # 평가대상(Xen)
_VC_MTH   = 15  # 판단방법(vCenter)
_VC_STD   = 16  # 판단기준(vCenter)
_ESXI_MTH = 17  # 판단방법(ESXi)
_ESXI_STD = 18  # 판단기준(ESXi)
_XEN_MTH  = 19  # 판단방법(Xen)
_XEN_STD  = 20  # 판단기준(Xen)


def _osvirt_xlsx(tmp_path, rows):
    """합성 'OS 가상화 시스템' 시트.

    rows: [(item_id, vc_app, esxi_app, xen_app, std_text, mth_text)]
    각 *_app는 bool. std/mth는 3변형에 동일 텍스트로 채운다(역전 검증용).
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "OS 가상화 시스템"
    ws.cell(4, _ID_COL, "평가항목ID")
    ws.cell(4, _NAME_COL, "평가항목")
    ws.cell(4, _RISK_COL, "위험도")
    ws.cell(4, _VC_APP, "평가대상(VMWare vCenter)")
    ws.cell(4, _ESXI_APP, "평가대상(VMWare ESXi)")
    ws.cell(4, _XEN_APP, "평가대상(XenServer)")
    ws.cell(4, _VC_MTH, "판단방법(vCenter)")
    ws.cell(4, _VC_STD, "판단기준(vCenter)")
    ws.cell(4, _ESXI_MTH, "판단방법(ESXi)")
    ws.cell(4, _ESXI_STD, "판단기준(ESXi)")
    ws.cell(4, _XEN_MTH, "판단방법(Xen)")
    ws.cell(4, _XEN_STD, "판단기준(Xen)")
    r = 5
    for item_id, vc, esxi, xen, std, mth in rows:
        ws.cell(r, _ID_COL, item_id)
        ws.cell(r, _NAME_COL, f"{item_id}항목")
        ws.cell(r, _RISK_COL, 4.0)
        if vc:
            ws.cell(r, _VC_APP, "o")
            ws.cell(r, _VC_STD, std)
            ws.cell(r, _VC_MTH, mth)
        if esxi:
            ws.cell(r, _ESXI_APP, "o")
            ws.cell(r, _ESXI_STD, std)
            ws.cell(r, _ESXI_MTH, mth)
        if xen:
            ws.cell(r, _XEN_APP, "o")
            ws.cell(r, _XEN_STD, std)
            ws.cell(r, _XEN_MTH, mth)
        r += 1
    p = str(tmp_path / "osvirt.xlsx")
    wb.save(p)
    return p


# ── 컬럼 역전 검증 (핵심) ─────────────────────────────────────────────────────

def test_column_inversion_standard_and_method(tmp_path):
    """판단방법(col15/17/19)과 판단기준(col16/18/20)이 올바른 필드로 로드되는지.

    std_text와 mth_text를 서로 명백히 다르게 넣어 역전 매핑을 검출한다.
    """
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-001", True, True, True,
         "양호기준_STANDARD_텍스트", "확인방법_METHOD_텍스트"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    for variant in ("vcenter", "esxi", "xen"):
        c = crit[("PRCV-001", variant)]
        assert c.standard == "양호기준_STANDARD_텍스트", (
            f"{variant}: standard가 method와 뒤바뀜")
        assert c.method == "확인방법_METHOD_텍스트", (
            f"{variant}: method가 standard와 뒤바뀜")


# ── 변형별 적용 차이 ──────────────────────────────────────────────────────────

def test_all_variants_applicable(tmp_path):
    """PRCV-001: 3변형 모두 'o' → 전부 applicable=True, judgment_method=llm."""
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-001", True, True, True, "* 양호 - ...", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    for variant in ("vcenter", "esxi", "xen"):
        c = crit[("PRCV-001", variant)]
        assert c.applicable is True
        assert c.is_judgeable is True
        assert c.label == "A"
        assert c.judgment_method == "llm"


def test_esxi_only_item(tmp_path):
    """PRCV-008: ESXi만 'o' → esxi applicable, vcenter/xen not applicable."""
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-008", False, True, False, "* 양호 - 예외 사용자 점검", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    assert crit[("PRCV-008", "esxi")].applicable is True
    assert crit[("PRCV-008", "esxi")].is_judgeable is True
    assert crit[("PRCV-008", "vcenter")].applicable is False
    assert crit[("PRCV-008", "xen")].applicable is False


def test_esxi_xen_item_vcenter_excluded(tmp_path):
    """PRCV-010: ESXi+Xen 'o', vCenter 제외."""
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-010", False, True, True, "* 양호 - Lockdown mode", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    assert crit[("PRCV-010", "esxi")].applicable is True
    assert crit[("PRCV-010", "xen")].applicable is True
    assert crit[("PRCV-010", "vcenter")].applicable is False


def test_vcenter_esxi_item_xen_excluded(tmp_path):
    """PRCV-014: vCenter+ESXi 'o', Xen 제외."""
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-014", True, True, False, "* 양호 - 관리 인터페이스", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    assert crit[("PRCV-014", "vcenter")].applicable is True
    assert crit[("PRCV-014", "esxi")].applicable is True
    assert crit[("PRCV-014", "xen")].applicable is False


def test_applicable_but_empty_standard_not_judgeable(tmp_path):
    """'o'지만 판단기준 빈칸 → is_judgeable=False."""
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-001", True, True, True, "", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    c = crit[("PRCV-001", "esxi")]
    assert c.applicable is True
    assert c.is_judgeable is False


# ── label B 회귀핀 (2026-07-11 PRCV-003/022/023 A→B 전환) ────────────────────
# 근거: docs/superpowers/reports/2026-07-11-osvirt-label-proposal.md.
# item_configs/osvirt.yaml에 실제 등재된 label/summary_instruction을
# load_criteria가 그대로 반영하는지 확인(회귀 방지) — 이 3항목은 osvirt cov
# 계약 테스트가 별도로 없으므로 이 파일에 최소 핀으로 정착시킨다.

def test_prcv_003_022_023_label_b_interview(tmp_path):
    """PRCV-003/022/023: item_configs/osvirt.yaml의 label B + summary_instruction이
    classify_method를 거쳐 judgment_method='interview'로 라우팅되는지 확인.

    핵심 계약: 이 3항목은 판단보류(인터뷰) 고정이며, det_common 자동판정으로
    우회되지 않는다(osvirt는 _DET_ADAPTERS에 어댑터가 등록되어 있지 않음 —
    DBM-020/024류처럼 label B에 det_common이 얹혀 자동판정으로 새는 사고가
    구조적으로 발생할 수 없음. 아래 assert로 yaml에 judgment_method가
    지정되지 않았음을 함께 확정한다).
    """
    p = _osvirt_xlsx(tmp_path, [
        ("PRCV-003", True, True, True, "* 양호 - 불필요 계정 제거", "확인방법"),
        ("PRCV-022", True, True, True, "* 양호 - 원격 로그 서버", "확인방법"),
        ("PRCV-023", True, True, True, "* 양호 - 이벤트 로그 설정", "확인방법"),
    ])
    crit = load_criteria(p, OS_VIRT, profile_key="osvirt")
    for item_id in ("PRCV-003", "PRCV-022", "PRCV-023"):
        for variant in ("vcenter", "esxi", "xen"):
            c = crit[(item_id, variant)]
            assert c.label == "B", f"{item_id}/{variant}: label이 B가 아님"
            assert c.summary_instruction, (
                f"{item_id}/{variant}: summary_instruction 누락 — holdonly로 새면 안 됨")
            assert c.judgment_method == "interview", (
                f"{item_id}/{variant}: judgment_method={c.judgment_method} "
                "(interview_holdonly/det_common 등으로 새면 안 됨)")


def test_osvirt_profile_registered():
    """get_profile('osvirt') 성공: parser=osvirt_xml, 3변형, 컬럼 역전 매핑."""
    from judge_tool.profile import get_profile
    prof = get_profile("osvirt")
    assert prof.parser == "osvirt_xml"
    assert set(prof.variants.keys()) == {"vcenter", "esxi", "xen"}
    # 컬럼 역전: standard_col(판단기준) > method_col(판단방법) (각 변형)
    assert prof.variants["vcenter"].standard_col == 16
    assert prof.variants["vcenter"].method_col == 15
    assert prof.variants["esxi"].standard_col == 18
    assert prof.variants["esxi"].method_col == 17
    assert prof.variants["xen"].standard_col == 20
    assert prof.variants["xen"].method_col == 19

"""컨테이너 가상화 기준 로더 테스트 (작업⑤).

합성 xlsx 픽스처로 criteria_loader.load_criteria()가 CONTAINER Profile의
다중 변형(standard/method/applicability 컬럼)을 올바르게 로드하는지 확인한다.
"""
import json

import openpyxl
import pytest

from judge_tool.criteria_loader import load_criteria
from judge_tool.main import run
from judge_tool.profile import CONTAINER

# 컨테이너 프로파일 컬럼 (profile.py 계약과 동일)
_COLS = {
    "id": 2, "name": 7, "risk": 8,
    "k8s_master_app":  12, "k8s_master_mth":  21, "k8s_master_std":  22,
    "k8s_worker_app":  13, "k8s_worker_mth":  23, "k8s_worker_std":  24,
    "eks_master_app":  14, "eks_master_mth":  25, "eks_master_std":  26,
    "eks_worker_app":  15, "eks_worker_mth":  27, "eks_worker_std":  28,
    "aks_master_app":  16, "aks_master_mth":  29, "aks_master_std":  30,
    "aks_worker_app":  17, "aks_worker_mth":  31, "aks_worker_std":  32,
    "ocp_master_app":  18, "ocp_master_mth":  33, "ocp_master_std":  34,
    "ocp_worker_app":  19, "ocp_worker_mth":  35, "ocp_worker_std":  36,
    "docker_linux_app":20, "docker_linux_mth":37, "docker_linux_std":38,
}


def _container_xlsx(path, rows):
    """합성 '컨테이너 가상화 시스템' 시트.

    rows: [(item_id, {variant: applicable}, standard_text)]
    standard_text는 모든 variant에 동일하게 적용(테스트 단순화).
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "컨테이너 가상화 시스템"
    ws.cell(4, _COLS["id"], "평가항목ID")
    ws.cell(4, _COLS["name"], "평가항목")
    ws.cell(4, _COLS["risk"], "위험도")
    r = 5
    for item_id, apps, std_text in rows:
        ws.cell(r, _COLS["id"], item_id)
        ws.cell(r, _COLS["name"], f"{item_id} 항목명")
        ws.cell(r, _COLS["risk"], 5.0)
        for vname in ["k8s_master", "k8s_worker", "eks_master", "eks_worker",
                      "aks_master", "aks_worker", "ocp_master", "ocp_worker",
                      "docker_linux"]:
            if apps.get(vname, False):
                ws.cell(r, _COLS[f"{vname}_app"], "o")
            ws.cell(r, _COLS[f"{vname}_std"], std_text)
            ws.cell(r, _COLS[f"{vname}_mth"], f"{vname} 방법")
        r += 1
    wb.save(str(path))


# ─ 기준 로더 단위 ─────────────────────────────────────────────────────────────

def test_k8s_master_applicable(tmp_path):
    p = str(tmp_path / "c.xlsx")
    _container_xlsx(p, [("PRCC-001", {"k8s_master": True}, "* 양호 - ...\n* 취약 - ...")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    c = crit[("PRCC-001", "k8s_master")]
    assert c.applicable is True
    assert c.is_judgeable is True
    assert "양호" in c.standard
    assert c.method == "k8s_master 방법"
    assert c.label == "A"
    # Phase 2: PRCC-001은 container.yaml에 det_common 등재됨 (k8s_master=DET)
    assert c.judgment_method == "det_common"


def test_k8s_worker_not_applicable(tmp_path):
    """k8s_worker에 'o' 없으면 applicable=False."""
    p = str(tmp_path / "c2.xlsx")
    _container_xlsx(p, [("PRCC-001", {"k8s_master": True}, "기준")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    c = crit[("PRCC-001", "k8s_worker")]
    assert c.applicable is False
    assert c.is_judgeable is False


def test_docker_linux_applicable(tmp_path):
    p = str(tmp_path / "c3.xlsx")
    _container_xlsx(p, [("PRCC-011", {"docker_linux": True}, "* 양호 - 원격 로그 서버 설정")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    c = crit[("PRCC-011", "docker_linux")]
    assert c.applicable is True
    assert c.is_judgeable is True


def test_all_variants_loaded(tmp_path):
    """한 항목이 9개 변형 모두에 대해 Criterion이 생성된다."""
    p = str(tmp_path / "c4.xlsx")
    all_apps = {v: True for v in [
        "k8s_master","k8s_worker","eks_master","eks_worker",
        "aks_master","aks_worker","ocp_master","ocp_worker","docker_linux"]}
    _container_xlsx(p, [("PRCC-009", all_apps, "기준텍스트")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    for vname in all_apps:
        key = ("PRCC-009", vname)
        assert key in crit, f"Missing: {key}"
        assert crit[key].applicable is True


def test_multiple_items_loaded(tmp_path):
    p = str(tmp_path / "c5.xlsx")
    _container_xlsx(p, [
        ("PRCC-001", {"k8s_master": True}, "기준A"),
        ("PRCC-007", {"k8s_master": True, "k8s_worker": True, "docker_linux": True}, "기준B"),
        ("PRCC-011", {"docker_linux": True}, "기준C"),
    ])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    assert crit[("PRCC-001", "k8s_master")].applicable is True
    assert crit[("PRCC-001", "docker_linux")].applicable is False
    assert crit[("PRCC-007", "k8s_worker")].applicable is True
    assert crit[("PRCC-011", "docker_linux")].applicable is True


def test_judgment_method_det_common_registered(tmp_path):
    """container.yaml에 등재된 항목(PRCC-001) → judgment_method=det_common (Phase 2)."""
    p = str(tmp_path / "c6.xlsx")
    _container_xlsx(p, [("PRCC-001", {"k8s_master": True}, "기준")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    # Phase 2: PRCC-001이 container.yaml에 det_common으로 등재됨
    assert crit[("PRCC-001", "k8s_master")].judgment_method == "det_common"


def test_judgment_method_llm_for_unlisted(tmp_path):
    """container.yaml에 미등재 항목(PRCC-999) → 기본 label=A, judgment_method=llm."""
    p = str(tmp_path / "c6b.xlsx")
    _container_xlsx(p, [("PRCC-999", {"k8s_master": True}, "기준")])
    crit = load_criteria(p, CONTAINER, profile_key="container")
    assert crit[("PRCC-999", "k8s_master")].judgment_method == "llm"


def test_standard_col_per_variant(tmp_path):
    """각 변형이 자신의 standard_col을 읽는다 — 다른 변형과 혼용 없음."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "컨테이너 가상화 시스템"
    ws.cell(4, 2, "ID"); ws.cell(4, 7, "name"); ws.cell(4, 8, "risk")
    ws.cell(5, 2, "PRCC-001"); ws.cell(5, 7, "항목"); ws.cell(5, 8, 5.0)
    # k8s_master: std=C22='기준_k8s', worker: std=C24='기준_worker'
    ws.cell(5, 12, "o");         ws.cell(5, 22, "기준_k8s_master"); ws.cell(5, 21, "방법_k8s")
    ws.cell(5, 13, "o");         ws.cell(5, 24, "기준_k8s_worker"); ws.cell(5, 23, "방법_worker")
    p = str(tmp_path / "std_col.xlsx")
    wb.save(p)
    crit = load_criteria(p, CONTAINER, profile_key="container")
    assert crit[("PRCC-001", "k8s_master")].standard == "기준_k8s_master"
    assert crit[("PRCC-001", "k8s_worker")].standard == "기준_k8s_worker"


# ─ main.run 통합 (경량 스텁) ──────────────────────────────────────────────────

class StubVuln:
    def chat(self, system, user):
        return ('{"verdict":"취약","confidence":0.8,'
                '"rationale":"테스트","cited_evidence":["x"]}')


def _container_xml_content(variant="k8s_master", dumps=None):
    if dumps is None:
        dumps = [("PRCC-001", "kubectl output here")]
    dump_xml = ""
    for cid, out in dumps:
        dump_xml += f"""
<dump>
<items><id>{cid}</id></items>
<output><![CDATA[{out}]]></output>
</dump>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<script>
<asset><hostname>test-node</hostname><variant>{variant}</variant></asset>
<results>{dump_xml}</results>
</script>
"""


def test_run_k8s_master_variant(tmp_path):
    """k8s_master variant XML → metadata.variant == "k8s_master"."""
    criteria = str(tmp_path / "c.xlsx")
    _container_xlsx(criteria, [
        ("PRCC-001", {"k8s_master": True}, "* 양호 - ...\n* 취약 - ..."),
    ])
    report = str(tmp_path / "k8s_master_result.xml")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(_container_xml_content(variant="k8s_master"))
    jout = str(tmp_path / "r.json")
    xout = str(tmp_path / "r.xlsx")
    cov = run(report, criteria, "container", StubVuln(), jout, xout, "stub")
    data = json.load(open(jout, encoding="utf-8"))
    assert data["metadata"]["variant"] == "k8s_master"
    assert data["metadata"]["profile"] == "container"
    by_id = {j["item_id"]: j for j in data["judgments"]}
    assert "PRCC-001" in by_id
    assert by_id["PRCC-001"]["script_status"] is None   # status_available=False
    assert by_id["PRCC-001"]["agreement"] == "N/A"
    assert by_id["PRCC-001"]["needs_review"] is True    # flag_vulnerable_for_review=True


def test_run_empty_output_pending(tmp_path):
    """output 공백 → 판단보류."""
    criteria = str(tmp_path / "c2.xlsx")
    _container_xlsx(criteria, [
        ("PRCC-001", {"docker_linux": True}, "* 양호 - ..."),
    ])
    report = str(tmp_path / "docker.xml")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(_container_xml_content(variant="docker_linux",
                                        dumps=[("PRCC-001", "   ")]))
    jout = str(tmp_path / "d.json")
    run(report, criteria, "container", StubVuln(), jout, str(tmp_path / "d.xlsx"), "stub")
    data = json.load(open(jout, encoding="utf-8"))
    by_id = {j["item_id"]: j for j in data["judgments"]}
    assert by_id["PRCC-001"]["verdict"] == "판단보류"


def test_run_all_judgments_needs_review(tmp_path):
    """flag_vulnerable_for_review=True → 취약 판정은 모두 needs_review True."""
    criteria = str(tmp_path / "c3.xlsx")
    _container_xlsx(criteria, [
        ("PRCC-001", {"k8s_master": True}, "* 양호 - ..."),
        ("PRCC-002", {"k8s_master": True}, "* 양호 - ..."),
    ])
    report = str(tmp_path / "k.xml")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(_container_xml_content(
            variant="k8s_master",
            dumps=[("PRCC-001", "vulnerable"), ("PRCC-002", "also vuln")],
        ))
    jout = str(tmp_path / "k.json")
    run(report, criteria, "container", StubVuln(), jout, str(tmp_path / "k.xlsx"), "stub")
    data = json.load(open(jout, encoding="utf-8"))
    for j in data["judgments"]:
        if j["verdict"] == "취약":
            assert j["needs_review"] is True

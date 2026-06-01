import os
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def project_root():
    return PROJECT_ROOT


@pytest.fixture
def aws_report_path(project_root):
    """업로드된 실제 AWS 점검 결과 샘플."""
    return os.path.join(project_root, "results", "Public Cloud",
                        "aws_report_20251223_hinno.xml")


@pytest.fixture
def criteria_xlsx_path(project_root):
    return os.path.join(
        project_root, "ref",
        "전자금융기반시설 보안 취약점 평가기준(제2026-1호) 평가자용_2603개정.xlsx")

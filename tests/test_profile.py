import pytest

from judge_tool.profile import CLOUD, get_profile


def test_normalize_id_strips_subindex():
    assert CLOUD.normalize_id("pism_001") == "PISM-001"
    assert CLOUD.normalize_id("pism_037_1") == "PISM-037"
    assert CLOUD.normalize_id("pism_046_3") == "PISM-046"


def test_variant_from_filename():
    assert CLOUD.variant_from_filename("aws_report_20251223_hinno.xml") == "AWS"
    assert CLOUD.variant_from_filename("azure_report_20251121.xml") == "Azure"
    assert CLOUD.variant_from_filename("random.xml") is None


def test_profile_columns():
    assert CLOUD.sheet_name == "클라우드 관리체계"
    aws = CLOUD.variants["AWS"]
    assert (aws.eval_type_col, aws.standard_col, aws.method_col) == (11, 17, 13)


def test_get_profile():
    assert get_profile("cloud") is CLOUD


def test_get_profile_unknown_raises():
    with pytest.raises(KeyError):
        get_profile("nope")


def test_azure_columns():
    az = CLOUD.variants["Azure"]
    assert (az.eval_type_col, az.standard_col, az.method_col) == (12, 18, 14)
    assert az.filename_markers == ("azure_report",)

import pytest

from judge_tool.parsers import cloud_xml, get_parser


def test_get_parser_returns_module():
    assert get_parser("cloud_xml") is cloud_xml


def test_get_parser_unknown_raises_value_error():
    with pytest.raises(ValueError):
        get_parser("nope")

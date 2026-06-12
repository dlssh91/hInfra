"""파서 레지스트리.

새 분야(파서) 추가 시 이 파일과 해당 프로파일만 손대면 되도록
파서 등록 지점을 한 곳으로 모은다(main.py 는 get_parser 만 사용).
"""
from judge_tool.parsers import (
    cloud_xml, container_xml, db_json, fw_policy_xlsx, iss_xml,
    network_xml, server_xml,
)

_PARSERS = {
    "cloud_xml":      cloud_xml,
    "container_xml":  container_xml,
    "db_json":        db_json,
    "fw_policy_xlsx": fw_policy_xlsx,
    "iss_xml":        iss_xml,
    "network_xml":    network_xml,
    "server_xml":     server_xml,
}


def get_parser(name):
    """프로파일의 parser 키에 대응하는 파서 모듈을 반환한다.

    등록되지 않은 이름이면 ValueError 를 던진다.
    """
    parser = _PARSERS.get(name)
    if parser is None:
        raise ValueError(f"지원하지 않는 파서: {name}")
    return parser

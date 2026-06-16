# coding=utf-8
# VENDOR-EDIT(a): flus-main ServerConfigLoader/sclib.py에서 순수 헬퍼만 추출
#   (Django/lxml/openpyxl/apps/flus 의존 코드 전부 제외).
#   원본 경로: flus-main/app/common/ServerConfigLoader/sclib.py
#   추출 대상: DELIMITER, get_check_service, get_check_service_escape_ver,
#              get_remove_line, split_output (check 함수들이 실제 import하는 것들)
#   robust_parse_xml: check 함수가 사용하지 않으므로 NotImplementedError 스텁으로 대체.
#   원본의 parseAnalysisResult/xmlToDict/extractHostInfo/repair_mixed_utf8_euckr_line 등
#   Django ORM·lxml·openpyxl 의존 함수는 모두 제외.

import re

DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="


def get_check_service(s, search_str):
    """서비스명 블록([S]~[E])이 존재하고 내용이 비지 않으면 True 반환."""
    # '|' 문자를 그대로 사용하고 각각의 서비스 이름을 이스케이프하지 않음
    pattern = r"\[ " + search_str + r" \]\[S\](.*?)\[ " + search_str + r" \]\[E\]"
    match = re.search(pattern, s, re.DOTALL)
    return False if not match or not match.group(1).strip() else True


def get_check_service_escape_ver(s, search_str):
    """get_check_service의 이스케이프 버전 — search_str을 re.escape 처리."""
    pattern = r"\[ " + re.escape(search_str) + r" \]\[S\](.*?)\[ " + re.escape(search_str) + r" \]\[E\]"
    match = re.search(pattern, s, re.DOTALL)
    return False if not match or not match.group(1).strip() else True


def get_remove_line(text, char):
    """각 줄이 char으로 시작하면 제거한다(주석·빈줄 제거용)."""
    return '\n'.join(line for line in text.split('\n') if not line.strip().startswith(char))


def split_output(output, expected_min_splits):
    """DELIMITER로 output을 분할. 기대 분할 수보다 적으면 빈 리스트 반환."""
    outputArr = output.split(DELIMITER)
    if len(outputArr) < expected_min_splits:
        return []
    return outputArr


def robust_parse_xml(file_path, target_tag='dump'):
    """벤더링: 어댑터는 check 함수를 직접 호출하므로 이 경로는 미사용.
    main() 경로가 이 함수를 사용하나, judge_tool에서는 호출하지 않는다."""
    raise NotImplementedError(
        "벤더링: main() 경로 미사용 — 어댑터는 check 함수 직접 호출"
    )

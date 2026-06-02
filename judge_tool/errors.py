"""judge_tool 전용 예외 타입.

무거운 모듈(models 등)을 import 하지 않아 순환 import 를 막는다.
"""


class ReportError(ValueError):
    """사용자 입력/보고서 문제로 인한 처리 불가 — CLI 가 트레이스백 대신
    한 줄로 깔끔히 안내하는 예외. ValueError 상속으로 기존 호환 유지."""

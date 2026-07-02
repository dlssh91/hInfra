"""`python3 -m judge_tool` 진입점.

기존 `python3 -m judge_tool.main` 과 동일하게 동작하되 '.main' 접미사를
없애 실사용자(보안 점검자)가 외우기 쉽게 한다. 판정 로직은 전혀 건드리지
않고 main.main()을 그대로 위임한다.
"""
from judge_tool.main import main

if __name__ == "__main__":
    main()

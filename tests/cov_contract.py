"""서버 LLM-production 항목 양극성 커버리지 픽스처 계약 (단일 진실원천).

cov-good / cov-vuln 픽스처가 만족해야 하는 골드라벨 계약을 정의한다.
- LLM_PROD_ITEMS: LLM이 production 1차 판정자인 label-A 항목(det_common 아님).
- VULN_SIGNALS / GOOD_SIGNALS: 각 극성 픽스처에 반드시 존재해야 하는 설계 단서.
  (None = 원본 XML에서 상속받는 극성 — 그 경우 good!=vuln 차이만 강제한다.)

생성기(_build_cov_fixtures.py)와 계약 테스트(test_cov_fixtures.py)가 공유한다.
"""

LLM_PROD_ITEMS = [
    "SRV-006", "SRV-027", "SRV-081", "SRV-091", "SRV-112",
    "SRV-144", "SRV-163", "SRV-165", "SRV-166", "SRV-175",
]

# 취약(cov-vuln) 픽스처가 반드시 포함해야 하는 설계 단서
VULN_SIGNALS = {
    "SRV-006": "LogLevel=0",
    "SRV-027": "policy ACCEPT",
    "SRV-081": "rwsrwxrwx",
    "SRV-091": "/tmp/.cache/rootbash",
    "SRV-112": None,            # 상속: cron 로깅 미설정
    "SRV-144": "/dev/backdoor",
    "SRV-163": None,            # 상속: 기본 issue(배너 없음)
    "SRV-165": None,            # 상속: 취약 쉘 계정
    "SRV-166": ".bd.sh",
    "SRV-175": "NTP service: inactive",
}

# 양호(cov-good) 픽스처가 반드시 포함해야 하는 설계 단서
GOOD_SIGNALS = {
    "SRV-006": "LogLevel=9",
    "SRV-027": "ALL: ALL",
    "SRV-081": "rwxr-x---",
    "SRV-091": None,            # 상속: 표준 SUID만
    "SRV-112": "cron.*",
    "SRV-144": None,            # 상속/주입: /dev 일반파일 없음
    "SRV-163": "Authorized",
    "SRV-165": None,            # 상속: 양호 쉘 계정
    "SRV-166": None,            # 상속: 정상 dotfile만
    "SRV-175": "NTP service: active",
}

GOOD_FIXTURE = "collected/server/linux/linux-s-cov-good.xml"
VULN_FIXTURE = "collected/server/linux/linux-s-cov-vuln.xml"

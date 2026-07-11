"""WST-033 Apache 서비스 조기반환 죽은 코드 → 허위근거 거짓양호 회귀테스트.

KNOWN_BUGS.md R-WST033 (BUG-WST033-apache) 참조.

배경: `judge_tool/vendor/common/webwas/WST_Apache_parse.py::check_WST_033`의
서비스-존재 조기반환이 `output_arr[0]`(fDumpS 진단 헤더 `[ ... ][S]`~`[E]`)에
`re.search(service_pattern, ...)` 를 수행했는데, 이 헤더 자체가 점검 대상
토큰을 항상 그대로 echo하므로(게다가 service_pattern이 이스케이프된 리터럴
파이프였던 탓에 사실상 헤더 문자열만 매치) 조기반환이 도달 불가능한 죽은
코드였다. 그 결과 Apache가 전혀 설치되지 않은 호스트(out/was_lab/
tomcat-good.xml 실측)에서도 "버전이 2.1 이상인 것으로 탐지되어 양호"라는
허위 근거로 자동 양호를 반환했다.

수정: 헤더 라인만 제거한 나머지에서 서비스 존재를 판정하고(service_pattern도
진짜 alternation으로 수정), 서비스는 확인되나 버전을 특정할 수 없는 경우는
"(*)" 마커로 판단보류시킨다(허위근거 "2.1 이상 탐지" 폴백 제거).
"""
import judge_tool.det_adapters.webwas  # noqa: F401 — judge() 레지스트리 등록 부작용
from judge_tool.det_adapters.base import ForcedVerdict
from judge_tool.det_adapters.webwas import judge
from judge_tool.vendor.common.webwas.WST_Apache_parse import check_WST_033

DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

# fDumpS 헤더(서비스 미확인, tomcat-good.xml 실측 형상 — Apache 완전 부재)
_SVC_HEADER = (
    "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
    "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
)


def _raw(rpm_line: str, dpkg_line: str, apache_v_line: str, svc_block: str = _SVC_HEADER) -> str:
    """check_WST_033 구분자 구조를 준수하는 합성 raw를 만든다."""
    return (
        f"{svc_block}"
        f"{DELIMITER}\n"
        f"$ rpm -qa httpd\n{rpm_line}\n"
        f"{DELIMITER}\n"
        f"$ dpkg -l | grep apache\n{dpkg_line}\n"
        f"{DELIMITER}\n"
        f"$ apache2 -v\n{apache_v_line}\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1) 헤더-only(Apache 부재) — tomcat-good.xml 실측 형상 기반
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceAbsentHonestVerdict:
    """헤더만 있고 실제 프로세스/패키지 증거가 전혀 없으면(Apache 완전 부재)
    조기반환이 실제로 발동해 정직한 사유로 양호를 반환해야 한다."""

    # tomcat-good.xml 실측 WST-033 output (그대로 재현)
    TOMCAT_GOOD_RAW = (
        "\n[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
        f"{DELIMITER}\n"
        "$ rpm -qa httpd\n"
        "/tmp/fsi_unix.sh: line 2670: rpm: command not found\n"
        f"{DELIMITER}\n"
        "$ dpkg -l | grep apache\n"
        f"{DELIMITER}\n"
        "$ apache2 -v\n"
        "/tmp/fsi_unix.sh: line 2678: apache2: command not found\n"
    )

    def test_tomcat_good_xml_shape_returns_good_with_honest_reason(self):
        """tomcat-good.xml 실측 형상: Apache 부재 → 양호 + 정직한 사유.

        수정 전에는 이 조기반환에 절대 도달하지 못하고, 버전 미검출임에도
        "(+) Apache 버전이 2.1 이상인 것으로 탐지되어 양호로 판단"이라는
        허위 근거를 반환했다.
        """
        result, reason, vul_list = check_WST_033(self.TOMCAT_GOOD_RAW)
        assert result == "N"
        assert "실행 중이지 않은" in reason, (
            f"조기반환 도달 실패 — 여전히 죽은 코드: {reason!r}"
        )
        assert "2.1 이상인 것으로 탐지" not in reason, (
            "허위근거 회귀: 버전 미검출인데 '2.1 이상 탐지' 문구가 남음"
        )
        assert vul_list == []

    def test_header_only_no_process_evidence_returns_good_honest_reason(self):
        """헤더 두 줄만 있고 그 외 어떤 라인도 없는 극단 형상도 동일하게 처리."""
        raw = _raw(
            "not found", "", "not found",
            svc_block="[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
                       "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n",
        )
        result, reason, _ = check_WST_033(raw)
        assert result == "N"
        assert "실행 중이지 않은" in reason

    def test_adapter_end_to_end_service_absent_is_good(self):
        """어댑터 경유(judge)로도 동일하게 양호 + handled=True 확인."""
        fv = judge("WST-033", self.TOMCAT_GOOD_RAW, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "양호"


# ─────────────────────────────────────────────────────────────────────────────
# 2) 실제 Apache 서비스 존재 + 구버전 → 취약 회귀
# ─────────────────────────────────────────────────────────────────────────────

class TestServicePresentVulnRegression:
    _SVC_WITH_PROC = (
        "-e [ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\n"
        "root      3471     1  0 09:44 ?        00:00:00 /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    def test_real_apache_old_version_httpd_rpm_is_vulnerable(self):
        """rpm -qa httpd 가 httpd-1.3.42-* 를 반환하면 취약(<2.1)."""
        raw = _raw(
            "httpd-1.3.42-1.el6.x86_64", "(none)",
            "Server version: Apache/1.3.42",
            svc_block=self._SVC_WITH_PROC,
        )
        result, reason, vul_list = check_WST_033(raw)
        assert result == "Y"
        assert vul_list, "취약 조건 리스트가 비어있음"
        assert "취약" in reason

    def test_adapter_end_to_end_old_version_is_vulnerable(self):
        raw = _raw(
            "httpd-1.3.42-1.el6.x86_64", "(none)",
            "Server version: Apache/1.3.42",
            svc_block=self._SVC_WITH_PROC,
        )
        fv = judge("WST-033", raw, "apache", {})
        assert fv.handled is True
        assert fv.verdict == "취약"


# ─────────────────────────────────────────────────────────────────────────────
# 3) 실제 Apache 서비스 존재 + 신버전 → 양호 회귀
# ─────────────────────────────────────────────────────────────────────────────

class TestServicePresentGoodRegression:
    _SVC_WITH_PROC = (
        "-e [ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\n"
        "root      3471     1  0 09:44 ?        00:00:00 /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    def test_real_apache_new_version_dpkg_is_good(self):
        """dpkg -l | grep apache 가 apache2 2.4.52 를 보이면 양호(>=2.1)."""
        raw = _raw(
            "httpd not found", "ii  apache2  2.4.52-1ubuntu4",
            "Server version: Apache/2.4.52 (Ubuntu)",
            svc_block=self._SVC_WITH_PROC,
        )
        result, reason, vul_list = check_WST_033(raw)
        assert result == "N"
        assert vul_list == []
        assert "2.1 이상인 것으로 탐지" in reason
        assert "apache2" in reason.lower() or "2.4.52" in reason

    def test_adapter_end_to_end_new_version_is_good(self):
        raw = _raw(
            "httpd not found", "ii  apache2  2.4.52-1ubuntu4",
            "Server version: Apache/2.4.52 (Ubuntu)",
            svc_block=self._SVC_WITH_PROC,
        )
        fv = judge("WST-033", raw, "apache", {})
        assert fv.handled is True
        assert fv.verdict == "양호"


# ─────────────────────────────────────────────────────────────────────────────
# 4) 서비스 존재 확인 + 버전 미검출 → 판단보류 (허위근거 폴백 제거 확인)
# ─────────────────────────────────────────────────────────────────────────────

class TestServicePresentVersionUndetectedHold:
    """서비스는 실제로 존재하나(ps에 apache2 프로세스) rpm/dpkg/apache2 -v
    어디서도 버전을 뽑아내지 못하면, "2.1 이상 탐지"라는 허위근거로 양호를
    내지 않고 판단보류로 흡수되어야 한다(가장 안전한 선택)."""

    _SVC_WITH_PROC = (
        "-e [ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\n"
        "root      3471     1  0 09:44 ?        00:00:00 /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    def test_version_undetected_returns_manual_marker(self):
        raw = _raw(
            "httpd not found", "(none)", "apache2: command not found",
            svc_block=self._SVC_WITH_PROC,
        )
        result, reason, vul_list = check_WST_033(raw)
        assert result == "N"  # Low-1 가드는 result != 'Y' 조건이므로 'N' 유지
        assert "(*)" in reason, "버전 미검출 시 '(*)' 수동 마커가 있어야 판단보류로 흡수됨"
        assert "2.1 이상인 것으로 탐지" not in reason, (
            "허위근거 회귀: 버전 미검출인데 '2.1 이상 탐지' 문구가 남음"
        )
        assert vul_list == []

    def test_adapter_end_to_end_version_undetected_is_hold(self):
        """어댑터 Low-1 가드(webwas._map_result)가 '(*)' 마커를 판단보류로 흡수하는지 확인."""
        raw = _raw(
            "httpd not found", "(none)", "apache2: command not found",
            svc_block=self._SVC_WITH_PROC,
        )
        fv = judge("WST-033", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False, "버전 미검출인데 자동 양호로 handled=True가 되면 거짓양호 위험"
        assert fv.verdict == "판단보류"

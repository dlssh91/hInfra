"""웹서버-WAS(WST) 결정론 어댑터 단위 테스트 (Phase 3).

검증 항목:
  (a) 어댑터 등록 확인: _DET_ADAPTERS["webwas"] callable
  (b) SRV-* 위임: server 어댑터 경로 통과
  (c) WST DET-PARTIAL variant 분기: apache/iis/webtob
  (d) WST-102 IIS 버그수정 회귀: 위반0건 → 양호 (KNOWN_BUGS §2 corrected)
  (e) WST-040 결정론 비활성: iis=MANUAL → gate 차단 → handled=False
  (f) config-항목 config 시그니처 가드: 시그니처 없음 → handled=False (거짓취약/거짓양호 방어)
  (g) 증거존재 가드: 수집 증거 없는 raw → 양호 오판 불가
  (h) Low-1 가드: (*) 수동 마커 + result='N' → handled=False
  (i) 웹서버 추론: OS variant(linux)에서 raw로 apache 추론 → WST 판정
  (j) ABSENT variant(tomcat/jeus) → gate 차단 → handled=False
  (k) 미지 ID 접두어 → handled=False
  (l) WST-033 apache 양호 합성 픽스처 (버전 2.4.x → 양호)
  (m) WST-033 apache 취약 합성 픽스처 (버전 1.x → 취약)
  (n) raw_evidence 누출 경계: raw가 citations/rationale에 통째로 포함되지 않음
  (o) F10 오류출력 가드 파급: SRV-* server 위임 자동적용 + WST-* 명시 재적용
      + 과트리거 0 검증(collected/web, out/was_lab 실샘플 corpus)
"""
from pathlib import Path

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.webwas  # noqa: F401,E402 — 등록 부작용
from judge_tool.det_adapters.webwas import (  # noqa: E402
    judge,
    _has_collection_evidence,
    _has_config_signature,
    _infer_web_variant,
)
from judge_tool.det_adapters.base import ForcedVerdict, _DET_ADAPTERS  # noqa: E402

# 공통 구분자
DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="


# ─────────────────────────────────────────────────────────────────────────────
# (a) 어댑터 등록 확인
# ─────────────────────────────────────────────────────────────────────────────

class TestAdapterRegistration:
    """_DET_ADAPTERS["webwas"] 등록 및 callable 확인."""

    def test_webwas_registered(self):
        assert "webwas" in _DET_ADAPTERS

    def test_webwas_is_callable(self):
        assert callable(_DET_ADAPTERS["webwas"])

    def test_webwas_is_judge_function(self):
        assert _DET_ADAPTERS["webwas"] is judge


# ─────────────────────────────────────────────────────────────────────────────
# (b) SRV-* 위임
# ─────────────────────────────────────────────────────────────────────────────

class TestSRVDelegation:
    """SRV-* 항목은 server 어댑터에 위임된다."""

    def test_srv_item_with_evidence_returns_forced_verdict(self):
        """SRV-082는 DET. linux variant + 증거 있는 양호 raw → ForcedVerdict 반환."""
        raw = "$ ls -alLd /usr /bin /sbin\ndrwxr-xr-x  2 root root 4096 Jan  1 00:00 /usr\n"
        fv = judge("SRV-082", raw, "linux", {})
        assert isinstance(fv, ForcedVerdict)

    def test_srv_item_absent_variant_gate_blocked(self):
        """SRV-* ABSENT 항목 → server gate 차단 → handled=False."""
        fv = judge("SRV-999", "$ ls -al\nsome output\n", "linux", {})
        assert isinstance(fv, ForcedVerdict)
        # ABSENT → handled=False (gate 차단)
        assert fv.handled is False

    def test_srv_item_web_variant_normalizes_to_linux(self):
        """apache 웹키로 SRV-082 호출 시 OS variant 미상 → linux로 정규화해 server 위임."""
        raw = "$ ls -alLd /usr\ndrwxr-xr-x  2 root root 4096 Jan  1 00:00 /usr\n"
        fv = judge("SRV-082", raw, "apache", {})
        # server 어댑터가 처리 (handled 여부는 server gate에 달림)
        assert isinstance(fv, ForcedVerdict)


# ─────────────────────────────────────────────────────────────────────────────
# (c) WST DET-PARTIAL variant 분기
# ─────────────────────────────────────────────────────────────────────────────

class TestWSTVariantRouting:
    """DET_SOURCE WST 분류 + 파서 모듈 선택."""

    def test_wst033_apache_returns_forced_verdict(self):
        """WST-033 apache → DET → check_WST_033 호출 → ForcedVerdict."""
        # 실데이터 WST-033 raw (단순화)
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            f"$ ps -ef | egrep apache\nroot 1 /usr/sbin/apache2 -k start\n"
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            f"$ rpm -qa httpd\nhttpd not found\n"
            f"{DELIMITER}\n"
            f"$ dpkg -l | grep apache\nii apache2 2.4.52\n"
            f"{DELIMITER}\n"
            f"$ apache2 -v\nServer version: Apache/2.4.52\n"
        )
        fv = judge("WST-033", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)

    def test_wst033_tomcat_absent_gate_blocked(self):
        """WST-033 tomcat → ABSENT → gate 차단 → handled=False."""
        fv = judge("WST-033", "some data", "tomcat", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False

    def test_wst033_jeus_absent_gate_blocked(self):
        """WST-033 jeus → ABSENT → gate 차단 → handled=False."""
        fv = judge("WST-033", "some data", "jeus", {})
        assert fv.handled is False

    def test_wst032_iis_returns_forced_verdict(self):
        """WST-032 iis → DET → check_WST_032 호출 → ForcedVerdict."""
        raw = f"some iis output\n{DELIMITER}\nmore output"
        fv = judge("WST-032", raw, "iis", {})
        assert isinstance(fv, ForcedVerdict)

    def test_wst032_apache_absent_gate_blocked(self):
        """WST-032 apache → ABSENT → gate 차단 → handled=False."""
        fv = judge("WST-032", "some data", "apache", {})
        assert fv.handled is False

    def test_wst044_all_variants_manual_gate_blocked(self):
        """WST-044 전파서 MANUAL → gate 차단 → handled=False."""
        for variant in ("apache", "iis", "webtob"):
            fv = judge("WST-044", "some tomcat output", variant, {})
            assert fv.handled is False, f"WST-044 {variant} should be handled=False"


# ─────────────────────────────────────────────────────────────────────────────
# (d) WST-102 IIS 버그수정 회귀
# ─────────────────────────────────────────────────────────────────────────────

class TestWST102IISBugfix:
    """WST-102 IIS polarity 버그수정 회귀 테스트 (KNOWN_BUGS §2 corrected).

    원본 버그: `if not vulnerability_condition_result_model_list: result = "Y"` (위반0건→취약).
    수정 후: `result = "N"` (위반0건→양호).
    """

    def _good_iis_config(self) -> str:
        """removeServerHeader=true 설정 → 위반 0건 → 양호."""
        return (
            '<requestFiltering removeServerHeader="true" />\n'
            '<httpErrors errorMode="DetailedLocalOnly" />\n'
        )

    def _vuln_iis_config(self) -> str:
        """removeServerHeader 없음 + httpErrors errorMode=Detailed → 취약."""
        return '<httpErrors errorMode="Detailed" />\n'

    def test_wst102_iis_good_config_not_vulnerable(self):
        """위반 0건(removeServerHeader=true) → 양호 (버그수정 확인)."""
        config = self._good_iis_config()
        fv = judge("WST-102", config, "iis", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "양호", f"Expected 양호 but got {fv.verdict!r} (WST-102 IIS 버그수정 미적용?)"

    def test_wst102_iis_vuln_config_is_vulnerable(self):
        """httpErrors errorMode=Detailed → 취약."""
        config = self._vuln_iis_config()
        fv = judge("WST-102", config, "iis", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "취약"


# ─────────────────────────────────────────────────────────────────────────────
# (e) WST-040 결정론 비활성 (xlsx 역전 의심)
# ─────────────────────────────────────────────────────────────────────────────

class TestWST040NonDeterministic:
    """WST-040 IIS: DET_SOURCE iis=MANUAL → gate 차단 → handled=False."""

    def test_wst040_iis_gate_blocked(self):
        """WST-040 iis → MANUAL → gate 차단 → handled=False (xlsx 역전 의심)."""
        config = '<requestFiltering><fileExtensions><add fileExtension=".asa" allowed="true" /></fileExtensions></requestFiltering>'
        fv = judge("WST-040", config, "iis", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False

    def test_wst040_apache_absent_gate_blocked(self):
        """WST-040 apache → ABSENT → gate 차단 → handled=False."""
        fv = judge("WST-040", "some output", "apache", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (f) config-항목 config 시그니처 가드 (§6.4 핵심 방어)
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigSignatureGuard:
    """§6.4 config 시그니처 부재 시 handled=False (거짓취약/거짓양호 방어)."""

    def test_has_config_signature_wst035_with_limit(self):
        """WST-035: LimitRequestBody 있음 → True."""
        assert _has_config_signature("WST-035", "LimitRequestBody 1048576\n") is True

    def test_has_config_signature_wst035_without_limit(self):
        """WST-035: LimitRequestBody 없음 → False (config 미수집)."""
        assert _has_config_signature("WST-035", "apache2 running\nsome ps output\n") is False

    def test_has_config_signature_wst102_with_servertokens(self):
        """WST-102: ServerTokens 있음 → True."""
        assert _has_config_signature("WST-102", "ServerTokens Prod\n") is True

    def test_has_config_signature_wst102_without_servertokens(self):
        """WST-102: ServerTokens 없음 → False."""
        assert _has_config_signature("WST-102", "$ ps -ef | grep apache\napache running\n") is False

    def test_has_config_signature_nonconfig_item(self):
        """명령출력 항목(WST-033): config 시그니처 체크 불필요 → True."""
        assert _has_config_signature("WST-033", "") is True
        assert _has_config_signature("WST-033", "any text") is True

    def test_wst035_no_config_handled_false(self):
        """WST-035 apache: raw에 LimitRequestBody 없음 → config 시그니처 가드 → handled=False."""
        # 실데이터 WST-035 패턴: 서비스 프로세스 출력만 있고 config 없음
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            "JEUS is NOT installed\n"
        )
        fv = judge("WST-035", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False, "WST-035 config 미수집 시 handled=True면 거짓취약!"

    def test_wst038_no_config_handled_false(self):
        """WST-038 apache: raw에 <Directory 없음 → config 시그니처 가드 → handled=False."""
        # 실데이터 WST-038 패턴: ls 디렉터리 리스팅만 (config 없음)
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            "$ ls -alL /etc/apache2/\ntotal 92\n-rw-r--r-- 1 root apache2.conf\n"
            "$ ls -alL /var/www/html/\ntotal 20\n-rw-r--r-- 1 root index.html\n"
        )
        fv = judge("WST-038", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False, "WST-038 config 미수집 시 handled=True면 거짓양호!"

    def test_wst102_no_config_handled_false(self):
        """WST-102 apache: raw에 ServerTokens 없음 → config 시그니처 가드 → handled=False."""
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
        )
        fv = judge("WST-102", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (g) 증거존재 가드
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectionEvidenceGuard:
    """빈 출력 / 수집 증거 없는 raw → 양호 오판 불가."""

    def test_empty_raw_evidence_absent(self):
        assert _has_collection_evidence("") is False
        assert _has_collection_evidence("   ") is False

    def test_cmd_prompt_is_evidence(self):
        assert _has_collection_evidence("$ ls -al /etc\ntotal 100\n") is True

    def test_hash_prompt_is_evidence(self):
        assert _has_collection_evidence("# cat /etc/passwd\nroot:x:0:0\n") is True

    def test_svc_block_is_evidence(self):
        assert _has_collection_evidence("[ apache2 ][S]\nrunning\n[ apache2 ][E]\n") is True

    def test_garbage_only_no_evidence(self):
        assert _has_collection_evidence("some random text\nno commands here\n") is False


# ─────────────────────────────────────────────────────────────────────────────
# (h) Low-1 가드: (*) 수동 마커
# ─────────────────────────────────────────────────────────────────────────────

class TestLow1Guard:
    """(*) 수동 마커 있는 result='N' → handled=False."""

    def test_wst034_apache_manual_handled_false(self):
        """WST-034 apache: MANUAL(*) → gate 차단 (DET_SOURCE apache=MANUAL) → handled=False."""
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
        )
        fv = judge("WST-034", raw, "apache", {})
        assert fv.handled is False

    def test_wst039_apache_manual_handled_false(self):
        """WST-039 apache: MANUAL(*) → gate 차단 → handled=False."""
        raw = "$ ps -ef | grep apache\nroot /usr/sbin/apache2\n"
        fv = judge("WST-039", raw, "apache", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (i) 웹서버 추론: OS variant에서 raw로 apache 추론
# ─────────────────────────────────────────────────────────────────────────────

class TestWebServerInference:
    """detect_variant가 linux 반환 시 raw에서 웹서버 추론 (§6.2)."""

    def test_infer_apache_from_raw(self):
        raw = "$ ps -ef | grep apache2\nroot /usr/sbin/apache2\n"
        assert _infer_web_variant(raw) == "apache"

    def test_infer_iis_from_raw(self):
        raw = "Get-WebSite\nIIS configuration\napplicationHost.config found"
        assert _infer_web_variant(raw) == "iis"

    def test_infer_webtob_from_raw(self):
        raw = "wsm status\nwebtob running\n"
        assert _infer_web_variant(raw) == "webtob"

    def test_infer_none_from_empty(self):
        assert _infer_web_variant("") is None
        assert _infer_web_variant(None) is None

    def test_infer_none_unknown(self):
        assert _infer_web_variant("some random text\nno web server info\n") is None

    def test_wst033_linux_variant_apache_inferred(self):
        """linux variant이지만 raw에 apache 프로세스 있음 → apache로 추론 → WST-033 판정."""
        raw = (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            "$ rpm -qa httpd\nnot found\n"
            f"{DELIMITER}\n"
            "$ dpkg -l | grep apache\nii apache2 2.4.52\n"
            f"{DELIMITER}\n"
            "$ apache2 -v\nServer version: Apache/2.4.52\n"
        )
        # linux variant → 추론 → apache → WST-033 DET
        fv = judge("WST-033", raw, "linux", {})
        assert isinstance(fv, ForcedVerdict)
        # 추론 성공 후 판정 시도 (handled 여부는 check_WST_033 결과에 달림)

    def test_wst033_linux_variant_no_web_inference_failed(self):
        """linux variant + 웹서버 흔적 없는 raw → 추론 불가 → handled=False."""
        raw = "$ cat /etc/passwd\nroot:x:0:0\n"
        fv = judge("WST-033", raw, "linux", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (j) ABSENT variant (tomcat/jeus) → gate 차단
# ─────────────────────────────────────────────────────────────────────────────

class TestAbsentVariantGate:
    """WST-031~102 tomcat/jeus → ABSENT → gate 차단 → handled=False."""

    @pytest.mark.parametrize("item_id", [
        "WST-031", "WST-033", "WST-035", "WST-036", "WST-037",
        "WST-038", "WST-102",
    ])
    def test_tomcat_variant_absent(self, item_id):
        fv = judge(item_id, "some raw data", "tomcat", {})
        assert fv.handled is False, f"{item_id} tomcat should be ABSENT"

    @pytest.mark.parametrize("item_id", [
        "WST-031", "WST-033", "WST-035", "WST-102",
    ])
    def test_jeus_variant_absent(self, item_id):
        fv = judge(item_id, "some raw data", "jeus", {})
        assert fv.handled is False, f"{item_id} jeus should be ABSENT"


# ─────────────────────────────────────────────────────────────────────────────
# (k) 미지 ID 접두어
# ─────────────────────────────────────────────────────────────────────────────

class TestUnknownIDPrefix:
    """미지 ID 접두어 → handled=False."""

    def test_unknown_prefix_handled_false(self):
        fv = judge("FOO-001", "some data", "linux", {})
        assert fv.handled is False

    def test_prcc_prefix_handled_false(self):
        """PRCC-* 는 webwas 어댑터가 처리하지 않음 → handled=False."""
        fv = judge("PRCC-001", "some data", "linux", {})
        assert fv.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# (l)(m) WST-033 apache 양호/취약 합성 픽스처
# ─────────────────────────────────────────────────────────────────────────────

class TestWST033ApacheVersionCheck:
    """WST-033 apache 버전 판정 합성 픽스처."""

    def _make_wst033_raw(self, dpkg_line: str, apache_v_line: str) -> str:
        """WST-033 raw 합성 (check_WST_033 구분자 구조 준수)."""
        return (
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            f"$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            f"$ rpm -qa httpd\nhttpd not found\n"
            f"{DELIMITER}\n"
            f"$ dpkg -l | grep apache\n{dpkg_line}\n"
            f"{DELIMITER}\n"
            f"$ apache2 -v\n{apache_v_line}\n"
        )

    def test_wst033_apache_2x_is_good(self):
        """Apache 2.4.52 → 버전 2.1 이상 → 양호."""
        raw = self._make_wst033_raw(
            "ii  apache2  2.4.52-1ubuntu4.21",
            "Server version: Apache/2.4.52 (Ubuntu)",
        )
        fv = judge("WST-033", raw, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_wst033_apache_1x_is_vulnerable(self):
        """Apache 1.3.x → 버전 2.1 미만 → 취약."""
        raw = self._make_wst033_raw(
            "ii  apache2  1.3.42-1",
            "Server version: Apache/1.3.42",
        )
        # check_WST_033은 httpd-NNN-* 패턴 + apache[0-9]NNN 패턴으로 버전 추출
        # httpd-1.3.42-xxx 패턴으로 취약 감지
        raw_httpd = (
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            f"$ ps -ef | egrep apache\nroot /usr/sbin/apache -k start\n"
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            f"$ rpm -qa httpd\nhttpd-1.3.42-1.el6.x86_64\n"
            f"{DELIMITER}\n"
            f"$ dpkg -l | grep apache\n(not found)\n"
            f"{DELIMITER}\n"
            f"$ apache2 -v\nServer version: Apache/1.3.42\n"
        )
        fv = judge("WST-033", raw_httpd, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "취약"


# ─────────────────────────────────────────────────────────────────────────────
# (n) raw_evidence 누출 경계 (§7)
# ─────────────────────────────────────────────────────────────────────────────

class TestRawEvidenceBoundary:
    """raw_output이 citations/rationale에 통째로 포함되지 않는지 확인 (§7)."""

    def test_good_verdict_no_raw_in_citations(self):
        """양호 판정: citations는 빈 리스트이고 raw가 통째로 rationale에 없음."""
        raw = self._make_wst033_good_raw()
        raw_marker = "UNIQUE_RAW_MARKER_12345"
        raw_with_marker = raw + raw_marker
        fv = judge("WST-033", raw_with_marker, "apache", {})
        if fv.handled:
            assert raw_marker not in fv.rationale, "raw 전체가 rationale에 누출됨"
            for c in fv.citations:
                assert raw_marker not in c, "raw 전체가 citation에 누출됨"

    def test_vuln_verdict_citations_not_raw(self):
        """취약 판정: citations는 vul_list의 구조화된 출력만 (raw 전체 아님)."""
        raw_httpd = (
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            f"$ ps -ef | egrep apache\nroot /usr/sbin/apache -k start\n"
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            f"$ rpm -qa httpd\nhttpd-1.3.42-UNIQUE_VULN_MARKER\n"
            f"{DELIMITER}\n"
            f"$ dpkg -l | grep apache\n(none)\n"
            f"{DELIMITER}\n"
            f"$ apache2 -v\nServer version: Apache/1.3.42\n"
        )
        fv = judge("WST-033", raw_httpd, "apache", {})
        if fv.handled and fv.verdict == "취약":
            # citations은 vul_list 구조화 출력만 (raw_httpd 전체가 아님)
            for c in fv.citations:
                assert len(c) < len(raw_httpd), "citation이 raw 전체 크기 → 누출 의심"

    def _make_wst033_good_raw(self) -> str:
        return (
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            f"$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
            f"[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            f"$ rpm -qa httpd\nnot found\n"
            f"{DELIMITER}\n"
            f"$ dpkg -l | grep apache\nii apache2 2.4.52\n"
            f"{DELIMITER}\n"
            f"$ apache2 -v\nServer version: Apache/2.4.52\n"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 실데이터 WST-033 re-check (실제 샘플 패턴 기반)
# ─────────────────────────────────────────────────────────────────────────────

class TestWST033RealDataPattern:
    """실데이터(web_apache-s-sample.xml WST-033 raw) 패턴 기반 검증."""

    REAL_WST033_RAW = (
        "-e [ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\n"
        "-e root         1     0  0 09:44 ?        00:00:00 bash -c apt-get install apache2\n"
        "root      3471     1  0 09:44 ?        00:00:00 /usr/sbin/apache2 -k start\n"
        "www-data  3474  3471  0 09:44 ?        00:00:00 /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
        f"{DELIMITER}\n"
        "$ rpm -qa httpd\nfsi.sh: 2670: rpm: not found\n"
        f"{DELIMITER}\n"
        "$ dpkg -l | grep apache\n"
        "ii  apache2                       2.4.52-1ubuntu4.21                      arm64        Apache HTTP Server\n"
        "ii  apache2-bin                   2.4.52-1ubuntu4.21                      arm64        Apache HTTP Server (modules and other binary files)\n"
        f"{DELIMITER}\n"
        "$ apache2 -v\nServer version: Apache/2.4.52 (Ubuntu)\nServer built:   2026-06-03T15:42:24\n"
    )

    def test_real_wst033_apache_good(self):
        """실데이터 WST-033: Apache 2.4.52 → 양호 기대."""
        fv = judge("WST-033", self.REAL_WST033_RAW, "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "양호", f"WST-033 2.4.52 버전이 취약 판정됨: {fv.rationale}"

    def test_real_wst033_linux_inferred_good(self):
        """linux variant + apache 프로세스 추론 → 동일 양호 기대."""
        fv = judge("WST-033", self.REAL_WST033_RAW, "linux", {})
        assert isinstance(fv, ForcedVerdict)
        # linux → apache 추론 → 판정 (handled 여부는 check 결과에 달림)
        if fv.handled:
            assert fv.verdict == "양호"


# ─────────────────────────────────────────────────────────────────────────────
# (o) WST-038 DOTALL 회귀테스트 (KNOWN_BUGS WST-038-apache-dotall)
# ─────────────────────────────────────────────────────────────────────────────

class TestWST038DotallRegression:
    """WST-038 Apache DOTALL 버그수정 회귀 테스트 (KNOWN_BUGS §2 corrected).

    원본 버그: re.IGNORECASE만 사용 → `.`이 개행을 넘지 못해
              멀티라인 Directory 블록에서 FollowSymLinks 미매치 → 거짓 양호.
    수정 후: re.DOTALL | re.IGNORECASE → 멀티라인 블록 정상 매치 → 취약.
    """

    # config 시그니처 충족을 위한 공통 prefix
    _PREFIX = (
        "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    def _raw(self, config_block: str) -> str:
        """config 시그니처를 포함한 WST-038 raw 합성."""
        return self._PREFIX + config_block

    def test_wst038_multiline_followsymlinks_is_vulnerable(self):
        """멀티라인 Directory 블록 + FollowSymLinks → 취약 (DOTALL 버그수정 핵심)."""
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes FollowSymLinks\n"
            "AllowOverride None\n"
            "</Directory>\n"
        )
        fv = judge("WST-038", self._raw(config), "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True, f"WST-038 멀티라인 취약 설정이 handled=False (gate 차단): {fv.rationale}"
        assert fv.verdict == "취약", (
            f"WST-038 멀티라인 FollowSymLinks가 양호 판정 — DOTALL 미수정? verdict={fv.verdict!r}, "
            f"rationale={fv.rationale!r}"
        )

    def test_wst038_singleline_followsymlinks_is_vulnerable(self):
        """단일라인 Directory 블록 + FollowSymLinks → 취약 (기존 동작 불변)."""
        config = '<Directory "/var/www">Options Indexes FollowSymLinks AllowOverride None</Directory>\n'
        fv = judge("WST-038", self._raw(config), "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "취약"

    def test_wst038_clean_block_is_good(self):
        """FollowSymLinks 없는 clean Directory 블록 → 양호."""
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes\n"
            "AllowOverride None\n"
            "Require all granted\n"
            "</Directory>\n"
        )
        fv = judge("WST-038", self._raw(config), "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "양호", f"WST-038 clean 블록이 취약 판정됨: {fv.verdict!r}"

    def test_wst038_multiline_plus_followsymlinks_is_vulnerable(self):
        """+FollowSymLinks(+ 접두어) 멀티라인 블록 → 취약."""
        config = (
            "<Directory /var/www>\n"
            "Options +FollowSymLinks MultiViews\n"
            "</Directory>\n"
        )
        fv = judge("WST-038", self._raw(config), "apache", {})
        assert isinstance(fv, ForcedVerdict)
        assert fv.handled is True
        assert fv.verdict == "취약"

    def test_wst038_vendor_function_direct_multiline(self):
        """벤더 check_WST_038 직접 호출 — 멀티라인 취약 → result='Y'."""
        from judge_tool.vendor.common.webwas.WST_Apache_parse import check_WST_038
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes FollowSymLinks\n"
            "AllowOverride None\n"
            "</Directory>\n"
        )
        result, reason, vul_list = check_WST_038(config)
        assert result == "Y", (
            f"check_WST_038 멀티라인 취약 → result='Y' 기대, 실제: {result!r}\n"
            f"reason: {reason!r}"
        )
        assert len(vul_list) > 0, "취약 시 vul_list에 항목이 있어야 함"

    def test_wst038_vendor_function_direct_clean(self):
        """벤더 check_WST_038 직접 호출 — clean 블록 → result='N'."""
        from judge_tool.vendor.common.webwas.WST_Apache_parse import check_WST_038
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes\n"
            "AllowOverride None\n"
            "</Directory>\n"
        )
        result, reason, vul_list = check_WST_038(config)
        assert result == "N", f"check_WST_038 clean 블록 → result='N' 기대, 실제: {result!r}"
        assert vul_list == [], f"양호 시 vul_list 비어있어야 함: {vul_list}"


# ─────────────────────────────────────────────────────────────────────────────
# (o) F10 오류출력 가드 파급 — server.py 재사용 확인
# (2026-07-03-falsegood-audit.md F10, 백로그 처리)
#
# SRV-* 항목은 server.judge() 위임 경로를 그대로 타므로 F10 가드가 자동 적용된다.
# WST-* 항목은 _map_result가 자체 매핑을 수행하므로 명시적으로 재적용했는지
# 확인한다(judge_tool/det_adapters/webwas.py _has_error_output 재사용).
# ─────────────────────────────────────────────────────────────────────────────

_F10_WEBWAS_ERROR_CASES = [
    ("bash_command_not_found", "-bash: nonexistent_tool: command not found"),
    ("connection_refused", "ssh: connect to host 10.0.0.5 port 22: Connection refused"),
    ("operation_not_permitted", "chattr: Operation not permitted"),
]


class TestF10ErrorOutputGuardPropagation:
    """F10: SRV-* 위임 자동적용 + WST-* 명시 재적용 확인."""

    def _wst033_good_raw(self):
        """WST-033 apache 정당 양호(버전 2.4.x) 합성 픽스처(재사용)."""
        return (
            "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
            "$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
            "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
            f"{DELIMITER}\n"
            "$ rpm -qa httpd\nhttpd not found\n"
            f"{DELIMITER}\n"
            "$ dpkg -l | grep apache\nii  apache2  2.4.52-1ubuntu4.21\n"
            f"{DELIMITER}\n"
            "$ apache2 -v\nServer version: Apache/2.4.52 (Ubuntu)\n"
        )

    def test_srv_star_delegation_guard_auto_applies(self):
        """SRV-082(server 위임) — F10 오류 라인 삽입 시 handled=False로 강등된다
        (server.judge() 위임 경로를 통해 F10 가드가 자동 적용됨을 확인)."""
        raw = (
            "$ ls -alLd /usr /bin /sbin /etc /var\n"
            "drwxr-xr-x  2 root root 4096 Jan  1 00:00 /etc\n"
            "ssh: connect to host 10.0.0.5 port 22: Connection refused\n"
        )
        fv = judge("SRV-082", raw, "linux", {})
        assert fv.handled is False, (
            f"SRV-082 위임 경로에서 F10 가드 미적용 — 거짓양호 위험: {fv}"
        )
        assert fv.verdict == "판단보류"

    @pytest.mark.parametrize(
        "case_id,error_line", _F10_WEBWAS_ERROR_CASES,
        ids=[c[0] for c in _F10_WEBWAS_ERROR_CASES],
    )
    def test_wst_item_error_tokens_handled_false(self, case_id, error_line):
        """WST-033(명령출력 항목) — F10 오류 라인 삽입 시 handled=False로 강등."""
        raw = self._wst033_good_raw() + f"{error_line}\n"
        fv = judge("WST-033", raw, "apache", {})
        assert fv.handled is False, (
            f"[{case_id}] WST-033에서 F10 가드 미발동 — 거짓양호 위험: {fv}"
        )
        assert fv.verdict == "판단보류"

    def test_wst033_normal_good_unaffected(self):
        """오류 토큰 없는 정상 WST-033 양호 입력 → 가드 미발동, 기존 판정 불변."""
        fv = judge("WST-033", self._wst033_good_raw(), "apache", {})
        assert fv.handled is True
        assert fv.verdict == "양호"

    def test_has_error_output_alias_matches_server(self):
        """webwas._has_error_output이 server._has_error_output과 동일 객체(재사용)."""
        from judge_tool.det_adapters import webwas as _webwas
        from judge_tool.det_adapters import server as _server
        assert _webwas._has_error_output is _server._has_error_output


class TestF10ErrorGuardNoOvertriggerWebwas:
    """F10 SHIP 조건: webwas(WEBWAS) 실샘플 corpus 과트리거 0 검증
    (collected/web, out/was_lab)."""

    def _corpus_files(self):
        base = Path(__file__).resolve().parents[1]
        patterns = [
            "collected/web/apache_linux/*.xml",
            "out/was_lab/*.xml",
        ]
        files = []
        for pat in patterns:
            files.extend(sorted(base.glob(pat)))
        return files

    def _corpus_outputs(self):
        from judge_tool.parsers.webwas_xml import parse
        outputs = []
        for x in self._corpus_files():
            for cid, resources, _ in parse(str(x)):
                for r in resources:
                    raw = getattr(r, "raw_evidence", None) or getattr(r, "evidence", None) or ""
                    outputs.append((x.name, cid, raw))
        return outputs

    def test_real_corpus_zero_false_matches(self):
        """실수집 webwas xml 전 항목 raw_output에 F10 가드 오매치 0건."""
        from judge_tool.det_adapters.server import _RE_ERROR_OUTPUT
        outputs = self._corpus_outputs()
        assert outputs, "corpus가 비어 있음 — 과트리거 검증 불가"
        false_matches = [
            (fname, cid, m.group(0))
            for fname, cid, raw in outputs
            if (m := _RE_ERROR_OUTPUT.search(raw))
        ]
        assert false_matches == [], (
            f"실샘플 과트리거 {len(false_matches)}건 — 토큰 재검토 필요: "
            f"{false_matches[:10]}"
        )

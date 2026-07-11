"""DBM-013(원격접속 접근제어) cloud 어댑터 와일드카드 매칭 parity 회귀 테스트.

배경(§F5 falsegood-audit, docs/superpowers/specs/2026-07-03-falsegood-audit.md):
  native 쪽 mysql/mariadb dbm_013은 R-MY013/R-MA013(VENDOR-EDIT)으로
  `'%' in HOST or '_' in HOST` 포함매칭으로 수정되어 '10.%', '%.corp.com' 같은
  부분 와일드카드 광역허용도 취약으로 잡는다. 그러나 cloud 어댑터
  (mysql/mariadb cloud_analysis.py)는 미반영 상태였다 — `HOST in ['%']` 정확일치만
  검사해 rds/aurora/azure에서 부분 와일드카드 Host가 양호로 새는 거짓양호가 있었다.

이 파일은 그 parity 수정(R-MY013-CLOUD/R-MA013-CLOUD)을 핀고정한다:
  1. cloud에서 '10.%'/'%.corp.com' 부분 와일드카드 → 취약
  2. cloud에서 HOST='%' 전체 와일드카드 → 취약 (기존 회귀 불변)
  3. cloud에서 특정 IP/localhost → 양호 (과탐 아님)
  4. native와 cloud 판정 일치(parity) — 같은 입력에 대해 같은 verdict
  5. 과탐 의도 고정: HOST='%' 전체 와일드카드나 관리 계정(root)이 취약으로
     뜨는 것은 스펙상 안전방향(과탐)이며 버그가 아니다.

⚠️ 범위: judge_tool/det_adapters/db.py, item_configs/*.yaml, DET_SOURCE.yaml,
tests/db_cov_contract.py, tests/test_det_adapters_db.py는 이 작업에서 수정하지 않는다
(다른 에이전트 병렬 작업 영역). 이 파일은 신규 파일이며 기존 테스트를 건드리지 않는다.
"""
import json
import os

import judge_tool.det_adapters.db  # noqa: F401 — 어댑터 레지스트리 등록 부작용
from judge_tool.det_adapters.db import judge, _RUN_CACHE

_CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "judge_tool", "vendor", "common", "db", "config",
)


def _load_config(engine: str) -> dict:
    with open(os.path.join(_CONFIG_DIR, f"{engine}-config.json"), encoding="utf-8") as f:
        return json.load(f)


def _real_violations(violations):
    """Note/NOTE 잡음 행({@@@:...} / {***:...})을 제외한 실제 위반행만."""
    return [v for v in violations if "***" not in v and "@@@" not in v]


def _run_mysql_cloud(rows):
    from judge_tool.vendor.common.db.mysql.cloud_analysis import MySQLCloudAnalysis
    config = _load_config("mysql")
    data = {"DBM-013": {"RESULT": rows}}
    result = MySQLCloudAnalysis(config, data).run
    return _real_violations(result.get("DBM-013", []))


def _run_mariadb_cloud(rows):
    from judge_tool.vendor.common.db.mariadb.cloud_analysis import MariaDBCloudAnalysis
    config = _load_config("mariadb")
    data = {"DBM-013": {"RESULT": rows}}
    result = MariaDBCloudAnalysis(config, data).run
    return _real_violations(result.get("DBM-013", []))


def _run_mysql_native(rows):
    from judge_tool.vendor.common.db.mysql.analysis import MySQLAnalysis
    config = _load_config("mysql")
    data = {"DBM-013": {"RESULT": rows}}
    result = MySQLAnalysis(config, data).run
    return _real_violations(result.get("DBM-013", []))


def _run_mariadb_native(rows):
    from judge_tool.vendor.common.db.mariadb.analysis import MariaDBAnalysis
    config = _load_config("mariadb")
    data = {"DBM-013": {"RESULT": rows}}
    result = MariaDBAnalysis(config, data).run
    return _real_violations(result.get("DBM-013", []))


def _make_raw(rows):
    return json.dumps({"DBM-013": {"RESULT": rows}}, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────────────────────
# 1) mysql cloud — 부분 와일드카드 거짓양호 갭 차단 (직접 class 단위)
# ─────────────────────────────────────────────────────────────────────────────

class TestMySQLCloudDBM013Wildcard:

    def test_subnet_wildcard_is_vuln(self):
        """cloud: HOST='10.%' 서브넷 와일드카드 → 취약 (수정 전: 거짓양호)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "10.%"}])
        assert len(violations) > 0, (
            "mysql cloud HOST='10.%'인데 위반 미포함 — parity 미수정(거짓양호)"
        )

    def test_domain_wildcard_is_vuln(self):
        """cloud: HOST='%.corp.com' 도메인 와일드카드 → 취약 (수정 전: 거짓양호)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "%.corp.com"}])
        assert len(violations) > 0, (
            "mysql cloud HOST='%.corp.com'인데 위반 미포함 — parity 미수정(거짓양호)"
        )

    def test_full_wildcard_is_vuln_regression(self):
        """cloud: HOST='%' 전체 와일드카드 → 취약 (기존 회귀, 정확매칭에서도 잡히던 케이스)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "%"}])
        assert len(violations) > 0, (
            "mysql cloud HOST='%'인데 위반 미포함 — 기존 회귀 깨짐"
        )

    def test_underscore_wildcard_is_vuln(self):
        """cloud: HOST='10.0.0._' 단일문자 와일드카드 → 취약 (native parity)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "10.0.0._"}])
        assert len(violations) > 0, (
            "mysql cloud HOST='10.0.0._'인데 위반 미포함 — '_' 와일드카드 parity 미수정"
        )

    def test_specific_ip_is_good(self):
        """cloud: HOST='192.168.1.50' 특정 IP → 양호 (과탐 아님)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "192.168.1.50"}])
        assert len(violations) == 0, (
            f"mysql cloud HOST='192.168.1.50'인데 위반 포함 — 과탐: {violations}"
        )

    def test_localhost_is_good(self):
        """cloud: HOST='localhost' → 양호 (과탐 아님)."""
        violations = _run_mysql_cloud([{"USER": "app_user", "HOST": "localhost"}])
        assert len(violations) == 0, (
            f"mysql cloud HOST='localhost'인데 위반 포함 — 과탐: {violations}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2) mariadb cloud — 부분 와일드카드 거짓양호 갭 차단 (직접 class 단위)
# ─────────────────────────────────────────────────────────────────────────────

class TestMariaDBCloudDBM013Wildcard:

    def test_subnet_wildcard_is_vuln(self):
        """cloud: HOST='10.%' 서브넷 와일드카드 → 취약 (수정 전: 거짓양호)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "10.%"}])
        assert len(violations) > 0, (
            "mariadb cloud HOST='10.%'인데 위반 미포함 — parity 미수정(거짓양호)"
        )

    def test_domain_wildcard_is_vuln(self):
        """cloud: HOST='%.corp.com' 도메인 와일드카드 → 취약 (수정 전: 거짓양호)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "%.corp.com"}])
        assert len(violations) > 0, (
            "mariadb cloud HOST='%.corp.com'인데 위반 미포함 — parity 미수정(거짓양호)"
        )

    def test_full_wildcard_is_vuln_regression(self):
        """cloud: HOST='%' 전체 와일드카드 → 취약 (기존 회귀)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "%"}])
        assert len(violations) > 0, (
            "mariadb cloud HOST='%'인데 위반 미포함 — 기존 회귀 깨짐"
        )

    def test_underscore_wildcard_is_vuln(self):
        """cloud: HOST='10.0.0._' 단일문자 와일드카드 → 취약 (native parity)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "10.0.0._"}])
        assert len(violations) > 0, (
            "mariadb cloud HOST='10.0.0._'인데 위반 미포함 — '_' 와일드카드 parity 미수정"
        )

    def test_specific_ip_is_good(self):
        """cloud: HOST='192.168.1.50' 특정 IP → 양호 (과탐 아님)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "192.168.1.50"}])
        assert len(violations) == 0, (
            f"mariadb cloud HOST='192.168.1.50'인데 위반 포함 — 과탐: {violations}"
        )

    def test_localhost_is_good(self):
        """cloud: HOST='localhost' → 양호 (과탐 아님)."""
        violations = _run_mariadb_cloud([{"USER": "app_user", "HOST": "localhost"}])
        assert len(violations) == 0, (
            f"mariadb cloud HOST='localhost'인데 위반 포함 — 과탐: {violations}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3) native ↔ cloud parity — 동일 입력에 대해 동일 판정(위반 유무)
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM013NativeCloudParity:
    """같은 HOST 입력에 대해 native와 cloud가 같은 취약/양호 판정을 내려야 한다."""

    _CASES = [
        ("10.%", True),
        ("%.corp.com", True),
        ("%", True),
        ("10.0.0._", True),
        ("192.168.1.50", False),
        ("localhost", False),
    ]

    def test_mysql_native_cloud_parity(self):
        for host, expect_vuln in self._CASES:
            rows = [{"USER": "app_user", "HOST": host}]
            native_v = len(_run_mysql_native(rows)) > 0
            cloud_v = len(_run_mysql_cloud(rows)) > 0
            assert native_v == expect_vuln, (
                f"mysql native HOST={host!r}: 기대 취약={expect_vuln}, 실제={native_v}"
            )
            assert cloud_v == expect_vuln, (
                f"mysql cloud HOST={host!r}: 기대 취약={expect_vuln}, 실제={cloud_v}"
            )
            assert native_v == cloud_v, (
                f"mysql native/cloud parity 불일치 HOST={host!r}: "
                f"native={native_v} cloud={cloud_v}"
            )

    def test_mariadb_native_cloud_parity(self):
        for host, expect_vuln in self._CASES:
            rows = [{"USER": "app_user", "HOST": host}]
            native_v = len(_run_mariadb_native(rows)) > 0
            cloud_v = len(_run_mariadb_cloud(rows)) > 0
            assert native_v == expect_vuln, (
                f"mariadb native HOST={host!r}: 기대 취약={expect_vuln}, 실제={native_v}"
            )
            assert cloud_v == expect_vuln, (
                f"mariadb cloud HOST={host!r}: 기대 취약={expect_vuln}, 실제={cloud_v}"
            )
            assert native_v == cloud_v, (
                f"mariadb native/cloud parity 불일치 HOST={host!r}: "
                f"native={native_v} cloud={cloud_v}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 4) judge() 어댑터 레벨 — cloud variant(mysql_rds/aurora/azure, mariadb_rds) 취약 판정
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM013CloudAdapterJudge:
    """DET_SOURCE.yaml: mysql_rds/mysql_aurora/mysql_azure/mariadb_rds DBM-013 = DET
    (gate 통과) → cloud_analysis.dbm_013 결과로 judge() verdict 확정.
    """

    def setup_method(self):
        _RUN_CACHE.clear()

    def test_mysql_rds_subnet_wildcard_is_vuln(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "10.%"}])
        fv = judge("DBM-013", raw, "mysql_rds", {})
        assert fv.handled is True, f"mysql_rds DBM-013 DET인데 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mysql_rds DBM-013 HOST='10.%'인데 취약이 아님 — 거짓양호: {fv}"
        )

    def test_mysql_aurora_domain_wildcard_is_vuln(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "%.corp.com"}])
        fv = judge("DBM-013", raw, "mysql_aurora", {})
        assert fv.handled is True, f"mysql_aurora DBM-013 DET인데 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mysql_aurora DBM-013 HOST='%.corp.com'인데 취약이 아님 — 거짓양호: {fv}"
        )

    def test_mysql_azure_subnet_wildcard_is_vuln(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "10.%"}])
        fv = judge("DBM-013", raw, "mysql_azure", {})
        assert fv.handled is True, f"mysql_azure DBM-013 DET인데 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mysql_azure DBM-013 HOST='10.%'인데 취약이 아님 — 거짓양호: {fv}"
        )

    def test_mariadb_rds_domain_wildcard_is_vuln(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "%.corp.com"}])
        fv = judge("DBM-013", raw, "mariadb_rds", {})
        assert fv.handled is True, f"mariadb_rds DBM-013 DET인데 handled=False: {fv}"
        assert fv.verdict == "취약", (
            f"mariadb_rds DBM-013 HOST='%.corp.com'인데 취약이 아님 — 거짓양호: {fv}"
        )

    def test_mysql_rds_specific_ip_is_good(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "192.168.1.50"}])
        fv = judge("DBM-013", raw, "mysql_rds", {})
        assert fv.handled is True
        assert fv.verdict == "양호", (
            f"mysql_rds DBM-013 특정IP인데 양호가 아님 — 과탐: {fv}"
        )

    def test_mariadb_rds_localhost_is_good(self):
        raw = _make_raw([{"USER": "app_user", "HOST": "localhost"}])
        fv = judge("DBM-013", raw, "mariadb_rds", {})
        assert fv.handled is True
        assert fv.verdict == "양호", (
            f"mariadb_rds DBM-013 localhost인데 양호가 아님 — 과탐: {fv}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5) 과탐(overtrigger) 논점 — 스펙 명시 의도 고정 (§F5 설계: 안전방향)
# ─────────────────────────────────────────────────────────────────────────────

class TestDBM013CloudOvertriggerIsIntentional:
    """HOST='%' 전체 와일드카드나 관리계정(root)이 cloud에서 취약으로 뜨는 것은
    §F5 설계 스펙에 명시된 안전방향(과탐) 의도이며 버그가 아니다.
    (native R-MY013/R-MA013 VENDOR-EDIT(b) — exception USER 비움 — 과 동일 정책을
    cloud도 공유 config를 통해 그대로 물려받는다.)
    """

    def test_mysql_cloud_root_wildcard_is_vuln_by_design(self):
        """cloud: root@% → 취약(의도된 과탐 — 관리계정도 면제하지 않음)."""
        violations = _run_mysql_cloud([{"USER": "root", "HOST": "%"}])
        assert len(violations) > 0, (
            "mysql cloud root@%가 양호로 처리됨 — §F5 안전방향 의도 위반"
        )

    def test_mariadb_cloud_root_wildcard_is_vuln_by_design(self):
        """cloud: root@% → 취약(의도된 과탐)."""
        violations = _run_mariadb_cloud([{"USER": "root", "HOST": "%"}])
        assert len(violations) > 0, (
            "mariadb cloud root@%가 양호로 처리됨 — §F5 안전방향 의도 위반"
        )

    def test_mysql_cloud_root_localhost_still_good(self):
        """관리계정이라도 와일드카드가 없으면(root@localhost) 양호 — 과탐이 무제한은 아님."""
        violations = _run_mysql_cloud([{"USER": "root", "HOST": "localhost"}])
        assert len(violations) == 0, (
            f"mysql cloud root@localhost인데 위반 포함 — 과잉 과탐: {violations}"
        )

    def test_mysql_rds_full_wildcard_admin_via_judge_is_vuln(self):
        """judge() 레벨: mysql_rds DBM-013 root@% → 취약(안전방향 의도 고정)."""
        _RUN_CACHE.clear()
        raw = _make_raw([{"USER": "root", "HOST": "%"}])
        fv = judge("DBM-013", raw, "mysql_rds", {})
        assert fv.verdict == "취약", (
            f"mysql_rds DBM-013 root@%인데 취약이 아님 — 안전방향 의도 미고정: {fv}"
        )

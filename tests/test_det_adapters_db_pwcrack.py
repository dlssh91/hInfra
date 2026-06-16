"""DBM-001 사전공격 결정론 어댑터 단위 테스트 — Phase 4c (b 레이어 + a 레이어).

검증 항목:
  §A KAT: 포맷별 verifier generate∘verify 라운드트립 + 외부표준
    - mysql_native: *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 (공개 표준값)
    - mssql 0x0200: self-roundtrip
    - postgres SCRAM-SHA-256: self-roundtrip
    - postgres md5: self-roundtrip
    - oracle 11g: self-roundtrip
    - caching_sha2: 비활성 (외부 KAT 미확보)
  §B 사전매치 → 취약
  §C 강한 비번 미스 → 판단보류 (handled=True, needs_review 아님이지만 ev=review)
  §D 빈 해시 → 취약, 잠금 빈 해시 → 스킵
  §E §7 평문 비노출 (weak pw 사용 케이스에서 평문이 출력 어디에도 없음)
  §F 증거가드: data_key 없음 → handled=False / RESULT 빔 → handled=False
  §G 실데이터 native 5엔진 스모크: 오류없음, 거짓취약 0, oracle handled=False
  §H 계정명 중복 제거 (같은 해시, 다른 HOST)
  §I mysql caching_sha2: 비활성 → 미지원포맷으로 처리
  §J Phase 4c-a hashcat 연동: mock, graceful-skip, export, §7, timeout, cleanup
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile

import pytest

# ── 프로젝트 루트 경로 설정 ────────────────────────────────────────────────────
_PROJ = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from judge_tool.det_adapters.db_pwcrack import (
    _verify_mysql_native,
    _generate_mysql_native,
    _verify_mssql,
    _generate_mssql_0200,
    _verify_postgres_scram,
    _generate_postgres_scram,
    _verify_postgres_md5,
    _generate_postgres_md5,
    _verify_oracle_11g,
    _generate_oracle_11g,
    _parse_mariadb_accounts,
    _parse_mysql_accounts,
    _parse_mssql_accounts,
    _parse_postgres_accounts,
    _parse_postgres_row,
    _parse_oracle_accounts,
    _crack_accounts,
    crack_judge,
    AccountInfo,
    _CACHING_SHA2_ENABLED,
    _MYSQL_PLACEHOLDER,
    # Phase 4c-a
    HashcatOpts,
    export_for_external,
    run_hashcat,
    _detect_hashcat,
    _HASHCAT_MODE,
    _normalize_hash,
    set_hashcat_opts,
    clear_hashcat_opts,
)
from judge_tool.det_adapters.base import ForcedVerdict

# ── 실데이터 경로 ─────────────────────────────────────────────────────────────
_DB_BASE = os.path.join(_PROJ, "collected", "db")
_MARIADB_NATIVE = os.path.join(_DB_BASE, "mariadb_native", "mariadb_native_result.json")
_MYSQL_NATIVE = os.path.join(_DB_BASE, "mysql_native", "mysql_native_result.json")
_MSSQL_NATIVE = os.path.join(_DB_BASE, "mssql_native", "mssql_native_result.json")
_PG_NATIVE = os.path.join(_DB_BASE, "postgresql_native", "postgresql_native_result.json")
_ORACLE_NATIVE = os.path.join(_DB_BASE, "oracle_native", "oracle_native_result.json")

_ALL_NATIVE_EXIST = all(
    os.path.exists(p) for p in [
        _MARIADB_NATIVE, _MYSQL_NATIVE, _MSSQL_NATIVE, _PG_NATIVE, _ORACLE_NATIVE
    ]
)


def _load_real_data(path: str) -> dict:
    """실데이터 파일 → db_json 파서를 거쳐 비마스킹 data dict 반환."""
    from judge_tool.parsers.db_json import _build_raw_data_dict, _strip_leading_noise
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    arr = _strip_leading_noise(raw)
    json_str = _build_raw_data_dict(arr)
    assert json_str is not None, f"_build_raw_data_dict 반환 None: {path}"
    return json.loads(json_str)


# ══════════════════════════════════════════════════════════════════════════════
# §A KAT — 포맷별 verifier KAT 단위 테스트
# ══════════════════════════════════════════════════════════════════════════════

class TestKATMysqlNative:
    """mysql_native_password (*SHA1(SHA1(pw))) KAT."""

    def test_external_kat_password(self):
        """외부 표준 KAT: 'password' → *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19.

        출처: MySQL 공식 문서 및 다수 공개 검증.
        """
        expected = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
        assert _generate_mysql_native("password") == expected
        assert _verify_mysql_native("password", expected) is True
        assert _verify_mysql_native("wrongpassword", expected) is False

    def test_roundtrip_various(self):
        """다양한 평문 generate∘verify 라운드트립."""
        for pw in ["admin", "root", "", "P@ssw0rd123!", "한글비번"]:
            h = _generate_mysql_native(pw)
            assert h.startswith("*"), f"해시가 *로 시작해야 함: {h}"
            assert len(h) == 41, f"해시 길이 41이어야 함: {len(h)}"
            assert _verify_mysql_native(pw, h) is True, f"라운드트립 실패: {repr(pw)}"

    def test_wrong_password_fails(self):
        """잘못된 비밀번호 → False."""
        h = _generate_mysql_native("correct_password")
        assert _verify_mysql_native("wrong_password", h) is False

    def test_empty_hash_fails(self):
        """빈 문자열 해시 → False (빈 해시는 별도 분기에서 처리)."""
        assert _verify_mysql_native("password", "") is False

    def test_malformed_hash_fails(self):
        """잘못된 형식 → False."""
        assert _verify_mysql_native("password", "ABCDEF") is False
        assert _verify_mysql_native("password", "*TOOLONG" + "A" * 40) is False


class TestKATMssql:
    """MSSQL 0x0200 (SHA512) 및 0x0100 (SHA1 구형) KAT."""

    def test_0x0200_roundtrip(self):
        """0x0200 generate∘verify 라운드트립 (salt 4bytes)."""
        salt = bytes.fromhex("AABBCCDD")
        pw = "TestPassword123!"
        h = _generate_mssql_0200(pw, salt)
        assert h.upper().startswith("0X0200")
        assert len(h) == 2 + 140  # "0x" + 140 hex chars (70 bytes)
        assert _verify_mssql(pw, h) is True
        assert _verify_mssql("wrongpassword", h) is False

    def test_0x0200_case_insensitive(self):
        """0x0200 해시는 대소문자 무관하게 검증."""
        salt = bytes.fromhex("11223344")
        pw = "admin123"
        h = _generate_mssql_0200(pw, salt)
        assert _verify_mssql(pw, h.lower()) is True
        assert _verify_mssql(pw, h.upper()) is True

    def test_0x0200_utf16le_encoding(self):
        """UTF-16LE 인코딩 확인 — 동일 비번이라도 다른 인코딩이면 불일치."""
        salt = bytes.fromhex("CAFEBABE")
        pw = "TestPw"
        h = _generate_mssql_0200(pw, salt)
        # UTF-16LE + salt의 SHA512 직접 계산
        hx = bytes.fromhex(h[2:])
        salt_extracted = hx[2:6]
        computed = hashlib.sha512(pw.encode("utf-16-le") + salt_extracted).digest()
        stored = hx[6:70]
        assert hmac.compare_digest(computed, stored)

    def test_unknown_version_fails(self):
        """미지원 version 프리픽스 → False."""
        assert _verify_mssql("password", "0x0300AABBCCDD" + "A" * 100) is False
        assert _verify_mssql("password", "invalid") is False
        assert _verify_mssql("password", "") is False

    def test_multiple_roundtrips(self):
        """다양한 패스워드 라운드트립."""
        for pw in ["", "sa", "Password123", "Admin@123"]:
            salt = hashlib.sha1(pw.encode()).digest()[:4]
            h = _generate_mssql_0200(pw, salt)
            assert _verify_mssql(pw, h) is True


class TestKATPostgresScram:
    """PostgreSQL SCRAM-SHA-256 KAT (RFC 5802 + self-roundtrip)."""

    def test_roundtrip_basic(self):
        """self-roundtrip: generate∘verify."""
        import os
        salt = os.urandom(16)
        pw = "scram_test_pw"
        h = _generate_postgres_scram(pw, salt)
        assert h.startswith("SCRAM-SHA-256$")
        assert _verify_postgres_scram(pw, h) is True
        assert _verify_postgres_scram("wrongpw", h) is False

    def test_roundtrip_empty_password(self):
        """빈 비밀번호 라운드트립."""
        import os
        salt = os.urandom(16)
        h = _generate_postgres_scram("", salt)
        assert _verify_postgres_scram("", h) is True
        assert _verify_postgres_scram("a", h) is False

    def test_various_iterations(self):
        """다양한 반복 횟수 라운드트립."""
        import os
        salt = os.urandom(16)
        for iters in [1000, 4096, 10000]:
            h = _generate_postgres_scram("pw", salt, iters)
            assert _verify_postgres_scram("pw", h) is True

    def test_rfc5802_scram_sha256_server_key(self):
        """RFC 7677 SCRAM-SHA-256 알고리즘 확인.

        PBKDF2-SHA256(pw, salt, 4096) → ServerKey = HMAC(SaltedPw, 'Server Key')
        자체 계산값과 verifier 결과 일치 확인.
        """
        pw = "pencil"
        salt = base64.b64decode("QSXCR+Q6sek8bf92")
        iterations = 4096
        # 알고리즘 직접 계산
        salted_pw = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
        server_key = hmac.new(salted_pw, b"Server Key", "sha256").digest()
        client_key = hmac.new(salted_pw, b"Client Key", "sha256").digest()
        stored_key = hashlib.sha256(client_key).digest()
        h = (
            f"SCRAM-SHA-256${iterations}:{base64.b64encode(salt).decode()}"
            f"${base64.b64encode(stored_key).decode()}:{base64.b64encode(server_key).decode()}"
        )
        # verifier 적용
        assert _verify_postgres_scram(pw, h) is True
        assert _verify_postgres_scram("wrong", h) is False

    def test_malformed_hash_fails(self):
        """잘못된 형식 → False."""
        assert _verify_postgres_scram("pw", "notscram") is False
        assert _verify_postgres_scram("pw", "SCRAM-SHA-256$malformed") is False
        assert _verify_postgres_scram("pw", "") is False


class TestKATPostgresMd5:
    """PostgreSQL md5 (md5(pw+rolname)) KAT."""

    def test_roundtrip_with_rolname(self):
        """rolname 포함 md5 라운드트립."""
        pw, rolname = "mypassword", "postgres"
        h = _generate_postgres_md5(pw, rolname)
        assert h.startswith("md5")
        assert len(h) == 35
        assert _verify_postgres_md5(pw, h, rolname) is True
        assert _verify_postgres_md5("wrongpw", h, rolname) is False
        assert _verify_postgres_md5(pw, h, "wronguser") is False

    def test_roundtrip_empty_password(self):
        """빈 비밀번호 md5."""
        h = _generate_postgres_md5("", "postgres")
        assert _verify_postgres_md5("", h, "postgres") is True
        assert _verify_postgres_md5("a", h, "postgres") is False

    def test_malformed_fails(self):
        """잘못된 형식 → False."""
        assert _verify_postgres_md5("pw", "notmd5xxx", "r") is False
        assert _verify_postgres_md5("pw", "md5" + "X" * 30, "r") is False  # 길이 오류
        assert _verify_postgres_md5("pw", "", "r") is False


class TestKATOracle11g:
    """Oracle 11g S: (SHA1+salt) KAT.

    Oracle 11g 형식: S:<40HEX_hash><20HEX_salt> (총 60 hex chars after S:)
    salt는 10bytes (20 hex chars) 가 표준.

    알고리즘(교정 후): SHA1(pw.encode('utf-8') + salt) — 대소문자 보존, raw UTF-8.
    Phase 4c Opus 리뷰 Critical-1: 이전 오류(UPPER+UTF-16BE) 수정.

    외부벡터 출처: passlib oracle11 테스트 벡터
      pw='password', S:=S:4143053633E59B4992A8EA17D2FF542C9EDEB335C886EED9C80450C1B4E6
    """

    # passlib 공식 외부벡터
    _EXT_PW = "password"
    _EXT_STORED = "S:4143053633E59B4992A8EA17D2FF542C9EDEB335C886EED9C80450C1B4E6"
    # hash_hex = "4143053633E59B4992A8EA17D2FF542C9EDEB335", salt_hex = "C886EED9C80450C1B4E6"

    def test_external_kat_passlib_vector(self):
        """passlib 외부벡터: pw='password' → verify=True.

        SHA1(b'password' + unhexlify('C886EED9C80450C1B4E6')).upper()
        == '4143053633E59B4992A8EA17D2FF542C9EDEB335'
        교정 전(UPPER+UTF-16BE): False → 교정 후(UTF-8 보존): True.
        """
        assert _verify_oracle_11g(self._EXT_PW, self._EXT_STORED) is True, (
            "passlib 외부벡터 검증 실패: SHA1(pw.utf-8 + salt) 알고리즘이 다름"
        )

    def test_external_kat_wrong_password_fails(self):
        """passlib 외부벡터: 틀린 비번 → verify=False."""
        assert _verify_oracle_11g("wrongpassword", self._EXT_STORED) is False
        assert _verify_oracle_11g("Password", self._EXT_STORED) is False
        assert _verify_oracle_11g("PASSWORD", self._EXT_STORED) is False

    def test_external_kat_generate_matches_stored(self):
        """generate로 생성한 해시가 외부벡터 stored 값과 일치."""
        import binascii
        salt = binascii.unhexlify("C886EED9C80450C1B4E6")
        generated = _generate_oracle_11g(self._EXT_PW, salt)
        assert generated.upper() == self._EXT_STORED.upper(), (
            f"생성 해시가 외부벡터와 불일치: {generated} != {self._EXT_STORED}"
        )

    def test_roundtrip(self):
        """self-roundtrip: generate∘verify (10-byte salt)."""
        salt = bytes.fromhex("AABBCCDDEEFF00112233")  # 10 bytes = 20 hex
        pw = "oracle123"
        h = _generate_oracle_11g(pw, salt)
        assert h.upper().startswith("S:")
        assert len(h) == 62, f"S: + 60 hex = 62 chars. got {len(h)}"
        assert _verify_oracle_11g(pw, h) is True
        assert _verify_oracle_11g("wrongpw", h) is False

    def test_case_sensitive_password(self):
        """Oracle 11g: 대소문자 구분 — 'password' ≠ 'PASSWORD'.

        교정 후 알고리즘은 UPPER 없이 UTF-8 그대로 사용하므로 대소문자 구분.
        """
        salt = bytes.fromhex("1122334455667788AABB")  # 10 bytes
        h_lower = _generate_oracle_11g("password", salt)
        h_upper = _generate_oracle_11g("PASSWORD", salt)
        # 대소문자 보존이므로 해시가 달라야 함
        assert h_lower != h_upper, (
            "Oracle 11g 교정 후: 대소문자 구분이어야 하나 동일 해시 생성됨"
        )
        assert _verify_oracle_11g("password", h_lower) is True
        assert _verify_oracle_11g("PASSWORD", h_lower) is False
        assert _verify_oracle_11g("PASSWORD", h_upper) is True
        assert _verify_oracle_11g("password", h_upper) is False

    def test_malformed_fails(self):
        """잘못된 형식 → False."""
        assert _verify_oracle_11g("pw", "T:invalidformat") is False
        assert _verify_oracle_11g("pw", "S:TOOSHORT") is False
        assert _verify_oracle_11g("pw", "") is False

    def test_roundtrip_multiple(self):
        """다양한 패스워드 라운드트립 (10-byte salt)."""
        for pw in ["sys", "change_on_install", "oracle123", "manager"]:
            # 10-byte salt: sha1(pw.utf-8)[:10]
            salt = hashlib.sha1(pw.encode()).digest()[:10]
            h = _generate_oracle_11g(pw, salt)
            assert _verify_oracle_11g(pw, h) is True, f"라운드트립 실패: {repr(pw)}"


class TestCachingSha2Disabled:
    """caching_sha2_password: 비활성 확인 (외부 KAT 미확보)."""

    def test_flag_is_disabled(self):
        """_CACHING_SHA2_ENABLED는 False여야 함 (외부 KAT 없음)."""
        assert _CACHING_SHA2_ENABLED is False

    def test_mysql_caching_sha2_marked_unsupported(self):
        """caching_sha2_password 계정은 unsupported_format=True로 마킹됨."""
        rows = [
            {
                "USER": "root",
                "AUTHENTICATION_STRING": "$A$005$somesalt",
                "PLUGIN": "caching_sha2_password",
                "ACCOUNT_LOCKED": "N",
                "HOST": "localhost",
            }
        ]
        accounts = _parse_mysql_accounts(rows)
        assert len(accounts) == 1
        assert accounts[0].unsupported_format is True

    def test_mysql_caching_sha2_placeholder_skipped(self):
        """THISISACOMBINATION... placeholder 해시 계정은 파싱 시 완전 제외."""
        rows = [
            {
                "USER": "mysql.sys",
                "AUTHENTICATION_STRING": "$A$005$" + _MYSQL_PLACEHOLDER,
                "PLUGIN": "caching_sha2_password",
                "ACCOUNT_LOCKED": "Y",
                "HOST": "localhost",
            }
        ]
        # placeholder가 있으므로 파싱에서 제외
        accounts = _parse_mysql_accounts(rows)
        assert len(accounts) == 0


# ══════════════════════════════════════════════════════════════════════════════
# §B 사전매치 → 취약
# ══════════════════════════════════════════════════════════════════════════════

class TestDictMatchVulnerable:
    """사전 매치 → 취약 판정."""

    def _make_data_with_mariadb_hash(self, pw: str, user: str = "root") -> dict:
        h = _generate_mysql_native(pw)
        return {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost",
                        "USER": user,
                        "PASSWORD": h,
                        "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }

    def test_mariadb_weak_password_detected(self):
        """mariadb: 사전에 있는 비번('password') → 취약."""
        data = self._make_data_with_mariadb_hash("password", "root")
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.verdict == "취약"
        assert fv.handled is True
        assert fv.confidence == 0.9
        assert any("root" in c for c in fv.citations)

    def test_mariadb_admin_default_detected(self):
        """mariadb: 'admin' 계정에 'admin' 비번 → 취약."""
        data = self._make_data_with_mariadb_hash("admin", "admin")
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.verdict == "취약"
        assert fv.confidence == 0.9

    def test_mssql_weak_password_detected(self):
        """mssql: 사전에 있는 비번 → 취약."""
        salt = bytes.fromhex("AABBCCDD")
        h = _generate_mssql_0200("Password123", salt)
        data = {
            "DBM-001": {
                "RESULT": [
                    {"name": "sa", "password_hash": h, "is_disabled": "0"}
                ]
            }
        }
        fv = crack_judge("mssql", data, "mssql_native")
        assert fv.verdict == "취약"
        assert fv.handled is True
        assert any("sa" in c for c in fv.citations)

    def test_postgres_scram_weak_detected(self):
        """postgres: SCRAM 해시 약한 비번 → 취약."""
        import os
        salt = os.urandom(16)
        h = _generate_postgres_scram("postgres", salt)
        raw = f'{{"rolname": \'postgres\', "rolpassword" : \'{h}\'}}'
        data = {
            "DBM-001_1": {"RESULT": [{"setting_name": "password_encryption", "value": "scram-sha-256"}]},
            "DBM-001_2": {"RESULT": [{"*": raw}]},
        }
        fv = crack_judge("postgresql", data, "pg_native")
        assert fv.verdict == "취약"
        assert fv.handled is True

    def test_postgres_md5_weak_detected(self):
        """postgres: md5 해시 약한 비번 → 취약."""
        h = _generate_postgres_md5("postgres", "postgres")
        raw = f'{{"rolname": \'postgres\', "rolpassword" : \'{h}\'}}'
        data = {
            "DBM-001_1": {"RESULT": [{"setting_name": "password_encryption", "value": "md5"}]},
            "DBM-001_2": {"RESULT": [{"*": raw}]},
        }
        fv = crack_judge("postgresql", data, "pg_native")
        assert fv.verdict == "취약"
        assert fv.handled is True


# ══════════════════════════════════════════════════════════════════════════════
# §C 강한 비번 미스 → 판단보류
# ══════════════════════════════════════════════════════════════════════════════

class TestStrongPasswordPending:
    """사전 미매치 → 판단보류 (handled=True, ev=review)."""

    STRONG_PW = "Str0ngP@ss!xyz#2026_notInDict"

    def test_mariadb_strong_password_pending(self):
        """mariadb: 사전에 없는 강한 비번 → 판단보류."""
        h = _generate_mysql_native(self.STRONG_PW)
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.verdict == "판단보류"
        assert fv.handled is True  # crack_judge가 처리했음
        assert fv.confidence == 0.0
        assert fv.ev_status == "review"

    def test_mssql_strong_password_pending(self):
        """mssql: 사전에 없는 강한 비번 → 판단보류."""
        salt = bytes.fromhex("DEADBEEF")
        h = _generate_mssql_0200(self.STRONG_PW, salt)
        data = {
            "DBM-001": {
                "RESULT": [
                    {"name": "sa", "password_hash": h, "is_disabled": "0"}
                ]
            }
        }
        fv = crack_judge("mssql", data, "mssql_native")
        assert fv.verdict == "판단보류"
        assert fv.handled is True


# ══════════════════════════════════════════════════════════════════════════════
# §D 빈 해시 처리
# ══════════════════════════════════════════════════════════════════════════════

class TestEmptyHash:
    """빈 해시 → 취약, 잠금/만료 계정 빈 해시 → 스킵."""

    def test_mariadb_empty_hash_vulnerable(self):
        """mariadb: 빈 PASSWORD + 미잠금 → 취약 (비밀번호 미설정)."""
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": "", "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.verdict == "취약"
        assert any("비밀번호 미설정" in c for c in fv.citations)

    def test_mariadb_empty_hash_expired_skipped(self):
        """mariadb: 빈 PASSWORD + PASSWORD_EXPIRED=Y → 스킵 (mariadb.sys 패턴).

        잠금/만료 계정의 빈 해시는 거짓취약 방지를 위해 스킵한다.
        """
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "mariadb.sys",
                        "PASSWORD": "", "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "Y",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native")
        # 잠금/만료 계정만 있고 모두 스킵 → 계정 없음 → handled=False
        assert fv.verdict != "취약", (
            "mariadb.sys(만료) 빈 해시가 취약으로 판정됨 — 거짓취약 (§D)"
        )

    def test_mssql_disabled_account_skipped(self):
        """mssql: is_disabled=1 → 잠금 → 사전공격 스킵."""
        salt = bytes.fromhex("AABBCCDD")
        h = _generate_mssql_0200("password", salt)
        data = {
            "DBM-001": {
                "RESULT": [
                    {"name": "##MS_Internal##", "password_hash": h, "is_disabled": "1"}
                ]
            }
        }
        fv = crack_judge("mssql", data, "mssql_native")
        # 비활성 계정만 있으면 크랙 스킵 → 미매치 → 판단보류
        assert fv.verdict != "취약", (
            "비활성 mssql 계정이 취약으로 판정됨 — 거짓취약 (§D)"
        )

    def test_mysql_locked_account_empty_hash_skipped(self):
        """mysql: ACCOUNT_LOCKED=Y 빈 해시 → 스킵."""
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "mysql.session",
                        "AUTHENTICATION_STRING": "",
                        "PLUGIN": "mysql_native_password",
                        "ACCOUNT_LOCKED": "Y",
                    }
                ]
            }
        }
        fv = crack_judge("mysql", data, "mysql_native")
        assert fv.verdict != "취약", (
            "mysql.session(잠금) 빈 해시가 취약으로 판정됨 — 거짓취약 (§D)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# §E §7 평문 비노출
# ══════════════════════════════════════════════════════════════════════════════

class TestSection7PlaintextMasking:
    """§7 보안: 매치 평문이 citations/rationale 어디에도 노출되지 않음."""

    # 사전공격으로 자체 생성한 해시를 사용하는 케이스의 평문
    _WEAK_PW = "password"

    def test_mariadb_match_no_plaintext_in_citations(self):
        """mariadb: 사전매치 시 citations에 평문 없음."""
        h = _generate_mysql_native(self._WEAK_PW)
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.verdict == "취약"
        # §7: citations에 평문('password') 절대 없음
        citation_text = " ".join(fv.citations)
        assert self._WEAK_PW not in citation_text, (
            f"§7 위반: citations에 평문 '{self._WEAK_PW}' 노출됨: {fv.citations}"
        )
        # 고정 문구 확인
        assert any("평문 비공개" in c for c in fv.citations), (
            f"§7 고정문구 없음: {fv.citations}"
        )

    def test_mariadb_match_no_plaintext_in_rationale(self):
        """mariadb: 사전매치 시 rationale에 평문 없음."""
        h = _generate_mysql_native(self._WEAK_PW)
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert self._WEAK_PW not in fv.rationale, (
            f"§7 위반: rationale에 평문 '{self._WEAK_PW}' 노출됨: {fv.rationale}"
        )

    def test_mssql_match_no_plaintext(self):
        """mssql: 사전매치 시 citations에 평문 없음."""
        _pw = "Password123"
        salt = bytes.fromhex("11223344")
        h = _generate_mssql_0200(_pw, salt)
        data = {
            "DBM-001": {
                "RESULT": [{"name": "sa", "password_hash": h, "is_disabled": "0"}]
            }
        }
        fv = crack_judge("mssql", data, "mssql_native")
        assert fv.verdict == "취약"
        citation_text = " ".join(fv.citations)
        assert _pw not in citation_text, (
            f"§7 위반: citations에 평문 '{_pw}' 노출됨"
        )

    def test_postgres_scram_match_no_plaintext(self):
        """postgres SCRAM: 사전매치 시 citations에 평문(비밀번호)이 노출되지 않음.

        §7 계약: 계정명은 citations에 표시되지만, 실제 비밀번호 평문은 절대 노출 금지.
        테스트: 계정명≠비밀번호 케이스 사용 — 비밀번호('password123_notinname')가
        citations에 나타나면 §7 위반.
        """
        # 계정명과 다른 비밀번호 사용 (계정명이 citations에 나오는 건 정상)
        _account = "dbuser"
        _pw = "password"  # 사전에 있는 비번 (계정명과 다름)
        import os
        salt = os.urandom(16)
        h = _generate_postgres_scram(_pw, salt)
        raw = f'{{"rolname": \'{_account}\', "rolpassword" : \'{h}\'}}'
        data = {
            "DBM-001_1": {"RESULT": []},
            "DBM-001_2": {"RESULT": [{"*": raw}]},
        }
        fv = crack_judge("postgresql", data, "pg_native")
        assert fv.verdict == "취약"
        citation_text = " ".join(fv.citations)
        # §7: 비밀번호 평문('password')이 citations에 없어야 함
        # 단, 계정명(_account)은 citations에 나타나는 것이 정상 설계
        assert _pw not in citation_text, (
            f"§7 위반: citations에 비밀번호 평문 '{_pw}' 노출됨: {fv.citations}"
        )
        # 고정 문구 확인
        assert any("평문 비공개" in c for c in fv.citations)


# ══════════════════════════════════════════════════════════════════════════════
# §F 증거가드
# ══════════════════════════════════════════════════════════════════════════════

class TestEvidenceGuard:
    """증거가드: DBM-001 data_key 없음 / RESULT 빔 → handled=False."""

    def test_no_dbm001_key_handled_false(self):
        """DBM-001 키가 없는 data → handled=False."""
        data = {"DBM-003": {"RESULT": [{"USER": "root"}]}}
        fv = crack_judge("mariadb", data, "mariadb_native")
        assert fv.handled is False
        assert fv.verdict == "판단보류"

    def test_empty_data_handled_false(self):
        """빈 data → handled=False."""
        data = {}
        fv = crack_judge("mysql", data, "mysql_native")
        assert fv.handled is False

    def test_result_empty_list_handled_false(self):
        """DBM-001 RESULT=[] → handled=False."""
        data = {"DBM-001": {"RESULT": []}}
        fv = crack_judge("mssql", data, "mssql_native")
        assert fv.handled is False

    def test_oracle_no_dbm001_handled_false(self):
        """oracle: DBM-001 없음 → handled=False (현 native 데이터 상황)."""
        data = {"DBM-003": {"RESULT": []}}
        fv = crack_judge("oracle", data, "oracle_native")
        assert fv.handled is False

    def test_postgres_no_dbm001_2_no_accounts(self):
        """postgres: DBM-001_2 없으면 계정 0 → handled=False."""
        data = {"DBM-001_1": {"RESULT": [{"setting_name": "password_encryption", "value": "scram-sha-256"}]}}
        fv = crack_judge("postgresql", data, "pg_native")
        assert fv.handled is False


# ══════════════════════════════════════════════════════════════════════════════
# §G 실데이터 native 5엔진 스모크
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(
    not _ALL_NATIVE_EXIST,
    reason="실데이터 파일 없음 (collected/db/*_native)",
)
class TestRealDataSmoke:
    """5엔진 실데이터 스모크: 오류없음, 거짓취약 0, oracle handled=False, §7 평문비노출."""

    def _run(self, engine: str, variant: str, path: str) -> ForcedVerdict:
        data = _load_real_data(path)
        return crack_judge(engine, data, variant)

    def test_mariadb_no_error_no_false_positive(self):
        """mariadb: 오류없음, 거짓취약 0."""
        fv = self._run("mariadb", "mariadb_native", _MARIADB_NATIVE)
        assert fv.verdict in ("취약", "판단보류")
        assert fv.verdict != "양호"
        # mariadb.sys(만료) 빈 해시가 취약으로 나오면 거짓취약
        # mariadb.sys는 PASSWORD_EXPIRED=Y이므로 스킵되어야 함
        for c in fv.citations:
            assert "mariadb.sys" not in c, (
                f"mariadb.sys(만료) 거짓취약 발생: {c}"
            )

    def test_mysql_no_error_no_false_positive(self):
        """mysql: 오류없음, 거짓취약 0 (caching_sha2 비활성 → 미지원포맷)."""
        fv = self._run("mysql", "mysql_native", _MYSQL_NATIVE)
        assert fv.verdict in ("취약", "판단보류")
        assert fv.verdict != "양호"

    def test_mssql_no_error_no_false_positive(self):
        """mssql: 오류없음, 거짓취약 0."""
        fv = self._run("mssql", "mssql_native", _MSSQL_NATIVE)
        assert fv.verdict in ("취약", "판단보류")
        assert fv.verdict != "양호"
        # 비활성 계정(##MS_Policy...##)이 취약으로 나오면 거짓취약
        for c in fv.citations:
            assert "##MS_Policy" not in c, (
                f"비활성 mssql 계정 거짓취약 발생: {c}"
            )

    def test_postgresql_no_error_no_false_positive(self):
        """postgresql: 오류없음, 거짓취약 0."""
        fv = self._run("postgresql", "pg_native", _PG_NATIVE)
        assert fv.verdict in ("취약", "판단보류")
        assert fv.verdict != "양호"

    def test_oracle_handled_false_no_data(self):
        """oracle: DBM-001 data 부재 → handled=False (현 native 수집 현황)."""
        fv = self._run("oracle", "oracle_native", _ORACLE_NATIVE)
        assert fv.handled is False, (
            f"oracle native에 DBM-001 없어야 handled=False인데 handled=True: {fv}"
        )

    def test_section7_no_plaintext_in_any_output(self):
        """§7: 모든 엔진 실데이터에서 plaintext가 citations/rationale에 없음."""
        all_engines = [
            ("mariadb", "mariadb_native", _MARIADB_NATIVE),
            ("mysql", "mysql_native", _MYSQL_NATIVE),
            ("mssql", "mssql_native", _MSSQL_NATIVE),
            ("postgresql", "pg_native", _PG_NATIVE),
            ("oracle", "oracle_native", _ORACLE_NATIVE),
        ]
        # 사전에 있는 약한 비번 샘플 (실데이터에 이게 나오면 §7 위반)
        # 이 목록의 단어가 citations 중 "평문 비공개" 문구 없이 노출되면 위반
        for engine, variant, path in all_engines:
            fv = self._run(engine, variant, path)
            for citation in fv.citations:
                # 취약 citation은 반드시 "평문 비공개" 또는 "빈 해시" 문구 포함
                if "기본/사전" in citation:
                    assert "평문 비공개" in citation, (
                        f"§7 위반: '{engine}' citation에 '평문 비공개' 문구 없음: {citation}"
                    )


# ══════════════════════════════════════════════════════════════════════════════
# §H 계정명 중복 제거
# ══════════════════════════════════════════════════════════════════════════════

class TestDeduplication:
    """같은 (USER, PASSWORD) 쌍의 HOST별 중복 계정 제거."""

    def test_mariadb_same_hash_different_host_deduped(self):
        """mariadb: HOST만 다르고 USER/PASSWORD 동일 → 1개 계정으로 처리."""
        h = _generate_mysql_native("password")
        rows = [
            {"HOST": "localhost", "USER": "root", "PASSWORD": h,
             "PLUGIN": "mysql_native_password", "PASSWORD_EXPIRED": "N"},
            {"HOST": "%", "USER": "root", "PASSWORD": h,
             "PLUGIN": "mysql_native_password", "PASSWORD_EXPIRED": "N"},
        ]
        accounts = _parse_mariadb_accounts(rows)
        assert len(accounts) == 1, f"중복 제거 실패: {len(accounts)}개"

    def test_mysql_same_hash_different_host_deduped(self):
        """mysql: 동일 (USER, AUTHENTICATION_STRING) HOST 다름 → 1개."""
        h = "$A$005$somehash_value_here"
        rows = [
            {"HOST": "127.0.0.1", "USER": "healthcheck", "AUTHENTICATION_STRING": h,
             "PLUGIN": "mysql_native_password", "ACCOUNT_LOCKED": "N"},
            {"HOST": "::1", "USER": "healthcheck", "AUTHENTICATION_STRING": h,
             "PLUGIN": "mysql_native_password", "ACCOUNT_LOCKED": "N"},
        ]
        accounts = _parse_mysql_accounts(rows)
        assert len(accounts) == 1


# ══════════════════════════════════════════════════════════════════════════════
# §I Postgres 행 파서 혼합 형식
# ══════════════════════════════════════════════════════════════════════════════

class TestPostgresRowParser:
    """postgres DBM-001_2 혼합 형식(이중따옴표 키 + 단따옴표 값) 파싱."""

    def test_mixed_format_parsed(self):
        """혼합 형식: "rolname": 'postgres' → 정상 파싱."""
        row = {"*": '{"rolname": \'postgres\', "rolpassword" : \'SCRAM-SHA-256$4096:abc$def:ghi\'}'}
        result = _parse_postgres_row(row)
        assert result is not None, "혼합 형식 파싱 실패"
        rolname, rolpwd = result
        assert rolname == "postgres"
        assert rolpwd == "SCRAM-SHA-256$4096:abc$def:ghi"

    def test_json_format_parsed(self):
        """JSON 형식: "rolname": "postgres" → 정상 파싱."""
        row = {"*": '{"rolname": "postgres", "rolpassword": "md5abc123"}'}
        result = _parse_postgres_row(row)
        assert result is not None
        assert result[0] == "postgres"
        assert result[1] == "md5abc123"

    def test_python_repr_format_parsed(self):
        """Python repr 형식: 'rolname': 'postgres' → 정상 파싱."""
        row = {"*": "{'rolname': 'postgres', 'rolpassword': 'md5abc123'}"}
        result = _parse_postgres_row(row)
        assert result is not None
        assert result[0] == "postgres"

    def test_direct_dict_fields(self):
        """row에 직접 rolname/rolpassword 키가 있으면 바로 반환."""
        row = {"rolname": "myuser", "rolpassword": "SCRAM-SHA-256$..."}
        result = _parse_postgres_row(row)
        assert result == ("myuser", "SCRAM-SHA-256$...")

    def test_unparseable_returns_none(self):
        """파싱 불가 형식 → None."""
        row = {"*": "garbage string that has no pattern"}
        result = _parse_postgres_row(row)
        assert result is None

    def test_real_postgres_hash_format(self):
        """실데이터 형식 파싱 확인."""
        real_row = {
            "*": (
                '{"rolname": \'postgres\', "rolpassword" : '
                "'SCRAM-SHA-256$4096:fewu1rJ5b14RCg64DkgtEw==$"
                "BBaimehDBv5jaWGLIKE7oxbzjtX/Vu8jm9z/siArpxI=:"
                "WqE21gd0mb72h8l0Yzr3p6cY4MSyJXMbB3SxHL2zl0M='}"
            )
        }
        result = _parse_postgres_row(real_row)
        assert result is not None
        rolname, rolpwd = result
        assert rolname == "postgres"
        assert rolpwd.startswith("SCRAM-SHA-256")


# ══════════════════════════════════════════════════════════════════════════════
# §J Phase 4c-a hashcat 연동 테스트
# ══════════════════════════════════════════════════════════════════════════════

class TestHashcatOpts:
    """HashcatOpts 기본 구조 확인."""

    def test_default_opts(self):
        """기본값: hashcat_path=None, wordlist=None, rules=None, timeout=600."""
        opts = HashcatOpts()
        assert opts.hashcat_path is None
        assert opts.wordlist is None
        assert opts.rules is None
        assert opts.timeout == 600

    def test_custom_opts(self):
        """커스텀 값 설정."""
        opts = HashcatOpts(
            hashcat_path="/usr/bin/hashcat",
            wordlist="/tmp/words.txt",
            rules="/tmp/rules.rule",
            timeout=300,
        )
        assert opts.hashcat_path == "/usr/bin/hashcat"
        assert opts.wordlist == "/tmp/words.txt"
        assert opts.rules == "/tmp/rules.rule"
        assert opts.timeout == 300


class TestDetectHashcat:
    """_detect_hashcat: 바이너리 탐지 및 graceful 처리."""

    def test_none_path_no_hashcat_installed(self, tmp_path):
        """hashcat 미설치 환경: None → None (graceful skip)."""
        import shutil
        # PATH에 hashcat이 없는지 확인 후 테스트
        if shutil.which("hashcat"):
            pytest.skip("hashcat이 PATH에 있으므로 미설치 케이스 스킵")
        result = _detect_hashcat(None)
        assert result is None

    def test_nonexistent_path_returns_none(self):
        """존재하지 않는 경로 → None."""
        result = _detect_hashcat("/nonexistent/path/to/hashcat")
        assert result is None

    def test_valid_executable_path(self, tmp_path):
        """실행 가능한 파일 경로 → 그 경로 반환."""
        fake_bin = tmp_path / "hashcat"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)
        result = _detect_hashcat(str(fake_bin))
        assert result == str(fake_bin)

    def test_non_executable_path_returns_none(self, tmp_path):
        """실행 권한 없는 파일 → None."""
        fake_bin = tmp_path / "hashcat"
        fake_bin.write_text("dummy")
        fake_bin.chmod(0o644)  # 실행 권한 없음
        result = _detect_hashcat(str(fake_bin))
        assert result is None


class TestExportForExternal:
    """export_for_external: (b) 미스 계정 → hashcat mode별 hashline 직렬화."""

    def test_mysql_native_mode300(self):
        """mysql_native *HEX → mode 300, hashline = hash 그대로."""
        h = _generate_mysql_native("password")
        accounts = [AccountInfo(name="root", hash_str=h, plugin="mysql_native_password")]
        result = export_for_external("mariadb", accounts)
        assert _HASHCAT_MODE["mysql_native"] in result
        assert h in result[_HASHCAT_MODE["mysql_native"]]

    def test_mssql_0x0200_mode1731(self):
        """mssql 0x0200 → mode 1731."""
        h = _generate_mssql_0200("password", bytes.fromhex("AABBCCDD"))
        accounts = [AccountInfo(name="sa", hash_str=h, plugin="mssql")]
        result = export_for_external("mssql", accounts)
        assert _HASHCAT_MODE["mssql_0x0200"] in result
        assert h in result[_HASHCAT_MODE["mssql_0x0200"]]

    def test_mssql_0x0100_not_exported(self):
        """mssql 0x0100 → mode 131 미검증(H-2) — export에서 제외됨.

        KAT 미확보·실데이터 없는 미검증 포맷은 export에서 명시적으로 제외한다.
        운영자 수동 hashcat 필요.
        """
        fake_hash = "0x0100" + "A" * 40
        accounts = [AccountInfo(name="olduser", hash_str=fake_hash, plugin="mssql")]
        result = export_for_external("mssql", accounts)
        # H-2: 미검증 포맷 → export에 포함되지 않아야 함
        assert _HASHCAT_MODE["mssql_0x0100"] not in result, (
            "mssql 0x0100은 미검증 포맷 — export에서 제외되어야 함 (H-2)"
        )

    def test_postgres_md5_mode12_with_rolname(self):
        """postgres md5 → mode 12, hashline = hash:rolname 형식."""
        h = _generate_postgres_md5("postgres", "postgres")
        accounts = [AccountInfo(name="postgres", hash_str=h, plugin="postgresql", rolname="postgres")]
        result = export_for_external("postgresql", accounts)
        assert _HASHCAT_MODE["pg_md5"] in result
        lines = result[_HASHCAT_MODE["pg_md5"]]
        # hashline 형식: md5<hex>:rolname
        assert any(l.startswith(h) and ":" in l for l in lines)

    def test_postgres_scram_mode28600(self):
        """postgres SCRAM-SHA-256 → mode 28600."""
        import os as _os
        h = _generate_postgres_scram("postgres", _os.urandom(16))
        accounts = [AccountInfo(name="postgres", hash_str=h, plugin="postgresql", rolname="postgres")]
        result = export_for_external("postgresql", accounts)
        assert _HASHCAT_MODE["pg_scram"] in result
        assert h in result[_HASHCAT_MODE["pg_scram"]]

    def test_oracle_11g_mode112(self):
        """oracle 11g S: → mode 112."""
        h = _generate_oracle_11g("password", bytes.fromhex("AABBCCDDEEFF001122AA"))
        accounts = [AccountInfo(name="sys", hash_str=h, plugin="oracle")]
        result = export_for_external("oracle", accounts)
        assert _HASHCAT_MODE["oracle_11g"] in result
        assert h in result[_HASHCAT_MODE["oracle_11g"]]

    def test_empty_hash_excluded(self):
        """빈 해시 계정은 export에서 제외 (이미 (b)에서 처리됨)."""
        accounts = [AccountInfo(name="root", hash_str="")]
        result = export_for_external("mariadb", accounts)
        # 빈 해시 → 어떤 모드에도 포함 안 됨
        for mode_lines in result.values():
            assert "" not in mode_lines

    def test_empty_accounts_returns_empty_dict(self):
        """계정 없음 → 빈 dict."""
        result = export_for_external("mariadb", [])
        assert result == {}

    def test_only_b_miss_accounts_included(self):
        """(b)에서 이미 취약 판정한 계정이 아닌, 미스 계정만 포함.

        export_for_external은 입력받은 accounts를 직렬화하므로,
        호출자가 미스 계정만 걸러서 넘겨야 함 — 여기서는 함수 동작만 확인.
        """
        h = _generate_mysql_native("strongpassword")
        accounts = [AccountInfo(name="user1", hash_str=h, plugin="mysql_native_password")]
        result = export_for_external("mariadb", accounts)
        assert _HASHCAT_MODE["mysql_native"] in result
        assert len(result[_HASHCAT_MODE["mysql_native"]]) == 1


class TestRunHashcatMockBasic:
    """run_hashcat: mock subprocess로 기본 동작 검증."""

    def _make_weak_hash(self) -> str:
        return _generate_mysql_native("password")

    def test_mock_hashcat_cracked_hash_detected(self, tmp_path, monkeypatch):
        """mock hashcat: 가짜 potfile에 크랙된 hash → 해당 hash 집합 반환.

        subprocess.run을 monkeypatch해 potfile에 hash:plaintext를 기록.
        """
        import subprocess as _subprocess
        h = self._make_weak_hash()

        def fake_run(cmd, **kwargs):
            # cmd에서 --potfile-path 인자 다음 값을 파싱
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                # §7 테스트: potfile에 hash:plaintext 기록
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    fh.write(f"{h}:password\n")  # plaintext는 potfile에만 있어야 함
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        # 더미 wordlist
        wl = tmp_path / "words.txt"
        wl.write_text("password\n")

        # 더미 hashcat 바이너리 (실행 가능)
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        mode_map = {300: [h]}
        cracked = run_hashcat(
            mode_map=mode_map,
            wordlist=str(wl),
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=10,
        )
        # H-1: cracked set은 _normalize_hash() 정규화된 값을 저장하므로 비교 시 정규화
        assert _normalize_hash(h) in cracked, f"크랙된 hash가 결과에 없음: {cracked}"

    def test_mock_hashcat_no_crack_empty_result(self, tmp_path, monkeypatch):
        """mock hashcat: potfile 비어있음 → 빈 집합 반환."""
        import subprocess as _subprocess

        def fake_run(cmd, **kwargs):
            # potfile에 아무것도 기록하지 않음
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        wl = tmp_path / "words.txt"
        wl.write_text("password\n")
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        mode_map = {300: [_generate_mysql_native("strongpassword")]}
        cracked = run_hashcat(
            mode_map=mode_map,
            wordlist=str(wl),
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=10,
        )
        assert cracked == set()

    def test_timeout_returns_partial_result_no_crash(self, tmp_path, monkeypatch):
        """hashcat timeout → TimeoutExpired 예외 → 크래시 없이 빈/부분 결과."""
        import subprocess as _subprocess

        def fake_run(cmd, **kwargs):
            raise _subprocess.TimeoutExpired(cmd, timeout=1)

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        wl = tmp_path / "words.txt"
        wl.write_text("password\n")
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        h = _generate_mysql_native("password")
        mode_map = {300: [h]}
        # 크래시 없이 반환되어야 함
        cracked = run_hashcat(
            mode_map=mode_map,
            wordlist=str(wl),
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=1,
        )
        assert isinstance(cracked, set)

    def test_subprocess_exception_no_crash(self, tmp_path, monkeypatch):
        """subprocess.run이 OSError → 크래시 없이 빈 결과."""
        def fake_run(cmd, **kwargs):
            raise OSError("바이너리 실행 실패")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        wl = tmp_path / "words.txt"
        wl.write_text("password\n")
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        mode_map = {300: [_generate_mysql_native("password")]}
        cracked = run_hashcat(
            mode_map=mode_map,
            wordlist=str(wl),
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=10,
        )
        assert isinstance(cracked, set)

    def test_tmpfile_cleanup_after_run(self, tmp_path, monkeypatch):
        """run_hashcat 완료 후 임시파일(hashfile, potfile) 삭제 확인."""
        import subprocess as _subprocess
        created_paths: list[str] = []

        original_mkstemp = tempfile.mkstemp

        def tracking_mkstemp(**kwargs_):
            # 위치 인자도 허용
            fd, path = original_mkstemp(**{k: v for k, v in kwargs_.items()
                                          if k in ("prefix", "suffix", "dir")})
            created_paths.append(path)
            return fd, path

        # tempfile.mkstemp 추적 — 직접 import한 모듈의 tempfile에 monkeypatch
        import judge_tool.det_adapters.db_pwcrack as _mod
        monkeypatch.setattr(_mod.tempfile, "mkstemp", tracking_mkstemp)

        def fake_run(cmd, **kwargs):
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        wl = tmp_path / "words.txt"
        wl.write_text("password\n")
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        h = _generate_mysql_native("password")
        mode_map = {300: [h]}
        run_hashcat(
            mode_map=mode_map,
            wordlist=str(wl),
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=10,
        )
        # 생성된 임시파일들이 모두 삭제되었어야 함
        for path in created_paths:
            assert not os.path.exists(path), f"임시파일 미삭제: {path}"

    def test_wordlist_fallback_pwdict_tmpfile_cleanup(self, tmp_path, monkeypatch):
        """wordlist=None → pwdict 폴백 임시파일 생성 후 cleanup 확인."""
        import subprocess as _subprocess
        created_paths: list[str] = []

        import judge_tool.det_adapters.db_pwcrack as _mod
        original_mkstemp = _mod.tempfile.mkstemp

        def tracking_mkstemp(**kwargs_):
            fd, path = original_mkstemp(**{k: v for k, v in kwargs_.items()
                                          if k in ("prefix", "suffix", "dir")})
            created_paths.append(path)
            return fd, path

        monkeypatch.setattr(_mod.tempfile, "mkstemp", tracking_mkstemp)

        def fake_run(cmd, **kwargs):
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        h = _generate_mysql_native("password")
        mode_map = {300: [h]}
        # wordlist=None → pwdict 폴백 임시파일
        run_hashcat(
            mode_map=mode_map,
            wordlist=None,
            rules=None,
            hashcat_path=str(fake_hc),
            timeout=10,
        )
        for path in created_paths:
            assert not os.path.exists(path), f"폴백 임시파일 미삭제: {path}"


class TestCrackJudgeWithHashcat:
    """crack_judge + mock hashcat 통합: (a) 레이어 연동 검증."""

    def _make_mariadb_data_strong(self, pw: str = "Str0ngP@ss!xyz#2026_notInDict") -> dict:
        h = _generate_mysql_native(pw)
        return {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost",
                        "USER": "root",
                        "PASSWORD": h,
                        "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }

    def test_no_hashcat_opts_b_only_pending(self):
        """hashcat_opts=None → (a) 스킵, (b) 결과만 (강한 비번 → 판단보류)."""
        data = self._make_mariadb_data_strong()
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=None)
        assert fv.verdict == "판단보류"
        assert fv.handled is True
        # (a) 스킵 표시가 rationale에 있어야 함
        assert "skipped(no hashcat)" in fv.rationale

    def test_hashcat_opts_no_binary_b_only_pending(self, tmp_path):
        """hashcat_opts 제공이지만 바이너리 없음 → (a) graceful skip, (b)-only."""
        opts = HashcatOpts(hashcat_path="/nonexistent/hashcat")
        data = self._make_mariadb_data_strong()
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        assert fv.verdict == "판단보류"
        assert fv.handled is True
        assert "skipped(no hashcat)" in fv.rationale

    def test_mock_hashcat_cracked_b_miss_becomes_vulnerable(self, tmp_path, monkeypatch):
        """mock hashcat: (b) 미스 계정을 (a)가 크랙 → 취약 판정."""
        import subprocess as _subprocess
        h = _generate_mysql_native("Str0ngP@ss!xyz#2026_notInDict")

        def fake_run(cmd, **kwargs):
            # potfile에 크랙 결과 기록
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    fh.write(f"{h}:Str0ngP@ss!xyz#2026_notInDict\n")
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        # 더미 hashcat 바이너리 (실행 가능)
        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)

        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        data = self._make_mariadb_data_strong()
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        assert fv.verdict == "취약", f"(a) 크랙 후 취약 판정 실패: {fv.verdict}"
        assert fv.handled is True
        # citation에 (a) 고정 문구 있어야 함
        assert any("사전/규칙 크랙으로 약한 비밀번호 확인" in c for c in fv.citations)

    def test_module_seam_set_clear(self, tmp_path, monkeypatch):
        """set_hashcat_opts / clear_hashcat_opts 세임 동작 확인."""
        import subprocess as _subprocess
        h = _generate_mysql_native("Str0ngP@ss!xyz#2026_notInDict")

        def fake_run(cmd, **kwargs):
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    fh.write(f"{h}:anything\n")
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        data = self._make_mariadb_data_strong()

        # 세임 설정 → crack_judge가 세임에서 opts를 읽어야 함
        set_hashcat_opts(opts)
        try:
            fv = crack_judge("mariadb", data, "mariadb_native")  # hashcat_opts 생략
            assert fv.verdict == "취약"
        finally:
            clear_hashcat_opts()

        # 클리어 후에는 (a) 스킵
        fv2 = crack_judge("mariadb", data, "mariadb_native")
        assert "skipped(no hashcat)" in fv2.rationale


class TestSection7HashcatPlaincext:
    """§7 보안: (a) hashcat 크랙 시 평문이 citations/rationale에 노출되지 않음."""

    # (a)에서 "크랙"하는 테스트용 평문 — 사전에 없는 강한 비번
    _CRACKED_PW = "SUPER_SECRET_PLAINTEXT_MUST_NOT_APPEAR_IN_OUTPUT"

    def test_cracked_plaintext_not_in_citations(self, tmp_path, monkeypatch):
        """(a) 크랙 성공 시 citations에 평문 없음 (§7)."""
        import subprocess as _subprocess
        h = _generate_mysql_native(self._CRACKED_PW)

        def fake_run(cmd, **kwargs):
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    # §7 위반 시뮬레이션: potfile에 평문 포함
                    fh.write(f"{h}:{self._CRACKED_PW}\n")
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "appuser",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)

        assert fv.verdict == "취약"
        # §7 핵심: citations에 실제 평문이 없어야 함
        citation_text = " ".join(fv.citations)
        assert self._CRACKED_PW not in citation_text, (
            f"§7 위반: citations에 크랙 평문 노출됨: {fv.citations}"
        )
        # §7 핵심: rationale에도 평문 없어야 함
        assert self._CRACKED_PW not in fv.rationale, (
            f"§7 위반: rationale에 크랙 평문 노출됨: {fv.rationale}"
        )
        # 고정 문구 확인
        assert any("평문 비공개" in c for c in fv.citations), (
            f"§7 고정문구 없음: {fv.citations}"
        )

    def test_cracked_plaintext_not_in_rationale(self, tmp_path, monkeypatch):
        """(a) 크랙 성공 시 rationale에 평문 없음 (§7)."""
        import subprocess as _subprocess
        h = _generate_mysql_native(self._CRACKED_PW)

        def fake_run(cmd, **kwargs):
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    fh.write(f"{h}:{self._CRACKED_PW}\n")
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("judge_tool.det_adapters.db_pwcrack.subprocess.run", fake_run)

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "appuser",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        assert self._CRACKED_PW not in fv.rationale


class TestHashcatAdversarialMapping:
    """H-1 검증: potfile 소문자 해시, 평문 내 콜론, postgres md5 rolname 매핑 정확성."""

    def _fake_run_with_potline(self, potline: str):
        """potfile에 potline을 기록하는 fake subprocess.run 반환."""
        import subprocess as _subprocess

        def fake_run(cmd, **kwargs):
            potfile_path = None
            for i, arg in enumerate(cmd):
                if arg == "--potfile-path" and i + 1 < len(cmd):
                    potfile_path = cmd[i + 1]
                    break
            if potfile_path:
                with open(potfile_path, "w", encoding="utf-8") as fh:
                    fh.write(potline + "\n")
            return _subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

        return fake_run

    def test_lowercase_hex_potfile_maps_correctly(self, tmp_path, monkeypatch):
        """hashcat potfile이 소문자 hex로 해시를 기록해도 계정이 취약으로 매핑됨 (H-1).

        mysql_native _generate는 대문자 hex(*2470...E19)를 생성하지만,
        hashcat은 potfile에 소문자(*2470...e19)로 기록한다.
        _normalize_hash(casefold) 없이는 in 연산이 false-negative 발생.

        (b) 레이어가 먼저 크랙하면 (a)가 실행되지 않으므로, 사전에 없는 강한 비번 사용.
        """
        # 사전에 없는 강한 비번 — (b) 미스, (a)에서만 크랙되는 케이스
        strong_pw = "Str0ngPw!LowercaseHexTest2026_#notInDict"
        h = _generate_mysql_native(strong_pw)
        # hashcat처럼 소문자로 변환한 potfile 라인
        potline = f"{h.lower()}:{strong_pw}"

        monkeypatch.setattr(
            "judge_tool.det_adapters.db_pwcrack.subprocess.run",
            self._fake_run_with_potline(potline),
        )

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "user1",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        assert fv.verdict == "취약", (
            f"소문자 hex potfile에서 계정 매핑 실패: {fv.verdict} | {fv.rationale}"
        )
        assert any("사전/규칙 크랙으로 약한 비밀번호 확인" in c for c in fv.citations)

    def test_plaintext_with_colon_maps_correctly(self, tmp_path, monkeypatch):
        """평문에 ':' 포함된 potfile 라인도 계정이 올바르게 취약 매핑됨 (H-1).

        rfind(":") 방식은 'hash:pa:ss:wd'에서 hash='hash:pa:ss'로 오파싱된다.
        startswith 방식은 export hashline을 기준으로 매칭해 이를 방지한다.
        """
        h = _generate_mysql_native("Str0ngP@ss!2026")
        # 평문에 ':' 여러 개 포함
        potline = f"{h}:pa:ss:wd:with:colons"

        monkeypatch.setattr(
            "judge_tool.det_adapters.db_pwcrack.subprocess.run",
            self._fake_run_with_potline(potline),
        )

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "dbuser",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        assert fv.verdict == "취약", (
            f"평문 내 ':' 포함 potfile에서 계정 매핑 실패: {fv.verdict} | {fv.rationale}"
        )
        assert any("사전/규칙 크랙으로 약한 비밀번호 확인" in c for c in fv.citations)

    def test_postgres_md5_plaintext_neq_rolname(self, tmp_path, monkeypatch):
        """postgres md5: 평문이 rolname과 다른 경우에도 계정이 취약으로 매핑됨 (H-1).

        postgres md5 export hashline은 'md5<hex>:rolname' 형식.
        potfile은 'md5<hex>:rolname:plaintext'를 기록.
        startswith 방식은 'md5<hex>:rolname:' 접두로 매칭하므로
        plaintext != rolname 이어도 정확히 동작한다.
        """
        rolname = "pguser"
        plaintext = "VeryStr0ngPw!2026_notRolname"
        h = _generate_postgres_md5(plaintext, rolname)
        # export hashline: md5<hex>:rolname
        export_hashline = f"{h}:{rolname}"
        # hashcat potfile: md5<hex>:rolname:plaintext (소문자)
        potline = f"{export_hashline.lower()}:{plaintext}"

        monkeypatch.setattr(
            "judge_tool.det_adapters.db_pwcrack.subprocess.run",
            self._fake_run_with_potline(potline),
        )

        fake_hc = tmp_path / "hashcat"
        fake_hc.write_text("#!/bin/sh\n")
        fake_hc.chmod(0o755)
        wl = tmp_path / "words.txt"
        wl.write_text("dummy\n")

        opts = HashcatOpts(hashcat_path=str(fake_hc), wordlist=str(wl), timeout=10)
        # postgresql crack_judge는 DBM-001_2 키 + {"*": '...'} 형식 사용
        raw_row = f'{{"rolname": "{rolname}", "rolpassword": "{h}"}}'
        data = {
            "DBM-001_2": {
                "RESULT": [{"*": raw_row}]
            }
        }
        fv = crack_judge("postgresql", data, "pg_native", hashcat_opts=opts)
        assert fv.verdict == "취약", (
            f"postgres md5 plaintext≠rolname 케이스 매핑 실패: {fv.verdict} | {fv.rationale}"
        )
        assert any("사전/규칙 크랙으로 약한 비밀번호 확인" in c for c in fv.citations)


class TestGracefulDegradation:
    """graceful degradation: hashcat 부재/오류 시 (b) 결과로 폴백."""

    def test_b_only_when_no_hashcat(self):
        """hashcat_opts=None → (b) 사전 탐지만, 정상 동작."""
        h = _generate_mysql_native("password")  # (b) 사전에 있는 비번
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=None)
        # (b)가 취약 판정한 케이스: (a) 없어도 취약
        assert fv.verdict == "취약"
        assert fv.handled is True
        assert any("기본/사전 비밀번호" in c for c in fv.citations)

    def test_b_pending_no_hashcat_gives_pending(self):
        """(b) 미스 + hashcat_opts=None → 판단보류 (graceful, 에러 아님)."""
        h = _generate_mysql_native("Str0ngP@ss!xyz#2026_notInDict")
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=None)
        assert fv.verdict == "판단보류"
        assert fv.handled is True
        # 에러가 아닌 정상 판단보류
        assert fv.ev_status == "review"

    def test_hashcat_binary_absent_graceful_skip(self, tmp_path):
        """hashcat 바이너리 부재 → graceful skip, (b) 결과만."""
        opts = HashcatOpts(hashcat_path="/nonexistent/hashcat", timeout=5)
        h = _generate_mysql_native("Str0ngP@ss!xyz#2026_notInDict")
        data = {
            "DBM-001": {
                "RESULT": [
                    {
                        "HOST": "localhost", "USER": "root",
                        "PASSWORD": h, "PLUGIN": "mysql_native_password",
                        "PASSWORD_EXPIRED": "N",
                    }
                ]
            }
        }
        fv = crack_judge("mariadb", data, "mariadb_native", hashcat_opts=opts)
        # (a) 스킵 후 (b) 미스 → 판단보류
        assert fv.verdict == "판단보류"
        assert fv.handled is True
        # rationale에 pwcrack_a 스킵 표시
        assert "skipped(no hashcat)" in fv.rationale


class TestRealDataSmokeWithHashcat:
    """실데이터 5엔진 + hashcat_opts=None: (a) graceful skip, DBM-001 verdict 불변."""

    @pytest.mark.skipif(
        not _ALL_NATIVE_EXIST,
        reason="실데이터 파일 없음 (collected/db/*_native)",
    )
    def test_all_engines_graceful_skip_no_false_positive(self):
        """5엔진 실데이터 + hashcat_opts=None: (a) 스킵, 거짓판정 없음, oracle handled=False."""
        engines = [
            ("mariadb", "mariadb_native", _MARIADB_NATIVE),
            ("mysql", "mysql_native", _MYSQL_NATIVE),
            ("mssql", "mssql_native", _MSSQL_NATIVE),
            ("postgresql", "pg_native", _PG_NATIVE),
            ("oracle", "oracle_native", _ORACLE_NATIVE),
        ]
        for engine, variant, path in engines:
            data = _load_real_data(path)
            fv = crack_judge(engine, data, variant, hashcat_opts=None)
            assert fv.verdict != "양호", (
                f"{engine}: 양호 판정 발생 (거짓양호) — 양호는 불가능한 값"
            )
            if engine == "oracle":
                assert fv.handled is False, (
                    f"oracle: handled=True는 거짓판정 위험 (DBM-001 데이터 없어야 함)"
                )
            # §7: citations에 평문 없음
            for citation in fv.citations:
                if "사전/규칙 크랙" in citation:
                    assert "평문 비공개" in citation

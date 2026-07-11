"""DBM-001 KAT(Known-Answer-Test) 해시 생성 헬퍼 — 테스트 전용.

judge_tool/det_adapters/db_pwcrack.py 의 _verify_*() 대응 해시 포맷을 그대로
생성해 라운드트립(generate∘verify) 테스트에 쓴다. production 판정 로직
(crack_judge/_verify_account 등)은 이 모듈을 참조하지 않는다 — 오직
tests/test_det_adapters_db_pwcrack.py 에서만 사용.
"""
from __future__ import annotations

import base64
import hashlib
import hmac


def _generate_mysql_native(password: str) -> str:
    """KAT/테스트용 mysql_native 해시 생성."""
    pw_bytes = password.encode("utf-8")
    inner = hashlib.sha1(pw_bytes).digest()
    outer = hashlib.sha1(inner).digest()
    return "*" + outer.hex().upper()


def _generate_mssql_0200(password: str, salt: bytes) -> str:
    """KAT/테스트용 MSSQL 0x0200 해시 생성 (salt 4bytes)."""
    h = hashlib.sha512(password.encode("utf-16-le") + salt).digest()
    raw = b"\x02\x00" + salt + h
    return "0x" + raw.hex().upper()


def _generate_postgres_scram(password: str, salt: bytes, iterations: int = 4096) -> str:
    """KAT/테스트용 SCRAM-SHA-256 해시 생성."""
    pw_bytes = password.encode("utf-8")
    salted_password = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iterations)
    client_key = hmac.new(salted_password, b"Client Key", "sha256").digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted_password, b"Server Key", "sha256").digest()
    b64salt = base64.b64encode(salt).decode()
    b64stored = base64.b64encode(stored_key).decode()
    b64server = base64.b64encode(server_key).decode()
    return f"SCRAM-SHA-256${iterations}:{b64salt}${b64stored}:{b64server}"


def _generate_postgres_md5(password: str, rolname: str = "") -> str:
    """KAT/테스트용 postgres md5 해시 생성."""
    combined = (password + rolname).encode("utf-8")
    return "md5" + hashlib.md5(combined).hexdigest()


def _generate_oracle_11g(password: str, salt: bytes) -> str:
    """KAT/테스트용 Oracle 11g S: 해시 생성.

    알고리즘: SHA1(pw.encode('utf-8') + salt) — 대소문자 보존, raw UTF-8.
    """
    h = hashlib.sha1(password.encode("utf-8") + salt).digest()
    return "S:" + h.hex().upper() + salt.hex().upper()

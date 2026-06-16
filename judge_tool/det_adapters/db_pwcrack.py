"""DB(DBM) 비밀번호 사전공격 어댑터 — Phase 4c (b 레이어 + a 레이어).

DBM-001 전용: 수집된 계정 해시를 정적 사전과 대조해 취약 비번을 탐지한다(b 레이어).
(a) 레이어: (b) 미스 계정을 외부 hashcat으로 추가 크랙 시도.

결정론 판정 (매치→취약 / 미스→판단보류 / 증거없음→handled=False).

§7 보안 계약:
  - 매치된 평문은 즉시 폐기. citations/rationale/log에 평문 절대 없음.
  - "계정 {name}: 기본/사전 비밀번호 사용(평문 비공개)" 고정 문구만 노출.
  - 빈 해시=비번 미설정: "계정 {name}: 비밀번호 미설정(빈 해시)"
  - (a) 레이어: potfile 평문도 즉시 폐기. "사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)".

지원 포맷:
  - mysql_native / mariadb: *40HEX (SHA1(SHA1(pw)).upper())
  - mssql 0x0200: 8byte salt + SHA512(pw.utf16le + salt)
  - mssql 0x0100: 미지원 강등 (레이아웃 KAT 미확보, 실데이터 없음 → 운영자 수동 hashcat 필요)
  - postgres SCRAM-SHA-256: PBKDF2-HMAC-SHA256 ServerKey 비교
  - postgres md5: md5(pw+rolname)
  - caching_sha2: 비활성 (외부 KAT 미확보 → 운영자 수동 hashcat 필요)
  - oracle 11g S:: SHA1+salt (코드 준비, 데이터 없으면 폴백)

입력: crack_judge(engine, data, variant, hashcat_opts=None) → ForcedVerdict
  data: db_json._build_raw_data_dict()이 조립한 비마스킹 dict
  variant: e.g. "mariadb_native", "mysql_native", "mssql_native", "pg_native", "oracle_native"
  hashcat_opts: HashcatOpts 또는 None (없으면 (a) 스킵)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional

from judge_tool.det_adapters.base import ForcedVerdict
from judge_tool.det_adapters.pwdict import candidates_for_account, MAX_ACCOUNTS, COMMON_WEAK_PASSWORDS

log = logging.getLogger(__name__)

# ── 성능 상한 ──────────────────────────────────────────────────────────────────
_MAX_ACCOUNTS = MAX_ACCOUNTS  # 200

# ── (a) hashcat 옵션 주입 세임 ──────────────────────────────────────────────────
# CLI 단일 프로세스(비다중스레드) 환경에서 JudgeContext → crack_judge 주입 경로.
# main.py(_det_common_handler)가 DBM-001 실행 전 set_hashcat_opts()로 설정,
# crack_judge 반환 후 clear_hashcat_opts()로 초기화.
# 다중스레드 환경이라면 threading.local()로 대체 필요.
_current_hashcat_opts: Optional["HashcatOpts"] = None


def set_hashcat_opts(opts: Optional["HashcatOpts"]) -> None:
    """(a) 레이어 주입: JudgeContext에서 crack_judge 호출 전 설정."""
    global _current_hashcat_opts
    _current_hashcat_opts = opts


def clear_hashcat_opts() -> None:
    """(a) 레이어 클리어: crack_judge 반환 후 초기화."""
    global _current_hashcat_opts
    _current_hashcat_opts = None


def get_hashcat_opts() -> Optional["HashcatOpts"]:
    """현재 설정된 hashcat 옵션 반환 (crack_judge 내부 참조용)."""
    return _current_hashcat_opts

# ── caching_sha2 활성화 플래그 ─────────────────────────────────────────────────
# 외부 공개 KAT 미확보 → 비활성. 이 포맷 계정은 미지원 — 운영자 수동 hashcat 필요.
_CACHING_SHA2_ENABLED: bool = False

# ── placeholder 해시 (MySQL 내장 계정, 크랙 불필요) ──────────────────────────────
_MYSQL_PLACEHOLDER = "THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED"


# ══════════════════════════════════════════════════════════════════════════════
# §A2 (Phase 4c-a). hashcat 연동 설정 / 모드 매핑
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HashcatOpts:
    """hashcat 연동 옵션 (CLI에서 주입).

    hashcat_path=None이거나 바이너리 부재 → (a) 스킵, 에러 아님.
    wordlist=None → pwdict 내장 사전을 임시 wordlist로 폴백.
    rules=None → 룰 없이 단순 사전 공격.
    timeout: 초 단위 (기본 600).
    """
    hashcat_path: Optional[str] = None   # None → PATH 자동탐지, 없으면 비활성
    wordlist: Optional[str] = None       # None → pwdict 폴백
    rules: Optional[str] = None          # 선택: 벤더 rule 파일 경로
    timeout: int = 600                   # 초


# ── hashcat 모드 매핑 (포맷 식별자 → hashcat -m 번호) ─────────────────────────
# 주의: 모드 번호는 hashcat 버전별 상이 가능.
# 활성화 시 `hashcat --help` 로 모드 목록 검증·교정 필요.
# 잘못된 모드는 hashcat이 거부(조용한 false-neg 아님 — 에러로 드러남).
_HASHCAT_MODE: dict[str, int] = {
    # MySQL/MariaDB
    "mysql_native":    300,    # *SHA1(SHA1(pw))
    # MySQL caching_sha2: 모드 번호 미확정.
    # hashcat 6.2.x에서 sha256crypt 계열 추정값(7401)이나 MySQL 전용 포맷과 다를 수 있음.
    # 활성화 전 반드시 `hashcat --help | grep -i sha256` 으로 검증 필요.
    # "mysql_caching_sha2": 7401,  # 미확정 — 주석 처리
    # MSSQL
    "mssql_0x0200":    1731,   # SHA512(UTF-16LE(pw) + salt)
    "mssql_0x0100":    131,    # SHA1 구형 (또는 132 case-sensitive 변형)
    # PostgreSQL
    "pg_md5":          12,     # md5(pw + rolname)
    "pg_scram":        28600,  # SCRAM-SHA-256 (hashcat 6.2.6+)
    # Oracle
    "oracle_11g":      112,    # SHA1(pw + salt)
    "oracle_12c":      12300,  # (b) 미구현분 — (a) 위임
    "oracle_10g":      3100,   # DES (b) 미구현분 — (a) 위임
}


def _detect_hashcat(hashcat_path: Optional[str]) -> Optional[str]:
    """hashcat 바이너리 경로 결정.

    hashcat_path가 None → PATH에서 자동탐지.
    바이너리 없으면 None (graceful skip 신호).
    경로 존재·실행권한 검증.
    """
    if hashcat_path:
        if os.path.isfile(hashcat_path) and os.access(hashcat_path, os.X_OK):
            return hashcat_path
        log.warning("hashcat 경로 존재·권한 없음: %s → (a) 스킵", hashcat_path)
        return None
    # PATH 자동탐지
    found = shutil.which("hashcat")
    if found and os.access(found, os.X_OK):
        return found
    return None


def _make_secure_tempfile() -> tuple[int, str]:
    """0600 권한 임시 파일 생성. (fd, path) 반환."""
    fd, path = tempfile.mkstemp(prefix="pwcrack_", suffix=".tmp")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass
    return fd, path


def _normalize_hash(h: str) -> str:
    """해시 문자열 정규화 (대소문자 무시 비교용).

    hashcat potfile은 소문자 hex로 기록하지만 export는 대문자를 쓰는 경우가 있다.
    (예: mysql_native *2470...E19 → potfile에는 *2470...e19로 기록)
    casefold()로 통일해 대소문자 불일치로 인한 false-negative를 방지한다.
    """
    return h.casefold()


def export_for_external(
    engine: str,
    accounts: list["AccountInfo"],
) -> dict[int, list[str]]:
    """(b) 미스/미지원 계정을 hashcat 모드별 hashline으로 직렬화.

    반환: {mode_number: [hashline, ...]}
    빈 accounts → 빈 dict.

    (b) 이미 취약 판정된 계정은 제외하고 uncracked(미스+미지원) 계정만 대상.
    포맷 (검증된 모드만 포함):
      mysql_native (*HEX)                  → mode 300, hashline=hash 그대로
      mssql 0x0200 (0x0200...)             → mode 1731, hashline=hash 그대로
      postgres md5 (md5<hex>)              → mode 12, hashline=hash:rolname (pg md5 포맷)
      postgres SCRAM-SHA-256               → mode 28600, hashline=hash 그대로
      oracle 11g (S:...)                   → mode 112, hashline=hash 그대로

    H-2: 미검증 포맷은 export에서 명시적으로 제외 — 운영자 수동 hashcat 필요:
      mssql 0x0100: mode 131 미검증 (KAT 미확보, 실데이터 없음)
      oracle 12c T:: mode 12300 미검증 (KAT 미확보, 실데이터 없음)
      oracle 10g DES: 포맷 식별 어려움 (운영자 직접 실행)
      caching_sha2: 모드 미확정 (외부 KAT 미확보)
    """
    result: dict[int, list[str]] = {}

    def _add(mode: int, line: str) -> None:
        result.setdefault(mode, []).append(line)

    for account in accounts:
        h = account.hash_str
        if not h:
            continue  # 빈 해시: (b) 이미 취약 처리 또는 잠금 스킵

        if engine in ("mariadb", "mysql"):
            plugin = account.plugin
            if plugin == "caching_sha2_password" or h.startswith("$A$"):
                # caching_sha2: 모드 미확정, 외부 KAT 미확보 → 미지원
                # 운영자 수동 hashcat 필요 (H-2: 미검증 포맷 export 제외)
                pass
            elif h.startswith("*") and len(h) == 41:
                _add(_HASHCAT_MODE["mysql_native"], h)

        elif engine == "mssql":
            upper = h.upper()
            if upper.startswith("0X0200"):
                _add(_HASHCAT_MODE["mssql_0x0200"], h)
            # 0x0100: mode 131 미검증 (KAT 미확보, 실데이터 없음) → H-2: export 제외
            # 운영자 수동 hashcat 필요

        elif engine == "postgresql":
            if h.startswith("SCRAM-SHA-256"):
                _add(_HASHCAT_MODE["pg_scram"], h)
            elif h.startswith("md5") and len(h) == 35:
                # postgres md5 hashcat 형식: hash:username
                rolname = account.rolname or account.name
                _add(_HASHCAT_MODE["pg_md5"], f"{h}:{rolname}")

        elif engine == "oracle":
            upper_h = h.upper()
            if upper_h.startswith("S:"):
                _add(_HASHCAT_MODE["oracle_11g"], h)
            # T: (12c): mode 12300 미검증 (KAT 미확보) → H-2: export 제외
            # 10g DES: 포맷 식별 어려움 → export 제외
            # 두 경우 모두 운영자 수동 hashcat 필요

    return result


def _write_wordlist_from_pwdict(fd: int, path: str) -> None:
    """pwdict 내장 사전을 임시 wordlist 파일에 기록."""
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for pw in COMMON_WEAK_PASSWORDS:
                fh.write(pw + "\n")
    except Exception as exc:  # noqa: BLE001
        log.warning("pwdict wordlist 기록 실패 path=%s: %s", path, exc)


def run_hashcat(
    mode_map: dict[int, list[str]],
    wordlist: Optional[str],
    rules: Optional[str],
    hashcat_path: str,
    timeout: int,
) -> set[str]:
    """hashcat을 모드별로 실행해 크랙된 hash 집합 반환.

    §7 보안:
      - potfile은 hash:plaintext 형식 — hash만 식별, 평문은 읽되 즉시 폐기.
      - 임시파일(hashfile, potfile, wordlist)은 0600 + finally 삭제.
      - subprocess 인자 리스트형(셸 인젝션 차단).
      - 예외/timeout → 빈 결과(부분결과 가능), 크래시 없음.

    반환: 크랙된 hash 문자열 집합 (potfile에서 추출).
    """
    if not mode_map:
        return set()

    cracked_hashes: set[str] = set()
    # wordlist 관리: None이면 pwdict 폴백(임시파일)
    tmp_wordlist_path: Optional[str] = None
    wordlist_path = wordlist

    if not wordlist_path:
        fd_wl, tmp_wordlist_path = _make_secure_tempfile()
        wordlist_path = tmp_wordlist_path
        _write_wordlist_from_pwdict(fd_wl, tmp_wordlist_path)
    elif not os.path.isfile(wordlist_path):
        log.warning("hashcat wordlist 없음: %s → pwdict 폴백", wordlist_path)
        fd_wl, tmp_wordlist_path = _make_secure_tempfile()
        wordlist_path = tmp_wordlist_path
        _write_wordlist_from_pwdict(fd_wl, tmp_wordlist_path)

    try:
        for mode, hashlines in mode_map.items():
            if not hashlines:
                continue
            # 임시 hashfile (0600)
            fd_hf, hashfile_path = _make_secure_tempfile()
            # 임시 potfile (0600) — 두 번째 생성 실패 시 첫 번째 fd/파일 정리 (L-1)
            try:
                fd_pot, potfile_path = _make_secure_tempfile()
            except Exception:
                try:
                    os.close(fd_hf)
                except OSError:
                    pass
                try:
                    os.unlink(hashfile_path)
                except OSError:
                    pass
                continue
            try:
                # hashfile 기록
                try:
                    with os.fdopen(fd_hf, "w", encoding="utf-8") as fh:
                        for line in hashlines:
                            fh.write(line + "\n")
                except Exception as exc:  # noqa: BLE001
                    log.warning("hashfile 기록 실패 mode=%d: %s", mode, exc)
                    os.close(fd_pot)
                    continue
                finally:
                    # fdopen이 성공하면 fd는 닫혀있음; 실패시도 닫아야 함
                    # (fdopen은 fd를 넘기면 소유권 이전 → try-finally에서 이중닫기 방지)
                    pass

                # potfile fd 닫기 (hashcat이 직접 씀)
                try:
                    os.close(fd_pot)
                except OSError:
                    pass

                # hashcat 실행 (리스트형 — 셸 인젝션 차단)
                cmd = [
                    hashcat_path,
                    "-m", str(mode),
                    "-a", "0",
                    hashfile_path,
                    wordlist_path,
                    "--potfile-path", potfile_path,
                    "--quiet",
                    "--force",
                ]
                if rules and os.path.isfile(rules):
                    cmd += ["-r", rules]
                elif rules:
                    log.warning("hashcat rules 파일 없음: %s → 룰 없이 실행", rules)

                try:
                    subprocess.run(
                        cmd,
                        timeout=timeout,
                        capture_output=True,
                    )
                except subprocess.TimeoutExpired:
                    log.warning(
                        "hashcat timeout(mode=%d, timeout=%ds) → 부분결과 반영",
                        mode, timeout,
                    )
                except FileNotFoundError:
                    log.warning("hashcat 바이너리 실행 실패: %s", hashcat_path)
                    break  # 바이너리 문제 → 모든 모드 중단
                except Exception as exc:  # noqa: BLE001
                    log.warning("hashcat 실행 예외 mode=%d: %s", mode, type(exc).__name__)

                # potfile 파싱: export hashline startswith 매칭 (H-1 수정)
                # rfind(":") 기반 추출 폐기 — 평문에 ":" 포함 시 오탐.
                # hashcat potfile 형식: <hash>:<plaintext> (§7: plaintext 즉시 폐기)
                # 각 export hashline을 정규화해 potfile 라인 접두 매칭.
                # 정규화(_normalize_hash=casefold): hashcat 소문자/export 대문자 불일치 해소.
                _norm_exports = {_normalize_hash(line): line for line in hashlines}
                try:
                    with open(potfile_path, encoding="utf-8", errors="replace") as fh:
                        for raw_line in fh:
                            raw_line = raw_line.rstrip("\n\r")
                            if not raw_line:
                                continue
                            raw_norm = _normalize_hash(raw_line)
                            for norm_export in _norm_exports:
                                # potline = normalized_hashline + ":" + plaintext
                                # §7: plaintext 부분은 읽되 즉시 폐기(변수 저장 없음)
                                if raw_norm.startswith(norm_export + ":"):
                                    cracked_hashes.add(norm_export)
                                    break
                except Exception as exc:  # noqa: BLE001
                    log.warning("potfile 파싱 실패 mode=%d: %s", mode, type(exc).__name__)

            finally:
                # 임시파일 삭제 (§7: 보안)
                for tmp_path in (hashfile_path, potfile_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    finally:
        # pwdict 폴백 wordlist 삭제
        if tmp_wordlist_path:
            try:
                os.unlink(tmp_wordlist_path)
            except OSError:
                pass

    return cracked_hashes


def _map_cracked_to_accounts(
    cracked_hashes: set[str],
    miss_accounts: list["AccountInfo"],
) -> list[str]:
    """크랙된 hash 집합 → 취약 계정 citation 리스트.

    §7: citation에 계정명만 포함, 평문 없음.
    고정 문구: "계정 X: 사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)"

    cracked_hashes: run_hashcat이 반환하는 _normalize_hash() 정규화된 export hashline 집합.
    H-1 수정: account.hash_str을 동일하게 정규화 후 비교.
      postgres md5는 export hashline이 "hash:rolname" 형식이므로 함께 정규화.
    """
    citations: list[str] = []
    for account in miss_accounts:
        h = account.hash_str
        # export hashline 재구성: postgres md5는 export 시 "hash:rolname" 형식
        if h.startswith("md5") and len(h) == 35 and account.rolname:
            export_hashline = f"{h}:{account.rolname}"
        else:
            export_hashline = h
        # _normalize_hash로 정규화해 대소문자 불일치 무관하게 매칭
        if _normalize_hash(export_hashline) in cracked_hashes:
            log.debug("DBM-001 (a): 크랙 계정=%s (평문 비공개)", account.name)
            citations.append(
                f"계정 {account.name}: 사전/규칙 크랙으로 약한 비밀번호 확인(평문 비공개)"
            )
    return citations


# ══════════════════════════════════════════════════════════════════════════════
# §A. 포맷별 해시 verifier
# ══════════════════════════════════════════════════════════════════════════════

def _verify_mysql_native(password: str, hash_str: str) -> bool:
    """MySQL/MariaDB mysql_native_password: *SHA1(SHA1(pw)).upper()

    KAT: password → *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
    """
    if not hash_str.startswith("*") or len(hash_str) != 41:
        return False
    try:
        pw_bytes = password.encode("utf-8")
        inner = hashlib.sha1(pw_bytes).digest()
        outer = hashlib.sha1(inner).digest()
        expected = "*" + outer.hex().upper()
        return hmac.compare_digest(expected, hash_str.upper())
    except Exception:  # noqa: BLE001
        return False


def _generate_mysql_native(password: str) -> str:
    """KAT/테스트용 mysql_native 해시 생성."""
    pw_bytes = password.encode("utf-8")
    inner = hashlib.sha1(pw_bytes).digest()
    outer = hashlib.sha1(inner).digest()
    return "*" + outer.hex().upper()


def _verify_mssql(password: str, hash_hex: str) -> bool:
    """MSSQL 비밀번호 해시 검증.

    0x0200: SHA512(pw.encode('utf-16-le') + salt8)
      - hash_hex 형식: 0x0200<salt16hex><sha512_128hex>  (총 148 hex chars after 0x)
    0x0100: SHA1(pw.upper().encode('utf-16-le') + salt8)
      - hash_hex 형식: 0x0100<salt8hex><sha1_40hex + padding>

    §3 설계: hx = bytes.fromhex(hash_hex[2:])
      0x0200: hx[0:2]=0x0200, hx[2:6]=case_salt(4byte, ignored?), hx[6:14]=salt(8byte), hx[14:78]=sha512
      실측: "0x0200<4hex=case_salt><16hex=salt><128hex=sha512>"
        → hx[0:2]=b'\x02\x00'  hx[2:4]=case_salt  hx[4:12]=salt8  hx[12:76]=sha512

    실데이터 확인:
      0x020036CB5F90FC845FF0AE20434BE2BF018C1B22F7190A80A97...
      → 0x + 0200 + 36CB5F90FC845FF0AE20 (10bytes=5byte?) 재확인 필요

    실제 MSSQL 0x0200 레이아웃 (공식):
      바이트: [version:2][SALT:4][hash:64]  → 총 70bytes = 140 hex chars after '0x'
      but variant exists: some store [version:2][case_salt:2][salt:4][hash:64] = 72bytes

    실데이터 길이 확인으로 레이아웃 결정.
    """
    if not hash_hex or not hash_hex.upper().startswith("0X"):
        return False
    try:
        hx = bytes.fromhex(hash_hex[2:])
    except Exception:  # noqa: BLE001
        return False

    version = hx[:2]

    if version == b"\x02\x00":
        # 0x0200: SHA512(UTF-16LE(pw) + salt)
        # 레이아웃 탐지: len 72 = version(2)+case_salt(2)+salt(4)+hash(64) or len 70 = version(2)+salt(4)+hash(64)
        if len(hx) == 70:
            salt = hx[2:6]
            stored_hash = hx[6:70]
        elif len(hx) == 72:
            # case_salt(2) 존재 변형
            salt = hx[4:8]
            stored_hash = hx[8:72]
        else:
            # 길이 기반 일반화: 마지막 64바이트=hash, 그 앞 4~8=salt
            # 가장 안전한 방법: 마지막에서 역산
            stored_hash = hx[-64:]
            # salt는 version(2) 이후 ~ hash(-64) 전 사이 마지막 4바이트
            pre = hx[2:-64]
            if len(pre) < 4:
                return False
            salt = pre[-4:]
        try:
            computed = hashlib.sha512(
                password.encode("utf-16-le") + salt
            ).digest()
            return hmac.compare_digest(computed, stored_hash)
        except Exception:  # noqa: BLE001
            return False

    elif version == b"\x01\x00":
        # 0x0100(SQL2000/2005 구형): 레이아웃 KAT 미확보 → 미지원.
        # _parse_mssql_accounts에서 이미 unsupported=True로 분류하므로
        # 이 분기는 정상 경로에서 호출되지 않는다.
        # Medium-1(Phase 4c Opus 리뷰): 레이아웃 오류 위험 → False 반환으로 안전 처리.
        return False

    return False


def _generate_mssql_0200(password: str, salt: bytes) -> str:
    """KAT/테스트용 MSSQL 0x0200 해시 생성 (salt 4bytes)."""
    h = hashlib.sha512(password.encode("utf-16-le") + salt).digest()
    raw = b"\x02\x00" + salt + h
    return "0x" + raw.hex().upper()


def _verify_postgres_scram(password: str, hash_str: str) -> bool:
    """PostgreSQL SCRAM-SHA-256 비밀번호 검증.

    형식: SCRAM-SHA-256$<iterations>:<b64salt>$<b64StoredKey>:<b64ServerKey>
    검증 방법 (RFC 5802):
      SaltedPassword = PBKDF2(SHA256, pw, salt, iterations)
      ServerKey = HMAC(SaltedPassword, "Server Key")
      저장된 b64ServerKey와 비교.
    """
    prefix = "SCRAM-SHA-256$"
    if not hash_str.startswith(prefix):
        return False
    rest = hash_str[len(prefix):]
    # <iterations>:<b64salt>$<b64StoredKey>:<b64ServerKey>
    try:
        iter_salt_part, keys_part = rest.split("$", 1)
        iterations_str, b64salt = iter_salt_part.split(":", 1)
        iterations = int(iterations_str)
        b64stored_key, b64server_key = keys_part.split(":", 1)
        salt = base64.b64decode(b64salt)
        stored_server_key = base64.b64decode(b64server_key)
    except Exception:  # noqa: BLE001
        return False

    try:
        pw_bytes = password.encode("utf-8")
        salted_password = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iterations)
        server_key = hmac.new(salted_password, b"Server Key", "sha256").digest()
        return hmac.compare_digest(server_key, stored_server_key)
    except Exception:  # noqa: BLE001
        return False


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


def _verify_postgres_md5(password: str, hash_str: str, rolname: str = "") -> bool:
    """PostgreSQL md5 비밀번호 검증: md5<hex(md5(pw+rolname))>."""
    if not hash_str.startswith("md5") or len(hash_str) != 35:
        return False
    try:
        combined = (password + rolname).encode("utf-8")
        expected = "md5" + hashlib.md5(combined).hexdigest()
        return hmac.compare_digest(expected, hash_str.lower())
    except Exception:  # noqa: BLE001
        return False


def _generate_postgres_md5(password: str, rolname: str = "") -> str:
    """KAT/테스트용 postgres md5 해시 생성."""
    combined = (password + rolname).encode("utf-8")
    return "md5" + hashlib.md5(combined).hexdigest()


def _verify_oracle_11g(password: str, hash_str: str) -> bool:
    """Oracle 11g S: 해시 검증.

    형식: S:<40HEX_hash><20HEX_salt> (총 60 hex chars after 'S:')
    알고리즘: SHA1(password.encode('utf-8') + salt_raw)

    수정 이력 (Phase 4c Opus 리뷰 Critical-1):
      - 이전 오류: SHA1(UPPER(pw).encode('utf-16-be') + salt)
      - 정답: Oracle 11g는 대소문자 보존(upper 없음), raw UTF-8 바이트
      - passlib 외부벡터 검증:
          pw='password', S: = 4143053633E59B4992A8EA17D2FF542C9EDEB335C886EED9C80450C1B4E6
          SHA1(b'password' + unhexlify('C886EED9C80450C1B4E6')).upper()
          == '4143053633E59B4992A8EA17D2FF542C9EDEB335'  ✓
    """
    if not hash_str.upper().startswith("S:") or len(hash_str) < 62:
        return False
    try:
        body = hash_str[2:].upper()  # 60 hex chars
        stored_hash_hex = body[:40]
        salt_hex = body[40:60]
        stored_hash = bytes.fromhex(stored_hash_hex)
        salt = bytes.fromhex(salt_hex)
        # Oracle 11g: SHA1(pw.encode('utf-8') + salt) — 대소문자 보존, raw UTF-8
        computed = hashlib.sha1(
            password.encode("utf-8") + salt
        ).digest()
        return hmac.compare_digest(computed, stored_hash)
    except Exception:  # noqa: BLE001
        return False


def _generate_oracle_11g(password: str, salt: bytes) -> str:
    """KAT/테스트용 Oracle 11g S: 해시 생성.

    알고리즘: SHA1(pw.encode('utf-8') + salt) — 대소문자 보존, raw UTF-8.
    """
    h = hashlib.sha1(password.encode("utf-8") + salt).digest()
    return "S:" + h.hex().upper() + salt.hex().upper()


# ══════════════════════════════════════════════════════════════════════════════
# §B. 계정 행 파서 (엔진별 RESULT 행 → 표준화된 AccountInfo)
# ══════════════════════════════════════════════════════════════════════════════

class AccountInfo:
    """파싱된 계정 정보."""
    __slots__ = ("name", "hash_str", "plugin", "is_locked", "is_expired",
                 "is_disabled", "unsupported_format", "rolname")

    def __init__(
        self,
        name: str,
        hash_str: str,
        plugin: str = "",
        is_locked: bool = False,
        is_expired: bool = False,
        is_disabled: bool = False,
        unsupported_format: bool = False,
        rolname: str = "",
    ) -> None:
        self.name = name
        self.hash_str = hash_str
        self.plugin = plugin
        self.is_locked = is_locked
        self.is_expired = is_expired
        self.is_disabled = is_disabled
        self.unsupported_format = unsupported_format
        self.rolname = rolname  # postgres md5용


def _parse_mariadb_accounts(rows: list[dict]) -> list[AccountInfo]:
    """MariaDB DBM-001 RESULT 행 → AccountInfo 리스트.

    필드: HOST, USER, PASSWORD, PLUGIN, PASSWORD_EXPIRED
    - PLUGIN=mysql_native_password: *40HEX or ""
    - PASSWORD_EXPIRED=Y → is_expired=True (mariadb.sys 등 잠금 유사)
    """
    accounts: list[AccountInfo] = []
    seen_names: set[str] = set()  # HOST별 중복 계정 → 같은 해시이므로 1개만
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("USER", "")).strip()
        if not name:
            continue
        hash_str = str(row.get("PASSWORD", "")).strip()
        plugin = str(row.get("PLUGIN", "")).strip().lower()
        expired = str(row.get("PASSWORD_EXPIRED", "")).strip().upper() == "Y"
        # HOST별 중복: 해시가 같으므로 이미 본 (name, hash_str) 쌍은 스킵
        key = (name, hash_str)
        if key in seen_names:
            continue
        seen_names.add(key)  # type: ignore[arg-type]
        unsupported = plugin not in ("mysql_native_password", "")
        accounts.append(AccountInfo(
            name=name,
            hash_str=hash_str,
            plugin=plugin,
            is_expired=expired,
            unsupported_format=unsupported,
        ))
    return accounts


def _parse_mysql_accounts(rows: list[dict]) -> list[AccountInfo]:
    """MySQL DBM-001 RESULT 행 → AccountInfo 리스트.

    필드: HOST, USER, AUTHENTICATION_STRING, PLUGIN, ACCOUNT_LOCKED
    - PLUGIN=caching_sha2_password: $A$... (비활성)
    - PLUGIN=mysql_native_password: *HEX
    """
    accounts: list[AccountInfo] = []
    seen: set[tuple] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("USER", "")).strip()
        if not name:
            continue
        hash_str = str(row.get("AUTHENTICATION_STRING", "")).strip()
        plugin = str(row.get("PLUGIN", "")).strip().lower()
        locked = str(row.get("ACCOUNT_LOCKED", "")).strip().upper() == "Y"
        key = (name, hash_str)
        if key in seen:
            continue
        seen.add(key)
        # placeholder 해시 → 스킵 (MySQL 내장 계정)
        if _MYSQL_PLACEHOLDER in hash_str:
            continue
        unsupported = False
        if plugin == "caching_sha2_password":
            if not _CACHING_SHA2_ENABLED:
                unsupported = True  # (a) 위임
        elif plugin not in ("mysql_native_password", ""):
            unsupported = True
        accounts.append(AccountInfo(
            name=name,
            hash_str=hash_str,
            plugin=plugin,
            is_locked=locked,
            unsupported_format=unsupported,
        ))
    return accounts


def _parse_mssql_accounts(rows: list[dict]) -> list[AccountInfo]:
    """MSSQL DBM-001 RESULT 행 → AccountInfo 리스트.

    필드: name, password_hash, is_disabled
    - is_disabled=1 → 계정 비활성 → 잠금으로 처리
    """
    accounts: list[AccountInfo] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        hash_str = str(row.get("password_hash", "")).strip()
        disabled = str(row.get("is_disabled", "0")).strip() == "1"
        if name in seen:
            continue
        seen.add(name)
        upper_hash = hash_str.upper()
        # 0x0100(SQL2000/2005 구형): 레이아웃 KAT 미확보 → 미지원으로 강등 (안전·정직).
        # 실데이터에 0x0100 계정 없음 확인. 향후 KAT 확보 시 0x0100 verifier 활성화 가능.
        # Phase 4c Opus 리뷰 Medium-1: 이전 코드는 레이아웃 오류(salt 위치 잘못 계산)로
        # 조용한 오탐 위험 → 미지원 강등이 더 안전하고 정직한 선택.
        unsupported = not (
            upper_hash.startswith("0X0200")
            or hash_str == ""
        )
        accounts.append(AccountInfo(
            name=name,
            hash_str=hash_str,
            plugin="mssql",
            is_disabled=disabled,
            unsupported_format=unsupported,
        ))
    return accounts


# postgres 행 파싱: RESULT_2는 {"*": python_repr 문자열} 형식
# 세 가지 형식 지원:
#   1) JSON 형식: "rolname": "...", "rolpassword": "..."
#   2) Python repr 형식: 'rolname': '...', 'rolpassword': '...'
#   3) 혼합 형식(실 수집): "rolname": '...', "rolpassword": '...' (실데이터 확인됨)
_PG_ROLNAME_RE = re.compile(r"'rolname'\s*:\s*'([^']+)'")
_PG_ROLPWD_RE = re.compile(r"'rolpassword'\s*:\s*'([^']+)'")
_PG_ROLNAME_JSON_RE = re.compile(r'"rolname"\s*:\s*"([^"]+)"')
_PG_ROLPWD_JSON_RE = re.compile(r'"rolpassword"\s*:\s*"([^"]+)"')
# 혼합 형식: 키는 이중따옴표, 값은 단따옴표 (실데이터 postgresql_native_result.json)
_PG_ROLNAME_MIX_RE = re.compile(r'"rolname"\s*:\s*\'([^\']+)\'')
_PG_ROLPWD_MIX_RE = re.compile(r'"rolpassword"\s*:\s*\'([^\']+)\'')


def _parse_postgres_row(row: dict) -> Optional[tuple[str, str]]:
    """postgres RESULT_2 행에서 (rolname, rolpassword) 추출.

    세 가지 형식을 순서대로 시도:
      1) row에 직접 키가 있는 경우 (파싱된 JSON)
      2) JSON 형식 {"*": '"rolname": "...", "rolpassword": "..."'}
      3) 혼합 형식 {"*": '"rolname": \'...\', "rolpassword": \'...\''}  ← 실데이터
      4) Python repr 형식 {"*": "'rolname': '...', 'rolpassword': '...'"}
    """
    if "rolname" in row and "rolpassword" in row:
        return str(row["rolname"]), str(row["rolpassword"])
    # {"*": python repr 또는 JSON 또는 혼합 형식 문자열}
    raw = str(row.get("*", ""))
    # 1. JSON 형식 (이중따옴표 키+값)
    m_name = _PG_ROLNAME_JSON_RE.search(raw)
    m_pwd = _PG_ROLPWD_JSON_RE.search(raw)
    if m_name and m_pwd:
        return m_name.group(1), m_pwd.group(1)
    # 2. 혼합 형식 (이중따옴표 키, 단따옴표 값) ← 실데이터 postgresql_native
    m_name = _PG_ROLNAME_MIX_RE.search(raw)
    m_pwd = _PG_ROLPWD_MIX_RE.search(raw)
    if m_name and m_pwd:
        return m_name.group(1), m_pwd.group(1)
    # 3. Python repr 형식 (단따옴표 키+값)
    m_name = _PG_ROLNAME_RE.search(raw)
    m_pwd = _PG_ROLPWD_RE.search(raw)
    if m_name and m_pwd:
        return m_name.group(1), m_pwd.group(1)
    return None


def _parse_postgres_accounts(data: dict) -> list[AccountInfo]:
    """PostgreSQL DBM-001_1 + DBM-001_2 → AccountInfo 리스트.

    DBM-001_1: password_encryption 설정 (메타, 계정 없음)
    DBM-001_2: 계정별 rolname + rolpassword
    """
    accounts: list[AccountInfo] = []
    seen: set[str] = set()

    rows2 = data.get("DBM-001_2", {}).get("RESULT", [])
    for row in rows2:
        if not isinstance(row, dict):
            continue
        parsed = _parse_postgres_row(row)
        if not parsed:
            continue
        rolname, rolpassword = parsed
        if rolname in seen:
            continue
        seen.add(rolname)
        if not rolpassword or rolpassword.lower() in ("null", "none", ""):
            # NULL 비번 → 빈 해시로 처리
            accounts.append(AccountInfo(name=rolname, hash_str="", rolname=rolname))
            continue
        unsupported = not (
            rolpassword.startswith("SCRAM-SHA-256")
            or rolpassword.startswith("md5")
        )
        accounts.append(AccountInfo(
            name=rolname,
            hash_str=rolpassword,
            plugin="postgresql",
            unsupported_format=unsupported,
            rolname=rolname,
        ))
    return accounts


def _parse_oracle_accounts(data: dict) -> list[AccountInfo]:
    """Oracle DBM-001 RESULT → AccountInfo 리스트.

    현재 native 샘플에 DBM-001 없음 → 빈 리스트 반환.
    코드는 11g S: 지원. 데이터 있으면 파싱.
    """
    accounts: list[AccountInfo] = []
    rows = data.get("DBM-001", {}).get("RESULT", [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        # spare4 컬럼 형식: {"USERNAME": ..., "spare4": "S:..."}
        name = str(row.get("USERNAME", row.get("NAME", ""))).strip()
        if not name:
            continue
        spare4 = str(row.get("spare4", row.get("SPARE4", ""))).strip()
        unsupported = not spare4.upper().startswith("S:")
        accounts.append(AccountInfo(
            name=name,
            hash_str=spare4,
            plugin="oracle",
            unsupported_format=unsupported,
        ))
    return accounts


# ══════════════════════════════════════════════════════════════════════════════
# §C. 엔진별 계정 해시 verifier 디스패처
# ══════════════════════════════════════════════════════════════════════════════

def _verify_account(
    engine: str,
    account: AccountInfo,
    password: str,
) -> bool:
    """엔진×포맷에 맞는 verifier로 password가 account.hash_str와 일치하는지 확인."""
    h = account.hash_str

    if engine in ("mariadb", "mysql"):
        plugin = account.plugin
        if plugin == "caching_sha2_password":
            if not _CACHING_SHA2_ENABLED:
                return False
            # 미구현 — caching_sha2 비활성
            return False
        # mysql_native_password 또는 빈 plugin
        return _verify_mysql_native(password, h)

    if engine == "mssql":
        return _verify_mssql(password, h)

    if engine == "postgresql":
        if h.startswith("SCRAM-SHA-256"):
            return _verify_postgres_scram(password, h)
        if h.startswith("md5"):
            return _verify_postgres_md5(password, h, account.rolname)
        return False

    if engine == "oracle":
        return _verify_oracle_11g(password, h)

    return False


# ══════════════════════════════════════════════════════════════════════════════
# §D. 빈 해시 & 잠금 판단
# ══════════════════════════════════════════════════════════════════════════════

def _is_empty_hash(hash_str: str) -> bool:
    """빈 문자열 = 비밀번호 미설정."""
    return hash_str.strip() == ""


def _is_locked_account(account: AccountInfo) -> bool:
    """잠금/비활성/만료 계정 여부.

    MariaDB PASSWORD_EXPIRED=Y, MySQL ACCOUNT_LOCKED=Y,
    MSSQL is_disabled=1 모두 잠금으로 처리.
    """
    return account.is_locked or account.is_expired or account.is_disabled


# ══════════════════════════════════════════════════════════════════════════════
# §E. 메인 크랙 로직
# ══════════════════════════════════════════════════════════════════════════════

def _crack_accounts(
    engine: str,
    accounts: list[AccountInfo],
) -> tuple[list[str], list[str], bool]:
    """계정 리스트에 대해 사전공격 수행.

    반환: (weak_citations, unsupported_names, truncated)
      weak_citations: 취약 계정 고정 문구 리스트 (§7)
      unsupported_names: 미지원 포맷 계정명 리스트 ((a) 위임)
      truncated: 계정 수 MAX_ACCOUNTS 초과로 절단 여부
    """
    weak_citations: list[str] = []
    unsupported_names: list[str] = []
    truncated = False

    proc_accounts = accounts[:_MAX_ACCOUNTS]
    if len(accounts) > _MAX_ACCOUNTS:
        truncated = True
        log.warning(
            "DBM-001 crack: 계정 수 %d > MAX_ACCOUNTS %d → 절단",
            len(accounts), _MAX_ACCOUNTS,
        )

    for account in proc_accounts:
        name = account.name
        h = account.hash_str

        # 1. 빈 해시 = 비번 미설정
        if _is_empty_hash(h):
            if _is_locked_account(account):
                # 잠금/만료 계정의 빈 해시는 스킵 (거짓취약 방지: mariadb.sys 등)
                log.debug("DBM-001: 빈해시 스킵(잠금/만료) 계정=%s", name)
                continue
            log.debug("DBM-001: 빈해시 취약 계정=%s", name)
            weak_citations.append(f"계정 {name}: 비밀번호 미설정(빈 해시)")
            continue

        # 2. 미지원 포맷 스킵
        if account.unsupported_format:
            unsupported_names.append(name)
            log.debug("DBM-001: 미지원포맷 계정=%s plugin=%s", name, account.plugin)
            continue

        # 3. 잠금/비활성 계정 → 크랙 불필요 (비밀번호 사용 불가)
        if _is_locked_account(account):
            log.debug("DBM-001: 잠금/비활성 계정=%s 크랙 스킵", name)
            continue

        # 4. 사전공격
        candidates = candidates_for_account(name)
        matched = False
        for pw in candidates:
            try:
                if _verify_account(engine, account, pw):
                    # §7: 평문 즉시 폐기, 계정명만 기록
                    log.debug("DBM-001: 사전매치 계정=%s (평문 비공개)", name)
                    weak_citations.append(
                        f"계정 {name}: 기본/사전 비밀번호 사용(평문 비공개)"
                    )
                    matched = True
                    break
            except Exception as exc:  # noqa: BLE001
                log.warning("DBM-001: verifier 예외 계정=%s: %s", name, exc)
                break
        if not matched:
            log.debug("DBM-001: 미매치 계정=%s", name)

    return weak_citations, unsupported_names, truncated


# ══════════════════════════════════════════════════════════════════════════════
# §F. 엔진별 데이터 파싱 + 크랙 통합
# ══════════════════════════════════════════════════════════════════════════════

def _has_dbm001_key(data: dict) -> bool:
    """data에 DBM-001 또는 DBM-001_N 키가 있는지 확인."""
    for k in data:
        if k == "DBM-001" or k.startswith("DBM-001_"):
            return True
    return False


def _has_result_rows(data: dict) -> bool:
    """DBM-001 관련 키의 RESULT가 비어있지 않은지 확인."""
    for k in data:
        if k == "DBM-001" or k.startswith("DBM-001_"):
            rows = data[k].get("RESULT", [])
            if rows:
                return True
    return False


def crack_judge(
    engine: str,
    data: dict,
    variant: str,
    hashcat_opts: Optional["HashcatOpts"] = None,
) -> ForcedVerdict:
    """DBM-001 결정론 판정 진입점.

    engine: mariadb/mysql/mssql/postgresql/oracle
    data: db_json._build_raw_data_dict()이 조립한 비마스킹 dict
    variant: e.g. "mariadb_native"
    hashcat_opts: HashcatOpts 또는 None (None → (a) 스킵, (b)-only 동작)

    §A2.3 오케스트레이션:
      1. (b) 먼저 실행(즉시 기본 탐지).
      2. (a) 활성화 게이트: hashcat_opts≠None, 바이너리 존재 시 (b) 미스 계정을 hashcat에 투입.
      3. (b)∪(a) 크랙≥1 → 취약 / 둘다0 → 판단보류 / 무데이터 → handled=False.

    반환 ForcedVerdict:
      - 사전매치 or 빈해시(미잠금) or (a) 크랙 → 취약 (conf=0.9, handled=True)
      - 매치0 → 판단보류 (conf=0.0, handled=True, ev=review)
      - 증거없음 → handled=False (폴백)
    """
    # ── 증거가드 1: DBM-001 key 없음 ──────────────────────────────────────────
    if not _has_dbm001_key(data):
        log.debug("DBM-001 crack: data_key 없음 engine=%s variant=%s", engine, variant)
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[증거 부재: DBM-001 data_key 없음 → 미수집 또는 해당 엔진 미대상] "
                f"(engine={engine}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 증거가드 2: RESULT 완전 비어있음 ──────────────────────────────────────
    if not _has_result_rows(data):
        log.debug("DBM-001 crack: RESULT 빔 engine=%s", engine)
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[증거 부재: DBM-001 RESULT 행 없음 → 데이터 미수집] "
                f"(engine={engine}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 엔진별 계정 파싱 ──────────────────────────────────────────────────────
    accounts: list[AccountInfo] = []
    if engine == "mariadb":
        rows = data.get("DBM-001", {}).get("RESULT", [])
        accounts = _parse_mariadb_accounts(rows)
    elif engine == "mysql":
        rows = data.get("DBM-001", {}).get("RESULT", [])
        accounts = _parse_mysql_accounts(rows)
    elif engine == "mssql":
        rows = data.get("DBM-001", {}).get("RESULT", [])
        accounts = _parse_mssql_accounts(rows)
    elif engine == "postgresql":
        accounts = _parse_postgres_accounts(data)
    elif engine == "oracle":
        accounts = _parse_oracle_accounts(data)
    else:
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=f"[미지원 엔진: {engine}] DBM-001 크랙 불가",
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── 계정 없음 → handled=False (데이터 구조 이상) ─────────────────────────
    if not accounts:
        return ForcedVerdict(
            verdict="판단보류",
            confidence=0.0,
            rationale=(
                f"[증거 부재: 파싱된 계정 없음 → 데이터 구조 미지원 또는 미수집] "
                f"(engine={engine}, variant={variant})"
            ),
            citations=[],
            ev_status="review",
            handled=False,
        )

    # ── (b) 사전공격 실행 ────────────────────────────────────────────────────
    weak_citations, unsupported_names, truncated = _crack_accounts(engine, accounts)

    # ── (a) hashcat 연동: (b) 미스 계정 → hashcat ────────────────────────────
    # §A2.3: (b) 취약 시 early-return(성능). (b) 미스 시만 (a) 시도.
    # hashcat_opts: 직접 인자 우선, 없으면 모듈 세임(_current_hashcat_opts) 참조.
    hashcat_citations: list[str] = []
    pwcrack_a_status: str = "skipped(no hashcat)"  # 메타 기록용

    # 직접 인자가 None이면 모듈 세임에서 읽음 (JudgeContext 주입 경로)
    _opts = hashcat_opts if hashcat_opts is not None else _current_hashcat_opts

    if not weak_citations and _opts is not None:
        # (a) 활성화 게이트: 바이너리 탐지
        hc_bin = _detect_hashcat(_opts.hashcat_path)
        if hc_bin is None:
            pwcrack_a_status = "skipped(no hashcat)"
            log.debug("DBM-001 (a): hashcat 바이너리 부재 → 스킵 (engine=%s)", engine)
        else:
            pwcrack_a_status = "active"
            # (b) 미스 계정 = 크랙 시도할 계정들 (잠금/빈해시/미지원 제외)
            miss_accounts = [
                acc for acc in accounts
                if (
                    not _is_empty_hash(acc.hash_str)
                    and not _is_locked_account(acc)
                    and acc.hash_str  # 빈 해시 재확인
                )
            ]
            if miss_accounts:
                mode_map = export_for_external(engine, miss_accounts)
                if mode_map:
                    try:
                        cracked_hashes = run_hashcat(
                            mode_map=mode_map,
                            wordlist=_opts.wordlist,
                            rules=_opts.rules,
                            hashcat_path=hc_bin,
                            timeout=_opts.timeout,
                        )
                        hashcat_citations = _map_cracked_to_accounts(
                            cracked_hashes, miss_accounts
                        )
                    except Exception as exc:  # noqa: BLE001
                        log.warning(
                            "DBM-001 (a): run_hashcat 예외 engine=%s type=%s → (b) 폴백",
                            engine, type(exc).__name__,
                        )
                        pwcrack_a_status = f"error({type(exc).__name__})"

    # ── 결과 매핑 (b)∪(a) ────────────────────────────────────────────────────
    all_weak_citations = weak_citations + hashcat_citations

    if all_weak_citations:
        rationale_parts: list[str] = []
        if weak_citations:
            rationale_parts.append(
                f"(-) DBM-001 결정론(b): 사전/빈비번 {len(weak_citations)}건 탐지 (engine={engine})"
            )
        if hashcat_citations:
            rationale_parts.append(
                f"(-) DBM-001 결정론(a): hashcat 크랙 {len(hashcat_citations)}건 탐지 (engine={engine})"
            )
        if unsupported_names:
            rationale_parts.append(
                f"미지원포맷 {len(unsupported_names)}계정(미지원 — 운영자 수동 hashcat 필요): "
                + ", ".join(unsupported_names[:5])
            )
        if truncated:
            rationale_parts.append(f"계정 초과 절단(MAX={_MAX_ACCOUNTS}), needs_review")
        return ForcedVerdict(
            verdict="취약",
            confidence=0.9,
            rationale=" | ".join(rationale_parts),
            citations=all_weak_citations,
            ev_status="bad",
            handled=True,
        )

    # 매치 0 케이스 ((b)∪(a) 모두 0)
    rationale_parts = [
        f"(?) DBM-001 결정론(b+a): 사전 미매치 — 판단보류, 수동 확인 필요 (engine={engine})"
    ]
    if pwcrack_a_status != "skipped(no hashcat)":
        rationale_parts.append(f"pwcrack_a={pwcrack_a_status}")
    else:
        rationale_parts.append(f"pwcrack_a={pwcrack_a_status}")
    if unsupported_names:
        rationale_parts.append(
            f"미지원포맷 {len(unsupported_names)}계정(미지원 — 운영자 수동 hashcat 필요): "
            + ", ".join(unsupported_names[:5])
        )
    if truncated:
        rationale_parts.append(f"계정 초과 절단(MAX={_MAX_ACCOUNTS})")

    return ForcedVerdict(
        verdict="판단보류",
        confidence=0.0,
        rationale=" | ".join(rationale_parts),
        citations=[],
        ev_status="review",
        handled=True,
    )

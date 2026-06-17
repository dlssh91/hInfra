from judge_tool.parsers import db_json


def test_mask_row_hash_and_plaintext():
    row = {"USER": "u1", "AUTHENTICATION_STRING": "$A$005$ABCDEF0123456789hash",
           "PLUGIN": "caching_sha2_password", "ACCOUNT_LOCKED": "N"}
    m = db_json._mask_row(row)
    assert "ABCDEF0123456789" not in m["AUTHENTICATION_STRING"]
    assert "REDACTED" in m["AUTHENTICATION_STRING"]
    assert "len=" in m["AUTHENTICATION_STRING"]
    assert m["PLUGIN"] == "caching_sha2_password"   # 비민감 보존
    assert m["ACCOUNT_LOCKED"] == "N"


def test_mask_row_plaintext_password_column():
    # DBM-005류: COLUMN_NAME이 비번류면 RESULT 값(평문)을 마스킹
    row = {"TABLE_SCHEMA": "app", "TABLE_NAME": "users",
           "COLUMN_NAME": "user_password", "RESULT": "PlainText123!,secret9"}
    m = db_json._mask_row(row)
    assert "PlainText123" not in m["RESULT"]
    assert "REDACTED" in m["RESULT"]
    assert m["TABLE_NAME"] == "users"   # 비민감 보존


def test_mask_row_broadened_sensitive_keys():
    row = {"pw": "p4ssw0rd", "credential": "topsecretval",
           "auth_token": "abc.def.ghi", "api_key": "AKIAxyz123"}
    m = db_json._mask_row(row)
    assert "p4ssw0rd" not in m["pw"]
    assert "REDACTED" in m["pw"]
    assert "topsecretval" not in m["credential"]
    assert "REDACTED" in m["credential"]
    assert "abc.def.ghi" not in m["auth_token"]
    assert "REDACTED" in m["auth_token"]
    assert "AKIAxyz123" not in m["api_key"]
    assert "REDACTED" in m["api_key"]


def test_mask_row_no_overmask_regression():
    # 비민감 키는 마스킹되지 않아야 한다(오마스킹 회귀 방지)
    row = {"PRIMARY_KEY": "id_column", "VARIABLE_NAME": "max_connections",
           "COLUMN_NAME": "username", "RESULT": "admin"}
    m = db_json._mask_row(row)
    assert m["PRIMARY_KEY"] == "id_column"
    assert m["VARIABLE_NAME"] == "max_connections"
    assert m["RESULT"] == "admin"   # COLUMN_NAME이 비민감이므로 평문 유지


def test_mask_row_nested_dict():
    row = {"meta": {"AUTHENTICATION_STRING": "$A$005$nestedhashvalue"}}
    m = db_json._mask_row(row)
    assert "nestedhashvalue" not in m["meta"]["AUTHENTICATION_STRING"]
    assert "REDACTED" in m["meta"]["AUTHENTICATION_STRING"]


def test_mask_row_nested_list():
    row = {"rows": [{"password": "plainpw1"}, {"username": "alice"}]}
    m = db_json._mask_row(row)
    assert "plainpw1" not in m["rows"][0]["password"]
    assert "REDACTED" in m["rows"][0]["password"]
    assert m["rows"][1]["username"] == "alice"   # 비민감 보존


import os

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sample_db_mysql.txt")


def test_parse_returns_items_with_context():
    out = db_json.parse(FIX)
    by_id = {cid: (res, ctx) for cid, res, ctx in out}
    assert "DBM-001" in by_id and "DBM-004" in by_id
    # DBM-001: 2행, 해시 마스킹됨
    res001, _ = by_id["DBM-001"]
    assert len(res001) == 2
    assert all("FAKEFAKE" not in r.evidence for r in res001)
    assert any("REDACTED" in r.evidence for r in res001)
    # DBM-017: 빈 RESULT → 실증거 0건 (Phase 4e: raw-carrier 더미 리소스만 있을 수 있음)
    res017, _ = by_id["DBM-017"]
    real_res017 = [r for r in res017 if r.detail != "(raw-carrier)"]
    assert real_res017 == []
    # DBM-011: bare 문자열 행 + NOTE(context)
    res011, ctx011 = by_id["DBM-011"]
    assert any("not loaded" in r.evidence or "not loaded" in r.detail
               for r in res011)
    assert ctx011 and "PISM-011" in ctx011
    # DBM-019: NOTE-only → 실증거 0건, context에 N/A (Phase 4e: raw-carrier 더미 리소스만 있을 수 있음)
    res019, ctx019 = by_id["DBM-019"]
    real_res019 = [r for r in res019 if r.detail != "(raw-carrier)"]
    assert real_res019 == []
    assert ctx019 and "N/A" in ctx019
    # DBM-022: 키only dict → 죽지 않고 처리(빈 resources 또는 context)
    assert "DBM-022" in by_id


def test_parse_dbm011_stray_note_not_evidence_but_context():
    """버그: 실데이터처럼 NOTE가 RESULT 배열 안에 콤마 누락 상태로 들어있을 때,
    진짜 결과("audit_log.so...not loaded")는 evidence 행에 남고, NOTE 값
    ("refer to the PISM-011")은 evidence 행에 절대 들어가면 안 되며
    context에만 들어가야 한다(phantom NOTE 행 금지)."""
    out = db_json.parse(FIX)
    by_id = {cid: (res, ctx) for cid, res, ctx in out}
    res011, ctx011 = by_id["DBM-011"]
    blob = "\n".join((r.evidence or "") + "\n" + (r.detail or "") for r in res011)
    # 진짜 점검 결과는 evidence 행에 유지
    assert "not loaded" in blob, f"진짜 결과행 손실: {blob!r}"
    # NOTE 값은 evidence 행에 절대 없음
    assert "PISM-011" not in blob, f"NOTE가 phantom evidence 행으로 누출됨: {blob!r}"
    assert "refer to" not in blob, f"NOTE가 phantom evidence 행으로 누출됨: {blob!r}"
    # NOTE는 context에 있어야 함
    assert ctx011 and "PISM-011" in ctx011, f"NOTE가 context에 없음: {ctx011!r}"


def test_parse_includes_query_in_context():
    out = db_json.parse(FIX)
    by_id = {cid: ctx for cid, res, ctx in out}
    assert "USER_PRIVILEGES" in (by_id["DBM-004"] or "")


def test_parse_malformed_raises_reporterror(tmp_path):
    import pytest
    p = tmp_path / "bad.txt"
    p.write_text("this is not json at all {{{", encoding="utf-8")
    with pytest.raises(Exception) as ei:
        db_json.parse(str(p))
    from judge_tool.errors import ReportError
    assert isinstance(ei.value, ReportError)


import re

# 실데이터 누출 가드용 해시 원문 패턴
_HASH_LEAK = re.compile(r"\$[A-Za-z0-9]\$\d|[0-9A-Fa-f]{32,}")


def test_parse_rows_illegal_escape_hash_masked():
    """합성 회귀: 불법 백슬래시 이스케이프+해시 행이 마스킹되어야 한다.

    근본(이스케이프 중화 후 json.loads→_mask_row) 또는 폴백
    (_mask_raw_text) 어느 경로로든 해시 본문이 evidence에 남으면 안 된다.
    """
    block = (
        '{"USER":"u","AUTHENTICATION_STRING":'
        '"$A$005$abXXXXXXXXXXcd\\x01ef\\zinvalid","PLUGIN":"p"}'
    )
    rows = db_json._parse_rows(block, "DBM-001")
    assert rows, "행이 하나도 추출되지 않았다"
    joined = " ".join(r.evidence or "" for r in rows)
    # 해시 본문(abXXXXXXXXXXcd)이 raw로 남으면 안 된다
    assert "abXXXXXXXXXXcd" not in joined
    assert "$A$005$" not in joined
    assert "REDACTED" in joined


def test_mask_raw_text_redacts_hashes_and_sensitive_keys():
    raw = ('{"AUTHENTICATION_STRING":"$A$005$abcdef0123456789",'
           '"PASSWORD":"plainsecret","HEX":"DEADBEEFCAFEBABE1234"}')
    masked = db_json._mask_raw_text(raw)
    assert "$A$005$abcdef0123456789" not in masked
    assert "plainsecret" not in masked
    assert "DEADBEEFCAFEBABE1234" not in masked
    assert "REDACTED" in masked


def test_json_safe_strips_invalid_escapes():
    s = db_json._json_safe('a\\x01b\\zc\\nd\\"e')
    # 유효 이스케이프(\n \") 백슬래시는 보존, 무효(\x \z)는 제거
    assert "\\x" not in s
    assert "\\z" not in s
    assert "\\n" in s
    assert '\\"' in s


def test_parse_survives_broken_braces_no_loss():
    """수정1: 손상 DBM-022(outer 미닫힘) 뒤 DBM-024/028이 손실 없이 파싱.

    중복키 DBM-028_3 둘 다 반환되어야 한다(병합은 aggregate 책임)."""
    out = db_json.parse(FIX)
    cids = [cid for cid, _res, _ctx in out]
    assert "DBM-024_1" in cids, f"손상 항목 뒤 DBM-024_1 손실됨: {cids}"
    assert cids.count("DBM-028_3") == 2, f"중복 DBM-028_3 보존 실패: {cids}"
    # 정상 항목이 손상 전후로 전부 살아있음(손실 0)
    for expected in ("DBM-001", "DBM-004", "DBM-011", "DBM-019",
                     "DBM-022", "DBM-024_1", "DBM-028_3"):
        assert expected in cids, f"{expected} 손실: {cids}"


def test_parse_rows_no_residue_ghost_extraction():
    """수정2: 값에 '}'가 든 행에서 다른 키 값이 bare 행으로 중복 추출되지 않음."""
    block = '{"A":"x}y","B":"secretval123"}'
    rows = db_json._parse_rows(block, "DBM-099")
    bare = [r for r in rows if r.resource_id.startswith("DBM-099#note")]
    joined = " ".join((r.detail or "") + " " + (r.evidence or "") for r in bare)
    assert "secretval123" not in joined, (
        f"bare 행으로 유령 추출됨: {[r.resource_id for r in rows]} / {joined!r}")
    # 정상 행 객체 1개는 추출되어야 한다
    obj_rows = [r for r in rows if r.resource_id.startswith("DBM-099#row")]
    assert len(obj_rows) == 1


def test_parse_rows_resource_id_convention():
    """수정3: 행 resource_id는 f'{check_id}#row{i}' 규약."""
    block = ('{"GRANTEE":"a","PRIVILEGE_TYPE":"SELECT"},'
             '{"GRANTEE":"b","PRIVILEGE_TYPE":"SUPER"}')
    rows = db_json._parse_rows(block, "DBM-004")
    assert rows[0].resource_id == "DBM-004#row0"
    assert rows[1].resource_id == "DBM-004#row1"


def test_parse_real_resource_id_convention():
    out = db_json.parse(FIX)
    by_id = {cid: res for cid, res, _ in out}
    res004 = by_id["DBM-004"]
    assert res004 and res004[0].resource_id == "DBM-004#row0"


_REAL_FILES = [
    os.path.join("results", "DB", "MySQL", f"mysql_result_{name}.txt")
    for name in ("rds", "aurora", "azure")
]


def _real_dbm_keys(path):
    """원본 텍스트에서 normalize 전 DBM 키를 등장 순서대로(중복 포함) 수집."""
    t = open(path, encoding="utf-8", errors="replace").read()
    return re.findall(r'"(DBM-[\w]+)"\s*:', t)


def test_real_data_no_item_loss():
    """수정1 가드: 실 3파일에서 파싱된 check_id 집합이 원본 DBM키를 전부 포함(손실 0)."""
    import pytest
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checked = 0
    for rel in _REAL_FILES:
        path = os.path.join(repo_root, rel)
        if not os.path.exists(path):
            continue
        checked += 1
        out = db_json.parse(path)
        parsed = {cid for cid, _res, _ctx in out}
        original = set(_real_dbm_keys(path))
        missing = original - parsed
        assert not missing, f"{rel}: 손실된 DBM키 {len(missing)}건: {sorted(missing)}"
    if checked == 0:
        pytest.skip("실데이터 파일 없음")


def test_real_data_no_phantom_note_rows():
    """phantom 가드: 실 3파일 어떤 항목의 evidence 행에도 NOTE 문구가
    들어가면 안 된다(DBM-011·DBM-013의 배열 내 stray NOTE 회귀 방지).
    NOTE는 context로만 가야 하므로 evidence/detail에 '스크립트 참고'·'refer to'가 0건."""
    import pytest
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    note_markers = ("스크립트 참고", "refer to")
    checked = 0
    for rel in _REAL_FILES:
        path = os.path.join(repo_root, rel)
        if not os.path.exists(path):
            continue
        checked += 1
        out = db_json.parse(path)
        for cid, res, ctx in out:
            for r in res:
                row_text = (r.evidence or "") + "\n" + (r.detail or "")
                for mark in note_markers:
                    assert mark not in row_text, (
                        f"{rel}/{cid}: phantom NOTE 행 누출 {mark!r}: {row_text!r}")
    if checked == 0:
        pytest.skip("실데이터 파일 없음")


def test_real_data_no_hash_leak():
    """실데이터 누출 회귀(가드): 실파일이 있으면 전체 evidence 직렬화에
    해시 원문 패턴이 0건이어야 한다. results/는 읽기만, 출력 안 만듦."""
    import pytest
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checked = 0
    for rel in _REAL_FILES:
        path = os.path.join(repo_root, rel)
        if not os.path.exists(path):
            continue
        checked += 1
        out = db_json.parse(path)
        blob = "\n".join(
            (r.evidence or "") + "\n" + (r.detail or "")
            for _cid, res, _ctx in out for r in res
        )
        leaks = _HASH_LEAK.findall(blob)
        assert not leaks, f"{rel}: 해시 원문 누출 {len(leaks)}건: {leaks[:3]}"
    if checked == 0:
        pytest.skip("실데이터 파일 없음")

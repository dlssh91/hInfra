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

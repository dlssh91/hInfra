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

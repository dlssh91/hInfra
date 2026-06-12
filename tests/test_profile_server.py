"""서버(OS) 프로파일 구조 테스트 (작업③).

평가기준 '서버' 시트 컬럼 매핑(확인된 사실)과 프로파일 속성을 고정한다.
"""
from judge_tool.profile import get_profile, SERVER


def test_server_registered():
    p = get_profile("server")
    assert p is SERVER
    assert p.sheet_name == "서버"
    assert p.header_row == 4
    assert p.data_start_row == 5
    assert p.id_col == 2
    assert p.name_col == 7
    assert p.risk_col == 8
    assert p.parser == "server_xml"
    assert p.evidence_mode == "raw"
    assert p.status_available is False
    assert p.flag_vulnerable_for_review is True
    assert p.excluded is False
    # 서버용 위반필터형 분석 자료가 없어 빈 집합으로 시작(보수적).
    assert p.empty_means_good == frozenset()


def test_server_variant_columns():
    expected = {
        "aix": (12, 17, 18),
        "hpux": (13, 19, 20),
        "linux": (14, 21, 22),
        "solaris": (15, 23, 24),
        "win": (16, 25, 26),
    }
    assert set(SERVER.variants) == set(expected)
    for name, (app_col, std_col, mth_col) in expected.items():
        v = SERVER.variants[name]
        assert v.name == name
        assert v.applicability_col == app_col   # 평가대상 'o' 컬럼(DB 방식)
        assert v.standard_col == std_col
        assert v.method_col == mth_col
        assert v.eval_type_col is None
        # 출력 파일명({hostname}-s-{date}.xml)에 OS 마커가 없으므로 빈 튜플.
        assert v.filename_markers == ()


def test_server_filename_detection_always_none():
    """파일명 기반 식별은 항상 None — 내용 기반(detect_variant) 폴백 전제."""
    assert SERVER.variant_from_filename("testhost-s-20260101.xml") is None
    assert SERVER.variant_from_filename("linux.xml") is None


def test_server_normalize_id():
    assert SERVER.normalize_id("SRV-001") == "SRV-001"
    assert SERVER.normalize_id("SRV-1") == "SRV-001"
    assert SERVER.normalize_id("srv_017") == "SRV-017"
    # 비-SRV 덤프 id는 정규식 미스매치 시 strip+upper만 적용된다.
    assert SERVER.normalize_id("Internet") == "INTERNET"

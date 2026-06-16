"""(d) 버그 회귀테스트 스켈레톤 — §18.6(d), KNOWN_BUGS.md 참조.

각 테스트는 Phase 1 (common 모듈 벤더링 + 어댑터 완성) 후 활성화된다.
활성화 시 @pytest.mark.skip을 제거하고 해당 KNOWN_BUG 검증을 구현한다.

각 버그의 corrected 동작:
  - SRV-010: result(Y/N)은 올바름 — reason 문자열만 역전. 수정 후: not restrictq(취약)→
             result='Y'+"(-)"+"취약" 문구, else(양호)→ result='N'+"(+)"+"양호" 문구.
  - WST-102: 위반 0건 → verdict=양호 (IIS 역전 수정)
  - WST-040: 판단기준(col21) 양호/취약 문구 역전 + 코드 polarity 수정
  - PRCV-027~036: elif 중첩버그 수정 후 9항목 모두 도달 가능 (도달성)
  - NET-051: 'tcp-keepalives-in'(올바른 철자) 매칭 확인 (오타 수정)
"""
import pytest


def test_srv010_polarity_corrected():
    """SRV-010 reason 문자열 역전 버그 수정 회귀테스트 — Phase 1 활성화.

    KNOWN_BUGS.md SRV-010-polarity:
      벤더링된 SRV_auto_parse.py:935-946 sendmail 분기에서
      result 값(Y=취약, N=양호)은 올바르게 설정되고, reason 문자열도 교정됨.

    corrected 동작:
      - restrictqrun 부재(not restrictq=취약): result='Y', reason에 (-)+취약 문구
      - restrictqrun 존재(else=양호): result='N', reason에 (+)+양호 문구
    """
    from judge_tool.vendor.common.server.SRV_auto_parse import check_SRV_010

    DELIMITER = "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    # DELIMITER는 줄 앞뒤에 개행이 있어야 splitlines() 후 각 섹션이 독립 줄로 인식됨
    D = "\n" + DELIMITER + "\n"

    # 공통 sendmail 서비스 섹션
    services = "-e [ smtp|sendmail|postfix|exim ][S]\nsendmail 12345 root\n[ smtp|sendmail|postfix|exim ][E]"
    unused = ""

    # ── 테스트 A: restrictqrun 없음 → 취약 ─────────────────────────────────
    cf_no_restrictq = "O PrivacyOptions=authwarnings,noexpn,novfry,noetrn"
    output_vuln = D.join([services, unused, cf_no_restrictq])

    result_v, reason_v, vul_list_v = check_SRV_010(output_vuln)
    assert result_v == 'Y', f"restrictqrun 부재 → result='Y'(취약) 기대, 실제: {result_v!r}"
    assert "(-)" in reason_v, f"취약 reason에 (-) 없음: {reason_v!r}"
    assert "취약" in reason_v, f"취약 reason에 '취약' 문구 없음: {reason_v!r}"
    # 이전 버그: 취약 분기에 "(+)"·"양호" 있었음 → 수정 후엔 없어야 함
    assert "(+)" not in reason_v, f"취약 reason에 (+) 있음 (버그 미수정): {reason_v!r}"

    # ── 테스트 B: restrictqrun 존재 → 양호 ─────────────────────────────────
    cf_has_restrictq = "O PrivacyOptions=authwarnings,noexpn,novfry,noetrn,restrictqrun"
    output_good = D.join([services, unused, cf_has_restrictq])

    result_g, reason_g, vul_list_g = check_SRV_010(output_good)
    assert result_g == 'N', f"restrictqrun 존재 → result='N'(양호) 기대, 실제: {result_g!r}"
    assert "(+)" in reason_g, f"양호 reason에 (+) 없음: {reason_g!r}"
    assert "양호" in reason_g, f"양호 reason에 '양호' 문구 없음: {reason_g!r}"
    # 이전 버그: 양호 분기에 "(-)"·"취약" 있었음 → 수정 후엔 없어야 함
    assert "(-)" not in reason_g, f"양호 reason에 (-) 있음 (버그 미수정): {reason_g!r}"
    assert vul_list_g == [], f"양호 시 vul_list 비어있어야 함: {vul_list_g}"


def test_wst102_iis_polarity_corrected():
    """WST-102 IIS 역전 버그 수정 회귀테스트 (KNOWN_BUGS.md §3 WST-102-iis-polarity).

    corrected 동작: 위반 0건(removeServerHeader=true) → result='N' → verdict=양호.
    위반 존재(httpErrors errorMode=Detailed) → result='Y' → verdict=취약.

    활성 커버리지: test_det_adapters_webwas.py TestWST102IISBugfix에도 동일 단언 있음.
    이 테스트는 벤더 check_WST_102 직접 호출로 corrected 동작을 핀고정한다.
    """
    from judge_tool.vendor.common.webwas.WST_IIS_parse import check_WST_102

    # ── 테스트 A: 위반 0건 → 양호 ─────────────────────────────────────────────
    good_config = (
        '<requestFiltering removeServerHeader="true" />\n'
        '<httpErrors errorMode="DetailedLocalOnly" />\n'
    )
    result_g, reason_g, vul_list_g = check_WST_102(good_config)
    assert result_g == "N", (
        f"WST-102 위반 0건 → result='N'(양호) 기대, 실제: {result_g!r}\n"
        f"reason: {reason_g!r}\n"
        "(WST-102-iis-polarity 버그 미수정?)"
    )
    assert vul_list_g == [], f"양호 시 vul_list 비어있어야 함: {vul_list_g}"
    assert "(+)" in reason_g or "양호" in reason_g, (
        f"양호 reason에 양호 문구 없음: {reason_g!r}"
    )

    # ── 테스트 B: 위반 존재 → 취약 ───────────────────────────────────────────
    vuln_config = '<httpErrors errorMode="Detailed" />\n'
    result_v, reason_v, vul_list_v = check_WST_102(vuln_config)
    assert result_v == "Y", (
        f"WST-102 위반 존재 → result='Y'(취약) 기대, 실제: {result_v!r}\n"
        f"reason: {reason_v!r}"
    )
    assert len(vul_list_v) > 0, "취약 시 vul_list에 항목이 있어야 함"


@pytest.mark.skip(
    reason=(
        "Phase 1: common 모듈 벤더링 후 활성화 — KNOWN_BUGS.md WST-040 참조. "
        "corrected 동작: xlsx 판단기준(col21) 양호/취약 문구 역전 + "
        "WST_IIS_parse.py:524-580 polarity도 판단방법과 일치하도록 수정."
    )
)
def test_wst040_polarity_corrected():
    """WST-040 IIS + xlsx 역전 버그 수정 회귀테스트.

    KNOWN_BUGS.md WST-040:
      xlsx 웹 row44 col31 판단기준 양호/취약 문구 역전 + 코드 polarity 불일치.
      corrected: 수정된 xlsx 기준 + 코드 polarity 일치 확인.

    Phase 1 구현 힌트:
      - 사용자가 xlsx 판단기준 셀 정정 확인 필요 (사람 작업 게이트)
      - 벤더링된 WST_IIS_parse.py:524-580 VENDOR-EDIT(bug) 확인
      - 테스트 입력: WST-040 대상 IIS 설정 raw output
      - 단언: verdict 방향이 수정된 xlsx 기준과 일치
    """
    raise NotImplementedError("Phase 1 활성화 필요")


@pytest.mark.skip(
    reason=(
        "Phase 1: common 모듈 벤더링 후 활성화 — KNOWN_BUGS.md PRCV-027~036 참조. "
        "corrected 동작: autoAnalysis.py:1678~ elif 중첩버그 수정 → "
        "PRCV-027~036(9항목) 모두 도달 가능(도달성 복구)."
    )
)
def test_prcv_027_036_reachability_corrected():
    """PRCV-027~036 도달불가 버그 수정 회귀테스트.

    KNOWN_BUGS.md PRCV-027~036:
      autoAnalysis.py:1678(elif 중첩, PRCV-026 esxi 블록 안에 잘못 들여쓰기)로
      PRCV-027~036 전부 도달불가 → 항상 기본값 'N' 반환(결정론 커버 손실).
      PRCV-032는 xlsx 결번이므로 실존 9항목(027~031, 033~036).
      corrected: 들여쓰기 수정 후 각 항목이 vcenter/esxi/xen 분기로 도달 가능.

    Phase 1 구현 힌트:
      - 벤더링된 autoAnalysis.py에 VENDOR-EDIT(bug) 주석 확인
      - 테스트 입력: PRCV-027~036 각 항목의 대표 raw output(vcenter/esxi/xen)
      - 단언: 각 항목의 fv.handled is True (도달 가능 확인)
              PRCV-027 esxi 입력 → verdict≠기본값('N'→handled=False 아님)
    """
    raise NotImplementedError("Phase 1 활성화 필요")


@pytest.mark.skip(
    reason=(
        "Phase 1: common 모듈 벤더링 후 활성화 — KNOWN_BUGS.md NET-051 참조. "
        "corrected 동작: NetworkConfig.py:2592 'tcp-kepalives-in' 오타 수정 → "
        "'tcp-keepalives-in'(올바른 철자)로 실제 수집 문자열 매칭."
    )
)
def test_net051_typo_corrected():
    """NET-051 오타 수정 회귀테스트.

    KNOWN_BUGS.md NET-051:
      NetworkConfig.py:2592에 'tcp-kepalives-in'(e 누락)으로 오타가 있어
      실제 수집 문자열('tcp-keepalives-in')과 불일치 → 판정 분기 영구 미발동.
      corrected: 올바른 철자 'tcp-keepalives-in'으로 수정 후 분기 발동 확인.

    Phase 1 구현 힌트:
      - 벤더링된 NetworkConfig.py에 VENDOR-EDIT(bug) 주석 확인
      - 테스트 입력: 'tcp-keepalives-in' 문자열 포함 네트워크 raw output
      - 단언: 분기가 발동하여 fv.verdict가 결정론 결과를 반환
              (오타 있을 때는 분기 미발동 → 기본값만 반환)
    """
    raise NotImplementedError("Phase 1 활성화 필요")

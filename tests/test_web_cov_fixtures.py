"""웹서버(WST) 변형별 DET 양극성 계약 테스트 (결정론, LLM 불필요).

목적: 각 웹서버 변형(apache/iis/webtob) × DET 항목에 대해
  - good 합성 config/raw → good_verdict(양호) 확인
  - vuln 합성 config/raw → vuln_verdict(취약) 확인
이로써 전 DET 항목의 양극성이 깨지지 않음을 회귀로 고정한다.

거짓양호(vuln→양호) 0 / 거짓취약(good→취약) 0 이 SHIP 조건.

불변 계약:
  - judge() 직접 호출 (LLM 없음)
  - results/·collected/ 쓰기 금지 (합성 픽스처 인라인)
  - 기존 판정 로직 변경 없음 (검증만)

WAS(tomcat/jeus)/webservice 변형:
  DET 항목 0개(전부 LLM ABSENT) — 커버 대상 아님. 명시적 확인 포함.

커버 항목 수:
  apache:  7개 DET (WST-031/033/035/036/037/038/102)
  iis:    13개 DET (WST-031/032/033/034/035/036/037/038/039/041/042/043/102)
          WST-039(iis): 수동(*) → uncovered
  webtob:  6개 DET (WST-031/035/036/037/039/102)
          WST-039(webtob): 수동(*) → uncovered
  취약여부 확인 DET 실항목: apache 7, iis 12(039 제외), webtob 5(039 제외) = 24개
  MANUAL/판단보류 확인: WST-044(3변형), WST-040(2), WST-034(2), WST-039(apache), WST-033/038(webtob) = 10항목
  WAS ABSENT 확인: tomcat/jeus 5개
"""
from __future__ import annotations

import pytest

# ── 어댑터 임포트 (import 시 레지스트리 등록 부작용) ──────────────────────────
import judge_tool.det_adapters.webwas  # noqa: F401 — 등록 부작용
from judge_tool.det_adapters.webwas import judge
from judge_tool.det_adapters.base import ForcedVerdict

from tests.web_cov_contract import WEB_COV, MANUAL_HOLD_ITEMS, WAS_UNCOVERED_NOTE


# ──────────────────────────────────────────────────────────────────────────────
# 파라미터 생성: (variant, item_id, polarity) 삼중 튜플
# ──────────────────────────────────────────────────────────────────────────────

def _gen_params():
    """WEB_COV에서 (variant, item_id, polarity) 조합 생성.

    uncovered 항목은 skip 처리.
    known_bug/known_bug_polarity 항목은 해당 극성만 xfail 처리
    (버그 문서화, 판정 로직 변경 금지).
    """
    params = []
    for variant, items in WEB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered"):
                reason = spec.get("uncovered_reason", "미커버")
                params.append(pytest.param(
                    variant, item_id, "good",
                    marks=pytest.mark.skip(reason=reason),
                ))
                params.append(pytest.param(
                    variant, item_id, "vuln",
                    marks=pytest.mark.skip(reason=reason),
                ))
            elif spec.get("known_bug"):
                bug_desc = spec["known_bug"]
                bug_polarity = spec.get("known_bug_polarity")  # "good" or "vuln"
                for polarity in ("good", "vuln"):
                    if polarity == bug_polarity:
                        # 이 극성에 버그 존재 — xfail (strict=True: 반드시 실패해야 함)
                        params.append(pytest.param(
                            variant, item_id, polarity,
                            marks=pytest.mark.xfail(
                                strict=True,
                                reason=f"[발견된 버그] {bug_desc}",
                            ),
                        ))
                    else:
                        # 반대 극성은 정상 — 일반 테스트
                        params.append((variant, item_id, polarity))
            else:
                params.append((variant, item_id, "good"))
                params.append((variant, item_id, "vuln"))
    return params


_ALL_PARAMS = _gen_params()


# ──────────────────────────────────────────────────────────────────────────────
# 메인 양극성 테스트
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant,item_id,polarity", _ALL_PARAMS)
def test_web_det_polarity(variant, item_id, polarity):
    """WST DET 항목 양극성: good→expected_verdict, vuln→expected_verdict.

    거짓양호(vuln입력→양호 판정) 및 거짓취약(good입력→취약 판정)이 없음을 확인한다.

    판정 흐름:
      1. gate()가 DET 아니면 handled=False → 결정론 범위 밖(이미 MANUAL/ABSENT 테스트 커버)
      2. handled=True이면 verdict가 기대값과 일치하는지 확인
      3. handled=False이면 verdict != '양호' 임을 확인 (거짓양호 방지)
    """
    spec = WEB_COV[variant][item_id]
    raw = spec[polarity]
    expected_verdict = spec[f"{polarity}_verdict"]

    fv = judge(item_id, raw, variant, {})

    assert isinstance(fv, ForcedVerdict), (
        f"{variant}/{item_id}/{polarity}: judge() 반환값이 ForcedVerdict가 아님"
    )

    if not fv.handled:
        # gate 차단(config 시그니처 미수집 등) — 거짓양호만 방지하고 skip
        assert fv.verdict != "양호", (
            f"[거짓양호] {variant}/{item_id}/{polarity}: "
            f"handled=False인데 verdict='양호' — 거짓양호 발생! "
            f"({fv!r})"
        )
        pytest.skip(
            f"{variant}/{item_id}/{polarity}: handled=False (gate/config가드). "
            f"verdict={fv.verdict!r} rationale={fv.rationale!r}. "
            f"합성 config를 확인하거나 MANUAL 분류 재검토 필요."
        )

    # handled=True: verdict 확인
    actual = fv.verdict

    if polarity == "vuln":
        # 거짓양호 검사: vuln 입력인데 양호가 나오면 안 됨
        assert actual != "양호", (
            f"[거짓양호] {variant}/{item_id}/vuln: "
            f"취약 입력인데 verdict='양호' — 거짓양호 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] {variant}/{item_id}/vuln: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} citations={fv.citations!r}"
        )

    else:  # polarity == "good"
        # 거짓취약 검사: good 입력인데 취약이 나오면 안 됨
        assert actual != "취약", (
            f"[거짓취약] {variant}/{item_id}/good: "
            f"양호 입력인데 verdict='취약' — 거짓취약 발생! "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )
        assert actual == expected_verdict, (
            f"[극성 불일치] {variant}/{item_id}/good: "
            f"기대={expected_verdict!r}, 실제={actual!r}. "
            f"confidence={fv.confidence} rationale={fv.rationale!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# MANUAL/판단보류 항목 — handled=False + verdict != '양호' 확인
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("item_id,variant,note", MANUAL_HOLD_ITEMS)
def test_wst_manual_items_no_false_positive(item_id, variant, note):
    """MANUAL/ABSENT 항목: gate 차단 → handled=False, verdict != '양호' 확인.

    MANUAL = 수동 판단 필요. ABSENT = 해당 변형 미지원.
    거짓양호(자동 양호 판정) 절대 금지.
    """
    # 서비스 블록이 있는 dummy raw 제공 (gate 차단이 목적이므로 내용 무관)
    raw = (
        "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\nroot /usr/sbin/apache2\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    fv = judge(item_id, raw, variant, {})

    assert isinstance(fv, ForcedVerdict)
    assert fv.handled is False, (
        f"MANUAL/ABSENT {variant}/{item_id} ({note}): "
        f"handled=False 기대인데 handled=True. "
        f"DET_SOURCE 분류 확인 필요. verdict={fv.verdict!r}"
    )
    assert fv.verdict != "양호", (
        f"[거짓양호] {variant}/{item_id} ({note}): "
        f"MANUAL/ABSENT인데 양호 판정 발생! verdict={fv.verdict!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# WAS(tomcat/jeus) 전 항목 ABSENT → handled=False 확인
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("variant,item_id", [
    ("tomcat", "WST-031"),
    ("tomcat", "WST-033"),
    ("tomcat", "WST-035"),
    ("jeus",   "WST-031"),
    ("jeus",   "WST-033"),
])
def test_was_variants_absent_no_false_positive(variant, item_id):
    """WAS(tomcat/jeus): 모든 WST-* 항목 ABSENT → gate 차단 → handled=False 확인.

    WAS 변형은 파서 없음 → 전 항목 결정론 불가 → LLM 경로.
    거짓양호(자동 양호 판정) 절대 금지.
    """
    fv = judge(item_id, "some raw data", variant, {})

    assert isinstance(fv, ForcedVerdict)
    assert fv.handled is False, (
        f"WAS {variant}/{item_id}: handled=False 기대인데 handled=True. "
        f"WAS 변형에 DET 분류가 생겼을 가능성 — DET_SOURCE.yaml 확인 필요. "
        f"verdict={fv.verdict!r}"
    )
    assert fv.verdict != "양호", (
        f"[거짓양호] WAS {variant}/{item_id}: "
        f"ABSENT인데 양호 판정 발생! verdict={fv.verdict!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# 커버리지 요약 테스트 (계약 완전성 검사)
# ──────────────────────────────────────────────────────────────────────────────

def test_web_cov_contract_completeness():
    """WEB_COV 계약이 각 변형의 주요 DET 항목을 커버하는지 확인.

    최소 기대:
      - apache: 7개 이상 항목 정의
      - iis:   13개 이상 항목 정의
      - webtob: 6개 이상 항목 정의
    """
    minimums = {
        "apache": 7,
        "iis":   13,
        "webtob": 6,
    }
    for variant, min_count in minimums.items():
        actual = len(WEB_COV[variant])
        assert actual >= min_count, (
            f"{variant}: WEB_COV에 {actual}개 항목만 정의됨, 최소 {min_count}개 기대. "
            f"DET 항목 커버리지 부족 — 계약 보강 필요."
        )


def test_web_cov_uncovered_items_documented():
    """미커버(uncovered) 항목이 모두 사유와 함께 문서화됨을 확인.

    uncovered=True인 항목은 uncovered_reason이 있어야 한다(은폐 금지).
    """
    for variant, items in WEB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered"):
                assert "uncovered_reason" in spec, (
                    f"{variant}/{item_id}: uncovered=True인데 "
                    f"uncovered_reason 없음 — 사유 문서화 필수."
                )
                assert spec["uncovered_reason"].strip(), (
                    f"{variant}/{item_id}: uncovered_reason이 비어있음."
                )


def test_web_cov_covered_items_have_both_polarities():
    """커버된 항목은 good/vuln 양쪽 데이터와 verdict가 모두 있어야 한다."""
    for variant, items in WEB_COV.items():
        for item_id, spec in items.items():
            if spec.get("uncovered"):
                continue
            assert "good" in spec, f"{variant}/{item_id}: good 데이터 없음"
            assert "vuln" in spec, f"{variant}/{item_id}: vuln 데이터 없음"
            assert "good_verdict" in spec, f"{variant}/{item_id}: good_verdict 없음"
            assert "vuln_verdict" in spec, f"{variant}/{item_id}: vuln_verdict 없음"
            assert spec["good_verdict"] in ("양호", "판단보류"), (
                f"{variant}/{item_id}: 알 수 없는 good_verdict={spec['good_verdict']!r}"
            )
            assert spec["vuln_verdict"] in ("취약", "판단보류"), (
                f"{variant}/{item_id}: 알 수 없는 vuln_verdict={spec['vuln_verdict']!r}"
            )


def test_was_uncovered_note_exists():
    """WAS 미커버 명시 노트가 존재함을 확인."""
    assert WAS_UNCOVERED_NOTE, "WAS_UNCOVERED_NOTE가 비어있음"
    assert "tomcat" in WAS_UNCOVERED_NOTE.lower() or "jeus" in WAS_UNCOVERED_NOTE.lower()
    assert "LLM" in WAS_UNCOVERED_NOTE


# ──────────────────────────────────────────────────────────────────────────────
# 개별 핵심 회귀 테스트 (기존 테스트와 동형, 명시적 단언)
# ──────────────────────────────────────────────────────────────────────────────

class TestWST038ApacheDotallRegression:
    """WST-038 Apache DOTALL 멀티라인 Directory 블록 회귀 (web_cov_contract 동형).

    KNOWN_BUGS §2: re.DOTALL 미적용 → 멀티라인 Directory 미매치 → 거짓양호.
    수정 후: re.DOTALL | re.IGNORECASE → 정상 취약 탐지.
    """

    _PREFIX = (
        "[ http|https|http-alt|www|www-http|apache|apache2 ][S]\n"
        "$ ps -ef | egrep apache\nroot /usr/sbin/apache2 -k start\n"
        "[ http|https|http-alt|www|www-http|apache|apache2 ][E]\n"
    )

    def test_multiline_followsymlinks_vuln(self):
        """멀티라인 Directory + FollowSymLinks → 취약 (DOTALL 핵심 회귀)."""
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes FollowSymLinks\n"
            "AllowOverride None\n"
            "</Directory>\n"
        )
        fv = judge("WST-038", self._PREFIX + config, "apache", {})
        assert fv.handled is True, f"WST-038 멀티라인 취약 config: handled=False — {fv.rationale!r}"
        assert fv.verdict == "취약", (
            f"[거짓양호] WST-038 멀티라인 FollowSymLinks: "
            f"취약 config인데 verdict={fv.verdict!r} — DOTALL 미수정 의심"
        )

    def test_clean_block_good(self):
        """FollowSymLinks 없는 clean Directory 블록 → 양호."""
        config = (
            "<Directory /var/www/html>\n"
            "Options Indexes\n"
            "AllowOverride None\n"
            "</Directory>\n"
        )
        fv = judge("WST-038", self._PREFIX + config, "apache", {})
        assert fv.handled is True
        assert fv.verdict == "양호", (
            f"[거짓취약] WST-038 clean 블록: "
            f"양호 config인데 verdict={fv.verdict!r}"
        )


class TestWST102IISPolarityRegression:
    """WST-102 IIS polarity 버그수정 회귀 (KNOWN_BUGS §2).

    원본 버그: `if not vul_list: result = "Y"` (위반0건→취약 역전).
    수정 후: 위반0건 → result='N'(양호).
    """

    def test_good_config_not_vulnerable(self):
        """removeServerHeader=true → 위반0건 → 양호 (버그수정 확인)."""
        config = (
            '<requestFiltering removeServerHeader="true" />\n'
            '<httpErrors errorMode="DetailedLocalOnly" />\n'
        )
        fv = judge("WST-102", config, "iis", {})
        assert fv.handled is True
        assert fv.verdict == "양호", (
            f"[거짓취약] WST-102 IIS removeServerHeader=true: "
            f"양호 config인데 verdict={fv.verdict!r} — polarity 버그 미수정?"
        )

    def test_vuln_config_is_vulnerable(self):
        """httpErrors errorMode=Detailed → 취약."""
        config = '<httpErrors errorMode="Detailed" />\n'
        fv = judge("WST-102", config, "iis", {})
        assert fv.handled is True
        assert fv.verdict == "취약"


def test_wst102_webtob_min_is_vuln():
    """WST-102 webtob: Min/Minimal/Minor도 전체버전 노출 → 취약 (Opus 재리뷰 거짓양호 봉쇄). Prod만 양호."""
    from judge_tool.vendor.common.webwas.WST_WebtoB_parse import check_WST_102
    for val in ("min", "minimal", "minor", "os", "full", "major"):
        r = check_WST_102(f'ServerTokens = "{val}"')
        res = r[0] if isinstance(r, tuple) else r
        assert res == "Y", f"ServerTokens={val} → {res} (기대 Y/취약)"
    r = check_WST_102('ServerTokens = "prod"')
    assert (r[0] if isinstance(r, tuple) else r) == "N", "Prod → 양호여야"

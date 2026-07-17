"""judge_tool.envcheck 단위 테스트 — 실행 환경 모델 적합성 체커.

기존 판정 코드(main.run, judge.OllamaClient, preflight)는 건드리지 않으며,
이 테스트도 그 경로를 호출하지 않는다. requests.get만 monkeypatch한다.
"""
import pytest

from judge_tool import envcheck


# ---------------------------------------------------------------------------
# estimate_footprint_gb / fit_verdict 임계값
# ---------------------------------------------------------------------------

def test_estimate_footprint_gb_formula():
    # download*1.2 + (num_ctx/4096)*0.5 + 0.5
    got = envcheck.estimate_footprint_gb(10.0, 4096)
    assert got == pytest.approx(10.0 * 1.2 + 0.5 + 0.5)


def test_estimate_footprint_gb_scales_with_ctx():
    small_ctx = envcheck.estimate_footprint_gb(10.0, 4096)
    big_ctx = envcheck.estimate_footprint_gb(10.0, 16384)
    assert big_ctx > small_ctx
    assert big_ctx == pytest.approx(small_ctx + (16384 - 4096) / 4096 * 0.5)


def test_fit_verdict_yeoyu_boundary():
    # footprint <= budget*0.8 -> "여유"
    assert envcheck.fit_verdict(8.0, 10.0) == "여유"
    assert envcheck.fit_verdict(8.0001, 10.0) == "빠듯"


def test_fit_verdict_ppadeut_boundary():
    # budget*0.8 < footprint <= budget*0.95 -> "빠듯"
    assert envcheck.fit_verdict(9.5, 10.0) == "빠듯"
    assert envcheck.fit_verdict(9.5001, 10.0) == "불가"


def test_fit_verdict_bulga():
    assert envcheck.fit_verdict(11.0, 10.0) == "불가"


def test_fit_verdict_zero_budget_is_bulga():
    assert envcheck.fit_verdict(0.1, 0.0) == "불가"


# ---------------------------------------------------------------------------
# list_installed_models
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise RuntimeError("bad status")

    def json(self):
        return self._payload


def test_list_installed_models_parses_tags(monkeypatch):
    payload = {
        "models": [
            {"name": "qwen2.5-coder:3b", "size": 1_900_000_000},
            {"name": "qwen3-coder:30b", "size": 19_000_000_000},
            "not-a-dict-entry",  # 방어적 스킵 대상 — 리스트 항목이 dict가 아닌 경우
        ]
    }

    def fake_get(url, timeout=None):
        assert url.endswith("/api/tags")
        return _FakeResp(payload)

    monkeypatch.setattr(envcheck.requests, "get", fake_get)

    models, err = envcheck.list_installed_models("http://localhost:11434")
    assert err is None
    names = {m["name"] for m in models}
    assert names == {"qwen2.5-coder:3b", "qwen3-coder:30b"}
    by_name = {m["name"]: m for m in models}
    # size_gb는 RAM과 동일 단위(GiB, 1024**3) — 19e9 bytes ≈ 17.69 GiB
    assert by_name["qwen3-coder:30b"]["size_gb"] == pytest.approx(
        19_000_000_000 / (1024 ** 3))


def test_list_installed_models_ollama_down(monkeypatch):
    def fake_get(url, timeout=None):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(envcheck.requests, "get", fake_get)

    models, err = envcheck.list_installed_models("http://localhost:11434")
    assert models == []
    assert err is not None
    assert "연결할 수 없습니다" in err


def test_list_installed_models_bad_http_status(monkeypatch):
    def fake_get(url, timeout=None):
        return _FakeResp({}, status_ok=False)

    monkeypatch.setattr(envcheck.requests, "get", fake_get)

    models, err = envcheck.list_installed_models("http://localhost:11434")
    assert models == []
    assert err is not None


# ---------------------------------------------------------------------------
# detect_total_ram_gb / detect_vram_gb — 크로스플랫폼 스모크 (크래시 없음)
# ---------------------------------------------------------------------------

def test_detect_total_ram_gb_no_crash():
    ram = envcheck.detect_total_ram_gb()
    assert ram is None or ram > 0


def test_detect_vram_gb_no_crash():
    vram, source = envcheck.detect_vram_gb()
    assert vram is None or vram > 0
    assert isinstance(source, str)
    assert source in ("nvidia", "apple_unified", "none")


# ---------------------------------------------------------------------------
# build_report / format_report
# ---------------------------------------------------------------------------

def test_build_report_production_not_installed(monkeypatch):
    monkeypatch.setattr(envcheck, "detect_total_ram_gb", lambda: 17.0)
    monkeypatch.setattr(envcheck, "detect_vram_gb", lambda: (None, "apple_unified"))
    monkeypatch.setattr(
        envcheck, "list_installed_models",
        lambda url, timeout=5: ([
            {"name": "qwen2.5-coder:3b", "size_gb": 1.9},
        ], None))

    report = envcheck.build_report(
        "http://localhost:11434", envcheck.PRODUCTION_MODEL, 16384)

    assert report["ram_gb"] == 17.0
    assert report["production_fit"]["installed"] is False
    assert report["production_fit"]["verdict"] == "불가"  # 30b footprint ~ 25.3GB > 17GB*0.95
    assert report["recommendation"] == "qwen2.5-coder:3b"
    assert "ollama_error" not in report


def test_build_report_production_base_name_not_mismatched(monkeypatch):
    """[Opus High 회귀] 같은 계열 다른 크기 태그(qwen3-coder:7b)가 설치돼 있어도
    미설치 production(qwen3-coder:30b)을 '설치·여유'로 오판하지 않는다."""
    monkeypatch.setattr(envcheck, "detect_total_ram_gb", lambda: 16.0)
    monkeypatch.setattr(envcheck, "detect_vram_gb", lambda: (None, "apple_unified"))
    monkeypatch.setattr(
        envcheck, "list_installed_models",
        lambda url, timeout=5: ([
            {"name": "qwen3-coder:7b", "size_gb": 4.5},   # 같은 base, 다른 태그
        ], None))

    report = envcheck.build_report(
        "http://localhost:11434", "qwen3-coder:30b", 16384)

    # 30b는 설치 안 됐으므로 상수추정 → 16GB에선 불가여야 한다(7b로 오인 금지).
    assert report["production_fit"]["installed"] is False
    assert report["production_fit"]["verdict"] == "불가"


def test_build_report_recommends_largest_fitting_model(monkeypatch):
    monkeypatch.setattr(envcheck, "detect_total_ram_gb", lambda: 64.0)
    monkeypatch.setattr(envcheck, "detect_vram_gb", lambda: (24.0, "nvidia"))
    monkeypatch.setattr(
        envcheck, "list_installed_models",
        lambda url, timeout=5: ([
            {"name": "qwen2.5-coder:3b", "size_gb": 1.9},
            {"name": "qwen3-coder:30b", "size_gb": 19.0},
        ], None))

    report = envcheck.build_report(
        "http://localhost:11434", envcheck.PRODUCTION_MODEL, 16384)

    assert report["production_fit"]["installed"] is True
    assert report["production_fit"]["verdict"] in ("여유", "빠듯")
    assert report["recommendation"] == "qwen3-coder:30b"


def test_build_report_ollama_error_propagates(monkeypatch):
    monkeypatch.setattr(envcheck, "detect_total_ram_gb", lambda: 17.0)
    monkeypatch.setattr(envcheck, "detect_vram_gb", lambda: (None, "none"))
    monkeypatch.setattr(
        envcheck, "list_installed_models",
        lambda url, timeout=5: ([], "Ollama 서버(http://localhost:11434)에 연결할 수 없습니다: ConnectionError"))

    report = envcheck.build_report(
        "http://localhost:11434", envcheck.PRODUCTION_MODEL, 16384)

    assert "ollama_error" in report
    assert report["installed"] == []
    assert report["recommendation"] is None


def test_format_report_contains_required_sections(monkeypatch):
    monkeypatch.setattr(envcheck, "detect_total_ram_gb", lambda: 17.0)
    monkeypatch.setattr(envcheck, "detect_vram_gb", lambda: (None, "apple_unified"))
    monkeypatch.setattr(
        envcheck, "list_installed_models",
        lambda url, timeout=5: ([
            {"name": "qwen2.5-coder:3b", "size_gb": 1.9},
        ], None))

    report = envcheck.build_report(
        "http://localhost:11434", envcheck.PRODUCTION_MODEL, 16384)
    text = envcheck.format_report(report)

    assert "17.0 GB" in text
    assert "qwen2.5-coder:3b" in text
    assert "미설치, 추정" in text
    assert "추천 모델" in text
    assert "qwen2.5-coder:3b" in text.split("추천 모델")[1]
    assert "자동 전환하지 않으니" in text
    assert "--model" in text


def test_format_report_ollama_down_message():
    report = {
        "ram_gb": 17.0,
        "vram_gb": None,
        "vram_source": "none",
        "budget_gb": 17.0,
        "installed": [],
        "production_fit": {
            "model": envcheck.PRODUCTION_MODEL,
            "installed": False,
            "footprint_gb": 23.6,
            "verdict": "불가",
        },
        "recommendation": None,
        "ollama_error": "Ollama 서버(http://localhost:11434)에 연결할 수 없습니다: ConnectionError",
    }
    text = envcheck.format_report(report)
    assert "연결할 수 없습니다" in text
    assert "다시 실행하세요" in text


def test_format_report_ram_undetected():
    report = {
        "ram_gb": None,
        "vram_gb": None,
        "vram_source": "none",
        "budget_gb": 0.0,
        "installed": [],
        "production_fit": {
            "model": envcheck.PRODUCTION_MODEL,
            "installed": False,
            "footprint_gb": 23.6,
            "verdict": "판정불가(RAM 미감지)",
        },
        "recommendation": None,
    }
    text = envcheck.format_report(report)
    assert "감지 실패" in text


# ---------------------------------------------------------------------------
# main() 스모크 — 실제 인자 파싱 + 감지 경로 (Ollama 미가동이어도 크래시 금지)
# ---------------------------------------------------------------------------

def test_main_does_not_crash(monkeypatch, capsys):
    # 실제 Ollama 서버 유무와 무관하게 exit 0으로 끝나야 한다(정보성 도구).
    envcheck.main([])
    out = capsys.readouterr().out
    assert "judge_tool 실행 환경 모델 적합성 리포트" in out

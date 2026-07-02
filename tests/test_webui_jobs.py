"""JobManager 단위 테스트 (T-5~T-7). judge_tool.main.run을 monkeypatch해
Ollama/실데이터 없이 검증한다."""
import json
import os
import time
from types import SimpleNamespace

import pytest

import judge_tool.main as main_mod
from judge_tool.webui.jobs import JobManager
from judge_tool.webui.store import ProjectStore


@pytest.fixture
def store(tmp_path):
    return ProjectStore(str(tmp_path / "projects"))


@pytest.fixture
def config(tmp_path):
    return SimpleNamespace(
        ollama_url="http://localhost:11434", model="stub-model",
        criteria=str(tmp_path / "criteria.xlsx"), max_upload_mb=50, token=None)


def _make_asset(store, profile="db_mysql", variant=None):
    project = store.create_project("잡테스트")
    asset = store.add_asset(project["project_id"], "mysql_result_rds.json", b'{"a":1}')
    if profile:
        store.set_asset_profile(project["project_id"], asset["asset_id"], profile, variant)
    return project["project_id"], asset["asset_id"]


def _wait_idle(jobs, timeout=5.0):
    # L-3: JobManager.join(timeout=...)이 실제로 폴링/타임아웃을 지키므로,
    # 워커 스레드가 죽어 큐가 영원히 안 비는 회귀가 생기면 여기서 무한 행
    # 대신 TimeoutError로 즉시 실패한다.
    jobs.join(timeout=timeout)


# ── T-5: 정상 판정 → judged + summary ─────────────────────────────────────

def test_run_one_success_updates_summary(store, config, monkeypatch):
    pid, aid = _make_asset(store)

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        payload = {
            "metadata": {"profile": profile_key},
            "coverage": {"expected": 3, "judged": 3, "missing": []},
            "judgments": [
                {"item_id": "DBM-001", "verdict": "양호", "needs_review": False},
                {"item_id": "DBM-002", "verdict": "취약", "needs_review": True},
                {"item_id": "DBM-003", "verdict": "판단보류", "needs_review": True},
            ],
        }
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return {"expected": 3, "judged": 3, "missing": []}

    monkeypatch.setattr(main_mod, "run", fake_run)

    jobs = JobManager(store, config)
    jobs.start()
    jobs.enqueue(pid, aid)
    _wait_idle(jobs)

    asset = store.get_asset(pid, aid)
    assert asset["status"] == "judged"
    assert asset["error"] is None
    assert asset["summary"]["verdict_counts"] == {"양호": 1, "취약": 1, "판단보류": 1}
    assert asset["summary"]["needs_review"] == 2
    assert asset["judged_at"] is not None


# ── T-6: run이 ReportError(Ollama 확인 실패)→failed + 한글 보존 ───────────

def test_run_one_report_error_preserves_message(store, config, monkeypatch):
    from judge_tool.errors import ReportError
    pid, aid = _make_asset(store)

    def fake_run(*args, **kwargs):
        raise ReportError("[Ollama 확인 실패] 연결할 수 없습니다: ConnectionError "
                          "Ollama가 실행 중인지 확인하세요: `ollama serve`.")

    monkeypatch.setattr(main_mod, "run", fake_run)

    jobs = JobManager(store, config)
    jobs.start()
    jobs.enqueue(pid, aid)
    _wait_idle(jobs)

    asset = store.get_asset(pid, aid)
    assert asset["status"] == "failed"
    assert "[Ollama 확인 실패]" in asset["error"]


# ── T-7: run이 RuntimeError("SECRET")→error에 원문 미포함(타입명만) ──────

def test_run_one_unexpected_exception_hides_message(store, config, monkeypatch):
    pid, aid = _make_asset(store)

    def fake_run(*args, **kwargs):
        raise RuntimeError("SECRET-EVIDENCE-leak")

    monkeypatch.setattr(main_mod, "run", fake_run)

    jobs = JobManager(store, config)
    jobs.start()
    jobs.enqueue(pid, aid)
    _wait_idle(jobs)

    asset = store.get_asset(pid, aid)
    assert asset["status"] == "failed"
    assert "SECRET-EVIDENCE-leak" not in asset["error"]
    assert "RuntimeError" in asset["error"]


# ── enqueue 중복 방지 ──────────────────────────────────────────────────────

# ── H-1: 워커 예외 내성 — _run_one이 무엇을 던지든 워커 스레드는 죽지 않고
#          다음 자산 판정을 정상 처리해야 한다 ─────────────────────────────

def test_worker_survives_run_one_exception_and_processes_next(store, config, monkeypatch):
    pid1, aid1 = _make_asset(store)
    pid2, aid2 = _make_asset(store)

    jobs = JobManager(store, config)
    original_run_one = jobs._run_one
    calls = []

    def flaky_run_one(pid, aid):
        calls.append((pid, aid))
        if (pid, aid) == (pid1, aid1):
            # _run_one 내부의 방어(try/except)를 완전히 우회하는 임의 예외를
            # 흉내낸다 — 예전 구현이라면 이 예외가 _loop까지 전파되어
            # 워커 스레드 자체가 죽었다(H-1 핵심 버그).
            raise RuntimeError("작업1: 예상 밖의 치명적 예외(워커를 죽일 뻔한 버그)")
        return original_run_one(pid, aid)

    monkeypatch.setattr(jobs, "_run_one", flaky_run_one)

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        return {"expected": 0, "judged": 0, "missing": []}

    monkeypatch.setattr(main_mod, "run", fake_run)

    jobs.start()
    jobs.enqueue(pid1, aid1)
    jobs.enqueue(pid2, aid2)
    # timeout이 실제로 지켜지므로(L-3), 워커가 죽어 큐가 안 비면 여기서
    # TimeoutError로 실패한다(무한 행 대신).
    jobs.join(timeout=5.0)

    assert calls == [(pid1, aid1), (pid2, aid2)]
    # 두 번째 작업은 첫 번째의 예외와 무관하게 정상적으로 처리되어야 한다.
    asset2 = store.get_asset(pid2, aid2)
    assert asset2["status"] == "judged"


def test_run_one_record_failure_ignores_deleted_asset(store, config, monkeypatch):
    """H-1(2): 판정 실패 기록 시점에 프로젝트/자산이 이미 삭제됐으면
    KeyError를 삼키고 조용히 넘어가야 한다(그래야 _loop까지 전파되지 않음)."""
    pid, aid = _make_asset(store)

    def fake_run(*args, **kwargs):
        raise RuntimeError("판정 도중 실패")

    monkeypatch.setattr(main_mod, "run", fake_run)

    jobs = JobManager(store, config)
    # store.update_asset을 실패 지점에서 asset이 이미 삭제된 것처럼 흉내낸다.
    store.delete_asset(pid, aid)

    # 예외 없이 조용히 끝나야 한다(과거였다면 update_asset의 KeyError가
    # _run_one 밖으로 새어나가 워커를 죽였을 것).
    jobs._run_one(pid, aid)


def test_enqueue_duplicate_raises(store, config, monkeypatch):
    pid, aid = _make_asset(store)
    started = []
    release = []

    def slow_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        started.append(1)
        while not release:
            time.sleep(0.01)
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        return {"expected": 0, "judged": 0, "missing": []}

    monkeypatch.setattr(main_mod, "run", slow_run)

    jobs = JobManager(store, config)
    jobs.start()
    jobs.enqueue(pid, aid)
    while not started:
        time.sleep(0.01)
    with pytest.raises(RuntimeError):
        jobs.enqueue(pid, aid)
    release.append(1)
    _wait_idle(jobs)

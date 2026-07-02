"""백그라운드 판정 작업 큐(워커 1개, Ollama 단일 서버 가정).

판정 엔진은 재사용만 한다 — judge_tool.main.run()/OllamaClient를 모듈참조로
호출할 뿐 재구현하지 않는다. 자산 단위 coarse 상태만 관리한다(run() 내부에
콜백 훅이 없으므로 항목단위 진행률은 제공하지 않음, 설계서 §8 리스크 참조).
"""
import json
import logging
import os
import queue
import threading
import time
from collections import Counter
from typing import Dict

from judge_tool import main as _main
from judge_tool.errors import ReportError
from judge_tool.judge import OllamaClient
from judge_tool.webui.store import _now

log = logging.getLogger(__name__)


def _summarize(json_out: str, cov: Dict) -> Dict:
    """결과 JSON + coverage → 요약 dict(verdict_counts/needs_review 등)."""
    with open(json_out, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    judgments = data.get("judgments", [])
    counts = Counter(j.get("verdict") for j in judgments)
    verdict_counts = {
        "양호": counts.get("양호", 0),
        "취약": counts.get("취약", 0),
        "판단보류": counts.get("판단보류", 0),
    }
    needs_review = sum(1 for j in judgments if j.get("needs_review"))
    return {
        "expected": cov.get("expected", 0),
        "judged": cov.get("judged", 0),
        "missing": cov.get("missing", []),
        "verdict_counts": verdict_counts,
        "needs_review": needs_review,
    }


class JobManager:
    """판정 작업 큐. 워커 스레드 1개(daemon)가 순차 처리한다."""

    def __init__(self, store, config):
        self.store = store
        self.config = config
        self._queue: "queue.Queue" = queue.Queue()
        self._active = set()
        self._active_lock = threading.Lock()
        self._thread = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="judge-tool-webui-worker", daemon=True)
        self._thread.start()

    def enqueue(self, pid: str, aid: str) -> None:
        key = (pid, aid)
        with self._active_lock:
            if key in self._active:
                raise RuntimeError("이미 판정이 진행 중인 자산입니다.")
            self._active.add(key)
        self._queue.put(key)

    def join(self, timeout: float = None) -> None:
        """테스트용: 큐가 비고 마지막 작업이 끝날 때까지 대기.

        timeout=None이면 무제한 대기(queue.Queue.join()과 동일). timeout이
        지정되면 실제로 그 시간만큼만 폴링 대기하고, 시간 내에 비지 않으면
        TimeoutError를 던진다(워커 스레드가 죽어 큐가 영원히 안 비는 경우
        테스트가 무한 행(hang)하지 않도록 — L-3).
        """
        if timeout is None:
            self._queue.join()
            return
        deadline = time.monotonic() + timeout
        poll_interval = 0.01
        while self._queue.unfinished_tasks > 0:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "작업 큐가 timeout 내에 비지 않았습니다(워커 정지 의심).")
            time.sleep(poll_interval)

    def _loop(self) -> None:
        while True:
            pid, aid = self._queue.get()
            try:
                self._run_one(pid, aid)
            except Exception:  # noqa: BLE001 - 워커 스레드는 어떤 예외에도 죽지 않아야 함
                log.exception(
                    "웹 판정 워커에서 예상치 못한 예외 발생 pid=%s aid=%s", pid, aid)
            finally:
                self._queue.task_done()

    def _run_one(self, pid: str, aid: str) -> None:
        try:
            asset = self.store.get_asset(pid, aid)
            report = self.store.asset_abspath(pid, aid)
            criteria = self.config.criteria or _main._discover_criteria_path()
            json_out, xlsx_out = self.store.result_paths(pid, aid)
            client = OllamaClient(url=self.config.ollama_url, model=self.config.model)
            cov = _main.run(
                report, criteria, asset["profile"], client, json_out, xlsx_out,
                self.config.model, variant_override=asset.get("variant"))
            summary = _summarize(json_out, cov)
            self.store.update_asset(
                pid, aid, status="judged", error=None, summary=summary,
                judged_at=_now(),
                result_json_relpath=os.path.relpath(json_out, self.store.root),
                result_xlsx_relpath=os.path.relpath(xlsx_out, self.store.root))
        except (ReportError, OSError) as e:
            self._record_failure(pid, aid, str(e))
        except Exception as e:  # noqa: BLE001 - 예상 밖 예외도 자산 단위로 격리
            log.warning("웹 판정 실패 pid=%s aid=%s type=%s", pid, aid, type(e).__name__)
            self._record_failure(
                pid, aid,
                f"판정 중 오류가 발생했습니다({type(e).__name__}). "
                "파일과 프로파일을 확인하세요.")
        finally:
            with self._active_lock:
                self._active.discard((pid, aid))

    def _record_failure(self, pid: str, aid: str, message: str) -> None:
        """실패 상태 기록. 판정 도중 프로젝트/자산이 이미 삭제됐으면 조용히 무시한다."""
        try:
            self.store.update_asset(pid, aid, status="failed", error=message)
        except KeyError:
            log.info(
                "실패 기록 생략(프로젝트/자산이 이미 삭제됨) pid=%s aid=%s", pid, aid)

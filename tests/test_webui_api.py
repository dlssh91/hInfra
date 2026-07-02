"""HTTP API 통합 테스트 (T-8~T-11). ThreadingHTTPServer를 실제로 띄우고
requests로 접속한다. Ollama/실데이터는 필요 없음(합성 데이터 + monkeypatch)."""
import json
import os
import socket
import threading
import time
import urllib.parse

import pytest
import requests

import judge_tool.main as main_mod
from judge_tool.judge import OllamaClient
from judge_tool.webui.jobs import JobManager
from judge_tool.webui.server import Config, make_server
from judge_tool.webui.store import ProjectStore


@pytest.fixture
def running_server(tmp_path):
    store = ProjectStore(str(tmp_path / "projects"), max_upload_bytes=1 * 1024 * 1024)
    config = Config(ollama_url="http://localhost:11434", model="stub-model",
                    criteria=str(tmp_path / "criteria.xlsx"), token=None,
                    max_upload_mb=1)
    jobs = JobManager(store, config)
    jobs.start()
    httpd = make_server(store, jobs, config, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base_url, store, jobs, config
    finally:
        httpd.shutdown()
        httpd.server_close()


def _upload(base_url, pid, filename, data, headers=None):
    hdrs = {"Content-Type": "application/octet-stream",
            "X-Filename": urllib.parse.quote(filename, safe="")}
    if headers:
        hdrs.update(headers)
    return requests.post(f"{base_url}/api/projects/{pid}/assets", data=data, headers=hdrs)


# ── T-8: 프로젝트 CRUD + 404/400 + pid 정규식 위반 ─────────────────────────

def test_project_crud_and_errors(running_server):
    base_url, store, jobs, config = running_server

    resp = requests.post(f"{base_url}/api/projects", json={"name": "웹 테스트"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["ok"] is True
    pid = body["project"]["project_id"]

    resp = requests.get(f"{base_url}/api/projects")
    assert resp.status_code == 200
    assert any(p["project_id"] == pid for p in resp.json()["projects"])

    resp = requests.get(f"{base_url}/api/projects/{pid}")
    assert resp.status_code == 200
    assert resp.json()["project"]["name"] == "웹 테스트"

    # 형식은 맞지만 존재하지 않음 → 404
    resp = requests.get(f"{base_url}/api/projects/p-00000000")
    assert resp.status_code == 404
    assert resp.json()["ok"] is False

    # 형식 위반 → 400
    resp = requests.get(f"{base_url}/api/projects/not-a-valid-id")
    assert resp.status_code == 400

    # 빈 이름 → 400
    resp = requests.post(f"{base_url}/api/projects", json={"name": "  "})
    assert resp.status_code == 400

    # 삭제
    resp = requests.post(f"{base_url}/api/projects/{pid}/delete", json={})
    assert resp.status_code == 200
    resp = requests.get(f"{base_url}/api/projects/{pid}")
    assert resp.status_code == 404


# ── T-9: octet-stream 업로드 e2e(한글 X-Filename) + 413 ────────────────────

def test_upload_asset_korean_filename_and_guessed_profile(running_server):
    base_url, store, jobs, config = running_server
    pid = store.create_project("업로드")["project_id"]

    resp = _upload(base_url, pid, "mysql_result_rds.json", b'{"a":1}')
    assert resp.status_code == 201
    asset = resp.json()["asset"]
    assert asset["original_filename"] == "mysql_result_rds.json"
    assert asset["profile"] == "db_mysql"
    assert asset["profile_source"] == "guessed"

    resp = _upload(base_url, pid, "한글결과파일.xml", b"<xml/>")
    assert resp.status_code == 201
    asset2 = resp.json()["asset"]
    assert asset2["original_filename"] == "한글결과파일.xml"


def test_upload_asset_exceeds_max_size_returns_413(running_server):
    base_url, store, jobs, config = running_server
    pid = store.create_project("초과")["project_id"]
    big = b"0" * (2 * 1024 * 1024)  # config max_upload_mb=1
    resp = _upload(base_url, pid, "big.xml", big)
    assert resp.status_code == 413


def test_upload_asset_traversal_rejected(running_server):
    base_url, store, jobs, config = running_server
    pid = store.create_project("트래버설웹")["project_id"]
    resp = _upload(base_url, pid, "../../evil.xml", b"<xml/>")
    assert resp.status_code == 400


# ── T-10: 판정 흐름(profile null→400, 202+judging, 폴링, 중복 409, 결과) ───

def test_judge_flow_end_to_end(running_server, monkeypatch):
    base_url, store, jobs, config = running_server
    pid = store.create_project("판정흐름")["project_id"]
    resp = _upload(base_url, pid, "unknown.xml", b"<xml/>")
    aid = resp.json()["asset"]["asset_id"]

    # 프로파일 없음 → 400
    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/judge", json={})
    assert resp.status_code == 400

    # 프로파일 지정
    resp = requests.post(
        f"{base_url}/api/projects/{pid}/assets/{aid}/profile",
        json={"profile": "db_mysql", "variant": "mysql_native"})
    assert resp.status_code == 200

    release = threading.Event()
    started = threading.Event()

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        started.set()
        release.wait(timeout=5)
        payload = {
            "metadata": {"profile": profile_key},
            "coverage": {"expected": 1, "judged": 1, "missing": []},
            "judgments": [{"item_id": "DBM-001", "verdict": "양호",
                          "needs_review": False}],
        }
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        # xlsx_out은 존재만 하면 되므로 최소 파일 생성
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake-xlsx")
        return {"expected": 1, "judged": 1, "missing": []}

    monkeypatch.setattr(main_mod, "run", fake_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/judge", json={})
    assert resp.status_code == 202
    assert resp.json()["asset"]["status"] == "judging"

    assert started.wait(timeout=5)

    # 판정 진행 중 중복 요청 → 409
    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/judge", json={})
    assert resp.status_code == 409

    # 판정 진행 중 삭제 → 409
    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/delete", json={})
    assert resp.status_code == 409

    # 결과 아직 없음 → 409
    resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}/result")
    assert resp.status_code == 409

    release.set()

    deadline = time.time() + 5
    status = None
    while time.time() < deadline:
        resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}")
        status = resp.json()["asset"]["status"]
        if status == "judged":
            break
        time.sleep(0.05)
    assert status == "judged"

    resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}/result")
    assert resp.status_code == 200
    assert resp.json()["result"]["judgments"][0]["item_id"] == "DBM-001"

    resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}/result.xlsx")
    assert resp.status_code == 200
    assert resp.content.startswith(b"PK")
    assert "attachment" in resp.headers.get("Content-Disposition", "")


# ── T-11: /api/health + index.html 200 + 외부 리소스 참조 부재 ─────────────

def test_health_ok_and_failure(running_server, monkeypatch):
    base_url, store, jobs, config = running_server

    monkeypatch.setattr(OllamaClient, "health_check", lambda self: None)
    resp = requests.get(f"{base_url}/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["ollama"]["ok"] is True

    def boom(self):
        raise RuntimeError("Ollama 서버에 연결할 수 없습니다")

    monkeypatch.setattr(OllamaClient, "health_check", boom)
    resp = requests.get(f"{base_url}/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["ollama"]["ok"] is False
    assert "연결할 수 없습니다" in body["ollama"]["error"]


def test_index_html_served_without_external_resources(running_server):
    base_url, store, jobs, config = running_server
    resp = requests.get(f"{base_url}/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("Content-Type", "")
    text = resp.text
    assert 'src="http' not in text
    assert 'href="http' not in text
    assert "<!doctype html>" in text.lower() or "<html" in text.lower()


def test_profiles_endpoint(running_server):
    base_url, store, jobs, config = running_server
    resp = requests.get(f"{base_url}/api/profiles")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    keys = {p["key"] for p in body["profiles"]}
    assert "db_mysql" in keys
    assert "cloud" in keys


# ── H-1(a): 판정 진행 중 프로젝트 삭제는 409로 거부되어야 한다 ─────────────

def test_delete_project_while_judging_returns_409(running_server, monkeypatch):
    base_url, store, jobs, config = running_server
    pid = store.create_project("판정중삭제")["project_id"]
    resp = _upload(base_url, pid, "unknown.xml", b"<xml/>")
    aid = resp.json()["asset"]["asset_id"]
    resp = requests.post(
        f"{base_url}/api/projects/{pid}/assets/{aid}/profile",
        json={"profile": "db_mysql", "variant": "mysql_native"})
    assert resp.status_code == 200

    release = threading.Event()
    started = threading.Event()

    def blocking_run(report_path, criteria_path, profile_key, client,
                    json_out, xlsx_out, model_name, **kwargs):
        started.set()
        release.wait(timeout=5)
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake-xlsx")
        return {"expected": 0, "judged": 0, "missing": []}

    monkeypatch.setattr(main_mod, "run", blocking_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/judge", json={})
    assert resp.status_code == 202
    assert started.wait(timeout=5)

    try:
        # 판정이 진행 중인 자산이 있는 프로젝트를 삭제하려 하면 409.
        resp = requests.post(f"{base_url}/api/projects/{pid}/delete", json={})
        assert resp.status_code == 409

        # 실제로 삭제되지 않았어야 한다.
        resp = requests.get(f"{base_url}/api/projects/{pid}")
        assert resp.status_code == 200
    finally:
        release.set()
        deadline = time.time() + 5
        while time.time() < deadline:
            resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}")
            if resp.json()["asset"]["status"] != "judging":
                break
            time.sleep(0.05)


# ── H-1(b): run이 임의 예외를 던져도 워커가 살아남아 다음 자산을 처리한다
#            (HTTP 레벨 — judge_all로 두 자산을 순차 enqueue) ──────────────

def test_worker_survives_exception_and_next_asset_still_judges(running_server, monkeypatch):
    base_url, store, jobs, config = running_server
    pid = store.create_project("워커생존")["project_id"]

    resp = _upload(base_url, pid, "boom.xml", b"<xml/>")
    aid1 = resp.json()["asset"]["asset_id"]
    resp = requests.post(
        f"{base_url}/api/projects/{pid}/assets/{aid1}/profile",
        json={"profile": "db_mysql", "variant": "mysql_native"})
    assert resp.status_code == 200

    resp = _upload(base_url, pid, "ok.xml", b"<xml/>")
    aid2 = resp.json()["asset"]["asset_id"]
    resp = requests.post(
        f"{base_url}/api/projects/{pid}/assets/{aid2}/profile",
        json={"profile": "db_mysql", "variant": "mysql_native"})
    assert resp.status_code == 200

    def flaky_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        if "boom" in report_path:
            raise RuntimeError("치명적 예외(과거엔 워커를 죽였음)")
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake-xlsx")
        return {"expected": 0, "judged": 0, "missing": []}

    monkeypatch.setattr(main_mod, "run", flaky_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid1}/judge", json={})
    assert resp.status_code == 202
    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid2}/judge", json={})
    assert resp.status_code == 202

    deadline = time.time() + 5
    status1 = status2 = None
    while time.time() < deadline:
        status1 = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid1}").json()["asset"]["status"]
        status2 = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid2}").json()["asset"]["status"]
        if status1 == "failed" and status2 == "judged":
            break
        time.sleep(0.05)
    assert status1 == "failed"
    assert status2 == "judged"


# ── M-1: 토큰 모드에서 ?token= 쿼리 인증도 허용(엑셀 다운로드 등) ──────────

def test_token_query_param_auth_allows_download(tmp_path, monkeypatch):
    store = ProjectStore(str(tmp_path / "projects"), max_upload_bytes=1 * 1024 * 1024)
    config = Config(ollama_url="http://localhost:11434", model="stub-model",
                    criteria=str(tmp_path / "criteria.xlsx"), token="secret-token",
                    max_upload_mb=1)
    jobs = JobManager(store, config)
    jobs.start()
    httpd = make_server(store, jobs, config, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        # (a) 헤더 토큰은 그대로 통과해야 한다.
        resp = requests.get(f"{base_url}/api/projects",
                            headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 200

        pid = requests.post(f"{base_url}/api/projects", json={"name": "쿼리토큰"},
                            headers={"X-Auth-Token": "secret-token"}).json()["project"]["project_id"]
        resp = _upload(base_url, pid, "unknown.xml", b"<xml/>",
                      headers={"X-Auth-Token": "secret-token"})
        aid = resp.json()["asset"]["asset_id"]
        resp = requests.post(
            f"{base_url}/api/projects/{pid}/assets/{aid}/profile",
            json={"profile": "db_mysql", "variant": "mysql_native"},
            headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 200

        def fake_run(report_path, criteria_path, profile_key, client,
                    json_out, xlsx_out, model_name, **kwargs):
            os.makedirs(os.path.dirname(json_out), exist_ok=True)
            with open(json_out, "w", encoding="utf-8") as fh:
                json.dump({"judgments": []}, fh)
            with open(xlsx_out, "wb") as fh:
                fh.write(b"PK\x03\x04fake-xlsx")
            return {"expected": 0, "judged": 0, "missing": []}

        monkeypatch.setattr(main_mod, "run", fake_run)
        resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/judge",
                            json={}, headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 202

        deadline = time.time() + 5
        status = None
        while time.time() < deadline:
            resp = requests.get(f"{base_url}/api/projects/{pid}/assets/{aid}",
                                headers={"X-Auth-Token": "secret-token"})
            status = resp.json()["asset"]["status"]
            if status == "judged":
                break
            time.sleep(0.05)
        assert status == "judged"

        # (b) 헤더 없이 ?token= 쿼리만으로 엑셀 다운로드가 통과해야 한다.
        resp = requests.get(
            f"{base_url}/api/projects/{pid}/assets/{aid}/result.xlsx"
            f"?token=secret-token")
        assert resp.status_code == 200
        assert resp.content.startswith(b"PK")

        # (c) 틀린 토큰이면 쿼리로도 401.
        resp = requests.get(
            f"{base_url}/api/projects/{pid}/assets/{aid}/result.xlsx"
            f"?token=wrong-token")
        assert resp.status_code == 401
    finally:
        httpd.shutdown()
        httpd.server_close()


# ── M-2: 본문을 읽지 않고 4xx를 반환하는 경로는 Connection: close ─────────

def _raw_request_no_content_length(base_url, path, extra_headers=""):
    """requests는 bytes 본문에 항상 Content-Length를 자동으로 붙이므로,
    Content-Length 헤더 없이 보내는 요청(411 유도)은 raw 소켓으로 만든다."""
    parsed = urllib.parse.urlparse(base_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            f"{extra_headers}"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(req)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def test_error_responses_close_connection_when_body_unread(running_server):
    base_url, store, jobs, config = running_server
    pid = store.create_project("커넥션클로즈")["project_id"]

    # 411: Content-Length 헤더 없이 업로드 시도(raw 소켓 — requests는 항상
    # Content-Length를 자동으로 채우므로 이렇게는 재현할 수 없다).
    raw = _raw_request_no_content_length(
        base_url, f"/api/projects/{pid}/assets", "X-Filename: a.xml\r\n")
    status_line = raw.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    assert " 411 " in status_line
    assert b"connection: close" in raw.lower()

    # 400: X-Filename 헤더 누락(본문 그대로 미독).
    resp = requests.post(f"{base_url}/api/projects/{pid}/assets", data=b"<xml/>")
    assert resp.status_code == 400
    assert resp.headers.get("Connection", "").lower() == "close"

    # 413: 업로드 용량 상한 초과(본문 미독).
    big = b"0" * (2 * 1024 * 1024)  # config max_upload_mb=1 (running_server fixture)
    resp = _upload(base_url, pid, "big.xml", big)
    assert resp.status_code == 413
    assert resp.headers.get("Connection", "").lower() == "close"

    # 정상 요청은 여전히 keep-alive(명시적으로 close를 걸지 않음)여야 한다.
    resp = requests.get(f"{base_url}/api/projects/{pid}")
    assert resp.status_code == 200
    assert resp.headers.get("Connection", "").lower() != "close"


def _read_http_response(sock):
    """소켓에서 HTTP/1.1 응답 1개(상태줄+헤더+Content-Length 본문)를 읽어
    (status_line_bytes, body_bytes) 반환. keep-alive 재사용 검증용."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    header_part, _, rest = buf.partition(b"\r\n\r\n")
    lines = header_part.split(b"\r\n")
    status_line = lines[0]
    clen = 0
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
    body = rest
    while len(body) < clen:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return status_line, body[:clen]


def test_keepalive_not_corrupted_after_bodyless_post(running_server):
    """M-3 회귀: 본문('{}')을 안 읽는 POST(delete 등) 뒤에 같은 keep-alive
    커넥션으로 온 다음 요청이 오염되면 안 된다. 미수정 시 서버가 남은 '{}'를
    다음 요청라인으로 오파싱해 501('{}GET ...')을 낸다."""
    base_url, store, jobs, config = running_server
    pid = requests.post(f"{base_url}/api/projects",
                        json={"name": "keepalive"}).json()["project"]["project_id"]
    parsed = urllib.parse.urlparse(base_url)
    host, port = parsed.hostname, parsed.port

    with socket.create_connection((host, port), timeout=5) as sock:
        # 프론트가 실제로 보내는 형태: 본문 "{}" + keep-alive 유지.
        req1 = (
            f"POST /api/projects/{pid}/delete HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: 2\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"{{}}"
        ).encode("utf-8")
        sock.sendall(req1)
        status1, _ = _read_http_response(sock)
        assert status1.startswith(b"HTTP/1.1 200"), status1

        # 같은 소켓으로 후속 요청 — 미수정 시 남은 '{}'로 501('{}GET ...').
        req2 = (
            f"GET /api/health HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(req2)
        status2, _ = _read_http_response(sock)
        assert status2.startswith(b"HTTP/1.1 200"), status2


def test_token_auth(tmp_path):
    store = ProjectStore(str(tmp_path / "projects"))
    config = Config(ollama_url="http://localhost:11434", model="stub-model",
                    criteria=None, token="secret-token", max_upload_mb=1)
    jobs = JobManager(store, config)
    jobs.start()
    httpd = make_server(store, jobs, config, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        # GET / 는 토큰 없이 허용
        resp = requests.get(f"{base_url}/")
        assert resp.status_code == 200

        # /api/* 는 토큰 불일치 시 401
        resp = requests.get(f"{base_url}/api/projects")
        assert resp.status_code == 401

        resp = requests.get(f"{base_url}/api/projects",
                            headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()

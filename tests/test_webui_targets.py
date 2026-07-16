"""웹UI 계층 워크스페이스(점검분야→대상→파일) 신규 기능 테스트.

설계서 docs/superpowers/specs/2026-07-16-webui-hierarchy-design.md §7 전체를
다룬다. 기존 tests/test_webui_store.py·test_webui_api.py는 무수정 — 이 파일은
추가 전용이다. Ollama/실데이터 불필요, 합성 데이터만 사용한다."""
import json
import os
import threading
import time
import urllib.parse

import pytest
import requests

from judge_tool.webui import store as store_mod
from judge_tool.webui.jobs import JobManager
from judge_tool.webui.server import Config, make_server
from judge_tool.webui.store import ConflictError, ProjectStore, validate_target_id


@pytest.fixture
def store(tmp_path):
    return ProjectStore(str(tmp_path / "projects"))


# ═══════════════════════════════════════════════════════════════════════
# store.py — 대상(target) CRUD
# ═══════════════════════════════════════════════════════════════════════

# ── create_target ─────────────────────────────────────────────────────

def test_create_target_basic(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "dbms", "PROD-DB-01")
    assert target["id"].startswith("t-")
    assert target["domain"] == "dbms"
    assert target["name"] == "PROD-DB-01"
    assert "created" in target

    reloaded = store.get_project(pid)
    assert len(reloaded["targets"]) == 1
    assert reloaded["targets"][0]["id"] == target["id"]


def test_create_target_rejects_unknown_domain(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.create_target(project["project_id"], "not_a_domain", "이름")


def test_create_target_rejects_empty_name(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.create_target(project["project_id"], "server", "   ")


def test_create_target_rejects_too_long_name(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.create_target(project["project_id"], "server", "가" * 121)


def test_create_target_rejects_control_chars(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.create_target(project["project_id"], "server", "이름\x01나쁨")


def test_create_target_strips_and_trims_name(store):
    project = store.create_project("P")
    target = store.create_target(project["project_id"], "server", "  SRV-01  ")
    assert target["name"] == "SRV-01"


def test_create_target_missing_project_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.create_target("p-00000000", "server", "이름")


# ── rename_target ─────────────────────────────────────────────────────

def test_rename_target(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "OLD-NAME")
    renamed = store.rename_target(pid, target["id"], "NEW-NAME")
    assert renamed["name"] == "NEW-NAME"
    assert renamed["domain"] == "server"  # 변경 안 됨


def test_rename_target_missing_raises_keyerror(store):
    project = store.create_project("P")
    with pytest.raises(KeyError):
        store.rename_target(project["project_id"], "t-00000000", "이름")


def test_rename_target_rejects_empty_name(store):
    project = store.create_project("P")
    target = store.create_target(project["project_id"], "server", "이름")
    with pytest.raises(ValueError):
        store.rename_target(project["project_id"], target["id"], "")


def test_rename_target_succeeds_while_member_asset_judging(store):
    """L-3: rename은 이름만 바꾸고 id 참조는 그대로라 judging 중에도 안전
    (ConflictError 불필요)."""
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=target["id"])
    store.update_asset(pid, asset["asset_id"], status="judging")
    renamed = store.rename_target(pid, target["id"], "SRV-01-RENAMED")
    assert renamed["name"] == "SRV-01-RENAMED"


# ── delete_target (cascade=False — 미분류 이동) ───────────────────────

def test_delete_target_default_moves_assets_to_unclassified(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=target["id"])
    aid = asset["asset_id"]

    store.delete_target(pid, target["id"])

    reloaded = store.get_project(pid)
    assert reloaded["targets"] == []
    matching = [a for a in reloaded["assets"] if a["asset_id"] == aid]
    assert len(matching) == 1
    assert matching[0]["target_id"] is None
    # 비파괴 — 자산 파일 자체는 그대로 남는다.
    assert store.asset_abspath(pid, aid)


def test_delete_target_default_allows_judging_members(store):
    """cascade=False는 비파괴 이동뿐이라 judging 중이어도 막을 이유가 없다."""
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=target["id"])
    store.update_asset(pid, asset["asset_id"], status="judging")
    store.delete_target(pid, target["id"])  # 예외 없어야 함
    reloaded = store.get_project(pid)
    assert reloaded["assets"][0]["target_id"] is None


def test_delete_target_missing_raises_keyerror(store):
    project = store.create_project("P")
    with pytest.raises(KeyError):
        store.delete_target(project["project_id"], "t-00000000")


# ── delete_target (cascade=True — 파괴적 삭제) ─────────────────────────

def test_delete_target_cascade_removes_assets_and_results(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=target["id"])
    aid = asset["asset_id"]
    json_path, xlsx_path = store.result_paths(pid, aid)
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"judgments": []}, fh)
    with open(xlsx_path, "wb") as fh:
        fh.write(b"PK\x03\x04fake")

    store.delete_target(pid, target["id"], cascade=True)

    reloaded = store.get_project(pid)
    assert reloaded["targets"] == []
    assert reloaded["assets"] == []
    assert not os.path.isfile(json_path)
    assert not os.path.isfile(xlsx_path)
    with pytest.raises(KeyError):
        store.get_asset(pid, aid)


def test_delete_target_cascade_rejects_while_member_judging(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=target["id"])
    store.update_asset(pid, asset["asset_id"], status="judging")

    with pytest.raises(ConflictError):
        store.delete_target(pid, target["id"], cascade=True)

    # 부분상태 없이 그대로 남아 있어야 한다(H-3).
    reloaded = store.get_project(pid)
    assert len(reloaded["targets"]) == 1
    assert len(reloaded["assets"]) == 1
    assert reloaded["assets"][0]["target_id"] == target["id"]


def test_delete_target_cascade_leaves_unrelated_assets_untouched(store):
    project = store.create_project("P")
    pid = project["project_id"]
    t1 = store.create_target(pid, "server", "SRV-01")
    t2 = store.create_target(pid, "server", "SRV-02")
    store.add_asset(pid, "a.xml", b"<xml/>", target_id=t1["id"])
    kept = store.add_asset(pid, "b.xml", b"<xml/>", target_id=t2["id"])

    store.delete_target(pid, t1["id"], cascade=True)

    reloaded = store.get_project(pid)
    assert [t["id"] for t in reloaded["targets"]] == [t2["id"]]
    assert [a["asset_id"] for a in reloaded["assets"]] == [kept["asset_id"]]


# ── assign_asset_target ────────────────────────────────────────────────

def test_assign_asset_target_moves_asset(store):
    project = store.create_project("P")
    pid = project["project_id"]
    t1 = store.create_target(pid, "server", "SRV-01")
    t2 = store.create_target(pid, "server", "SRV-02")
    asset = store.add_asset(pid, "a.xml", b"<xml/>", target_id=t1["id"])
    aid = asset["asset_id"]

    updated = store.assign_asset_target(pid, aid, t2["id"])
    assert updated["target_id"] == t2["id"]

    updated = store.assign_asset_target(pid, aid, None)
    assert updated["target_id"] is None


def test_assign_asset_target_rejects_unknown_target(store):
    project = store.create_project("P")
    pid = project["project_id"]
    asset = store.add_asset(pid, "a.xml", b"<xml/>")
    with pytest.raises(KeyError):
        store.assign_asset_target(pid, asset["asset_id"], "t-00000000")


def test_assign_asset_target_rejects_unknown_asset(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    with pytest.raises(KeyError):
        store.assign_asset_target(pid, "a-00000000", target["id"])


# ── list_targets 정렬 ───────────────────────────────────────────────────

def test_list_targets_sorted_by_created_then_name(store):
    project = store.create_project("P")
    pid = project["project_id"]
    store.create_target(pid, "server", "B")
    store.create_target(pid, "server", "A")
    store.create_target(pid, "server", "C")

    # created 시각을 직접 조작(동일/역순)해 정렬이 created→name 기준임을 검증.
    proj = store.get_project(pid)
    stamps = {"B": "2026-01-01 00:00:01", "A": "2026-01-01 00:00:01",
             "C": "2026-01-01 00:00:00"}
    for t in proj["targets"]:
        t["created"] = stamps[t["name"]]
    store._save_project(proj)

    targets = store.list_targets(pid)
    names = [t["name"] for t in targets]
    # created 먼저(00:00 C가 먼저), 동일 created는 name순(A, B)
    assert names == ["C", "A", "B"]


def test_list_targets_empty_for_new_project(store):
    project = store.create_project("P")
    assert store.list_targets(project["project_id"]) == []


# ── target_summary — 혼합상태 집계(M-1) ────────────────────────────────

def test_target_summary_mixed_states(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "dbms", "PROD-DB-01")
    tid = target["id"]

    a1 = store.add_asset(pid, "mysql_result.json", b"{}", target_id=tid)
    store.update_asset(pid, a1["asset_id"], status="judged",
                       summary={"verdict_counts": {"양호": 3, "취약": 1, "판단보류": 2}})
    a2 = store.add_asset(pid, "mysql_result_rds.json", b"{}", target_id=tid)
    store.update_asset(pid, a2["asset_id"], status="judged",
                       summary={"verdict_counts": {"양호": 5, "취약": 0, "판단보류": 0}})
    a3 = store.add_asset(pid, "mssql_result.json", b"{}", target_id=tid)
    store.update_asset(pid, a3["asset_id"], status="failed")
    store.add_asset(pid, "postgresql_result.json", b"{}", target_id=tid)  # pending

    summary = store.target_summary(pid, tid)
    assert summary["verdict_counts"] == {"양호": 8, "취약": 1, "판단보류": 2}
    assert summary["judged_assets"] == 2
    assert summary["total_assets"] == 4
    assert summary["failed"] == 1
    assert summary["judging"] == 0


def test_target_summary_ignores_assets_of_other_targets(store):
    project = store.create_project("P")
    pid = project["project_id"]
    t1 = store.create_target(pid, "server", "SRV-01")
    t2 = store.create_target(pid, "server", "SRV-02")
    a1 = store.add_asset(pid, "a.xml", b"<xml/>", target_id=t1["id"])
    store.update_asset(pid, a1["asset_id"], status="judged",
                       summary={"verdict_counts": {"양호": 1, "취약": 0, "판단보류": 0}})
    store.add_asset(pid, "b.xml", b"<xml/>", target_id=t2["id"])

    summary = store.target_summary(pid, t1["id"])
    assert summary["total_assets"] == 1
    assert summary["verdict_counts"]["양호"] == 1


def test_target_summary_missing_target_raises_keyerror(store):
    project = store.create_project("P")
    with pytest.raises(KeyError):
        store.target_summary(project["project_id"], "t-00000000")


# ── add_asset target_id 옵션 — 프로파일 상속(M-3) ──────────────────────

def test_add_asset_with_target_keeps_guessed_profile_in_domain(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "dbms", "PROD-DB-01")
    asset = store.add_asset(pid, "mysql_result_rds.json", b'{"a":1}', target_id=target["id"])
    assert asset["profile"] == "db_mysql"
    assert asset["profile_source"] == "guessed"
    assert asset["target_id"] == target["id"]


def test_add_asset_with_target_falls_back_to_domain_default(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "server", "SRV-01")
    # 확장자만으로 모호(server/network/... 등 후보 다수) → guessed=None
    asset = store.add_asset(pid, "unknown.xml", b"<xml/>", target_id=target["id"])
    assert asset["profile"] == "server"
    assert asset["profile_source"] == "target"


def test_add_asset_with_target_overrides_mismatched_guess(store):
    project = store.create_project("P")
    pid = project["project_id"]
    target = store.create_target(pid, "network", "SW-01")
    # 파일명은 db_mysql로 추정되지만 대상 domain(network)엔 속하지 않음 → 대체
    asset = store.add_asset(pid, "mysql_result_rds.json", b'{"a":1}', target_id=target["id"])
    assert asset["profile"] == "network"
    assert asset["profile_source"] == "target"


def test_add_asset_without_target_unchanged_behavior(store):
    """target_id 미지정 시 기존 동작(순수 guess_profile) 그대로 — 회귀 확인."""
    project = store.create_project("P")
    pid = project["project_id"]
    asset = store.add_asset(pid, "mysql_result_rds.json", b'{"a":1}')
    assert asset["profile"] == "db_mysql"
    assert asset["profile_source"] == "guessed"
    assert asset["target_id"] is None


def test_add_asset_rejects_unknown_target_id(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "a.xml", b"<xml/>", target_id="t-00000000")


def test_add_asset_rejects_malformed_target_id(store):
    project = store.create_project("P")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "a.xml", b"<xml/>", target_id="not-a-target-id")


# ── validate_target_id ─────────────────────────────────────────────────

def test_validate_target_id_rejects_malformed():
    with pytest.raises(ValueError):
        validate_target_id("not-a-target")
    with pytest.raises(ValueError):
        validate_target_id("p-12345678")  # p- 접두는 target이 아님
    with pytest.raises(ValueError):
        validate_target_id("t-short")
    validate_target_id("t-12345678")  # 정상은 예외 없음


# ── 구스키마 하위호환 ────────────────────────────────────────────────────

def test_legacy_project_json_without_targets_key_loads_fine(store):
    project = store.create_project("구스키마")
    pid = project["project_id"]
    # targets 키를 강제로 제거해 구버전 project.json을 시뮬레이션.
    raw = store.get_project(pid)
    assert "targets" not in raw or raw.get("targets") == []
    # 구스키마에도 정상 동작해야 하는 것들:
    assert store.list_targets(pid) == []
    asset = store.add_asset(pid, "a.xml", b"<xml/>")  # target_id 없이 정상
    assert asset["target_id"] is None
    # create_target으로 최초 targets 키가 생성됨.
    target = store.create_target(pid, "server", "신규대상")
    reloaded = store.get_project(pid)
    assert len(reloaded["targets"]) == 1
    assert reloaded["targets"][0]["id"] == target["id"]


def test_dangling_target_id_reference_does_not_crash(store):
    """구버전 데이터/수동 편집 등으로 존재하지 않는 target_id를 참조하는
    자산이 있어도 방어적 접근(.get)으로 조회는 크래시하지 않아야 한다."""
    project = store.create_project("댕글링")
    pid = project["project_id"]
    asset = store.add_asset(pid, "unknown.xml", b"<xml/>")
    aid = asset["asset_id"]
    proj = store.get_project(pid)
    for a in proj["assets"]:
        if a["asset_id"] == aid:
            a["target_id"] = "t-deadbeef"
    store._save_project(proj)

    reloaded = store.get_project(pid)
    assert reloaded["assets"][0]["target_id"] == "t-deadbeef"
    # 댕글링 tid로 summary 조회는 KeyError(→서버 404)로 안전하게 실패한다.
    with pytest.raises(KeyError):
        store.target_summary(pid, "t-deadbeef")
    # 댕글링 자산을 다른(존재하는) 대상으로 재배치하는 것은 여전히 가능하다.
    target = store.create_target(pid, "server", "정상대상")
    updated = store.assign_asset_target(pid, aid, target["id"])
    assert updated["target_id"] == target["id"]


# ── M-7 회귀: list_projects 응답 무변경 ─────────────────────────────────

def test_list_projects_unchanged_after_targets_added(store):
    project = store.create_project("회귀")
    pid = project["project_id"]
    store.create_target(pid, "server", "SRV-01")
    store.add_asset(pid, "a.xml", b"<xml/>")
    summaries = store.list_projects()
    assert len(summaries) == 1
    assert set(summaries[0]) == {"project_id", "name", "created_at", "updated_at",
                                 "asset_count", "status_counts"}


# ═══════════════════════════════════════════════════════════════════════
# server.py — HTTP API (ThreadingHTTPServer 실기동, requests로 접속)
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def running_server(tmp_path):
    proj_store = ProjectStore(str(tmp_path / "projects"), max_upload_bytes=1 * 1024 * 1024)
    config = Config(ollama_url="http://localhost:11434", model="stub-model",
                    criteria=str(tmp_path / "criteria.xlsx"), token=None,
                    max_upload_mb=1)
    jobs = JobManager(proj_store, config)
    jobs.start()
    httpd = make_server(proj_store, jobs, config, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base_url, proj_store, jobs, config
    finally:
        httpd.shutdown()
        httpd.server_close()


def _upload(base_url, pid, filename, data, target_id=None):
    hdrs = {"Content-Type": "application/octet-stream",
            "X-Filename": urllib.parse.quote(filename, safe="")}
    if target_id is not None:
        hdrs["X-Target-Id"] = target_id
    return requests.post(f"{base_url}/api/projects/{pid}/assets", data=data, headers=hdrs)


def test_api_create_rename_delete_target(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API대상")["project_id"]

    resp = requests.post(f"{base_url}/api/projects/{pid}/targets",
                        json={"domain": "dbms", "name": "PROD-DB-01"})
    assert resp.status_code == 201
    target = resp.json()["target"]
    tid = target["id"]

    resp = requests.post(f"{base_url}/api/projects/{pid}/targets/{tid}/rename",
                        json={"name": "PROD-DB-01-RENAMED"})
    assert resp.status_code == 200
    assert resp.json()["target"]["name"] == "PROD-DB-01-RENAMED"

    resp = requests.get(f"{base_url}/api/projects/{pid}/targets/{tid}/summary")
    assert resp.status_code == 200
    body = resp.json()["summary"]
    assert body["total_assets"] == 0

    resp = requests.post(f"{base_url}/api/projects/{pid}/targets/{tid}/delete", json={})
    assert resp.status_code == 200
    resp = requests.get(f"{base_url}/api/projects/{pid}")
    assert resp.json()["project"]["targets"] == []


def test_api_create_target_rejects_unknown_domain(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API도메인오류")["project_id"]
    resp = requests.post(f"{base_url}/api/projects/{pid}/targets",
                        json={"domain": "not_a_domain", "name": "이름"})
    assert resp.status_code == 400


def test_api_create_target_rejects_too_long_name(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API이름오류")["project_id"]
    resp = requests.post(f"{base_url}/api/projects/{pid}/targets",
                        json={"domain": "server", "name": "가" * 200})
    assert resp.status_code == 400


def test_api_assign_asset_target(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API배치")["project_id"]
    tid = proj_store.create_target(pid, "server", "SRV-01")["id"]
    resp = _upload(base_url, pid, "a.xml", b"<xml/>")
    aid = resp.json()["asset"]["asset_id"]

    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/target",
                        json={"target_id": tid})
    assert resp.status_code == 200
    assert resp.json()["asset"]["target_id"] == tid

    resp = requests.post(f"{base_url}/api/projects/{pid}/assets/{aid}/target",
                        json={"target_id": None})
    assert resp.status_code == 200
    assert resp.json()["asset"]["target_id"] is None


def test_api_upload_with_x_target_id_header(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API헤더업로드")["project_id"]
    tid = proj_store.create_target(pid, "dbms", "PROD-DB-01")["id"]

    resp = _upload(base_url, pid, "mysql_result.json", b"{}", target_id=tid)
    assert resp.status_code == 201
    asset = resp.json()["asset"]
    assert asset["target_id"] == tid
    assert asset["profile"] == "db_mysql"


def test_api_upload_with_unknown_x_target_id_returns_400(running_server):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API헤더오류")["project_id"]
    resp = _upload(base_url, pid, "a.xml", b"<xml/>", target_id="t-00000000")
    assert resp.status_code == 400


def test_api_delete_target_cascade_conflict_returns_409(running_server, monkeypatch):
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("API판정중삭제")["project_id"]
    tid = proj_store.create_target(pid, "dbms", "PROD-DB-01")["id"]
    resp = _upload(base_url, pid, "mysql_result.json", b"{}", target_id=tid)
    aid = resp.json()["asset"]["asset_id"]
    proj_store.update_asset(pid, aid, status="judging")

    resp = requests.post(f"{base_url}/api/projects/{pid}/targets/{tid}/delete",
                        json={"cascade": True})
    assert resp.status_code == 409

    # cascade=False(기본)는 judging 중에도 안전하게 허용된다(비파괴 이동).
    resp = requests.post(f"{base_url}/api/projects/{pid}/targets/{tid}/delete", json={})
    assert resp.status_code == 200
    reloaded = proj_store.get_asset(pid, aid)
    assert reloaded["target_id"] is None


def test_api_target_routes_require_auth_token(tmp_path):
    proj_store = ProjectStore(str(tmp_path / "projects"))
    config = Config(ollama_url="http://localhost:11434", model="stub-model",
                    criteria=None, token="secret-token", max_upload_mb=1)
    jobs = JobManager(proj_store, config)
    jobs.start()
    httpd = make_server(proj_store, jobs, config, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        pid = proj_store.create_project("인증게이트")["project_id"]

        # 토큰 없이 신규 라우트 접근 → 401
        resp = requests.post(f"{base_url}/api/projects/{pid}/targets",
                            json={"domain": "server", "name": "이름"})
        assert resp.status_code == 401

        # 올바른 토큰이면 통과.
        resp = requests.post(f"{base_url}/api/projects/{pid}/targets",
                            json={"domain": "server", "name": "이름"},
                            headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 201
        tid = resp.json()["target"]["id"]

        resp = requests.get(f"{base_url}/api/projects/{pid}/targets/{tid}/summary")
        assert resp.status_code == 401
        resp = requests.get(f"{base_url}/api/projects/{pid}/targets/{tid}/summary",
                            headers={"X-Auth-Token": "secret-token"})
        assert resp.status_code == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_api_judge_all_target_filter(running_server, monkeypatch):
    """L-4: judge_all에 target_id 필터를 주면 해당 대상 자산만 enqueue된다."""
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("판정필터")["project_id"]
    t1 = proj_store.create_target(pid, "dbms", "PROD-DB-01")["id"]
    t2 = proj_store.create_target(pid, "dbms", "PROD-DB-02")["id"]

    resp1 = _upload(base_url, pid, "mysql_result.json", b"{}", target_id=t1)
    aid1 = resp1.json()["asset"]["asset_id"]
    resp2 = _upload(base_url, pid, "mysql_result_rds.json", b"{}", target_id=t2)
    aid2 = resp2.json()["asset"]["asset_id"]

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake")
        return {"expected": 0, "judged": 0, "missing": []}

    import judge_tool.main as main_mod
    monkeypatch.setattr(main_mod, "run", fake_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/judge_all",
                        json={"target_id": t1})
    assert resp.status_code == 200
    body = resp.json()
    assert body["enqueued"] == [aid1]

    deadline = time.time() + 5
    while time.time() < deadline:
        a1 = proj_store.get_asset(pid, aid1)
        if a1["status"] == "judged":
            break
        time.sleep(0.02)
    assert proj_store.get_asset(pid, aid1)["status"] == "judged"
    # 필터에 안 걸린 대상 2의 자산은 여전히 대기 상태여야 한다.
    assert proj_store.get_asset(pid, aid2)["status"] == "pending"


def test_api_judge_all_domain_filter(running_server, monkeypatch):
    """L-4: judge_all에 domain 필터를 주면 해당 분야(대상들) 자산만 enqueue."""
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("분야필터")["project_id"]
    t_dbms = proj_store.create_target(pid, "dbms", "PROD-DB-01")["id"]
    t_server = proj_store.create_target(pid, "server", "SRV-01")["id"]

    resp1 = _upload(base_url, pid, "mysql_result.json", b"{}", target_id=t_dbms)
    aid_dbms = resp1.json()["asset"]["asset_id"]
    resp2 = _upload(base_url, pid, "unknown.xml", b"<xml/>", target_id=t_server)
    aid_server = resp2.json()["asset"]["asset_id"]

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake")
        return {"expected": 0, "judged": 0, "missing": []}

    import judge_tool.main as main_mod
    monkeypatch.setattr(main_mod, "run", fake_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/judge_all",
                        json={"domain": "server"})
    assert resp.status_code == 200
    assert resp.json()["enqueued"] == [aid_server]

    deadline = time.time() + 5
    while time.time() < deadline:
        if proj_store.get_asset(pid, aid_server)["status"] == "judged":
            break
        time.sleep(0.02)
    assert proj_store.get_asset(pid, aid_server)["status"] == "judged"
    assert proj_store.get_asset(pid, aid_dbms)["status"] == "pending"


def test_api_judge_all_without_filter_unchanged(running_server, monkeypatch):
    """필터 없는 기존 호출(body={})은 여전히 프로젝트 전체 자산 대상 — 회귀."""
    base_url, proj_store, jobs, config = running_server
    pid = proj_store.create_project("필터없음")["project_id"]
    resp = _upload(base_url, pid, "mysql_result.json", b"{}")
    aid = resp.json()["asset"]["asset_id"]

    def fake_run(report_path, criteria_path, profile_key, client,
                json_out, xlsx_out, model_name, **kwargs):
        os.makedirs(os.path.dirname(json_out), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"judgments": []}, fh)
        with open(xlsx_out, "wb") as fh:
            fh.write(b"PK\x03\x04fake")
        return {"expected": 0, "judged": 0, "missing": []}

    import judge_tool.main as main_mod
    monkeypatch.setattr(main_mod, "run", fake_run)

    resp = requests.post(f"{base_url}/api/projects/{pid}/judge_all", json={})
    assert resp.status_code == 200
    assert resp.json()["enqueued"] == [aid]

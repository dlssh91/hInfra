"""ProjectStore 단위 테스트 (T-1~T-4). Ollama/실데이터 불필요, 합성 데이터만 사용."""
import json
import os

import pytest

from judge_tool.webui import store as store_mod
from judge_tool.webui.store import ConflictError, ProjectStore, check_project_root_safe


@pytest.fixture
def store(tmp_path):
    return ProjectStore(str(tmp_path / "projects"))


# ── T-1: CRUD + 원자적 저장 + _new_id monkeypatch ──────────────────────────

def test_create_and_get_project(store):
    project = store.create_project("테스트 프로젝트")
    assert project["schema_version"] == 1
    assert project["project_id"].startswith("p-")
    assert project["assets"] == []

    loaded = store.get_project(project["project_id"])
    assert loaded["name"] == "테스트 프로젝트"


def test_create_project_empty_name_rejected(store):
    with pytest.raises(ValueError):
        store.create_project("   ")


def test_get_project_missing_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.get_project("p-00000000")


def test_list_projects_summary(store):
    p1 = store.create_project("A")
    store.create_project("B")
    summaries = store.list_projects()
    assert len(summaries) == 2
    ids = {s["project_id"] for s in summaries}
    assert p1["project_id"] in ids
    for s in summaries:
        assert set(s) == {"project_id", "name", "created_at", "updated_at",
                          "asset_count", "status_counts"}


def test_project_json_written_atomically(store, tmp_path):
    project = store.create_project("A")
    pjson = os.path.join(store.root, project["project_id"], "project.json")
    assert os.path.isfile(pjson)
    assert not os.path.isfile(pjson + ".tmp")
    with open(pjson, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["project_id"] == project["project_id"]


def test_new_id_monkeypatch(store, monkeypatch):
    monkeypatch.setattr(store_mod, "_new_id", lambda prefix: f"{prefix}-deadbeef")
    project = store.create_project("고정ID")
    assert project["project_id"] == "p-deadbeef"


def test_delete_project(store):
    project = store.create_project("삭제대상")
    pid = project["project_id"]
    store.delete_project(pid)
    with pytest.raises(KeyError):
        store.get_project(pid)


def test_delete_project_missing_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.delete_project("p-00000000")


# ── T-2: add_asset 검증 (프로파일 추정/후보/확장자/크기) ───────────────────

def test_add_asset_guesses_profile_db_mysql(store):
    project = store.create_project("DB")
    pid = project["project_id"]
    asset = store.add_asset(pid, "mysql_result_rds.json", b'{"a":1}')
    assert asset["profile"] == "db_mysql"
    assert asset["profile_source"] == "guessed"
    assert asset["original_filename"] == "mysql_result_rds.json"
    assert asset["status"] == "pending"
    # 원본 파일이 asset_id 하위 디렉터리에 원본명 그대로 저장됨
    abspath = store.asset_abspath(pid, asset["asset_id"])
    assert os.path.basename(abspath) == "mysql_result_rds.json"
    with open(abspath, "rb") as fh:
        assert fh.read() == b'{"a":1}'


def test_add_asset_ambiguous_xml_has_candidates(store):
    project = store.create_project("모호")
    asset = store.add_asset(project["project_id"], "foo.xml", b"<xml/>")
    assert asset["profile"] is None
    assert asset["profile_source"] is None
    assert len(asset["profile_candidates"]) > 1


def test_add_asset_rejects_disallowed_extension(store):
    project = store.create_project("확장자")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "malware.exe", b"MZ")


def test_add_asset_rejects_oversized_file(tmp_path):
    small_store = ProjectStore(str(tmp_path / "p2"), max_upload_bytes=10)
    project = small_store.create_project("사이즈")
    with pytest.raises(ValueError):
        small_store.add_asset(project["project_id"], "a.xml", b"0" * 100)


def test_add_asset_rejects_empty_file(store):
    project = store.create_project("빈파일")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "a.xml", b"")


def test_add_asset_missing_project_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.add_asset("p-00000000", "a.xml", b"<xml/>")


# ── T-3: traversal 방어 ────────────────────────────────────────────────────

def test_add_asset_rejects_path_traversal(store):
    project = store.create_project("트래버설")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "../../evil.xml", b"<xml/>")


def test_add_asset_rejects_nul_byte(store):
    project = store.create_project("NUL")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "evil\x00.xml", b"<xml/>")


def test_add_asset_rejects_backslash(store):
    project = store.create_project("백슬래시")
    with pytest.raises(ValueError):
        store.add_asset(project["project_id"], "..\\evil.xml", b"<xml/>")


def test_validate_id_rejects_malformed(store):
    from judge_tool.webui.store import validate_id
    with pytest.raises(ValueError):
        validate_id("not-an-id")
    with pytest.raises(ValueError):
        validate_id("p-short")
    validate_id("p-12345678")  # 정상은 예외 없음


def test_asset_abspath_traversal_guard(store):
    project = store.create_project("가드")
    asset = store.add_asset(project["project_id"], "a.xml", b"<xml/>")
    aid = asset["asset_id"]
    # stored_relpath를 조작해 root 밖을 가리키게 하면 거부돼야 한다.
    proj = store.get_project(project["project_id"])
    for a in proj["assets"]:
        if a["asset_id"] == aid:
            a["stored_relpath"] = "../../../etc/passwd"
    store._save_project(proj)
    with pytest.raises(ValueError):
        store.asset_abspath(project["project_id"], aid)


def test_check_project_root_safe_rejects_inside_results(tmp_path):
    results_dir = tmp_path / "results"
    bad_root = results_dir / "judge_projects"
    with pytest.raises(ValueError):
        check_project_root_safe(str(bad_root), str(results_dir))
    with pytest.raises(ValueError):
        check_project_root_safe(str(results_dir), str(results_dir))


def test_check_project_root_safe_allows_sibling(tmp_path):
    results_dir = tmp_path / "results"
    ok_root = tmp_path / "judge_projects"
    check_project_root_safe(str(ok_root), str(results_dir))  # 예외 없어야 함


# ── T-4: set_asset_profile 검증 + sweep_stale_judging ──────────────────────

def test_set_asset_profile_valid(store):
    project = store.create_project("프로파일")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    updated = store.set_asset_profile(
        project["project_id"], asset["asset_id"], "db_mysql", "mysql_native")
    assert updated["profile"] == "db_mysql"
    assert updated["profile_source"] == "user"
    assert updated["variant"] == "mysql_native"


def test_set_asset_profile_rejects_unknown_profile(store):
    project = store.create_project("프로파일오류")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    with pytest.raises(ValueError):
        store.set_asset_profile(
            project["project_id"], asset["asset_id"], "not_a_real_profile")


def test_set_asset_profile_rejects_unknown_variant(store):
    project = store.create_project("variant오류")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    with pytest.raises(ValueError):
        store.set_asset_profile(
            project["project_id"], asset["asset_id"], "db_mysql", "not_a_variant")


def test_set_asset_profile_rejects_while_judging(store):
    # L-1: judging 충돌은 ValueError(→400)가 아니라 ConflictError(→409)로 통일
    # (delete_asset/delete_project의 judging 가드와 동일 상태코드).
    project = store.create_project("판정중")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    store.update_asset(project["project_id"], asset["asset_id"], status="judging")
    with pytest.raises(ConflictError):
        store.set_asset_profile(
            project["project_id"], asset["asset_id"], "db_mysql")


def test_delete_project_rejects_while_judging(store):
    # H-1(3): 자산 중 하나라도 judging이면 프로젝트 삭제를 막는다(→서버 409).
    project = store.create_project("프로젝트삭제판정중")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    store.update_asset(project["project_id"], asset["asset_id"], status="judging")
    with pytest.raises(ConflictError):
        store.delete_project(project["project_id"])
    # 삭제되지 않고 그대로 남아 있어야 한다.
    assert store.get_project(project["project_id"])["project_id"] == project["project_id"]


def test_delete_asset_rejects_while_judging(store):
    project = store.create_project("삭제판정중")
    asset = store.add_asset(project["project_id"], "unknown.xml", b"<xml/>")
    store.update_asset(project["project_id"], asset["asset_id"], status="judging")
    with pytest.raises(ConflictError):
        store.delete_asset(project["project_id"], asset["asset_id"])


def test_delete_asset_removes_files(store):
    project = store.create_project("삭제")
    asset = store.add_asset(project["project_id"], "a.xml", b"<xml/>")
    aid = asset["asset_id"]
    abspath = store.asset_abspath(project["project_id"], aid)
    assert os.path.isfile(abspath)
    store.delete_asset(project["project_id"], aid)
    assert not os.path.isfile(abspath)
    with pytest.raises(KeyError):
        store.get_asset(project["project_id"], aid)


def test_sweep_stale_judging(store):
    project = store.create_project("스윕")
    asset = store.add_asset(project["project_id"], "a.xml", b"<xml/>")
    store.update_asset(project["project_id"], asset["asset_id"], status="judging")
    count = store.sweep_stale_judging()
    assert count == 1
    refreshed = store.get_asset(project["project_id"], asset["asset_id"])
    assert refreshed["status"] == "failed"
    assert "재시작" in refreshed["error"]


def test_result_paths_deterministic(store):
    project = store.create_project("결과경로")
    asset = store.add_asset(project["project_id"], "a.xml", b"<xml/>")
    aid = asset["asset_id"]
    json1, xlsx1 = store.result_paths(project["project_id"], aid)
    json2, xlsx2 = store.result_paths(project["project_id"], aid)
    assert json1 == json2
    assert xlsx1 == xlsx2
    assert json1.endswith(f"result_{aid}.json")
    assert xlsx1.endswith(f"result_{aid}.xlsx")

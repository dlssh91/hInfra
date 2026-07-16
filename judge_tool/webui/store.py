"""프로젝트/자산 디스크 영속화 + 검증.

레이아웃:
    <root>/p-xxxxxxxx/project.json
    <root>/p-xxxxxxxx/assets/a-xxxxxxxx/<원본파일명>
    <root>/p-xxxxxxxx/results/result_a-xxxxxxxx.json / .xlsx

judge_tool 판정 엔진(main.run 등)은 전혀 건드리지 않는다 — 이 모듈은
웹 UI 전용 신규 파일이다. results/(대외비, repo 루트) 는 절대 읽고 쓰지
않는다(가드는 check_project_root_safe로 별도 제공, __main__.py에서 호출).
"""
import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from judge_tool.main import _CANDIDATE_EXTS
from judge_tool.profile import (
    DOMAIN_PROFILES, get_profile, guess_profile, list_profile_keys)

_TIME_FMT = "%Y-%m-%d %H:%M:%S"
_ID_RE = re.compile(r"^[ap]-[0-9a-f]{8}$")
_TARGET_ID_RE = re.compile(r"^t-[0-9a-f]{8}$")
_DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024
_FORBIDDEN_NAME_TOKENS = ("..", "/", "\\", "\x00")
_MAX_TARGET_NAME_LEN = 120


class ConflictError(RuntimeError):
    """자산이 이미 처리 중(judging)이라 요청을 수행할 수 없을 때."""


def _now() -> str:
    """main.py meta 와 동일 포맷의 현재 시각 문자열. 테스트에서 monkeypatch 가능."""
    return datetime.now().strftime(_TIME_FMT)


def _new_id(prefix: str) -> str:
    """'p-'/'a-' + uuid4 hex 8자. 테스트에서 monkeypatch 가능하도록 분리된 함수."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _is_within(child: str, parent: str) -> bool:
    """child(realpath)가 parent(realpath)와 같거나 그 하위인지 확인.

    main.py의 _is_within과 동일 로직(사설 복사, §75 설계 지시).
    """
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    if child == parent:
        return True
    return child.startswith(parent + os.sep)


def validate_id(id_str: str) -> None:
    """경로 파라미터(pid/aid) 공통 검증. 불일치 시 ValueError(→서버 400)."""
    if not isinstance(id_str, str) or not _ID_RE.fullmatch(id_str):
        raise ValueError(f"잘못된 ID 형식입니다: {id_str}")


def validate_target_id(id_str: str) -> None:
    """대상(target) ID 전용 검증(H-1 — 기존 _ID_RE/validate_id는 무수정).

    target ID는 'p-'/'a-'와 별개 네임스페이스('t-' + hex8)이므로 기존
    _ID_RE(a/p 전용)에 합치지 않고 별도 정규식·함수로 신설한다."""
    if not isinstance(id_str, str) or not _TARGET_ID_RE.fullmatch(id_str):
        raise ValueError(f"잘못된 대상 ID 형식입니다: {id_str}")


def check_project_root_safe(root: str, results_dir: str) -> None:
    """project_root가 대외비 results/ 디렉터리와 같거나 하위이면 거부.

    존재 여부와 무관하게 경로 문자열(realpath)만으로 비교한다(results/는
    보통 로컬 실데이터라 존재하지 않을 수도 있음 — 여전히 안전하게 가드).
    """
    rp = os.path.realpath(root)
    rd = os.path.realpath(results_dir)
    if rp == rd or _is_within(rp, rd):
        raise ValueError(
            f"프로젝트 저장 위치({root})가 대외비 results/ 디렉터리와 같거나 "
            "하위 경로입니다. --project-root로 다른 위치를 지정하세요.")


def _validate_filename(filename: str) -> str:
    """원본 파일명 검증. 정상이면 그대로 반환, 위반 시 ValueError."""
    if not filename:
        raise ValueError("파일명이 비어 있습니다.")
    base = os.path.basename(filename)
    if base != filename or base in ("", ".", ".."):
        raise ValueError(f"허용되지 않는 파일명입니다: {filename!r}")
    for tok in _FORBIDDEN_NAME_TOKENS:
        if tok in filename:
            raise ValueError(f"허용되지 않는 파일명입니다: {filename!r}")
    return base


def _validate_target_name(name: str) -> str:
    """대상 이름 검증(M-5). strip 후 비어있음 거부, 길이 상한, 제어문자 거부.
    정상이면 strip된 이름을 반환한다."""
    name = (name or "").strip()
    if not name:
        raise ValueError("대상 이름을 입력하세요.")
    if len(name) > _MAX_TARGET_NAME_LEN:
        raise ValueError(f"대상 이름이 너무 깁니다(최대 {_MAX_TARGET_NAME_LEN}자).")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name):
        raise ValueError("대상 이름에 제어 문자를 포함할 수 없습니다.")
    return name


class ProjectStore:
    """프로젝트/자산 디스크 영속화. 모든 쓰기는 self._lock(RLock) + 원자적 저장."""

    def __init__(self, root: str, max_upload_bytes: int = _DEFAULT_MAX_UPLOAD_BYTES):
        self.root = os.path.realpath(root)
        os.makedirs(self.root, exist_ok=True)
        self.max_upload_bytes = max_upload_bytes
        self._lock = threading.RLock()

    # ── 경로 헬퍼 ────────────────────────────────────────────────────────
    def _project_dir(self, pid: str) -> str:
        validate_id(pid)
        return os.path.join(self.root, pid)

    def _project_json_path(self, pid: str) -> str:
        return os.path.join(self._project_dir(pid), "project.json")

    def _atomic_write_json(self, path: str, data: Dict) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    def _load_project(self, pid: str) -> Dict:
        path = self._project_json_path(pid)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            raise KeyError(pid)

    def _save_project(self, project: Dict) -> None:
        project["updated_at"] = _now()
        self._atomic_write_json(
            self._project_json_path(project["project_id"]), project)

    # ── 프로젝트 CRUD ────────────────────────────────────────────────────
    def create_project(self, name: str) -> Dict:
        name = (name or "").strip()
        if not name:
            raise ValueError("프로젝트 이름을 입력하세요.")
        with self._lock:
            pid = _new_id("p")
            pdir = os.path.join(self.root, pid)
            os.makedirs(os.path.join(pdir, "assets"), exist_ok=True)
            os.makedirs(os.path.join(pdir, "results"), exist_ok=True)
            now = _now()
            project = {
                "schema_version": 1,
                "project_id": pid,
                "name": name,
                "created_at": now,
                "updated_at": now,
                "assets": [],
            }
            self._atomic_write_json(os.path.join(pdir, "project.json"), project)
            return project

    def list_projects(self) -> List[Dict]:
        with self._lock:
            out = []
            if not os.path.isdir(self.root):
                return out
            for entry in sorted(os.listdir(self.root)):
                if not _ID_RE.fullmatch(entry) or not entry.startswith("p-"):
                    continue
                pjson = os.path.join(self.root, entry, "project.json")
                if not os.path.isfile(pjson):
                    continue
                try:
                    project = self._load_project(entry)
                except (KeyError, json.JSONDecodeError, OSError):
                    continue
                counts = Counter(a.get("status") for a in project.get("assets", []))
                out.append({
                    "project_id": project["project_id"],
                    "name": project["name"],
                    "created_at": project["created_at"],
                    "updated_at": project.get("updated_at", project["created_at"]),
                    "asset_count": len(project.get("assets", [])),
                    "status_counts": dict(counts),
                })
            out.sort(key=lambda p: p["created_at"], reverse=True)
            return out

    def get_project(self, pid: str) -> Dict:
        with self._lock:
            return self._load_project(pid)

    def delete_project(self, pid: str) -> None:
        with self._lock:
            pdir = self._project_dir(pid)
            rp = os.path.realpath(pdir)
            if not _is_within(rp, self.root):
                raise ValueError("잘못된 프로젝트 경로입니다.")
            if not os.path.isdir(rp):
                raise KeyError(pid)
            project = self._load_project(pid)
            if any(a.get("status") == "judging" for a in project.get("assets", [])):
                raise ConflictError(
                    "판정이 진행 중인 자산이 있어 프로젝트를 삭제할 수 없습니다.")
            shutil.rmtree(rp)

    # ── 대상(target) CRUD ────────────────────────────────────────────────
    # 웹UI 계층 워크스페이스(점검분야→대상→파일). target은 가벼운 레코드
    # (디스크 디렉터리 없음, project.json 안에만 존재) — 설계서 §2/§3.
    def create_target(self, pid: str, domain: str, name: str) -> Dict:
        if domain not in DOMAIN_PROFILES:
            raise ValueError(f"알 수 없는 점검분야입니다: {domain}")
        name = _validate_target_name(name)
        with self._lock:
            project = self._load_project(pid)  # KeyError→404 if missing
            tid = _new_id("t")
            target = {
                "id": tid,
                "domain": domain,
                "name": name,
                "created": _now(),
            }
            project.setdefault("targets", []).append(target)
            self._save_project(project)
            return target

    def rename_target(self, pid: str, tid: str, name: str) -> Dict:
        """이름만 변경 — 참조는 id라 judging 중에도 안전(ConflictError 불요, L-3)."""
        validate_target_id(tid)
        name = _validate_target_name(name)
        with self._lock:
            project = self._load_project(pid)
            for target in project.get("targets", []):
                if target["id"] == tid:
                    target["name"] = name
                    self._save_project(project)
                    return target
            raise KeyError(tid)

    def delete_target(self, pid: str, tid: str, cascade: bool = False) -> None:
        """대상 삭제. 단일 lock+원자쓰기(H-3) — 부분상태 없이 한 번만 저장한다.

        cascade=False(기본): 참조 자산들의 target_id를 None으로 옮겨 "미분류"
        상태로 만든다(비파괴 — LLM 재판정 비용 보호).
        cascade=True: 대상 내 자산 중 judging이 하나라도 있으면 어떤 파일도
        건드리지 않고 ConflictError. 없으면 자산 파일·결과 파일까지 함께
        삭제한다(delete_project/delete_asset 패턴을 이 메서드 안에서 인라인
        수행 — 자산별로 별도 lock+저장을 반복하면 H-3 위반이므로 재사용하지
        않는다)."""
        validate_target_id(tid)
        with self._lock:
            project = self._load_project(pid)
            targets = project.get("targets", [])
            if not any(t["id"] == tid for t in targets):
                raise KeyError(tid)
            assets = project.get("assets", [])
            member_assets = [a for a in assets if a.get("target_id") == tid]

            if cascade:
                if any(a.get("status") == "judging" for a in member_assets):
                    raise ConflictError(
                        "판정이 진행 중인 자산이 있어 대상을 삭제할 수 없습니다.")
                pdir = self._project_dir(pid)
                for asset in member_assets:
                    aid = asset["asset_id"]
                    adir = os.path.realpath(os.path.join(pdir, "assets", aid))
                    if _is_within(adir, self.root) and os.path.isdir(adir):
                        shutil.rmtree(adir)
                    json_path, xlsx_path = self.result_paths(pid, aid)
                    for p in (json_path, xlsx_path):
                        rp = os.path.realpath(p)
                        if _is_within(rp, self.root) and os.path.isfile(rp):
                            os.remove(rp)
                member_ids = {a["asset_id"] for a in member_assets}
                project["assets"] = [
                    a for a in assets if a["asset_id"] not in member_ids]
            else:
                for asset in assets:
                    if asset.get("target_id") == tid:
                        asset["target_id"] = None

            project["targets"] = [t for t in targets if t["id"] != tid]
            self._save_project(project)

    def assign_asset_target(self, pid: str, aid: str,
                            target_id: Optional[str]) -> Dict:
        """자산을 대상에 배치/이동한다. target_id=None이면 미분류로 이동."""
        validate_id(aid)
        if target_id is not None:
            validate_target_id(target_id)
        with self._lock:
            project = self._load_project(pid)
            if target_id is not None and not any(
                    t["id"] == target_id for t in project.get("targets", [])):
                raise KeyError(target_id)
            for asset in project.get("assets", []):
                if asset["asset_id"] == aid:
                    asset["target_id"] = target_id
                    self._save_project(project)
                    return asset
            raise KeyError(aid)

    def list_targets(self, pid: str) -> List[Dict]:
        """created→name 정렬로 대상 목록 반환."""
        with self._lock:
            project = self._load_project(pid)
            targets = list(project.get("targets", []))
            targets.sort(key=lambda t: (t.get("created", ""), t.get("name", "")))
            return targets

    def target_summary(self, pid: str, tid: str) -> Dict:
        """대상 롤업 요약 — 읽기시점 파생(M-1). 결과 JSON을 재파싱하지 않고
        asset["summary"]["verdict_counts"](jobs.py _summarize 기록분)만
        합산한다. 혼합상태(일부만 판정완료 등)를 위해 judged/failed/judging
        카운트도 함께 반환한다."""
        validate_target_id(tid)
        with self._lock:
            project = self._load_project(pid)
            if not any(t["id"] == tid for t in project.get("targets", [])):
                raise KeyError(tid)
            member_assets = [
                a for a in project.get("assets", []) if a.get("target_id") == tid]
            verdict_counts = {"양호": 0, "취약": 0, "판단보류": 0}
            judged_assets = 0
            failed = 0
            judging = 0
            for asset in member_assets:
                status = asset.get("status")
                if status == "judged":
                    judged_assets += 1
                    vc = (asset.get("summary") or {}).get("verdict_counts") or {}
                    for key in verdict_counts:
                        verdict_counts[key] += vc.get(key, 0)
                elif status == "failed":
                    failed += 1
                elif status == "judging":
                    judging += 1
            return {
                "verdict_counts": verdict_counts,
                "judged_assets": judged_assets,
                "total_assets": len(member_assets),
                "failed": failed,
                "judging": judging,
            }

    # ── 자산 CRUD ────────────────────────────────────────────────────────
    def add_asset(self, pid: str, filename: str, data: bytes,
                  target_id: Optional[str] = None) -> Dict:
        base = _validate_filename(filename)
        ext = os.path.splitext(base)[1].lower()
        if ext not in _CANDIDATE_EXTS:
            raise ValueError(
                f"허용되지 않는 확장자입니다: {ext!r} "
                f"(허용: {_CANDIDATE_EXTS})")
        if not data:
            raise ValueError("빈 파일은 업로드할 수 없습니다.")
        if len(data) > self.max_upload_bytes:
            raise ValueError(
                f"파일 크기가 상한({self.max_upload_bytes} bytes)을 초과했습니다.")

        with self._lock:
            project = self._load_project(pid)  # KeyError→404 if missing
            target = None
            if target_id is not None:
                validate_target_id(target_id)
                target = next(
                    (t for t in project.get("targets", []) if t["id"] == target_id),
                    None)
                if target is None:
                    raise ValueError(f"존재하지 않는 대상입니다: {target_id}")
            aid = _new_id("a")
            pdir = self._project_dir(pid)
            adir = os.path.join(pdir, "assets", aid)
            os.makedirs(adir, exist_ok=True)
            abspath = os.path.join(adir, base)
            with open(abspath, "wb") as fh:
                fh.write(data)

            guessed, candidates = guess_profile(base)
            # 대상이 지정됐으면 프로파일은 대상 domain 집합 우선(M-3): guess_profile
            # 결과가 그 집합에 속하면 유지(guessed), 아니면 domain 기본 프로파일로
            # 대체(profile_source="target"). 대상 미지정이면 기존 동작 그대로.
            profile = guessed
            profile_source = "guessed" if guessed else None
            if target is not None:
                domain_profiles = DOMAIN_PROFILES.get(target["domain"], ())
                if not (guessed and guessed in domain_profiles):
                    profile = domain_profiles[0] if domain_profiles else None
                    profile_source = "target" if profile else None
            asset = {
                "asset_id": aid,
                "original_filename": base,
                "stored_relpath": os.path.relpath(abspath, pdir),
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "uploaded_at": _now(),
                "profile": profile,
                "profile_source": profile_source,
                "profile_candidates": list(candidates),
                "target_id": target_id,
                "variant": None,
                "status": "pending",
                "error": None,
                "result_json_relpath": None,
                "result_xlsx_relpath": None,
                "summary": None,
                "judged_at": None,
            }
            project["assets"].append(asset)
            self._save_project(project)
            return asset

    def get_asset(self, pid: str, aid: str) -> Dict:
        validate_id(aid)
        project = self.get_project(pid)
        for asset in project.get("assets", []):
            if asset["asset_id"] == aid:
                return asset
        raise KeyError(aid)

    def update_asset(self, pid: str, aid: str, **fields) -> Dict:
        validate_id(aid)
        with self._lock:
            project = self._load_project(pid)
            for asset in project.get("assets", []):
                if asset["asset_id"] == aid:
                    asset.update(fields)
                    self._save_project(project)
                    return asset
            raise KeyError(aid)

    def set_asset_profile(self, pid: str, aid: str,
                          profile: str, variant: Optional[str] = None) -> Dict:
        if profile not in list_profile_keys():
            raise ValueError(f"알 수 없는 프로파일입니다: {profile}")
        if variant is not None:
            prof = get_profile(profile)
            if variant not in prof.variants:
                raise ValueError(
                    f"알 수 없는 variant입니다: {variant} "
                    f"(프로파일 '{profile}' 사용 가능: {list(prof.variants)})")
        with self._lock:
            asset = self.get_asset(pid, aid)
            if asset["status"] == "judging":
                raise ConflictError("판정이 진행 중인 자산은 프로파일을 변경할 수 없습니다.")
            return self.update_asset(
                pid, aid, profile=profile, profile_source="user", variant=variant)

    def asset_abspath(self, pid: str, aid: str) -> str:
        asset = self.get_asset(pid, aid)
        pdir = self._project_dir(pid)
        abspath = os.path.join(pdir, asset["stored_relpath"])
        rp = os.path.realpath(abspath)
        if not _is_within(rp, self.root):
            raise ValueError("잘못된 자산 경로입니다.")
        return rp

    def result_paths(self, pid: str, aid: str) -> Tuple[str, str]:
        validate_id(aid)
        pdir = self._project_dir(pid)
        results_dir = os.path.join(pdir, "results")
        os.makedirs(results_dir, exist_ok=True)
        json_path = os.path.join(results_dir, f"result_{aid}.json")
        xlsx_path = os.path.join(results_dir, f"result_{aid}.xlsx")
        return json_path, xlsx_path

    def delete_asset(self, pid: str, aid: str) -> None:
        with self._lock:
            asset = self.get_asset(pid, aid)
            if asset["status"] == "judging":
                raise ConflictError("판정이 진행 중인 자산은 삭제할 수 없습니다.")
            pdir = self._project_dir(pid)
            adir = os.path.realpath(os.path.join(pdir, "assets", aid))
            if _is_within(adir, self.root) and os.path.isdir(adir):
                shutil.rmtree(adir)
            json_path, xlsx_path = self.result_paths(pid, aid)
            for p in (json_path, xlsx_path):
                rp = os.path.realpath(p)
                if _is_within(rp, self.root) and os.path.isfile(rp):
                    os.remove(rp)
            project = self._load_project(pid)
            project["assets"] = [
                a for a in project["assets"] if a["asset_id"] != aid]
            self._save_project(project)

    def sweep_stale_judging(self) -> int:
        """서버 재시작 직후 'judging'으로 멈춰있는 자산을 failed로 되돌린다."""
        count = 0
        with self._lock:
            if not os.path.isdir(self.root):
                return 0
            for entry in os.listdir(self.root):
                if not _ID_RE.fullmatch(entry) or not entry.startswith("p-"):
                    continue
                pjson = os.path.join(self.root, entry, "project.json")
                if not os.path.isfile(pjson):
                    continue
                try:
                    project = self._load_project(entry)
                except (KeyError, json.JSONDecodeError, OSError):
                    continue
                changed = False
                for asset in project.get("assets", []):
                    if asset.get("status") == "judging":
                        asset["status"] = "failed"
                        asset["error"] = (
                            "서버 재시작으로 판정이 중단되었습니다. 다시 실행하세요.")
                        changed = True
                        count += 1
                if changed:
                    self._save_project(project)
        return count

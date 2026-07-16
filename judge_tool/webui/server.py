"""ThreadingHTTPServer + 라우팅. stdlib만 사용(pip 설치 금지, Flask 등 금지).

바인딩은 항상 127.0.0.1 리터럴(대외비 보호, §6). 판정 엔진은 재사용만
한다 — profile.list_profile_keys/get_profile, judge.OllamaClient만 호출.
"""
import hmac
import http.server
import json
import logging
import os
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from judge_tool.errors import ReportError
from judge_tool.judge import OllamaClient
from judge_tool.profile import get_profile, list_profile_keys
from judge_tool.webui.store import ConflictError

log = logging.getLogger(__name__)

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@dataclass
class Config:
    ollama_url: str = "http://localhost:11434"
    model: str = "qwen3-coder:30b"
    criteria: Optional[str] = None
    token: Optional[str] = None
    max_upload_mb: int = 50


class HttpError(Exception):
    """명시적 HTTP 상태코드를 지정하고 싶은 핸들러 오류(409/411/413/401 등).

    close=True는 "요청 본문을 (전부) 읽지 않고 응답한다"는 뜻 — 이 경우
    keep-alive 커넥션에 아직 클라이언트가 보낸 바이트가 남아있어 다음 요청과
    뒤섞일 수 있으므로, 응답 시 Connection: close로 커넥션을 닫아야 한다(M-2).
    """

    def __init__(self, status: int, message: str, close: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.close = close


# 경로 파라미터는 느슨하게 캡처하고, 형식 검증은 store.validate_id(ValueError→400)에
# 위임한다(설계서 §3: "ID 검증 정규식... 불일치→400" — 라우팅 자체는 세그먼트만 분리).
_SEG = r"[^/]+"
_ROUTES = [
    ("GET", r"^/$", "index"),
    ("GET", r"^/api/health$", "health"),
    ("GET", r"^/api/profiles$", "profiles"),
    ("GET", r"^/api/projects$", "list_projects"),
    ("POST", r"^/api/projects$", "create_project"),
    ("GET", rf"^/api/projects/(?P<pid>{_SEG})$", "get_project"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/delete$", "delete_project"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/assets$", "upload_asset"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/profile$", "set_profile"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/judge$", "judge_asset"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/judge_all$", "judge_all"),
    ("GET", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})$", "get_asset"),
    ("GET", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/result$", "get_result"),
    ("GET", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/result\.xlsx$", "get_result_xlsx"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/delete$", "delete_asset"),
    # 웹UI 계층 워크스페이스(점검분야→대상→파일) — 신규(설계서 §4).
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/targets$", "create_target"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/targets/(?P<tid>{_SEG})/rename$", "rename_target"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/targets/(?P<tid>{_SEG})/delete$", "delete_target"),
    ("GET", rf"^/api/projects/(?P<pid>{_SEG})/targets/(?P<tid>{_SEG})/summary$", "target_summary"),
    ("POST", rf"^/api/projects/(?P<pid>{_SEG})/assets/(?P<aid>{_SEG})/target$", "assign_asset_target"),
]

import re as _re  # noqa: E402 - 라우트 테이블 컴파일 직전 배치(가독성)
_COMPILED_ROUTES = [(m, _re.compile(p), name) for m, p, name in _ROUTES]


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "judge-tool-webui/1"
    protocol_version = "HTTP/1.1"

    # ── 로깅 ────────────────────────────────────────────────────────────
    def log_message(self, fmt, *args):  # noqa: A003
        log.info("%s - %s", self.address_string(), fmt % args)

    # ── 서버 주입 접근자 ─────────────────────────────────────────────────
    @property
    def store(self):
        return self.server.store

    @property
    def jobs(self):
        return self.server.jobs

    @property
    def config(self) -> Config:
        return self.server.config

    # ── 공통 응답 헬퍼 ───────────────────────────────────────────────────
    def _send_json(self, status: int, payload: dict, close: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str, close: bool = False) -> None:
        self._send_json(status, {"ok": False, "error": message}, close=close)

    def _read_body_bytes(self, max_len: Optional[int] = None) -> bytes:
        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None:
            raise HttpError(411, "Content-Length 헤더가 필요합니다.", close=True)
        try:
            length = int(length_hdr)
        except ValueError:
            raise HttpError(411, "Content-Length 헤더가 올바르지 않습니다.", close=True)
        if length < 0:
            raise HttpError(411, "Content-Length 헤더가 올바르지 않습니다.", close=True)
        if max_len is not None and length > max_len:
            # 본문을 읽지 않고 거절 — 클라이언트가 이미 보낸 바이트가 소켓에
            # 남아있으므로 커넥션을 재사용하면 다음 요청과 뒤섞인다(M-2).
            raise HttpError(413, "업로드 용량 상한을 초과했습니다.", close=True)
        self._body_read = True  # 본문 소비 표시 — _dispatch가 중복 drain 안 하도록(M-3)
        return self.rfile.read(length)

    def _drain_body(self) -> None:
        """본문을 사용하지 않은 POST에서 선언된 Content-Length 바이트를 읽어
        버린다 — keep-alive 재사용 시 잔여 바이트가 다음 요청을 오염시키는
        것(M-3) 방지. 헤더 없으면 무동작. 비정상적으로 큰 본문은 읽지 않고
        커넥션을 닫는다(무제한 read 방지)."""
        length_hdr = self.headers.get("Content-Length")
        if not length_hdr:
            return
        try:
            length = int(length_hdr)
        except ValueError:
            self.close_connection = True
            return
        if length <= 0:
            return
        if length > 65536:  # 본문 불필요 엔드포인트에 큰 본문 = 이상 → 그냥 닫음
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except Exception:  # noqa: BLE001 - 드레인 실패 시 커넥션만 닫으면 안전
            self.close_connection = True

    def _read_json_body(self) -> dict:
        raw = self._read_body_bytes()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"잘못된 JSON 본문입니다: {e}")

    def _check_auth(self, path: str) -> bool:
        """X-Auth-Token 헤더 또는 ?token= 쿼리 중 하나라도 일치하면 통과(M-1).

        bytes로 인코딩 후 비교한다 — hmac.compare_digest는 비ASCII를 포함한
        str 인자를 섞어 비교할 때 TypeError를 던질 수 있으므로(L-2), 항상
        UTF-8 bytes로 맞춰 비교해 예외 없이 동작하게 한다.
        """
        token = self.config.token
        if not token or not path.startswith("/api/"):
            return True
        token_bytes = token.encode("utf-8")
        header_token = self.headers.get("X-Auth-Token", "")
        if hmac.compare_digest(header_token.encode("utf-8"), token_bytes):
            return True
        query = urllib.parse.urlparse(self.path).query
        query_token = urllib.parse.parse_qs(query).get("token", [""])[0]
        return hmac.compare_digest(query_token.encode("utf-8"), token_bytes)

    # ── 라우팅/디스패치 ──────────────────────────────────────────────────
    def _dispatch(self, method: str) -> None:
        self._body_read = False
        path = urllib.parse.urlparse(self.path).path
        try:
            if not self._check_auth(path):
                self._send_error_json(401, "인증 토큰이 올바르지 않습니다.")
                return
            for m, pattern, name in _COMPILED_ROUTES:
                if m != method:
                    continue
                match = pattern.fullmatch(path)
                if not match:
                    continue
                handler = getattr(self, f"_h_{name}")
                try:
                    handler(**match.groupdict())
                except HttpError as e:
                    self._send_error_json(e.status, e.message, close=e.close)
                except ConflictError as e:
                    self._send_error_json(409, str(e))
                except KeyError:
                    self._send_error_json(404, "찾을 수 없습니다.")
                except (ReportError, ValueError) as e:
                    self._send_error_json(400, str(e))
                except Exception as e:  # noqa: BLE001 - 증거/스택 유출 방지, 타입명만 노출
                    log.warning("웹UI 서버 오류 path=%s type=%s", path, type(e).__name__)
                    self._send_error_json(500, f"서버 내부 오류({type(e).__name__})")
                return
            self._send_error_json(404, "찾을 수 없는 경로입니다.")
        finally:
            # 본문을 사용하지 않은 POST(삭제/판정 등 프론트가 '{}'를 보내는
            # 경로)의 잔여 Content-Length가 keep-alive 소켓에 남아 다음 요청을
            # 오염시키는 것(M-3) 방지. 커넥션을 닫는 경우엔 불필요.
            if method == "POST" and not self.close_connection and not self._body_read:
                self._drain_body()

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    # ── 핸들러 ───────────────────────────────────────────────────────────
    def _h_index(self):
        path = os.path.join(_STATIC_DIR, "index.html")
        with open(path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _h_health(self):
        client = OllamaClient(url=self.config.ollama_url, model=self.config.model)
        ok, err = True, None
        try:
            client.health_check()
        except Exception as e:  # noqa: BLE001 - 원인 다양(미가동/모델없음/네트워크)
            ok, err = False, str(e)
        self._send_json(200, {
            "ok": True,
            "ollama": {"ok": ok, "error": err},
            "model": self.config.model,
            "ollama_url": self.config.ollama_url,
            "project_root": self.store.root,
        })

    def _h_profiles(self):
        profiles = [
            {"key": key, "variants": list(get_profile(key).variants.keys())}
            for key in list_profile_keys()
        ]
        self._send_json(200, {"ok": True, "profiles": profiles})

    def _h_list_projects(self):
        self._send_json(200, {"ok": True, "projects": self.store.list_projects()})

    def _h_create_project(self):
        body = self._read_json_body()
        project = self.store.create_project(body.get("name", ""))
        self._send_json(201, {"ok": True, "project": project})

    def _h_get_project(self, pid):
        project = self.store.get_project(pid)
        self._send_json(200, {"ok": True, "project": project})

    def _h_delete_project(self, pid):
        self.store.delete_project(pid)
        self._send_json(200, {"ok": True})

    def _h_upload_asset(self, pid):
        max_bytes = self.config.max_upload_mb * 1024 * 1024
        filename_hdr = self.headers.get("X-Filename")
        if not filename_hdr:
            # 본문을 아직 읽지 않은 상태로 400 응답 — 커넥션 재사용 시 다음
            # 요청과 뒤섞이는 것을 막기 위해 close=True(M-2).
            raise HttpError(400, "X-Filename 헤더가 필요합니다.", close=True)
        filename = urllib.parse.unquote(filename_hdr)
        # X-Target-Id(M-2, 선택) — 지정 시 store.add_asset이 동일 lock 내
        # 대상 존재검증을 하고, 없는 tid면 ValueError→400으로 자동 변환된다.
        target_hdr = self.headers.get("X-Target-Id")
        target_id = urllib.parse.unquote(target_hdr) if target_hdr else None
        data = self._read_body_bytes(max_len=max_bytes)
        asset = self.store.add_asset(pid, filename, data, target_id=target_id)
        self._send_json(201, {"ok": True, "asset": asset})

    def _h_set_profile(self, pid, aid):
        body = self._read_json_body()
        profile = body.get("profile")
        variant = body.get("variant")
        if not profile:
            raise ValueError("profile 값이 필요합니다.")
        asset = self.store.set_asset_profile(pid, aid, profile, variant)
        self._send_json(200, {"ok": True, "asset": asset})

    def _h_judge_asset(self, pid, aid):
        asset = self.store.get_asset(pid, aid)
        if not asset.get("profile"):
            raise ValueError("프로파일이 설정되지 않았습니다. 먼저 프로파일을 지정하세요.")
        if asset.get("status") == "judging":
            raise HttpError(409, "이미 판정이 진행 중입니다.")
        self.store.update_asset(pid, aid, status="judging", error=None)
        try:
            self.jobs.enqueue(pid, aid)
        except RuntimeError as e:
            raise HttpError(409, str(e))
        asset = self.store.get_asset(pid, aid)
        self._send_json(202, {"ok": True, "asset": asset})

    def _h_judge_all(self, pid):
        # 선택적 target/domain 필터(L-4) — 대상 단위(target_id)·분야 단위
        # (domain, 대상의 domain으로 조인) 일괄판정을 지원한다. 둘 다 없으면
        # 기존과 동일하게 프로젝트 전체 자산이 대상이다(하위호환).
        body = self._read_json_body()
        target_id = body.get("target_id")
        domain = body.get("domain")
        project = self.store.get_project(pid)
        domain_target_ids = None
        if domain is not None:
            domain_target_ids = {
                t["id"] for t in project.get("targets", []) if t.get("domain") == domain}
        enqueued, skipped = [], []
        for asset in project.get("assets", []):
            aid = asset["asset_id"]
            if target_id is not None and asset.get("target_id") != target_id:
                continue
            if domain_target_ids is not None and asset.get("target_id") not in domain_target_ids:
                continue
            if asset.get("status") not in ("pending", "failed"):
                skipped.append({"asset_id": aid,
                                "reason": f"상태가 '{asset.get('status')}'입니다."})
                continue
            if not asset.get("profile"):
                skipped.append({"asset_id": aid, "reason": "프로파일 미지정"})
                continue
            try:
                self.store.update_asset(pid, aid, status="judging", error=None)
                self.jobs.enqueue(pid, aid)
                enqueued.append(aid)
            except RuntimeError:
                skipped.append({"asset_id": aid, "reason": "이미 판정 진행 중"})
        self._send_json(200, {"ok": True, "enqueued": enqueued, "skipped": skipped})

    def _h_get_asset(self, pid, aid):
        asset = self.store.get_asset(pid, aid)
        self._send_json(200, {"ok": True, "asset": asset})

    def _h_get_result(self, pid, aid):
        asset = self.store.get_asset(pid, aid)
        if asset.get("status") != "judged":
            raise HttpError(409, "아직 판정이 완료되지 않았습니다.")
        json_path, _ = self.store.result_paths(pid, aid)
        with open(json_path, "r", encoding="utf-8") as fh:
            result = json.load(fh)
        self._send_json(200, {"ok": True, "result": result})

    def _h_get_result_xlsx(self, pid, aid):
        asset = self.store.get_asset(pid, aid)
        if asset.get("status") != "judged":
            raise HttpError(409, "아직 판정이 완료되지 않았습니다.")
        _, xlsx_path = self.store.result_paths(pid, aid)
        with open(xlsx_path, "rb") as fh:
            body = fh.read()
        base = asset.get("original_filename", "result")
        filename = f"result_{os.path.splitext(base)[0]}.xlsx"
        quoted = urllib.parse.quote(filename)
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header(
            "Content-Disposition",
            f"attachment; filename=\"result.xlsx\"; filename*=UTF-8''{quoted}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _h_delete_asset(self, pid, aid):
        asset = self.store.get_asset(pid, aid)
        if asset.get("status") == "judging":
            raise HttpError(409, "판정이 진행 중인 자산은 삭제할 수 없습니다.")
        self.store.delete_asset(pid, aid)
        self._send_json(200, {"ok": True})

    # ── 대상(target) 라우트 — 웹UI 계층 워크스페이스 신규(설계서 §4) ───────
    def _h_create_target(self, pid):
        body = self._read_json_body()
        target = self.store.create_target(pid, body.get("domain", ""), body.get("name", ""))
        self._send_json(201, {"ok": True, "target": target})

    def _h_rename_target(self, pid, tid):
        body = self._read_json_body()
        target = self.store.rename_target(pid, tid, body.get("name", ""))
        self._send_json(200, {"ok": True, "target": target})

    def _h_delete_target(self, pid, tid):
        body = self._read_json_body()
        cascade = bool(body.get("cascade", False))
        self.store.delete_target(pid, tid, cascade=cascade)
        self._send_json(200, {"ok": True})

    def _h_target_summary(self, pid, tid):
        summary = self.store.target_summary(pid, tid)
        self._send_json(200, {"ok": True, "summary": summary})

    def _h_assign_asset_target(self, pid, aid):
        body = self._read_json_body()
        asset = self.store.assign_asset_target(pid, aid, body.get("target_id"))
        self._send_json(200, {"ok": True, "asset": asset})


class ThreadingHTTPServerWithDeps(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_cls, store, jobs, config: Config):
        self.store = store
        self.jobs = jobs
        self.config = config
        super().__init__(server_address, handler_cls)


def make_server(store, jobs, config: Config, port: int = 0,
                host: str = "127.0.0.1") -> ThreadingHTTPServerWithDeps:
    """테스트/운영 공용 팩토리. host는 항상 127.0.0.1 리터럴이어야 한다(§6)."""
    if host != "127.0.0.1":
        raise SystemExit("대외비 보호를 위해 127.0.0.1만 허용됩니다.")
    return ThreadingHTTPServerWithDeps((host, port), Handler, store, jobs, config)

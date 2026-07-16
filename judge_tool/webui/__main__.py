"""`python3 -m judge_tool.webui` 진입점 — 로컬 웹 UI 서버.

판정 엔진은 전혀 수정하지 않는다. main.py._PKG_ROOT/_discover_criteria_path,
profile.guess_profile/list_profile_keys, judge.OllamaClient를 호출만 한다.
"""
import argparse
import logging
import os
import sys

from judge_tool.main import _PKG_ROOT
from judge_tool.webui.jobs import JobManager
from judge_tool.webui.server import Config, make_server
from judge_tool.webui.store import ProjectStore, check_project_root_safe

log = logging.getLogger("judge_tool.webui")


def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python3 -m judge_tool.webui",
        description="judge_tool 로컬 웹 UI — 프로젝트/자산 워크스페이스 (대외비: 127.0.0.1 전용)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="바인딩 호스트. 대외비 보호를 위해 127.0.0.1만 허용됩니다.")
    ap.add_argument("--port", type=int, default=8765, help="바인딩 포트(기본 8765)")
    ap.add_argument("--project-root", default=None,
                    help="프로젝트 저장 위치(기본: 저장소 루트/judge_projects)")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--model", default="qwen3-coder:30b")
    ap.add_argument("--criteria", default=None,
                    help="평가기준 xlsx 경로(미지정 시 판정 시점에 ref/ 자동탐색)")
    ap.add_argument("--token", default=None,
                    help="선택: /api/* 요청에 X-Auth-Token 헤더 검증을 요구합니다.")
    ap.add_argument("--max-upload-mb", type=int, default=50,
                    help="자산 업로드 용량 상한(MB, 기본 50)")
    return ap.parse_args(argv)


def main(argv=None) -> None:
    from judge_tool.main import _configure_windows_console
    _configure_windows_console()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    args = _parse_args(argv)

    if args.host != "127.0.0.1":
        raise SystemExit("대외비 보호를 위해 127.0.0.1만 허용됩니다.")

    project_root = args.project_root or os.path.join(_PKG_ROOT, "judge_projects")
    project_root = os.path.abspath(project_root)
    results_dir = os.path.join(_PKG_ROOT, "results")
    try:
        check_project_root_safe(project_root, results_dir)
    except ValueError as e:
        raise SystemExit(str(e))

    os.makedirs(project_root, exist_ok=True)
    store = ProjectStore(project_root, max_upload_bytes=args.max_upload_mb * 1024 * 1024)
    swept = store.sweep_stale_judging()

    config = Config(
        ollama_url=args.ollama_url, model=args.model, criteria=args.criteria,
        token=args.token, max_upload_mb=args.max_upload_mb)
    jobs = JobManager(store, config)
    jobs.start()

    httpd = make_server(store, jobs, config, port=args.port, host=args.host)
    bound_port = httpd.server_address[1]

    print("=" * 64)
    print("judge_tool 로컬 웹 UI")
    print(f"접속 주소     : http://127.0.0.1:{bound_port}")
    print(f"저장 위치     : {project_root}")
    print("주의(대외비)   : 이 서버는 127.0.0.1(로컬)에서만 접속됩니다. 외부 노출 금지.")
    if args.token:
        print("인증 토큰     : 설정됨 (?token=... 쿼리 또는 X-Auth-Token 헤더 필요)")
    if swept:
        print(f"복구 안내     : 이전 실행 중 중단된 판정 {swept}건을 '실패'로 표시했습니다.")
    print("종료하려면 Ctrl+C 를 누르세요.")
    print("=" * 64)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

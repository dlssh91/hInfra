#!/usr/bin/env bash
# judge_tool 스마트 런처.
#
# 사용법:
#   ./judge.sh                                    # 인자 없이 실행 → 대화형 모드
#   ./judge.sh <결과파일>                          # 프로파일/평가기준 자동추정 후 판정
#   ./judge.sh --report <파일|폴더> [옵션...]      # 기존 옵션 그대로 사용 가능
#   ./judge.sh --web [--port 8765] [옵션...]       # 로컬 웹 UI(127.0.0.1 전용) 기동
#   ./judge.sh --check-model [옵션...]             # 실행 환경 모델 적합성 체커(추천만, 자동전환 안 함)
#
# 항상 이 스크립트가 위치한 디렉터리(작업 루트: judge_tool/, ref/, tests/가
# 있는 곳)로 이동한 뒤 실행하므로, 어느 위치에서 호출해도 동일하게 동작한다.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --web → 로컬 웹 UI(프로젝트/자산 워크스페이스) 기동. 127.0.0.1 전용.
if [[ "${1:-}" == "--web" ]]; then
  shift
  exec python3 -m judge_tool.webui "$@"
fi

# --check-model → 실행 환경 모델 적합성 체커(RAM/VRAM/설치모델 확인, 추천만).
if [[ "${1:-}" == "--check-model" ]]; then
  shift
  exec python3 -m judge_tool.envcheck "$@"
fi

# 인자 없음 → 대화형 모드, "<파일>" → 위치인자로 --report 대체,
# "--report ... --profile ..." 등 기존 옵션 → 그대로 위임(하위호환).
exec python3 -m judge_tool "$@"

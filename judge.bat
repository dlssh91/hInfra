@echo off
rem judge_tool 스마트 런처 (Windows) - judge.sh와 동일 동작.
rem
rem 사용법:
rem   judge.bat                                   인자 없이 실행 - 대화형 모드
rem   judge.bat 결과파일.xml                       프로파일/평가기준 자동추정 후 판정
rem   judge.bat --report 파일또는폴더 [옵션...]     기존 옵션 그대로 사용 가능
rem   judge.bat --web [--port 8765] [옵션...]      로컬 웹 UI(127.0.0.1 전용) 기동
rem   judge.bat --check-model [옵션...]            실행 환경 모델 적합성 체커(추천만, 자동전환 안 함)
rem
rem 주의: rem 줄에도 리다이렉션 문자가 파싱되므로 꺾쇠괄호를 쓰지 않는다.
rem 항상 이 스크립트가 위치한 디렉터리(작업 루트)로 이동한 뒤 실행하므로,
rem 어느 위치에서 호출해도 동일하게 동작한다.
setlocal
cd /d "%~dp0"

rem 콘솔/파이프 인코딩을 UTF-8로 고정(cp949 콘솔에서도 출력 깨짐/크래시 방지).
set PYTHONUTF8=1

rem 파이썬 탐지: py 런처(-3) 우선, 없으면 python.
set "PY=python"
where py >nul 2>nul && set "PY=py -3"

if /i "%~1"=="--web" goto :web
if /i "%~1"=="--check-model" goto :checkmodel

%PY% -m judge_tool %*
exit /b %errorlevel%

:web
rem --web 뒤 옵션을 그대로 전달. cmd의 shift는 %*에 반영되지 않으므로
rem %2~%9 직접 전달(옵션 8개 초과는 비현실적). delayed expansion을 쓰지
rem 않아 경로에 느낌표가 있어도 안전하다.
%PY% -m judge_tool.webui %2 %3 %4 %5 %6 %7 %8 %9
exit /b %errorlevel%

:checkmodel
rem --check-model → 실행 환경 모델 적합성 체커(RAM/VRAM/설치모델 확인, 추천만).
%PY% -m judge_tool.envcheck %2 %3 %4 %5 %6 %7 %8 %9
exit /b %errorlevel%

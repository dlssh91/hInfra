@echo off
rem judge_tool 스마트 런처 (Windows) — judge.sh와 동일 동작.
rem
rem 사용법:
rem   judge.bat                                    인자 없이 실행 - 대화형 모드
rem   judge.bat <결과파일>                          프로파일/평가기준 자동추정 후 판정
rem   judge.bat --report <파일^|폴더> [옵션...]      기존 옵션 그대로 사용 가능
rem   judge.bat --web [--port 8765] [옵션...]       로컬 웹 UI(127.0.0.1 전용) 기동
rem
rem 항상 이 스크립트가 위치한 디렉터리(작업 루트)로 이동한 뒤 실행하므로,
rem 어느 위치에서 호출해도 동일하게 동작한다.
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem 콘솔/파이프 인코딩을 UTF-8로 고정(cp949 콘솔에서도 출력 깨짐/크래시 방지).
set PYTHONUTF8=1

rem 파이썬 탐지: py 런처(-3) 우선, 없으면 python.
set "PY=python"
where py >nul 2>nul && set "PY=py -3"

if /i not "%~1"=="--web" goto :cli

rem --web - 로컬 웹 UI 기동 (첫 인자 --web 제거 후 나머지 인자 전달)
shift
set "ARGS="
:collect
if "%~1"=="" goto :web
set ARGS=!ARGS! %1
shift
goto :collect

:web
%PY% -m judge_tool.webui !ARGS!
exit /b %errorlevel%

:cli
%PY% -m judge_tool %*
exit /b %errorlevel%

@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem ---------------------------------------------------------------
rem  测试-某动漫 本地播放站  启动脚本
rem  ★ 本文件必须保持 CRLF 换行（UTF-8 无 BOM）。实测 LF 换行会让 cmd
rem    解析错位：把 rem/echo 行的开头吃掉，并报「不是内部或外部命令」。
rem ---------------------------------------------------------------

if not exist ".token" (
  echo [WARN] .token not found. Generating a new random token...
  python -c "import secrets;open('.token','w').write(secrets.token_urlsafe(24))"
)

set /p MYUKO_TOKEN=<.token
if "%MYUKO_POOL%"=="" set MYUKO_POOL=8

echo.
echo   Token : %MYUKO_TOKEN%
echo   URL   : http://127.0.0.1:8000/?k=%MYUKO_TOKEN%
echo.
echo   (Ctrl+C to stop, or run stop.bat in another window)
echo.

python webapp_server.py
if errorlevel 1 (
  echo.
  echo [ERROR] Failed to start. Check:
  echo   1^) Python 3.10+ installed and on PATH
  echo   2^) pycryptodome installed:  pip install pycryptodome
  echo.
  pause
)

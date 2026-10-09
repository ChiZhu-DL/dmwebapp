@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem ---------------------------------------------------------------
rem  测试-某动漫 本地播放站  停止脚本
rem    · 结束占用 8000 端口的进程（连同它的 ffmpeg 子进程）
rem    · 顺手清掉转码缓存 %TEMP%\myuko_tc
rem  ★ 本文件必须保持 CRLF 换行（UTF-8 无 BOM），理由同 start.bat。
rem ---------------------------------------------------------------

set PORT=8000
if not "%~1"=="" set PORT=%~1

echo Stopping service on port %PORT% ...
set FOUND=0

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
  rem /T 连子进程一起杀：否则 ffmpeg 会变孤儿，服务没了还继续往缓存目录写
  taskkill /F /T /PID %%a >nul 2>&1
  if !errorlevel! equ 0 (
    echo   killed PID %%a  [+ children]
    set FOUND=1
  )
)

if "!FOUND!"=="0" (
  echo   nothing listening on port %PORT%.
) else (
  echo Done.
)

if exist "%TEMP%\myuko_tc" (
  echo Cleaning transcode cache ...
  rem taskkill 返回时 ffmpeg 可能还没放开文件句柄，所以要重试几次（成了就不再等）
  for /l %%i in (1,1,6) do (
    if exist "%TEMP%\myuko_tc" (
      rd /s /q "%TEMP%\myuko_tc" 2>nul
      ping -n 2 127.0.0.1 >nul
    )
  )
  if exist "%TEMP%\myuko_tc" (
    echo   partial only - something still holds a file in it.
  ) else (
    echo   cache removed.
  )
)

endlocal

@echo off
rem Windows entry point. Double-click this file, or run "run" from a terminal.
rem
rem It exists because a freshly cloned .ps1 is blocked on a default Windows
rem install with "running scripts is disabled on this system". This wrapper
rem bypasses that for this one script only, without changing any machine
rem setting.
rem
rem   run            full three-configuration experiment
rem   run demo       narrated prompt-injection demo
rem   run test       self-test
rem   run up         start the stack and leave it running
rem   run down       stop everything

setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "EXITCODE=%ERRORLEVEL%"

rem Keep the window open when launched by double-click, not when run from a shell.
echo %cmdcmdline% | find /i "%~nx0" >nul
if not errorlevel 1 (
    echo.
    pause
)
exit /b %EXITCODE%

@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch-prism-demo.ps1" %*
exit /b %ERRORLEVEL%

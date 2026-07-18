@echo off
setlocal
title HalberdStrike
cd /d "%~dp0"

py -3.14 -m src.main web --port 5000

endlocal

@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "PYTHON=%~dp0.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    echo This is a development launcher and requires .venv\Scripts\python.exe.
    echo For a clean machine, install and run the VStackLens setup package instead.
    pause
    exit /b 1
)

echo Starting VStackLens...
"%PYTHON%" -m vstacklens.cli desktop
if errorlevel 1 (
    echo.
    echo VStackLens failed to start. Keep this window open and check the error above.
    echo Recreate the development environment, then run this launcher again.
    pause
    exit /b 1
)

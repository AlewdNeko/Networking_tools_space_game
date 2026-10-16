@echo off
setlocal
title THE GATE - launcher
rem everything except this launcher lives one level down in app\, to
rem keep this top-level folder looking simple
cd /d "%~dp0app"

echo ============================================
echo   THE GATE - Live Network Visibility
echo ============================================
echo.

rem --- request Administrator elevation (needed for exact per-packet ---
rem --- attribution via packet capture). Without it, the tool still  ---
rem --- runs, just in approximate attribution mode.                  ---
net session >nul 2>nul
if not %errorlevel%==0 (
    echo This tool works best as Administrator ^(it enables exact
    echo per-packet traffic attribution instead of an approximation^).
    echo Windows will now ask you to approve that - click Yes.
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

rem --- prefer the bundled portable Python (self-contained, no install ---
rem --- or internet needed) - fall back to a system Python if someone ---
rem --- removed that folder.                                          ---
set PY=
if exist "%~dp0app\python-portable\python.exe" (
    set PY="%~dp0app\python-portable\python.exe"
    echo [OK] Using bundled Python ^(self-contained, Administrator^)
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set PY=python
    ) else (
        where py >nul 2>nul
        if %errorlevel%==0 (
            set PY=py
        )
    )

    if "%PY%"=="" (
        echo [ERROR] No bundled Python found, and none is installed on this machine.
        echo Install Python 3.10+ from https://python.org/downloads and re-run this file.
        pause
        exit /b 1
    )

    echo [OK] Using system %PY% ^(Administrator^)
    echo.

    rem --- make sure required packages are installed (only needed for a ---
    rem --- system Python - the bundled one already has them installed) ---
    echo Checking dependencies...
    %PY% -c "import psutil, websockets, pydivert" >nul 2>nul
    if not %errorlevel%==0 (
        echo Installing required packages ^(psutil, websockets, pydivert^)...
        %PY% -m pip install -r requirements.txt --quiet
        if not %errorlevel%==0 (
            echo [ERROR] Failed to install dependencies. Check your internet connection.
            pause
            exit /b 1
        )
    )
    echo [OK] Dependencies ready.
)
echo.

rem --- start the backend in its own window so it's easy to see / close ---
echo Starting backend server...
start "THE GATE - backend (close this window to stop monitoring)" %PY% server.py

rem give it a moment to bind the port before the page tries to connect
timeout /t 2 /nobreak >nul

rem --- open the visualization in the default browser ---
echo Opening visualization...
start "" "%~dp0app\index.html"

rem this launcher window's job is done - close it so only the backend
rem window (titled above) is left on screen; that's the one to close
rem to stop monitoring
exit /b

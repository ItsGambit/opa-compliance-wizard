@echo off
where py >nul 2>nul
if %errorlevel%==0 (
    py "%~dp0launch.py" %*
) else (
    python "%~dp0launch.py" %*
)
pause

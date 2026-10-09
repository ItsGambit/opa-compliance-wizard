@echo off
rem Windows launcher -- all real logic lives in launch.py.
rem LNCH-05: prefer the "py" launcher (picks the newest installed Python 3); a bare
rem "python" on a stock Windows is often the Microsoft Store alias, not Python.
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
    if errorlevel 1 goto nopython
    py -3 "%~dp0launch.py" %*
    goto done
)
where python >nul 2>nul
if errorlevel 1 goto nopython
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if errorlevel 1 goto nopython
python "%~dp0launch.py" %*
goto done
:nopython
echo No Python 3.9 or newer was found. Install it from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH"), then run this again.
:done
pause

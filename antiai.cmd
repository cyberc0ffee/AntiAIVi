@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROJECT_DIR=%~dp0"
set "BUNDLED_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
set "BUNDLED_NODE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"

if exist "%BUNDLED_PYTHON%" (
  "%BUNDLED_PYTHON%" "%PROJECT_DIR%antiai.py" %*
  exit /b !ERRORLEVEL!
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%PROJECT_DIR%antiai.py" %*
  exit /b !ERRORLEVEL!
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py "%PROJECT_DIR%antiai.py" %*
  exit /b !ERRORLEVEL!
)

if exist "%BUNDLED_NODE%" (
  "%BUNDLED_NODE%" "%PROJECT_DIR%src\main.js" %*
  exit /b !ERRORLEVEL!
)

where node >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  node "%PROJECT_DIR%src\main.js" %*
  exit /b !ERRORLEVEL!
)

echo Python o Node.js non trovati.
echo Installa Python oppure esegui con il runtime bundled Codex:
echo "%BUNDLED_PYTHON%" "%PROJECT_DIR%antiai.py" %*
exit /b 1

@echo off
:: Request Administrator privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting Administrator privileges...
    goto UACPrompt
) else (
    goto gotAdmin
)

:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
exit /B

:gotAdmin
if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
pushd "%CD%"
CD /D "%~dp0"

echo.
echo ============================================
echo   CoinShield Reinstallation
echo ============================================
echo.
echo Step 1: Uninstalling old version...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Installer\uninstall.ps1"

echo.
echo Step 2: Installing new version...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Installer\install.ps1" -Silent -Mode Enforcement

echo.
echo ============================================
echo   Installation Complete
echo ============================================
echo.
powershell -Command "Get-Service CoinShield, CoinShieldWatchdog -ErrorAction SilentlyContinue | Format-Table Status, Name, DisplayName -AutoSize"
echo.
pause

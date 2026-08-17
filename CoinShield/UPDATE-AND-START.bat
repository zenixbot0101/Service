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
echo   CoinShield - Update and Start
echo ============================================
echo.

echo Step 1: Stopping services...
powershell -Command "Stop-Service CoinShield, CoinShieldWatchdog -Force -ErrorAction SilentlyContinue"
timeout /t 2 >nul

echo Step 2: Copying new binaries...
xcopy /Y "%~dp0Installer\build\*.exe" "C:\Program Files\CoinShield\"
xcopy /Y "%~dp0Installer\build\*.json" "C:\Program Files\CoinShield\"

echo Step 3: Starting services...
sc start CoinShieldWatchdog
timeout /t 2 >nul
sc start CoinShield
timeout /t 3 >nul

echo.
echo ============================================
echo   Service Status
echo ============================================
echo.
powershell -Command "Get-Service CoinShield, CoinShieldWatchdog | Format-Table Status, Name, DisplayName -AutoSize"

echo.
echo Recent logs:
powershell -Command "Get-EventLog -LogName Application -Source CoinShield -Newest 3 -ErrorAction SilentlyContinue | Format-Table TimeGenerated, EntryType, Message -AutoSize -Wrap"

echo.
pause

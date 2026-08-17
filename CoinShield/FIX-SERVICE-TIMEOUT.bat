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
echo   Fix CoinShield Service Timeout
echo ============================================
echo.

echo Increasing service timeout to 120 seconds...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v ServicesPipeTimeout /t REG_DWORD /d 120000 /f

echo.
echo Restarting services...
sc stop CoinShield
timeout /t 2 >nul
sc stop CoinShieldWatchdog
timeout /t 2 >nul

echo.
echo Starting with increased timeout...
sc start CoinShieldWatchdog
timeout /t 5 >nul
sc start CoinShield
timeout /t 10 >nul

echo.
echo ============================================
echo   Service Status
echo ============================================
echo.
powershell -Command "Get-Service CoinShield, CoinShieldWatchdog | Format-Table Status, Name, DisplayName -AutoSize"

echo.
echo If still fails, the binary may need to be rebuilt smaller.
echo.
pause

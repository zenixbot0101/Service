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
echo   Starting CoinShield Service
echo ============================================
echo.

sc start CoinShield
timeout /t 3 >nul

echo.
echo Service Status:
powershell -Command "Get-Service CoinShield | Format-Table Status, Name, DisplayName -AutoSize"

echo.
echo Recent Logs:
powershell -Command "Get-EventLog -LogName Application -Source CoinShield -Newest 3 | Format-Table TimeGenerated, EntryType, Message -AutoSize -Wrap"

echo.
pause

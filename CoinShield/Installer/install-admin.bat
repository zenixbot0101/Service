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
echo   CoinShield Installation
echo ============================================
echo.
echo Mode: Enforcement (auto-terminate miners)
echo Service: Automatic (Delayed Start)
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Silent -Mode Enforcement

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo   Installation Complete!
    echo ============================================
    echo.
    echo Service Status:
    powershell.exe -Command "Get-Service CoinShield, CoinShieldWatchdog | Format-Table Status, Name, DisplayName -AutoSize"
    echo.
    echo Press any key to exit...
    pause >nul
) else (
    echo.
    echo ============================================
    echo   Installation Failed!
    echo ============================================
    echo.
    echo Check Event Log for errors:
    echo   Get-EventLog -LogName Application -Source CoinShield -EntryType Error -Newest 5
    echo.
    pause
)

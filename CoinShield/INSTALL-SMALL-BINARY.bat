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
echo   CoinShield - Install Small Binary
echo ============================================
echo.
echo Using framework-dependent build (160KB vs 77MB)
echo Requires .NET 10 Runtime (already installed)
echo.

echo Step 1: Stopping services...
sc stop CoinShield 2>nul
sc stop CoinShieldWatchdog 2>nul
timeout /t 3 >nul

echo Step 2: Removing old files...
del /Q "C:\Program Files\CoinShield\*.exe" 2>nul
del /Q "C:\Program Files\CoinShield\*.dll" 2>nul

echo Step 3: Copying new binaries and dependencies...
xcopy /Y /I "%~dp0Installer\build-small\*.*" "C:\Program Files\CoinShield\"

echo Step 4: Starting services...
sc start CoinShieldWatchdog
timeout /t 3 >nul
sc start CoinShield
timeout /t 5 >nul

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

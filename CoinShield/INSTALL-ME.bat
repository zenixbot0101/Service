@echo off
echo.
echo ============================================
echo   CoinShield Installation
echo ============================================
echo.
echo This will install CoinShield service with:
echo   Mode: Enforcement (auto-terminate miners)
echo   Service: Automatic (Delayed Start)
echo.
pause

powershell -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0Installer\install.ps1\" -Silent -Mode Enforcement'"

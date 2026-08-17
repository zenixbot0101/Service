@echo off
echo.
echo ============================================
echo   Testing CoinShield Binary (Console Mode)
echo ============================================
echo.
echo This will try to run the service binary as a console app
echo to see any startup errors.
echo.
echo Press Ctrl+C to stop when you see output.
echo.
pause

cd "C:\Program Files\CoinShield"
CoinShield.Service.exe

pause

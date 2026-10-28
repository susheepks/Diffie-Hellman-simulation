@echo off
REM run_demo.bat – Windows launcher for local rehearsal of Alice & Bob network demo
REM Usage: run_demo.bat [--preset] [--show-wire]

echo ============================================================
echo   Diffie-Hellman Network Demo (Localhost Rehearsal)
echo ============================================================
echo.
echo Starting Alice (server on port 5000) in a new window...
start "Laptop 1 - Alice (Server)" cmd /k "python network_demo/alice.py --port 5000 %* && pause"

echo Waiting 2 seconds for Alice to initialize...
timeout /t 2 /nobreak > nul

echo Starting Bob (client connecting to 127.0.0.1:5000) in a new window...
start "Laptop 2 - Bob (Client)" cmd /k "python network_demo/bob.py --host 127.0.0.1 --port 5000 %* && pause"

echo.
echo Both windows are running. Test encrypted chat between them!
echo Press any key to close this launcher.
pause > nul

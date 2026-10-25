@echo off
REM run_demo.bat – Windows batch file to run the Alice+Bob network demo
REM Usage: run_demo.bat [--preset] [--bits N]
REM
REM Opens two cmd windows: one for Alice (server) and one for Bob (client).
REM Bob's window waits 3 seconds to give Alice time to start.

echo ============================================================
echo  Diffie-Hellman Network Demo – Alice and Bob
echo ============================================================
echo.
echo Starting Alice (server) in a new window...
start "Alice - DH Server" cmd /k "python network_demo/alice_server.py %* && pause"

echo Waiting 3 seconds for Alice to start...
timeout /t 3 /nobreak > nul

echo Starting Bob (client) in a new window...
start "Bob - DH Client" cmd /k "python network_demo/bob_client.py %* && pause"

echo.
echo Both windows should show a matching key fingerprint.
echo Press any key to close this launcher window.
pause > nul

#!/usr/bin/env bash
# run_demo.sh – Shell script to run the Alice+Bob network demo (Linux/macOS)
# Usage: bash run_demo.sh [--preset] [--show-wire]

set -e
ARGS="$*"

echo "============================================================"
echo " Diffie-Hellman Network Demo – Localhost Rehearsal"
echo "============================================================"
echo

launch_terminal() {
    local title="$1"
    local cmd="$2"
    if command -v gnome-terminal &>/dev/null; then
        gnome-terminal --title="$title" -- bash -c "$cmd; echo; echo 'Press ENTER to close'; read"
    elif command -v xterm &>/dev/null; then
        xterm -T "$title" -e bash -c "$cmd; echo; echo 'Press ENTER to close'; read" &
    elif command -v osascript &>/dev/null; then
        osascript -e "tell application \"Terminal\" to do script \"$cmd\""
    else
        echo "No terminal emulator found; running in background (output -> ${title// /_}.log)"
        eval "$cmd" > "${title// /_}.log" 2>&1 &
        echo "  PID: $!"
    fi
}

echo "Starting Alice (server on port 5000)..."
launch_terminal "Laptop 1 - Alice" "cd '$(pwd)' && python3 network_demo/alice.py --port 5000 $ARGS"

echo "Waiting 2 seconds for Alice to start..."
sleep 2

echo "Starting Bob (client connecting to 127.0.0.1:5000)..."
launch_terminal "Laptop 2 - Bob" "cd '$(pwd)' && python3 network_demo/bob.py --host 127.0.0.1 --port 5000 $ARGS"

echo
echo "Both processes launched. Check your terminal windows!"

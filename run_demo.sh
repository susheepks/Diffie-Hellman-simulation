#!/usr/bin/env bash
# run_demo.sh – Shell script to run the Alice+Bob network demo (Linux/macOS)
# Usage: bash run_demo.sh [--preset] [--bits N]
#
# Opens two terminals (tries gnome-terminal, then xterm, then tmux, then
# falls back to background processes with output to files).

set -e

ARGS="$*"

echo "============================================================"
echo " Diffie-Hellman Network Demo – Alice and Bob"
echo "============================================================"
echo

# Helper: launch a command in a new terminal window
launch_terminal() {
    local title="$1"
    local cmd="$2"
    if command -v gnome-terminal &>/dev/null; then
        gnome-terminal --title="$title" -- bash -c "$cmd; echo; echo 'Press ENTER to close'; read"
    elif command -v xterm &>/dev/null; then
        xterm -T "$title" -e bash -c "$cmd; echo; echo 'Press ENTER to close'; read" &
    elif command -v osascript &>/dev/null; then
        # macOS
        osascript -e "tell application \"Terminal\" to do script \"$cmd\""
    else
        echo "No terminal emulator found; running in background (output → ${title// /_}.log)"
        eval "$cmd" > "${title// /_}.log" 2>&1 &
        echo "  PID: $!"
    fi
}

echo "Starting Alice (server)…"
launch_terminal "Alice - DH Server" "cd '$(pwd)' && python network_demo/alice_server.py $ARGS"

echo "Waiting 3 seconds for Alice to start…"
sleep 3

echo "Starting Bob (client)…"
launch_terminal "Bob - DH Client" "cd '$(pwd)' && python network_demo/bob_client.py $ARGS"

echo
echo "Demo running. Both terminals should print a matching key fingerprint."

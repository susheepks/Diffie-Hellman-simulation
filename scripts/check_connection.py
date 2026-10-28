"""
scripts/check_connection.py – Pre-Flight Network Connectivity Tester
===================================================================
Run this script on Laptop 2 (Bob) to test if you can reach Laptop 1 (Alice)
before starting the full Diffie-Hellman demo. Acts as a "ping" for the TCP port.

Usage:
    python scripts/check_connection.py --host 192.168.1.23 --port 5000
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

# Force UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    print("\n" + "=" * 65)
    print("      🔍 PRE-FLIGHT TCP CONNECTIVITY CHECK")
    print("=" * 65)
    print(f"  Target Server: {host}")
    print(f"  Target Port:   {port}")
    print(f"  Timeout:       {timeout} seconds\n")

    t0 = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        latency = (time.perf_counter() - t0) * 1000
        sock.close()
        print(f"  \033[1;32m✅ SUCCESS: Connected to {host}:{port} in {latency:.1f} ms!\033[0m")
        print("  Network link is ready for the Diffie-Hellman demo.")
        print("=" * 65 + "\n")
        return True
    except socket.timeout:
        print(f"  \033[1;31m❌ TIMEOUT: Could not reach {host}:{port} within {timeout}s.\033[0m")
        show_troubleshooting(host, port)
        return False
    except ConnectionRefusedError:
        print(f"  \033[1;31m❌ CONNECTION REFUSED: Reached {host}, but no service is listening on port {port}.\033[0m")
        print("  -> Ensure Alice's script is currently running:")
        print("     python network_demo/alice.py --port " + str(port))
        print("=" * 65 + "\n")
        return False
    except Exception as e:
        print(f"  \033[1;31m❌ ERROR: {e}\033[0m")
        show_troubleshooting(host, port)
        return False


def show_troubleshooting(host: str, port: int) -> None:
    print("\n  Troubleshooting Checklist:")
    print("  1. Are both laptops connected to the EXACT same Wi-Fi or phone hotspot?")
    print("     (Note: University/college campus Wi-Fi often blocks client-to-client traffic;")
    print("      using a phone's mobile hotspot solves this 100% of the time).")
    print(f"  2. Did you type the correct IP address? Double-check Alice's terminal.")
    print("  3. Windows Firewall on Alice's laptop might be blocking incoming port " + str(port) + ":")
    print("     Run this on Alice's laptop in PowerShell (Admin):")
    print(f'       New-NetFirewallRule -DisplayName "DH Demo" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow')
    print("  4. Linux Firewall on Alice's laptop:")
    print(f"       sudo ufw allow {port}/tcp")
    print("=" * 65 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test TCP connection to Alice's server")
    parser.add_argument("--host", required=True, help="Alice's IP address")
    parser.add_argument("--port", type=int, default=5000, help="Alice's TCP port (default: 5000)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds (default: 3.0)")
    args = parser.parse_args()

    success = check_port(args.host, args.port, timeout=args.timeout)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

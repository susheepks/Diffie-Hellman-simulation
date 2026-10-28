"""
scripts/find_ip.py – Discover Local IPv4 LAN Addresses
======================================================
Run this script on Laptop 1 (Alice) to find your LAN IP address before
starting the demonstration.

Usage:
    python scripts/find_ip.py
"""

from __future__ import annotations

import platform
import socket
import sys
from pathlib import Path

# Force UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.transport import get_lan_ips


def main() -> None:
    print("\n" + "=" * 65)
    print("      🌐 LOCAL NETWORK IP DISCOVERY – TWO-LAPTOP SETUP")
    print("=" * 65)

    ips = get_lan_ips()
    hostname = socket.gethostname()

    print(f"  Device Hostname: {hostname}")
    print(f"  Operating System: {platform.system()} {platform.release()}\n")

    if ips:
        print("  \033[1;32mDetected Usable LAN IPv4 Address(es):\033[0m")
        for i, ip in enumerate(ips, start=1):
            print(f"    {i}. \033[1;32m{ip}\033[0m")
            print(f"       -> Tell Bob to run: python network_demo/bob.py --host {ip} --port 5000\n")
    else:
        print("  \033[1;33m⚠️ No active LAN IP address found!\033[0m")
        print("  Ensure you are connected to Wi-Fi or a phone hotspot.\n")

    print("-" * 65)
    print("  Manual OS Commands to Verify IP:")
    print("  • Windows:      ipconfig          (Look for 'IPv4 Address' under Wi-Fi)")
    print("  • Linux:        ip a              (or: hostname -I)")
    print("  • macOS:        ifconfig | grep inet")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()

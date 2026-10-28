"""
network_demo/alice_server.py – Compatibility wrapper for alice.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_demo.alice import main

if __name__ == "__main__":
    main()

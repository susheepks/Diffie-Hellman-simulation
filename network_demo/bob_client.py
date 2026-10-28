"""
network_demo/bob_client.py – Compatibility wrapper for bob.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_demo.bob import main

if __name__ == "__main__":
    main()

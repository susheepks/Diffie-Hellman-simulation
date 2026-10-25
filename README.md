# Diffie-Hellman Key Exchange – VTU CNS Demo

> **Course:** Cryptography and Network Security (21CS62 / equivalent)  
> **Module:** Public-Key Cryptography  
> **Topic:** Diffie-Hellman Key Exchange between Alice and Bob

---

## 📋 Overview

This project is a **complete, demo-ready simulation** of the Diffie-Hellman (DH)
key-exchange protocol. It is implemented entirely in Python 3.10+ using the
standard library for the core, with Streamlit for an interactive UI.

The demo covers:
- The full DH protocol (parameter setup → key generation → exchange → shared secret)
- Three parameter modes: textbook preset, auto-generated primes, manual entry
- Mathematical transparency: every step shown with substituted formulas
- Square-and-multiply trace for the fast modular exponentiation
- Security demonstrations: passive eavesdropper (Eve) and Man-in-the-Middle (Mallory)
- Shared key proof via SHA-256 KDF + XOR stream cipher
- Real TCP socket simulation (Alice server ↔ Bob client)

---

## 🗂️ Project Structure

```
dh_project/
├── dh/
│   ├── __init__.py         # Package exports
│   ├── math_utils.py       # Square-and-multiply, Miller-Rabin, prime gen, primitive root
│   ├── party.py            # Party class (Alice / Bob) with key lifecycle
│   ├── protocol.py         # DHProtocol: orchestrates exchange + step logs
│   ├── attacks.py          # Eve (brute-force DLP) + Mallory (MITM)
│   └── kdf.py              # SHA-256 KDF + XOR stream cipher demo
├── network_demo/
│   ├── alice_server.py     # TCP server (Alice)
│   └── bob_client.py       # TCP client (Bob)
├── tests/
│   └── test_dh.py          # Unit tests (run with python -m unittest)
├── app.py                  # Streamlit interactive UI
├── cli.py                  # Command-line demo
├── requirements.txt        # pip install -r requirements.txt
├── run_demo.bat            # Windows: launch Alice + Bob in separate windows
├── run_demo.sh             # Linux/macOS: same
├── README.md               # This file
├── REPORT.md               # VTU project report
└── VIVA_QA.md              # 20 viva Q&A
```

---

## ⚡ Quick Start

```bash
# 1. Clone / download the project
cd dh_project

# 2. Install dependencies (Streamlit + pandas for UI only)
pip install -r requirements.txt

# 3. Launch the interactive Streamlit app
streamlit run app.py

# 4. Run the CLI textbook example
python cli.py

# 5. Run unit tests
python -m unittest tests/test_dh.py -v
```

---

## 🖥️ Streamlit UI

```bash
streamlit run app.py
```

Opens at **http://localhost:8501**

### Sidebar Options

| Setting | Description |
|---------|-------------|
| Parameter Mode | Textbook preset / Auto-generate / Manual input |
| Prime Bit Size | 16 – 1024 bits (AUTO mode) |
| Use Safe Prime | p = 2q+1 for fast primitive-root check |
| Reveal Private Keys | Toggle to show/hide secret values |
| Show Square-and-Multiply | Step-by-step exponentiation trace |
| Run / Re-run | Regenerate parameters and re-run the protocol |

### Demo Tabs

| Tab | Content |
|-----|---------|
| 🔑 Key Exchange | Main 3-column Alice/Channel/Bob view with step navigator |
| 🕵️ Eve | Brute-force DLP attack + infeasibility benchmark chart |
| 🦹 MITM | Mallory intercepts two independent DH sessions |
| 🌐 Network | Instructions + expected output for socket demo |
| 📚 Theory | Mathematical background: modular arithmetic, DLP, key sizes |

---

## 💻 CLI Usage

```bash
# Textbook preset (p=23, g=5, a=6, b=15)
python cli.py

# Auto 64-bit safe prime
python cli.py --mode auto --bits 64

# Auto 128-bit, reveal private keys + show square-and-multiply
python cli.py --mode auto --bits 128 --reveal --verbose-steps

# Manual parameters
python cli.py --mode manual --p 23 --g 5 --reveal

# Eve brute-force on a 20-bit prime
python cli.py --mode auto --bits 20 --eve --timeout 10

# Eve + benchmark across bit sizes
python cli.py --mode auto --bits 20 --eve --benchmark

# Man-in-the-Middle demo
python cli.py --mode auto --bits 32 --mitm
```

---

## 🌐 Network Demo (Socket Simulation)

### Option A – Automated (Windows)
```
run_demo.bat --preset
```

### Option B – Automated (Linux/macOS)
```bash
bash run_demo.sh --preset
```

### Option C – Manual (two terminals)
```bash
# Terminal 1
python network_demo/alice_server.py --preset

# Terminal 2 (after Alice is listening)
python network_demo/bob_client.py --preset
```

### Expected Output
Both terminals print a **matching key fingerprint** (first 8 bytes of the SHA-256 derived key).

```
[ALICE] Key fingerprint (first 8 bytes): 3a:f1:22:bc:09:de:7f:44
[BOB  ] Key fingerprint (first 8 bytes): 3a:f1:22:bc:09:de:7f:44
[BOB  ] Fingerprint check: ✅ MATCH
```

---

## 🧪 Unit Tests

```bash
python -m unittest tests/test_dh.py -v
```

Tests cover:
1. `mod_exp` == `pow(a,b,m)` for 1000 random cases
2. Miller-Rabin on known primes, composites, Carmichael numbers
3. Textbook example: A=8, B=19, s=2
4. 100 random exchanges: alice\_secret == bob\_secret
5. Invalid inputs raise `ValueError`
6. MITM: alice\_secret != bob\_secret (in general)
7. KDF + XOR round-trip

---

## 📚 Mathematical Quick Reference

| Symbol | Meaning |
|--------|---------|
| p | Large prime modulus (public) |
| g | Generator / primitive root mod p (public) |
| a | Alice's private key (secret, 1 < a < p-1) |
| b | Bob's private key (secret, 1 < b < p-1) |
| A | Alice's public key = g^a mod p (public) |
| B | Bob's public key = g^b mod p (public) |
| s | Shared secret = B^a mod p = A^b mod p |
| K | Derived symmetric key = SHA-256(s) |

**Why it works:**  
`(g^a)^b ≡ g^(ab) ≡ (g^b)^a  (mod p)`

---

## 🎬 Demo Script (for viva / presentation)

1. **Open Streamlit app** → Textbook preset is loaded by default.
2. **Point to the three columns**: "Alice on the left, Bob on the right, Public Channel in the middle."
3. **Show the green values**: "g, p, A, B are green — public, anyone can see these."
4. **Click 'Reveal Private Keys'**: "a and b are red — these never leave their owner."
5. **Step Navigator**: Walk through each step explaining the formula.
6. **Square-and-Multiply**: Enable the toggle, explain the binary exponent scanning.
7. **KDF tab**: Type a message, show Alice encrypts and Bob decrypts.
8. **Eve tab**: Run brute force on 16-bit prime (fast), then point to the chart showing exponential growth.
9. **MITM tab**: Run the attack, show that Alice and Bob have different secrets.
10. **Network tab**: Open two terminals and run `run_demo.bat --preset`.

---

## ⚠️ Assumptions & Limitations

- The XOR cipher is a **teaching demo only** — not production crypto.
- Miller-Rabin has negligible error probability (< 4^{-20}) — not zero.
- Brute-force DLP is O(p); only shown for p < 2^28 within a few seconds.
- No ECDH, no RSA, no other algorithms — scope is DH only (per VTU requirement).
- Network demo uses plaintext TCP; a real system would add TLS.

---

## 📝 License

MIT — free to use for educational purposes.

---

*Diffie, W. & Hellman, M.E. (1976). New Directions in Cryptography. IEEE Trans. Inf. Theory.*

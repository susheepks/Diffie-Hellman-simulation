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

## 🌐 Two-Laptop Setup Demonstration

The project supports a real two-laptop live demonstration over TCP:
- **Laptop 1 = Alice (TCP Server):** Binds to `0.0.0.0` on port 5000 and announces its LAN IP.
- **Laptop 2 = Bob (TCP Client):** Connects to Alice's LAN IP on port 5000.
- **Protocol:** 4-byte big-endian length-prefixed JSON frames over TCP.

---

### Step 1: Network & Wi-Fi Configuration

1. **Connect both laptops to the SAME network.**
   > **Pro Tip for College Demos:** Use a **Personal Mobile Phone Hotspot**. College and university Wi-Fi networks typically enforce "Client Isolation" which blocks laptop-to-laptop socket connections. A phone hotspot guarantees direct communication.
2. **Find Alice's IP (Laptop 1):**
   ```bash
   python scripts/find_ip.py
   ```
   *Alternative OS Commands:*
   - **Windows:** `ipconfig` (look for `IPv4 Address` under your Wi-Fi adapter, e.g., `192.168.43.120`)
   - **Linux:** `ip a` or `hostname -I`
   - **macOS:** `ifconfig | grep inet`
3. **Configure Firewall on Laptop 1 (Alice):**
   Ensure incoming TCP traffic on port 5000 is allowed:
   - **Windows PowerShell (Run as Administrator):**
     ```powershell
     New-NetFirewallRule -DisplayName "DH Demo" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
     ```
   - **Linux:**
     ```bash
     sudo ufw allow 5000/tcp
     ```

---

### Step 2: Pre-Flight Connection Check

Before the presentation, verify that Laptop 2 can reach Laptop 1:
```bash
# Run on Laptop 2 (Bob):
python scripts/check_connection.py --host <ALICE_IP> --port 5000
```
If reachable, it will report latency and success (`✅ SUCCESS: Connected to ALICE_IP:5000`).

---

### Step 3: Run the Demonstration

#### 👩 On Laptop 1 (Alice – Server):
```bash
python network_demo/alice.py --port 5000 --preset
```
*(For 64-bit safe prime generation, omit `--preset`: `python network_demo/alice.py --port 5000`)*

#### 👨 On Laptop 2 (Bob – Client):
```bash
python network_demo/bob.py --host <ALICE_IP> --port 5000 --preset
```

#### 💻 Localhost Rehearsal (Single Machine):
```bash
# Windows one-click launcher:
run_demo.bat --preset

# Linux / macOS:
bash run_demo.sh --preset
```

#### 🕵️ Optional: Eavesdropper & MITM Relay
To demonstrate what an eavesdropper sees or run a Man-in-the-Middle attack on a 3rd laptop (or in a 3rd terminal):
```bash
# 1. Start Alice on port 5001:
python network_demo/alice.py --port 5001 --preset

# 2. Start Eve sniffer listening on port 5000, relaying to Alice on 5001:
python network_demo/eve_sniffer.py --listen-port 5000 --alice-host <ALICE_IP> --alice-port 5001

# For active Man-in-the-Middle attack:
python network_demo/eve_sniffer.py --listen-port 5000 --alice-host <ALICE_IP> --alice-port 5001 --mitm

# 3. Start Bob connecting to Eve on port 5000:
python network_demo/bob.py --host <EVE_IP> --port 5000 --preset
```

---

### 🔧 Troubleshooting Table

| Symptom | Cause | Solution |
|---------|-------|----------|
| **Connection Timeout** | Campus Wi-Fi blocks client-to-client traffic | Switch both laptops to a mobile phone hotspot. |
| **Connection Refused** | Alice's server is not yet running or wrong port | Start `network_demo/alice.py` first, then run Bob. |
| **Firewall Blocking** | Windows/Linux firewall drops inbound TCP | Run the PowerShell firewall command on Alice's laptop. |
| **Wrong IP Address** | Laptop has multiple IPs (virtual adapters/VPN) | Run `python scripts/find_ip.py` to identify the active Wi-Fi LAN IP. |
| **Key Mismatch Warning** | Data corrupted on wire or MITM attack | Verify wire integrity or check if `eve_sniffer.py --mitm` is active. |

---

### 🎭 Step-by-Step Two-Presenter Live Demo Script

| Step | Presenter 1 (Alice - Laptop 1) | Presenter 2 (Bob - Laptop 2) | Script & What to Explain to Evaluators |
|:---:|:---|:---|:---|
| **1** | Runs: `python network_demo/alice.py --port 5000 --preset` | Prepares command line with Alice's IP. | *"Alice starts as the TCP server listening on port 5000. Notice Alice's terminal announces her LAN IP address."* |
| **2** | Observes connection from Bob. | Runs: `python network_demo/bob.py --host <IP> --port 5000 --preset` | *"Bob connects across the Wi-Fi network and sends a protocol greeting."* |
| **3** | Sends parameters `p=23, g=5`. | Receives `p=23, g=5` and validates. | *"Alice announces public parameters p=23 and g=5. Bob runs the Miller-Rabin test to verify p is prime before accepting."* |
| **4** | Generates secret $a=6$ (hidden). Computes $A = 5^6 \pmod{23} = 8$. | Generates secret $b=15$ (hidden). Computes $B = 5^{15} \pmod{23} = 19$. | *"Both parties generate private keys independently. Private keys never leave the machines."* |
| **5** | Transmits $A = 8$ to Bob. Receives $B = 19$. | Transmits $B = 19$ to Alice. Receives $A = 8$. | *"Only public keys A and B cross the network wire. An eavesdropper sees A=8 and B=19."* |
| **6** | Computes $s = B^a \pmod p = 19^6 \pmod{23} = \mathbf{2}$. | Computes $s = A^b \pmod p = 8^{15} \pmod{23} = \mathbf{2}$. | *"Both laptops compute the shared secret locally. Both reach s = 2 independently!"* |
| **7** | Sends SHA-256 confirmation hash. Displays `✅ MATCH`. | Sends SHA-256 confirmation hash. Displays `✅ MATCH`. | *"Both derive a 256-bit key and exchange a short confirmation fingerprint to verify agreement."* |
| **8** | Types a message: `"Meet at library 📚"`. | Terminal decrypts and displays plaintext. Types reply: `"Got it! 🚀"`. | *"Hybrid Cryptography in action: Alice and Bob now use the shared key to exchange end-to-end encrypted messages!"* |


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

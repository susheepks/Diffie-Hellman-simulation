# 💻 BOB AGENT PLAYBOOK: TWO-LAPTOP DIFFIE-HELLMAN DEMO

This document contains complete, step-by-step instructions for an **AI Agent or Human Presenter running on Laptop 2 (Bob)** to connect to **Laptop 1 (Alice)** over a local network, perform the Diffie-Hellman Key Exchange, and run the end-to-end encrypted chat session.

---

## 🎯 Role and Objective
- **Role**: Bob (TCP Client)
- **Target Peer**: Alice (TCP Server, Laptop 1)
- **Default Port**: `5000`
- **Framing**: 4-byte big-endian length prefix preceding UTF-8 JSON payloads
- **Security Rule**: Private keys and shared secrets are computed locally and **never** transmitted across the network. Only public parameters ($p, g$), public keys ($A, B$), 8-character confirmation fingerprints, and ciphertext are exchanged.

---

## 📋 Prerequisites

1. **Network**: Both Laptop 1 (Alice) and Laptop 2 (Bob) must be connected to the **SAME Wi-Fi or Mobile Hotspot**.
   > ⚠️ **CRITICAL NOTE ON CAMPUS WI-FI**: College / institutional Wi-Fi networks typically enforce **AP/Client Isolation**, blocking laptops from communicating directly. **Use a personal mobile hotspot (phone hotspot)** for a reliable demo.
2. **Python**: Python 3.10+ installed and added to `PATH`.
3. **Alice's IP Address**: Obtain Alice's IP address displayed on Laptop 1 (for example: `172.20.10.3` or `192.168.1.x`). In all commands below, replace `<ALICE_IP>` with this address.

---

## 🚀 Step 1: Clone / Update the Repository on Laptop 2

Open PowerShell (Windows) or Terminal (macOS/Linux) on Laptop 2:

```bash
# If cloning for the first time:
git clone https://github.com/susheepks/Diffie-Hellman-simulation.git
cd Diffie-Hellman-simulation

# If already cloned, pull latest changes:
git pull origin main
```

*(Note: Core CLI demo uses Python's standard library only. To run the Streamlit browser UI, install requirements: `pip install -r requirements.txt`)*

---

## 🔍 Step 2: Pre-Flight Network Connectivity Check

Before launching the key exchange, test direct socket reachability to Alice:

```bash
python scripts/check_connection.py --host <ALICE_IP> --port 5000
```

### Expected Output:
```text
=================================================================
      🔍 PRE-FLIGHT TCP CONNECTIVITY CHECK
=================================================================
  Target Server: <ALICE_IP>
  Target Port:   5000
  Timeout:       3.0 seconds

  ✅ SUCCESS: Connected to <ALICE_IP>:5000 in 3.5 ms!
  Network link is ready for the Diffie-Hellman demo.
=================================================================
```

> 🛑 **If this step fails / times out**:
> 1. Verify that Alice's server (`python network_demo/alice.py --port 5000`) is actively running on Laptop 1.
> 2. Verify that Laptop 1 has opened inbound port 5000 in Windows Firewall:
>    `New-NetFirewallRule -DisplayName "DH Demo" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow`
> 3. Verify both laptops are connected to the same phone hotspot.

---

## 🧪 Step 3: Automated Sanity Test (Non-Interactive)

To verify the full handshake and crypto pipeline autonomously without waiting for keyboard inputs, run:

```bash
python network_demo/bob.py --host <ALICE_IP> --port 5000 --show-wire --no-interactive
```

### Verification Criteria:
- [x] Bob connects to `<ALICE_IP>:5000`.
- [x] Alice sends $p=23, g=5$. Bob validates primality with Miller-Rabin (`p=23 is prime`).
- [x] Bob selects private key $b \in [2, p-2]$ (kept hidden).
- [x] Bob receives Alice's public key $A$ and sends public key $B$.
- [x] Both calculate shared secret $s = A^b \bmod p = 2$.
- [x] SHA-256 confirmation fingerprints match (`✅ MATCH (Fingerprint: fbef1743)`).
- [x] Initial encrypted test message is received and decrypted.
- [x] Command exits with code `0`.

---

## 💬 Step 4: Live Interactive Key Exchange & Secure Chat (For Evaluators)

When demonstrating in front of professors / evaluators, run Bob in interactive mode with wire inspection:

```bash
python network_demo/bob.py --host <ALICE_IP> --port 5000 --show-wire
```

### Expected Terminal Output Trace:
```text
=================================================================
      🔐 BOB – DIFFIE-HELLMAN KEY EXCHANGE CLIENT (TCP)
=================================================================
  Target Alice server: <ALICE_IP>:5000
  Connection attempts: up to 5 (delay: 2.0s)
=================================================================

[15:30:00.120] [BOB  ] Connecting to Alice at <ALICE_IP>:5000 (Attempt 1/5)...
[15:30:00.125] [BOB  ] Connected successfully to Alice at <ALICE_IP>:5000!
  [BOB WIRE  ] > {"type":"hello","from":"Bob"}
[15:30:00.126] [BOB  ] Step 1: Sent handshake greeting to Alice
  [BOB WIRE  ] < {"type":"params","p":23,"g":5}
[15:30:00.127] [BOB  ] Step 2: Received public parameters from Alice: p=23, g=5
[15:30:00.127] [BOB  ] Validating received parameters before proceeding...
[15:30:00.127] [BOB  ]   ✓ Primality verified: p=23 is prime (Miller-Rabin passed)
[15:30:00.127] [BOB  ]   ✓ Generator verified: g=5 is within [2, 21]
[15:30:00.128] [BOB  ] Step 2: Public parameters approved.
[15:30:00.128] [BOB  ] Step 3: Private key chosen: b = [GENERATED - KEPT SECRET]
  [BOB WIRE  ] < {"type":"public","name":"Alice","value":8}
[15:30:00.129] [BOB  ] Step 4: Received Alice's public key: A = 8
  [BOB WIRE  ] > {"type":"public","name":"Bob","value":4}
[15:30:00.129] [BOB  ] Step 4: Sent public key to Alice: B = g^b mod p = 4
[15:30:00.130] [BOB  ] Step 5: Computed shared secret: s = A^b mod p = 8^4 mod 23 = 2
[15:30:00.130] [BOB  ] Step 6: Derived 256-bit AES/XOR key (SHA-256). Fingerprint: fbef1743
  [BOB WIRE  ] < {"type":"confirm","fingerprint":"fbef1743"}
  [BOB WIRE  ] > {"type":"confirm","fingerprint":"fbef1743"}
[15:30:00.131] [BOB  ] Step 6: Key Confirmation: ✅ MATCH (Fingerprint: fbef1743)

=================================================================
  🎉 SUCCESS: Both parties hold the same key! (Fingerprint: fbef1743)
=================================================================

-----------------------------------------------------------------
  💬 SECURE CHAT DEMO (End-to-End Encrypted via DH Shared Key)
  Notice: Demonstration cipher (SHA-256 counter-mode keystream).
  Type a message and press Enter. Type 'exit' to quit chat session.
-----------------------------------------------------------------
  [BOB WIRE  ] < {"type":"chat","sender":"Alice","ciphertext":"b00b84..."}

📩 [Alice]: Hello Bob! Secure channel established over Diffie-Hellman.
```

### Performing the Chat:
1. Type a reply in Bob's terminal, for example:
   ```text
   Hi Alice! Key confirmed. This message is encrypted with our shared secret.
   ```
2. Press `Enter`.
3. Observe `[BOB WIRE] > {"type":"chat","sender":"Bob","ciphertext":"..."}` showing that only encrypted hex ciphertext travels across the Wi-Fi.
4. Alice receives, decrypts, and displays the plaintext message on Laptop 1.
5. Type `exit` to cleanly close the session.

---

## 🌐 Step 5: Web UI Alternative (Streamlit on Laptop 2)

If the evaluator prefers the web browser interface on Laptop 2:

1. Launch Streamlit:
   ```bash
   streamlit run app.py
   ```
2. Open browser at `http://localhost:8501`.
3. In the sidebar, select **🌐 Network Demo**.
4. Select Role: **👨 Laptop 2: Bob (Client)**.
5. In **Alice's IP Address**, enter `<ALICE_IP>` (e.g., `172.20.10.3`).
6. Click **🔍 Test Connection to Alice** -> must show green success badge.
7. Click **🚀 Connect to Alice & Run Handshake**.
8. The UI renders Bob's card showing received public values, local secret computation ($s=2$), and key confirmation status.

---

## 🛡️ Step 6: Verify Offline Cryptographic Integrity

To verify all mathematical proofs, prime generators, MITM defense tests, and network packet framing locally on Laptop 2:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

**Expected Result**: `Ran 41 tests in ~1.0s ... OK`.

---

## 🔧 Troubleshooting Matrix for Bob

| Issue | Root Cause | Solution |
|:---|:---|:---|
| `[Errno 10061] Connection refused` | Alice server is not listening on that port. | Make sure Laptop 1 has launched `python network_demo/alice.py --port 5000`. |
| `[Errno 10060] Connection timed out` | Wi-Fi client isolation or firewall blocking inbound traffic on Alice. | Switch both laptops to phone hotspot. On Laptop 1, run `New-NetFirewallRule` in PowerShell as Admin. |
| `SECURITY ALERT: Modulus p=... is NOT prime!` | Alice transmitted a composite or invalid modulus. | Bob immediately aborts to protect security. Verify Alice is using `--preset` or `--bits 64`. |
| `Key Confirmation: ❌ MISMATCH` | Shared secrets did not match (possible active MITM on network). | Check if an Eve proxy relay is running between Alice and Bob. |

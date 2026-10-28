# VIVA_QA.md – 20 Likely Viva Questions & Short Answers

**Course:** Cryptography and Network Security  
**Topic:** Diffie-Hellman Key Exchange  

---

## Q1. What problem does Diffie-Hellman solve?

**A:** The **key distribution problem** — how two parties can agree on a shared secret
key over an insecure public channel without any prior shared secret.  
Before DH, symmetric-key systems required keys to be exchanged through a physically
secure channel (courier, trusted intermediary).

---

## Q2. What are the public parameters in DH, and how are they chosen?

**A:**
- **p** – a large prime number (≥ 2048 bits for modern use)
- **g** – a generator (primitive root modulo p)

Both are chosen by one party and sent to the other openly; knowing them gives an
attacker no advantage because of the hardness of the Discrete Logarithm Problem.

---

## Q3. What is a primitive root (generator)?

**A:** An element `g` of `Z_p*` is a primitive root modulo prime `p` if the powers
`g^1, g^2, …, g^(p−1)` produce every element of `{1, 2, …, p−1}` exactly once.
Equivalently, the *order* of `g` in the multiplicative group equals `p−1`.

**Example:** `g=5, p=23`: the 22 powers of 5 mod 23 give all non-zero residues.

---

## Q4. What is the Discrete Logarithm Problem (DLP)?

**A:** Given a prime `p`, a generator `g`, and a value `A = g^a mod p`, find `a`.  
This is easy in one direction (computing `g^a mod p` is fast) but believed to be
computationally infeasible in the other direction for large `p` (no polynomial-time
classical algorithm is known).

---

## Q5. Walk through the DH exchange step-by-step.

**A:**
1. Alice and Bob agree on public `p` and `g`.
2. Alice picks secret `a`, computes `A = g^a mod p`, sends A to Bob.
3. Bob picks secret `b`, computes `B = g^b mod p`, sends B to Alice.
4. Alice computes `s = B^a mod p = (g^b)^a = g^(ab) mod p`.
5. Bob computes `s = A^b mod p = (g^a)^b = g^(ab) mod p`.
6. Both hold the same `s = g^(ab) mod p`.

---

## Q6. Why do Alice and Bob arrive at the same shared secret?

**A:** Commutativity of exponentiation in a cyclic group:
```
(g^a)^b ≡ g^(ab) ≡ (g^b)^a  (mod p)
```
Multiplication (and therefore exponentiation) in `Z_p*` is commutative, so the
order of applying the exponents doesn't matter.

---

## Q7. What is fast modular exponentiation (square-and-multiply)?

**A:** An algorithm that computes `g^a mod p` in O(log a) multiplications by scanning
the binary representation of `a`:
- Start with `result = 1`.
- For each bit of `a` from MSB to LSB: always square, then multiply if the bit is 1.

Without this, computing `g^(10^300)` would be impossible; with it, it takes about
1000 multiplications.

---

## Q8. What does "the shared secret is not transmitted" mean?

**A:** Neither Alice nor Bob ever sends `a`, `b`, or `s = g^(ab)` over the channel.
Alice sends `A = g^a` and Bob sends `B = g^b`. An eavesdropper who sees `A` and
`B` cannot compute `g^(ab)` without solving the DLP. The shared secret is
computed *locally* on each side.

---

## Q9. Is DH an encryption algorithm?

**A:** No. DH is a **key agreement** (key exchange) protocol. It produces a shared
integer, which is then fed into a key-derivation function (e.g., SHA-256) to produce
a symmetric key. That key is used with a separate encryption algorithm (AES,
ChaCha20) for actual data encryption.

---

## Q10. What is a Man-in-the-Middle (MITM) attack on DH?

**A:** Mallory sits between Alice and Bob and intercepts their public values.  
Instead of forwarding `A` and `B`, she conducts two independent DH sessions:
- Mallory ↔ Alice: they agree on secret `s1`.
- Mallory ↔ Bob: they agree on secret `s2`.

Alice thinks `s1` is shared with Bob; Bob thinks `s2` is shared with Alice.
Mallory knows both and can decrypt, read, modify, and re-encrypt all traffic.

---

## Q11. How do you defend against MITM in DH?

**A:** **Authenticate the public values.** Options:
1. **Signed DH**: Both parties sign their public values with a long-term identity key (RSA/ECDSA). The other party verifies the signature using a pre-shared public key.
2. **Certificates (TLS)**: Public DH values are signed by a Certificate Authority; the browser checks the certificate chain.
3. **Station-to-Station (STS) Protocol**: Extends DH with mutual authentication using digital signatures.

---

## Q12. What is a safe prime, and why is it used?

**A:** A prime `p = 2q + 1` where `q` is also prime (a *Sophie Germain prime*).
For safe primes, `p−1 = 2q` has only two prime factors, which:
1. Makes the primitive-root check very fast (only 2 factors to test).
2. Prevents **small-subgroup attacks** — Z_p\* has no small subgroups (only orders 1, 2, q, 2q).

---

## Q13. What is a small-subgroup attack?

**A:** If `g` has a small order `q` (i.e., `g^q ≡ 1 mod p` with `q` small), then
`g^a` takes only `q` values. An attacker can brute-force all `q` values to find
`a`. To defend: use a generator of full order `p−1` (primitive root) or a
safe prime, and validate received public values.

---

## Q14. What is the Miller-Rabin primality test?

**A:** A probabilistic test for primality based on properties of square roots of
unity modulo a prime. It writes `n−1 = 2^r × d` (d odd) and checks multiple
"witnesses" `a`. If `n` is composite, Miller-Rabin detects it with probability
≥ 3/4 per witness. With 20 witnesses, error probability < 4^{-20} ≈ 10^{-12}.

---

## Q15. What is the difference between DH and RSA?

**A:**
| | DH | RSA |
|-|----|----|
| Purpose | Key agreement | Encryption + Digital signatures |
| Security basis | DLP (discrete log mod p) | Integer factorization |
| Parties produce | Shared secret | Public/private keypair |
| Transmission | Public values A, B | Ciphertext or signature |

Both are public-key techniques, but DH doesn't encrypt or sign — it only agrees on a key.

---

## Q16. What key sizes does NIST recommend for DH?

**A:**
- **Minimum (2024):** 2048-bit prime (≈ 112-bit symmetric security)
- **Recommended:** 3072 bits (≈ 128-bit) or 4096 bits (≈ 140-bit)
- **Deprecated:** 1024 bits (≤ 80-bit security — broken by nation-state attackers)

Source: NIST SP 800-57, RFC 7919.

---

## Q17. What is ECDH, and how does it differ from DH?

**A:** **Elliptic Curve Diffie-Hellman** replaces the multiplicative group `Z_p*`
with the group of points on an elliptic curve over a finite field. The DLP on
elliptic curves is believed to be harder, so:
- **256-bit ECDH** ≈ **3072-bit DH** in security level.
- ECDH keys are much smaller and operations are faster.
- Used in modern TLS (ECDHE), Signal, and SSH.

---

## Q18. Why do we hash the shared secret with SHA-256 before using it?

**A:** The raw DH shared secret `g^(ab) mod p` may be **biased** (e.g., it's
always in `{1,…,p−1}` and has specific structure). Hashing it with SHA-256
(a KDF step) produces a **uniformly distributed**, fixed-size key suitable for
use with symmetric ciphers. This also provides domain separation if the same
DH value is used for multiple purposes.

---

## Q19. What is forward secrecy (Perfect Forward Secrecy)?

**A:** A property of key-exchange protocols where **past session keys cannot be
compromised** even if long-term private keys are later exposed.

DH achieves forward secrecy when fresh (ephemeral) private keys `a` and `b` are
generated for every session (called **DHE** — ephemeral DH). If the server's
long-term key is stolen in the future, recorded past sessions remain protected
because each session used a different random `a`.

---

## Q20. What happens in the network demo, and what does it demonstrate?

**A:** `alice.py` (Laptop 1 / server) and `bob.py` (Laptop 2 / client) communicate over real TCP sockets using 4-byte length-prefixed JSON messages:
1. Bob connects and sends `{"type":"hello","from":"Bob"}`.
2. Alice sends `{"type":"params","p":p,"g":g}` (Bob verifies $p$ is prime and $g$ is in range).
3. Each side independently picks private key $a$ or $b$ (kept secret).
4. Alice sends $A = g^a \pmod p$; Bob sends $B = g^b \pmod p$.
5. Both compute $s$ locally ($s = B^a \pmod p = A^b \pmod p$).
6. Both derive a 256-bit SHA-256 key and exchange a short confirmation fingerprint (`MATCH`).
7. Both exchange end-to-end encrypted chat messages over the socket.

Both screens display **MATCH**, demonstrating that real DH over a physical network establishes identical shared keys without ever transmitting private keys or the secret.

---

## Q21. Why is TCP used instead of UDP for the Diffie-Hellman key exchange?

**A:** TCP provides **reliable, in-order, connection-oriented byte stream delivery**:
1. **Guaranteed Delivery:** If a single parameter ($p, g$) or public key ($A, B$) is dropped or corrupted on the network, the mathematical modular exponentiation will compute a completely wrong secret, breaking the exchange.
2. **Strict In-Order Sequencing:** DH is a stateful multi-step handshake (Parameters $\rightarrow$ Keys $\rightarrow$ Secrets $\rightarrow$ Confirmation). Packet reordering in UDP would cause out-of-order state failures.
3. **Stream Framing:** Our 4-byte length header ensures complete message reassembly across IP packets regardless of network MTU.

---

## Q22. Exactly what values travel over the network wire, and what values are NEVER sent?

**A:**
- **Values sent over the wire (Public Channel):**
  - Protocol greetings (`{"type":"hello"}`)
  - Public modulus $p$ and generator $g$ (`{"type":"params"}`)
  - Public keys $A = g^a \pmod p$ and $B = g^b \pmod p$ (`{"type":"public"}`)
  - Short 8-character confirmation fingerprints (`{"type":"confirm"}`)
  - Encrypted message ciphertexts (`{"type":"chat"}`)
- **Values NEVER sent over the wire (Private / Secret):**
  - Alice's private key $a$
  - Bob's private key $b$
  - The shared secret $s = g^{ab} \pmod p$
  - The derived 256-bit symmetric encryption key $K$

---

## Q23. What does a passive eavesdropper (Eve) sniffing Wi-Fi packets see? Can she decrypt the chat?

**A:** When running a Wi-Fi packet sniffer (like Wireshark or our `network_demo/eve_sniffer.py`), Eve intercepts all plaintext JSON packets. She sees:
- $p$, $g$, $A$, and $B$
- The confirmation fingerprint
- The raw hexadecimal ciphertext of each chat message (e.g. `b00b84b7...`)

**Can Eve decrypt the chat? No.**  
To decrypt the chat, Eve needs key $K = \text{SHA-256}(s)$.  
To compute $s = g^{ab} \pmod p$, Eve must find $a$ or $b$ from the captured values $A = g^a \pmod p$ and $B = g^b \pmod p$. This is the **Discrete Logarithm Problem (DLP)**, which is computationally infeasible for large prime moduli.

---

## Q24. Why do Alice and Bob send a short key fingerprint (hash) during key confirmation instead of the key itself?

**A:** If Alice or Bob transmitted the symmetric key $K$ over the network to check for a match, Eve would simply intercept $K$ and decrypt all traffic, defeating the entire purpose of Diffie-Hellman!

Instead, both parties compute a one-way cryptographic hash:
$$\text{Fingerprint} = \text{SHA-256}(K)[:8]$$
Because cryptographic hash functions are **pre-image resistant (one-way)**, Eve cannot invert the fingerprint to discover $K$. However, Alice and Bob can compare fingerprints to confirm that both parties arrived at the exact same key before transmitting encrypted data.

---

## Q25. How would a Man-in-the-Middle (MITM) attack work on this two-laptop setup, and how do real-world systems prevent it?

**A:**
1. **How MITM works:** An attacker (Mallory) sitting between Alice and Bob (demonstrated by `eve_sniffer.py --mitm`) intercepts Alice's public key $A$ and Bob's public key $B$, replacing them with Mallory's own public key $M = g^m \pmod p$.
   - Alice computes shared secret $s_1 = M^a \pmod p$ (shared with Mallory).
   - Bob computes shared secret $s_2 = M^b \pmod p$ (shared with Mallory).
   - Mallory decrypts Alice's messages with $s_1$, tampers with or reads them, re-encrypts with $s_2$, and forwards them to Bob. Neither party realizes their messages are being intercepted.
2. **How real-world systems prevent it:** Unauthenticated Diffie-Hellman is inherently vulnerable to MITM. Real-world systems use **Authenticated DH**:
   - **TLS / HTTPS:** The server signs its ephemeral DH public key with an RSA or ECDSA private key certified by a trusted Certificate Authority (CA).
   - **SSH:** Uses host keys stored in `~/.ssh/known_hosts` to authenticate the server's public key.
   - **Signal / WhatsApp:** Uses long-term Identity Keys and Safety Number verification (comparing QR codes / fingerprints out-of-band).

---

*"The most beautiful thing in cryptography is that you can share a secret
without ever actually sharing it." — paraphrase of Diffie & Hellman's insight.*


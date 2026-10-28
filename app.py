"""
app.py – Streamlit UI for Diffie-Hellman Key Exchange Demo
===========================================================
Run with:
    streamlit run app.py

Features
--------
* Three-column layout: Alice | Public Channel | Bob
* Color coding: green = public, red = private
* Step-by-step navigation with "Next Step" button
* Square-and-multiply trace toggle (for small inputs)
* Eve brute-force demo with timing graph
* Man-in-the-Middle demo
* KDF + XOR encryption proof
* Network demo instructions
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path
import streamlit as st

# ── Ensure project root is on path ──────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dh.protocol import DHProtocol, DHMode, TEXTBOOK_P, TEXTBOOK_G, TEXTBOOK_A, TEXTBOOK_B
from dh.attacks import Eve, Mallory, timing_attack_benchmark
from dh.kdf import derive_key, xor_encrypt, xor_decrypt, fingerprint
from dh.math_utils import (
    mod_exp_steps, miller_rabin_is_prime, is_primitive_root,
    _factorize_p_minus_1, generate_prime, generate_safe_prime, find_primitive_root,
)
from dh.party import Party
from dh.transport import get_lan_ips, send_msg, recv_msg, compute_key_fingerprint

# ──────────────────────────────────────────────────────────────────────────────
# Page config
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DH Key Exchange – VTU CNS Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# Custom CSS
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}
code, .mono {
    font-family: 'JetBrains Mono', monospace;
}

/* Gradient header */
.dh-header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 40%, #0f3460 100%);
    padding: 1.2rem 1.8rem;
    border-radius: 14px;
    margin-bottom: 1rem;
    border: 1px solid rgba(99,179,237,0.25);
    box-shadow: 0 6px 24px rgba(0,0,0,0.35);
}
.dh-header h1 {
    color: #63b3ed;
    font-size: 1.7rem;
    font-weight: 700;
    margin: 0;
}
.dh-header p {
    color: #a0aec0;
    margin: 0.3rem 0 0;
    font-size: 0.95rem;
}

/* Party cards */
.party-card {
    border-radius: 12px;
    padding: 1rem 1.1rem;
    margin-bottom: 0.8rem;
    border: 1px solid;
    line-height: 1.45;
}
.alice-card {
    background: linear-gradient(135deg, #1a2744 0%, #162132 100%);
    border-color: rgba(72,187,120,0.4);
}
.bob-card {
    background: linear-gradient(135deg, #1a2440 0%, #162030 100%);
    border-color: rgba(99,179,237,0.4);
}
.channel-card {
    background: linear-gradient(135deg, #2d2d1a 0%, #1e1e12 100%);
    border-color: rgba(237,211,99,0.4);
}

/* Value badges */
.public-val {
    display: inline-block;
    background: rgba(72,187,120,0.15);
    border: 1px solid rgba(72,187,120,0.5);
    color: #68d391;
    padding: 3px 10px;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9em;
    font-weight: 600;
}
.private-val {
    display: inline-block;
    background: rgba(245,101,101,0.15);
    border: 1px solid rgba(245,101,101,0.5);
    color: #fc8181;
    padding: 3px 10px;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9em;
    font-weight: 600;
}

/* Step log */
.step-entry {
    background: rgba(255,255,255,0.03);
    border-left: 3px solid;
    padding: 0.8rem 1rem;
    margin: 0.4rem 0;
    border-radius: 0 8px 8px 0;
}
.step-alice { border-color: #48bb78; }
.step-bob   { border-color: #63b3ed; }
.step-channel { border-color: #ecc94b; }
.step-system  { border-color: #a0aec0; }
.step-mallory { border-color: #fc8181; }

.step-actor {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    opacity: 0.7;
}
.step-action {
    font-size: 0.95rem;
    font-weight: 600;
    color: #e2e8f0;
}
.step-detail {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    color: #a0aec0;
    white-space: pre-wrap;
    margin-top: 0.3rem;
}

/* Success / failure banners */
.success-banner {
    background: linear-gradient(135deg, rgba(72,187,120,0.2), rgba(72,187,120,0.05));
    border: 1px solid rgba(72,187,120,0.5);
    border-radius: 12px;
    padding: 1rem 1.5rem;
    text-align: center;
    font-size: 1.2rem;
    font-weight: 700;
    color: #68d391;
}
.fail-banner {
    background: linear-gradient(135deg, rgba(245,101,101,0.2), rgba(245,101,101,0.05));
    border: 1px solid rgba(245,101,101,0.5);
    border-radius: 12px;
    padding: 1rem 1.5rem;
    text-align: center;
    font-size: 1.2rem;
    font-weight: 700;
    color: #fc8181;
}

/* Formula box */
.formula-box {
    background: rgba(99,179,237,0.08);
    border: 1px solid rgba(99,179,237,0.25);
    border-radius: 8px;
    padding: 0.8rem 1.2rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.88rem;
    color: #bee3f8;
    margin: 0.5rem 0;
}

/* Attack warning */
.attack-warning {
    background: linear-gradient(135deg, rgba(245,101,101,0.15), rgba(245,101,101,0.05));
    border: 1px solid rgba(245,101,101,0.4);
    border-radius: 12px;
    padding: 1rem 1.5rem;
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def pub(v) -> str:
    """Render value as green public badge."""
    return f'<span class="public-val">{v}</span>'

def priv(v) -> str:
    """Render value as red private badge."""
    return f'<span class="private-val">{v}</span>'

def formula(text: str) -> str:
    return f'<div class="formula-box">{text}</div>'

def render_step(entry: dict, show_private: bool = False) -> str:
    actor = entry["actor"]
    cls_map = {
        "Alice": "step-alice",
        "Bob": "step-bob",
        "Public Channel": "step-channel",
        "System": "step-system",
        "Mallory": "step-mallory",
        "Mallory→Alice": "step-mallory",
        "Mallory→Bob": "step-mallory",
    }
    cls = cls_map.get(actor, "step-system")
    detail = entry["detail"]
    if not show_private and "private key" in entry["action"].lower():
        detail = "🔒 [Hidden – reveal with sidebar toggle]"
    return f"""
    <div class="step-entry {cls}">
        <div class="step-actor">{entry['step']:02d} · {actor}</div>
        <div class="step-action">{entry['action']}</div>
        <div class="step-detail">{detail}</div>
    </div>"""


def render_summary_table(proto: DHProtocol, reveal: bool) -> None:
    tbl = proto.summary_table()
    rows = []
    for k, v in tbl.items():
        is_priv = "private" in k.lower() or "secret" in k.lower()
        display = str(v) if reveal or not is_priv else "🔒 Hidden"
        color = "#fc8181" if is_priv else "#68d391"
        rows.append({"Parameter": k, "Value": display, "_color": color, "_priv": is_priv})

    import pandas as pd
    df = pd.DataFrame(rows)[["Parameter", "Value"]]
    st.dataframe(df, use_container_width=True, hide_index=True)


# ──────────────────────────────────────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## ⚙️ Configuration")

    demo_tab = st.radio("Demo Mode", [
        "🔑 Key Exchange",
        "🕵️ Eve (Eavesdropper)",
        "🦹 Man-in-the-Middle",
        "🌐 Network Demo",
        "📚 About / Theory",
    ])

    st.markdown("---")

    mode_label = st.selectbox("Parameter Mode", [
        "Textbook Preset (p=23, g=5)",
        "Manual Input",
        "Auto-Generate",
    ])

    if "Auto" in mode_label:
        bits = st.select_slider("Prime Bit Size", [16, 32, 64, 128, 256, 512, 1024], value=64)
        use_safe = st.checkbox("Use Safe Prime (p=2q+1)", value=True)
    elif "Manual" in mode_label:
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            manual_p = st.number_input("Prime (p)", value=23, min_value=5, step=2,
                                       help="Diffie-Hellman requires a prime number")
        with col_m2:
            manual_g = st.number_input("Generator (g)", value=5, min_value=2,
                                       help="Generator or primitive root mod p (2 ≤ g ≤ p-2)")

        p_int = int(manual_p)
        g_int = int(manual_g)
        is_p_prime = miller_rabin_is_prime(p_int)
        if not is_p_prime:
            st.error(f"❌ p={p_int} is NOT prime! (Try 23, 29, 31, 47, 59...)")
        else:
            factors = _factorize_p_minus_1(p_int)
            is_g_prim = is_primitive_root(g_int, p_int, factors) if (2 <= g_int <= p_int - 2) else False
            if is_g_prim:
                st.caption(f"✅ Prime p={p_int} & g={g_int} is a primitive root")
            elif 2 <= g_int <= p_int - 2:
                st.caption(f"ℹ️ Prime p={p_int}; g={g_int} is valid (subgroup order < p-1)")
            else:
                st.error(f"❌ g must be between 2 and {p_int - 2}")

        st.markdown("**Enter Your Own Private Keys:**")
        max_k = max(2, p_int - 2)
        col_k1, col_k2 = st.columns(2)
        with col_k1:
            manual_a = st.number_input(
                "Alice's private (a)",
                value=2,
                min_value=0,
                max_value=max_k,
                help=f"Secret key chosen by Alice (2 ≤ a ≤ {max_k}, or 0 for random)",
            )
        with col_k2:
            manual_b = st.number_input(
                "Bob's private (b)",
                value=5,
                min_value=0,
                max_value=max_k,
                help=f"Secret key chosen by Bob (2 ≤ b ≤ {max_k}, or 0 for random)",
            )
        st.caption(f"🔑 Valid private key range: **2 ≤ key ≤ {max_k}** (0 = random)")

    st.markdown("---")
    reveal = st.checkbox("🔓 Reveal Private Keys", value=True)
    show_steps = st.checkbox("📐 Show Square-and-Multiply Steps", value=False)

    st.markdown("---")
    if st.button("🔄 Run / Re-run Exchange", use_container_width=True, type="primary"):
        st.cache_data.clear()
        for k in list(st.session_state.keys()):
            if k.startswith("dh_"):
                del st.session_state[k]
        st.rerun()

    st.markdown("---")
    st.markdown("**VTU CNS – Cryptography & Network Security**\n\nDH Key Exchange Demo\n\n*Standard library only*")


# ──────────────────────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="dh-header">
    <h1>🔐 Diffie-Hellman Key Exchange</h1>
    <p>Interactive simulation — Alice & Bob establish a shared secret over a public channel</p>
</div>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Helper: build protocol (runs synchronously on every input change, no stale cache)
# ──────────────────────────────────────────────────────────────────────────────

def build_and_run_proto(mode_label: str, bits: int = 64, use_safe: bool = True,
                        p: int = 23, g: int = 5, a: int = 0, b: int = 0) -> DHProtocol:
    """Build and run the DH protocol with given parameters."""
    if "Textbook" in mode_label:
        proto = DHProtocol(DHMode.TEXTBOOK)
    elif "Auto" in mode_label:
        proto = DHProtocol(DHMode.AUTO, bits=bits, use_safe_prime=use_safe)
    else:
        pa = int(a) if (a is not None and int(a) > 0) else None
        pb = int(b) if (b is not None and int(b) > 0) else None
        proto = DHProtocol(DHMode.MANUAL, p=int(p), g=int(g),
                           alice_private=pa, bob_private=pb)
    proto.run()
    return proto


# ──────────────────────────────────────────────────────────────────────────────
# TAB: Key Exchange
# ──────────────────────────────────────────────────────────────────────────────

if demo_tab == "🔑 Key Exchange":

    # Validate p before running in Manual mode
    if "Manual" in mode_label and not miller_rabin_is_prime(int(manual_p)):
        st.error(f"❌ Cannot run exchange: p={manual_p} is not a prime number. Diffie-Hellman requires a prime modulus.")
        st.info("💡 Try entering a prime number such as 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 71, 73, 79, 83, 89, 97, 101, 353, etc.")
        st.stop()

    # Build protocol
    with st.spinner("Computing DH exchange…"):
        try:
            if "Auto" in mode_label:
                proto = build_and_run_proto(mode_label, bits=bits, use_safe=use_safe)
            elif "Manual" in mode_label:
                proto = build_and_run_proto(
                    mode_label,
                    p=int(manual_p),
                    g=int(manual_g),
                    a=int(manual_a),
                    b=int(manual_b),
                )
            else:
                proto = build_and_run_proto(mode_label)
        except ValueError as e:
            st.error(f"❌ Validation error: {e}")
            st.stop()
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")
            st.stop()

    alice = proto.alice  # type: ignore
    bob   = proto.bob    # type: ignore
    p, g  = proto.p, proto.g
    s_val = alice.shared_secret if alice else 0

    # ── Result banner ────────────────────────────────────────────────
    if proto.success:
        st.markdown(f"""
        <div class="success-banner" style="padding: 1rem 1.4rem; margin-bottom: 1.2rem;">
            <div style="font-size: 1.35rem; margin-bottom: 0.35rem;">
                🎉 Shared Secret Established: <span style="background: rgba(72,187,120,0.3); border: 1px solid #48bb78; color: #fff; padding: 3px 16px; border-radius: 8px; font-family: monospace; font-size: 1.15em;">s = {s_val}</span>
            </div>
            <div style="font-size: 0.95rem; font-weight: 500; opacity: 0.95; color: #bee3f8;">
                👩 Alice: <code>{bob.public_key}^{alice.private_key} mod {p} = {s_val}</code> &nbsp; │ &nbsp;
                👨 Bob: <code>{alice.public_key}^{bob.private_key} mod {p} = {s_val}</code> &nbsp; │ &nbsp;
                <b style="color: #68d391;">✅ Both parties computed the same shared key!</b>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="fail-banner">❌ Mismatch — something went wrong!</div>', unsafe_allow_html=True)
    st.markdown("")

    # ── Three-column layout ──────────────────────────────────────────
    col_alice, col_channel, col_bob = st.columns([2, 2, 2])

    with col_alice:
        st.markdown(f"""
        <div class="party-card alice-card">
            <h3 style="color:#68d391;margin:0 0 0.6rem">👩 Alice</h3>
            <b>Agreed Parameters:</b><br>
            p = {pub(p)}, &nbsp; g = {pub(g)}<br><br>
            <b>Alice's Secret Private Key (a):</b><br>
            a = {priv(alice.private_key) if reveal else '<span class="private-val">🔒 Hidden</span>'}<br><br>
            <b>Public Key (A = g<sup>a</sup> mod p):</b><br>
            A = {g}<sup>{alice.private_key if reveal else 'a'}</sup> mod {p} = {pub(alice.public_key)}<br><br>
            <b>Received from Bob (B):</b><br>
            B = {pub(alice.received_public)}<br><br>
            <b>Shared Secret (s = B<sup>a</sup> mod p):</b><br>
            s = {alice.received_public}<sup>{alice.private_key if reveal else 'a'}</sup> mod {p} = {pub(alice.shared_secret)}
        </div>
        """, unsafe_allow_html=True)

    with col_channel:
        st.markdown(f"""
        <div class="party-card channel-card">
            <h3 style="color:#ecc94b;margin:0 0 0.6rem">📡 Public Channel (Insecure)</h3>
            <b>Agreed Parameters:</b><br>
            p = {pub(p)}, &nbsp; g = {pub(g)}<br><br>
            <b>Exchanged Public Keys:</b><br>
            Alice → Bob: &nbsp; A = {pub(alice.public_key)}<br>
            Bob → Alice: &nbsp; B = {pub(bob.public_key)}<br><br>
            <hr style="border-color:rgba(255,255,255,0.15); margin: 0.8rem 0;">
            <b style="color:#fc8181">🕵️ Eve (Eavesdropper) View:</b><br>
            <small style="color:#cbd5e0; line-height: 1.4; display: inline-block;">
            Eve sees: <code>p={p}, g={g}, A={alice.public_key}, B={bob.public_key}</code><br>
            Eve CANNOT see: <code>a={alice.private_key if reveal else '?'}, b={bob.private_key if reveal else '?'}</code><br>
            Eve cannot compute <code>s = {s_val}</code> without solving DLP!
            </small>
        </div>
        """, unsafe_allow_html=True)

    with col_bob:
        st.markdown(f"""
        <div class="party-card bob-card">
            <h3 style="color:#63b3ed;margin:0 0 0.6rem">👨 Bob</h3>
            <b>Agreed Parameters:</b><br>
            p = {pub(p)}, &nbsp; g = {pub(g)}<br><br>
            <b>Bob's Secret Private Key (b):</b><br>
            b = {priv(bob.private_key) if reveal else '<span class="private-val">🔒 Hidden</span>'}<br><br>
            <b>Public Key (B = g<sup>b</sup> mod p):</b><br>
            B = {g}<sup>{bob.private_key if reveal else 'b'}</sup> mod {p} = {pub(bob.public_key)}<br><br>
            <b>Received from Alice (A):</b><br>
            A = {pub(bob.received_public)}<br><br>
            <b>Shared Secret (s = A<sup>b</sup> mod p):</b><br>
            s = {bob.received_public}<sup>{bob.private_key if reveal else 'b'}</sup> mod {p} = {pub(bob.shared_secret)}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # ── Summary table ────────────────────────────────────────────────
    with st.expander("📊 Summary Table", expanded=True):
        render_summary_table(proto, reveal)

    # ── Step-by-step log ─────────────────────────────────────────────
    st.markdown("### 📋 Step-by-Step Protocol Log")
    step_mode = st.radio("Display mode", ["Show all steps", "Step navigator"], horizontal=True)

    if step_mode == "Show all steps":
        for entry in proto.log:
            st.markdown(render_step(entry, reveal), unsafe_allow_html=True)
    else:
        total_steps = len(proto.log)
        if "step_idx" not in st.session_state:
            st.session_state.step_idx = 0

        c1, c2, c3 = st.columns([1, 2, 1])
        with c1:
            if st.button("⬅ Prev") and st.session_state.step_idx > 0:
                st.session_state.step_idx -= 1
        with c2:
            st.markdown(f"<center>Step {st.session_state.step_idx+1} / {total_steps}</center>",
                        unsafe_allow_html=True)
        with c3:
            if st.button("Next ➡") and st.session_state.step_idx < total_steps - 1:
                st.session_state.step_idx += 1

        st.markdown(render_step(proto.log[st.session_state.step_idx], reveal),
                    unsafe_allow_html=True)

    # ── Square-and-multiply trace ─────────────────────────────────────
    if show_steps and alice:
        st.markdown("---")
        st.markdown("### 🔢 Square-and-Multiply Trace")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Alice: computing A = g^a mod p**")
            steps_a = mod_exp_steps(g, alice.private_key, p)
            for s in steps_a[:20]:
                st.markdown(f"`Step {s['step']}` — {s['description']}")
            if len(steps_a) > 20:
                st.caption(f"… {len(steps_a)-20} more steps (binary exponent is large)")
        with col2:
            st.markdown("**Alice: computing s = B^a mod p**")
            if alice.received_public:
                steps_s = mod_exp_steps(alice.received_public, alice.private_key, p)
                for s in steps_s[:20]:
                    st.markdown(f"`Step {s['step']}` — {s['description']}")

    # ── KDF + Encrypted Chat Demo ─────────────────────────────────────
    st.markdown("---")
    st.markdown("### 💬 End-to-End Encrypted Chat: What Does the Shared Key Do?")
    st.markdown("""
    **Crucial Concept:** Diffie-Hellman is a **Key Exchange** protocol, *not* an encryption algorithm.  
    It computes a shared number $s$. To actually send messages, Alice and Bob use **Hybrid Cryptography**:
    1. **Key Derivation (KDF):** Feed the shared integer $s$ into a cryptographic hash (SHA-256) to produce a 256-bit symmetric key $K$.
    2. **Symmetric Encryption:** Use key $K$ with a fast cipher (AES in TLS/HTTPS; XOR in this demo) to encrypt and decrypt chat messages.
    """)

    s_val = alice.shared_secret if alice else 0
    demo_key = derive_key(s_val)
    demo_fp  = fingerprint(demo_key)

    col_k1, col_k2 = st.columns([1, 1])
    with col_k1:
        st.markdown(f"""
        <div style="background:rgba(99,179,237,0.1); border:1px solid rgba(99,179,237,0.3); border-radius:10px; padding:0.9rem;">
            <b>🔑 Derived Symmetric Key (K):</b><br>
            <code>K = SHA-256( s = {s_val} )</code><br>
            <small style="color:#a0aec0">Full 256-bit key (hex):</small><br>
            <code style="word-break:break-all; font-size:0.85em;">{demo_key.hex()}</code><br>
            <b>Fingerprint:</b> <code>{demo_fp}</code>
        </div>
        """, unsafe_allow_html=True)
    with col_k2:
        st.markdown("""
        <div style="background:rgba(72,187,120,0.1); border:1px solid rgba(72,187,120,0.3); border-radius:10px; padding:0.9rem;">
            <b>🛡️ Why This Is Secure:</b><br>
            • Both Alice and Bob hold key $K$ without ever sending $K$ over the network.<br>
            • Eve intercepts only ciphertext on the public channel.<br>
            • Without the secret $s$, Eve cannot derive $K$ or decrypt any message!
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")
    chat_col1, chat_col2 = st.columns(2)

    with chat_col1:
        st.markdown("#### 👩 Alice ➡️ Bob")
        alice_msg = st.text_input("Alice types a message:", value="Meet me at 5 PM! DH works 🔐", key="alice_chat_input")
        if alice_msg:
            a_bytes = alice_msg.encode()
            a_ct = xor_encrypt(demo_key, a_bytes)
            a_pt = xor_decrypt(demo_key, a_ct).decode("utf-8", errors="replace")
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.03); border-left:3px solid #48bb78; padding:0.6rem 0.8rem; border-radius:4px; font-size:0.9rem;">
                <b>Plaintext:</b> "{alice_msg}"<br>
                <b>Ciphertext on wire:</b> <code style="word-break:break-all;">{a_ct.hex()}</code><br>
                <b>👨 Bob decrypts:</b> <span style="color:#68d391; font-weight:600;">"{a_pt}"</span> ✅
            </div>
            """, unsafe_allow_html=True)

    with chat_col2:
        st.markdown("#### 👨 Bob ➡️ Alice (Reply)")
        bob_msg = st.text_input("Bob types a reply:", value="Got it! Secure tunnel active 🚀", key="bob_chat_input")
        if bob_msg:
            b_bytes = bob_msg.encode()
            b_ct = xor_encrypt(demo_key, b_bytes)
            b_pt = xor_decrypt(demo_key, b_ct).decode("utf-8", errors="replace")
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.03); border-left:3px solid #63b3ed; padding:0.6rem 0.8rem; border-radius:4px; font-size:0.9rem;">
                <b>Plaintext:</b> "{bob_msg}"<br>
                <b>Ciphertext on wire:</b> <code style="word-break:break-all;">{b_ct.hex()}</code><br>
                <b>👩 Alice decrypts:</b> <span style="color:#63b3ed; font-weight:600;">"{b_pt}"</span> ✅
            </div>
            """, unsafe_allow_html=True)

    st.markdown("")
    with st.expander("🕵️ What does Eve see on the public channel? (Click to inspect)", expanded=False):
        st.markdown(f"""
        Eve is listening on the public network wires between Alice and Bob. Here is **all** Eve sees:
        - Packet 1 (Alice public key): `A = {alice.public_key}`
        - Packet 2 (Bob public key): `B = {bob.public_key}`
        - Packet 3 (Alice's message): `{xor_encrypt(demo_key, alice_msg.encode()).hex() if alice_msg else ''}`
        - Packet 4 (Bob's reply): `{xor_encrypt(demo_key, bob_msg.encode()).hex() if bob_msg else ''}`

        *Notice: Eve sees purely random-looking hexadecimal garbage. Without private key $a$ or $b$, she cannot calculate $s={s_val}$ and cannot decrypt either message!*
        """)


# ──────────────────────────────────────────────────────────────────────────────
# TAB: Eve (Eavesdropper)
# ──────────────────────────────────────────────────────────────────────────────

elif demo_tab == "🕵️ Eve (Eavesdropper)":
    st.markdown("## 🕵️ Eve: Passive Eavesdropper")
    st.markdown("""
    Eve sits on the public channel and observes **p, g, A, B**.  
    She must solve the **Discrete Logarithm Problem (DLP)**: find *a* such that `g^a ≡ A (mod p)`.  
    For small *p* this is feasible by brute force. For large *p* it becomes computationally infeasible.
    """)

    col_ev1, col_ev2 = st.columns([1, 1])
    with col_ev1:
        eve_bits = st.slider("Eve's target prime bit size", 8, 28, 16, step=4)
    with col_ev2:
        eve_timeout = st.number_input("Brute-force timeout (seconds)", value=5.0, min_value=0.5)

    if st.button("🔍 Run Eve's Attack", type="primary"):
        with st.spinner("Running DH exchange and Eve's brute force…"):
            # Run a fresh exchange
            proto_eve = DHProtocol(DHMode.AUTO, bits=eve_bits, use_safe_prime=False)
            proto_eve.run()
            p_e, g_e = proto_eve.p, proto_eve.g
            alice_e = proto_eve.alice
            bob_e   = proto_eve.bob

            st.markdown("**Public channel contents:**")
            st.markdown(f"""
            | p | g | A (Alice's public) | B (Bob's public) |
            |---|---|--------------------|-----------------|
            | `{p_e}` | `{g_e}` | `{alice_e.public_key}` | `{bob_e.public_key}` |
            """)

            eve = Eve(p_e, g_e, alice_e.public_key, timeout_seconds=eve_timeout)
            t0 = time.perf_counter()
            result = eve.brute_force(big_b=bob_e.public_key)
            elapsed = time.perf_counter() - t0

            if result["success"]:
                st.markdown(f"""
                <div class="attack-warning">
                    <b style="color:#fc8181">⚠️ Eve cracked DH!</b><br>
                    Found <b>a = {result['recovered_a']}</b> in 
                    <b>{result['elapsed_ms']:.1f} ms</b> 
                    ({result['iterations']:,} iterations).<br>
                    Recovered shared secret = <b>{result['recovered_secret']}</b><br>
                    Actual shared secret   = <b>{alice_e.shared_secret}</b><br>
                    Match: {'✅' if result['recovered_secret'] == alice_e.shared_secret else '❌'}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.success(
                    f"✅ Eve timed out after {result['elapsed_ms']:.0f} ms "
                    f"({result['iterations']:,} iterations) — DLP is hard for {eve_bits}-bit p!"
                )

    # ── Infeasibility graph ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📈 Brute-Force Time vs. Prime Bit Size")
    st.caption("Click to run benchmark (small sizes; larger sizes extrapolated).")

    if st.button("📊 Run Benchmark", key="bench_btn"):
        with st.spinner("Benchmarking…"):
            bench_sizes = [8, 10, 12, 14, 16, 18, 20]
            bench_results = timing_attack_benchmark(bench_sizes, timeout=2.0)

        try:
            import pandas as pd
            df = pd.DataFrame(bench_results)
            df["time_s"] = df["elapsed_ms"] / 1000
            df["label"] = df.apply(
                lambda r: f"{r['elapsed_ms']:.1f} ms {'(timeout)' if r['timed_out'] else ''}",
                axis=1,
            )
            st.markdown("**Benchmark results:**")
            st.dataframe(df[["bits", "elapsed_ms", "iterations", "timed_out"]],
                         use_container_width=True, hide_index=True)

            # Use st.line_chart
            chart_data = df.set_index("bits")[["elapsed_ms"]]
            st.line_chart(chart_data, y="elapsed_ms", x_label="Prime bit size",
                         y_label="Time (ms)")

            st.info(
                "📌 Key insight: brute-force DLP time grows **exponentially** with bit size. "
                "NIST recommends ≥ 2048 bits for production DH — completely infeasible to brute-force."
            )
        except ImportError:
            st.warning("pandas not installed; table display skipped. Install with: pip install pandas")
            for r in bench_results:
                st.write(r)


# ──────────────────────────────────────────────────────────────────────────────
# TAB: Man-in-the-Middle
# ──────────────────────────────────────────────────────────────────────────────

elif demo_tab == "🦹 Man-in-the-Middle":
    st.markdown("## 🦹 Man-in-the-Middle Attack (Mallory)")
    st.markdown("""
    Mallory intercepts the public channel and performs **two independent DH exchanges**:
    - **Mallory ↔ Alice** (Mallory pretends to be Bob)  
    - **Mallory ↔ Bob** (Mallory pretends to be Alice)  

    Result: Alice and Bob believe they have a shared secret, but each actually shares a *different* 
    secret with Mallory. Mallory can read, modify, and re-encrypt all traffic.

    **Fix:** Authenticate public keys with digital signatures or certificates (e.g., TLS certificates).
    """)

    mitm_bits = st.slider("Prime bit size for MITM demo", 8, 64, 16, step=8)

    if st.button("🦹 Run MITM Attack", type="primary"):
        with st.spinner("Simulating MITM…"):
            proto_m = DHProtocol(DHMode.AUTO, bits=mitm_bits, use_safe_prime=False)
            proto_m.run()
            p_m, g_m = proto_m.p, proto_m.g

            alice_m = Party("Alice", p_m, g_m)
            bob_m   = Party("Bob",   p_m, g_m)

            mallory = Mallory(p_m, g_m)
            result  = mallory.intercept_exchange(alice_m, bob_m)

        # Log
        st.markdown("### Attack Log")
        for entry in result["log"]:
            st.markdown(render_step(entry, reveal=True), unsafe_allow_html=True)

        # Summary
        st.markdown("---")
        st.markdown("### MITM Summary")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            **👩 Alice believes:**  
            Shared secret with "Bob":  
            `{result['alice_secret']}`
            """)
        with c2:
            st.markdown(f"""
            **🦹 Mallory knows:**  
            Key with Alice: `{result['mallory_s_alice']}`  
            Key with Bob:   `{result['mallory_s_bob']}`
            """)
        with c3:
            st.markdown(f"""
            **👨 Bob believes:**  
            Shared secret with "Alice":  
            `{result['bob_secret']}`
            """)

        if result["alice_secret"] != result["bob_secret"]:
            st.markdown("""
            <div class="fail-banner">
                ⚠️ MITM SUCCEEDED — Alice and Bob have DIFFERENT secrets!<br>
                Mallory decrypts Alice's messages with s1, re-encrypts with s2, forwards to Bob.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Keys coincidentally matched this run (very rare). Re-run for a clearer demo.")

        st.markdown("""
        ---
        ### 🛡️ Defence
        **Why plain DH fails against MITM:** DH only guarantees that two parties who *directly communicate* 
        derive the same secret. It provides **no authentication** — Mallory can substitute her own public values.

        **Fix:** Use **Authenticated DH** (e.g., sign public keys with long-term RSA/ECDSA keys), 
        or use **TLS certificates** which chain to a trusted Certificate Authority (CA).
        This is how HTTPS, Signal, and SSH defend against MITM.
        """)


# ──────────────────────────────────────────────────────────────────────────────
# TAB: Network Demo
# ──────────────────────────────────────────────────────────────────────────────

elif demo_tab == "🌐 Network Demo":
    st.markdown("## 🌐 Two-Laptop Network Demo (Real TCP Sockets)")
    st.markdown("""
    Demonstrate Diffie-Hellman Key Exchange across **two separate laptops** over a real local network (Wi-Fi or phone hotspot):
    - **Laptop 1 = Alice (TCP Server):** Binds to port `5000` and announces its LAN IP.
    - **Laptop 2 = Bob (TCP Client):** Connects to Alice's LAN IP and verifies public parameters.
    - **Framing:** 4-byte big-endian length header preceding UTF-8 JSON packets.
    """)

    role = st.radio("Select This Laptop's Role:", [
        "👩 Laptop 1: Alice (Server)",
        "👨 Laptop 2: Bob (Client)"
    ], horizontal=True)

    lan_ips = get_lan_ips()

    if "Alice" in role:
        st.markdown("### 👩 Laptop 1: Alice (Server)")
        col_a1, col_a2 = st.columns([1, 1])
        with col_a1:
            srv_port = st.number_input("Listen Port", value=5000, min_value=1024, max_value=65535, key="net_srv_port")
            preset_choice = st.checkbox("Use Textbook Preset (p=23, g=5, a=6)", value=True, key="net_alice_preset")
        with col_a2:
            st.markdown("**Detected Usable LAN IPv4 Address(es):**")
            if lan_ips:
                for ip in lan_ips:
                    st.code(f"python network_demo/bob.py --host {ip} --port {srv_port}", language="bash")
                st.caption("Tell Bob on Laptop 2 to run the command above!")
            else:
                st.warning("⚠️ No Wi-Fi LAN IP detected. Connect both laptops to the same Wi-Fi or phone hotspot.")

        st.markdown("""
        <div style="background:rgba(72,187,120,0.1); border:1px solid rgba(72,187,120,0.3); border-radius:10px; padding:0.9rem; margin-bottom:1rem;">
            <b>🖥️ Recommended: Run Live Terminal on Laptop 1:</b><br>
            <code>python network_demo/alice.py --port 5000 --preset</code>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚀 Listen for Bob (Wait for Connection – 20s timeout)", type="primary", key="alice_listen_btn"):
            with st.spinner(f"Alice listening on 0.0.0.0:{srv_port}... Tell Bob to connect now!"):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        srv.bind(("0.0.0.0", int(srv_port)))
                        srv.listen(1)
                        srv.settimeout(20.0)
                        conn, addr = srv.accept()
                        with conn:
                            # 1. Hello
                            hello = recv_msg(conn)
                            # 2. Params
                            p = TEXTBOOK_P if preset_choice else 23
                            g = TEXTBOOK_G if preset_choice else 5
                            send_msg(conn, {"type": "params", "p": p, "g": g})
                            # 3. Party
                            alice = Party("Alice", p, g, private_key=TEXTBOOK_A if preset_choice else None)
                            # 4. Exchange
                            send_msg(conn, {"type": "public", "name": "Alice", "value": alice.public_key})
                            b_msg = recv_msg(conn)
                            bob_val = b_msg["value"]
                            # 5. Shared secret
                            alice.receive_public_value(bob_val)
                            s = alice.compute_shared_secret()
                            key = derive_key(s)
                            fp = compute_key_fingerprint(key)
                            # 6. Confirm
                            send_msg(conn, {"type": "confirm", "fingerprint": fp})
                            c_msg = recv_msg(conn)
                            bob_fp = c_msg.get("fingerprint")
                            match = "✅ MATCH" if bob_fp == fp else "❌ MISMATCH"

                            st.success(f"✅ Bob connected from {addr[0]}:{addr[1]}! Handshake Completed.")
                            st.markdown(f"""
                            <div class="party-card alice-card">
                                <h3>👩 Alice's Side of the Exchange</h3>
                                <b>Parameters:</b> p={p}, g={g}<br>
                                <b>Alice's Private Key (a):</b> {priv(alice.private_key)}<br>
                                <b>Alice's Public Key (A):</b> {pub(alice.public_key)}<br>
                                <b>Received Bob's Public Key (B):</b> {pub(bob_val)}<br>
                                <b>Shared Secret:</b> <code>s = B^a mod p = {bob_val}^{alice.private_key} mod {p} = {s}</code><br>
                                <b>Derived Key Fingerprint:</b> <code>{fp}</code><br>
                                <b>Bob's Fingerprint:</b> <code>{bob_fp}</code> ({match})
                            </div>
                            """, unsafe_allow_html=True)
                except socket.timeout:
                    st.warning("⏱️ Listening timed out after 20 seconds. Ensure Bob ran his connection command!")
                except Exception as e:
                    st.error(f"❌ Server error: {e}")

    else:
        st.markdown("### 👨 Laptop 2: Bob (Client)")
        col_b1, col_b2 = st.columns([1, 1])
        with col_b1:
            target_ip = st.text_input("Alice's IP Address (Laptop 1)", value=lan_ips[0] if lan_ips else "127.0.0.1", key="net_alice_ip")
            target_port = st.number_input("Alice's Port", value=5000, min_value=1024, max_value=65535, key="net_bob_port")
            preset_bob = st.checkbox("Use Textbook Preset (b=15)", value=True, key="net_bob_preset")
        with col_b2:
            st.markdown("**Pre-Flight Connectivity Test:**")
            if st.button("🔍 Test Connection to Alice", key="test_conn_btn"):
                try:
                    s_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_test.settimeout(2.0)
                    s_test.connect((target_ip, int(target_port)))
                    s_test.close()
                    st.success(f"✅ Reachable! Port {target_port} on {target_ip} is open and ready.")
                except Exception as e:
                    st.error(f"❌ Cannot connect ({e}). Check Wi-Fi, IP, and Alice's firewall.")

        st.markdown(f"""
        <div style="background:rgba(99,179,237,0.1); border:1px solid rgba(99,179,237,0.3); border-radius:10px; padding:0.9rem; margin-bottom:1rem;">
            <b>🖥️ Recommended: Run Live Terminal on Laptop 2:</b><br>
            <code>python network_demo/bob.py --host {target_ip} --port {target_port} --preset</code>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚀 Connect to Alice & Run Handshake", type="primary", key="bob_connect_btn"):
            with st.spinner(f"Connecting to Alice at {target_ip}:{target_port}..."):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect((target_ip, int(target_port)))
                    with sock:
                        # 1. Hello
                        send_msg(sock, {"type": "hello", "from": "Bob"})
                        # 2. Params
                        p_msg = recv_msg(sock)
                        p, g = p_msg["p"], p_msg["g"]
                        if not miller_rabin_is_prime(p):
                            st.error(f"❌ SECURITY ALERT: Modulus p={p} is NOT prime! Bob aborts.")
                            st.stop()
                        # 3. Party
                        bob = Party("Bob", p, g, private_key=TEXTBOOK_B if preset_bob else None)
                        # 4. Exchange
                        a_msg = recv_msg(sock)
                        alice_val = a_msg["value"]
                        send_msg(sock, {"type": "public", "name": "Bob", "value": bob.public_key})
                        # 5. Secret
                        bob.receive_public_value(alice_val)
                        s = bob.compute_shared_secret()
                        key = derive_key(s)
                        fp = compute_key_fingerprint(key)
                        # 6. Confirm
                        conf_msg = recv_msg(sock)
                        alice_fp = conf_msg["fingerprint"]
                        send_msg(sock, {"type": "confirm", "fingerprint": fp})
                        match = "✅ MATCH" if alice_fp == fp else "❌ MISMATCH"

                        st.success(f"✅ Handshake Completed with Alice at {target_ip}:{target_port}!")
                        st.markdown(f"""
                        <div class="party-card bob-card">
                            <h3>👨 Bob's Side of the Exchange</h3>
                            <b>Parameters Received & Verified:</b> p={p} (Prime ✓), g={g}<br>
                            <b>Bob's Private Key (b):</b> {priv(bob.private_key)}<br>
                            <b>Bob's Public Key (B):</b> {pub(bob.public_key)}<br>
                            <b>Received Alice's Public Key (A):</b> {pub(alice_val)}<br>
                            <b>Shared Secret:</b> <code>s = A^b mod p = {alice_val}^{bob.private_key} mod {p} = {s}</code><br>
                            <b>Derived Key Fingerprint:</b> <code>{fp}</code><br>
                            <b>Alice's Fingerprint:</b> <code>{alice_fp}</code> ({match})
                        </div>
                        """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"❌ Connection failed: {e}. Check IP and firewall!")

    st.markdown("---")
    with st.expander("📡 Wire Protocol Details (Length-Prefixed Framing)", expanded=False):
        st.markdown("""
        ### Length-Prefixed Framing Specification
        Each network message begins with a **4-byte big-endian unsigned integer** indicating payload byte count:
        ```
        +-------------------------+----------------------------------+
        |  4-Byte Length Header   |       UTF-8 JSON Payload         |
        |  struct.pack('>I', len) |  {"type": "params", "p": 23, ..} |
        +-------------------------+----------------------------------+
        ```
        **Security Guarantee:** Private keys ($a, b$) and shared secret ($s$) are **never transmitted**. Only public values ($p, g, A, B$), confirmation fingerprints, and encrypted ciphertext cross the wire.
        """)


# ──────────────────────────────────────────────────────────────────────────────
# TAB: About / Theory
# ──────────────────────────────────────────────────────────────────────────────

elif demo_tab == "📚 About / Theory":
    st.markdown("## 📚 Mathematical Background")

    with st.expander("1. Modular Arithmetic", expanded=True):
        st.markdown(r"""
        For integers a, b and a positive modulus m:  
        `a ≡ b (mod m)` means `m | (a - b)`.

        The set `{0, 1, …, m-1}` under multiplication forms the group **Z_m\***.  
        When m = p (prime), Z_p\* has order **p-1** and every non-zero element has a multiplicative inverse.
        """)

    with st.expander("2. Primitive Roots (Generators)"):
        st.markdown(r"""
        An element **g** is a *primitive root* mod p if the powers  
        `g^1, g^2, …, g^(p-1)` produce every element of `{1, 2, …, p-1}`.

        Equivalently, the *order* of g equals p-1.

        **Example:** g=5, p=23:  
        `5^1=5, 5^2=2, 5^3=10, 5^4=4, …, 5^22=1 (mod 23)` — all 22 non-zero residues appear.

        **How to check:** g is a primitive root iff `g^((p-1)/q) ≢ 1 (mod p)` for every prime factor q of p-1.
        """)

    with st.expander("3. Discrete Logarithm Problem (DLP)"):
        st.markdown(r"""
        Given p, g, and A = g^a mod p, find **a**.

        For large p (≥ 2048 bits), no efficient classical algorithm exists.  
        The best known algorithms (Number Field Sieve) run in **sub-exponential** time but are 
        still infeasible for 2048+ bits.

        This hardness is the **security foundation of DH**.
        """)

    with st.expander("4. Why the Exchange Works"):
        st.markdown(r"""
        The key mathematical identity is:

        ```
        (g^a)^b ≡ g^(ab) ≡ (g^b)^a  (mod p)
        ```

        Alice computes: **s = B^a mod p = (g^b)^a mod p = g^(ab) mod p**  
        Bob   computes: **s = A^b mod p = (g^a)^b mod p = g^(ab) mod p**

        Both arrive at the same value `g^(ab) mod p` because multiplication in Z_p\* 
        is **commutative and associative**.
        """)

    with st.expander("5. Safe Primes & Small-Subgroup Attacks"):
        st.markdown(r"""
        A **safe prime** p = 2q+1 (where q is prime) ensures the subgroup structure of Z_p\* 
        has orders only 1, 2, q, p-1. This prevents **small-subgroup attacks** where an attacker 
        forces the key into a tiny subgroup to recover it trivially.

        NIST recommends using safe primes or verifying that received public values lie in the 
        correct large-prime-order subgroup.
        """)

    with st.expander("6. Key Sizes (NIST Recommendations)"):
        st.markdown("""
        | DH key size | Symmetric equivalent | Status (2024) |
        |-------------|---------------------|---------------|
        | 1024 bits   | ~80 bits             | ❌ Deprecated  |
        | 2048 bits   | ~112 bits            | ✅ Minimum recommended |
        | 3072 bits   | ~128 bits            | ✅ Recommended |
        | 4096 bits   | ~140 bits            | ✅ High security |

        *Source: NIST SP 800-57, RFC 7919*
        """)

    st.markdown("---")
    st.markdown("### 📖 References")
    st.markdown("""
    1. Diffie, W. & Hellman, M.E. (1976). *New Directions in Cryptography*. IEEE Trans. Inf. Theory 22(6):644-654.
    2. Stallings, W. (2017). *Cryptography and Network Security* (7th ed.). Pearson.
    3. Forouzan, B.A. (2007). *Cryptography & Network Security*. McGraw-Hill.
    4. RFC 7919 – *Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for TLS*.
    5. NIST SP 800-57 – *Recommendation for Key Management*.
    """)

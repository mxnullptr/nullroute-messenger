"""
Crypto primitives for nullroute-messenger.

Key generation  : ED25519 (signing) + X25519 (key exchange)
Client ↔ Client : X25519 ECDH → HKDF-SHA256 → AES-256-GCM
Client → Server : ephemeral X25519 → HKDF-SHA256(44 bytes) → ChaCha20-Poly1305
Server → Client : static X25519 → HKDF-SHA256 → ChaCha20-Poly1305
"""

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# ── Key generation ────────────────────────────────────────────────────────────

def generate_ed25519() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) for signing."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def generate_x25519() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) for key exchange."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


# ── Signing ───────────────────────────────────────────────────────────────────

def sign(ed25519_priv_bytes: bytes, message: bytes) -> bytes:
    """Sign message; return 64-byte ED25519 signature."""
    return Ed25519PrivateKey.from_private_bytes(ed25519_priv_bytes).sign(message)


def verify(ed25519_pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Return True if signature is valid, False otherwise."""
    pub = Ed25519PublicKey.from_public_bytes(ed25519_pub_bytes)
    try:
        pub.verify(signature, message)
        return True
    except Exception:
        return False


# ── Client → Server outer envelope ───────────────────────────────────────────

def outer_encrypt(server_x25519_pub_bytes: bytes, plaintext: bytes) -> bytes:
    """
    Wrap plaintext in the C2S outer envelope using a fresh ephemeral X25519 key.
    Wire: EPHEM_PUB(32) | CIPHERTEXT+TAG

    Key and nonce are both derived from HKDF so no nonce is transmitted.
    Each call generates a unique ephemeral key → unique shared secret → no nonce reuse.
    """
    ephem_priv = X25519PrivateKey.generate()
    server_pub = X25519PublicKey.from_public_bytes(server_x25519_pub_bytes)
    shared = ephem_priv.exchange(server_pub)

    key_nonce = _hkdf(shared, b"nullroute-c2s", length=44)
    key, nonce = key_nonce[:32], key_nonce[32:]

    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    ephem_pub = ephem_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return ephem_pub + ciphertext


# ── Server → Client outer envelope ───────────────────────────────────────────

def outer_decrypt(
    client_x25519_priv_bytes: bytes,
    server_x25519_pub_list: list[bytes],
    packet: bytes,
) -> bytes:
    """
    Unwrap the S2C outer envelope.
    Wire: NONCE(12) | CIPHERTEXT+TAG

    Tries each key in server_x25519_pub_list (hardcoded server keys) until
    the authentication tag matches. Raises ValueError if none match.
    """
    nonce      = packet[:12]
    ciphertext = packet[12:]
    client_priv = X25519PrivateKey.from_private_bytes(client_x25519_priv_bytes)

    for server_pub_bytes in server_x25519_pub_list:
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared = client_priv.exchange(server_pub)
        key = _hkdf(shared, b"nullroute-s2c")
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            continue

    raise ValueError("outer_decrypt: no matching server key")


# ── Client ↔ Client E2E (AES-256-GCM) ────────────────────────────────────────

def e2e_encrypt(
    sender_x25519_priv_bytes: bytes,
    recipient_x25519_pub_bytes: bytes,
    plaintext: bytes,
) -> bytes:
    """
    E2E encrypt for client-to-client messages.
    Wire: SENDER_PUB(32) | NONCE(12) | CIPHERTEXT+TAG
    """
    priv = X25519PrivateKey.from_private_bytes(sender_x25519_priv_bytes)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_x25519_pub_bytes)

    shared = priv.exchange(recipient_pub)
    key = _hkdf(shared, b"nullroute-messenger")

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    sender_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return sender_pub + nonce + ciphertext


def e2e_decrypt(recipient_x25519_priv_bytes: bytes, packet: bytes) -> bytes:
    """
    E2E decrypt for client-to-client messages.
    Wire: SENDER_PUB(32) | NONCE(12) | CIPHERTEXT+TAG
    """
    sender_pub = X25519PublicKey.from_public_bytes(packet[:32])
    nonce      = packet[32:44]
    ciphertext = packet[44:]

    priv = X25519PrivateKey.from_private_bytes(recipient_x25519_priv_bytes)
    shared = priv.exchange(sender_pub)
    key = _hkdf(shared, b"nullroute-messenger")

    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ── Internal ──────────────────────────────────────────────────────────────────

def _hkdf(shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(shared_secret)

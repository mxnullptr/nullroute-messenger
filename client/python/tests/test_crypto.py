"""
Tests for client/python/lib/crypto.py

Coverage:
  - Key generation (ED25519 and X25519)
  - Signing / verification
  - C2S outer envelope (outer_encrypt + server-side decrypt)
  - S2C outer envelope (server-side encrypt + outer_decrypt)
  - E2E AES-256-GCM (e2e_encrypt / e2e_decrypt)
  - _hkdf internals
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

from lib.crypto import (
    generate_ed25519,
    generate_x25519,
    sign,
    verify,
    outer_encrypt,
    outer_decrypt,
    e2e_encrypt,
    e2e_decrypt,
    _hkdf,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _server_encrypt_s2c(server_priv_bytes: bytes, client_pub_bytes: bytes, plaintext: bytes) -> bytes:
    """Simulate the server-side S2C encryption that outer_decrypt expects."""
    server_priv = X25519PrivateKey.from_private_bytes(server_priv_bytes)
    client_pub  = X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = server_priv.exchange(client_pub)
    key    = _hkdf(shared, b"nullroute-s2c")
    nonce  = os.urandom(12)
    ct     = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def _server_decrypt_c2s(server_priv_bytes: bytes, packet: bytes) -> bytes:
    """Simulate the server-side C2S decryption of a packet produced by outer_encrypt."""
    ephem_pub   = X25519PublicKey.from_public_bytes(packet[:32])
    ciphertext  = packet[32:]
    server_priv = X25519PrivateKey.from_private_bytes(server_priv_bytes)
    shared      = server_priv.exchange(ephem_pub)
    key_nonce   = _hkdf(shared, b"nullroute-c2s", length=44)
    key, nonce  = key_nonce[:32], key_nonce[32:]
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)


# ── Key generation ────────────────────────────────────────────────────────────

class TestGenerateEd25519:
    def test_returns_32_byte_keys(self):
        priv, pub = generate_ed25519()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keys_are_bytes(self):
        priv, pub = generate_ed25519()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_unique_on_each_call(self):
        priv1, pub1 = generate_ed25519()
        priv2, pub2 = generate_ed25519()
        assert priv1 != priv2
        assert pub1  != pub2

    def test_priv_and_pub_differ(self):
        priv, pub = generate_ed25519()
        assert priv != pub


class TestGenerateX25519:
    def test_returns_32_byte_keys(self):
        priv, pub = generate_x25519()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keys_are_bytes(self):
        priv, pub = generate_x25519()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_unique_on_each_call(self):
        priv1, pub1 = generate_x25519()
        priv2, pub2 = generate_x25519()
        assert priv1 != priv2
        assert pub1  != pub2

    def test_priv_and_pub_differ(self):
        priv, pub = generate_x25519()
        assert priv != pub


# ── Signing / verification ────────────────────────────────────────────────────

class TestSignVerify:
    def setup_method(self):
        self.priv, self.pub = generate_ed25519()
        self.msg = b"hello nullroute"

    def test_sign_returns_64_bytes(self):
        sig = sign(self.priv, self.msg)
        assert len(sig) == 64

    def test_sign_is_bytes(self):
        sig = sign(self.priv, self.msg)
        assert isinstance(sig, bytes)

    def test_verify_valid_signature(self):
        sig = sign(self.priv, self.msg)
        assert verify(self.pub, self.msg, sig) is True

    def test_verify_tampered_message(self):
        sig = sign(self.priv, self.msg)
        assert verify(self.pub, self.msg + b"x", sig) is False

    def test_verify_tampered_signature(self):
        sig = bytearray(sign(self.priv, self.msg))
        sig[0] ^= 0xFF
        assert verify(self.pub, self.msg, bytes(sig)) is False

    def test_verify_wrong_key(self):
        _, other_pub = generate_ed25519()
        sig = sign(self.priv, self.msg)
        assert verify(other_pub, self.msg, sig) is False

    def test_sign_is_deterministic(self):
        # ED25519 is deterministic: same key + message → same signature
        assert sign(self.priv, self.msg) == sign(self.priv, self.msg)

    def test_verify_empty_message(self):
        sig = sign(self.priv, b"")
        assert verify(self.pub, b"", sig) is True

    def test_verify_large_message(self):
        big = os.urandom(100_000)
        sig = sign(self.priv, big)
        assert verify(self.pub, big, sig) is True

    def test_verify_returns_bool(self):
        sig = sign(self.priv, self.msg)
        result = verify(self.pub, self.msg, sig)
        assert type(result) is bool

    def test_verify_bad_sig_length_returns_false(self):
        assert verify(self.pub, self.msg, b"\x00" * 63) is False
        assert verify(self.pub, self.msg, b"") is False


# ── C2S outer envelope ────────────────────────────────────────────────────────

class TestOuterEncrypt:
    def setup_method(self):
        self.server_priv, self.server_pub = generate_x25519()
        self.plaintext = b"secret c2s payload"

    def test_packet_minimum_length(self):
        # 32 (ephem pub) + 16 (Poly1305 tag) minimum
        pkt = outer_encrypt(self.server_pub, self.plaintext)
        assert len(pkt) >= 32 + 16

    def test_packet_exact_length(self):
        pkt = outer_encrypt(self.server_pub, self.plaintext)
        assert len(pkt) == 32 + len(self.plaintext) + 16

    def test_server_can_decrypt(self):
        pkt = outer_encrypt(self.server_pub, self.plaintext)
        recovered = _server_decrypt_c2s(self.server_priv, pkt)
        assert recovered == self.plaintext

    def test_unique_packets_per_call(self):
        pkt1 = outer_encrypt(self.server_pub, self.plaintext)
        pkt2 = outer_encrypt(self.server_pub, self.plaintext)
        assert pkt1 != pkt2  # ephemeral key is fresh each time

    def test_wrong_server_key_cannot_decrypt(self):
        _, wrong_pub = generate_x25519()
        pkt = outer_encrypt(wrong_pub, self.plaintext)
        with pytest.raises(Exception):
            _server_decrypt_c2s(self.server_priv, pkt)

    def test_empty_plaintext(self):
        pkt = outer_encrypt(self.server_pub, b"")
        assert _server_decrypt_c2s(self.server_priv, pkt) == b""

    def test_large_plaintext(self):
        big = os.urandom(64_000)
        pkt = outer_encrypt(self.server_pub, big)
        assert _server_decrypt_c2s(self.server_priv, pkt) == big

    def test_tampered_ciphertext_fails(self):
        pkt = bytearray(outer_encrypt(self.server_pub, self.plaintext))
        pkt[-1] ^= 0xFF
        with pytest.raises(Exception):
            _server_decrypt_c2s(self.server_priv, bytes(pkt))

    def test_tampered_ephem_pub_fails(self):
        pkt = bytearray(outer_encrypt(self.server_pub, self.plaintext))
        pkt[0] ^= 0xFF
        with pytest.raises(Exception):
            _server_decrypt_c2s(self.server_priv, bytes(pkt))

    def test_returns_bytes(self):
        assert isinstance(outer_encrypt(self.server_pub, self.plaintext), bytes)


# ── S2C outer envelope ────────────────────────────────────────────────────────

class TestOuterDecrypt:
    def setup_method(self):
        self.server_priv, self.server_pub = generate_x25519()
        self.client_priv, self.client_pub = generate_x25519()
        self.plaintext = b"secret s2c payload"

    def test_roundtrip(self):
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        recovered = outer_decrypt(self.client_priv, [self.server_pub], pkt)
        assert recovered == self.plaintext

    def test_packet_structure_nonce_plus_ct(self):
        # nonce is 12 bytes prepended
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        assert len(pkt) == 12 + len(self.plaintext) + 16

    def test_tries_multiple_server_keys(self):
        _, decoy1 = generate_x25519()
        _, decoy2 = generate_x25519()
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        recovered = outer_decrypt(self.client_priv, [decoy1, decoy2, self.server_pub], pkt)
        assert recovered == self.plaintext

    def test_first_matching_key_used(self):
        _, decoy = generate_x25519()
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        # correct key is first in list
        recovered = outer_decrypt(self.client_priv, [self.server_pub, decoy], pkt)
        assert recovered == self.plaintext

    def test_no_matching_key_raises_value_error(self):
        _, wrong_pub = generate_x25519()
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        with pytest.raises(ValueError, match="no matching server key"):
            outer_decrypt(self.client_priv, [wrong_pub], pkt)

    def test_empty_key_list_raises_value_error(self):
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        with pytest.raises(ValueError):
            outer_decrypt(self.client_priv, [], pkt)

    def test_tampered_nonce_fails(self):
        pkt = bytearray(_server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext))
        pkt[0] ^= 0xFF
        with pytest.raises(ValueError):
            outer_decrypt(self.client_priv, [self.server_pub], bytes(pkt))

    def test_tampered_ciphertext_fails(self):
        pkt = bytearray(_server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext))
        pkt[-1] ^= 0xFF
        with pytest.raises(ValueError):
            outer_decrypt(self.client_priv, [self.server_pub], bytes(pkt))

    def test_empty_plaintext(self):
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, b"")
        assert outer_decrypt(self.client_priv, [self.server_pub], pkt) == b""

    def test_returns_bytes(self):
        pkt = _server_encrypt_s2c(self.server_priv, self.client_pub, self.plaintext)
        assert isinstance(outer_decrypt(self.client_priv, [self.server_pub], pkt), bytes)


# ── E2E AES-256-GCM ───────────────────────────────────────────────────────────

class TestE2E:
    def setup_method(self):
        self.alice_priv, self.alice_pub = generate_x25519()
        self.bob_priv,   self.bob_pub   = generate_x25519()
        self.plaintext = b"end-to-end secret"

    def test_packet_structure_length(self):
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        assert len(pkt) == 32 + 12 + len(self.plaintext) + 16

    def test_alice_to_bob_roundtrip(self):
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        assert e2e_decrypt(self.bob_priv, pkt) == self.plaintext

    def test_bob_to_alice_roundtrip(self):
        pkt = e2e_encrypt(self.bob_priv, self.alice_pub, self.plaintext)
        assert e2e_decrypt(self.alice_priv, pkt) == self.plaintext

    def test_unique_packets_random_nonce(self):
        pkt1 = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        pkt2 = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        assert pkt1 != pkt2

    def test_sender_pub_embedded_in_packet(self):
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        embedded = pkt[:32]
        expected = X25519PrivateKey.from_private_bytes(self.alice_priv).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        assert embedded == expected

    def test_wrong_recipient_key_fails(self):
        charlie_priv, _ = generate_x25519()
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        with pytest.raises(Exception):
            e2e_decrypt(charlie_priv, pkt)

    def test_tampered_ciphertext_fails(self):
        pkt = bytearray(e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext))
        pkt[-1] ^= 0xFF
        with pytest.raises(Exception):
            e2e_decrypt(self.bob_priv, bytes(pkt))

    def test_tampered_nonce_fails(self):
        pkt = bytearray(e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext))
        pkt[32] ^= 0xFF
        with pytest.raises(Exception):
            e2e_decrypt(self.bob_priv, bytes(pkt))

    def test_tampered_sender_pub_fails(self):
        pkt = bytearray(e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext))
        pkt[0] ^= 0xFF
        with pytest.raises(Exception):
            e2e_decrypt(self.bob_priv, bytes(pkt))

    def test_empty_plaintext(self):
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, b"")
        assert e2e_decrypt(self.bob_priv, pkt) == b""

    def test_large_plaintext(self):
        big = os.urandom(100_000)
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, big)
        assert e2e_decrypt(self.bob_priv, pkt) == big

    def test_returns_bytes(self):
        pkt = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        assert isinstance(pkt, bytes)
        assert isinstance(e2e_decrypt(self.bob_priv, pkt), bytes)

    def test_ecdh_symmetric(self):
        # alice→bob and bob→alice share the same ECDH secret
        pkt_ab = e2e_encrypt(self.alice_priv, self.bob_pub, self.plaintext)
        assert e2e_decrypt(self.bob_priv, pkt_ab) == self.plaintext

        pkt_ba = e2e_encrypt(self.bob_priv, self.alice_pub, self.plaintext)
        assert e2e_decrypt(self.alice_priv, pkt_ba) == self.plaintext


# ── _hkdf ─────────────────────────────────────────────────────────────────────

class TestHkdf:
    def test_default_output_length(self):
        out = _hkdf(b"\x00" * 32, b"test-info")
        assert len(out) == 32

    def test_custom_length(self):
        out = _hkdf(b"\x00" * 32, b"test-info", length=44)
        assert len(out) == 44

    def test_deterministic(self):
        a = _hkdf(b"\xAB" * 32, b"info")
        b = _hkdf(b"\xAB" * 32, b"info")
        assert a == b

    def test_different_info_different_output(self):
        a = _hkdf(b"\x01" * 32, b"info-a")
        b = _hkdf(b"\x01" * 32, b"info-b")
        assert a != b

    def test_different_secret_different_output(self):
        a = _hkdf(b"\x01" * 32, b"same-info")
        b = _hkdf(b"\x02" * 32, b"same-info")
        assert a != b

    def test_c2s_and_s2c_infos_produce_different_keys(self):
        secret = os.urandom(32)
        a = _hkdf(secret, b"nullroute-c2s")
        b = _hkdf(secret, b"nullroute-s2c")
        assert a != b

    def test_returns_bytes(self):
        assert isinstance(_hkdf(b"\x00" * 32, b"info"), bytes)

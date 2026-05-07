# Nullroute Messenger Protocol
**Version:** 1.0  
**Status:** Draft

---

## 1. Overview

Nullroute is an end-to-end encrypted messaging protocol. The server acts as a
relay only — it never has access to plaintext message content.

Two encryption layers are used:

| Layer | Parties | Algorithm |
|-------|---------|-----------|
| Transport | Client ↔ Server | ChaCha20-Poly1305 (key via X25519 ECDH) |
| End-to-End | Client ↔ Client | AES-256-GCM (key via X25519 ECDH) |

Identity is established via ED25519 key pairs. Every request is signed by the
sender's ED25519 private key, allowing the server and peers to verify
authenticity without trusting the transport layer.

---

## 2. Notation

```
[N]       — fixed N-byte field
[N..M]    — variable field, N to M bytes
U8        — unsigned 8-bit integer
U16       — unsigned 16-bit integer, big-endian
U32       — unsigned 32-bit integer, big-endian
UID       — U32, server-assigned unique identifier
SIG       — 64-byte ED25519 signature over the packet body (all fields before SIG)
```

All multi-byte integers are big-endian unless noted otherwise.

---

## 3. Packet Structure

Every packet is wrapped in an outer encryption envelope (see section 4).
The inner plaintext structure is:

```
+---------+-----------+--------------+------------------+
| VERSION | MSG_TYPE  | PAYLOAD_LEN  | PAYLOAD          |
|  U8 (1) |  U8 (1)  |   U32 (4)   | [PAYLOAD_LEN]    |
+---------+-----------+--------------+------------------+
```

After the transport layer decrypts the envelope, the server reads `MSG_TYPE` and
routes the payload accordingly.

**Version:** `0x01`

**Message types:**

| Value | Name                    | Direction       |
|-------|-------------------------|-----------------|
| 0x01  | REGISTER                | Client → Server |
| 0x02  | REGISTER_OK             | Server → Client |
| 0x03  | CONNECT_REQUEST         | Client → Server |
| 0x04  | CONNECT_REQUEST_OK      | Server → Client |
| 0x05  | CONNECT_CONFIRM         | Client → Server |
| 0x06  | GET_PEER                | Client → Server |
| 0x07  | GET_PEER_OK             | Server → Client |
| 0x08  | SEND_MESSAGE            | Client → Server |
| 0x09  | DELIVER_MESSAGE         | Server → Client |
| 0xFF  | ERROR                   | Server → Client |

---

## 4. Outer Encryption Layer

There is no transport handshake. Every frame is independently encrypted and
self-contained. The server's X25519 public keys are compiled into the client
binary; multiple keys are supported for rotation.

### 4.1 Client → Server (C2S)

Each message uses a freshly generated ephemeral X25519 key. This prevents any
observer (including the server itself) from linking frames to a specific client
based on transport-layer data alone.

Wire format:
```
+----------+-----------------+-------------------+
| LEN [2]  | EPHEM_PUB  [32] | CIPHERTEXT (var)  |
+----------+-----------------+-------------------+
```

- `LEN` — byte count after the LEN field: `32 + len(CIPHERTEXT)`
- `EPHEM_PUB` — one-time X25519 public key, freshly generated per frame
- `CIPHERTEXT` — ChaCha20-Poly1305 output, includes 16-byte authentication tag

Key and nonce derivation:
```
ephem_priv, ephem_pub = X25519_keygen()
shared                = X25519(ephem_priv, server_x25519_pub)
key_nonce             = HKDF-SHA256(shared,
                                     salt=none,
                                     info="nullroute-c2s",
                                     length=44)
key   = key_nonce[0:32]
nonce = key_nonce[32:44]
```

The nonce is not transmitted — it is derived deterministically from the shared
secret. Each unique EPHEM_PUB produces a unique shared secret, making nonce
reuse structurally impossible.

Server decryption:
```
shared    = X25519(server_x25519_priv, EPHEM_PUB)
key_nonce = HKDF-SHA256(shared, info="nullroute-c2s", length=44)
key, nonce = key_nonce[0:32], key_nonce[32:44]
inner_packet = ChaCha20-Poly1305_decrypt(key, nonce, CIPHERTEXT)
// discard frame silently if tag check fails
```

### 4.2 Server → Client (S2C)

The server encrypts with one of its static X25519 private keys and the
client's registered X25519 public key. No ephemeral key is included in the
frame. The client tries each hardcoded server key in turn until decryption
succeeds.

Wire format:
```
+----------+-------------------+
| LEN [2]  | CIPHERTEXT (var)  |
+----------+-------------------+
```

- `LEN` — byte count after the LEN field: `len(CIPHERTEXT)`
- `CIPHERTEXT` — `NONCE[12] || ChaCha20-Poly1305 output || TAG[16]`

Server encryption:
```
shared = X25519(server_x25519_priv, client_x25519_pub)
key    = HKDF-SHA256(shared, salt=none, info="nullroute-s2c", length=32)
nonce  = random(12)
CIPHERTEXT = nonce || ChaCha20-Poly1305_encrypt(key, nonce, inner_packet)
```

Client decryption:
```
for server_pub in HARDCODED_SERVER_KEYS:
    shared = X25519(client_x25519_priv, server_pub)
    key    = HKDF-SHA256(shared, info="nullroute-s2c", length=32)
    nonce  = CIPHERTEXT[0:12]
    result = ChaCha20-Poly1305_try_decrypt(key, nonce, CIPHERTEXT[12:])
    if result is not None:
        inner_packet = result
        break
// discard frame silently if no key matches
```

When server keys are rotated, the old key stays in `HARDCODED_SERVER_KEYS`
until all deployed clients have received the new binary.

---

## 5. Messages

### 5.1 REGISTER (0x01)

Register a new user account. The server issues a verification code
out-of-band (e.g. email/SMS/existing user's reference) before this call is made.

**Payload:**
```
+---------------+------------------+----------------+
| USERNAME_LEN  | USERNAME [8..32] | VERIF_CODE [6] |
|    U8         |                  | (ASCII digits) |
+---------------+------------------+----------------+
| ED25519_PUB [32] | X25519_PUB [32] | SIG [64]     |
+------------------+-----------------+--------------+
```

- `USERNAME` — `[a-z0-9.\-]{8,32}`
- `VERIF_CODE` — 6 ASCII decimal digits
- `SIG` — ED25519 signature over all preceding fields in this payload

**Response — REGISTER_OK (0x02):**
```
+----------+
| UID  U32 |
+----------+
```

**Response — ERROR (0xFF):** see section 7.

**Example (hex, payload only):**
```
08                                  # USERNAME_LEN = 8
61 6c 69 63 65 39 39 38             # "alice998"
31 32 33 34 35 36                   # verif code "123456"
<32 bytes ed25519 pub>
<32 bytes x25519 pub>
<64 bytes ed25519 signature>
```

---

### 5.2 CONNECT_REQUEST (0x03)

Request a peer connection with another registered user by username.

**Payload:**
```
+---------------+------------------+-----------+
| USERNAME_LEN  | USERNAME [8..32] | SIG [64]  |
|    U8         |                  |           |
+---------------+------------------+-----------+
```

**Response — CONNECT_REQUEST_OK (0x04):**
```
+----------------+
| CONN_UID  U32  |
+----------------+
```

`CONN_UID` identifies this pending connection. The target user must confirm
it via `CONNECT_CONFIRM` before either party can exchange messages or fetch
each other's public keys.

---

### 5.3 CONNECT_CONFIRM (0x05)

Accept a pending connection request.

**Payload:**
```
+-----------------+-----------+
| CONN_UID  U32   | SIG [64]  |
+-----------------+-----------+
```

After confirmation the connection is considered established and both parties
may call `GET_PEER` to retrieve each other's public keys.

---

### 5.4 GET_PEER (0x06)

Retrieve a confirmed peer's identity and public keys.

**Payload:**
```
+---------------+-----------+
| PEER_UID  U32 | SIG [64]  |
+---------------+-----------+
```

**Response — GET_PEER_OK (0x07):**
```
+---------------+------------------+------------------+-----------------+
| USERNAME_LEN  | USERNAME [8..32] | ED25519_PUB [32] | X25519_PUB [32] |
|    U8         |                  |                  |                 |
+---------------+------------------+------------------+-----------------+
```

The server returns data only if a confirmed connection exists between the
requester and the target; otherwise returns ERROR `0x04`.

---

### 5.5 SEND_MESSAGE (0x08)

Send an end-to-end encrypted message to a peer. The server relays the
ciphertext without decrypting it.

**Payload:**
```
+---------------+--------------------+-------------------+
| PEER_UID  U32 | CHUNK_INFO  U32    | E2E_PACKET        |
|               | [TOTAL  U16]       | (variable)        |
|               | [CURRENT U16]      |                   |
+---------------+--------------------+-------------------+
| CHUNK_HASH [8]          | PAYLOAD_HASH [24]            |
| sha512[0..3]+sha512[60..63] | sha256[0..3]            |
|                         | + sha512[48..63]             |
|                         | + sha256[28..31]             |
+-------------------------+------------------------------+
```

`E2E_PACKET` wire format (AES-256-GCM):
```
+------------------+------------+---------------------------+----------+
| SENDER_PUB  [32] | NONCE [12] | CIPHERTEXT (variable)     | TAG [16] |
+------------------+------------+---------------------------+----------+
```

E2E key derivation:
```
shared_secret = X25519(sender_priv, recipient_x25519_pub)
e2e_key       = HKDF-SHA256(shared_secret,
                             salt=none,
                             info="nullroute-messenger",
                             length=32)
```

For single-chunk messages: `TOTAL = 1`, `CURRENT = 0`.

The server sends no response to `SEND_MESSAGE`. The recipient receives the
message via an asynchronous `DELIVER_MESSAGE` push.

---

### 5.6 DELIVER_MESSAGE (0x09)

Server pushes an incoming message to a connected recipient.

**Payload:**
```
+----------------+--------------------+-------------------+
| SENDER_UID U32 | CHUNK_INFO  U32    | E2E_PACKET        |
|                | [TOTAL  U16]       | (variable)        |
|                | [CURRENT U16]      |                   |
+----------------+--------------------+-------------------+
| CHUNK_HASH [8] | PAYLOAD_HASH [24]  |
+----------------+--------------------+
```

Same layout as `SEND_MESSAGE`; `PEER_UID` is replaced by `SENDER_UID`.

---

## 6. End-to-End Message Flow

```
Alice                        Server                        Bob
  |                            |                            |
  |==[transport encrypted]===========================[transport encrypted]==|
  |                            |                            |
  |-- GET_PEER(bob_uid) -----> |                            |
  |<-- GET_PEER_OK(bob_keys) --|                            |
  |                            |                            |
  |  e2e_key = HKDF(X25519(alice_priv, bob_x25519_pub))    |
  |  e2e_packet = AES-256-GCM(e2e_key, "Hello, Bob!")      |
  |                            |                            |
  |-- SEND_MESSAGE ----------> |                            |
  |   peer_uid  = bob_uid      |-- DELIVER_MESSAGE -------> |
  |   e2e_packet               |   sender_uid = alice_uid   |
  |                            |   e2e_packet               |
  |                            |                            |
  |                            |  e2e_key = HKDF(X25519(bob_priv, alice_x25519_pub))
  |                            |  plaintext = AES-256-GCM-decrypt(e2e_key, e2e_packet)
```

The server sees only ciphertext in both directions. It cannot derive the E2E
key because it does not hold either party's X25519 private key.

---

## 7. Error Packet (0xFF)

```
+----------+--------------+-----------------+
| CODE  U8 | MSG_LEN  U8  | MSG [0..255]    |
+----------+--------------+-----------------+
```

| Code | Meaning                       |
|------|-------------------------------|
| 0x01 | Wrong verification code       |
| 0x02 | Username already taken        |
| 0x03 | User not found                |
| 0x04 | No established connection     |
| 0x05 | Invalid signature             |
| 0x06 | Malformed packet              |
| 0x07 | Authentication tag mismatch   |

---

## 8. Key and Field Sizes

| Field                | Size     |
|----------------------|----------|
| ED25519 private key  | 32 bytes |
| ED25519 public key   | 32 bytes |
| ED25519 signature    | 64 bytes |
| X25519 private key   | 32 bytes |
| X25519 public key    | 32 bytes |
| AES-256 / ChaCha key | 32 bytes |
| GCM / Poly1305 tag   | 16 bytes |
| Nonce (both ciphers) | 12 bytes |
| UID                  | 4 bytes  |
| C2S outer overhead   | 48 bytes (ephem_pub + tag; nonce derived) |
| S2C outer overhead   | 28 bytes (nonce + tag) |
| E2E overhead         | 60 bytes (sender_pub + nonce + tag) |

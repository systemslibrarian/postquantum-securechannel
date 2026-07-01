# PostQuantum.SecureChannel — Protocol Specification (v2)

This document describes the wire protocol and key schedule for PostQuantum.SecureChannel protocol
version `2` (library `1.0.0`). It is intended to be precise enough to audit and to reimplement.

> **Stable as of 1.0.** This wire format (protocol version 2) is stable under Semantic Versioning: it
> will not change incompatibly without a major-version bump. **Protocol version 2 originally landed
> inside the `0.3.0-preview.1` window as remediation for an external review of the HKDF info
> construction (Finding 2) and transcript framing (Finding 3),** and is unchanged through `1.0.0`. It
> is not wire-compatible with version 1; a v1 peer and a v2 peer fail cleanly at version negotiation.
> The message-format byte and the negotiated protocol version guard against silently mixing
> incompatible peers. The one anticipated future wire change is the X-Wing combiner tracking its final
> RFC, which would ship as a major version — see `KNOWN-GAPS.md` §2.

## 1. Primitives

| Role | Algorithm | Source |
| --- | --- | --- |
| Hybrid KEM | X-Wing (ML-KEM-768 + X25519) | `draft-connolly-cfrg-xwing-kem-06` |
| Signatures | ML-DSA-65 (FIPS 204) | BouncyCastle |
| KDF | HKDF-SHA256 | .NET BCL |
| Transcript hash | SHA-256 | .NET BCL |
| Record AEAD | AES-256-GCM (128-bit tag) | .NET BCL |
| Key confirmation | HMAC-SHA256 | .NET BCL |

Sizes: X-Wing public key 1216 B, ciphertext 1120 B, shared secret 32 B. ML-DSA-65 public key 1952 B.
Random nonces (`clientRandom`, `serverRandom`) are 32 B each.

The X-Wing combiner is validated byte-for-byte against the three Known-Answer Tests in Appendix C of
the draft. When that draft is published as an RFC, the pinned reference here will be updated to the RFC
number and the vectors re-checked.

**Why SHA-256 (not SHA3-256) for the transcript and HKDF.** The protocol-glue layer is uniformly
SHA-256 (HKDF-SHA256, HMAC-SHA256, transcript SHA-256). SHA-256 is FIPS-approved, hardware-accelerated
on every modern CPU, and gives 128-bit collision resistance under standard assumptions — sufficient
for transcript binding and for HKDF. SHA3-256 is used inside the X-Wing combiner only, because
`draft-connolly-cfrg-xwing-kem` mandates it; the choice is independent.

## 2. Wire encoding

All integers are big-endian. A **block** is a 16-bit length prefix followed by that many bytes. Every
handshake message begins with a 1-byte **message-format** byte (currently `0x02`).

When carried over a byte stream by `PqSecureChannelStream`, each handshake message and each record is
additionally wrapped in a 4-byte big-endian length prefix (see `Transport/PqFraming.cs`).

### 2.1 ClientHello

```
format:            u8  (0x02)
supportedVersions: block (1..64 bytes, one byte per offered protocol version, highest preference first)
clientRandom:      block (32 bytes)
kemPublicKey:      block (1216 bytes, X-Wing public key)
```

### 2.2 ServerHello

```
format:               u8  (0x02)
negotiatedVersion:    u8  (the single protocol version the server selected)
serverRandom:         block (32 bytes)
kemCiphertext:        block (1120 bytes, X-Wing ciphertext)
serverIdentityPublic: block (1952 bytes, ML-DSA-65 public key; may be empty)
signature:            block (ML-DSA-65 signature over the signed body below)
```

The **signed body** is the message above *excluding* the `signature` block.

### 2.3 ClientFinished

```
format:               u8  (0x02)
clientIdentityPublic: block (1952 bytes if mutual auth, else empty)
clientSignature:      block (ML-DSA-65 signature if mutual auth, else empty)
finishedMac:          block (32 bytes, HMAC-SHA256)
```

## 3. Version negotiation

The client lists every protocol version it supports in `supportedVersions`. The server selects the
highest version that appears in both its own and the client's lists and echoes it in
`negotiatedVersion`; if there is no overlap it aborts. The client verifies the negotiated version is
one it offered and still supports. (Only version `2` exists today; version `1` is not negotiable from
this build — by design, since the v1 schedule is the artifact this remediation removed.)

## 4. Transcript hashes

**Each fragment is preceded by its 4-byte big-endian length when fed to SHA-256.** This guarantees
that no two distinct fragment sequences can collide on the same hash by concatenation ambiguity:

```
TranscriptHash(f₁, …, fₙ) = SHA-256( len(f₁) ‖ f₁ ‖ … ‖ len(fₙ) ‖ fₙ )

h1 = TranscriptHash( ClientHello, ServerHello-body )   // signed by the server, binds the key schedule
h2 = TranscriptHash( ClientHello, ServerHello-full )   // covers the server signature; used for Finished
```

`ServerHello-full` includes the server's `signature` block; `ServerHello-body` does not.

## 5. Authentication

```
serverSignature = ML-DSA-65.Sign( serverIdentitySk, "pqsc/v2 server-auth" ‖ h1 )
clientSignature = ML-DSA-65.Sign( clientIdentitySk, "pqsc/v2 client-auth" ‖ h2 )   // mutual auth only
```

The client verifies `serverSignature` against the **pinned** server identity before proceeding. If the
`ServerHello` carries an identity key, it must equal the pinned key (constant-time compared).

## 6. Key schedule (HKDF-SHA256)

Every HKDF `Expand` call uses a TLS 1.3-style `HkdfLabel` structure for the `info` parameter, so no
two `(length, label, context)` triples can collide on the same `info` bytes:

```
HkdfLabel = uint16_BE(length) ‖ uint8(label_len) ‖ label ‖ uint8(context_len) ‖ context

Expand(prk, label, length, context = empty) = HKDF-Expand(prk, HkdfLabel, length)
```

The schedule itself:

```
ss   = X-Wing shared secret (32 bytes)
psk  = resumption secret (32 bytes) if resuming, else empty
salt = clientRandom ‖ serverRandom ‖ psk
PRK  = HKDF-Extract(salt, ss)

master = Expand(PRK, "pqsc/v2 master", 32, context = h1)

c2sTrafficSecret = Expand(master, "pqsc/v2 c2s traffic", 32)
s2cTrafficSecret = Expand(master, "pqsc/v2 s2c traffic", 32)
clientFinKey     = Expand(master, "pqsc/v2 client finished", 32)
serverFinKey     = Expand(master, "pqsc/v2 server finished", 32)   // reserved
resumptionSecret = Expand(master, "pqsc/v2 resumption", 32)         // exportable
```

Each direction's AEAD keys come from its traffic secret:

```
key = Expand(trafficSecret, "pqsc/v2 key", 32)
iv  = Expand(trafficSecret, "pqsc/v2 iv", 4)
```

The master secret is bound to `h1`, so it depends on the full handshake transcript, both nonces, and
the resumption secret (if any).

## 7. Key confirmation

```
finishedMac = HMAC-SHA256( clientFinKey, h2 )
```

The server recomputes and compares (constant-time) before the session is live. For mutual auth, the
server then verifies `clientSignature` and, if configured, checks the client identity against its
allowlist.

## 8. Record format

Each record:

```
format:      u8 (0x02)
contentType: u8 (0x17 = application data, 0x18 = key update)
sequence:    u64 (big-endian, per-direction, per-epoch, starts at 0)
ciphertext:  AES-256-GCM ciphertext (same length as plaintext)
tag:         16 bytes
```

- **Nonce** = `ivPrefix(4) ‖ sequence(8)` for the current epoch of that direction (12 bytes).
- **AEAD associated data** = `format ‖ contentType ‖ sequence ‖ callerAad`.
- **Replay/order**: strict mode requires `sequence == expectedNext`; sliding-window mode accepts any
  in-window, not-yet-seen sequence and rejects replays and records older than the window. `Commit`
  enforces the `IsAcceptable` precondition in code.
- **Per-epoch hard caps** matching NIST SP 800-38D: sending more than `2^32` records, or encrypting
  more than `2^36` plaintext bytes, in one epoch is refused with `PqEpochExhaustedException`
  (perform a key update first). `PqSession.NeedsKeyUpdate` trips inside a 1/256th safety margin of
  either cap.
- **Per-record cap**: a single record's plaintext must not exceed `2^30` bytes (1 GiB).

Directions are independent: client→server and server→client have separate traffic secrets, nonce
prefixes, sequence counters, and epochs.

## 9. Key update

A key update is a record with `contentType = 0x18` and an empty payload, encrypted under the sender's
current epoch keys at the current sequence number. After sending it, the sender ratchets its send
direction:

```
trafficSecret' = Expand(trafficSecret, "pqsc/v2 key update", 32)
```

then re-derives `key`/`iv` from `trafficSecret'`, resets its sequence number to 0, and increments its
epoch. On receipt (after successful authentication), the peer ratchets its receive direction the same
way. Each direction updates independently.

## 10. Why v2: external review remediation

Protocol version `2` is the wire-format result of two findings from an external adversarial review of
the protocol glue:

- **Finding 2 — HKDF info construction.** v1's `info` was raw `ASCII label ‖ context` with no length
  framing. It was unambiguous in practice because every call site used fixed labels, but the helper
  permitted future `(label, context)` collisions. v2 uses the TLS 1.3 `HkdfLabel` structure above.
- **Finding 3 — Transcript framing.** v1's transcript fed each fragment directly into SHA-256, also
  unambiguous in practice because the two call sites pass self-framed messages, but fragile against
  future variable-length additions. v2 length-prefixes each fragment.

Both changes alter every derived key byte and the transcript hash, so v1 and v2 are not wire-
compatible. See `KNOWN-GAPS.md` §13 and `CHANGELOG.md` for adopter guidance, and
`docs/AUDIT-SCOPE.md` for what remains in the post-v2 audit scope.

---

**To God be the glory.** — *1 Corinthians 10:31*

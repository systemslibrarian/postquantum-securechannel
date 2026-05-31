# Architecture

A one-page tour of how PostQuantum.SecureChannel fits together. For wire-format detail see
[`protocol.md`](protocol.md); for trust and threat assumptions see
[`threat-model.md`](threat-model.md).

## Layers

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ Application code (your business logic)                                 │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Integration layer  (optional)                                          │
 │   • PostQuantum.SecureChannel.AspNetCore — DI, WebSocket adapter,      │
 │     IConfiguration binding, MapPqWebSocket()                           │
 │   • PostQuantum.SecureChannel.Testing — in-memory duplex, harness      │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Transport adapter  (PqSecureChannelStream)                             │
 │   • length-prefixed framing over any Stream                            │
 │   • automatic key-update honoring the configured policy                │
 │   • configurable handshake timeout                                     │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Session  (PqSession)                                                   │
 │   • AES-256-GCM record encryption / decryption                         │
 │   • per-direction sequence + epoch state                               │
 │   • strict-order or sliding-window replay protection                   │
 │   • in-band UpdateSendKey() ratchet                                    │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Handshake  (PqSecureChannel.CreateClient / CreateServer)               │
 │   • X-Wing hybrid KEM (ML-KEM-768 + X25519)                            │
 │   • ML-DSA-65 transcript signature                                     │
 │   • HKDF-SHA256 key schedule + Finished MAC confirmation               │
 │   • version negotiation                                                │
 ├────────────────────────────────────────────────────────────────────────┤
 │ Cryptographic primitives                                               │
 │   • BouncyCastle: ML-KEM, ML-DSA, X25519, SHA-3, SHAKE                 │
 │   • .NET BCL: AES-GCM, HKDF, SHA-256, HMAC                             │
 └────────────────────────────────────────────────────────────────────────┘
```

Each layer above can be skipped if you do not need it. The most common shapes are:

- **TCP / WebSocket / pipe**: app code → stream adapter → session → handshake.
- **Queue / message broker**: app code → session only (drop the transport adapter); use
  `PqSession.Encrypt` and `PqSession.Decrypt` directly. See `samples/QueueEnvelope`.
- **ASP.NET Core service**: app code → DI / endpoint helpers (`AspNetCore` package) → stream
  adapter → session → handshake. See `samples/MicroserviceWebSocket.*`.

## Handshake (three messages, one round trip)

```
Client                                              Server
  │                                                   │
  │  ClientHello  (versions, X-Wing pk, random)       │
  │  ──────────────────────────────────────▶          │
  │                                                   │  Encapsulate to X-Wing pk
  │                                                   │  Build ServerHello, sign with ML-DSA
  │  ServerHello  (version, ciphertext, sig)          │
  │  ◀──────────────────────────────────────          │
  │  Verify ML-DSA sig against pinned identity        │
  │  Decapsulate to derive shared secret              │
  │  Run HKDF → traffic + Finished keys               │
  │                                                   │
  │  ClientFinished  (HMAC over transcript)           │
  │  ──────────────────────────────────────▶          │
  │                                                   │  Verify Finished MAC
  │                                                   │  (mutual auth: verify client ML-DSA sig)
  │                                                   │
  │            AES-256-GCM session records            │
  │  ◀══════════════════════════════════════▶         │
```

`ClientHello` is a single small message; `ServerHello` adds the X-Wing ciphertext, the server's
ML-DSA public key, and a transcript signature; `ClientFinished` is a tiny key-confirmation MAC plus
any optional client-side authentication.

## Session

Each direction has independent state:

- A **traffic secret**, ratcheted via HKDF on each key update.
- A 96-bit nonce = 32-bit HKDF-derived IV prefix ‖ 64-bit sequence counter.
- A sequence counter starting at 0 each epoch.
- A replay/order check: strict next-sequence or a fixed-size bitmap window.

This means client→server and server→client are cryptographically independent — neither side can
forge the other's traffic, and a compromise of one direction's secret does not compromise the other.

## Key schedule (HKDF-SHA256)

```
ss     = X-Wing shared secret (32 bytes)
psk    = resumption secret if any (32 bytes)
salt   = clientRandom ‖ serverRandom ‖ psk
PRK    = HKDF-Extract(salt, ss)
master = HKDF-Expand(PRK, "pqsc/v1 master" ‖ transcriptHash, 32)

      ┌─ HKDF-Expand(master, "pqsc/v1 c2s traffic")     → c2s_traffic_secret
      │     └─ HKDF-Expand(..., "pqsc/v1 key", 32)       → c2s_aead_key
      │     └─ HKDF-Expand(..., "pqsc/v1 iv", 4)         → c2s_iv_prefix
      │     └─ HKDF-Expand(..., "pqsc/v1 key update")    → c2s_next_epoch_secret
      │
      ├─ HKDF-Expand(master, "pqsc/v1 s2c traffic")     → s2c_traffic_secret (parallel)
      ├─ HKDF-Expand(master, "pqsc/v1 client finished") → client Finished MAC key
      ├─ HKDF-Expand(master, "pqsc/v1 server finished") → reserved
      └─ HKDF-Expand(master, "pqsc/v1 resumption")      → exportable resumption secret
```

Every label is versioned (`pqsc/v1 …`) so a future protocol version can introduce new derivations
without colliding with old ones.

## Trust model in one paragraph

Authentication is by **raw-key pinning**. The client must hold the server's `PqIdentityPublicKey`
out of band; during the handshake the server signs the transcript with its long-term ML-DSA seed,
and the client verifies that signature against the pinned key. If the pin matches, the channel is
mutually authenticated (also of the client, when `PqClientOptions.ClientIdentity` is supplied). If
the pin does not match, the handshake aborts before any traffic is exchanged. There are no
certificates, no CA, no revocation, and no expiry — for those, layer this on top of TLS or roll
your own distribution.

See [`threat-model.md`](threat-model.md) for the assumptions this trust model rests on.

---

**To God be the glory.** — *1 Corinthians 10:31*

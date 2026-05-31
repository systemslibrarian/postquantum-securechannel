# Threat model

What PostQuantum.SecureChannel is designed to defend against, what it is **not** designed to defend
against, and the assumptions it relies on. Read alongside [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).

## Goals (in scope)

When used as documented (server identity pinned out of band, code path follows the public API):

1. **Confidentiality, post-quantum.** A passive adversary that records every byte of the
   handshake and every record cannot read application data, even with a future large quantum
   computer. This is the harvest-now-decrypt-later defence.
2. **Server authentication.** A client refuses to talk to anyone but the holder of the pinned
   server identity seed. A MitM cannot impersonate the server without that seed.
3. **Mutual authentication (optional).** A server can require, and verify, that the client
   holds a specific identity seed, and can compare it against an allowlist.
4. **Integrity & forgery resistance.** Tampered or truncated records fail to decrypt. Replay,
   reorder, or pre-epoch records are rejected.
5. **Forward secrecy.** Each session uses a fresh ephemeral X-Wing key pair; a later compromise
   of long-term identity seeds does not retroactively decrypt past sessions.
6. **Crypto-agility within the hybrid.** Even if either ML-KEM-768 or X25519 is later broken in
   isolation, X-Wing's combiner keeps the session secret as long as the other primitive holds.

## Non-goals (out of scope)

1. **Endpoint security.** If either endpoint is compromised (root access, ML-DSA seed stolen
   from memory, a malicious in-process attacker), no transport-layer protocol can help. Protect
   identity seeds in a secret manager or HSM; do not log them.
2. **Side-channel resistance** beyond what BouncyCastle and the .NET BCL provide. Timing of
   handshake failure paths is not guaranteed to be constant; see `KNOWN-GAPS.md` §8–§9.
3. **DoS at the transport layer.** A peer who floods you with bytes can exhaust CPU or memory.
   The library bounds receive frame size (16 MiB default) and replay-window memory, but it does
   not rate-limit; that is your job at the integration layer.
4. **Identity distribution.** The library never tells you whose pinned key you should trust. A
   stolen distribution channel (compromised package, MitM'd config push) means the wrong key is
   pinned and the channel authenticates the wrong peer. Trust distribution is the hard part.
5. **Long-term key compromise reversal.** A leaked ML-DSA seed lets an attacker impersonate the
   identity in *new* sessions. Rotate immediately and redistribute the public half. There is no
   CRL — that is the cost of avoiding PKI.
6. **A TLS / Noise / libsodium replacement.** This is an *application-layer* secure channel. Run
   it inside TLS at the edge; do not expose it to the public internet without surrounding
   transport security.

## Assumptions

The guarantees above hold only if:

- **The CSPRNG works.** `RandomNumberGenerator.Fill` on Windows/Linux/macOS, hardware RNG on
  modern devices. A broken RNG breaks confidentiality and forward secrecy.
- **AES-256-GCM, HKDF-SHA256, and SHA-256 are not broken classically.** Quantum impact on
  symmetric primitives is a 2× key-length effect; AES-256 retains ≥128-bit post-quantum strength.
- **ML-KEM-768 or X25519 is unbroken.** Both can fall and you only need one to remain.
- **ML-DSA-65 is unbroken.** Signature forgery would let an attacker impersonate any identity in
  *new* handshakes; past sessions are unaffected.
- **Pinned identity keys reach clients via a path the adversary does not control.** Out-of-band
  by definition. Multi-pin (`AllowedServerIdentities`) helps during rotation but assumes the
  *initial* pin reached the client safely.
- **The endpoint is not compromised at the time the session is established.** Forward secrecy
  protects past traffic; nothing protects an actively compromised process.
- **No actor can replay the entire transport stream into a fresh session.** The handshake
  contains random nonces from both sides, so replays produce different traffic keys and the
  Finished MAC fails. This is structural; you do not need to defend it yourself.

## Adversary capabilities considered

| Adversary capability                                       | Defended? |
| ---------------------------------------------------------- | --------- |
| Passive recording of the wire                              | ✅        |
| Active modification of any byte on the wire                | ✅        |
| Replay of recorded records                                 | ✅ (strict or window) |
| Replay of the whole handshake                              | ✅ (fresh randoms / Finished) |
| Future quantum computer running Shor on captured traffic   | ✅ (hybrid KEM)       |
| Forge a record under a known-good tag                      | ✅ (AES-GCM)          |
| Forge a transcript signature without the ML-DSA seed       | ✅ (assuming ML-DSA)  |
| Adversarial sequence numbers driving memory growth         | ✅ (bitmap replay)    |
| Send the receiver above the AES-GCM safety bound           | ✅ (NIST caps + rekey)|
| Compromise either endpoint at runtime                      | ❌ (out of scope)     |
| Steal an identity seed from disk / memory                  | ❌ (out of scope)     |
| Substitute the pinned key before distribution              | ❌ (out of scope)     |
| Side-channel: timing / cache / power analysis              | ⚠ (best-effort only) |
| DoS by raw bandwidth / connection flooding                 | ❌ (your job)         |

---

**To God be the glory.** — *1 Corinthians 10:31*

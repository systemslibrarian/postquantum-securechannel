# Known Gaps & Honest Limitations

I would rather you know exactly what this library does and does not do than discover it the hard way.
This document is a deliberately candid account of the current state of PostQuantum.SecureChannel
(0.2.1-preview.1). None of these are hidden; they are design boundaries, deferred work, or honest
caveats.

If any of these gaps blocks your use case, please open an issue — it helps prioritize.

---

## 1. No independent security audit

The protocol and code have **not** been reviewed by an independent cryptographer or audit firm. The
X-Wing combiner is validated byte-for-byte against the published IETF test vectors, and the handshake
and session layers have a focused test suite — but tests prove the presence of correct behavior, not
the absence of flaws. **Treat this as preview-quality software.**

## 2. X-Wing is based on an IETF draft

X-Wing is specified in `draft-connolly-cfrg-xwing-kem` (revision 06 is the pinned reference), which is
on the standards track but **not yet a final RFC**. The construction is stable and widely implemented,
and this library matches all three published Known-Answer Test vectors, but the specification could
still change before final publication. When the RFC is published the implementation will be re-pinned
to it and the vectors re-validated; until then the wire format may change to track the draft.

## 3. Pre-1.0: the wire format and API are not yet stable

This is a preview. Message formats, the key schedule labels, and public APIs may change between
preview releases. There is **no cross-version interoperability guarantee** until 1.0. A protocol
version byte is present on every message so that future changes can be negotiated/rejected cleanly,
but version negotiation itself is not implemented.

## 4. Replay protection: strict ordering by default

`PqSession` defaults to enforcing a **strictly increasing per-direction sequence number**, which
assumes an in-order, reliable transport such as TCP. For unordered/lossy transports you can opt into a
DTLS/IPsec-style **sliding window** (`PqReplayProtection.SlidingWindow`). As of 0.2.1 the window is a
fixed-size bitmap allocated once at session construction — its memory footprint is bounded by
`ReplayWindowSize` and cannot be influenced by a peer's sequence-number choices. It is still
per-epoch (a key update resets it), and records from a previous epoch that arrive after a key update
are dropped. There is no message-loss recovery — the channel does not retransmit.

## 5. Rekeying is manual; resumption is experimental

In-band **key update** is supported (`PqSession.UpdateSendKey` / `PqSecureChannelStream.UpdateSendKeyAsync`):
each direction can ratchet to fresh keys without a new handshake. The hard caps per epoch are now
`PqSession.MaxRecordsPerEpoch = 2^32` (matching NIST SP 800-38D's deterministic-IV invocation cap)
and `PqSession.MaxBytesPerEpoch = 2^36` (~64 GiB, the AES-GCM data bound); exceeding either raises
`PqEpochExhaustedException`. A record/byte-threshold **auto-rekey policy** (`PqKeyUpdatePolicy`) is
available and honoured by the stream adapter, but it is **count-based, not time-based** — there is
no built-in periodic/timer rekey, and a key update is only emitted when you next send (it does not
proactively rekey an idle connection).

**Resumption** (`ResumptionSecret`) is **experimental**. It mixes a shared secret into the key schedule
of a *full* (still forward-secret) handshake to bind sessions together; it does **not** provide a
shortened round-trip, ticket lifetimes, anti-replay for 0-RTT, or any server-side ticket store. Both
peers must obtain and protect the secret out of band, and a mismatch aborts the handshake. It has not
been independently reviewed — treat it as a building block, not a finished resumption protocol.

## 6. Transport adapter is a convenience, not a hardened server

`PqSecureChannelStream` plus `ConnectAsync`/`AcceptAsync` give you a drop-in encrypted `Stream` with
length-prefixed framing over any transport, an optional `handshakeTimeout`, and a `CancellationToken`.
However: the core still does no I/O of its own; the stream expects one outstanding read and one
outstanding write at a time (it is not internally synchronized for concurrent reads or concurrent
writes); **post-handshake** read/write timeouts are still your responsibility (pass a token); and frame
size is bounded (16 MiB default) but there is no other DoS mitigation. You remain responsible for
connection lifecycle, timeouts, and back-pressure.

## 7. Identity trust is your responsibility (no PKI)

Authentication is via **raw-key pinning**: the client must obtain and pin the server's
`PqIdentityPublicKey` out of band, and (for mutual auth) the server pins/allowlists client keys.
As of 0.2.1, clients can pin multiple server identities at once via
`PqClientOptions.AllowedServerIdentities` to support staged rotation. There is **no certificate
chain, no CA, no revocation, and no expiry**. If a private identity seed is compromised, you must
rotate it and redistribute the public key yourself.

## 8. Side-channel resistance is inherited, not independently verified

Constant-time comparisons are used for authentication tags and pinned-key checks
(`CryptographicOperations.FixedTimeEquals`), and key material is zeroed on `Dispose`. However, the
overall timing/cache/power side-channel resistance is only as good as the underlying BouncyCastle and
.NET implementations, and this has **not** been independently measured for this library. Managed .NET
also cannot guarantee secret data is never copied by the GC.

## 9. Not constant-time against malformed input in every path

Message parsing aims to fail cleanly, but parsing/validation error paths are not guaranteed to be
constant-time. Do not rely on the *timing* of a handshake failure to be uninformative.

## 10. No formal protocol analysis

The handshake follows well-understood patterns (ephemeral KEM + signature authentication + transcript
binding + key confirmation, with HKDF key separation), but it has **not** been modeled in a formal
verification tool (Tamarin, ProVerif, etc.). It is not TLS, Noise, or any standardized protocol — it
is a purpose-built channel.

## 11. Test surface is growing but not exhaustive

The suite covers all three X-Wing Known-Answer Test vectors (wire-compatibility with any conformant
implementation), primitive round-trips, every handshake variant, session failure modes, key update,
anti-replay (both modes), resumption, version negotiation, the TCP stream adapter, and randomized
parser/record **fuzzing** that asserts only well-typed exceptions ever escape. It does **not** yet
include a formal property-based testing framework, exhaustive malformed-message enumeration, coverage
measurement, or a live interop harness running a *different* implementation in the same test run (the
KAT vectors are the interop check today).

## 12. Quantum authentication caveat

Confidentiality is hybrid post-quantum. Authentication uses ML-DSA (post-quantum) — good. But note
that the **"harvest now, decrypt later"** threat applies to *confidentiality*, which is why hybrid KEM
matters most today; a forged signature requires a quantum computer *now*, not later. ML-DSA addresses
this, but as with all of the above, it has not been independently audited in this integration.

---

## Summary

This library is built carefully, uses vetted primitives, and is validated against official test
vectors. It is a strong, secure-by-default starting point — and it is **preview software without an
independent audit**. Use it accordingly, read the code, and report anything that looks wrong.

---

**To God be the glory.** — *1 Corinthians 10:31*

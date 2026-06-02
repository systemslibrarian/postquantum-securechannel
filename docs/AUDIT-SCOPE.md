# Audit scope

A focused scope document for an external cryptographer or audit firm reviewing
PostQuantum.SecureChannel. The goal is to make the highest-risk surfaces obvious
and to be honest about what the project's own test suite does and does not cover.

> **Status:** preview, 0.3.0-preview.1. Primitives are vetted (BouncyCastle for
> ML-KEM, ML-DSA, X25519, SHA-3/SHAKE; .NET BCL for AES-256-GCM, HKDF, SHA-256,
> HMAC). The composition implemented in this repository has **not** been
> independently reviewed.

## What an external reviewer should examine

The six surfaces below are where protocol-composition bugs typically live. Each
links to the primary source location and to the tests in this repo that
exercise it. "Tested" here means "the repo asserts the documented behavior in
at least one case"; it does **not** mean exhaustively verified.

### 1. Three-message handshake orchestration

- **What:** the client / server state machine that produces and consumes
  `ClientHello`, `ServerHello`, `ClientFinished`; ordering, idempotence, and
  fail-closed behavior when a message is missing, out of order, replayed, or
  malformed. Mutual-auth and resumption variants.
- **Source:** `src/PostQuantum.SecureChannel/PqSecureChannel.cs`
  (`PqClientHandshake`, `PqServerHandshake`).
- **Repo tests covering it:** `HandshakeTests.cs`, `HandshakeDisposalTests.cs`,
  `MultiPinTests.cs`, `VersionNegotiationTests.cs`, `FuzzTests.cs` (randomized
  parser/record fuzzing — asserts only well-typed exceptions ever escape).
- **What the repo does *not* assert:** formal state-machine modelling
  (Tamarin / ProVerif), exhaustive enumeration of every malformed-message
  ordering, or constant-time behavior of the rejection paths.

### 2. Key schedule (HKDF labels and domain separation)

- **What:** every derived secret uses a distinct, versioned HKDF-SHA256 label
  framed inside a TLS 1.3-style `HkdfLabel` structure
  (`uint16 length ‖ uint8 label_len ‖ label ‖ uint8 context_len ‖ context`),
  so no two `(length, label, context)` triples can collide on the same `info`
  bytes. The `Extract` salt is `clientRandom ‖ serverRandom ‖ resumptionPsk`;
  `Expand` for the master secret is bound to the transcript hash; per-direction
  traffic secrets and `Finished` keys derive cleanly without label collision;
  `KeySchedule` is `IDisposable` and zeroes all intermediate buffers.
- **Source:** `src/PostQuantum.SecureChannel/Internal/KeySchedule.cs`,
  `Internal/Hkdf.cs` (`BuildInfo`), `Internal/PqProtocol.cs` (label constants
  and protocol version).
- **Repo tests covering it:** `KeyScheduleKatTests.cs` (pinned full-schedule
  KAT), `HkdfInfoFormatTests.cs` (byte-locks every call site's `info` bytes),
  `XWingTests.cs` (combiner KATs against the IETF draft),
  `HandshakeTests.cs` (end-to-end agreement), `SessionTests.cs` (round-trip).
- **What the repo does *not* assert:** formal proof that the schedule
  satisfies indistinguishability under chosen-handshake-context attack.
  A reviewer should walk `PqProtocol.cs` against `docs/protocol.md` to confirm
  every label is unique, versioned, and listed in both places.

### 3. Transcript binding

- **What:** signatures and the `Finished` MAC cover SHA-256 of *all* prior
  handshake bytes, with each fragment prefixed by its 4-byte big-endian length
  so concatenation ambiguity is impossible. Mutual-auth client signature must
  also bind the transcript so a stolen-and-replayed client signature from a
  different session is rejected.
- **Source:** `src/PostQuantum.SecureChannel/Internal/Transcript.cs`;
  transcript accumulation inside `PqClientHandshake` / `PqServerHandshake`.
- **Repo tests covering it:** `HandshakeTests.cs` (tamper / wrong-identity
  rejection), `TranscriptFramingTests.cs` (per-fragment length framing
  prevents ambiguous re-splits), `FuzzTests.cs` (random-byte mutations),
  `MultiPinTests.cs` (wrong pinned identity is rejected).
- **What the repo does *not* assert:** a higher-order transcript-equivalence
  attack — two *valid* but differently-structured transcripts that hash the
  same — is not exercised. A reviewer should confirm that every byte that
  influences key derivation is included in the transcript, exactly once, in
  a canonical order.

### 4. Anti-replay window

- **What:** the receive-side `PqReplayProtection.SlidingWindow` is a
  fixed-size bitmap whose memory footprint is bounded by `ReplayWindowSize` at
  session construction and cannot be influenced by a peer's sequence-number
  choices. Strict-ordered mode rejects any non-monotonic sequence. Both modes
  reset on key update; pre-epoch records arriving after rekey are dropped.
  `Commit` enforces the `IsAcceptable` precondition in code, not just by
  comment.
- **Source:** `src/PostQuantum.SecureChannel/Internal/AntiReplayWindow.cs`.
- **Repo tests covering it:** `AntiReplayTests.cs`, `AntiReplayBitmapTests.cs`,
  `AntiReplayWrapTests.cs` (sequences adjacent to `ulong.MaxValue`, large
  forward jumps, sparse adversarial sequences — locks in the Step-0 analysis
  that the wrap path correctly rejects).
- **What the repo does *not* assert:** behavior under adversarial sequence
  patterns specifically engineered to wedge the bitmap shift across epoch
  boundaries. A reviewer should verify the bitmap shift logic against the
  DTLS RFC 9147 anti-replay text.

### 5. Nonce construction (AES-256-GCM)

- **What:** per-direction 64-bit counters concatenated with a per-direction,
  per-epoch HKDF-derived 32-bit nonce-prefix. The construction must guarantee
  that no `(key, nonce)` pair ever repeats within an epoch and that a key
  update yields a fresh prefix. NIST SP 800-38D caps
  (`MaxRecordsPerEpoch = 2^32`, `MaxBytesPerEpoch = 2^36`) are enforced and
  exceeding either raises `PqEpochExhaustedException`.
- **Source:** `src/PostQuantum.SecureChannel/PqSession.cs` (nonce assembly,
  cap enforcement) and `Internal/KeySchedule.cs` (prefix derivation).
- **Repo tests covering it:** `SessionTests.cs` (round-trip),
  `EpochLimitTests.cs` (cap enforcement), `KeyUpdateTests.cs` and
  `AutoRekeyTests.cs` (prefix freshness after rekey),
  `RecordNonceKatTests.cs` (round-trip across an explicit `Ratchet()` boundary;
  asserts the nonce-prefix actually changes between epochs and that sequence
  counter resets to 0).
- **What the repo does *not* assert:** there is no test that programmatically
  enumerates a *very large* window of sequence numbers across a key update
  and asserts no reused 96-bit nonce ever appears. This is the single most
  catastrophic failure mode for AES-GCM, and even with the byte-locking and
  ratchet-boundary tests in place a reviewer may want a property-based
  no-nonce-reuse sweep.

### 6. Rekeying (key update)

- **What:** in-band `KeyUpdate` content-type records ratchet each direction
  independently; the old epoch's keys can no longer decrypt new traffic; the
  policy-driven auto-rekey path (`PqKeyUpdatePolicy`) trips at safe thresholds
  before the hard caps. `NeedsKeyUpdate` trips inside a 1/256 safety margin.
- **Source:** `PqSession.cs` (`UpdateSendKey`, `Open` for `KeyUpdate`),
  `PqSecureChannelStream.cs` (auto-rekey on send).
- **Repo tests covering it:** `KeyUpdateTests.cs`, `AutoRekeyTests.cs`,
  `EpochLimitTests.cs`, `RecordNonceKatTests.cs`.
- **What the repo does *not* assert:** behavior when both peers attempt a
  simultaneous key update on the same epoch (race on the same direction is
  ruled out structurally, but cross-direction interaction during rapid rekeys
  is not stress-tested). Auto-rekey is **count-based, not time-based** — an
  idle long-lived session does not proactively rekey.

## Cross-cutting items worth a separate look

- **Domain separation labels** in `Internal/PqProtocol.cs` — confirm every
  label is unique, includes the protocol version byte, and is documented in
  `docs/protocol.md`. The `HkdfLabel` framing makes silent collisions
  structurally impossible, but human review of label *choice* still matters.
- **Disposal and zeroization** — `PqClientHandshake`, `PqServerHandshake`,
  `KeySchedule`, and `PqSession` all implement `IDisposable` and zero secret
  material via `CryptographicOperations.ZeroMemory`. Verify there is no
  remaining `byte[]` holding key material that escapes a dispose path.
- **Constant-time comparisons** — tag and pinned-key checks use
  `CryptographicOperations.FixedTimeEquals`. Verify no `==`, `SequenceEqual`,
  or short-circuit comparison of secret material slipped in.
- **X-Wing combiner** — `Cryptography/XWing.cs` is validated byte-for-byte
  against the IETF draft test vectors (`XWingTests.cs`). The pinned draft
  revision is in `docs/protocol.md`. The combiner is the most sensitive code
  in the repo and the place where the spec is most likely to shift before
  RFC publication.

## What is out of scope for a first audit

- **PostQuantum.SecureChannel.AspNetCore** — DI wiring and a WebSocket-to-
  Stream adapter. Worth reviewing but secondary to the core protocol.
- **PostQuantum.SecureChannel.Testing** — in-memory duplex transport and a
  one-call harness, intended for test projects only.
- **Samples and benchmarks** — illustrative, not in the trusted path.

## Reporting

Vulnerabilities: see [`SECURITY.md`](../SECURITY.md). Scope-level findings
(things the audit identifies as out-of-test-coverage): please file as issues
so they can be added to the test suite.

---

**To God be the glory.** — *1 Corinthians 10:31*

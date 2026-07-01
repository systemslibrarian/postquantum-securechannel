# Changelog

All notable changes to PostQuantum.SecureChannel are documented here. This project follows
[Semantic Versioning](https://semver.org/). As of 1.0.0 the public API and wire format are stable:
breaking changes require a major-version bump. The one forward-looking caveat is the X-Wing combiner,
which tracks an IETF draft — a combiner change in the final RFC would be a major-version wire break
(see `KNOWN-GAPS.md` §2).

## [1.0.0]

**First stable release.** Commits to a stable public API and wire format (protocol version 2) under
Semantic Versioning. **There is no wire-format change from `0.3.0-preview.2`** — a peer built from
`0.3.0-preview.2` interoperates with `1.0.0`. This release is the stabilization of that wire format,
not a change to it.

### Added

- **Property-based no-nonce-reuse sweep** (`NonceUniquenessTests`). Enumerates the record-layer
  nonce (`ivPrefix ‖ sequence`) across a wide window at both ends of the `[0, 2^32)` sequence space
  and across many key-update epochs, asserting no 96-bit nonce ever repeats — the single most
  catastrophic AES-GCM failure mode. Closes `docs/AUDIT-SCOPE.md` §5's "no test that programmatically
  enumerates a very large window across a key update" gap.
- **Higher-order transcript-equivalence tests** (`TranscriptEquivalenceTests`). Order sensitivity,
  exhaustive three-way repartition of fixed flat bytes, pre-framed nesting confusion, forged
  length-prefix, and positional significance of empty fragments — asserting `Transcript.Hash` is an
  injective encoding of the ordered fragment *list*, not just its concatenation. Closes the
  transcript-equivalence item flagged in `docs/AUDIT-SCOPE.md` §3.

### Changed

- `PqProtocol.Version` remains `2`. API surface is now frozen under SemVer.

### Not changed

The X-Wing combiner, ML-DSA-65 signature flow, AES-256-GCM record framing, key schedule,
anti-replay logic, NIST SP 800-38D caps, and the three-message handshake state machine are all
identical to `0.3.0-preview.2`.

### Honest status

**1.0.0 has not been independently audited.** An external cryptographic review of the protocol
composition has not been performed and is not feasible at this time. The primitives are validated
against published IETF/NIST vectors and the composition is covered by this repository's own test
suite (now including the two additions above), but that is not a substitute for third-party review.
See `KNOWN-GAPS.md` §1. The "stable" commitment above is about API/wire compatibility, not an audit
claim.

## [0.3.0-preview.2]

**External-review remediation of the protocol glue.** This release bumps `PqProtocol.Version` from
`1` to `2`. It is a **wire-format break with `0.3.0-preview.1`** — v1 and v2 peers fail cleanly at
version negotiation (`PqProtocolException("No mutually supported protocol version...")`); they do
not silently mis-decrypt. Adopters running `0.3.0-preview.1` must update both ends to talk again.
See `KNOWN-GAPS.md` §13 and `docs/protocol.md` §10 for the full statement.

### Wire-format & protocol-version bump to 2

Two findings from an external adversarial review of the protocol glue land here:

- **HKDF info construction is now RFC 5869 / TLS 1.3-HkdfLabel compliant.** v1's wrapper concatenated
  `ASCII label ‖ context` with no length framing, working only because every call site used fixed
  labels and `context` was empty everywhere except the master expansion. The new construction is
  `uint16_BE(length) ‖ uint8(label_len) ‖ label ‖ uint8(context_len) ‖ context`, making
  `(length, label, context)` triples unambiguous by design and structurally precluding any future
  label addition from silently colliding. Source: external review, Finding 2.
- **Transcript hashing now length-prefixes each fragment.** `Transcript.Hash(a, b, …)` feeds
  `uint32_BE(len(a)) ‖ a ‖ uint32_BE(len(b)) ‖ b ‖ …` into SHA-256. v1's call sites passed two
  self-framed messages and were unambiguous in practice, but the helper signature accepts any
  fragment list — length framing makes future ambiguity impossible. Source: external review,
  Finding 3.
- **Domain-separation labels rebased** from `pqsc/v1 …` to `pqsc/v2 …` to make the wire change loud
  and visible. `PqProtocol.SupportedVersions = [2]` — no backwards-negotiation to v1, by design.

**What did NOT change:** the X-Wing combiner, ML-DSA-65 signature flow, AES-256-GCM record framing,
anti-replay bitmap shape, NIST SP 800-38D caps, and the three-message handshake state machine. This
is a key-schedule and transcript-framing change, not a protocol-redesign.

### Hardening (not wire-affecting)

- `AntiReplayWindow.Commit` actively enforces the precondition documented since 0.2.1: committing a
  sequence that `IsAcceptable` did not approve throws `InvalidOperationException`. Defense against a
  future caller forgetting the gate; no behavior change for correctly-gated callers. Source:
  external review, Finding 1e.

### New tests

- `KeyScheduleKatTests` — pinned KAT for the full schedule (master → traffic secrets, Finished keys,
  resumption secret) against an independently-rebuilt reference implementation.
- `HkdfInfoFormatTests` — byte-locks the new `Hkdf.BuildInfo` output for every call site so future
  label additions cannot silently collide.
- `TranscriptFramingTests` — pins the per-fragment length-prefix and the boundary-distinguishing
  property.
- `AntiReplayWrapTests` — regression-locks the analysis that sequence wrap rejects correctly.
- `RecordNonceKatTests` — round-trips at and across an explicit `Ratchet()` boundary; asserts the
  nonce-prefix actually changes and that the sequence counter resets to 0.

Suite is now 134 tests in the core project (450 total across the three projects × three TFMs).

### Honesty / maturity framing (no behavior change)

- README gains a prominent top-of-file status banner: preview, NOT independently audited, evaluation
  / internal-use only today. The existing security-properties table is unchanged but is now prefaced
  with "these are design intentions validated by the project's own tests, not audited guarantees."
- `docs/AUDIT-SCOPE.md` (new) — per-surface scope and test-coverage map for an external reviewer.
- `KNOWN-GAPS.md` §1 expanded with explicit protocol-composition risk language; §2 expanded with
  concrete IETF-draft wire-format consequences; new §13 covering the v1↔v2 non-interop.
- `docs/threat-model.md` — caveat above Goals and a key above the adversary-capability table
  clarifying that ✅ means "designed-and-tested-against", not "independently verified".

### Companion packages

`PostQuantum.SecureChannel.AspNetCore` and `PostQuantum.SecureChannel.Testing` ship in lockstep at
`0.3.0-preview.2`. They `<ProjectReference>` the core, so they inherit the wire-format break — a
0.3.0-preview.2 AspNetCore endpoint requires 0.3.0-preview.2 clients and vice versa.

## [0.3.0-preview.1]

An **ecosystem-foundation release**. No core wire-format changes — 0.3.0-preview.1 talks to 0.2.x
peers. What's new is shape: companion packages, samples that look like real production, and the
documentation real engineers ask for before adopting a crypto library. *(Superseded for new
adoption by `0.3.0-preview.2`, which is a wire-format break for the protocol-glue remediation
above.)*

### New packages
- **`PostQuantum.SecureChannel.AspNetCore`** — DI registration
  (`services.AddPostQuantumSecureChannel()`), `IConfiguration` binding for the server identity
  seed and pinned client keys, a `PqWebSocketStream` adapter that wraps any WebSocket as a
  `PqSecureChannelStream`, and a `MapPqWebSocket("/route", handler)` endpoint helper for minimal
  APIs. Includes a client-side `ws.AcceptPqClientAsync(options)` extension.
- **`PostQuantum.SecureChannel.Testing`** — `PqInMemoryDuplex.CreatePair()` for tests that need
  a real `Stream` pair without TCP, and `PqHandshakeHarness.Create()` that returns a connected
  `(Client, Server)` `PqSession` pair in one call (with opt-in mutual auth, resumption secret,
  and session preset).

### Observability
- **`ActivitySource` for distributed tracing.** Alongside the existing `EventSource` and `Meter`,
  every handshake now emits a `pqsc.handshake.{client,server}` activity with tags for mutual auth,
  resumption, and outcome. OpenTelemetry users: `AddSource("PostQuantum.SecureChannel")`.

### Samples (production shapes, not just echo)
- `samples/MicroserviceWebSocket.Server` + `.Client` — two ASP.NET Core services exchanging
  PQ-secured WebSocket traffic, identity loaded from configuration.
- `samples/WorkerControlPlane` — a `BackgroundService` worker dialing a control plane over TCP
  with `PqSessionOptions.Recommended` auto-rekey.
- `samples/QueueEnvelope` — `PqSession.Encrypt` / `Decrypt` for envelope encryption through an
  untrusted broker (the broker never sees plaintext).

### Documentation
- `docs/architecture.md` — one-page tour of the layers, handshake, key schedule, and trust model.
- `docs/threat-model.md` — goals, non-goals, assumptions, and an adversary-capability table.
- `docs/decision-guide.md` — when (not) to use this vs TLS / Noise / libsodium, with a
  comparison table and decision shortcuts.
- `docs/operations.md` — pinning, rotation playbook, choosing replay protection / rekey cadence,
  what to alert on, incident response on key compromise.
- `docs/troubleshooting.md` — every common exception with diagnosis and recovery steps.

### Benchmarks
- New `benchmarks/PostQuantum.SecureChannel.Benchmarks` (BenchmarkDotNet): X-Wing encap/decap,
  full handshake, record throughput at 64B / 1KiB / 16KiB / 256KiB. Run before each release.

### Includes everything from 0.2.1-preview.1
(the 0.2.1 preview was rolled into this release rather than published separately — see below.)

## [0.2.1-preview.1] — superseded, never published

A hardening and ergonomics release. **No wire-format changes** — peers running 0.2.0 and 0.2.1 are
interoperable.

### Security & correctness
- **DoS-resistant sliding-window anti-replay.** The previous `HashSet<ulong>`-backed window allocated
  per replay check; a peer using sparse sequence numbers could push the receiver into unbounded
  memory growth. Replaced with a fixed-size bitmap whose footprint is bounded by `ReplayWindowSize`
  at construction. Every check and commit is now O(1) and allocation-free.
- **NIST SP 800-38D safety bounds enforced.** Tightened `PqSession.MaxRecordsPerEpoch` from `2^48` to
  `2^32` (NIST's deterministic-IV invocation cap) and added `PqSession.MaxBytesPerEpoch = 2^36`
  (~64 GiB, the AES-GCM data bound). Reaching either now raises
  `PqEpochExhaustedException` instead of a generic `InvalidOperationException`, naming the limit and
  pointing callers at `UpdateSendKey`. `NeedsKeyUpdate` now also trips inside a 1/256th safety margin
  of either hard cap, so a well-behaved caller never reaches the exception.
- **Per-record plaintext cap.** `PqSession.Encrypt` rejects plaintexts above
  `PqSession.MaxRecordPlaintextSize` (1 GiB) with `ArgumentOutOfRangeException`, preventing a single
  record from straying near the AES-GCM single-call ciphertext bound.
- **Aborted handshakes no longer leak ephemeral key material.** `PqClientHandshake` and
  `PqServerHandshake` now implement `IDisposable`; disposing them zeroes any ephemeral X-Wing seed,
  client random, or partial key schedule still held. The successful-completion path now also
  disposes the local key schedule once the session has cloned what it needs.

### Adoption ergonomics
- **Multi-pinned server identities for staged rotation.** New
  `PqClientOptions.AllowedServerIdentities` accepts a collection of pinned keys; the handshake
  succeeds if the server's advertised identity matches any of them. Trust both the old and the new
  key during the rotation overlap window, then drop the old one.
- **Named `PqSessionOptions` presets.** `Default`, `Recommended` (auto-rekey for long-lived TCP),
  `UnorderedTransport` (sliding-window + auto-rekey), and `HighThroughput` (larger rekey thresholds).
  These replace hand-tuning for the most common deployments.
- **More specific exception taxonomy.** New `PqEpochExhaustedException`; finer reasons attached to
  diagnostic events (see below).

### Operational features
- **Built-in observability via `PqDiagnostics`.** An `EventSource` (`PostQuantum.SecureChannel`) for
  ETW / EventPipe / `dotnet-trace`, and a `Meter` of the same name for OpenTelemetry / `dotnet-counters`.
  Counters: `pqsc.handshakes.{started,completed,failed}`, `pqsc.records.rejected`,
  `pqsc.key_updates.{sent,received}`, `pqsc.epochs.exhausted`. Tagged with role, reason, direction,
  and limit type.

### Internal
- `Sha3.Hash256` / `Shake256` now use BouncyCastle's `ReadOnlySpan`-friendly digest API, removing
  intermediate `byte[]` copies of secret material on the X-Wing combiner path.
- `KeySchedule` is now `IDisposable` and zeroes its salt, PRK, master, traffic-secret, finished-key,
  and resumption-secret buffers.

### Tests
- 33 new tests across bitmap behavior, epoch limits, handshake disposal, multi-pin rotation,
  observability counters, and option presets. Suite is now 94 tests across `net8.0`, `net9.0`, and
  `net10.0`.

## [0.2.0-preview.1]

### Added
- **Async stream adapter** — `PqSecureChannel.ConnectAsync` / `AcceptAsync` and `PqSecureChannelStream`
  with length-prefixed framing.
- **In-band key update (rekey)** — `PqSession.UpdateSendKey()` ratchets each direction independently.
- **Sliding-window anti-replay** — `PqReplayProtection.SlidingWindow` for unordered/lossy transports.
- **Protocol version negotiation** — every handshake selects the highest mutually-supported version.
- **Experimental resumption** — `PqSession.ExportResumptionSecret()` plus `ResumptionSecret` options.
- **Automatic key-update policy** — `PqKeyUpdatePolicy` (records and/or bytes per epoch), surfaced as
  `PqSession.NeedsKeyUpdate`. `PqSecureChannelStream` ratchets automatically when crossed.
- **Handshake timeouts** — `ConnectAsync` / `AcceptAsync` accept a `handshakeTimeout` and throw
  `TimeoutException` if the handshake stalls.
- **Identity ergonomics** — `PqIdentityPublicKey.ToBase64()` / `FromBase64()` and a short,
  colon-grouped `ShortFingerprint()` for human-friendly pinning.
- **Runnable sample** — `samples/EchoDemo`, a TCP echo client/server demonstrating handshake,
  server verification, echo, and a mid-session key update.
- Expanded tests: all three X-Wing Known-Answer Test vectors and randomized parser/record fuzzing.
- CI matrix building and testing on net8.0 / net9.0 / net10.0 across Ubuntu and Windows.

### Changed
- **Wire format is not compatible with 0.1.x.** Handshake messages carry a supported-versions list and
  a negotiated version; records carry a content-type byte; the key schedule now derives ratcheting
  per-direction traffic secrets.

## [0.1.0-preview.1]

### Added
- Initial release: X-Wing (ML-KEM-768 + X25519) hybrid key agreement, ML-DSA-65 handshake
  authentication, HKDF-SHA256 key schedule, and AES-256-GCM sessions with replay protection.
- X-Wing combiner validated against the published IETF test vector.
- README, SECURITY, KNOWN-GAPS, protocol specification, and a focused test suite.

---

**To God be the glory.** — *1 Corinthians 10:31*

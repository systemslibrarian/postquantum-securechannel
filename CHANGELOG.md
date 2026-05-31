# Changelog

All notable changes to PostQuantum.SecureChannel are documented here. This project follows
[Semantic Versioning](https://semver.org/). While pre-1.0, the wire format and API may change between
preview releases.

## [0.3.0-preview.1]

An **ecosystem-foundation release**. No core wire-format changes — 0.3.0 talks to 0.2.x peers.
What's new is shape: companion packages, samples that look like real production, and the
documentation real engineers ask for before adopting a crypto library.

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

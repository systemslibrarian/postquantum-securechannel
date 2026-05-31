# Changelog

All notable changes to PostQuantum.SecureChannel are documented here. This project follows
[Semantic Versioning](https://semver.org/). While pre-1.0, the wire format and API may change between
preview releases.

## [Unreleased]

### Added
- **Automatic key-update policy** — `PqKeyUpdatePolicy` (records and/or bytes per epoch), surfaced as
  `PqSession.NeedsKeyUpdate`. `PqSecureChannelStream` ratchets automatically when the threshold is
  crossed.
- **Handshake timeouts** — `ConnectAsync` / `AcceptAsync` accept a `handshakeTimeout` and throw
  `TimeoutException` if the handshake stalls.
- **Identity ergonomics** — `PqIdentityPublicKey.ToBase64()` / `FromBase64()` and a short,
  colon-grouped `ShortFingerprint()` for human-friendly pinning.
- **Runnable sample** — `samples/EchoDemo`, a TCP echo client/server demonstrating handshake,
  server verification, echo, and a mid-session key update.

## [0.2.0-preview.1]

### Added
- **Async stream adapter** — `PqSecureChannel.ConnectAsync` / `AcceptAsync` and `PqSecureChannelStream`
  with length-prefixed framing.
- **In-band key update (rekey)** — `PqSession.UpdateSendKey()` ratchets each direction independently.
- **Sliding-window anti-replay** — `PqReplayProtection.SlidingWindow` for unordered/lossy transports.
- **Protocol version negotiation** — every handshake selects the highest mutually-supported version.
- **Experimental resumption** — `PqSession.ExportResumptionSecret()` plus `ResumptionSecret` options.
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

# CLAUDE.md — Project Conventions for PostQuantum.SecureChannel

Guidance for AI assistants (and humans) working in this repository. The goal is to preserve the
security, clarity, and honesty this project is built on.

## What this project is

A high-level, secure-by-default post-quantum **secure channel / session encryption** library for
.NET. It establishes authenticated sessions with **X-Wing** hybrid key agreement (ML-KEM-768 +
X25519) and **ML-DSA-65** signatures, then protects traffic with **AES-256-GCM**. It is part of the
`PostQuantum.*` family and must match its standards.

## Non-negotiable principles

1. **Security correctness first.** Never weaken a cryptographic guarantee for convenience. When in
   doubt, choose the conservative, standards-aligned option.
2. **Validate against test vectors.** Any change to the X-Wing core, key schedule, or wire format must
   keep `XWingTests.MatchesPublishedTestVector` passing. Cryptographic primitives are validated against
   official IETF/NIST vectors, not just self-consistency.
3. **Secure by default; no insecure knobs.** Algorithms and parameters are fixed
   (ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA-256/SHA3-256, HKDF-SHA256). Do not add configuration that
   could produce an insecure configuration.
4. **Be honest.** If something is unaudited, incomplete, or assumes a precondition, document it in
   [`KNOWN-GAPS.md`](KNOWN-GAPS.md). Never overstate guarantees in code comments, docs, or commit
   messages.
5. **No I/O in the core.** The library is transport-agnostic: it produces and consumes `byte[]`. Keep
   networking, framing, and persistence out of it.

## Cryptographic conventions

- **Primitives:** ML-KEM, ML-DSA, X25519, SHA-3/SHAKE come from **BouncyCastle.Cryptography**.
  AES-256-GCM, HKDF, SHA-256, HMAC come from the **.NET BCL**. Do not hand-roll primitives.
- **The X-Wing combiner is implemented here** and is the most sensitive code. Order of inputs and the
  domain label are spec-defined: `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`. Do not change it.
- **Domain separation:** every derived secret uses a distinct, versioned HKDF label
  (see `Internal/PqProtocol.cs`). Add new labels rather than reusing existing ones.
- **Randomness** goes through `Internal/RandomBytes` (platform CSPRNG) — never `System.Random`.
- **Key material** is zeroed on `Dispose` via `CryptographicOperations.ZeroMemory`. Comparisons of
  secrets/tags use `CryptographicOperations.FixedTimeEquals`.
- **Bump the protocol version** (`PqProtocol.Version`) and document any wire-format change.

## Code style

- Target `net8.0;net9.0;net10.0`. Keep it building on all three. `Nullable` and `ImplicitUsings` are
  on; warnings are errors. Do not suppress warnings without justification.
- Public API: XML doc comments on every public type and member. Keep the surface small and obvious.
- Internal helpers live under `Internal/`; cryptographic building blocks under `Cryptography/`.
- Prefer `Span<byte>`/`ReadOnlySpan<byte>` on hot/crypto paths; avoid unnecessary allocations and
  copies of secret data.
- Match the voice of the existing docs: clear, precise, and candid.

## Testing

- Run `dotnet test` before committing. Add tests for any new behavior.
- Every security-relevant change needs a test demonstrating both the success path and the rejection
  path (e.g., tamper, replay, wrong identity).
- Test categories: test-vector validation, primitive round-trips, handshake variants, session failure
  modes. Keep these green.

## Documentation expectations

When you change behavior, update in the same change:

- `README.md` — usage and security posture.
- `KNOWN-GAPS.md` — if you add, close, or change a limitation.
- `SECURITY.md` — if reporting/scope changes.
- XML doc comments — for any API change.

## Commit / PR conventions

- Clear, scoped commits explaining the *why*, especially for crypto changes.
- Never commit private key material, seeds, or real secrets.
- Do not claim "audited", "production-ready", or "unbreakable". This library is preview, unaudited,
  and honest about it.

---

**To God be the glory.** — *1 Corinthians 10:31*

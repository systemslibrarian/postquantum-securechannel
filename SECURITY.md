# Security Policy

PostQuantum.SecureChannel is security-critical software. I take reports seriously and aim to be
transparent about both its strengths and its limits.

## Status

**This is 1.0.0. The API and wire format are stable, but it has not undergone an independent security
audit** — and one is not feasible at this time. The cryptographic core is validated against published
IETF/NIST test vectors and the protocol composition is covered by this repository's own test suite,
but absence of a finding is not a proof of security. Do not rely on it as your sole protection for
high-value secrets if you cannot accept the risk of an unreviewed composition. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §1 for specifics.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ |
| 0.x-preview | ❌ (superseded by 1.0; `0.3.0-preview.2` is wire-compatible with 1.0 but unsupported) |

Under Semantic Versioning, the `1.x` line receives fixes; breaking API or wire changes would ship as
a new major version. The pre-1.0 previews are no longer supported.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using **[GitHub Security Advisories](https://github.com/systemslibrarian/postquantum-securechannel/security/advisories/new)**
("Report a vulnerability"), which keeps the discussion confidential until a fix is ready.

Please include, where possible:

- A description of the issue and its security impact.
- Affected version(s) and target framework(s).
- Minimal steps or a proof-of-concept to reproduce it.
- Any suggested remediation.

### What to expect

- **Acknowledgement:** within 5 business days.
- **Assessment & triage:** I will confirm the issue and assess severity, and keep you updated.
- **Fix & disclosure:** I will work on a fix and coordinate a disclosure timeline with you. Credit is
  gladly given to reporters who wish to be named.

## Scope

In scope:

- Flaws in the handshake, key schedule, authentication, record encryption, or key update.
- Incorrect use of the underlying primitives (ML-KEM, ML-DSA, X25519, AES-GCM, HKDF).
- Deviations from the X-Wing specification.
- Replay-protection or sequence-handling weaknesses (strict or sliding-window).
- Memory-handling issues with key material.

Out of scope (but still welcome as regular issues):

- Vulnerabilities in dependencies (please also report upstream to BouncyCastle / .NET).
- Misuse that the documentation explicitly warns against (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md)).

## Cryptographic primitives

This library relies on:

- **ML-KEM-768 / ML-DSA-65 / X25519 / SHA-3 / SHAKE** — from
  [BouncyCastle.Cryptography](https://www.bouncycastle.org/).
- **AES-256-GCM / HKDF-SHA256 / SHA-256 / HMAC** — from the .NET base class library.

The X-Wing combiner and the channel protocol (handshake, key schedule, record format) are implemented
in this repository and are the primary subject of any review.

---

**To God be the glory.** — *1 Corinthians 10:31*

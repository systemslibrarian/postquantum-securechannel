# Security Policy

PostQuantum.SecureChannel is security-critical software. I take reports seriously and aim to be
transparent about both its strengths and its limits.

## Status

**This is a preview (0.2.0-preview.1) and has not undergone an independent security audit.** The
cryptographic core is validated against published IETF/NIST test vectors, but absence of a finding is
not a proof of security. Do not rely on it as your sole protection for high-value secrets until it has
been independently reviewed. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for specifics.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x-preview | ✅ (pre-release, best-effort) |

Until 1.0, only the latest preview is supported. APIs and the wire format may change between previews.

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

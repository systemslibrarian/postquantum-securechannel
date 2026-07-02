# Interop vectors

Language-neutral test vectors for **PostQuantum.SecureChannel protocol version 2**. They exist so an
implementation in *any* language can verify it reproduces this library's composition byte-for-byte —
the part no external standard covers.

## What's here

[`composition-vectors.v2.json`](composition-vectors.v2.json) pins the four surfaces a second
implementation must match to interoperate:

1. **`hkdfInfo`** — the TLS 1.3-style `HkdfLabel` info construction
   (`uint16_BE(length) ‖ uint8(label_len) ‖ label ‖ uint8(context_len) ‖ context`).
2. **`transcriptHash`** — SHA-256 over each fragment prefixed by its `uint32_BE` length.
3. **`keySchedule`** — the full HKDF-SHA256 schedule (salt, PRK, master, and all five derived
   secrets), with and without a resumption pre-shared secret.
4. **`recordKeying`** — the per-direction AES-256-GCM key, IV prefix, nonce construction, and the
   key-update ratchet, derived from a direction's traffic secret.

Every entry has an `input` and an `output`; a conformant implementation fed the `input` MUST produce
the `output`.

## What's *not* here

The **X-Wing KEM** (ML-KEM-768 + X25519 combiner) is validated separately, byte-for-byte, against the
three published IETF Known-Answer Test vectors from `draft-connolly-cfrg-xwing-kem` — see
[`../../tests/PostQuantum.SecureChannel.Tests/XWingTests.cs`](../../tests/PostQuantum.SecureChannel.Tests/XWingTests.cs).
Reuse those upstream vectors for the KEM; these vectors cover the glue this repository owns.

## Provenance

This file is **generated from the running implementation** and self-verified in CI: `InteropVectorTests`
regenerates the vectors on every test run and fails if the library's output drifts from the checked-in
file. So the vectors can never silently diverge from the code that produced them. To regenerate after an
intentional (major-version) protocol change, delete the file and re-run the test suite.

See [`../protocol.md`](../protocol.md) for the full wire-format and key-schedule specification these
vectors accompany.

---

**To God be the glory.** — *1 Corinthians 10:31*

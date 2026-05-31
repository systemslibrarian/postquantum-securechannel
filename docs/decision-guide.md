# Should I use PostQuantum.SecureChannel?

A blunt comparison page. The goal is to help you choose the right tool quickly, not to claim this
library is better at everything. The library author wrote this; expect it to be honest about
weaknesses.

## When to reach for this library

- You run **.NET services that talk to each other** (microservices, workers, agents, devices) and
  you want PQ-safe confidentiality on the application layer.
- You can **pin a server identity out of band** — a config file, a secret manager, an environment
  variable. You don't need certificate authorities and you don't want to operate one.
- The data is **valuable for years** and a future quantum adversary could plausibly decrypt
  recorded TLS traffic later (the "harvest now, decrypt later" threat).
- You're already running over TCP, WebSockets, named pipes, or a message queue — you want a
  drop-in encrypted `Stream` (or `Encrypt`/`Decrypt` envelope) you can wrap around any of them.
- You want **mutual authentication** without designing the protocol yourself.

## When *not* to use this library

- You need to talk to a web browser. Browsers speak TLS, not this. Front your service with TLS
  and stop here.
- You need PKI: chains of trust, CRLs, OCSP, ACME, X.509. This library is raw-key pinning by
  design. Use TLS with a proper CA.
- You need a finalized standard with broad cross-language tooling today. The cryptographic
  primitives are standardized (FIPS 203, FIPS 204); the X-Wing combiner is still on the IETF
  standards track (`draft-connolly-cfrg-xwing-kem`).
- You need an audited, production-ready library. This is preview, unaudited; see
  [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).

## Comparison

| | **PostQuantum.SecureChannel** | TLS 1.3 | Noise Protocol Framework | libsodium |
|---|---|---|---|---|
| Transport dependency | None (any `byte[]` or `Stream`) | TCP-shaped (TLS records) | None (handshake patterns only) | None (primitives only) |
| PQ confidentiality | ✅ X-Wing hybrid | ⚠ Hybrid KEX in TLS 1.3 with newer drafts only | varies by pattern | ❌ no PQ KEM today |
| Mutual auth | ✅ ML-DSA, pinned keys | ✅ X.509 client certs | ✅ static keys / patterns | DIY |
| Trust model | Raw-key pinning | X.509 / WebPKI / mTLS | Raw-key, your choice | DIY |
| Operational maturity | Preview, unaudited | Decades, audited | Mature, well-modelled | Mature, widely deployed |
| Cross-language interop | Spec is small; only .NET implementation today | Universal | Many implementations | C / wrappers everywhere |
| Browser compatibility | ❌ | ✅ | ❌ | ❌ |
| Best for | .NET-to-.NET app-layer channels with PQ defence in depth | Any transport security, anywhere | Custom protocols, embedded devices | Building your own crypto |
| Worst for | Public-internet endpoints; browser clients; multi-language fleets today | Replacing application-layer envelope encryption | Drop-in TLS replacement | Anything but primitives |

## Decision shortcuts

> **"I want PQ-safe encryption between my .NET services and I'm comfortable pinning keys."**
> → This library.

> **"I'm a browser or mobile app talking to a server."**
> → TLS. Don't even think about it.

> **"I'm building a custom protocol from scratch and I want a framework."**
> → Noise Protocol Framework.

> **"I just need primitives — KEMs, signatures, hashes — and I'll glue them myself."**
> → libsodium or BouncyCastle directly. Read carefully and write tests against vectors.

> **"I'm protecting messages in a queue that the broker shouldn't be able to read."**
> → This library's `PqSession.Encrypt` / `Decrypt`. See `samples/QueueEnvelope`.

> **"My data is long-lived secrets and I'm worried about harvest-now-decrypt-later."**
> → Any hybrid PQ option is correct, including this one.

## Defense in depth

The right answer in production is often **both**: run TLS at the edge, then layer this library
inside it for application-level mutual authentication and PQ-safe envelope encryption. TLS handles
the public-internet ceremony; this library gives you a small, auditable, transport-agnostic core
for the messages you cannot afford to lose to a future quantum adversary.

---

**To God be the glory.** — *1 Corinthians 10:31*

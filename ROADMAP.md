# Roadmap

An honest, public plan for PostQuantum.SecureChannel. It is deliberately candid about what is done,
what is deferred, and — most importantly — what this project **cannot** do on its own. Items are
grouped by how much they actually move the needle, not by how easy they are.

This roadmap complements [`KNOWN-GAPS.md`](KNOWN-GAPS.md) (current limitations) and
[`docs/AUDIT-SCOPE.md`](docs/AUDIT-SCOPE.md) (the brief an external reviewer would follow).

---

## Ground rules

- **1.x is wire-stable.** Anything that changes the wire format (protocol version 2) ships as a **new
  major version (2.0)** with migration guidance — never silently inside 1.x. Wire-affecting roadmap
  items are marked **[2.0]** below.
- **Additive, source-compatible API and behavior changes** ship inside 1.x (minor versions).
- **Honesty over optics.** "Stable" means API/wire compatibility, not "audited." The unaudited status
  stays disclosed until it changes.

---

## Tier 1 — confidence gates (highest value)

These are what would turn "carefully engineered" into "independently assured." Two of the three are
**not things code can buy.**

1. **Independent security audit — blocked on funding.**
   The composition (handshake, key schedule, transcript binding, nonce construction, replay window)
   has not been reviewed by an external cryptographer, and the maintainer is **not currently able to
   fund one.** `docs/AUDIT-SCOPE.md` is a ready-to-use scope document if funding, a sponsor, or a
   program such as a Microsoft/OSS security-review grant becomes available. Until then this gap stays
   open and stated plainly. Everything else on this roadmap is chosen to make an eventual audit
   cheaper and to substitute defense-in-depth where an audit would otherwise be the only assurance.

2. **X-Wing RFC tracking.**
   The combiner tracks `draft-connolly-cfrg-xwing-kem`. When the RFC finalizes: re-pin, re-validate
   the three published KAT vectors, and — if the combiner changed — ship as **[2.0]** with explicit
   interop guidance. Until then the wire format is draft-pinned, not standards-pinned.

3. **Formal protocol model (ProVerif / Tamarin).** *(in progress — see [`formal/`](formal/))*
   A mechanized model of the handshake checking secrecy, mutual authentication, and absence of
   signature/transcript reflection. This is the closest thing to an audit that can be produced without
   hiring one, and it is fully within reach. The model in `formal/` is authored and **wired into CI as
   an advisory (non-blocking) job** that installs ProVerif and runs it on every push
   (`.github/workflows/ci.yml`). It stays advisory — and is not cited as a proof — until a verified pass
   is confirmed and reviewed, at which point the job becomes blocking. Mutual-auth (Q3) and a
   forward-secrecy phase are the next additions to the model.

## Tier 2 — correctness & robustness hardening

4. **Time-based auto-rekey.** *(done)*
   `PqKeyUpdatePolicy.MaxAge` bounds the wall-clock age of an active send epoch, complementing the
   existing record/byte thresholds. Uses an injectable `TimeProvider` so it is deterministically
   testable. Note: like the count/byte thresholds, it triggers on the next send — a fully idle
   connection is still not proactively rekeyed (that needs application-driven timers).

5. **Zero transient KEM/signature intermediates.** *(done)*
   The expanded ML-KEM/X25519 private key, the per-operation KEM shared-secret halves, and the seed
   copies handed to BouncyCastle are now zeroed after use, tightening the "secrets zeroed" boundary
   beyond just the long-lived `IDisposable` key material.

6. **Authenticated close / truncation detection.** **[2.0]**
   A `close_notify`-equivalent so a cut connection is distinguishable from a clean end-of-stream. This
   adds a control record type, so it is a wire change. Until then, applications needing truncation
   detection should carry their own end-of-message marker (documented in `KNOWN-GAPS.md` §6).

6a. **On-wire epoch field for reordering-robust rekey.** **[2.0]**
   Key-update records carry no epoch identifier today, so a rekey interleaved with reordering or loss on
   an unordered transport can drop records or permanently desynchronize a direction (`KNOWN-GAPS.md` §5).
   An authenticated epoch field on each record — letting the receiver select the right epoch's keys and
   detect a missed key update — makes rekeying robust under `SlidingWindow`, but changes the record
   header, so it ships as a wire break with the other **[2.0]** items.

## Tier 3 — features (deferred, non-gating)

7. **Mature resumption.** **[2.0-ish]**
   Today's `ResumptionSecret` is experimental (no shortened round-trip, ticket store, lifetimes, or
   0-RTT anti-replay). A real resumption protocol is a design effort in its own right and would touch
   the wire.

8. **Client-identity confidentiality.** **[2.0]**
   Encrypt the client identity/signature in `ClientFinished` so a passive observer cannot see which
   pinned client is connecting (`KNOWN-GAPS.md` §7). Wire-affecting.

9. **Full-duplex / internally-synchronized stream.**
   The stream is one-outstanding-read / one-outstanding-write by contract. An internally-synchronized
   variant is additive and could land in 1.x.

10. **PKI-optional trust.** Beyond raw-key pinning — CA chains, expiry, revocation — for adopters who
    want it. Pinning stays the default (simpler and safer for most). Low priority.

## Tier 4 — engineering & release hygiene

11. **CI on all TFMs + pack.** *(done)* `.github/workflows/ci.yml` builds Release (warnings-as-errors)
    and runs the full suite — including the public-API freeze guard — on net8/9/10 across Ubuntu and
    Windows, plus a pack-validation job.

12. **Property-based testing.** *(in progress)* Dependency-free property tests over record round-trips,
    the replay window, and framing, complementing the existing fuzz and KAT suites (`AUDIT-SCOPE.md`
    §11).

13. **`Microsoft.DotNet.PackageValidation` baseline.** Machine-enforced API/ABI compatibility across
    future 1.x releases. Requires a published `1.0.0` to baseline against, so it lands **after** the
    first public release; the in-repo public-API freeze test guards the surface until then.

14. **Live interop harness.** *(largely done)* `MlKemInteropTests` and `MlDsaInteropTests` cross-check
    ML-KEM-768 and ML-DSA-65 between BouncyCastle (what this library uses) and .NET's independent
    built-in `MLKem`/`MLDsa` — key generation and both encapsulation / both signing directions must
    agree (net10+, where the platform supports it). Remaining: ideally a second full *X-Wing*
    implementation (combiner included) in the loop (`AUDIT-SCOPE.md` §11).

15. **Coverage & perf-regression gates.** *(coverage done)* CI collects code coverage
    (`coverlet.collector`; a dedicated `coverage` job uploads a Cobertura report — core library line
    coverage is ~89%). Remaining: tracked benchmarks so performance regressions fail the build.

---

## What "done" looks like without an audit

Realistically, absent external review this project can reach: **stable, wire-frozen, formally modeled,
property- and KAT-tested, fully zeroized, CI-gated on three runtimes and two OSes, and honest about
being unaudited.** That is a strong place for a single-maintainer PQ library to be — and it is the
target this roadmap drives toward. The audit remains the one thing that needs a hand from outside.

---

**To God be the glory.** — *1 Corinthians 10:31*

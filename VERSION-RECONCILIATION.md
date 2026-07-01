# VERSION-RECONCILIATION.md

## Suite-assigned version

**1.0.0** — applies to all three packages in this repo:

- `PostQuantum.SecureChannel`
- `PostQuantum.SecureChannel.AspNetCore`
- `PostQuantum.SecureChannel.Testing`

The AspNetCore and Testing packages move in exact lockstep with the core
`PostQuantum.SecureChannel` package; they share its `<Version>` element value
and ship together.

## What changed in this reconciliation pass

All three `.csproj` files were bumped from `0.3.0-preview.2` to `1.0.0`, with
`<AssemblyVersion>` and `<FileVersion>` pinned to `1.0.0.0`. The version is
**not** centralized in a `Directory.Build.props`; each project declares its own
`<Version>` element and they are kept in sync by this convention. The `README.md`
badges/install commands, `CHANGELOG.md`, `KNOWN-GAPS.md`, `docs/protocol.md`, and
`docs/AUDIT-SCOPE.md` were updated to `1.0.0` in the same pass.

> **Wire format is unchanged from `0.3.0-preview.2`.** `PqProtocol.Version` stays
> at `2`; a `0.3.0-preview.2` peer interoperates with `1.0.0`. 1.0 stabilizes that
> wire format under SemVer rather than changing it. The one anticipated future
> wire break is the X-Wing combiner tracking its final RFC, which would ship as a
> major version (`2.0`). See `CHANGELOG.md`, `KNOWN-GAPS.md` §2/§3, and
> `docs/protocol.md`.

## Inter-package dependency constraints

| From → To | Constraint | How enforced |
| --- | --- | --- |
| `PostQuantum.SecureChannel` → `PostQuantum.Cryptography` | (n/a — not referenced in this repo) | The SecureChannel project does **not** depend on a `PostQuantum.Cryptography` NuGet package. It consumes ML-KEM, ML-DSA, X25519, and SHA-3/SHAKE directly from `BouncyCastle.Cryptography 2.6.2`. No pin was added because no such dependency exists, and a phantom dependency was explicitly rejected during reconciliation. If a future release switches to `PostQuantum.Cryptography`, this row must pin `= 1.0.0-rc.1`. |
| `PostQuantum.SecureChannel.AspNetCore` → `PostQuantum.SecureChannel` | exactly `1.0.0` | Enforced via `<ProjectReference>`; at pack time NuGet emits a dependency on the referenced project's own `<Version>`. |
| `PostQuantum.SecureChannel.Testing` → `PostQuantum.SecureChannel` | exactly `1.0.0` | Same — `<ProjectReference>` to the SecureChannel project. |

## Maturity-ordering invariant

Each package's stated maturity must be **less than or equal to** the maturity
of every dependency it advertises. Preview < rc < stable.

| Package | Maturity | Depends on | Dependency maturity | OK? |
| --- | --- | --- | --- | --- |
| `PostQuantum.SecureChannel` | stable (`1.0.0`) | `BouncyCastle.Cryptography 2.6.2` | stable | OK — stable ≤ stable |
| `PostQuantum.SecureChannel.AspNetCore` | stable (`1.0.0`) | `PostQuantum.SecureChannel 1.0.0` | stable | OK — equal |
| `PostQuantum.SecureChannel.Testing` | stable (`1.0.0`) | `PostQuantum.SecureChannel 1.0.0` | stable | OK — equal |

No package in this repo advertises more maturity than anything it depends on.
Note that "stable" here is a **SemVer API/wire-compatibility** statement, not an
audit statement — see below.

## Audit posture

`PostQuantum.SecureChannel` is the package in the suite most in need of an
external composition audit: it is where the X-Wing combiner, the handshake
transcript, the HKDF key schedule, the AES-256-GCM record layer, and the
anti-replay logic all come together. Component primitives are validated against
published IETF/NIST test vectors, but the composition has **not** had an
independent security review, and one is **not feasible at this time**. Shipping
`1.0.0` stabilizes the API and wire format; it does not change the audit posture.
The "not independently audited" caveat in `README.md` and `KNOWN-GAPS.md` §1
stays prominent regardless of version number until such a review happens. See
`docs/AUDIT-SCOPE.md` for the per-surface test-coverage map a reviewer should
walk.

---

**To God be the glory.** — *1 Corinthians 10:31*

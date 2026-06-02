# VERSION-RECONCILIATION.md

## Suite-assigned version

**0.3.0-preview.1** — applies to all three packages in this repo:

- `PostQuantum.SecureChannel`
- `PostQuantum.SecureChannel.AspNetCore`
- `PostQuantum.SecureChannel.Testing`

The AspNetCore and Testing packages move in exact lockstep with the core
`PostQuantum.SecureChannel` package; they share its `<Version>` element value
and ship together.

## What changed in this reconciliation pass

All three `.csproj` files were already at `0.3.0-preview.1` (set in commit
`fc512a7` — "Ship 0.3.0-preview.1: ecosystem foundation"). No `<Version>` edits
were necessary. The version is **not** centralized in a `Directory.Build.props`;
each project declares its own `<Version>` element and they are kept in sync by
this convention.

The `README.md` version badge and install commands already reference
`0.3.0-preview.1`. The `CHANGELOG.md` already contains a `[0.3.0-preview.1]`
entry. No edits were required.

> **Note on post-publication remediation within `0.3.0-preview.1`.** An external
> review landed two wire-format-affecting changes inside the `0.3.0-preview.1`
> window (HKDF info construction and transcript framing). The package version
> stays at `0.3.0-preview.1` per the suite-level decision that preview tags
> absorb wire changes, but `PqProtocol.Version` bumps from `1` to `2`. Peers
> running pre-remediation `0.3.0-preview.1` will not interoperate with this
> build; the handshake fails cleanly at version negotiation. See `CHANGELOG.md`
> and `KNOWN-GAPS.md` §13 for the full statement.

## Inter-package dependency constraints

| From → To | Constraint | How enforced |
| --- | --- | --- |
| `PostQuantum.SecureChannel` → `PostQuantum.Cryptography` | (n/a — not referenced in this repo) | The SecureChannel project does **not** depend on a `PostQuantum.Cryptography` NuGet package. It consumes ML-KEM, ML-DSA, X25519, and SHA-3/SHAKE directly from `BouncyCastle.Cryptography 2.6.2`. No pin was added because no such dependency exists, and a phantom dependency was explicitly rejected during reconciliation. If a future release switches to `PostQuantum.Cryptography`, this row must pin `= 1.0.0-rc.1`. |
| `PostQuantum.SecureChannel.AspNetCore` → `PostQuantum.SecureChannel` | exactly `0.3.0-preview.1` | Enforced via `<ProjectReference>`; at pack time NuGet emits a dependency on the referenced project's own `<Version>`. |
| `PostQuantum.SecureChannel.Testing` → `PostQuantum.SecureChannel` | exactly `0.3.0-preview.1` | Same — `<ProjectReference>` to the SecureChannel project. |

## Maturity-ordering invariant

Each package's stated maturity must be **less than or equal to** the maturity
of every dependency it advertises. Preview < rc < stable.

| Package | Maturity | Depends on | Dependency maturity | OK? |
| --- | --- | --- | --- | --- |
| `PostQuantum.SecureChannel` | preview (`0.3.0-preview.1`) | `BouncyCastle.Cryptography 2.6.2` | stable | OK — preview ≤ stable |
| `PostQuantum.SecureChannel` | preview (`0.3.0-preview.1`) | *(would be `PostQuantum.Cryptography 1.0.0-rc.1` if referenced)* | rc | OK — preview ≤ rc |
| `PostQuantum.SecureChannel.AspNetCore` | preview (`0.3.0-preview.1`) | `PostQuantum.SecureChannel 0.3.0-preview.1` | preview | OK — equal |
| `PostQuantum.SecureChannel.Testing` | preview (`0.3.0-preview.1`) | `PostQuantum.SecureChannel 0.3.0-preview.1` | preview | OK — equal |

No package in this repo advertises more maturity than anything it depends on.

## Audit posture

`PostQuantum.SecureChannel` is the package in the suite most in need of an
external composition audit: it is where the X-Wing combiner, the handshake
transcript, the HKDF key schedule, the AES-256-GCM record layer, and the
anti-replay logic all come together. Component primitives are validated against
published IETF/NIST test vectors, but the composition has **not** had an
independent security review. The "preview / not independently audited" caveat
in `README.md` and `KNOWN-GAPS.md` stays prominent regardless of version
number until that audit happens. See `docs/AUDIT-SCOPE.md` for the per-surface
test-coverage map a reviewer should walk.

---

**To God be the glory.** — *1 Corinthians 10:31*

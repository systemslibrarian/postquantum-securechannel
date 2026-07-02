# Releasing PostQuantum.SecureChannel

This project ships three packages in lockstep — `PostQuantum.SecureChannel`,
`PostQuantum.SecureChannel.AspNetCore`, and `PostQuantum.SecureChannel.Testing` — all at the same
version. Releases are automated by [`.github/workflows/release.yml`](.github/workflows/release.yml),
which is designed so that anyone can independently verify what they installed.

## What a release produces

Pushing a `vX.Y.Z` tag builds, runs the **full test suite on net8/9/10** (including the public-API
freeze guard), then:

1. **Packs** the three packages (deterministic, SourceLink-enabled, symbols as `.snupkg`).
2. **Generates a CycloneDX SBOM** and attaches it to the GitHub release.
3. **Attests build provenance** for every `.nupkg` (verifiable with
   `gh attestation verify <file> --repo systemslibrarian/postquantum-securechannel`).
4. **Creates a GitHub release** with the packages, symbols, and SBOM attached.
5. **Publishes to NuGet.org via Trusted Publishing** — a short-lived OIDC token, **no long-lived API
   key stored anywhere**.

## One-time setup: NuGet Trusted Publishing

So the release workflow can publish without a stored API key:

1. Sign in to [nuget.org](https://www.nuget.org) as `systemslibrarian`.
2. Account → **Trusted Publishing** → **Add**.
3. Configure the policy for each of the three package IDs (or a glob if supported):
   - Repository owner: `systemslibrarian`
   - Repository: `postquantum-securechannel`
   - Workflow file: `release.yml`
4. Save. No secret is added to the GitHub repository.

> If you ever need to fall back to an API-key push (e.g. before the policy is set up), the local
> `nuget.txt` key still works for a manual `dotnet nuget push` from your machine — but that key is
> gitignored and must never be committed or added as a plaintext workflow step.

## Cutting a release

1. Ensure `main` is green and the version in all three `.csproj` files is the target `X.Y.Z`
   (see [`VERSION-RECONCILIATION.md`](VERSION-RECONCILIATION.md)).
2. Update [`CHANGELOG.md`](CHANGELOG.md) and the `<PackageReleaseNotes>`.
3. Tag and push:
   ```bash
   git tag -a vX.Y.Z -m "X.Y.Z — <summary>"
   git push origin main
   git push origin vX.Y.Z
   ```
4. Watch the **Release** workflow. When it completes, verify the packages appear on nuget.org and that
   `gh attestation verify` succeeds against a downloaded `.nupkg`.

## Verifying a published package (for consumers)

```bash
# Download the .nupkg from nuget.org, then:
gh attestation verify PostQuantum.SecureChannel.X.Y.Z.nupkg \
  --repo systemslibrarian/postquantum-securechannel
```

A successful verification proves the package was built by this repository's release workflow from the
tagged commit — not re-uploaded or tampered with.

---

**To God be the glory.** — *1 Corinthians 10:31*

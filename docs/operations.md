# Operations guide

Running PostQuantum.SecureChannel in production. Pin identities safely, rotate them on a schedule,
watch the signals that matter, and have a runbook for the day a key leaks.

## 1. Pinning server identities

A server's long-term identity is a 32-byte ML-DSA seed. Treat it like a private key, because that
is exactly what it is.

**Do**
- Generate it once: `PqIdentity.Create()` → `.ExportPrivateSeed()` → base64 → secret manager
  (Azure Key Vault, AWS Secrets Manager, Google Secret Manager, HashiCorp Vault, Kubernetes Secret
  with sealed-secrets / KMS encryption at rest).
- Distribute only the **public** half (`PqIdentityPublicKey.ToBase64()`) to clients via
  configuration. Print the `ShortFingerprint()` in deploy logs so a human can sanity-check it.
- Store the public key alongside non-secret configuration; it does not need a secret manager.

**Don't**
- Check the seed (or even the seed file path with predictable contents) into source control.
- Log the seed at any level.
- Ship the seed in container images. Mount it at runtime.

## 2. Rotating server identities

You will rotate at least when:

- A staff member with prior access leaves.
- A suspected leak occurs.
- Your policy says so (annually is a defensible baseline).

The rotation pattern this library is designed for is **staged, with overlap**:

1. Generate a new identity (`PqIdentity.Create()`); store its seed in the secret manager next to
   the existing one (e.g. `Pq:SeedV2`).
2. Push the new public key to clients **alongside** the existing one:
   ```csharp
   new PqClientOptions
   {
       ServerIdentity = newKey,
       AllowedServerIdentities = [oldKey, newKey],
   }
   ```
   Clients now accept either; servers still present the old key.
3. Roll servers to present the new seed. Clients still accept either, so there is no flag day.
4. Once every server has rolled and you have run a soak period, push a client update that drops
   the old pin (`AllowedServerIdentities = [newKey]`).
5. Destroy the old seed from the secret manager.

The same pattern works for client identities (rotate `ClientIdentity`, update the server's
`AuthorizedClients` allowlist with an overlap window).

## 3. Choosing replay protection and key-update cadence

| Transport shape                                            | Preset                                  |
| ---------------------------------------------------------- | --------------------------------------- |
| TCP, named pipes, ordered WebSocket                        | `PqSessionOptions.Recommended`          |
| UDP-style, sliding-window-tolerant transports              | `PqSessionOptions.UnorderedTransport`   |
| Long-lived, high-throughput streams                        | `PqSessionOptions.HighThroughput`       |
| You know the channel is short-lived (one-shot RPC)         | `PqSessionOptions.Default`              |

The hard caps (NIST: 2^32 records, 2^36 bytes per epoch) cannot be exceeded; the auto-rekey
policy presets sit well below them. If you operate at extreme record rates, rekey explicitly.

## 4. Watching the signals

Wire `PqDiagnostics` into whatever you already use:

### dotnet-counters (live in a terminal)
```bash
dotnet-counters monitor --counters PostQuantum.SecureChannel
```

### dotnet-trace (full handshake spans + counter samples)
```bash
dotnet-trace collect --providers PostQuantum.SecureChannel
```

### OpenTelemetry
```csharp
services.AddOpenTelemetry()
    .WithMetrics(b => b.AddMeter("PostQuantum.SecureChannel").AddPrometheusExporter())
    .WithTracing(b => b.AddSource("PostQuantum.SecureChannel").AddOtlpExporter());
```

### What to alert on
| Signal                                                    | Likely cause                                     |
| --------------------------------------------------------- | ------------------------------------------------ |
| `pqsc.handshakes.failed` spike, tag `reason=server-identity-not-pinned` | Pinned key drift between client and server config |
| `pqsc.handshakes.failed` tag `reason=client-finished-mac-invalid`       | Network corruption, peer misconfigured, key-schedule bug |
| `pqsc.records.rejected` sustained > 0                                   | Replay attempts, reorder under wrong replay mode, or peer bug |
| `pqsc.epochs.exhausted` non-zero                                        | Rekey policy is too lax for the workload; tune `PqKeyUpdatePolicy` |
| Latency on `pqsc.handshake.client` activity spans growing               | Handshake CPU pressure or X-Wing-side hardware issue |

## 5. Incident response: pinned key compromise

If you have credible evidence that a server identity seed has leaked:

1. **Mint a new identity** and push it to staging.
2. **Rotate immediately**, skipping the slow overlap if compromise is confirmed: deploy the new
   server first, push a client config update that pins only the new key, observe handshake-failed
   counters return to baseline.
3. **Destroy the old seed** in the secret manager, and **rotate any secrets that the compromised
   server had access to** (database passwords, OAuth client secrets, etc.).
4. **Audit**: how did the seed leak? Plug the hole.
5. **Communicate**: per your normal incident process.

Past sessions are forward-secret (a stolen identity seed cannot decrypt them retroactively), but
*new* sessions could have been MitM'd between leak and rotation. Treat data that traversed those
sessions during the exposure window as potentially compromised.

## 6. Identity loading from common providers

```csharp
// From IConfiguration (binds ServerIdentitySeedBase64 / ServerIdentitySeedFile):
services.AddPostQuantumSecureChannel()
        .AddServerIdentityFromConfiguration("PqSecureChannel");

// From a file mounted at runtime (Kubernetes secret as volume):
services.AddPostQuantumSecureChannel()
        .AddServerIdentityFromSeedFile("/var/run/pq/seed.b64");

// From your own provider (Vault, custom KMS):
services.AddPostQuantumSecureChannel()
        .AddServerIdentity(myVaultClient.LoadPqIdentity("pq/server"));
```

## 7. Sizing limits to remember

- Per-record plaintext: **1 GiB** (`PqSession.MaxRecordPlaintextSize`). Split larger payloads.
- Per-epoch records: **2^32** (`PqSession.MaxRecordsPerEpoch`). Recommended policy rekeys at 2^24.
- Per-epoch bytes: **2^36** = 64 GiB (`PqSession.MaxBytesPerEpoch`). Recommended policy rekeys at 4 GiB.
- Framed transport: **16 MiB** per frame default. Override with the `maxFrameSize` parameter on
  the stream adapter if you genuinely need larger.
- Sliding-window replay window: 8 to 1024 sequences. Pick the smallest that tolerates your
  expected reordering depth.

---

**To God be the glory.** — *1 Corinthians 10:31*

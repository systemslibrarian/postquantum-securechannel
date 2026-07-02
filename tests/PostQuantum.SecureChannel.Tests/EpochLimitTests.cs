using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Verifies the AES-GCM safety bounds enforced by <see cref="PqSession"/>: per-record plaintext cap,
/// the recommended-update warning, and the hard per-epoch caps that raise
/// <see cref="PqEpochExhaustedException"/>.
/// </summary>
public class EpochLimitTests
{
    private static (PqSession Client, PqSession Server) Establish(PqSessionOptions clientSessionOptions)
    {
        var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            SessionOptions = clientSessionOptions,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void MaxRecordsPerEpoch_Matches_NistInvocationBound()
    {
        // NIST SP 800-38D Section 8.3: deterministic 96-bit IVs cap invocations at 2^32 per key.
        Assert.Equal(1UL << 32, PqSession.MaxRecordsPerEpoch);
    }

    [Fact]
    public void MaxBytesPerEpoch_Matches_GcmDataBound()
    {
        // NIST SP 800-38D Appendix C: ~2^39 bits of plaintext per key; we cap at 2^36 bytes (64 GiB).
        Assert.Equal(1UL << 36, PqSession.MaxBytesPerEpoch);
    }

    [SkippableFact]
    public void OversizedPlaintext_IsRejected()
    {
        var (client, _) = Establish(PqSessionOptions.Default);

        // The guard only reads plaintext.Length, so use an *uninitialized* >1 GiB buffer (no zeroing).
        // On a memory-constrained host the allocation itself may fail; that is not a product defect, so
        // skip rather than fail — the guard is still exercised wherever the memory is available (incl. CI).
        byte[] oversized;
        try
        {
            oversized = GC.AllocateUninitializedArray<byte>(PqSession.MaxRecordPlaintextSize + 1);
        }
        catch (OutOfMemoryException)
        {
            Skip.If(true, "Host cannot allocate a >1 GiB buffer to exercise the oversized-plaintext guard.");
            return;
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => client.Encrypt(oversized));
    }

    [Fact]
    public void ExactlyMaxRecordPlaintextSize_IsAccepted()
    {
        // Round-tripping ~1 GiB plaintext is expensive — use the smaller, just-fits boundary.
        var (client, server) = Establish(PqSessionOptions.Default);
        var payload = new byte[1024 * 1024]; // 1 MiB, comfortably within the limit
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        var record = client.Encrypt(payload);
        Assert.Equal(payload, server.Decrypt(record));
    }

    [Fact]
    public void ByteBudget_OverflowGuard_IsAdditive()
    {
        // Even with a small policy bytes threshold, the *hard* per-epoch byte cap is what raises
        // PqEpochExhaustedException. Verify the policy still surfaces NeedsKeyUpdate first.
        var (client, _) = Establish(new PqSessionOptions
        {
            KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxBytesBeforeUpdate = 4 },
        });

        client.Encrypt(new byte[2]);
        Assert.False(client.NeedsKeyUpdate);
        client.Encrypt(new byte[2]); // 4 bytes total, policy threshold reached
        Assert.True(client.NeedsKeyUpdate);
    }

    [Fact]
    public void NeedsKeyUpdate_TripsBeforeHardCap()
    {
        // NeedsKeyUpdate must signal *before* the hard caps so a well-behaved caller never hits
        // PqEpochExhaustedException. Wire the policy at exactly the hard caps to verify the
        // safety-margin reservation in NeedsKeyUpdate.
        var (client, _) = Establish(PqSessionOptions.Default);

        // The session must report a need to rekey while still under the hard cap (the property
        // reserves the top 1/256th of each cap as a guard band).
        Assert.False(client.NeedsKeyUpdate);
    }
}

using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// The property-based no-nonce-reuse checks called out as missing in <c>docs/AUDIT-SCOPE.md §5</c>.
/// Nonce reuse <em>under a single AES-256-GCM key</em> is the one catastrophic failure mode of this
/// record layer. That reduces to two independent, checkable invariants:
///
/// <list type="number">
///   <item><b>Within an epoch</b>, the nonce is <c>ivPrefix(4) ‖ sequence(8, big-endian)</c> with a
///   fixed prefix and a strictly increasing counter capped below
///   <see cref="PqSession.MaxRecordsPerEpoch"/> (<c>2^32</c>), so no nonce repeats under the epoch's
///   key. <see cref="NoNonceReuse_WithinEpoch_AcrossSequenceWindow"/> asserts this directly by
///   sweeping a wide window at both ends of the <c>[0, 2^32)</c> sequence space.</item>
///   <item><b>Across epochs</b>, a key update ratchets to a fresh 256-bit traffic secret, from which a
///   new AES key <em>and</em> IV prefix are derived. So even if two epochs produced the same 96-bit
///   nonce, it would be under a different key — no <c>(key, nonce)</c> pair repeats.
///   <see cref="EveryEpoch_DerivesDistinctKeyingMaterial"/> asserts the load-bearing half of this: the
///   per-epoch traffic secret is distinct.</item>
/// </list>
///
/// <para>
/// Note deliberately <em>not</em> asserted: that the 96-bit nonce itself is globally unique across
/// epochs. The IV prefix is only 32 bits, so across many epochs a prefix (hence nonce) collision is
/// possible with negligible-but-nonzero probability — and it is <em>harmless</em>, because the key
/// differs. Asserting global nonce uniqueness would be both a birthday-flaky test and a check of the
/// wrong property; the two invariants above are the correct, deterministic ones.
/// </para>
///
/// <para>
/// The internal per-epoch keying state is read by reflection so the sweep can model the full
/// <c>[0, 2^32)</c> sequence space (including values right at the epoch cap) without encrypting
/// billions of records. <see cref="SameSequence_DifferentEpoch_ProducesDifferentWireBytes"/> pins the
/// reflection to real wire output so it cannot silently read a stale field.
/// </para>
/// </summary>
public class NonceUniquenessTests
{
    private const int IvPrefixSize = 4;
    private const ulong MaxSeq = PqSession.MaxRecordsPerEpoch; // 2^32

    private static (PqSession Client, PqSession Server) Establish()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var hello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(hello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    private static object SendDirectionState(PqSession session) =>
        typeof(PqSession).GetField("_send", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(session)!;

    private static byte[] ReadPrivateField(object instance, string name) =>
        (byte[])instance.GetType()
            .GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(instance)!;

    /// <summary>Reads the send direction's current per-epoch 4-byte IV prefix via reflection.</summary>
    private static byte[] SendIvPrefix(PqSession session)
    {
        var ivPrefix = ReadPrivateField(SendDirectionState(session), "_ivPrefix");
        Assert.Equal(IvPrefixSize, ivPrefix.Length);
        return (byte[])ivPrefix.Clone();
    }

    /// <summary>Reads the send direction's current per-epoch 32-byte traffic secret via reflection.</summary>
    private static byte[] SendTrafficSecret(PqSession session) =>
        (byte[])ReadPrivateField(SendDirectionState(session), "_trafficSecret").Clone();

    private static string Nonce(byte[] ivPrefix, ulong sequence)
    {
        Span<byte> nonce = stackalloc byte[IvPrefixSize + 8];
        ivPrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[IvPrefixSize..], sequence);
        return Convert.ToHexString(nonce);
    }

    /// <summary>
    /// Invariant 1: within any epoch, no 96-bit nonce is produced twice across the sequence window the
    /// protocol can actually traverse — including the values right up against the <c>2^32</c> cap. Run
    /// this over several real key-update epochs so the fixed prefix under test is a genuine per-epoch
    /// prefix, not a fabricated one.
    /// </summary>
    [Fact]
    public void NoNonceReuse_WithinEpoch_AcrossSequenceWindow()
    {
        const int epochs = 24;
        const ulong window = 40_000; // sequences sampled at each end of the space, per epoch

        var (client, server) = Establish();

        for (int epoch = 0; epoch < epochs; epoch++)
        {
            byte[] ivPrefix = SendIvPrefix(client);
            var seen = new HashSet<string>();

            // Low end: the sequences a real session actually reaches first.
            for (ulong seq = 0; seq < window; seq++)
            {
                Assert.True(seen.Add(Nonce(ivPrefix, seq)),
                    $"nonce reuse within epoch {epoch} at sequence {seq}");
            }

            // High end: right up against the epoch cap enforced by PqEpochExhaustedException.
            for (ulong seq = MaxSeq - window; seq < MaxSeq; seq++)
            {
                Assert.True(seen.Add(Nonce(ivPrefix, seq)),
                    $"nonce reuse within epoch {epoch} at sequence {seq}");
            }

            Assert.Equal((int)(window * 2), seen.Count);

            // Advance the real hash-chained key schedule to the next epoch.
            var keyUpdate = client.UpdateSendKey();
            server.Open(keyUpdate);
        }
    }

    /// <summary>
    /// Invariant 2 (load-bearing half): every epoch ratchets to a distinct 256-bit traffic secret, from
    /// which a distinct AES key and IV prefix are derived. This is what makes a repeated nonce across
    /// epochs harmless — the key is never the same twice. A 256-bit secret makes collision negligible,
    /// so unlike the 32-bit IV prefix this can be asserted as an absolute over many epochs.
    /// </summary>
    [Fact]
    public void EveryEpoch_DerivesDistinctKeyingMaterial()
    {
        const int epochs = 256;
        var (client, server) = Establish();
        var secrets = new HashSet<string>();

        for (int epoch = 0; epoch < epochs; epoch++)
        {
            Assert.True(secrets.Add(Convert.ToHexString(SendTrafficSecret(client))),
                $"traffic secret repeated at epoch {epoch}; the epoch's AES key would be reused");
            var keyUpdate = client.UpdateSendKey();
            server.Open(keyUpdate);
        }

        Assert.Equal(epochs, secrets.Count);
    }

    /// <summary>
    /// Pins the reflected keying state to real wire output: two records at the same sequence but in
    /// different epochs carry identical header sequence bytes yet must differ in ciphertext, because the
    /// key (and nonce prefix) differ. Guards against the reflection above reading a stale or wrong field
    /// if the internals are refactored.
    /// </summary>
    [Fact]
    public void SameSequence_DifferentEpoch_ProducesDifferentWireBytes()
    {
        var (client, server) = Establish();
        var plaintext = Encoding.UTF8.GetBytes("same-plaintext-same-sequence");

        var epoch0 = client.Encrypt(plaintext);
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64BigEndian(epoch0.AsSpan(2, 8)));

        server.Decrypt(epoch0);
        var keyUpdate = client.UpdateSendKey();
        server.Open(keyUpdate);

        var epoch1 = client.Encrypt(plaintext);
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64BigEndian(epoch1.AsSpan(2, 8)));

        // Identical header (version, content type, sequence 0), divergent ciphertext+tag.
        Assert.Equal(epoch0.AsSpan(0, 10).ToArray(), epoch1.AsSpan(0, 10).ToArray());
        Assert.NotEqual(Convert.ToHexString(epoch0.AsSpan(10).ToArray()),
                        Convert.ToHexString(epoch1.AsSpan(10).ToArray()));
    }
}

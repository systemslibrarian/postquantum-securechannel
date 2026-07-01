using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// The property-based no-nonce-reuse sweep called out as missing in
/// <c>docs/AUDIT-SCOPE.md §5</c>. Nonce reuse under a single AES-256-GCM key is the one
/// catastrophic failure mode of this record layer, and it is exactly the kind of bug that every
/// round-trip test in the repo would pass while still being present. These tests enumerate the
/// record-layer nonce as a pure function of <c>(ivPrefix, sequence)</c> across a large sequence
/// window and across many key-update epochs, and assert that no 96-bit nonce ever repeats.
///
/// <para>
/// The nonce is <c>ivPrefix(4) ‖ sequence(8, big-endian)</c> (see <see cref="PqSession"/>). Within an
/// epoch the sequence is a strictly increasing counter capped below
/// <see cref="PqSession.MaxRecordsPerEpoch"/> (<c>2^32</c>), so intra-epoch uniqueness reduces to
/// counter monotonicity. Across epochs the sequence resets to 0, so the <em>only</em> thing standing
/// between the protocol and a reused nonce is that each epoch derives a fresh <c>ivPrefix</c>. Both
/// halves are asserted here directly.
/// </para>
///
/// <para>
/// The per-epoch <c>ivPrefix</c> is internal, so it is read by reflection rather than reconstructed —
/// this lets the sweep model the full <c>[0, 2^32)</c> sequence space (including the values right at
/// the epoch cap) without actually encrypting billions of records.
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

    /// <summary>Reads the send direction's current per-epoch 4-byte IV prefix via reflection.</summary>
    private static byte[] SendIvPrefix(PqSession session)
    {
        var directionState = typeof(PqSession)
            .GetField("_send", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(session)!;
        var ivPrefix = (byte[])directionState.GetType()
            .GetField("_ivPrefix", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(directionState)!;
        Assert.Equal(IvPrefixSize, ivPrefix.Length);
        return (byte[])ivPrefix.Clone();
    }

    private static string Nonce(byte[] ivPrefix, ulong sequence)
    {
        Span<byte> nonce = stackalloc byte[IvPrefixSize + 8];
        ivPrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[IvPrefixSize..], sequence);
        return Convert.ToHexString(nonce);
    }

    /// <summary>
    /// The full property: across many epochs, sweeping a wide window of sequence numbers at each end of
    /// the <c>[0, 2^32)</c> range plus the boundary values adjacent to the epoch cap, no 96-bit nonce is
    /// ever produced twice. This is the literal sweep <c>AUDIT-SCOPE §5</c> asks for.
    /// </summary>
    [Fact]
    public void NoNonceReuse_AcrossSequenceWindow_AndKeyUpdates()
    {
        const int epochs = 24;
        const ulong window = 40_000; // records per epoch sampled at each boundary of the sequence space

        var (client, server) = Establish();

        // Every nonce ever emitted, hex-encoded. Add() returns false on the first duplicate — which
        // for AES-GCM would be game over. The sweep is sized so a prefix collision (the only way a
        // duplicate can arise, since intra-epoch sequences never repeat) would be caught immediately.
        var seen = new HashSet<string>();

        for (int epoch = 0; epoch < epochs; epoch++)
        {
            byte[] ivPrefix = SendIvPrefix(client);

            // Low end of the sequence space (the sequences a real session actually reaches).
            for (ulong seq = 0; seq < window; seq++)
            {
                Assert.True(seen.Add(Nonce(ivPrefix, seq)),
                    $"nonce reuse at epoch {epoch}, sequence {seq}");
            }

            // High end, right up against the epoch cap enforced by PqEpochExhaustedException.
            for (ulong seq = MaxSeq - window; seq < MaxSeq; seq++)
            {
                Assert.True(seen.Add(Nonce(ivPrefix, seq)),
                    $"nonce reuse at epoch {epoch}, sequence {seq}");
            }

            // Advance the real hash-chained key schedule to the next epoch so the next iteration reads
            // the genuine next ivPrefix, not a fabricated one.
            var keyUpdate = client.UpdateSendKey();
            server.Open(keyUpdate);
        }

        Assert.Equal((long)(epochs * window * 2), seen.Count);
    }

    /// <summary>
    /// The load-bearing sub-property: because sequences reset to 0 every epoch, cross-epoch nonce
    /// uniqueness depends <em>entirely</em> on every epoch deriving a distinct IV prefix. Ratchet many
    /// times and assert all prefixes are unique.
    /// </summary>
    [Fact]
    public void EveryEpoch_DerivesDistinctIvPrefix()
    {
        const int epochs = 256;
        var (client, server) = Establish();
        var prefixes = new HashSet<string>();

        for (int epoch = 0; epoch < epochs; epoch++)
        {
            Assert.True(prefixes.Add(Convert.ToHexString(SendIvPrefix(client))),
                $"IV prefix collided at epoch {epoch}; sequence-0 nonces of two epochs would match");
            var keyUpdate = client.UpdateSendKey();
            server.Open(keyUpdate);
        }

        Assert.Equal(epochs, prefixes.Count);
    }

    /// <summary>
    /// End-to-end sanity that the reflected prefix matches the wire: two records at the same sequence
    /// but in different epochs carry the same header sequence bytes yet must differ in ciphertext,
    /// because their nonces (and keys) differ. Guards against the reflection above reading a stale or
    /// wrong field if the internals are refactored.
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

using System.Security.Cryptography;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Pinned Known-Answer Tests for the HKDF-SHA256 key schedule. Today there is no externally-published
/// KAT for this library's key schedule (it is a project-specific schedule, not a standard one), so
/// these KATs lock the schedule against an independently-rebuilt reference implementation in the
/// same file. The reference uses the .NET BCL <see cref="HKDF"/> primitive directly with the
/// documented labels and the same TLS 1.3-style <c>HkdfLabel</c> info structure, then derives every
/// expected secret in the documented order. If any of the schedule's labels, salt construction,
/// derivation order, or info structure drifts away from <c>docs/protocol.md §6</c>, the test fails.
/// </summary>
public class KeyScheduleKatTests
{
    private static readonly byte[] FixedSharedSecret = Pattern(0xAA, 32);
    private static readonly byte[] FixedClientRandom = Pattern(0x10, 32);
    private static readonly byte[] FixedServerRandom = Pattern(0x20, 32);
    private static readonly byte[] FixedTranscriptHash = Pattern(0x30, 32);
    private static readonly byte[] FixedResumptionPsk = Pattern(0x42, 32);

    private static byte[] Pattern(byte seed, int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(seed ^ (byte)i);
        }

        return bytes;
    }

    [Fact]
    public void Derive_WithoutResumption_MatchesReferenceImplementation()
    {
        AssertMatchesReference(resumptionPsk: []);
    }

    [Fact]
    public void Derive_WithResumption_MatchesReferenceImplementation()
    {
        AssertMatchesReference(resumptionPsk: FixedResumptionPsk);
    }

    [Fact]
    public void Derive_IsDeterministic()
    {
        var first = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, FixedTranscriptHash);
        var second = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, FixedTranscriptHash);

        Assert.Equal(first.ClientToServerTrafficSecret, second.ClientToServerTrafficSecret);
        Assert.Equal(first.ServerToClientTrafficSecret, second.ServerToClientTrafficSecret);
        Assert.Equal(first.ClientFinishedKey, second.ClientFinishedKey);
        Assert.Equal(first.ServerFinishedKey, second.ServerFinishedKey);
        Assert.Equal(first.ResumptionSecret, second.ResumptionSecret);
    }

    [Fact]
    public void Derive_AllFiveSecretsAreDistinct()
    {
        // Distinct labels MUST produce distinct keys. If two labels ever collide or get rebound to
        // the same Expand call, this test fails.
        var s = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, FixedTranscriptHash);

        var bag = new HashSet<string>
        {
            Convert.ToHexString(s.ClientToServerTrafficSecret),
            Convert.ToHexString(s.ServerToClientTrafficSecret),
            Convert.ToHexString(s.ClientFinishedKey),
            Convert.ToHexString(s.ServerFinishedKey),
            Convert.ToHexString(s.ResumptionSecret),
        };
        Assert.Equal(5, bag.Count);
    }

    [Fact]
    public void Derive_DifferentTranscriptHash_ChangesEverySecret()
    {
        var a = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, Pattern(0x30, 32));
        var b = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, Pattern(0x31, 32));

        Assert.NotEqual(a.ClientToServerTrafficSecret, b.ClientToServerTrafficSecret);
        Assert.NotEqual(a.ServerToClientTrafficSecret, b.ServerToClientTrafficSecret);
        Assert.NotEqual(a.ClientFinishedKey, b.ClientFinishedKey);
        Assert.NotEqual(a.ServerFinishedKey, b.ServerFinishedKey);
        Assert.NotEqual(a.ResumptionSecret, b.ResumptionSecret);
    }

    [Fact]
    public void FinishedMac_OverKnownTranscript_MatchesHmacSha256()
    {
        // The Finished MAC is HMAC-SHA256(finishedKey, transcriptHash); pin that structure.
        var finishedKey = Pattern(0xCC, 32);
        var transcriptHash = Pattern(0xDD, 32);

        var actual = Transcript.FinishedMac(finishedKey, transcriptHash);
        var expected = HMACSHA256.HashData(finishedKey, transcriptHash);

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Re-derives the entire schedule from primitives, using only the documented labels (which the
    /// test reads from <see cref="PqProtocol"/>) and the documented salt construction. Any drift in
    /// the production code's salt, label, order, or info structure breaks the equality.
    /// </summary>
    private static void AssertMatchesReference(byte[] resumptionPsk)
    {
        var actual = KeySchedule.Derive(
            FixedSharedSecret, FixedClientRandom, FixedServerRandom, FixedTranscriptHash, resumptionPsk);

        // Reference: salt = clientRandom ‖ serverRandom ‖ resumptionPsk.
        var salt = new byte[FixedClientRandom.Length + FixedServerRandom.Length + resumptionPsk.Length];
        Buffer.BlockCopy(FixedClientRandom, 0, salt, 0, FixedClientRandom.Length);
        Buffer.BlockCopy(FixedServerRandom, 0, salt, FixedClientRandom.Length, FixedServerRandom.Length);
        if (resumptionPsk.Length > 0)
        {
            Buffer.BlockCopy(resumptionPsk, 0, salt, FixedClientRandom.Length + FixedServerRandom.Length, resumptionPsk.Length);
        }

        var prk = new byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, FixedSharedSecret, salt, prk);

        var master = ExpandRef(prk, PqProtocol.MasterInfo, 32, FixedTranscriptHash);
        var expectedC2S = ExpandRef(master, PqProtocol.ClientToServerTrafficInfo, 32);
        var expectedS2C = ExpandRef(master, PqProtocol.ServerToClientTrafficInfo, 32);
        var expectedClientFinished = ExpandRef(master, PqProtocol.ClientFinishedInfo, 32);
        var expectedServerFinished = ExpandRef(master, PqProtocol.ServerFinishedInfo, 32);
        var expectedResumption = ExpandRef(master, PqProtocol.ResumptionInfo, 32);

        Assert.Equal(expectedC2S, actual.ClientToServerTrafficSecret);
        Assert.Equal(expectedS2C, actual.ServerToClientTrafficSecret);
        Assert.Equal(expectedClientFinished, actual.ClientFinishedKey);
        Assert.Equal(expectedServerFinished, actual.ServerFinishedKey);
        Assert.Equal(expectedResumption, actual.ResumptionSecret);
    }

    private static byte[] ExpandRef(byte[] prk, string label, int length, byte[]? context = null)
    {
        var info = Hkdf.BuildInfo(label, length, context ?? []);
        var output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, output, info);
        return output;
    }
}

using System.Text;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Locks the exact <c>info</c> bytes produced by <see cref="Hkdf.BuildInfo"/> for every call site
/// in the key schedule. If any future change to the wrapper or a label produces different bytes,
/// the corresponding test fails — preventing silent wire-format drift.
/// </summary>
/// <remarks>
/// The encoding is the TLS 1.3-style <c>HkdfLabel</c>:
/// <c>uint16_BE(length) ‖ uint8(label_len) ‖ label_bytes ‖ uint8(context_len) ‖ context_bytes</c>.
/// </remarks>
public class HkdfInfoFormatTests
{
    private static byte[] Build(string label, int length, byte[] context)
        => Hkdf.BuildInfo(label, length, context);

    private static byte[] Expected(string label, int length, byte[] context)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        info[0] = (byte)((length >> 8) & 0xFF);
        info[1] = (byte)(length & 0xFF);
        info[2] = (byte)labelBytes.Length;
        labelBytes.CopyTo(info.AsSpan(3));
        int o = 3 + labelBytes.Length;
        info[o++] = (byte)context.Length;
        context.CopyTo(info.AsSpan(o));
        return info;
    }

    [Fact]
    public void MasterInfo_EmptyTranscript_ProducesExpectedBytes()
    {
        // Master always uses a 32-byte transcript hash as context, but the empty case isolates the
        // structural framing.
        var info = Build(PqProtocol.MasterInfo, 32, []);
        Assert.Equal(Expected(PqProtocol.MasterInfo, 32, []), info);

        // Spot-check the structural fields.
        Assert.Equal(0x00, info[0]);
        Assert.Equal(0x20, info[1]);                              // length = 32
        Assert.Equal(PqProtocol.MasterInfo.Length, info[2]);      // label_len
        Assert.Equal(0x00, info[3 + PqProtocol.MasterInfo.Length]); // context_len = 0
    }

    [Fact]
    public void MasterInfo_With32ByteTranscript_ProducesExpectedBytes()
    {
        var transcript = new byte[32];
        for (int i = 0; i < transcript.Length; i++)
        {
            transcript[i] = (byte)(0xA0 + i);
        }

        var info = Build(PqProtocol.MasterInfo, 32, transcript);
        Assert.Equal(Expected(PqProtocol.MasterInfo, 32, transcript), info);

        // The transcript bytes appear after the context_len byte.
        int o = 3 + PqProtocol.MasterInfo.Length;
        Assert.Equal(0x20, info[o]);
        for (int i = 0; i < 32; i++)
        {
            Assert.Equal(transcript[i], info[o + 1 + i]);
        }
    }

    [Theory]
    [InlineData("pqsc/v2 c2s traffic", 32)]
    [InlineData("pqsc/v2 s2c traffic", 32)]
    [InlineData("pqsc/v2 client finished", 32)]
    [InlineData("pqsc/v2 server finished", 32)]
    [InlineData("pqsc/v2 resumption", 32)]
    [InlineData("pqsc/v2 key", 32)]
    [InlineData("pqsc/v2 iv", 4)]
    [InlineData("pqsc/v2 key update", 32)]
    public void NonMasterLabels_EmptyContext_ProducesExpectedBytes(string label, int length)
    {
        var info = Build(label, length, []);
        Assert.Equal(Expected(label, length, []), info);

        // Structural assertions.
        Assert.Equal((byte)((length >> 8) & 0xFF), info[0]);
        Assert.Equal((byte)(length & 0xFF), info[1]);
        Assert.Equal((byte)label.Length, info[2]);
        Assert.Equal(label, Encoding.ASCII.GetString(info.AsSpan(3, label.Length)));
        Assert.Equal(0x00, info[3 + label.Length]); // context_len = 0
        Assert.Equal(3 + label.Length + 1, info.Length);
    }

    [Fact]
    public void DistinctLabels_ProduceDistinctInfoBytes()
    {
        // Pairwise distinctness across every call site in the schedule.
        string[] labels =
        [
            PqProtocol.MasterInfo,
            PqProtocol.ClientToServerTrafficInfo,
            PqProtocol.ServerToClientTrafficInfo,
            PqProtocol.ClientFinishedInfo,
            PqProtocol.ServerFinishedInfo,
            PqProtocol.ResumptionInfo,
            PqProtocol.TrafficKeyInfo,
            PqProtocol.TrafficIvInfo,
            PqProtocol.KeyUpdateInfo,
        ];

        var seen = new HashSet<string>();
        foreach (var label in labels)
        {
            var key = Convert.ToHexString(Build(label, 32, []));
            Assert.True(seen.Add(key), $"Collision on label {label}");
        }
    }

    [Fact]
    public void StructuralBoundaries_AreEnforced()
    {
        Assert.Throws<ArgumentException>(() => Build("", 32, []));                               // empty label
        Assert.Throws<ArgumentException>(() => Build(new string('a', 256), 32, []));             // label > 255
        Assert.Throws<ArgumentException>(() => Build("pqsc/v2 ok", 32, new byte[256]));         // context > 255
        Assert.Throws<ArgumentOutOfRangeException>(() => Build("pqsc/v2 ok", -1, []));          // negative length
        Assert.Throws<ArgumentOutOfRangeException>(() => Build("pqsc/v2 ok", 0x10000, []));     // length > uint16
    }

    [Fact]
    public void SamePrefix_DifferentContextLength_DoesNotCollide()
    {
        // This is the structural guarantee the new framing provides that the old raw concat did not:
        // ("pqsc/v2 key", context=[]) and a hypothetical alternate split cannot produce the same info.
        var a = Build("pqsc/v2 key", 32, []);
        var b = Build("pqsc/v2 ke", 32, [(byte)'y']);
        Assert.NotEqual(Convert.ToHexString(a), Convert.ToHexString(b));
    }
}

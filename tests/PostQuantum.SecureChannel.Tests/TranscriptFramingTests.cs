using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Locks Finding 3's remediation: <see cref="Transcript.Hash"/> length-prefixes every fragment, so
/// no two distinct fragment sequences with the same total byte content can collide on the same hash.
/// </summary>
public class TranscriptFramingTests
{
    [Fact]
    public void Hash_PrependsBigEndianLengthToEachFragment()
    {
        byte[] a = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] b = [0x01, 0x02, 0x03];

        var actual = Transcript.Hash(a, b);

        // Reference: SHA-256( len32(a) ‖ a ‖ len32(b) ‖ b )
        Span<byte> framed = stackalloc byte[4 + a.Length + 4 + b.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed[..4], (uint)a.Length);
        a.CopyTo(framed[4..]);
        BinaryPrimitives.WriteUInt32BigEndian(framed.Slice(4 + a.Length, 4), (uint)b.Length);
        b.CopyTo(framed[(4 + a.Length + 4)..]);
        var expected = SHA256.HashData(framed);

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Without per-fragment length framing, <c>Hash(a, b)</c> and <c>Hash(a ‖ prefix_of_b, suffix_of_b)</c>
    /// would collide (the previous raw-concat implementation did exactly that). With length framing,
    /// the two must differ.
    /// </summary>
    [Fact]
    public void Hash_DistinguishesFragmentBoundaries()
    {
        byte[] a = [0x10, 0x20, 0x30, 0x40];
        byte[] b = [0x50, 0x60, 0x70, 0x80];

        var canonical = Transcript.Hash(a, b);

        // Slide one byte from b into a's "trailing" fragment, keeping total bytes identical.
        byte[] aPlusOne = [.. a, b[0]];
        byte[] bMinusOne = b[1..];
        var ambiguous = Transcript.Hash(aPlusOne, bMinusOne);

        Assert.NotEqual(canonical, ambiguous);
    }

    [Fact]
    public void Hash_EmptyFragmentStillContributesLengthZero()
    {
        byte[] a = [0xAA, 0xBB];
        var withEmpty = Transcript.Hash(a, []);
        var withoutEmpty = Transcript.Hash(a);

        // An empty fragment still contributes a 4-byte zero length prefix to the hash input, so
        // Hash(a, []) and Hash(a) differ — this is the framing's whole point.
        Assert.NotEqual(withEmpty, withoutEmpty);
    }

    [Fact]
    public void Hash_NoFragments_ProducesEmptySha256()
    {
        // Hash() with no fragments hashes the empty byte sequence; SHA-256("") is a fixed constant.
        var actual = Transcript.Hash();
        var expected = SHA256.HashData([]);
        Assert.Equal(expected, actual);
    }
}

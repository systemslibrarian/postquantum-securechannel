using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// The higher-order transcript-equivalence attack surface called out as unexercised in
/// <c>docs/AUDIT-SCOPE.md §3</c>: two <em>valid but differently structured</em> transcripts that an
/// attacker might try to make hash the same. <see cref="TranscriptFramingTests"/> already locks the
/// single 2-fragment boundary slide; these tests go after the general property — that
/// <see cref="Transcript.Hash"/> is an injective encoding of the ordered <em>list</em> of fragments,
/// not merely of their concatenation — with adversarially constructed collision candidates.
///
/// <para>
/// The framing is <c>SHA-256( Σ len32(fragment_i) ‖ fragment_i )</c>. A collision at the hash level
/// would require a SHA-256 collision; these tests instead assert the pre-image (the framed byte
/// stream) is distinct for every structurally distinct fragment list, which is the property the key
/// schedule actually depends on.
/// </para>
/// </summary>
public class TranscriptEquivalenceTests
{
    /// <summary>Reference implementation of the framing, to prove specific candidates are distinct pre-images.</summary>
    private static byte[] Framed(params byte[][] fragments)
    {
        using var ms = new MemoryStream();
        Span<byte> len = stackalloc byte[4];
        foreach (var f in fragments)
        {
            BinaryPrimitives.WriteUInt32BigEndian(len, (uint)f.Length);
            ms.Write(len);
            ms.Write(f);
        }

        return ms.ToArray();
    }

    /// <summary>Reordering fragments with identical content must change the transcript.</summary>
    [Fact]
    public void Hash_IsOrderSensitive()
    {
        byte[] a = [0x01, 0x02];
        byte[] b = [0x03, 0x04, 0x05];

        Assert.NotEqual(Transcript.Hash(a, b), Transcript.Hash(b, a));
    }

    /// <summary>
    /// Repartitioning three fragments while keeping the total concatenated bytes identical must change
    /// the transcript. This generalizes the 2-fragment slide in <see cref="TranscriptFramingTests"/> to
    /// show the framing survives an attacker who is free to choose the fragment count and every split
    /// point, as long as the flat byte content is held constant.
    /// </summary>
    [Fact]
    public void Hash_DistinguishesEveryRepartition_OfTheSameFlatBytes()
    {
        byte[] flat = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // Every way to cut `flat` into three (possibly empty) ordered fragments must hash distinctly.
        var seen = new HashSet<string>();
        for (int i = 0; i <= flat.Length; i++)
        {
            for (int j = i; j <= flat.Length; j++)
            {
                byte[] f0 = flat[..i];
                byte[] f1 = flat[i..j];
                byte[] f2 = flat[j..];
                string hash = Convert.ToHexString(Transcript.Hash(f0, f1, f2));
                Assert.True(seen.Add(hash),
                    $"repartition ({i},{j}) of the same flat bytes collided with an earlier split");
            }
        }
    }

    /// <summary>
    /// The nesting / length-confusion attack: a single fragment whose <em>content</em> is itself a
    /// validly framed stream must not collide with the multi-fragment transcript it encodes. In other
    /// words, an attacker cannot smuggle a pre-framed <c>len32(x)‖x</c> blob into one fragment and have
    /// it be read as two fragments <c>x</c>.
    /// </summary>
    [Fact]
    public void Hash_ResistsPreFramedNestingConfusion()
    {
        byte[] x = [0xAB, 0xCD];
        byte[] y = [0xEF];

        // Honest transcript: two fragments x, y.
        var honest = Transcript.Hash(x, y);

        // Attacker: one fragment carrying the honest transcript's *framed* pre-image verbatim.
        byte[] preFramed = Framed(x, y);
        var nested = Transcript.Hash(preFramed);

        Assert.NotEqual(honest, nested);

        // And concretely: the two framed pre-images differ (the nested one carries an extra outer
        // length prefix), so no SHA-256 collision is even being relied upon.
        Assert.NotEqual(Convert.ToHexString(Framed(x, y)),
                        Convert.ToHexString(Framed(preFramed)));
    }

    /// <summary>
    /// A fragment whose leading bytes look like the length prefix of a following fragment must not let
    /// an attacker merge or split fields. Construct a candidate collision pair explicitly and prove the
    /// framed pre-images differ.
    /// </summary>
    [Fact]
    public void Hash_LengthPrefixCannotBeForgedFromContent()
    {
        // Transcript A: fragment "aa" then fragment "bbbb".
        byte[] aa = [0xAA, 0xAA];
        byte[] bbbb = [0xBB, 0xBB, 0xBB, 0xBB];

        // Transcript B: a single fragment whose bytes are len32(bbbb) ‖ bbbb — i.e. the attacker tries
        // to make one fragment "contain" the framing of the second. Held to the same flat interior.
        byte[] forged = Framed(bbbb); // len32(4) ‖ bbbb

        Assert.NotEqual(Transcript.Hash(aa, bbbb), Transcript.Hash(aa, forged));
        Assert.NotEqual(Convert.ToHexString(Framed(aa, bbbb)),
                        Convert.ToHexString(Framed(aa, forged)));
    }

    /// <summary>
    /// Empty fragments are load-bearing: an absent fragment and a present-but-empty fragment must hash
    /// differently at every position, not just at the end (the framing test covers the trailing case).
    /// </summary>
    [Fact]
    public void Hash_EmptyFragmentIsPositionallySignificant()
    {
        byte[] a = [0x01];
        byte[] b = [0x02];

        var noEmpty = Transcript.Hash(a, b);
        var leadingEmpty = Transcript.Hash([], a, b);
        var middleEmpty = Transcript.Hash(a, [], b);
        var trailingEmpty = Transcript.Hash(a, b, []);

        // All four fragment lists are distinct, so all four hashes must be distinct.
        var all = new[] { noEmpty, leadingEmpty, middleEmpty, trailingEmpty }
            .Select(Convert.ToHexString)
            .ToHashSet();
        Assert.Equal(4, all.Count);
    }

    /// <summary>
    /// Sanity anchor: the framing this test file reasons about matches the production hash for a
    /// non-trivial multi-fragment input, so the adversarial cases above are testing the real code path.
    /// </summary>
    [Fact]
    public void Hash_MatchesReferenceFraming()
    {
        byte[] a = [0xDE, 0xAD];
        byte[] b = [];
        byte[] c = [0xBE, 0xEF, 0x00];

        Assert.Equal(SHA256.HashData(Framed(a, b, c)), Transcript.Hash(a, b, c));
    }
}

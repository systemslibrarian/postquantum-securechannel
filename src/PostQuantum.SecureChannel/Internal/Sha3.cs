using Org.BouncyCastle.Crypto.Digests;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// Thin wrappers over BouncyCastle's SHA-3 and SHAKE primitives. These are the hash
/// functions required by the X-Wing construction (SHA3-256 combiner, SHAKE256 key expansion).
/// </summary>
internal static class Sha3
{
    /// <summary>Computes SHA3-256 over the concatenation of the supplied fragments.</summary>
    internal static byte[] Hash256(params ReadOnlyMemory<byte>[] fragments)
    {
        var digest = new Sha3Digest(256);
        foreach (var fragment in fragments)
        {
            var span = fragment.Span;
            if (span.Length > 0)
            {
                digest.BlockUpdate(span.ToArray(), 0, span.Length);
            }
        }

        var output = new byte[32];
        digest.DoFinal(output, 0);
        return output;
    }

    /// <summary>Computes <paramref name="outputLength"/> bytes of SHAKE256 over <paramref name="input"/>.</summary>
    internal static byte[] Shake256(ReadOnlySpan<byte> input, int outputLength)
    {
        var digest = new ShakeDigest(256);
        digest.BlockUpdate(input.ToArray(), 0, input.Length);
        var output = new byte[outputLength];
        digest.OutputFinal(output, 0, outputLength);
        return output;
    }
}

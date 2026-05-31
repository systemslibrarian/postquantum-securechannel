using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>Transcript hashing and Finished-MAC helpers shared by both handshake roles.</summary>
internal static class Transcript
{
    /// <summary>SHA-256 over the concatenation of the supplied fragments.</summary>
    internal static byte[] Hash(params byte[][] fragments)
    {
        using var sha = SHA256.Create();
        for (int i = 0; i < fragments.Length; i++)
        {
            sha.TransformBlock(fragments[i], 0, fragments[i].Length, null, 0);
        }

        sha.TransformFinalBlock([], 0, 0);
        return sha.Hash!;
    }

    /// <summary>A context label concatenated with a transcript hash, the message that gets signed.</summary>
    internal static byte[] SignedPayload(byte[] context, byte[] transcriptHash)
    {
        var payload = new byte[context.Length + transcriptHash.Length];
        context.CopyTo(payload, 0);
        transcriptHash.CopyTo(payload, context.Length);
        return payload;
    }

    /// <summary>The Finished key-confirmation MAC over a transcript hash.</summary>
    internal static byte[] FinishedMac(byte[] finishedKey, byte[] transcriptHash)
        => HMACSHA256.HashData(finishedKey, transcriptHash);
}

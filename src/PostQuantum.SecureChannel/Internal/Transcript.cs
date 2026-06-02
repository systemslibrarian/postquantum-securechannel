using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>Transcript hashing and Finished-MAC helpers shared by both handshake roles.</summary>
/// <remarks>
/// <para>
/// <b>Hash choice — SHA-256.</b> The transcript hash, HKDF, and Finished MAC all use SHA-256 (matching
/// the rest of the protocol-glue layer: HKDF-SHA256 key schedule, HMAC-SHA256 Finished MAC). SHA-256
/// is FIPS-approved, hardware-accelerated on every modern CPU, and gives 128-bit collision resistance
/// — sufficient for transcript binding under the standard one-shot collision-resistance assumption.
/// The X-Wing combiner separately uses SHA3-256 because <c>draft-connolly-cfrg-xwing-kem</c>
/// mandates it; the glue layer's choice is independent and need not match.
/// </para>
/// <para>
/// <b>Framing — per-fragment length prefix.</b> Each fragment is fed into the hash preceded by its
/// 4-byte big-endian length, so no two distinct fragment sequences can collide by concatenation
/// ambiguity. Today's callers pass two self-framed messages (<c>ClientHello</c> + <c>ServerHello</c>
/// body or full), but the helper's <c>params byte[][]</c> signature would silently allow ambiguity
/// without this framing.
/// </para>
/// </remarks>
internal static class Transcript
{
    /// <summary>SHA-256 over each fragment prefixed by its 4-byte big-endian length.</summary>
    internal static byte[] Hash(params byte[][] fragments)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> lenBuf = stackalloc byte[4];
        for (int i = 0; i < fragments.Length; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)fragments[i].Length);
            sha.AppendData(lenBuf);
            sha.AppendData(fragments[i]);
        }

        return sha.GetHashAndReset();
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

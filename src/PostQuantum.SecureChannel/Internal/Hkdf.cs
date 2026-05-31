using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>Centralized HKDF-SHA256 helpers with ASCII-labelled, context-bound expansion.</summary>
internal static class Hkdf
{
    internal static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm)
    {
        var prk = new byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);
        return prk;
    }

    /// <summary>Expands <paramref name="prk"/> into <paramref name="length"/> bytes bound to a label and optional context.</summary>
    internal static byte[] Expand(ReadOnlySpan<byte> prk, string label, int length, ReadOnlySpan<byte> context = default)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        Span<byte> info = stackalloc byte[labelBytes.Length + context.Length];
        labelBytes.CopyTo(info);
        context.CopyTo(info[labelBytes.Length..]);

        var output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, output, info);
        return output;
    }
}

using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// Centralized HKDF-SHA256 helpers. The Expand <c>info</c> field is built in a TLS 1.3-style
/// <c>HkdfLabel</c> structure with explicit length framing, so no two distinct
/// <c>(length, label, context)</c> triples can collide on the same <c>info</c> bytes — a guarantee
/// the previous raw-concatenation form did not provide.
/// </summary>
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
        var info = BuildInfo(label, length, context);
        var output = new byte[length];
        try
        {
            HKDF.Expand(HashAlgorithmName.SHA256, prk, output, info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(info);
        }

        return output;
    }

    /// <summary>
    /// Builds the HKDF <c>info</c> field in a TLS 1.3-style <c>HkdfLabel</c> structure:
    /// <c>uint16 length ‖ uint8 label_len ‖ label ‖ uint8 context_len ‖ context</c>.
    /// Exposed <c>internal</c> so byte-locking tests can pin the exact info bytes for each call site.
    /// </summary>
    internal static byte[] BuildInfo(string label, int length, ReadOnlySpan<byte> context)
    {
        ArgumentNullException.ThrowIfNull(label);
        if (length < 0 || length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length), length, "HKDF output length must fit in a uint16.");
        }

        var labelBytes = Encoding.ASCII.GetBytes(label);
        if (labelBytes.Length is 0 or > 255)
        {
            throw new ArgumentException("Label must be 1..255 ASCII bytes.", nameof(label));
        }

        if (context.Length > 255)
        {
            throw new ArgumentException("Context must be 0..255 bytes.", nameof(context));
        }

        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        info[0] = (byte)((length >> 8) & 0xFF);
        info[1] = (byte)(length & 0xFF);
        info[2] = (byte)labelBytes.Length;
        labelBytes.CopyTo(info.AsSpan(3));
        int offset = 3 + labelBytes.Length;
        info[offset++] = (byte)context.Length;
        context.CopyTo(info.AsSpan(offset));
        return info;
    }
}

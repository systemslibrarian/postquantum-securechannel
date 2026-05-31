using System.Security.Cryptography;
using PostQuantum.SecureChannel.Cryptography;

namespace PostQuantum.SecureChannel;

/// <summary>
/// The public half of a <see cref="PqIdentity"/>: an encoded ML-DSA-65 verification key plus a short,
/// human-comparable fingerprint for pinning.
/// </summary>
public sealed class PqIdentityPublicKey
{
    private readonly byte[] _publicKey;

    internal PqIdentityPublicKey(byte[] publicKey)
    {
        if (publicKey.Length != MlDsaSignature.PublicKeySize)
        {
            throw new ArgumentException(
                $"Identity public key must be {MlDsaSignature.PublicKeySize} bytes.", nameof(publicKey));
        }

        _publicKey = publicKey;
    }

    /// <summary>Serializes the public key to bytes for distribution.</summary>
    public byte[] Export() => (byte[])_publicKey.Clone();

    /// <summary>Restores a public key from bytes produced by <see cref="Export"/>.</summary>
    public static PqIdentityPublicKey Import(ReadOnlySpan<byte> publicKey) => new(publicKey.ToArray());

    /// <summary>Serializes the public key to a Base64 string &#8212; convenient for config files and pinning.</summary>
    public string ToBase64() => Convert.ToBase64String(_publicKey);

    /// <summary>Restores a public key from a Base64 string produced by <see cref="ToBase64"/>.</summary>
    public static PqIdentityPublicKey FromBase64(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        try
        {
            return new PqIdentityPublicKey(Convert.FromBase64String(base64));
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Value is not valid Base64.", nameof(base64), ex);
        }
    }

    /// <summary>
    /// A SHA-256 fingerprint of the public key, formatted as lowercase hex. Useful for out-of-band
    /// verification ("does the server's fingerprint match what I pinned?").
    /// </summary>
    public string Fingerprint()
    {
        var hash = SHA256.HashData(_publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// A short, human-comparable form of <see cref="Fingerprint"/>: the first 8 bytes as colon-separated
    /// hex (for example, <c>9f:86:d0:81:88:4c:7d:65</c>). Handy for quick visual checks in logs or a UI.
    /// </summary>
    public string ShortFingerprint()
    {
        var hash = SHA256.HashData(_publicKey);
        var hex = Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
        return string.Join(':', Enumerable.Range(0, 8).Select(i => hex.Substring(i * 2, 2)));
    }

    internal ReadOnlySpan<byte> Bytes => _publicKey;

    internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        => MlDsaSignature.Verify(_publicKey, message, signature);
}

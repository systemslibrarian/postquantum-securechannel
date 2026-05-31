using System.Security.Cryptography;
using PostQuantum.SecureChannel.Cryptography;

namespace PostQuantum.SecureChannel;

/// <summary>
/// The public half of a <see cref="PqIdentity"/>: an encoded ML-DSA-65 verification key plus a short,
/// human-comparable fingerprint for pinning.
/// </summary>
/// <remarks>
/// Equality and hashing compare the underlying public-key bytes in constant time, so instances can be
/// safely used as keys in <see cref="HashSet{T}"/> or <see cref="Dictionary{TKey,TValue}"/>. Two
/// instances are equal exactly when they represent the same identity.
/// </remarks>
public sealed class PqIdentityPublicKey : IEquatable<PqIdentityPublicKey>
{
    private readonly byte[] _publicKey;
    private string? _cachedFingerprint;

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
    /// verification ("does the server's fingerprint match what I pinned?"). Cached after first call.
    /// </summary>
    public string Fingerprint()
    {
        return _cachedFingerprint ??= Convert.ToHexString(SHA256.HashData(_publicKey)).ToLowerInvariant();
    }

    /// <summary>
    /// A short, human-comparable form of <see cref="Fingerprint"/>: the first 8 bytes as colon-separated
    /// hex (for example, <c>9f:86:d0:81:88:4c:7d:65</c>). Handy for quick visual checks in logs or a UI.
    /// </summary>
    public string ShortFingerprint()
    {
        var hex = Fingerprint();
        return $"{hex[..2]}:{hex[2..4]}:{hex[4..6]}:{hex[6..8]}:{hex[8..10]}:{hex[10..12]}:{hex[12..14]}:{hex[14..16]}";
    }

    /// <summary>Returns a short, log-friendly representation: <c>pq:&lt;short-fingerprint&gt;</c>.</summary>
    public override string ToString() => $"pq:{ShortFingerprint()}";

    /// <inheritdoc />
    public bool Equals(PqIdentityPublicKey? other)
        => other is not null && CryptographicOperations.FixedTimeEquals(_publicKey, other._publicKey);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PqIdentityPublicKey other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        // Use the first 4 bytes of the SHA-256 fingerprint — it is already cached and produces a
        // well-distributed hash for collection keys without exposing the underlying public key.
        var fp = Fingerprint();
        return HashCode.Combine(fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]);
    }

    /// <summary>Constant-time equality of two pinned public keys.</summary>
    public static bool operator ==(PqIdentityPublicKey? left, PqIdentityPublicKey? right)
        => left is null ? right is null : left.Equals(right);

    /// <summary>Inverse of <see cref="op_Equality"/>.</summary>
    public static bool operator !=(PqIdentityPublicKey? left, PqIdentityPublicKey? right) => !(left == right);

    internal ReadOnlySpan<byte> Bytes => _publicKey;

    internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        => MlDsaSignature.Verify(_publicKey, message, signature);
}

using System.Security.Cryptography;
using PostQuantum.SecureChannel.Cryptography;

namespace PostQuantum.SecureChannel;

/// <summary>
/// A long-term cryptographic identity: an ML-DSA-65 signing key used to authenticate one endpoint
/// across many sessions. A server (and, for mutual authentication, a client) owns one of these and
/// distributes the matching <see cref="PqIdentityPublicKey"/> to its peers out of band (for example,
/// pinned in configuration).
/// </summary>
public sealed class PqIdentity : IDisposable
{
    private readonly byte[] _privateSeed;
    private bool _disposed;

    private PqIdentity(byte[] privateSeed, PqIdentityPublicKey publicKey)
    {
        _privateSeed = privateSeed;
        PublicKey = publicKey;
    }

    /// <summary>The shareable public half of this identity.</summary>
    public PqIdentityPublicKey PublicKey { get; }

    /// <summary>Creates a brand-new random identity.</summary>
    public static PqIdentity Create()
    {
        var (seed, publicKey) = MlDsaSignature.GenerateKeyPair();
        return new PqIdentity(seed, new PqIdentityPublicKey(publicKey));
    }

    /// <summary>
    /// Exports the 32-byte private seed for secure storage. Treat the result as highly sensitive key
    /// material: store it in a secret manager or protected file, never in source control.
    /// </summary>
    public byte[] ExportPrivateSeed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_privateSeed.Clone();
    }

    /// <summary>Restores an identity from a 32-byte private seed previously produced by <see cref="ExportPrivateSeed"/>.</summary>
    public static PqIdentity ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
    {
        if (privateSeed.Length != MlDsaSignature.PrivateSeedSize)
        {
            throw new ArgumentException(
                $"Identity private seed must be {MlDsaSignature.PrivateSeedSize} bytes.", nameof(privateSeed));
        }

        var seed = privateSeed.ToArray();
        var publicKey = MlDsaSignature.DerivePublicKey(seed);
        return new PqIdentity(seed, new PqIdentityPublicKey(publicKey));
    }

    internal byte[] Sign(ReadOnlySpan<byte> message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return MlDsaSignature.Sign(_privateSeed, message);
    }

    /// <summary>Zeroes the private seed.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_privateSeed);
        _disposed = true;
    }
}

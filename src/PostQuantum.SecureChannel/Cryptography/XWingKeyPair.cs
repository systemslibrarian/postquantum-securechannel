using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Cryptography;

/// <summary>
/// An ephemeral X-Wing key pair: a 32-byte private seed and its derived 1216-byte public key.
/// </summary>
/// <remarks>
/// In the handshake these key pairs are short-lived (one per session), which is what gives the
/// channel forward secrecy. Hold them no longer than necessary and call <see cref="Dispose"/> to
/// zero the private seed when finished.
/// </remarks>
public sealed class XWingKeyPair : IDisposable
{
    private readonly byte[] _privateSeed;
    private readonly byte[] _publicKey;
    private bool _disposed;

    private XWingKeyPair(byte[] privateSeed, byte[] publicKey)
    {
        _privateSeed = privateSeed;
        _publicKey = (byte[])publicKey.Clone();
    }

    /// <summary>The encapsulation (public) key to publish to the peer.</summary>
    public byte[] PublicKey => (byte[])_publicKey.Clone();

    /// <summary>Reconstructs a key pair from a previously generated 32-byte seed.</summary>
    public static XWingKeyPair FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != XWing.PrivateKeySize)
        {
            throw new ArgumentException($"X-Wing seed must be {XWing.PrivateKeySize} bytes.", nameof(seed));
        }

        var copy = (byte[])seed.Clone();
        var expanded = XWing.ExpandPrivateKey(copy);
        return new XWingKeyPair(copy, expanded.PublicKey);
    }

    /// <summary>Decapsulates a ciphertext produced against <see cref="PublicKey"/>.</summary>
    public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return XWing.Decapsulate(_privateSeed, ciphertext);
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

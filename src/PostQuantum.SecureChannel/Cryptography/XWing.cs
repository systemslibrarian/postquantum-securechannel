using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PostQuantum.SecureChannel.Internal;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace PostQuantum.SecureChannel.Cryptography;

/// <summary>
/// The X-Wing hybrid KEM (ML-KEM-768 + X25519), per
/// <see href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">draft-connolly-cfrg-xwing-kem</see>.
/// <para>
/// X-Wing combines a NIST-standardized lattice KEM with the classical X25519 Diffie-Hellman so that
/// the agreed secret stays secure as long as <em>either</em> primitive is unbroken. The combiner and
/// key-derivation here are validated byte-for-byte against the published IETF test vectors.
/// </para>
/// </summary>
/// <remarks>
/// This type only performs key agreement. Authentication of the peer is layered on top via ML-DSA
/// signatures (see <see cref="MlDsaSignature"/> and the handshake), and the agreed secret is never
/// used directly as a session key &#8212; it is always run through HKDF first.
/// </remarks>
public static class XWing
{
    /// <summary>Length, in bytes, of an X-Wing decapsulation (private) key &#8212; a 32-byte seed.</summary>
    public const int PrivateKeySize = 32;

    /// <summary>Length, in bytes, of an X-Wing encapsulation (public) key (ML-KEM-768 ek || X25519 pk).</summary>
    public const int PublicKeySize = 1216;

    /// <summary>Length, in bytes, of an X-Wing ciphertext (ML-KEM-768 ct || X25519 ct).</summary>
    public const int CiphertextSize = 1120;

    /// <summary>Length, in bytes, of the agreed shared secret.</summary>
    public const int SharedSecretSize = 32;

    private const int MlKemPublicKeySize = 1184;
    private const int MlKemCiphertextSize = 1088;
    private const int X25519Size = 32;

    // XWingLabel = ASCII "\.//^\" (draft-connolly-cfrg-xwing-kem, the combiner domain separator).
    private static readonly byte[] XWingLabel = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

    /// <summary>Generates a fresh X-Wing key pair from cryptographically secure randomness.</summary>
    public static XWingKeyPair GenerateKeyPair()
    {
        var seed = new byte[PrivateKeySize];
        RandomBytes.Fill(seed);
        try
        {
            // FromSeed clones the seed; this local is a second copy of the master private seed and
            // must not be abandoned to the GC un-zeroed (the whole key pair re-derives from it).
            return XWingKeyPair.FromSeed(seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Encapsulates to <paramref name="publicKey"/>, returning the ciphertext to send to the peer and
    /// the shared secret to keep locally.
    /// </summary>
    /// <param name="publicKey">The peer's <see cref="PublicKeySize"/>-byte encapsulation key.</param>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException($"X-Wing public key must be {PublicKeySize} bytes.", nameof(publicKey));
        }

        // Fresh per-encapsulation randomness: 32 bytes seed the ML-KEM message, 32 the X25519 ephemeral.
        Span<byte> randomness = stackalloc byte[64];
        RandomBytes.Fill(randomness);
        try
        {
            return EncapsulateInternal(publicKey, randomness);
        }
        finally
        {
            randomness.Clear();
        }
    }

    /// <summary>Recovers the shared secret from <paramref name="ciphertext"/> using the local private key.</summary>
    /// <param name="privateKey">The local <see cref="PrivateKeySize"/>-byte decapsulation seed.</param>
    /// <param name="ciphertext">The peer's <see cref="CiphertextSize"/>-byte ciphertext.</param>
    public static byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext)
    {
        if (privateKey.Length != PrivateKeySize)
        {
            throw new ArgumentException($"X-Wing private key must be {PrivateKeySize} bytes.", nameof(privateKey));
        }

        if (ciphertext.Length != CiphertextSize)
        {
            throw new ArgumentException($"X-Wing ciphertext must be {CiphertextSize} bytes.", nameof(ciphertext));
        }

        var expanded = ExpandPrivateKey(privateKey);
        byte[]? ssM = null;
        byte[]? ssX = null;
        try
        {
            var ctM = ciphertext[..MlKemCiphertextSize];
            var ctX = ciphertext.Slice(MlKemCiphertextSize, X25519Size);

            // ss_M = ML-KEM-768.Decaps(ct_M, dk_M)
            var decap = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            decap.Init(MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, expanded.MlKemSeed));
            ssM = new byte[decap.SecretLength];
            decap.Decapsulate(ctM, ssM);

            // ss_X = X25519(sk_X, ct_X)
            ssX = new byte[X25519Size];
            BcX25519.ScalarMult(expanded.X25519PrivateKey, ctX, ssX);

            return Combiner(ssM, ssX, ctX, expanded.X25519PublicKey);
        }
        finally
        {
            // Zero the derived private key and the KEM shared-secret halves; only the combined,
            // HKDF-bound result leaves this method (and the caller zeroes that in turn).
            expanded.ClearSecrets();
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
        }
    }

    /// <summary>
    /// Deterministic encapsulation used for test-vector validation. Not part of the public surface
    /// because callers must never supply their own KEM randomness in production.
    /// </summary>
    internal static (byte[] Ciphertext, byte[] SharedSecret) EncapsulateInternal(
        ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> randomness64)
    {
        var pkM = publicKey[..MlKemPublicKeySize];
        var pkX = publicKey.Slice(MlKemPublicKeySize, X25519Size).ToArray();

        var mlkemMessage = randomness64[..32].ToArray();
        var ephemeralX = randomness64.Slice(32, 32);

        byte[]? ssX = null;
        byte[]? ssM = null;
        try
        {
            // X25519 ephemeral: ct_X = X25519(ek_X, base), ss_X = X25519(ek_X, pk_X)
            var ctX = new byte[X25519Size];
            BcX25519.ScalarMultBase(ephemeralX, ctX);
            ssX = new byte[X25519Size];
            BcX25519.ScalarMult(ephemeralX, pkX, ssX);

            // ML-KEM-768 encapsulation, deterministic in the supplied message.
            var encap = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            encap.Init(new ParametersWithRandom(
                MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pkM.ToArray()),
                new SingleShotRandom(mlkemMessage)));
            var ctM = new byte[encap.EncapsulationLength];
            ssM = new byte[encap.SecretLength];
            encap.Encapsulate(ctM, 0, ctM.Length, ssM, 0, ssM.Length);

            var sharedSecret = Combiner(ssM, ssX, ctX, pkX);

            var ciphertext = new byte[CiphertextSize];
            ctM.CopyTo(ciphertext.AsSpan(0));
            ctX.CopyTo(ciphertext.AsSpan(MlKemCiphertextSize));
            return (ciphertext, sharedSecret);
        }
        finally
        {
            // The secret ML-KEM message and both KEM shared-secret halves are transient; zero them so
            // only the combined, HKDF-bound shared secret survives (the caller zeroes that in turn).
            CryptographicOperations.ZeroMemory(mlkemMessage);
            CryptographicOperations.ZeroMemory(ssX);
            CryptographicOperations.ZeroMemory(ssM);
        }
    }

    /// <summary>Derives the full public key (and intermediate keys) from a 32-byte seed.</summary>
    internal static ExpandedKey ExpandPrivateKey(ReadOnlySpan<byte> seed)
    {
        // expanded = SHAKE256(sk, 96); [0:64] seeds ML-KEM KeyGen_internal(d, z); [64:96] is the X25519 scalar.
        // The C# range operator copies into new arrays, so `expanded` itself is a third copy of the full
        // expanded decapsulation key that ClearSecrets() cannot reach; zero it here once the slices are taken.
        var expanded = Sha3.Shake256(seed, 96);
        try
        {
            var mlkemSeed = expanded[..64];
            var skX = expanded[64..96];

            var dkM = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, mlkemSeed);
            var pkM = dkM.GetPublicKeyEncoded();

            var pkX = new byte[X25519Size];
            BcX25519.ScalarMultBase(skX, pkX);

            var publicKey = new byte[PublicKeySize];
            pkM.CopyTo(publicKey.AsSpan(0));
            pkX.CopyTo(publicKey.AsSpan(MlKemPublicKeySize));

            return new ExpandedKey(mlkemSeed, skX, pkX, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
        }
    }

    // SS = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    private static byte[] Combiner(
        ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX, ReadOnlySpan<byte> ctX, ReadOnlySpan<byte> pkX)
    {
        // ct_X and pk_X are public; the two shared-secret halves are the secret inputs and are the
        // transient copies worth zeroing after hashing.
        byte[] a = ssM.ToArray();
        byte[] b = ssX.ToArray();
        try
        {
            return Sha3.Hash256(a, b, ctX.ToArray(), pkX.ToArray(), XWingLabel);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(a);
            CryptographicOperations.ZeroMemory(b);
        }
    }

    internal readonly struct ExpandedKey(byte[] mlKemSeed, byte[] x25519PrivateKey, byte[] x25519PublicKey, byte[] publicKey)
    {
        internal byte[] MlKemSeed { get; } = mlKemSeed;
        internal byte[] X25519PrivateKey { get; } = x25519PrivateKey;
        internal byte[] X25519PublicKey { get; } = x25519PublicKey;
        internal byte[] PublicKey { get; } = publicKey;

        /// <summary>Zeroes the secret components (the ML-KEM seed and the X25519 scalar).</summary>
        internal void ClearSecrets()
        {
            CryptographicOperations.ZeroMemory(MlKemSeed);
            CryptographicOperations.ZeroMemory(X25519PrivateKey);
        }
    }

    /// <summary>A <see cref="SecureRandom"/> that emits a fixed buffer once, for deterministic ML-KEM encapsulation.</summary>
    private sealed class SingleShotRandom(byte[] buffer) : SecureRandom
    {
        private readonly byte[] _buffer = buffer;
        private int _position;

        public override void NextBytes(byte[] bytes) => NextBytes(bytes, 0, bytes.Length);

        public override void NextBytes(byte[] bytes, int start, int len)
        {
            Array.Copy(_buffer, _position, bytes, start, len);
            _position += len;
        }

        public override void NextBytes(Span<byte> bytes)
        {
            _buffer.AsSpan(_position, bytes.Length).CopyTo(bytes);
            _position += bytes.Length;
        }
    }
}

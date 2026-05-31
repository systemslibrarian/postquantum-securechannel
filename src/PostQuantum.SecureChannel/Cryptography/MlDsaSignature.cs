using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace PostQuantum.SecureChannel.Cryptography;

/// <summary>
/// ML-DSA (FIPS 204) digital signatures, used to authenticate the handshake transcript. The library
/// fixes the parameter set at ML-DSA-65 (NIST security category 3) to match the strength of X-Wing's
/// ML-KEM-768 component.
/// </summary>
public static class MlDsaSignature
{
    private static readonly MLDsaParameters Parameters = MLDsaParameters.ml_dsa_65;

    /// <summary>Length, in bytes, of an ML-DSA-65 private key seed.</summary>
    public const int PrivateSeedSize = 32;

    /// <summary>Length, in bytes, of an encoded ML-DSA-65 public key.</summary>
    public const int PublicKeySize = 1952;

    /// <summary>Generates a fresh ML-DSA-65 key pair, returned as (privateSeed, publicKey).</summary>
    public static (byte[] PrivateSeed, byte[] PublicKey) GenerateKeyPair()
    {
        var seed = Internal.RandomBytes.Create(PrivateSeedSize);
        var sk = MLDsaPrivateKeyParameters.FromSeed(Parameters, seed);
        return (seed, sk.GetPublicKeyEncoded());
    }

    /// <summary>Derives the encoded public key from a private seed.</summary>
    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateSeed)
    {
        var sk = MLDsaPrivateKeyParameters.FromSeed(Parameters, privateSeed.ToArray());
        return sk.GetPublicKeyEncoded();
    }

    /// <summary>Signs <paramref name="message"/> with the private key identified by <paramref name="privateSeed"/>.</summary>
    public static byte[] Sign(ReadOnlySpan<byte> privateSeed, ReadOnlySpan<byte> message)
    {
        var sk = MLDsaPrivateKeyParameters.FromSeed(Parameters, privateSeed.ToArray());
        var signer = new MLDsaSigner(Parameters, deterministic: false);
        signer.Init(forSigning: true, sk);
        signer.BlockUpdate(message);
        return signer.GenerateSignature();
    }

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="message"/> against an encoded public key.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize)
        {
            return false;
        }

        try
        {
            var pk = MLDsaPublicKeyParameters.FromEncoding(Parameters, publicKey.ToArray());
            var verifier = new MLDsaSigner(Parameters, deterministic: false);
            verifier.Init(forSigning: false, pk);
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(signature.ToArray());
        }
        catch (Exception)
        {
            // A malformed key or signature is simply an invalid signature, never an exception to the caller.
            return false;
        }
    }
}

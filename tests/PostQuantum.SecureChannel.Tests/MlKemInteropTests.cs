#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Live interop between the two ML-KEM-768 implementations that matter here: BouncyCastle (the one this
/// library uses under X-Wing) and .NET's built-in <see cref="MLKem"/> (an entirely separate codebase).
/// This is the "different implementation in the same test run" cross-check called out in
/// <c>docs/AUDIT-SCOPE.md</c> §11 — stronger than a static KAT vector because both live stacks must
/// agree on key generation, encapsulation, and decapsulation.
///
/// <para>
/// Runs only where the platform provides an independent ML-KEM (e.g. Linux with OpenSSL 3.5+, where
/// <see cref="MLKem.IsSupported"/> is true). On platforms without it (e.g. Windows without CNG ML-KEM),
/// the check is skipped rather than failing — the value is realized in CI where support is present.
/// </para>
/// </summary>
// System.Security.Cryptography's PQC types are marked [Experimental]; opting in is deliberate here.
#pragma warning disable SYSLIB5006
public class MlKemInteropTests
{
    [SkippableFact]
    public void BouncyCastle_And_DotNet_MLKem768_Interoperate()
    {
        Skip.IfNot(MLKem.IsSupported,
            "This platform has no built-in ML-KEM (MLKem.IsSupported == false); interop check is exercised on supporting platforms in CI.");

        // (1) Key generation interop: the same FIPS 203 (d‖z) seed must derive the same key pair in both.
        byte[] seed = new byte[64];
        RandomNumberGenerator.Fill(seed);

        var bcPrivate = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
        byte[] bcPublic = bcPrivate.GetPublicKeyEncoded();

        using var netKey = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seed);
        byte[] netPublic = netKey.ExportEncapsulationKey();

        Assert.Equal(bcPublic, netPublic);

        // (2) .NET encapsulates -> BouncyCastle decapsulates -> shared secrets agree.
        netKey.Encapsulate(out byte[] ciphertextFromNet, out byte[] ssFromNet);

        var bcDecap = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        bcDecap.Init(bcPrivate);
        byte[] ssFromBc = new byte[bcDecap.SecretLength];
        bcDecap.Decapsulate(ciphertextFromNet, ssFromBc);

        Assert.Equal(ssFromNet, ssFromBc);

        // (3) BouncyCastle encapsulates -> .NET decapsulates -> shared secrets agree.
        var bcEncap = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        bcEncap.Init(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, bcPublic));
        byte[] ciphertextFromBc = new byte[bcEncap.EncapsulationLength];
        byte[] ssFromBc2 = new byte[bcEncap.SecretLength];
        bcEncap.Encapsulate(ciphertextFromBc, 0, ciphertextFromBc.Length, ssFromBc2, 0, ssFromBc2.Length);

        byte[] ssFromNet2 = netKey.Decapsulate(ciphertextFromBc);

        Assert.Equal(ssFromBc2, ssFromNet2);
    }
}
#pragma warning restore SYSLIB5006
#endif // NET10_0_OR_GREATER

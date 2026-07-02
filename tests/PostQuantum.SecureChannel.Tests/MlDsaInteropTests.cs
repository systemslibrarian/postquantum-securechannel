#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using PostQuantum.SecureChannel.Cryptography;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Live interop between the two ML-DSA-65 implementations that matter here: BouncyCastle (what this
/// library signs handshake transcripts with, via <see cref="MlDsaSignature"/>) and .NET's built-in
/// <see cref="MLDsa"/> — a separate codebase. Cross-verifying signatures across the two independent
/// stacks is the "different implementation in the same test run" check from <c>docs/AUDIT-SCOPE.md</c>
/// §11, and stronger than a static KAT because both live stacks must agree on key derivation and on
/// signature verification.
///
/// <para>
/// Runs only where the platform provides an independent ML-DSA (<see cref="MLDsa.IsSupported"/>);
/// skipped otherwise, with the value realized in CI where support is present.
/// </para>
/// </summary>
// System.Security.Cryptography's PQC types are marked [Experimental]; opting in is deliberate here.
#pragma warning disable SYSLIB5006
public class MlDsaInteropTests
{
    [SkippableFact]
    public void BouncyCastle_And_DotNet_MLDsa65_Interoperate()
    {
        Skip.IfNot(MLDsa.IsSupported,
            "This platform has no built-in ML-DSA (MLDsa.IsSupported == false); interop check is exercised on supporting platforms in CI.");

        byte[] seed = new byte[MlDsaSignature.PrivateSeedSize];
        RandomNumberGenerator.Fill(seed);
        byte[] message = "post-quantum handshake transcript"u8.ToArray();

        // (1) Key generation interop: the same seed must derive the same public key in both.
        byte[] bcPublic = MlDsaSignature.DerivePublicKey(seed);

        using var netKey = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, seed);
        byte[] netPublic = netKey.ExportMLDsaPublicKey();

        Assert.Equal(bcPublic, netPublic);

        // (2) BouncyCastle signs -> .NET verifies (empty context on both sides).
        byte[] sigFromBc = MlDsaSignature.Sign(seed, message);
        Assert.True(netKey.VerifyData(message, sigFromBc), "a BouncyCastle signature must verify under .NET");

        // (3) .NET signs -> BouncyCastle verifies.
        byte[] sigFromNet = netKey.SignData(message);
        Assert.True(MlDsaSignature.Verify(bcPublic, message, sigFromNet), "a .NET signature must verify under BouncyCastle");

        // (4) A tampered message must fail cross-verification, both ways.
        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0x01;
        Assert.False(netKey.VerifyData(tampered, sigFromBc));
        Assert.False(MlDsaSignature.Verify(bcPublic, tampered, sigFromNet));
    }
}
#pragma warning restore SYSLIB5006
#endif // NET10_0_OR_GREATER

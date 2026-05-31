using PostQuantum.SecureChannel.Cryptography;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class IdentityTests
{
    [Fact]
    public void Identity_ExportImport_RoundTrips()
    {
        using var identity = PqIdentity.Create();
        var seed = identity.ExportPrivateSeed();

        using var restored = PqIdentity.ImportPrivateSeed(seed);

        Assert.Equal(identity.PublicKey.Export(), restored.PublicKey.Export());
        Assert.Equal(identity.PublicKey.Fingerprint(), restored.PublicKey.Fingerprint());
    }

    [Fact]
    public void PublicKey_ExportImport_RoundTrips()
    {
        using var identity = PqIdentity.Create();
        var exported = identity.PublicKey.Export();

        var imported = PqIdentityPublicKey.Import(exported);

        Assert.Equal(identity.PublicKey.Fingerprint(), imported.Fingerprint());
    }

    [Fact]
    public void Fingerprint_IsStableAndHex()
    {
        using var identity = PqIdentity.Create();
        var fingerprint = identity.PublicKey.Fingerprint();

        Assert.Equal(64, fingerprint.Length); // SHA-256 hex
        Assert.Matches("^[0-9a-f]+$", fingerprint);
        Assert.Equal(fingerprint, identity.PublicKey.Fingerprint());
    }

    [Fact]
    public void PublicKey_Base64_RoundTrips()
    {
        using var identity = PqIdentity.Create();
        var base64 = identity.PublicKey.ToBase64();

        var restored = PqIdentityPublicKey.FromBase64(base64);

        Assert.Equal(identity.PublicKey.Fingerprint(), restored.Fingerprint());
    }

    [Fact]
    public void FromBase64_RejectsGarbage()
    {
        Assert.Throws<ArgumentException>(() => PqIdentityPublicKey.FromBase64("not valid base64!!!"));
    }

    [Fact]
    public void ShortFingerprint_IsPrefixOfFullFingerprint()
    {
        using var identity = PqIdentity.Create();

        var full = identity.PublicKey.Fingerprint();
        var shortFp = identity.PublicKey.ShortFingerprint();

        Assert.Matches("^([0-9a-f]{2}:){7}[0-9a-f]{2}$", shortFp);
        Assert.Equal(full[..16], shortFp.Replace(":", string.Empty));
    }

    [Fact]
    public void MlDsa_SignVerify_RoundTrips()
    {
        var (seed, publicKey) = MlDsaSignature.GenerateKeyPair();
        var message = System.Text.Encoding.UTF8.GetBytes("authenticate me");

        var signature = MlDsaSignature.Sign(seed, message);

        Assert.True(MlDsaSignature.Verify(publicKey, message, signature));
    }

    [Fact]
    public void MlDsa_RejectsTamperedMessage()
    {
        var (seed, publicKey) = MlDsaSignature.GenerateKeyPair();
        var message = System.Text.Encoding.UTF8.GetBytes("original");
        var signature = MlDsaSignature.Sign(seed, message);

        var tampered = System.Text.Encoding.UTF8.GetBytes("Original");
        Assert.False(MlDsaSignature.Verify(publicKey, tampered, signature));
    }
}

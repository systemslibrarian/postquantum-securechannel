using PostQuantum.SecureChannel.Cryptography;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class XWingTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    // Known-Answer Tests from draft-connolly-cfrg-xwing-kem (IETF), Appendix C. Passing these means
    // this implementation is wire-compatible with any other conformant X-Wing implementation: it
    // validates key expansion, the combiner (order + label), ML-KEM encapsulation, and X25519 clamping.
    [Theory]
    [InlineData(
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")]
    [InlineData(
        "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
        "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
        "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150")]
    [InlineData(
        "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
        "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
        "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f")]
    public void MatchesPublishedKnownAnswerTests(string skHex, string eseedHex, string expectedSharedSecret)
    {
        var keyPair = XWingKeyPair.FromSeed(Hex(skHex));
        var (_, sharedSecret) = XWing.EncapsulateInternal(keyPair.PublicKey, Hex(eseedHex));

        Assert.Equal(expectedSharedSecret, Convert.ToHexString(sharedSecret).ToLowerInvariant());
    }

    [Fact]
    public void EncapsulateDecapsulate_RoundTrips()
    {
        using var keyPair = XWing.GenerateKeyPair();

        var (ciphertext, senderSecret) = XWing.Encapsulate(keyPair.PublicKey);
        var receiverSecret = keyPair.Decapsulate(ciphertext);

        Assert.Equal(XWing.SharedSecretSize, senderSecret.Length);
        Assert.Equal(senderSecret, receiverSecret);
    }

    [Fact]
    public void DifferentKeyPair_ProducesDifferentSecret()
    {
        using var alice = XWing.GenerateKeyPair();
        using var mallory = XWing.GenerateKeyPair();

        var (ciphertext, _) = XWing.Encapsulate(alice.PublicKey);

        // Decapsulating Alice's ciphertext with Mallory's key yields an unrelated (implicitly-rejected) secret.
        var wrong = mallory.Decapsulate(ciphertext);
        var right = alice.Decapsulate(ciphertext);
        Assert.NotEqual(right, wrong);
    }

    [Fact]
    public void ProducedSizes_MatchSpecification()
    {
        using var keyPair = XWing.GenerateKeyPair();
        var (ciphertext, secret) = XWing.Encapsulate(keyPair.PublicKey);

        Assert.Equal(XWing.PublicKeySize, keyPair.PublicKey.Length);
        Assert.Equal(XWing.CiphertextSize, ciphertext.Length);
        Assert.Equal(XWing.SharedSecretSize, secret.Length);
    }
}

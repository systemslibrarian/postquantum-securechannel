using PostQuantum.SecureChannel.Cryptography;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class VersionNegotiationTests
{
    [Theory]
    [InlineData(new byte[] { 1 }, 1)]          // exact match
    [InlineData(new byte[] { 2, 1 }, 1)]       // client offers extra unknown version + 1
    [InlineData(new byte[] { 9, 8, 1 }, 1)]    // 1 is the only common one
    [InlineData(new byte[] { 2, 3 }, 0)]       // no overlap
    [InlineData(new byte[] { }, 0)]            // empty
    public void NegotiateVersion_PicksHighestCommon(byte[] clientSupported, int expected)
    {
        Assert.Equal((byte)expected, PqProtocol.NegotiateVersion(clientSupported));
    }

    [Fact]
    public void HappyPath_NegotiatesVersionOne()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var serverHelloBytes = server.ProcessClientHello(client.CreateClientHello());
        var sh = ServerHello.Parse(serverHelloBytes);

        Assert.Equal(1, sh.NegotiatedVersion);
        // And the client accepts it.
        var result = client.ProcessServerHello(serverHelloBytes);
        Assert.Equal(PqRole.Client, result.Session.Role);
    }

    [Fact]
    public void Server_RejectsClientWithNoCommonVersion()
    {
        using var serverIdentity = PqIdentity.Create();
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        // Craft a ClientHello that only offers an unsupported version.
        using var keyPair = XWing.GenerateKeyPair();
        var hostileHello = new ClientHello
        {
            SupportedVersions = [42],
            ClientRandom = new byte[PqProtocol.RandomSize],
            KemPublicKey = keyPair.PublicKey,
        }.Serialize();

        Assert.Throws<PqProtocolException>(() => server.ProcessClientHello(hostileHello));
    }

    [Fact]
    public void Client_RejectsUnsupportedNegotiatedVersion()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var clientHello = client.CreateClientHello();

        // Forge a ServerHello claiming an unsupported negotiated version (signature won't matter; the
        // version check happens first).
        using var kp = XWing.GenerateKeyPair();
        var (ciphertext, _) = XWing.Encapsulate(kp.PublicKey);
        var forged = new ServerHello
        {
            NegotiatedVersion = 99,
            ServerRandom = new byte[PqProtocol.RandomSize],
            KemCiphertext = ciphertext,
            ServerIdentityPublicKey = serverIdentity.PublicKey.Export(),
            Signature = [1, 2, 3],
        }.Serialize();

        Assert.Throws<PqProtocolException>(() => client.ProcessServerHello(forged));
    }
}

using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// <see cref="PqClientOptions.AllowedServerIdentities"/> enables staged identity rotation: clients
/// accept either the old or the new server key during the overlap window, then drop the old one.
/// </summary>
public class MultiPinTests
{
    private static (PqSession Client, PqSession Server) Handshake(PqClientOptions clientOptions, PqIdentity serverIdentity)
    {
        var client = PqSecureChannel.CreateClient(clientOptions);
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void MultiplePinned_AcceptsTheActiveIdentity()
    {
        using var oldIdentity = PqIdentity.Create();
        using var newIdentity = PqIdentity.Create();

        // The client trusts both during the rotation window.
        var options = new PqClientOptions
        {
            ServerIdentity = newIdentity.PublicKey,
            AllowedServerIdentities = [oldIdentity.PublicKey, newIdentity.PublicKey],
        };

        // Server is still presenting the old identity → handshake succeeds (matches an allowed pin).
        var (client, _) = Handshake(options, oldIdentity);
        Assert.Equal(oldIdentity.PublicKey.Fingerprint(), client.RemoteIdentity!.Fingerprint());
    }

    [Fact]
    public void MultiplePinned_UnknownIdentity_IsRejected()
    {
        using var trustedA = PqIdentity.Create();
        using var trustedB = PqIdentity.Create();
        using var stranger = PqIdentity.Create();

        var options = new PqClientOptions
        {
            ServerIdentity = trustedA.PublicKey,
            AllowedServerIdentities = [trustedA.PublicKey, trustedB.PublicKey],
        };

        Assert.Throws<PqAuthenticationException>(() => Handshake(options, stranger));
    }

    [Fact]
    public void AllowedServerIdentities_Only_NoPrimary_StillWorks()
    {
        using var serverIdentity = PqIdentity.Create();
        var options = new PqClientOptions
        {
            AllowedServerIdentities = [serverIdentity.PublicKey],
        };

        var (client, server) = Handshake(options, serverIdentity);

        var record = client.Encrypt(Encoding.UTF8.GetBytes("rotation works"));
        Assert.Equal("rotation works", Encoding.UTF8.GetString(server.Decrypt(record)));
    }

    [Fact]
    public void NoPinsAtAll_FailsAtCreation()
    {
        Assert.Throws<ArgumentException>(() =>
            PqSecureChannel.CreateClient(new PqClientOptions()));
    }
}

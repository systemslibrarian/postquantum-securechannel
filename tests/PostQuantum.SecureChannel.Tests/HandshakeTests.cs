using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class HandshakeTests
{
    private static (PqSession Client, PqSession Server) Handshake(
        PqClientOptions clientOptions, PqServerOptions serverOptions)
    {
        var client = PqSecureChannel.CreateClient(clientOptions);
        var server = PqSecureChannel.CreateServer(serverOptions);

        var clientHello = client.CreateClientHello();
        var serverHello = server.ProcessClientHello(clientHello);
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        return (result.Session, serverSession);
    }

    [Fact]
    public void ServerAuthenticatedHandshake_EstablishesWorkingChannel()
    {
        using var serverIdentity = PqIdentity.Create();

        var (clientSession, serverSession) = Handshake(
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey },
            new PqServerOptions { Identity = serverIdentity });

        Assert.Equal(PqRole.Client, clientSession.Role);
        Assert.Equal(PqRole.Server, serverSession.Role);

        // Client authenticated the server.
        Assert.NotNull(clientSession.RemoteIdentity);
        Assert.Equal(serverIdentity.PublicKey.Fingerprint(), clientSession.RemoteIdentity!.Fingerprint());

        // Anonymous client: server has no client identity.
        Assert.Null(serverSession.RemoteIdentity);
    }

    [Fact]
    public void Roundtrip_BothDirections()
    {
        using var serverIdentity = PqIdentity.Create();
        var (client, server) = Handshake(
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey },
            new PqServerOptions { Identity = serverIdentity });

        var toServer = Encoding.UTF8.GetBytes("hello server");
        var record1 = client.Encrypt(toServer);
        Assert.Equal(toServer, server.Decrypt(record1));

        var toClient = Encoding.UTF8.GetBytes("hello client");
        var record2 = server.Encrypt(toClient);
        Assert.Equal(toClient, client.Decrypt(record2));
    }

    [Fact]
    public void MutualAuthentication_ServerLearnsClientIdentity()
    {
        using var serverIdentity = PqIdentity.Create();
        using var clientIdentity = PqIdentity.Create();

        var (_, serverSession) = Handshake(
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey, ClientIdentity = clientIdentity },
            new PqServerOptions { Identity = serverIdentity, RequireClientAuthentication = true });

        Assert.NotNull(serverSession.RemoteIdentity);
        Assert.Equal(clientIdentity.PublicKey.Fingerprint(), serverSession.RemoteIdentity!.Fingerprint());
    }

    [Fact]
    public void RequireClientAuth_WithoutClientIdentity_Fails()
    {
        using var serverIdentity = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(
            new PqServerOptions { Identity = serverIdentity, RequireClientAuthentication = true });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);

        Assert.Throws<PqAuthenticationException>(() => server.ProcessClientFinished(result.ClientFinished));
    }

    [Fact]
    public void AuthorizedClients_RejectsUnknownClient()
    {
        using var serverIdentity = PqIdentity.Create();
        using var knownClient = PqIdentity.Create();
        using var unknownClient = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey, ClientIdentity = unknownClient });
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            RequireClientAuthentication = true,
            AuthorizedClients = [knownClient.PublicKey],
        });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);

        Assert.Throws<PqAuthenticationException>(() => server.ProcessClientFinished(result.ClientFinished));
    }

    [Fact]
    public void WrongPinnedServerIdentity_IsRejected()
    {
        using var realServer = PqIdentity.Create();
        using var imposter = PqIdentity.Create();

        // Client pins the imposter's key, but the real server signs the handshake.
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = imposter.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = realServer });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());

        Assert.Throws<PqAuthenticationException>(() => client.ProcessServerHello(serverHello));
    }

    [Fact]
    public void TamperedServerHello_IsRejected()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        serverHello[serverHello.Length / 2] ^= 0xFF; // flip a byte

        Assert.ThrowsAny<PqSecureChannelException>(() => client.ProcessServerHello(serverHello));
    }
}

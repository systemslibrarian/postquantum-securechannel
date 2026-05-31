using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class ResumptionTests
{
    private static (PqSession Client, PqSession Server) Handshake(
        PqIdentity serverIdentity, byte[]? clientPsk, byte[]? serverPsk)
    {
        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            ResumptionSecret = clientPsk,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            ResumptionSecret = serverPsk,
        });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void ExportedResumptionSecrets_MatchOnBothSides()
    {
        using var serverIdentity = PqIdentity.Create();
        var (client, server) = Handshake(serverIdentity, null, null);

        Assert.Equal(client.ExportResumptionSecret(), server.ExportResumptionSecret());
        Assert.Equal(32, client.ExportResumptionSecret().Length);
    }

    [Fact]
    public void MatchingResumptionSecret_EstablishesWorkingChannel()
    {
        using var serverIdentity = PqIdentity.Create();

        // First session yields a resumption secret both sides agree on.
        var (c1, s1) = Handshake(serverIdentity, null, null);
        var psk = c1.ExportResumptionSecret();
        Assert.Equal(psk, s1.ExportResumptionSecret());

        // Second session mixes it in on both sides.
        var (c2, s2) = Handshake(serverIdentity, psk, psk);
        var record = c2.Encrypt(Encoding.UTF8.GetBytes("resumed"));
        Assert.Equal("resumed", Encoding.UTF8.GetString(s2.Decrypt(record)));
    }

    [Fact]
    public void MismatchedResumptionSecret_FailsHandshake()
    {
        using var serverIdentity = PqIdentity.Create();
        var clientPsk = new byte[32];
        var serverPsk = new byte[32];
        serverPsk[0] = 1; // different

        // The mismatch yields different key schedules, so client key confirmation fails on the server.
        Assert.Throws<PqAuthenticationException>(() => Handshake(serverIdentity, clientPsk, serverPsk));
    }

    [Fact]
    public void ResumptionSecretOnOneSideOnly_FailsHandshake()
    {
        using var serverIdentity = PqIdentity.Create();
        var psk = new byte[32];
        for (int i = 0; i < psk.Length; i++)
        {
            psk[i] = (byte)i;
        }

        Assert.Throws<PqAuthenticationException>(() => Handshake(serverIdentity, psk, null));
    }
}

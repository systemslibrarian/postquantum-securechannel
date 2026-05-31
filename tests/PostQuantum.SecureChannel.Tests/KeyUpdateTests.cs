using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class KeyUpdateTests
{
    private static (PqSession Client, PqSession Server) Establish()
    {
        var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void KeyUpdate_RatchetsAndKeepsChannelWorking()
    {
        var (client, server) = Establish();

        // Send a record under the original keys.
        var r0 = client.Encrypt(Encoding.UTF8.GetBytes("epoch0"));
        Assert.Equal("epoch0", Encoding.UTF8.GetString(server.Decrypt(r0)));

        Assert.Equal(0u, client.SendEpoch);
        var keyUpdate = client.UpdateSendKey();
        Assert.Equal(1u, client.SendEpoch);

        // The server processes the key-update control record transparently.
        var processed = server.Open(keyUpdate);
        Assert.Equal(PqContentType.KeyUpdate, processed.ContentType);
        Assert.Empty(processed.Payload);
        Assert.Equal(1u, server.ReceiveEpoch);

        // New-epoch records still round-trip; sequence counters reset within the new epoch.
        Assert.Equal(0UL, client.RecordsSent);
        var r1 = client.Encrypt(Encoding.UTF8.GetBytes("epoch1"));
        Assert.Equal("epoch1", Encoding.UTF8.GetString(server.Decrypt(r1)));
    }

    [Fact]
    public void DecryptThrowsOnControlRecord()
    {
        var (client, server) = Establish();
        var keyUpdate = client.UpdateSendKey();

        // Decrypt (the simple API) refuses control records; callers must use Open.
        Assert.Throws<PqProtocolException>(() => server.Decrypt(keyUpdate));
    }

    [Fact]
    public void BothDirectionsCanUpdateIndependently()
    {
        var (client, server) = Establish();

        var cu = client.UpdateSendKey();
        Assert.Equal(PqContentType.KeyUpdate, server.Open(cu).ContentType);

        var su = server.UpdateSendKey();
        Assert.Equal(PqContentType.KeyUpdate, client.Open(su).ContentType);

        Assert.Equal(1u, client.SendEpoch);
        Assert.Equal(1u, client.ReceiveEpoch);
        Assert.Equal(1u, server.SendEpoch);
        Assert.Equal(1u, server.ReceiveEpoch);

        var msg = client.Encrypt(Encoding.UTF8.GetBytes("after both updates"));
        Assert.Equal("after both updates", Encoding.UTF8.GetString(server.Decrypt(msg)));
    }

    [Fact]
    public void StaleEpochRecord_FailsUnderNewEpoch()
    {
        var (client, server) = Establish();

        // Deliver an epoch-0 record normally.
        var m0 = client.Encrypt(Encoding.UTF8.GetBytes("m0"));
        Assert.Equal("m0", Encoding.UTF8.GetString(server.Decrypt(m0)));

        // Client signals a key update; the server ratchets its receive direction.
        var ku = client.UpdateSendKey();
        Assert.Equal(PqContentType.KeyUpdate, server.Open(ku).ContentType);

        // Replaying the old epoch-0 record now fails: it cannot authenticate under the epoch-1 keys.
        Assert.Throws<PqDecryptionException>(() => server.Decrypt(m0));
    }
}

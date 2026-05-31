using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class AntiReplayTests
{
    private static (PqSession Client, PqSession Server) Establish(PqSessionOptions serverSessionOptions)
    {
        var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            SessionOptions = serverSessionOptions,
        });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void SlidingWindow_AcceptsOutOfOrder()
    {
        var (client, server) = Establish(new PqSessionOptions
        {
            ReplayProtection = PqReplayProtection.SlidingWindow,
            ReplayWindowSize = 8,
        });

        var records = Enumerable.Range(0, 6)
            .Select(i => client.Encrypt(Encoding.UTF8.GetBytes($"m{i}")))
            .ToList();

        // Deliver out of order: 2, 0, 1, 5, 3, 4 — all accepted.
        foreach (var i in new[] { 2, 0, 1, 5, 3, 4 })
        {
            var opened = server.Open(records[i]);
            Assert.Equal($"m{i}", Encoding.UTF8.GetString(opened.Payload));
        }
    }

    [Fact]
    public void SlidingWindow_RejectsReplay()
    {
        var (client, server) = Establish(new PqSessionOptions
        {
            ReplayProtection = PqReplayProtection.SlidingWindow,
            ReplayWindowSize = 8,
        });

        var r0 = client.Encrypt(Encoding.UTF8.GetBytes("zero"));
        var r1 = client.Encrypt(Encoding.UTF8.GetBytes("one"));

        server.Open(r0);
        server.Open(r1);
        Assert.Throws<PqDecryptionException>(() => server.Open(r0)); // replay
    }

    [Fact]
    public void SlidingWindow_RejectsTooOld()
    {
        var (client, server) = Establish(new PqSessionOptions
        {
            ReplayProtection = PqReplayProtection.SlidingWindow,
            ReplayWindowSize = 8,
        });

        var records = Enumerable.Range(0, 25)
            .Select(i => client.Encrypt(Encoding.UTF8.GetBytes($"m{i}")))
            .ToList();

        server.Open(records[20]);                                   // advance the window to 20
        Assert.Throws<PqDecryptionException>(() => server.Open(records[5])); // 20 - 5 = 15 >= window (too old)
        Assert.Equal("m19", Encoding.UTF8.GetString(server.Open(records[19]).Payload)); // still inside the window
    }

    [Fact]
    public void InvalidWindowSize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PqSecureChannel.CreateClient(new PqClientOptions
            {
                ServerIdentity = PqIdentity.Create().PublicKey,
                SessionOptions = new PqSessionOptions
                {
                    ReplayProtection = PqReplayProtection.SlidingWindow,
                    ReplayWindowSize = 4, // below the minimum of 8
                },
            }));
    }
}

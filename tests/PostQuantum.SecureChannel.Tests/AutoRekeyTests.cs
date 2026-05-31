using System.Net;
using System.Net.Sockets;
using System.Text;
using PostQuantum.SecureChannel.Transport;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class AutoRekeyTests
{
    private static (PqSession Client, PqSession Server) Establish(PqSessionOptions clientSessionOptions)
    {
        var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            SessionOptions = clientSessionOptions,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void DisabledPolicy_NeverNeedsKeyUpdate()
    {
        var (client, _) = Establish(PqSessionOptions.Default);
        for (int i = 0; i < 100; i++)
        {
            client.Encrypt(Encoding.UTF8.GetBytes("x"));
        }

        Assert.False(client.NeedsKeyUpdate);
    }

    [Fact]
    public void RecordThreshold_TriggersNeedsKeyUpdate()
    {
        var (client, _) = Establish(new PqSessionOptions
        {
            KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxRecordsBeforeUpdate = 3 },
        });

        Assert.False(client.NeedsKeyUpdate);
        client.Encrypt([1]);
        client.Encrypt([2]);
        Assert.False(client.NeedsKeyUpdate);
        client.Encrypt([3]);
        Assert.True(client.NeedsKeyUpdate); // 3 records sent

        // Ratcheting resets the epoch counters and clears the flag.
        client.UpdateSendKey();
        Assert.False(client.NeedsKeyUpdate);
    }

    [Fact]
    public void ByteThreshold_TriggersNeedsKeyUpdate()
    {
        var (client, _) = Establish(new PqSessionOptions
        {
            KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxBytesBeforeUpdate = 10 },
        });

        client.Encrypt(new byte[6]);
        Assert.False(client.NeedsKeyUpdate);
        client.Encrypt(new byte[6]); // 12 bytes total >= 10
        Assert.True(client.NeedsKeyUpdate);
    }

    [Fact]
    public void ZeroThreshold_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PqSecureChannel.CreateClient(new PqClientOptions
            {
                ServerIdentity = PqIdentity.Create().PublicKey,
                SessionOptions = new PqSessionOptions
                {
                    KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxRecordsBeforeUpdate = 0 },
                },
            }));
    }

    [Fact]
    public async Task Stream_AutoRekeysWhenThresholdCrossed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var clientTcp = new TcpClient();
        var acceptTask = listener.AcceptTcpClientAsync();
        await clientTcp.ConnectAsync(IPAddress.Loopback, port);
        using var serverTcp = await acceptTask;
        listener.Stop();

        using var serverIdentity = PqIdentity.Create();
        var clientTask = PqSecureChannel.ConnectAsync(
            clientTcp.GetStream(),
            new PqClientOptions
            {
                ServerIdentity = serverIdentity.PublicKey,
                SessionOptions = new PqSessionOptions
                {
                    KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxRecordsBeforeUpdate = 2 },
                },
            });
        var serverTask = PqSecureChannel.AcceptAsync(
            serverTcp.GetStream(), new PqServerOptions { Identity = serverIdentity });
        await Task.WhenAll(clientTask, serverTask);
        await using var client = await clientTask;
        await using var server = await serverTask;

        // Write several messages; the client should auto-rekey once it crosses two records.
        for (int i = 0; i < 5; i++)
        {
            var payload = Encoding.UTF8.GetBytes($"msg{i}");
            await client.WriteAsync(payload);
            var buffer = new byte[payload.Length];
            await server.ReadExactlyAsync(buffer);
            Assert.Equal($"msg{i}", Encoding.UTF8.GetString(buffer));
        }

        Assert.True(client.Session.SendEpoch >= 1);
        Assert.Equal(client.Session.SendEpoch, server.Session.ReceiveEpoch);
    }
}

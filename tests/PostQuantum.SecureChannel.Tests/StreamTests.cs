using System.Net;
using System.Net.Sockets;
using System.Text;
using PostQuantum.SecureChannel.Transport;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class StreamTests
{
    private static async Task<(NetworkStream Client, NetworkStream Server)> ConnectedPairAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var clientConnect = new TcpClient();
        var acceptTask = listener.AcceptTcpClientAsync();
        await clientConnect.ConnectAsync(IPAddress.Loopback, port);
        var serverConn = await acceptTask;
        listener.Stop();

        return (clientConnect.GetStream(), serverConn.GetStream());
    }

    [Fact]
    public async Task SecureChannelStream_RoundTripsOverTcp()
    {
        var (clientNet, serverNet) = await ConnectedPairAsync();
        using var serverIdentity = PqIdentity.Create();

        // Drive both handshakes concurrently.
        var clientTask = PqSecureChannel.ConnectAsync(
            clientNet, new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var serverTask = PqSecureChannel.AcceptAsync(
            serverNet, new PqServerOptions { Identity = serverIdentity });

        await Task.WhenAll(clientTask, serverTask);
        await using var client = await clientTask;
        await using var server = await serverTask;

        // Client authenticated the server.
        Assert.NotNull(client.Session.RemoteIdentity);
        Assert.Equal(serverIdentity.PublicKey.Fingerprint(), client.Session.RemoteIdentity!.Fingerprint());

        // Application data flows both directions.
        var hello = Encoding.UTF8.GetBytes("hello over tcp");
        await client.WriteAsync(hello);

        var buffer = new byte[hello.Length];
        await server.ReadExactlyAsync(buffer);
        Assert.Equal("hello over tcp", Encoding.UTF8.GetString(buffer));

        var reply = Encoding.UTF8.GetBytes("hi back");
        await server.WriteAsync(reply);
        var replyBuffer = new byte[reply.Length];
        await client.ReadExactlyAsync(replyBuffer);
        Assert.Equal("hi back", Encoding.UTF8.GetString(replyBuffer));
    }

    [Fact]
    public async Task ConnectAsync_TimesOutWhenServerSilent()
    {
        var (clientNet, serverNet) = await ConnectedPairAsync();
        using var serverIdentity = PqIdentity.Create();

        // No server handshake is driven, so the client blocks waiting for ServerHello until the timeout.
        await Assert.ThrowsAsync<TimeoutException>(() => PqSecureChannel.ConnectAsync(
            clientNet,
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey },
            handshakeTimeout: TimeSpan.FromMilliseconds(250)));

        serverNet.Dispose();
    }

    [Fact]
    public async Task WriteAsync_AboveFrameLimit_FailsLocallyWithoutPoisoningPeer()
    {
        var (clientNet, serverNet) = await ConnectedPairAsync();
        using var serverIdentity = PqIdentity.Create();

        const int smallFrame = 16384; // above the ~6.4 KB ServerHello handshake frame, below our test write
        var clientTask = PqSecureChannel.ConnectAsync(
            clientNet, new PqClientOptions { ServerIdentity = serverIdentity.PublicKey }, maxFrameSize: smallFrame);
        var serverTask = PqSecureChannel.AcceptAsync(
            serverNet, new PqServerOptions { Identity = serverIdentity }, maxFrameSize: smallFrame);
        await Task.WhenAll(clientTask, serverTask);
        await using var client = await clientTask;
        await using var server = await serverTask;

        // A write whose encrypted frame would exceed the peer's frame limit must fail on THIS side,
        // before anything is sent, rather than silently bricking the remote reader.
        var tooBig = new byte[smallFrame]; // + record overhead pushes the frame over the limit
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await client.WriteAsync(tooBig));

        // The channel is still healthy: a within-limit write round-trips normally.
        var ok = Encoding.UTF8.GetBytes("still fine");
        await client.WriteAsync(ok);
        var buffer = new byte[ok.Length];
        await server.ReadExactlyAsync(buffer);
        Assert.Equal("still fine", Encoding.UTF8.GetString(buffer));
    }

    [Fact]
    public async Task SecureChannelStream_HandlesKeyUpdateTransparently()
    {
        var (clientNet, serverNet) = await ConnectedPairAsync();
        using var serverIdentity = PqIdentity.Create();

        var clientTask = PqSecureChannel.ConnectAsync(
            clientNet, new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var serverTask = PqSecureChannel.AcceptAsync(
            serverNet, new PqServerOptions { Identity = serverIdentity });
        await Task.WhenAll(clientTask, serverTask);
        await using var client = await clientTask;
        await using var server = await serverTask;

        // Client ratchets, then sends data in the new epoch. The server's stream consumes the key-update
        // record transparently and returns only the application data.
        await client.UpdateSendKeyAsync();
        await client.WriteAsync(Encoding.UTF8.GetBytes("after rekey"));

        var buffer = new byte[11];
        await server.ReadExactlyAsync(buffer);
        Assert.Equal("after rekey", Encoding.UTF8.GetString(buffer));
        Assert.Equal(1u, client.Session.SendEpoch);
        Assert.Equal(1u, server.Session.ReceiveEpoch);
    }
}

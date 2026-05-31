// PostQuantum.SecureChannel — runnable echo demo.
//
// Spins up a TCP echo server and a client on loopback, establishes a post-quantum secure channel
// (X-Wing + ML-DSA), and exchanges a few lines over it — including a mid-session key update.
//
//   dotnet run --project samples/EchoDemo
//
// To God be the glory. — 1 Corinthians 10:31

using System.Net;
using System.Net.Sockets;
using System.Text;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.Transport;

// 1. The server has a long-term identity. Its public half is pinned by clients out of band.
using var serverIdentity = PqIdentity.Create();
var pinnedServerKey = serverIdentity.PublicKey.ToBase64();
Console.WriteLine($"Server identity fingerprint: {serverIdentity.PublicKey.ShortFingerprint()}");
Console.WriteLine();

// 2. Start a TCP listener on a free loopback port.
var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;

var serverTask = RunServerAsync(listener, serverIdentity);
await RunClientAsync(port, pinnedServerKey);
await serverTask;

listener.Stop();
Console.WriteLine();
Console.WriteLine("Done. To God be the glory.");

static async Task RunServerAsync(TcpListener listener, PqIdentity identity)
{
    using var tcp = await listener.AcceptTcpClientAsync();
    await using var channel = await PqSecureChannel.AcceptAsync(
        tcp.GetStream(),
        new PqServerOptions { Identity = identity },
        handshakeTimeout: TimeSpan.FromSeconds(10));

    Console.WriteLine("[server] secure channel established; echoing lines.");

    using var reader = new StreamReader(channel, Encoding.UTF8, false, 1024, leaveOpen: true);
    await using var writer = new StreamWriter(channel, Encoding.UTF8, 1024, leaveOpen: true) { AutoFlush = true };

    string? line;
    while ((line = await reader.ReadLineAsync()) is not null)
    {
        Console.WriteLine($"[server] received: {line}  (recv epoch {channel.Session.ReceiveEpoch})");
        await writer.WriteLineAsync($"ECHO: {line}");
    }
}

static async Task RunClientAsync(int port, string pinnedServerKey)
{
    using var tcp = new TcpClient();
    await tcp.ConnectAsync(IPAddress.Loopback, port);

    await using var channel = await PqSecureChannel.ConnectAsync(
        tcp.GetStream(),
        new PqClientOptions { ServerIdentity = PqIdentityPublicKey.FromBase64(pinnedServerKey) },
        handshakeTimeout: TimeSpan.FromSeconds(10));

    // The client has cryptographically authenticated the server.
    Console.WriteLine($"[client] connected; verified server {channel.Session.RemoteIdentity!.ShortFingerprint()}");

    using var reader = new StreamReader(channel, Encoding.UTF8, false, 1024, leaveOpen: true);
    await using var writer = new StreamWriter(channel, Encoding.UTF8, 1024, leaveOpen: true) { AutoFlush = true };

    foreach (var message in new[] { "hello", "post-quantum world", "rekey please" })
    {
        if (message == "rekey please")
        {
            await channel.UpdateSendKeyAsync();
            Console.WriteLine($"[client] issued key update; now on send epoch {channel.Session.SendEpoch}");
        }

        await writer.WriteLineAsync(message);
        var echoed = await reader.ReadLineAsync();
        Console.WriteLine($"[client] sent '{message}' -> got '{echoed}'");
    }
}

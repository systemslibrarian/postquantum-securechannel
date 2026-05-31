// WorkerControlPlane — a hosted service ("worker") that dials a control plane over TCP, establishes
// a PQ-secured channel, sends periodic heartbeats, and ratchets keys automatically. Both worker and
// control plane run in-process here for demonstration; in production they'd be separate hosts.
//
//   dotnet run --project samples/WorkerControlPlane
//
// To God be the glory. — 1 Corinthians 10:31

using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.Transport;

// Spin up an in-process "control plane" listener; production deployments would resolve the address
// from configuration and the long-term identity from a secret manager.
var controlPlaneIdentity = PqIdentity.Create();
var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddHostedService(_ => new WorkerService(port, controlPlaneIdentity.PublicKey));
        services.AddHostedService(_ => new ControlPlaneService(listener, controlPlaneIdentity));
    })
    .Build();

await host.RunAsync(new CancellationTokenSource(TimeSpan.FromSeconds(8)).Token);

controlPlaneIdentity.Dispose();
listener.Stop();
Console.WriteLine("done.");

internal sealed class WorkerService(int port, PqIdentityPublicKey pinned) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, stoppingToken);

        await using var channel = await PqSecureChannel.ConnectAsync(
            tcp.GetStream(),
            new PqClientOptions
            {
                ServerIdentity = pinned,
                SessionOptions = PqSessionOptions.Recommended, // auto-rekey for long-lived
            },
            handshakeTimeout: TimeSpan.FromSeconds(5),
            cancellationToken: stoppingToken);

        Console.WriteLine($"[worker] connected; control-plane fingerprint {channel.Session.RemoteIdentity!.ShortFingerprint()}");

        int beat = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var payload = Encoding.UTF8.GetBytes($"heartbeat #{beat++}");
            await channel.WriteAsync(payload, stoppingToken);

            var buffer = new byte[256];
            int read = await channel.ReadAsync(buffer, stoppingToken);
            Console.WriteLine($"[worker] control-plane replied: {Encoding.UTF8.GetString(buffer, 0, read)} (epoch send={channel.Session.SendEpoch}, recv={channel.Session.ReceiveEpoch})");

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }
}

internal sealed class ControlPlaneService(TcpListener listener, PqIdentity identity) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var conn = await listener.AcceptTcpClientAsync(stoppingToken);
        await using var channel = await PqSecureChannel.AcceptAsync(
            conn.GetStream(),
            new PqServerOptions { Identity = identity, SessionOptions = PqSessionOptions.Recommended },
            handshakeTimeout: TimeSpan.FromSeconds(5),
            cancellationToken: stoppingToken);

        Console.WriteLine("[control-plane] worker authenticated and connected.");

        var buffer = new byte[256];
        while (!stoppingToken.IsCancellationRequested)
        {
            int read = await channel.ReadAsync(buffer, stoppingToken);
            if (read == 0) break;
            var msg = Encoding.UTF8.GetString(buffer, 0, read);
            await channel.WriteAsync(Encoding.UTF8.GetBytes($"ack: {msg}"), stoppingToken);
        }
    }
}

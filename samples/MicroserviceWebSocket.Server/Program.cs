// MicroserviceWebSocket.Server — an ASP.NET Core service that exposes a PQ-secured WebSocket
// endpoint over the standard Kestrel pipeline. It loads its server identity from configuration and
// echoes each received message back to the caller.
//
//   dotnet run --project samples/MicroserviceWebSocket.Server
//
// To God be the glory. — 1 Corinthians 10:31

using System.Text;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.AspNetCore;
using PostQuantum.SecureChannel.AspNetCore.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// In production, store ServerIdentitySeedBase64 in a secret manager (Key Vault, AWS Secrets
// Manager, Kubernetes secret). For this demo we synthesise one if none is configured.
var section = builder.Configuration.GetSection("PqSecureChannel");
if (string.IsNullOrWhiteSpace(section["ServerIdentitySeedBase64"]))
{
    using var ephemeral = PqIdentity.Create();
    var seed = ephemeral.ExportPrivateSeed();
    section["ServerIdentitySeedBase64"] = Convert.ToBase64String(seed);
    Console.WriteLine($"[server] generated ephemeral identity for this run.");
    Console.WriteLine($"[server] pin this on the client: {ephemeral.PublicKey.ToBase64()}");
    Console.WriteLine($"[server] fingerprint: {ephemeral.PublicKey.ShortFingerprint()}");
}

builder.Services
    .AddPostQuantumSecureChannel()
    .AddServerIdentityFromConfiguration("PqSecureChannel");

var app = builder.Build();
app.UseWebSockets();
app.MapPqWebSocket("/pqsc/echo", async (channel, ctx) =>
{
    Console.WriteLine($"[server] handshake complete; peer identity: " +
                      (channel.Session.RemoteIdentity?.ShortFingerprint() ?? "(anonymous)"));

    var buffer = new byte[4096];
    while (!ctx.RequestAborted.IsCancellationRequested)
    {
        int read = await channel.ReadAsync(buffer, ctx.RequestAborted);
        if (read == 0) break;

        var msg = Encoding.UTF8.GetString(buffer, 0, read);
        Console.WriteLine($"[server] received: {msg}");
        await channel.WriteAsync(Encoding.UTF8.GetBytes($"ECHO: {msg}"), ctx.RequestAborted);
    }
});

app.MapGet("/", () => "MicroserviceWebSocket.Server: connect to /pqsc/echo over a WebSocket.");

app.Run();

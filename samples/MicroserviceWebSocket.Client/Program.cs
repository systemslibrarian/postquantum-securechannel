// MicroserviceWebSocket.Client — calls a sibling ASP.NET Core service over a PQ-secured WebSocket.
//
//   Usage: dotnet run --project samples/MicroserviceWebSocket.Client \
//                     -- "wss://localhost:5077/pqsc/echo" "<pinned base64 key>"
//
// The first argument is the WebSocket URL, the second is the server's pinned public key produced by
// MicroserviceWebSocket.Server on first run. In production both come from configuration.
//
// To God be the glory. — 1 Corinthians 10:31

using System.Net.WebSockets;
using System.Text;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.AspNetCore;

if (args.Length < 2)
{
    Console.WriteLine("Usage: MicroserviceWebSocket.Client <wsUrl> <pinnedServerKeyBase64>");
    return 1;
}

var url = new Uri(args[0]);
var pinned = PqIdentityPublicKey.FromBase64(args[1]);

using var ws = new ClientWebSocket();
await ws.ConnectAsync(url, CancellationToken.None);
Console.WriteLine($"[client] WebSocket connected to {url}.");

await using var channel = await ws.AcceptPqClientAsync(
    new PqClientOptions { ServerIdentity = pinned },
    handshakeTimeout: TimeSpan.FromSeconds(5));

Console.WriteLine($"[client] handshake complete; verified server {channel.Session.RemoteIdentity!.ShortFingerprint()}.");

foreach (var message in new[] { "hello", "second", "third" })
{
    await channel.WriteAsync(Encoding.UTF8.GetBytes(message));
    var buffer = new byte[256];
    int read = await channel.ReadAsync(buffer);
    Console.WriteLine($"[client] sent '{message}' → got '{Encoding.UTF8.GetString(buffer, 0, read)}'");
}

return 0;

# PostQuantum.SecureChannel.AspNetCore

ASP.NET Core integration for
[PostQuantum.SecureChannel](https://github.com/systemslibrarian/postquantum-securechannel). DI
registration, configuration binding for pinned identities, and a WebSocket adapter that turns any
incoming or outgoing WebSocket into a `PqSecureChannelStream`.

```bash
dotnet add package PostQuantum.SecureChannel.AspNetCore --version 1.0.1
```

## Server (Kestrel + WebSockets)

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddPostQuantumSecureChannel()                              // base options
    .AddServerIdentityFromConfiguration("PqSecureChannel");     // reads identity from IConfiguration

var app = builder.Build();
app.UseWebSockets();
app.MapPqWebSocket("/pqsc", async (channel, ctx) =>
{
    // channel is a PqSecureChannelStream; ctx is the HttpContext.
    var buffer = new byte[1024];
    int read = await channel.ReadAsync(buffer);
    await channel.WriteAsync(buffer.AsMemory(0, read));
});

app.Run();
```

```jsonc
// appsettings.json
{
  "PqSecureChannel": {
    "ServerIdentitySeedBase64": "…32 bytes base64…",
    "RequireClientAuthentication": false
  }
}
```

## Client (HttpClient + WebSockets)

```csharp
using var ws = new ClientWebSocket();
await ws.ConnectAsync(new Uri("wss://server/pqsc"), CancellationToken.None);

await using var channel = await ws.AcceptPqClientAsync(new PqClientOptions
{
    ServerIdentity = PqIdentityPublicKey.FromBase64(config["PqSecureChannel:PinnedServerKey"]!),
});

await channel.WriteAsync(Encoding.UTF8.GetBytes("hello server"));
```

## Identity loading

- **From IConfiguration**: bind `ServerIdentitySeedBase64` / `PinnedServerKeyBase64` from JSON,
  environment variables, Azure Key Vault, AWS Secrets Manager, or any provider you already use.
- **From a file**: `services.AddServerIdentityFromSeedFile(path)`.
- **From memory**: `services.AddServerIdentity(identity)`.

Mixing providers is fine — the last one wins, matching the standard .NET `IOptions<T>` semantics.

## What this package is *not*

- It is **not** application-layer encryption over arbitrary HTTP request/response. The WebSocket
  adapter is the supported path; full request-encrypting middleware needs careful design and is
  deferred. For most service-to-service traffic, WebSockets + a tiny RPC layer (gRPC, SignalR,
  hand-rolled JSON-over-frames) is enough.
- It is **not** a replacement for TLS at the edge. Run it inside TLS; it adds an authenticated,
  forward-secret, PQ-safe envelope around your application messages.

See the parent project's [`KNOWN-GAPS.md`](https://github.com/systemslibrarian/postquantum-securechannel/blob/main/KNOWN-GAPS.md)
for honest limitations of the underlying library.

---

**To God be the glory.** — *1 Corinthians 10:31*

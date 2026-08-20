# PostQuantum.SecureChannel.Testing

Test helpers for [PostQuantum.SecureChannel](https://github.com/systemslibrarian/postquantum-securechannel).
Drop into a test project to skip the boilerplate around real transports and identity generation.

```bash
dotnet add package PostQuantum.SecureChannel.Testing --version 1.0.2
```

## What's included

- **`PqInMemoryDuplex`** — a pair of in-memory `Stream`s connected to each other. No TCP, no
  sockets, no port allocation. Hand each end to `PqSecureChannel.ConnectAsync` /
  `AcceptAsync`.
- **`PqHandshakeHarness`** — one call returns a client-side and server-side `PqSession`
  ready to exchange records. Mutual auth, resumption, and custom `PqSessionOptions` are all
  supported via opt-in parameters.
- **`PqTestIdentities`** — generate, reuse, and reset deterministic-looking long-term
  identities across a fixture without leaking state between tests.

```csharp
using PostQuantum.SecureChannel.Testing;

// Three lines for a complete client/server session:
using var harness = PqHandshakeHarness.Create();
var ciphertext = harness.Client.Encrypt(Encoding.UTF8.GetBytes("hi"));
Assert.Equal("hi", Encoding.UTF8.GetString(harness.Server.Decrypt(ciphertext)));
```

```csharp
// Need a real Stream pair (e.g. for testing the stream adapter)?
var (clientStream, serverStream) = PqInMemoryDuplex.CreatePair();    // replaces TCP/sockets in tests
var clientTask = PqSecureChannel.ConnectAsync(clientStream, clientOptions);
var serverTask = PqSecureChannel.AcceptAsync(serverStream, serverOptions);
await Task.WhenAll(clientTask, serverTask);
```

## Not for production

These helpers are deliberately permissive (e.g. `PqInMemoryDuplex` does not enforce backpressure
the way a real socket does). They are intended for tests; do not use them in production code
paths.

---

**To God be the glory.** — *1 Corinthians 10:31*

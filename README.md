# PostQuantum.SecureChannel

**A clean, high-level post-quantum secure channel and session-encryption library for .NET.**

PostQuantum.SecureChannel lets two endpoints establish a mutually-verifiable, authenticated session
that stays secure against both today's adversaries and tomorrow's quantum computers — with an API
small enough to fit in your head.

It combines:

- **[X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) hybrid key agreement**
  — ML-KEM-768 (FIPS 203) *and* X25519, so the session key is safe as long as **either** primitive
  holds. You are protected even if one of them is later broken.
- **[ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) signatures** (FIPS 204, ML-DSA-65) — to
  authenticate the handshake and defeat man-in-the-middle attacks.
- **AES-256-GCM** — for fast, authenticated record encryption once the session is up.

```
   ┌────────────┐   ClientHello  (X-Wing public key)    ┌────────────┐
   │            │ ───────────────────────────────────▶ │            │
   │   Client   │   ServerHello  (ciphertext + ML-DSA)  │   Server   │
   │            │ ◀─────────────────────────────────── │            │
   │            │   ClientFinished (key confirmation)   │            │
   │            │ ───────────────────────────────────▶ │            │
   └────────────┘                                       └────────────┘
        │                                                     │
        └──────────  AES-256-GCM session records  ────────────┘
```

> ⚠️ **Preview release (0.2.0-preview.1).** The cryptographic core is validated against published
> IETF/NIST test vectors, but this library has **not** had an independent security audit. Please read
> [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before using it for anything that matters. The wire format changed
> in 0.2 and is **not** compatible with 0.1.x.

---

## Why post-quantum, and why hybrid?

A sufficiently large quantum computer running Shor's algorithm would break the classical key exchange
(ECDH/RSA) that protects most traffic today. The threat is **"harvest now, decrypt later"**: an
adversary can record your encrypted traffic today and decrypt it years later once such a machine
exists. Anything that needs to stay confidential into the 2030s+ needs post-quantum protection now.

**Hybrid** key agreement is the conservative path the IETF and NIST recommend during the transition:
combine a new lattice KEM with a battle-tested classical one. X-Wing does exactly this. If ML-KEM is
later found to have a flaw, X25519 still protects you; if a quantum computer breaks X25519, ML-KEM
still protects you. You only lose if **both** fall.

---

## Install

```bash
dotnet add package PostQuantum.SecureChannel --version 0.2.0-preview.1
```

Targets `net8.0`, `net9.0`, and `net10.0`.

### What's new in 0.2

- **Async stream adapter** — `PqSecureChannel.ConnectAsync` / `AcceptAsync` drive the handshake over
  any `Stream` and hand back a `PqSecureChannelStream` you can read and write like a normal stream.
- **In-band key update (rekey)** — `UpdateSendKey()` ratchets to fresh keys mid-session without a new
  handshake.
- **Configurable replay protection** — strict-ordered (default) or a DTLS-style sliding window for
  unordered transports.
- **Protocol version negotiation** — every handshake selects the highest mutually-supported version.
- **Experimental resumption** — bind a new session to a previous one via a shared resumption secret.

---

## Quick start (server-authenticated)

This is the common case — like TLS, the client verifies the server's pinned identity, and the channel
is confidential and integrity-protected in both directions.

```csharp
using PostQuantum.SecureChannel;
using System.Text;

// ── One-time setup: the server has a long-term identity. ───────────────────────
// Distribute serverIdentity.PublicKey.Export() to clients out of band and pin it.
using var serverIdentity = PqIdentity.Create();
byte[] pinnedServerKey = serverIdentity.PublicKey.Export();

// ── Handshake ──────────────────────────────────────────────────────────────────
// Client side:
var client = PqSecureChannel.CreateClient(new PqClientOptions
{
    ServerIdentity = PqIdentityPublicKey.Import(pinnedServerKey),
});
byte[] clientHello = client.CreateClientHello();          // send to server

// Server side:
var server = PqSecureChannel.CreateServer(new PqServerOptions
{
    Identity = serverIdentity,
});
byte[] serverHello = server.ProcessClientHello(clientHello); // send to client

// Client completes and authenticates the server:
PqClientHandshakeResult result = client.ProcessServerHello(serverHello);
PqSession clientSession = result.Session;
byte[] clientFinished = result.ClientFinished;             // send to server

// Server completes:
PqSession serverSession = server.ProcessClientFinished(clientFinished);

// ── Send data ────────────────────────────────────────────────────────────────
byte[] record = clientSession.Encrypt(Encoding.UTF8.GetBytes("hello, server"));
byte[] plain  = serverSession.Decrypt(record);
Console.WriteLine(Encoding.UTF8.GetString(plain)); // "hello, server"

// Replies work the same way:
byte[] reply = serverSession.Encrypt(Encoding.UTF8.GetBytes("hello, client"));
Console.WriteLine(Encoding.UTF8.GetString(clientSession.Decrypt(reply)));
```

The three handshake messages (`clientHello`, `serverHello`, `clientFinished`) are just `byte[]` — send
them over whatever transport you already have (TCP, a message queue, HTTP, gRPC metadata, …). The
library does no I/O.

### Pin and verify the server fingerprint

```csharp
// Distribute the key (e.g. in config) and print a fingerprint to compare out of band:
string pinned = serverIdentity.PublicKey.ToBase64();         // store this on the client
Console.WriteLine(serverIdentity.PublicKey.Fingerprint());   // full SHA-256, lowercase hex
Console.WriteLine(serverIdentity.PublicKey.ShortFingerprint()); // e.g. "9f:86:d0:81:88:4c:7d:65"

// On the client:
var options = new PqClientOptions { ServerIdentity = PqIdentityPublicKey.FromBase64(pinned) };
```

If a client ever sees a different fingerprint, the server's key has changed (or someone is in the
middle) — and the handshake will fail with `PqAuthenticationException`.

---

## Mutual authentication

Have the client present its own identity, and require it on the server:

```csharp
using var clientIdentity = PqIdentity.Create();

var client = PqSecureChannel.CreateClient(new PqClientOptions
{
    ServerIdentity = PqIdentityPublicKey.Import(pinnedServerKey),
    ClientIdentity = clientIdentity,            // ← client authenticates too
});

var server = PqSecureChannel.CreateServer(new PqServerOptions
{
    Identity = serverIdentity,
    RequireClientAuthentication = true,         // ← reject anonymous clients
    AuthorizedClients = [clientIdentity.PublicKey], // optional allowlist
});

// After the handshake, the server knows exactly who connected:
Console.WriteLine(serverSession.RemoteIdentity!.Fingerprint());
```

---

## Encrypting with associated data (AAD)

Bind a record to context that is authenticated but not encrypted — a message type, a route, a
connection id. The same value must be supplied on decrypt or the record is rejected.

```csharp
byte[] aad = Encoding.UTF8.GetBytes("channel:orders");
byte[] record = clientSession.Encrypt(payload, aad);
byte[] plain  = serverSession.Decrypt(record, aad);   // must match
```

---

## Streaming over a transport (TCP, etc.)

If you'd rather not move three handshake messages and frame records yourself, wrap any bidirectional
`Stream`. The adapter performs the handshake and then encrypts/decrypts transparently.

```csharp
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.Transport;

// Server side — over an accepted TcpClient's NetworkStream:
await using PqSecureChannelStream channel =
    await PqSecureChannel.AcceptAsync(networkStream, new PqServerOptions { Identity = serverIdentity });
await channel.WriteAsync(Encoding.UTF8.GetBytes("welcome"));

// Client side — over a connected TcpClient's NetworkStream:
await using PqSecureChannelStream channel = await PqSecureChannel.ConnectAsync(
    networkStream, new PqClientOptions { ServerIdentity = PqIdentityPublicKey.Import(pinnedServerKey) });
var buffer = new byte[7];
await channel.ReadExactlyAsync(buffer); // "welcome"
```

`PqSecureChannelStream` is a real `Stream`: hand it to a `StreamReader`, a serializer, or anything else
that speaks streams. Pass `handshakeTimeout:` to fail fast if a peer stalls during the handshake.

> 💡 **Try it:** `dotnet run --project samples/EchoDemo` runs a complete TCP client/server demo —
> handshake, server verification by fingerprint, echo, and a mid-session key update.

---

## Rekeying a long-lived session (key update)

For long-lived connections, ratchet to fresh keys periodically without re-handshaking. The peer
handles it transparently.

```csharp
// On a raw session:
byte[] keyUpdate = clientSession.UpdateSendKey();   // send these bytes to the peer
PqIncomingRecord r = serverSession.Open(keyUpdate); // r.ContentType == PqContentType.KeyUpdate

// On a stream:
await channel.UpdateSendKeyAsync();                 // peer's reads continue seamlessly
```

Each direction ratchets independently, and the old epoch's keys can no longer decrypt new traffic.

**Automatic rekeying.** Set a policy and the stream ratchets for you once a threshold is crossed:

```csharp
var options = new PqClientOptions
{
    ServerIdentity = PqIdentityPublicKey.FromBase64(pinnedServerKey),
    SessionOptions = new PqSessionOptions { KeyUpdatePolicy = PqKeyUpdatePolicy.Recommended },
    // or: new PqKeyUpdatePolicy { MaxRecordsBeforeUpdate = 1_000_000, MaxBytesBeforeUpdate = 1L << 30 }
};
// On a raw session, check it yourself:
if (session.NeedsKeyUpdate) { var ku = session.UpdateSendKey(); /* send ku */ }
```

---

## Unordered or lossy transports (sliding-window anti-replay)

The default is strict in-order delivery (ideal for TCP). For transports that may reorder or drop
records, switch the receive side to a DTLS-style sliding window:

```csharp
var options = new PqServerOptions
{
    Identity = serverIdentity,
    SessionOptions = new PqSessionOptions
    {
        ReplayProtection = PqReplayProtection.SlidingWindow,
        ReplayWindowSize = 64,
    },
};
```

In-window, not-yet-seen records are accepted in any order; replays and records older than the window
are rejected.

---

## Resumption (experimental)

Bind a new session to a previous one by caching its resumption secret on both ends. A full,
forward-secret X-Wing handshake still runs; the secret simply provides continuity. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md).

```csharp
byte[] psk = previousSession.ExportResumptionSecret();   // cache on both peers
// next time:
var client = new PqClientOptions { ServerIdentity = pinned, ResumptionSecret = psk };
var server = new PqServerOptions { Identity = serverIdentity, ResumptionSecret = psk };
```

---

## Security posture

**What this library guarantees when used as documented:**

| Property | How it is achieved |
| --- | --- |
| Post-quantum confidentiality | X-Wing (ML-KEM-768 + X25519) hybrid key agreement |
| Forward secrecy | A fresh ephemeral X-Wing key pair per handshake; private seeds are zeroed after use |
| Server authentication | ML-DSA-65 signature over the full handshake transcript, verified against a pinned key |
| Mutual authentication (optional) | Client ML-DSA-65 signature + optional allowlist |
| Key confirmation | HMAC-SHA256 `Finished` MAC proves both sides derived the same keys |
| Transcript integrity | Every signature/MAC covers a SHA-256 hash of all prior handshake bytes |
| Record confidentiality + integrity | AES-256-GCM with per-direction keys |
| Nonce-reuse safety | Per-direction 64-bit counters with HKDF-derived nonce prefixes — a nonce is never reused under a key |
| Replay / reordering protection | Strict in-order sequence checking (default), or a DTLS-style sliding window for unordered transports |
| Rekeying | In-band key update ratchets each direction to fresh keys without a new handshake |
| Strong key separation | HKDF-SHA256 with distinct, versioned domain-separation labels for every derived secret |
| Version negotiation | Each handshake selects the highest mutually-supported protocol version |

**Defaults are not configurable on purpose.** Algorithms and parameters (ML-KEM-768, ML-DSA-65,
AES-256-GCM, SHA-256/SHA3-256) are fixed so there are no insecure knobs to misconfigure. A protocol
version byte on every message leaves room to evolve safely.

**Please also read [`KNOWN-GAPS.md`](KNOWN-GAPS.md)** for an honest account of what this library does
*not* yet do, and [`SECURITY.md`](SECURITY.md) for how to report a vulnerability.

---

## How it works (one level deeper)

1. **Key agreement.** The client sends an ephemeral X-Wing public key. The server encapsulates to it,
   yielding a shared secret and a ciphertext. X-Wing's shared secret is
   `SHA3-256(ss_MLKEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)` — binding both primitives together.
2. **Authentication.** The server signs `SHA-256(ClientHello ‖ ServerHello-body)` with ML-DSA-65. The
   client verifies it against the pinned identity before trusting anything.
3. **Key schedule.** `HKDF-Extract(salt = clientRandom ‖ serverRandom, IKM = X-Wing secret)` →
   `HKDF-Expand` into a master secret bound to the transcript hash, then into directional AES-256-GCM
   keys, nonce prefixes, and `Finished` keys.
4. **Confirmation.** The client returns an HMAC `Finished` over the full transcript (and, for mutual
   auth, its own signature). The server verifies it before the session is considered live.
5. **Records.** Each `Encrypt` emits `version ‖ sequence ‖ ciphertext ‖ tag`; the sequence number
   feeds both the GCM nonce and a strict replay check.

The X-Wing combiner is validated **byte-for-byte against the IETF draft test vectors** (see
`tests/PostQuantum.SecureChannel.Tests/XWingTests.cs`).

---

## Project layout

```
src/PostQuantum.SecureChannel/     The library
  Cryptography/                    X-Wing KEM, ML-DSA signatures (validated primitives)
  Internal/                        Key schedule, wire format, transcript, anti-replay, protocol constants
  Transport/                       Async stream adapter + length-prefixed framing
  PqSecureChannel.cs               Handshake orchestration (client + server)
  PqSession.cs                     Established session: Encrypt / Decrypt / key update
  PqIdentity*.cs                   Long-term ML-DSA identities
tests/PostQuantum.SecureChannel.Tests/   KAT vectors, handshake, session, key update, anti-replay,
                                          resumption, version negotiation, stream, auto-rekey, and fuzz tests
samples/EchoDemo/                  Runnable TCP echo client/server demo
docs/protocol.md                   Wire-format and key-schedule specification
```

---

## Building and testing

```bash
dotnet build -c Release
dotnet test
```

---

## The PostQuantum.* family

PostQuantum.SecureChannel follows the same standards, transparency, and engineering discipline as the
other `PostQuantum.*` libraries: vetted primitives, secure-by-default APIs, validated test vectors,
and honest documentation of limitations.

---

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*Built with care, and an honest accounting of its limits.*

**To God be the glory.** — *1 Corinthians 10:31*

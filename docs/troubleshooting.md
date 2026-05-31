# Troubleshooting

Concrete failure modes you may hit, what they mean, and how to recover. Each entry maps to the
exception type or diagnostic counter you will see.

## Handshake-time failures

### `PqAuthenticationException: ServerHello identity does not match any pinned server identity`

**What happened.** The server presented an identity public key the client does not trust.

**Common causes.**
- Pinned key was rotated on the server but the client config still references the old key.
- A different deployment (staging vs. production) was reached due to DNS / load-balancer
  misconfiguration.
- An actual MitM (rare, but the protocol's whole point is to catch it).

**Diagnose.** Compare `serverIdentity.PublicKey.ShortFingerprint()` on the server's logs to the
`PqIdentityPublicKey.Import(pinnedBytes).ShortFingerprint()` you computed on the client.

**Fix.** Push the correct pinned key to the client. If you are in the middle of a rotation, set
`PqClientOptions.AllowedServerIdentities = [oldKey, newKey]` so both are accepted during overlap.

---

### `PqAuthenticationException: Server signature verification failed`

**What happened.** The server's ML-DSA signature over the transcript did not verify against the
key the client pinned.

**Common causes.**
- The server is using a different identity than the client expects (so the signed transcript
  doesn't match the pinned public key).
- The transcript was tampered with on the wire.
- Software version mismatch where one side computes a different transcript hash. (Should not
  happen at protocol version 1, but verify with `dotnet --version` and your package versions.)

**Fix.** Same as above for pin mismatch. If pins match, capture the handshake bytes (network
trace) and confirm both sides reach byte equality before the signature.

---

### `PqAuthenticationException: Client key confirmation (Finished MAC) failed`

**What happened.** The server's recomputed Finished MAC did not match the client's. This is a
strong signal that the two sides derived different key schedules.

**Common causes.**
- One side passed a `ResumptionSecret` and the other did not (or they differ).
- Library version mismatch across the wire (a 0.1.x peer talking to a 0.2.x peer — wire format
  changed).
- The two ends are not actually talking to each other (proxy / load-balancer fanning the
  handshake messages to different backends).

**Fix.** Verify both sides are on the same library major.minor and pass matching resumption
secrets (or both `null`). Confirm session stickiness if you have a load balancer in front.

---

### `PqProtocolException: No mutually supported protocol version was offered by the client`

**What happened.** The client only offered protocol versions the server doesn't speak.

**Fix.** Upgrade the older side. The library only ships version 1 today, so this means a peer
running outside the supported version range.

---

### `TimeoutException` from `ConnectAsync` / `AcceptAsync`

**What happened.** The peer didn't respond to a handshake message within `handshakeTimeout`.

**Common causes.**
- The peer crashed mid-handshake.
- The transport (TCP / WebSocket) is alive but the application above is stuck.
- A firewall is silently dropping a fragment.

**Fix.** Increase the timeout while investigating, but the root cause is on the peer or in the
transport — not in this library.

## Session-time failures

### `PqDecryptionException: Record sequence … rejected (replay, reorder, or outside the replay window)`

**What happened.** The receive side rejected the record's sequence number.

**Common causes.**
- Real replay (an attacker, or an unintentional re-delivery).
- You're running with `PqReplayProtection.StrictOrdered` over an unordered transport. Switch to
  `SlidingWindow` if the transport reorders or loses records.
- You bumped the receive epoch without the sender also updating; old-epoch records arrive after.

**Fix.** Choose the right `ReplayProtection` for your transport (`PqSessionOptions.Recommended` for
TCP, `PqSessionOptions.UnorderedTransport` for UDP-style). If you see real replays, alert.

---

### `PqDecryptionException: Record failed authentication; it may be corrupt or tampered`

**What happened.** AES-GCM rejected the tag.

**Common causes.**
- Truncation by a misbehaving transport (rare with TCP, common with custom proxies).
- The peer is using different keys (key-schedule divergence — see Finished MAC notes above).
- Real tampering.

**Fix.** Capture the framed bytes on the wire vs. what the application gives `Decrypt`. If they
differ, your transport is at fault. If they match, the keys diverged at handshake time.

---

### `PqEpochExhaustedException: Send sequence exhausted for this epoch`

**What happened.** The send direction hit the NIST safety cap of 2^32 records per epoch.

**Fix.** Call `PqSession.UpdateSendKey()` (or rely on `PqKeyUpdatePolicy.Recommended` / set
`SessionOptions = PqSessionOptions.Recommended`). The exception is intentional — never accepting
input above the cap is what guarantees AES-GCM security.

---

### `PqEpochExhaustedException: Send byte budget exhausted for this epoch`

**What happened.** The send direction hit the 2^36-byte (64 GiB) AES-GCM data bound.

**Fix.** Same as above: rekey, or pick a `PqKeyUpdatePolicy` that does it for you.

---

### `ArgumentOutOfRangeException: Plaintext exceeds the 1073741824-byte per-record limit`

**What happened.** You called `Encrypt` with a plaintext larger than 1 GiB.

**Fix.** Split the payload into multiple records. A single AES-GCM record this large is unusual
for streaming and you almost certainly want multiple smaller frames.

## Framing failures (stream adapter)

### `PqProtocolException: Incoming frame length … exceeds the limit of 16777216 bytes`

**What happened.** A peer declared a frame larger than the configured `maxFrameSize` (default 16 MiB).

**Fix.** Either the peer is misconfigured (sending oversized records) or you genuinely need
larger frames — raise `maxFrameSize` on `ConnectAsync` / `AcceptAsync` if so. Note that a hostile
peer could announce arbitrarily large lengths; keep the cap tight unless you know better.

---

### `EndOfStreamException` from `ReadFrameAsync` (often surfaced as `IOException`)

**What happened.** The peer closed the connection mid-frame.

**Fix.** Handle as normal disconnect. If unexpected, investigate the peer's logs.

## Diagnostic walkthrough

When you don't know what's wrong, in order:

1. **Look at `pqsc.handshakes.failed`** in `dotnet-counters`. The tag `reason` names the failure
   class. If it's zero, the handshake is fine and the problem is at the session layer.
2. **Look at `pqsc.records.rejected`**. Sustained non-zero means session-time tampering, replay,
   or replay-mode misconfiguration.
3. **Run `dotnet-trace collect --providers PostQuantum.SecureChannel`** and inspect the
   handshake activity spans for stage timings. A handshake that times out at "ServerHello sign"
   versus "X-Wing decapsulate" tells you very different things.

---

**To God be the glory.** — *1 Corinthians 10:31*

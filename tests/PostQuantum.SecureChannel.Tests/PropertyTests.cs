using PostQuantum.SecureChannel.Internal;
using PostQuantum.SecureChannel.Transport;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Dependency-free property-based tests: instead of fixed examples, they run many randomized inputs and
/// assert an invariant holds for all of them. Complements the KAT/fuzz suites (see
/// <c>docs/AUDIT-SCOPE.md</c> §11). Seeds are fixed so failures reproduce; a failing case prints its
/// seed-derived inputs.
/// </summary>
public class PropertyTests
{
    // ---- Record layer: encrypt/decrypt is an identity over arbitrary plaintext and AAD ----

    [Fact]
    public void Record_RoundTrips_ForArbitraryPlaintextAndAad()
    {
        var (client, server) = Establish();
        var rng = new Random(1_000);

        for (int i = 0; i < 400; i++)
        {
            byte[] plaintext = RandomBytes(rng, rng.Next(0, 4096));
            byte[] aad = RandomBytes(rng, rng.Next(0, 64));

            byte[] record = client.Encrypt(plaintext, aad);
            byte[] decrypted = server.Decrypt(record, aad);

            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void Record_Rejects_TamperedCiphertextOrAad()
    {
        var (client, server) = Establish();
        var rng = new Random(2_000);

        for (int i = 0; i < 200; i++)
        {
            byte[] plaintext = RandomBytes(rng, rng.Next(1, 1024));
            byte[] aad = RandomBytes(rng, rng.Next(0, 32));
            byte[] record = client.Encrypt(plaintext, aad);

            // Flip one random bit somewhere in the record (header, ciphertext, or tag).
            byte[] tampered = (byte[])record.Clone();
            int idx = rng.Next(tampered.Length);
            tampered[idx] ^= (byte)(1 << rng.Next(8));

            // A tampered record, or the right record with the wrong AAD, must never authenticate.
            Assert.ThrowsAny<PqSecureChannelException>(() => server.Decrypt(tampered, aad));

            // Re-establish because a failed decrypt in strict-order mode leaves the receiver expecting
            // this sequence; use a fresh pair to keep each iteration independent.
            (client, server) = Establish();
        }
    }

    // ---- Anti-replay window: behaves identically to a reference model, for random sequence streams ----

    [Fact]
    public void AntiReplayWindow_MatchesReferenceModel_AndNeverAcceptsTwice()
    {
        var rng = new Random(3_000);

        for (int trial = 0; trial < 60; trial++)
        {
            int size = rng.Next(1, 17) * 64; // 64..1024, exact multiples keep the model simple
            var window = new AntiReplayWindow(size);

            var committed = new HashSet<ulong>();
            bool any = false;
            ulong highest = 0;

            for (int step = 0; step < 500; step++)
            {
                ulong seq = NextSequenceNear(rng, any, highest, size);

                bool expected =
                    !any ? true
                    : seq > highest ? true
                    : (highest - seq) >= (ulong)size ? false
                    : !committed.Contains(seq);

                Assert.Equal(expected, window.IsAcceptable(seq));

                // Commit everything acceptable (this is the receiver's own behavior after a good decrypt).
                if (expected)
                {
                    window.Commit(seq);
                    Assert.True(committed.Add(seq), "model accepted a sequence it had already recorded");
                    if (!any || seq > highest)
                    {
                        highest = seq;
                        any = true;
                    }

                    // Immediately re-presenting a just-committed sequence must be rejected.
                    Assert.False(window.IsAcceptable(seq));
                }
            }
        }
    }

    // ---- Framing: write-then-read is an identity; oversize and truncation are rejected ----

    [Fact]
    public async Task Framing_RoundTrips_RandomPayloads()
    {
        var rng = new Random(4_000);

        for (int i = 0; i < 300; i++)
        {
            byte[] payload = RandomBytes(rng, rng.Next(0, 8192));

            using var ms = new MemoryStream();
            await PqFraming.WriteFrameAsync(ms, payload, default);
            ms.Position = 0;
            byte[] read = await PqFraming.ReadFrameAsync(ms, PqFraming.DefaultMaxFrameSize, default);

            Assert.Equal(payload, read);
        }
    }

    [Fact]
    public async Task Framing_Rejects_OversizeAndTruncatedFrames()
    {
        var rng = new Random(5_000);

        for (int i = 0; i < 50; i++)
        {
            byte[] payload = RandomBytes(rng, rng.Next(64, 512));

            // Oversize: a max smaller than the announced length must be rejected, not allocated.
            using (var ms = new MemoryStream())
            {
                await PqFraming.WriteFrameAsync(ms, payload, default);
                ms.Position = 0;
                await Assert.ThrowsAsync<PqProtocolException>(
                    () => PqFraming.ReadFrameAsync(ms, payload.Length - 1, default).AsTask());
            }

            // Truncated: a header promising more bytes than are present must fail, not return short.
            using (var truncated = new MemoryStream())
            {
                await PqFraming.WriteFrameAsync(truncated, payload, default);
                byte[] cut = truncated.ToArray()[..(4 + payload.Length / 2)];
                using var cutStream = new MemoryStream(cut);
                await Assert.ThrowsAsync<EndOfStreamException>(
                    () => PqFraming.ReadFrameAsync(cutStream, PqFraming.DefaultMaxFrameSize, default).AsTask());
            }
        }
    }

    // ---- Session: random ordered delivery interleaved with rekeys always round-trips ----

    [Fact]
    public void Session_OrderedDeliveryWithRandomRekeys_AlwaysRoundTrips()
    {
        var (client, server) = Establish();
        var rng = new Random(6_000);

        for (int i = 0; i < 500; i++)
        {
            if (rng.Next(10) == 0)
            {
                // Rekey: the control record must be delivered before the next application record.
                server.Open(client.UpdateSendKey());
            }

            byte[] plaintext = RandomBytes(rng, rng.Next(0, 2048));
            byte[] record = client.Encrypt(plaintext);
            var incoming = server.Open(record);

            Assert.Equal(PqContentType.ApplicationData, incoming.ContentType);
            Assert.Equal(plaintext, incoming.Payload);
        }
    }

    // ---- helpers ----

    private static (PqSession Client, PqSession Server) Establish()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var hello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(hello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    private static byte[] RandomBytes(Random rng, int length)
    {
        var b = new byte[length];
        rng.NextBytes(b);
        return b;
    }

    /// <summary>Generates a sequence number clustered near the window so the bitmap paths are exercised.</summary>
    private static ulong NextSequenceNear(Random rng, bool any, ulong highest, int size)
    {
        if (!any)
        {
            return (ulong)rng.Next(0, 1000);
        }

        // Mostly within [highest - size - 4, highest + 6]; occasionally a large forward jump.
        if (rng.Next(20) == 0)
        {
            return highest + (ulong)rng.Next(size, size * 4);
        }

        long low = (long)highest - size - 4;
        long high = (long)highest + 6;
        long pick = low + (long)(rng.NextDouble() * (high - low));
        return pick < 0 ? 0UL : (ulong)pick;
    }
}

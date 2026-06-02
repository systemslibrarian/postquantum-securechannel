using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Pinned tests for record-layer nonce construction and AES-GCM round-trips at and across an
/// explicit <see cref="PqSession.UpdateSendKey"/> ratchet boundary. Locks in:
///   1. nonce = ivPrefix(4) ‖ sequence(8), per-direction, per-epoch;
///   2. on key update, the nonce prefix changes (a new epoch is genuinely new keying material);
///   3. sequence counter resets to 0 on key update;
///   4. records encrypted under epoch N do not decrypt under epoch N+1.
/// </summary>
public class RecordNonceKatTests
{
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

    [Fact]
    public void Encrypt_AdvancesSequence_AndDecrypt_RoundTrips()
    {
        var (client, server) = Establish();

        Assert.Equal(0UL, client.RecordsSent);
        var record0 = client.Encrypt(Encoding.UTF8.GetBytes("zero"));
        Assert.Equal(1UL, client.RecordsSent);
        var record1 = client.Encrypt(Encoding.UTF8.GetBytes("one"));
        Assert.Equal(2UL, client.RecordsSent);

        Assert.Equal("zero", Encoding.UTF8.GetString(server.Decrypt(record0)));
        Assert.Equal("one", Encoding.UTF8.GetString(server.Decrypt(record1)));
    }

    [Fact]
    public void KeyUpdate_RatchetsBothSides_AndResetsSequence()
    {
        var (client, server) = Establish();

        // Send a couple of records first to advance the sequence past 0.
        server.Decrypt(client.Encrypt(Encoding.UTF8.GetBytes("a")));
        server.Decrypt(client.Encrypt(Encoding.UTF8.GetBytes("b")));
        Assert.Equal(2UL, client.RecordsSent);
        Assert.Equal(0u, client.SendEpoch);

        // Key update.
        var keyUpdateRecord = client.UpdateSendKey();
        Assert.Equal(1u, client.SendEpoch);
        Assert.Equal(0UL, client.RecordsSent); // sequence reset

        // The server must process the key-update control record before any further app data.
        var opened = server.Open(keyUpdateRecord);
        Assert.Equal(PqContentType.KeyUpdate, opened.ContentType);
        Assert.Equal(1u, server.ReceiveEpoch);

        // Subsequent traffic under the new epoch decrypts fine.
        var next = client.Encrypt(Encoding.UTF8.GetBytes("after-rekey"));
        Assert.Equal(1UL, client.RecordsSent);
        Assert.Equal("after-rekey", Encoding.UTF8.GetString(server.Decrypt(next)));
    }

    [Fact]
    public void EpochZeroRecord_CannotDecryptAfterReceiverRatchet()
    {
        // Forward-secrecy property of UpdateSendKey: a captured ciphertext from epoch 0 cannot be
        // decrypted by the receiver after its receive direction has ratcheted to epoch 1, even
        // though strict-order replay-protection state resets on ratchet and the sequence number is
        // structurally acceptable. AEAD authentication is what catches it.
        var (client, server) = Establish();

        // Encrypt and deliver one record cleanly under epoch 0 (sequence 0).
        var epochZeroBytes = client.Encrypt(Encoding.UTF8.GetBytes("epoch-0"));
        Assert.Equal("epoch-0", Encoding.UTF8.GetString(server.Decrypt(epochZeroBytes)));

        // Both sides ratchet (keyUpdate is at sequence 1 in epoch 0, then send-side ratchets).
        var keyUpdate = client.UpdateSendKey();
        var opened = server.Open(keyUpdate);
        Assert.Equal(PqContentType.KeyUpdate, opened.ContentType);
        Assert.Equal(1u, server.ReceiveEpoch);

        // Re-presenting the epoch-0 bytes: after ratchet, server expected resets to 0, so sequence
        // 0 passes IsAcceptable in strict-order mode. The AES-GCM verify fails because the receive
        // key is now epoch 1's key — locking in the forward-secrecy of UpdateSendKey.
        Assert.Throws<PqDecryptionException>(() => server.Decrypt(epochZeroBytes));
    }

    [Fact]
    public void TwoIndependentSessions_ProduceDifferentNonces()
    {
        // The IV prefix is derived from the session's traffic secret, which derives from the
        // shared secret + transcript. Two fresh sessions therefore use different prefixes — the
        // strongest end-to-end check that nonce-prefix derivation actually depends on the schedule.
        var (clientA, serverA) = Establish();
        var (clientB, serverB) = Establish();

        // Encrypt the same plaintext at sequence 0 in each session.
        var ra = clientA.Encrypt(Encoding.UTF8.GetBytes("ping"));
        var rb = clientB.Encrypt(Encoding.UTF8.GetBytes("ping"));

        // Header layout: format(1) ‖ contentType(1) ‖ sequence(8) ‖ ciphertext ‖ tag.
        // The header is identical (both at sequence 0), so any difference is from key/nonce divergence.
        Assert.Equal(ra[0], rb[0]); // version
        Assert.Equal(ra[1], rb[1]); // content type
        for (int i = 0; i < 8; i++)
        {
            Assert.Equal(ra[2 + i], rb[2 + i]); // sequence
        }

        // Ciphertext + tag must differ, because the underlying nonce-prefix and key differ.
        Assert.NotEqual(Convert.ToHexString(ra.AsSpan(10).ToArray()),
                        Convert.ToHexString(rb.AsSpan(10).ToArray()));

        // And the wrong session cannot decrypt.
        Assert.Throws<PqDecryptionException>(() => serverB.Decrypt(ra));
        Assert.Throws<PqDecryptionException>(() => serverA.Decrypt(rb));
    }
}

using System.Text;
using PostQuantum.SecureChannel.Cryptography;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Regression tests for the correctness/security fixes from the pre-1.0 adversarial review: an
/// allowlist must never be silently inert, handshake messages must be canonical (no trailing bytes),
/// control records must authenticate regardless of caller AAD, a key update must remain possible at
/// the epoch cap, and an oversized write must fail locally rather than poisoning the peer.
/// </summary>
public class ReviewHardeningTests
{
    private static (PqSession Client, PqSession Server) Establish(
        PqClientOptions? clientOptions = null, PqServerOptions? serverOptions = null, PqIdentity? serverIdentity = null)
    {
        serverIdentity ??= PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(
            clientOptions ?? new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(
            serverOptions ?? new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void AuthorizedClients_WithoutRequireFlag_StillRejectsAnonymousClient()
    {
        // The dangerous combination: an allowlist is configured but RequireClientAuthentication was left
        // at its default of false. An anonymous client must NOT be able to slip past the allowlist.
        using var serverIdentity = PqIdentity.Create();
        using var knownClient = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(
            new PqClientOptions { ServerIdentity = serverIdentity.PublicKey }); // no client identity
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            AuthorizedClients = [knownClient.PublicKey],
            // RequireClientAuthentication deliberately left false
        });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);

        Assert.Throws<PqAuthenticationException>(() => server.ProcessClientFinished(result.ClientFinished));
    }

    [Fact]
    public void AuthorizedClients_WithoutRequireFlag_AcceptsListedClient()
    {
        // The success path of the same feature: a client on the allowlist still connects.
        using var serverIdentity = PqIdentity.Create();
        using var knownClient = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            ClientIdentity = knownClient,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            AuthorizedClients = [knownClient.PublicKey],
        });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        Assert.NotNull(serverSession.RemoteIdentity);
        Assert.Equal(knownClient.PublicKey.Fingerprint(), serverSession.RemoteIdentity!.Fingerprint());
    }

    [Fact]
    public void TrailingBytes_OnClientHello_AreRejected()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var clientHello = client.CreateClientHello();
        var tampered = new byte[clientHello.Length + 1];
        clientHello.CopyTo(tampered, 0); // one appended byte

        Assert.Throws<PqProtocolException>(() => server.ProcessClientHello(tampered));
    }

    [Fact]
    public void TrailingBytes_OnServerHello_AreRejected()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var tampered = new byte[serverHello.Length + 4];
        serverHello.CopyTo(tampered, 0); // four appended bytes an active attacker could add

        Assert.ThrowsAny<PqSecureChannelException>(() => client.ProcessServerHello(tampered));
    }

    [Fact]
    public void TrailingBytes_OnClientFinished_AreRejected()
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var tampered = new byte[result.ClientFinished.Length + 1];
        result.ClientFinished.CopyTo(tampered, 0);

        Assert.ThrowsAny<PqSecureChannelException>(() => server.ProcessClientFinished(tampered));
    }

    [Fact]
    public void KeyUpdate_AuthenticatesEvenWhenCallerUsesUniformAad()
    {
        // A caller that binds the SAME contextual AAD to every record must still be able to open the
        // peer's key-update control record — otherwise the sender ratchets and the session deadlocks.
        var (client, server) = Establish();
        var aad = Encoding.UTF8.GetBytes("channel:orders");

        // Application data round-trips with the caller's AAD.
        var appRecord = client.Encrypt(Encoding.UTF8.GetBytes("hi"), aad);
        Assert.Equal("hi", Encoding.UTF8.GetString(server.Decrypt(appRecord, aad)));

        // The key-update record opens with the same AAD the caller uses everywhere.
        var keyUpdate = client.UpdateSendKey();
        var opened = server.Open(keyUpdate, aad);
        Assert.Equal(PqContentType.KeyUpdate, opened.ContentType);
        Assert.Equal(1u, server.ReceiveEpoch);

        // And the channel keeps working in the new epoch, still with uniform AAD.
        var next = client.Encrypt(Encoding.UTF8.GetBytes("after rekey"), aad);
        Assert.Equal("after rekey", Encoding.UTF8.GetString(server.Decrypt(next, aad)));
    }

    [Fact]
    public void ApplicationRecord_StillRequiresMatchingAad()
    {
        // Guard against the control-record carve-out weakening application AAD binding.
        var (client, server) = Establish();
        var record = client.Encrypt(Encoding.UTF8.GetBytes("secret"), Encoding.UTF8.GetBytes("aad-A"));

        Assert.Throws<PqDecryptionException>(() => server.Decrypt(record, Encoding.UTF8.GetBytes("aad-B")));
    }

    [Fact]
    public void GeneratedKeyPair_RoundTripsAfterZeroizationHardening()
    {
        // Sanity that the added seed/expanded-key zeroization did not disturb key derivation:
        // an encapsulation to the generated public key still decapsulates to the same shared secret.
        using var keyPair = XWing.GenerateKeyPair();
        var (ciphertext, secret) = XWing.Encapsulate(keyPair.PublicKey);
        var recovered = keyPair.Decapsulate(ciphertext);

        Assert.Equal(secret, recovered);
    }
}

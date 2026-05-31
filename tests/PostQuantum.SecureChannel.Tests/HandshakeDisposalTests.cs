using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Aborted handshakes leak ephemeral key material until the GC reclaims them. Verifying that
/// <see cref="PqClientHandshake"/> and <see cref="PqServerHandshake"/> implement <see cref="IDisposable"/>
/// and zero their key material on dispose protects against partial-handshake memory exposure.
/// </summary>
public class HandshakeDisposalTests
{
    [Fact]
    public void ClientHandshake_CanBeDisposedBeforeHello()
    {
        using var serverIdentity = PqIdentity.Create();
        using var handshake = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
        });
        // No exception, no leaked ephemeral key.
    }

    [Fact]
    public void ClientHandshake_DisposingAfterHello_PreventsReuse()
    {
        using var serverIdentity = PqIdentity.Create();
        var handshake = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
        });

        _ = handshake.CreateClientHello();
        handshake.Dispose();

        Assert.Throws<ObjectDisposedException>(() => handshake.CreateClientHello());
        Assert.Throws<ObjectDisposedException>(() => handshake.ProcessServerHello(new byte[64]));
    }

    [Fact]
    public void ServerHandshake_CanBeDisposedBeforeClientHello()
    {
        using var serverIdentity = PqIdentity.Create();
        using var handshake = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
        });
    }

    [Fact]
    public void ServerHandshake_DisposingMidFlight_PreventsCompletion()
    {
        using var serverIdentity = PqIdentity.Create();
        using var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });

        var clientHello = client.CreateClientHello();
        var serverHello = server.ProcessClientHello(clientHello);

        // Server gives up before the client gets a chance to finish.
        server.Dispose();

        // The client finishes its half; the server-side handshake is no longer usable.
        var result = client.ProcessServerHello(serverHello);
        Assert.Throws<ObjectDisposedException>(() => server.ProcessClientFinished(result.ClientFinished));
    }

    [Fact]
    public void DoubleDispose_IsSafe()
    {
        using var serverIdentity = PqIdentity.Create();
        var handshake = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
        });
        handshake.Dispose();
        handshake.Dispose(); // idempotent
    }
}

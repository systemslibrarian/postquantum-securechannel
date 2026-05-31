namespace PostQuantum.SecureChannel.Testing;

/// <summary>
/// Drives a full PQ handshake in one call and exposes both sides as ready-to-use
/// <see cref="PqSession"/> instances. Lets tests focus on the behavior under test (record encryption,
/// key updates, policy thresholds) without re-implementing handshake plumbing in every fixture.
/// </summary>
public sealed class PqHandshakeHarness : IDisposable
{
    private readonly PqIdentity _serverIdentity;
    private readonly PqIdentity? _clientIdentity;

    private PqHandshakeHarness(PqIdentity serverIdentity, PqIdentity? clientIdentity, PqSession client, PqSession server)
    {
        _serverIdentity = serverIdentity;
        _clientIdentity = clientIdentity;
        Client = client;
        Server = server;
    }

    /// <summary>The client-side session ready to <see cref="PqSession.Encrypt"/> / <see cref="PqSession.Decrypt"/>.</summary>
    public PqSession Client { get; }

    /// <summary>The server-side session.</summary>
    public PqSession Server { get; }

    /// <summary>The server's long-term identity used in this fixture.</summary>
    public PqIdentity ServerIdentity => _serverIdentity;

    /// <summary>The client's long-term identity, if mutual authentication was requested.</summary>
    public PqIdentity? ClientIdentity => _clientIdentity;

    /// <summary>Creates a fresh harness with optional client identity, presets, and resumption secret.</summary>
    public static PqHandshakeHarness Create(
        bool mutual = false,
        PqSessionOptions? sessionOptions = null,
        byte[]? resumptionSecret = null)
    {
        var serverIdentity = PqIdentity.Create();
        var clientIdentity = mutual ? PqIdentity.Create() : null;

        var clientOptions = new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            ClientIdentity = clientIdentity,
            ResumptionSecret = resumptionSecret,
            SessionOptions = sessionOptions ?? PqSessionOptions.Default,
        };
        var serverOptions = new PqServerOptions
        {
            Identity = serverIdentity,
            RequireClientAuthentication = mutual,
            ResumptionSecret = resumptionSecret,
            SessionOptions = sessionOptions ?? PqSessionOptions.Default,
        };

        using var client = PqSecureChannel.CreateClient(clientOptions);
        using var server = PqSecureChannel.CreateServer(serverOptions);

        var clientHello = client.CreateClientHello();
        var serverHello = server.ProcessClientHello(clientHello);
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        return new PqHandshakeHarness(serverIdentity, clientIdentity, result.Session, serverSession);
    }

    /// <summary>Disposes both sessions and the long-term identities created by the harness.</summary>
    public void Dispose()
    {
        Client.Dispose();
        Server.Dispose();
        _serverIdentity.Dispose();
        _clientIdentity?.Dispose();
    }
}

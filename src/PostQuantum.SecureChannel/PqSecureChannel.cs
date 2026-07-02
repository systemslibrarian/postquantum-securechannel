using System.Security.Cryptography;
using PostQuantum.SecureChannel.Cryptography;
using PostQuantum.SecureChannel.Internal;

namespace PostQuantum.SecureChannel;

/// <summary>
/// Entry point for establishing a post-quantum secure channel. Create a client or server handshake,
/// exchange the three handshake messages over any transport, and receive a ready-to-use
/// <see cref="PqSession"/> on each side.
/// </summary>
/// <remarks>
/// The handshake is a single round trip plus a confirmation:
/// <list type="number">
///   <item><description>Client &#8594; <c>ClientHello</c> (<see cref="PqClientHandshake.CreateClientHello"/>)</description></item>
///   <item><description>Server &#8594; <c>ServerHello</c> (<see cref="PqServerHandshake.ProcessClientHello"/>)</description></item>
///   <item><description>Client &#8594; <c>ClientFinished</c> (<see cref="PqClientHandshake.ProcessServerHello"/>)</description></item>
/// </list>
/// For a transport-driven, async alternative see <see cref="Transport.PqSecureChannelStream"/>.
/// </remarks>
public static partial class PqSecureChannel
{
    /// <summary>
    /// The library version this build was produced from. Useful for diagnostics, logs, and bug
    /// reports.
    /// </summary>
    public static string LibraryVersion { get; } =
        typeof(PqSecureChannel).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    /// <summary>Begins a client-side handshake.</summary>
    public static PqClientHandshake CreateClient(PqClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.ServerIdentity is null && (options.AllowedServerIdentities is null || options.AllowedServerIdentities.Count == 0))
        {
            throw new ArgumentException(
                $"At least one pinned server identity must be supplied via {nameof(PqClientOptions.ServerIdentity)} or {nameof(PqClientOptions.AllowedServerIdentities)}.",
                nameof(options));
        }

        options.SessionOptions.Validate();
        return new PqClientHandshake(options);
    }

    /// <summary>Begins a server-side handshake.</summary>
    public static PqServerHandshake CreateServer(PqServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Identity);
        options.SessionOptions.Validate();
        return new PqServerHandshake(options);
    }
}

/// <summary>
/// The client side of a handshake. Single-use and not thread-safe: call
/// <see cref="CreateClientHello"/> then <see cref="ProcessServerHello"/>, in order. Dispose to zero
/// the ephemeral private key even when the handshake is abandoned mid-flight.
/// </summary>
public sealed class PqClientHandshake : IDisposable
{
    private readonly PqClientOptions _options;
    private XWingKeyPair? _keyPair;
    private byte[]? _clientRandom;
    private byte[]? _clientHelloBytes;
    private System.Diagnostics.Activity? _activity;
    private bool _completed;
    private bool _disposed;

    internal PqClientHandshake(PqClientOptions options) => _options = options;

    /// <summary>Produces the <c>ClientHello</c> bytes to send to the server.</summary>
    public byte[] CreateClientHello()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_clientHelloBytes is not null)
        {
            throw new InvalidOperationException("ClientHello has already been created.");
        }

        _activity = PqDiagnostics.StartHandshakeActivity(PqRole.Client);
        PqDiagnostics.HandshakeStarted(PqRole.Client);
        _keyPair = XWing.GenerateKeyPair();
        _clientRandom = RandomBytes.Create(PqProtocol.RandomSize);

        var hello = new ClientHello
        {
            SupportedVersions = PqProtocol.SupportedVersions,
            ClientRandom = _clientRandom,
            KemPublicKey = _keyPair.PublicKey,
        };
        _clientHelloBytes = hello.Serialize();
        return _clientHelloBytes;
    }

    /// <summary>
    /// Verifies the server's <c>ServerHello</c>, completes key agreement, and returns the established
    /// session together with the <c>ClientFinished</c> bytes to send back to the server.
    /// </summary>
    public PqClientHandshakeResult ProcessServerHello(ReadOnlySpan<byte> serverHello)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_keyPair is null || _clientRandom is null || _clientHelloBytes is null)
        {
            throw new InvalidOperationException("Call CreateClientHello before ProcessServerHello.");
        }

        if (_completed)
        {
            throw new InvalidOperationException("This handshake has already completed.");
        }

        ServerHello sh;
        try
        {
            sh = ServerHello.Parse(serverHello);
        }
        catch (PqSecureChannelException ex)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Client, "server-hello-malformed");
            throw new PqProtocolException("Malformed ServerHello.", ex);
        }

        // Declared outside the try so the finally can zero/dispose them even if any step below throws
        // (e.g. signing, serialization, or session construction) — otherwise the shared secret and the
        // key-schedule secrets would linger un-zeroed on the exception path.
        byte[]? sharedSecret = null;
        KeySchedule? schedule = null;
        try
        {
            // The server must have chosen a version we offered and still support.
            if (Array.IndexOf(PqProtocol.SupportedVersions, sh.NegotiatedVersion) < 0)
            {
                PqDiagnostics.HandshakeFailed(PqRole.Client, "version-mismatch");
                throw new PqProtocolException(
                    $"Server negotiated unsupported protocol version {sh.NegotiatedVersion}.");
            }

            var serverHelloBody = sh.SerializeBody();
            var h1 = Transcript.Hash(_clientHelloBytes, serverHelloBody);

            var pinned = ResolveServerIdentity(sh);
            if (!pinned.Verify(Transcript.SignedPayload(PqProtocol.ServerAuthContext, h1), sh.Signature))
            {
                PqDiagnostics.HandshakeFailed(PqRole.Client, "server-signature-invalid");
                throw new PqAuthenticationException("Server signature verification failed.");
            }

            // Recover the shared secret and derive the session keys (mixing the resumption secret if present).
            sharedSecret = _keyPair.Decapsulate(sh.KemCiphertext);
            schedule = KeySchedule.Derive(
                sharedSecret, _clientRandom, sh.ServerRandom, h1, _options.ResumptionSecret);

            var h2 = Transcript.Hash(_clientHelloBytes, sh.Serialize());
            var finishedMac = Transcript.FinishedMac(schedule.ClientFinishedKey, h2);

            // Optional client authentication.
            byte[] clientIdentityBytes = [];
            byte[] clientSignature = [];
            bool mutual = false;
            if (_options.ClientIdentity is { } clientIdentity)
            {
                clientIdentityBytes = clientIdentity.PublicKey.Export();
                clientSignature = clientIdentity.Sign(Transcript.SignedPayload(PqProtocol.ClientAuthContext, h2));
                mutual = true;
            }

            var finished = new ClientFinished
            {
                ClientIdentityPublicKey = clientIdentityBytes,
                ClientSignature = clientSignature,
                FinishedMac = finishedMac,
            };

            _keyPair.Dispose();
            _keyPair = null;
            _completed = true;

            var session = new PqSession(PqRole.Client, schedule, pinned, _options.SessionOptions);
            PqDiagnostics.HandshakeCompleted(PqRole.Client, _options.ResumptionSecret is { Length: > 0 }, mutual);
            _activity?.SetTag("pqsc.mutual", mutual);
            _activity?.SetTag("pqsc.resumed", _options.ResumptionSecret is { Length: > 0 });
            _activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Ok);
            _activity?.Dispose();
            _activity = null;
            return new PqClientHandshakeResult(session, finished.Serialize());
        }
        catch (PqSecureChannelException ex)
        {
            _activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            throw;
        }
        catch (Exception ex)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Client, "unexpected-error");
            _activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            throw new PqProtocolException("Unexpected error while processing ServerHello.", ex);
        }
        finally
        {
            // On success the session already holds its own clones of the secrets it needs; on failure
            // these are the only references. Either way, zero the shared secret and dispose the schedule.
            if (sharedSecret is not null)
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            schedule?.Dispose();
        }
    }

    private PqIdentityPublicKey ResolveServerIdentity(ServerHello sh)
    {
        // Build the set of acceptable identities from both ServerIdentity (primary) and AllowedServerIdentities.
        var primary = _options.ServerIdentity;
        var extras = _options.AllowedServerIdentities;

        // If the server advertised an identity, it must equal one of our pinned keys (constant-time per pin).
        if (sh.ServerIdentityPublicKey.Length > 0)
        {
            if (primary is not null
                && CryptographicOperations.FixedTimeEquals(sh.ServerIdentityPublicKey, primary.Bytes))
            {
                return primary;
            }

            if (extras is not null)
            {
                foreach (var candidate in extras)
                {
                    if (CryptographicOperations.FixedTimeEquals(sh.ServerIdentityPublicKey, candidate.Bytes))
                    {
                        return candidate;
                    }
                }
            }

            PqDiagnostics.HandshakeFailed(PqRole.Client, "server-identity-not-pinned");
            throw new PqAuthenticationException("ServerHello identity does not match any pinned server identity.");
        }

        // No advertised identity: fall back to the primary pin (single-pin compatibility).
        if (primary is not null)
        {
            return primary;
        }

        // Multi-pin only and no advertised key: cannot decide which pin to verify against.
        PqDiagnostics.HandshakeFailed(PqRole.Client, "server-identity-missing");
        throw new PqAuthenticationException(
            "Server did not advertise an identity public key; cannot select among multiple pinned identities.");
    }

    /// <summary>Zeroes any ephemeral key material still held by this handshake.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _keyPair?.Dispose();
        _keyPair = null;
        if (_clientRandom is not null)
        {
            CryptographicOperations.ZeroMemory(_clientRandom);
        }

        _activity?.Dispose();
        _activity = null;
        _disposed = true;
    }
}

/// <summary>The result of <see cref="PqClientHandshake.ProcessServerHello"/>.</summary>
public sealed class PqClientHandshakeResult
{
    private readonly byte[] _clientFinished;

    internal PqClientHandshakeResult(PqSession session, byte[] clientFinished)
    {
        Session = session;
        _clientFinished = (byte[])clientFinished.Clone();
    }

    /// <summary>The established session, ready for <see cref="PqSession.Encrypt"/> / <see cref="PqSession.Decrypt"/>.</summary>
    public PqSession Session { get; }

    /// <summary>The <c>ClientFinished</c> bytes to deliver to the server to complete the handshake.</summary>
    public byte[] ClientFinished => (byte[])_clientFinished.Clone();
}

/// <summary>
/// The server side of a handshake. Single-use and not thread-safe: call
/// <see cref="ProcessClientHello"/> then <see cref="ProcessClientFinished"/>, in order. Dispose to
/// zero the partial key schedule even when the handshake is abandoned mid-flight.
/// </summary>
public sealed class PqServerHandshake : IDisposable
{
    private readonly PqServerOptions _options;
    private KeySchedule? _schedule;
    private byte[]? _confirmationHash; // h2
    private System.Diagnostics.Activity? _activity;
    private bool _helloProcessed;
    private bool _completed;
    private bool _disposed;

    internal PqServerHandshake(PqServerOptions options) => _options = options;

    /// <summary>Processes the client's <c>ClientHello</c> and returns the <c>ServerHello</c> bytes to send back.</summary>
    public byte[] ProcessClientHello(ReadOnlySpan<byte> clientHello)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_helloProcessed)
        {
            throw new InvalidOperationException("ClientHello has already been processed.");
        }

        _activity = PqDiagnostics.StartHandshakeActivity(PqRole.Server);
        PqDiagnostics.HandshakeStarted(PqRole.Server);

        var clientHelloBytes = clientHello.ToArray();
        ClientHello ch;
        try
        {
            ch = ClientHello.Parse(clientHelloBytes);
        }
        catch (PqSecureChannelException)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "client-hello-malformed");
            throw;
        }

        var negotiated = PqProtocol.NegotiateVersion(ch.SupportedVersions);
        if (negotiated == 0)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "version-no-overlap");
            throw new PqProtocolException("No mutually supported protocol version was offered by the client.");
        }

        var (ciphertext, sharedSecret) = XWing.Encapsulate(ch.KemPublicKey);
        var serverRandom = RandomBytes.Create(PqProtocol.RandomSize);

        var sh = new ServerHello
        {
            NegotiatedVersion = negotiated,
            ServerRandom = serverRandom,
            KemCiphertext = ciphertext,
            ServerIdentityPublicKey = _options.Identity.PublicKey.Export(),
        };

        var serverHelloBody = sh.SerializeBody();
        var h1 = Transcript.Hash(clientHelloBytes, serverHelloBody);
        sh.Signature = _options.Identity.Sign(Transcript.SignedPayload(PqProtocol.ServerAuthContext, h1));

        var serverHelloFull = sh.Serialize();

        _schedule = KeySchedule.Derive(
            sharedSecret, ch.ClientRandom, serverRandom, h1, _options.ResumptionSecret);
        CryptographicOperations.ZeroMemory(sharedSecret);

        _confirmationHash = Transcript.Hash(clientHelloBytes, serverHelloFull);
        _helloProcessed = true;
        return serverHelloFull;
    }

    /// <summary>
    /// Verifies the client's <c>ClientFinished</c> (key confirmation and optional client authentication)
    /// and returns the established session.
    /// </summary>
    public PqSession ProcessClientFinished(ReadOnlySpan<byte> clientFinished)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_schedule is null || _confirmationHash is null)
        {
            throw new InvalidOperationException("Call ProcessClientHello before ProcessClientFinished.");
        }

        if (_completed)
        {
            throw new InvalidOperationException("This handshake has already completed.");
        }

        ClientFinished cf;
        try
        {
            cf = ClientFinished.Parse(clientFinished);
        }
        catch (PqSecureChannelException)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "client-finished-malformed");
            throw;
        }

        var expectedMac = Transcript.FinishedMac(_schedule.ClientFinishedKey, _confirmationHash);
        if (!CryptographicOperations.FixedTimeEquals(cf.FinishedMac, expectedMac))
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "client-finished-mac-invalid");
            throw new PqAuthenticationException("Client key confirmation (Finished MAC) failed.");
        }

        var clientIdentity = VerifyClientAuthentication(cf);

        _completed = true;
        var session = new PqSession(PqRole.Server, _schedule, clientIdentity, _options.SessionOptions);
        _schedule.Dispose(); // session has its own clones of the secrets it needs
        _schedule = null;
        PqDiagnostics.HandshakeCompleted(
            PqRole.Server,
            _options.ResumptionSecret is { Length: > 0 },
            clientIdentity is not null);
        _activity?.SetTag("pqsc.mutual", clientIdentity is not null);
        _activity?.SetTag("pqsc.resumed", _options.ResumptionSecret is { Length: > 0 });
        _activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Ok);
        _activity?.Dispose();
        _activity = null;
        return session;
    }

    private PqIdentityPublicKey? VerifyClientAuthentication(ClientFinished cf)
    {
        if (cf.ClientIdentityPublicKey.Length == 0)
        {
            // An allowlist is meaningless if an anonymous client is admitted past it: treat a configured
            // AuthorizedClients list as implying that client authentication is required, so the list can
            // never be silently inert just because RequireClientAuthentication was left at its default.
            if (_options.RequireClientAuthentication || _options.AuthorizedClients is { Count: > 0 })
            {
                PqDiagnostics.HandshakeFailed(PqRole.Server, "client-auth-required");
                throw new PqAuthenticationException("Client authentication is required but none was provided.");
            }

            return null;
        }

        PqIdentityPublicKey clientIdentity;
        try
        {
            clientIdentity = PqIdentityPublicKey.Import(cf.ClientIdentityPublicKey);
        }
        catch (ArgumentException)
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "client-identity-malformed");
            throw new PqAuthenticationException("Client identity public key is malformed.");
        }

        if (!clientIdentity.Verify(
                Transcript.SignedPayload(PqProtocol.ClientAuthContext, _confirmationHash!), cf.ClientSignature))
        {
            PqDiagnostics.HandshakeFailed(PqRole.Server, "client-signature-invalid");
            throw new PqAuthenticationException("Client signature verification failed.");
        }

        if (_options.AuthorizedClients is { Count: > 0 } allowlist)
        {
            bool authorized = false;
            foreach (var a in allowlist)
            {
                if (a.Equals(clientIdentity))
                {
                    authorized = true;
                    break;
                }
            }

            if (!authorized)
            {
                PqDiagnostics.HandshakeFailed(PqRole.Server, "client-not-authorized");
                throw new PqAuthenticationException("Client identity is not in the authorized clients list.");
            }
        }

        return clientIdentity;
    }

    /// <summary>Zeroes any partial key material still held by this handshake.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _schedule?.Dispose();
        _schedule = null;
        if (_confirmationHash is not null)
        {
            CryptographicOperations.ZeroMemory(_confirmationHash);
        }

        _activity?.Dispose();
        _activity = null;
        _disposed = true;
    }
}

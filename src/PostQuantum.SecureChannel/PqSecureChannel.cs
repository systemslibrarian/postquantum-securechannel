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
    /// <summary>Begins a client-side handshake.</summary>
    public static PqClientHandshake CreateClient(PqClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.ServerIdentity);
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
/// <see cref="CreateClientHello"/> then <see cref="ProcessServerHello"/>, in order.
/// </summary>
public sealed class PqClientHandshake
{
    private readonly PqClientOptions _options;
    private XWingKeyPair? _keyPair;
    private byte[]? _clientRandom;
    private byte[]? _clientHelloBytes;
    private bool _completed;

    internal PqClientHandshake(PqClientOptions options) => _options = options;

    /// <summary>Produces the <c>ClientHello</c> bytes to send to the server.</summary>
    public byte[] CreateClientHello()
    {
        if (_clientHelloBytes is not null)
        {
            throw new InvalidOperationException("ClientHello has already been created.");
        }

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
        if (_keyPair is null || _clientRandom is null || _clientHelloBytes is null)
        {
            throw new InvalidOperationException("Call CreateClientHello before ProcessServerHello.");
        }

        if (_completed)
        {
            throw new InvalidOperationException("This handshake has already completed.");
        }

        var sh = ServerHello.Parse(serverHello);

        // The server must have chosen a version we offered and still support.
        if (Array.IndexOf(PqProtocol.SupportedVersions, sh.NegotiatedVersion) < 0)
        {
            throw new PqProtocolException(
                $"Server negotiated unsupported protocol version {sh.NegotiatedVersion}.");
        }

        var serverHelloBody = sh.SerializeBody();
        var h1 = Transcript.Hash(_clientHelloBytes, serverHelloBody);

        // Authenticate the server against the pinned identity.
        var pinned = _options.ServerIdentity;
        if (sh.ServerIdentityPublicKey.Length > 0
            && !CryptographicOperations.FixedTimeEquals(sh.ServerIdentityPublicKey, pinned.Bytes))
        {
            throw new PqAuthenticationException("ServerHello identity does not match the pinned server identity.");
        }

        if (!pinned.Verify(Transcript.SignedPayload(PqProtocol.ServerAuthContext, h1), sh.Signature))
        {
            throw new PqAuthenticationException("Server signature verification failed.");
        }

        // Recover the shared secret and derive the session keys (mixing the resumption secret if present).
        var sharedSecret = _keyPair.Decapsulate(sh.KemCiphertext);
        var schedule = KeySchedule.Derive(
            sharedSecret, _clientRandom, sh.ServerRandom, h1, _options.ResumptionSecret);
        CryptographicOperations.ZeroMemory(sharedSecret);

        var h2 = Transcript.Hash(_clientHelloBytes, sh.Serialize());
        var finishedMac = Transcript.FinishedMac(schedule.ClientFinishedKey, h2);

        // Optional client authentication.
        byte[] clientIdentityBytes = [];
        byte[] clientSignature = [];
        if (_options.ClientIdentity is { } clientIdentity)
        {
            clientIdentityBytes = clientIdentity.PublicKey.Export();
            clientSignature = clientIdentity.Sign(Transcript.SignedPayload(PqProtocol.ClientAuthContext, h2));
        }

        var finished = new ClientFinished
        {
            ClientIdentityPublicKey = clientIdentityBytes,
            ClientSignature = clientSignature,
            FinishedMac = finishedMac,
        };

        _keyPair.Dispose();
        _completed = true;

        var session = new PqSession(PqRole.Client, schedule, pinned, _options.SessionOptions);
        return new PqClientHandshakeResult(session, finished.Serialize());
    }
}

/// <summary>The result of <see cref="PqClientHandshake.ProcessServerHello"/>.</summary>
public sealed class PqClientHandshakeResult
{
    internal PqClientHandshakeResult(PqSession session, byte[] clientFinished)
    {
        Session = session;
        ClientFinished = clientFinished;
    }

    /// <summary>The established session, ready for <see cref="PqSession.Encrypt"/> / <see cref="PqSession.Decrypt"/>.</summary>
    public PqSession Session { get; }

    /// <summary>The <c>ClientFinished</c> bytes to deliver to the server to complete the handshake.</summary>
    public byte[] ClientFinished { get; }
}

/// <summary>
/// The server side of a handshake. Single-use and not thread-safe: call
/// <see cref="ProcessClientHello"/> then <see cref="ProcessClientFinished"/>, in order.
/// </summary>
public sealed class PqServerHandshake
{
    private readonly PqServerOptions _options;
    private KeySchedule? _schedule;
    private byte[]? _confirmationHash; // h2
    private bool _helloProcessed;
    private bool _completed;

    internal PqServerHandshake(PqServerOptions options) => _options = options;

    /// <summary>Processes the client's <c>ClientHello</c> and returns the <c>ServerHello</c> bytes to send back.</summary>
    public byte[] ProcessClientHello(ReadOnlySpan<byte> clientHello)
    {
        if (_helloProcessed)
        {
            throw new InvalidOperationException("ClientHello has already been processed.");
        }

        var clientHelloBytes = clientHello.ToArray();
        var ch = ClientHello.Parse(clientHelloBytes);

        var negotiated = PqProtocol.NegotiateVersion(ch.SupportedVersions);
        if (negotiated == 0)
        {
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
        if (_schedule is null || _confirmationHash is null)
        {
            throw new InvalidOperationException("Call ProcessClientHello before ProcessClientFinished.");
        }

        if (_completed)
        {
            throw new InvalidOperationException("This handshake has already completed.");
        }

        var cf = ClientFinished.Parse(clientFinished);

        var expectedMac = Transcript.FinishedMac(_schedule.ClientFinishedKey, _confirmationHash);
        if (!CryptographicOperations.FixedTimeEquals(cf.FinishedMac, expectedMac))
        {
            throw new PqAuthenticationException("Client key confirmation (Finished MAC) failed.");
        }

        var clientIdentity = VerifyClientAuthentication(cf);

        _completed = true;
        return new PqSession(PqRole.Server, _schedule, clientIdentity, _options.SessionOptions);
    }

    private PqIdentityPublicKey? VerifyClientAuthentication(ClientFinished cf)
    {
        if (cf.ClientIdentityPublicKey.Length == 0)
        {
            if (_options.RequireClientAuthentication)
            {
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
            throw new PqAuthenticationException("Client identity public key is malformed.");
        }

        if (!clientIdentity.Verify(
                Transcript.SignedPayload(PqProtocol.ClientAuthContext, _confirmationHash!), cf.ClientSignature))
        {
            throw new PqAuthenticationException("Client signature verification failed.");
        }

        if (_options.AuthorizedClients is { Count: > 0 } allowlist)
        {
            var fingerprint = clientIdentity.Fingerprint();
            if (!allowlist.Any(a => a.Fingerprint() == fingerprint))
            {
                throw new PqAuthenticationException("Client identity is not in the authorized clients list.");
            }
        }

        return clientIdentity;
    }
}

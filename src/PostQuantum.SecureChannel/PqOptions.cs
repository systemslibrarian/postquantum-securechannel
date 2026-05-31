namespace PostQuantum.SecureChannel;

/// <summary>Configuration for the client (initiating) side of a handshake.</summary>
public sealed class PqClientOptions
{
    /// <summary>
    /// The server's pinned identity public key. Required unless <see cref="AllowedServerIdentities"/>
    /// is provided. The client authenticates the server by verifying the handshake signature against a
    /// pinned key, which defeats man-in-the-middle attacks. Distribute it out of band and compare its
    /// <see cref="PqIdentityPublicKey.Fingerprint"/>.
    /// </summary>
    public PqIdentityPublicKey? ServerIdentity { get; init; }

    /// <summary>
    /// An optional set of additional pinned server identities. The handshake succeeds if the server's
    /// advertised identity equals <see cref="ServerIdentity"/> or any entry in this collection. Use
    /// this to support staged key rotation: trust both the old and the new server identity during the
    /// overlap window, then drop the old one once all servers have rolled.
    /// </summary>
    /// <remarks>
    /// If <see cref="ServerIdentity"/> is <see langword="null"/> and this collection is non-empty, the
    /// server <em>must</em> advertise its identity public key in the <c>ServerHello</c> so the client
    /// knows which pin to verify against.
    /// </remarks>
    public IReadOnlyCollection<PqIdentityPublicKey>? AllowedServerIdentities { get; init; }

    /// <summary>
    /// An optional client identity. Supply it for mutual authentication, when the server is configured
    /// to require or record client identities. Leave <see langword="null"/> for anonymous clients.
    /// </summary>
    public PqIdentity? ClientIdentity { get; init; }

    private byte[]? _resumptionSecret;

    /// <summary>
    /// An optional resumption secret obtained from a previous session via
    /// <see cref="PqSession.ExportResumptionSecret"/>. When both peers supply the same secret it is mixed
    /// into the key schedule, binding this session to the earlier one. Still performs a full,
    /// forward-secret X-Wing handshake. Experimental &#8212; see <c>KNOWN-GAPS.md</c>.
    /// </summary>
    public byte[]? ResumptionSecret
    {
        get => _resumptionSecret is null ? null : (byte[])_resumptionSecret.Clone();
        init => _resumptionSecret = value is null ? null : (byte[])value.Clone();
    }

    /// <summary>Local session tuning (replay protection). Defaults to <see cref="PqSessionOptions.Default"/>.</summary>
    public PqSessionOptions SessionOptions { get; init; } = PqSessionOptions.Default;
}

/// <summary>Configuration for the server (accepting) side of a handshake.</summary>
public sealed class PqServerOptions
{
    /// <summary>The server's long-term identity, used to sign each handshake transcript. Required.</summary>
    public required PqIdentity Identity { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the handshake fails unless the client presents a valid identity
    /// signature. Defaults to <see langword="false"/> (server-authenticated only).
    /// </summary>
    public bool RequireClientAuthentication { get; init; }

    /// <summary>
    /// An optional allowlist of client identities. When set, a presented client identity must appear in
    /// this collection (compared by fingerprint) or the handshake is rejected.
    /// </summary>
    public IReadOnlyCollection<PqIdentityPublicKey>? AuthorizedClients { get; init; }

    private byte[]? _resumptionSecret;

    /// <summary>
    /// An optional resumption secret matching the client's. See <see cref="PqClientOptions.ResumptionSecret"/>.
    /// </summary>
    public byte[]? ResumptionSecret
    {
        get => _resumptionSecret is null ? null : (byte[])_resumptionSecret.Clone();
        init => _resumptionSecret = value is null ? null : (byte[])value.Clone();
    }

    /// <summary>Local session tuning (replay protection). Defaults to <see cref="PqSessionOptions.Default"/>.</summary>
    public PqSessionOptions SessionOptions { get; init; } = PqSessionOptions.Default;
}

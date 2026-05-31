namespace PostQuantum.SecureChannel;

/// <summary>Configuration for the client (initiating) side of a handshake.</summary>
public sealed class PqClientOptions
{
    /// <summary>
    /// The server's pinned identity public key. Required: the client authenticates the server by
    /// verifying the handshake signature against this key, which defeats man-in-the-middle attacks.
    /// Distribute it out of band and compare its <see cref="PqIdentityPublicKey.Fingerprint"/>.
    /// </summary>
    public required PqIdentityPublicKey ServerIdentity { get; init; }

    /// <summary>
    /// An optional client identity. Supply it for mutual authentication, when the server is configured
    /// to require or record client identities. Leave <see langword="null"/> for anonymous clients.
    /// </summary>
    public PqIdentity? ClientIdentity { get; init; }

    /// <summary>
    /// An optional resumption secret obtained from a previous session via
    /// <see cref="PqSession.ExportResumptionSecret"/>. When both peers supply the same secret it is mixed
    /// into the key schedule, binding this session to the earlier one. Still performs a full,
    /// forward-secret X-Wing handshake. Experimental &#8212; see <c>KNOWN-GAPS.md</c>.
    /// </summary>
    public byte[]? ResumptionSecret { get; init; }

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

    /// <summary>
    /// An optional resumption secret matching the client's. See <see cref="PqClientOptions.ResumptionSecret"/>.
    /// </summary>
    public byte[]? ResumptionSecret { get; init; }

    /// <summary>Local session tuning (replay protection). Defaults to <see cref="PqSessionOptions.Default"/>.</summary>
    public PqSessionOptions SessionOptions { get; init; } = PqSessionOptions.Default;
}

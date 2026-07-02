namespace PostQuantum.SecureChannel.AspNetCore;

/// <summary>
/// Options resolved by <see cref="DependencyInjection.PqSecureChannelServiceCollectionExtensions"/> for
/// a service hosting a PQ secure channel. Bind to a configuration section to populate.
/// </summary>
public sealed class PqSecureChannelOptions
{
    /// <summary>
    /// Base64-encoded 32-byte private seed for the server's long-term ML-DSA identity. Required for
    /// server-side use; supply via a secret manager (Key Vault / Secrets Manager / Kubernetes Secret).
    /// </summary>
    public string? ServerIdentitySeedBase64 { get; set; }

    /// <summary>
    /// Path to a file containing the base64-encoded 32-byte server identity seed. Alternative to
    /// <see cref="ServerIdentitySeedBase64"/> for environments that mount secrets as files.
    /// </summary>
    public string? ServerIdentitySeedFile { get; set; }

    /// <summary>
    /// Base64-encoded pinned server public key for client-side use. Distribute out of band; the
    /// fingerprint must match what the server presents during the handshake.
    /// </summary>
    public string? PinnedServerKeyBase64 { get; set; }

    /// <summary>
    /// Additional pinned server keys (base64) the client will accept during identity rotation.
    /// </summary>
    public IList<string> AllowedServerKeysBase64 { get; set; } = new List<string>();

    /// <summary>Reject handshakes that do not present a client identity. Defaults to <see langword="false"/>.</summary>
    public bool RequireClientAuthentication { get; set; }

    /// <summary>
    /// An allowlist of base64-encoded client public keys permitted to connect. When non-empty, only a
    /// client presenting one of these identities is accepted; an anonymous client is rejected even if
    /// <see cref="RequireClientAuthentication"/> is left <see langword="false"/> (a configured allowlist
    /// implies authentication is required). Distribute the keys out of band; a client is compared by its
    /// full public key in constant time. Leave empty to accept any authenticated client.
    /// </summary>
    public IList<string> AuthorizedClientKeysBase64 { get; set; } = new List<string>();

    /// <summary>
    /// Resolves <see cref="AuthorizedClientKeysBase64"/> into pinned identities, or <see langword="null"/>
    /// when the allowlist is empty (i.e. any authenticated client is accepted).
    /// </summary>
    public IReadOnlyCollection<PqIdentityPublicKey>? ResolveAuthorizedClients()
        => AuthorizedClientKeysBase64.Count == 0
            ? null
            : AuthorizedClientKeysBase64.Select(PqIdentityPublicKey.FromBase64).ToArray();

    /// <summary>Handshake timeout for the stream adapter. Defaults to 10 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>The named session preset to apply. One of <c>Default</c>, <c>Recommended</c>, <c>UnorderedTransport</c>, <c>HighThroughput</c>.</summary>
    public string SessionPreset { get; set; } = "Recommended";

    /// <summary>Resolves <see cref="SessionPreset"/> to the corresponding <see cref="PqSessionOptions"/> instance.</summary>
    public PqSessionOptions ResolveSessionOptions() => SessionPreset?.Trim() switch
    {
        null or "" or "Default" => PqSessionOptions.Default,
        "Recommended" => PqSessionOptions.Recommended,
        "UnorderedTransport" => PqSessionOptions.UnorderedTransport,
        "HighThroughput" => PqSessionOptions.HighThroughput,
        var other => throw new InvalidOperationException(
            $"Unknown session preset '{other}'. Expected: Default, Recommended, UnorderedTransport, HighThroughput."),
    };
}

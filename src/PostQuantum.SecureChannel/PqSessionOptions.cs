namespace PostQuantum.SecureChannel;

/// <summary>How a <see cref="PqSession"/> protects its receive direction against replay and reordering.</summary>
public enum PqReplayProtection
{
    /// <summary>
    /// Records must arrive in exact order; any gap or repeat is rejected. The safe default for reliable,
    /// ordered transports such as TCP.
    /// </summary>
    StrictOrdered,

    /// <summary>
    /// A DTLS/IPsec-style sliding window accepts in-window, not-yet-seen sequence numbers in any order
    /// and rejects replays and records older than the window. Use for unordered/lossy transports.
    /// </summary>
    SlidingWindow,
}

/// <summary>Per-endpoint session tuning. These choices are local; they are not negotiated with the peer.</summary>
public sealed class PqSessionOptions
{
    /// <summary>The default options: strict in-order delivery, manual rekey.</summary>
    public static PqSessionOptions Default { get; } = new();

    /// <summary>
    /// A balanced preset for typical long-lived TCP connections: strict ordering + the recommended
    /// automatic rekey thresholds (<see cref="PqKeyUpdatePolicy.Recommended"/>).
    /// </summary>
    public static PqSessionOptions Recommended { get; } = new()
    {
        ReplayProtection = PqReplayProtection.StrictOrdered,
        KeyUpdatePolicy = PqKeyUpdatePolicy.Recommended,
    };

    /// <summary>
    /// A preset for unordered/lossy transports (UDP-style, message queues): a sliding-window replay
    /// filter sized at 128 and the recommended automatic rekey thresholds.
    /// </summary>
    public static PqSessionOptions UnorderedTransport { get; } = new()
    {
        ReplayProtection = PqReplayProtection.SlidingWindow,
        ReplayWindowSize = 128,
        KeyUpdatePolicy = PqKeyUpdatePolicy.Recommended,
    };

    /// <summary>
    /// A preset for very high-throughput streams: ratchet less often (32M records / 16 GiB per epoch)
    /// to reduce ratchet overhead, still well inside NIST's deterministic-IV bound. Strict ordering.
    /// </summary>
    public static PqSessionOptions HighThroughput { get; } = new()
    {
        ReplayProtection = PqReplayProtection.StrictOrdered,
        KeyUpdatePolicy = new PqKeyUpdatePolicy
        {
            MaxRecordsBeforeUpdate = 1UL << 25,
            MaxBytesBeforeUpdate = 1UL << 34,
        },
    };

    /// <summary>Receive-side replay/reordering policy. Defaults to <see cref="PqReplayProtection.StrictOrdered"/>.</summary>
    public PqReplayProtection ReplayProtection { get; init; } = PqReplayProtection.StrictOrdered;

    /// <summary>
    /// Window size, in records, for <see cref="PqReplayProtection.SlidingWindow"/>. Must be between 8 and
    /// 1024; defaults to 64. Ignored for strict ordering.
    /// </summary>
    public int ReplayWindowSize { get; init; } = 64;

    /// <summary>
    /// When the send direction should ratchet to fresh keys. Defaults to <see cref="PqKeyUpdatePolicy.Disabled"/>
    /// (manual rekeying). Drives <see cref="PqSession.NeedsKeyUpdate"/>.
    /// </summary>
    public PqKeyUpdatePolicy KeyUpdatePolicy { get; init; } = PqKeyUpdatePolicy.Disabled;

    internal void Validate()
    {
        if (ReplayProtection == PqReplayProtection.SlidingWindow && (ReplayWindowSize < 8 || ReplayWindowSize > 1024))
        {
            throw new ArgumentOutOfRangeException(
                nameof(ReplayWindowSize), ReplayWindowSize, "Replay window size must be between 8 and 1024.");
        }

        KeyUpdatePolicy.Validate();
    }
}

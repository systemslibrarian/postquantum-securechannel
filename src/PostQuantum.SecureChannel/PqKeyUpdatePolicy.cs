namespace PostQuantum.SecureChannel;

/// <summary>
/// Thresholds that determine when a session's send direction should ratchet to fresh keys. A session
/// exposes <see cref="PqSession.NeedsKeyUpdate"/> based on this policy; <see cref="Transport.PqSecureChannelStream"/>
/// acts on it automatically. Raw-session callers can check it and call <see cref="PqSession.UpdateSendKey"/>.
/// </summary>
public sealed class PqKeyUpdatePolicy
{
    /// <summary>No automatic key update; the caller rekeys manually (the default).</summary>
    public static PqKeyUpdatePolicy Disabled { get; } = new();

    /// <summary>
    /// A conservative recommendation for long-lived connections: update after 16 million records or
    /// 4 GiB sent in the current epoch, whichever comes first.
    /// </summary>
    public static PqKeyUpdatePolicy Recommended { get; } = new()
    {
        MaxRecordsBeforeUpdate = 1UL << 24,
        MaxBytesBeforeUpdate = 1UL << 32,
    };

    /// <summary>Update after this many records in the current send epoch, if set.</summary>
    public ulong? MaxRecordsBeforeUpdate { get; init; }

    /// <summary>Update after this many plaintext bytes in the current send epoch, if set.</summary>
    public ulong? MaxBytesBeforeUpdate { get; init; }

    internal bool IsExceededBy(ulong records, ulong bytes)
        => (MaxRecordsBeforeUpdate is { } r && records >= r)
        || (MaxBytesBeforeUpdate is { } b && bytes >= b);

    internal void Validate()
    {
        if (MaxRecordsBeforeUpdate is 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxRecordsBeforeUpdate), "Must be null (disabled) or greater than zero.");
        }

        if (MaxBytesBeforeUpdate is 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxBytesBeforeUpdate), "Must be null (disabled) or greater than zero.");
        }
    }
}

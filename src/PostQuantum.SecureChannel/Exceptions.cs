namespace PostQuantum.SecureChannel;

/// <summary>Base type for all errors raised by PostQuantum.SecureChannel.</summary>
public class PqSecureChannelException : Exception
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqSecureChannelException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public PqSecureChannelException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when a handshake message is malformed, has an unexpected version, or arrives out of the
/// expected sequence.
/// </summary>
public sealed class PqProtocolException : PqSecureChannelException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqProtocolException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public PqProtocolException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when peer authentication fails: a missing, untrusted, or invalid signature, or a failed
/// key-confirmation check. A channel that raises this MUST be abandoned.
/// </summary>
public sealed class PqAuthenticationException : PqSecureChannelException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqAuthenticationException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public PqAuthenticationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when an encrypted record fails to decrypt or authenticate: a bad tag, a replayed or
/// out-of-order sequence number, or a tampered record.
/// </summary>
public sealed class PqDecryptionException : PqSecureChannelException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqDecryptionException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public PqDecryptionException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when the send direction has reached the configured per-epoch hard cap (records sent or
/// plaintext bytes encrypted). The caller must perform a key update (or re-handshake) before sending
/// further data; the receive direction is unaffected.
/// </summary>
/// <remarks>
/// The default caps match NIST SP 800-38D's safety bounds for AES-256-GCM under deterministic IVs
/// (<see cref="PqSession.MaxRecordsPerEpoch"/> records, <see cref="PqSession.MaxBytesPerEpoch"/> bytes).
/// Reaching them indicates the application sent further than a single key should ever protect; the
/// remedy is to ratchet, not to ignore.
/// </remarks>
public sealed class PqEpochExhaustedException : PqSecureChannelException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqEpochExhaustedException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public PqEpochExhaustedException(string message, Exception innerException) : base(message, innerException) { }
}

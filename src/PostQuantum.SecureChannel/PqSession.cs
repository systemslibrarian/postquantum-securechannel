using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.SecureChannel.Internal;

namespace PostQuantum.SecureChannel;

/// <summary>Which side of the channel a <see cref="PqSession"/> represents.</summary>
public enum PqRole
{
    /// <summary>The endpoint that initiated the handshake.</summary>
    Client,

    /// <summary>The endpoint that accepted the handshake.</summary>
    Server,
}

/// <summary>The kind of payload carried by a record.</summary>
public enum PqContentType
{
    /// <summary>Application data supplied by the caller.</summary>
    ApplicationData,

    /// <summary>A key-update control record; the receive direction has ratcheted to new keys.</summary>
    KeyUpdate,
}

/// <summary>The result of <see cref="PqSession.Open"/>: the decrypted payload and what kind of record it was.</summary>
public readonly struct PqIncomingRecord
{
    internal PqIncomingRecord(PqContentType contentType, byte[] payload)
    {
        ContentType = contentType;
        Payload = payload;
    }

    /// <summary>The record's content type.</summary>
    public PqContentType ContentType { get; }

    /// <summary>The decrypted payload (empty for control records such as <see cref="PqContentType.KeyUpdate"/>).</summary>
    public byte[] Payload { get; }
}

/// <summary>
/// An established, authenticated post-quantum secure channel. Each side holds a <see cref="PqSession"/>
/// and uses <see cref="Encrypt"/> / <see cref="Decrypt"/> (or <see cref="Open"/>) to protect application
/// messages with AES-256-GCM, and <see cref="UpdateSendKey"/> to ratchet to fresh keys without a new
/// handshake.
/// </summary>
/// <remarks>
/// <para>
/// Each direction has its own ratcheting traffic secret and a 64-bit sequence number, so a nonce is
/// never reused under a key. Replay/reordering protection is configurable via <see cref="PqSessionOptions"/>.
/// </para>
/// <para>This type is not thread-safe. Serialize calls per direction, or use one session per connection.</para>
/// </remarks>
public sealed class PqSession : IDisposable
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int IvPrefixSize = 4;
    private const int KeySize = 32;
    private const int HeaderSize = 1 + 1 + 8; // version + contentType + sequence

    /// <summary>
    /// Fixed per-record overhead added to the plaintext to form a wire record: the 10-byte header
    /// (version, content type, 64-bit sequence) plus the 16-byte AES-GCM tag. A record is therefore
    /// exactly <c>plaintext.Length + RecordOverhead</c> bytes, which callers can use to size framing.
    /// </summary>
    public const int RecordOverhead = HeaderSize + TagSize;

    /// <summary>
    /// Maximum number of records that may be sent within a single key epoch before a key update is
    /// required. Set to <c>2^32</c>, matching NIST SP 800-38D's invocation-count bound for AES-GCM with
    /// deterministic 96-bit IVs. Reaching it throws <see cref="PqEpochExhaustedException"/>.
    /// </summary>
    public const ulong MaxRecordsPerEpoch = 1UL << 32;

    /// <summary>
    /// Maximum number of plaintext bytes that may be encrypted within a single key epoch. Set to
    /// <c>2^36</c> (64 GiB), the AES-GCM-safe data bound under the same standard. Reaching it throws
    /// <see cref="PqEpochExhaustedException"/>.
    /// </summary>
    public const ulong MaxBytesPerEpoch = 1UL << 36;

    /// <summary>Maximum plaintext bytes accepted by <see cref="Encrypt"/> in a single record (<c>2^30</c>, 1 GiB).</summary>
    public const int MaxRecordPlaintextSize = 1 << 30;

    private readonly DirectionState _send;
    private readonly DirectionState _recv;
    private readonly byte[] _resumptionSecret;
    private readonly PqKeyUpdatePolicy _keyUpdatePolicy;
    private readonly TimeProvider _timeProvider;
    private long _sendEpochStartedAt;
    private bool _disposed;

    internal PqSession(
        PqRole role, KeySchedule schedule, PqIdentityPublicKey? remoteIdentity, PqSessionOptions options)
    {
        Role = role;
        RemoteIdentity = remoteIdentity;
        _keyUpdatePolicy = options.KeyUpdatePolicy;
        _timeProvider = options.TimeProvider;
        _sendEpochStartedAt = _timeProvider.GetTimestamp();
        _resumptionSecret = (byte[])schedule.ResumptionSecret.Clone();

        // The sender of one direction is the receiver of the other: pick traffic secrets by role.
        var (sendSecret, recvSecret) = role == PqRole.Client
            ? (schedule.ClientToServerTrafficSecret, schedule.ServerToClientTrafficSecret)
            : (schedule.ServerToClientTrafficSecret, schedule.ClientToServerTrafficSecret);

        _send = new DirectionState(sendSecret, PqReplayProtection.StrictOrdered, 0);
        _recv = new DirectionState(recvSecret, options.ReplayProtection, options.ReplayWindowSize);
    }

    /// <summary>Which side of the channel this session represents.</summary>
    public PqRole Role { get; }

    /// <summary>The authenticated identity of the remote peer, or <see langword="null"/> if unauthenticated.</summary>
    public PqIdentityPublicKey? RemoteIdentity { get; }

    /// <summary>Records sent in the current send epoch.</summary>
    public ulong RecordsSent => _send.Sequence;

    /// <summary>Records received in the current receive epoch.</summary>
    public ulong RecordsReceived => _recv.Received;

    /// <summary>How many times the send direction has ratcheted (0 = original keys).</summary>
    public uint SendEpoch => _send.Epoch;

    /// <summary>How many times the receive direction has ratcheted (0 = original keys).</summary>
    public uint ReceiveEpoch => _recv.Epoch;

    /// <summary>
    /// <see langword="true"/> when either the configured <see cref="PqKeyUpdatePolicy"/> threshold has
    /// been reached, or the send direction is approaching the hard <see cref="MaxRecordsPerEpoch"/> /
    /// <see cref="MaxBytesPerEpoch"/> caps (within 1/256th). Call <see cref="UpdateSendKey"/>; the
    /// stream adapter does this for you.
    /// </summary>
    public bool NeedsKeyUpdate =>
        _keyUpdatePolicy.IsExceededBy(_send.Sequence, _send.BytesThisEpoch)
        || (_keyUpdatePolicy.MaxAge is { } maxAge && _timeProvider.GetElapsedTime(_sendEpochStartedAt) >= maxAge)
        || _send.Sequence >= MaxRecordsPerEpoch - (MaxRecordsPerEpoch >> 8)
        || _send.BytesThisEpoch >= MaxBytesPerEpoch - (MaxBytesPerEpoch >> 8);

    /// <summary>Encrypts application <paramref name="plaintext"/> into a self-framed record.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        => Seal(PqProtocol.RecordApplicationData, plaintext, associatedData);

    /// <summary>
    /// Decrypts an application-data record. Throws <see cref="PqProtocolException"/> if the record is a
    /// control record (use <see cref="Open"/> if you exchange key updates), or
    /// <see cref="PqDecryptionException"/> if it fails to authenticate.
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> record, ReadOnlySpan<byte> associatedData = default)
    {
        var incoming = Open(record, associatedData);
        if (incoming.ContentType != PqContentType.ApplicationData)
        {
            throw new PqProtocolException(
                $"Received a {incoming.ContentType} control record; use Open to handle control records.");
        }

        return incoming.Payload;
    }

    /// <summary>
    /// Decrypts any record and reports its content type. Key-update control records are processed
    /// transparently (the receive direction ratchets) and reported as <see cref="PqContentType.KeyUpdate"/>
    /// with an empty payload.
    /// </summary>
    public PqIncomingRecord Open(ReadOnlySpan<byte> record, ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (record.Length < HeaderSize + TagSize)
        {
            throw new PqDecryptionException("Record is too short to be valid.");
        }

        if (record[0] != PqProtocol.Version)
        {
            throw new PqDecryptionException("Unsupported record version.");
        }

        byte contentType = record[1];
        ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(record.Slice(2, 8));

        if (!_recv.IsAcceptable(sequence))
        {
            PqDiagnostics.RecordRejected(Role, "sequence-replay-or-reorder");
            throw new PqDecryptionException(
                $"Record sequence {sequence} rejected (replay, reorder, or outside the replay window).");
        }

        Span<byte> nonce = stackalloc byte[NonceSize];
        _recv.BuildNonce(sequence, nonce);

        int plaintextLength = record.Length - HeaderSize - TagSize;
        var plaintext = new byte[plaintextLength];
        var ciphertext = record.Slice(HeaderSize, plaintextLength);
        var tag = record.Slice(HeaderSize + plaintextLength, TagSize);

        // Application AAD binds application records only. Control records (key update) are always sealed
        // with no caller AAD, so authenticate them with the header alone — otherwise a caller that passes
        // the same contextual AAD to every Open() call would fail to authenticate the peer's key-update
        // record (which the sender has already ratcheted past), permanently desynchronizing the session.
        // The content-type byte lives in the header and is itself covered by the AAD, so an attacker
        // cannot relabel an application record as a control record to strip its AAD binding.
        ReadOnlySpan<byte> effectiveAad =
            contentType == PqProtocol.RecordApplicationData ? associatedData : default;
        var aad = BuildAssociatedData(record[..HeaderSize], effectiveAad);
        try
        {
            _recv.Cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException ex)
        {
            PqDiagnostics.RecordRejected(Role, "aead-auth-failure");
            throw new PqDecryptionException("Record failed authentication; it may be corrupt or tampered.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }

        _recv.Commit(sequence);

        switch (contentType)
        {
            case PqProtocol.RecordApplicationData:
                return new PqIncomingRecord(PqContentType.ApplicationData, plaintext);

            case PqProtocol.RecordKeyUpdate:
                _recv.Ratchet();
                PqDiagnostics.KeyUpdated(Role, isReceive: true, _recv.Epoch);
                CryptographicOperations.ZeroMemory(plaintext);
                return new PqIncomingRecord(PqContentType.KeyUpdate, []);

            default:
                CryptographicOperations.ZeroMemory(plaintext);
                throw new PqProtocolException($"Unknown record content type 0x{contentType:x2}.");
        }
    }

    /// <summary>
    /// Produces a key-update control record and ratchets the send direction to fresh keys. Send the
    /// returned bytes to the peer; once delivered, all subsequent records use the new epoch's keys.
    /// </summary>
    public byte[] UpdateSendKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var record = Seal(PqProtocol.RecordKeyUpdate, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, isControl: true);
        _send.Ratchet();
        _sendEpochStartedAt = _timeProvider.GetTimestamp();
        PqDiagnostics.KeyUpdated(Role, isReceive: false, _send.Epoch);
        return record;
    }

    /// <summary>
    /// Exports a 32-byte resumption secret that both peers can cache to bind a future handshake to this
    /// session (see <see cref="PqClientOptions.ResumptionSecret"/>). Treat it as sensitive key material.
    /// </summary>
    public byte[] ExportResumptionSecret()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_resumptionSecret.Clone();
    }

    private byte[] Seal(
        byte contentType, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, bool isControl = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (plaintext.Length > MaxRecordPlaintextSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plaintext),
                plaintext.Length,
                $"Plaintext exceeds the {MaxRecordPlaintextSize}-byte per-record limit; split into multiple records.");
        }

        // Application data is capped at MaxRecordsPerEpoch invocations. The key-update control record is
        // allowed exactly one slot beyond that cap so a session that reaches the limit can still emit the
        // escape record UpdateSendKey() advertises, rather than throwing the very exception it tells the
        // caller to resolve by calling UpdateSendKey. One extra AES-GCM invocation past 2^32 is
        // cryptographically negligible, and it fails closed for all subsequent application data.
        ulong recordCap = isControl ? MaxRecordsPerEpoch + 1 : MaxRecordsPerEpoch;
        if (_send.Sequence >= recordCap)
        {
            PqDiagnostics.EpochExhausted(Role, isReceive: false, recordCap: true);
            throw new PqEpochExhaustedException(
                $"Send sequence exhausted for this epoch ({MaxRecordsPerEpoch} records); call UpdateSendKey before sending more data.");
        }

        if (_send.BytesThisEpoch + (ulong)plaintext.Length > MaxBytesPerEpoch)
        {
            PqDiagnostics.EpochExhausted(Role, isReceive: false, recordCap: false);
            throw new PqEpochExhaustedException(
                $"Send byte budget exhausted for this epoch ({MaxBytesPerEpoch} bytes); call UpdateSendKey before sending more data.");
        }

        ulong sequence = _send.Sequence;
        var record = new byte[HeaderSize + plaintext.Length + TagSize];
        record[0] = PqProtocol.Version;
        record[1] = contentType;
        BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(2, 8), sequence);

        Span<byte> nonce = stackalloc byte[NonceSize];
        _send.BuildNonce(sequence, nonce);

        var aad = BuildAssociatedData(record.AsSpan(0, HeaderSize), associatedData);
        try
        {
            var ciphertext = record.AsSpan(HeaderSize, plaintext.Length);
            var tag = record.AsSpan(HeaderSize + plaintext.Length, TagSize);
            _send.Cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }

        _send.Advance(plaintext.Length);
        return record;
    }

    private static byte[] BuildAssociatedData(ReadOnlySpan<byte> header, ReadOnlySpan<byte> callerAad)
    {
        var aad = new byte[header.Length + callerAad.Length];
        header.CopyTo(aad);
        callerAad.CopyTo(aad.AsSpan(header.Length));
        return aad;
    }

    /// <summary>Disposes the ciphers and zeroes all key material.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _send.Dispose();
        _recv.Dispose();
        CryptographicOperations.ZeroMemory(_resumptionSecret);
        _disposed = true;
    }

    /// <summary>One direction's keying state, including ratchet and replay tracking.</summary>
    private sealed class DirectionState : IDisposable
    {
        private readonly PqReplayProtection _replayProtection;
        private readonly int _windowSize;
        private byte[] _trafficSecret;
        private byte[] _ivPrefix;

        // Receive bookkeeping.
        private ulong _expected;          // next sequence in strict mode
        private AntiReplayWindow? _window; // sliding-window mode

        internal AesGcm Cipher { get; private set; }
        internal ulong Sequence { get; private set; }       // next send sequence
        internal ulong BytesThisEpoch { get; private set; } // plaintext bytes sent this epoch
        internal ulong Received { get; private set; }       // count of accepted records (this epoch)
        internal uint Epoch { get; private set; }

        internal DirectionState(byte[] trafficSecret, PqReplayProtection replayProtection, int windowSize)
        {
            _replayProtection = replayProtection;
            _windowSize = windowSize;
            _trafficSecret = (byte[])trafficSecret.Clone();
            (Cipher, _ivPrefix) = DeriveKeys(_trafficSecret);
            ResetReplayState();
        }

        private static (AesGcm Cipher, byte[] IvPrefix) DeriveKeys(byte[] trafficSecret)
        {
            var key = Hkdf.Expand(trafficSecret, PqProtocol.TrafficKeyInfo, KeySize);
            var iv = Hkdf.Expand(trafficSecret, PqProtocol.TrafficIvInfo, IvPrefixSize);
            try
            {
                return (new AesGcm(key, TagSize), iv);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        internal void BuildNonce(ulong sequence, Span<byte> nonce)
        {
            _ivPrefix.AsSpan(0, IvPrefixSize).CopyTo(nonce);
            BinaryPrimitives.WriteUInt64BigEndian(nonce[IvPrefixSize..], sequence);
        }

        internal void Advance(int payloadLength)
        {
            Sequence++;
            BytesThisEpoch += (ulong)payloadLength;
        }

        internal bool IsAcceptable(ulong sequence) => _replayProtection switch
        {
            PqReplayProtection.SlidingWindow => _window!.IsAcceptable(sequence),
            _ => sequence == _expected,
        };

        internal void Commit(ulong sequence)
        {
            if (_replayProtection == PqReplayProtection.SlidingWindow)
            {
                _window!.Commit(sequence);
            }
            else
            {
                _expected = sequence + 1;
            }

            Received++;
        }

        /// <summary>Ratchets this direction to a new key epoch and resets sequence/replay state.</summary>
        internal void Ratchet()
        {
            var next = Hkdf.Expand(_trafficSecret, PqProtocol.KeyUpdateInfo, KeySize);
            CryptographicOperations.ZeroMemory(_trafficSecret);
            _trafficSecret = next;

            Cipher.Dispose();
            CryptographicOperations.ZeroMemory(_ivPrefix);
            (Cipher, _ivPrefix) = DeriveKeys(_trafficSecret);

            Sequence = 0;
            BytesThisEpoch = 0;
            Received = 0;
            Epoch++;
            ResetReplayState();
        }

        private void ResetReplayState()
        {
            _expected = 0;
            _window = _replayProtection == PqReplayProtection.SlidingWindow ? new AntiReplayWindow(_windowSize) : null;
        }

        public void Dispose()
        {
            Cipher.Dispose();
            CryptographicOperations.ZeroMemory(_trafficSecret);
            CryptographicOperations.ZeroMemory(_ivPrefix);
        }
    }
}

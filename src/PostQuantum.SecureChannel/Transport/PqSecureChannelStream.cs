using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Transport;

/// <summary>
/// A <see cref="Stream"/> that transparently encrypts everything written and decrypts everything read
/// over an inner transport stream, using an established <see cref="PqSession"/>. Each write becomes one
/// length-framed AES-256-GCM record; reads reassemble plaintext from records. Key-update control records
/// are handled transparently.
/// </summary>
/// <remarks>
/// Obtain an instance from <see cref="PqSecureChannel.ConnectAsync"/> (client) or
/// <see cref="PqSecureChannel.AcceptAsync"/> (server), which drive the handshake first. The stream is
/// read/write but not seekable. Reads and writes should each be serialized (one outstanding at a time).
/// </remarks>
public sealed class PqSecureChannelStream : Stream
{
    private readonly Stream _inner;
    private readonly PqSession _session;
    private readonly bool _leaveInnerOpen;
    private readonly int _maxFrameSize;

    private byte[] _readBuffer = [];
    private int _readOffset;
    private bool _disposed;

    internal PqSecureChannelStream(Stream inner, PqSession session, bool leaveInnerOpen, int maxFrameSize)
    {
        _inner = inner;
        _session = session;
        _leaveInnerOpen = leaveInnerOpen;
        _maxFrameSize = maxFrameSize;
    }

    /// <summary>The underlying session, exposing peer identity, epochs, and resumption export.</summary>
    public PqSession Session => _session;

    /// <inheritdoc />
    public override bool CanRead => !_disposed;

    /// <inheritdoc />
    public override bool CanWrite => !_disposed;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// Ratchets the send key and notifies the peer with a key-update record. Subsequent writes use the
    /// new epoch's keys.
    /// </summary>
    /// <remarks>
    /// The send direction ratchets in memory before the key-update record is flushed, so if this call is
    /// cancelled or the underlying write fails, the local and remote epochs can diverge. As with any
    /// failed write on this stream, a cancelled or faulted <see cref="UpdateSendKeyAsync"/> (or
    /// <see cref="WriteAsync(ReadOnlyMemory{byte},CancellationToken)"/>, which auto-rekeys) leaves the
    /// session in an indeterminate state: dispose the stream and re-handshake rather than continuing to
    /// use it.
    /// </remarks>
    public async ValueTask UpdateSendKeyAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var record = _session.UpdateSendKey();
        await PqFraming.WriteFrameAsync(_inner, record, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

        // Refill from the next application-data record, skipping any control records.
        while (_readOffset >= _readBuffer.Length)
        {
            byte[] frame;
            try
            {
                frame = await PqFraming.ReadFrameAsync(_inner, _maxFrameSize, cancellationToken).ConfigureAwait(false);
            }
            catch (EndOfStreamException)
            {
                return 0; // peer closed cleanly
            }

            var incoming = _session.Open(frame);
            if (incoming.ContentType == PqContentType.ApplicationData)
            {
                _readBuffer = incoming.Payload;
                _readOffset = 0;
                if (_readBuffer.Length == 0)
                {
                    continue; // empty application record; keep reading
                }
            }
            // KeyUpdate (or other control) records are consumed transparently; loop to read the next frame.
        }

        int toCopy = Math.Min(buffer.Length, _readBuffer.Length - _readOffset);
        _readBuffer.AsSpan(_readOffset, toCopy).CopyTo(buffer.Span);
        _readOffset += toCopy;

        if (_readOffset == _readBuffer.Length && _readBuffer.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_readBuffer);
            _readBuffer = [];
            _readOffset = 0;
        }

        return toCopy;
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Honour the session's key-update policy automatically for long-lived connections.
        if (_session.NeedsKeyUpdate)
        {
            await UpdateSendKeyAsync(cancellationToken).ConfigureAwait(false);
        }

        var record = _session.Encrypt(buffer.Span);
        await PqFraming.WriteFrameAsync(_inner, record, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    /// <inheritdoc />
    public override void Flush() => _inner.Flush();

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            CryptographicOperations.ZeroMemory(_readBuffer);
            _readBuffer = [];
            _readOffset = 0;
            _session.Dispose();
            if (!_leaveInnerOpen)
            {
                _inner.Dispose();
            }
        }

        _disposed = true;
        base.Dispose(disposing);
    }
}

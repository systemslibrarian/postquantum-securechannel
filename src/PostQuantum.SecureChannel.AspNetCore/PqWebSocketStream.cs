using System.Net.WebSockets;

namespace PostQuantum.SecureChannel.AspNetCore;

/// <summary>
/// Wraps a <see cref="WebSocket"/> as a <see cref="Stream"/> of binary messages so it can drive
/// <see cref="PqSecureChannel.ConnectAsync"/> / <see cref="PqSecureChannel.AcceptAsync"/>. Each
/// <see cref="WriteAsync(ReadOnlyMemory{byte},CancellationToken)"/> sends a single binary WebSocket
/// message; reads concatenate fragments until the end-of-message flag arrives.
/// </summary>
/// <remarks>
/// This adapter is intended for one outstanding read and one outstanding write at a time, matching
/// <see cref="Transport.PqSecureChannelStream"/>'s contract. Close the wrapped <see cref="WebSocket"/>
/// or dispose this stream to terminate the channel.
/// </remarks>
public sealed class PqWebSocketStream : Stream
{
    /// <summary>
    /// Default maximum size, in bytes, of a single reassembled inbound WebSocket message (16 MiB plus a
    /// small framing allowance). A message carries exactly one length-prefixed channel frame, so this
    /// bounds inbound buffering to roughly the channel's own frame limit.
    /// </summary>
    public const int DefaultMaxReceiveMessageSize = (16 * 1024 * 1024) + 4096;

    private readonly WebSocket _socket;
    private readonly bool _ownsSocket;
    private readonly int _maxReceiveMessageSize;
    private byte[]? _readBuffer;
    private int _readOffset;
    private bool _disposed;

    /// <summary>Initializes a new instance wrapping <paramref name="socket"/>.</summary>
    /// <param name="socket">The connected WebSocket to wrap.</param>
    /// <param name="ownsSocket">If <see langword="true"/>, disposing this stream also disposes the socket.</param>
    /// <param name="maxReceiveMessageSize">
    /// Maximum size, in bytes, of a single reassembled inbound WebSocket message. A peer that sends a
    /// larger (or unterminated) message is rejected before the whole message is buffered, bounding
    /// memory use even before the handshake completes. Defaults to <see cref="DefaultMaxReceiveMessageSize"/>.
    /// </param>
    public PqWebSocketStream(WebSocket socket, bool ownsSocket = true, int maxReceiveMessageSize = DefaultMaxReceiveMessageSize)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxReceiveMessageSize);
        _socket = socket;
        _ownsSocket = ownsSocket;
        _maxReceiveMessageSize = maxReceiveMessageSize;
    }

    /// <inheritdoc />
    public override bool CanRead => !_disposed && _socket.State is WebSocketState.Open or WebSocketState.CloseSent;

    /// <inheritdoc />
    public override bool CanWrite => !_disposed && _socket.State is WebSocketState.Open or WebSocketState.CloseReceived;

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

    /// <inheritdoc />
    public override void Flush() { }

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

        // Drain any leftover bytes from the previous WebSocket message first.
        if (_readBuffer is not null && _readOffset < _readBuffer.Length)
        {
            int available = _readBuffer.Length - _readOffset;
            int toCopy = Math.Min(available, buffer.Length);
            _readBuffer.AsMemory(_readOffset, toCopy).CopyTo(buffer);
            _readOffset += toCopy;
            return toCopy;
        }

        // Receive a fresh WebSocket message, concatenating fragments. Bound the total so a malicious or
        // buggy peer cannot force unbounded buffering (a pre-handshake OOM) with one huge or unterminated
        // message — the size guard in the framing layer sits above this adapter and would never see it.
        using var ms = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            WebSocketReceiveResult result;
            try
            {
                result = await _socket.ReceiveAsync(chunk, cancellationToken).ConfigureAwait(false);
            }
            catch (WebSocketException)
            {
                return 0;
            }

            if (result.MessageType == WebSocketMessageType.Close)
            {
                return 0;
            }

            if (ms.Length + result.Count > _maxReceiveMessageSize)
            {
                throw new PostQuantum.SecureChannel.PqProtocolException(
                    $"Inbound WebSocket message exceeds the {_maxReceiveMessageSize}-byte limit.");
            }

            ms.Write(chunk, 0, result.Count);
            if (result.EndOfMessage)
            {
                break;
            }
        }

        _readBuffer = ms.ToArray();
        _readOffset = 0;

        int copy = Math.Min(_readBuffer.Length, buffer.Length);
        _readBuffer.AsMemory(0, copy).CopyTo(buffer);
        _readOffset = copy;
        return copy;
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _socket.SendAsync(buffer, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing && _ownsSocket)
        {
            try
            {
                if (_socket.State == WebSocketState.Open)
                {
                    _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closed", CancellationToken.None)
                        .GetAwaiter().GetResult();
                }
            }
            catch (WebSocketException) { /* peer already torn down */ }
            catch (ObjectDisposedException) { /* socket already disposed */ }

            _socket.Dispose();
        }

        _disposed = true;
        base.Dispose(disposing);
    }
}

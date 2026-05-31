using System.Collections.Concurrent;

namespace PostQuantum.SecureChannel.Testing;

/// <summary>
/// An in-memory, bidirectional <see cref="Stream"/> pair: one writer's bytes appear at the other end's
/// reader, and vice versa. Use it to drive <see cref="PqSecureChannel.ConnectAsync"/> /
/// <see cref="PqSecureChannel.AcceptAsync"/> in tests without binding a TCP listener.
/// </summary>
/// <remarks>
/// Each side is a separate <see cref="Stream"/>. Reads block (asynchronously) until the peer writes;
/// closing one end signals end-of-stream on the other. The implementation is intentionally simple — it
/// is for tests, not production traffic.
/// </remarks>
public static class PqInMemoryDuplex
{
    /// <summary>Creates a connected pair of in-memory bidirectional streams.</summary>
    public static (Stream Client, Stream Server) CreatePair()
    {
        var clientToServer = new Pipe();
        var serverToClient = new Pipe();
        return (new Side(serverToClient, clientToServer), new Side(clientToServer, serverToClient));
    }

    private sealed class Pipe : IDisposable
    {
        internal readonly BlockingCollection<byte[]> Chunks = new(new ConcurrentQueue<byte[]>());
        internal byte[]? Pending;
        internal int PendingOffset;
        internal bool Closed;

        public void Dispose() => Chunks.Dispose();
    }

    private sealed class Side : Stream
    {
        private readonly Pipe _readPipe;
        private readonly Pipe _writePipe;
        private bool _disposed;

        internal Side(Pipe readPipe, Pipe writePipe)
        {
            _readPipe = readPipe;
            _writePipe = writePipe;
        }

        public override bool CanRead => !_disposed;
        public override bool CanWrite => !_disposed;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (buffer.IsEmpty)
            {
                return 0;
            }

            while (true)
            {
                if (_readPipe.Pending is not null)
                {
                    int available = _readPipe.Pending.Length - _readPipe.PendingOffset;
                    int toCopy = Math.Min(available, buffer.Length);
                    _readPipe.Pending.AsMemory(_readPipe.PendingOffset, toCopy).CopyTo(buffer);
                    _readPipe.PendingOffset += toCopy;
                    if (_readPipe.PendingOffset >= _readPipe.Pending.Length)
                    {
                        _readPipe.Pending = null;
                        _readPipe.PendingOffset = 0;
                    }

                    return toCopy;
                }

                if (_readPipe.Closed && _readPipe.Chunks.Count == 0)
                {
                    return 0;
                }

                byte[] chunk;
                try
                {
                    chunk = await Task.Run(() => _readPipe.Chunks.Take(cancellationToken), cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (InvalidOperationException)
                {
                    return 0; // collection completed
                }

                _readPipe.Pending = chunk;
                _readPipe.PendingOffset = 0;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (_writePipe.Closed)
            {
                throw new IOException("Peer has closed the duplex stream.");
            }

            _writePipe.Chunks.Add(buffer.ToArray(), cancellationToken);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _writePipe.Closed = true;
                _writePipe.Chunks.CompleteAdding();
            }

            _disposed = true;
            base.Dispose(disposing);
        }
    }
}

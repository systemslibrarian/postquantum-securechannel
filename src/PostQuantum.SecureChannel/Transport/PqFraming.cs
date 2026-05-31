using System.Buffers.Binary;

namespace PostQuantum.SecureChannel.Transport;

/// <summary>
/// Length-prefixed framing for handshake messages and records over a byte stream. Each frame is a
/// 4-byte big-endian length followed by that many bytes. A configurable maximum guards against a peer
/// that announces an absurd length.
/// </summary>
internal static class PqFraming
{
    /// <summary>Default maximum frame size (16 MiB). Large enough for any handshake message or record.</summary>
    internal const int DefaultMaxFrameSize = 16 * 1024 * 1024;

    internal static async ValueTask WriteFrameAsync(
        Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static async ValueTask<byte[]> ReadFrameAsync(
        Stream stream, int maxFrameSize, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header);

        if (length > (uint)maxFrameSize)
        {
            throw new PqProtocolException($"Incoming frame length {length} exceeds the limit of {maxFrameSize} bytes.");
        }

        var payload = new byte[length];
        if (length > 0)
        {
            await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        }

        return payload;
    }
}

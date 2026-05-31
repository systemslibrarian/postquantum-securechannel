using PostQuantum.SecureChannel.Transport;

namespace PostQuantum.SecureChannel;

public static partial class PqSecureChannel
{
    /// <summary>
    /// Performs the client handshake over <paramref name="stream"/> and returns a
    /// <see cref="PqSecureChannelStream"/> that transparently encrypts and decrypts further traffic.
    /// </summary>
    /// <param name="stream">A connected, bidirectional transport stream (for example, a TCP <c>NetworkStream</c>).</param>
    /// <param name="options">Client configuration, including the pinned server identity.</param>
    /// <param name="leaveInnerOpen">If <see langword="true"/>, disposing the result leaves <paramref name="stream"/> open.</param>
    /// <param name="maxFrameSize">Maximum accepted frame size, in bytes.</param>
    /// <param name="handshakeTimeout">If set, the handshake fails with <see cref="TimeoutException"/> after this duration.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    public static Task<PqSecureChannelStream> ConnectAsync(
        Stream stream,
        PqClientOptions options,
        bool leaveInnerOpen = false,
        int maxFrameSize = PqFraming.DefaultMaxFrameSize,
        TimeSpan? handshakeTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return WithTimeout(handshakeTimeout, async token =>
        {
            var handshake = CreateClient(options);

            var clientHello = handshake.CreateClientHello();
            await PqFraming.WriteFrameAsync(stream, clientHello, token).ConfigureAwait(false);

            var serverHello = await PqFraming.ReadFrameAsync(stream, maxFrameSize, token).ConfigureAwait(false);
            var result = handshake.ProcessServerHello(serverHello);

            await PqFraming.WriteFrameAsync(stream, result.ClientFinished, token).ConfigureAwait(false);
            return new PqSecureChannelStream(stream, result.Session, leaveInnerOpen, maxFrameSize);
        }, cancellationToken);
    }

    /// <summary>
    /// Performs the server handshake over <paramref name="stream"/> and returns a
    /// <see cref="PqSecureChannelStream"/> that transparently encrypts and decrypts further traffic.
    /// </summary>
    /// <param name="stream">A connected, bidirectional transport stream (for example, a TCP <c>NetworkStream</c>).</param>
    /// <param name="options">Server configuration, including the long-term identity.</param>
    /// <param name="leaveInnerOpen">If <see langword="true"/>, disposing the result leaves <paramref name="stream"/> open.</param>
    /// <param name="maxFrameSize">Maximum accepted frame size, in bytes.</param>
    /// <param name="handshakeTimeout">If set, the handshake fails with <see cref="TimeoutException"/> after this duration.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    public static Task<PqSecureChannelStream> AcceptAsync(
        Stream stream,
        PqServerOptions options,
        bool leaveInnerOpen = false,
        int maxFrameSize = PqFraming.DefaultMaxFrameSize,
        TimeSpan? handshakeTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return WithTimeout(handshakeTimeout, async token =>
        {
            var handshake = CreateServer(options);

            var clientHello = await PqFraming.ReadFrameAsync(stream, maxFrameSize, token).ConfigureAwait(false);
            var serverHello = handshake.ProcessClientHello(clientHello);
            await PqFraming.WriteFrameAsync(stream, serverHello, token).ConfigureAwait(false);

            var clientFinished = await PqFraming.ReadFrameAsync(stream, maxFrameSize, token).ConfigureAwait(false);
            var session = handshake.ProcessClientFinished(clientFinished);
            return new PqSecureChannelStream(stream, session, leaveInnerOpen, maxFrameSize);
        }, cancellationToken);
    }

    private static async Task<PqSecureChannelStream> WithTimeout(
        TimeSpan? timeout,
        Func<CancellationToken, Task<PqSecureChannelStream>> operation,
        CancellationToken cancellationToken)
    {
        if (timeout is null)
        {
            return await operation(cancellationToken).ConfigureAwait(false);
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout.Value);
        try
        {
            return await operation(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"The handshake did not complete within {timeout.Value}.");
        }
    }
}

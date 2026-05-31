using System.Net.WebSockets;
using PostQuantum.SecureChannel.Transport;

namespace PostQuantum.SecureChannel.AspNetCore;

/// <summary>Client-side helpers: drive a PQ handshake over a connected <see cref="WebSocket"/>.</summary>
public static class PqWebSocketClientExtensions
{
    /// <summary>
    /// Performs a client-side PQ handshake over <paramref name="socket"/> and returns a
    /// <see cref="PqSecureChannelStream"/> that transparently encrypts subsequent traffic.
    /// </summary>
    /// <param name="socket">A connected WebSocket (for example, a <see cref="ClientWebSocket"/> after <c>ConnectAsync</c>).</param>
    /// <param name="options">Client options including the pinned server identity.</param>
    /// <param name="handshakeTimeout">Optional handshake timeout.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    public static Task<PqSecureChannelStream> AcceptPqClientAsync(
        this WebSocket socket,
        PqClientOptions options,
        TimeSpan? handshakeTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(options);

        var transport = new PqWebSocketStream(socket, ownsSocket: false);
        return PqSecureChannel.ConnectAsync(
            transport, options, leaveInnerOpen: true,
            handshakeTimeout: handshakeTimeout, cancellationToken: cancellationToken);
    }
}

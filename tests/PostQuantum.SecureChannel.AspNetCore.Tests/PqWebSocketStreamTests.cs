using System.Net.WebSockets;
using PostQuantum.SecureChannel.AspNetCore;
using Xunit;

namespace PostQuantum.SecureChannel.AspNetCore.Tests;

/// <summary>
/// Rejection-path coverage for <see cref="PqWebSocketStream"/>'s inbound message-size cap, which bounds
/// pre-handshake buffering so a malicious or buggy peer cannot force unbounded reassembly (an OOM DoS)
/// with one huge or never-terminated WebSocket message.
/// </summary>
public class PqWebSocketStreamTests
{
    /// <summary>A WebSocket that streams binary fragments forever without ever setting end-of-message.</summary>
    private sealed class NeverEndingWebSocket : WebSocket
    {
        private readonly int _chunkSize;
        public int ReceiveCalls { get; private set; }

        public NeverEndingWebSocket(int chunkSize) => _chunkSize = chunkSize;

        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            ReceiveCalls++;
            int count = Math.Min(_chunkSize, buffer.Count);
            return Task.FromResult(new WebSocketReceiveResult(count, WebSocketMessageType.Binary, endOfMessage: false));
        }

        public override WebSocketState State => WebSocketState.Open;
        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override string? SubProtocol => null;
        public override void Abort() { }
        public override Task CloseAsync(WebSocketCloseStatus s, string? d, CancellationToken c) => Task.CompletedTask;
        public override Task CloseOutputAsync(WebSocketCloseStatus s, string? d, CancellationToken c) => Task.CompletedTask;
        public override Task SendAsync(ArraySegment<byte> b, WebSocketMessageType t, bool e, CancellationToken c) => Task.CompletedTask;
        public override void Dispose() { }
    }

    [Fact]
    public async Task ReadAsync_RejectsMessageExceedingCap_InsteadOfBufferingUnbounded()
    {
        var socket = new NeverEndingWebSocket(chunkSize: 8);
        // Small cap so the guard trips after a couple of fragments rather than 16 MiB.
        await using var stream = new PqWebSocketStream(socket, ownsSocket: false, maxReceiveMessageSize: 16);

        var buffer = new byte[64];
        var ex = await Assert.ThrowsAsync<PostQuantum.SecureChannel.PqProtocolException>(
            // CA2022 (inexact read) does not apply: this read is expected to throw before returning a
            // count, which is exactly what the test asserts.
#pragma warning disable CA2022
            async () => await stream.ReadAsync(buffer));
#pragma warning restore CA2022

        Assert.Contains("exceeds", ex.Message, StringComparison.OrdinalIgnoreCase);
        // It must have failed early — not read an unbounded number of fragments.
        Assert.True(socket.ReceiveCalls <= 4, $"expected an early bail-out, got {socket.ReceiveCalls} receives");
    }

    [Fact]
    public void Constructor_RejectsNonPositiveCap()
    {
        using var socket = new NeverEndingWebSocket(chunkSize: 8);
        Assert.Throws<ArgumentOutOfRangeException>(() => new PqWebSocketStream(socket, ownsSocket: false, maxReceiveMessageSize: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PqWebSocketStream(socket, ownsSocket: false, maxReceiveMessageSize: -1));
    }
}

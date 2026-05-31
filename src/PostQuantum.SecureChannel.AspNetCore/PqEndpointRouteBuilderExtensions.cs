using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PostQuantum.SecureChannel.Transport;

namespace PostQuantum.SecureChannel.AspNetCore;

/// <summary>
/// Endpoint helpers for hosting a PQ secure channel inside an ASP.NET Core application. Map a
/// WebSocket route; the helper drives the handshake and hands a <see cref="PqSecureChannelStream"/>
/// to the supplied delegate.
/// </summary>
public static class PqEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps a WebSocket endpoint that, upon connection, accepts a PQ secure-channel handshake using
    /// the registered <see cref="PqIdentity"/> and invokes <paramref name="handler"/> with the
    /// resulting encrypted <see cref="Stream"/>.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="pattern">The route pattern (for example, <c>"/pqsc"</c>).</param>
    /// <param name="handler">Invoked once per accepted connection with the established channel.</param>
    public static IEndpointConventionBuilder MapPqWebSocket(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        Func<PqSecureChannelStream, HttpContext, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(handler);

        return endpoints.Map(pattern, async (HttpContext ctx) =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            var identity = ctx.RequestServices.GetRequiredService<PqIdentity>();
            var options = ctx.RequestServices.GetRequiredService<IOptions<PqSecureChannelOptions>>().Value;

            using var webSocket = await ctx.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
            using var transport = new PqWebSocketStream(webSocket, ownsSocket: false);

            await using var channel = await PqSecureChannel.AcceptAsync(
                transport,
                new PqServerOptions
                {
                    Identity = identity,
                    RequireClientAuthentication = options.RequireClientAuthentication,
                    SessionOptions = options.ResolveSessionOptions(),
                },
                leaveInnerOpen: true,
                handshakeTimeout: options.HandshakeTimeout,
                cancellationToken: ctx.RequestAborted).ConfigureAwait(false);

            await handler(channel, ctx).ConfigureAwait(false);
        });
    }
}

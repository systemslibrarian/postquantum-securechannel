using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PostQuantum.SecureChannel.AspNetCore;
using PostQuantum.SecureChannel.AspNetCore.DependencyInjection;
using Xunit;

namespace PostQuantum.SecureChannel.AspNetCore.Tests;

public class WebSocketEndpointTests
{
    [Fact]
    public async Task MapPqWebSocket_EchoesEncryptedTraffic()
    {
        using var serverIdentity = PqIdentity.Create();

        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddPostQuantumSecureChannel().AddServerIdentity(serverIdentity);
                });
                web.Configure(app =>
                {
                    app.UseWebSockets();
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapPqWebSocket("/pqsc", async (channel, _) =>
                        {
                            var buf = new byte[64];
                            int read = await channel.ReadAsync(buf);
                            await channel.WriteAsync(buf.AsMemory(0, read));
                        });
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestServer().CreateWebSocketClient();
        var ws = await client.ConnectAsync(new Uri("ws://localhost/pqsc"), CancellationToken.None);

        await using var channel = await ws.AcceptPqClientAsync(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
        });

        var payload = Encoding.UTF8.GetBytes("post-quantum");
        await channel.WriteAsync(payload);

        var reply = new byte[payload.Length];
        await channel.ReadExactlyAsync(reply);
        Assert.Equal("post-quantum", Encoding.UTF8.GetString(reply));
    }
}

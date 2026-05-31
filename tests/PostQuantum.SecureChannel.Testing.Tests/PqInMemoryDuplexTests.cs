using System.Text;
using PostQuantum.SecureChannel.Testing;
using Xunit;

namespace PostQuantum.SecureChannel.Testing.Tests;

public class PqInMemoryDuplexTests
{
    [Fact]
    public async Task CreatePair_FullDuplexHandshakeWorks()
    {
        var (clientStream, serverStream) = PqInMemoryDuplex.CreatePair();

        using var serverIdentity = PqIdentity.Create();
        var clientTask = PqSecureChannel.ConnectAsync(
            clientStream, new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var serverTask = PqSecureChannel.AcceptAsync(
            serverStream, new PqServerOptions { Identity = serverIdentity });

        await Task.WhenAll(clientTask, serverTask);
        await using var client = await clientTask;
        await using var server = await serverTask;

        await client.WriteAsync(Encoding.UTF8.GetBytes("hello"));
        var buffer = new byte[5];
        await server.ReadExactlyAsync(buffer);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer));
    }

    [Fact]
    public async Task ClosingOneSide_SignalsEndOfStreamToTheOther()
    {
        var (clientStream, serverStream) = PqInMemoryDuplex.CreatePair();
        clientStream.Dispose();

        var buffer = new byte[16];
        int read = await serverStream.ReadAsync(buffer);
        Assert.Equal(0, read);
    }
}

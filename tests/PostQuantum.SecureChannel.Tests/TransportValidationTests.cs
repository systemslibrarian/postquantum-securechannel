using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Argument-validation coverage for the transport entry points. A non-positive <c>maxFrameSize</c>
/// would otherwise disable the allocation guard in the framing layer (a negative value casts to a huge
/// <c>uint</c> bound), so it must be rejected up front.
/// </summary>
public class TransportValidationTests
{
    private static PqClientOptions ClientOptions()
    {
        using var serverIdentity = PqIdentity.Create();
        return new PqClientOptions { ServerIdentity = serverIdentity.PublicKey };
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public async Task ConnectAsync_RejectsNonPositiveMaxFrameSize(int maxFrameSize)
    {
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => PqSecureChannel.ConnectAsync(stream, ClientOptions(), maxFrameSize: maxFrameSize));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public async Task AcceptAsync_RejectsNonPositiveMaxFrameSize(int maxFrameSize)
    {
        using var serverIdentity = PqIdentity.Create();
        var options = new PqServerOptions { Identity = serverIdentity };
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => PqSecureChannel.AcceptAsync(stream, options, maxFrameSize: maxFrameSize));
    }
}

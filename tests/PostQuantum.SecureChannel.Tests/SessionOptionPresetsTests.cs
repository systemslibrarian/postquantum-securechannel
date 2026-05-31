using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// The named presets (<see cref="PqSessionOptions.Default"/>, <see cref="PqSessionOptions.Recommended"/>,
/// <see cref="PqSessionOptions.UnorderedTransport"/>, <see cref="PqSessionOptions.HighThroughput"/>) must
/// be self-consistent and validate.
/// </summary>
public class SessionOptionPresetsTests
{
    [Fact]
    public void Default_IsStrictOrdered_NoAutoRekey()
    {
        Assert.Equal(PqReplayProtection.StrictOrdered, PqSessionOptions.Default.ReplayProtection);
        Assert.Same(PqKeyUpdatePolicy.Disabled, PqSessionOptions.Default.KeyUpdatePolicy);
    }

    [Fact]
    public void Recommended_HasAutoRekey()
    {
        var preset = PqSessionOptions.Recommended;
        Assert.Equal(PqReplayProtection.StrictOrdered, preset.ReplayProtection);
        Assert.NotNull(preset.KeyUpdatePolicy.MaxRecordsBeforeUpdate);
        Assert.NotNull(preset.KeyUpdatePolicy.MaxBytesBeforeUpdate);
    }

    [Fact]
    public void UnorderedTransport_UsesSlidingWindow()
    {
        var preset = PqSessionOptions.UnorderedTransport;
        Assert.Equal(PqReplayProtection.SlidingWindow, preset.ReplayProtection);
        Assert.InRange(preset.ReplayWindowSize, 8, 1024);
    }

    [Theory]
    [MemberData(nameof(AllPresets))]
    public void AllPresets_PassValidationAndDriveHandshake(PqSessionOptions preset)
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            SessionOptions = preset,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions
        {
            Identity = serverIdentity,
            SessionOptions = preset,
        });

        var hello = client.CreateClientHello();
        var sh = server.ProcessClientHello(hello);
        var result = client.ProcessServerHello(sh);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        var record = result.Session.Encrypt(new byte[] { 1, 2, 3 });
        Assert.Equal(new byte[] { 1, 2, 3 }, serverSession.Decrypt(record));
    }

    public static IEnumerable<object[]> AllPresets()
    {
        yield return new object[] { PqSessionOptions.Default };
        yield return new object[] { PqSessionOptions.Recommended };
        yield return new object[] { PqSessionOptions.UnorderedTransport };
        yield return new object[] { PqSessionOptions.HighThroughput };
    }
}

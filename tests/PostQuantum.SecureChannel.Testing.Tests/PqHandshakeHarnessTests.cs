using System.Text;
using PostQuantum.SecureChannel.Testing;
using Xunit;

namespace PostQuantum.SecureChannel.Testing.Tests;

public class PqHandshakeHarnessTests
{
    [Fact]
    public void Create_ProducesWorkingSessionPair()
    {
        using var harness = PqHandshakeHarness.Create();

        var record = harness.Client.Encrypt(Encoding.UTF8.GetBytes("hi"));
        Assert.Equal("hi", Encoding.UTF8.GetString(harness.Server.Decrypt(record)));
    }

    [Fact]
    public void Create_Mutual_BothSidesKnowEachOther()
    {
        using var harness = PqHandshakeHarness.Create(mutual: true);

        Assert.NotNull(harness.ClientIdentity);
        Assert.NotNull(harness.Server.RemoteIdentity);
        Assert.Equal(
            harness.ClientIdentity!.PublicKey.Fingerprint(),
            harness.Server.RemoteIdentity!.Fingerprint());
    }

    [Fact]
    public void Create_WithResumptionSecret_ExportsMatching()
    {
        var psk = new byte[32];
        for (int i = 0; i < psk.Length; i++) psk[i] = (byte)i;

        using var harness = PqHandshakeHarness.Create(resumptionSecret: psk);

        Assert.Equal(harness.Client.ExportResumptionSecret(), harness.Server.ExportResumptionSecret());
    }

    [Fact]
    public void Create_AppliesSessionPreset()
    {
        using var harness = PqHandshakeHarness.Create(sessionOptions: PqSessionOptions.UnorderedTransport);
        // The receive side honors the preset's sliding-window mode; round-trip still works.
        var record = harness.Client.Encrypt(new byte[] { 1, 2, 3 });
        Assert.Equal(new byte[] { 1, 2, 3 }, harness.Server.Decrypt(record));
    }
}

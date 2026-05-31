using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.SecureChannel.AspNetCore;
using PostQuantum.SecureChannel.AspNetCore.DependencyInjection;
using Xunit;

namespace PostQuantum.SecureChannel.AspNetCore.Tests;

public class OptionsBindingTests
{
    [Fact]
    public void AddPostQuantumSecureChannel_RegistersOptions()
    {
        var services = new ServiceCollection();
        services.AddPostQuantumSecureChannel();
        var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<Microsoft.Extensions.Options.IOptions<PqSecureChannelOptions>>());
    }

    [Fact]
    public void AddServerIdentityFromConfiguration_LoadsIdentityFromSeed()
    {
        using var seedSource = PqIdentity.Create();
        var seedBase64 = Convert.ToBase64String(seedSource.ExportPrivateSeed());

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PqSecureChannel:ServerIdentitySeedBase64"] = seedBase64,
            })
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddPostQuantumSecureChannel().AddServerIdentityFromConfiguration("PqSecureChannel");
        using var provider = services.BuildServiceProvider();

        using var identity = provider.GetRequiredService<PqIdentity>();
        Assert.Equal(seedSource.PublicKey.Fingerprint(), identity.PublicKey.Fingerprint());
    }

    [Theory]
    [InlineData("Default")]
    [InlineData("Recommended")]
    [InlineData("UnorderedTransport")]
    [InlineData("HighThroughput")]
    public void SessionPreset_ResolvesToKnownPreset(string preset)
    {
        var options = new PqSecureChannelOptions { SessionPreset = preset };
        var resolved = options.ResolveSessionOptions();
        Assert.NotNull(resolved);
    }

    [Fact]
    public void SessionPreset_Unknown_Throws()
    {
        var options = new PqSecureChannelOptions { SessionPreset = "bogus" };
        Assert.Throws<InvalidOperationException>(() => options.ResolveSessionOptions());
    }

    [Fact]
    public void BuildClientOptions_RequiresAtLeastOnePin()
    {
        var options = new PqSecureChannelOptions();
        Assert.Throws<InvalidOperationException>(() => options.BuildClientOptions());
    }

    [Fact]
    public void BuildClientOptions_AcceptsBase64Pin()
    {
        using var identity = PqIdentity.Create();
        var options = new PqSecureChannelOptions { PinnedServerKeyBase64 = identity.PublicKey.ToBase64() };

        var built = options.BuildClientOptions();
        Assert.NotNull(built.ServerIdentity);
        Assert.Equal(identity.PublicKey.Fingerprint(), built.ServerIdentity!.Fingerprint());
    }
}

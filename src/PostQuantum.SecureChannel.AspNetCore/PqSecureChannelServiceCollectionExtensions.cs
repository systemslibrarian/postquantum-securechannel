using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace PostQuantum.SecureChannel.AspNetCore.DependencyInjection;

/// <summary>
/// DI registration helpers for PostQuantum.SecureChannel. Bind <see cref="PqSecureChannelOptions"/>
/// from <see cref="IConfiguration"/>, then materialize a long-lived <see cref="PqIdentity"/> from a
/// base64 seed (config or file) and register it for downstream injection.
/// </summary>
public static class PqSecureChannelServiceCollectionExtensions
{
    /// <summary>
    /// Adds base PostQuantum.SecureChannel options to DI. Chain with
    /// <see cref="AddServerIdentityFromConfiguration"/>, <see cref="AddServerIdentityFromSeedFile"/>,
    /// or <see cref="AddServerIdentity"/> to materialize the identity.
    /// </summary>
    public static PqSecureChannelBuilder AddPostQuantumSecureChannel(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<PqSecureChannelOptions>();
        return new PqSecureChannelBuilder(services);
    }

    /// <summary>
    /// Binds <see cref="PqSecureChannelOptions"/> from the given configuration section and registers
    /// a <see cref="PqIdentity"/> singleton resolved from <c>ServerIdentitySeedBase64</c> or
    /// <c>ServerIdentitySeedFile</c>.
    /// </summary>
    public static PqSecureChannelBuilder AddServerIdentityFromConfiguration(
        this PqSecureChannelBuilder builder, string sectionName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        builder.Services.AddOptions<PqSecureChannelOptions>().BindConfiguration(sectionName);

        builder.Services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<IOptions<PqSecureChannelOptions>>().Value;
            return LoadServerIdentity(options);
        });

        return builder;
    }

    /// <summary>Registers a <see cref="PqIdentity"/> singleton loaded from a base64-seed file.</summary>
    public static PqSecureChannelBuilder AddServerIdentityFromSeedFile(
        this PqSecureChannelBuilder builder, string path)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        builder.Services.AddSingleton(_ =>
        {
            var base64 = File.ReadAllText(path).Trim();
            var seed = Convert.FromBase64String(base64);
            return PqIdentity.ImportPrivateSeed(seed);
        });
        return builder;
    }

    /// <summary>Registers an explicit <see cref="PqIdentity"/> singleton.</summary>
    public static PqSecureChannelBuilder AddServerIdentity(this PqSecureChannelBuilder builder, PqIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(identity);
        builder.Services.AddSingleton(identity);
        return builder;
    }

    /// <summary>Resolves the pinned server identity for client-side use from options (base64 or seed file).</summary>
    public static PqClientOptions BuildClientOptions(this PqSecureChannelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.PinnedServerKeyBase64) && options.AllowedServerKeysBase64.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(options.PinnedServerKeyBase64)} or {nameof(options.AllowedServerKeysBase64)} must be set for client-side use.");
        }

        PqIdentityPublicKey? primary = !string.IsNullOrWhiteSpace(options.PinnedServerKeyBase64)
            ? PqIdentityPublicKey.FromBase64(options.PinnedServerKeyBase64)
            : null;

        var extras = options.AllowedServerKeysBase64.Count > 0
            ? options.AllowedServerKeysBase64.Select(PqIdentityPublicKey.FromBase64).ToList()
            : null;

        return new PqClientOptions
        {
            ServerIdentity = primary,
            AllowedServerIdentities = extras,
            SessionOptions = options.ResolveSessionOptions(),
        };
    }

    private static PqIdentity LoadServerIdentity(PqSecureChannelOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.ServerIdentitySeedBase64))
        {
            return PqIdentity.ImportPrivateSeed(Convert.FromBase64String(options.ServerIdentitySeedBase64));
        }

        if (!string.IsNullOrWhiteSpace(options.ServerIdentitySeedFile))
        {
            var base64 = File.ReadAllText(options.ServerIdentitySeedFile).Trim();
            return PqIdentity.ImportPrivateSeed(Convert.FromBase64String(base64));
        }

        throw new InvalidOperationException(
            "PqSecureChannel options have no server identity: set ServerIdentitySeedBase64 or ServerIdentitySeedFile.");
    }
}

/// <summary>
/// Returned by <see cref="PqSecureChannelServiceCollectionExtensions.AddPostQuantumSecureChannel"/> to chain identity-loading helpers.
/// </summary>
public sealed class PqSecureChannelBuilder
{
    internal PqSecureChannelBuilder(IServiceCollection services) => Services = services;

    /// <summary>The underlying <see cref="IServiceCollection"/>.</summary>
    public IServiceCollection Services { get; }
}

using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>Polish-pass guarantees on the public surface.</summary>
public class PublicApiTests
{
    [Fact]
    public void LibraryVersion_IsExposed()
    {
        var v = PqSecureChannel.LibraryVersion;
        Assert.False(string.IsNullOrWhiteSpace(v));
        Assert.Matches(@"^\d+\.\d+\.\d+", v);
    }

    [Fact]
    public void PublicKey_Equality_IsValueBased()
    {
        using var a = PqIdentity.Create();
        using var b = PqIdentity.Create();

        var imported = PqIdentityPublicKey.Import(a.PublicKey.Export());

        Assert.True(a.PublicKey.Equals(imported));
        Assert.True(a.PublicKey == imported);
        Assert.False(a.PublicKey.Equals(b.PublicKey));
        Assert.True(a.PublicKey != b.PublicKey);
    }

    [Fact]
    public void PublicKey_GetHashCode_IsStableAcrossImports()
    {
        using var identity = PqIdentity.Create();
        var imported = PqIdentityPublicKey.Import(identity.PublicKey.Export());

        Assert.Equal(identity.PublicKey.GetHashCode(), imported.GetHashCode());
    }

    [Fact]
    public void PublicKey_UsableAsHashSetKey()
    {
        using var a = PqIdentity.Create();
        using var b = PqIdentity.Create();

        var set = new HashSet<PqIdentityPublicKey> { a.PublicKey, b.PublicKey };
        var importedA = PqIdentityPublicKey.Import(a.PublicKey.Export());

        Assert.Contains(importedA, set);
        Assert.Equal(2, set.Count);
        set.Add(importedA); // dedupes via Equals
        Assert.Equal(2, set.Count);
    }

    [Fact]
    public void PublicKey_ToString_IsShortFingerprintForm()
    {
        using var identity = PqIdentity.Create();
        var s = identity.PublicKey.ToString();
        Assert.StartsWith("pq:", s);
        Assert.Contains(":", s[3..]);
    }
}

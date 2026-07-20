using System.Text;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Trust.Tests;

public class StaticTrustListResolverTests
{
    [Fact]
    public async Task TrustedIssuer_ResolvesTrusted_WithSource()
    {
        var resolver = new StaticTrustListResolver(["https://issuer.example"], source: "unit-test");

        var status = await resolver.ResolveAsync("https://issuer.example", []);

        Assert.True(status.Trusted);
        Assert.Equal("unit-test", status.TrustListSource);
        Assert.Null(status.Reason);
    }

    [Fact]
    public async Task UnknownIssuer_ResolvesUntrusted_WithReason()
    {
        var resolver = new StaticTrustListResolver(["https://issuer.example"]);

        var status = await resolver.ResolveAsync("https://evil.example", []);

        Assert.False(status.Trusted);
        Assert.Null(status.TrustListSource);
        Assert.NotNull(status.Reason);
    }

    [Fact]
    public async Task FromJson_ParsesTrustedIssuers()
    {
        using var json = new MemoryStream(Encoding.UTF8.GetBytes(
            """{"trusted_issuers":["https://a.example","https://b.example"]}"""));

        var resolver = await TrustListLoader.FromJsonAsync(json);

        Assert.True((await resolver.ResolveAsync("https://a.example", [])).Trusted);
        Assert.True((await resolver.ResolveAsync("https://b.example", [])).Trusted);
        Assert.False((await resolver.ResolveAsync("https://c.example", [])).Trusted);
    }

    [Fact]
    public async Task FromJson_MissingArray_Throws()
    {
        using var json = new MemoryStream(Encoding.UTF8.GetBytes("""{"issuers":[]}"""));

        await Assert.ThrowsAsync<InvalidOperationException>(() => TrustListLoader.FromJsonAsync(json));
    }

    [Fact]
    public async Task LoadAsync_FromFile_Works()
    {
        var path = Path.Combine(Path.GetTempPath(), $"tessio-trust-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, """{"trusted_issuers":["https://file.example"]}""");
        try
        {
            var resolver = await TrustListLoader.LoadAsync(path);
            Assert.True((await resolver.ResolveAsync("https://file.example", [])).Trusted);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

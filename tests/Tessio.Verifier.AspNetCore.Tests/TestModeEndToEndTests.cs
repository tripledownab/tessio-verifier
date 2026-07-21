using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// TEST mode replays the pinned RFC 9901 conformance vector through the real verifier and completes
/// the session with the actual result — fully offline.
/// </summary>
public sealed class TestModeEndToEndTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider;

    public TestModeEndToEndTests()
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Test);
        _provider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task TestMode_ReplaysRfc9901Vector_AndVerifies()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        await _provider.GetRequiredService<TestFixtureQueue>().EnqueueAsync(session.SessionId);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var terminal = await store.WaitForTerminalAsync(session.SessionId, timeout.Token);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        var result = terminal.Result!;
        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        // The RFC vector's disclosed claims, verified via real key resolution and trust.
        Assert.Equal(ConformanceFixture.Issuer, result.Issuer.Identifier);
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.True(result.DisclosedClaims.ContainsKey("nationalities"));
        Assert.True(result.DisclosedClaims.ContainsKey("age_equal_or_over"));
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StopAsync(CancellationToken.None);
        }

        await _provider.DisposeAsync();
    }
}

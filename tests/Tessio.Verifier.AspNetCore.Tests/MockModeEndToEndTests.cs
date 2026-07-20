using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The v0.1 definition-of-done pipeline test: MOCK mode issues a real signed SD-JWT VC and pushes it
/// through response parsing (OpenId4Vp), credential verification (Core), trust resolution (Trust)
/// and session completion (AspNetCore) using the exact service graph AddTessioVerifier registers.
/// </summary>
public sealed class MockModeEndToEndTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider;

    public MockModeEndToEndTests()
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.RequestedClaims = ["age_over_18", "given_name"];
        });
        _provider = services.BuildServiceProvider();
    }

    private async Task<VerificationSession> RunSessionAsync(Action<VerificationSession>? beforeWallet = null)
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));
        beforeWallet?.Invoke(session);

        await _provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        return await store.WaitForTerminalAsync(session.SessionId, timeout.Token);
    }

    [Fact]
    public async Task MockMode_FullPipeline_VerifiesRealCredential()
    {
        var terminal = await RunSessionAsync();

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        var result = terminal.Result!;
        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
        Assert.Equal("Erika", result.DisclosedClaims["given_name"]);

        // The credential really went through Core's x5c resolution and the trust seam.
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Equal(MockCredentialIssuer.Issuer, result.Issuer.Identifier);
        Assert.True(result.Issuer.Trusted);
    }

    [Fact]
    public async Task Callback_WithUnknownState_IsRejected()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();
        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { """{"credential":["a.b.c~"]}""" },
                ["state"] = new[] { "no-such-state" },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        Assert.Equal(CallbackOutcome.UnknownSession, await processor.ProcessAsync(response, CancellationToken.None));
    }

    [Fact]
    public async Task Callback_TamperedPresentation_CompletesSessionAsInvalid()
    {
        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var issuer = _provider.GetRequiredService<MockCredentialIssuer>();
        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // A presentation bound to the WRONG nonce simulates a replayed response.
        var replayed = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, nonce: "some-other-nonce", audience: options.ClientId);

        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{replayed}}"]}""" },
                ["state"] = new[] { session.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        Assert.Equal(CallbackOutcome.Completed, await processor.ProcessAsync(response, CancellationToken.None));

        var terminal = await store.GetAsync(session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, terminal!.Status);
        Assert.False(terminal.Result!.IsValid);
        Assert.Contains(terminal.Result.Errors, e => e.Code == "nonce_mismatch");
    }

    [Fact]
    public async Task Callback_SecondResponseForSameSession_IsRejected()
    {
        var terminal = await RunSessionAsync();
        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);

        var issuer = _provider.GetRequiredService<MockCredentialIssuer>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();

        var replay = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, terminal.Request.Nonce, options.ClientId);
        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{replay}}"]}""" },
                ["state"] = new[] { terminal.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        Assert.Equal(CallbackOutcome.SessionNotPending, await processor.ProcessAsync(response, CancellationToken.None));
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
